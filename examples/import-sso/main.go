// Command import-sso moves Supabase Auth's SAML SSO providers into
// plugin/sso: each provider's IdP metadata, attribute mapping, NameID format
// and email domains, registered through the plugin's own RegisterProvider so
// the configuration is checked exactly as a registration over HTTP would be.
// Run it after import-users, naming the imported administrator who will own
// the providers.
//
//	go run ./import-sso -providers sso_providers.csv -saml saml_providers.csv -domains sso_domains.csv \
//	  -sp-entity-id https://<ref>.supabase.co/auth/v1/sso/saml/metadata -owner <user id> -db app.db
//
// The program wires the plugins the import needs; in your app, call
// importProviders with your own auth.New so your options apply.
package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// baseURL is the app's public URL: the ACS URL each provider gets is
	// built from it, so run the import with the production value (-base-url).
	baseURL = "http://localhost:8081"
	// dbFile is the SQLite database the import writes; -db changes it.
	dbFile = "import.db"
	// supabaseIDPrefix starts the id of a provider whose Supabase
	// resource_id is empty or not a valid provider id.
	supabaseIDPrefix = "supabase-"
)

// providerID is the shape plugin/sso accepts for a provider id.
var providerID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

// samlRow is one Supabase SAML provider, joined from the three tables.
type samlRow struct {
	SupabaseID   string // auth.sso_providers.id
	ResourceID   string // auth.sso_providers.resource_id, a name the owner chose
	EntityID     string // auth.saml_providers.entity_id, the IdP's
	MetadataXML  string
	MetadataURL  string
	Mapping      string // auth.saml_providers.attribute_mapping, JSON
	NameIDFormat string
	Domains      []string
}

// result is the outcome for one provider.
type result struct {
	Row        samlRow
	ProviderID string
	Err        error
	Notes      []string
}

func main() {
	providers := flag.String("providers", "", "auth.sso_providers as CSV")
	saml := flag.String("saml", "", "auth.saml_providers as CSV")
	domains := flag.String("domains", "", "auth.sso_domains as CSV")
	spEntityID := flag.String("sp-entity-id", "", "Supabase's SP entity id, kept so the IdPs need only the new ACS URL")
	owner := flag.String("owner", "", "the id of the imported user who will own the providers")
	base := flag.String("base-url", baseURL, "the app's public URL; each provider's ACS URL is built from it")
	dbPath := flag.String("db", dbFile, "the SQLite database to write")
	flag.Parse()

	rows, err := readSupabase(*providers, *saml, *domains)
	if err != nil {
		log.Fatal(err)
	}
	if *owner == "" || *spEntityID == "" {
		log.Fatal("-owner and -sp-entity-id are required")
	}
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: *dbPath}).EscapedPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	a, p, err := newAuth(db, *base, []byte(os.Getenv(auth.EnvSecret)))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	results, err := importProviders(ctx, a, p, *owner, *spEntityID, rows)
	if err != nil {
		log.Fatal(err)
	}
	if printSummary(os.Stdout, results) > 0 {
		os.Exit(1)
	}
}

// newAuth wires what the import writes through: the sso plugin, and email
// and password because auth.New refuses an app nobody could sign in to.
// AUTH_SECRET must be the app's: provider keys are sealed with it. opts are
// the app's sso options; the test passes sso.TrustProviders.
func newAuth(db *sql.DB, base string, secret []byte, opts ...sso.Option) (*auth.Auth, *sso.Plugin, error) {
	p := sso.New(opts...)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(base),
		auth.WithSecret(secret),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(noMail{})), password.New(), p),
	)
	return a, p, err
}

// importProviders registers each row as a SAML provider owned by owner.
// RegisterProvider is an operation of a signed-in user, so the import holds
// a session of owner for its duration and deletes it at the end. Each
// provider keeps Supabase's SP entity id, so the IdP admin changes only the
// ACS URL. A provider that fails (metadata the plugin refuses, an id already
// registered) is listed; the rest land.
//
//ds:def id=importproviders-4c7mx2ra
func importProviders(ctx context.Context, a *auth.Auth, p *sso.Plugin, owner, spEntityID string, rows []samlRow) ([]result, error) {
	s, tok, err := a.CreateSession(ctx, owner, auth.Client{UserAgent: "import-sso"})
	if err != nil {
		return nil, fmt.Errorf("owner %s: %w", owner, err)
	}
	defer func() { _ = a.DeleteSession(context.Background(), owner, s.ID) }() // best effort; it expires anyway
	as := a.WithRequest(ctx, auth.Request{Transport: auth.TransportGo, Credential: auth.CredentialBearer, Token: tok})

	out := make([]result, 0, len(rows))
	for _, r := range rows {
		res := result{Row: r, ProviderID: providerIDFor(r)}
		cfg, notes, err := samlConfig(r, spEntityID)
		res.Notes = notes
		if err == nil {
			_, err = p.RegisterProvider(as, sso.RegisterRequest{ProviderID: res.ProviderID, Issuer: spEntityID, Domain: strings.Join(r.Domains, ","), SAMLConfig: cfg})
		}
		res.Err = err
		out = append(out, res)
	}
	return out, nil
}

// providerIDFor keeps Supabase's resource_id when plugin/sso accepts it, so
// links and logs that name it stay meaningful; otherwise the Supabase uuid.
func providerIDFor(r samlRow) string {
	if providerID.MatchString(r.ResourceID) {
		return r.ResourceID
	}
	return supabaseIDPrefix + r.SupabaseID
}

// supabaseMapping is auth.saml_providers.attribute_mapping:
// {"keys": {"email": {"name": "mail"}, ...}}.
type supabaseMapping struct {
	Keys map[string]struct {
		Name  string   `json:"name"`
		Names []string `json:"names"`
	} `json:"keys"`
}

// samlConfig builds a provider's SAML configuration from a row: the IdP
// metadata XML as Supabase stored it, the NameID format, Supabase's SP
// entity id, and the attribute mapping.
func samlConfig(r samlRow, spEntityID string) (*sso.SAMLConfig, []string, error) {
	if r.MetadataXML == "" {
		return nil, nil, fmt.Errorf("no metadata_xml (metadata_url %q): fetch the XML and put it in the CSV", r.MetadataURL)
	}
	mapping, notes, err := samlMapping(r.Mapping)
	if err != nil {
		return nil, nil, err
	}
	return &sso.SAMLConfig{
		IdPMetadata:          sso.IdPMetadata{Metadata: r.MetadataXML},
		SPMetadata:           sso.SPMetadata{EntityID: spEntityID},
		IdentifierFormat:     r.NameIDFormat,
		WantAssertionsSigned: true,
		Mapping:              mapping,
	}, notes, nil
}

// samlMapping turns Supabase's attribute_mapping into the plugin's: keys
// email, name, first_name/given_name and last_name/family_name map onto its
// fields; any other key becomes an extra field under its own name. A key
// with several attribute names keeps the first, with a note.
//
//ds:def id=samlmapping-9t3pv6hd
func samlMapping(raw string) (sso.SAMLMapping, []string, error) {
	var out sso.SAMLMapping
	var m supabaseMapping
	if raw == "" {
		return out, nil, nil
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return out, nil, fmt.Errorf("attribute_mapping: %w", err)
	}
	var notes []string
	keys := slices.Sorted(maps.Keys(m.Keys))
	for _, k := range keys {
		attr := m.Keys[k].Name
		if names := m.Keys[k].Names; attr == "" && len(names) > 0 {
			attr = names[0]
			if len(names) > 1 {
				notes = append(notes, fmt.Sprintf("%s: kept the first of %d attribute names (%s)", k, len(names), attr))
			}
		}
		switch {
		case attr == "":
		case k == "email":
			out.Email = attr
		case k == "name":
			out.Name = attr
		case k == "first_name" || k == "given_name":
			out.FirstName = attr
		case k == "last_name" || k == "family_name":
			out.LastName = attr
		default:
			if out.ExtraFields == nil {
				out.ExtraFields = map[string]string{}
			}
			out.ExtraFields[k] = attr
		}
	}
	return out, notes, nil
}

// readSupabase reads the three \copy CSVs and joins them on the provider id.
func readSupabase(providersPath, samlPath, domainsPath string) ([]samlRow, error) {
	providers, err := readCSV(providersPath)
	if err != nil {
		return nil, fmt.Errorf("providers: %w", err)
	}
	saml, err := readCSV(samlPath)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	domains, err := readCSV(domainsPath)
	if err != nil {
		return nil, fmt.Errorf("domains: %w", err)
	}
	byProvider := map[string]map[string]string{}
	for _, s := range saml {
		byProvider[s["sso_provider_id"]] = s
	}
	domainsOf := map[string][]string{}
	for _, d := range domains {
		domainsOf[d["sso_provider_id"]] = append(domainsOf[d["sso_provider_id"]], d["domain"])
	}
	var out []samlRow
	for _, p := range providers {
		s, ok := byProvider[p["id"]]
		if !ok {
			continue // a provider without a SAML row has nothing to sign in with
		}
		out = append(out, samlRow{SupabaseID: p["id"], ResourceID: p["resource_id"], EntityID: s["entity_id"], MetadataXML: s["metadata_xml"],
			MetadataURL: s["metadata_url"], Mapping: s["attribute_mapping"], NameIDFormat: s["name_id_format"], Domains: domainsOf[p["id"]]})
	}
	return out, nil
}

// readCSV reads a CSV with a header row into one map per row.
func readCSV(path string) ([]map[string]string, error) {
	if path == "" {
		return nil, errors.New("a file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	var out []map[string]string
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		row := make(map[string]string, len(header))
		for i, h := range header {
			row[h] = rec[i]
		}
		out = append(out, row)
	}
}

// printSummary prints the outcome and returns how many failed.
func printSummary(w io.Writer, results []result) int {
	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
		}
	}
	fmt.Fprintf(w, "imported %d provider(s), %d failed\n", len(results)-failed, failed)
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(w, "  FAILED %s: %v\n", r.ProviderID, r.Err)
		default:
			fmt.Fprintf(w, "  ok     %s: %s (IdP %s)\n", r.ProviderID, strings.Join(r.Row.Domains, ", "), r.Row.EntityID)
		}
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note   %s: %s\n", r.ProviderID, n)
		}
	}
	return failed
}

// noMail is the email plugin's mailer during an import: nothing here sends
// mail, and an attempt is an error rather than a message to a real user.
type noMail struct{}

// Send refuses.
func (noMail) Send(context.Context, email.Mail) error {
	return errors.New("import-sso sends no mail")
}
