// Command geo-rules judges every sign-in by where it comes from: one country
// is refused before the password is even looked at, and a sign-in from a city
// no flight could have reached since the user's previous sign-in is refused
// too, with each refusal reported to the security event stream.
//
//	go run ./geo-rules
//
// The library has no GeoIP database and no vendor client: where an address
// is comes from the GeoLocator the app passes. Here it is a table of three
// documentation addresses (203.0.113.0/24, reserved for examples) standing
// in for a MaxMind reader; a real app wraps its reader in the same
// auth.GeoLocatorFunc. The app runs behind a reverse proxy on this machine,
// so the client address is the one the proxy writes into X-Forwarded-For.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "geo-rules.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is 8081, or $PORT when it is set, so two examples can run side by
	// side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas: WAL so readers do not block the writer, and a busy timeout
// instead of an immediate "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	opts := append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins()...),
		// The zero-setup sink: each refusal is one line on the logger.
		auth.WithSecurityLog(auth.SecurityQueue{}),
	}, geoOptions()...)
	a, err := auth.New(opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// The documentation addresses the fake locator knows, one per city.
const (
	berlinIP  = "203.0.113.7"
	newYorkIP = "203.0.113.8"
	moscowIP  = "203.0.113.9"
)

// ISO 3166-1 alpha-2 codes of the cities' countries.
const (
	countryGermany = "DE"
	countryUS      = "US"
	countryRussia  = "RU"
)

// geoTable is what the fake locator knows: each address's country and
// coordinates, as a city-level GeoIP database answers. An address missing
// from it is "not found", which GeoRules lets through unless DenyUnknown.
var geoTable = map[netip.Addr]auth.GeoLocation{
	netip.MustParseAddr(berlinIP):  {Country: countryGermany, Latitude: 52.52, Longitude: 13.405, HasCoordinates: true},
	netip.MustParseAddr(newYorkIP): {Country: countryUS, Latitude: 40.7128, Longitude: -74.006, HasCoordinates: true},
	netip.MustParseAddr(moscowIP):  {Country: countryRussia, Latitude: 55.7558, Longitude: 37.6173, HasCoordinates: true},
}

// locator is the GeoLocator: a map lookup, fast and local as the interface
// requires, since it runs on the sign-in request. A MaxMind reader goes in
// the same function, returning its error when the database cannot be read
// (the check then fails open and logs, so a GeoIP outage is never a sign-in
// outage).
//
//ds:def id=georules-example-locator-6nq2kw8x
var locator = auth.GeoLocatorFunc(func(_ context.Context, ip netip.Addr) (auth.GeoLocation, bool, error) {
	loc, found := geoTable[ip]
	return loc, found, nil
})

// deniedCountries may not sign in. The check runs before the credentials are
// read, so the refusal is the same whether the password was right.
var deniedCountries = []string{countryRussia}

// geoOptions turns on both checks: the country rule, and impossible travel
// at the defaults (900 km/h, hops under 100 km ignored), both blocking with
// 403. auth.RateLog would only record, auth.RateChallenge would ask the app's
// RateChallenger.
//
//ds:def id=georules-example-options-3vw9qk5n
func geoOptions() []auth.Option {
	return []auth.Option{
		auth.WithGeoLocator(locator),
		auth.WithGeoRules(auth.GeoRules{Deny: deniedCountries}),
		auth.WithImpossibleTravel(auth.ImpossibleTravelRule{}),
	}
}

// plugins is the app's plugin list.
func plugins() []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
	}
}

// trustedProxies is the reverse proxy in front of the app, on this machine.
// Only its X-Forwarded-For is believed; a client that writes the header
// itself from anywhere else keeps its connection address.
var trustedProxies = []string{"127.0.0.1", "::1"}

// newHandler mounts the library's routes behind the trusted proxy.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.TrustedProxies(trustedProxies...)))
	return mux
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
