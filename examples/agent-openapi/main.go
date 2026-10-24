// Command agent-openapi lets AI agents call an HTTP API the app already has,
// described by an OpenAPI document. Every operation in the document becomes
// an agent capability; executing one proxies the call to the API with the
// user's credentials, so the API itself needs no change.
//
//	go run ./agent-openapi
//
// The API here is a small invoices API the same program serves on a second
// port, standing in for an internal service that runs elsewhere. Mail is
// printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "agent-openapi.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// opListInvoices and opPayInvoice are the operationIds in openAPISpec,
	// and so the capability names agents ask for.
	opListInvoices = "list_invoices"
	opPayInvoice   = "pay_invoice"
	// headerActingUser is the header the proxy adds to every upstream call:
	// which user the agent acts for. A real app sends the user's own
	// credential for the API here instead.
	headerActingUser = "X-Acting-User"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL and the agent provider's issuer.
	baseURL = "http://localhost:" + port
	// apiPort is the invoices API's port: 8083, or $API_PORT. It listens
	// on this machine only; agents never reach it except through the proxy.
	apiPort = cmp.Or(os.Getenv("API_PORT"), "8083")
	// apiURL is the invoices API's base URL: each operation's path in the
	// document is appended to it.
	apiURL = "http://localhost:" + apiPort
)

// openAPISpec returns the invoices API's OpenAPI document. Each
// operationId becomes a capability, its description the capability's
// description, and its parameters the capability's input schema.
// info.title becomes the provider's name in the agent configuration.
//
//ds:def id=openapispec-agentopenapi-example
func openAPISpec() []byte {
	return []byte(`{
  "openapi": "3.1.0",
  "info": {"title": "Invoices", "description": "Read and pay your invoices"},
  "paths": {
    "/invoices": {
      "get": {"operationId": "list_invoices", "description": "List your invoices",
        "responses": {"200": {"description": "The invoices", "content": {"application/json": {"schema": {"type": "array"}}}}}}
    },
    "/invoices/{id}/pay": {
      "post": {"operationId": "pay_invoice", "description": "Pay one invoice",
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "The payment"}}}
    }
  }
}`)
}

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	go func() {
		log.Printf("invoices API listening on %s", apiURL)
		api := &http.Server{Addr: "localhost:" + apiPort, Handler: newInvoicesAPI(), ReadHeaderTimeout: readHeaderTimeout}
		log.Fatal(api.ListenAndServe())
	}()
	ag, err := newAgentAuth(apiURL, nil)
	if err != nil {
		log.Fatal(err) // the document is broken or the API URL is not absolute
	}
	a, err := newAuth(db, logMailer{}, ag)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, ag), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAgentAuth derives the whole agent provider from openAPISpec: the
// capabilities, the provider's name, and an OnExecute that proxies each
// call to base, the API's URL. Headers adds the acting user to every upstream call,
// after the arguments, so an agent can never replace it. Every GET
// operation goes into a new host's budget, so read-only calls need no
// approval. client sends the upstream calls; nil is http.DefaultClient.
//
//ds:def id=newagentauth-agentopenapi-example
func newAgentAuth(base string, client *http.Client) (*agentauth.Plugin, error) {
	opts, err := agentauth.FromOpenAPISpec(openAPISpec(), agentauth.OpenAPIOptions{
		OpenAPIHandlerOptions: agentauth.OpenAPIHandlerOptions{
			BaseURL: base,
			Client:  client,
			Headers: func(_ context.Context, _ string, s agentauth.AgentSession) (http.Header, error) {
				return http.Header{headerActingUser: {s.User.ID}}, nil
			},
		},
		HostCapabilities: agentauth.OperationsWithMethod(http.MethodGet),
	})
	if err != nil {
		return nil, err
	}
	return agentauth.New(opts...), nil
}

// newAuth wires email and password sign-in, which users need to register
// hosts and approve agents, and the agent provider.
func newAuth(db *sql.DB, m email.Mailer, ag *agentauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ag),
	)
}

// newHandler mounts the library's routes and the agent protocol, which is
// served at the root because agents discover it at
// /.well-known/agent-configuration on the app's own origin.
func newHandler(a *auth.Auth, ag *agentauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/", ag.Handler())
	return mux
}

// invoice is one of a user's invoices.
type invoice struct {
	ID     string `json:"id"`
	Amount int    `json:"amount"`
	Paid   bool   `json:"paid"`
}

// seedInvoices are every user's invoices.
var seedInvoices = []invoice{{ID: "inv_1", Amount: 40}, {ID: "inv_2", Amount: 900}}

// invoicesAPI is the API the document describes. It knows nothing about
// agents: it trusts headerActingUser, which only the proxy sets, because it
// listens where only this machine reaches it. Replace the header with the
// credential your API already checks.
type invoicesAPI struct {
	mu   sync.Mutex
	paid map[string]bool // keyed by user id + "/" + invoice id
}

// newInvoicesAPI is an API with nothing paid yet.
func newInvoicesAPI() *invoicesAPI { return &invoicesAPI{paid: map[string]bool{}} }

// ServeHTTP answers GET /invoices and POST /invoices/{id}/pay.
func (api *invoicesAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /invoices", api.list)
	mux.HandleFunc("POST /invoices/{id}/pay", api.pay)
	mux.ServeHTTP(w, r)
}

// list answers the acting user's invoices.
func (api *invoicesAPI) list(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get(headerActingUser)
	api.mu.Lock()
	out := make([]invoice, 0, len(seedInvoices))
	for _, inv := range seedInvoices {
		inv.Paid = api.paid[user+"/"+inv.ID]
		out = append(out, inv)
	}
	api.mu.Unlock()
	writeJSON(w, out)
}

// pay marks one of the acting user's invoices paid.
func (api *invoicesAPI) pay(w http.ResponseWriter, r *http.Request) {
	user, id := r.Header.Get(headerActingUser), r.PathValue("id")
	for _, inv := range seedInvoices {
		if inv.ID == id {
			api.mu.Lock()
			api.paid[user+"/"+id] = true
			api.mu.Unlock()
			inv.Paid = true
			writeJSON(w, inv)
			return
		}
	}
	http.Error(w, "no such invoice", http.StatusNotFound)
}

// writeJSON answers v as JSON.
func writeJSON[T []invoice | invoice](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
