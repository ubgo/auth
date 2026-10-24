// Command agent-auth lets AI agents act for this app's users under
// capabilities the users grant them. The app is the provider: it publishes
// a catalogue of capabilities, users register the program their agents run
// in (a host) and approve what each agent may do, and every call names the
// agent that made it.
//
//	go run ./agent-auth
//
// The agent side is the agentclient package; agentConnect and agentPay show
// it, and main_test.go runs a whole agent against this server. Mail is
// printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/agentauth/agentclient"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "agent-auth.db"
	// authPrefix is where the library's routes are mounted, agentauth's user
	// operations (create-host, approve-capability, …) among them.
	authPrefix = "/auth"
	// capListInvoices reads the user's invoices. Hosts get it without asking.
	capListInvoices = "list_invoices"
	// capPayInvoice pays one. Every agent must ask for it, and must say how
	// much it may pay at most.
	capPayInvoice = "pay_invoice"
	// argInvoiceID and argAmount are pay_invoice's arguments.
	argInvoiceID = "invoice_id"
	argAmount    = "amount"
	// agentName is what the example agent calls itself on approval pages.
	agentName = "Bookkeeping assistant"
	// hostName is what the example host calls itself.
	hostName = "Laptop CLI"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL and the agent provider's issuer: every
	// agent and host token names it as its audience.
	baseURL = "http://localhost:" + port
)

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

	ag := newAgentAuth(newLedger())
	a, err := newAuth(db, logMailer{}, ag)
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, ag), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAgentAuth builds the agent provider: the catalogue of capabilities and
// the function that runs one. pay_invoice lists amount in
// RequiredConstraints, so an agent cannot ask to pay without a limit the
// user sees and approves.
//
//ds:def id=newagentauth-agentauth-example
func newAgentAuth(l *ledger) *agentauth.Plugin {
	return agentauth.New(
		agentauth.Capabilities(
			agentauth.Capability{Name: capListInvoices, Description: "List your unpaid invoices"},
			agentauth.Capability{Name: capPayInvoice, Description: "Pay one of your invoices", RequiredConstraints: []string{argAmount}},
		),
		agentauth.OnExecute(l.execute),
	)
}

// newAuth wires email and password sign-in, which users need to register
// hosts and approve agents, and the agent provider. The test builds the app
// with the same function.
//
//ds:def id=newauth-agentauth-example
func newAuth(db *sql.DB, m email.Mailer, ag *agentauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ag),
	)
}

// newHandler mounts the library's routes and the agent protocol. The
// protocol is served at the root, because agents discover it at
// /.well-known/agent-configuration on the app's own origin.
//
//ds:def id=newhandler-agentauth-example
func newHandler(a *auth.Auth, ag *agentauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+agentauth.DefaultDeviceAuthorizationPage, approvalPage)
	mux.Handle("/", ag.Handler())
	return mux
}

// approvalPageHTML is the page an agent's verification_uri opens. The user
// is signed in, types the code the agent showed, and approves or denies;
// approve-capability needs a fresh sign-in.
//
//ds:def id=approvalpagehtml-agentauth-example
const approvalPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Approve an agent</title>
<form id="f"><input name="user_code" placeholder="Code"> <button value="approve">Approve</button> <button value="deny">Deny</button></form>
<pre id="out"></pre>
<script>
const q = new URLSearchParams(location.search);
document.querySelector("[name=user_code]").value = q.get("user_code") || "";
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const res = await fetch("` + authPrefix + `/agentauth/approve-capability", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({agent_id: q.get("agent_id"), user_code: e.target.user_code.value, action: e.submitter.value}),
  });
  document.getElementById("out").textContent = JSON.stringify(await res.json(), null, 2);
};
</script>
`

// approvalPage serves approvalPageHTML.
func approvalPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(approvalPageHTML)) // a client that hung up cannot be told
}

// invoice is one of a user's invoices.
type invoice struct {
	ID     string  `json:"id"`
	Amount float64 `json:"amount"`
	Paid   bool    `json:"paid"`
}

// payment is what pay_invoice answers.
type payment struct {
	InvoiceID string  `json:"invoice_id"`
	Amount    float64 `json:"amount"`
	PaidBy    string  `json:"paid_by"`
}

// errUnknownInvoice answers a payment for an invoice the user does not have.
var errUnknownInvoice = auth.NewError("example.unknown_invoice", http.StatusNotFound, "No such invoice.")

// errBadArguments answers a pay_invoice call whose invoice_id is not a string
// or whose amount is not a number.
var errBadArguments = auth.NewError("example.bad_arguments", http.StatusBadRequest, "invoice_id must be a string and amount a number.")

// ledger stands in for the app's billing: every user starts with the same
// invoices. A real app reads its own tables here.
type ledger struct {
	mu   sync.Mutex
	paid map[string]bool // keyed by user id + "/" + invoice id
}

// seedInvoices are every user's invoices: id and amount.
var seedInvoices = []invoice{{ID: "inv_1", Amount: 40}, {ID: "inv_2", Amount: 900}}

// newLedger is an empty ledger: nothing paid yet.
func newLedger() *ledger { return &ledger{paid: map[string]bool{}} }

// execute is the OnExecute function. It runs only after the plugin has
// checked the agent's token, the agent's status, an active grant for the
// capability and the grant's constraints against the arguments, so it
// only does the work, for ex.Session.User. Its result reaches the agent as
// {"data": ...}. The any in the signature is agentauth.ExecuteFunc's.
//
//ds:def id=ledger-execute-agentauth-example
func (l *ledger) execute(_ context.Context, ex agentauth.Execution) (any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	user := ex.Session.User.ID
	switch ex.Capability.Name {
	case capListInvoices:
		out := make([]invoice, 0, len(seedInvoices))
		for _, inv := range seedInvoices {
			inv.Paid = l.paid[user+"/"+inv.ID]
			out = append(out, inv)
		}
		return out, nil
	case capPayInvoice:
		// Arguments are decoded JSON, so a number arrives as float64. A missing
		// or mistyped argument is refused, never read as "" or 0.
		id, okID := ex.Arguments[argInvoiceID].(string)
		amount, okAmount := ex.Arguments[argAmount].(float64)
		if !okID || !okAmount {
			return nil, errBadArguments
		}
		for _, inv := range seedInvoices {
			if inv.ID == id && inv.Amount == amount {
				l.paid[user+"/"+id] = true
				return payment{InvoiceID: id, Amount: amount, PaidBy: ex.Session.Agent.ID}, nil
			}
		}
		return nil, errUnknownInvoice
	}
	return nil, errors.New("unreachable: the plugin refuses capabilities outside the catalogue")
}

// agentConnect is the agent side: a host with its own key discovers the
// provider and registers a new agent asking for list_invoices. The host's
// budget grants it at once, so the agent comes back active. The host key is
// what a user registered with create-host; keep its private half with your
// secrets.
//
//ds:def id=agentconnect-agentauth-example
func agentConnect(ctx context.Context, c *agentclient.Client, providerURL string) (agentclient.Agent, agentauth.RegisterResult, error) {
	p, err := c.Discover(ctx, providerURL)
	if err != nil {
		return agentclient.Agent{}, agentauth.RegisterResult{}, err
	}
	return c.Connect(ctx, p, agentclient.ConnectRequest{
		Name:         agentName,
		Capabilities: []agentauth.CapabilityRequest{{Name: capListInvoices}},
	})
}

// agentAskToPay asks for pay_invoice, limited to payments of at most limit.
// The answer carries an approval: a user_code and a verification_uri the
// agent shows its user.
//
//ds:def id=agentasktopay-agentauth-example
func agentAskToPay(ctx context.Context, c *agentclient.Client, a agentclient.Agent, limit float64) (agentauth.RequestCapabilityResult, error) {
	caps := []agentauth.CapabilityRequest{{
		Name:        capPayInvoice,
		Constraints: agentauth.Constraints{argAmount: {Max: &limit}},
	}}
	return c.RequestCapability(ctx, a, caps, "pay small invoices for you", agentauth.ApprovalHints{})
}

// agentPay pays one invoice. Every call is signed with a fresh agent token
// bound to this request. The map[string]any is agentclient.Execute's
// argument type: capability arguments are free-form JSON.
//
//ds:def id=agentpay-agentauth-example
func agentPay(ctx context.Context, c *agentclient.Client, a agentclient.Agent, inv invoice) (string, error) {
	out, err := c.Execute(ctx, a, capPayInvoice, "", map[string]any{argInvoiceID: inv.ID, argAmount: inv.Amount})
	return string(out), err
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
