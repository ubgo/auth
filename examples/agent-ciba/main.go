// Command agent-ciba approves AI agents without a code: the agent's request
// goes straight to the user who owns its host (CIBA, client-initiated
// backchannel authentication), the app notifies that user, and the user
// answers from an inbox. A capability that moves money also needs a
// passkey, so an agent driving the user's browser cannot approve itself.
//
//	go run ./agent-ciba
//
// The agent side is the agentclient package; agentConnect shows it, and
// main_test.go runs a whole agent and a software passkey against this
// server. Notifications and mail are printed to the log instead of sent.
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
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "agent-ciba.db"
	// authPrefix is where the library's routes are mounted, agentauth's user
	// operations (pending-approvals, approve-capability, …) among them.
	authPrefix = "/auth"
	// inboxPath is the page where a user answers the agents' requests.
	inboxPath = "/approvals"
	// appName is the relying party's name the passkey prompt shows.
	appName = "Agent bank"
	// capReadBalance reads the user's balance; a click approves it.
	capReadBalance = "read_balance"
	// capTransfer moves money: approving it needs a passkey, and every
	// agent must say how much it may move at most.
	capTransfer = "transfer_money"
	// argAmount is transfer_money's argument and its required constraint.
	argAmount = "amount"
	// agentName is what the example agent calls itself in the inbox.
	agentName = "Budget assistant"
	// startingBalance is every user's balance before any transfer.
	startingBalance = 1000.0
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL, the agent provider's issuer, and the
	// passkeys' origin (relying party id "localhost").
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

	pk := passkey.New(passkey.DisplayName(appName))
	ag := newAgentAuth(pk, logNotifier, newBank())
	a, err := newAuth(db, logMailer{}, pk, ag)
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

// notifyFunc tells a user that an agent waits for their answer: a push, an
// email, a chat message. approvalID is what the inbox approves.
type notifyFunc func(ctx context.Context, userID, approvalID, message string)

// logNotifier prints the notification. Replace it with your push service.
func logNotifier(_ context.Context, userID, approvalID, message string) {
	log.Printf("notify user=%s approval=%s: %q", userID, approvalID, message)
}

// newAgentAuth builds the agent provider. transfer_money has
// StrengthWebAuthn, so approving it needs a passkey assertion through
// ProofOfPresence(pk) on top of the signed-in session; pk is the passkey
// plugin the app already has.
//
//ds:def id=newagentauth-agentciba-example
func newAgentAuth(pk *passkey.Plugin, notify notifyFunc, b *bank) *agentauth.Plugin {
	return agentauth.New(
		agentauth.Capabilities(
			agentauth.Capability{Name: capReadBalance, Description: "Read your balance"},
			agentauth.Capability{
				Name: capTransfer, Description: "Transfer money", RequiredConstraints: []string{argAmount},
				ApprovalStrength: agentauth.StrengthWebAuthn,
			},
		),
		agentauth.ProofOfPresence(pk),
		agentauth.OnEvent(cibaNotifier(notify)),
		agentauth.OnExecute(b.execute),
	)
}

// cibaNotifier turns approval events into notifications. A CIBA request
// shows no code anywhere: it reaches its user only because the app tells
// them, so this is where the notification is sent. The event runs after the
// commit, in the background, so a slow push never delays the agent.
//
//ds:def id=cibanotifier-agentciba-example
func cibaNotifier(notify notifyFunc) agentauth.EventFunc {
	return func(ctx context.Context, e agentauth.Event) {
		if e.Type == agentauth.EventApprovalCreated && e.Method == agentauth.MethodCIBA && e.UserID != nil {
			notify(ctx, *e.UserID, e.ApprovalID, e.BindingMessage)
		}
	}
}

// newAuth wires email and password sign-in, passkeys (for proof of
// presence), and the agent provider. The test builds the app with the same
// function.
func newAuth(db *sql.DB, m email.Mailer, pk *passkey.Plugin, ag *agentauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), pk, ag),
	)
}

// newHandler mounts the library's routes, the inbox page, and the agent
// protocol at the root, where agents discover it.
func newHandler(a *auth.Auth, ag *agentauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+inboxPath, inboxPage)
	mux.Handle("/", ag.Handler())
	return mux
}

// inboxPageHTML lists the signed-in user's pending requests and answers
// one by its approval_id. When the answer is webauthn_required, it runs the
// passkey ceremony with the options it got and posts the same approval
// again with the assertion.
//
//ds:def id=inboxpagehtml-agentciba-example
const inboxPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Agent requests</title>
<ul id="list"></ul>
<pre id="out"></pre>
<script>
const api = (path, init) => fetch("` + authPrefix + `/agentauth/" + path, init).then(r => r.json());
const approve = (body) => api("approve-capability", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
const answer = async (id) => {
  let res = await approve({approval_id: id, action: "approve"});
  if (res.status === "webauthn_required") {
    const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(res.webauthn.webauthn_options.publicKey)});
    res = await approve({approval_id: id, action: "approve", webauthn_response: {ceremony: res.webauthn.ceremony, credential: cred.toJSON()}});
  }
  document.getElementById("out").textContent = JSON.stringify(res, null, 2);
};
api("pending-approvals").then(({requests}) => requests.forEach((r) => {
  const li = document.createElement("li");
  li.textContent = (r.agent_name || r.agent_id) + " asks for " + r.capabilities.join(", ") + ": " + (r.binding_message || "") + " ";
  const b = document.createElement("button");
  b.textContent = "Approve";
  b.onclick = () => answer(r.approval_id);
  li.append(b);
  document.getElementById("list").append(li);
}));
</script>
`

// inboxPage serves inboxPageHTML.
func inboxPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(inboxPageHTML)) // a client that hung up cannot be told
}

// agentConnect is the agent side: a host the user registered connects a
// new agent asking for read_balance, and asks for CIBA, so no code is
// shown; the binding message tells the user which request this is.
//
//ds:def id=agentconnect-agentciba-example
func agentConnect(ctx context.Context, c *agentclient.Client, providerURL, message string) (agentclient.Agent, agentauth.RegisterResult, error) {
	p, err := c.Discover(ctx, providerURL)
	if err != nil {
		return agentclient.Agent{}, agentauth.RegisterResult{}, err
	}
	return c.Connect(ctx, p, agentclient.ConnectRequest{
		Name:          agentName,
		Capabilities:  []agentauth.CapabilityRequest{{Name: capReadBalance}},
		ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA, BindingMessage: message},
	})
}

// errBadAmount answers a transfer whose amount is not a positive number.
var errBadAmount = auth.NewError("example.bad_amount", http.StatusBadRequest, "amount must be a positive number.")

// errInsufficientFunds answers a transfer above the balance.
var errInsufficientFunds = auth.NewError("example.insufficient_funds", http.StatusConflict, "Not enough money.")

// balance is what read_balance and transfer_money answer.
type balance struct {
	Balance float64 `json:"balance"`
}

// bank stands in for the app's accounts: every user starts with
// startingBalance.
type bank struct {
	mu    sync.Mutex
	spent map[string]float64 // by user id
}

// newBank is a bank where nobody has spent anything.
func newBank() *bank { return &bank{spent: map[string]float64{}} }

// execute is the OnExecute function. The plugin has already checked the
// agent, its grant and the grant's constraints (the amount limit the user
// approved), so it only does the work. The any in the signature is
// agentauth.ExecuteFunc's.
func (b *bank) execute(_ context.Context, ex agentauth.Execution) (any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	user := ex.Session.User.ID
	switch ex.Capability.Name {
	case capReadBalance:
		return balance{Balance: startingBalance - b.spent[user]}, nil
	case capTransfer:
		amount, ok := ex.Arguments[argAmount].(float64) // decoded JSON numbers are float64
		if !ok || amount <= 0 {
			return nil, errBadAmount
		}
		if b.spent[user]+amount > startingBalance {
			return nil, errInsufficientFunds
		}
		b.spent[user] += amount
		return balance{Balance: startingBalance - b.spent[user]}, nil
	}
	return nil, errors.New("unreachable: the plugin refuses capabilities outside the catalogue")
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
