// Command audit-history keeps a security log and shows each user their own
// history: every sign-in and failed sign-in, every sign-up, and an event of
// the app's own (a data export) typed with a name of the app's choosing. It
// also shows the log kept somewhere other than the database: a sink that
// implements Querier serves the same reads.
//
//	go run ./audit-history            # events in the audit_event table
//	go run ./audit-history -memory    # events in the process, for the demo
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "audit-history.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
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
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs.
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
	memory := flag.Bool("memory", false, "keep events in the process instead of the audit_event table")
	flag.Parse()

	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var sink audit.Sink
	if *memory {
		sink = &memoryLog{}
	}
	x, err := newApp(db, logMailer{}, sink)
	if err != nil {
		log.Fatal(err)
	}
	defer x.auth.Close()
	if _, err := x.auth.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: x.handler(), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// TypeDataExportRequested is the event type the app gives its own export
// operation. Without audit.Types the event's type would be the operation id,
// exports.request, which works but leaks a route name into the log's
// vocabulary.
//
//ds:def id=typedataexportrequested-nnym6b47 owner=@khanakia stability=stable
const TypeDataExportRequested audit.EventType = "data_export_requested"

// app holds the library and the audit plugin, which the app's own pages
// query from Go.
type app struct {
	auth  *auth.Auth
	audit *audit.Plugin
}

// newApp wires email, passwords, the app's export operation and the audit
// log. A nil sink keeps events in the audit_event table; any other sink
// receives them instead, and the reads work only when it implements
// audit.Querier. The test builds the app with the same function.
//
//ds:def id=newapp-ufs2h6hj owner=@khanakia stability=stable
func newApp(db *sql.DB, m email.Mailer, sink audit.Sink) (*app, error) {
	opts := []audit.Option{
		audit.Types(map[auth.EndpointID]audit.EventType{EndpointExport: TypeDataExportRequested}),
	}
	if sink != nil {
		opts = append(opts, audit.To(sink))
	}
	x := &app{audit: audit.New(opts...)}
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			newExports(),
			x.audit,
		),
	)
	x.auth = a
	return x, err
}

// handler mounts the library's routes, which include GET
// /auth/audit/my-events, and the app's sign-in history page.
//
//ds:def id=app-handler-n22ts3ry owner=@khanakia stability=stable
func (x *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(x.auth, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /security/sign-ins", authhttp.Middleware(x.auth)(authhttp.RequireUser(http.HandlerFunc(x.signIns))))
	return mux
}

// signInsLimit is how many recent sign-ins the security page lists.
const signInsLimit = 10

// signIns lists the caller's recent sign-ins, every method alike. It reads
// the log from Go with audit.Plugin.Events, which has no authorization of its
// own: scoping the query to the caller is this handler's job.
//
//ds:def id=app-signins-rcgcu64r owner=@khanakia stability=stable
func (x *app) signIns(w http.ResponseWriter, r *http.Request) {
	page, err := x.audit.Events(r.Context(), audit.Query{
		UserID: authhttp.MustUser(r).ID,
		Type:   audit.TypeUserSignedIn,
		Limit:  signInsLimit,
	})
	if err != nil {
		authhttp.WriteErrorFor(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page) // a client that hung up cannot be told
}

// EndpointExport is the app's own operation: a signed-in user asks for a copy
// of their data. A Mutation, so the audit plugin records it with no wiring.
const EndpointExport auth.EndpointID = "exports.request"

// exportsPlugin is the smallest plugin that adds an operation: a name and the
// operation, served at /auth/exports/request.
type exportsPlugin struct {
	request *auth.Op[struct{}, auth.Done]
}

// newExports defines the export operation. A real app would queue the export
// job here.
//
//ds:def id=newexports-4zf2nbbp owner=@khanakia stability=stable
func newExports() *exportsPlugin {
	return &exportsPlugin{request: auth.Define(
		auth.OpInfo{ID: EndpointExport, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/request"},
		func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil },
	)}
}

// Name is the plugin's identity and its route prefix.
func (*exportsPlugin) Name() string { return "exports" }

// Operations lists the export operation.
func (p *exportsPlugin) Operations() []auth.Operation { return []auth.Operation{p.request} }

// memoryLog keeps events in the process. It implements audit.Sink and
// audit.Querier, so every read (Events, my-events, the admin route) works from
// it. It shows the shape of a sink for a log service or a SIEM; it is not one,
// since a restart loses every event.
//
//ds:def id=memorylog-bgn48ztm owner=@khanakia stability=stable
type memoryLog struct {
	mu     sync.Mutex
	events []audit.Event
}

// Record keeps e. For a success it runs inside the operation's transaction,
// so an error here would refuse the sign-in rather than grant one unrecorded.
func (l *memoryLog) Record(_ context.Context, e audit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	return nil
}

// Events answers q newest first. Page and Limit arrive resolved (Page at
// least 1, Limit at most audit.MaxPageSize); Type matches the type Record
// was given, so storing the event is enough.
//
//ds:def id=memorylog-events-j2fm697q owner=@khanakia stability=stable
func (l *memoryLog) Events(_ context.Context, q audit.Query) (audit.Page, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var hits []audit.Event
	for _, e := range slices.Backward(l.events) {
		if matches(e, q) {
			hits = append(hits, e)
		}
	}
	from := min((q.Page-1)*q.Limit, len(hits))
	to := min(from+q.Limit, len(hits))
	return audit.Page{Events: hits[from:to], Total: int64(len(hits)), Page: q.Page, Limit: q.Limit}, nil
}

// matches applies Query's rules: UserID is the actor or the subject, and every
// other field set must be equal.
func matches(e audit.Event, q audit.Query) bool {
	return (q.UserID == "" || e.ActorID == q.UserID || e.SubjectID == q.UserID) &&
		(q.Identifier == "" || e.Identifier == q.Identifier) &&
		(q.Op == "" || e.Op == q.Op) &&
		(q.OrgID == "" || e.OrgID == q.OrgID) &&
		(q.Type == "" || e.Type == q.Type) &&
		(q.Severity == "" || e.Severity == q.Severity) &&
		(q.MinSeverity == "" || severityRank(e.Severity) >= severityRank(q.MinSeverity))
}

// severityRank orders severities lowest first, as auth.SecuritySeverityValues
// lists them.
func severityRank(s audit.Severity) int {
	return slices.Index(auth.SecuritySeverityValues, s)
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
