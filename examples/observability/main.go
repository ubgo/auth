// Command observability shows the three ways the library reports what it
// does: an Observer that sees every call end (metrics, error counts), a
// Tracer that sees the structure inside a call (OpenTelemetry spans through
// contrib/otel), and a *slog.Logger for the failures nobody is waiting on
// (a mail that could not be delivered, an internal error behind a 500).
//
//	go run ./observability
//
// Everything is written to stderr as JSON lines: the observer's call records,
// the ended spans and the library's own log lines. Mail to an address at
// bounceDomain fails, so the delivery-failure log line can be seen.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	authotel "github.com/ubgo/auth/contrib/otel"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "observability.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// shutdownTimeout bounds how long the tracer provider may take to flush
	// its last spans when the program ends.
	shutdownTimeout = 5 * time.Second
	// bounceDomain is the mail domain logMailer refuses, standing in for a
	// provider that rejects a message, so the library's delivery-failure log
	// line has something to report.
	bounceDomain = "@bounce.example"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// errBounced is what logMailer returns for an address at bounceDomain.
var errBounced = errors.New("mail provider rejected the message")

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file. It
// escapes only the path, never building a url.URL with a scheme, because Go
// writes a relative path such as "auth.db" as "file://auth.db", which SQLite
// reads as a host.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("observability", "error", err)
		os.Exit(1)
	}
}

// run builds the app and serves it until the server fails.
func run(logger *slog.Logger) error {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		return err
	}
	defer db.Close()

	tp := newTracerProvider(logSpans{logger: logger})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = tp.Shutdown(ctx) // the program is ending; nothing is left to report a failure to
	}()

	a, err := newAuth(db, logMailer{logger: logger}, logger, tp, &callLog{logger: logger})
	if err != nil {
		return err // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		return err
	}

	logger.Info("listening", "url", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, logger), ReadHeaderTimeout: readHeaderTimeout}
	return srv.ListenAndServe()
}

// newAuth wires email and password sign-in plus the three reporting seams:
// WithObserver gets every call's outcome, WithTracer (through contrib/otel)
// gets a span per call, hook and statement, and WithLogger gets the core's
// warnings and background failures. The test builds the app with the same
// function and its own recorders.
//
//ds:def id=obs-newauth-z6v7v9tm
func newAuth(db *sql.DB, m email.Mailer, logger *slog.Logger, tp trace.TracerProvider, obs auth.Observer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithObserver(obs),
		auth.WithTracer(authotel.Tracer(tp)),
		auth.WithLogger(logger),
	)
}

// newHandler mounts the library's routes. authhttp has a logger of its own
// for the internal errors behind a 500, which defaults to slog.Default()
// rather than the core's: pass the same logger to both, or a 500's cause
// lands somewhere else.
//
//ds:def id=obs-newhandler-b6bkmd6m
func newHandler(a *auth.Auth, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.Logger(logger)))
	return mux
}

// callRecord is what callLog keeps of one finished call: which operation,
// which plugin served it, and its outcome, "ok" or the error code.
type callRecord struct {
	Op      auth.EndpointID
	Plugin  string
	Outcome string
}

// callLog is an auth.Observer that logs every finished call and keeps a
// record of it. A real app would add to a counter by Op and Outcome instead
// (contrib/otel's Observer does exactly that); the event never carries the
// call's input or output, so no password or token can reach a metrics sink.
//
//ds:def id=obs-observer-kngwsmc7
type callLog struct {
	logger *slog.Logger
	mu     sync.Mutex
	calls  []callRecord
}

// Operation records e. It runs on the request's goroutine before the answer
// is sent, so it only appends and logs.
//
//ds:def id=obs-observer-operation-m8pbc5rb
func (l *callLog) Operation(ctx context.Context, e auth.OperationEvent) {
	rec := callRecord{Op: e.Op.ID, Plugin: e.Plugin, Outcome: authotel.OutcomeOK}
	if e.Err != nil {
		rec.Outcome = auth.ErrorOf(e.Err).Code
	}
	l.mu.Lock()
	l.calls = append(l.calls, rec)
	l.mu.Unlock()
	l.logger.InfoContext(ctx, "auth call", "op", string(rec.Op), "plugin", rec.Plugin,
		"transport", string(e.Transport), "outcome", rec.Outcome, "duration", e.Duration.String())
}

// records returns a copy of every call seen so far.
func (l *callLog) records() []callRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]callRecord(nil), l.calls...)
}

// newTracerProvider is an OpenTelemetry SDK provider that hands every ended
// span to p. In production p is a batch processor around an OTLP exporter
// (sdktrace.NewBatchSpanProcessor(otlptracegrpc.New(…))); here it logs, and
// the test passes an in-memory recorder.
//
//ds:def id=obs-tracer-provider-8emg4nk3
func newTracerProvider(p sdktrace.SpanProcessor) *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(p))
}

// logSpans is a SpanProcessor that logs each span when it ends, so the trace
// of a call can be read without a collector.
type logSpans struct{ logger *slog.Logger }

// OnStart does nothing: a span is logged once, when it ends.
func (logSpans) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

// OnEnd logs the span's name, its status and how long it took.
//
//ds:def id=obs-logspans-onend-tue4jpss
func (s logSpans) OnEnd(sp sdktrace.ReadOnlySpan) {
	s.logger.Info("span", "name", sp.Name(), "status", sp.Status().Code.String(),
		"description", sp.Status().Description, "duration", sp.EndTime().Sub(sp.StartTime()).String())
}

// Shutdown has nothing to release.
func (logSpans) Shutdown(context.Context) error { return nil }

// ForceFlush has nothing buffered.
func (logSpans) ForceFlush(context.Context) error { return nil }

// logMailer logs mail instead of sending it, and refuses any address at
// bounceDomain the way a provider rejects a message. Replace it with SMTP,
// an email API or a queue.
type logMailer struct{ logger *slog.Logger }

// Send logs the message, or fails for bounceDomain. The library sends after
// the sign-up committed, so a failure here cannot fail the sign-up: it can
// only be logged, through WithLogger.
//
//ds:def id=obs-mailer-send-jvp5wbdc
func (m logMailer) Send(ctx context.Context, mail email.Mail) error {
	if strings.HasSuffix(mail.To, bounceDomain) {
		return errBounced
	}
	m.logger.InfoContext(ctx, "mail", "to", mail.To, "subject", mail.Subject)
	return nil
}
