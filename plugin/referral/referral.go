// Ported from @marinedotsh/better-auth-referral by marinedotsh
// (https://github.com/marinedotsh/better-auth-referral), MIT; see NOTICE.

// Package referral is user-to-user referrals as a Go plugin: every user has a
// referral code; a sign-up that brings one records who referred whom; a
// referral completes once every required step is recorded (sign-up always,
// then the app's own steps such as a first purchase); and the referrer reads
// a dashboard and the list of the people they referred.
//
// It is a separate module because referrals are not authentication (the
// module rule, 2026-10-02): an app without them never compiles it.
//
// The code reaches the sign-up the way an invite does: the ReferralHeader
// header, or the referral cookie remember sets for a visitor who signs up
// through an OAuth provider later. A data hook on user creation records the
// referral inside the sign-up's transaction, and a code that names nobody
// refuses the sign-up. Steps are recorded from Go
// only (MarkStep), never by a client, because a step is the app's statement
// that a reward was earned.
package referral

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and route prefix.
const PluginName = "referral"

// Operation ids, stable wire names.
const (
	EndpointDashboard auth.EndpointID = "referral.dashboard"
	EndpointList      auth.EndpointID = "referral.list"
	EndpointRemember  auth.EndpointID = "referral.remember"
)

// ReferralHeader carries a referral code on a sign-up request.
// ds:def id=referralheader-dmcrtk6w owner=@khanakia stability=stable
const ReferralHeader = "Referral-Code"

// CookieName is the plugin cookie remember sets.
const CookieName = "referral"

// StepSignUp is the step every referral records at sign-up; it is reserved.
const StepSignUp = "sign_up"

// Code shape and limits.
const (
	// CodeLength is a code's length: eight upper-case letters and digits,
	// unique-indexed and shared on purpose, so not a secret. The default
	// codes use base32's letters and digits 2-7 (40 bits); GenerateCode may
	// use any of A-Z and 0-9.
	CodeLength = 8
	// DefaultCookieTTL is how long remember keeps a code: long enough for
	// an OAuth round trip and a sign-up form.
	DefaultCookieTTL = time.Hour
	// MaxListLimit bounds one page of list.
	MaxListLimit = 100
	// MaxMetadataLength bounds a step's metadata once encoded.
	MaxMetadataLength = 4096
	defaultListLimit  = 20
	// codeAttempts draws before giving up on a free code; 41 bits do not
	// collide in practice.
	codeAttempts = 10
	// rememberLimit remember calls per IP per rememberWindow.
	rememberLimit  = 30
	rememberWindow = time.Minute
)

// codePattern is what a code looks like after normalizing.
var codePattern = regexp.MustCompile(`^[A-Z0-9]{8}$`)

// Status is a referral's state.
type Status string

// The states.
const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
)

// The tables. No foreign keys (ADR-0002).
const (
	TableNameCode      = "auth_referral_code"
	TableAliasCode     = "rfc"
	TableNameReferral  = "auth_referral"
	TableAliasReferral = "rfr"
	TableNameStep      = "auth_referral_step"
	TableAliasStep     = "rfs"

	ColCodeUserID    = "user_id"
	ColCode          = "code"
	ColCodeCreatedAt = "created_at"

	ColID          = "id"
	ColReferrer    = "referrer_user_id"
	ColReferred    = "referred_user_id"
	ColUsedCode    = "code"
	ColStatus      = "status"
	ColCompletedAt = "completed_at"
	ColCreatedAt   = "created_at"

	ColStepReferral = "referral_id"
	ColStep         = "step"
	ColStepMeta     = "metadata"
	ColStepAt       = "completed_at"

	migrationName = "0001_referral"
	idPrefix      = "rfl"
)

// The tables and their typed columns, for an app that reads them.
var (
	TableCode     = sqlb.Table{Name: TableNameCode, Alias: TableAliasCode}
	TableReferral = sqlb.Table{Name: TableNameReferral, Alias: TableAliasReferral}
	TableStep     = sqlb.Table{Name: TableNameStep, Alias: TableAliasStep}

	CodeUserID    = sqlb.Col[string](TableCode, ColCodeUserID)
	CodeValue     = sqlb.Col[string](TableCode, ColCode)
	CodeCreatedAt = sqlb.Col[time.Time](TableCode, ColCodeCreatedAt)

	ReferralID          = sqlb.Col[string](TableReferral, ColID)
	ReferralReferrer    = sqlb.Col[string](TableReferral, ColReferrer)
	ReferralReferred    = sqlb.Col[string](TableReferral, ColReferred)
	ReferralCode        = sqlb.Col[string](TableReferral, ColUsedCode)
	ReferralStatus      = sqlb.Col[Status](TableReferral, ColStatus)
	ReferralCompletedAt = sqlb.Col[*time.Time](TableReferral, ColCompletedAt)
	ReferralCreatedAt   = sqlb.Col[time.Time](TableReferral, ColCreatedAt)

	StepReferralID = sqlb.Col[string](TableStep, ColStepReferral)
	StepName       = sqlb.Col[string](TableStep, ColStep)
	StepMetadata   = sqlb.Col[string](TableStep, ColStepMeta)
	StepAt         = sqlb.Col[time.Time](TableStep, ColStepAt)
)

// Errors.
var (
	ErrInvalidCode = auth.NewError("referral.invalid_code", http.StatusBadRequest, "This referral code is not valid.")
	ErrUnknownStep = auth.NewError("referral.unknown_step", http.StatusBadRequest, "This referral step is not configured.")
	ErrNotFound    = auth.NewError("referral.not_found", http.StatusNotFound, "This user was not referred.")

	ErrBadSteps = errors.New("referral: steps must be unique, trimmed, non-empty, and not \"sign_up\"")
	// ErrNoCode fails the write that needed a code when codeAttempts draws
	// gave no free code of the right shape: with the default generator that
	// does not happen, with GenerateCode it means the generator repeats.
	ErrNoCode = errors.New("referral: no free code after several draws")
)

// User is the user side of an event.
type User struct {
	ID   string
	Name string
}

// Event is what the callbacks receive. Step is set for AfterStep.
type Event struct {
	ReferralID string
	Referrer   User
	Referred   User
	Step       string
	Progress   Progress
}

// Plugin is the referral plugin. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs        auth.OptionErrors
	steps          []string
	showEmails     bool
	cookieTTL      time.Duration
	gen            func() string
	afterSignUp    func(ctx context.Context, e Event)
	afterStep      func(ctx context.Context, e Event)
	afterCompleted func(ctx context.Context, e Event)
	core           *auth.Auth

	dashboard *auth.Op[struct{}, Dashboard]
	list      *auth.Op[ListRequest, ListResult]
	remember  *auth.Op[CodeRequest, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin.
type Option func(*Plugin)

// Steps are the app's steps a referral needs after sign-up to complete, such
// as "email_verified" and "first_purchase", recorded with MarkStep.
func Steps(steps ...string) Option { return func(p *Plugin) { p.steps = steps } }

// ShowEmails shows referred users' email addresses in list unmasked. By
// default they read "a***@example.com": the referrer did not need the
// address to refer them.
func ShowEmails() Option { return func(p *Plugin) { p.showEmails = true } }

// GenerateCode replaces the code generator, for vanity codes. Its output is
// normalized (NormalizeCode) and must be CodeLength letters and digits; a
// draw that is not, or that another user holds, is drawn again, and
// codeAttempts failed draws fail with ErrNoCode.
func GenerateCode(fn func() string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("referral.GenerateCode", fn) {
			return
		}
		p.gen = fn
	}
}

// AfterSignUp runs after a referred sign-up commits. It cannot fail the
// sign-up, which has already happened.
func AfterSignUp(fn func(ctx context.Context, e Event)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("referral.AfterSignUp", fn) {
			return
		}
		p.afterSignUp = fn
	}
}

// AfterStep runs after a newly recorded step commits; a repeated step does
// not run it again.
func AfterStep(fn func(ctx context.Context, e Event)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("referral.AfterStep", fn) {
			return
		}
		p.afterStep = fn
	}
}

// AfterCompleted runs once, after the step that completes a referral
// commits: the place to grant the reward.
func AfterCompleted(fn func(ctx context.Context, e Event)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("referral.AfterCompleted", fn) {
			return
		}
		p.afterCompleted = fn
	}
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{cookieTTL: DefaultCookieTTL, gen: newCode}
	for _, o := range opts {
		o(p)
	}
	p.dashboard = auth.Define(auth.OpInfo{ID: EndpointDashboard, Kind: auth.Query, Require: auth.SignedIn, Path: "/dashboard"}, p.doDashboard)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.remember = auth.Define(auth.OpInfo{ID: EndpointRemember, Kind: auth.Mutation, Require: auth.Public, Path: "/remember"}, p.doRemember)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Operations lists the three operations.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.dashboard, p.list, p.remember}
}

// RateLimits bounds remember, the one public operation.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointRemember, Key: auth.ByIP, Limit: rememberLimit, Window: rememberWindow}}
}

// Validate refuses a bad step list.
func (p *Plugin) Validate(*auth.Config) error { return checkSteps(p.steps) }

// checkSteps reports whether steps are unique, trimmed, non-empty and not
// the reserved sign-up step.
func checkSteps(steps []string) error {
	seen := map[string]bool{}
	for _, s := range steps {
		if s == "" || strings.TrimSpace(s) != s || s == StepSignUp || seen[s] {
			return ErrBadSteps
		}
		seen[s] = true
	}
	return nil
}

// Init captures the core.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Tables declares the three tables.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableCode, TableReferral, TableStep} }

// UserTables tells DeleteUser which rows are a user's: the code, and the
// referrals in which the user was referred or referred someone. Steps of a
// deleted referral stay until the app clears them; they name no user.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{
		{Table: TableCode, Column: ColCodeUserID},
		{Table: TableReferral, Column: ColReferrer},
		{Table: TableReferral, Column: ColReferred},
	}
}

// TypedMigrations creates the three tables. referred_user_id is unique: a user is
// referred once.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableCode) + " (" +
			ColCodeUserID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColCode + " " + t.Key + " NOT NULL UNIQUE, " +
			ColCodeCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableReferral) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColReferrer + " " + t.ID + " NOT NULL, " +
			ColReferred + " " + t.ID + " NOT NULL UNIQUE, " +
			ColUsedCode + " " + t.Key + " NOT NULL, " +
			ColStatus + " " + t.Key + " NOT NULL, " +
			ColCompletedAt + " " + t.Timestamp + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableStep) + " (" +
			ColStepReferral + " " + t.ID + " NOT NULL, " +
			ColStep + " " + t.Key + " NOT NULL, " +
			ColStepMeta + " " + t.Long + " NOT NULL, " +
			ColStepAt + " " + t.Timestamp + " NOT NULL, " +
			"PRIMARY KEY (" + ColStepReferral + ", " + ColStep + "))" + t.TableSuffix,
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationName, Statements: st}}, nil
}

// NormalizeCode upper-cases and trims a typed code.
func NormalizeCode(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

// requestCode is the code the request brings: the header's, else the
// cookie's.
func requestCode(ctx context.Context) string {
	if h := auth.RequestHeader(ctx, ReferralHeader); strings.TrimSpace(h) != "" {
		return NormalizeCode(h)
	}
	v, _ := auth.RequestCookie(ctx, CookieName)
	return NormalizeCode(v)
}

// DataHooks give every new user a code and, when the sign-up brings a
// referral code, record the referral and its sign-up step, in the sign-up's
// transaction.
// ds:def id=plugin-datahooks-h9da73gq owner=@khanakia stability=stable
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
		code := requestCode(ctx)
		var referrer string
		if code != "" {
			id, ok, err := p.owner(ctx, code)
			if err != nil {
				return err
			}
			if !ok {
				return ErrInvalidCode
			}
			referrer = id
		}
		if _, err := p.codeOf(ctx, u.ID); err != nil {
			return err
		}
		if referrer == "" {
			return nil
		}
		return p.refer(ctx, referrer, *u, code)
	}}}
}

// owner returns the user whose code is code.
func (p *Plugin) owner(ctx context.Context, code string) (string, bool, error) {
	if !codePattern.MatchString(code) {
		return "", false, nil
	}
	var id string
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(CodeUserID, &id)).From(TableCode).Where(sqlb.Eq(CodeValue, code)).Limit(1))
	if errors.Is(err, sqlb.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}

// codeOf returns userID's code, creating it on first use. A drawn code that
// is not eight letters and digits counts as a failed draw. A drawn code is
// checked before the insert because a failed insert aborts a Postgres
// transaction, so a unique violation cannot be caught and retried.
func (p *Plugin) codeOf(ctx context.Context, userID string) (string, error) {
	var code string
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(CodeValue, &code)).From(TableCode).Where(sqlb.Eq(CodeUserID, userID)).Limit(1))
	if err == nil {
		return code, nil
	}
	if !errors.Is(err, sqlb.ErrNoRows) {
		return "", err
	}
	for range codeAttempts {
		c := NormalizeCode(p.gen())
		if !codePattern.MatchString(c) {
			continue
		}
		if _, taken, err := p.owner(ctx, c); err != nil || taken {
			if err != nil {
				return "", err
			}
			continue
		}
		_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableCode).Row(
			sqlb.Set(CodeUserID, userID), sqlb.Set(CodeValue, c), sqlb.Set(CodeCreatedAt, p.core.Now())))
		if err != nil {
			return "", fmt.Errorf("referral: store code: %w", err)
		}
		return c, nil
	}
	return "", ErrNoCode
}

// newCode is CodeLength characters of rand.Text, which is base32 (A-Z and
// 2-7) and never fails: 40 random bits per code.
func newCode() string { return rand.Text()[:CodeLength] }

// refer records that referrer referred u, and the sign-up step. A code that
// is the user's own cannot happen here (the user has none before this hook),
// so no self-referral check is needed beyond the referred column's
// uniqueness.
func (p *Plugin) refer(ctx context.Context, referrer string, u auth.User, code string) error {
	id, err := p.core.NewID(idPrefix)
	if err != nil {
		return err
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableReferral).Row(
		sqlb.Set(ReferralID, id), sqlb.Set(ReferralReferrer, referrer), sqlb.Set(ReferralReferred, u.ID),
		sqlb.Set(ReferralCode, code), sqlb.Set(ReferralStatus, StatusPending), sqlb.Set(ReferralCompletedAt, nil),
		sqlb.Set(ReferralCreatedAt, p.core.Now())))
	if err != nil {
		return fmt.Errorf("referral: record referral: %w", err)
	}
	if p.afterSignUp != nil {
		ev := Event{ReferralID: id, Referrer: User{ID: referrer}, Referred: User{ID: u.ID, Name: u.Name}}
		p.core.AfterCommit(ctx, func(ctx context.Context) { p.afterSignUp(ctx, p.named(ctx, ev)) })
	}
	_, err = p.markStep(ctx, ref{id: id, referrer: referrer, referred: u.ID, status: StatusPending}, StepSignUp, nil)
	return err
}

// named fills the referrer's name in ev, after the commit; a failed read
// leaves it empty rather than dropping the event.
func (p *Plugin) named(ctx context.Context, ev Event) Event {
	if u, err := p.core.User(ctx, ev.Referrer.ID); err == nil {
		ev.Referrer.Name = u.Name
	}
	if ev.Referred.Name == "" {
		if u, err := p.core.User(ctx, ev.Referred.ID); err == nil {
			ev.Referred.Name = u.Name
		}
	}
	return ev
}

// Required is the full list of steps a referral needs: sign-up, then the
// configured ones.
func (p *Plugin) Required() []string { return append([]string{StepSignUp}, p.steps...) }

// Progress is how far a referral got.
type Progress struct {
	RequiredSteps  []string `json:"requiredSteps"`
	CompletedSteps []string `json:"completedSteps"`
	RemainingSteps []string `json:"remainingSteps"`
	Completed      int      `json:"completed"`
	Total          int      `json:"total"`
	IsCompleted    bool     `json:"isCompleted"`
}

// progress computes Progress from the steps recorded.
func (p *Plugin) progress(done []string) Progress {
	have := map[string]bool{}
	for _, s := range done {
		have[s] = true
	}
	out := Progress{RequiredSteps: p.Required(), CompletedSteps: []string{}, RemainingSteps: []string{}}
	for _, s := range out.RequiredSteps {
		if have[s] {
			out.CompletedSteps = append(out.CompletedSteps, s)
		} else {
			out.RemainingSteps = append(out.RemainingSteps, s)
		}
	}
	out.Completed, out.Total = len(out.CompletedSteps), len(out.RequiredSteps)
	out.IsCompleted = len(out.RemainingSteps) == 0
	return out
}

// ref is a referral as MarkStep reads it.
type ref struct {
	id, referrer, referred string
	status                 Status
}

// stepsOf returns the steps recorded for referral id.
func (p *Plugin) stepsOf(ctx context.Context, id string) ([]string, error) {
	var s string
	out := []string{}
	err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(StepName, &s)).From(TableStep).
		Where(sqlb.Eq(StepReferralID, id)).Order(sqlb.OrderBy(StepAt, sqlb.SortAsc), sqlb.OrderBy(StepName, sqlb.SortAsc)), func() error {
		out = append(out, s)
		return nil
	})
	return out, err
}

// StepResult is the answer of MarkStep.
type StepResult struct {
	// AlreadyCompleted is true when the step had been recorded before; the
	// call changed nothing and ran no callback.
	AlreadyCompleted bool
	Status           Status
	Progress         Progress
}

// MarkStep records that the user referredUserID reached step, with metadata
// for the app's records (an order id), and completes the referral when it was
// the last required step. It is Go only: a step is the app's statement that a
// reward was earned, never a client's. Recording a step twice is a no-op.
// ds:def id=plugin-markstep-sk2dyp6p owner=@khanakia stability=stable
func (p *Plugin) MarkStep(ctx context.Context, referredUserID, step string, metadata map[string]string) (StepResult, error) {
	if p.core == nil {
		return StepResult{}, auth.ErrOperationNotWired
	}
	known := false
	for _, s := range p.Required() {
		known = known || s == step
	}
	if !known {
		return StepResult{}, ErrUnknownStep
	}
	var out StepResult
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		var r ref
		err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(ReferralID, &r.id), sqlb.Bind(ReferralReferrer, &r.referrer),
			sqlb.Bind(ReferralReferred, &r.referred), sqlb.Bind(ReferralStatus, &r.status)).
			From(TableReferral).Where(sqlb.Eq(ReferralReferred, referredUserID)).Limit(1))
		if errors.Is(err, sqlb.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = p.markStep(ctx, r, step, metadata)
		return err
	})
	return out, err
}

// markStep records step for r unless it is there, and completes r when it
// was the last one. The completion is guarded on pending, so two steps
// racing to complete it run AfterCompleted once.
func (p *Plugin) markStep(ctx context.Context, r ref, step string, metadata map[string]string) (StepResult, error) {
	done, err := p.stepsOf(ctx, r.id)
	if err != nil {
		return StepResult{}, err
	}
	for _, s := range done {
		if s == step {
			return StepResult{AlreadyCompleted: true, Status: r.status, Progress: p.progress(done)}, nil
		}
	}
	meta := "{}"
	if len(metadata) > 0 {
		b, err := json.Marshal(metadata)
		if err != nil {
			return StepResult{}, err
		}
		if len(b) > MaxMetadataLength {
			return StepResult{}, auth.ErrBadRequest
		}
		meta = string(b)
	}
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableStep).Row(
		sqlb.Set(StepReferralID, r.id), sqlb.Set(StepName, step), sqlb.Set(StepMetadata, meta), sqlb.Set(StepAt, now))); err != nil {
		return StepResult{}, fmt.Errorf("referral: record step: %w", err)
	}
	done = append(done, step)
	prog := p.progress(done)
	out := StepResult{Status: r.status, Progress: prog}
	ev := Event{ReferralID: r.id, Referrer: User{ID: r.referrer}, Referred: User{ID: r.referred}, Step: step, Progress: prog}
	if p.afterStep != nil {
		p.core.AfterCommit(ctx, func(ctx context.Context) { p.afterStep(ctx, p.named(ctx, ev)) })
	}
	if !prog.IsCompleted || r.status == StatusCompleted {
		return out, nil
	}
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableReferral).
		Set(sqlb.Set(ReferralStatus, StatusCompleted), sqlb.Set(ReferralCompletedAt, &now)).
		Where(sqlb.Eq(ReferralID, r.id), sqlb.Eq(ReferralStatus, StatusPending)))
	if err != nil {
		return StepResult{}, err
	}
	if n == 1 {
		out.Status = StatusCompleted
		if p.afterCompleted != nil {
			p.core.AfterCommit(ctx, func(ctx context.Context) { p.afterCompleted(ctx, p.named(ctx, ev)) })
		}
	}
	return out, nil
}

// Stats counts the caller's referrals.
type Stats struct {
	Total       int64 `json:"total"`
	Completed   int64 `json:"completed"`
	Pending     int64 `json:"pending"`
	JoinedToday int64 `json:"joinedToday"`
}

// Dashboard is the caller's code and counts.
type Dashboard struct {
	Code  string `json:"code"`
	Stats Stats  `json:"stats"`
}

// MyDashboard returns the signed-in user's code and counts.
func (p *Plugin) MyDashboard(ctx context.Context) (Dashboard, error) {
	return p.dashboard.Call(ctx, struct{}{})
}

// count returns how many of the caller's referrals match where.
func (p *Plugin) count(ctx context.Context, where ...sqlb.Predicate) (int64, error) {
	var n int64
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableReferral).Where(where...))
	return n, err
}

// doDashboard creates the caller's code if missing (a user from before the
// plugin) and counts. "Today" is the UTC day of the auth clock.
func (p *Plugin) doDashboard(ctx context.Context, c *auth.Call, _ struct{}) (Dashboard, error) {
	code, err := p.codeOf(ctx, c.User.ID)
	if err != nil {
		return Dashboard{}, err
	}
	mine := sqlb.Eq(ReferralReferrer, c.User.ID)
	out := Dashboard{Code: code}
	if out.Stats.Total, err = p.count(ctx, mine); err != nil {
		return Dashboard{}, err
	}
	if out.Stats.Pending, err = p.count(ctx, mine, sqlb.Eq(ReferralStatus, StatusPending)); err != nil {
		return Dashboard{}, err
	}
	day := c.Auth.Now().UTC().Truncate(24 * time.Hour)
	if out.Stats.JoinedToday, err = p.count(ctx, mine, sqlb.GreaterEq(ReferralCreatedAt, day), sqlb.Less(ReferralCreatedAt, day.Add(24*time.Hour))); err != nil {
		return Dashboard{}, err
	}
	out.Stats.Completed = out.Stats.Total - out.Stats.Pending
	return out, nil
}

// ListRequest pages list, newest first.
type ListRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ReferredUser is the referred side of a row in list.
type ReferredUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Image string `json:"image,omitempty"`
}

// Referral is one row of list.
type Referral struct {
	ID           string       `json:"id"`
	Status       Status       `json:"status"`
	CompletedAt  *time.Time   `json:"completedAt"`
	CreatedAt    time.Time    `json:"createdAt"`
	Progress     Progress     `json:"progress"`
	ReferredUser ReferredUser `json:"referredUser"`
}

// ListResult is a page of list.
type ListResult struct {
	Code      string     `json:"code"`
	Referrals []Referral `json:"referrals"`
	Total     int64      `json:"total"`
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
}

// List returns a page of the signed-in user's referrals.
func (p *Plugin) List(ctx context.Context, in ListRequest) (ListResult, error) {
	return p.list.Call(ctx, in)
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, in ListRequest) (ListResult, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if in.Offset < 0 {
		return ListResult{}, auth.ErrBadRequest
	}
	limit = min(limit, MaxListLimit)
	code, err := p.codeOf(ctx, c.User.ID)
	if err != nil {
		return ListResult{}, err
	}
	mine := sqlb.Eq(ReferralReferrer, c.User.ID)
	out := ListResult{Code: code, Referrals: []Referral{}, Limit: limit, Offset: in.Offset}
	if out.Total, err = p.count(ctx, mine); err != nil {
		return ListResult{}, err
	}
	var r Referral
	q := c.Auth.Select().Columns(sqlb.Bind(ReferralID, &r.ID), sqlb.Bind(ReferralStatus, &r.Status),
		sqlb.Bind(ReferralCompletedAt, &r.CompletedAt), sqlb.Bind(ReferralCreatedAt, &r.CreatedAt), sqlb.Bind(ReferralReferred, &r.ReferredUser.ID)).
		From(TableReferral).Where(mine).
		Order(sqlb.OrderBy(ReferralCreatedAt, sqlb.SortDesc), sqlb.OrderBy(ReferralID, sqlb.SortDesc)).Limit(limit).Offset(in.Offset)
	if err := c.Auth.Each(ctx, q, func() error {
		out.Referrals = append(out.Referrals, r)
		return nil
	}); err != nil {
		return ListResult{}, err
	}
	for i := range out.Referrals {
		if err := p.fill(ctx, &out.Referrals[i]); err != nil {
			return ListResult{}, err
		}
	}
	return out, nil
}

// fill reads a row's steps and the referred user's profile and primary email.
func (p *Plugin) fill(ctx context.Context, r *Referral) error {
	done, err := p.stepsOf(ctx, r.ID)
	if err != nil {
		return err
	}
	r.Progress = p.progress(done)
	u, err := p.core.User(ctx, r.ReferredUser.ID)
	if err != nil {
		return err
	}
	r.ReferredUser.Name, r.ReferredUser.Image = u.Name, u.Image
	ids, err := p.core.Identities(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id.Kind == kindEmail && (r.ReferredUser.Email == "" || id.IsPrimary) {
			r.ReferredUser.Email = id.Value
		}
	}
	if !p.showEmails {
		r.ReferredUser.Email = MaskEmail(r.ReferredUser.Email)
	}
	return nil
}

// kindEmail is plugin/email's kind name; the referral module does not import
// that plugin for one constant.
const kindEmail auth.IdentifierKindName = "email"

// MaskEmail keeps the first character of the local part and the domain:
// "a***@example.com"; anything without both parts becomes "hidden", and ""
// stays "".
func MaskEmail(addr string) string {
	if addr == "" {
		return ""
	}
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || domain == "" {
		return "hidden"
	}
	return local[:1] + "***@" + domain
}

// CodeRequest carries a referral code.
type CodeRequest struct {
	Code string `json:"code"`
}

// Remember keeps a valid code in the referral cookie, for a visitor who will
// sign up through a provider, whose callback request carries no header.
func (p *Plugin) Remember(ctx context.Context, code string) error {
	_, err := p.remember.Call(ctx, CodeRequest{Code: code})
	return err
}

// doRemember refuses a code that names nobody, so the visitor learns at once
// rather than at sign-up.
func (p *Plugin) doRemember(ctx context.Context, c *auth.Call, in CodeRequest) (auth.Done, error) {
	code := NormalizeCode(in.Code)
	_, ok, err := p.owner(ctx, code)
	if err != nil {
		return auth.Done{}, err
	}
	if !ok {
		return auth.Done{}, ErrInvalidCode
	}
	if err := c.Effects.SetCookie(CookieName, code, c.Auth.Now().Add(p.cookieTTL)); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}
