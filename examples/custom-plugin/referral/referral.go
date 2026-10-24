// Package referral is a plugin written outside the library, to show the plugin
// contract from the outside: it adds a column to auth_user, fills it in a data
// hook when a user is created, and serves one operation that reads it.
//
// It uses only exported API, so anything it does, a plugin in your own repo
// can do too.
package referral

import (
	"context"
	"crypto/rand"
	"encoding/base32"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Names the plugin registers. PluginName is the route prefix and the owner of
// the column's migration, so renaming it orphans that migration.
const (
	PluginName                   = "referral"
	ColCode                      = "referral_code"
	EndpointCode auth.EndpointID = "referral.code"
	// codeBytes is 5 random bytes: 8 characters of base32, 40 bits, plenty
	// for a code that is unique-indexed and only shared on purpose.
	codeBytes = 5
)

// Code is the column this plugin adds to auth_user. Nullable, so a pointer:
// users created before the plugin was added have none.
//
//ds:def id=code-zcb8fwrm
var Code = sqlb.Col[*string](auth.TableUser, ColCode)

// ReferralColumns is this plugin's part of the app's composite user. Embed it:
// the column is on auth_user, so the field is flat.
//
//ds:def id=referralcolumns-aefg6jvc
type ReferralColumns struct {
	ReferralCode *string
}

// Bindings binds ReferralColumns for a query on auth_user.
//
//ds:def id=bindings-rjc6nqd2
func Bindings(c *ReferralColumns) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(Code, &c.ReferralCode)}
}

// CodeResult is the output of the code operation, on every transport.
type CodeResult struct {
	Code string `json:"code"`
}

// Plugin is the referral plugin. Build it with New.
type Plugin struct {
	a    *auth.Auth
	code *auth.Op[struct{}, CodeResult]
}

// The optional interfaces this plugin implements, checked by the compiler so a
// typo in a method signature fails the build instead of silently dropping a
// capability.
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
)

// New builds the plugin and declares its one operation.
func New() *Plugin {
	p := &Plugin{}
	p.code = auth.Define(auth.OpInfo{ID: EndpointCode, Kind: auth.Query, Require: auth.SignedIn, Path: "/code"}, p.doCode)
	return p
}

// Name is the only method every plugin must have.
func (p *Plugin) Name() string { return PluginName }

// Init keeps the core handle for the hook and the operation.
func (p *Plugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}

// Columns adds referral_code to auth_user. The core writes its migration for
// each engine; the plugin writes none.
//
//ds:def id=plugin-columns-2szmrbsf
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColCode, Type: auth.ColumnText, Nullable: true, Unique: true}}
}

// DataHooks gives every new user a code, inside the transaction that creates
// the user, so a user never exists without one.
//
//ds:def id=plugin-datahooks-fejs8nh6
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
			code, err := newCode()
			if err != nil {
				return err
			}
			// ctx carries the sign-up's transaction. SetUserColumn is the one
			// sanctioned write to a core table, and it refuses a column this
			// plugin did not add.
			return auth.SetUserColumn(ctx, p.a, PluginName, u.ID, Code, &code)
		},
	}}
}

// Operations lists the operation for every transport: GET /auth/referral/code
// over HTTP, a field in GraphQL, and Plugin.Code from Go.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.code} }

// Code returns the signed-in user's code, through the same pipeline as the
// HTTP route.
func (p *Plugin) Code(ctx context.Context) (CodeResult, error) {
	return p.code.Call(ctx, struct{}{})
}

//ds:def id=plugin-docode-854s72jz
func (p *Plugin) doCode(ctx context.Context, c *auth.Call, _ struct{}) (CodeResult, error) {
	var cols ReferralColumns
	if err := p.a.LoadUserColumns(ctx, c.User.ID, Bindings(&cols)...); err != nil {
		return CodeResult{}, err
	}
	if cols.ReferralCode == nil {
		return CodeResult{}, nil // a user from before the plugin was added
	}
	return CodeResult{Code: *cols.ReferralCode}, nil
}

// codeEncoding is base32 without padding: uppercase letters and digits, easy
// to read aloud and to type.
var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newCode() (string, error) {
	b := make([]byte, codeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return codeEncoding.EncodeToString(b), nil
}
