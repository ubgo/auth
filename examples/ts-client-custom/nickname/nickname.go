// Package nickname is the app's own plugin, written outside the library: a
// nickname per user, stored in a column the plugin adds to auth_user, with
// one operation to set it and one to read it, and an error code of its own.
// The app's TypeScript client (`auth client ts`) types both operations and
// the code exactly, because it is generated from the app's operation list.
package nickname

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Names the plugin registers. PluginName is the route prefix, the client's
// namespace (client.nickname) and the owner of the column's migration, so
// renaming it orphans that migration and renames the client's methods.
const (
	PluginName                  = "nickname"
	ColNickname                 = "nickname"
	EndpointSet auth.EndpointID = "nickname.set"
	EndpointGet auth.EndpointID = "nickname.get"
	// MaxLength is the longest nickname, in characters: short enough for a
	// header bar.
	MaxLength = 32
)

// ErrTooLong is the plugin's own error code. Declared at package level with
// auth.NewError, so it is in auth.Errors() and therefore in the generated
// client's error-code union, where a frontend can switch on it.
//
//ds:def id=nickname-errtoolong-3vq8kd2m
var ErrTooLong = auth.NewError("nickname.too_long", http.StatusBadRequest, fmt.Sprintf("A nickname is at most %d characters.", MaxLength))

// Nickname is the column this plugin adds to auth_user. Nullable, so a
// pointer: a user who never set one has none.
var Nickname = sqlb.Col[*string](auth.TableUser, ColNickname)

// SetRequest is the input of nickname.set. The JSON tags are the wire
// names, and so the TypeScript field names.
//
//ds:def id=nickname-types-8mw2xq4t
type SetRequest struct {
	Nickname string `json:"nickname"`
}

// Result is the output of both operations. A nil pointer encodes as null,
// so the TypeScript type is `string | null`.
type Result struct {
	Nickname *string `json:"nickname"`
}

// Plugin is the nickname plugin. Build it with New.
type Plugin struct {
	a   *auth.Auth
	set *auth.Op[SetRequest, Result]
	get *auth.Op[struct{}, Result]
}

// The optional interfaces this plugin implements, checked by the compiler.
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
)

// New builds the plugin and declares its two operations: a mutation is a
// POST and a query a GET, on every transport, and in the client.
//
//ds:def id=nickname-new-5kz9wq3h
func New() *Plugin {
	p := &Plugin{}
	p.set = auth.Define(auth.OpInfo{ID: EndpointSet, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/set"}, p.doSet)
	p.get = auth.Define(auth.OpInfo{ID: EndpointGet, Kind: auth.Query, Require: auth.SignedIn, Path: "/get"}, p.doGet)
	return p
}

// Name is the only method every plugin must have.
func (p *Plugin) Name() string { return PluginName }

// Init keeps the core handle for the operations.
func (p *Plugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}

// Columns adds nickname to auth_user; the core writes its migration.
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColNickname, Type: auth.ColumnText, Nullable: true}}
}

// Operations lists both operations for every transport and for the
// TypeScript generator, which reads the same list.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.set, p.get} }

// doSet trims the nickname and stores it; an empty one clears it.
func (p *Plugin) doSet(ctx context.Context, c *auth.Call, in SetRequest) (Result, error) {
	name := strings.TrimSpace(in.Nickname)
	if utf8.RuneCountInString(name) > MaxLength {
		return Result{}, ErrTooLong
	}
	var v *string
	if name != "" {
		v = &name
	}
	if err := auth.SetUserColumn(ctx, p.a, PluginName, c.User.ID, Nickname, v); err != nil {
		return Result{}, err
	}
	return Result{Nickname: v}, nil
}

// doGet reads the signed-in user's nickname.
func (p *Plugin) doGet(ctx context.Context, c *auth.Call, _ struct{}) (Result, error) {
	var v *string
	if err := p.a.LoadUserColumns(ctx, c.User.ID, sqlb.Bind(Nickname, &v)); err != nil {
		return Result{}, err
	}
	return Result{Nickname: v}, nil
}
