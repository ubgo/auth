package twofactor

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Trusted devices: "remember this browser". After a verified second factor
// the client may ask to be trusted; the plugin then stores a random token's
// hash against the user and hands the token to the transport (EffectRememberDevice),
// which keeps it in a cookie of its own, apart from the session, so it
// survives sign-out. At the next sign-in SecondFactorRequired sees the token
// on the request, finds an unexpired row for THIS user, and the session is
// created full instead of pending. A row is bound to one user: a token minted
// for one account skips nothing on another.
//
// Off by default (TrustDevices turns it on), because every trusted device is
// a place where the second factor does not apply.

// Operation ids and paths of the device operations.
const (
	// EndpointDevices lists the signed-in user's trusted devices.
	EndpointDevices auth.EndpointID = "twofactor.devices"
	// EndpointForgetDevice revokes one trusted device, or all of them.
	EndpointForgetDevice auth.EndpointID = "twofactor.forget-device"

	pathDevices      = "/devices"
	pathForgetDevice = "/devices/forget"
)

// The device table: one row per trusted device, looked up by token hash at
// sign-in and by user for the list.
const (
	//ds:def id=tablenamedevice-x4m9kq7v owner=@khanakia stability=stable
	TableNameDevice  = "auth_two_factor_device"
	TableAliasDevice = "tfd"

	ColDeviceID        = "id"
	ColDeviceUser      = "user_id"
	ColDeviceTokenHash = "token_hash"
	ColDeviceUserAgent = "user_agent"
	ColDeviceCreatedAt = "created_at"
	ColDeviceExpiresAt = "expires_at"
	ColDeviceLastUsed  = "last_used_at"

	idPrefixDevice = "tfd"
	// indexDeviceUserSuffix, after the device table's real name, names the
	// index the list reads.
	indexDeviceUserSuffix = "_user_idx"
	// maxUserAgentLength bounds what a row keeps of the client's User-Agent:
	// enough to recognise a browser in a list, short enough that a hostile
	// header cannot bloat the table.
	maxUserAgentLength = 200
)

// Typed columns of the device table, for an app that reads it.
var (
	TableDevice = sqlb.Table{Name: TableNameDevice, Alias: TableAliasDevice}

	DeviceID        = sqlb.Col[string](TableDevice, ColDeviceID)
	DeviceUser      = sqlb.Col[string](TableDevice, ColDeviceUser)
	DeviceTokenHash = sqlb.Col[[]byte](TableDevice, ColDeviceTokenHash)
	DeviceUserAgent = sqlb.Col[string](TableDevice, ColDeviceUserAgent)
	DeviceCreatedAt = sqlb.Col[time.Time](TableDevice, ColDeviceCreatedAt)
	DeviceExpiresAt = sqlb.Col[time.Time](TableDevice, ColDeviceExpiresAt)
	DeviceLastUsed  = sqlb.Col[*time.Time](TableDevice, ColDeviceLastUsed)
)

// Trusted-device lifetimes.
const (
	// DefaultTrustedDeviceAge is how long a trusted device skips the second
	// factor: thirty days, the figure users expect from "remember this
	// browser", and the age is fixed at trust time, never renewed by use,
	// so a stolen cookie has a known end.
	//ds:def id=defaulttrusteddeviceage-m2k7xn4q owner=@khanakia stability=stable
	DefaultTrustedDeviceAge = 30 * 24 * time.Hour
	// MaxTrustedDeviceAge bounds TrustDevices: a year of skipping the second
	// factor is no longer two-factor sign-in.
	//ds:def id=maxtrusteddeviceage-8gw3rz6p owner=@khanakia stability=stable
	MaxTrustedDeviceAge = 365 * 24 * time.Hour
)

// Errors of the device operations and option.
var (
	// ErrTrustDisabled: a verify asked to trust the device, but the plugin
	// was built without TrustDevices. Refused rather than ignored, so a
	// client that offers the checkbox learns the server will not honour it.
	ErrTrustDisabled = auth.NewError("twofactor.trust_disabled", http.StatusBadRequest, "Remembering this device is not available.")
	// ErrDeviceNotFound: forget named a device that is not the user's.
	ErrDeviceNotFound = auth.NewError("twofactor.device_not_found", http.StatusNotFound, "Not found.")
	// ErrBadTrustAge: TrustDevices was given no duration, or more than
	// MaxTrustedDeviceAge.
	ErrBadTrustAge = errors.New("twofactor: TrustDevices needs a positive duration of at most MaxTrustedDeviceAge")
)

// TrustDevices lets a user skip the second factor on a device they trusted at
// verify (CodeRequest.TrustDevice), for maxAge from that moment; 0 means
// DefaultTrustedDeviceAge. Trust is bound to the user and to the device
// token the transport keeps in its own cookie, is listed and revocable
// (Devices, ForgetDevice), ends when the factor is disabled, and is cleared
// when the user's password changes, because a device trusted before a
// takeover should not outlive the response to it.
func TrustDevices(maxAge time.Duration) Option {
	return func(p *Plugin) {
		if maxAge == 0 {
			maxAge = DefaultTrustedDeviceAge
		}
		p.trustAge = maxAge
	}
}

// TrustedDevice is one row of the device list: what a settings page shows.
type TrustedDevice struct {
	ID        string     `json:"id"`
	UserAgent string     `json:"userAgent"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	LastUsed  *time.Time `json:"lastUsedAt"`
	// Current is true for the device this request came from.
	Current bool `json:"current"`
}

// DevicesResult is the output of devices, oldest first.
type DevicesResult struct {
	Devices []TrustedDevice `json:"devices"`
}

// ForgetDeviceRequest names one device of the signed-in user, or all of them.
type ForgetDeviceRequest struct {
	ID  string `json:"id,omitempty"`
	All bool   `json:"all,omitempty"`
}

// Devices lists the signed-in user's trusted devices, oldest first.
func (p *Plugin) Devices(ctx context.Context) ([]TrustedDevice, error) {
	r, err := p.devices.Call(ctx, struct{}{})
	return r.Devices, err
}

// ForgetDevice revokes one trusted device by id, or every one with All. The
// next sign-in from it asks for the second factor again. When the device is
// the one this request came from, the transport is told to drop its token.
func (p *Plugin) ForgetDevice(ctx context.Context, in ForgetDeviceRequest) error {
	_, err := p.forget.Call(ctx, in)
	return err
}

// deviceMigration creates the device table. MySQL has no CREATE INDEX IF NOT
// EXISTS, so there the index is declared inside the CREATE TABLE.
func (p *Plugin) deviceMigration(engine string, t auth.SQLTypes) auth.Migration {
	table := p.core.TableName(TableDevice)
	indexDeviceUser := table + indexDeviceUserSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColDeviceID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColDeviceUser + " " + t.ID + " NOT NULL, " +
		ColDeviceTokenHash + " " + t.Hash + " NOT NULL UNIQUE, " +
		ColDeviceUserAgent + " " + t.Text + " NOT NULL, " +
		ColDeviceCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColDeviceExpiresAt + " " + t.Timestamp + " NOT NULL, " +
		ColDeviceLastUsed + " " + t.Timestamp + " NULL"
	st := []string{}
	if engine == auth.EngineMySQL {
		st = append(st, create+", INDEX "+indexDeviceUser+" ("+ColDeviceUser+"))"+t.TableSuffix)
	} else {
		st = append(st, create+")"+t.TableSuffix, "CREATE INDEX IF NOT EXISTS "+indexDeviceUser+" ON "+table+" ("+ColDeviceUser+")")
	}
	return auth.Migration{Owner: PluginName, Name: "0003_two_factor_device", Statements: st}
}

// deviceTrusted reports whether the request in ctx carries a token of an
// unexpired trusted device of userID, and marks the row used. The lookup is
// by the token's hash and the user id together, so a token of another
// account finds nothing. No token, or an unknown one, is simply false.
func (p *Plugin) deviceTrusted(ctx context.Context, userID string) (bool, error) {
	tok := auth.RequestDevice(ctx)
	if tok == "" {
		return false, nil
	}
	now := p.core.Now()
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableDevice).Set(sqlb.Set(DeviceLastUsed, &now)).
		Where(sqlb.Eq(DeviceUser, userID), sqlb.Eq(DeviceTokenHash, auth.HashToken(tok)), sqlb.Greater(DeviceExpiresAt, now))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// trustDevice stores a new trusted device for userID and hands its token to
// the transport. Called by verify after the factor passed.
func (p *Plugin) trustDevice(ctx context.Context, c *auth.Call, userID string) error {
	id, err := c.Auth.NewID(idPrefixDevice)
	if err != nil {
		return err
	}
	tok := auth.NewToken()
	now := c.Auth.Now()
	expires := now.Add(p.trustAge)
	ins := sqlb.NewInsert(c.Auth.Dialect()).Into(TableDevice).Row(
		sqlb.Set(DeviceID, id), sqlb.Set(DeviceUser, userID), sqlb.Set(DeviceTokenHash, auth.HashToken(tok)),
		sqlb.Set(DeviceUserAgent, auth.TruncateRunes(c.Client.UserAgent, maxUserAgentLength)),
		sqlb.Set(DeviceCreatedAt, now), sqlb.Set(DeviceExpiresAt, expires),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return err
	}
	c.Effects.RememberDevice(tok, expires)
	return nil
}

// forgetDevices deletes every trusted device of userID: on disable, and on
// CredentialChanged.
func (p *Plugin) forgetDevices(ctx context.Context, userID string) error {
	_, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableDevice).Where(sqlb.Eq(DeviceUser, userID)))
	return err
}

// CredentialChanged forgets every trusted device of userID. The core calls it
// when a plugin reports that a credential of the user changed (a password
// reset or change): a device trusted before the response to a stolen account
// must not keep skipping the second factor after it.
func (p *Plugin) CredentialChanged(ctx context.Context, userID string) error {
	return p.forgetDevices(ctx, userID)
}

func (p *Plugin) doDevices(ctx context.Context, c *auth.Call, _ struct{}) (DevicesResult, error) {
	var row TrustedDevice
	var hash []byte
	sel := p.core.Select().Columns(
		sqlb.Bind(DeviceID, &row.ID), sqlb.Bind(DeviceUserAgent, &row.UserAgent), sqlb.Bind(DeviceCreatedAt, &row.CreatedAt),
		sqlb.Bind(DeviceExpiresAt, &row.ExpiresAt), sqlb.Bind(DeviceLastUsed, &row.LastUsed), sqlb.Bind(DeviceTokenHash, &hash),
	).From(TableDevice).Where(sqlb.Eq(DeviceUser, c.User.ID), sqlb.Greater(DeviceExpiresAt, c.Auth.Now())).Order(sqlb.OrderBy(DeviceCreatedAt, sqlb.SortAsc))
	current := auth.HashToken(auth.RequestDevice(ctx))
	out := []TrustedDevice{}
	err := p.core.Each(ctx, sel, func() error {
		d := row
		d.Current = auth.RequestDevice(ctx) != "" && string(hash) == string(current)
		out = append(out, d)
		return nil
	})
	return DevicesResult{Devices: out}, err
}

// doForgetDevice deletes the user's own rows only, so another user's id is
// ErrDeviceNotFound like an unknown one. When the current device is among
// them, the transport drops its token.
func (p *Plugin) doForgetDevice(ctx context.Context, c *auth.Call, in ForgetDeviceRequest) (auth.Done, error) {
	d := c.Auth.Dialect()
	tok := auth.RequestDevice(ctx)
	if in.All {
		if err := p.forgetDevices(ctx, c.User.ID); err != nil {
			return auth.Done{}, err
		}
		if tok != "" {
			c.Effects.RememberDevice("", time.Time{})
		}
		return auth.Done{OK: true}, nil
	}
	var hash []byte
	sel := p.core.Select().Columns(sqlb.Bind(DeviceTokenHash, &hash)).From(TableDevice).
		Where(sqlb.Eq(DeviceID, in.ID), sqlb.Eq(DeviceUser, c.User.ID)).Limit(1)
	if err := p.core.One(ctx, sel); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return auth.Done{}, ErrDeviceNotFound
		}
		return auth.Done{}, err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableDevice).Where(sqlb.Eq(DeviceID, in.ID), sqlb.Eq(DeviceUser, c.User.ID))); err != nil {
		return auth.Done{}, err
	}
	if tok != "" && string(hash) == string(auth.HashToken(tok)) {
		c.Effects.RememberDevice("", time.Time{})
	}
	return auth.Done{OK: true}, nil
}

// Sweep deletes expired trusted devices, for auth sweep.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableDevice).Where(sqlb.LessEq(DeviceExpiresAt, cutoff)))
}
