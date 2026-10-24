package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/sqlb"
)

// Resource paths, relative to where Handler is mounted.
const (
	pathUsers         = "/Users"
	pathGroups        = "/Groups"
	pathSPConfig      = "/ServiceProviderConfig"
	pathSchemas       = "/Schemas"
	pathResourceTypes = "/ResourceTypes"
)

// serve routes one request.
func (p *Plugin) serve(w http.ResponseWriter, r *http.Request) {
	// The SCIM bearer token is the connection's, never a session: the
	// request reaches the core without a credential.
	req := authhttp.RequestOf(r)
	req.Credential, req.Token = "", ""
	ctx := p.core.WithRequest(r.Context(), req)
	r = r.WithContext(ctx)
	path := "/" + strings.Trim(r.URL.Path, "/")
	if doc, ok := p.discovery(r, path); ok {
		if err := p.admit(ctx, ""); err != nil {
			authhttp.SetRetryAfter(w, err)
			writeError(w, err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, errMethod)
			return
		}
		if doc == nil {
			writeError(w, errorf(http.StatusNotFound, "", "Schema or resource type not found"))
			return
		}
		writeJSON(w, http.StatusOK, doc)
		return
	}
	pr, err := p.authenticate(r)
	// Every request is counted, a refused token by its address alone, so
	// guessing tokens is limited too.
	if gate := p.admit(ctx, pr.ConnectionID); gate != nil {
		authhttp.SetRetryAfter(w, gate)
		writeError(w, gate)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if !slices.Contains(pr.Scopes, requiredScope(r.Method, path)) {
		writeError(w, errScope)
		return
	}
	// The projection is read before anything is written: a bad one found
	// after a create would answer 400 for a user that now exists, and the
	// IdP's retry would then meet a conflict.
	proj, err := parseProjection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	if err := p.bind(ctx, pr); err != nil {
		writeError(w, err)
		return
	}
	ctx = context.WithValue(ctx, principalKey{}, pr)
	r = r.WithContext(ctx)
	collection, id, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	var status int
	var out any
	switch "/" + collection {
	case pathUsers:
		status, out, err = p.users(r, pr.ConnectionID, id, proj)
	case pathGroups:
		status, out, err = p.groupsRoute(r, pr.ConnectionID, id, proj)
	default:
		err = errNotFound
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, out)
}

// readDoc reads a JSON object body in one of the SCIM media types.
func readDoc(r *http.Request) (map[string]any, error) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != MediaType && mt != mediaTypeJSON {
		return nil, errMediaType
	}
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		return nil, errorf(http.StatusRequestEntityTooLarge, TooMany, "The request body is too large")
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil || doc == nil {
		return nil, errSyntax
	}
	return doc, nil
}

// readPatch reads a PATCH body.
func readPatch(r *http.Request) ([]PatchOp, error) {
	doc, err := readDoc(r)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(doc)
	var pr PatchRequest
	if err := json.Unmarshal(b, &pr); err != nil {
		return nil, invalid("Operations must be a list of operations")
	}
	if !slices.Contains(pr.Schemas, SchemaPatchOp) {
		return nil, invalid("schemas must contain " + SchemaPatchOp)
	}
	return pr.Operations, nil
}

// keyOfValue is the SHA-256 hex of a compared form: a unique index stays
// within MySQL's key length whatever the attribute's length.
func keyOfValue(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// optKey is keyOfValue of a non-empty value, nil for an empty one.
func optKey(s string) *string {
	if s == "" {
		return nil
	}
	k := keyOfValue(s)
	return &k
}

// optString is a non-empty value, nil for an empty one.
func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// page reads startIndex and count: 1-based, default 1; default and maximum
// MaxPageSize.
func page(q url.Values) (start, count int, err error) {
	start, count = 1, MaxPageSize
	if s := q.Get("startIndex"); s != "" {
		if start, err = strconv.Atoi(s); err != nil {
			return 0, 0, invalid("startIndex must be an integer")
		}
		start = max(start, 1)
	}
	if s := q.Get("count"); s != "" {
		if count, err = strconv.Atoi(s); err != nil {
			return 0, 0, invalid("count must be an integer")
		}
		count = min(max(count, 0), MaxPageSize)
	}
	return start, count, nil
}

// listResponse is RFC 7644 §3.4.2's ListResponse.
type listResponse struct {
	Schemas      []string         `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []map[string]any `json:"Resources"`
}

// pageOf slices docs into one ListResponse page.
func pageOf(docs []map[string]any, start, count int) listResponse {
	out := listResponse{Schemas: []string{SchemaListResponse}, TotalResults: len(docs), StartIndex: start, Resources: []map[string]any{}}
	if from := start - 1; from < len(docs) {
		out.Resources = docs[from:min(from+count, len(docs))]
	}
	out.ItemsPerPage = len(out.Resources)
	return out
}

// location is the absolute link of a resource: the request's base URL, the
// path the handler is mounted at, the collection and the id.
//
// The collection is the one of the resource linked, which need not be the
// request's: a Group's members link to /Users from a /Groups request, so the
// mount is found from the request's own path, never by searching it for the
// linked collection.
func location(r *http.Request, base, collection, id string) string {
	mount := mountOf(r)
	if u, err := url.Parse(base); err == nil {
		u.Path, u.RawQuery = "", ""
		base = u.String()
	}
	return strings.TrimSuffix(base, "/") + strings.TrimSuffix(mount, "/") + collection + "/" + id
}

// mountOf is the path the SCIM handler is mounted at, without a trailing
// slash. Behind http.StripPrefix the request URI ends with the handler's own
// path, and the mount is what comes before it; without a prefix strip the
// mount ends before the last /Users or /Groups segment.
func mountOf(r *http.Request) string {
	full := r.URL.EscapedPath()
	if u, err := url.ParseRequestURI(r.RequestURI); err == nil {
		full = u.EscapedPath()
	}
	if inner := r.URL.EscapedPath(); inner != full && strings.HasSuffix(full, inner) {
		return strings.TrimSuffix(full[:len(full)-len(inner)], "/")
	}
	segs := strings.Split(full, "/")
	for i := len(segs) - 1; i > 0; i-- {
		if seg := "/" + segs[i]; seg == pathUsers || seg == pathGroups {
			return strings.Join(segs[:i], "/")
		}
	}
	return strings.TrimSuffix(full, "/")
}

// errConflict is a uniqueness conflict on attr.
func errConflict(what string) *Error {
	return errorf(http.StatusConflict, Uniqueness, what+" already exists")
}

// truncateName fits a SCIM display name into the core's name bound.
func truncateName(s string) string {
	runes := []rune(s)
	if len(runes) > auth.MaxNameLength {
		return string(runes[:auth.MaxNameLength])
	}
	return s
}

// now is the core's clock.
func (p *Plugin) now() time.Time { return p.core.Now() }

// exists reports whether q matches a row.
func (p *Plugin) exists(ctx context.Context, q auth.Statement) (bool, error) {
	err := p.core.One(ctx, q)
	if errors.Is(err, sqlb.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
