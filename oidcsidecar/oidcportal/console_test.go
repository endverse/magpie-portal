package oidcportal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/access"
)

// consoleConfig is serverConfig with a fake magpie console behind it.
func consoleConfig(t *testing.T, upstream string) *Config {
	t.Helper()
	cfg := serverConfig(t)
	cfg.ConsoleURL = upstream
	cfg.GatewayURL = upstream // its gateway's route, /v1/magpie/me, is there too
	cfg.ConsoleWebKey = strings.Repeat("w", 32)
	// magpie web's own name for its cookie, the console's port in it
	cfg.ConsoleCookie = "magpie_web_" + consolePort(mustURL(t, upstream))
	return cfg
}

// consoleUpstream answers the console paths the proxy forwards, as magpie
// web does behind its key's sign-in, and keeps what it was sent. The paths
// an admin's console asks are magpie's own, answered by the console's fetch
// (consolefetch) as magpie answers them when testFetch is on.
type consoleUpstream struct {
	*httptest.Server
	cookie string
	query  string
	path   string
	auth   string
	// testFetch is whether the paths an admin's console asks are magpie's
	// own, answered by the console's fetch: the answer the console's fetch
	// gives is what magpie would, and what it was sent is kept here.
	testFetch bool
}

// newConsoleServer is the portal with this console behind it, holding no
// console of magpie's own: the areas an admin's pages reach are the
// console's proxy's (console.go), for an admin who is not an admin of
// magpie's own console.
func newConsoleServer(t *testing.T, cfg *Config, fp *fakeProvider) (*httptest.Server, *State, *PolicyStore, *http.Client) {
	t.Helper()
	cfg.Fetch = false
	ts, st, pol, c := newTestServerFull(t, cfg, fp)
	return ts, st, pol, c
}

// formCookieEscape is the key as a Set-Cookie header carries it (percent-
// encoded, as the key is not a cookie's value): {{SECRET_akwxtc4m}}.
func formCookieEscape(k string) string { return url.QueryEscape(k) }

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newConsoleUpstream(t *testing.T) *consoleUpstream {
	t.Helper()
	u := &consoleUpstream{testFetch: true}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.cookie, u.query, u.path, u.auth = r.Header.Get("Cookie"), r.URL.RawQuery, r.URL.Path, r.Header.Get("Authorization")

		if r.URL.Path == consoleSignIn {
			// magpie web's sign-in: the key becomes its cookie, a byte
			// outside a cookie's range in the tests' key and all
			r.ParseForm()
			w.Header().Set("Set-Cookie", "magpie_web_test="+formCookieEscape(r.PostFormValue("key"))+"; Path=/; HttpOnly")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if r.URL.Path == "/" {
			// the app's page, as magpie answers it for this deployment
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if u.testFetch {
				io.WriteString(w, `<html lang="en"><head><script src="app.js?v=c3143f1d8ca4"></script></head><body>`+
					`<nav id="nav"><button data-view="gateway">Gateway</button></nav><main id="view-gateway"></main>`+
					`<script src="start.js?v=98b02085ec90"></script></body></html>`)
				return
			}
			io.WriteString(w, `<html lang="en"><head></head><body><script src="app.js"></script></body></html>`)
			return
		}
		if p := r.URL.Path; p == "/me" || strings.HasPrefix(p, "/console/") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, `<html lang="en"><head></head><body><script src="app.js"></script></body></html>`)
			return
		}
		switch r.URL.Path {
		case "/v1/magpie/me":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"name":"oidc:boss","limits":[]}`)
		case "/api/state":
			w.Header().Set("Set-Cookie", "console-cookie=1; Path=/")
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"ok":true,"secret":"sk-state","requestBody":"prompt","responseBody":"reply","nested":{"secret":"sk-nested","keep":1}}`)
		case "/api/caller-keys/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"secret":"sk-rotated","keys":[{"id":"k1","name":"oidc:bob"}]}`)
		case "/api/caller-keys/copy-key":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"secret":"sk-copied"}`)
		case "/api/gateway/call":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"requestBody":"prompt","responseBody":"reply"}`)
		case "/api/usage/requests/content":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"requestBody":"prompt"}`)
		case "/api/settings/search-key":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"key":"sk-search"}`)
		case "/api/plugins":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"plugins":[]}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(u.Close)
	return u
}

func doConsole(t *testing.T, c *http.Client, method, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

// An operator gets the operations face, read and write, but no key
// secret, no request or response words and not the library, and never the
// console's own web key.
func TestOrdinaryAdminConsoleIsScoped(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	fp := &fakeProvider{id: Identity{Subject: "boss", Email: "boss@example.com", Groups: []string{"team-c", RoleOperator}}}
	ts, _, _, _ := newConsoleServer(t, cfg, fp)
	c := freshClient(ts)
	signIn(t, ts, c, fp, "/console/")

	resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/console/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "app.js") {
		t.Fatalf("console page: %d %s", resp.StatusCode, body)
	}
	if up.path != "/" {
		t.Fatalf("upstream path = %q, want /", up.path)
	}
	// the console is asked with the cookie its own sign-in set, the key's
	if up.cookie != "magpie_web_test="+cfg.ConsoleWebKey {
		t.Fatalf("upstream cookie = %q, want the console's own sign-in cookie", up.cookie)
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("the console's cookie leaked: %v", resp.Header.Values("Set-Cookie"))
	}

	resp, body = doConsole(t, c, http.MethodGet, ts.URL+"/console/app.js?k=leak&x=1")
	if resp.StatusCode != http.StatusOK || up.path != "/app.js" {
		t.Fatalf("asset: %d path %q", resp.StatusCode, up.path)
	}
	if strings.Contains(up.query, "k=") || !strings.Contains(up.query, "x=1") {
		t.Fatalf("upstream query = %q", up.query)
	}

	resp, body = doConsole(t, c, http.MethodGet, ts.URL+"/api/state")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state: %d %s", resp.StatusCode, body)
	}
	var state map[string]any
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	if state["ok"] != true {
		t.Fatalf("state = %s", body)
	}
	for _, k := range []string{"secret", "requestBody", "responseBody"} {
		if _, ok := state[k]; ok {
			t.Fatalf("%s survived: %s", k, body)
		}
	}
	if nested, _ := state["nested"].(map[string]any); nested["secret"] != nil || nested["keep"] == nil {
		t.Fatalf("nested = %v", state["nested"])
	}

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/gateway/call", http.StatusForbidden},
		{http.MethodGet, "/api/usage/requests/content", http.StatusForbidden},
		{http.MethodPost, "/api/caller-keys/copy-key", http.StatusForbidden},
		{http.MethodPost, "/api/caller-keys/add-key", http.StatusForbidden},
		{http.MethodPost, "/api/caller-keys/rotate-key", http.StatusForbidden},
		{http.MethodGet, "/api/settings/search-key", http.StatusForbidden},
		{http.MethodGet, "/api/gateway/trace", http.StatusForbidden},
		{http.MethodGet, "/api/usage/requests", http.StatusForbidden},
		{http.MethodPost, "/api/caller-keys/on", http.StatusForbidden},
		{http.MethodPost, "/api/gateway/session-titles", http.StatusForbidden},
		{http.MethodGet, "/api/library", http.StatusForbidden},
		{http.MethodGet, "/api/unknown", http.StatusForbidden},
		{http.MethodGet, "/api/plugins", http.StatusOK},
		{http.MethodPost, "/api/gateway/route", http.StatusOK},
		{http.MethodPost, "/api/settings/allowips", http.StatusOK},
		{http.MethodPost, "/api/providers/arrange", http.StatusOK},
	} {
		resp, body := doConsole(t, c, tc.method, ts.URL+tc.path)
		if resp.StatusCode != tc.want {
			t.Fatalf("%s %s = %d %s, want %d", tc.method, tc.path, resp.StatusCode, body, tc.want)
		}
	}

	// Rotation is the portal's, which does not show the new value: the
	// console endpoint answers with the secret and is refused.
	resp, body = doConsole(t, c, http.MethodPost, ts.URL+"/api/caller-keys/rotate-key")
	if resp.StatusCode != http.StatusForbidden || strings.Contains(string(body), "sk-rotated") {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
}

// A super admin sees the request and response words an operator does not,
// but the same key answers stay closed.
func TestSuperAdminConsoleStillHidesKeysAndBodies(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	fp := &fakeProvider{id: Identity{Subject: "root", Email: "root@example.com", Groups: []string{"team-c", RoleSuper}}}
	ts, _, _, _ := newConsoleServer(t, cfg, fp)
	c := freshClient(ts)
	signIn(t, ts, c, fp, "/console/")

	for _, path := range []string{"/api/plugins", "/api/gateway/trace", "/api/gateway/call", "/api/usage/requests/content"} {
		if resp, body := doConsole(t, c, http.MethodGet, ts.URL+path); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/caller-keys/copy-key"},
		{http.MethodPost, "/api/caller-keys/add-key"},
	} {
		if resp, body := doConsole(t, c, tc.method, ts.URL+tc.path); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s = %d %s, want 403", tc.method, tc.path, resp.StatusCode, body)
		}
	}
	_, body := doConsole(t, c, http.MethodGet, ts.URL+"/api/state")
	if strings.Contains(string(body), "sk-state") || strings.Contains(string(body), "prompt") {
		t.Fatalf("super admin saw a secret or body: %s", body)
	}
}

func TestConsoleNeedsAnAdmin(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	fp := &fakeProvider{id: Identity{Subject: "bob", Email: "bob@example.com", Groups: []string{"team-a"}}}
	ts, _, _, _ := newConsoleServer(t, cfg, fp)
	c := freshClient(ts)

	resp, _ := doConsole(t, c, http.MethodGet, ts.URL+"/console/")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?next=%2Fconsole%2F" {
		t.Fatalf("signed-out console: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/api/state"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed-out API: %d %s", resp.StatusCode, body)
	}

	signIn(t, ts, c, fp, "/")
	resp, _ = doConsole(t, c, http.MethodGet, ts.URL+"/console/")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("ordinary user console: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/api/state"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user API: %d %s", resp.StatusCode, body)
	}
}

func TestConsoleRedirectsToTheConsolePath(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	ts, _, _, _ := newConsoleServer(t, cfg, &fakeProvider{})
	c := freshClient(ts)
	resp, _ := doConsole(t, c, http.MethodGet, ts.URL+"/console")
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/console/" {
		t.Fatalf("/console = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// The key page is the admin's own: the console asks magpie with the key the
// portal made them, so /me and its data come back as theirs, and /me/rotate
// turns the value over without showing it.
func TestTheKeyPageIsTheAdminsOwn(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	fp := &fakeProvider{id: Identity{Subject: "boss", Email: "boss@example.com", Username: "boss", Groups: []string{"team-c", RoleOperator}}}
	ts, state, _, _ := newConsoleServer(t, cfg, fp)
	u, err := NewProvisioner(cfg, state).EnsureUser(fp.id)
	if err != nil {
		t.Fatal(err)
	}
	c := freshClient(ts)
	signIn(t, ts, c, fp, "/admin")

	resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/me")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "oidc-zh") {
		t.Fatalf("key page: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), u.Key) {
		t.Fatal("the page does not hand the signed-in admin their own key")
	}

	// Its data at /v1/magpie/me is the portal's answer, in magpie's own
	// shape: it asks the gateway with this person's key and passes the
	// gateway's word on. A tab whose key is another's gets 401.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/magpie/me", nil)
	req.Header.Set("Authorization", "Bearer "+u.Key)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"name"`) {
		t.Fatalf("/v1/magpie/me: %d %s", resp.StatusCode, b)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/magpie/me", nil)
	req.Header.Set("Authorization", "Bearer sk-someone-else")
	// the page's own ask: from the portal's own origin (and its session)
	req.Header.Set("Origin", ts.URL)
	// and the site that asks isn't the portal's
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a tab with another key: %d", resp.StatusCode)
	}

	// The usage answers the operations face already reaches are theirs too.
	if resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/api/usage"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/usage: %d %s", resp.StatusCode, body)
	}

	// Rotating from the key page turns the value over, answers nothing of
	// it that the portal does not already say, and the console asks with
	// the new one from then on.
	rotate, _ := http.NewRequest(http.MethodPost, ts.URL+"/me/rotate", nil)
	rotate.Header.Set("Origin", ts.URL)
	rotate.Header.Set("Authorization", "Bearer "+u.Key)
	resp, err = c.Do(rotate)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"keyId":"`+u.KeyID+`"`) {
		t.Fatalf("rotate: %d %s", resp.StatusCode, b)
	}
	now, ok := state.Get(u.Sub)
	if !ok || now.Key == u.Key || now.Generation != u.Generation+1 {
		t.Fatalf("after rotating: %+v, was %+v", now, u)
	}
	if who, ok := access.Authenticate(now.Key); !ok || who.KeyID != u.KeyID {
		t.Fatal("the rotated key does not authenticate as the same key")
	}
	// and the console's own answers are asked as the new key too: the
	// portal's /v1/magpie/me asks the gateway's route as it
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/magpie/me", nil)
	if resp, err = c.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if up.auth != "Bearer "+now.Key {
		t.Fatalf("after rotating the console asked as %q", up.auth)
	}
}

func TestConsoleAllowedByRole(t *testing.T) {
	const (
		op  = "operator"
		sup = "super"
	)
	cases := []struct {
		role   string
		path   string
		method string
		want   bool
	}{
		// the operator's operations face
		{op, "/api/providers", "GET", true},
		{op, "/api/providers", "POST", true},
		{op, "/api/groups", "GET", true},
		{op, "/api/gateway", "GET", true},
		{op, "/api/gateway/route", "POST", true},
		{op, "/api/gateway/route", "GET", false},
		{op, "/api/gateway/restart", "POST", false}, // sub-paths are not blanket-allowed
		{op, "/api/usage", "GET", true},
		{op, "/api/usage/heatmap", "GET", true},
		// the ledger is row by row: operator reads the overview only
		{op, "/api/usage/requests", "GET", false},
		{op, "/api/usage/requests.csv", "GET", false},
		{op, "/api/usage/requests/export", "GET", false},
		{sup, "/api/usage/requests", "GET", true},
		// the key table is the operator's; changing a key is a super admin's
		{op, "/api/caller-keys", "GET", true},
		{op, "/api/caller-keys/models", "GET", true},
		{op, "/api/caller-keys/models", "POST", false},
		{op, "/api/caller-keys/rename-key", "POST", false},
		{op, "/api/caller-keys/on", "POST", false},
		{sup, "/api/caller-keys/rename-key", "POST", true},
		{op, "/api/masking/records", "GET", true},
		{op, "/api/plugins", "GET", true},
		{op, "/api/plugin-panels", "GET", true},
		{op, "/api/settings", "GET", true},
		{op, "/api/set", "POST", true},
		// the routing page's context, confidential: operator no, super yes
		{op, "/api/gateway/trace", "GET", false},
		{op, "/api/gateway/history", "GET", false},
		{op, "/api/gateway/session-titles", "POST", false},
		{op, "/api/gateway/call", "GET", false},
		{op, "/api/usage/requests/content", "GET", false},
		{op, "/api/context/text", "GET", false},
		{sup, "/api/gateway/trace", "GET", true},
		{sup, "/api/gateway/history", "GET", true},
		{sup, "/api/gateway/session-titles", "POST", true},
		{sup, "/api/gateway/call", "GET", true},
		{sup, "/api/usage/requests/content", "GET", true},
		{sup, "/api/context/text", "GET", true},
		// nobody's: key values and archives
		{sup, "/api/caller-keys/copy-key", "POST", false},
		{sup, "/api/sessions/one", "GET", false},
		{op, "/api/caller-keys/copy-key", "POST", false},
		// operator does not read the business face
		{op, "/api/library", "GET", false},
		{sup, "/api/library", "GET", true},
		// InGroup reads groups case-insensitively, and roles are groups too;
		// paths themselves stay case-sensitive
		{op, "/api/PROVIDERS", "GET", false},
		// an API path not listed: refused
		{op, "/api/unknown", "GET", false},
	}
	for _, c := range cases {
		super := c.role == sup
		if got := consoleAllowed(super, c.path, c.method, ""); got != c.want {
			t.Errorf("%s %s %s: got %v want %v", c.role, c.method, c.path, got, c.want)
		}
	}
}

// A super admin whose policy an admin rejected is still let into the
// console and its admin page: the gates read the role, which is Keycloak's,
// not the policy, which keeps them unadopted and without a key. ROUTE TO
// OWNER: the policy is the wrong place for this assertion.
func TestRejectedSuperAdminIsNotAdopted(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	fp := &fakeProvider{id: Identity{Subject: "root", Email: "root@example.com", Groups: []string{"team-c", RoleSuper}}}
	ts, state, pol, _ := newConsoleServer(t, cfg, fp)
	if _, err := pol.Seen(fp.id); err != nil {
		t.Fatal(err)
	}
	if p, err := pol.Reject("root", "boss@example.com", "not this one"); err != nil || p.Status != StatusRejected {
		t.Fatalf("reject = %+v, %v", p, err)
	}
	c := freshClient(ts)
	signIn(t, ts, c, fp, "/")
	if p, _ := pol.Get("root"); p.Status != StatusRejected {
		t.Fatalf("signing in adopted a rejected policy: %+v", p)
	}
	// what the policy does say: no key for a rejected person
	if u, ok := state.Get("root"); ok && u.KeyID != "" {
		t.Fatalf("a rejected person holds a key: %+v", u)
	}
	if resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/api/state"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/state = %d %s, want the role's 200", resp.StatusCode, body)
	}
	// the admin page answers them too: the role is Keycloak's, not the
	// policy's, and the page lists the request it was refused in
	if resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/admin"); resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "root@example.com") {
		t.Fatalf("/admin = %d, want the role's 200: %s", resp.StatusCode, body)
	}
}
