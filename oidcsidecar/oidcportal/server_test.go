package oidcportal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/access"
)

func serverConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	on := true
	c, err := (&Config{
		Issuer:       "https://id.example.com/realms/main",
		ClientID:     "magpie",
		RedirectURL:  "http://magpie.example.com/callback",
		CookieSecret: strings.Repeat("c", 32),
		Groups: map[string][]string{
			"team-a": {"a"},
			"team-c": {"c", "a"},
		},
		Admins:        []string{"boss@example.com"},
		AutoProvision: &on, // these tests predate applications; approval has its own
	}).Prepare()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type fakeProvider struct {
	id       Identity
	err      error
	state    string
	nonce    string
	verifier string
}

func (f *fakeProvider) AuthCodeURL(state, nonce, verifier string) string {
	f.state, f.nonce, f.verifier = state, nonce, verifier
	return "https://id.example.com/auth?state=" + url.QueryEscape(state)
}

func (f *fakeProvider) Exchange(_ context.Context, code, verifier, nonce string) (Identity, error) {
	if f.err != nil {
		return Identity{}, f.err
	}
	if code != "good" {
		return Identity{}, errors.New("unexpected code")
	}
	if verifier != f.verifier || nonce != f.nonce {
		return Identity{}, errors.New("the flow's verifier or nonce is not this login's")
	}
	return f.id, nil
}

func newTestServer(t *testing.T, cfg *Config, fp *fakeProvider) (*httptest.Server, *State, *http.Client) {
	t.Helper()
	ts, state, _, c := newTestServerFull(t, cfg, fp)
	return ts, state, c
}

func newTestServerFull(t *testing.T, cfg *Config, fp *fakeProvider) (*httptest.Server, *State, *PolicyStore, *http.Client) {
	t.Helper()
	state, err := OpenState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := OpenPolicy(cfg.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewServer(cfg, state, policy, fp))
	t.Cleanup(ts.Close)
	return ts, state, policy, freshClient(ts)
}

// freshClient is a browser of its own: ts.Client() is one shared *Client,
// so two sign-ins through it would share a cookie jar.
func freshClient(ts *httptest.Server) *http.Client {
	c := *ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func formPost(t *testing.T, c *http.Client, origin, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, origin+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func signIn(t *testing.T, ts *httptest.Server, c *http.Client, fp *fakeProvider, next string) {
	t.Helper()
	resp, err := c.Get(ts.URL + "/login?next=" + url.QueryEscape(next))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("state") == "" {
		t.Fatalf("login redirect = %q, %v", resp.Header.Get("Location"), err)
	}
	resp, err = c.Get(ts.URL + "/callback?code=good&state=" + url.QueryEscape(loc.Query().Get("state")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func apiMe(t *testing.T, ts *httptest.Server, c *http.Client) map[string]any {
	t.Helper()
	resp, err := c.Get(ts.URL + "/portal/api/me")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/portal/api/me: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return m
}

func apiMyKey(t *testing.T, ts *httptest.Server, c *http.Client) string {
	t.Helper()
	resp, err := c.Get(ts.URL + "/portal/api/my-key")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/portal/api/my-key: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	var m map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return m["key"]
}

func TestHealthz(t *testing.T) {
	ts, _, c := newTestServer(t, serverConfig(t), &fakeProvider{})
	resp, err := c.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if got := bodyOf(t, resp); resp.StatusCode != http.StatusOK || got != "ok\n" {
		t.Fatalf("healthz = %d %q", resp.StatusCode, got)
	}
}

func TestPortalNeedsASignIn(t *testing.T) {
	ts, _, c := newTestServer(t, serverConfig(t), &fakeProvider{})
	resp, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("portal = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSignInMakesAndShowsAKey(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Name: "Alice", Groups: []string{"team-a"}}}
	ts, state, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")

	resp, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("portal: %d", resp.StatusCode)
	}
	u, ok := state.Get("alice")
	if !ok || u.Key == "" {
		t.Fatalf("state = %+v, %v", u, ok)
	}
	if strings.Contains(body, u.Key) || !strings.Contains(body, maskKey(u.Key)) || !strings.Contains(body, "a/*") {
		t.Fatalf("portal should show the masked key and its providers, not the key:\n%s", body)
	}
	if got := apiMyKey(t, ts, c); got != u.Key {
		t.Fatalf("/portal/api/my-key = %q, want the owner's key", got)
	}

	me := apiMe(t, ts, c)
	if me["keyMasked"] != maskKey(u.Key) || me["subject"] != "alice" {
		t.Fatalf("/portal/api/me = %+v", me)
	}
	providers, _ := me["providers"].([]any)
	if len(providers) != 1 || providers[0] != "a/*" {
		t.Fatalf("providers = %v", me["providers"])
	}
	who, ok := access.Authenticate(u.Key)
	if !ok || who.KeyName != "oidc:alice" {
		t.Fatalf("the key does not authenticate: %+v %v", who, ok)
	}
}

func TestCallbackRejectsAnotherLogin(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "alice", Groups: []string{"team-a"}}}
	ts, _, c := newTestServer(t, cfg, fp)
	resp, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(ts.URL + "/callback?code=good&state=not-the-one")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback with a wrong state: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCallbackWithoutAGroupIsTurnedAway(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "carol", Email: "carol@example.com", Groups: []string{"contractors"}}}
	ts, state, c := newTestServer(t, cfg, fp)
	resp, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp, err = c.Get(ts.URL + "/callback?code=good&state=" + url.QueryEscape(loc.Query().Get("state")))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	body := bodyOf(t, resp)
	if !strings.Contains(body, "none of your groups") {
		t.Fatalf("message = %s", body)
	}
	if _, ok := state.Get("carol"); ok {
		t.Fatal("a user with no group was recorded")
	}
}

func TestRotateChangesTheKey(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-a"}}}
	ts, _, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")
	before := apiMyKey(t, ts, c)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/rotate", nil)
	req.Header.Set("Origin", ts.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("rotate: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	resp.Body.Close()

	after := apiMyKey(t, ts, c)
	if after == before {
		t.Fatal("the key did not change")
	}
	if _, ok := access.Authenticate(before); ok {
		t.Fatal("the old key still works")
	}
	if _, ok := access.Authenticate(after); !ok {
		t.Fatal("the new key does not work")
	}
}

func TestCrossOriginFormsAreRefused(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-a"}}}
	ts, _, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/api/rotate", nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-origin rotate: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdminSeesUsersAndOnlyAdminsSeeThePage(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "boss", Email: "boss@example.com", Groups: []string{"team-c"}}}
	ts, state, c := newTestServer(t, cfg, fp)
	if _, err := NewProvisioner(cfg, state).EnsureUser(alice()); err != nil {
		t.Fatal(err)
	}
	signIn(t, ts, c, fp, "/admin")

	resp, err := c.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "alice@example.com") {
		t.Fatalf("admin: %d\n%s", resp.StatusCode, body)
	}

	// Remove alice's key from the page.
	form := url.Values{"sub": {"alice"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", ts.URL)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("remove: %d", resp.StatusCode)
	}
	resp.Body.Close()
	u, _ := state.Get("alice")
	if !u.Disabled || u.Key != "" {
		t.Fatalf("alice = %+v", u)
	}
	if keys, _ := access.List(); len(keys) != 1 {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestANonAdminIsRefusedTheAdminPage(t *testing.T) {
	cfg := serverConfig(t)
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-a"}}}
	ts, _, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")
	resp, err := c.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}
	resp.Body.Close()
}
