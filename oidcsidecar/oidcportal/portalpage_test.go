package oidcportal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/usage"
)

func mustGet(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// Magpie's key page, embedded, is magpie's file: the parts this deployment
// changed are the ones it says it changed, and nothing else.
func TestTheKeyPageIsMagpiesOwn(t *testing.T) {
	src, err := readMagpieKeyPage()
	if err != nil {
		t.Skip("magpie's source is not beside the sidecar:", err)
	}
	for _, want := range []string{
		"title: \"你的网关密钥\"", "const STR = {", "function drawLimits()", "function drawUsage()", "async function stored()",
		"function drawModels()", "--accent: #0071e3", `const BASE = location.origin;`,
	} {
		if !strings.Contains(string(keyPage), want) {
			t.Fatalf("the key page lacks %q", want)
		}
	}
	if n := strings.Count(string(keyPage), `const BASE = location.origin`); n > 1 {
		t.Fatalf("BASE patched %d times", n)
	}
	// every line magpie's page has is here, unchanged but for the BASE
	ours := strings.Split(string(keyPage), "\n")
	saw := map[string]int{}
	for _, l := range ours {
		saw[strings.TrimSpace(l)]++
	}
	var missing []string
	// this deployment's pages are Chinese: magpie's English lines in the
	// markup (a word quoted in the script is a word the page is not drawn in)
	for _, l := range strings.Split(string(src), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.Contains(l, "const BASE =") || strings.HasPrefix(l, "refresh: ") ||
			strings.HasPrefix(l, "const k = store.get();") || l == "async function stored()" || strings.Contains(l, `credentials: "omit"`) {
			continue // the BASE, and the two words the page's head adds to refresh:
		}
		if saw[l] == 0 && !(strings.HasPrefix(l, "<") && !strings.HasPrefix(l, "<script") && !strings.HasPrefix(l, "<style")) {
			missing = append(missing, l)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("lines of magpie's page not in the embedded copy: %q", missing)
	}
}

// A person's page shows their own key, masked, its limit, its usage by
// model and its recent calls; never the key itself, never another key's.
func TestThePortalPageIsMagpiesAndShowsTheKeysOwnData(t *testing.T) {
	cfg := serverConfig(t)
	cfg.Budget = &BudgetConfig{Period: "month", Cost: 20}
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Name: "Alice", Groups: []string{"team-a"}}}
	ts, state, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")
	u, ok := state.Get("alice")
	if !ok || u.Key == "" {
		t.Fatal("no key")
	}
	usage.Append(usage.Record{
		Time: time.Now(), CallerKeyID: u.KeyID, CallerKeyName: u.Name,
		Provider: "a", Model: "a/one", Input: 12000, Output: 500, Status: 200, Millis: 300,
	})
	usage.Append(usage.Record{
		Time: time.Now(), CallerKeyID: "someone-elses", CallerKeyName: "oidc:bob",
		Provider: "a", Model: "a/not-alices", Input: 99, Output: 1, Status: 200,
	})

	body := bodyOf(t, mustGet(t, c, ts.URL+"/"))
	// magpie's own frame (magpiepage.go): its stylesheet, its scripts, and
	// the portal's pages in its sidebar — never the portal's own look
	for _, want := range []string{
		"<!doctype html>", `<html lang="zh-CN">`,
		`<link rel="stylesheet" href="/app.css?v=`, `<script src="/kernel.js"></script>`,
		`<script src="/portal/page.js"></script>`,
		"我的密钥", "额度", "用量", "退出登录", "轮换密钥", "可用模型",
		maskKey(u.Key), "a", `"items":[{"name":"a/*"}]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the page does not show %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "--accent: #0071e3") {
		t.Fatal("the page is the portal's own look, not magpie's page")
	}
	if strings.Contains(body, u.Key) {
		t.Fatal("the page shows the full key")
	}
	if !strings.Contains(body, "$20.00") {
		t.Fatal("the page does not show the key's limit")
	}
}

// The key page carries its own script (one inline element, under its own
// header), reads the signed-in person's key from the portal rather than a
// typed one, and asks for its data as the portal's own page: by its
// session's cookie. Its setup names the portal's address.
func TestTheKeyPageIsThePortalsOwn(t *testing.T) {
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-a"}}}
	ts, _, c := newTestServer(t, serverConfig(t), fp)
	signIn(t, ts, c, fp, "/")
	resp := mustGet(t, c, ts.URL+"/mine")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := strings.TrimSpace(string(raw))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/mine = %d", resp.StatusCode)
	}
	// the page's one script runs under the portal's default policy only if
	// told to: script-src 'unsafe-inline'
	if csp := resp.Header.Get("Content-Security-Policy"); csp != keyPageCSP {
		t.Fatalf("key page CSP = %q", csp)
	}
	for _, want := range []string{
		`k = await stored()`, `/portal/api/my-key`, `credentials: "same-origin"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the key page misses %q", want)
		}
	}
	if strings.Contains(body, `credentials: "omit"`) {
		t.Fatalf("the key page asks for its data without the portal's session")
	}
}

// The key page's data, when the gateway can't be asked (it isn't at
// GatewayURL: the portal in its own container answers the gateway's /v1
// routes), is the portal's record of the key: its name, its usage and the
// models it may use, and the portal's address as the gateway's.
func TestTheKeyPagesDataWithoutTheGateway(t *testing.T) {
	cfg := serverConfig(t)
	cfg.GatewayURL = "http://127.0.0.1:1" // nothing there
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Name: "Alice", Groups: []string{"team-a"}}}
	ts, state, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")
	u, _ := state.Get("alice")
	resp := mustGet(t, c, ts.URL+"/v1/magpie/me")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	b := raw
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/magpie/me = %d %s", resp.StatusCode, b)
	}
	var me struct {
		Name    string         `json:"name"`
		BaseURL string         `json:"baseURL"`
		Usage   map[string]any `json:"usage"`
		Models  []any          `json:"models"`
	}
	if err := json.Unmarshal(b, &me); err != nil {
		t.Fatal(err, string(b))
	}
	if me.Name != u.Name || me.Name == "" {
		t.Fatalf("name = %q, want the key's own %q", me.Name, u.Name)
	}
	for _, p := range []string{"today", "7d", "30d"} {
		if _, ok := me.Usage[p]; !ok {
			t.Fatalf("usage misses %q: %s", p, b)
		}
	}
	want := strings.TrimSuffix(cfg.RedirectURL, "/callback")
	if me.BaseURL != want {
		t.Fatalf("baseURL = %q, want the portal's %q", me.BaseURL, want)
	}
	if strings.Contains(string(b), u.Key) {
		t.Fatalf("the key's value is in its page's data")
	}
	// another person's session is another key's data, never this one's
	if strings.Contains(string(b), "someone-else") {
		t.Fatalf("another key is in the page's data")
	}
}

// The page's own route, /v1/magpie/me, is the gateway's word about this
// person's key, asked with it; the page's Rotate turns that key over and
// keeps its id.
func TestThePortalAnswersThePagesData(t *testing.T) {
	var gotAuth string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/magpie/me" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"oidc:alice","limits":[],"usage":{"today":{"calls":1}},"topModels":[],"models":[{"id":"a/one","label":"One"}]}`))
	}))
	defer gw.Close()
	cfg := serverConfig(t)
	cfg.GatewayURL = gw.URL
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-a"}}}
	ts, state, c := newTestServer(t, cfg, fp)
	signIn(t, ts, c, fp, "/")
	u, _ := state.Get("alice")

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/magpie/me", nil)
	req.Header.Set("Authorization", "Bearer "+u.Key)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var me map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || me["name"] != "oidc:alice" || gotAuth != "Bearer "+u.Key {
		t.Fatalf("me = %d %v, asked as %q", resp.StatusCode, me, gotAuth)
	}

	// another tab's key, or none signed in, gets nothing
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/magpie/me", nil)
	req.Header.Set("Authorization", "Bearer sk-someone-else")
	// the page's own ask: from the portal's own origin (and its session)
	req.Header.Set("Origin", ts.URL)
	// and the site that asks isn't the portal's
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, err = c.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a tab with another key: %d", resp.StatusCode)
	}
	if resp, err = freshClient(ts).Get(ts.URL + "/v1/magpie/me"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("signed out: %d", resp.StatusCode)
		}
	}

	// Rotate: the same id, a new value, an old one that no longer works
	rot, _ := http.NewRequest(http.MethodPost, ts.URL+"/key/rotate", nil)
	rot.Header.Set("Origin", ts.URL)
	if resp, err = c.Do(rot); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	now, _ := state.Get("alice")
	if resp.StatusCode != http.StatusOK || out["key"] != now.Key || now.Key == u.Key || out["keyId"] != u.KeyID {
		t.Fatalf("rotate = %d %v, now %+v", resp.StatusCode, out, now)
	}
	if _, ok := access.Authenticate(u.Key); ok {
		t.Fatal("the old key still works")
	}
}

// A page of the portal's in magpie's frame runs magpie's scripts as its
// page does, and its own: magpie's console's CSP, not the portal's own
// (which holds a page's scripts to files of its own). (The page itself
// needs the console's magpie, which a console's own test answers.)
func TestTheFramedPageRunsMagpiesScripts(t *testing.T) {
	fp := &fakeProvider{id: Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-a"}}}
	ts, _, c := newTestServer(t, serverConfig(t), fp)
	signIn(t, ts, c, fp, "/")
	for _, path := range []string{"/portal/page.js", "/app.css", "/layout.js"} {
		resp := mustGet(t, c, ts.URL+path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d", path, resp.StatusCode)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "'unsafe-eval'") {
			t.Fatalf("%s: the portal's own CSP for a page of magpie's (%q)", path, csp)
		}
	}
}
