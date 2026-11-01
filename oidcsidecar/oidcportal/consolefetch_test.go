package oidcportal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fetchUpstream is a magpie console and gateway behind the portal's own
// page: magpie's sign-in and its console's cookie, its page and scripts,
// and the answers its page asks /api for. It records every path and the
// bearer each was sent with.
type fetchUpstream struct {
	*httptest.Server
	mu      sync.Mutex
	seen    map[string]string // path -> Authorization
	queries map[string]string
}

func (u *fetchUpstream) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seen[r.URL.Path] = r.Header.Get("Authorization")
	u.queries[r.URL.Path] = r.URL.RawQuery
}

func newFetchUpstream(t *testing.T) *fetchUpstream {
	t.Helper()
	u := &fetchUpstream{seen: map[string]string{}, queries: map[string]string{}}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		if r.URL.Path == consoleSignIn {
			// magpie web's sign-in: the key becomes its cookie, under the
			// name of the port it serves
			r.ParseForm()
			w.Header().Set("Set-Cookie", "magpie_web_3430="+r.PostFormValue("key")+"; Path=/; HttpOnly")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		// magpie's own page and scripts, as they are (vendor/gui/assets):
		// what an admin is given is that page, and what a person is given
		// is it too, its views theirs alone
		if b, err := readPageFile(strings.TrimPrefix(r.URL.Path, "/")); err == nil && r.URL.Path != "/" {
			io.WriteString(w, string(b))
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			b, _ := readPageFile("index.html")
			io.WriteString(w, string(b))
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			io.WriteString(w, "window.app=1;")
		case "/start.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			io.WriteString(w, "window.start=1;")
		case "/boot.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			io.WriteString(w, `window.bootPrefs = {"lang":"en","web":true};`)
		case "/api/state":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"settings":{"lang":"en","theme":"dark"},"gateway":{"urls":["192.168.1.5:3425"]}}`)
		case "/api/settings":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"settings":{"lang":"en","modelIds":true}}`)
		case "/api/providers":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"providers":[{"id":"p1","accounts":[{"id":"a1"}]}]}`)
		case "/api/caller-keys":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"keys":[{"id":"k-other","name":"someone-else"}],"accountNames":{}}`)
		case "/api/caller-keys/models":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"models":[{"id":"m"}],"accounts":["a1"]}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(u.Close)
	return u
}

// TestMain gives each console's page to the test that serves it: the page
// is magpie's, read by every portal in a test binary from one cache
// (consolePage), and a test's magpie answers its own page.
func TestMain(m *testing.M) {
	forced = true
	m.Run()
}

// personServer is the portal with the fetch upstream, an ordinary person
// (bob) with a key of his own and an admin (boss).
func personServer(t *testing.T, up *fetchUpstream) (*httptest.Server, *State, *http.Client) {
	t.Helper()
	cfg := consoleConfig(t, up.URL)
	bob := &fakeProvider{id: Identity{Subject: "bob", Email: "bob@example.com", Name: "Bob", Groups: []string{"team-a"}}}
	ts, state, c := newTestServer(t, cfg, bob)
	if _, err := state.Update("bob", func(u *User) error {
		u.Email, u.Name, u.Groups = "bob@example.com", "Bob", []string{"team-a"}
		id, secret, err := makeKey("bob", []string{"a/*"}, nil)
		u.KeyID, u.Key = id, secret
		u.rememberKey(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	signIn(t, ts, c, bob, "/")
	return ts, state, c
}

func mustReadApp(t *testing.T) []byte {
	t.Helper()
	b, err := readPageFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bobKey(t *testing.T, state *State) (string, string) {
	t.Helper()
	u, ok := state.Get("bob")
	if !ok || u.Key == "" {
		t.Fatalf("bob has no key: %+v", u)
	}
	return u.KeyID, u.Key
}

func getAs(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return resp, bodyOf(t, resp)
}

// The page is magpie's own, served as it is, with what this deployment
// adds around its scripts: its boot prefs in Chinese, the person, and
// their sidebar.
func TestPersonConsolePageIsMaggies(t *testing.T) {
	up := newFetchUpstream(t)
	ts, _, c := personServer(t, up)
	resp, body := getAs(t, c, ts.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page: %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{
		`<nav class="seg" id="nav"`, `data-view="gateway"`, `data-view="providers"`, // magpie's own, unchanged
		// named by the hash of the file the portal serves, magpie's own
		`<script src="app.js?v=` + contentHash(mustReadApp(t)) + `"></script>`,
		`<script src="start.js?v=`,
		`<script id="oidc-person">`,
		// the person's pages, registered as the page's own (kernel.js):
		// 我的密钥 and 用量, in the page's own sidebar and styling
		`magpie.plugin("oidc-person"`, `key:"mine"`, `key:"oidc-usage"`,
		`window.oidcPerson={"email":"bob@example.com"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q:\n%s", want, body)
		}
	}
	// a person's script says no page of the whole deployment's is theirs:
	// the sidebar it leaves is 我的密钥 and 用量 alone, so it takes the
	// page's own views out of its nav (a setting the deployment's would
	// draw), and never draws the page's own sidebar of its own
	script := string(personScript(Identity{}, User{}))
	for _, not := range []string{`"网关"`, `"设置"`, `"供应商"`, `"会话"`, `["gateway"`, `["settings"`} {
		if strings.Contains(script, not) {
			t.Fatalf("a person's script names the page's own view %q", not)
		}
	}
	// a person's lines come after the page's own, once its views are drawn
	if i, j := strings.Index(body, `<script id="oidc-person">`), strings.Index(body, `<main class="view" id="view-agents">`); i < 0 || j < 0 || i < j {
		t.Fatalf("the portal's lines are not after the page's views")
	}
	// at the body's end, before its </body>: what it adds is its last
	// element, and nothing of the page's follows it but that
	if i, j := strings.Index(body, `<script id="oidc-person">`), strings.Index(body, "</body>"); i < 0 || j < 0 || i > j || strings.TrimSpace(body[strings.Index(body[i:], "</script>")+i+len("</script>"):j]) != "" {
		t.Fatalf("the portal's lines are not at the page's end")
	}
	if strings.Contains(body, `"lang":"en"`) {
		t.Fatalf("the page is not Chinese")
	}

	// its own files, as magpie serves them
	resp, js := getAs(t, c, ts.URL+"/app.js?v=whatever")
	if resp.StatusCode != http.StatusOK || js != string(mustReadApp(t)) {
		t.Fatalf("app.js: %d %q", resp.StatusCode, js)
	}
	if _, ok := up.seen["/app.js"]; !ok {
		t.Fatalf("app.js was not asked of magpie")
	}

	// the page's stylesheet, served by the portal
	if resp, css := getAs(t, c, ts.URL+"/portal/console.css"); resp.StatusCode != http.StatusOK || !strings.Contains(css, ".oidc-key") {
		t.Fatalf("console.css: %d %s", resp.StatusCode, css)
	}

	// boot.js: magpie's prefs, in Chinese, whose console this is, and the
	// style that makes it this deployment's. The page is not magpie web
	// (web false): the Update pill and the pages of the computer magpie
	// runs on are not a person's.
	_, boot := getAs(t, c, ts.URL+"/boot.js")
	for _, want := range []string{`"lang":"zh"`, `"web":false`, `window.oidcPerson={"email":"bob@example.com"`, `href:'/portal/console.css'`} {
		if !strings.Contains(boot, want) {
			t.Fatalf("boot.js misses %q: %s", want, boot)
		}
	}
	if _, ok := up.seen["/boot.js"]; !ok {
		t.Fatalf("boot.js was not asked of magpie")
	}
}

// boot.js is whose console the page is (the person), before the page's own
// scripts: the page's Chinese lines (zh.go) use it. A person's page's two
// views are the page's own (consolepage.go).
func TestThePagesOwnScriptSaysThePerson(t *testing.T) {
	up := newFetchUpstream(t)
	ts, _, c := personServer(t, up)
	resp, body := getAs(t, c, ts.URL+"/")
	resp.Body.Close()
	_, boot := getAs(t, c, ts.URL+"/boot.js")
	for _, want := range []string{`key:"mine"`, `key:"oidc-usage"`, `magpie.plugin("oidc-person"`} {
		if !strings.Contains(body, want) && !strings.Contains(boot, want) {
			t.Fatalf("the page misses %q", want)
		}
	}
	if !strings.Contains(boot, `window.oidcPerson={"email":"bob@example.com"`) {
		t.Fatalf("the page's boot misses the person: %s", boot)
	}
}

// A person's data is their own key's, and only theirs: their key in the
// list (never its value), their usage, and the whole deployment's
// answers nowhere.
func TestPersonConsoleAnswersOnlyTheirOwnData(t *testing.T) {
	up := newFetchUpstream(t)
	ts, state, c := personServer(t, up)
	keyID, secret := bobKey(t, state)

	resp, body := getAs(t, c, ts.URL+"/api/caller-keys")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("caller-keys: %d %s", resp.StatusCode, body)
	}
	var keys struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0]["id"] != keyID {
		t.Fatalf("keys = %s, want only %s", body, keyID)
	}
	if _, ok := keys.Keys[0]["secret"]; ok {
		t.Fatalf("a key's value is in the list: %s", body)
	}
	if strings.Contains(body, secret) || strings.Contains(body, "someone-else") {
		t.Fatalf("another key or a value is in the list: %s", body)
	}

	// The page's answers come from magpie, signed in with its web key.
	if got := up.seen["/api/caller-keys"]; got != "" {
		t.Fatalf("caller-keys asked magpie with %q", got)
	}
	_, state2 := getAs(t, c, ts.URL+"/api/state")
	if !strings.Contains(state2, `"lang":"zh"`) || !strings.Contains(state2, `"portal"`) {
		t.Fatalf("state = %s", state2)
	}
	_, settings := getAs(t, c, ts.URL+"/api/settings")
	if !strings.Contains(settings, `"lang":"zh"`) {
		t.Fatalf("settings = %s", settings)
	}
	_, models := getAs(t, c, ts.URL+"/api/caller-keys/models")
	if !strings.Contains(models, `"accounts":[]`) {
		t.Fatalf("models offer accounts: %s", models)
	}
	if q := up.queries["/api/state"]; q != "" {
		t.Fatalf("state was asked with %q", q)
	}

	// The Gateway view reads what it draws at every start, and a person is
	// shown no provider of the deployment's and no call of it: every list
	// it would draw is there, empty (its code takes none missing).
	resp, body = getAs(t, c, ts.URL+"/api/providers")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("providers: %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{`"providers":[]`, `"presets":[]`, `"calls":[]`, `"groups":[]`, `"lanes":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers misses %q: %s", want, body)
		}
	}
	if strings.Contains(body, `"p1"`) {
		t.Fatalf("a person was shown the deployment's providers: %s", body)
	}

	// The page's lines that read what the deployment has (updates, agent
	// CLIs, what's new, the routing it shows) are answered, not forwarded.
	for path, want := range map[string]string{
		"/api/gateway/trace?after=0": `"routes":[]`,
		"/api/update?lang=zh":        `"state":"latest"`,
		"/api/whatsnew?lang=zh":      `"releases":[]`,
		"/api/agents/cli":            `"pending":false`,
		"/api/agents/install":        `[]`,
		"/api/plugins/agents":        `[]`,
		"/api/cli":                   `"ours":false`,
	} {
		delete(up.seen, path)
		resp, body := getAs(t, c, ts.URL+path)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, want) {
			t.Fatalf("%s = %d %s, want %q", path, resp.StatusCode, body, want)
		}
		if _, ok := up.seen[strings.SplitN(path, "?", 2)[0]]; ok {
			t.Fatalf("%s reached magpie", path)
		}
	}

	// What is not a person's is not forwarded, nor answered: the whole
	// deployment's data, another key's, a body.
	for _, path := range []string{"/api/sessions/manage", "/api/library", "/api/plugins", "/api/caller-keys/copy-key", "/api/gateway/call"} {
		delete(up.seen, path)
		resp, body := getAs(t, c, ts.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s = %d %s, want 404", path, resp.StatusCode, body)
		}
		if _, ok := up.seen[path]; ok {
			t.Fatalf("%s reached magpie", path)
		}
	}

	// The console is read-only here.
	for _, path := range []string{"/api/caller-keys/add-key", "/api/settings/lan"} {
		resp, body := doConsole(t, c, http.MethodPost, ts.URL+path)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("POST %s = %d %s", path, resp.StatusCode, body)
		}
	}
}

// An admin's console is magpie's own even where the portal serves ordinary
// people (its page for them, their answers): theirs is the page as magpie
// has it, every view, with the portal's pages in its sidebar.
func TestAdminGetsMagpiesPageWhereAPersonServesTheRest(t *testing.T) {
	up := newFetchUpstream(t)
	ts, _, bob := personServer(t, up)
	resp, body := getAs(t, bob, ts.URL+"/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "我的密钥") || strings.Contains(body, "门户管理") {
		t.Fatalf("a person's page: %d (wants their sidebar, not the admin links)", resp.StatusCode)
	}
	if _, boot := getAs(t, bob, ts.URL+"/boot.js"); strings.Contains(boot, `"admin":true`) {
		t.Fatalf("a person's boot says they are an admin: %s", boot)
	}

	cfg := consoleConfig(t, up.URL)
	boss := &fakeProvider{id: Identity{Subject: "boss", Email: "boss@example.com", Groups: []string{"team-c", RoleOperator}}}
	ts2, _, c := newTestServer(t, cfg, boss)
	signIn(t, ts2, c, boss, "/")
	resp, body = getAs(t, c, ts2.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an admin's page: %d", resp.StatusCode)
	}
	for _, want := range []string{`<main class="view" id="view-providers"`, "门户管理", "我的密钥", "退出登录", `"admin":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("an admin's page misses %q", want)
		}
	}
	if _, prov := getAs(t, c, ts2.URL+"/api/providers"); !strings.Contains(prov, `"p1"`) {
		t.Fatalf("an admin's providers are not magpie's own: %s", prov)
	}
	_, boot := getAs(t, c, ts2.URL+"/boot.js")
	if !strings.Contains(boot, `"admin":true`) {
		t.Fatalf("an admin's boot: %s", boot)
	}
}

// The usage answers are cut to the person's key, whatever the page asks.
func TestPersonConsoleUsageIsCutToTheirKey(t *testing.T) {
	up := newFetchUpstream(t)
	ts, state, c := personServer(t, up)
	keyID, _ := bobKey(t, state)

	resp, body := getAs(t, c, ts.URL+"/api/usage/requests")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("requests: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(body, "k-other") {
		t.Fatalf("another key is in the ledger: %s", body)
	}
	if _, ok := up.seen["/api/usage/requests"]; ok {
		t.Fatalf("the ledger was asked of magpie")
	}

	// 用量's own views answer from the portal's ledger, cut to the person's
	// key, whatever the page asks.
	for _, q := range []string{"/api/usage", "/api/usage/requests?callerKey=k-other&period=today", "/api/usage/heatmap?callerKey=k-other"} {
		resp, body := getAs(t, c, ts.URL+q)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", q, resp.StatusCode, body)
		}
		if strings.Contains(body, "k-other") {
			t.Fatalf("%s has another key: %s", q, body)
		}
	}
	_ = keyID
}

// An admin's console is magpie's own: its API, any method, answered by
// magpie itself.
func TestAdminConsoleIsMaggiesOwn(t *testing.T) {
	up := newFetchUpstream(t)
	// boss's own browser, no one else signed in before: the shared client's
	// jar would carry bob's session over to boss
	cfg := consoleConfig(t, up.URL)
	boss := &fakeProvider{id: Identity{Subject: "boss", Email: "boss@example.com", Groups: []string{"team-a", RoleOperator}}}
	ts, _, c := newTestServer(t, cfg, boss)
	signIn(t, ts, c, boss, "/")
	resp, body := getAs(t, c, ts.URL+"/api/providers")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"p1"`) {
		t.Fatalf("admin providers: %d %s", resp.StatusCode, body)
	}
	// the portal's own routes stay the portal's
	resp, body = getAs(t, c, ts.URL+"/admin")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "boss@example.com") {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}
}

// Without a session the console is not one's to read, and a page one opens
// goes to the sign-in.
func TestConsoleNeedsThePortalsSignIn(t *testing.T) {
	up := newFetchUpstream(t)
	ts, _, _ := personServer(t, up)
	anon := freshClient(ts)
	resp, _ := getAs(t, anon, ts.URL+"/api/caller-keys")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("caller-keys without a session = %d", resp.StatusCode)
	}
	resp, _ = getAs(t, anon, ts.URL+"/mine")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("/mine without a session = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
