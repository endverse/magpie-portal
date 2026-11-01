package oidcportal

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/budget"
	"github.com/yetone/magpie/internal/usage"
	"github.com/yetone/magpie/internal/usageapi"
)

// consoleFetch is magpie's own console for everyone who is not an admin:
// the page is magpie's, served as it is, and every answer magpie would give
// of the whole deployment is answered here instead, for the signed-in
// person alone. The page asks the same routes, with the same data; what it
// shows is that person's gateway key, its limit and its usage, and its
// providers' faces (not their accounts, keys or secrets).
//
// The page is magpie's frontend, copied as it is: index.html, app.js,
// i18n.js, boot.js, the plugins' scripts and stylesheets. Nothing in it is
// rewritten but the bootstrap before it (fetchPage): the data is answered,
// not the page.
type consoleFetch struct {
	cfg      *Config
	signer   *Signer
	upstream *url.URL
	webKey   string
	cookie   string
	proxy    *httputil.ReverseProxy
	client   *http.Client
	// person is whether the console is a person's own (the portal's own
	// page's, with its sidebar and its own data) or the admin's: magpie's
	// console as magpie draws it, with the portal's management pages
	// beside it. One portal serves one kind.
	person bool
	// signIn is the console's cookie, got by signing in to magpie web.
	signIn *consoleCookie
}

// consoleCookie is magpie web's key cookie, kept for a while: signing in is
// a request of its own, and every one of a page's files would ask for it.
type consoleCookie struct {
	upstream *url.URL
	webKey   string
	ttl      time.Duration
	mu       sync.Mutex
	at       time.Time
	value    string
}

// get is the cookie, signing in for it when it is old or unknown. An empty
// answer is magpie web not taking the key.
func (c *consoleCookie) get(ctx context.Context) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != "" && time.Since(c.at) < c.ttl {
		return c.value
	}
	form := signInForm(c.webKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.upstream.Scheme+"://"+c.upstream.Host+consoleSignIn, strings.NewReader(form))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = c.upstream.Host
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "" || cookie.Value == "" {
			continue
		}
		c.value, c.at = cookie.Name+"="+cookie.Value, time.Now()
		return c.value
	}
	return ""
}

func newConsoleFetch(cfg *Config, signer *Signer) *consoleFetch {
	if cfg.ConsoleURL == "" {
		return nil
	}
	u, err := url.Parse(cfg.ConsoleURL)
	if err != nil {
		return nil
	}
	f := &consoleFetch{
		cfg: cfg, signer: signer, upstream: u,
		webKey: cfg.ConsoleWebKey, cookie: cfg.ConsoleCookie,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	// signed in to magpie web once, for the next few minutes: its sign-in
	// is the same answer for any route until the cookie's life runs out
	f.signIn = &consoleCookie{upstream: u, webKey: cfg.ConsoleWebKey, ttl: 5 * time.Minute}
	// The static files are magpie's, served as they are; every route that
	// is not a person's own is answered above, never forwarded.
	f.proxy = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("oidc portal: console fetch %s %s: %v", r.Method, r.URL.Path, err)
			writeText(w, http.StatusBadGateway, "magpie's console is not reachable.\n")
		},
	}
	return f
}

// HandlesWith says whether a path is magpie's console page and its files,
// for a person listFiles names: the page itself, its scripts, stylesheets
// and icons. It is only asked when the path is not a portal route.
func (f *consoleFetch) HandlesWith(path string, files map[string]bool) bool {
	if path == "/" || f.isPage(path) {
		return files["index.html"]
	}
	return files[strings.TrimPrefix(path, "/")]
}

// ServeHTTP serves a person's console: the page, its files, and their own
// data. An admin's console is magpie's own, every route of it: all is
// whether id is an admin of this deployment.
func (f *consoleFetch) ServeHTTP(w http.ResponseWriter, r *http.Request, id Identity, all bool) {
	if all && f.isAdminRoute(r) {
		f.serveAdmin(w, r)
		return
	}
	switch {
	case r.Method == http.MethodGet && f.isPage(r.URL.Path):
		f.servePage(w, r, id)
	case r.URL.Path == "/boot.js":
		f.serveBoot(w, r, id)
	case strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api":
		f.serveData(w, r, id)
	case strings.HasPrefix(r.URL.Path, "/wails/"):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "这个页面不需要它"})
	case strings.HasPrefix(r.URL.Path, "/v1/magpie/me"):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not here"})
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		f.serveFile(w, r)
	default:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "这个控制台只读"})
	}
}

// isAdminRoute says whether a request is to the page's API or the Wails
// runtime its page asks for: an admin's is magpie's own, any method and
// every route, and the portal's routes are never it.
func (f *consoleFetch) isAdminRoute(r *http.Request) bool {
	p := r.URL.Path
	if consoleRoutes[p] {
		return false
	}
	return strings.HasPrefix(p, "/api/") || p == "/api" || strings.HasPrefix(p, "/wails/")
}

// serveAdmin forwards a request to magpie's console as magpie answers it,
// signed in with the portal's web key.
func (f *consoleFetch) serveAdmin(w http.ResponseWriter, r *http.Request) {
	in := r.Clone(r.Context())
	in.RequestURI = ""
	in.URL.Scheme, in.URL.Host = f.upstream.Scheme, f.upstream.Host
	in.Host = f.upstream.Host
	if cookie, ok := f.consoleCookie(r); ok {
		in.Header.Set("Cookie", cookie)
	}
	f.proxy.ServeHTTP(w, in)
}

// isMine is whether the console serves the portal's own key page (我的密钥)
// at a path: never, since the page's key answers are theirs already (keys,
// usage), and the page's /mine is the portal's (server.go, mine).
func (f *consoleFetch) isMine(p string) bool {
	return false
}

// routes are the portal's own, which are never the console's.
var consoleRoutes = map[string]bool{
	"/healthz": true, "/login": true, "/logout": true, "/callback": true,
	"/admin": true, "/admin/user": true, "/admin/save": true, "/admin/reject": true,
	"/admin/disable": true, "/admin/enable": true, "/admin/remove": true, "/admin/rotate": true,
	"/me/rotate": true, "/key/rotate": true, "/request-access": true, "/cancel-request": true,
	"/rotate": true, "/hooks/approval": true, "/mine": true, "/v1/magpie/me": true, "/v1/magpie/me/": true,
	"/portal/page.js": true,
	// the portal's own pages in magpie's frame (magpiepage.go): none is
	// magpie's page's data, and none is served by its fetch
	"/admin/": true,
}

// assetFiles are magpie's own files a page of the portal's draws its frame
// with (magpiepage.go, magpiePageHead): none of them is the console's page,
// so none of them carries what a console's page is given (the person's
// boot.js, the portal's role), and each is served as magpie serves it.
var assetFiles = map[string]bool{
	"app.css": true, "omarchy.css": true, "plugins.css": true, "context.css": true,
	"theme.js": true, "omarchy.js": true, "fonts.js": true, "layout.js": true,
	"kernel.js": true, "compat.js": true, "i18n.js": true,
}

// favicon is magpie's own icon (index.html's), so the browser asks once for
// a built-in one it does not have.
func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{"icons/favicon.svg", "icons/apple-touch-icon.png", "favicon.svg"} {
		if b, err := readPageFile(name); err == nil {
			if strings.HasSuffix(name, ".png") {
				w.Header().Set("Content-Type", "image/png")
			} else {
				w.Header().Set("Content-Type", "image/svg+xml")
			}
			w.Header().Set("Cache-Control", "public, max-age=86400")
			_, _ = w.Write(b)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// assetFile is a path of one of those files.
func assetFile(p string) bool { return assetFiles[strings.TrimPrefix(p, "/")] }

// wants says whether a request is the console's rather than the portal's:
// its own routes, the page and its files, its API, and the Wails runtime
// its page asks for.
func (f *consoleFetch) wants(r *http.Request) bool {
	p := r.URL.Path
	if consoleRoutes[p] {
		return false
	}
	if strings.HasPrefix(p, "/portal/api/") || strings.HasPrefix(p, "/portal/") ||
		p == "/favicon.svg" || p == "/favicon.ico" || p == "/favicon.png" || assetFile(p) {
		return false
	}
	switch {
	case p == "/", strings.HasPrefix(p, "/api/"), p == "/api":
		return true
	case p == "/mine":
		return false // 我的密钥 is the portal's page
	case strings.HasPrefix(p, "/wails/"), strings.HasPrefix(p, "/_magpie/"):
		return true
	case strings.Contains(p, "."):
		return f.isFile(p)
	}
	return true
}

// isFile says whether a path is one of the page's own files.
func (f *consoleFetch) isFile(p string) bool {
	name := strings.TrimPrefix(p, "/")
	if !pageFileAllowed(name) {
		return false
	}
	if name == "boot.js" || name == "index.html" {
		return true
	}
	if _, ok := consolePage.files[name]; ok && !consolePage.at.IsZero() {
		return true
	}
	return fsFile(name)
}

// serve is the request for a signed-in person, or the sign-in for one who
// is not.
func (f *consoleFetch) serve(w http.ResponseWriter, r *http.Request) {
	sess, ok := f.signer.Session(r)
	if !ok {
		if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api") && !strings.HasPrefix(r.URL.Path, "/v1/") {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	id := identityOf(sess)
	f.ServeHTTP(w, r, id, f.cfg.IsAdmin(id))
}

// isPage is the console's index.html: "/" and any of its own page paths
// (magpie's page draws every view at one address). An address with a file
// extension is a file.
func (f *consoleFetch) isPage(path string) bool {
	if path == "/" {
		return true
	}
	if strings.Contains(path, ".") {
		return false
	}
	switch {
	case strings.HasPrefix(path, "/api"), strings.HasPrefix(path, "/boot.js"),
		strings.HasPrefix(path, "/plugins/"), strings.HasPrefix(path, "/icons/"):
		return false
	}
	return true
}

// serveFile is one of magpie's own files, unchanged: scripts, stylesheets,
// icons and fonts, which name nothing of anyone's.
func (f *consoleFetch) serveFile(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme, out.URL.Host = f.upstream.Scheme, f.upstream.Host
	out.Header = http.Header{"Accept-Encoding": {"identity"}}
	if rr := r.Header.Get("Range"); rr != "" {
		out.Header.Set("Range", rr)
	}
	if cookie, ok := f.consoleCookie(r); ok {
		out.Header.Set("Cookie", cookie)
	}
	out.Host = f.upstream.Host
	resp, err := f.client.Do(out)
	if err != nil {
		writeText(w, http.StatusBadGateway, "magpie's console is not reachable.\n")
		return
	}
	defer resp.Body.Close()
	h := w.Header()
	for _, k := range []string{"Content-Type", "Content-Length", "Cache-Control", "ETag", "Last-Modified", "Content-Range", "Accept-Ranges"} {
		if v := resp.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// get fetches an upstream path with the console's web key, the way the
// console's own signed-in page does, and returns the JSON it answered.
func (f *consoleFetch) get(r *http.Request, path string, q url.Values) (map[string]any, error) {
	if q == nil {
		q = url.Values{}
	}
	q.Del("k")
	u := f.upstream.Scheme + "://" + f.upstream.Host + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	cookie, ok := f.consoleCookie(r)
	if !ok {
		return nil, errWebKey
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxConsoleJSON))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamError{status: resp.StatusCode, body: string(b)}
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}

var errWebKey = &upstreamError{status: http.StatusBadGateway, body: "magpie web did not take MAGPIE_WEB_KEY"}

type upstreamError struct {
	status int
	body   string
}

func (e *upstreamError) Error() string { return "upstream: " + strconv.Itoa(e.status) + " " + e.body }

// serveData answers /api/... for a person: their own key's state, their
// own usage, what magpie knows of their own key, and nothing of anyone
// else's. An answer not in the table is a 404 in this deployment's words.
func (f *consoleFetch) serveData(w http.ResponseWriter, r *http.Request, id Identity) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "这个控制台只读"})
		return
	}
	u, ok := f.personKey(id)
	var body any
	var err error
	switch path := r.URL.Path; {
	case path == "/api/usage":
		body, err = f.usage(r)
	case path == "/api/usage/requests":
		body, err = f.requests(r)
	case path == "/api/usage/heatmap":
		body, err = f.heatmap(r)
	case path == "/api/caller-keys":
		body, err = f.keys(u, ok)
	case path == "/api/usage/quotas":
		body = map[string]any{"quotas": []any{}, "refreshedAt": ""}
	case path == "/api/usage/quotas/history":
		body = map[string]any{}
	case path == "/api/fonts":
		body = map[string]any{"fonts": []any{}}
	case path == "/api/masking/summary":
		body = map[string]any{"days": 0, "values": []any{}, "calls": 0}
	case path == "/api/plugins/updates", path == "/api/plugin-panels", path == "/api/plugin-pages":
		body = map[string]any{}
	case path == "/api/providers", path == "/api/providers/arrange":
		// what magpie's page reads at every start, and the Gateway page's
		// 更新: who providers are is the deployment's, and a person is
		// shown none. What the page says of the gateway is the person's to
		// see: its address is the gateway this portal fronts. The lists are
		// the page's own empty ones.
		gw, _ := f.get(r, "/api/state", nil)
		gateway, _ := gw["gateway"].(map[string]any)
		if gateway == nil {
			gateway = map[string]any{}
		}
		// the view draws each list it reads without asking whether it is
		// there: none of them, not nil (the routing groups a person is not
		// shown, nor the calls of the whole deployment, nor its models)
		for _, k := range []string{"calls", "groups", "lanes"} {
			if _, ok := gateway[k]; !ok {
				gateway[k] = []any{}
			}
		}
		body = map[string]any{"providers": []any{}, "presets": []any{}, "excluded": []any{}, "gateway": gateway}
	case path == "/api/upstream":
		body = map[string]any{"upstream": []any{}, "pool": []any{}}
	case path == "/api/caller-keys/models":
		body, err = f.keyModels(r)
	case path == "/api/groups":
		body = map[string]any{"groups": []any{}}
	case path == "/api/state":
		body, err = f.state(r, id)
	case path == "/api/settings":
		var v map[string]any
		v, err = f.get(r, "/api/settings", r.URL.Query())
		if err == nil {
			if st, ok := v["settings"].(map[string]any); ok {
				st["lang"] = "zh"
			}
		}
		body = v
	case path == "/api/icon-http-failed":
		body = map[string]any{}
	case path == "/api/gateway/trace":
		// the Gateway view keeps reading the routing it shows; a person
		// sees none of the deployment's, so there is no routing to read
		body = map[string]any{"seq": 0, "routes": []any{}, "totals": map[string]int{},
			"mine": false, "now": time.Now().UTC(), "paused": false}
	case path == "/api/update", path == "/api/update/check":
		// this deployment's magpie is the portal's to update, not a
		// person's: theirs is always the latest
		body = map[string]any{"state": "latest", "current": ""}
	case path == "/api/whatsnew":
		body = map[string]any{"releases": []any{}, "unread": 0}
	case path == "/api/agents/cli":
		// the agents of this computer are the deployment's
		body = map[string]any{"agents": map[string]any{}, "pending": false}
	case path == "/api/agents/install":
		body = []any{}
	case path == "/api/plugins/agents":
		body = []any{}
	case path == "/api/cli":
		// the command a new terminal would run is this deployment's
		body = map[string]any{"ours": false, "command": "", "shells": []any{}, "windows": false}
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "这个页面不在门户的控制台里"})
		return
	}
	if err != nil {
		if ue, ok := err.(*upstreamError); ok && ue == errWebKey {
			log.Printf("oidc portal: console %s: magpie web did not take MAGPIE_WEB_KEY", r.URL.Path)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "门户和 magpie 的控制台密钥不一致（MAGPIE_WEB_KEY）"})
			return
		}
		log.Printf("oidc portal: console %s: %v", r.URL.Path, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "magpie 没有回答"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

// personKey is the signed-in person's gateway key, from the portal's state.
func (f *consoleFetch) personKey(id Identity) (User, bool) {
	u, ok := f.cfg.state.GetAny(id.Subject)
	if !ok || u.Key == "" || u.Disabled {
		return User{}, false
	}
	return u, true
}

// who is the signed-in person's identity, for the routes answered here.
func (f *consoleFetch) who(r *http.Request) Identity {
	sess, ok := f.signer.Session(r)
	if !ok {
		return Identity{}
	}
	return identityOf(sess)
}

// usage is /api/usage: magpie's own summary of a key's calls, built from
// magpie's usage log (magpie's page's own builder) and cut to the person's
// key: its totals, its models, its limit's use, and none of the other
// keys, accounts or sessions the log names.
func (f *consoleFetch) usage(r *http.Request) (any, error) {
	u, ok := f.personKey(f.who(r))
	if !ok {
		return nil, errNoKey
	}
	return personUsage(u.KeyID, usageapi.PageIn(usageapi.PeriodOf(r.URL.Query().Get("period")), usageapi.ZoneOf(r))), nil
}

// personUsage is s, magpie's summary of the period, cut to the person's
// key: the accounts and sessions it names are not theirs to see, and the
// keys list is theirs alone.
func personUsage(keyID string, s usageapi.Usage) usageapi.Usage {
	s.Accounts = []usageapi.Group{}
	s.Sessions = []usage.Group{}
	s.SessionCount = 0
	mine := make([]usageapi.Group, 0, 1)
	for _, g := range s.CallerKeys {
		if g.CallerKeyID == keyID {
			mine = append(mine, g)
		}
	}
	s.CallerKeys = mine
	return s
}

// keyGet asks the gateway a route that answers a key's own data, with that
// key as the bearer.
func (f *consoleFetch) keyGet(r *http.Request, key, path string, q url.Values) ([]byte, error) {
	gw := f.cfg.GatewayURL
	if gw == "" {
		return nil, errNoGateway
	}
	u := gw + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxConsoleJSON))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamError{status: resp.StatusCode, body: string(b)}
	}
	return b, nil
}

var (
	errNoKey     = &upstreamError{status: http.StatusForbidden, body: "no key"}
	errNoGateway = &upstreamError{status: http.StatusBadGateway, body: "no gateway_url"}
)

// requests is /api/usage/requests, the Requests page's ledger: magpie's
// own ledger of the person's calls, built from the same usage log magpie's
// page reads (/api/usage/requests) and narrowed to the person's key, with
// magpie's own cut of the filter lists (usageapi.OwnPage). The filters the
// page sends are kept; one it does not send is the person's key.
func (f *consoleFetch) requests(r *http.Request) (any, error) {
	u, ok := f.personKey(f.who(r))
	if !ok {
		return nil, errNoKey
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := usageapi.FilterOf(q)
	filter.CallerKey = u.KeyID
	page := usageapi.LedgerPage(usageapi.PeriodOf(q.Get("period")), filter, offset, limit)
	return usageapi.OwnPage(page, u.KeyID), nil
}

// heatmap is /api/usage/heatmap: the person's calls by day.
func (f *consoleFetch) heatmap(r *http.Request) (any, error) {
	u, ok := f.personKey(f.who(r))
	if !ok {
		return nil, errNoKey
	}
	filter := usageapi.FilterOf(r.URL.Query())
	filter.Zone = usageapi.ZoneOf(r)
	filter.CallerKey = u.KeyID
	return usage.HeatmapOf(filter), nil
}

// keys is /api/caller-keys: the person's own key only, as the Gateway page
// lists keys, with its limit and what it has used of it. Never the secret:
// the owner copies that from their own page, through the portal.
func (f *consoleFetch) keys(u User, ok bool) (any, error) {
	if !ok {
		return nil, errNoKey
	}
	all, err := access.List()
	if err != nil {
		return nil, err
	}
	var mine *access.Key
	for i := range all {
		if all[i].ID != u.KeyID {
			continue
		}
		k := all[i]
		k.Secret = ""
		mine = &k
	}
	out := map[string]any{"keys": []any{}, "accountNames": map[string]string{}}
	if mine == nil {
		return out, nil
	}
	row := map[string]any{}
	b, _ := json.Marshal(mine)
	_ = json.Unmarshal(b, &row)
	used := budget.All(*mine, time.Now())
	row["usedAll"] = used
	if len(used) > 0 {
		row["used"] = used[0]
	}
	out["keys"] = []any{row}
	return out, nil
}

// keyModels is /api/caller-keys/models: what a key may be held to, as the
// picker lists it. The person's own key may be held to no account or key,
// so none is offered; the groups and models magpie knows are.
func (f *consoleFetch) keyModels(r *http.Request) (any, error) {
	v, err := f.get(r, "/api/caller-keys/models", nil)
	if err != nil {
		return nil, err
	}
	if m, ok := v["models"].([]any); ok {
		v["models"] = m
	} else {
		v["models"] = []any{}
	}
	v["accounts"] = []any{}
	return v, nil
}

// state is /api/state: what the page draws before its data — its language,
// its theme, and the gateway's line. None of it is anyone's: the settings
// are the deployment's, and the sidebar's line names the gateway this
// portal brings the person to, which is the console itself.
func (f *consoleFetch) state(r *http.Request, id Identity) (any, error) {
	v, err := f.get(r, "/api/state", r.URL.Query())
	if err != nil {
		return nil, err
	}
	if _, ok := v["settings"]; ok {
		set, _ := v["settings"].(map[string]any)
		if set == nil {
			set = map[string]any{}
			v["settings"] = set
		}
		set["lang"] = "zh"
	}
	v["portal"] = map[string]any{"email": id.Email, "name": id.Name, "sub": id.Subject}
	return v, nil
}

// signInForm is magpie web's sign-in form: its key, and where back to.
func signInForm(webKey string) string {
	return url.Values{"key": {webKey}, "back": {"/"}}.Encode()
}

// consoleCookie is the console's cookie, signed in for once for the next
// few minutes (f.signIn), or by pendingCache when the fetch has none.
func (f *consoleFetch) consoleCookie(r *http.Request) (string, bool) {
	if f.signIn != nil {
		v := f.signIn.get(r.Context())
		return v, v != ""
	}
	pendingCache.mu.Lock()
	if pendingCache.upstream == nil {
		pendingCache.upstream, pendingCache.webKey = f.upstream, f.webKey
	}
	pendingCache.mu.Unlock()
	v := pendingCache.get(r.Context())
	return v, v != ""
}

// pendingCache is the console's cookie for a fetch that has none of its
// own.
var pendingCache = &consoleCookie{}
