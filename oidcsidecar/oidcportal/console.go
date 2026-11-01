package oidcportal

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// consolePrefix is where magpie's own web console appears: the page at
// /console/, its relative assets below it, and its absolute /api and
// /wails paths beside it.
const consolePrefix = "/console"

// maxConsoleJSON bounds a console JSON answer the proxy will read to scrub
// it. The state answer is the big one; 64 MiB is far past a deployment of
// a hundred people.
const maxConsoleJSON = 64 << 20

// maxConsolePage bounds the page the proxy rewrites and the key page's
// answer. The app's page is a few hundred kilobytes.
const maxConsolePage = 16 << 20

// ConsoleProxy fronts magpie's web console without changing magpie: it
// authenticates the portal's own session, injects the console's web key
// upstream (the browser never sees it), and holds every role to the paths
// it may use. Ordinary admins may read and write the six areas the portal
// grants them; request bodies and key secrets are withheld from everyone,
// super admins included.
type ConsoleProxy struct {
	cfg      *Config
	signer   *Signer
	upstream *url.URL
	webKey   string
	cookie   string
	proxy    *httputil.ReverseProxy
	client   *http.Client
}

// NewConsoleProxy builds the proxy for cfg.ConsoleURL; nil when the console
// is not configured, which leaves /console and /api to the portal (404).
func NewConsoleProxy(cfg *Config, signer *Signer) *ConsoleProxy {
	if cfg.ConsoleURL == "" {
		return nil
	}
	u, err := url.Parse(cfg.ConsoleURL)
	if err != nil {
		return nil
	}
	p := &ConsoleProxy{
		cfg: cfg, signer: signer, upstream: u,
		webKey: cfg.ConsoleWebKey, cookie: cfg.ConsoleCookie,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	p.proxy = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
		},
		ModifyResponse: p.modify,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("oidc portal: console proxy %s %s: %v", r.Method, r.URL.Path, err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("magpie's console is not reachable.\n"))
		},
	}
	return p
}

// Handles says whether a path belongs to the console rather than the
// portal: the console page and its relative assets, its absolute API, the
// Wails runtime its page asks for, and its plugin frames.
const (
	// consoleSignIn is magpie web's own sign-in, where a page turned away
	// for want of its key takes the key pasted: the portal signs itself in
	// there before serving any page.
	consoleSignIn = "/_magpie/sign-in"
	// consoleKeyPage is where the Gateway page's "密钥持有人可在此查看" leads
	// the keys' holders: its own page, not /me.
	consoleKeyPath = "/key"
)

func (p *ConsoleProxy) Handles(path string) bool {
	switch {
	case path == keyPageDataPath:
		return false // the portal's own: the signed-in person's key, never the console's
	case path == consoleSignIn:
		return true
	case path == consoleKeyPath || path == consoleKeyPath+"/":
		return true
	case path == "/me" || path == "/me/":
		return true
	case path == consolePrefix || strings.HasPrefix(path, consolePrefix+"/"):
		return true
	case path == "/api" || strings.HasPrefix(path, "/api/"):
		return true
	case strings.HasPrefix(path, "/wails/"):
		return true
	case strings.HasPrefix(path, "/_magpie/"):
		return true
	case strings.HasPrefix(path, "/v1/magpie/"):
		return true // the key page's data
	}
	return false
}

// signIn asks magpie web for its key cookie with MAGPIE_WEB_KEY, the way
// its sign-in form does: every page and API answer below then comes with
// the web key, and an answer that still turns the request away means the
// two keys are not the same.
func (p *ConsoleProxy) signIn(r *http.Request) (string, bool) {
	form := url.Values{"key": {p.webKey}, "back": {"/"}}.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		p.upstream.Scheme+"://"+p.upstream.Host+consoleSignIn, strings.NewReader(form))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = p.upstream.Host
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	resp.Body.Close()
	// magpie web's sign-in sets one cookie, its key's, under the name of the
	// port it serves: that cookie is the sign-in, whatever the config says
	// console_cookie is
	for _, cookie := range resp.Cookies() {
		if cookie.Value == "" || cookie.Name == "" {
			continue
		}
		return cookie.Name + "=" + cookie.Value, true
	}
	return "", false
}

func (p *ConsoleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == consoleSignIn {
		// magpie web's sign-in is the portal's to make, never the browser's
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == consolePrefix {
		// A trailing slash makes the page's relative assets resolve below
		// /console/ rather than at the site's root.
		http.Redirect(w, r, consolePrefix+"/", http.StatusMovedPermanently)
		return
	}
	sess, ok := p.signer.Session(r)
	if !ok {
		if p.document(r) {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	id := identityOf(sess)
	if !p.cfg.IsAdmin(id) {
		if p.document(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this page is for the portal's admins"})
		return
	}
	up := p.upstreamPath(r.URL.Path)
	keyID := ""
	if !strings.HasPrefix(up, "/api/") && up != "/api" && !strings.HasPrefix(up, "/wails/") {
		keyID = p.cfg.KeyIDFor(id)
	}
	if !consoleAllowed(p.cfg.IsSuperAdmin(id), up, r.Method, keyID) {
		if r.Method == http.MethodGet {
			p.refuse(w, r)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this console path is not allowed for your role"})
		return
	}
	if r.Method == http.MethodGet && p.document(r) {
		p.page(w, r, id)
		return
	}
	p.data(w, r, id, up, keyID != "")
}

// data forwards an API answer. Every request is sent the way magpie web's
// own signed-in page sends it: with the web key's cookie, which the portal
// gets by signing in for it. The key page's answers take the admin's own
// gateway key as the bearer, which the browser never supplies.
func (p *ConsoleProxy) data(w http.ResponseWriter, r *http.Request, id Identity, up string, keyPage bool) {
	cookie, ok := p.signIn(r)
	if !ok {
		log.Printf("oidc portal: console %s %s: magpie web did not take MAGPIE_WEB_KEY", r.Method, up)
		writeText(w, http.StatusBadGateway, "magpie web did not take the console's key: MAGPIE_WEB_KEY in the portal and in magpie must be the same.\n")
		return
	}
	out := r.Clone(r.Context())
	out.Header = r.Header.Clone()
	out.Header.Del("Authorization")
	out.Header.Set("Cookie", cookie)
	if keyPage {
		if k := p.cfg.ConsoleKeyFor(id); k != "" {
			out.Header.Set("Authorization", "Bearer "+k)
		}
	}
	out.URL.Path = up
	out.URL.RawPath = ""
	q := out.URL.Query()
	q.Del("k") // the console's own sign-in link is never the browser's
	out.URL.RawQuery = q.Encode()
	// Uncompressed answers are scrubbed below; asking upstream for them is
	// cheaper than decompressing every one.
	out.Header.Set("Accept-Encoding", "identity")
	out.Host = r.Host // links the console makes keep the public address
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", requestScheme(r))
	p.proxy.ServeHTTP(w, out)
}

func (p *ConsoleProxy) document(r *http.Request) bool {
	up := p.upstreamPath(r.URL.Path)
	if up == "/" {
		return true
	}
	switch {
	case strings.HasPrefix(up, "/api"),
		strings.HasPrefix(up, "/wails/"),
		strings.HasPrefix(up, "/_magpie/"):
		return false
	}
	if strings.HasPrefix(up, "/me") {
		return true
	}
	return !strings.Contains(up, ".")
}

// page serves magpie's page with console-zh.js added: the page's language
// is Chinese here, and the lines its Gateway and Settings pages draw as
// plain HTML are answered from zhConsole.
func (p *ConsoleProxy) page(w http.ResponseWriter, r *http.Request, id Identity) {
	out := r.Clone(r.Context())
	out.RequestURI = "" // a client request carries none
	out.URL.Scheme, out.URL.Host = p.upstream.Scheme, p.upstream.Host
	out.URL.Path = p.upstreamPath(r.URL.Path)
	out.URL.RawPath = ""
	out.URL.RawQuery = r.URL.RawQuery
	cookie, ok := p.signIn(r)
	if !ok {
		writeText(w, http.StatusBadGateway, "magpie web did not take the console's key: MAGPIE_WEB_KEY in the portal and in magpie must be the same.\n")
		return
	}
	out.Header = http.Header{}
	out.Header.Set("Cookie", cookie)
	out.Header.Set("Accept", "")
	out.Header.Set("Accept-Encoding", "identity")
	out.Host = r.Host
	resp, err := p.client.Do(out)
	if err != nil {
		log.Printf("oidc portal: console page %s: %v", out.URL.Path, err)
		writeText(w, http.StatusBadGateway, "magpie's console is not reachable.\n")
		return
	}
	header := w.Header()
	for _, h := range []string{"Content-Type", "Content-Security-Policy"} {
		if v := resp.Header.Get(h); v != "" {
			header.Set(h, v)
		}
	}
	header.Set("X-Content-Type-Options", "nosniff")
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxConsolePage+1))
	if err != nil || len(b) > maxConsolePage {
		header.Del("Content-Type")
		writeText(w, http.StatusBadGateway, "magpie's console answered a page too large to read.\n")
		return
	}
	// The key page picks its language from the browser's, and the browser
	// here may be English: the page is Chinese in the portal.
	b = bytes.ReplaceAll(b, []byte(`<html lang="en">`), []byte(`<html lang="zh-CN">`))
	page := p.withConsoleScript(b, id)
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Length", strconv.Itoa(len(page)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(page)
}

// writeText answers a plain-text note, for the console's own failures.
func writeText(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

// withConsoleScript puts the page's Chinese before its own scripts draw it,
// and the signed-in admin's own key and key id with it.
func (p *ConsoleProxy) withConsoleScript(page []byte, id Identity) []byte {
	// whose console this is: the page's own boot.js says it (oidcPerson),
	// and this script says the same, as the page's lines before it are
	person := oidcPerson(id, User{KeyID: p.cfg.KeyIDFor(id)}, nil)
	script := []byte(`<script id="oidc-zh">` + person + fmt.Sprintf(zhConsoleJS,
		objJSON(zhConsole), p.upstream.Scheme+"://"+p.upstream.Host,
		p.cfg.KeyIDFor(id), keyNameFor(p.cfg.KeyNamePrefix, id), p.cfg.ConsoleKeyFor(id)) + `</script>`)
	if i := bytes.Index(page, []byte("</head>")); i >= 0 {
		return append(append(append([]byte(nil), page[:i]...), script...), page[i:]...)
	}
	return append(script, page...)
}

// refuse is the page a role may not open: it says so in the portal's
// words, rather than magpie's own, and offers the way back.
func (p *ConsoleProxy) refuse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, `<html lang="zh-CN"><meta charset="utf-8"><title>没有权限</title>
<style>body{font:15px -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#f4f4f6;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;border-radius:12px;padding:32px 40px;box-shadow:0 1px 2px rgba(0,0,0,.04);max-width:520px}
h1{font-size:20px;margin:0 0 8px}p{color:#6b6b70;margin:0 0 16px;line-height:1.6}a{color: #5b4be8}</style>
<main><h1>这个页面不属于你的角色</h1><p>你可以看哪些控制台页面由门户决定。密钥内容由本人复制，请求和响应正文请在 Langfuse 查看。</p>
<p><a href="/">回到我的密钥</a> · <a href="/admin">门户管理</a></p></main></html>`)
}

func (p *ConsoleProxy) upstreamPath(path string) string {
	if path == consolePrefix+"/" || path == consoleKeyPath || path == consoleKeyPath+"/" {
		return "/"
	}
	if strings.HasPrefix(path, consolePrefix+"/") {
		return strings.TrimPrefix(path, consolePrefix)
	}
	return path
}

// consoleAllowed is the role's path and method table. It is an allow list:
// an API path this version does not know is refused, so a new endpoint in a
// newer magpie cannot quietly widen an admin's reach.
func consoleAllowed(super bool, path, method string, keyID string) bool {
	get := method == http.MethodGet || method == http.MethodHead
	if strings.HasPrefix(path, "/console/") {
		return get
	}
	// The key page magpie serves at /me, and the answers it asks for, work
	// on the caller's own gateway key, always the one the portal made
	// them: it reaches no other key, no account and no secret.
	if keyID != "" {
		if kind, ok := keyPageRoute(path); ok && get {
			return kind == keyPageAny || super || ordinaryConsoleAllowed(path, method)
		}
	}
	if strings.HasPrefix(path, "/wails/") {
		return method == http.MethodGet || method == http.MethodHead
	}
	if strings.HasPrefix(path, "/_magpie/") {
		if strings.HasPrefix(path, "/_magpie/sign-in") {
			return false
		}
		return super // plugin frames are not part of the six admin areas
	}
	if path != "/api" && !strings.HasPrefix(path, "/api/") {
		// The console's own page and its relative assets (app.js, app.css,
		// plugins/…): static files, no data behind them.
		return method == http.MethodGet || method == http.MethodHead
	}
	if consoleBlocked(path) {
		return false
	}
	if super {
		return true
	}
	return ordinaryConsoleAllowed(path, method)
}

const (
	keyPageAny     = iota // the caller's own key and its usage: any admin
	keyPageGranted        // beside the caller's own: what their role already may read
)

// keyPageRoute is the key page's data routes (internal/gateway/key_page.go):
// the bearer is the portal's key for this admin, so the answer is that
// key's own. A result of keyPageGranted sits between the two roles: an
// ordinary admin only where the six areas already reach.
func keyPageRoute(path string) (int, bool) {
	switch path {
	case "/v1/magpie/me", "/v1/magpie/me/usage":
		return keyPageAny, true
	case "/api/model-speeds", "/api/usage", "/api/usage/requests":
		return keyPageGranted, true
	}
	return 0, false
}

// consoleBlocked names the answers that would give away a gateway key or a
// request or response body. They are refused for every role: the key is the
// owner's to copy in the portal, and bodies are read in Langfuse.
func consoleBlocked(path string) bool {
	switch path {
	case "/api/gateway/call", // request and response bodies
		"/api/usage/requests/content", // a request's body
		"/api/caller-keys/copy-key",   // any key's full value
		"/api/caller-keys/add-key",    // a new key's full value
		"/api/caller-keys/rotate-key", // the new value, in the answer
		"/api/gateway/held/reveal",
		"/api/library/reveal",
		"/api/masking/value",
		"/api/plugin-pages/read",
		"/api/web-page",
		"/api/context/text",
		"/api/settings/search-key", // returns a saved search API key
		"/api/settings/archive",    // turning body capture on
		"/api/config/repair":
		return true
	}
	for _, prefix := range []string{
		"/api/archive",
		"/api/backup/",
		"/api/davsync/",
		"/api/sessions/transcript",
		"/api/sessions/one",
		"/api/sessions/markdown",
		"/api/sessions/export",
		"/api/sessions/reads",
		"/api/keys/",
		"/api/import/",
		"/api/dev/",
	} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ordinaryConsoleAllowed is the six areas an ordinary admin may read and
// write: library, providers, gateway, usage overview, masking and settings.
func ordinaryConsoleAllowed(path, method string) bool {
	get := method == http.MethodGet || method == http.MethodHead
	switch {
	case path == "/api/state", path == "/api/upstream", path == "/api/lanes",
		path == "/api/model-speeds", path == "/api/update",
		path == "/api/notices", path == "/api/whatsnew", path == "/api/fonts":
		return get
	case strings.HasPrefix(path, "/api/icons/"):
		return get
	case path == "/api/set":
		return method == http.MethodPost
	case path == "/api/library", strings.HasPrefix(path, "/api/library/"):
		return true
	case path == "/api/providers", strings.HasPrefix(path, "/api/providers/"),
		strings.HasPrefix(path, "/api/provider/"):
		return true
	case path == "/api/groups", strings.HasPrefix(path, "/api/groups/"):
		return true
	case path == "/api/gateway", strings.HasPrefix(path, "/api/gateway/"):
		return true
	case path == "/api/caller-keys", strings.HasPrefix(path, "/api/caller-keys/"):
		return true
	case path == "/api/usage", strings.HasPrefix(path, "/api/usage/"):
		return true
	case path == "/api/masking", strings.HasPrefix(path, "/api/masking/"):
		return true
	case path == "/api/settings", strings.HasPrefix(path, "/api/settings/"):
		return true
	}
	return false
}

// modify strips what the proxy must never pass to a browser: the console's
// own sign-in cookie, and the fields that carry a key or a body.
func (p *ConsoleProxy) modify(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", p.rewriteLocation(loc))
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified || resp.Request != nil && resp.Request.Method == http.MethodHead {
		return nil
	}
	var body io.Reader = resp.Body
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gz.Close()
		body = gz
	}
	b, err := io.ReadAll(io.LimitReader(body, maxConsoleJSON+1))
	resp.Body.Close()
	if err != nil {
		return err
	}
	if len(b) > maxConsoleJSON {
		return fmt.Errorf("console answer is larger than %d bytes", maxConsoleJSON)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		resp.ContentLength = 0
		resp.Header.Set("Content-Length", "0")
		resp.Header.Del("Content-Encoding")
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		// A JSON answer that cannot be read cannot be scrubbed; refuse it
		// rather than pass bytes that might hold a key or a body.
		return fmt.Errorf("console answer is not JSON: %w", err)
	}
	scrubConsole(v)
	if b, err = json.Marshal(v); err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Header.Del("Content-Encoding")
	return nil
}

// scrubConsole removes the fields that carry secrets or bodies from any
// console answer, whichever endpoint produced it. The path table already
// refuses the endpoints that exist only to return them; this is the second
// line, for answers that carry one beside ordinary data.
func scrubConsole(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch strings.ToLower(k) {
			case "secret", "requestbody", "responsebody", "bodyin", "bodyout",
				"lankey", "webkey", "apikey", "accesstoken", "refreshtoken",
				"password", "privatekey":
				delete(x, k)
				continue
			}
			scrubConsole(val)
		}
	case []any:
		for _, e := range x {
			scrubConsole(e)
		}
	}
}

// rewriteLocation keeps a console redirect under the console's path: an
// upstream "/" would otherwise land the browser on the portal.
func (p *ConsoleProxy) rewriteLocation(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	if u.IsAbs() {
		if !strings.EqualFold(u.Host, p.upstream.Host) {
			return loc
		}
		u.Scheme, u.Host = "", ""
	}
	if u.Path == "/" || u.Path == "" {
		u.Path = consolePrefix + "/"
		return u.String()
	}
	return u.String()
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if p := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); p != "" {
		return p
	}
	return "http"
}
