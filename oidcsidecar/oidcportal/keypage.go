package oidcportal

import (
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/usage"
)

// keyPageDataPath is the route magpie's page asks for its own data
// (internal/gateway/key_page.go); the portal answers it at the same path, so
// the page's script asks it unchanged. It is the portal's even when the
// console is configured: the console proxy leaves it to the portal.
const keyPageDataPath = "/v1/magpie/me"

// The page a person sees after signing in is magpie's own: the file its
// gateway serves at /me (internal/gateway/keypage.html), kept here rather
// than drawn again, so the portal cannot drift from the app. Its Copy,
// Refresh and Rotate are magpie's own logic. The page asks its gateway
// address plus /v1/magpie/me for its data; that address is the portal, which
// answers (meData) with the gateway's own word about the person's key.
// Rotate asks /key/rotate, because the page's own Rotate is drawn in
// magpie's page for a key its holder types: keyRotate is the same call.
//
//go:embed keypage.html
var keyPageHTML []byte

// keyPage is magpie's keypage.html, changed in one place only: the gateway
// address its setup snippets name, which magpie takes from the page's path
// ("/me"). The page is opened at /key here.
//
// A second change: the portal's browser has signed in for (the OIDC
// session), so the key is not typed here: the page asks for it
// (/portal/api/my-key) and looks it up as magpie's page does when a tab kept
// it, and only the person signed in for is handed it.
var keyPage = []byte(strings.Replace(strings.Replace(string(keyPageHTML),
	`const BASE = location.origin + location.pathname.replace(/\/me\/?$/, "");`,
	`const BASE = location.origin;`, 1),
	`const STORE = "magpie-key";`,
	`const STORE = "magpie-key";
// the key of the person signed in here: the portal hands it to its own page
async function stored() { try { const r = await fetch("/portal/api/my-key", { credentials: "same-origin", cache: "no-store" }); if (!r.ok) return ""; const j = await r.json(); store.set(j.key || ""); return j.key || ""; } catch (e) { return ""; } }`, 1))

func init() {
	// the tab's key is the signed-in person's, handed over by stored():
	// without one it is asked for first
	keyPage = []byte(strings.Replace(string(keyPage),
		`  const k = store.get();
  if (!k) `,
		`  var k = store.get();
  if (!k) k = await stored();
  if (!k) `, 1))
	// magpie's page asks its gateway with no cookies, the key alone; here
	// the person is signed in by cookie to the portal, and the key read for
	// them is the session's own (meData)
	keyPage = []byte(strings.Replace(string(keyPage),
		`credentials: "omit"`,
		`credentials: "same-origin"`, 1))
}

// meData is GET /v1/magpie/me, what magpie's key page asks for: the
// signed-in person's key's own name, limits and usage, from the gateway
// when the portal can ask it (keyData, which the portal's browser cannot:
// see console), and from the portal's record of the key when it cannot.
// Nothing in it is another key's. A bearer that isn't this key, sent from
// another site, is 401 as the gateway would answer it.
func (s *Server) meData(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	if r.URL.Query().Has("key") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the key goes in Authorization, never the address"})
		return
	}
	id := identityOf(sess)
	u, ok := s.state.GetAny(id.Subject)
	if !ok || u.Key == "" || u.Disabled {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no enabled key"})
		return
	}
	// The page's tab keeps its key; one from before a rotation is not this
	// key, and magpie's answer to it is the same "not enabled". The page
	// asking is the portal's own (Sec-Fetch-Site); one another site gives
	// a key is 401.
	if b := requestBearer(r); b != "" && b != u.Key && (r.Header.Get("Sec-Fetch-Site") == "cross-site" || !sameOrigin(r)) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not this key"})
		return
	}
	v := s.keyUsage(u)
	if out, status, err := s.keyData(r, u.Key); err == nil && status == http.StatusOK && len(out) > 0 && out[0] == '{' {
		var gw map[string]any
		if json.Unmarshal(out, &gw) == nil {
			if gw["name"] == nil || gw["name"] == "" {
				gw["name"] = v["name"]
			}
			gw["baseURL"] = s.siteBase()
			out, _ = json.Marshal(gw)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(out)
			return
		}
	}
	body, _ := json.Marshal(v)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// keyData asks the running gateway about key, as magpie's page does: the
// same route with the same bearer, and the gateway's own answer. What it
// says of a key is that key's: its limits, its usage, the models it may
// use, never another key's, an account's or a provider's secret.
func (s *Server) keyData(r *http.Request, key string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.cfg.GatewayURL+keyPageDataPath, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}
	return b, resp.StatusCode, nil
}

// keyRotate is POST /key/rotate, the page's own Rotate, sent there because
// the page's tab keeps the portal's address: magpie's rotate-key on this
// person's key, the same call magpie's own Rotate makes from its page. The
// key id stays; only the person's own value changes.
func (s *Server) keyRotate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok || !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not signed in from this page"})
		return
	}
	id := identityOf(sess)
	u, err := s.prov.Rotate(id.Subject)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit.Log(personOf(Policy{Email: id.Email, Sub: id.Subject}), "rotate", u.Sub, "key page")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"key": u.Key, "keyId": u.KeyID})
}

// siteBase is the portal's own address, less any path: where a person
// reaches this gateway, and what their agents are given.
func (s *Server) siteBase() string {
	if u, err := url.Parse(s.cfg.RedirectURL); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return s.cfg.GatewayURL
}

// keyUsage is the key page's data: the key's limits and usage over today, 7
// and 30 days, its top models, and the models it may use, as magpie's page
// draws them. The sums are magpie's own (usage.Summarize, as its gateway
// answers with); what is said of the key is the person's own record of it
// and its sums: never another key's, an account's or a provider's.
func (s *Server) keyUsage(u User) map[string]any {
	sums := map[string]any{}
	for _, p := range []usage.Period{usage.Today, usage.Week, usage.Month} {
		sums[string(p)] = usage.Summarize(p).Totals
	}
	top := []any{}
	seen := map[string]bool{}
	for _, g := range usage.Summarize(usage.Month).Models {
		if len(top) >= 8 || g.Model == "" || seen[g.Model] {
			continue
		}
		seen[g.Model] = true
		// as magpie's key page reads a model's sums: its own fields, top level
		row, _ := json.Marshal(g.Totals)
		m := map[string]any{"id": g.Model, "provider": g.Provider, "model": g.Model}
		_ = json.Unmarshal(row, &m)
		top = append(top, m)
	}
	return map[string]any{
		"name": u.Name, "readOnly": false, "limits": []any{},
		"usage": sums, "topModels": top, "models": s.keyModels(), "baseURL": s.siteBase(),
	}
}

// keyModels are the models a key may use, as the key page lists them (id
// and label), from magpie's catalog: its groups, then every model on.
func (s *Server) keyModels() []any {
	out := []any{}
	groups, models := provider.Groups(), provider.Catalog()
	for _, g := range groups {
		out = append(out, map[string]string{"id": "group/" + g.ID, "label": g.Name})
	}
	labels := provider.Labels(models)
	for i, m := range models {
		out = append(out, map[string]string{"id": m.ID, "label": labels[i]})
	}
	return out
}

// requestBearer is the key a request to the key page's route carries.
func requestBearer(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		if rest, ok := strings.CutPrefix(v, "Bearer "); ok {
			return rest
		}
		if rest, ok := strings.CutPrefix(v, "bearer "); ok {
			return rest
		}
	}
	return r.Header.Get("x-api-key")
}
