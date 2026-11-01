package oidcportal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/budget"
	"github.com/yetone/magpie/internal/usage"
	"golang.org/x/oauth2"
)

const (
	sessionTTL = 12 * time.Hour
	flowTTL    = 10 * time.Minute
)

// Server is the portal's HTTP surface: sign in, apply for access, see your
// key and its usage, rotate it, and for an admin, decide who may use what.
type Server struct {
	cfg     *Config
	state   *State
	policy  *PolicyStore
	prov    *Provisioner
	oidc    OIDCProvider
	signer  *Signer
	console *ConsoleProxy
	fetch   *consoleFetch
	notify  Notifier
	audit   *Audit
	handler http.Handler
}

// NewServer builds the portal around an OIDC provider; NewProvider is the
// real one, a fake in tests.
func NewServer(cfg *Config, state *State, policy *PolicyStore, provider OIDCProvider) *Server {
	s := &Server{
		cfg:    cfg,
		state:  state,
		policy: policy,
		prov:   NewProvisioner(cfg, state),
		oidc:   provider,
		signer: NewSigner(cfg.CookieSecret, strings.HasPrefix(cfg.RedirectURL, "https://")),
		notify: NewNotifier(cfg.Notify),
		audit:  OpenAudit(AuditPath()),
	}
	cfg.state = state
	s.console = NewConsoleProxy(cfg, s.signer)
	if cfg.Fetch {
		s.fetch = newConsoleFetch(cfg, s.signer)
	}
	if s.fetch != nil {
		s.fetch.person = true
	}
	s.handler = s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	// magpie's page, drawn in magpie's own frame (magpiepage.go): its
	// files, and the portal's script that draws what the page says
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/portal/page.js":
			s.pageJS(w, r)
		case assetFile(r.URL.Path):
			s.assetFile(w, r)
		case r.URL.Path == "/favicon.ico":
			s.favicon(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /{$}", s.portal)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("POST /request-access", s.requestAccess)
	mux.HandleFunc("POST /cancel-request", s.cancelRequest)
	mux.HandleFunc("POST /rotate", s.rotate)
	mux.HandleFunc("POST /logout", s.logout)

	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /admin/user", s.adminUser)
	mux.HandleFunc("POST /admin/save", s.adminSave)
	mux.HandleFunc("POST /admin/reject", s.adminReject)
	mux.HandleFunc("POST /admin/disable", s.adminDisable)
	mux.HandleFunc("POST /admin/enable", s.adminEnable)
	mux.HandleFunc("POST /admin/remove", s.adminRemove)
	mux.HandleFunc("POST /admin/rotate", s.adminRotate)

	// The key page (magpie's /me) is for its holder alone: inside the
	// portal it rotates the key the signed-in admin's console asks with,
	// and never shows the new value. GET /me itself is the console's.
	mux.HandleFunc("POST /me/rotate", s.rotateMine)

	// The key page is magpie's own /me, drawn by the gateway for a key its
	// holder types. Here the page is signed in for: GET /v1/magpie/me is the
	// route magpie's page asks, the portal answers it with the gateway's own
	// word about this person's key, and POST /key/rotate is its Rotate.
	mux.HandleFunc("GET /mine", s.mine)
	mux.HandleFunc("GET /portal/console.css", s.consoleCSS)
	mux.HandleFunc("GET /v1/magpie/me", s.meData)
	mux.HandleFunc("GET /v1/magpie/me/", s.meData) // the page's BASE is the origin; keep both
	mux.HandleFunc("POST /key/rotate", s.keyRotate)

	mux.HandleFunc("POST /hooks/approval", s.approvalHook)

	mux.HandleFunc("GET /portal/api/me", s.apiMe)
	mux.HandleFunc("GET /portal/api/me/usage", s.apiUsage)
	mux.HandleFunc("GET /portal/api/my-key", s.apiMyKey)
	mux.HandleFunc("GET /portal/api/key", s.apiMyKey) // what magpie's key page asks (keypage.go)
	mux.HandleFunc("POST /portal/api/rotate", s.apiRotate)
	mux.HandleFunc("GET /portal/copy.js", s.copyJS)
	return s.dispatch(s.headers(mux))
}

// dispatch hands the console's page and what it asks for to the console
// fetch, whose signed-in person's answers they are, and the rest of the
// console's paths to its proxy. The portal's own CSP and no-store headers
// must not fall on the console's page, so they wrap only the portal mux.
func (s *Server) dispatch(portal http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.fetch != nil && s.fetch.wants(r) {
			s.fetch.serve(w, r)
			return
		}
		// the key page's own data is the portal's (keypage.go, meData),
		// which asks the gateway itself: it never goes to the console
		if s.console != nil && !strings.HasPrefix(r.URL.Path, "/v1/magpie/me") && s.console.Handles(r.URL.Path) {
			s.console.ServeHTTP(w, r)
			return
		}
		portal.ServeHTTP(w, r)
	})
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		// whether a page is magpie's own: magpie's console (its page, its
		// files, its API), or a page of the portal's drawn in magpie's frame
		// (magpiepage.go) — each runs magpie's scripts as its page does
		isMagpie := (s.console != nil && s.console.Handles(r.URL.Path)) || r.URL.Path == "/portal/page.js" || assetFile(r.URL.Path) ||
			(s.fetch != nil && s.fetch.isPage(r.URL.Path))
		// the key page's own data is the portal's (keypage.go, meData),
		// which asks the gateway itself: it never goes to the console
		if isMagpie && !strings.HasPrefix(r.URL.Path, "/v1/magpie/me") {
			// magpie's console header, as magpie web sends it (internal/gui):
			// the page's own files, its styles, its frames and its API
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https: http:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; worker-src 'self' blob:; base-uri 'self'; form-action 'self'; frame-ancestors 'self'")
			h.Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	verifier := oauth2.GenerateVerifier()
	s.signer.SetFlow(w, Flow{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		Next:     safeNext(r.URL.Query().Get("next")),
	}, flowTTL)
	http.Redirect(w, r, s.oidc.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		desc := r.URL.Query().Get("error_description")
		if desc == "" {
			desc = e
		}
		s.fail(w, http.StatusForbidden, "The provider did not sign you in: "+desc, false)
		return
	}
	flow, ok := s.signer.Flow(r)
	s.signer.ClearFlow(w)
	if !ok {
		s.fail(w, http.StatusBadRequest, "This login has expired: start again.", false)
		return
	}
	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(flow.State)) != 1 {
		s.fail(w, http.StatusBadRequest, "This login is not the one this browser started: start again.", false)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.fail(w, http.StatusBadRequest, "The provider returned no code.", false)
		return
	}
	id, err := s.oidc.Exchange(r.Context(), code, flow.Verifier, flow.Nonce)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	pol, err := s.policyFor(id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	pol, err = s.ensureAdminKey(id, pol)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if pol.Status == StatusActive {
		if _, err := s.prov.ApplyPolicy(pol); err != nil {
			s.provisionFailed(w, r, err)
			return
		}
	}
	if pol.Status == StatusDisabled {
		_, _ = s.prov.ApplyPolicy(pol)
	}
	s.signer.SetSession(w, Session{
		Subject: id.Subject,
		Email:   id.Email,
		Name:    id.Name,
		Groups:  id.Groups,
	}, sessionTTL)
	http.Redirect(w, r, safeNext(flow.Next), http.StatusFound)
}

// policyFor is the person's standing: the policy the store has, else one
// made for them now. An existing key from before policies were kept is
// adopted as active, so an upgrade takes no one's access away; with
// auto_provision on, the config's grant is adopted instead.
func (s *Server) policyFor(id Identity) (Policy, error) {
	pol, ok := s.policy.Get(id.Subject)
	if !ok {
		var err error
		pol, err = s.policy.Seen(id)
		if err != nil {
			return Policy{}, err
		}
	}
	if pol.Status != StatusPending {
		return pol, nil
	}
	if s.cfg.autoProvision() {
		return s.policy.Adopt(id, nil, nil)
	}
	u, ok := s.state.Get(id.Subject)
	if !ok || u.KeyID == "" {
		return pol, nil
	}
	keys, err := access.List()
	if err != nil {
		return pol, err
	}
	if k, ok := keyByID(keys, u.KeyID); ok {
		return s.policy.Adopt(id, k.Models, budgetConfigOf(k.Limit))
	}
	return pol, nil
}

func (s *Server) portal(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	id := identityOf(sess)
	pol, err := s.policyFor(id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	// With the console fetch, everyone signs in to magpie's own console,
	// theirs alone: an admin's whole, with the portal's management pages in
	// its sidebar (consolepage.go); without it, an admin's portal is their
	// management pages.
	if s.cfg.IsAdmin(id) {
		if s.fetch != nil {
			s.adminHome(w, r)
			return
		}
		s.admin(w, r)
		return
	}
	notice := noticeOf(r)
	person := id.Email
	if person == "" {
		person = id.Subject
	}
	switch pol.Status {
	case StatusRequested:
		when := ""
		if !pol.RequestedAt.IsZero() {
			when = "（" + pol.RequestedAt.Local().Format("1月2日 15:04") + "）"
		}
		s.serveMagicPage(w, http.StatusOK, magpiePageData{
			Title: "等待审批", Crumb: "网关密钥", Person: person, Pages: simplePages("/", "waiting"), Open: "waiting",
			Notice: notice,
			Blocks: []pageBlock{{Text: "你的申请已提交" + when + "。", Rows: []pageRow{
				{Name: "管理员会分配你上游和模型，并设置额度。开通后刷新本页即可看到密钥。"},
			}, Acts: []pageAct{{Label: "取消申请", Post: "/cancel-request"}}}},
		})
		return
	case StatusPending:
		s.serveMagicPage(w, http.StatusOK, magpiePageData{
			Title: "申请访问", Crumb: "网关密钥", Person: person, Pages: simplePages("/", "apply"), Open: "apply",
			Notice: notice,
			Blocks: []pageBlock{{Text: "你以 " + person + " 的身份登录了，但还没有被授予网关访问权限。", Rows: []pageRow{
				{Name: "管理员会为你选择可用的上游和模型，并设置每月额度。"},
			}, Acts: []pageAct{{Label: "申请访问权限", Kind: "primary", Post: "/request-access"}}}},
		})
		return
	case StatusRejected, StatusDisabled:
		what := "你的申请没有通过。"
		if pol.Status == StatusDisabled {
			what = "你的网关密钥已被管理员停用。"
		}
		rows := []pageRow{{Name: what}}
		if pol.Note != "" {
			rows = append(rows, pageRow{Name: "备注", Sub: pol.Note})
		}
		rows = append(rows, pageRow{Name: "如果认为这是误会，请联系管理员。"})
		s.serveMagicPage(w, http.StatusForbidden, magpiePageData{
			Title: "访问已关闭", Crumb: "网关密钥", Person: person, Pages: simplePages("/", "blocked"), Open: "blocked",
			Notice: notice,
			Blocks: []pageBlock{{Rows: rows}},
		})
		return
	}
	u, err := s.prov.ApplyPolicy(pol)
	if err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	if s.fetch != nil {
		s.fetch.serve(w, r)
		return
	}
	s.serveMagicPage(w, http.StatusOK, magpiePageData{
		Title: "我的密钥", Crumb: "网关密钥", Person: person, Pages: keyReadyPages(), Open: "mine",
		Notice: notice,
		Blocks: []pageBlock{
			{Rows: []pageRow{
				{Name: "密钥", Code: maskKey(u.Key)},
				{Name: "网关地址", Code: s.siteBase()},
				{Name: "额度", Text: limitText(pol.budgetFor(s.cfg))},
			}, Acts: []pageAct{{Label: "轮换密钥", Kind: "danger", Post: "/rotate", Confirm: "轮换后旧密钥立即失效，需要把新密钥换到每个客户端。"}}},
			{Head: "可用模型", Items: modelItems(pol.modelsFor(s.cfg))},
		},
	})
}

// serveMagicPage is a page of the portal's in magpie's own frame
// (magpiepage.go): its scripts as magpie serves them, its own kernel, and
// the portal's data of what it draws for the page's script (/portal/page.js).
func (s *Server) serveMagicPage(w http.ResponseWriter, status int, d magpiePageData) {
	b, err := readPageFile("app.css")
	if err != nil {
		log.Printf("oidc portal: page: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d.Assets = "/app.css?v=" + contentHash(b)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, magpiePageHead(d.Title, magpiePageView(d), d.Assets))
}

// PeriodLabel is a usage period in Chinese, as its tab says it.
func PeriodLabel(p usage.Period) string {
	switch p {
	case usage.Today:
		return "今天"
	case usage.Week:
		return "最近 7 天"
	case usage.All:
		return "全部"
	}
	return "最近 30 天"
}

// modelItems is the models a key may use, as a page's plain list.
func modelItems(models []string) []pageItem {
	out := make([]pageItem, 0, len(models))
	for _, m := range models {
		out = append(out, pageItem{Name: m})
	}
	return out
}

func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok || !sameOrigin(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	pol, err := s.policy.Request(sess.Subject)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.notifyAdmins(Event{
		Kind: "application", Sub: pol.Sub, Email: pol.Email, Name: pol.Name,
		Text: fmt.Sprintf("magpie: %s applied for gateway access", personOf(pol)),
		At:   time.Now().UTC(),
	})
	http.Redirect(w, r, "/?requested=1", http.StatusFound)
}

func (s *Server) cancelRequest(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok || !sameOrigin(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if _, err := s.policy.CancelRequest(sess.Subject); err != nil {
		s.internal(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// rotateMine is the key page's rotate: the admin's own key, a new value,
// and no value in the answer — the page draws it through the console the
// portal alone reaches.
func (s *Server) rotateMine(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this request did not come from the portal"})
		return
	}
	if s.console == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no console configured"})
		return
	}
	id := identityOf(sess)
	if !s.cfg.IsAdmin(id) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this page is for the portal's admins"})
		return
	}
	u, ok := s.state.GetAny(id.Subject)
	if !ok || u.KeyID == "" || u.Disabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no key to rotate"})
		return
	}
	secret, err := access.Update("rotate-key", access.Change{Key: u.KeyID})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.state.Update(u.Sub, func(x *User) error {
		x.rememberKey(x.KeyID)
		x.Key, x.Generation = secret, x.Generation+1
		return nil
	}); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit.Log(personOf(Policy{Email: id.Email, Sub: id.Subject}), "rotate", u.Sub, "key page")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": secret, "keyId": u.KeyID})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok || !sameOrigin(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	pol, err := s.policyFor(identityOf(sess))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if pol.Status != StatusActive {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if _, err := s.prov.ApplyPolicy(pol); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	if _, err := s.prov.Rotate(sess.Subject); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	s.audit.Log(personOf(pol), "rotate", sess.Subject, "")
	http.Redirect(w, r, "/?rotated=1", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.signer.ClearSession(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// admin lists everyone, with applications first.
// ensureAdminKey gives an admin the config names an active grant and a key
// the first time they sign in or open the admin page: the console asks as
// their own key, so without one every console popup would say it is not
// allowed. Their groups' providers and the config's budget, unless the
// portal already holds a standing for them.
func (s *Server) ensureAdminKey(id Identity, pol Policy) (Policy, error) {
	if !s.cfg.IsAdmin(id) {
		return pol, nil
	}
	// an admin the provider gave their role is trusted by that alone, whether
	// or not the portal provisions anyone else; otherwise only until they
	// apply, as anyone else
	grant := s.cfg.ProvidersFor(id.Groups)
	if *s.cfg.Provision || pol.Status == "" || pol.Status == StatusPending {
		if _, err := s.policy.EnsureAdmin(id, grant, nil); err != nil {
			return pol, err
		}
	}
	pol, ok := s.policy.Get(id.Subject)
	if !ok || pol.Status != StatusActive {
		return pol, nil
	}
	if _, err := s.prov.ApplyPolicy(pol); err != nil {
		return pol, err
	}
	return pol, nil
}

// keyPageCSP is the key page's own header: magpie's page is one file with
// its script in it, which the portal's default policy (script-src 'self')
// would hold. What it loads is none but its own lines.
const keyPageCSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"

// mine is 我的密钥: the portal's key page (keypage.html), signed in for:
// it shows the signed-in person's key and rotates it, and never one typed.
func (s *Server) mine(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.signer.Session(r); !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	w.Header().Set("Content-Security-Policy", keyPageCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(keyPage)
}

// consoleCSS is an ordinary person's console's stylesheet: the sidebar the
// page draws after its own scripts, once the portal's script has moved it
// under the page's frame (consolepage.go, personScript).
func (s *Server) consoleCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = io.WriteString(w, consoleCSS)
}

// adminHome is an admin's "/": their own console as magpie's page is, with
// the portal's management pages in its sidebar (consolepage.go).
func (s *Server) adminHome(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if _, err := s.ensureAdminKey(id, Policy{}); err != nil {
		s.internal(w, r, err)
		return
	}
	if s.fetch != nil {
		s.fetch.serve(w, r)
		return
	}
	s.admin(w, r)
}

// admin is 门户管理: everyone's standing in one page, as magpie's page draws
// a list (magpiepage.go): the applications waiting first, then everyone with
// their status, models, allowance and how much of it they have used. The
// search and the status filter are the address's (q, status).
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if _, err := s.ensureAdminKey(id, Policy{}); err != nil {
		s.internal(w, r, err)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	rows, requests := s.adminRows(q, status)
	d := magpiePageData{
		Title: "门户管理", Crumb: "网站门户控制管理", Person: id.Email,
		Pages: adminPages(), Open: "admin", Notice: noticeOf(r),
	}
	d.Blocks = append(d.Blocks, pageBlock{
		Head: "人员",
		Note: fmt.Sprintf("%d 人 · %d 个申请待审批", len(rows), len(requests)),
		Table: &pageTable{
			Head: []string{"人员", "状态", "可用的模型", "额度", "已用", "最近登录", ""},
			// each line's last cell is its address: the script makes it the
			// line's own link
			Rows: adminTableRows(rows),
		},
	})
	// the search and the filter: a form of the address's own, its fields
	// submitted as a GET
	d.Blocks = append(d.Blocks, pageBlock{Form: &pageForm{
		Post: "/admin",
		Fields: &[]pageField{
			{Name: "q", Label: "搜索", Value: q, Kind: "text", Note: "邮箱、姓名或 ID"},
			{Name: "status", Label: "状态", Value: status, Kind: "select", Options: []string{"", StatusRequested, StatusActive, StatusPending, StatusDisabled, StatusRejected}},
		},
		Acts: []pageAct{{Label: "筛选", Kind: "primary", Submit: true}},
	}})
	if len(requests) > 0 {
		var rr []pageRow
		for _, p := range requests {
			who := p.Email
			if who == "" {
				who = p.Sub
			}
			applied := "—"
			if !p.RequestedAt.IsZero() {
				applied = p.RequestedAt.Local().Format("1月2日 15:04")
			}
			rr = append(rr, pageRow{
				Name: who, Sub: p.Sub, Tag: "待审批", TagOn: "warn", Note: "申请于 " + applied,
				Acts: []pageAct{{Label: "审批", Kind: "primary", Href: "/admin/user?sub=" + url.QueryEscape(p.Sub)}},
			})
		}
		d.Blocks = append([]pageBlock{{Head: "申请", Rows: rr}}, d.Blocks...)
	}
	s.serveMagicPage(w, http.StatusOK, d)
}

// adminTableRows is everyone's standing as a table's lines.
func adminTableRows(rows []adminRow) [][]string {
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		who := row.Email
		if who == "" {
			who = row.Sub
		}
		if row.Name != "" && row.Name != who {
			who += " · " + row.Name
		}
		last := row.LastSeen
		if last == "" {
			last = "—"
		}
		out = append(out, []string{
			who, statusLabel(row.Status), row.Models, row.Budget, row.Used, last, row.Link,
		})
	}
	return out
}

// statusLabel is a standing in Chinese.
func statusLabel(status string) string {
	switch status {
	case StatusActive:
		return "在用"
	case StatusPending:
		return "未申请"
	case StatusRequested:
		return "待审批"
	case StatusDisabled:
		return "已停用"
	case StatusRejected:
		return "已拒绝"
	}
	return status
}

// adminUser is one person's page: their standing, their models and
// allowance (the form that grants or changes them), their key's state, and
// their usage over the period asked for. Never their key: a key's value is
// its owner's alone.
func (s *Server) adminUser(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.URL.Query().Get("sub"))
	pol, found := s.policyForSub(sub)
	if !found {
		s.serveMagicPage(w, http.StatusNotFound, magpiePageData{
			Title: "没有这个人", Crumb: "门户管理", Person: id.Email,
			Pages: adminPages(), Open: "admin",
			Blocks: []pageBlock{{Rows: []pageRow{
				{Name: "这个人还没有登录过：需要先登录一次，这里才有他们的记录。"},
			}, Acts: []pageAct{{Label: "返回门户管理", Href: "/admin"}}}},
		})
		return
	}
	period := PeriodOf(r.URL.Query().Get("period"))
	u, hasKey := s.state.Get(pol.Sub)
	usage := UsageForUser(u, period)
	who := personOf(pol)
	status := statusLabel(pol.Status)

	d := magpiePageData{Title: who, Crumb: "门户管理 / " + status, Person: id.Email, Pages: adminPages(), Open: "admin", Notice: noticeOf(r)}
	// who they are, and how their key stands
	keyRows := []pageRow{
		{Name: "状态", Tag: status, TagOn: statusTone(pol.Status)},
		{Name: "分组", Sub: strings.Join(pol.Groups, ", "), Mono: true},
		{Name: "密钥", Code: "—", Sub: "还没有密钥"},
	}
	if hasKey && u.KeyID != "" {
		keyRows[2] = pageRow{Name: "密钥", Code: maskKey(u.Key), Sub: fmt.Sprintf("第 %d 代 · 已用 %s", u.Generation, usedText(u.KeyID))}
		keyRows[2].Note = "密钥的值只有本人能复制；管理员看不到。"
	}
	if u.Disabled {
		keyRows = append(keyRows, pageRow{Name: "密钥状态", Tag: "已停用", TagOn: "bad"})
	}
	if pol.ApprovedBy != "" {
		by := "由 " + pol.ApprovedBy + " 开通"
		if !pol.ApprovedAt.IsZero() {
			by += "，于 " + pol.ApprovedAt.Local().Format("1月6日 15:04")
		}
		keyRows = append(keyRows, pageRow{Name: "开通", Sub: by})
	}
	keyRows = append(keyRows, pageRow{Acts: adminUserActs(pol)})
	d.Blocks = append(d.Blocks, pageBlock{Head: "身份与密钥", Rows: keyRows})

	// the grant: their models and allowance
	models := pol.Models
	if len(models) == 0 {
		models = s.cfg.ProvidersFor(pol.Groups)
	}
	bud := pol.Budget
	d.Blocks = append(d.Blocks, pageBlock{
		Head: "授权",
		Note: "当前额度：" + budgetText(bud) + "（" + limitText(pol.budgetFor(s.cfg)) + "）",
		Form: &pageForm{
			Post: "/admin/save", Sub: pol.Sub,
			Fields: &[]pageField{
				{Name: "models", Label: "可用的模型", Value: strings.Join(models, ", "), Kind: "textarea", Wide: true,
					Note: "用逗号或换行分开。a 或 a/* 表示上游 a 的全部模型；a/model 是一个模型。留空则用分组映射的上游。"},
				{Name: "period", Label: "额度周期", Value: budgetPeriod(bud), Kind: "select",
					Options: []string{"day", "week", "month", "days", "hours"}},
				{Name: "cost", Label: "费用上限（美元）", Value: costText(bud), Kind: "number"},
				{Name: "tokens", Label: "Token 上限", Value: tokensText(bud), Kind: "number"},
				{Name: "days", Label: "每 N 天", Value: cycleText(bud, "days"), Kind: "number"},
				{Name: "hours", Label: "每 N 小时", Value: cycleText(bud, "hours"), Kind: "number"},
				{Name: "note", Label: "备注", Value: pol.Note, Kind: "text", Wide: true},
			},
			Acts: []pageAct{{Label: saveLabel(pol.Status), Kind: "primary", Submit: true}},
		},
	})

	// their usage over the period, the page's own tabs
	if usage.HasKey {
		d.Blocks = append(d.Blocks, pageBlock{
			Head: "用量",
			Stats: []pageStat{
				{Value: humanInt(int64(usage.Totals.Tokens())), Label: "tokens", Sub: fmt.Sprintf("%d 次请求", usage.Totals.Calls)},
				{Value: fmt.Sprintf("$%.2f", usage.Totals.Cost), Label: "费用（标价）"},
				{Value: humanInt(int64(usage.Totals.Input)), Label: "输入"},
				{Value: humanInt(int64(usage.Totals.Output)), Label: "输出"},
			},
			Form: &pageForm{Tabs: periodActs(pol, period)},
		})
		d.Blocks = append(d.Blocks, pageBlock{Head: "按模型", Rows: usageRows(usage)})
		d.Blocks = append(d.Blocks, pageBlock{
			Head:  "最近请求",
			Table: &pageTable{Head: []string{"时间", "模型", "上游", "状态", "Tokens", "耗时"}, Rows: recentRows(usage)},
			Note:  "只显示请求的元数据；请求和响应正文请在 Langfuse 查看。",
		})
	} else {
		d.Blocks = append(d.Blocks, pageBlock{Note: "还没有密钥，所以没有用量。"})
	}
	s.serveMagicPage(w, http.StatusOK, d)
}

// statusTone is a standing's colour in a row's tag.
func statusTone(status string) string {
	switch status {
	case StatusActive:
		return "good"
	case StatusRequested:
		return "warn"
	case StatusDisabled, StatusRejected:
		return "bad"
	}
	return "mute"
}

// adminUserActs are the buttons of one person's key: each a form's post to
// the portal's own route, the destructive ones asking first.
func adminUserActs(pol Policy) []pageAct {
	sub := pol.Sub
	acts := []pageAct{
		{Label: "轮换密钥", Post: "/admin/rotate", Sub: sub, Confirm: "轮换后这位用户当前的密钥立即失效，需要把新密钥换到每个客户端。"},
	}
	if pol.Status == StatusActive {
		acts = append(acts, pageAct{Label: "停用", Kind: "danger", Post: "/admin/disable", Sub: sub, Confirm: "停用后这位用户不能再用这个密钥。"})
	}
	if pol.Status == StatusDisabled {
		acts = append(acts, pageAct{Label: "启用", Post: "/admin/enable", Sub: sub})
	}
	acts = append(acts, pageAct{Label: "移除密钥", Kind: "danger", Post: "/admin/remove", Sub: sub, Confirm: "移除后这位用户的密钥被删除。"})
	if pol.Status != StatusActive && pol.Status != StatusDisabled {
		acts = append(acts, pageAct{Label: "拒绝", Kind: "danger", Post: "/admin/reject", Sub: sub, Confirm: "拒绝这个申请？"})
	}
	return acts
}

// saveLabel is the grant form's button, by what saving does.
func saveLabel(status string) string {
	if status == StatusActive {
		return "保存"
	}
	return "通过并创建密钥"
}

// periodActs are the usage's tabs: the page again, the period asked for.
func periodActs(pol Policy, period usage.Period) []pageAct {
	var acts []pageAct
	for _, q := range []string{"today", "week", "month", "all"} {
		label := PeriodLabel(PeriodOf(q))
		a := pageAct{Label: label, Href: "/admin/user?sub=" + url.QueryEscape(pol.Sub) + "&period=" + q}
		if PeriodOf(q) == period {
			a.Kind = "seg-on"
		}
		acts = append(acts, a)
	}
	return acts
}

// usageRows is the usage's models, each a row of a list.
func usageRows(u UsageView) []pageRow {
	var rows []pageRow
	for _, m := range u.Models {
		sub := fmt.Sprintf("%d 次 · 输入 %d · 输出 %d", m.Calls, m.Input, m.Output)
		if m.CacheRead > 0 {
			sub += fmt.Sprintf(" · 缓存读取 %d", m.CacheRead)
		}
		cost := "无标价"
		if m.Cost > 0 {
			cost = fmt.Sprintf("$%.2f", m.Cost)
		}
		rows = append(rows, pageRow{Name: m.Model, Mono: true, Sub: sub, Text: humanInt(int64(m.Tokens)) + " tokens · " + cost})
	}
	if len(rows) == 0 {
		rows = []pageRow{{Name: "这个时间段还没有请求。"}}
	}
	return rows
}

// recentRows is the usage's recent requests as a table's lines.
func recentRows(u UsageView) [][]string {
	var rows [][]string
	for _, q := range u.Recent {
		provider := q.Provider
		if provider == "" {
			provider = "—"
		}
		rows = append(rows, []string{
			q.Time.Local().Format("01-02 15:04:05"), q.Model, provider, q.Status,
			humanInt(int64(q.Tokens)), fmt.Sprintf("%d ms", q.Millis),
		})
	}
	return rows
}

func (s *Server) adminSave(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.FormValue("sub"))
	pol, found := s.policy.Get(sub)
	if !found {
		s.fail(w, http.StatusNotFound, "No such person.", true)
		return
	}
	models := splitModels(r.FormValue("models"))
	effective, err := normalizePatterns(models)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	if len(effective) == 0 {
		effective = s.cfg.ProvidersFor(pol.Groups)
	}
	if *s.cfg.Provision && len(effective) == 0 {
		s.fail(w, http.StatusBadRequest, "Assign at least one model, or put the person in a group oidc.yaml maps to providers.", true)
		return
	}
	bud, err := budgetFromForm(r)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	actor := personOf(Policy{Email: id.Email, Sub: id.Subject})
	note := r.FormValue("note")
	if pol.Status == StatusActive {
		pol, err = s.policy.Save(sub, models, bud, note)
	} else {
		pol, err = s.policy.Approve(sub, actor, models, bud, note)
	}
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	if _, err := s.prov.ApplyPolicy(pol); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	s.audit.Log(actor, "grant", sub, strings.Join(effective, ",")+" "+budgetText(bud))
	http.Redirect(w, r, "/admin/user?sub="+url.QueryEscape(sub)+"&saved=1", http.StatusFound)
}

func (s *Server) adminReject(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.FormValue("sub"))
	actor := personOf(Policy{Email: id.Email, Sub: id.Subject})
	pol, err := s.policy.Reject(sub, actor, r.FormValue("note"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	s.audit.Log(actor, "reject", sub, r.FormValue("note"))
	s.notifyAdmins(Event{Kind: "rejected", Sub: sub, Email: pol.Email, Text: fmt.Sprintf("magpie: %s was declined access", personOf(pol)), At: time.Now().UTC()})
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) adminDisable(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.FormValue("sub"))
	actor := personOf(Policy{Email: id.Email, Sub: id.Subject})
	pol, err := s.policy.Disable(sub, actor, r.FormValue("note"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	if _, err := s.prov.ApplyPolicy(pol); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	s.audit.Log(actor, "disable", sub, "")
	http.Redirect(w, r, "/admin/user?sub="+url.QueryEscape(sub)+"&disabled=1", http.StatusFound)
}

func (s *Server) adminEnable(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.FormValue("sub"))
	actor := personOf(Policy{Email: id.Email, Sub: id.Subject})
	pol, err := s.policy.Enable(sub, actor)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	if _, err := s.prov.ApplyPolicy(pol); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	s.audit.Log(actor, "enable", sub, "")
	http.Redirect(w, r, "/admin/user?sub="+url.QueryEscape(sub)+"&enabled=1", http.StatusFound)
}

func (s *Server) adminRemove(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.FormValue("sub"))
	actor := personOf(Policy{Email: id.Email, Sub: id.Subject})
	if _, err := s.policy.Disable(sub, actor, "key removed"); err != nil && !errors.Is(err, ErrUnknownUser) {
		s.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	if _, err := s.prov.RemoveUser(sub); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	s.audit.Log(actor, "remove", sub, "")
	http.Redirect(w, r, "/admin?removed=1", http.StatusFound)
}

func (s *Server) adminRotate(w http.ResponseWriter, r *http.Request) {
	_, id, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	sub := strings.TrimSpace(r.FormValue("sub"))
	actor := personOf(Policy{Email: id.Email, Sub: id.Subject})
	if _, err := s.prov.Rotate(sub); err != nil {
		s.provisionFailed(w, r, err)
		return
	}
	s.audit.Log(actor, "rotate", sub, "")
	http.Redirect(w, r, "/admin/user?sub="+url.QueryEscape(sub)+"&rotated=1", http.StatusFound)
}

// approvalHook is where an approval system (a Feishu bot, a workflow) may
// call in. It is off unless hooks.secret is set, and every call carries an
// HMAC-SHA256 of its body in X-Magpie-Signature.
func (s *Server) approvalHook(w http.ResponseWriter, r *http.Request) {
	secret := s.cfg.Hooks.Secret
	if secret == "" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body too large"})
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	got := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Magpie-Signature")))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}
	var in struct {
		Action string        `json:"action"`
		Sub    string        `json:"sub"`
		Models []string      `json:"models"`
		Budget *BudgetConfig `json:"budget"`
		Note   string        `json:"note"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	sub := strings.TrimSpace(in.Sub)
	var pol Policy
	actor := "hook"
	switch in.Action {
	case "approve":
		pol, err = s.policy.Approve(sub, actor, in.Models, in.Budget, in.Note)
	case "reject":
		pol, err = s.policy.Reject(sub, actor, in.Note)
	case "disable":
		pol, err = s.policy.Disable(sub, actor, in.Note)
	case "enable":
		pol, err = s.policy.Enable(sub, actor)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action is approve, reject, disable or enable"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.prov.ApplyPolicy(pol); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit.Log(actor, in.Action, sub, in.Note)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": pol.Status})
}

// apiMyKey is the owner's one way to the full value: the page shows a mask,
// and its copy button asks here. The subject comes from the signed session,
// never from the request, so an admin cannot ask for someone else's key.
func (s *Server) apiMyKey(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	pol, err := s.policyFor(identityOf(sess))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	u, ok := s.state.Get(sess.Subject)
	if pol.Status != StatusActive || !ok || u.Key == "" || u.Disabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no active key"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": u.Key})
}

// copyJS is the portal page's copy button: it asks the owner-only endpoint
// for the value and writes it straight to the clipboard, never into the
// page's DOM. A browser without the async clipboard API falls back to a
// temporary textarea.
func (s *Server) copyJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `document.addEventListener("click", function (e) {
  var b = e.target.closest("#copy-key");
  if (!b) return;
  e.preventDefault();
  fetch("/portal/api/my-key", {cache: "no-store", credentials: "same-origin"})
    .then(function (r) { if (!r.ok) throw new Error("no key"); return r.json(); })
    .then(function (d) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(d.key);
      }
      var t = document.createElement("textarea");
      t.value = d.key; t.setAttribute("readonly", ""); t.style.position = "fixed";
      t.style.opacity = "0"; document.body.appendChild(t); t.select();
      document.execCommand("copy"); t.remove();
    })
    .then(function () {
      b.textContent = "Copied";
      setTimeout(function () { b.textContent = "Copy"; }, 1500);
    })
    .catch(function () { b.textContent = "Copy failed"; });
});
`)
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	pol, err := s.policyFor(identityOf(sess))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	u, _ := s.state.Get(sess.Subject)
	out := userJSON(u)
	out["subject"] = sess.Subject
	if u.Email == "" {
		out["email"], out["name"], out["groups"] = sess.Email, sess.Name, sess.Groups
	}
	out["status"] = pol.Status
	out["models"] = pol.modelsFor(s.cfg)
	out["budget"] = limitText(pol.budgetFor(s.cfg))
	if pol.Status != StatusActive {
		out["keyMasked"], out["keyId"] = "", ""
	}
	// The portal's page asks for this: the gateway address its setup
	// snippets paste, which is this portal's own, not magpie's local one.
	if s.fetch != nil && s.fetch.person {
		out["url"] = requestBase(r)
	}
	writeJSON(w, http.StatusOK, out)
}

// requestBase is the address this request came in at, as the page that
// made it sees it: scheme, host and any path a proxy serves the portal
// under, less its trailing slash.
func requestBase(r *http.Request) string {
	scheme := requestScheme(r)
	base := scheme + "://" + r.Host
	if p := strings.TrimSuffix(r.Header.Get("X-Forwarded-Prefix"), "/"); p != "" && strings.HasPrefix(p, "/") {
		base += p
	}
	return base
}

func (s *Server) apiUsage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	u, ok := s.state.Get(sess.Subject)
	if !ok {
		writeJSON(w, http.StatusOK, UsageView{Period: PeriodName(PeriodOf(r.URL.Query().Get("period")))})
		return
	}
	writeJSON(w, http.StatusOK, UsageForUser(u, PeriodOf(r.URL.Query().Get("period"))))
}

func (s *Server) apiRotate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok || !sameOrigin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	pol, err := s.policyFor(identityOf(sess))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if pol.Status != StatusActive {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no active key"})
		return
	}
	u, err := s.prov.Rotate(sess.Subject)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

// requireAdmin admits the admin page's caller: a signed-in identity the
// config names, asking from the same origin.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (Session, Identity, bool) {
	sess, ok := s.signer.Session(r)
	if !ok {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/login?next=/admin", http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
		return Session{}, Identity{}, false
	}
	id := identityOf(sess)
	if !s.cfg.IsAdmin(id) {
		s.fail(w, http.StatusForbidden, "This page is for the portal's admins.", true)
		return Session{}, Identity{}, false
	}
	if r.Method != http.MethodGet && !sameOrigin(r) {
		s.fail(w, http.StatusForbidden, "This form did not come from the portal.", true)
		return Session{}, Identity{}, false
	}
	return sess, id, true
}

func (s *Server) provisionFailed(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNoAccess):
		s.fail(w, http.StatusForbidden, "No models are assigned to you yet: none of your groups names a provider, and no admin has granted any. Ask an admin to grant the upstreams you need.", true)
	case errors.Is(err, ErrDisabled):
		s.fail(w, http.StatusForbidden, "Your gateway key has been disabled. Ask an admin to enable it.", true)
	case errors.Is(err, ErrUnknownUser):
		s.fail(w, http.StatusNotFound, "The portal has no key for that user.", true)
	default:
		s.internal(w, r, err)
	}
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("oidc portal: %s %s: %v", r.Method, r.URL.Path, err)
	s.fail(w, http.StatusInternalServerError, "Something went wrong on the portal's side. The details are in its log.", true)
}

// fail is a page that could not go on: what happened, in magpie's frame,
// with the way forward.
func (s *Server) fail(w http.ResponseWriter, status int, msg string, signedIn bool) {
	d := magpiePageData{Title: "无法继续", Crumb: "magpie", Error: msg}
	acts := []pageAct{{Label: "重试", Href: "/"}}
	if signedIn {
		d.Pages = simplePages("/", "home")
		acts = append(acts, pageAct{Label: "退出登录", Href: "/logout"})
	}
	d.Blocks = []pageBlock{{Acts: acts}}
	s.serveMagicPage(w, status, d)
}

// assetFile serves magpie's own file at the request's path (assetFiles) as
// magpie serves it: the page of the portal's draws its frame with these.
func (s *Server) assetFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	ctype := "text/javascript; charset=utf-8"
	if strings.HasSuffix(name, ".css") {
		ctype = "text/css; charset=utf-8"
	}
	b, err := readPageFile(name)
	if err != nil || !fsFile(name) {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	// a versioned address is the content's: it never changes
	if r.URL.Query().Get("v") == contentHash(b) {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	_, _ = w.Write(b)
}

func (s *Server) notifyAdmins(e Event) {
	if s.notify == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.notify.Notify(ctx, e); err != nil {
			log.Printf("oidc portal: notify: %v", err)
		}
	}()
}

// adminRows merges policies with any legacy key the portal kept before
// policies, so nobody disappears from the list on the upgrade.
func (s *Server) adminRows(q, status string) ([]adminRow, []Policy) {
	seen := map[string]bool{}
	var rows []adminRow
	var requests []Policy
	for _, p := range s.policy.List() {
		seen[p.Sub] = true
		if p.Status == StatusRequested && matchesAdminQuery(p, q) && (status == "" || status == StatusRequested) {
			requests = append(requests, p)
		}
		if !matchesAdminQuery(p, q) || (status != "" && p.Status != status) {
			continue
		}
		rows = append(rows, s.adminRow(p))
	}
	for _, u := range s.state.All() {
		if seen[u.Sub] {
			continue
		}
		p := Policy{Sub: u.Sub, Email: u.Email, Name: u.Name, Groups: u.Groups, Models: u.Providers, Status: StatusActive}
		if u.Disabled {
			p.Status = StatusDisabled
		}
		if !matchesAdminQuery(p, q) || (status != "" && p.Status != status) {
			continue
		}
		rows = append(rows, s.adminRow(p))
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := strings.ToLower(rows[i].Email), strings.ToLower(rows[j].Email)
		if a != b {
			return a < b
		}
		return rows[i].Sub < rows[j].Sub
	})
	return rows, requests
}

func matchesAdminQuery(p Policy, q string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	return strings.Contains(strings.ToLower(p.Email), q) ||
		strings.Contains(strings.ToLower(p.Name), q) ||
		strings.Contains(strings.ToLower(p.Sub), q)
}

func (s *Server) adminRow(p Policy) adminRow {
	u, _ := s.state.Get(p.Sub)
	row := adminRow{
		Sub: p.Sub, Email: p.Email, Name: p.Name, Status: p.Status,
		Models: strings.Join(p.modelsFor(s.cfg), ", "),
		Budget: limitText(p.budgetFor(s.cfg)),
		Used:   "—",
		Link:   "/admin/user?sub=" + url.QueryEscape(p.Sub),
	}
	if !p.LastSeen.IsZero() {
		row.LastSeen = p.LastSeen.Format("2006-01-02 15:04")
	}
	if u.KeyID != "" {
		row.HasKey = true
		row.Used = usedText(u.KeyID)
	}
	if row.Models == "" {
		row.Models = "—"
	}
	return row
}

// policyForSub finds a policy, or makes one from a legacy state record.
func (s *Server) policyForSub(sub string) (Policy, bool) {
	if p, ok := s.policy.Get(sub); ok {
		return p, true
	}
	if u, ok := s.state.Get(sub); ok {
		p := Policy{Sub: u.Sub, Email: u.Email, Name: u.Name, Groups: u.Groups, Models: u.Providers, Status: StatusActive}
		if u.Disabled {
			p.Status = StatusDisabled
		}
		return p, true
	}
	return Policy{}, false
}

func usedText(keyID string) string {
	if keyID == "" {
		return "—"
	}
	keys, err := access.List()
	if err != nil {
		return "—"
	}
	for _, k := range keys {
		if k.ID != keyID {
			continue
		}
		st := budget.Of(k, time.Now())
		if st == nil {
			return "no budget"
		}
		switch {
		case st.CostLimit > 0:
			return fmt.Sprintf("$%.2f / $%.2f", st.Cost, st.CostLimit)
		case st.TokenLimit > 0:
			return fmt.Sprintf("%d / %d tokens", st.Tokens, st.TokenLimit)
		}
		return "no budget"
	}
	return "—"
}

func splitModels(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

func budgetFromForm(r *http.Request) (*BudgetConfig, error) {
	cost, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("cost")), 64)
	tokens, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("tokens")), 10, 64)
	days, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("days")))
	hours, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("hours")))
	if cost == 0 && tokens == 0 {
		return nil, nil
	}
	b := &BudgetConfig{Period: strings.TrimSpace(r.FormValue("period")), Days: days, Hours: hours, Cost: cost, Tokens: tokens}
	if b.Period == "" {
		b.Period = "month"
	}
	if _, err := b.limit().Valid(); err != nil {
		return nil, err
	}
	return b, nil
}

func budgetConfigOf(l *access.Limit) *BudgetConfig {
	if l == nil || !l.Limited() {
		return nil
	}
	return &BudgetConfig{Period: l.Period, Days: l.Days, Hours: l.Hours, Cost: l.Cost, Tokens: l.Tokens}
}

func budgetPeriod(b *BudgetConfig) string {
	if b == nil || b.Period == "" {
		return "month"
	}
	return b.Period
}

func costText(b *BudgetConfig) string {
	if b == nil || b.Cost == 0 {
		return ""
	}
	return strconv.FormatFloat(b.Cost, 'f', -1, 64)
}

func tokensText(b *BudgetConfig) string {
	if b == nil || b.Tokens == 0 {
		return ""
	}
	return strconv.FormatInt(b.Tokens, 10)
}

func cycleText(b *BudgetConfig, field string) string {
	if b == nil {
		return ""
	}
	n := b.Days
	if field == "hours" {
		n = b.Hours
	}
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func budgetText(b *BudgetConfig) string {
	if b == nil {
		return "no budget"
	}
	l, err := b.limit().Valid()
	if err != nil || l == nil {
		return "no budget"
	}
	return limitText(l)
}

func personOf(p Policy) string {
	if p.Email != "" {
		return p.Email
	}
	if p.Name != "" {
		return p.Name
	}
	return p.Sub
}

func (c *Config) autoProvision() bool {
	return c.AutoProvision != nil && *c.AutoProvision
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Local().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local)
}

func identityOf(s Session) Identity {
	return Identity{Subject: s.Subject, Email: s.Email, Name: s.Name, Groups: s.Groups}
}

func userJSON(u User) map[string]any {
	return map[string]any{
		"subject":    u.Sub,
		"email":      u.Email,
		"name":       u.Name,
		"groups":     u.Groups,
		"providers":  u.Providers,
		"keyMasked":  maskKey(u.Key),
		"keyId":      u.KeyID,
		"generation": u.Generation,
		"disabled":   u.Disabled,
		"updatedAt":  u.UpdatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// safeNext keeps a post-login redirect on this site.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	return next
}

// sameOrigin says whether a form's Origin (or, failing that, Referer) is
// this site. A request with neither is let through: browsers send Origin on
// cross-site form posts, and the cookies are SameSite=Lax besides.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func noticeOf(r *http.Request) string {
	switch {
	case r.URL.Query().Get("rotated") != "":
		return "Your key has a new value. The old one no longer works."
	case r.URL.Query().Get("requested") != "":
		return "Your application was sent. An admin will assign your upstreams."
	case r.URL.Query().Get("saved") != "":
		return "Saved. The person's key now has this scope and budget."
	case r.URL.Query().Get("removed") != "":
		return "The user's key was removed."
	case r.URL.Query().Get("enabled") != "":
		return "The user may sign in again."
	case r.URL.Query().Get("disabled") != "":
		return "The user's key was disabled."
	}
	return ""
}

func maskKey(k string) string {
	if len(k) <= 4 {
		return "…"
	}
	return "…" + k[len(k)-4:]
}

type adminRow struct {
	Sub, Email, Name, Status, Models, Budget, Used, LastSeen, Link string
	HasKey                                                         bool
}
