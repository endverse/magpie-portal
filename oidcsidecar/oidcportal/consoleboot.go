package oidcportal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// serveBoot is /boot.js: magpie web writes it for the page before it
// paints (its saved language and theme, and the pages it switches off).
// The portal asks magpie for it as it is, then says two things of its own:
// the page is Chinese whatever the deployment's setting, and this person
// has no pages of the deployment's to switch off, so theirs are on.
func (f *consoleFetch) serveBoot(w http.ResponseWriter, r *http.Request, id Identity) {
	prefs := map[string]any{}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, f.upstream.Scheme+"://"+f.upstream.Host+"/boot.js", nil)
	if err == nil {
		if cookie, ok := f.consoleCookie(r); ok {
			req.Header.Set("Cookie", cookie)
		}
		if resp, err := f.client.Do(req); err == nil {
			b := make([]byte, 0, 4096)
			buf := make([]byte, 4096)
			for {
				n, err := resp.Body.Read(buf)
				b = append(b, buf[:n]...)
				if err != nil || len(b) > maxConsoleJSON {
					break
				}
			}
			resp.Body.Close()
			if s := strings.TrimSpace(string(b)); strings.HasPrefix(s, "window.bootPrefs = ") {
				s = strings.TrimSuffix(strings.TrimPrefix(s, "window.bootPrefs = "), ";")
				if err := json.Unmarshal([]byte(s), &prefs); err != nil {
					log.Printf("oidc portal: boot.js: %v", err)
				}
			}
		}
	}
	prefs["lang"] = "zh"
	prefs["featuresOff"] = []any{}
	// The portal is not magpie web: the pages web shows of the computer it
	// runs on (the Update pill, opening windows, the CLI) are not this
	// deployment's, and app.js leaves them out when web is false.
	prefs["web"] = false
	b, _ := json.Marshal(prefs)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprintf(w, "window.bootPrefs = %s;\n", b)
	// the person's own line, before the page's scripts, which this one
	// runs ahead of
	person, _ := f.personKey(id)
	extra := map[string]any{}
	// an admin's console is magpie's own, whoever else the portal serves
	if f.cfg.IsAdmin(id) {
		extra["admin"] = true
	}
	if f.cfg.IsSuperAdmin(id) {
		extra["super"] = true
	}
	fmt.Fprintf(w, "%s\n", oidcPerson(id, person, extra))
	// the page is the portal's own from its first script; this deployment's
	// style for it goes in beside the page's, not through document.write,
	// which a browser run by a tool (or a reader) may never finish
	fmt.Fprint(w, "document.head.append(Object.assign(document.createElement('link'),{rel:'stylesheet',href:'/portal/console.css'}));\n")
	fmt.Fprint(w, roleScript)
}

// roleScript says whose console this is, from the page's first script:
// magpie's own drawn by the page, for a super admin (oidc-super) or an
// operator (oidc-operator), or an ordinary person's here (oidc-person).
// console.css prunes the page by the class.
const roleScript = "document.addEventListener('DOMContentLoaded',function(){setTimeout(function(){var p=window.oidcPerson||{};var r=p.super?'oidc-super':p.admin?'oidc-operator':'oidc-person';document.documentElement.className+=' '+r},300)});\n"
