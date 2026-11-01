package oidcportal

import "net/http"

// myKey is GET /portal/api/my-key (and the key page's own /portal/api/key):
// the owner's full key, to the owner's own
// page alone — 我的密钥 (mine, server.go), which shows it, and its Copy and
// Rotate put it where the holder wants it. Every console answer that would
// carry a key is refused; this one carries only the caller's own, which
// they may already send as a bearer.
func (s *Server) myKey(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.signer.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this answer is for the portal's own page"})
		return
	}
	u, ok := s.state.GetAny(identityOf(sess).Subject)
	if !ok || u.Key == "" || u.Disabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no key"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": u.Key})
}
