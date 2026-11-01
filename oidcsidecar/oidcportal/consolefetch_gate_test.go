package oidcportal

import (
	"net/http"
	"testing"
)

// An operator's data goes to magpie's console through serveAdmin, which
// consults consoleAllowed — /api/gateway/trace is confidential, so an
// operator's GET is refused there. But /api/gateway/trace is also in
// serveData's person table, and isAdminRoute sends it to serveAdmin first.
// In fetch mode (production, cfg.Fetch on) the same request goes to
// serveAdmin too, and must be refused the same way.
func TestAnOperatorsTraceIsRefusedInFetchModeToo(t *testing.T) {
	up := newConsoleUpstream(t)
	cfg := consoleConfig(t, up.URL)
	fp := &fakeProvider{id: Identity{Subject: "boss", Email: "boss@example.com", Groups: []string{"team-c", RoleOperator}}}
	ts, _, _, _ := newTestServerFull(t, cfg, fp)
	c := freshClient(ts)
	signIn(t, ts, c, fp, "/")
	resp, body := doConsole(t, c, http.MethodGet, ts.URL+"/api/gateway/trace")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("fetch-mode operator trace = %d %s, want 403", resp.StatusCode, string(body))
	}
}
