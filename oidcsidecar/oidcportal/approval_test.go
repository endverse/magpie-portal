package oidcportal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/usage"
)

func approvalConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	off := false
	c, err := (&Config{
		Issuer:       "https://id.example.com/realms/main",
		ClientID:     "magpie",
		RedirectURL:  "http://magpie.example.com/callback",
		CookieSecret: strings.Repeat("c", 32),
		Groups: map[string][]string{
			"team-a": {"a"},
			"team-c": {"c", "a"},
		},
		AutoProvision: &off,
	}).Prepare()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The flow the portal is for: sign in, apply, an admin assigns models and a
// budget, and the person has a key without signing in again.
func TestApplicationThenApprovalGivesAKey(t *testing.T) {
	cfg := approvalConfig(t)
	fp := &fakeProvider{}
	ts, state, policy, bob := newTestServerFull(t, cfg, fp)

	fp.id = Identity{Subject: "bob", Email: "bob@example.com", Name: "Bob", Groups: []string{"team-a"}}
	signIn(t, ts, bob, fp, "/")

	pol, ok := policy.Get("bob")
	if !ok || pol.Status != StatusPending {
		t.Fatalf("policy = %+v, %v", pol, ok)
	}
	if _, ok := state.Get("bob"); ok {
		t.Fatal("a key was made before an admin approved")
	}
	resp, err := bob.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	status := resp.StatusCode
	body := bodyOf(t, resp)
	if status != http.StatusOK || !strings.Contains(body, "申请访问权限") {
		t.Fatalf("portal for a pending person: %d\n%s", resp.StatusCode, body)
	}

	resp = formPost(t, bob, ts.URL, "/request-access", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("apply: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	resp.Body.Close()
	if pol, _ := policy.Get("bob"); pol.Status != StatusRequested {
		t.Fatalf("after applying: %+v", pol)
	}

	admin := freshClient(ts)
	fp.id = Identity{Subject: "boss", Email: "boss@example.com", Name: "Boss", Groups: []string{"team-c", RoleOperator}}
	signIn(t, ts, admin, fp, "/admin")
	resp, err = admin.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	body = bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "bob@example.com") || !strings.Contains(body, "审批") {
		t.Fatalf("admin does not list the application: %d\n%s", resp.StatusCode, body)
	}

	resp = formPost(t, admin, ts.URL, "/admin/save", url.Values{
		"sub": {"bob"}, "models": {"a"}, "period": {"month"}, "cost": {"10"},
	})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("approve: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	resp.Body.Close()

	pol, _ = policy.Get("bob")
	if pol.Status != StatusActive || pol.ApprovedBy != "boss@example.com" {
		t.Fatalf("policy after approval = %+v", pol)
	}
	u, ok := state.Get("bob")
	if !ok || u.Key == "" {
		t.Fatalf("state after approval = %+v, %v", u, ok)
	}
	who, ok := access.Authenticate(u.Key)
	if !ok || who.KeyID != u.KeyID || strings.Join(who.Models, ",") != "a/*" {
		t.Fatalf("key = %+v, %v", who, ok)
	}
	// bob has one key; the admin who approved it has their own, which the
	// console asks as (no group gives bob's admin any here but the config's
	// admin list and team-c).
	keys, _ := access.List()
	own := make([]access.Key, 0, len(keys))
	for _, k := range keys {
		if k.ID == u.KeyID {
			own = append(own, k)
		}
	}
	if len(own) != 1 || len(keys) != 2 {
		t.Fatalf("keys = %+v", keys)
	}
	if own[0].Limit == nil || own[0].Limit.Cost != 10 || own[0].Limit.Period != "month" {
		t.Fatalf("limit = %+v", own[0].Limit)
	}

	resp, err = bob.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body = bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, u.Key) ||
		!strings.Contains(body, maskKey(u.Key)) || !strings.Contains(body, "每月 $10.00") {
		t.Fatalf("portal after approval: %d\n%s", resp.StatusCode, body)
	}
	if got := apiMyKey(t, ts, bob); got != u.Key {
		t.Fatalf("/portal/api/my-key = %q, want the owner's key", got)
	}

	me := apiMe(t, ts, bob)
	if me["status"] != StatusActive {
		t.Fatalf("/api/me = %+v", me)
	}
	models, _ := me["models"].([]any)
	if len(models) != 1 || models[0] != "a/*" {
		t.Fatalf("models = %v", me["models"])
	}

	// An admin opening the person sees the same per-model usage.
	usage.Append(usage.Record{
		Time: time.Now(), CallerKeyID: u.KeyID, CallerKeyName: u.Name,
		Provider: "a", Model: "test-model", Input: 10, Output: 5, Status: 200,
	})
	resp, err = admin.Get(ts.URL + "/admin/user?sub=bob")
	if err != nil {
		t.Fatal(err)
	}
	body = bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "用量") ||
		!strings.Contains(body, "test-model") || !strings.Contains(body, "最近请求") {
		t.Fatalf("admin usage page: %d\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, u.Key) {
		t.Fatal("the admin page carries the user's full key")
	}
	// The copy endpoint is the owner's: an admin asking for bob's key gets
	// only their own, never bob's.
	resp, err = admin.Get(ts.URL + "/portal/api/my-key?sub=bob")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodyOf(t, resp), u.Key) {
		t.Fatal("an admin copied bob's key")
	}

	// The person cannot grant themselves anything.
	resp = formPost(t, bob, ts.URL, "/admin/save", url.Values{"sub": {"bob"}, "models": {"c/*"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a user saved a grant: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// A deployment that ran before policies existed keeps every key on the
// upgrade.
func TestAKeyFromBeforePoliciesIsAdopted(t *testing.T) {
	cfg := approvalConfig(t)
	state, err := OpenState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	before, err := NewProvisioner(cfg, state).EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := OpenPolicy(cfg.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProvider{id: alice()}
	ts := httptest.NewServer(NewServer(cfg, state, policy, fp))
	t.Cleanup(ts.Close)
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	signIn(t, ts, c, fp, "/")

	pol, ok := policy.Get("alice")
	if !ok || pol.Status != StatusActive || pol.ApprovedBy != "migration" {
		t.Fatalf("policy = %+v, %v", pol, ok)
	}
	after, _ := state.Get("alice")
	if after.KeyID != before.KeyID || after.Key != before.Key {
		t.Fatalf("the key changed: %+v -> %+v", before, after)
	}
	resp, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	if strings.Contains(body, before.Key) || !strings.Contains(body, maskKey(before.Key)) || !strings.Contains(body, "a/*") {
		t.Fatalf("portal after adoption:\n%s", body)
	}
	if got := apiMyKey(t, ts, c); got != before.Key {
		t.Fatalf("/portal/api/my-key = %q, want the adopted key", got)
	}
}

func signHook(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// The approval hook is off without a secret, and refuses a body that is not
// signed with it.
func TestApprovalHook(t *testing.T) {
	cfg := approvalConfig(t)
	ts, _, policy, _ := newTestServerFull(t, cfg, &fakeProvider{})
	if _, err := policy.Seen(Identity{Subject: "bob", Email: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"approve","sub":"bob","models":["a/*"],"budget":{"period":"month","cost":5}}`)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/hooks/approval", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("hook without a secret: %d", resp.StatusCode)
	}
	resp.Body.Close()

	cfg.Hooks.Secret = strings.Repeat("h", 32)
	ts2, state2, policy2, _ := newTestServerFull(t, cfg, &fakeProvider{})
	if _, err := policy2.Seen(Identity{Subject: "bob", Email: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPost, ts2.URL+"/hooks/approval", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Magpie-Signature", "not-the-signature")
	resp, err = ts2.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned hook: %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, ts2.URL+"/hooks/approval", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Magpie-Signature", signHook(cfg.Hooks.Secret, body))
	resp, err = ts2.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed hook: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if pol, _ := policy2.Get("bob"); pol.Status != StatusActive {
		t.Fatalf("policy = %+v", pol)
	}
	if u, ok := state2.Get("bob"); !ok || u.Key == "" {
		t.Fatalf("no key from the hook: %+v, %v", u, ok)
	}
}
