package oidcportal

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/access"
)

func openTestState(t *testing.T) *State {
	t.Helper()
	s, err := OpenState(filepath.Join(t.TempDir(), "oidc-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func alice() Identity {
	return Identity{Subject: "alice", Email: "alice@example.com", Name: "Alice", Groups: []string{"team-a"}}
}

func TestEnsureUserMakesAScopedKey(t *testing.T) {
	cfg := testConfig(t)
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	if u.Key == "" || u.KeyID == "" || u.Generation != 1 {
		t.Fatalf("user = %+v", u)
	}
	who, ok := access.Authenticate(u.Key)
	if !ok || who.KeyID != u.KeyID || !slices.Equal(who.Models, []string{"a/*"}) {
		t.Fatalf("key = %+v, %v", who, ok)
	}
	keys, err := access.List()
	if err != nil || len(keys) != 1 || keys[0].Name != "oidc:alice" || !keys[0].Quotas {
		t.Fatalf("keys = %+v, %v", keys, err)
	}

	// Signing in again gives the same key, not another.
	again, err := p.EnsureUser(alice())
	if err != nil || again.KeyID != u.KeyID || again.Key != u.Key {
		t.Fatalf("second sign-in changed the key: %+v %v", again, err)
	}
	if keys, _ := access.List(); len(keys) != 1 {
		t.Fatalf("a second key was made: %+v", keys)
	}
}

func TestEnsureUserFollowsTheGroups(t *testing.T) {
	cfg := testConfig(t)
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	id := alice()
	id.Groups = []string{"team-c"}
	u2, err := p.EnsureUser(id)
	if err != nil {
		t.Fatal(err)
	}
	if u2.KeyID != u.KeyID || u2.Key != u.Key {
		t.Fatal("changing groups made another key")
	}
	if !slices.Equal(u2.Providers, []string{"a/*", "c/*"}) {
		t.Fatalf("providers = %v", u2.Providers)
	}
	who, ok := access.Authenticate(u2.Key)
	if !ok || !slices.Equal(who.Models, []string{"a/*", "c/*"}) {
		t.Fatalf("key scope = %+v, %v", who, ok)
	}
}

func TestBudgetIsSetOnceAndKept(t *testing.T) {
	cfg := testConfig(t)
	cfg.Budget = &BudgetConfig{Period: "month", Cost: 20}
	p := NewProvisioner(cfg, openTestState(t))
	if _, err := p.EnsureUser(alice()); err != nil {
		t.Fatal(err)
	}
	keys, _ := access.List()
	since := keys[0].Limit.Since
	if keys[0].Limit == nil || keys[0].Limit.Cost != 20 || keys[0].Limit.Period != "month" {
		t.Fatalf("limit = %+v", keys[0].Limit)
	}
	if _, err := p.EnsureUser(alice()); err != nil {
		t.Fatal(err)
	}
	keys, _ = access.List()
	if !keys[0].Limit.Since.Equal(since) {
		t.Fatal("a second sign-in reset the budget window")
	}
}

// A person's entry in users: owns their key's models and budget, even over
// what their groups name, and a changed entry reaches the key they already
// have.
func TestAUsersPolicyScopesTheirKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.Budget = &BudgetConfig{Period: "month", Cost: 20}
	cfg.Users = map[string]UserPolicy{
		"alice@example.com": {Models: []string{"c/one"}, Budget: &BudgetConfig{Period: "month", Cost: 5}},
	}
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice()) // alice's group names a/*; her entry replaces it
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(u.Providers, []string{"c/one"}) {
		t.Fatalf("providers = %v", u.Providers)
	}
	who, ok := access.Authenticate(u.Key)
	if !ok || !slices.Equal(who.Models, []string{"c/one"}) {
		t.Fatalf("key = %+v, %v", who, ok)
	}
	keys, _ := access.List()
	if keys[0].Limit == nil || keys[0].Limit.Cost != 5 || keys[0].Limit.Period != "month" {
		t.Fatalf("limit = %+v", keys[0].Limit)
	}
	since := keys[0].Limit.Since

	cfg.Users["alice@example.com"] = UserPolicy{
		Models: []string{"a/two"},
		Budget: &BudgetConfig{Period: "month", Cost: 2},
	}
	u2, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	if u2.KeyID != u.KeyID || u2.Key != u.Key {
		t.Fatal("a changed policy made another key")
	}
	if who, ok := access.Authenticate(u2.Key); !ok || !slices.Equal(who.Models, []string{"a/two"}) {
		t.Fatalf("key scope = %+v, %v", who, ok)
	}
	keys, _ = access.List()
	if keys[0].Limit == nil || keys[0].Limit.Cost != 2 {
		t.Fatalf("limit = %+v", keys[0].Limit)
	}
	if !keys[0].Limit.Since.Equal(since) {
		t.Fatal("changing the cap restarted the budget window")
	}
}

// A person whose groups give them nothing can still have a key when their
// own entry says which models it may use.
func TestAUserPolicyCanStandInForAGroup(t *testing.T) {
	cfg := testConfig(t)
	cfg.Groups = nil
	cfg.DefaultProviders = nil
	cfg.Users = map[string]UserPolicy{"alice": {Models: []string{"b/*"}}}
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	if who, ok := access.Authenticate(u.Key); !ok || !slices.Equal(who.Models, []string{"b/*"}) {
		t.Fatalf("key = %+v, %v", who, ok)
	}
}

func TestRotateKeepsTheIdentity(t *testing.T) {
	cfg := testConfig(t)
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := p.Rotate("alice")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KeyID != u.KeyID || rotated.Key == u.Key || rotated.Generation != 2 {
		t.Fatalf("rotated = %+v", rotated)
	}
	if _, ok := access.Authenticate(u.Key); ok {
		t.Fatal("the old key still works")
	}
	if who, ok := access.Authenticate(rotated.Key); !ok || who.KeyID != u.KeyID || !slices.Equal(who.Models, []string{"a/*"}) {
		t.Fatalf("the new key = %+v, %v", who, ok)
	}
	if _, err := p.Rotate("nobody"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("rotated an unknown user: %v", err)
	}
}

func TestRemoveDisablesAndEnableLetsThemBack(t *testing.T) {
	cfg := testConfig(t)
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.RemoveUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := access.Authenticate(u.Key); ok {
		t.Fatal("the removed key still works")
	}
	if keys, _ := access.List(); len(keys) != 0 {
		t.Fatalf("keys left: %+v", keys)
	}
	if _, err := p.EnsureUser(alice()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("a removed user signed back in: %v", err)
	}
	if _, err := p.EnableUser("alice"); err != nil {
		t.Fatal(err)
	}
	back, err := p.EnsureUser(alice())
	if err != nil || back.Key == "" || back.Disabled {
		t.Fatalf("enabled user got no key: %+v %v", back, err)
	}
}

func TestNoGroupMeansNoKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.Groups = nil
	cfg.DefaultProviders = nil
	p := NewProvisioner(cfg, openTestState(t))
	if _, err := p.EnsureUser(alice()); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("err = %v", err)
	}
	if keys, _ := access.List(); len(keys) != 0 {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestProvisionOffHandsOutAnUnrestrictedKey(t *testing.T) {
	cfg := testConfig(t)
	off := false
	cfg.Provision = &off
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	who, ok := access.Authenticate(u.Key)
	if !ok || len(who.Models) != 0 {
		t.Fatalf("key = %+v, %v", who, ok)
	}
}

func TestALostStateFileAdoptsTheKey(t *testing.T) {
	cfg := testConfig(t)
	first := NewProvisioner(cfg, openTestState(t))
	u, err := first.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	// The portal's own file is gone; the key is still in caller-keys.json.
	second := NewProvisioner(cfg, openTestState(t))
	u2, err := second.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	if u2.KeyID != u.KeyID || u2.Key != u.Key {
		t.Fatalf("adopted %+v, had %+v", u2, u)
	}
	if keys, _ := access.List(); len(keys) != 1 {
		t.Fatalf("duplicate keys: %+v", keys)
	}
}

// A key rotated outside the portal (or a state write that failed after the
// key store changed) is read back from the store, not shown stale.
func TestEnsureUserShowsTheStoresKey(t *testing.T) {
	cfg := testConfig(t)
	p := NewProvisioner(cfg, openTestState(t))
	u, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := access.Update("rotate-key", access.Change{Key: u.KeyID})
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.EnsureUser(alice())
	if err != nil {
		t.Fatal(err)
	}
	if again.Key != rotated {
		t.Fatalf("portal shows %q, store has %q", again.Key, rotated)
	}
}

func TestKeyNameFitsMagpieAndStaysDistinct(t *testing.T) {
	long := strings.Repeat("x", 200)
	a, b := keyName("oidc:", long+"a"), keyName("oidc:", long+"b")
	if len([]rune(a)) > 120 || len([]rune(b)) > 120 {
		t.Fatalf("names too long: %d, %d", len([]rune(a)), len([]rune(b)))
	}
	if a == b {
		t.Fatal("two long subjects share a name")
	}
	if got := keyName("oidc:", "alice"); got != "oidc:alice" {
		t.Fatalf("name = %q", got)
	}
}

// The name on the key is what the person is called in Keycloak, not the
// subject UUID: preferred_username, then the email's local part, then the
// subject. A username two people share gets a stable subject suffix.
func TestKeyNameUsesPreferredUsername(t *testing.T) {
	cases := []struct {
		id   Identity
		want string
	}{
		{Identity{Subject: "uuid-1", Email: "a@example.com", Username: "zhangsan"}, "oidc:zhangsan"},
		{Identity{Subject: "uuid-2", Email: "alice@example.com"}, "oidc:alice"},
		{Identity{Subject: "uuid-3"}, "oidc:uuid-3"},
	}
	for _, tc := range cases {
		if got := keyNameFor("oidc:", tc.id); got != tc.want {
			t.Fatalf("keyNameFor(%+v) = %q, want %q", tc.id, got, tc.want)
		}
	}
	one := uniqueKeyName("oidc:", Identity{Subject: "s1", Username: "same"})
	two := uniqueKeyName("oidc:", Identity{Subject: "s2", Username: "same"})
	if one == two || one == "oidc:same" || two == "oidc:same" {
		t.Fatalf("shared username names = %q, %q", one, two)
	}
	if again := uniqueKeyName("oidc:", Identity{Subject: "s1", Username: "same"}); again != one {
		t.Fatalf("a person's name changed between sign-ins: %q, then %q", one, again)
	}
	if len([]rune(uniqueKeyName("oidc:", Identity{Subject: "s", Username: strings.Repeat("x", 200)}))) > 120 {
		t.Fatal("a suffixed name is longer than magpie allows")
	}
}

// Two people who share a preferred_username each keep their own key, and
// signing in again does not hand one of them the other's.
func TestTwoPeopleSharingAUsernameKeepTheirKeys(t *testing.T) {
	cfg := testConfig(t)
	p := NewProvisioner(cfg, openTestState(t))
	a := Identity{Subject: "sub-a", Email: "a@example.com", Username: "same", Groups: []string{"team-a"}}
	b := Identity{Subject: "sub-b", Email: "b@example.com", Username: "same", Groups: []string{"team-a"}}
	ua, err := p.EnsureUser(a)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := p.EnsureUser(b)
	if err != nil {
		t.Fatal(err)
	}
	if ua.KeyID == ub.KeyID || ua.Key == ub.Key {
		t.Fatalf("the two share a key: %+v / %+v", ua, ub)
	}
	keys, _ := access.List()
	if len(keys) != 2 || keys[0].Name == keys[1].Name {
		t.Fatalf("keys = %+v", keys)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k.Name, "oidc:same") {
			t.Fatalf("key name %q does not start with the username", k.Name)
		}
	}
	again, err := p.EnsureUser(a)
	if err != nil {
		t.Fatal(err)
	}
	if again.KeyID != ua.KeyID || again.Key != ua.Key {
		t.Fatalf("a later sign-in moved a to %+v, had %+v", again, ua)
	}
}

// A key named the old way, after the subject, is renamed to the person's
// preferred_username without losing its id or value.
func TestAnOldSubjectNamedKeyIsRenamed(t *testing.T) {
	cfg := testConfig(t)
	secret, err := access.Update("add-key", access.Change{Name: "oidc:uuid-123"})
	if err != nil {
		t.Fatal(err)
	}
	who, _ := access.Authenticate(secret)
	st := openTestState(t)
	if _, err := st.Update("uuid-123", func(u *User) error {
		u.KeyID, u.Key = who.KeyID, secret
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := NewProvisioner(cfg, st)
	u, err := p.EnsureUser(Identity{
		Subject: "uuid-123", Email: "alice@example.com", Username: "alice", Groups: []string{"team-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.KeyID != who.KeyID || u.Key != secret {
		t.Fatalf("the key was replaced: %+v", u)
	}
	keys, _ := access.List()
	if len(keys) != 1 || keys[0].Name != "oidc:alice" {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestStateSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update("alice", func(u *User) error { u.KeyID = "k1"; u.Key = "secret"; return nil }); err != nil {
		t.Fatal(err)
	}
	again, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := again.Get("alice")
	if !ok || u.KeyID != "k1" || u.Key != "secret" {
		t.Fatalf("user = %+v, %v", u, ok)
	}
}
