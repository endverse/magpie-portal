package oidcportal

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	c, err := (&Config{
		Issuer:       "https://id.example.com/realms/main",
		ClientID:     "magpie",
		RedirectURL:  "https://magpie.example.com/callback",
		CookieSecret: strings.Repeat("c", 32),
		Groups: map[string][]string{
			"team-a": {"a"},
			"team-c": {"c", "a"},
		},
		DefaultProviders: []string{"b"},
	}).Prepare()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPrepareDefaults(t *testing.T) {
	c := testConfig(t)
	if c.Listen != "127.0.0.1:3440" || c.KeyNamePrefix != "oidc:" || c.GroupClaim != "groups" {
		t.Fatalf("defaults: %+v", c)
	}
	if !slices.Equal(c.Scopes, []string{"openid", "profile", "email"}) {
		t.Fatalf("scopes = %v", c.Scopes)
	}
	if c.Provision == nil || !*c.Provision {
		t.Fatal("provisioning is off by default")
	}
	if !strings.HasSuffix(c.StateFile, "oidc-state.json") {
		t.Fatalf("state file = %q", c.StateFile)
	}
	if !strings.HasSuffix(c.PolicyFile, "oidc-policy.json") {
		t.Fatalf("policy file = %q", c.PolicyFile)
	}
	if c.AutoProvision == nil || *c.AutoProvision {
		t.Fatal("a new person is granted access without an admin by default")
	}
}

func TestConsoleConfig(t *testing.T) {
	t.Setenv("MAGPIE_WEB_KEY", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	base := func() *Config {
		return &Config{
			Issuer:       "https://id.example.com/realms/main",
			ClientID:     "magpie",
			RedirectURL:  "https://magpie.example.com/callback",
			CookieSecret: strings.Repeat("c", 32),
			Groups:       map[string][]string{"team-a": {"a"}},
		}
	}

	c := base()
	c.ConsoleURL = "http://magpie:3430"
	c.ConsoleWebKey = strings.Repeat("w", 32)
	if _, err := c.Prepare(); err != nil {
		t.Fatal(err)
	}
	if c.ConsoleCookie != "magpie_web_3430" {
		t.Fatalf("console cookie = %q", c.ConsoleCookie)
	}

	for name, mutate := range map[string]func(*Config){
		"no key":     func(c *Config) { c.ConsoleWebKey = "" },
		"short key":  func(c *Config) { c.ConsoleWebKey = "short" },
		"bad url":    func(c *Config) { c.ConsoleURL = "ftp://magpie:3430" },
		"userinfo":   func(c *Config) { c.ConsoleURL = "http://u:p@magpie:3430" },
		"bad cookie": func(c *Config) { c.ConsoleCookie = "not a cookie" },
	} {
		c := base()
		c.ConsoleURL = "http://magpie:3430"
		c.ConsoleWebKey = strings.Repeat("w", 32)
		mutate(c)
		if _, err := c.Prepare(); err == nil {
			t.Fatalf("%s: the config was accepted", name)
		}
	}
}

func TestPrepareRefusesWhatItCannotRun(t *testing.T) {
	for _, c := range []*Config{
		{ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32)},
		{Issuer: "https://id.example.com", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32)},
		{Issuer: "https://id.example.com", ClientID: "x", CookieSecret: strings.Repeat("c", 32)},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "not a url", CookieSecret: strings.Repeat("c", 32)},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: "short"},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Groups: map[string][]string{"team": {"a/"}}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Budget: &BudgetConfig{Period: "fortnight", Cost: 1}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Users: map[string]UserPolicy{"someone@example.com": {}}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Users: map[string]UserPolicy{"someone": {Models: []string{"a/"}}}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Users: map[string]UserPolicy{"someone": {Budget: &BudgetConfig{Period: "fortnight", Cost: 1}}}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Users: map[string]UserPolicy{
				"A@example.com": {Models: []string{"a"}},
				"a@example.com": {Models: []string{"c"}},
			}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Notify: NotifyConfig{Webhook: "not a url"}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Notify: NotifyConfig{Feishu: "https://user:pw@open.feishu.cn/hook"}},
		{Issuer: "https://id.example.com", ClientID: "x", RedirectURL: "https://m.example.com/cb", CookieSecret: strings.Repeat("c", 32),
			Hooks: HookConfig{Secret: "short"}},
	} {
		if _, err := c.Prepare(); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestProvidersForGroups(t *testing.T) {
	c := testConfig(t)
	cases := []struct {
		groups []string
		want   []string
	}{
		{[]string{"team-a"}, []string{"a/*"}},
		{[]string{"/team-a/"}, []string{"a/*"}},
		{[]string{"team-c"}, []string{"a/*", "c/*"}},
		{[]string{"team-a", "team-c"}, []string{"a/*", "c/*"}},
		{[]string{"other"}, []string{"b/*"}},
		{nil, []string{"b/*"}},
	}
	for _, tc := range cases {
		if got := c.ProvidersFor(tc.groups); !slices.Equal(got, tc.want) {
			t.Fatalf("ProvidersFor(%v) = %v, want %v", tc.groups, got, tc.want)
		}
	}
}

// A person's own entry beats the groups they are in, by email (whatever its
// case) or by subject; what they leave out still comes from their groups.
func TestUsersOverrideTheirGroups(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c, err := (&Config{
		Issuer:       "https://id.example.com",
		ClientID:     "x",
		RedirectURL:  "https://m.example.com/cb",
		CookieSecret: strings.Repeat("c", 32),
		Groups: map[string][]string{
			"team-a": {"a"},
			"team-c": {"c", "a"},
		},
		Budget: &BudgetConfig{Period: "month", Cost: 20},
		Users: map[string]UserPolicy{
			"Alice@Example.com": {Models: []string{"a/one-model"}, Budget: &BudgetConfig{Period: "month", Cost: 5}},
			"bob-subject":       {Budget: &BudgetConfig{Period: "week", Cost: 1}},
		},
	}).Prepare()
	if err != nil {
		t.Fatal(err)
	}

	alice := Identity{Subject: "alice", Email: "ALICE@example.COM", Groups: []string{"team-a"}}
	if got := c.ModelsFor(alice); !slices.Equal(got, []string{"a/one-model"}) {
		t.Fatalf("alice models = %v", got)
	}
	if l := c.BudgetFor(alice); l == nil || l.Cost != 5 || l.Period != "month" {
		t.Fatalf("alice budget = %+v", l)
	}

	// bob's entry sets only a budget: his models still come from his groups.
	bob := Identity{Subject: "bob-subject", Email: "bob@example.com", Groups: []string{"team-c"}}
	if got := c.ModelsFor(bob); !slices.Equal(got, []string{"a/*", "c/*"}) {
		t.Fatalf("bob models = %v", got)
	}
	if l := c.BudgetFor(bob); l == nil || l.Cost != 1 || l.Period != "week" {
		t.Fatalf("bob budget = %+v", l)
	}

	// Someone with no entry keeps the groups and the config's budget.
	carol := Identity{Subject: "carol", Email: "carol@example.com", Groups: []string{"team-a"}}
	if got := c.ModelsFor(carol); !slices.Equal(got, []string{"a/*"}) {
		t.Fatalf("carol models = %v", got)
	}
	if l := c.BudgetFor(carol); l == nil || l.Cost != 20 || l.Period != "month" {
		t.Fatalf("carol budget = %+v", l)
	}

	none := &Config{}
	if l := none.BudgetFor(carol); l != nil {
		t.Fatalf("no budget configured gave %+v", l)
	}
}

func TestRolesDecide(t *testing.T) {
	c := &Config{} // no admin fields at all
	super := Identity{Subject: "s", Groups: []string{"magpie-super"}}
	operator := Identity{Subject: "s", Groups: []string{"magpie-operator"}}
	plain := Identity{Subject: "s"}
	if !c.IsAdmin(super) || !c.IsSuperAdmin(super) {
		t.Fatal("magpie-super is not the super admin")
	}
	if !c.IsAdmin(operator) {
		t.Fatal("magpie-operator is not an admin")
	}
	if c.IsSuperAdmin(operator) {
		t.Fatal("magpie-operator reads as a super admin")
	}
	if c.IsAdmin(plain) || c.IsSuperAdmin(plain) {
		t.Fatal("a person with no role reads as an admin")
	}
}

func TestGroupPatternsAreKeyPatterns(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c, err := (&Config{
		Issuer:       "https://id.example.com",
		ClientID:     "x",
		RedirectURL:  "https://m.example.com/cb",
		CookieSecret: strings.Repeat("c", 32),
		Groups:       map[string][]string{"team": {"a", "b/some-model"}},
	}).Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Groups["team"]; !slices.Equal(got, []string{"a/*", "b/some-model"}) {
		t.Fatalf("patterns = %v", got)
	}
}

func TestConfigHasNoAdminFields(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "oidc.yaml")
	src := []byte("issuer: http://x\nclient_id: c\nredirect_url: http://x/cb\nlisten: :0\n" +
		"admins: [a@x]\nsuper_admins: [b@x]\n")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("a config with the retired fields loads, ignored: %v", err)
	}
}
