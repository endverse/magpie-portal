// Package oidcportal is the OIDC control plane for magpie's gateway keys: a
// user signs in at an OpenID Connect provider (Keycloak and the like), and
// the portal keeps that user's gateway key held to the providers their
// groups name. It is a separate program (cmd/magpie-oidc), not a plugin:
// the gateway's plugins never see the caller's key, and a page plugin can't
// reach the network. It runs on the same computer and as the same user as
// magpie, so access.Update writes the very store the gateway reads.
package oidcportal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/edit"
	"github.com/yetone/magpie/internal/settings"
	"gopkg.in/yaml.v3"
)

// Config is what the portal is run with: the OIDC client, where the portal
// listens, and which provider patterns each group of users may use.
type Config struct {
	Issuer       string `yaml:"issuer" json:"issuer"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
	RedirectURL  string `yaml:"redirect_url" json:"redirect_url"`
	Listen       string `yaml:"listen" json:"listen"`

	// ConsoleURL is magpie's own web console, which this portal fronts at
	// /console: http://magpie:3430 in the Docker network. Empty turns the
	// console proxy off.
	ConsoleURL string `yaml:"console_url" json:"console_url"`
	// ConsoleWebKey is the MAGPIE_WEB_KEY that console is served with. The
	// sidecar injects it on the way upstream; the browser never sees it.
	// Empty reads $MAGPIE_WEB_KEY.
	ConsoleWebKey string `yaml:"console_web_key" json:"console_web_key"`
	// ConsoleCookie is the console's sign-in cookie name, derived from the
	// console URL's port ("magpie_web_3430") when empty.
	ConsoleCookie string `yaml:"console_cookie" json:"console_cookie"`
	// GatewayURL is the running gateway, where the key page's own data is
	// asked for with the person's key (/v1/magpie/me): http://magpie:3425
	// in the Docker network. Empty falls back to the console URL's host on
	// the gateway's port.
	GatewayURL string `yaml:"gateway_url" json:"gateway_url"`
	// state answers ConsoleKeyFor; NewServer sets it.
	state *State

	// Groups maps an OIDC group (a Keycloak group path, its leading slash
	// optional) to what its members may use: provider patterns as a
	// gateway key keeps them, "<provider>/*" or "<provider>/<model>". A
	// bare "<provider>" is short for "<provider>/*".
	Groups map[string][]string `yaml:"groups" json:"groups"`
	// DefaultProviders are what a user whose groups match none may use.
	// Empty means such a user gets no key, and the portal turns them away.
	DefaultProviders []string `yaml:"default_providers" json:"default_providers"`
	// Users are per-person overrides, by email (ignoring case) or by OIDC
	// subject: the models that person's key may use and its budget, instead
	// of what their groups give. A key is one person's, so this is how one
	// key gets a model list or a monthly cost of its own.
	Users map[string]UserPolicy `yaml:"users" json:"users"`

	// Admins and AdminGroups say who may open the portal's admin page,
	// by email or subject, and by OIDC group. SuperAdmins and
	// SuperAdminGroups are admins who may also read request and response
	// contents: no content is readable while these are empty.
	Admins           []string `yaml:"admins" json:"admins"`
	AdminGroups      []string `yaml:"admin_groups" json:"admin_groups"`
	SuperAdmins      []string `yaml:"super_admins" json:"super_admins"`
	SuperAdminGroups []string `yaml:"super_admin_groups" json:"super_admin_groups"`

	// GroupClaim is the ID token claim holding the user's groups; "groups"
	// by default, or Keycloak's "realm_access.roles" to map realm roles
	// instead. A dotted path reaches into an object.
	GroupClaim string   `yaml:"group_claim" json:"group_claim"`
	Scopes     []string `yaml:"scopes" json:"scopes"`

	// KeyNamePrefix starts each key's name in caller-keys.json
	// ("oidc:<sub>"), which is how the portal finds it again if its own
	// state file is lost.
	KeyNamePrefix string `yaml:"key_name_prefix" json:"key_name_prefix"`

	// StateFile is where the portal keeps each user's key id, generation
	// and key value. It is written 0600, like caller-keys.json.
	StateFile string `yaml:"state_file" json:"state_file"`
	// PolicyFile is where the portal keeps each person's grant and
	// standing: what an admin assigned, and whether they applied. Written
	// 0600.
	PolicyFile string `yaml:"policy_file" json:"policy_file"`

	// AutoProvision, on, grants a new person what oidc.yaml's users: and
	// groups: say without an admin approving them, as the portal did
	// before it kept policies. Off by default: a person applies, an admin
	// assigns their models and budget.
	AutoProvision *bool `yaml:"auto_provision" json:"auto_provision"`

	// Fetch is whether this portal serves magpie's own console page to its
	// signed-in people (consolepage.go), from ConsoleURL, with their own
	// data behind it; with it off, the console is the proxy's own pages under
	// /console/ (console.go). It is the portal's, not a setting.
	Fetch bool `yaml:"-" json:"-"`

	// Notify and Hooks are where applications and approvals are announced,
	// and where an approval system (Feishu and the like) may call in.
	Notify NotifyConfig `yaml:"notify" json:"notify"`
	Hooks  HookConfig   `yaml:"hooks" json:"hooks"`
	// CookieSecret signs the portal's session and login cookies. Empty
	// reads (or makes, once) ~/.config/magpie/oidc-cookie.key.
	CookieSecret string `yaml:"cookie_secret" json:"cookie_secret"`

	// Budget, when set, is each key's limit (access.Limit): a period and
	// a cost or token cap.
	Budget *BudgetConfig `yaml:"budget" json:"budget"`

	// Provision says whether to hold each key to the providers its groups
	// name. It is on unless a config says otherwise; a portal that only
	// hands out unrestricted keys is not a thing to leave on by accident.
	Provision *bool `yaml:"provision" json:"provision"`
}

// UserPolicy is one person's override of what their groups give. Models
// left out keeps the groups' providers; Budget left out keeps the config's
// budget.
type UserPolicy struct {
	Models []string      `yaml:"models" json:"models"`
	Budget *BudgetConfig `yaml:"budget" json:"budget"`
}

// BudgetConfig is a key's limit as the config writes it.
type BudgetConfig struct {
	Period string  `yaml:"period" json:"period"`
	Days   int     `yaml:"days" json:"days"`
	Hours  int     `yaml:"hours" json:"hours"`
	Cost   float64 `yaml:"cost" json:"cost"`
	Tokens int64   `yaml:"tokens" json:"tokens"`
}

// NotifyConfig announces an application outside the portal: a generic
// webhook that receives JSON, or a Feishu bot's webhook. Both empty means
// applications are only listed on the admin page.
type NotifyConfig struct {
	Webhook string `yaml:"webhook" json:"webhook"`
	Feishu  string `yaml:"feishu" json:"feishu"`
}

// HookConfig is the shared secret an approval system signs its calls with:
// POST /hooks/approval, HMAC-SHA256 of the body in X-Magpie-Signature.
// Empty turns the hook off.
type HookConfig struct {
	Secret string `yaml:"secret" json:"secret"`
}

func (b *BudgetConfig) limit() *access.Limit {
	if b == nil {
		return nil
	}
	return &access.Limit{Period: b.Period, Days: b.Days, Hours: b.Hours, Cost: b.Cost, Tokens: b.Tokens}
}

// LoadConfig reads a YAML (or JSON) config at path and fills its defaults.
// A file OIDC cannot work without is an error, never a zero value that
// leaves the portal open.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return c.Prepare()
}

// Prepare fills the defaults and checks the config.
func (c *Config) Prepare() (*Config, error) {
	c.Fetch = true
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		c.Listen = "127.0.0.1:3440"
	}
	if c.KeyNamePrefix == "" {
		c.KeyNamePrefix = "oidc:"
	}
	if c.GroupClaim == "" {
		c.GroupClaim = "groups"
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	} else if !slicesContainsFold(c.Scopes, "openid") {
		c.Scopes = append([]string{"openid"}, c.Scopes...)
	}
	var err error
	if c.Issuer == "" {
		return nil, errors.New("issuer is required: the OIDC provider's URL, like https://keycloak.example.com/realms/main")
	}
	if u, err := url.Parse(c.Issuer); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("issuer %q is not an http(s) URL", c.Issuer)
	}
	if c.ClientID == "" {
		return nil, errors.New("client_id is required")
	}
	if c.RedirectURL == "" {
		return nil, errors.New("redirect_url is required: it must be the OIDC client's redirect URI, like https://magpie.example.com/callback")
	}
	if u, err := url.Parse(c.RedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("redirect_url %q is not an http(s) URL", c.RedirectURL)
	}
	c.ConsoleURL = strings.TrimSpace(c.ConsoleURL)
	c.ConsoleWebKey = strings.TrimSpace(c.ConsoleWebKey)
	c.ConsoleCookie = strings.TrimSpace(c.ConsoleCookie)
	if c.ConsoleWebKey == "" {
		c.ConsoleWebKey = strings.TrimSpace(os.Getenv("MAGPIE_WEB_KEY"))
	}
	if c.ConsoleURL != "" {
		u, err := url.Parse(c.ConsoleURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("console_url %q is not an http(s) URL", c.ConsoleURL)
		}
		if c.ConsoleWebKey == "" {
			return nil, errors.New("console_web_key is required with console_url (or set MAGPIE_WEB_KEY): the console's own key")
		}
		if len(c.ConsoleWebKey) < 16 {
			return nil, errors.New("console_web_key needs at least 16 characters")
		}
		if c.ConsoleCookie == "" {
			c.ConsoleCookie = "magpie_web_" + consolePort(u)
		}
		if strings.ContainsAny(c.ConsoleCookie, " \t\r\n;,=") {
			return nil, errors.New("console_cookie is not a cookie name")
		}
	}
	c.GatewayURL = strings.TrimSpace(c.GatewayURL)
	if c.GatewayURL == "" && c.ConsoleURL != "" {
		if u, err := url.Parse(c.ConsoleURL); err == nil {
			c.GatewayURL = u.Scheme + "://" + u.Hostname() + ":" + gatewayPort
		}
	}
	if c.GatewayURL != "" {
		u, err := url.Parse(c.GatewayURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("gateway_url %q is not an http(s) URL", c.GatewayURL)
		}
		c.GatewayURL = strings.TrimSuffix(c.GatewayURL, "/")
	}
	if c.StateFile == "" {
		c.StateFile = filepath.Join(settings.Dir(), "oidc-state.json")
	}
	if c.PolicyFile == "" {
		c.PolicyFile = filepath.Join(settings.Dir(), "oidc-policy.json")
	}
	if c.AutoProvision == nil {
		off := false
		c.AutoProvision = &off
	}
	c.Notify.Webhook = strings.TrimSpace(c.Notify.Webhook)
	c.Notify.Feishu = strings.TrimSpace(c.Notify.Feishu)
	for name, v := range map[string]string{"notify.webhook": c.Notify.Webhook, "notify.feishu": c.Notify.Feishu} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("%s %q is not an http(s) URL", name, v)
		}
	}
	c.Hooks.Secret = strings.TrimSpace(c.Hooks.Secret)
	if c.Hooks.Secret != "" && len(c.Hooks.Secret) < 16 {
		return nil, errors.New("hooks.secret needs at least 16 characters")
	}
	if c.CookieSecret == "" {
		c.CookieSecret, err = cookieSecret(filepath.Join(settings.Dir(), "oidc-cookie.key"))
		if err != nil {
			return nil, err
		}
	}
	if len(c.CookieSecret) < 32 {
		return nil, errors.New("cookie_secret needs at least 32 characters")
	}
	if c.Provision == nil {
		on := true
		c.Provision = &on
	}
	c.Groups, err = normalizeGroups(c.Groups)
	if err != nil {
		return nil, err
	}
	if c.DefaultProviders, err = normalizePatterns(c.DefaultProviders); err != nil {
		return nil, fmt.Errorf("default_providers: %w", err)
	}
	sort.Strings(c.DefaultProviders)
	if _, err := c.Budget.limit().Valid(); err != nil {
		return nil, fmt.Errorf("budget: %w", err)
	}
	if c.Users, err = normalizeUsers(c.Users); err != nil {
		return nil, err
	}
	return c, nil
}

// gatewayPort is the port magpie's gateway listens on (MAGPIE_ADDR's
// default), where the key page's data is asked for.
const gatewayPort = "3425"

// consolePort is the port magpie's web server listens on, which names its
// sign-in cookie ("magpie_web_<port>"). The console URL's port when it has
// one; magpie's own web port otherwise.
func consolePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "3430"
}

// ProvidersFor is the provider patterns a user with groups may use: every
// matching group's patterns, deduplicated and sorted; the defaults when no
// group matches.
func (c *Config) ProvidersFor(groups []string) []string {
	have := make(map[string]bool, len(groups))
	for _, g := range groups {
		have[strings.Trim(strings.TrimSpace(g), "/")] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range sortedKeys(c.Groups) {
		if !have[strings.Trim(strings.TrimSpace(name), "/")] {
			continue
		}
		for _, p := range c.Groups[name] {
			if !seen[strings.ToLower(p)] {
				seen[strings.ToLower(p)] = true
				out = append(out, p)
			}
		}
	}
	if len(out) > 0 {
		sort.Strings(out)
		return out
	}
	return append([]string(nil), c.DefaultProviders...)
}

// ModelsFor is what the identity's key may use: its own policy's models
// when it sets some, else the providers its groups name.
func (c *Config) ModelsFor(id Identity) []string {
	if p, ok := c.policyFor(id); ok && len(p.Models) > 0 {
		return append([]string(nil), p.Models...)
	}
	return c.ProvidersFor(id.Groups)
}

// BudgetFor is the limit the identity's key gets: its own policy's budget
// when it sets one, else the config's budget, nil for none.
func (c *Config) BudgetFor(id Identity) *access.Limit {
	if p, ok := c.policyFor(id); ok && p.Budget != nil {
		l, _ := p.Budget.limit().Valid()
		return l
	}
	l, _ := c.Budget.limit().Valid()
	return l
}

// policyFor finds the identity's own entry by email first (ignoring case),
// then by subject.
func (c *Config) policyFor(id Identity) (UserPolicy, bool) {
	if email := strings.TrimSpace(id.Email); email != "" {
		if p, ok := c.Users[strings.ToLower(email)]; ok {
			return p, true
		}
	}
	if sub := strings.TrimSpace(id.Subject); sub != "" {
		if p, ok := c.Users[sub]; ok {
			return p, true
		}
	}
	return UserPolicy{}, false
}

func normalizeUsers(in map[string]UserPolicy) (map[string]UserPolicy, error) {
	out := make(map[string]UserPolicy, len(in))
	for who, p := range in {
		who = strings.TrimSpace(who)
		if who == "" {
			return nil, errors.New("users: a key (email or subject) is empty")
		}
		key := who
		if strings.Contains(who, "@") {
			key = strings.ToLower(who)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("users[%q]: named twice", who)
		}
		models, err := normalizePatterns(p.Models)
		if err != nil {
			return nil, fmt.Errorf("users[%q]: %w", who, err)
		}
		if len(models) == 0 && p.Budget == nil {
			return nil, fmt.Errorf("users[%q]: set models, budget, or both", who)
		}
		if _, err := p.Budget.limit().Valid(); err != nil {
			return nil, fmt.Errorf("users[%q] budget: %w", who, err)
		}
		out[key] = UserPolicy{Models: models, Budget: p.Budget}
	}
	return out, nil
}

// IsAdmin says whether the identity may open the admin page: its email or
// subject is in Admins, or one of its groups is in AdminGroups. A super
// admin is an admin too. No admin configured admits no one.
func (c *Config) IsAdmin(id Identity) bool {
	return c.IsSuperAdmin(id) || c.named(id, c.Admins, c.AdminGroups)
}

// IsSuperAdmin says whether the identity may do what only a super admin
// may, such as read a request's and reply's contents.
func (c *Config) IsSuperAdmin(id Identity) bool {
	return c.named(id, c.SuperAdmins, c.SuperAdminGroups)
}

// ConsoleKeyFor is the gateway key the portal asks magpie's console and the
// key page with for this identity: the one the portal made them. Empty when
// they have none.
func (c *Config) ConsoleKeyFor(id Identity) string {
	if c.state == nil {
		return ""
	}
	u, ok := c.state.GetAny(id.Subject)
	if !ok || u.Disabled {
		return ""
	}
	return u.Key
}

// KeyIDFor is ConsoleKeyFor's key id.
func (c *Config) KeyIDFor(id Identity) string {
	if c.state == nil {
		return ""
	}
	if u, ok := c.state.GetAny(id.Subject); ok && !u.Disabled {
		return u.KeyID
	}
	return ""
}

// emailNamed says whether an admin: or super_admins: entry names the
// identity's email or subject, rather than a group's membership.
func (c *Config) emailNamed(id Identity) bool {
	return namedPerson(id, c.Admins) || namedPerson(id, c.SuperAdmins)
}

func (c *Config) named(id Identity, people, groups []string) bool {
	if namedPerson(id, people) {
		return true
	}
	for _, g := range groups {
		if id.InGroup(g) {
			return true
		}
	}
	return false
}

func namedPerson(id Identity, people []string) bool {
	for _, a := range people {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.EqualFold(a, id.Email) || strings.EqualFold(a, id.Subject) {
			return true
		}
	}
	return false
}

func normalizeGroups(in map[string][]string) (map[string][]string, error) {
	out := make(map[string][]string, len(in))
	for name, patterns := range in {
		name = strings.Trim(strings.TrimSpace(name), "/")
		if name == "" {
			return nil, errors.New("groups: a group name is empty")
		}
		ps, err := normalizePatterns(patterns)
		if err != nil {
			return nil, fmt.Errorf("groups[%q]: %w", name, err)
		}
		out[name] = ps
	}
	return out, nil
}

// normalizePatterns keeps what access.CleanModels keeps, so a key made
// with them is made: a bare provider is its every model.
func normalizePatterns(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			p += "/*"
		}
		out = append(out, p)
	}
	return access.CleanModels(out)
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func slicesContainsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// cookieSecret reads the cookie secret beside magpie's config, or makes
// one the first time: a secret that changes each start would sign every
// user out, and change every derived key.
func cookieSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(b))
		if len(s) >= 32 {
			return s, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := hex.EncodeToString(b)
	if err := edit.WriteAtomic(path, []byte(s+"\n")); err != nil {
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	return s, nil
}
