package oidcportal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/yetone/magpie/internal/access"
)

var (
	// ErrNoAccess is a user whose groups name no provider and who has no
	// default to fall back on: they get no key.
	ErrNoAccess = errors.New("no configured group gives this user a provider")
	// ErrDisabled is a user an admin has turned away; signing in again does
	// not make them a key.
	ErrDisabled = errors.New("this user's key has been disabled")
	// ErrUnknownUser is a rotation asked for a user the portal has no key
	// for.
	ErrUnknownUser = errors.New("the portal has made no key for this user")
)

// Provisioner keeps each signed-in user's gateway key: one key per subject,
// named and held to the providers their groups name, its value kept in the
// portal's state so the portal can show it again.
type Provisioner struct {
	cfg   *Config
	state *State
}

func NewProvisioner(cfg *Config, state *State) *Provisioner {
	return &Provisioner{cfg: cfg, state: state}
}

// EnsureUser makes the identity's key or brings it up to the groups they
// signed in with, and returns the record, its key value included. It is the
// path an auto-provisioning portal takes; one that keeps policies calls
// EnsureScoped with the grant an admin made.
func (p *Provisioner) EnsureUser(id Identity) (User, error) {
	return p.EnsureScoped(id, p.cfg.ModelsFor(id), p.cfg.BudgetFor(id))
}

// EnsureScoped makes the identity's key or brings it to models and budget,
// which the caller resolved (an admin's policy, or the config's defaults).
func (p *Provisioner) EnsureScoped(id Identity, models []string, budget *access.Limit) (User, error) {
	if strings.TrimSpace(id.Subject) == "" {
		return User{}, errors.New("the identity has no subject")
	}
	providers := models
	if !*p.cfg.Provision {
		providers = nil
	} else if len(providers) == 0 {
		return User{}, ErrNoAccess
	}
	return p.state.Update(id.Subject, func(u *User) error {
		return p.sync(u, id, providers, budget)
	})
}

// ApplyPolicy brings a person's key to the policy an admin set: active
// grants models and budget, disabled takes the key away. A pending or
// requested person has no key and is left alone.
func (p *Provisioner) ApplyPolicy(pol Policy) (User, error) {
	switch pol.Status {
	case StatusActive:
		models := pol.modelsFor(p.cfg)
		if len(models) == 0 {
			return User{}, ErrNoAccess
		}
		return p.EnsureScoped(pol.identity(), models, pol.budgetFor(p.cfg))
	case StatusDisabled:
		if u, ok := p.state.Get(pol.Sub); ok && u.KeyID != "" {
			return p.RemoveUser(pol.Sub)
		}
	}
	return User{}, nil
}

// Rotate gives the user's key a new value and leaves its id, scope and
// on/off state as they were.
func (p *Provisioner) Rotate(sub string) (User, error) {
	return p.state.Update(sub, func(u *User) error {
		if u.Disabled {
			return ErrDisabled
		}
		if u.KeyID == "" {
			return ErrUnknownUser
		}
		u.rememberKey(u.KeyID)
		keys, err := access.List()
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(keys, func(k access.Key) bool { return k.ID == u.KeyID }) {
			u.KeyID, u.Key = "", ""
			return ErrUnknownUser
		}
		secret, err := access.Update("rotate-key", access.Change{Key: u.KeyID})
		if err != nil {
			return err
		}
		u.Key, u.Generation = secret, u.Generation+1
		return nil
	})
}

// RemoveUser deletes the user's gateway key and marks them disabled, so a
// later sign-in does not make a new one.
func (p *Provisioner) RemoveUser(sub string) (User, error) {
	return p.state.Update(sub, func(u *User) error {
		if u.KeyID != "" {
			keys, err := access.List()
			if err != nil {
				return err
			}
			if slices.ContainsFunc(keys, func(k access.Key) bool { return k.ID == u.KeyID }) {
				if _, err := access.Update("remove-key", access.Change{Key: u.KeyID}); err != nil {
					return err
				}
			}
		}
		u.KeyID, u.Key, u.Disabled = "", "", true
		return nil
	})
}

// EnableUser lets a disabled user sign in again; their next sign-in makes a
// key.
func (p *Provisioner) EnableUser(sub string) (User, error) {
	return p.state.Update(sub, func(u *User) error {
		if u.Sub == "" {
			return ErrUnknownUser
		}
		u.Disabled = false
		return nil
	})
}

func (p *Provisioner) sync(u *User, id Identity, providers []string, budget *access.Limit) error {
	if u.Disabled {
		return ErrDisabled
	}
	u.Email, u.Name, u.Username, u.Groups = id.Email, displayName(id), id.Username, slices.Clone(id.Groups)
	u.Providers = slices.Clone(providers)

	keys, err := access.List()
	if err != nil {
		return err
	}
	// The key's name is what magpie's console shows, so it reads as the
	// person: Keycloak's preferred_username. The subject stays the
	// portal's identity; a username another person already holds gets a
	// short subject suffix.
	name := keyNameFor(p.cfg.KeyNamePrefix, id)
	if other, ok := keyWithName(keys, name); ok {
		// A single, unclaimed key with this name is adopted below when the
		// portal has no key for the person (a lost state file). Two keys
		// with it, one another person's record already holds, or one this
		// person's record does not name, means the plain name is taken:
		// suffix it so no one is handed a neighbour's key.
		_, single := adoptable(keys, name)
		_, claimed := p.state.keyOwnerLocked(other.ID, u.Sub)
		mine := u.KeyID != "" && other.ID == u.KeyID
		if !mine && (claimed || u.KeyID != "" || !single) {
			name = uniqueKeyName(p.cfg.KeyNamePrefix, id)
		}
	}
	if u.KeyID != "" && !slices.ContainsFunc(keys, func(k access.Key) bool { return k.ID == u.KeyID }) {
		// caller-keys.json lost the key (removed by hand, or a restore):
		// make another rather than hand out a value no gateway knows.
		u.KeyID, u.Key = "", ""
	}
	if u.KeyID == "" {
		if k, ok := adoptable(keys, name); ok {
			u.KeyID = k.ID
			u.rememberKey(u.KeyID)
			if u.Generation == 0 {
				u.Generation = 1
			}
		}
	}
	if u.KeyID == "" {
		var secret string
		var err error
		u.KeyID, secret, err = makeKey(name, providers, budget)
		if err != nil {
			return err
		}
		u.rememberKey(u.KeyID)
		u.Key, u.Generation = secret, 1
		return nil
	}
	u.rememberKey(u.KeyID)

	k, ok := keyByID(keys, u.KeyID)
	if !ok {
		return ErrUnknownUser
	}
	// Read the value the store has now, not the one the state remembers: a
	// rotation whose state write failed, or one made outside the portal,
	// would otherwise show a key no gateway accepts.
	secret, err := access.Update("copy-key", access.Change{Key: u.KeyID})
	if err != nil {
		return err
	}
	u.Key = secret
	if k.Name != name {
		if _, err := access.Update("rename-key", access.Change{Key: u.KeyID, Name: name}); err != nil {
			return err
		}
	}
	if !slices.Equal(k.Models, providers) {
		if _, err := access.Update("models-key", access.Change{Key: u.KeyID, Models: providers}); err != nil {
			return err
		}
	}
	want, err := budget.Valid()
	if err != nil {
		return err
	}
	if !sameLimit(k.Limit, want) {
		if _, err := access.Update("limit-key", access.Change{Key: u.KeyID, Limit: want}); err != nil {
			return err
		}
	}
	if !k.Quotas {
		if _, err := access.Update("quotas-key", access.Change{Key: u.KeyID, Quotas: true}); err != nil {
			return err
		}
	}
	if k.ReadOnly {
		// A provision interrupted between add-key and access-key leaves
		// the key read-only; finish it here rather than hand out a key
		// no model call accepts.
		if _, err := access.Update("access-key", access.Change{Key: u.KeyID}); err != nil {
			return err
		}
	}
	return nil
}

// makeKey adds a gateway key with its scope in place, using only the actions
// magpie's key store offers: add-key takes a name, a value and read-only,
// and models-key, limit-key and quotas-key set the rest.
//
// The key is added read-only, which lets it read stats but call no model,
// and is only made usable after its scope is set. An interrupted provision
// thus leaves a harmless key, not an unrestricted one. If a later step
// fails, the key is removed; if even that fails, the read-only key is
// adopted and finished by the next sign-in.
func makeKey(name string, providers []string, budget *access.Limit) (id, secret string, err error) {
	secret, err = access.Update("add-key", access.Change{Name: name, ReadOnly: true})
	if err != nil {
		return "", "", err
	}
	who, ok := access.Authenticate(secret)
	if !ok {
		return "", "", errors.New("the key magpie just made does not authenticate")
	}
	id = who.KeyID
	fail := func(err error) (string, string, error) {
		_, _ = access.Update("remove-key", access.Change{Key: id})
		return "", "", err
	}
	if len(providers) > 0 {
		if _, err := access.Update("models-key", access.Change{Key: id, Models: providers}); err != nil {
			return fail(err)
		}
	}
	lim, err := budget.Valid()
	if err != nil {
		return fail(err)
	}
	if lim != nil {
		if _, err := access.Update("limit-key", access.Change{Key: id, Limit: lim}); err != nil {
			return fail(err)
		}
	}
	if _, err := access.Update("quotas-key", access.Change{Key: id, Quotas: true}); err != nil {
		return fail(err)
	}
	if _, err := access.Update("access-key", access.Change{Key: id}); err != nil {
		return fail(err)
	}
	return id, secret, nil
}

// adoptable finds a key a lost state file would otherwise leave orphaned:
// one named exactly as the portal names this user's, and only one.
func adoptable(keys []access.Key, name string) (access.Key, bool) {
	var found access.Key
	n := 0
	for _, k := range keys {
		if k.Name == name {
			found, n = k, n+1
		}
	}
	return found, n == 1
}

// keyWithName is a key already named name, if there is one: the name may be
// another person's, which is why the caller compares the id.
func keyWithName(keys []access.Key, name string) (access.Key, bool) {
	for _, k := range keys {
		if k.Name == name {
			return k, true
		}
	}
	return access.Key{}, false
}

// keyNameFor names the person's key after what they are called in Keycloak:
// preferred_username, then the email's local part, then the subject. The
// portal's identity stays the subject; only the label magpie shows changes.
func keyNameFor(prefix string, id Identity) string {
	name := strings.TrimSpace(id.Username)
	if name == "" {
		name = strings.TrimSpace(id.Email)
		if i := strings.IndexByte(name, '@'); i > 0 {
			name = name[:i]
		}
	}
	if name == "" {
		name = id.Subject
	}
	return keyName(prefix, name)
}

// uniqueKeyName is keyNameFor with a short subject suffix, for a username
// two people share: the same person always gets the same name, and the two
// never collide.
func uniqueKeyName(prefix string, id Identity) string {
	sum := sha256.Sum256([]byte(id.Subject))
	suffix := "-" + hex.EncodeToString(sum[:3])
	base := keyNameFor(prefix, id)
	const max = 120
	if utf8.RuneCountInString(base)+len(suffix) > max {
		base = string([]rune(base)[:max-len(suffix)])
	}
	return base + suffix
}

func keyByID(keys []access.Key, id string) (access.Key, bool) {
	for _, k := range keys {
		if k.ID == id {
			return k, true
		}
	}
	return access.Key{}, false
}

// keyName is the name the portal keeps the user's key under, within
// magpie's 120 characters; a subject too long for that ends in a hash, so
// two of them never share a name.
func keyName(prefix, sub string) string {
	const max = 120
	name := prefix + sub
	if utf8.RuneCountInString(name) <= max {
		return name
	}
	sum := sha256.Sum256([]byte(sub))
	suffix := "-" + hex.EncodeToString(sum[:4])
	keep := max - utf8.RuneCountInString(suffix)
	return string([]rune(name)[:keep]) + suffix
}

func displayName(id Identity) string {
	for _, s := range []string{id.Name, id.Email, id.Username} {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return id.Subject
}

// sameLimit compares what the config sets, not Since: the window a limit is
// in is magpie's, and resetting it because the config was re-read would
// give the user a fresh budget every sign-in.
func sameLimit(a, b *access.Limit) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Period == b.Period && a.Days == b.Days && a.Hours == b.Hours &&
		a.Tokens == b.Tokens && a.Cost == b.Cost && a.CacheReads == b.CacheReads
}
