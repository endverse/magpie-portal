package oidcportal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/edit"
)

// A person's standing at the portal: signed in but not asked for yet,
// waiting for an admin, let in, or turned away. The portal keeps this, not
// Keycloak's groups: who may use which upstream is a decision an admin
// makes for each person.
const (
	StatusPending   = "pending"   // signed in, has not applied
	StatusRequested = "requested" // applied, waits for an admin
	StatusActive    = "active"    // may use models and holds a key
	StatusDisabled  = "disabled"  // an admin turned them away
	StatusRejected  = "rejected"  // an admin declined the application
)

// Policy is one person's grant: the models their key may use, its budget,
// and where their application stands. It is the portal's own record and the
// source of truth for per-person access; oidc.yaml's users: and groups: are
// defaults for a deployment that does not use the portal's admin page.
type Policy struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// GroupStash holds the groups an admin granted with while the person's
	// sign-in claims carried none (a role given after the approval): the
	// grant then resolves through them until an admin edits it.
	GroupStash  []string      `json:"grantGroups,omitempty"`
	Status      string        `json:"status"`
	Models      []string      `json:"models,omitempty"`
	Budget      *BudgetConfig `json:"budget,omitempty"`
	RequestedAt time.Time     `json:"requestedAt,omitzero"`
	ApprovedAt  time.Time     `json:"approvedAt,omitzero"`
	ApprovedBy  string        `json:"approvedBy,omitempty"`
	LastSeen    time.Time     `json:"lastSeen,omitzero"`
	Note        string        `json:"note,omitempty"`
	UpdatedAt   time.Time     `json:"updatedAt,omitzero"`
}

// PolicyStore is the portal's policy file: every person who has signed in,
// and what an admin granted them. Like State, a file that cannot be read is
// an error, never an empty store: an empty one would put everyone back to
// pending.
type PolicyStore struct {
	path      string
	mu        sync.Mutex
	data      map[string]Policy
	templates map[string]UserPolicy
}

type policyFile struct {
	Version int               `json:"version"`
	Users   map[string]Policy `json:"users"`
	// Templates are named grants an admin applies to a person; kept here so
	// a later page can offer them without another file.
	Templates map[string]UserPolicy `json:"templates,omitempty"`
	// templates is kept as read so a write does not drop what this build
	// does not use yet.
	templates map[string]UserPolicy
}

// OpenPolicy reads path, or starts an empty store when it does not exist.
func OpenPolicy(path string) (*PolicyStore, error) {
	s := &PolicyStore{path: path, data: map[string]Policy{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f policyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Users != nil {
		s.data = f.Users
	}
	s.templates = f.Templates
	return s, nil
}

// Get is a copy of the person's policy.
func (s *PolicyStore) Get(sub string) (Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.data[sub]
	return p, ok
}

// List is every policy, by email then subject.
func (s *PolicyStore) List() []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, 0, len(s.data))
	for _, p := range s.data {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Email), strings.ToLower(out[j].Email)
		if a != b {
			return a < b
		}
		return out[i].Sub < out[j].Sub
	})
	return out
}

// Seen records who just signed in: their email, name and groups as the
// provider said, and when. A person the store has never held starts
// pending; one it holds keeps their standing.
func (s *PolicyStore) Seen(id Identity) (Policy, error) {
	return s.Update(id.Subject, func(p *Policy) error {
		if p.Status == "" {
			p.Status = StatusPending
		}
		p.Email, p.Name = id.Email, id.Name
		p.Groups = append([]string(nil), id.Groups...)
		p.LastSeen = time.Now().UTC()
		return nil
	})
}

// Request moves a person to waiting for an admin; applying again after a
// rejection is allowed. An active or disabled person is left as they are.
func (s *PolicyStore) Request(sub string) (Policy, error) {
	return s.Update(sub, func(p *Policy) error {
		switch p.Status {
		case StatusActive, StatusDisabled, StatusRequested:
			return nil
		}
		p.Status, p.RequestedAt = StatusRequested, time.Now().UTC()
		return nil
	})
}

// CancelRequest takes an application back.
func (s *PolicyStore) CancelRequest(sub string) (Policy, error) {
	return s.Update(sub, func(p *Policy) error {
		if p.Status == StatusRequested {
			p.Status = StatusPending
		}
		return nil
	})
}

// Approve grants the person models and a budget and lets them in. Models
// may be empty only when their groups name some (modelsFor does the same
// fallback); an empty fit for nothing is an error, so an approval never
// leaves a person active with no key.
func (s *PolicyStore) Approve(sub, by string, models []string, budget *BudgetConfig, note string) (Policy, error) {
	clean, err := normalizePatterns(models)
	if err != nil {
		return Policy{}, fmt.Errorf("models: %w", err)
	}
	if budget != nil {
		if _, err := budget.limit().Valid(); err != nil {
			return Policy{}, fmt.Errorf("budget: %w", err)
		}
	}
	return s.Update(sub, func(p *Policy) error {
		if p.Email == "" && p.Sub == "" {
			return errors.New("no such person: they must sign in first")
		}
		p.Status = StatusActive
		p.Models = clean
		p.Budget = budget
		p.Note = strings.TrimSpace(note)
		p.ApprovedAt, p.ApprovedBy = time.Now().UTC(), by
		return nil
	})
}

// Save changes an active person's models and budget without touching their
// standing or approval history.
func (s *PolicyStore) Save(sub string, models []string, budget *BudgetConfig, note string) (Policy, error) {
	clean, err := normalizePatterns(models)
	if err != nil {
		return Policy{}, fmt.Errorf("models: %w", err)
	}
	if budget != nil {
		if _, err := budget.limit().Valid(); err != nil {
			return Policy{}, fmt.Errorf("budget: %w", err)
		}
	}
	return s.Update(sub, func(p *Policy) error {
		if p.Status == "" {
			return errors.New("no such person: they must sign in first")
		}
		p.Models, p.Budget = clean, budget
		p.Note = strings.TrimSpace(note)
		return nil
	})
}

// Reject declines an application.
func (s *PolicyStore) Reject(sub, by, note string) (Policy, error) {
	return s.Update(sub, func(p *Policy) error {
		p.Status, p.ApprovedBy, p.Note = StatusRejected, by, strings.TrimSpace(note)
		return nil
	})
}

// Disable stops a person from using their key.
func (s *PolicyStore) Disable(sub, by, note string) (Policy, error) {
	return s.Update(sub, func(p *Policy) error {
		p.Status, p.ApprovedBy, p.Note = StatusDisabled, by, strings.TrimSpace(note)
		return nil
	})
}

// Enable lets a disabled or rejected person in again with the grant they
// had, if any; an admin may grant it anew.
func (s *PolicyStore) Enable(sub, by string) (Policy, error) {
	return s.Update(sub, func(p *Policy) error {
		switch p.Status {
		case StatusDisabled, StatusRejected:
			p.Status, p.ApprovedBy = StatusActive, by
		}
		return nil
	})
}

// Adopt turns an existing key into an active policy, for a deployment that
// ran before the portal kept policies: nobody loses access on the upgrade.
func (s *PolicyStore) Adopt(id Identity, models []string, budget *BudgetConfig) (Policy, error) {
	return s.Update(id.Subject, func(p *Policy) error {
		if p.Status == StatusActive {
			return nil
		}
		p.Email, p.Name = id.Email, id.Name
		p.Groups = append([]string(nil), id.Groups...)
		p.Status, p.Models, p.Budget = StatusActive, models, budget
		p.ApprovedAt, p.ApprovedBy = time.Now().UTC(), "migration"
		return nil
	})
}

// EnsureAdmin gives an admin or super admin, as the roles they hold give
// them, an active grant when they have none yet: the console they may open
// asks as their own gateway key, so an admin needs one like everyone else.
// What they already have is left as it is; a disabled or rejected person
// stays out.
func (s *PolicyStore) EnsureAdmin(id Identity, models []string, budget *BudgetConfig) (Policy, error) {
	if pol, ok := s.Get(id.Subject); ok && pol.Status != "" && pol.Status != StatusPending {
		return pol, nil
	}
	return s.Adopt(id, models, budget)
}

// Update changes one policy under the store's lock and writes the file
// before it returns; an error leaves the store as it was.
func (s *PolicyStore) Update(sub string, fn func(*Policy) error) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.data[sub]
	if p.Sub == "" {
		p.Sub = sub
	}
	before := p
	if err := fn(&p); err != nil {
		return before, err
	}
	p.Sub = sub
	p.UpdatedAt = time.Now().UTC()
	s.data[sub] = p
	if err := s.saveLocked(); err != nil {
		if before.Sub == "" {
			delete(s.data, sub)
		} else {
			s.data[sub] = before
		}
		return before, err
	}
	return p, nil
}

func (s *PolicyStore) saveLocked() error {
	b, err := json.MarshalIndent(policyFile{Version: 1, Users: s.data, Templates: s.templates}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := edit.WriteAtomic(s.path, b); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}

// modelsFor is the models a policy grants: its own, or, failing that, the
// providers its groups name.
func (p Policy) modelsFor(c *Config) []string {
	if len(p.Models) > 0 {
		return append([]string(nil), p.Models...)
	}
	if out := c.ProvidersFor(p.Groups); len(out) > 0 {
		return out
	}
	have := make(map[string]bool, len(p.GroupStash))
	for _, g := range p.GroupStash {
		have[strings.Trim(strings.TrimSpace(g), "/")] = true
	}
	return c.providersNamed(have)
}

// budgetFor is the limit a policy grants: its own, or the config's.
func (p Policy) budgetFor(c *Config) *access.Limit {
	if p.Budget != nil {
		if l, err := p.Budget.limit().Valid(); err == nil {
			return l
		}
	}
	if l, err := c.Budget.limit().Valid(); err == nil {
		return l
	}
	return nil
}

// identity is the policy as the person who signed in, for provisioning.
func (p Policy) identity() Identity {
	return Identity{Subject: p.Sub, Email: p.Email, Name: p.Name, Groups: p.Groups}
}
