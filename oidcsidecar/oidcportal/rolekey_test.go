package oidcportal

import (
	"testing"
)

// A person who was approved before they were given a role, and whose groups
// name no provider, still gets in once they hold one: the console asks as
// their own key, and the role is what they signed in with all along.
func TestAnOperatorApprovedEarlierStillGetsIn(t *testing.T) {
	cfg := approvalConfig(t)
	// The only models on offer are the ones an admin set in the config for
	// this person: the approval made before the role gave the standing the
	// groups they had then, which name no provider.
	cfg.Groups = map[string][]string{"team-c": {"openai/*"}}
	cfg.DefaultProviders = nil
	cfg.Users = map[string]UserPolicy{
		"li@example.com":  {Models: []string{"openai/*"}},
		"kim@example.com": {Models: []string{"openai/*"}},
	}

	li, kim := "li", "kim"
	fp := &fakeProvider{id: Identity{Subject: "nobody"}}
	ts, state, policy, _ := newTestServerFull(t, cfg, fp)

	id := Identity{Subject: li, Email: "li@example.com", Name: "Li", Groups: []string{RoleOperator}}
	if _, err := policy.Seen(id); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Update(li, func(p *Policy) error {
		p.Status, p.ApprovedBy = StatusActive, "boss"
		p.Groups = []string{"team-c"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fp.id = id
	signIn(t, ts, freshClient(ts), fp, "/")

	if pol := mustPolicy(t, policy, li); pol.Status != StatusActive || len(pol.modelsFor(cfg)) == 0 {
		t.Fatalf("policy after sign-in = %+v", pol)
	}
	u, ok := state.Get(li)
	if !ok || u.KeyID == "" {
		t.Fatalf("no key after sign-in: %+v, %v", u, ok)
	}

	// A person who was turned away stays away, role or no role.
	off := Identity{Subject: kim, Email: "kim@example.com", Groups: []string{RoleOperator}}
	if _, err := policy.Reject(kim, "boss", "not now"); err != nil {
		t.Fatal(err)
	}
	if pol, err := policy.EnsureAdmin(off, []string{"openai/*"}, nil); err != nil || pol.Status != StatusRejected {
		t.Fatalf("a rejected operator: %+v, %v", pol, err)
	}
	// The portal's sign-in takes no stand on who holds the role — that is
	// Keycloak's — so a refused person is let into the console by the
	// route gate alone. The admin page is where a super is refused.
	fp.id = Identity{Subject: kim, Email: "kim@example.com", Groups: []string{"team-c", RoleSuper}}
	signIn(t, ts, freshClient(ts), fp, "/")
	if pol := mustPolicy(t, policy, kim); pol.Status != StatusRejected {
		t.Fatalf("signing in adopted a rejected super: %+v", pol)
	}
	if _, err := policy.Update(kim, func(p *Policy) error {
		p.Status = StatusDisabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if pol, err := policy.EnsureAdmin(off, []string{"openai/*"}, nil); err != nil || pol.Status != StatusDisabled {
		t.Fatalf("a disabled operator: %+v, %v", pol, err)
	}
}

func mustPolicy(t *testing.T, p *PolicyStore, sub string) Policy {
	t.Helper()
	pol, ok := p.Get(sub)
	if !ok {
		t.Fatalf("no policy for %s", sub)
	}
	return pol
}
