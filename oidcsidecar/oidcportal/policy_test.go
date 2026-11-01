package oidcportal

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
)

func openTestPolicy(t *testing.T) *PolicyStore {
	t.Helper()
	s, err := OpenPolicy(filepath.Join(t.TempDir(), "oidc-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPolicyFromApplicationToGrant(t *testing.T) {
	s := openTestPolicy(t)
	id := Identity{Subject: "bob", Email: "bob@example.com", Name: "Bob", Groups: []string{"team-a"}}

	p, err := s.Seen(id)
	if err != nil || p.Status != StatusPending || p.Email != "bob@example.com" {
		t.Fatalf("seen = %+v, %v", p, err)
	}
	if p, _ = s.Request("bob"); p.Status != StatusRequested || p.RequestedAt.IsZero() {
		t.Fatalf("requested = %+v", p)
	}
	if p, _ = s.CancelRequest("bob"); p.Status != StatusPending {
		t.Fatalf("cancelled = %+v", p)
	}
	if p, _ = s.Request("bob"); p.Status != StatusRequested {
		t.Fatalf("re-applied = %+v", p)
	}

	p, err = s.Approve("bob", "boss@example.com", []string{"a", "c/gpt-5"}, &BudgetConfig{Period: "month", Cost: 10}, "welcome")
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != StatusActive || p.ApprovedBy != "boss@example.com" || p.Note != "welcome" {
		t.Fatalf("approved = %+v", p)
	}
	if !slices.Equal(p.Models, []string{"a/*", "c/gpt-5"}) {
		t.Fatalf("models = %v", p.Models)
	}
	if p.Budget == nil || p.Budget.Cost != 10 || p.Budget.Period != "month" {
		t.Fatalf("budget = %+v", p.Budget)
	}

	// A later sign-in keeps the grant and only refreshes the profile.
	id.Groups = []string{"team-c"}
	p, _ = s.Seen(id)
	if p.Status != StatusActive || !slices.Equal(p.Groups, []string{"team-c"}) {
		t.Fatalf("after signing in again = %+v", p)
	}
	if !slices.Equal(p.Models, []string{"a/*", "c/gpt-5"}) {
		t.Fatalf("the grant changed: %v", p.Models)
	}
}

func TestPolicyKeepsTheGrantAcrossReopen(t *testing.T) {
	s := openTestPolicy(t)
	if _, err := s.Seen(Identity{Subject: "bob", Email: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve("bob", "boss", []string{"a"}, &BudgetConfig{Period: "week", Cost: 3}, ""); err != nil {
		t.Fatal(err)
	}
	again, err := OpenPolicy(s.path)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := again.Get("bob")
	if !ok || p.Status != StatusActive || !slices.Equal(p.Models, []string{"a/*"}) || p.Budget.Cost != 3 {
		t.Fatalf("reopened = %+v, %v", p, ok)
	}
}

func TestPolicyRefusesWhatCannotBeAGrant(t *testing.T) {
	s := openTestPolicy(t)
	if _, err := s.Seen(Identity{Subject: "bob"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve("bob", "boss", []string{"a/"}, nil, ""); err == nil {
		t.Fatal("an invalid model was accepted")
	}
	if _, err := s.Approve("bob", "boss", []string{"a"}, &BudgetConfig{Period: "fortnight", Cost: 1}, ""); err == nil {
		t.Fatal("an invalid budget was accepted")
	}
	if p, _ := s.Get("bob"); p.Status != StatusPending {
		t.Fatalf("a refused grant changed the policy: %+v", p)
	}
	if _, err := s.Save("nobody", []string{"a"}, nil, ""); err == nil {
		t.Fatal("saved a grant for someone who never signed in")
	}
}

func TestPolicySteersDisableAndReject(t *testing.T) {
	s := openTestPolicy(t)
	id := Identity{Subject: "bob", Email: "bob@example.com"}
	if _, err := s.Seen(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve("bob", "boss", []string{"a"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Disable("bob", "boss", "left the team"); p.Status != StatusDisabled {
		t.Fatalf("disabled = %+v", p)
	}
	if p, _ := s.Enable("bob", "boss"); p.Status != StatusActive {
		t.Fatalf("enabled = %+v", p)
	}
	if p, _ := s.Reject("bob", "boss", "not needed"); p.Status != StatusRejected {
		t.Fatalf("rejected = %+v", p)
	}
	if p, _ := s.Request("bob"); p.Status != StatusRequested {
		t.Fatalf("a rejected person could not apply again: %+v", p)
	}
}

// A hundred-plus people is a small file and a fast write: the store must
// hold them and survive a reopen.
func TestPolicyHoldsManyPeople(t *testing.T) {
	s := openTestPolicy(t)
	const n = 150
	for i := 0; i < n; i++ {
		id := Identity{Subject: fmt.Sprintf("sub-%03d", i), Email: fmt.Sprintf("person%03d@example.com", i)}
		if _, err := s.Seen(id); err != nil {
			t.Fatal(err)
		}
	}
	again, err := OpenPolicy(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(again.List()); got != n {
		t.Fatalf("policies = %d, want %d", got, n)
	}
}
