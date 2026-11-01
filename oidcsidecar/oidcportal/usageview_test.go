package oidcportal

import (
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/budget"
	"github.com/yetone/magpie/internal/usage"
)

// One person's page is read from the same log as everyone else's, filtered
// to their key: their totals, their models, never a neighbour's call.
func TestUsageIsOnlyThatKeysCalls(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	if _, err := access.Update("add-key", access.Change{Name: "oidc:bob"}); err != nil {
		t.Fatal(err)
	}
	if _, err := access.Update("add-key", access.Change{Name: "oidc:alice"}); err != nil {
		t.Fatal(err)
	}
	keys, err := access.List()
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys = %+v, %v", keys, err)
	}
	bob, alice := keys[0], keys[1]
	if bob.Name != "oidc:bob" {
		bob, alice = alice, bob
	}
	if _, err := access.Update("limit-key", access.Change{
		Key: bob.ID, Limit: &access.Limit{Period: "month", Cost: 10},
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	for _, r := range []usage.Record{
		{Time: now.Add(-3 * time.Minute), CallerKeyID: bob.ID, CallerKeyName: bob.Name, Provider: "a", Model: "m1", Input: 100, Output: 50, Status: 200, Millis: 120},
		{Time: now.Add(-2 * time.Minute), CallerKeyID: bob.ID, CallerKeyName: bob.Name, Provider: "a", Model: "m1", Input: 20, Output: 10, Status: 200, Millis: 80},
		{Time: now.Add(-time.Minute), CallerKeyID: bob.ID, CallerKeyName: bob.Name, Provider: "a", Model: "m2", Input: 5, Output: 5, Status: 500, Error: "upstream", Millis: 60},
		{Time: now, CallerKeyID: alice.ID, CallerKeyName: alice.Name, Provider: "a", Model: "not-his", Input: 999, Output: 999, Status: 200},
	} {
		usage.Append(r)
	}

	v := UsageFor(bob.ID, usage.Today)
	if !v.HasKey || v.Period != "today" {
		t.Fatalf("view = %+v", v)
	}
	if v.Totals.Calls != 3 || v.Totals.Input != 125 || v.Totals.Output != 65 {
		t.Fatalf("totals = %+v", v.Totals)
	}
	if len(v.Models) != 2 {
		t.Fatalf("models = %+v", v.Models)
	}
	if v.Models[0].Model != "m1" || v.Models[0].Calls != 2 || v.Models[0].Input != 120 {
		t.Fatalf("first model = %+v", v.Models[0])
	}
	if v.Models[1].Model != "m2" || v.Models[1].Calls != 1 {
		t.Fatalf("second model = %+v", v.Models[1])
	}
	if len(v.Recent) != 3 || v.Recent[0].Model != "m2" || v.Recent[0].Status != "500" {
		t.Fatalf("recent = %+v", v.Recent)
	}
	for _, r := range v.Recent {
		if r.Model == "not-his" {
			t.Fatal("another key's call is on the page")
		}
	}

	if len(v.Series) != 24 || v.SeriesUnit != "tokens" || !strings.Contains(v.SeriesPeak, "最高") {
		t.Fatalf("today's series = %d bars, unit %q, peak %q", len(v.Series), v.SeriesUnit, v.SeriesPeak)
	}
	height := 0.0
	for _, b := range v.Series {
		height += b.InPct + b.OutPct
	}
	if height == 0 {
		t.Fatal("the chart has no bars")
	}
	if v.Models[0].Color != 1 || v.Models[1].Color != 2 {
		t.Fatalf("model colours = %d, %d", v.Models[0].Color, v.Models[1].Color)
	}
	if want := 200.0 / 3; v.Models[0].Share < want-0.1 || v.Models[0].Share > want+0.1 {
		t.Fatalf("first model's share = %.2f, want %.2f", v.Models[0].Share, want)
	}
	if v.Models[0].Tokens != 180 {
		t.Fatalf("first model's tokens = %d", v.Models[0].Tokens)
	}

	if len(v.Budgets) != 1 {
		t.Fatalf("budgets = %+v", v.Budgets)
	}
	b := v.Budgets[0]
	if b.UsedText != "已用 $0.00 / $10.00" || b.CostLimit != 10 || b.Calls != 3 {
		t.Fatalf("budget = %+v", b)
	}

	other := UsageFor(alice.ID, usage.Today)
	if other.Totals.Calls != 1 || len(other.Models) != 1 || other.Models[0].Model != "not-his" {
		t.Fatalf("alice = %+v", other)
	}
	if none := UsageFor("", usage.Today); none.HasKey || none.Totals.Calls != 0 {
		t.Fatalf("no key = %+v", none)
	}
}

// A month's chart is 30 days, and calls land in their own day's bar.
func TestTheChartBucketsByDay(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if _, err := access.Update("add-key", access.Change{Name: "oidc:day"}); err != nil {
		t.Fatal(err)
	}
	keys, _ := access.List()
	k := keys[0]
	now := time.Now()
	for _, ago := range []time.Duration{0, 24 * time.Hour, 9 * 24 * time.Hour} {
		usage.Append(usage.Record{
			Time: now.Add(-ago), CallerKeyID: k.ID, Provider: "a", Model: "m",
			Input: 100, Output: 50, Status: 200,
		})
	}
	v := UsageFor(k.ID, usage.Month)
	if len(v.Series) != 30 {
		t.Fatalf("series = %d bars, want 30", len(v.Series))
	}
	bars := 0
	for _, b := range v.Series {
		if b.InPct+b.OutPct > 0 {
			bars++
		}
	}
	if bars != 3 {
		t.Fatalf("bars with calls = %d, want 3", bars)
	}
	if v.SeriesPeak == "" {
		t.Fatal("the peak is not named")
	}
	if last := v.Series[len(v.Series)-1]; last.InPct+last.OutPct == 0 {
		t.Fatal("today has no bar")
	}
	if !v.Series[len(v.Series)-1].ShowLabel {
		t.Fatal("the last bar has no label")
	}
}

// A person's usage follows their key history: rotation keeps the id, and a
// key removed and made again leaves an older id whose calls are still
// theirs, never a neighbour's.
func TestUsageFollowsThePersonsKeyHistory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	secret, err := access.Update("add-key", access.Change{Name: "oidc:bob"})
	if err != nil {
		t.Fatal(err)
	}
	first, ok := access.Authenticate(secret)
	if !ok {
		t.Fatal("the first key does not authenticate")
	}
	secret, err = access.Update("add-key", access.Change{Name: "oidc:bob"})
	if err != nil {
		t.Fatal(err)
	}
	second, ok := access.Authenticate(secret)
	if !ok {
		t.Fatal("the second key does not authenticate")
	}
	other, err := access.Update("add-key", access.Change{Name: "oidc:alice"})
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := access.Authenticate(other)

	now := time.Now()
	for _, r := range []usage.Record{
		{Time: now.Add(-3 * time.Minute), CallerKeyID: first.KeyID, Provider: "a", Model: "m1", Input: 10, Output: 5, Status: 200},
		{Time: now.Add(-2 * time.Minute), CallerKeyID: second.KeyID, Provider: "a", Model: "m2", Input: 20, Output: 10, Status: 200},
		{Time: now.Add(-time.Minute), CallerKeyID: alice.KeyID, Provider: "a", Model: "not-his", Input: 999, Output: 999, Status: 200},
	} {
		usage.Append(r)
	}

	u := User{Sub: "bob", KeyID: second.KeyID, KeyIDs: []string{first.KeyID, second.KeyID}}
	v := UsageForUser(u, usage.Today)
	if v.Totals.Calls != 2 || v.Totals.Input != 30 || len(v.Models) != 2 {
		t.Fatalf("history view = %+v", v.Totals)
	}
	for _, r := range v.Recent {
		if r.Model == "not-his" {
			t.Fatal("a neighbour's call is on the page")
		}
	}

	// A record written before KeyIDs existed still counts its current id.
	old := UsageForUser(User{Sub: "bob", KeyID: first.KeyID}, usage.Today)
	if old.Totals.Calls != 1 || old.Totals.Input != 10 {
		t.Fatalf("migrated record = %+v", old.Totals)
	}
}

func TestBudgetViews(t *testing.T) {
	reset := time.Date(2026, 11, 1, 0, 0, 0, 0, time.Local)
	v := budgetViews([]budget.Status{
		{Period: "month", Cost: 7.5, CostLimit: 10, CostLeft: 2.5, Calls: 12, Reset: reset},
		{Period: "week", Tokens: 1500, TokenLimit: 10000, TokensLeft: 8500, Calls: 4},
		{Period: "days", Days: 5, Calls: 2},
	})
	if len(v) != 3 {
		t.Fatalf("views = %+v", v)
	}
	if v[0].Percent != 75 || v[0].UsedText != "已用 $7.50 / $10.00" || !strings.HasPrefix(v[0].LeftText, "剩 $2.50 · ") {
		t.Fatalf("cost = %+v", v[0])
	}
	if v[1].Percent != 15 || v[1].UsedText != "已用 1500 / 10.0k" {
		t.Fatalf("tokens = %+v", v[1])
	}
	if v[2].UsedText != "没有上限" || v[2].Percent != 0 {
		t.Fatalf("no cap = %+v", v[2])
	}
	if got := budgetLabel(budget.Status{Period: "days", Days: 5, CostLimit: 2}); got != "每 5 天 $2.00" {
		t.Fatalf("label = %q", got)
	}
	if got := budgetLabel(budget.Status{Period: "month"}); got != "没有额度" {
		t.Fatalf("label = %q", got)
	}
}

func TestPeriodOf(t *testing.T) {
	cases := map[string]string{
		"":      "last 30 days",
		"today": "today",
		"week":  "last 7 days",
		"all":   "all time",
		"other": "last 30 days",
	}
	for q, want := range cases {
		if got := PeriodName(PeriodOf(q)); got != want {
			t.Fatalf("PeriodOf(%q) = %q, want %q", q, got, want)
		}
	}
}
