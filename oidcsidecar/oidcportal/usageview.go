package oidcportal

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/access"
	"github.com/yetone/magpie/internal/budget"
	"github.com/yetone/magpie/internal/usage"
)

// UsageView is what the portal shows a person of their own key: its budget,
// the period's totals, the same by model, and the newest requests. It is
// read from the very usage log the gateway writes, filtered to that key, so
// one person never sees another's calls.
type UsageView struct {
	HasKey  bool
	Period  string
	Budgets []BudgetView
	Totals  usage.Totals
	Models  []ModelUsage
	Recent  []RecentRequest
	// Series is the period's calls by hour (today) or by day, as the Usage
	// page's bar chart draws them; SeriesUnit says whether a bar's height is
	// cost or tokens, and SeriesPeak names the fullest one.
	Series     []Bar
	SeriesUnit string
	SeriesPeak string
}

// Bar is one column of the usage chart: its height is a share of the
// fullest column, split into the input tokens' light cap and the rest.
type Bar struct {
	Label     string
	Title     string
	InPct     float64 // light part, as a percentage of the chart's height
	OutPct    float64 // solid part, the two adding up to the column
	ShowLabel bool
}

// BudgetView is one of a key's limits, as the portal shows it.
type BudgetView struct {
	Label      string
	Period     string
	Cost       float64
	CostLimit  float64
	CostLeft   float64
	Tokens     int64
	TokenCap   int64
	TokensLeft int64
	Calls      int
	Reset      time.Time
	Spent      bool
	Percent    float64 // 0-100 of the cost cap, or of the token cap
	UsedText   string
	LeftText   string
}

// ModelUsage is one model's calls in the period. Share is its part of the
// period's calls, and Color the chart series (1-7) it is drawn in.
type ModelUsage struct {
	Model     string
	Color     int
	Calls     int
	Share     float64
	Tokens    int
	Input     int
	Output    int
	CacheRead int
	Cost      float64
	Unpriced  int
}

// RecentRequest is one call's metadata, never its body.
type RecentRequest struct {
	Time     time.Time
	Model    string
	Provider string
	Status   string
	Tokens   int
	Millis   int64
	Error    string
}

// PeriodOf reads a usage page's period, "month" unless the query names one.
func PeriodOf(q string) usage.Period {
	switch q {
	case "today":
		return usage.Today
	case "week", "7d":
		return usage.Week
	case "all":
		return usage.All
	default:
		return usage.Month
	}
}

// PeriodName is a period as a person reads it.
func PeriodName(p usage.Period) string {
	switch p {
	case usage.Today:
		return "today"
	case usage.Week:
		return "last 7 days"
	case usage.All:
		return "all time"
	default:
		return "last 30 days"
	}
}

// UsageFor is the key's own usage. A key the store no longer has reads as
// empty rather than as an error: the page already says the key is gone.
func UsageFor(keyID string, period usage.Period) UsageView {
	return UsageForKeys([]string{keyID}, keyID, period)
}

// UsageForUser is the person's usage across every key id they have had:
// rotation keeps the id, and a key removed and made again leaves an older
// id behind whose calls are still theirs.
func UsageForUser(u User, period usage.Period) UsageView {
	return UsageForKeys(u.keyIDs(), u.KeyID, period)
}

// UsageForKeys sums the periods of each key id; budgetKeyID is the key
// whose current budget the page shows.
func UsageForKeys(keyIDs []string, budgetKeyID string, period usage.Period) UsageView {
	out := UsageView{Period: PeriodName(period)}
	valid := 0
	for _, id := range keyIDs {
		if id != "" {
			valid++
		}
	}
	if budgetKeyID == "" && valid == 0 {
		return out
	}
	out.HasKey = true
	now := time.Now()
	if budgetKeyID != "" {
		if keys, err := access.List(); err == nil {
			for _, k := range keys {
				if k.ID == budgetKeyID {
					out.Budgets = budgetViews(budget.All(k, now))
					break
				}
			}
		}
	}
	var rows []usage.Row
	var totals usage.Totals
	seen := make(map[string]bool, len(keyIDs))
	for _, id := range keyIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		rs, t, _ := usage.Ledger(period, usage.Filter{CallerKey: id})
		rows = append(rows, rs...)
		totals.Calls += t.Calls
		totals.Errors += t.Errors
		totals.Retried += t.Retried
		totals.Loops += t.Loops
		totals.Input += t.Input
		totals.Output += t.Output
		totals.CacheRead += t.CacheRead
		totals.CacheWrite += t.CacheWrite
		totals.CacheWrite1h += t.CacheWrite1h
		totals.CacheUnknown += t.CacheUnknown
		totals.CacheUnknownCalls += t.CacheUnknownCalls
		totals.Reasoning += t.Reasoning
		totals.Cost += t.Cost
		totals.Unpriced += t.Unpriced
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Time.After(rows[j].Time) })
	out.Totals = totals
	out.Models, out.Recent = summarise(rows)
	total := 0
	for _, m := range out.Models {
		total += m.Calls
	}
	for i := range out.Models {
		out.Models[i].Color = i%7 + 1
		if total > 0 {
			out.Models[i].Share = float64(out.Models[i].Calls) / float64(total) * 100
		}
	}
	out.Series, out.SeriesUnit, out.SeriesPeak = seriesOf(rows, period, now)
	return out
}

// seriesOf buckets a period's calls for the bar chart: an hour a bar today,
// a day a bar otherwise, the last 7 or 30 days for the rolling periods, and
// the last 30 days of an all-time one. Bars are drawn at cost when any call
// was priced, at tokens otherwise.
func seriesOf(rows []usage.Row, period usage.Period, now time.Time) ([]Bar, string, string) {
	loc := now.Location()
	hourly := period == usage.Today
	n := 7
	switch period {
	case usage.Today:
		n = 24
	case usage.Month, usage.All:
		n = 30
	}
	type bucket struct {
		at     time.Time
		calls  int
		cost   float64
		input  int64
		tokens int64
		priced bool
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	start := today
	if !hourly {
		start = today.AddDate(0, 0, -(n - 1))
	}
	if period == usage.All {
		// Start at the first call when the history is shorter than the
		// chart, so its bars fill the width instead of crowding the end.
		var earliest time.Time
		for _, r := range rows {
			if r.IsRejected() {
				continue
			}
			t := r.Time.In(loc)
			d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
			if !d.Before(start) {
				continue
			}
			if earliest.IsZero() || d.Before(earliest) {
				earliest = d
			}
		}
		if !earliest.IsZero() {
			start = earliest
		}
		days := 0
		for d := start; d.Before(today); d = d.AddDate(0, 0, 1) {
			days++
		}
		n = days + 1
		if n > 30 {
			n = 30
			start = today.AddDate(0, 0, -29)
		}
	}
	buckets := make([]bucket, n)
	at := func(i int) time.Time {
		if hourly {
			return start.Add(time.Duration(i) * time.Hour)
		}
		return start.AddDate(0, 0, i)
	}
	for i := range buckets {
		buckets[i].at = at(i)
	}
	keyOf := func(t time.Time) int {
		t = t.In(loc)
		if hourly {
			if !sameDay(t, now) {
				return -1
			}
			return t.Hour()
		}
		for i := range buckets {
			if sameDay(t, buckets[i].at) {
				return i
			}
		}
		return -1
	}
	for _, r := range rows {
		if r.IsRejected() {
			continue
		}
		i := keyOf(r.Time)
		if i < 0 {
			continue
		}
		b := &buckets[i]
		b.calls++
		b.input += int64(r.Input)
		b.tokens += int64(r.Input + r.Output + r.CacheRead)
		if r.Priced {
			b.cost += r.Cost
			b.priced = true
		}
	}
	// Tokens are the chart's default, as the app's Usage page opens; cost is
	// drawn only for a period with no token counts at all.
	unit := "tokens"
	anyTokens := false
	anyCost := false
	for _, b := range buckets {
		if b.tokens > 0 {
			anyTokens = true
		}
		if b.priced && b.cost > 0 {
			anyCost = true
		}
	}
	if !anyTokens && anyCost {
		unit = "cost"
	}
	value := func(b bucket) float64 {
		if unit == "cost" {
			return b.cost
		}
		return float64(b.tokens)
	}
	var max float64
	var peak bucket
	for _, b := range buckets {
		if v := value(b); v > max {
			max, peak = v, b
		}
	}
	every := n / 6
	if every < 1 {
		every = 1
	}
	out := make([]Bar, n)
	for i, b := range buckets {
		bar := Bar{ShowLabel: i%every == 0 || i == n-1}
		if hourly {
			bar.Label = b.at.Format("15:04")
		} else {
			bar.Label = b.at.Format("1月2日")
		}
		if max > 0 {
			h := value(b) / max * 100
			in := 0.0
			if unit == "tokens" && b.tokens > 0 {
				in = float64(b.input) / float64(b.tokens) * 100
			}
			bar.InPct = h * in / 100
			bar.OutPct = h - bar.InPct
		}
		bar.Title = bar.Label + " · " + strconv.Itoa(b.calls) + " 次请求"
		if b.tokens > 0 {
			bar.Title += " · " + humanInt(b.tokens) + " tokens"
		}
		if b.cost > 0 {
			bar.Title += " · " + fmt.Sprintf("$%.2f", b.cost)
		}
		out[i] = bar
	}
	peakText := ""
	if max > 0 {
		if unit == "cost" {
			peakText = fmt.Sprintf("最高 $%.2f · %s", peak.cost, peak.at.Format("1月2日"))
		} else {
			peakText = fmt.Sprintf("最高 %s tokens · %s", humanInt(peak.tokens), peak.at.Format("1月2日"))
			if hourly {
				peakText = fmt.Sprintf("最高 %s tokens · %s", humanInt(peak.tokens), peak.at.Format("15:04"))
			}
		}
	}
	return out, unit, peakText
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func budgetViews(all []budget.Status) []BudgetView {
	out := make([]BudgetView, 0, len(all))
	for _, s := range all {
		v := BudgetView{
			Label: budgetLabel(s), Period: s.Period,
			Cost: s.Cost, CostLimit: s.CostLimit, CostLeft: s.CostLeft,
			Tokens: s.Tokens, TokenCap: s.TokenLimit, TokensLeft: s.TokensLeft,
			Calls: s.Calls, Reset: s.Reset, Spent: s.Spent,
		}
		switch {
		case s.CostLimit > 0:
			v.Percent = clampPercent(s.Cost / s.CostLimit * 100)
			v.UsedText = fmt.Sprintf("已用 $%.2f / $%.2f", s.Cost, s.CostLimit)
			v.LeftText = fmt.Sprintf("剩 $%.2f", s.CostLeft)
		case s.TokenLimit > 0:
			v.Percent = clampPercent(float64(s.Tokens) / float64(s.TokenLimit) * 100)
			v.UsedText = fmt.Sprintf("已用 %s / %s", humanInt(s.Tokens), humanInt(s.TokenLimit))
			v.LeftText = fmt.Sprintf("剩 %s", humanInt(s.TokensLeft))
		default:
			v.UsedText = "没有上限"
			v.LeftText = fmt.Sprintf("%d 次请求", s.Calls)
		}
		if !s.Reset.IsZero() {
			v.LeftText += " · " + s.Reset.Local().Format("1月2日") + " 重置"
		}
		out = append(out, v)
	}
	return out
}

func budgetLabel(s budget.Status) string {
	var parts []string
	if s.CostLimit > 0 {
		parts = append(parts, fmt.Sprintf("$%.2f", s.CostLimit))
	}
	if s.TokenLimit > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens", s.TokenLimit))
	}
	if len(parts) == 0 {
		return "没有额度"
	}
	return zhCycle(&access.Limit{Period: s.Period, Days: s.Days, Hours: s.Hours}) + " " + strings.Join(parts, " · ")
}

func humanInt(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fb", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fm", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprint(n)
	}
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func summarise(rows []usage.Row) ([]ModelUsage, []RecentRequest) {
	byModel := map[string]*ModelUsage{}
	recent := make([]RecentRequest, 0, min(len(rows), 50))
	for _, r := range rows {
		if r.IsRejected() {
			continue
		}
		name := r.Model
		if name == "" {
			name = "unknown"
		}
		m := byModel[name]
		if m == nil {
			m = &ModelUsage{Model: name}
			byModel[name] = m
		}
		m.Calls++
		m.Tokens += r.Input + r.Output + r.CacheRead
		m.Input += r.Input
		m.Output += r.Output
		m.CacheRead += r.CacheRead
		if r.Priced {
			m.Cost += r.Cost
		} else if r.Input+r.Output+r.CacheRead > 0 {
			m.Unpriced++
		}
		if len(recent) < 50 {
			recent = append(recent, RecentRequest{
				Time: r.Time, Model: name, Provider: r.Provider,
				Status: statusText(r), Tokens: r.Input + r.Output + r.CacheRead,
				Millis: r.Millis, Error: r.Error,
			})
		}
	}
	models := make([]ModelUsage, 0, len(byModel))
	for _, m := range byModel {
		models = append(models, *m)
	}
	sort.Slice(models, func(i, j int) bool {
		if models[i].Calls != models[j].Calls {
			return models[i].Calls > models[j].Calls
		}
		return models[i].Model < models[j].Model
	})
	return models, recent
}

func statusText(r usage.Row) string {
	if r.Error != "" && r.Status < 400 {
		return "error"
	}
	if r.Status == 0 {
		return "—"
	}
	return fmt.Sprint(r.Status)
}

// limitText is a limit as a person reads it.
func limitText(l *access.Limit) string {
	if l == nil || !l.Limited() {
		return "没有额度"
	}
	var parts []string
	if l.Cost > 0 {
		parts = append(parts, fmt.Sprintf("$%.2f", l.Cost))
	}
	if l.Tokens > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens", l.Tokens))
	}
	return zhCycle(l) + " " + strings.Join(parts, " · ")
}

// zhCycle is a limit's window in Chinese: each calendar month and week,
// every n days or hours.
func zhCycle(l *access.Limit) string {
	switch l.Period {
	case "day", "today":
		return "每天"
	case "week":
		return "每周"
	case "month":
		return "每月"
	case "days":
		return fmt.Sprintf("每 %d 天", l.Days)
	case "hours":
		return fmt.Sprintf("每 %d 小时", l.Hours)
	}
	return "每 " + l.Per()
}
