package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

var soonestResetTestNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// claudeQuota builds a Claude unified rate-limit snapshot. Usage values are fractions.
func claudeQuota(fiveHourUsed float64, fiveHourReset time.Time, weeklyUsed float64, weeklyReset time.Time) QuotaState {
	return QuotaState{
		ObservedAt: soonestResetTestNow,
		Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Utilization": strconv.FormatFloat(fiveHourUsed, 'f', -1, 64),
			"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(fiveHourReset.Unix(), 10),
			"Anthropic-Ratelimit-Unified-7d-Utilization": strconv.FormatFloat(weeklyUsed, 'f', -1, 64),
			"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(weeklyReset.Unix(), 10),
		},
	}
}

func claudeAuth(id string, quota QuotaState) *Auth {
	return &Auth{ID: id, Provider: "claude", Status: StatusActive, Quota: quota}
}

func pickID(t *testing.T, auths []*Auth, cfg SoonestResetConfig) string {
	t.Helper()
	picked, noData := pickSoonestReset(auths, soonestResetTestNow, cfg)
	if picked == nil {
		t.Fatalf("pickSoonestReset returned no pick; no-data=%d", len(noData))
	}
	return picked.ID
}

func TestPickSoonestResetPrefersSoonestWeeklyReset(t *testing.T) {
	fiveHourReset := soonestResetTestNow.Add(2 * time.Hour)
	auths := []*Auth{
		claudeAuth("a-late", claudeQuota(0.1, fiveHourReset, 0.2, soonestResetTestNow.Add(5*24*time.Hour))),
		claudeAuth("b-soon", claudeQuota(0.1, fiveHourReset, 0.6, soonestResetTestNow.Add(1*24*time.Hour))),
		claudeAuth("c-mid", claudeQuota(0.1, fiveHourReset, 0.1, soonestResetTestNow.Add(3*24*time.Hour))),
	}
	if got := pickID(t, auths, SoonestResetConfig{}); got != "b-soon" {
		t.Fatalf("pick = %q, want b-soon", got)
	}
}

func TestPickSoonestResetTieMarginPrefersMoreWeeklyLeft(t *testing.T) {
	fiveHourReset := soonestResetTestNow.Add(2 * time.Hour)
	soon := soonestResetTestNow.Add(24 * time.Hour)
	auths := []*Auth{
		claudeAuth("a-soonest-mostly-used", claudeQuota(0.1, fiveHourReset, 0.8, soon)),
		claudeAuth("b-within-margin-more-left", claudeQuota(0.1, fiveHourReset, 0.3, soon.Add(5*time.Hour))),
		claudeAuth("c-outside-margin-most-left", claudeQuota(0.1, fiveHourReset, 0.0, soon.Add(7*time.Hour))),
	}
	if got := pickID(t, auths, SoonestResetConfig{}); got != "b-within-margin-more-left" {
		t.Fatalf("default 6h margin pick = %q, want b-within-margin-more-left", got)
	}
	if got := pickID(t, auths, SoonestResetConfig{TieMargin: 4 * time.Hour}); got != "a-soonest-mostly-used" {
		t.Fatalf("4h margin pick = %q, want a-soonest-mostly-used", got)
	}
}

func TestPickSoonestResetSkipsNearlyFullFiveHourWindow(t *testing.T) {
	fiveHourReset := soonestResetTestNow.Add(2 * time.Hour)
	auths := []*Auth{
		claudeAuth("a-soonest-but-5h-full", claudeQuota(0.92, fiveHourReset, 0.5, soonestResetTestNow.Add(24*time.Hour))),
		claudeAuth("b-later", claudeQuota(0.1, fiveHourReset, 0.5, soonestResetTestNow.Add(4*24*time.Hour))),
	}
	if got := pickID(t, auths, SoonestResetConfig{}); got != "b-later" {
		t.Fatalf("pick = %q, want b-later", got)
	}
	// A higher limit keeps the soonest account in play.
	if got := pickID(t, auths, SoonestResetConfig{FiveHourLimit: 0.95}); got != "a-soonest-but-5h-full" {
		t.Fatalf("95%% limit pick = %q, want a-soonest-but-5h-full", got)
	}
	// Once the 5-hour reset time passes, the stale snapshot no longer blocks.
	stale := []*Auth{
		claudeAuth("a-soonest-5h-reset-passed", claudeQuota(0.99, soonestResetTestNow.Add(-time.Minute), 0.5, soonestResetTestNow.Add(24*time.Hour))),
		auths[1],
	}
	if got := pickID(t, stale, SoonestResetConfig{}); got != "a-soonest-5h-reset-passed" {
		t.Fatalf("pick after 5h reset = %q, want a-soonest-5h-reset-passed", got)
	}
}

func TestPickSoonestResetSkipsExhaustedWeeklyAndRollsElapsedReset(t *testing.T) {
	fiveHourReset := soonestResetTestNow.Add(2 * time.Hour)
	auths := []*Auth{
		claudeAuth("a-weekly-exhausted", claudeQuota(0.1, fiveHourReset, 1.0, soonestResetTestNow.Add(time.Hour))),
		// Weekly reset passed 1h ago: usage is projected to zero and reset rolls forward a week.
		claudeAuth("b-weekly-reset-passed", claudeQuota(0.1, fiveHourReset, 0.9, soonestResetTestNow.Add(-time.Hour))),
		claudeAuth("c-resets-in-3d", claudeQuota(0.1, fiveHourReset, 0.5, soonestResetTestNow.Add(3*24*time.Hour))),
	}
	if got := pickID(t, auths, SoonestResetConfig{}); got != "c-resets-in-3d" {
		t.Fatalf("pick = %q, want c-resets-in-3d", got)
	}
	windows := soonestResetWindowsOf(auths[1], soonestResetTestNow)
	if want := soonestResetTestNow.Add(-time.Hour).Add(7 * 24 * time.Hour); !windows.weeklyReset.Equal(want) || windows.weeklyUsed != 0 {
		t.Fatalf("rolled weekly window = %v used %v, want %v used 0", windows.weeklyReset, windows.weeklyUsed, want)
	}
}

func TestPickSoonestResetMissingDataRanksLast(t *testing.T) {
	fiveHourReset := soonestResetTestNow.Add(2 * time.Hour)
	noData := claudeAuth("a-no-data", QuotaState{})
	withData := claudeAuth("b-late-reset", claudeQuota(0.5, fiveHourReset, 0.9, soonestResetTestNow.Add(6*24*time.Hour)))
	if got := pickID(t, []*Auth{noData, withData}, SoonestResetConfig{}); got != "b-late-reset" {
		t.Fatalf("pick = %q, want b-late-reset", got)
	}

	// Every account with data is blocked: the account without data is still eligible.
	full := claudeAuth("b-5h-full", claudeQuota(0.95, fiveHourReset, 0.2, soonestResetTestNow.Add(24*time.Hour)))
	picked, rest := pickSoonestReset([]*Auth{noData, full}, soonestResetTestNow, SoonestResetConfig{})
	if picked != nil || len(rest) != 1 || rest[0].ID != "a-no-data" {
		t.Fatalf("pick = %v rest = %v, want round-robin over a-no-data", picked, rest)
	}

	// Every account is blocked and none lacks data: the one with most 5-hour headroom serves.
	fuller := claudeAuth("c-5h-fuller", claudeQuota(0.99, fiveHourReset, 0.2, soonestResetTestNow.Add(time.Hour)))
	if got := pickID(t, []*Auth{fuller, full}, SoonestResetConfig{}); got != "b-5h-full" {
		t.Fatalf("all-blocked pick = %q, want b-5h-full", got)
	}
}

func TestSoonestResetSelectorRoundRobinsWithoutQuotaData(t *testing.T) {
	selector := NewSoonestResetSelector(SoonestResetConfig{})
	auths := []*Auth{
		{ID: "gemini-a", Provider: "gemini", Status: StatusActive},
		{ID: "gemini-b", Provider: "gemini", Status: StatusActive},
	}
	var got []string
	for range 4 {
		picked, err := selector.Pick(context.Background(), "gemini", "", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		got = append(got, picked.ID)
	}
	if want := []string{"gemini-a", "gemini-b", "gemini-a", "gemini-b"}; !equalStrings(got, want) {
		t.Fatalf("picks = %v, want %v", got, want)
	}
}

func TestSoonestResetCodexWindows(t *testing.T) {
	auth := &Auth{ID: "codex-a", Provider: "codex", Quota: QuotaState{
		ObservedAt: soonestResetTestNow,
		Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":          "93",
			"X-Codex-Primary-Window-Minutes":        "300",
			"X-Codex-Primary-Reset-At":              strconv.FormatInt(soonestResetTestNow.Add(time.Hour).Unix(), 10),
			"X-Codex-Secondary-Used-Percent":        "40",
			"X-Codex-Secondary-Window-Minutes":      "10080",
			"X-Codex-Secondary-Reset-After-Seconds": "86400",
		},
	}}
	windows := soonestResetWindowsOf(auth, soonestResetTestNow)
	if !windows.known || windows.fiveHourUsed != 0.93 || windows.weeklyUsed != 0.4 ||
		!windows.weeklyReset.Equal(soonestResetTestNow.Add(24*time.Hour)) {
		t.Fatalf("codex windows = %+v", windows)
	}
	if !windows.blocked(SoonestResetConfig{}.normalized()) {
		t.Fatal("codex account at 93% of its 5-hour window must be blocked at the 90% default")
	}
}

func TestQuotaProbeResponsesMatchResponseSnapshots(t *testing.T) {
	claudeBody := []byte(`{"five_hour":{"utilization":95.0,"resets_at":"2026-10-28T14:00:00+00:00"},` +
		`"seven_day":{"utilization":40.0,"resets_at":"2026-10-30T12:00:00.123+00:00"},"seven_day_opus":null}`)
	var claude QuotaState
	if !claude.ObserveResponseHeadersForProvider("claude", claudeUsageProbeHeaders(claudeBody), soonestResetTestNow) {
		t.Fatal("claude probe headers were not accepted as quota signals")
	}
	if got := claude.Signals["Anthropic-Ratelimit-Unified-Representative-Claim"]; got != "five_hour" {
		t.Fatalf("claude representative claim = %q, want five_hour", got)
	}
	windows := soonestResetWindowsOf(&Auth{Provider: "claude", Quota: claude}, soonestResetTestNow)
	if windows.fiveHourUsed != 0.95 || windows.weeklyUsed != 0.4 ||
		!windows.weeklyReset.Equal(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("claude probe windows = %+v", windows)
	}

	codexBody := []byte(`{"plan_type":"plus","credits":{"has_credits":true,"unlimited":false,"balance":"12.5"},` +
		`"rate_limit":{"allowed":true,"limit_reached":false,` +
		`"primary_window":{"used_percent":12,"limit_window_seconds":18000,"reset_after_seconds":3600,"reset_at":` +
		strconv.FormatInt(soonestResetTestNow.Add(time.Hour).Unix(), 10) + `},` +
		`"secondary_window":{"used_percent":55,"limit_window_seconds":604800,"reset_after_seconds":172800,"reset_at":` +
		strconv.FormatInt(soonestResetTestNow.Add(48*time.Hour).Unix(), 10) + `}}}`)
	var codex QuotaState
	if !codex.ObserveResponseHeadersForProvider("codex", codexUsageProbeHeaders(codexBody), soonestResetTestNow) {
		t.Fatal("codex probe headers were not accepted as quota signals")
	}
	for name, want := range map[string]string{
		"X-Codex-Plan-Type": "plus", "X-Codex-Allowed": "True", "X-Codex-Credits-Unlimited": "False", "X-Codex-Credits-Balance": "12.5",
	} {
		if got := codex.Signals[name]; got != want {
			t.Fatalf("codex %s = %q, want %q", name, got, want)
		}
	}
	windows = soonestResetWindowsOf(&Auth{Provider: "codex", Quota: codex}, soonestResetTestNow)
	if windows.fiveHourUsed != 0.12 || windows.weeklyUsed != 0.55 ||
		!windows.weeklyReset.Equal(soonestResetTestNow.Add(48*time.Hour)) {
		t.Fatalf("codex probe windows = %+v", windows)
	}
}

// TestManagerSoonestResetSessionAffinity drives the real manager selection path:
// a session holds its account while it stays eligible, moves once when the
// account's 5-hour window fills, and then stays on the new account.
func TestManagerSoonestResetSessionAffinity(t *testing.T) {
	for _, rebindOn := range []string{SessionAffinityRebindOnAny, SessionAffinityRebindOnQuota} {
		t.Run(rebindOn, func(t *testing.T) {
			ctx := context.Background()
			model := "soonest-reset-affinity-model-" + rebindOn
			manager := NewManager(nil, nil, nil)
			affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
				Fallback: NewSoonestResetSelector(SoonestResetConfig{}),
				TTL:      time.Hour,
				RebindOn: rebindOn,
			})
			defer affinity.Stop()
			manager.SetSelector(affinity)
			manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})

			now := time.Now()
			fiveHourReset := now.Add(2 * time.Hour)
			ids := []string{"sr-affinity-" + rebindOn + "-a", "sr-affinity-" + rebindOn + "-b"}
			for _, id := range ids {
				if _, errRegister := manager.Register(WithSkipPersist(ctx), &Auth{ID: id, Provider: "claude", Status: StatusActive}); errRegister != nil {
					t.Fatalf("Register(%s): %v", id, errRegister)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			setQuota := func(id string, fiveHourUsed float64, weeklyReset time.Time) {
				manager.mu.Lock()
				defer manager.mu.Unlock()
				quota := claudeQuota(fiveHourUsed, fiveHourReset, 0.5, weeklyReset)
				manager.auths[id].Quota.ObservedAt = now
				manager.auths[id].Quota.Signals = quota.Signals
			}
			pick := func(session string) string {
				t.Helper()
				opts := cliproxyexecutor.Options{Metadata: map[string]any{
					cliproxyexecutor.DerivedSessionIDMetadataKey: session,
				}}
				auth, _, errPick := manager.pickNext(ctx, "claude", model, opts, nil)
				if errPick != nil {
					t.Fatalf("pick: %v", errPick)
				}
				return auth.ID
			}

			a, b := ids[0], ids[1]
			setQuota(a, 0.1, now.Add(24*time.Hour))
			setQuota(b, 0.1, now.Add(4*24*time.Hour))
			if got := pick("session-1"); got != a {
				t.Fatalf("cold binding = %q, want soonest reset %q", got, a)
			}

			// B now resets sooner, but the session stays on A while A is eligible.
			setQuota(b, 0.1, now.Add(time.Hour))
			if got := pick("session-1"); got != a {
				t.Fatalf("held binding = %q, want %q", got, a)
			}
			if got := pick("session-2"); got != b {
				t.Fatalf("new session = %q, want soonest reset %q", got, b)
			}

			// A's 5-hour window fills: the session moves to B.
			setQuota(a, 0.95, now.Add(24*time.Hour))
			if got := pick("session-1"); got != b {
				t.Fatalf("after A filled = %q, want %q", got, b)
			}

			// A recovers and resets soonest again; the session stays on B.
			setQuota(a, 0.1, now.Add(30*time.Minute))
			if got := pick("session-1"); got != b {
				t.Fatalf("after A recovered = %q, want %q (moves only once)", got, b)
			}
		})
	}
}

// TestManagerSoonestResetSkipsFullAccountAcrossPriorityTiers checks that a nearly full
// account does not hold its priority tier, while priority still orders eligible accounts.
func TestManagerSoonestResetSkipsFullAccountAcrossPriorityTiers(t *testing.T) {
	ctx := context.Background()
	model := "soonest-reset-priority-model"
	manager := NewManager(nil, nil, nil)
	manager.SetSelector(NewSoonestResetSelector(SoonestResetConfig{}))
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	high, low := "sr-priority-high", "sr-priority-low"
	for _, auth := range []*Auth{
		{ID: high, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"priority": "1"}},
		{ID: low, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"priority": "0"}},
	} {
		if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
		id := auth.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	now := time.Now()
	setQuota := func(id string, fiveHourUsed float64) {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		manager.auths[id].Quota = claudeQuota(fiveHourUsed, now.Add(2*time.Hour), 0.5, now.Add(4*24*time.Hour))
	}
	pick := func() string {
		t.Helper()
		auth, _, errPick := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pick: %v", errPick)
		}
		return auth.ID
	}
	setQuota(high, 0.1)
	setQuota(low, 0.1)
	if got := pick(); got != high {
		t.Fatalf("both eligible = %q, want higher priority %q", got, high)
	}
	setQuota(high, 0.95)
	if got := pick(); got != low {
		t.Fatalf("high priority 5h full = %q, want %q", got, low)
	}
}

func TestSoonestResetClaimProbeAllowsOneInFlight(t *testing.T) {
	selector := NewSoonestResetSelector(SoonestResetConfig{})
	if !selector.claimProbe("a", soonestResetTestNow, time.Minute) {
		t.Fatal("first claim refused")
	}
	if selector.claimProbe("a", soonestResetTestNow.Add(time.Hour), time.Minute) {
		t.Fatal("claim granted while a probe is in flight")
	}
	selector.releaseProbe("a")
	if selector.claimProbe("a", soonestResetTestNow.Add(30*time.Second), time.Minute) {
		t.Fatal("claim granted before the interval elapsed")
	}
	if !selector.claimProbe("a", soonestResetTestNow.Add(2*time.Minute), time.Minute) {
		t.Fatal("claim refused after release and interval")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
