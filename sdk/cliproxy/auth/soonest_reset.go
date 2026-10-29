package auth

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	defaultSoonestResetFiveHourLimit      = 0.9
	defaultSoonestResetTieMargin          = 6 * time.Hour
	defaultSoonestResetRefreshInterval    = 5 * time.Minute
	minSoonestResetRefreshInterval        = time.Minute
	soonestResetWeeklyWindow              = 7 * 24 * time.Hour
	soonestResetShortWindowMaxMinutes     = 24 * 60
	soonestResetQuotaSignalUnifiedPrefix  = "Anthropic-Ratelimit-Unified-"
	soonestResetQuotaSignalCodexPrefix    = "X-Codex-"
	soonestResetQuotaSignalRejectedStatus = "rejected"
)

// SoonestResetConfig configures the soonest-reset routing strategy.
type SoonestResetConfig struct {
	// FiveHourLimit is the 5-hour window usage fraction (0..1] at which an
	// account is skipped. Zero selects the default (0.9).
	FiveHourLimit float64
	// TieMargin treats weekly resets this close together as equal; the account
	// with more weekly usage left wins the tie. Zero selects the default (6h).
	TieMargin time.Duration
	// RefreshInterval is how old an account's quota snapshot may get before the
	// background probe refreshes it. Zero selects the default (5m).
	RefreshInterval time.Duration
}

func (c SoonestResetConfig) normalized() SoonestResetConfig {
	if c.FiveHourLimit <= 0 || c.FiveHourLimit > 1 {
		c.FiveHourLimit = defaultSoonestResetFiveHourLimit
	}
	if c.TieMargin <= 0 {
		c.TieMargin = defaultSoonestResetTieMargin
	}
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = defaultSoonestResetRefreshInterval
	}
	if c.RefreshInterval < minSoonestResetRefreshInterval {
		c.RefreshInterval = minSoonestResetRefreshInterval
	}
	return c
}

// SoonestResetSelector prefers the account whose weekly quota resets soonest,
// because weekly usage left at reset is lost. Accounts whose 5-hour window is
// nearly full are skipped. Accounts without quota data rank last; when no
// candidate has quota data the selector falls back to round-robin.
type SoonestResetSelector struct {
	cfg        SoonestResetConfig
	roundRobin RoundRobinSelector

	probeMu    sync.Mutex
	lastProbes map[string]time.Time
}

// NewSoonestResetSelector builds a soonest-reset selector with defaults applied.
func NewSoonestResetSelector(cfg SoonestResetConfig) *SoonestResetSelector {
	return &SoonestResetSelector{cfg: cfg.normalized()}
}

// Config returns the normalized selector configuration.
func (s *SoonestResetSelector) Config() SoonestResetConfig {
	if s == nil {
		return SoonestResetConfig{}.normalized()
	}
	return s.cfg
}

// Pick selects the available auth whose weekly quota resets soonest.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	picked, noData := pickSoonestReset(available, now, s.cfg)
	if picked != nil {
		selectorLogEntry(ctx).Debugf("soonest-reset: picked auth=%s provider=%s model=%s", picked.ID, provider, model)
		return picked, nil
	}
	return s.roundRobin.Pick(ctx, provider, model, opts, noData)
}

// eligibleAuths drops accounts whose quota data shows a nearly full 5-hour
// window or an exhausted weekly window. When that would drop every account,
// the input is returned unchanged so routing never stalls on local data.
func (s *SoonestResetSelector) eligibleAuths(auths []*Auth, now time.Time) []*Auth {
	eligible := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if windows := soonestResetWindowsOf(auth, now); windows.known && windows.blocked(s.cfg) {
			continue
		}
		eligible = append(eligible, auth)
	}
	if len(eligible) == 0 {
		return auths
	}
	return eligible
}

// quotaWindows is the projected state of an account's 5-hour and weekly windows.
// Used fractions run from 0 to 1.
type quotaWindows struct {
	known        bool
	fiveHourUsed float64
	weeklyUsed   float64
	weeklyReset  time.Time
}

func (w quotaWindows) blocked(cfg SoonestResetConfig) bool {
	return w.fiveHourUsed >= cfg.FiveHourLimit || w.weeklyUsed >= 1
}

type soonestResetCandidate struct {
	auth    *Auth
	windows quotaWindows
}

// pickSoonestReset applies the soonest-reset rule to already available auths.
// It returns the chosen auth, or nil plus the auths without quota data when no
// account with data qualifies. When every account with data is blocked and no
// account lacks data, it returns the blocked account with the most 5-hour
// headroom so a stale or pessimistic snapshot never takes routing down.
func pickSoonestReset(auths []*Auth, now time.Time, cfg SoonestResetConfig) (*Auth, []*Auth) {
	cfg = cfg.normalized()
	var eligible, blocked []soonestResetCandidate
	var noData []*Auth
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		windows := soonestResetWindowsOf(auth, now)
		switch {
		case !windows.known:
			noData = append(noData, auth)
		case windows.blocked(cfg):
			blocked = append(blocked, soonestResetCandidate{auth: auth, windows: windows})
		default:
			eligible = append(eligible, soonestResetCandidate{auth: auth, windows: windows})
		}
	}
	if len(eligible) > 0 {
		return pickSoonestResetEligible(eligible, cfg.TieMargin), nil
	}
	if len(noData) > 0 {
		return nil, noData
	}
	if len(blocked) == 0 {
		return nil, nil
	}
	sort.SliceStable(blocked, func(i, j int) bool {
		a, b := blocked[i].windows, blocked[j].windows
		if a.fiveHourUsed != b.fiveHourUsed {
			return a.fiveHourUsed < b.fiveHourUsed
		}
		if !a.weeklyReset.Equal(b.weeklyReset) {
			return a.weeklyReset.Before(b.weeklyReset)
		}
		return blocked[i].auth.ID < blocked[j].auth.ID
	})
	return blocked[0].auth, nil
}

// pickSoonestResetEligible finds the soonest weekly reset, then picks the
// account with the most weekly usage left among those resetting within
// tieMargin of it. Remaining ties go to the sooner reset, then the lower ID.
func pickSoonestResetEligible(candidates []soonestResetCandidate, tieMargin time.Duration) *Auth {
	soonest := candidates[0].windows.weeklyReset
	for _, candidate := range candidates[1:] {
		if candidate.windows.weeklyReset.Before(soonest) {
			soonest = candidate.windows.weeklyReset
		}
	}
	cutoff := soonest.Add(tieMargin)
	var best *soonestResetCandidate
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.windows.weeklyReset.After(cutoff) {
			continue
		}
		if best == nil || soonestResetBetter(candidate, best) {
			best = candidate
		}
	}
	return best.auth
}

func soonestResetBetter(a, b *soonestResetCandidate) bool {
	if a.windows.weeklyUsed != b.windows.weeklyUsed {
		return a.windows.weeklyUsed < b.windows.weeklyUsed
	}
	if !a.windows.weeklyReset.Equal(b.windows.weeklyReset) {
		return a.windows.weeklyReset.Before(b.windows.weeklyReset)
	}
	return a.auth.ID < b.auth.ID
}

// soonestResetWindowsOf reads the passive quota snapshot of an auth and
// projects it to now: a window whose reset time has passed counts as empty,
// and an elapsed weekly reset rolls forward by whole weeks.
func soonestResetWindowsOf(auth *Auth, now time.Time) quotaWindows {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return quotaWindows{}
	}
	var short, weekly quotaWindowSignal
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		short = claudeQuotaWindowSignal(auth.Quota.Signals, "5h")
		weekly = claudeQuotaWindowSignal(auth.Quota.Signals, "7d")
	case "codex":
		short, weekly = codexQuotaWindowSignals(auth.Quota.Signals, auth.Quota.ObservedAt)
	default:
		return quotaWindows{}
	}
	if !short.known && !weekly.known {
		return quotaWindows{}
	}
	windows := quotaWindows{known: true}
	if short.known && (short.reset.IsZero() || short.reset.After(now)) {
		windows.fiveHourUsed = short.used
	}
	weeklyLength := weekly.length
	if weeklyLength <= 0 {
		weeklyLength = soonestResetWeeklyWindow
	}
	switch {
	case !weekly.known || weekly.reset.IsZero():
		// No active weekly window: it starts on next use, so it resets last.
		windows.weeklyUsed = weekly.used
		windows.weeklyReset = now.Add(weeklyLength)
	case weekly.reset.After(now):
		windows.weeklyUsed = weekly.used
		windows.weeklyReset = weekly.reset
	default:
		elapsed := now.Sub(weekly.reset)
		windows.weeklyReset = weekly.reset.Add((elapsed/weeklyLength + 1) * weeklyLength)
	}
	return windows
}

type quotaWindowSignal struct {
	known  bool
	used   float64
	reset  time.Time
	length time.Duration
}

func quotaSignal(signals map[string]string, name string) (string, bool) {
	value, ok := signals[http.CanonicalHeaderKey(name)]
	if !ok {
		value, ok = signals[name]
	}
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func quotaSignalFloat(signals map[string]string, name string) (float64, bool) {
	raw, ok := quotaSignal(signals, name)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func quotaSignalUnix(signals map[string]string, name string) time.Time {
	value, ok := quotaSignalFloat(signals, name)
	if !ok || value <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0)
}

// claudeQuotaWindowSignal reads one Anthropic unified rate-limit window.
// Utilization is a 0..1 fraction; reset is a Unix timestamp in seconds.
func claudeQuotaWindowSignal(signals map[string]string, window string) quotaWindowSignal {
	prefix := soonestResetQuotaSignalUnifiedPrefix + window + "-"
	used, ok := quotaSignalFloat(signals, prefix+"Utilization")
	if !ok {
		return quotaWindowSignal{}
	}
	if status, _ := quotaSignal(signals, prefix+"Status"); strings.EqualFold(status, soonestResetQuotaSignalRejectedStatus) && used < 1 {
		used = 1
	}
	signal := quotaWindowSignal{known: true, used: clampUnit(used), reset: quotaSignalUnix(signals, prefix+"Reset")}
	if window == "7d" {
		signal.length = soonestResetWeeklyWindow
	}
	return signal
}

// codexQuotaWindowSignals reads the Codex primary and secondary windows and
// sorts them into the short (5-hour) and weekly window by window length.
func codexQuotaWindowSignals(signals map[string]string, observedAt time.Time) (short, weekly quotaWindowSignal) {
	for _, name := range []string{"Primary", "Secondary"} {
		prefix := soonestResetQuotaSignalCodexPrefix + name + "-"
		usedPercent, ok := quotaSignalFloat(signals, prefix+"Used-Percent")
		if !ok {
			continue
		}
		signal := quotaWindowSignal{known: true, used: clampUnit(usedPercent / 100)}
		signal.reset = quotaSignalUnix(signals, prefix+"Reset-At")
		if signal.reset.IsZero() && !observedAt.IsZero() {
			if after, okAfter := quotaSignalFloat(signals, prefix+"Reset-After-Seconds"); okAfter && after >= 0 {
				signal.reset = observedAt.Add(time.Duration(after) * time.Second)
			}
		}
		minutes, hasMinutes := quotaSignalFloat(signals, prefix+"Window-Minutes")
		if hasMinutes && minutes > 0 {
			signal.length = time.Duration(minutes) * time.Minute
		}
		isShort := name == "Primary"
		if hasMinutes && minutes > 0 {
			isShort = minutes <= soonestResetShortWindowMaxMinutes
		}
		if isShort {
			short = signal
		} else {
			weekly = signal
		}
	}
	return short, weekly
}

func clampUnit(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
