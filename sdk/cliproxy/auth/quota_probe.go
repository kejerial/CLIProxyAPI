package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const (
	quotaProbeTick         = time.Minute
	quotaProbeMaxBodyBytes = 1 << 20
	claudeUsageProbeURL    = "https://api.anthropic.com/api/oauth/usage"
	claudeUsageProbeBeta   = "oauth-2025-04-20"
	codexUsageProbeURL     = "https://chatgpt.com/backend-api/wham/usage"
)

// runQuotaProbeLoop keeps passive quota snapshots fresh while the soonest-reset
// strategy is active. Accounts that serve traffic are observed on every
// response; the probe only covers accounts whose snapshot is missing or older
// than the configured refresh interval, so it never probes per request.
func (m *Manager) runQuotaProbeLoop(ctx context.Context) {
	ticker := time.NewTicker(quotaProbeTick)
	defer ticker.Stop()
	for {
		m.probeStaleQuotaSnapshots(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// soonestResetSelectorOf returns the active soonest-reset selector, directly or
// as the session-affinity fallback.
func soonestResetSelectorOf(selector Selector) *SoonestResetSelector {
	switch typed := selector.(type) {
	case *SoonestResetSelector:
		return typed
	case *SessionAffinitySelector:
		if typed != nil {
			fallback, _ := typed.fallback.(*SoonestResetSelector)
			return fallback
		}
	}
	return nil
}

func (m *Manager) probeStaleQuotaSnapshots(ctx context.Context, now time.Time) {
	selector := soonestResetSelectorOf(m.Selector())
	if selector == nil {
		return
	}
	interval := selector.cfg.RefreshInterval
	var due []*Auth
	m.mu.RLock()
	for _, auth := range m.auths {
		if quotaProbeURL(auth) == "" || auth.Disabled || auth.Status == StatusDisabled {
			continue
		}
		if !auth.Quota.ObservedAt.IsZero() && now.Sub(auth.Quota.ObservedAt) < interval {
			continue
		}
		due = append(due, auth.Clone())
	}
	m.mu.RUnlock()

	for _, auth := range due {
		if !selector.claimProbe(auth.ID, now, interval) {
			continue
		}
		// Each probe runs on its own goroutine so one slow upstream cannot
		// delay the others; an account has at most one probe in flight.
		go func(auth *Auth) {
			defer selector.releaseProbe(auth.ID)
			m.probeQuota(ctx, auth)
		}(auth)
	}
}

// claimProbe reports whether a probe may start now and marks it in flight.
// An account is not probed while a probe is in flight, and failed probes are
// not retried before the next interval.
func (s *SoonestResetSelector) claimProbe(authID string, now time.Time, interval time.Duration) bool {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if _, busy := s.inFlightProbes[authID]; busy {
		return false
	}
	if last, ok := s.lastProbes[authID]; ok && now.Sub(last) < interval {
		return false
	}
	if s.lastProbes == nil {
		s.lastProbes = make(map[string]time.Time)
		s.inFlightProbes = make(map[string]struct{})
	}
	s.lastProbes[authID] = now
	s.inFlightProbes[authID] = struct{}{}
	return true
}

func (s *SoonestResetSelector) releaseProbe(authID string) {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	delete(s.inFlightProbes, authID)
}

// quotaProbeURL returns the usage endpoint for OAuth accounts of providers with
// a known usage API, or "" when the account cannot be probed.
func quotaProbeURL(auth *Auth) string {
	if auth == nil || auth.AuthKind() == AuthKindAPIKey {
		return ""
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return ""
	}
	if IsCodexUseSIWC(auth) {
		// SIWC tokens are not accepted by the ChatGPT usage endpoint.
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		return claudeUsageProbeURL
	case "codex":
		return codexUsageProbeURL
	default:
		return ""
	}
}

func (m *Manager) probeQuota(ctx context.Context, auth *Auth) {
	entry := log.WithFields(log.Fields{"auth": auth.ID, "provider": auth.Provider})
	headers, err := m.fetchQuotaProbe(ctx, auth)
	if err != nil {
		entry.Debugf("soonest-reset: quota probe failed: %v", err)
		return
	}
	if len(headers) == 0 {
		entry.Debug("soonest-reset: quota probe returned no usage windows")
		return
	}
	observedAt := time.Now()
	m.mu.Lock()
	current := m.auths[auth.ID]
	// A response observed while the probe was in flight is at least as fresh.
	if current != nil && !current.Quota.ObservedAt.After(auth.Quota.ObservedAt) {
		current.Quota.ObserveResponseHeadersForProvider(current.Provider, headers, observedAt)
	}
	m.mu.Unlock()
	entry.Debug("soonest-reset: quota probe refreshed snapshot")
}

func (m *Manager) fetchQuotaProbe(ctx context.Context, auth *Auth) (http.Header, error) {
	targetURL := quotaProbeURL(auth)
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	switch provider {
	case "claude":
		headers.Set("Anthropic-Beta", claudeUsageProbeBeta)
	case "codex":
		if accountID, ok := auth.Metadata["account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
			headers.Set("Chatgpt-Account-Id", strings.TrimSpace(accountID))
		}
	}
	req, err := m.NewHttpRequest(ctx, auth, http.MethodGet, targetURL, nil, headers)
	if err != nil {
		return nil, err
	}
	resp, err := m.HttpRequest(ctx, auth, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("soonest-reset: close quota probe body: %v", errClose)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, quotaProbeMaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if provider == "claude" {
		return claudeUsageProbeHeaders(body), nil
	}
	return codexUsageProbeHeaders(body), nil
}

// claudeUsageProbeHeaders converts the Claude OAuth usage response
// ({"five_hour":{"utilization":12.0,"resets_at":"..."},"seven_day":{...}},
// utilization in percent) into the unified rate-limit headers that Claude
// responses carry, so probe and response snapshots read the same way.
//
// The overall unified status, reset, and representative claim follow the most
// used window, as they do on responses.
func claudeUsageProbeHeaders(body []byte) http.Header {
	root := gjson.ParseBytes(body)
	headers := make(http.Header)
	representativeUsed := -1.0
	for _, window := range []struct{ field, name string }{{"five_hour", "5h"}, {"seven_day", "7d"}} {
		node := root.Get(window.field)
		utilization := node.Get("utilization")
		if !node.IsObject() || utilization.Type != gjson.Number {
			continue
		}
		used := clampUnit(utilization.Float() / 100)
		prefix := soonestResetQuotaSignalUnifiedPrefix + window.name + "-"
		headers.Set(prefix+"Utilization", strconv.FormatFloat(used, 'f', -1, 64))
		status := "allowed"
		if used >= 1 {
			status = soonestResetQuotaSignalRejectedStatus
		}
		headers.Set(prefix+"Status", status)
		reset := ""
		if resetsAt, errParse := time.Parse(time.RFC3339Nano, node.Get("resets_at").String()); errParse == nil {
			reset = strconv.FormatInt(resetsAt.Unix(), 10)
			headers.Set(prefix+"Reset", reset)
		}
		if used > representativeUsed {
			representativeUsed = used
			headers.Set(soonestResetQuotaSignalUnifiedPrefix+"Status", status)
			headers.Set(soonestResetQuotaSignalUnifiedPrefix+"Representative-Claim", window.field)
			headers.Del(soonestResetQuotaSignalUnifiedPrefix + "Reset")
			if reset != "" {
				headers.Set(soonestResetQuotaSignalUnifiedPrefix+"Reset", reset)
			}
		}
	}
	return headers
}

// codexUsageProbeHeaders converts the Codex usage response
// ({"rate_limit":{"primary_window":{"used_percent":..,"limit_window_seconds":..,
// "reset_at":..},"secondary_window":{...}}}) into X-Codex-* response headers.
//
// Plan type, allowed/limit-reached flags, and credits are carried over too, so
// a probe snapshot shows what a response snapshot shows.
func codexUsageProbeHeaders(body []byte) http.Header {
	root := gjson.ParseBytes(body)
	rateLimit := root.Get("rate_limit")
	headers := make(http.Header)
	setString := func(name string, value gjson.Result) {
		if value.Type == gjson.String && strings.TrimSpace(value.String()) != "" {
			headers.Set(soonestResetQuotaSignalCodexPrefix+name, strings.TrimSpace(value.String()))
		}
	}
	setBool := func(name string, value gjson.Result) {
		if value.IsBool() {
			// Codex responses spell booleans as Python-style True/False.
			headers.Set(soonestResetQuotaSignalCodexPrefix+name, strings.ToUpper(value.Raw[:1])+value.Raw[1:])
		}
	}
	setString("Plan-Type", root.Get("plan_type"))
	setBool("Allowed", rateLimit.Get("allowed"))
	setBool("Limit-Reached", rateLimit.Get("limit_reached"))
	setBool("Credits-Has-Credits", root.Get("credits.has_credits"))
	setBool("Credits-Unlimited", root.Get("credits.unlimited"))
	if balance := root.Get("credits.balance"); balance.Exists() && balance.Type != gjson.Null {
		headers.Set(soonestResetQuotaSignalCodexPrefix+"Credits-Balance", balance.String())
	}
	for _, window := range []struct{ field, name string }{{"primary_window", "Primary"}, {"secondary_window", "Secondary"}} {
		node := rateLimit.Get(window.field)
		used := node.Get("used_percent")
		if !node.IsObject() || used.Type != gjson.Number {
			continue
		}
		prefix := soonestResetQuotaSignalCodexPrefix + window.name + "-"
		headers.Set(prefix+"Used-Percent", strconv.FormatFloat(used.Float(), 'f', -1, 64))
		if seconds := node.Get("limit_window_seconds").Int(); seconds > 0 {
			headers.Set(prefix+"Window-Minutes", strconv.FormatInt(seconds/60, 10))
		}
		if resetAt := node.Get("reset_at").Int(); resetAt > 0 {
			headers.Set(prefix+"Reset-At", strconv.FormatInt(resetAt, 10))
		}
		if after := node.Get("reset_after_seconds"); after.Exists() && after.Int() >= 0 {
			headers.Set(prefix+"Reset-After-Seconds", strconv.FormatInt(after.Int(), 10))
		}
	}
	return headers
}
