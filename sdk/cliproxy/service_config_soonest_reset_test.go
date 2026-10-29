package cliproxy

import (
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestSoonestResetRoutingSelector(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:                    "soonest-reset",
			SoonestResetFiveHourLimit:   80,
			SoonestResetTieMargin:       "3h",
			SoonestResetRefreshInterval: "10m",
		},
	})
	selector, ok := newRoutingSelector(state).(*coreauth.SoonestResetSelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SoonestResetSelector", newRoutingSelector(state))
	}
	want := coreauth.SoonestResetConfig{FiveHourLimit: 0.8, TieMargin: 3 * time.Hour, RefreshInterval: 10 * time.Minute}
	if got := selector.Config(); got != want {
		t.Fatalf("config = %+v, want %+v", got, want)
	}

	defaults := newRoutingSelector(normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "soonest-reset", SoonestResetTieMargin: "bogus"},
	})).(*coreauth.SoonestResetSelector)
	want = coreauth.SoonestResetConfig{FiveHourLimit: 0.9, TieMargin: 6 * time.Hour, RefreshInterval: 5 * time.Minute}
	if got := defaults.Config(); got != want {
		t.Fatalf("default config = %+v, want %+v", got, want)
	}
}
