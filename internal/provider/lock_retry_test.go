package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// fakeClock is a lockRetryPolicy clock where sleeping advances time instantly.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) policy(p lockRetryPolicy) lockRetryPolicy {
	p.now = func() time.Time { return c.now }
	p.sleep = func(ctx context.Context, d time.Duration) error {
		c.sleeps = append(c.sleeps, d)
		c.now = c.now.Add(d)
		return ctx.Err()
	}
	return p
}

func gateAPI(t *testing.T, g *fakeGate) *apiClient {
	t.Helper()
	c, err := newClient(
		eurodns.WithBaseURL(g.URL),
		eurodns.WithAuth(&eurodns.BearerAuth{Source: staticTokenSource(testToken)}),
		eurodns.WithRateLimit(time.Millisecond, 100),
		// Transport retries enabled with a negligible backoff: a 503 on a
		// write must still reach the provider loop once per refusal.
		eurodns.WithMaxRetries(2),
		eurodns.WithRetryBackoff(time.Millisecond, time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	return newAPIClient(c, modeGate, g.features)
}

func createTXT(api *apiClient, host, value string) error {
	key := rrset.Key{Host: host, Type: "TXT"}
	return api.write(context.Background(), testZone, func(*eurodns.Zone) ([]zonediff.Change, error) {
		return []zonediff.Change{{Op: zonediff.OpCreate, Key: key, New: buildSet(key, 600, []string{value}, nil)}}, nil
	})
}

func TestWriteWaitsForZoneLock(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership)
	g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 3, "5" })
	api := gateAPI(t, g)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	api.lockRetry = clock.policy(defaultLockRetry)

	if err := createTXT(api, "locked-then-free", "v1"); err != nil {
		t.Fatal(err)
	}
	if g.lockRefusals != 3 || g.saves != 1 {
		t.Fatalf("lock refusals %d, saves %d, want 3 and 1", g.lockRefusals, g.saves)
	}
	if fmt.Sprint(clock.sleeps) != "[5s 5s 5s]" {
		t.Fatalf("waits %v, want Retry-After (5s) three times", clock.sleeps)
	}
	if got := upstreamSet(up, "locked-then-free", "TXT"); fmt.Sprint(got) != "[v1]" {
		t.Fatalf("upstream %v", got)
	}
}

func TestWriteLockWaitIsCapped(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch)
	g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 1, "120" })
	api := gateAPI(t, g)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	api.lockRetry = clock.policy(defaultLockRetry)

	if err := createTXT(api, "capped", "v1"); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(clock.sleeps) != "[30s]" {
		t.Fatalf("waits %v, want the 30s cap", clock.sleeps)
	}
}

func TestWriteLockWaitBacksOffWithoutRetryAfter(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch)
	g.set(func(g *fakeGate) { g.failLocked = 6 })
	api := gateAPI(t, g)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	api.lockRetry = clock.policy(defaultLockRetry)

	if err := createTXT(api, "backoff", "v1"); err != nil {
		t.Fatal(err)
	}
	if len(clock.sleeps) != 6 {
		t.Fatalf("waits %v, want 6", clock.sleeps)
	}
	for i, d := range clock.sleeps {
		nominal := min(defaultLockRetry.baseWait<<i, defaultLockRetry.maxWait)
		if d < nominal/2 || d > defaultLockRetry.maxWait {
			t.Fatalf("wait %d = %v, want between %v and %v", i, d, nominal/2, defaultLockRetry.maxWait)
		}
	}
}

func TestWriteGivesUpWhenLockBudgetIsSpent(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch)
	g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 1000, "5" })
	api := gateAPI(t, g)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	api.lockRetry = clock.policy(defaultLockRetry)

	err := createTXT(api, "never-free", "v1")
	if !isZoneLocked(err) {
		t.Fatalf("expected the zone_locked refusal, got %v", err)
	}
	// 5 minutes of 5s waits, then the refusal that would exceed the budget.
	if len(clock.sleeps) != 60 || g.lockRefusals != 61 || g.saves != 0 {
		t.Fatalf("waits %d, refusals %d, saves %d", len(clock.sleeps), g.lockRefusals, g.saves)
	}
}

func TestWriteLockWaitStopsOnCancel(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch)
	g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 1000, "5" })
	api := gateAPI(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	key := rrset.Key{Host: "cancelled", Type: "TXT"}
	start := time.Now()
	err := api.write(ctx, testZone, func(*eurodns.Zone) ([]zonediff.Change, error) {
		return []zonediff.Change{{Op: zonediff.OpCreate, Key: key, New: buildSet(key, 600, []string{"v"}, nil)}}, nil
	})
	if !isZoneLocked(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected zone_locked joined with the context error, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the wait ignored the context")
	}
}

func TestWriteDoesNotRetryOther503(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch)
	g.set(func(g *fakeGate) { g.failUnavailable = 1 })
	api := gateAPI(t, g)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	api.lockRetry = clock.policy(defaultLockRetry)

	err := createTXT(api, "unavailable", "v1")
	var apiErr *eurodns.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 || apiErr.Reason != "maintenance" {
		t.Fatalf("expected the 503 maintenance error, got %v", err)
	}
	if len(clock.sleeps) != 0 || g.saves != 0 {
		t.Fatalf("waits %v, saves %d", clock.sleeps, g.saves)
	}
}

func TestAdoptWaitsForZoneLock(t *testing.T) {
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership, eurodns.FeatureAdopt)
	g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 2, "5" })
	api := gateAPI(t, g)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	api.lockRetry = clock.policy(defaultLockRetry)

	err := api.adopt(context.Background(), testZone, eurodns.AdoptRequest{RRsets: []eurodns.AdoptRRset{{Host: "legacy", Type: "TXT"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.adopted) != 1 || fmt.Sprint(clock.sleeps) != "[5s 5s]" {
		t.Fatalf("adopted %v, waits %v", g.adopted, clock.sleeps)
	}
}

func TestParseRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "5": 5 * time.Second, "0": 0, "-1": 0, "soon": 0} {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
	if got := parseRetryAfter(time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)); got < 59*time.Minute {
		t.Errorf("HTTP date: got %v", got)
	}
}

// withFastLockRetry shortens the lock waits of providers configured during the
// test.
func withFastLockRetry(t *testing.T, budget time.Duration) {
	prev := defaultLockRetry
	defaultLockRetry.maxWait = time.Millisecond
	defaultLockRetry.budget = budget
	t.Cleanup(func() { defaultLockRetry = prev })
}

func TestAccRecordSet_gateZoneLocked(t *testing.T) {
	clearEnv(t)
	withFastLockRetry(t, time.Minute)
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership, eurodns.FeatureAdopt)
	p := gateProvider(g.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 2, "5" }) },
				Config:    p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-1"),
				Check: resource.ComposeTestCheckFunc(
					checkUpstream(up, "_acme-challenge.www", "TXT", "token-1"),
					func(*terraform.State) error {
						if g.lockRefusals != 2 {
							return fmt.Errorf("expected two zone_locked refusals, got %d", g.lockRefusals)
						}
						return nil
					},
				),
			},
			{
				// Import adopts through the same wait.
				PreConfig:          func() { g.set(func(g *fakeGate) { g.failLocked = 1 }) },
				Config:             p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-1") + recordSet("legacy", "legacy", "TXT", 600, "keep-me"),
				ResourceName:       "eurodns_record_set.legacy",
				ImportState:        true,
				ImportStateId:      "example.com/legacy/TXT",
				ImportStatePersist: true,
			},
			{
				PreConfig: func() { g.set(func(g *fakeGate) { g.failLocked = 1 }) },
				Config:    p + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-2") + recordSet("legacy", "legacy", "TXT", 600, "keep-me"),
				Check: resource.ComposeTestCheckFunc(
					checkUpstream(up, "_acme-challenge.www", "TXT", "token-2"),
					func(*terraform.State) error {
						if g.lockRefusals != 4 || len(g.adopted) != 1 {
							return fmt.Errorf("refusals %d, adoptions %v", g.lockRefusals, g.adopted)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAccRecordSet_gateZoneLockedBudgetSpent(t *testing.T) {
	clearEnv(t)
	withFastLockRetry(t, 50*time.Millisecond)
	up := seededUpstream(t)
	g := newFakeGate(t, up, eurodns.FeatureIfMatch, eurodns.FeatureOwnership)
	g.set(func(g *fakeGate) { g.failLocked, g.retryAfter = 1_000_000, "5" })

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      gateProvider(g.URL) + recordSet("acme", "_acme-challenge.www", "TXT", 600, "token-1"),
			ExpectError: regexp.MustCompile(`Gate reason: zone_locked \(HTTP 503\)`),
		}},
	})
	if g.saves != 0 || g.lockRefusals < 2 {
		t.Fatalf("saves %d, refusals %d", g.saves, g.lockRefusals)
	}
}
