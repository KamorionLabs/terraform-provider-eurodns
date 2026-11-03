package provider

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

// reasonZoneLocked is the gate refusal sent when a write waited longer than
// its lock wait because another writer (another Terraform run, the gate UI)
// holds the zone. The gate answers 503 with Retry-After.
const reasonZoneLocked = "zone_locked"

func isZoneLocked(err error) bool {
	var apiErr *eurodns.APIError
	return errors.As(err, &apiErr) && apiErr.Reason == reasonZoneLocked
}

// lockRetryPolicy bounds the waits on a zone lock held by another process.
// Writes of one provider process are already serialized per zone; this
// covers concurrent processes. The eurodns-go transport never retries a
// non-idempotent request on 5xx, so these are the only retries of a write.
type lockRetryPolicy struct {
	baseWait time.Duration // first wait when the gate sends no Retry-After, doubled on each retry
	maxWait  time.Duration // cap of one wait, Retry-After included
	budget   time.Duration // total time spent on one write before giving up

	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

var defaultLockRetry = lockRetryPolicy{
	baseWait: 2 * time.Second,
	maxWait:  30 * time.Second,
	budget:   5 * time.Minute,
	now:      time.Now,
	sleep:    sleepCtx,
}

type lockWaiter struct {
	policy   lockRetryPolicy
	op, zone string
	started  time.Time
	retries  int
}

func (p lockRetryPolicy) start(op, zone string) *lockWaiter {
	return &lockWaiter{policy: p, op: op, zone: zone, started: p.now()}
}

// wait sleeps before the next attempt after a zone_locked refusal. It returns
// the refusal when the budget would be exceeded, and the refusal joined with
// the context error when the context ends first.
func (w *lockWaiter) wait(ctx context.Context, lockErr error, retryAfter time.Duration) error {
	d := retryAfter
	if d <= 0 {
		d = w.policy.baseWait << w.retries
		if d <= 0 || d > w.policy.maxWait {
			d = w.policy.maxWait
		}
		d = time.Duration(float64(d) * (0.5 + rand.Float64()))
	}
	d = min(d, w.policy.maxWait)
	elapsed := w.policy.now().Sub(w.started)
	if elapsed+d > w.policy.budget {
		tflog.Warn(ctx, "zone still locked by another write, giving up", map[string]any{
			"zone": w.zone, "operation": w.op, "retries": w.retries, "elapsed": elapsed.String(),
		})
		return lockErr
	}
	w.retries++
	tflog.Warn(ctx, "zone locked by another write, retrying", map[string]any{
		"zone": w.zone, "operation": w.op, "retry": w.retries, "wait": d.String(), "elapsed": elapsed.String(),
	})
	if err := w.policy.sleep(ctx, d); err != nil {
		return errors.Join(lockErr, fmt.Errorf("stopped waiting for the zone lock: %w", err))
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryAfterHint receives the Retry-After of a 503 answer. eurodns.APIError
// does not carry the response headers, so retryAfterTransport records it for
// requests whose context holds a hint.
type retryAfterHint struct{ d atomic.Int64 }

func (h *retryAfterHint) get() time.Duration { return time.Duration(h.d.Load()) }

type retryAfterHintKey struct{}

func withRetryAfterHint(ctx context.Context, h *retryAfterHint) context.Context {
	return context.WithValue(ctx, retryAfterHintKey{}, h)
}

// retryAfterTransport sits below the eurodns-go transport, so it sees every
// attempt and keeps the Retry-After of the last one.
type retryAfterTransport struct {
	base http.RoundTripper
}

func (t retryAfterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil && resp.StatusCode == http.StatusServiceUnavailable {
		if h, ok := req.Context().Value(retryAfterHintKey{}).(*retryAfterHint); ok {
			h.d.Store(int64(parseRetryAfter(resp.Header.Get("Retry-After"))))
		}
	}
	return resp, err
}

// parseRetryAfter reads delay-seconds or an HTTP date, 0 when absent or invalid.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(time.Until(at), 0)
	}
	return 0
}
