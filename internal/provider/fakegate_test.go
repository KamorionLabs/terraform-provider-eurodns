package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

const (
	testAppID  = "test-app"
	testAPIKey = "test-key"
	testToken  = "test-token"
	testZone   = "example.com"
)

// fakeGate is a minimal eurodns-gate: bearer auth, ETag/If-Match on zones,
// RRset ownership (records seeded upstream are foreign) and adoption.
type fakeGate struct {
	*httptest.Server
	upstream *eurodnstest.Server
	client   *eurodns.Client
	features []string

	mu            sync.Mutex
	version       int
	owned         map[rrset.Key]bool
	fail412       int // number of PUTs to refuse with 412
	preconditions int
	adopted       []eurodns.AdoptRRset
	saves         int // PUTs that reached EuroDNS

	// failLocked writes (PUT or adopt) are refused with 503 zone_locked, as
	// when another process holds the zone lock; failUnavailable with a 503
	// of another reason.
	failLocked      int
	failUnavailable int
	lockRefusals    int
	retryAfter      string
}

func newFakeGate(t *testing.T, upstream *eurodnstest.Server, features ...string) *fakeGate {
	t.Helper()
	c, err := eurodns.New(
		eurodns.WithBaseURL(upstream.URL),
		eurodns.WithAuth(&eurodns.APIKeyAuth{AppID: testAppID, APIKey: testAPIKey}),
		eurodns.WithRateLimit(time.Millisecond, 100),
		eurodns.WithMaxRetries(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGate{upstream: upstream, client: c, features: features, version: 1, owned: map[rrset.Key]bool{}}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.Close)
	return g
}

func gateError(w http.ResponseWriter, status int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason, "message": msg})
}

func (g *fakeGate) etag() string { return fmt.Sprintf(`"v%d"`, g.version) }

func (g *fakeGate) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		gateError(w, http.StatusUnauthorized, "unauthenticated", "bad token")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx := r.Context()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == eurodns.GateInfoPath:
		_ = json.NewEncoder(w).Encode(eurodns.GateInfo{Version: "test", Features: g.features})

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, eurodns.GateInfoPath+"/zones/") && strings.HasSuffix(r.URL.Path, "/adopt"):
		if g.refuseUnavailable(w) {
			return
		}
		var req eurodns.AdoptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			gateError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		for _, a := range req.RRsets {
			g.owned[rrset.Key{Host: a.Host, Type: a.Type}] = true
			g.adopted = append(g.adopted, a)
		}
		w.WriteHeader(http.StatusNoContent)

	case r.URL.Path == "/dns-zones/"+testZone && r.Method == http.MethodGet:
		z, err := g.client.GetZone(ctx, testZone)
		if err != nil {
			gateError(w, http.StatusBadGateway, "upstream", err.Error())
			return
		}
		w.Header().Set("ETag", g.etag())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(z)

	case r.URL.Path == "/dns-zones/"+testZone && r.Method == http.MethodPut:
		if g.refuseUnavailable(w) {
			return
		}
		if m := r.Header.Get("If-Match"); m != "" && m != g.etag() {
			g.preconditions++
			gateError(w, http.StatusPreconditionFailed, "precondition", "zone changed")
			return
		}
		if g.fail412 > 0 {
			g.fail412--
			g.preconditions++
			g.version++ // simulate a concurrent write
			gateError(w, http.StatusPreconditionFailed, "precondition", "zone changed")
			return
		}
		body, _ := io.ReadAll(r.Body)
		var desired eurodns.Zone
		if err := json.Unmarshal(body, &desired); err != nil {
			gateError(w, http.StatusBadRequest, "invalid_zone", err.Error())
			return
		}
		current, err := g.client.GetZone(ctx, testZone)
		if err != nil {
			gateError(w, http.StatusBadGateway, "upstream", err.Error())
			return
		}
		delta := zonediff.Diff(testZone, current, &desired)
		var created []rrset.Key
		for _, c := range delta.Changes {
			if c.Op == zonediff.OpCreate {
				created = append(created, c.Key)
				continue
			}
			if !g.owned[c.Key] {
				gateError(w, http.StatusConflict, "foreign_rrset", fmt.Sprintf("%s %s is not owned by the gate", c.Key.Host, c.Key.Type))
				return
			}
		}
		if err := g.client.SaveZone(ctx, testZone, &desired); err != nil {
			gateError(w, http.StatusBadGateway, "upstream", err.Error())
			return
		}
		for _, k := range created {
			g.owned[k] = true
		}
		g.saves++
		g.version++
		w.WriteHeader(http.StatusNoContent)

	default:
		gateError(w, http.StatusNotFound, "not_found", r.Method+" "+r.URL.Path)
	}
}

// refuseUnavailable answers 503 while failLocked or failUnavailable remain.
func (g *fakeGate) refuseUnavailable(w http.ResponseWriter) bool {
	switch {
	case g.failLocked > 0:
		g.failLocked--
		g.lockRefusals++
		if g.retryAfter != "" {
			w.Header().Set("Retry-After", g.retryAfter)
		}
		gateError(w, http.StatusServiceUnavailable, reasonZoneLocked, "zone "+testZone+" is locked by another write")
		return true
	case g.failUnavailable > 0:
		g.failUnavailable--
		gateError(w, http.StatusServiceUnavailable, "maintenance", "gate in maintenance")
		return true
	}
	return false
}

// set runs f with the gate locked, to change its behaviour between steps.
func (g *fakeGate) set(f func(*fakeGate)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(g)
}
