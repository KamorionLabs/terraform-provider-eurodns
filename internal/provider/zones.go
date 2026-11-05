package provider

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"golang.org/x/sync/singleflight"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// maxPreconditionRetries bounds the re-read and re-apply loop on HTTP 412.
const maxPreconditionRetries = 5

const (
	modeDirect = "direct"
	modeGate   = "gate"
)

// apiClient is shared by all resources and data sources of one provider
// instance. Reads hit EuroDNS once per zone until a write invalidates the
// cache; writes are serialized per zone.
type apiClient struct {
	client   *eurodns.Client
	mode     string
	features map[string]bool

	sf     singleflight.Group
	mu     sync.Mutex
	cache  map[string]*eurodns.Zone
	gen    map[string]uint64
	writes map[string]*sync.Mutex

	lockRetry lockRetryPolicy

	baseURL        string // gate URL, for the policy API
	delegatedRetry delegatedRetry
}

func newAPIClient(c *eurodns.Client, mode string, features []string) *apiClient {
	f := make(map[string]bool, len(features))
	for _, name := range features {
		f[name] = true
	}
	return &apiClient{
		client:   c,
		mode:     mode,
		features: f,
		cache:    map[string]*eurodns.Zone{},
		gen:      map[string]uint64{},
		writes:   map[string]*sync.Mutex{},

		lockRetry:      defaultLockRetry,
		delegatedRetry: defaultDelegatedRetry,
	}
}

func (a *apiClient) hasFeature(name string) bool { return a.features[name] }

// zone returns the cached zone, fetching it once if needed.
func (a *apiClient) zone(ctx context.Context, name string) (*eurodns.Zone, error) {
	a.mu.Lock()
	z, ok := a.cache[name]
	gen := a.gen[name]
	a.mu.Unlock()
	if ok {
		return z, nil
	}
	v, err, _ := a.sf.Do(fmt.Sprintf("%s#%d", name, gen), func() (any, error) {
		z, err := a.client.GetZone(ctx, name)
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		// A write that completed during the fetch makes this result stale.
		if a.gen[name] == gen {
			a.cache[name] = z
		}
		a.mu.Unlock()
		return z, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*eurodns.Zone), nil
}

func (a *apiClient) invalidate(name string) {
	a.mu.Lock()
	delete(a.cache, name)
	a.gen[name]++
	a.mu.Unlock()
}

func (a *apiClient) writeLock(name string) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, ok := a.writes[name]
	if !ok {
		m = &sync.Mutex{}
		a.writes[name] = m
	}
	return m
}

// findSet returns the RRset for key in z, nil if absent.
func findSet(zoneName string, z *eurodns.Zone, key rrset.Key) *rrset.Set {
	sets := rrset.Group(zoneName, z.Records)
	if s, ok := sets[key]; ok {
		return &s
	}
	return nil
}

// mutateFunc returns the changes to apply to the freshly read zone, none
// when nothing has to be written.
type mutateFunc func(current *eurodns.Zone) ([]zonediff.Change, error)

// write reads the zone fresh, applies the RRset changes and saves the whole
// zone with If-Match, retrying from a fresh read when the gate reports that
// the zone changed meanwhile or that another process holds its lock. Records
// outside the change are written back unchanged.
func (a *apiClient) write(ctx context.Context, zoneName string, mutate mutateFunc) error {
	lock := a.writeLock(zoneName)
	lock.Lock()
	defer lock.Unlock()
	defer a.invalidate(zoneName)

	waiter := a.lockRetry.start("save", zoneName)
	for preconditions := 0; ; {
		current, err := a.client.GetZone(ctx, zoneName)
		if err != nil {
			return err
		}
		changes, err := mutate(current)
		if err != nil || len(changes) == 0 {
			return err
		}
		desired := zonediff.Apply(zoneName, current, changes)
		hint := &retryAfterHint{}
		err = a.client.SaveZone(withRetryAfterHint(ctx, hint), zoneName, desired, eurodns.WithIfMatch(current.ETag))
		switch {
		case err == nil:
			return nil
		case isZoneLocked(err):
			if err := waiter.wait(ctx, err, hint.get()); err != nil {
				return err
			}
		case eurodns.IsPreconditionFailed(err):
			preconditions++
			if preconditions >= maxPreconditionRetries {
				return err
			}
		default:
			return err
		}
	}
}

// adopt asks the gate to adopt RRsets, waiting while another process holds
// the zone lock.
func (a *apiClient) adopt(ctx context.Context, zoneName string, req eurodns.AdoptRequest) error {
	lock := a.writeLock(zoneName)
	lock.Lock()
	defer lock.Unlock()
	defer a.invalidate(zoneName)

	waiter := a.lockRetry.start("adopt", zoneName)
	for {
		hint := &retryAfterHint{}
		err := a.gateAdopt(withRetryAfterHint(ctx, hint), zoneName, req)
		if err == nil || !isZoneLocked(err) {
			return err
		}
		if err := waiter.wait(ctx, err, hint.get()); err != nil {
			return err
		}
	}
}

// buildSet builds the desired RRset, reusing the ids, host spelling and
// extra fields of existing records whose rdata is unchanged.
func buildSet(key rrset.Key, ttl int, values []string, old *rrset.Set) *rrset.Set {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)

	host := key.Host
	existing := map[string]eurodns.Record{}
	if old != nil {
		for _, r := range old.Records {
			existing[r.RData] = r
			host = r.Host
		}
	}

	set := &rrset.Set{Key: key, TTL: ttl, Values: sorted}
	for _, v := range sorted {
		rec := eurodns.Record{Type: key.Type, Host: host, TTL: ttl, RData: v}
		if prev, ok := existing[v]; ok {
			rec.ID = prev.ID
			rec.IsDynDNS = prev.IsDynDNS
			rec.Proxy = prev.Proxy
			rec.Extra = prev.Extra
		}
		set.Records = append(set.Records, rec)
	}
	return set
}

func recordSetID(zone string, key rrset.Key) string {
	return fmt.Sprintf("%s/%s/%s", zone, key.Host, key.Type)
}
