package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

func TestFetchGateInfoOnlyUsesDNSGatePath(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		notGate bool
	}{
		{"dns-gate", "/.well-known/dns-gate", false},
		{"legacy path only", "/.well-known/eurodns-gate", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(eurodns.GateInfo{Version: "1", Features: []string{eurodns.FeatureAdopt}})
			}))
			defer srv.Close()
			c, err := newClient(eurodns.WithBaseURL(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			info, err := fetchGateInfo(context.Background(), c, srv.URL)
			if tc.notGate {
				if !errors.Is(err, errNotGate) {
					t.Fatalf("expected errNotGate, got %v %+v", err, info)
				}
				return
			}
			if err != nil || !info.HasFeature(eurodns.FeatureAdopt) {
				t.Fatalf("info %+v, err %v", info, err)
			}
		})
	}
}

func TestGateAdoptPath(t *testing.T) {
	if got := gateAdoptPath("example.com"); got != "/.well-known/dns-gate/zones/example.com/adopt" {
		t.Fatal(got)
	}
}
