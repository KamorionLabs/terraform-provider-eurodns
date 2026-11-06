package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/terraform-plugin-framework/types"

	eurodns "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

func fakeJWT(exp time.Time) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":"x","exp":%d}`, exp.Unix()))) + ".sig"
}

func TestJWTExpiry(t *testing.T) {
	exp := time.Unix(2000000000, 0)
	if got := jwtExpiry(fakeJWT(exp)); !got.Equal(exp) {
		t.Fatalf("got %v", got)
	}
	if got := jwtExpiry("not-a-jwt"); !got.IsZero() {
		t.Fatalf("expected zero, got %v", got)
	}
}

func TestCachingTokenSourceRefetchesBeforeExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	src := newCachingTokenSource(func(context.Context) (string, time.Time, error) {
		calls++
		return fmt.Sprintf("tok-%d", calls), now.Add(10 * time.Minute), nil
	})
	src.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if tok, _ := src.Token(ctx); tok != "tok-1" {
			t.Fatalf("got %s", tok)
		}
	}
	now = now.Add(9 * time.Minute) // inside the refresh margin
	if tok, _ := src.Token(ctx); tok != "tok-2" {
		t.Fatalf("expected refresh, got %s", tok)
	}
}

func TestFileTokenIsReReadWhenExpired(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "token")
	now := time.Now()
	if err := os.WriteFile(f, []byte(fakeJWT(now.Add(time.Minute))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := newCachingTokenSource(fileTokenFetch(f))
	first, err := src.Token(context.Background())
	if err != nil || strings.HasSuffix(first, "\n") {
		t.Fatalf("token %q, err %v", first, err)
	}
	second := fakeJWT(now.Add(time.Hour))
	if err := os.WriteFile(f, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	// The first token expires within the refresh margin: the file is read again.
	if tok, _ := src.Token(context.Background()); tok != second {
		t.Fatal("rotated token not picked up")
	}
}

func TestCommandToken(t *testing.T) {
	src := newCachingTokenSource(commandTokenFetch([]string{"sh", "-c", "echo cmd-token"}))
	if tok, err := src.Token(context.Background()); err != nil || tok != "cmd-token" {
		t.Fatalf("token %q, err %v", tok, err)
	}
	bad := newCachingTokenSource(commandTokenFetch([]string{"sh", "-c", "echo boom >&2; exit 3"}))
	if _, err := bad.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

type fakeSTS struct {
	in  *sts.GetWebIdentityTokenInput
	exp time.Time
}

func (f *fakeSTS) GetWebIdentityToken(_ context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.in = in
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String("aws-jwt"), Expiration: &f.exp}, nil
}

func TestAWSWebIdentityToken(t *testing.T) {
	fake := &fakeSTS{exp: time.Now().Add(time.Hour)}
	src := newCachingTokenSource(awsWebIdentityFetch(
		awsWebIdentityConfig{Audience: "dns-gate", SigningAlgorithm: "ES384", DurationSeconds: 900},
		func(context.Context) (stsTokenAPI, error) { return fake, nil },
	))
	tok, err := src.Token(context.Background())
	if err != nil || tok != "aws-jwt" {
		t.Fatalf("token %q, err %v", tok, err)
	}
	if fake.in.Audience[0] != "dns-gate" || *fake.in.SigningAlgorithm != "ES384" || *fake.in.DurationSeconds != 900 {
		t.Fatalf("unexpected input %+v", fake.in)
	}
}

func TestResolveModes(t *testing.T) {
	ctx := context.Background()
	p := &eurodnsProvider{newSTS: defaultSTSClient}
	null := providerModel{
		AppID: types.StringNull(), APIKey: types.StringNull(), BaseURL: types.StringNull(),
		MaxRetries: types.Int64Null(), RequestInterval: types.StringNull(), RequestBurst: types.Int64Null(),
	}

	t.Run("env gate mode with token file", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envGateURL, "https://gate.example.com")
		t.Setenv(envGateTokenFile, "/var/run/token")
		s, err := p.resolve(ctx, null)
		if err != nil || s.mode != modeGate || s.baseURL != "https://gate.example.com" {
			t.Fatalf("settings %+v, err %v", s, err)
		}
	})
	t.Run("legacy EURODNS_GATE_ variables", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("EURODNS_GATE_URL", "https://legacy.example.com")
		t.Setenv("EURODNS_GATE_TOKEN", "t")
		s, err := p.resolve(ctx, null)
		if err != nil || s.mode != modeGate || s.baseURL != "https://legacy.example.com" {
			t.Fatalf("settings %+v, err %v", s, err)
		}
		t.Setenv(envGateURL, "https://gate.example.com")
		s, err = p.resolve(ctx, null)
		if err != nil || s.baseURL != "https://gate.example.com" {
			t.Fatalf("DNS_GATE_URL must win: settings %+v, err %v", s, err)
		}
	})
	t.Run("env direct mode", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envAppID, "a")
		t.Setenv(envAPIKey, "k")
		s, err := p.resolve(ctx, null)
		if err != nil || s.mode != modeDirect || s.baseURL != eurodns.DefaultBaseURL {
			t.Fatalf("settings %+v, err %v", s, err)
		}
	})
	t.Run("env ambiguity", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envAppID, "a")
		t.Setenv(envAPIKey, "k")
		t.Setenv(envGateURL, "https://gate.example.com")
		t.Setenv(envGateToken, "t")
		if _, err := p.resolve(ctx, null); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("two auth methods", func(t *testing.T) {
		clearEnv(t)
		m := null
		m.Gate = &gateModel{URL: types.StringValue("https://gate.example.com"), Auth: &gateAuthModel{
			Token: types.StringValue("t"), TokenFile: types.StringValue("/f"), TokenCommand: types.ListNull(types.StringType),
		}}
		if _, err := p.resolve(ctx, m); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("expected exactly-one error, got %v", err)
		}
	})
	t.Run("missing credentials", func(t *testing.T) {
		clearEnv(t)
		if _, err := p.resolve(ctx, null); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestZoneReadIsSharedAcrossResources(t *testing.T) {
	up := seededUpstream(t)
	c, err := eurodns.New(
		eurodns.WithBaseURL(up.URL),
		eurodns.WithAuth(&eurodns.APIKeyAuth{AppID: testAppID, APIKey: testAPIKey}),
		eurodns.WithRateLimit(time.Millisecond, 100),
	)
	if err != nil {
		t.Fatal(err)
	}
	api := newAPIClient(c, modeDirect, nil)
	start := up.Requests()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := api.zone(context.Background(), testZone); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := up.Requests() - start; n != 1 {
		t.Fatalf("expected one upstream read, got %d", n)
	}
	api.invalidate(testZone)
	if _, err := api.zone(context.Background(), testZone); err != nil {
		t.Fatal(err)
	}
	if n := up.Requests() - start; n != 2 {
		t.Fatalf("expected a fresh read after invalidation, got %d", n)
	}
}

func TestUpdateChanges(t *testing.T) {
	zone := &eurodns.Zone{Name: testZone, Records: []eurodns.Record{
		{Type: "CNAME", Host: "_validation.www", TTL: 600, RData: "_token.acm-validations.example.net."},
		{Type: "TXT", Host: "legacy", TTL: 600, RData: "keep-me"},
	}}
	cur := rrset.Key{Host: "_validation.www", Type: "CNAME"}
	values := []string{"_token.acm-validations.example.net."}
	ops := func(changes []zonediff.Change) string {
		var out []string
		for _, c := range changes {
			out = append(out, fmt.Sprintf("%v %s/%s", c.Op, c.Key.Host, c.Key.Type))
		}
		return strings.Join(out, ", ")
	}

	t.Run("same key and content writes nothing", func(t *testing.T) {
		changes, err := updateChanges(testZone, zone, cur, cur, 600, values)
		if err != nil || len(changes) != 0 {
			t.Fatalf("changes %s, err %v", ops(changes), err)
		}
	})
	t.Run("same key, new content", func(t *testing.T) {
		changes, err := updateChanges(testZone, zone, cur, cur, 3600, values)
		if err != nil || len(changes) != 1 || changes[0].Op != zonediff.OpUpdate {
			t.Fatalf("changes %s, err %v", ops(changes), err)
		}
	})
	t.Run("host change deletes and creates in one change list", func(t *testing.T) {
		next := rrset.Key{Host: "_validation.api", Type: "CNAME"}
		changes, err := updateChanges(testZone, zone, cur, next, 600, values)
		if err != nil || len(changes) != 2 || changes[0].Op != zonediff.OpDelete || changes[0].Key != cur ||
			changes[1].Op != zonediff.OpCreate || changes[1].Key != next {
			t.Fatalf("changes %s, err %v", ops(changes), err)
		}
	})
	t.Run("host change onto an unmanaged RRset is refused", func(t *testing.T) {
		_, err := updateChanges(testZone, zone, cur, rrset.Key{Host: "legacy", Type: "TXT"}, 600, []string{"x"})
		var e *existsError
		if !errors.As(err, &e) {
			t.Fatalf("expected existsError, got %v", err)
		}
	})
}
