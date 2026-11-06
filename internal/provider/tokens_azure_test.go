package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type fakeAzureCredential struct {
	calls int
	opts  policy.TokenRequestOptions
	exp   time.Time
	err   error
}

func (f *fakeAzureCredential) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	f.opts = o
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "entra-token", ExpiresOn: f.exp}, nil
}

func TestAzureIdentityToken(t *testing.T) {
	fake := &fakeAzureCredential{exp: time.Now().Add(time.Hour)}
	var got azureIdentityConfig
	src := newCachingTokenSource(azureTokenFetch(
		azureIdentityConfig{Scope: "api://dns-gate/.default", TenantID: "tenant", ClientID: "client"},
		func(c azureIdentityConfig) (azcore.TokenCredential, error) { got = c; return fake, nil },
	))
	for i := 0; i < 3; i++ {
		tok, err := src.Token(context.Background())
		if err != nil || tok != "entra-token" {
			t.Fatalf("token %q, err %v", tok, err)
		}
	}
	if fake.calls != 1 {
		t.Fatalf("token not cached: %d calls", fake.calls)
	}
	if fake.opts.Scopes[0] != "api://dns-gate/.default" || fake.opts.TenantID != "tenant" || got.ClientID != "client" {
		t.Fatalf("unexpected request %+v / %+v", fake.opts, got)
	}
}

func TestAzureIdentityTokenRefreshAndError(t *testing.T) {
	fake := &fakeAzureCredential{exp: time.Now().Add(time.Minute)} // inside the refresh margin
	src := newCachingTokenSource(azureTokenFetch(azureIdentityConfig{Scope: "s"},
		func(azureIdentityConfig) (azcore.TokenCredential, error) { return fake, nil }))
	_, _ = src.Token(context.Background())
	_, _ = src.Token(context.Background())
	if fake.calls != 2 {
		t.Fatalf("expected a refresh, got %d calls", fake.calls)
	}
	fake.err = errors.New("no credential")
	fake.exp = time.Time{}
	src = newCachingTokenSource(azureTokenFetch(azureIdentityConfig{Scope: "s"},
		func(azureIdentityConfig) (azcore.TokenCredential, error) { return fake, nil }))
	if _, err := src.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Fatalf("expected credential error, got %v", err)
	}
}

func TestResolveAzureIdentity(t *testing.T) {
	ctx := context.Background()
	p := &eurodnsProvider{newSTS: defaultSTSClient, newAzureCredential: func(azureIdentityConfig) (azcore.TokenCredential, error) {
		return &fakeAzureCredential{exp: time.Now().Add(time.Hour)}, nil
	}}
	base := providerModel{
		AppID: types.StringNull(), APIKey: types.StringNull(), BaseURL: types.StringNull(),
		MaxRetries: types.Int64Null(), RequestInterval: types.StringNull(), RequestBurst: types.Int64Null(),
	}
	auth := func(a *gateAuthModel) providerModel {
		m := base
		a.TokenCommand = types.ListNull(types.StringType)
		if a.Token.IsNull() || a.Token.IsUnknown() {
			a.Token = types.StringNull()
		}
		m.Gate = &gateModel{URL: types.StringValue("https://gate.example.com"), Auth: a}
		return m
	}
	clearEnv(t)

	s, err := p.resolve(ctx, auth(&gateAuthModel{AzureIdentity: &azureIdentityModel{
		Scope: types.StringValue("api://dns-gate/.default"), TenantID: types.StringNull(), ClientID: types.StringNull(),
	}}))
	if err != nil || s.mode != modeGate {
		t.Fatalf("settings %+v, err %v", s, err)
	}
	if _, err := p.resolve(ctx, auth(&gateAuthModel{AzureIdentity: &azureIdentityModel{
		Scope: types.StringNull(), TenantID: types.StringNull(), ClientID: types.StringNull(),
	}})); err == nil || !strings.Contains(err.Error(), "scope is required") {
		t.Fatalf("expected missing scope error, got %v", err)
	}
	if _, err := p.resolve(ctx, auth(&gateAuthModel{
		Token:         types.StringValue("t"),
		AzureIdentity: &azureIdentityModel{Scope: types.StringValue("s"), TenantID: types.StringNull(), ClientID: types.StringNull()},
	})); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected exclusivity error, got %v", err)
	}
}
