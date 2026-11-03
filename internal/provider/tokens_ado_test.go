package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/terraform-plugin-framework/types"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

func fakeADO(t *testing.T, calls *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Method != http.MethodPost || r.URL.Path != "/plan/jobs/job/oidctoken" ||
			r.URL.Query().Get("api-version") != adoOIDCAPIVersion || r.URL.Query().Get("serviceConnectionId") != "sc-id" {
			http.Error(w, "unexpected request "+r.Method+" "+r.URL.String(), http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer job-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"oidcToken":"ado-token"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAzureDevOpsToken(t *testing.T) {
	calls := 0
	srv := fakeADO(t, &calls)
	src := newCachingTokenSource(azureDevOpsFetch(azureDevOpsConfig{
		ServiceConnectionID: "sc-id", RequestURI: srv.URL + "/plan/jobs/job/oidctoken", AccessToken: "job-token",
	}, srv.Client()))
	for i := 0; i < 2; i++ {
		tok, err := src.Token(context.Background())
		if err != nil || tok != "ado-token" {
			t.Fatalf("token %q, err %v", tok, err)
		}
	}
	if calls != 1 {
		t.Fatalf("token not cached: %d calls", calls)
	}

	bad := newCachingTokenSource(azureDevOpsFetch(azureDevOpsConfig{
		ServiceConnectionID: "sc-id", RequestURI: srv.URL + "/plan/jobs/job/oidctoken", AccessToken: "wrong",
	}, srv.Client()))
	if _, err := bad.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected HTTP 401, got %v", err)
	}
}

func TestResolveAzureDevOps(t *testing.T) {
	ctx := context.Background()
	calls := 0
	srv := fakeADO(t, &calls)
	azure := &fakeAzureCredential{exp: time.Now().Add(time.Hour)}
	p := &eurodnsProvider{newSTS: defaultSTSClient, adoHTTP: srv.Client(),
		newAzureCredential: func(azureIdentityConfig) (azcore.TokenCredential, error) { return azure, nil }}
	model := func(a *gateAuthModel) providerModel {
		a.TokenCommand = types.ListNull(types.StringType)
		a.Token, a.TokenFile = types.StringNull(), types.StringNull()
		return providerModel{
			AppID: types.StringNull(), APIKey: types.StringNull(), BaseURL: types.StringNull(),
			MaxRetries: types.Int64Null(), RequestInterval: types.StringNull(), RequestBurst: types.Int64Null(),
			Gate: &gateModel{URL: types.StringValue("https://gate.example.com"), Auth: a},
		}
	}
	ado := &azureDevOpsModel{ServiceConnectionID: types.StringValue("sc-id")}
	both := func() providerModel {
		return model(&gateAuthModel{AzureDevOps: ado, AzureIdentity: &azureIdentityModel{
			Scope: types.StringValue("api://gate/.default"), TenantID: types.StringNull(), ClientID: types.StringNull(),
		}})
	}
	token := func(m providerModel) (string, error) {
		s, err := p.resolve(ctx, m)
		if err != nil {
			return "", err
		}
		return s.auth.(*eurodns.BearerAuth).Source.Token(ctx)
	}
	clearEnv(t)

	if tok, err := token(both()); err != nil || tok != "entra-token" {
		t.Fatalf("outside a job: token %q, err %v", tok, err)
	}
	if _, err := p.resolve(ctx, model(&gateAuthModel{AzureDevOps: ado})); err == nil ||
		!strings.Contains(err.Error(), "only works inside an Azure DevOps job") {
		t.Fatalf("expected outside-a-job error, got %v", err)
	}

	t.Setenv(envADOOIDCRequestURI, srv.URL+"/plan/jobs/job/oidctoken")
	if _, err := p.resolve(ctx, both()); err == nil || !strings.Contains(err.Error(), envADOAccessToken) {
		t.Fatalf("expected missing access token error, got %v", err)
	}
	t.Setenv(envADOAccessToken, "job-token")
	if tok, err := token(both()); err != nil || tok != "ado-token" {
		t.Fatalf("inside a job: token %q, err %v", tok, err)
	}
	if tok, err := token(model(&gateAuthModel{AzureDevOps: ado})); err != nil || tok != "ado-token" {
		t.Fatalf("inside a job, azure_devops alone: token %q, err %v", tok, err)
	}

	noID := func() providerModel {
		return model(&gateAuthModel{AzureDevOps: &azureDevOpsModel{ServiceConnectionID: types.StringNull()}})
	}
	if _, err := p.resolve(ctx, noID()); err == nil ||
		!strings.Contains(err.Error(), "service_connection_id is required") {
		t.Fatalf("expected missing id error, got %v", err)
	}
	t.Setenv(envADOServiceConnectionID, "sc-id")
	if tok, err := token(noID()); err != nil || tok != "ado-token" {
		t.Fatalf("id from %s: token %q, err %v", envADOServiceConnectionID, tok, err)
	}
}

func TestResolveAzureDevOpsNoIDOutsideJob(t *testing.T) {
	ctx := context.Background()
	azure := &fakeAzureCredential{exp: time.Now().Add(time.Hour)}
	p := &eurodnsProvider{newSTS: defaultSTSClient,
		newAzureCredential: func(azureIdentityConfig) (azcore.TokenCredential, error) { return azure, nil }}
	clearEnv(t)
	a := &gateAuthModel{
		AzureDevOps: &azureDevOpsModel{ServiceConnectionID: types.StringNull()},
		AzureIdentity: &azureIdentityModel{
			Scope: types.StringValue("api://gate/.default"), TenantID: types.StringNull(), ClientID: types.StringNull(),
		},
		TokenCommand: types.ListNull(types.StringType), Token: types.StringNull(), TokenFile: types.StringNull(),
	}
	m := providerModel{
		AppID: types.StringNull(), APIKey: types.StringNull(), BaseURL: types.StringNull(),
		MaxRetries: types.Int64Null(), RequestInterval: types.StringNull(), RequestBurst: types.Int64Null(),
		Gate: &gateModel{URL: types.StringValue("https://gate.example.com"), Auth: a},
	}
	s, err := p.resolve(ctx, m)
	if err != nil {
		t.Fatalf("outside a job without id: %v", err)
	}
	if tok, err := s.auth.(*eurodns.BearerAuth).Source.Token(ctx); err != nil || tok != "entra-token" {
		t.Fatalf("outside a job without id: token %q, err %v", tok, err)
	}
}
