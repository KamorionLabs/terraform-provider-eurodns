package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

const (
	envAppID          = "EURODNS_APP_ID"
	envAPIKey         = "EURODNS_API_KEY"
	envBaseURL        = "EURODNS_BASE_URL"
	envGateURL        = "EURODNS_GATE_URL"
	envGateToken      = "EURODNS_GATE_TOKEN"
	envGateTokenFile  = "EURODNS_GATE_TOKEN_FILE"
	defaultInterval   = 1100 * time.Millisecond
	defaultBurst      = 5
	defaultMaxRetries = 4
	defaultSigningAlg = "RS256"
)

var _ provider.Provider = (*eurodnsProvider)(nil)

type eurodnsProvider struct {
	version string
	// newSTS is replaced in tests.
	newSTS             func(region string) func(ctx context.Context) (stsTokenAPI, error)
	newAzureCredential func(azureIdentityConfig) (azcore.TokenCredential, error)
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &eurodnsProvider{version: version, newSTS: defaultSTSClient, newAzureCredential: defaultAzureCredential}
	}
}

type providerModel struct {
	AppID           types.String `tfsdk:"app_id"`
	APIKey          types.String `tfsdk:"api_key"`
	BaseURL         types.String `tfsdk:"base_url"`
	MaxRetries      types.Int64  `tfsdk:"max_retries"`
	RequestInterval types.String `tfsdk:"request_interval"`
	RequestBurst    types.Int64  `tfsdk:"request_burst"`
	Gate            *gateModel   `tfsdk:"gate"`
}

type gateModel struct {
	URL  types.String   `tfsdk:"url"`
	Auth *gateAuthModel `tfsdk:"auth"`
}

type gateAuthModel struct {
	Token          types.String         `tfsdk:"token"`
	TokenFile      types.String         `tfsdk:"token_file"`
	TokenCommand   types.List           `tfsdk:"token_command"`
	AWSWebIdentity *awsWebIdentityModel `tfsdk:"aws_web_identity"`
	AzureIdentity  *azureIdentityModel  `tfsdk:"azure_identity"`
}

type azureIdentityModel struct {
	Scope    types.String `tfsdk:"scope"`
	TenantID types.String `tfsdk:"tenant_id"`
	ClientID types.String `tfsdk:"client_id"`
}

type awsWebIdentityModel struct {
	Audience         types.String `tfsdk:"audience"`
	SigningAlgorithm types.String `tfsdk:"signing_algorithm"`
	Region           types.String `tfsdk:"region"`
	DurationSeconds  types.Int64  `tfsdk:"duration_seconds"`
}

func (p *eurodnsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "eurodns"
	resp.Version = p.version
}

func (p *eurodnsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages DNS records hosted at EuroDNS, either directly with an API key " +
			"(`app_id`/`api_key`) or through an [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate) " +
			"instance (`gate` block) that holds the EuroDNS key and enforces RBAC and record ownership. " +
			"The two modes are mutually exclusive and expose the same resources.",
		Attributes: map[string]schema.Attribute{
			"app_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Direct mode: EuroDNS application id (`X-APP-ID`). Env: `EURODNS_APP_ID`.",
			},
			"api_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Direct mode: EuroDNS API key (`X-API-KEY`). Env: `EURODNS_API_KEY`.",
			},
			"base_url": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Direct mode: API endpoint. Default `https://rest-api.eurodns.com`. Env: `EURODNS_BASE_URL`.",
			},
			"max_retries": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Retries on rate limiting and transient errors. Default 4.",
			},
			"request_interval": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Minimum interval between two API requests, as a Go duration. Default `1.1s`: " +
					"EuroDNS allows 10 requests per 10 seconds per IP and bans offenders progressively.",
			},
			"request_burst": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Requests allowed in a burst before `request_interval` applies. Default 5.",
			},
		},
		Blocks: map[string]schema.Block{
			"gate": schema.SingleNestedBlock{
				MarkdownDescription: "Gate mode: talk to an eurodns-gate instead of EuroDNS. Mutually exclusive with `app_id`/`api_key`.",
				Attributes: map[string]schema.Attribute{
					"url": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "eurodns-gate base URL. Env: `EURODNS_GATE_URL`.",
					},
				},
				Blocks: map[string]schema.Block{
					"auth": schema.SingleNestedBlock{
						MarkdownDescription: "How to obtain the bearer token sent to the gate. Exactly one method. " +
							"Without this block, `EURODNS_GATE_TOKEN` or `EURODNS_GATE_TOKEN_FILE` is used.",
						Attributes: map[string]schema.Attribute{
							"token": schema.StringAttribute{
								Optional:            true,
								Sensitive:           true,
								MarkdownDescription: "Static token (OIDC JWT or gate virtual key).",
							},
							"token_file": schema.StringAttribute{
								Optional:            true,
								MarkdownDescription: "File holding the token, re-read when the token expires (projected Kubernetes tokens, CI OIDC tokens).",
							},
							"token_command": schema.ListAttribute{
								Optional:            true,
								ElementType:         types.StringType,
								MarkdownDescription: "Command (argv) printing the token on stdout, run again when the token expires.",
							},
						},
						Blocks: map[string]schema.Block{
							"aws_web_identity": schema.SingleNestedBlock{
								MarkdownDescription: "Get a JWT signed by AWS STS (`sts:GetWebIdentityToken`, IAM outbound identity " +
									"federation) for the current AWS principal, from the default AWS credential chain.",
								Attributes: map[string]schema.Attribute{
									"audience": schema.StringAttribute{
										Optional:            true,
										MarkdownDescription: "Token audience expected by the gate. Required in this block.",
									},
									"signing_algorithm": schema.StringAttribute{
										Optional:            true,
										MarkdownDescription: "`RS256` (default) or `ES384`.",
									},
									"region": schema.StringAttribute{
										Optional:            true,
										MarkdownDescription: "STS region. Default: from the AWS configuration.",
									},
									"duration_seconds": schema.Int64Attribute{
										Optional:            true,
										MarkdownDescription: "Requested token lifetime.",
									},
								},
							},
							"azure_identity": schema.SingleNestedBlock{
								MarkdownDescription: "Get a Microsoft Entra ID access token for the gate application: environment " +
									"credentials, AKS workload identity, managed identity, then Azure CLI (so `AzureCLI@2` in Azure DevOps works).",
								Attributes: map[string]schema.Attribute{
									"scope": schema.StringAttribute{
										Optional:            true,
										MarkdownDescription: "Scope of the gate application, for example `api://eurodns-gate/.default`. Required in this block.",
									},
									"tenant_id": schema.StringAttribute{
										Optional:            true,
										MarkdownDescription: "Entra tenant. Default: from the environment or the Azure CLI login.",
									},
									"client_id": schema.StringAttribute{
										Optional:            true,
										MarkdownDescription: "Client id of a user-assigned managed identity or workload identity.",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// settings is the resolved provider configuration.
type settings struct {
	mode     string
	baseURL  string
	auth     eurodns.Authenticator
	interval time.Duration
	burst    int
	retries  int
}

func (p *eurodnsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := p.resolve(ctx, cfg)
	if err != nil {
		resp.Diagnostics.AddError("Invalid eurodns provider configuration", err.Error())
		return
	}

	client, err := eurodns.New(
		eurodns.WithBaseURL(s.baseURL),
		eurodns.WithAuth(s.auth),
		eurodns.WithRateLimit(s.interval, s.burst),
		eurodns.WithMaxRetries(s.retries),
		eurodns.WithUserAgent("terraform-provider-eurodns/"+p.version),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cannot create the EuroDNS client", err.Error())
		return
	}

	var features []string
	if s.mode == modeGate {
		info, err := client.GateInfo(ctx)
		if errors.Is(err, eurodns.ErrNotGate) {
			resp.Diagnostics.AddAttributeError(path.Root("gate").AtName("url"), "Not an eurodns-gate",
				fmt.Sprintf("%s does not serve %s. Point gate.url at an eurodns-gate instance, or use app_id/api_key to talk to EuroDNS directly.", s.baseURL, eurodns.GateInfoPath))
			return
		}
		if err != nil {
			addAPIError(&resp.Diagnostics, "Cannot reach the eurodns-gate", err)
			return
		}
		features = info.Features
	}

	api := newAPIClient(client, s.mode, features)
	resp.ResourceData = api
	resp.DataSourceData = api
}

// resolve merges configuration and environment and enforces mode exclusivity.
func (p *eurodnsProvider) resolve(ctx context.Context, cfg providerModel) (*settings, error) {
	s := &settings{interval: defaultInterval, burst: defaultBurst, retries: defaultMaxRetries}
	if v := cfg.RequestInterval.ValueString(); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("request_interval: invalid duration %q", v)
		}
		s.interval = d
	}
	if !cfg.RequestBurst.IsNull() {
		if cfg.RequestBurst.ValueInt64() < 1 {
			return nil, errors.New("request_burst must be at least 1")
		}
		s.burst = int(cfg.RequestBurst.ValueInt64())
	}
	if !cfg.MaxRetries.IsNull() {
		if cfg.MaxRetries.ValueInt64() < 0 {
			return nil, errors.New("max_retries cannot be negative")
		}
		s.retries = int(cfg.MaxRetries.ValueInt64())
	}

	directInConfig := cfg.AppID.ValueString() != "" || cfg.APIKey.ValueString() != "" || cfg.BaseURL.ValueString() != ""
	gateInConfig := cfg.Gate != nil
	if directInConfig && gateInConfig {
		return nil, errors.New("app_id/api_key/base_url (direct mode) and the gate block (gate mode) are mutually exclusive: " +
			"the gate holds the EuroDNS key, Terraform only sends its own identity")
	}

	gateURL := os.Getenv(envGateURL)
	if gateInConfig && cfg.Gate.URL.ValueString() != "" {
		gateURL = cfg.Gate.URL.ValueString()
	}
	useGate := gateInConfig || (!directInConfig && gateURL != "")
	if !useGate {
		return p.resolveDirect(cfg, s)
	}
	if !gateInConfig && (os.Getenv(envAppID) != "" || os.Getenv(envAPIKey) != "") {
		return nil, fmt.Errorf("both %s and %s/%s are set: choose gate mode or direct mode", envGateURL, envAppID, envAPIKey)
	}
	if gateURL == "" {
		return nil, fmt.Errorf("gate mode needs gate.url or %s", envGateURL)
	}
	var auth *gateAuthModel
	if gateInConfig {
		auth = cfg.Gate.Auth
	}
	src, err := p.tokenSource(ctx, auth)
	if err != nil {
		return nil, err
	}
	s.mode, s.baseURL, s.auth = modeGate, gateURL, &eurodns.BearerAuth{Source: src}
	return s, nil
}

func (p *eurodnsProvider) resolveDirect(cfg providerModel, s *settings) (*settings, error) {
	appID := firstNonEmpty(cfg.AppID.ValueString(), os.Getenv(envAppID))
	apiKey := firstNonEmpty(cfg.APIKey.ValueString(), os.Getenv(envAPIKey))
	if appID == "" || apiKey == "" {
		return nil, fmt.Errorf("direct mode needs app_id and api_key (or %s and %s); for gate mode, set the gate block or %s",
			envAppID, envAPIKey, envGateURL)
	}
	s.mode = modeDirect
	s.baseURL = firstNonEmpty(cfg.BaseURL.ValueString(), os.Getenv(envBaseURL), eurodns.DefaultBaseURL)
	s.auth = &eurodns.APIKeyAuth{AppID: appID, APIKey: apiKey}
	return s, nil
}

func (p *eurodnsProvider) tokenSource(ctx context.Context, a *gateAuthModel) (eurodns.TokenSource, error) {
	if a == nil {
		tok, file := os.Getenv(envGateToken), os.Getenv(envGateTokenFile)
		switch {
		case tok != "" && file != "":
			return nil, fmt.Errorf("set only one of %s and %s", envGateToken, envGateTokenFile)
		case tok != "":
			return staticTokenSource(tok), nil
		case file != "":
			return newCachingTokenSource(fileTokenFetch(file)), nil
		}
		return nil, fmt.Errorf("gate mode needs gate.auth, %s or %s", envGateToken, envGateTokenFile)
	}

	n := 0
	for _, set := range []bool{
		a.Token.ValueString() != "",
		a.TokenFile.ValueString() != "",
		!a.TokenCommand.IsNull() && len(a.TokenCommand.Elements()) > 0,
		a.AWSWebIdentity != nil,
		a.AzureIdentity != nil,
	} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, errors.New("gate.auth must set exactly one of token, token_file, token_command, aws_web_identity, azure_identity")
	}

	switch {
	case a.Token.ValueString() != "":
		return staticTokenSource(a.Token.ValueString()), nil
	case a.TokenFile.ValueString() != "":
		return newCachingTokenSource(fileTokenFetch(a.TokenFile.ValueString())), nil
	case a.AWSWebIdentity != nil:
		w := a.AWSWebIdentity
		if w.Audience.ValueString() == "" {
			return nil, errors.New("gate.auth.aws_web_identity.audience is required")
		}
		alg := firstNonEmpty(w.SigningAlgorithm.ValueString(), defaultSigningAlg)
		if alg != "RS256" && alg != "ES384" {
			return nil, fmt.Errorf("gate.auth.aws_web_identity.signing_algorithm: %q is not RS256 or ES384", alg)
		}
		c := awsWebIdentityConfig{
			Audience:         w.Audience.ValueString(),
			SigningAlgorithm: alg,
			Region:           w.Region.ValueString(),
			DurationSeconds:  int32(w.DurationSeconds.ValueInt64()),
		}
		return newCachingTokenSource(awsWebIdentityFetch(c, p.newSTS(c.Region))), nil
	case a.AzureIdentity != nil:
		z := a.AzureIdentity
		if z.Scope.ValueString() == "" {
			return nil, errors.New("gate.auth.azure_identity.scope is required")
		}
		c := azureIdentityConfig{Scope: z.Scope.ValueString(), TenantID: z.TenantID.ValueString(), ClientID: z.ClientID.ValueString()}
		return newCachingTokenSource(azureTokenFetch(c, p.newAzureCredential)), nil
	default:
		var argv []string
		if diags := a.TokenCommand.ElementsAs(ctx, &argv, false); diags.HasError() {
			return nil, errors.New("gate.auth.token_command must be a list of strings")
		}
		return newCachingTokenSource(commandTokenFetch(argv)), nil
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (p *eurodnsProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newRecordSetResource}
}

func (p *eurodnsProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newZoneDataSource, newRecordSetDataSource}
}
