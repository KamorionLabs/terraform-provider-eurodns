package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type azureIdentityConfig struct {
	Scope    string
	TenantID string
	ClientID string
}

// azureTokenFetch obtains an Entra ID access token for the gate's application
// (environment credentials, AKS workload identity, managed identity, Azure CLI).
func azureTokenFetch(cfg azureIdentityConfig, newCred func(azureIdentityConfig) (azcore.TokenCredential, error)) fetchFunc {
	var (
		once    sync.Once
		cred    azcore.TokenCredential
		credErr error
	)
	return func(ctx context.Context) (string, time.Time, error) {
		once.Do(func() { cred, credErr = newCred(cfg) })
		if credErr != nil {
			return "", time.Time{}, credErr
		}
		tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{cfg.Scope}, TenantID: cfg.TenantID})
		if err != nil {
			return "", time.Time{}, fmt.Errorf("azure identity token for %s: %w", cfg.Scope, err)
		}
		return tok.Token, tok.ExpiresOn, nil
	}
}

// defaultAzureCredential uses DefaultAzureCredential, or, when a client id is
// given (user-assigned managed identity), an explicit chain bound to it.
func defaultAzureCredential(cfg azureIdentityConfig) (azcore.TokenCredential, error) {
	if cfg.ClientID == "" {
		return azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{TenantID: cfg.TenantID})
	}
	var chain []azcore.TokenCredential
	if os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" {
		wi, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			ClientID: cfg.ClientID, TenantID: cfg.TenantID,
		})
		if err == nil {
			chain = append(chain, wi)
		}
	}
	mi, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: azidentity.ClientID(cfg.ClientID)})
	if err != nil {
		return nil, err
	}
	chain = append(chain, mi)
	if cli, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: cfg.TenantID}); err == nil {
		chain = append(chain, cli)
	}
	if len(chain) == 0 {
		return nil, errors.New("no Azure credential available")
	}
	return azidentity.NewChainedTokenCredential(chain, nil)
}
