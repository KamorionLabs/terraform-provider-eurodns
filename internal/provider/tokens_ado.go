package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	envADOOIDCRequestURI = "SYSTEM_OIDCREQUESTURI"
	envADOAccessToken    = "SYSTEM_ACCESSTOKEN"
	// envADOServiceConnectionID is the service connection id when the configuration sets none.
	envADOServiceConnectionID = "EURODNS_GATE_ADO_SERVICE_CONNECTION_ID"
	adoOIDCAPIVersion         = "7.1"
)

type azureDevOpsConfig struct {
	ServiceConnectionID string
	RequestURI          string
	AccessToken         string
}

// inAzureDevOpsJob reports whether the process runs in an Azure DevOps job
// able to request OIDC tokens.
func inAzureDevOpsJob() bool { return os.Getenv(envADOOIDCRequestURI) != "" }

// azureDevOpsFetch obtains the OIDC token Azure DevOps issues for a service
// connection (issuer https://vstoken.dev.azure.com/<organization id>,
// subject sc://<organization>/<project>/<service connection>).
func azureDevOpsFetch(cfg azureDevOpsConfig, client *http.Client) fetchFunc {
	return func(ctx context.Context) (string, time.Time, error) {
		u, err := url.Parse(cfg.RequestURI)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("%s: %w", envADOOIDCRequestURI, err)
		}
		q := u.Query()
		q.Set("api-version", adoOIDCAPIVersion)
		q.Set("serviceConnectionId", cfg.ServiceConnectionID)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(nil))
		if err != nil {
			return "", time.Time{}, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-TFS-FedAuthRedirect", "Suppress")
		resp, err := client.Do(req)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("azure devops oidc token: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return "", time.Time{}, fmt.Errorf("azure devops oidc token for service connection %s: HTTP %d: %s",
				cfg.ServiceConnectionID, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var out struct {
			OIDCToken string `json:"oidcToken"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", time.Time{}, fmt.Errorf("azure devops oidc token: %w", err)
		}
		if out.OIDCToken == "" {
			return "", time.Time{}, errors.New("azure devops returned no oidcToken")
		}
		return out.OIDCToken, time.Time{}, nil
	}
}
