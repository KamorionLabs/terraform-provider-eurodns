package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// featurePolicyDelegation is advertised by gates that serve the delegation
// API (/api/v1/policy/delegated), used by eurodns_gate_role and
// eurodns_gate_binding.
const featurePolicyDelegation = "policy-delegation"

// delegatedPath is the delegation API of eurodns-gate.
const delegatedPath = "/api/v1/policy/delegated"

// managedBy labels the objects this provider writes in the gate.
const managedBy = "terraform"

// Gate wire types of the delegation API (see eurodns-gate internal/uiapi).

type gateRecordScope struct {
	Hosts []string `json:"hosts,omitempty"`
	Types []string `json:"types,omitempty"`
}

type gateRule struct {
	Zones   []string         `json:"zones"`
	Actions []string         `json:"actions"`
	Records *gateRecordScope `json:"records,omitempty"`
}

type gateRole struct {
	Description          string     `json:"description,omitempty"`
	Rules                []gateRule `json:"rules"`
	RebaseOnSave         bool       `json:"rebase_on_save,omitempty"`
	EphemeralTTL         string     `json:"ephemeral_ttl,omitempty"`
	MaxChangesPerRequest int        `json:"max_changes_per_request,omitempty"`
}

type gateTeamFrom struct {
	Claim  string `json:"claim"`
	Regex  string `json:"regex"`
	Prefix string `json:"prefix,omitempty"`
}

type gateSubject struct {
	Issuer string              `json:"issuer"`
	Claims map[string][]string `json:"claims,omitempty"`
}

type gateBinding struct {
	Role     string        `json:"role"`
	Team     string        `json:"team"`
	TeamFrom *gateTeamFrom `json:"team_from,omitempty"`
	Groups   []string      `json:"groups,omitempty"`
	Subjects []gateSubject `json:"subjects,omitempty"`
}

type gateOwner struct {
	Delegation string `json:"delegation"`
	ManagedBy  string `json:"managed_by,omitempty"`
	CreatedBy  string `json:"created_by"`
	UpdatedBy  string `json:"updated_by"`
}

type gateObject struct {
	Kind    string       `json:"kind"`
	Name    string       `json:"name"`
	Role    *gateRole    `json:"role,omitempty"`
	Binding *gateBinding `json:"binding,omitempty"`
	Owner   gateOwner    `json:"owner"`
	ETag    string       `json:"etag"`
}

type gateImpact struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type gateResult struct {
	Object     *gateObject  `json:"object,omitempty"`
	Changed    bool         `json:"changed"`
	RevisionID string       `json:"revision_id"`
	Impact     []gateImpact `json:"impact"`
}

// gateValidationError is one entry of a 400 invalid_policy answer.
type gateValidationError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// gatePolicyError is a refusal of the delegation API.
type gatePolicyError struct {
	Status  int
	Method  string
	Path    string
	Reason  string
	Message string
	Errors  []gateValidationError
	Body    string
}

func (e *gatePolicyError) Error() string {
	msg := fmt.Sprintf("eurodns-gate: %s %s: status %d", e.Method, e.Path, e.Status)
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

func gateStatus(err error) (int, string) {
	var pe *gatePolicyError
	if errors.As(err, &pe) {
		return pe.Status, pe.Reason
	}
	return 0, ""
}

// delegatedReasonHelp explains refusals of the delegation API.
var delegatedReasonHelp = map[string]string{
	"invalid_policy":      "The gate refused the object: it is outside the limits of the delegation (policy.delegations in the gate configuration) or of the managed policy. The errors below name the offending fields.",
	"forbidden":           "This identity is not a subject of any policy delegation of the gate, or not of the delegation requested.",
	"not_owner":           "The object belongs to another delegation of the gate.",
	"name_taken":          "The name is used by a role of the base policy or by a managed role edited by humans (it may have been taken over by a policy administrator). Choose another name, or remove the resource from this configuration.",
	"delegation_required": "This identity matches several delegations: set the delegation attribute.",
	"policy_busy":         "The gate policy kept changing concurrently and the retries were exhausted. Run the operation again.",
	"policy_not_editable": "The managed policy of the gate is disabled (policy.editable is false).",
	"reauth_required":     "A human identity must have signed in recently to change the gate policy.",
}

func addGatePolicyError(diags *diag.Diagnostics, summary string, err error) {
	var pe *gatePolicyError
	if !errors.As(err, &pe) {
		diags.AddError(summary, err.Error())
		return
	}
	var b strings.Builder
	if help, ok := delegatedReasonHelp[pe.Reason]; ok {
		fmt.Fprintf(&b, "%s\n\n", help)
	}
	fmt.Fprintf(&b, "Gate reason: %s (HTTP %d on %s %s)\n", firstNonEmpty(pe.Reason, "unknown"), pe.Status, pe.Method, pe.Path)
	if pe.Message != "" {
		fmt.Fprintf(&b, "Message: %s\n", pe.Message)
	}
	for _, e := range pe.Errors {
		fmt.Fprintf(&b, "  - %s: %s\n", firstNonEmpty(e.Path, "(document)"), e.Message)
	}
	if pe.Reason == "" && pe.Body != "" {
		fmt.Fprintf(&b, "Response: %s", truncate(pe.Body, 2000))
	}
	diags.AddError(summary, b.String())
}

// delegatedRetry bounds the retries of a delegated write the gate answers
// 409 policy_busy (concurrent activations on several replicas) or 503.
type delegatedRetry struct {
	attempts int
	base     time.Duration
	max      time.Duration
	sleep    func(ctx context.Context, d time.Duration) error
}

var defaultDelegatedRetry = delegatedRetry{attempts: 8, base: 500 * time.Millisecond, max: 10 * time.Second, sleep: sleepCtx}

func (a *apiClient) requireDelegation(diags *diag.Diagnostics, resourceType string) bool {
	if a.mode != modeGate {
		diags.AddError(resourceType+" requires gate mode",
			"This resource manages objects of an eurodns-gate policy: configure the provider with a gate block (or EURODNS_GATE_URL), not app_id/api_key.")
		return false
	}
	if !a.hasFeature(featurePolicyDelegation) {
		diags.AddError("The eurodns-gate does not serve the delegation API",
			fmt.Sprintf("%s needs an eurodns-gate that advertises the %q feature (GET /.well-known/eurodns-gate). Upgrade the gate.", resourceType, featurePolicyDelegation))
		return false
	}
	return true
}

func (a *apiClient) gateHTTP() *http.Client {
	return &http.Client{Transport: a.client.Transport(), Timeout: gateHTTPTimeout}
}

// gateDo sends one request to the gate policy API and decodes the answer.
func (a *apiClient) gateDo(ctx context.Context, method, path string, hdr http.Header, in, out any) (http.Header, error) {
	u, err := url.Parse(strings.TrimRight(a.baseURL, "/") + path)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := a.gateHTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		pe := &gatePolicyError{Status: resp.StatusCode, Method: method, Path: u.Path, Body: string(b)}
		var eb struct {
			Reason  string                `json:"reason"`
			Message string                `json:"message"`
			Errors  []gateValidationError `json:"errors"`
		}
		if json.Unmarshal(b, &eb) == nil {
			pe.Reason, pe.Message, pe.Errors = eb.Reason, eb.Message, eb.Errors
		}
		return resp.Header, pe
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.Header, fmt.Errorf("eurodns-gate: decode %s %s: %w", method, u.Path, err)
		}
	}
	return resp.Header, nil
}

func delegatedObjectPath(kind, name string) string {
	return delegatedPath + "/" + kind + "s/" + url.PathEscape(name)
}

// getDelegated reads a delegated object; nil when it does not exist (or is
// no longer delegated, for example after a takeover by an administrator).
func (a *apiClient) getDelegated(ctx context.Context, kind, name string) (*gateObject, error) {
	var obj gateObject
	_, err := a.gateDo(ctx, http.MethodGet, delegatedObjectPath(kind, name), nil, nil, &obj)
	if status, _ := gateStatus(err); status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// writeDelegated sends a PUT (body != nil) or a DELETE, retrying while the
// gate answers 409 policy_busy or 503.
func (a *apiClient) writeDelegated(ctx context.Context, method, kind, name string, hdr http.Header, body any) (*gateResult, error) {
	r := a.delegatedRetry
	path := delegatedObjectPath(kind, name)
	for attempt := 1; ; attempt++ {
		var res gateResult
		_, err := a.gateDo(ctx, method, path, hdr, body, &res)
		status, reason := gateStatus(err)
		retry := (status == http.StatusConflict && reason == "policy_busy") || status == http.StatusServiceUnavailable
		if err == nil || !retry || attempt >= r.attempts {
			if err != nil {
				return nil, err
			}
			for _, it := range res.Impact {
				if it.Kind == "warning" {
					tflog.Warn(ctx, "gate policy impact", map[string]any{"kind": kind, "name": name, "message": it.Message})
				}
			}
			return &res, nil
		}
		d := min(r.base<<(attempt-1), r.max)
		d = time.Duration(float64(d) * (0.5 + rand.Float64()))
		tflog.Warn(ctx, "gate policy busy, retrying", map[string]any{"kind": kind, "name": name, "attempt": attempt, "wait": d.String(), "reason": reason})
		if err := r.sleep(ctx, d); err != nil {
			return nil, errors.Join(err, fmt.Errorf("stopped retrying %s %s", method, path))
		}
	}
}

func ifNoneMatchAny() http.Header { return http.Header{"If-None-Match": []string{"*"}} }

func ifMatch(etag string) http.Header {
	if etag == "" {
		return nil
	}
	return http.Header{"If-Match": []string{etag}}
}

// preconditionDiag explains a 412 of a delegated write.
func preconditionDiag(diags *diag.Diagnostics, kind, name string, create bool, err error) bool {
	status, _ := gateStatus(err)
	if status != http.StatusPreconditionFailed {
		return false
	}
	if create {
		diags.AddError(fmt.Sprintf("Gate %s %q already exists", kind, name),
			fmt.Sprintf("A delegated %s with this name already exists in the gate. Import it (terraform import eurodns_gate_%s.<name> %s) or choose another name.", kind, kind, name))
		return true
	}
	diags.AddError(fmt.Sprintf("Gate %s %q changed outside Terraform", kind, name),
		"The object changed in the gate since Terraform last read it (another stack or an administrator). Run terraform plan again to see the difference, then apply.")
	return true
}
