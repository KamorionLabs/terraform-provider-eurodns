package provider

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	eurodns "github.com/KamorionLabs/eurodns-go"
)

// gateReasonHelp explains eurodns-gate refusal reasons to the user.
var gateReasonHelp = map[string]string{
	"forbidden":        "The gate policy does not allow this identity to perform this change (role scope or protected record).",
	"foreign_rrset":    "This RRset exists in the zone but was not created or adopted through the gate. Ask a gate administrator to adopt it, then import it with `terraform import`.",
	"not_owner":        "This RRset is owned by another team in the gate. Only its owner team can modify or delete it.",
	"tainted":          "This RRset was modified outside the gate (for example in the EuroDNS console). Writes are blocked until a gate administrator reviews and re-adopts it.",
	"precondition":     "The zone changed during the write and the retries were exhausted. Run the operation again.",
	"too_many_changes": "The change exceeds the maximum number of RRset changes per request allowed for this identity.",
	"invalid_zone":     "EuroDNS rejected the resulting zone. See the validation report below.",
	"zone_locked":      "Another write on this zone holds the gate lock. Retry later.",
}

// addAPIError turns an API error into a readable diagnostic.
func addAPIError(diags *diag.Diagnostics, summary string, err error) {
	var apiErr *eurodns.APIError
	if !errors.As(err, &apiErr) {
		diags.AddError(summary, err.Error())
		return
	}
	var b strings.Builder
	if help, ok := gateReasonHelp[apiErr.Reason]; ok {
		fmt.Fprintf(&b, "%s\n\n", help)
	}
	switch {
	case apiErr.Reason != "":
		fmt.Fprintf(&b, "Gate reason: %s (HTTP %d)\n", apiErr.Reason, apiErr.StatusCode)
	case apiErr.Code != "":
		fmt.Fprintf(&b, "EuroDNS error: %s (HTTP %d)\n", apiErr.Code, apiErr.StatusCode)
	default:
		fmt.Fprintf(&b, "HTTP %d on %s %s\n", apiErr.StatusCode, apiErr.Method, apiErr.Path)
	}
	if apiErr.StatusCode == 429 {
		b.WriteString("EuroDNS rate limit reached (10 requests per 10 seconds per IP, with progressive bans). Lower Terraform parallelism or raise request_interval.\n")
	}
	if apiErr.Message != "" {
		fmt.Fprintf(&b, "Message: %s\n", apiErr.Message)
	}
	if problems := apiErr.Report.Problems(); len(problems) > 0 {
		b.WriteString("Validation report:\n")
		for _, p := range problems {
			fmt.Fprintf(&b, "  - %s\n", p.String())
		}
	}
	if apiErr.Message == "" && apiErr.Report == nil && len(apiErr.Body) > 0 {
		fmt.Fprintf(&b, "Response: %s", truncate(string(apiErr.Body), 2000))
	}
	diags.AddError(summary, b.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
