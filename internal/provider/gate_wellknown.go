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
	"strings"
	"time"

	"github.com/KamorionLabs/eurodns-go"
)

// gateInfoPath is the extension endpoint served by dns-gate only. It answers
// the gate version and features; the adoption extension lives below it.
const gateInfoPath = "/.well-known/dns-gate"

const gateHTTPTimeout = 60 * time.Second

// errNotGate reports that the endpoint does not serve gateInfoPath.
var errNotGate = errors.New("endpoint is not a dns-gate")

func gateAdoptPath(zone string) string {
	return gateInfoPath + "/zones/" + url.PathEscape(zone) + "/adopt"
}

// wellKnownDo sends one request to the well-known extension of the gate,
// through the transport of the EuroDNS client (credentials, rate limit,
// Retry-After hint). Refusals are returned as *eurodns.APIError, like the
// answers of the zone API, so the zone lock retries apply.
func wellKnownDo(ctx context.Context, c *eurodns.Client, baseURL, method, path string, in, out any) error {
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := &http.Client{Transport: c.Transport(), Timeout: gateHTTPTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return wellKnownError(method, u.Path, resp.StatusCode, b)
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("dns-gate: decode %s %s: %w", method, u.Path, err)
		}
	}
	return nil
}

func wellKnownError(method, path string, status int, body []byte) *eurodns.APIError {
	e := &eurodns.APIError{StatusCode: status, Method: method, Path: path, Body: body}
	var parsed struct {
		Reason  string              `json:"reason"`
		Message string              `json:"message"`
		Errors  []eurodns.ErrorItem `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		e.Reason, e.Message, e.Errors = parsed.Reason, parsed.Message, parsed.Errors
		if len(parsed.Errors) > 0 {
			e.Code = parsed.Errors[0].Code
			if e.Message == "" {
				e.Message = parsed.Errors[0].Title
			}
		}
	}
	return e
}

// fetchGateInfo queries GET /.well-known/dns-gate. It returns errNotGate when
// the endpoint does not answer it as a gate (plain EuroDNS, another service,
// or a gate too old to serve this path).
func fetchGateInfo(ctx context.Context, c *eurodns.Client, baseURL string) (*eurodns.GateInfo, error) {
	var gi eurodns.GateInfo
	err := wellKnownDo(ctx, c, baseURL, http.MethodGet, gateInfoPath, nil, &gi)
	if err != nil {
		var ae *eurodns.APIError
		if errors.As(err, &ae) {
			switch ae.StatusCode {
			case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnauthorized, http.StatusForbidden:
				return nil, errNotGate
			}
		}
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, errNotGate
		}
		return nil, err
	}
	if gi.Version == "" {
		return nil, errNotGate
	}
	return &gi, nil
}

// gateAdopt asks the gate to adopt existing foreign RRsets of a zone.
func (a *apiClient) gateAdopt(ctx context.Context, zone string, req eurodns.AdoptRequest) error {
	if req.RRsets == nil {
		req.RRsets = []eurodns.AdoptRRset{}
	}
	return wellKnownDo(ctx, a.client, a.baseURL, http.MethodPost, gateAdoptPath(zone), req, nil)
}
