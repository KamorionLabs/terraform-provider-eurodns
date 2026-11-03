package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// fakePolicy is the delegation API of the fake gate: delegated roles and
// bindings by name, ETags, If-Match / If-None-Match, 409 policy_busy.
type fakePolicy struct {
	objects map[string]*gateObject // "<kind>/<name>"
	version int

	busy          int    // writes to refuse with 409 policy_busy
	busyRefusals  int    // writes refused so far
	forbiddenZone string // a rule on this zone is refused with 400 invalid_policy
	ifNoneMatch   int    // PUTs that carried If-None-Match: *
	ifMatch       int    // PUTs that carried a matching If-Match
	managedBy     []string
}

func newFakePolicy() *fakePolicy { return &fakePolicy{objects: map[string]*gateObject{}} }

// serve runs under the fake gate lock.
func (p *fakePolicy) serve(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, delegatedPath+"/")
	kindPlural, name, ok := strings.Cut(rest, "/")
	if !ok || (kindPlural != "roles" && kindPlural != "bindings") {
		gateError(w, http.StatusNotFound, "not_found", rest)
		return
	}
	kind := strings.TrimSuffix(kindPlural, "s")
	key := kind + "/" + name
	cur := p.objects[key]
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			gateError(w, http.StatusNotFound, "not_found", key)
			return
		}
		w.Header().Set("ETag", cur.ETag)
		_ = json.NewEncoder(w).Encode(cur)
		return
	case http.MethodDelete:
		if p.refuseBusy(w) {
			return
		}
		if cur == nil {
			gateError(w, http.StatusNotFound, "not_found", key)
			return
		}
		delete(p.objects, key)
		_ = json.NewEncoder(w).Encode(gateResult{Changed: true, RevisionID: "rev"})
		return
	case http.MethodPut:
	default:
		gateError(w, http.StatusMethodNotAllowed, "method_not_allowed", r.Method)
		return
	}
	if p.refuseBusy(w) {
		return
	}
	if r.Header.Get("If-None-Match") == "*" {
		p.ifNoneMatch++
		if cur != nil {
			gateError(w, http.StatusPreconditionFailed, "precondition", "exists")
			return
		}
	}
	if m := r.Header.Get("If-Match"); m != "" {
		if cur == nil || m != cur.ETag {
			gateError(w, http.StatusPreconditionFailed, "precondition", "changed")
			return
		}
		p.ifMatch++
	}
	var body struct {
		gateRole
		gateBinding
		Delegation string `json:"delegation"`
		ManagedBy  string `json:"managed_by"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		gateError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if body.Delegation != "" && body.Delegation != "ci" {
		gateError(w, http.StatusForbidden, "forbidden", "this identity cannot act for delegation "+body.Delegation)
		return
	}
	p.managedBy = append(p.managedBy, body.ManagedBy)
	obj := &gateObject{Kind: kind, Name: name, Owner: gateOwner{Delegation: "ci", ManagedBy: body.ManagedBy, CreatedBy: "ci", UpdatedBy: "ci"}}
	if kind == "role" {
		role := body.gateRole
		for i, rule := range role.Rules {
			for _, z := range rule.Zones {
				if z == p.forbiddenZone {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]any{"reason": "invalid_policy", "message": "the change is outside the delegation",
						"errors": []gateValidationError{{Path: fmt.Sprintf("delegated.roles.%s.rules[%d].zones[0]", name, i), Message: fmt.Sprintf("zone %q is outside the allow.zones of delegation \"ci\"", z)}}})
					return
				}
			}
		}
		obj.Role = &role
	} else {
		b := body.gateBinding
		obj.Binding = &b
	}
	p.version++
	obj.ETag = fmt.Sprintf(`"e%d"`, p.version)
	p.objects[key] = obj
	w.Header().Set("ETag", obj.ETag)
	_ = json.NewEncoder(w).Encode(gateResult{Object: obj, Changed: true, RevisionID: "rev"})
}

func (p *fakePolicy) refuseBusy(w http.ResponseWriter) bool {
	if p.busy == 0 {
		return false
	}
	p.busy--
	p.busyRefusals++
	gateError(w, http.StatusConflict, "policy_busy", "concurrent activation")
	return true
}
