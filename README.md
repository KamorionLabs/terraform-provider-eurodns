# terraform-provider-eurodns

Terraform and OpenTofu provider for [EuroDNS](https://www.eurodns.com) DNS zones.

One provider, two connection modes:

- **direct**: talks to the EuroDNS API with an application id and API key;
- **gate**: talks to an [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate)
  with a short-lived OIDC token; the gate holds the EuroDNS key and enforces RBAC,
  ownership and safe writes.

Resources and data sources are identical in both modes: switching is a change of the
provider block, with no state migration. The exceptions are `eurodns_gate_role` and
`eurodns_gate_binding`, which manage the gate policy itself and only exist in gate mode.

> Status: **beta**. In production since November 2026 in gate mode: OpenTofu
> pipelines writing certificate validation and site records through an
> [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate). Direct mode shares the
> same client and record handling but has seen less use. Versions are still 0.x.

Published on the [OpenTofu registry](https://search.opentofu.org/provider/kamorionlabs/eurodns/latest)
as `kamorionlabs/eurodns`. It is not on the HashiCorp registry yet.

## Direct mode

```hcl
terraform {
  required_providers {
    eurodns = {
      source = "KamorionLabs/eurodns"
    }
  }
}

provider "eurodns" {
  app_id  = var.eurodns_app_id   # or EURODNS_APP_ID
  api_key = var.eurodns_api_key  # or EURODNS_API_KEY
}
```

## Gate mode

```hcl
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com"   # or EURODNS_GATE_URL

    auth {
      # One token source:
      aws_web_identity {
        audience = "eurodns-gate"              # sts:GetWebIdentityToken
      }
      # azure_identity {
      #   scope = "api://<gate-app>/.default"  # Managed Identity, AKS Workload Identity,
      # }                                      # ADO workload identity federation, az CLI
      # azure_devops {}                        # Azure DevOps OIDC token of a dedicated
      #                                        # service connection, inside a job
      # token_file    = "/var/run/secrets/tokens/eurodns-gate"
      # token_command = ["my-token-helper", "--audience", "eurodns-gate"]
      # token         = var.gate_token
    }
  }
}
```

Token sources: `aws_web_identity` (AWS workloads and pipelines assuming an IAM
role), `azure_identity` (Entra ID access token for the gate's app registration,
through the Azure default credential chain: Managed Identity, AKS Workload Identity,
Azure DevOps service connection in workload identity federation mode, Azure CLI),
`azure_devops` (the OIDC token Azure DevOps issues for a service connection, with no
cloud login; outside a job it falls back to the other method of the block, so the same
configuration runs on a workstation), `token_file`, `token_command`, `token`. The
Azure DevOps token has an audience shared by every service connection of the
organization: use it only with service connections dedicated to the gate, as the
gate's [configuration guide](https://github.com/KamorionLabs/eurodns-gate/blob/main/docs/CONFIG.md#azure-devops-oidc)
explains.

`app_id`/`api_key` and `gate` are mutually exclusive. At configuration time the
provider queries `/.well-known/eurodns-gate` to check it is talking to a gate and
which features it supports.

## Managing records

```hcl
resource "eurodns_record_set" "www" {
  zone   = "example.com"
  host   = "www"
  type   = "CNAME"
  ttl    = 3600
  values = ["www.example.net."]
}
```

- An `eurodns_record_set` is all records sharing a host and a type (RRset).
- TTLs are validated against the values EuroDNS accepts.
- Creation fails if the RRset already exists: import it (see below).
- The provider reads each zone once per run, serializes writes per zone and retries
  within the EuroDNS rate limit.
- Changing `host` or `type` moves the RRset within the zone in a single save; changing
  `zone` replaces it.
- In gate mode, a write refused because another process holds the zone lock
  (`zone_locked`) is retried from a fresh read, honoring `Retry-After`, for up to
  about 5 minutes.

Safety differences between modes:

| | Direct | Gate |
|---|---|---|
| Records not managed by Terraform | rewritten unchanged | rewritten unchanged, enforced server-side |
| Concurrent runs on the same zone | not protected across processes | per-zone lock and `If-Match` |
| Ownership (who may change an RRset) | Terraform state only | enforced by the gate per team |
| EuroDNS key | in the pipeline | never leaves the gate |

## Importing records that already exist

Import ids have the form `<zone>/<host>/<type>`:

```sh
terraform import eurodns_record_set.www example.com/www/CNAME
```

or, with Terraform / OpenTofu 1.5+:

```hcl
import {
  to = eurodns_record_set.www
  id = "example.com/www/CNAME"
}
```

- **Direct mode**: import reads the RRset into the state.
- **Gate mode**: import is an **adoption**. The provider asks the gate to adopt the
  RRset for the caller's team, which requires the `dns.record.adopt` permission. An
  RRset owned by another team, protected or server-managed cannot be imported.

To take over a whole zone, the recommended path keeps adoption with admins: adopt in
the gate (UI or API, with preview), then export ready-made HCL with `import` blocks
from `GET /api/v1/zones/<zone>/terraform?team=<team>`. Already-adopted RRsets import
without the adopt permission. The first plan must show only imports and no change.
See the gate's [onboarding guide](https://github.com/KamorionLabs/eurodns-gate/blob/main/docs/ONBOARDING.md).

## Gate roles and bindings

A stack that creates CI pipelines can create, in the same apply, each pipeline's gate
role and binding, the way it creates each pipeline's cloud role and scoped policy:

```hcl
resource "eurodns_gate_role" "web" {
  name  = "eurodns-gate-web"
  rules = [{ zones = ["example.com"], actions = ["dns.read", "dns.record.write"], hosts = ["web.apps"], types = ["CNAME"] }]
}

resource "eurodns_gate_binding" "web" {
  name     = "eurodns-gate-web"
  role     = eurodns_gate_role.web.name
  team     = "eurodns-gate-web"
  subjects = [{ issuer = "azure-devops", claims = { sub = ["sc://org/project/eurodns-gate-web"] } }]
}
```

The stack's identity must be a subject of a `policy.delegations` entry of the gate,
which bounds what it may create; changes are activated without approval. See the
[delegation guide](docs/guides/gate-delegation.md).

## Related repositories

- [eurodns-go](https://github.com/KamorionLabs/eurodns-go): the Go client used by this provider.
- [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate): the gateway, its [design](https://github.com/KamorionLabs/eurodns-gate/blob/main/docs/DESIGN.md) and [ACME guide](https://github.com/KamorionLabs/eurodns-gate/blob/main/docs/ACME.md).

## License

MIT — see [LICENSE](LICENSE).
