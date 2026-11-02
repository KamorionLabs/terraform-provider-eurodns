# terraform-provider-eurodns

Terraform and OpenTofu provider for [EuroDNS](https://www.eurodns.com) DNS zones.

One provider, two connection modes:

- **direct**: talks to the EuroDNS API with an application id and API key;
- **gate**: talks to an [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate)
  with a short-lived OIDC token; the gate holds the EuroDNS key and enforces RBAC,
  ownership and safe writes.

Resources and data sources are identical in both modes: switching is a change of the
provider block, with no state migration.

> Status: **pre-alpha**. Not yet tested against the live EuroDNS API.

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
`token_file`, `token_command`, `token`. In Azure DevOps, use the Entra token
obtained through the service connection, not the raw pipeline OIDC token.

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

## Related repositories

- [eurodns-go](https://github.com/KamorionLabs/eurodns-go): the Go client used by this provider.
- [eurodns-gate](https://github.com/KamorionLabs/eurodns-gate): the gateway, its [design](https://github.com/KamorionLabs/eurodns-gate/blob/main/docs/DESIGN.md) and [ACME guide](https://github.com/KamorionLabs/eurodns-gate/blob/main/docs/ACME.md).

## License

MIT — see [LICENSE](LICENSE).
