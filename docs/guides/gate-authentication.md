---
page_title: "Authenticating to dns-gate"
subcategory: ""
description: |-
  Choose how Terraform proves its identity to a dns-gate.
---

# Authenticating to dns-gate

In gate mode Terraform never holds the EuroDNS key: it sends a bearer token that the gate verifies
(issuer, audience, claims) and maps to roles and owner teams. `gate.auth` takes exactly one method, plus optionally `azure_devops`
(see below).

| Method | Token | Typical use |
|--------|-------|-------------|
| `aws_web_identity` | JWT signed by AWS STS (`sts:GetWebIdentityToken`) for the current IAM principal | CI with an AWS role, EKS Pod Identity |
| `azure_identity` | Microsoft Entra ID access token for the gate application | Azure DevOps (`AzureCLI@2`), AKS workload identity, managed identity |
| `azure_devops` | OIDC token Azure DevOps issues for a service connection | Azure DevOps jobs, without any cloud login |
| `token_file` | File re-read on expiry | Projected Kubernetes service account tokens, CI OIDC token files |
| `token_command` | stdout of a command, run again on expiry | Any other OIDC helper |
| `token` | Static value | Gate virtual keys, tests |

Tokens are cached and renewed two minutes before they expire.

## AWS

```terraform
# Gate mode: the provider talks to a dns-gate, which holds the EuroDNS
# key and enforces RBAC and record ownership. Terraform only proves its
# identity, here with a JWT signed by AWS STS for the current IAM role.
provider "eurodns" {
  gate {
    url = "https://dns-gate.example.com" # or DNS_GATE_URL

    auth {
      aws_web_identity {
        audience = "dns-gate"
      }
    }
  }
}

# Other authentication methods, exactly one per provider:
#   auth { token_file    = "/var/run/secrets/tokens/dns-gate" }
#   auth { token_command = ["my-oidc-helper", "--audience", "dns-gate"] }
#   auth { token         = var.gate_token }
# Without an auth block, DNS_GATE_TOKEN or DNS_GATE_TOKEN_FILE is used.
```

## Microsoft Entra ID

`azure_identity` tries, in order: environment credentials, AKS workload identity, managed identity, then
the Azure CLI login. With `client_id`, the chain is bound to that user-assigned identity.

```terraform
# Gate mode with a Microsoft Entra ID token for the gate application.
provider "eurodns" {
  gate {
    url = "https://dns-gate.example.com"

    auth {
      azure_identity {
        scope = "api://dns-gate/.default"
        # tenant_id = "00000000-0000-0000-0000-000000000000"
        # client_id = "11111111-1111-1111-1111-111111111111" # user-assigned managed identity
      }
    }
  }
}
```

Azure DevOps, with the service connection logged in by `AzureCLI@2`:

```yaml
# Azure DevOps: AzureCLI@2 logs the Azure CLI in with the service connection
# (workload identity federation), and azure_identity picks the CLI login up.
trigger: none

pool:
  vmImage: ubuntu-latest

steps:
  - task: AzureCLI@2
    displayName: terraform apply
    inputs:
      azureSubscription: dns-automation # service connection allowed by the gate policy
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        terraform init -input=false
        terraform apply -input=false -auto-approve
      workingDirectory: dns
```

AKS workload identity:

```yaml
# AKS: a pod running Terraform with Entra workload identity. The webhook
# injects AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_FEDERATED_TOKEN_FILE,
# which azure_identity uses without extra configuration.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dns-terraform
  namespace: dns
  annotations:
    azure.workload.identity/client-id: 11111111-1111-1111-1111-111111111111
---
apiVersion: batch/v1
kind: Job
metadata:
  name: dns-terraform-apply
  namespace: dns
spec:
  template:
    metadata:
      labels:
        azure.workload.identity/use: "true"
    spec:
      serviceAccountName: dns-terraform
      restartPolicy: Never
      containers:
        - name: terraform
          image: hashicorp/terraform:1.10
          workingDir: /work
          command: ["sh", "-c", "terraform init -input=false && terraform apply -input=false -auto-approve"]
```

## Azure DevOps OIDC

`azure_devops` requests the token Azure DevOps issues for a service connection (issuer
`https://vstoken.dev.azure.com/<organization id>`, audience `api://AzureADTokenExchange`, subject
`sc://<organization>/<project>/<service connection>`). No cloud login is involved, so it suits pipelines that
only manage DNS, on any cloud.

The service connection id is `service_connection_id`, or else the `DNS_GATE_ADO_SERVICE_CONNECTION_ID`
environment variable: a variable group named after the pipeline can carry it, so the configuration and the
pipeline YAML only use names. It applies inside an Azure DevOps job only. Elsewhere, for example on a workstation, the other method of the
block is used, typically `azure_identity` with the Azure CLI login of the person running Terraform:

```terraform
# Gate mode with the Azure DevOps OIDC token of a service connection. In the
# pipeline, azure_devops is used; on a workstation (no SYSTEM_OIDCREQUESTURI),
# azure_identity takes over with the Azure CLI login of the person running
# Terraform, so the same configuration works in both places.
provider "eurodns" {
  gate {
    url = "https://dns-gate.example.com"

    auth {
      # service_connection_id defaults to DNS_GATE_ADO_SERVICE_CONNECTION_ID,
      # for example from a variable group of the pipeline.
      azure_devops {}
      azure_identity {
        scope = "api://dns-gate/.default"
      }
    }
  }
}
```

```yaml
# Azure DevOps: the job requests an OIDC token for the service connection of the
# provider. The connection must be authorized for this pipeline, and
# System.AccessToken must be mapped into the step environment. The connection id
# can come from a variable group (DNS_GATE_ADO_SERVICE_CONNECTION_ID), so the
# Terraform configuration names no id.
trigger: none

pool:
  vmImage: ubuntu-latest

variables:
  - group: dns-gate-dns # DNS_GATE_ADO_SERVICE_CONNECTION_ID

steps:
  - script: |
      terraform init -input=false
      terraform apply -input=false -auto-approve
    displayName: terraform apply
    workingDirectory: dns
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

The audience is the same for every service connection of the organization and is also accepted by Entra ID
and by cloud identity federations. Bind the gate issuer to the subjects of dedicated service connections
(`bound_claims.sub`) that no cloud role or federated credential trusts, so a token sent to the gate cannot be
used anywhere else.
