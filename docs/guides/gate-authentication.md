---
page_title: "Authenticating to eurodns-gate"
subcategory: ""
description: |-
  Choose how Terraform proves its identity to an eurodns-gate.
---

# Authenticating to eurodns-gate

In gate mode Terraform never holds the EuroDNS key: it sends a bearer token that the gate verifies
(issuer, audience, claims) and maps to roles and owner teams. `gate.auth` takes exactly one method.

| Method | Token | Typical use |
|--------|-------|-------------|
| `aws_web_identity` | JWT signed by AWS STS (`sts:GetWebIdentityToken`) for the current IAM principal | CI with an AWS role, EKS Pod Identity |
| `azure_identity` | Microsoft Entra ID access token for the gate application | Azure DevOps (`AzureCLI@2`), AKS workload identity, managed identity |
| `token_file` | File re-read on expiry | Projected Kubernetes service account tokens, CI OIDC token files |
| `token_command` | stdout of a command, run again on expiry | Any other OIDC helper |
| `token` | Static value | Gate virtual keys, tests |

Tokens are cached and renewed two minutes before they expire.

## AWS

```terraform
# Gate mode: the provider talks to an eurodns-gate, which holds the EuroDNS
# key and enforces RBAC and record ownership. Terraform only proves its
# identity, here with a JWT signed by AWS STS for the current IAM role.
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com" # or EURODNS_GATE_URL

    auth {
      aws_web_identity {
        audience = "eurodns-gate"
      }
    }
  }
}

# Other authentication methods, exactly one per provider:
#   auth { token_file    = "/var/run/secrets/tokens/eurodns-gate" }
#   auth { token_command = ["my-oidc-helper", "--audience", "eurodns-gate"] }
#   auth { token         = var.gate_token }
# Without an auth block, EURODNS_GATE_TOKEN or EURODNS_GATE_TOKEN_FILE is used.
```

## Microsoft Entra ID

`azure_identity` tries, in order: environment credentials, AKS workload identity, managed identity, then
the Azure CLI login. With `client_id`, the chain is bound to that user-assigned identity.

```terraform
# Gate mode with a Microsoft Entra ID token for the gate application.
provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com"

    auth {
      azure_identity {
        scope = "api://eurodns-gate/.default"
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
