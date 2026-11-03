---
page_title: "Validating ACM certificates"
subcategory: ""
description: |-
  Create the DNS validation records of an AWS ACM certificate in a EuroDNS zone.
---

# Validating ACM certificates

ACM validates public certificates through CNAME records in the public zone. With this provider the
certificate, its validation records and the validation wait live in the same configuration.

```terraform
# Public ACM certificate for a name hosted at EuroDNS, validated by DNS in
# the same configuration.
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    eurodns = {
      source = "kamorionlabs/eurodns"
    }
  }
}

provider "aws" {
  region = "us-east-1" # CloudFront certificates live in us-east-1
}

provider "eurodns" {
  gate {
    url = "https://eurodns-gate.example.com"
    auth {
      aws_web_identity {
        audience = "eurodns-gate"
      }
    }
  }
}

locals {
  zone = "example.com"
}

resource "aws_acm_certificate" "site" {
  domain_name               = "www.example.com"
  subject_alternative_names = ["static.example.com"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# One validation CNAME per distinct name (ACM may return the same record for
# several SANs).
resource "eurodns_record_set" "validation" {
  for_each = {
    for o in aws_acm_certificate.site.domain_validation_options : o.resource_record_name => o...
  }

  zone = local.zone
  host = trimsuffix(trimsuffix(each.key, "."), ".${local.zone}")
  type = "CNAME"
  ttl  = 600
  # ACM returns the target with its trailing dot, as EuroDNS requires.
  values = [each.value[0].resource_record_value]
}

resource "aws_acm_certificate_validation" "site" {
  certificate_arn         = aws_acm_certificate.site.arn
  validation_record_fqdns = [for o in aws_acm_certificate.site.domain_validation_options : o.resource_record_name]

  depends_on = [eurodns_record_set.validation]
}
```

Notes:

- `host` is relative to the zone: strip the zone suffix from `resource_record_name`.
- ACM returns the same validation record for a name and its wildcard: group by record name.
- `host` is unknown at plan time while a certificate is being created or replaced. The record set then
  plans an update, not a replacement, and the provider writes nothing if the host resolves to its current
  value. A new host moves the RRset within the zone in a single save.
- For ACME clients (Let's Encrypt), prefer delegating `_acme-challenge.<name>` with a CNAME to a zone
  dedicated to challenges: the EuroDNS zone is changed once, renewals never touch it.
