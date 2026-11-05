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
    url = "https://dns-gate.example.com"
    auth {
      aws_web_identity {
        audience = "dns-gate"
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
