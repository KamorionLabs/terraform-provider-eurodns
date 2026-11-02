resource "eurodns_record_set" "www" {
  zone   = "example.com"
  host   = "www"
  type   = "CNAME"
  ttl    = 3600
  values = ["www.example.net."]
}

resource "eurodns_record_set" "apex" {
  zone   = "example.com"
  host   = "@"
  type   = "A"
  ttl    = 600
  values = ["192.0.2.10", "192.0.2.11"]
}

# TXT values are sent raw: no surrounding quotes.
resource "eurodns_record_set" "spf" {
  zone   = "example.com"
  host   = "@"
  type   = "TXT"
  ttl    = 3600
  values = ["v=spf1 include:_spf.example.net -all"]
}

# Names must end with a dot, otherwise EuroDNS makes them relative to the zone.
resource "eurodns_record_set" "mail" {
  zone   = "example.com"
  host   = "@"
  type   = "MX"
  values = ["10 mx1.example.net.", "20 mx2.example.net."]
}
