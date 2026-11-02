data "eurodns_record_set" "mx" {
  zone = "example.com"
  host = "@"
  type = "MX"
}
