data "eurodns_zone" "example" {
  zone = "example.com"
}

output "record_count" {
  value = length(data.eurodns_zone.example.records)
}
