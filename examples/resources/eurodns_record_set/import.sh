# <zone>/<host>/<type>. In gate mode, the import first asks the gate to adopt
# the existing RRset (requires the dns.record.adopt permission).
terraform import eurodns_record_set.www example.com/www/CNAME
