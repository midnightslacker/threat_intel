
# Sort and diff IPs looking for most recent threats
tail -n +2 ~/lookups/threats.csv | sort > ~/sorted_threats
tail -n +2 ~/lookups/threats.csv.old | sort > ~/sorted_threats.old
diff --changed-group-format='%<' --unchanged-group-format='' ~/sorted_threats ~/sorted_threats.old > ~/lookups/newest_threat_IPs

#Sort and diff Domains looking for most recent domain_threats
tail -n +2 ~/lookups/threat_domains.csv | sort > ~/sorted_threat_domains
tail -n +2 ~/lookups/threat_domains.csv.old | sort > ~/sorted_threat_domains.old
diff --changed-group-format='%<' --unchanged-group-format='' ~/sorted_threat_domains ~/sorted_threat_domains.old > ~/lookups/newest_threat_domains

#Remove sorted files
rm -f ~/sorted_*
