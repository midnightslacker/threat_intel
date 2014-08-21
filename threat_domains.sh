#!/bin/sh

# malwareBytes hpHosts
# grab lines that are not comments | remove 127.0.0.1\t | remove googletag false positive
echo '[+] Grabbing malwareBytes Hosts.txt'
curl -o ./hosts.txt http://hosts-file.net/download/hosts.txt
grep -v "#"  hosts.txt | sed -e 's/127\.0\.0\.1[\t]//g' | sed -e 's/googletag//g' > $HOME/lookups/malwareBytes_hpHosts
rm -f ./hosts.txt

# malwareBytes hpHosts updates
# grab everything but comment lines | remove 127.0.0.1\t
echo '[+] Grabbing hpHosts updates'
curl -o ./update_hosts.txt http://hosts-file.net/hphosts-partial.txt
grep -v "#" update_hosts.txt | sed -e 's/127\.0\.0\.1[\t]//g' > $HOME/dev/threat_domains/malwareBytes_updates
rm -f ./update_hosts.txt

# Malware Domains List
# grab everything but comment lines | remove 127.0.0.1 | remove whitespace | remove first 3 lines
echo '[+] Grabbing malware domain list'
curl -o malware_domains_list http://www.malwaredomainlist.com/hostslist/hosts.txt
grep -v "#" malware_domains_list | sed -e 's/127\.0\.0\.1//g' | sed -e 's/^ *//g' | tail -n +4 > $HOME/dev/threat_domains/malware_domains_list
rm -f malware_domains_list

# Malware Domains
# use tab as deliminiter and return field 3 | remove whitespace | remove lines with notice or domain 
echo '[+] Grabbing malware domains '
curl -o ./malware_domains http://mirror1.malwaredomains.com/files/domains.txt
cut -d$'\t' -f3 ./malware_domains | awk 'NF' | grep -E -v "notice|domain" > $HOME/dev/threat_domains/malware_domains
rm -f ./malware_domains

# DShield
# remove empty lines | give me everything that isn't a comment | remove the line with the word Site
echo '[+] Grabbing DShield threat feed'
curl -o ./DShield http://www.dshield.org/feeds/suspiciousdomains_High.txt
awk 'NF' DShield | grep -v "#" | grep -v "Site"  > $HOME/dev/threat_domains/DShield
rm -f ./DShield

# Feodo Domains
echo '[+] Grabbingn Feodo Tracker'
curl -o ./feodo_tracker https://feodotracker.abuse.ch/blocklist/?download=domainblocklist
awk 'NF' feodo_tracker | grep -v "#" > $HOME/dev/threat_domains/feodo_tracker
rm -f feodo_tracker

# Palevo
echo '[+] Grabbing Palevo Tracker'
curl -o palevo_tracker https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist
awk 'NF' palevo_tracker | grep -v "#" > $HOME/dev/threat_domains/palevo_tracker
rm -f palevo_tracker

# SpyEye
echo '[+] Grabbing SpyEye Tracker'
curl -o spyeye_tracker https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist
awk 'NF' spyeye_tracker | grep -v "#" > $HOME/dev/threat_domains/spyeye_tracker
rm -f spyeye_tracker

# Zeus
echo '[+] Grabbing Zeus Tracker'
curl -o zeus_tracker https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
awk 'NF' zeus_tracker | grep -v "#" > $HOME/dev/threat_domains/zeus_tracker
rm -f zeus_tracker

############################################################################################

# tor nodes
echo '[+] Grabbing tor nodes list'
curl -k -o ./tor_nodes https://www.dan.me.uk/torlist/
python $HOME/bin/filter_ips ./tor_nodes $HOME/dev/threat_sources/tor_nodes
rm -f ./tor_nodes

# ssl blacklist -- Currently offline
echo '[+] Grabbing ssl blacklist' 
curl -k -o ./ssl_blacklist  https://sslbl.abuse.ch/blacklist/sslipblacklist.rules
python $HOME/bin/filter_ips ./ssl_blacklist $HOME/dev/threat_sources/ssl_blacklist
rm -f ./ssl_blacklist
