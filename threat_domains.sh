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

# Malware Domains
# use tab as deliminiter and return field 3 | remove whitespace | remove lines with notice or domain | remove 'legit' advertisers 
echo '[+] Grabbing malware domains '
curl -o ./malware_domains http://mirror1.malwaredomains.com/files/domains.txt
cut -d$'\t' -f3 ./malware_domains | awk 'NF' | grep -E -v "notice|domain" | grep -E -v "collective-media.net|tlvmedia.com" > $HOME/dev/threat_domains/malware_domains
rm -f ./malware_domains

# More Malware Domains
echo '[+] Grabbing malware_urls'
curl -o malware_urls http://malwareurls.joxeankoret.com/domains.txt
grep -v "#" malware_urls | tail -n +2 > $HOME/dev/threat_domains/malware_urls
rm -f malware_urls

# DShield
# remove empty lines | give me everything that isn't a comment | remove the line with the word Site
echo '[+] Grabbing DShield threat feed'
curl -o ./DShield http://www.dshield.org/feeds/suspiciousdomains_High.txt
awk 'NF' DShield | grep -v "#" | grep -v "Site"  > $HOME/dev/threat_domains/DShield
rm -f ./DShield

# Palevo
echo '[+] Grabbing Palevo Tracker'
curl -o palevo_tracker https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist
awk 'NF' palevo_tracker | grep -v "#" > $HOME/dev/threat_domains/palevo_tracker
rm -f palevo_tracker

# Zeus
echo '[+] Grabbing Zeus Tracker'
curl -o zeus_tracker https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
awk 'NF' zeus_tracker | grep -v "#" > $HOME/dev/threat_domains/zeus_tracker
rm -f zeus_tracker

# OSINT bambenekconsulting
echo '[+] Grabbing Bambenek OSINT'
curl -o osint_domainslist http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt
awk 'NF' osint_domainslist | grep -v "#" | cut -d$',' -f1 > $HOME/dev/threat_domains/osint_domainslist
rm -f osint_domainstlist

# Angler Domains
echo '[+] Grabbing Angler Domains'
curl -o angler_domains http://www.beerandraptors.com/dontcrawlmebro/angler_domains
sed -i -e 's/<br>/\n/g' angler_domains
cat angler_domains | grep -v "#" > $HOME/dev/threat_domains/angler_domains
rm -f angler_domains

# Ransomeware Tracker
echo '[+] Grabbing Ransomeware Tracker'
curl -o ransomeware_tracker https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt
awk 'NF' ransomeware_tracker | grep -v "#" > $HOME/dev/threat_domains/ransomeware_tracker_FP-LOW
rm -f ransomeware_tracker

############################################################################################

# TALOS Black List
echo '[+] Grabbing Talos Black List'
curl -k -o ~/dev/threat_sources/Talos_blacklist http://www.talosintel.com/feeds/ip-filter.blf

# spamhaus DROP list
echo '[+] Grabbing Emerging Threats Spamhaus DROP List'
curl -k -o ./spamhaus_droplist http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules
awk 'NF' spamhaus_droplist | grep -v "#" | cut -d$' ' -f5 > $HOME/dev/threat_sources/spamhaus_droplist
rm -f ./spamhaus_droplist
