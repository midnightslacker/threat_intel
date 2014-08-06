#!/usr/bin/env python
import re
import os
import cyber_threat_intel as cti

file_path = os.environ['HOME']+"/dev/threat_domains/"
output_file = os.environ['HOME']+"/lookups/threat_domains.csv"
output_dir = os.environ['HOME']+"/lookups"

# Malware Domains
maldomlist  = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
maldom      = "http://mirror1.malwaredomains.com/files/domains.txt"
feodo       = "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"
DShield     = "http://www.dshield.org/feeds/suspiciousdomains_High.txt"
spyEye      = "https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist"
zeus        = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
palevo      = "https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist"
ntDNS       = "http://www.nothink.org/blacklist/blacklist_malware_dns.txt"
ntHTTP      = "http://www.nothink.org/blacklist/blacklist_malware_http.txt"
ntIRC       = "http://www.nothink.org/blacklist/blacklist_malware_irc.txt"
hpHosts     = "http://hosts-file.net/download/hosts.txt"
# malwareURLs = "http://malwareurls.joxeankoret.com/normal.txt"
# cyberCrime  = "http://cybercrime-tracker.net/all.php" TODO: Has a mix of IPs and domains, fix filter

threat_domains = {
        "malware_domain_list":maldomlist,
        "malware_domains":maldom,
        "DShield":DShield,
        "feodo_domain_list":feodo,
        "spyEye_domain_list":spyEye,
        "zeus_domain_list":zeus,
        "palevo_domain_list":palevo,
        "noThink_malware_dns_domains":ntDNS,
        "noThink_malware_http_domains":ntHTTP,
        "noThink_malware_IRC_domains":ntIRC,
        "malwareBytes_hpHosts":hpHosts,
        #"malwareURLs":malwareURLs,
        #"cyber_crime_tracker": cyberCrime 
        }

# Domain Regex
domain = re.compile('([a-z0-9]+(?:[\-|\.][a-z0-9]+)*\.[a-z]{2,5}(?:[0-9]{1,5})?)')

def main():
    # Loop through open source threat intelligence sources
    # Pull them down from the interwebs and format them
    # Write them to file.
    for filename, source in threat_domains.iteritems():
        print "[+] Grabbing: " + source
        threat_list=cti.urlgrab2(source, domain)
        cti.writeToFile(file_path, threat_list, filename)
    
    # Create CSV
    print "[+] Creating CSV. . .\n"
    cti.createCSV(file_path, output_dir, output_file, "Domain,Threat_Feed\n")
    
if __name__ == "__main__":
    main()
