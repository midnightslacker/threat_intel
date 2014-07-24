#!/usr/bin/env python
import urllib2
import re
import os
import sys

file_path = os.environ['HOME']+"/dev/threat_sources/"
output_file = os.environ['HOME']+"/lookups/threats.csv"
output_dir = os.environ['HOME']+"/lookups"

#Emerging Threats
ethreat_blockedIP =        "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
ethreat_compromisedIP =    "http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
ethreat_RBN_malvertisers = "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/emerging-rbn-malvertisers.txt"
ethreat_RBN_IP =           "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt"

#AlienVault
alien = "https://reputation.alienvault.com/reputation.generic"

#IP Trackers for known malware
zeus = "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
spyEye = "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist"
palevo = "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist"
feodo = "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"

#Malc0de Black List
malcode = "http://malc0de.com/bl/IP_Blacklist.txt"

#Malware Domain List - list of active ip addresses
malwareDom = "http://www.malwaredomainlist.com/hostslist/ip.txt"

#OpenBL.org
openBL = "http://www.openbl.org/lists/base.txt"

#NoThink.org -- DNS, HTTP and IRC
ntDNS = "http://www.nothink.org/blacklist/blacklist_malware_dns.txt"
ntHTTP = "http://www.nothink.org/blacklist/blacklist_malware_http.txt"
ntIRC = "http://www.nothink.org/blacklist/blacklist_malware_irc.txt"

open_source_threat_intel = {
    "AlienVault_blacklist":alien,
    "malc0de_blacklist":malcode, 
    "palevo_ip_blacklist":palevo, 
    "spyEye_ip_blacklist":spyEye, 
    "zeus_tracker_ip_blacklist":zeus,
    "feodo_black_list":feodo,
    "emerging_threats_ip_blacklist":ethreat_blockedIP, 
    "emerging_threats_compromised_ips":ethreat_compromisedIP, 
    "emerging_threats_malvertisers":ethreat_RBN_malvertisers,
    "emerging_threats_RBN_ips":ethreat_RBN_IP, 
    "malware_domain_list_ips":malwareDom,
    "open_blacklist":openBL,
    "noThink_DNS_blacklist":ntDNS,
    "noThink_HTTP_blacklist":ntHTTP,
    "noThink_IRC_blacklist":ntIRC }

# IP and Domain REGEX
ip = re.compile('((?:(?:[12]\d?\d?|[1-9]\d|[1-9])\.){3}(?:[12]\d?\d?|[\d+]{1,2}))')

def regex(threat_list, pattern):
    ''' Grab only the IPs out of the file '''
    threat_intel = re.findall(pattern, str(threat_list))
    return '\n'.join(threat_intel)

def urlgrab2 (host, pattern):
    ''' Grab OS threat intel source from host '''
    req = urllib2.Request(host)
    try:
        response = urllib2.urlopen(host)
    except urllib2.URLError as e:
        if hasattr(e, 'reason'):
            print "\t [-] Failed to reach " + str(host) +"\n\t [-] Reason: ", e.reason +"\n"
            sys.exit()
        elif hasattr(e, 'code'):
            print "\t [-] The server (%s) couldn't fulfill the requst.\n\t [-] Reason: %s" % (host, e.code)
            sys.exit()
    
    threat_list = response.readlines()
    return regex(threat_list, pattern)


def writeToFile (source_path, threat_list, filename):
    ''' Write updated threat intel to correct file and directory '''
    # check if file already exists, if it does, overwrite it. If the file doesn't exist, create it.
    if os.path.isfile(source_path+filename):
        f = open(source_path+filename, 'r+')
        f.writelines(threat_list)
        f.truncate()
        f.close()
    else:
        f = open(source_path+filename, 'w+')
        f.writelines(threat_list)
        f.close()

def createCSV(source_path, directory, oFile, header):
    ''' Take each IP address for column 1 and source into column 2 '''
    # Make sure the directory is mounted
    if not os.path.isdir(directory):
        print "\t [-] Output directory does not exist or is not mounted\n"
        sys.exit()

    # delete yesterdays outdated CSV
    if os.path.isfile(oFile):
        os.remove(oFile)
    
    # create header for first line
    f = open(oFile, 'w+')
    f.write(header)
    
    for hFile in os.listdir(source_path):
        with open(source_path+hFile) as infile:
            for line in infile:
                f.write(line.rstrip()+","+hFile+"\n")
    f.close()

def main():
    # Loop through open source threat intelligence sources
    # Pull them down from the interwebs and format them
    # Write them to file.
    for filename, source in open_source_threat_intel.iteritems():
        print "[+] Grabbing: " + source
        threat_list=urlgrab2(source, ip)
        writeToFile(file_path, threat_list, filename)

    # Create CSV for Splunk integration
    print "[+] Creating CSV. . .\n"
    createCSV(file_path, output_dir, output_file, "IP,Threat_Feed\n")

if __name__ == "__main__":
    main()

