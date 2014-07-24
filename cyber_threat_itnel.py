#!/usr/bin/env python
import urllib2
import re
import os
import sys

file_path = os.environ['HOME']+"/dev/threat_sources/"
output_file = os.environ['HOME']+"/.gvfs/lookups on tpappspl01/threats.csv"

#Emerging Threats
ethreat_blockedIP =        "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
ethreat_compromisedIP =    "http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
ethreat_RBN_malvertisers = "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/emerging-rbn-malvertisers.txt"
ethreat_RBN_IP =           "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt"

#AlienVault
alien = "https://reputation.alienvault.com/reputation.generic"

#Zeus Tracker
zeus = "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"

#SpyEye Tracker
spyEye = "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist"

#Palevo Tracker
palevo = "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist"

#Feodo Tracker
feodo = "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"

#Malc0de Black List
malcode = "http://malc0de.com/bl/IP_Blacklist.txt"

#Malware Domain List - list of active ip addresses
malwareDom = "http://www.malwaredomainlist.com/hostslist/ip.txt"

#OpenBL.org
openBL = "http://www.openbl.org/lists/base.txt"

#NoThink.org -- DNS
ntDNS = "http://www.nothink.org/blacklist/blacklist_malware_dns.txt"

#NoThink.org -- HTTP
ntHTTP = "http://www.nothink.org/blacklist/blacklist_malware_http.txt"

#NoThink.org -- IRC
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
domain = re.compile('([a-z0-9]+(?:[\-|\.][a-z0-9]+)*\.[a-z]{2,5}(?:[0-9]{1,5})?)')

def regex(threat_list):
    ''' Grab only the IPs out of the file '''
    threat_intel = re.findall(ip, str(threat_list))
    return '\n'.join(threat_intel)

def urlgrab2 (host):
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
    return regex(threat_list)


def writeToFile (threat_list, filename):
    ''' Write updated threat intel to correct file and directory '''
    # check if file already exists, if it does, overwrite it. If the file doesn't exist, create it.
    if os.path.isfile(file_path+filename):
        f = open(file_path+filename, 'r+')
        f.writelines(threat_list)
        f.truncate()
        f.close()
    else:
        f = open(file_path+filename, 'w+')
        f.writelines(threat_list)
        f.close()

def createCSV():
    ''' Take each IP address for column 1 and source into column 2 '''
    # Make sure the directory is mounted
    if not os.path.isdir("/root/.gvfs/lookups on tpappspl01"):
        print "\t [-] Output directory does not exist or is not mounted\n"
        sys.exit()

    # delete yesterdays outdated CSV
    if os.path.isfile(output_file):
        os.remove(output_file)
    
    # create header for first line
    f = open(output_file, 'w+')
    f.write("IP,Threat_Feed\n")
    
    for hFile in os.listdir(file_path):
        with open(file_path+hFile) as infile:
            for line in infile:
                f.write(line.rstrip()+","+hFile+"\n")
    f.close()

def main():
    # Loop through open source threat intelligence sources
    # Pull them down from the interwebs and format them
    # Write them to file.
    for filename, source in open_source_threat_intel.iteritems():
        print "[+] Grabbing: " + source
        threat_list=urlgrab2(source)
        writeToFile(threat_list, filename)

    # Create CSV for Splunk integration
    print "[+] Creating CSV for Splunk integration\n"
    createCSV()

if __name__ == "__main__":
    main()

