#!/usr/bin/env python
import urllib
import urllib2
import gzip
import re
import os
import sys
import csv

file_path = os.environ['HOME']+"/dev/threat_sources/"
output_file = "/Volumes/lookups/threats.csv"

#Emerging Threats
ethreat_blockedIP =        "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
ethreat_compromisedIP =    "http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
ethreat_RBN_malvertisers = "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/emerging-rbn-malvertisers.txt"
ethreat_RBN_IP =           "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt"

#AlienVault (needs to be gunzipped)
alien = "https://reputation.alienvault.com/reputation.snort.gz"

#Zeus Tracker
zeus = "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"

#SpyEye
spyEye = "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist"

#Palevo Tracker
palevo = "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist"

#Malc0de Black List
malcode = "http://malc0de.com/bl/IP_Blacklist.txt"

# Malware Domain List - list of active ip addresses
malwareDom = "http://www.malwaredomainlist.com/hostslist/ip.txt"

open_source_threat_intel = {
    "malc0de_blacklist":malcode, 
    "palevo_ip_blocklist":palevo, 
    "spyEye_ip_blocklist":spyEye, 
    "zeus_tracker_ip_blocklist":zeus, 
    "emerging_threats_ip_blocklist":ethreat_blockedIP, 
    "emerging_threats_compromised_ips":ethreat_compromisedIP, 
    "emerging_threats_malvertisers":ethreat_RBN_malvertisers,
    "emerging_threats_RBN_ips":ethreat_RBN_IP, 
    "malware_domain_list_ips":malwareDom }

# Simple IPv4 regex -- will include invalid IPs like 999.999.0.0 if they're in the file
ip = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')

def regex(threat_list):
    ''' Grab only the IPs out of the file '''
    threat_intel = re.findall(ip, str(threat_list))
    return '\n'.join(threat_intel)


def gzipURL (host, filename):
    ''' Download OS threat intel source and gunzip it '''
    urllib.urlretrieve(host, filename)
    f = gzip.open(filename)
    threat_list = f.readlines()
    # remove gzipped file
    os.remove(filename)
    return regex(threat_list)

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
    if not os.path.isdir("/Volumes/lookups"):
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
    # AlienVault is a special case because its gzipped
    print "[+] Grabbing: " + str(alien)
    alienVault = gzipURL(alien, "alien_vault_blacklist")
    writeToFile(alienVault, "alien_vault_blacklist")

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

