#!/bin/sh

# malwareBytes hpHosts
echo 'Grabbing malwareBytes Hosts.txt'
curl -o ./hosts.txt http://hosts-file.net/download/hosts.txt
grep 127\.0\.0\.1 hosts.txt | sed -e "1d" | sed -e 's/127\.0\.0\.1[\t]//g' | sed -e 's/googletag//g' > $HOME/dev/threat_domains/malwareBytes_hpHosts
rm -f ./hosts.txt

# tor nodes
echo 'Grabbing tor nodes list'
curl -k -o ./tor_nodes https://www.dan.me.uk/torlist/
python $HOME/bin/filter_ips ./tor_nodes $HOME/dev/threat_sources/tor_nodes
rm -f ./tor_nodes

# ssl blacklist -- Currently offline
echo 'Grabbing ssl blacklist' 
curl -k -o ./ssl_blacklist  https://sslbl.abuse.ch/blacklist/sslipblacklist.rules
python $HOME/bin/filter_ips ./ssl_blacklist $HOME/dev/threat_sources/ssl_blacklist
rm -f ./ssl_blacklist
