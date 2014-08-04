#!/bin/sh

curl -k -o ./ssl_blacklist  https://sslbl.abuse.ch/blacklist/sslipblacklist.rules
filter_ips ./ssl_blacklist $HOME/dev/threat_sources/ssl_blacklist
rm -f ./ssl_blacklist
