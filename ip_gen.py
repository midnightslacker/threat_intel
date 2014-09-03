#!/bin/env python
from optparse import OptionParser
from netaddr import IPNetwork

parser = OptionParser('usage %prog -i --cidr '+'<IP cidr range>')
parser.add_option('-i', '--cidr', dest='ip_range', type='string', help='specify IPv4 cidr range (i.e. 192.168.1.1/23)')

(options, args) = parser.parse_args()

ip_range = options.ip_range
if (ip_range == None):
    print parser.usage
    exit(0)

for ip in IPNetwork(ip_range):
    print ('%s' %ip)

