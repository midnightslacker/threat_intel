#!/bin/env python
from optparse import OptionParser
from netaddr import IPNetwork
from netaddr import iter_iprange

parser = OptionParser('usage %prog -i --cidr '+'<IP cidr range>')
parser.add_option('-i', '--cidr', dest='ip_cidr', type='string', help='specify IPv4 cidr range (i.e. 192.168.1.1/23)')
parser.add_option('-r', '--range', dest='ip_range', type='string', help='specify IPv4 range (i.e. 192.168.1.1-198.162.1.24')

(options, args) = parser.parse_args()

ip_cidr  = options.ip_cidr
ip_range = options.ip_range

if (ip_cidr == None) and (ip_range == None):
    print parser.usage
    exit(0)

def cidr():
    for ip in IPNetwork(ip_cidr):
        print ('%s' % ip)

def ipRange():
   ip_list = list(iter_iprange(ip_range.split('-')[0], ip_range.split('-')[1]))
   for ip in ip_list:
       print ('%s' % ip)

def main():
    if (ip_cidr != None):
        cidr()
    elif (ip_range != None):
        ipRange()
    else:
        print parser.usage()
        exit(0)

if __name__ == "__main__":
    main()
