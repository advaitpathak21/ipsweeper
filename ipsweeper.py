#!/usr/bin/env python

import scapy.all as scapy
import optparse

def getargs():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="range", help="Range of IPs to be scanned")

    (options, arguments) = parser.parse_args()

    if not options.range:
        parser.error("~Range option not Specified, use --help for more info")
    return options.range

def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_rb = broadcast/arp_request

	ansd = scapy.srp(arp_rb, timeout=2, verbose=False)[0]

	clientsl = []
	for a in ansd:
		clientsd = {"ip":a[1].psrc,"mac":a[1].hwsrc}
		clientsl.append(clientsd)
		
	return clientsl

def printer(clist):
	print("------------------------------------------")
	print("IP\t\t\tIt's MAC")
	print("------------------------------------------")
	for a in clist:
		print(a["ip"] + "\t\t" + a["mac"])	

range = getargs()
clist = scan(range)
printer(clist)
