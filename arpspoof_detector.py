#!/usr/bin/env python3

import sys
import scapy.all as scapy
from argparse import ArgumentParser

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and make sure you use the command python3 arpspoof_detector.py --interface "
                     "<interface>\n\n")
    sys.exit(0)


def args():
    parser = ArgumentParser()
    parser.add_argument('-i', '--interface', dest='iface', help='specify you card interface, run (ifconfig)')
    options = parser.parse_args()
    if not options.iface:
        parser.error("[-] Please specify a valid interface card, or type it correctly, ex: --interface wlan0")
    return options


def fetch_mac_address(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)  # create an ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast an ARP packets to all devices in the network
    broadcast_arp_packets = broadcast / arp_request  # combining these 2 packets together to send

    ans, unans = scapy.srp(broadcast_arp_packets, timeout=2, verbose=False)  # send packets to all devices
    return ans[0][1].hwsrc  # return only the mac address of the target


def sniff(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)  # store=False that tells scapy do not store flowing packets in memory so
    # that it doesn't cause too much pressure on our machine


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac_address = fetch_mac_address(ip_address=packet[scapy.ARP].psrc)
            response_mac_address = fetch_mac_address(ip_address=packet[scapy.ARP].hwsrc)
            if real_mac_address != response_mac_address:
                print("[*] arping-tables poisoning!")
        except IndexError:
            pass


print("[+] arp spoof detector is running..")
sniff(interface=args().iface)
