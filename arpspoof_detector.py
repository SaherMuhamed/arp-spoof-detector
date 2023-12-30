#!/usr/bin/env python3

import sys
import time
import requests
import scapy.all as scapy
from argparse import ArgumentParser

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and make sure you use the command python3 arpspoof_detector.py --interface "
                     "<interface>\n\n")
    sys.exit(0)

ip_mac_mapping = {}  # dictionary to store IP-MAC mappings


def args():
    parser = ArgumentParser()
    parser.add_argument('-i', '--interface', dest='iface', help='specify your card interface, run (ifconfig)')
    options = parser.parse_args()
    if not options.iface:
        parser.error("[-] Please specify a valid interface card, or type it correctly, e.g., --interface wlan0")
    return options


def fetch_mac_vendor(mac):
    return requests.get(url="https://www.macvendorlookup.com/api/v2/" + mac, timeout=7).json()[0]["company"]


def fetch_mac_address(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_packets = broadcast / arp_request

    ans, unans = scapy.srp(broadcast_arp_packets, timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None


def update_mapping(ip_address, mac_address):
    ip_mac_mapping[ip_address] = mac_address


def is_arp_spoof(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            source_ip = packet[scapy.ARP].psrc
            source_mac = packet[scapy.ARP].hwsrc

            if source_ip not in ip_mac_mapping:
                update_mapping(source_ip, source_mac)  # if the source IP is not in the mapping, add it
            else:
                real_mac_address = ip_mac_mapping[
                    source_ip]  # if the source IP is in the mapping, check for MAC address inconsistency
                if real_mac_address != source_mac:
                    print("[*] ARP spoof detected! IP: {} , Real MAC: {}, Spoofed MAC: {} ({})".format(
                        source_ip, real_mac_address, source_mac, fetch_mac_vendor(mac=source_mac)))
                    time.sleep(1)  # slow requests to an api to not ddos the server
        except IndexError:
            pass


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=is_arp_spoof)


print("[+] ARP spoof detector is running..")
sniff(interface=args().iface)
