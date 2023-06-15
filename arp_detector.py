#!/usr/bin/env python3

import scapy.all as scapy


def get_mac_address(ip_address):
    try:
        arp_request = scapy.ARP(pdst=ip_address)
        broadcast_packets = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_arp_packets = broadcast_packets / arp_request
        answered_device = scapy.srp(x=broadcast_arp_packets, timeout=3, verbose=False)[0]
        return answered_device[0][1].hwsrc
    except IndexError:
        pass


def sniff(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except KeyboardInterrupt:
        print("\n[*] Detected 'ctrl + c' pressed, program terminated.\n")


def process_sniffed_packet(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = get_mac_address(ip_address=packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print('[+] You are under attack!!')
    except TypeError:
        pass


# sniff(interface='Realtek RTL8822BE 802.11ac PCIe Adapter')
sniff(interface='eth0')
