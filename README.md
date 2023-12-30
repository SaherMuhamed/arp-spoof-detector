# ARP Spoofing Detector

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)  ![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)  ![Windows](https://img.shields.io/badge/Windows-0078D4.svg?style=for-the-badge&logo=Windows&logoColor=white)  ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)

This Python script detects ARP spoofing attacks by sniffing network packets using the `Scapy` library.

## Description
ARP spoofing is a type of attack where an attacker sends falsified Address Resolution Protocol (ARP) messages on a local network. This script helps in detecting such attacks by analyzing network packets and comparing the actual MAC address of the sender with the MAC address provided in the response. The script utilizes the `Scapy` library, which provides powerful tools for network packet manipulation and sniffing.

## Features
- Sniffs network packets in real-time
- Detects ARP spoofing attacks by comparing MAC addresses
- Provides a warning message when an attack is detected
- Display the vendor of the attacking machine

## Screenshot
![](https://github.com/SaherMuhamed/arp-spoof-detector/blob/master/screenshot/Screenshot%20from%202023-09-19%2010-28-24.png)

## Requirements
- Python 3.x
- Scapy library
- requests

## Usage
1. Install the required dependencies by running the following command:
```commandline
pip install scapy requests
```
2. Download or clone this repository to your local machine.
3. Open a terminal and navigate to the project directory.
4. Run the following command to execute the script:
   ```commandline
   python3 arpspoof_detector.py --interface <interface>
   ```
   By default, the script will sniff packets on the 'eth0' network interface. You can modify the interface by editing the sniff(interface='eth0') line in the script.

5. The script will start sniffing network packets and display a warning message if an ARP spoofing attack is detected.
6. Press Ctrl + C to stop the script.
