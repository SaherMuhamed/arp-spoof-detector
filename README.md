# ARP Spoofing Detector

This Python script detects ARP spoofing attacks by sniffing network packets using the Scapy library.

## Description
ARP spoofing is a type of attack where an attacker sends falsified Address Resolution Protocol (ARP) messages on a local network. This script helps in detecting such attacks by analyzing network packets and comparing the actual MAC address of the sender with the MAC address provided in the response.
The script utilizes the Scapy library, which provides powerful tools for network packet manipulation and sniffing.

## Features
- Sniffs network packets in real-time.
- Detects ARP spoofing attacks by comparing MAC addresses.
- Provides a warning message when an attack is detected.

## Requirements
- Python 3.x
- Scapy library

## Usage
1. Install the required dependencies by running the following command:
```commandline
pip install scapy
```
2. Download or clone this repository to your local machine.
3. Open a terminal and navigate to the project directory.
4. Run the following command to execute the script:
   ```commandline
   python3 arp_spoofing_detector.py
   ```
   By default, the script will sniff packets on the 'eth0' network interface. You can modify the interface by editing the sniff(interface='eth0') line in the script.

5. The script will start sniffing network packets and display a warning message if an ARP spoofing attack is detected.
6. Press Ctrl + C to stop the script.

### Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
