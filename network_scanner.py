#!/usr/bin/env python
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip_address", help="Gateway IP Address for scanning")
    options = parser.parse_args()   # In argparse, you get only options returned.
    if not options.ip_address:
        parser.error("Please specify an ip address, use --help for more info")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst = ip) # create an ARP object
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")        # Create an ethernet object
    arp_request_broadcast = broadcast/arp_request # Appending broadcast with arp message i.e. combination of two.
  
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)   # SR means send and receive. 'srp' means send and receive with a custom ether part.
    clients_list = []
    for element in answered_list:
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc} # Create a dictionary
        clients_list.append(client_dict)  # Add the dictionary as an element in a list.
    return clients_list

def print_result(results_list):
    print("---------------------------------------------------------")
    print("    IP\t\t\tMAC Address\n---------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


# Do route -n on terminal and check the gateway = 172.16.61.2.
options = get_arguments()
scan_result = scan(options.ip_address)
print_result(scan_result)

############OUTPUT##############OUTPUT##############OUTPUT############
# root@kali:~/PycharmProjects/net_scanner# python net_scanner.py -t 172.16.61.2/24
# ---------------------------------------------------------
#     IP			MAC Address
# ---------------------------------------------------------
# 172.16.61.1		00:50:56:c0:00:08
# 172.16.61.2		00:50:56:e5:74:f6
# 172.16.61.200		00:0c:29:bb:4e:db
# 172.16.61.254		00:50:56:e8:58:bb

