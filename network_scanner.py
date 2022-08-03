import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for items in answered_list:
        clients_dict = {'IP': items[1].psrc, 'MAC': items[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def show_result(results_list):
    print('IP\t\t\t\tMAC Address')
    print('-' * 60)
    for client in results_list:
        print(client['IP'] + '\t\t\t' + client['MAC'])


options = get_arguments()
result = scan(options.target)
show_result(result)
