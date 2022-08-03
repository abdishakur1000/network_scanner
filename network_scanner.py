import scapy.all as scapy
import time


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


result = scan('10.0.2.1/24')
show_result(result)
