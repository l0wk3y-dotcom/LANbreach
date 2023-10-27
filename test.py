import scapy.all as scapy
def get_mac_arp(ip):
    arp_packet=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip)
    answered_list,_=scapy.srp(arp_packet,timeout=5,verbose=False)
    return answered_list[1].hwsrc
print(get_mac_arp(str("192.168.1.3")))
python main.py spoof --target_host 192.168.1.2 --spoof_host 192.168.1.1