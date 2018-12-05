import os
from scapy.all import sniff,wrpcap,Raw,IP,TCP

def get_pcap(ifs, ip=None, size=100):
    filter = ""
    if ip:
        filter += "ip src %s and tcp and tcp port 80"%ip
        dpkt = sniff()