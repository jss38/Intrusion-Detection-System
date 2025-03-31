#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption, Ether, IP, TCP, raw

def handle_pkt(pkt):    
    if pkt.haslayer(TCP):
        print('%s:%s -> %s:%s' % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))

    sys.stdout.flush()

def main():
    if len(sys.argv) < 2:
        iface = 's1-cpu-eth0'
    else:
        iface = sys.argv[1]

    print('Sniffing on %s' % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
