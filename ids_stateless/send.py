from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw
import sys, socket, random

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

if __name__ == '__main__':
    if len(sys.argv) < 1:
        print("Usage: python send.py <dst_ip>")
        sys.exit(1)
    else:
        payload = '04710471'
        dst_name = sys.argv[1]
        dst_addr = socket.gethostbyname(dst_name)
        iface = get_if()

        f1_pkt1 = Ether(dst='00:00:0a:00:02:02', src=get_if_hwaddr(iface)) / IP(dst=dst_addr) / TCP(dport=1025, sport=1080) / '\x04\x04\x04\x04'
        sendp(f1_pkt1, iface = iface)

        f1_pkt2 = Ether(dst='00:00:0a:00:02:02', src=get_if_hwaddr(iface)) / IP(dst=dst_addr) / TCP(dport=1025, sport=1080) / '\x04\x71\x04\x71'
        sendp(f1_pkt2, iface = iface)

        f2_pkt1 = Ether(dst='00:00:0a:00:02:02', src=get_if_hwaddr(iface)) / IP(dst=dst_addr) / TCP(dport=9999, sport=1080) / '\x03\x71\x03\x71'
        sendp(f2_pkt1, iface = iface)

        f2_pkt2 = Ether(dst='00:00:0a:00:02:02', src=get_if_hwaddr(iface)) / IP(dst=dst_addr) / TCP(dport=9999, sport=1080) / '\xaa\xaa\xaa\xaa'
        sendp(f2_pkt2, iface = iface)

        f1_pkt3 = Ether(dst='00:00:0a:00:02:02', src=get_if_hwaddr(iface)) / IP(dst=dst_addr) / TCP(dport=1025, sport=1080) / '\x04\x04\x04\x04'
        sendp(f1_pkt3, iface = iface)