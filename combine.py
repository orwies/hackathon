import add_packets
import port_scanning_types
from add_packets import *
from port_scanning_types import *
import random


def func(x):
    r = 0
    target_ip = "127.0.0.1"
    pkt_list = PacketList()
    while r <= x:
        random_choice = random.randint(1,101)
        if 1 <= random_choice <= 20:
            random_scan = random.randint(1, 5)
            if random_scan == 1:
                for i in range(20):
                    packet = tcp_syn_scan(target_ip, random.randint(1025,65535))
                    pkt_list.append(packet)
                    r += 1
            if random_scan == 2:
                for i in range(20):
                    packet = tcp_fin_scan(target_ip, random.randint(1025,65535))
                    pkt_list.append(packet)
                    r += 1
            if random_scan == 3:
                for i in range(20):
                    packet = tcp_xmas_scan(target_ip, random.randint(1025,65535))
                    pkt_list.append(packet)
                    r += 1
            if random_scan == 4:
                for i in range(20):
                    packet = udp_scan(target_ip, random.randint(1025,65535))
                    pkt_list.append(packet)
                    r += 1
        else:
            parser = argparse.ArgumentParser(description='Send random packets using UDP, TCP, or DNS')
            args = parser.parse_args()
            state, packet = send_random_packet()
            if state == True:
                pkt_list.append(packet)
    return pkt_list

list_pkt = func(2500)
