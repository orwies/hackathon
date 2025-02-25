import sys
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
from scapy.layers.inet import *
sys.stdin, sys.stdout, sys.stderr = i, o, e

# def tcp_port_scan(target, port):
#     """
#     Perform a TCP port scan using socket.
#     :param target: Target IP address
#     :param port: Port to scan
#     """
#
#     # TCP Connect Scan (Full Handshake)
#
#     try:
#         SYN = IP(src='172.16.120.5', dst=target)/ TCP(sport=1234, dport=port, flags='S', seq=1000)
#         SYNACK = sr1(SYN)
#         my_ack = SYNACK.seq + 1
#         ACK = IP(src='172.16.120.5', dst=target)/ TCP(sport=1234, dport=port, flags='A', seq=1001, ack=my_ack)
#         send(ACK)
#         print(f"Open port on {target}: {port}")
#         return SYN, ACK
#     except (socket.timeout, ConnectionRefusedError):
#         print(f"Closed port on {target}: {port}")
#         return '', ''

def tcp_syn_scan(target,port):
    """
    Perform a TCP SYN port scan using Scapy.
    :param target: Target IP address
    :param ports: List of ports to scan
    """
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK received (open port)
            print(f"Open port on {target}: {port}")
            sr(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)  # Send RST to close
        elif resp[TCP].flags == 0x14:  # RST-ACK received (closed port)
            print(f"Closed port on {target}: {port}")
    return pkt
        
def tcp_fin_scan(target, port):
    """
    Perform a TCP FIN port scan using Scapy.
    :param target: Target IP address
    :param ports: List of ports to scan
    """

    pkt = IP(dst=target)/TCP(dport=port, flags="F")
    resp = sr1(pkt, timeout=1, verbose=0)

    if resp is None:  # No response means port is open or filtered
        print(f"Open/Filtered ports on {target}: {port}")
    elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:  # RST-ACK means closed
        print(f"Closed ports on {target}: {port}")
    return pkt
        
def tcp_xmas_scan(target, port):
    """
    Perform a TCP XMAS port scan using Scapy.
    :param target: Target IP address
    :param ports: List of ports to scan
    """
    
    pkt = IP(dst=target)/TCP(dport=port, flags="FPU")  # XMAS scan sets FIN, PSH, URG flags
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:  # No response means port is open or filtered
        print(f"Open/Filtered ports on {target}: {port}")            
    elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:  # RST-ACK means closed
        print(f"Closed ports on {target}: {port}")
    return pkt



def udp_scan(target : str, port : int, timeout=3) -> None:
    print(f"Scanning UDP port {port} on {target}...")

    # Send an empty UDP packet
    udp_packet = IP(dst=target) / UDP(dport=port)
    response = sr1(udp_packet, timeout=timeout, verbose=False)

    if response is None:
        print(f"Port {port}: OPEN or FILTERED (No response)")
    elif response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code == 3:
            print(f"Port {port}: CLOSED")
        else:
            print(f"Port {port}: FILTERED (ICMP response: Type {icmp_layer.type}, Code {icmp_layer.code})")
    else:
        print(f"Port {port}: OPEN (Unexpected response received)")
    return udp_packet
