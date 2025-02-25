import scapy.all  as sc
import socket

def tcp_port_scan(target, port):
    """
    Perform a TCP port scan using socket.
    :param target: Target IP address
    :param port: Port to scan
    """

    # TCP Connect Scan (Full Handshake)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((target, port))
        sock.close()    
        print(f"Open port on {target}: {port}")
    except (socket.timeout, ConnectionRefusedError):
        print(f"Closed port on {target}: {port}")

def tcp_syn_scan(target,port):
    """
    Perform a TCP SYN port scan using Scapy.
    :param target: Target IP address
    :param ports: List of ports to scan
    """
    pkt = sc.IP(dst=target)/sc.TCP(dport=port, flags="S")
    resp = sc.sr1(pkt, timeout=1, verbose=0)
    
    if resp and resp.haslayer(sc.TCP):
        if resp[sc.TCP].flags == 0x12:  # SYN-ACK received (open port)
            print(f"Open port on {target}: {port}")
            sc.sr(sc.IP(dst=target)/sc.TCP(dport=port, flags="R"), timeout=1, verbose=0)  # Send RST to close
        elif resp[sc.TCP].flags == 0x14:  # RST-ACK received (closed port)
            print(f"Closed port on {target}: {port}")
        
def tcp_fin_scan(target, port):
    """
    Perform a TCP FIN port scan using Scapy.
    :param target: Target IP address
    :param ports: List of ports to scan
    """

    pkt = sc.IP(dst=target)/sc.TCP(dport=port, flags="F")
    resp = sc.sr1(pkt, timeout=1, verbose=0)

    if resp is None:  # No response means port is open or filtered
        print(f"Open/Filtered ports on {target}: {port}")
    elif resp.haslayer(sc.TCP) and resp[sc.TCP].flags == 0x14:  # RST-ACK means closed
        print(f"Closed ports on {target}: {port}")
        
def tcp_xmas_scan(target, port):
    """
    Perform a TCP XMAS port scan using Scapy.
    :param target: Target IP address
    :param ports: List of ports to scan
    """
    
    pkt = sc.IP(dst=target)/sc.TCP(dport=port, flags="FPU")  # XMAS scan sets FIN, PSH, URG flags
    resp = sc.sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:  # No response means port is open or filtered
        print(f"Open/Filtered ports on {target}: {port}")            
    elif resp.haslayer(sc.TCP) and resp[sc.TCP].flags == 0x14:  # RST-ACK means closed
        print(f"Closed ports on {target}: {port}")



def udp_scan(target : str, port : int, timeout=3) -> None:
    print(f"Scanning UDP port {port} on {target}...")

    # Send an empty UDP packet
    udp_packet = sc.IP(dst=target) / sc.UDP(dport=port)
    response = sc.sr1(udp_packet, timeout=timeout, verbose=False)

    if response is None:
        print(f"Port {port}: OPEN or FILTERED (No response)")
    elif response.haslayer(sc.ICMP):
        icmp_layer = response.getlayer(sc.ICMP)
        if icmp_layer.type == 3 and icmp_layer.code == 3:
            print(f"Port {port}: CLOSED")
        else:
            print(f"Port {port}: FILTERED (ICMP response: Type {icmp_layer.type}, Code {icmp_layer.code})")
    else:
        print(f"Port {port}: OPEN (Unexpected response received)")


target_ip = "127.0.0.1"
for i in range(49664, 59664):  # Fixed range to include 5555
    udp_scan(target_ip, i)
