from scapy.all import *
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

target_ip = "127.0.0.1"
for i in range(49664, 59664):  # Fixed range to include 5555
    tcp_port_scan(target_ip, i)
