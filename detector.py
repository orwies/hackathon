from scapy.all import *
from collections import defaultdict
import time

# Target IP to monitor
TARGET_IP = "127.0.0.1"  # Change this to your target IP

# Track connection attempts for the target IP
scan_tracker = {
    'syn_count': 0,
    'fin_count': 0,
    'null_count': 0,
    'xmas_count': 0,
    'ack_count': 0,
    'udp_count': 0,
    'last_time': time.time(),
    'last_syn_time': time.time(),  # Track the time of the last SYN packet
    'tcp_ports': set(),
    'udp_ports': set(),
    'tcp_scan_detected': False  # New flag to track TCP scan detection
}

# Thresholds for detection
SCAN_THRESHOLD = 10  # Number of ports in a short timeframe
TIME_WINDOW = 3  # Time window in seconds
TIME_DIFF_THRESHOLD = 0.6 # Threshold for time difference between SYN packets

def detect_port_scan(pkt):
    if IP in pkt and pkt[IP].dst == TARGET_IP:
        # Reset counter if the time window has passed
        if time.time() - scan_tracker['last_time'] > TIME_WINDOW:
            scan_tracker.update({
                'syn_count': 0,
                'fin_count': 0,
                'null_count': 0,
                'xmas_count': 0,
                'ack_count': 0,
                'udp_count': 0,
                'last_time': time.time(),
                'last_syn_time': time.time(),  # Reset last SYN time
                'tcp_ports': set(),
                'udp_ports': set(),
                'tcp_scan_detected': False  # Reset the flag
            })

        scan_tracker['last_time'] = time.time()

        # TCP scan detection
        if TCP in pkt:
            dst_port = pkt[TCP].dport
            scan_tracker['tcp_ports'].add(dst_port)

            # SYN scan (only SYN flag set)
            if pkt[TCP].flags == 0x02:  # SYN flag = 0x02
                scan_tracker['syn_count'] += 1
                current_time = time.time()
                time_diff = current_time - scan_tracker['last_syn_time']

                if time_diff > TIME_DIFF_THRESHOLD:
                    print(f"[!] TCP Connect Port Scan detected targeting {TARGET_IP}!")
                    print(f"    Time between SYN packets: {time_diff:.4f} seconds")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['tcp_ports']}")
                    scan_tracker['last_syn_time'] = current_time

                # Update last SYN time

                elif scan_tracker['syn_count'] >= SCAN_THRESHOLD and len(scan_tracker['tcp_ports']) >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP SYN scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['tcp_ports']}")
                    scan_tracker['syn_count'] = 0
                    scan_tracker['tcp_scan_detected'] = True  # Mark that a TCP scan was detected

            # FIN scan (only FIN flag set)
            elif pkt[TCP].flags == 0x01:  # FIN flag = 0x01
                scan_tracker['fin_count'] += 1
                if scan_tracker['fin_count'] >= SCAN_THRESHOLD and len(scan_tracker['tcp_ports']) >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP FIN scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['tcp_ports']}")
                    scan_tracker['fin_count'] = 0
                    scan_tracker['tcp_scan_detected'] = True  # Mark that a TCP scan was detected

            # NULL scan (no flags set)
            elif pkt[TCP].flags == 0x00:  # No flags set
                scan_tracker['null_count'] += 1
                if scan_tracker['null_count'] >= SCAN_THRESHOLD and len(scan_tracker['tcp_ports']) >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP NULL scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['tcp_ports']}")
                    scan_tracker['null_count'] = 0
                    scan_tracker['tcp_scan_detected'] = True  # Mark that a TCP scan was detected

            # XMAS scan (FIN, PSH, URG flags set)
            elif pkt[TCP].flags == 0x29:  # XMAS scan: FIN, PSH, URG = 0x29
                scan_tracker['xmas_count'] += 1
                if scan_tracker['xmas_count'] >= SCAN_THRESHOLD and len(scan_tracker['tcp_ports']) >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP XMAS scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['tcp_ports']}")
                    scan_tracker['xmas_count'] = 0
                    scan_tracker['tcp_scan_detected'] = True  # Mark that a TCP scan was detected

            # ACK scan (only ACK flag set)
           

        # UDP scan detection
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            scan_tracker['udp_ports'].add(dst_port)
            scan_tracker['udp_count'] += 1

            if scan_tracker['udp_count'] >= SCAN_THRESHOLD and len(scan_tracker['udp_ports']) >= SCAN_THRESHOLD:
                print(f"[!] Possible UDP scan detected targeting {TARGET_IP}!")
                print(f"    From source: {pkt[IP].src}")
                print(f"    Ports: {scan_tracker['udp_ports']}")
                scan_tracker['udp_count'] = 0


# Start sniffing
def main():
    print(f"[*] Starting port scan detector for {TARGET_IP}...")
    print("[*] Press Ctrl+C to stop")

    # Set up a BPF filter to only capture traffic destined for the target IP
    ip_filter = f"dst host {TARGET_IP} and (tcp or udp)"

    try:
        sniff(iface="Software Loopback Interface 1", filter=ip_filter, prn=detect_port_scan, store=0)
    except KeyboardInterrupt:
        print("\n[*] Scan detection stopped.")


if __name__ == "__main__":
    main()
