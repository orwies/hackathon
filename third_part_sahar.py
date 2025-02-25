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
    'ports': set()
}

# Thresholds for detection
SCAN_THRESHOLD = 5  # Number of ports in a short timeframe
TIME_WINDOW = 5  # Time window in seconds


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
                'ports': set()
            })

        scan_tracker['last_time'] = time.time()

        # TCP scan detection
        if TCP in pkt:
            dst_port = pkt[TCP].dport
            scan_tracker['ports'].add(dst_port)

            # SYN scan (only SYN flag set)
            if pkt[TCP].flags == 'S':
                scan_tracker['syn_count'] += 1
                if scan_tracker['syn_count'] >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP SYN scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['ports']}")
                    scan_tracker['syn_count'] = 0

            # FIN scan (only FIN flag set)
            elif pkt[TCP].flags == 'F':
                scan_tracker['fin_count'] += 1
                if scan_tracker['fin_count'] >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP FIN scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['ports']}")
                    scan_tracker['fin_count'] = 0

            # NULL scan (no flags set)
            elif pkt[TCP].flags == 0:
                scan_tracker['null_count'] += 1
                if scan_tracker['null_count'] >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP NULL scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['ports']}")
                    scan_tracker['null_count'] = 0

            # XMAS scan (FIN, PSH, URG flags set)
            elif pkt[TCP].flags == 'FPU':
                scan_tracker['xmas_count'] += 1
                if scan_tracker['xmas_count'] >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP XMAS scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['ports']}")
                    scan_tracker['xmas_count'] = 0

            # ACK scan (only ACK flag set)
            elif pkt[TCP].flags == 'A':
                scan_tracker['ack_count'] += 1
                if scan_tracker['ack_count'] >= SCAN_THRESHOLD:
                    print(f"[!] Possible TCP ACK scan detected targeting {TARGET_IP}!")
                    print(f"    From source: {pkt[IP].src}")
                    print(f"    Ports: {scan_tracker['ports']}")
                    scan_tracker['ack_count'] = 0

        # UDP scan detection
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            scan_tracker['ports'].add(dst_port)
            scan_tracker['udp_count'] += 1

            if scan_tracker['udp_count'] >= SCAN_THRESHOLD:
                print(f"[!] Possible UDP scan detected targeting {TARGET_IP}!")
                print(f"    From source: {pkt[IP].src}")
                print(f"    Ports: {scan_tracker['ports']}")
                scan_tracker['udp_count'] = 0


# Start sniffing
def main():
    print(f"[*] Starting port scan detector for {TARGET_IP}...")
    print("[*] Press Ctrl+C to stop")

    # Set up a BPF filter to only capture traffic destined for the target IP
    ip_filter = f"dst host {TARGET_IP} and (tcp or udp)"

    try:
        sniff(filter=ip_filter, prn=detect_port_scan, store=0)
    except KeyboardInterrupt:
        print("\n[*] Scan detection stopped.")


if __name__ == "__main__":
    main()