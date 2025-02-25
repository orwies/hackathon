import sys
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
from scapy.layers.inet import *
sys.stdin, sys.stdout, sys.stderr = i, o, e
import csv


def packets_to_csv(packet_list, csv_filename):
    """
    Convert a list of Scapy packets to a CSV file

    :param packet_list: List of Scapy packet objects
    :param csv_filename: Output CSV filename
    """
    # Define the fields you want to extract from each packet
    # Adjust these based on what information you need
    with open(csv_filename, 'w', newline='') as csvfile:
        # Create CSV writer
        csv_writer = csv.writer(csvfile)

        # Write the header row
        csv_writer.writerow([
            'Time', 'Source IP', 'Destination IP', 'Protocol',
            'Source Port', 'Destination Port', 'Length', 'TCP Flags',
            'ICMP Type', 'ICMP Code'
        ])

        # Process each packet
        for packet in packet_list:
            # Initialize variables
            timestamp = packet.time
            src_ip = dst_ip = protocol = src_port = dst_port = length = tcp_flags = icmp_type = icmp_code = "N/A"

            # Extract basic IP information if present
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                length = len(packet)
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                protocol = packet[IPv6].nh
                length = len(packet)

            # Extract transport layer information if present
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_flags = packet[TCP].flags
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code

            # Write the row for this packet
            csv_writer.writerow([
                timestamp, src_ip, dst_ip, protocol,
                src_port, dst_port, length, tcp_flags,
                icmp_type, icmp_code
            ])

    print(f"Successfully wrote {len(packet_list)} packets to {csv_filename}")



def create_files(traffic):
    """
    sniffs the traffic on a ip and creating pcap file and csv file of the traffic
    :param target_ip: the required ip
    :param sniff_count: the size of the traffic
    :return: void. creates pcp and csv files
    """
    packets_to_csv(traffic, 'traffic_csv.csv')
    wrpcap('traffic_pcap.pcap', traffic)


if __name__ == "__main__":
    traffic =
    create_files(traffic)

