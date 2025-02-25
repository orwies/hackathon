import argparse
import random
import struct
from datetime import datetime
from scapy.all import *

packet_list = PacketList()


class DNSHeader:
    def __init__(self, id=None, flags=0, num_questions=0, num_answers=0, num_authorities=0, num_additionals=0):
        self.id = id or random.randint(0, 65535)
        self.flags = flags
        self.num_questions = num_questions
        self.num_answers = num_answers
        self.num_authorities = num_authorities
        self.num_additionals = num_additionals


def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def header_to_bytes(header):
    fields = (
        header.id,
        header.flags,
        header.num_questions,
        header.num_answers,
        header.num_authorities,
        header.num_additionals
    )
    return struct.pack("!HHHHHH", *fields)


def build_dns_query(domain_name, record_type=1):
    name = encode_dns_name(domain_name)
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(num_questions=1, flags=RECURSION_DESIRED)
    return header_to_bytes(header) + name + struct.pack("!HH", record_type, 1)


def generate_random_data(size):
    """Generate random binary data with patterns"""
    patterns = [
        lambda x: bytes([random.randint(65, 90)] * x),  # Random uppercase letters
        lambda x: bytes([random.randint(97, 122)] * x),  # Random lowercase letters
        lambda x: bytes([random.randint(48, 57)] * x),  # Random numbers
        lambda x: bytes([random.randint(32, 126)] * x),  # Random printable ASCII
        lambda x: bytes([random.choice([0x00, 0xFF])] * x),  # Alternating 0x00/0xFF
        lambda x: bytes([(i % 256) for i in range(x)]),  # Incrementing sequence
        lambda x: bytes([random.choice([0x00, 0x01])] * x),  # Binary sequence
    ]

    pattern = random.choice(patterns)
    return pattern(size)


def send_random_packet():
    """Send a random packet using UDP, TCP, or DNS protocol."""
    protocols = ['udp', 'tcp', 'dns']
    domains = ['example.com', 'test.com', 'sample.com', 'demo.com']

    # Randomly select protocol and parameters
    protocol = random.choice(protocols)
    domain = random.choice(domains)

    # Choose port based on protocol
    if protocol == 'dns':
        port = 53
    else:
        port = random.randint(1025, 65535)  # Ephemeral ports

    print(f"[{datetime.now().strftime('%H:%M:%S')}]")
    print(f"Protocol: {protocol.upper()}")
    print(f"Port: {port}")
    print(f"Destination: 127.0.0.1:{port}")
    print("-" * 50)

    try:
        packet_size = random.randint(64, 1024)

        if protocol == 'udp':
            # Create UDP packet with random data
            random_data = generate_random_data(packet_size)
            packet = UDP(dport=port) / Raw(load=random_data)
            packet_list.append(packet)
            return True, packet
            print("Random UDP packet sent")

        elif protocol == 'tcp':
            # Create TCP packet with random data
            random_data = generate_random_data(packet_size)
            packet = TCP(dport=port) / Raw(load=random_data)
            packet_list.append(packet)
            return True, packet
            print("Random TCP packet sent")

        elif protocol == 'dns':
            # Create DNS query
            query = build_dns_query(domain)
            packet = UDP(sport=1234, dport=port) / DNS(qd=query)
            packet_list.append(packet)
            return True, packet
            print(f"DNS query sent for {domain}")

    except Exception as e:
        return False, "-"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {e}")

def main():
    for i in range(5):
        parser = argparse.ArgumentParser(description='Send random packets using UDP, TCP, or DNS')
        args = parser.parse_args()
        send_random_packet()

    print("\nPackets captured:")
    for i, packet in enumerate(packet_list):
        print(f"\nPacket #{i}:")
        print(packet.show())


if __name__ == "__main__":
    main()
