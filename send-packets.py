import socket
import argparse
import random
import struct
from datetime import datetime


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
        port = random.randint(1050, 65535)  # Ephemeral ports

    print(f"[{datetime.now().strftime('%H:%M:%S')}]")
    print(f"Protocol: {protocol.upper()}")
    print(f"Port: {port}")
    print(f"Destination: 127.0.0.1:{port}")
    print("-" * 50)

    try:
        if protocol == 'udp':
            # Send random UDP packet
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            packet_size = random.randint(64, 1024)
            random_data = bytes(random.getrandbits(8) for _ in range(packet_size))
            sock.sendto(random_data, ("127.0.0.1", port))
            print("Random UDP packet sent")

        elif protocol == 'tcp':
            # Send random TCP packet
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect(("127.0.0.1", port))
            packet_size = random.randint(64, 1024)
            random_data = bytes(random.getrandbits(8) for _ in range(packet_size))
            sock.send(random_data)
            print("Random TCP packet sent")

        elif protocol == 'dns':
            # Send DNS query
            query = build_dns_query(domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(query, ("127.0.0.1", port))
            print(f"DNS query sent for {domain}")

        sock.close()

    except socket.error as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Socket Error: {e}")


def main():
    for i in range(5):
        parser = argparse.ArgumentParser(description='Send random packets using UDP, TCP, or DNS')
        args = parser.parse_args()
        send_random_packet()


if __name__ == "__main__":
    main()