# -----------------------------------------------------------
# Lookalike DNS client
#
# Responsible for buildng, and/or sending, the DNS message
# query and redirected the response back to the issuer.
#
# Examples of valid bytes for queries
#
# 1) Standard Query
# 2dd1012000010000000000010462696e6703636f6d00000100010000291000000000000000 (bing)
# b121012000010000000000010866616365626f6f6b03636f6d00000100010000291000000000000000 (facebook)
# a38301200001000000000001047562657203636f6d00000100010000291000000000000000(uber)
#
# 2) Inverse Query
# 55750120000100000000000103313732033231370231310331373400000100010000291000000000000000 (172.217.11.174)
# b3a5012000010000000000010331353103313031033132390331343000000100010000291000000000000000 (151.101.129.140)
# 3ed201200001000000000001023133023333033232390331323900000100010000291000000000000000 (13.33.229.129)
#
# (C) 2020 Tyler Ilunga
# -----------------------------------------------------------


import sys
import socket
import argparse
from binascii import hexlify, unhexlify
from codecs import encode
from random import randint


class Connection:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = None

    def getIp(self):
        return self.ip

    def getPort(self):
        return self.port

    def setSocket(self, socket):
        self.socket = socket

    def getSocket(self):
        return self.socket

    def toString(self):
        return f'{self.ip}:{self.port}'


def handle_options(sock, args):
    print("handle_options():")
    try:
        conn = Connection(args.host, int(args.port))

        print("Choose a query type:\n\n[0] Standard Query\n[1] Inverse Query")
        query_type = int(sys.stdin.readline().strip())
        if (query_type != 0 and query_type != 1):
            raise ValueError("INVALID query type given")

        print("Choose DNS message input format[NUM]:\n[0] Bytes\n[1] String")
        input_format = int(sys.stdin.readline().strip())
        if (input_format != 0 and input_format != 1):
            raise ValueError("INVALID input Format given")
        if (input_format == 0):
            return handle_dns_message_bytes(sock, conn)

        handle_dns_message_stdin(sock, conn, query_type)
    except Exception as e:
        print(f'ERROR: Invalid input given.\n {e}')
        handle_options(sock, args)


def handle_dns_message_bytes(sock, conn):
    while True:
        print("Enter a valid dns message below(bytes):")
        line = sys.stdin.readline().strip()
        if not line:
            print("INVALID input: Please enter a value")
        else:
            send_dns_query(sock, conn, line)


def handle_dns_message_stdin(sock, conn, query_type):
    while True:
        domain, tld, ip = None, None, None

        if (query_type == 0):
            print("Enter a domain name[not Top Level Domain!] below:")
            domain = sys.stdin.readline().strip()
            if not domain:
                print("Please provide a domain name.")
            else:
                print("Enter a top level domain below [ex: com]:")
                tld = sys.stdin.readline().strip()
                if not tld:
                    print(
                        "Please provide a top level domain (TLD) such as 'com'")
                else:
                    send_dns_query(sock, conn, build_dns_query(query_type, (domain, tld), ip))
        else:
            print("Enter the host (IP) address assigned to the target machine below:")
            ip = sys.stdin.readline().strip()
            if (not ip):
                print(
                    "Please provide the host (IP) address assigned to the target machine.")
            else:
                send_dns_query(sock, conn, build_dns_query(query_type, (domain, tld), ip))

        


def generate_id():
    id = ""
    for num in range(4):
        id += str(hex(randint(0, 15)))[2:]
    print("generated_id:", id)
    return id


def build_dns_query(query_type, domain_tld, ip):
    query = ""
    qname_hex = ""
    EOT = "03"  # End of Text

    if query_type == 0:
        qname_hex = str(hexlify(encode(
            domain_tld[0])), 'ascii') + EOT + str(hexlify(encode(domain_tld[1])), 'ascii')
    else:
        qname_hex = str(hexlify(encode(ip)), 'ascii')

    print("qname_hex:", qname_hex)

    # **HEADER**
    # ID (should generate)
    query += generate_id()  # 16 bits
    # QR (0), OpCode(0000 || 0001), AA(1), TC(0), RD(1)
    query += "05" if query_type == 0 else "0D"
    # RA(1) Z(000) RCode(0000)
    query += "80"
    # query += "20"
    # QDCOUNT
    query += "0001"
    # ANCOUNT
    query += "0000"
    # NSCOUNT
    query += "0000"
    # ARCOUNT
    query += "0001"
    query += "08"
    # **QUESTION**
    # QNAME
    # "The domain name terminates with the
    # zero length octet for the null label of the root."
    query += (qname_hex + "00")
    # QTYPE
    query += "0001"
    # QCLASS
    query += "0001"
    # **OPT (Additional) RR (EDNS0)**
    # OPTION-CODE
    query += "0000"
    # OPTION-LENGTH
    query += "2910"
    # OPTION-DATA
    query += "00000000000000"

    print("query (string):", query)
    return query


def send_dns_query(sock, conn, data):
    # Send data
    print(f'Sending "{data}" to ({conn.toString()})')
    try:
        sock.settimeout(5)  # 5 second request timeout
        sent = sock.sendto(bytearray.fromhex(
            data), (conn.getIp(), conn.getPort()))
        print("Waiting for response...")
        rdata, server = sock.recvfrom(4096)  # Receive response
        print(f'Response received from {conn.toString()}: {rdata}')
        if len(rdata) == 0:
            raise ValueError("Response received contains no data (bytes)")
    except Exception as error:
        raise ValueError(
            f'Raised while attempting to send "{data}" to ({conn.toString()}): {error}')


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    parser = argparse.ArgumentParser(
        description="Lookalike Recursive DNS Client")
    parser.add_argument('host', metavar="host", type=str,
                        help="Host Address of the target DNS resolver machine.")
    parser.add_argument('port', metavar="port", type=int,
                        help="Open port of the target DNS resolver process.")

    handle_options(sock, parser.parse_args())
