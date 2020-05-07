# -----------------------------------------------------------
# Lookalike DNS Recursive Server
# 
# Responsible for receiving the recursive query 
# from resolver and issuing iterative queries to the following:
#
# 1) A Lookalike Root Server that responds to the query with the IP of the TLD Name Server (a list of length = 1 for lookalike project)
#
# 2) A Lookalike TLD name Server containing the IP of the machine hosting the site
# 
# (C) 2020 Tyler Ilunga
# -----------------------------------------------------------

import socket
import socketserver
import re
import json
from os import getenv
from threading import currentThread, Timer
from sys import byteorder, getsizeof
from time import sleep
from codecs import decode, encode

PORT = getenv("PORT", 54)
# Docker: root_server
ROOT_SERVER_HOST_IP = getenv("RS_DOMAIN", "localhost")
ROOT_SERVER_PORT = getenv("RS_PORT", 55)
# 60 seconds
CACHE_FLUSH_TIMEOUT = getenv("CACHE_FLUSH_TIMEOUT", 5) 

DNS_ZONE_CACHE = {}

def flush_cache():
    print("flushing cache")
    DNS_ZONE_CACHE.clear()
    Timer(CACHE_FLUSH_TIMEOUT, flush_cache).start()    

def build_response(message, cached, qnameStr):
    res = bytearray(message["header"]["bytes"])
    res += message["question"]["bytes"]
    res += message["answer"] if not cached else DNS_ZONE_CACHE[qnameStr]
    res += message["additional"]  # additional data (edns pseudosection)
    print("response:", res)
    return bytes(res)


def get_proper_qname(qname_as_bytes):
    new_qname = bytearray()
    for (index, byte) in enumerate(qname_as_bytes):
        if (index == 0):
            continue
        if (byte == 0):
            continue
        if (byte != 0 and (byte < 33 or byte > 172)):
            new_qname.append(46)  # ASCII period
            continue
        new_qname.append(byte)
    return decode(new_qname.strip(), "ascii")

class Connection:
    def __init__(self, socketInstance, ip, port=None, thread=None):
        if socketInstance != None:
            self.socket = socketInstance
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = ip
        self.port = port
        self.thread = thread

    def getSocket(self):
        return self.socket

    def getIP(self):
        return self.ip

    def getPort(self):
        return self.port

    def getThread(self):
        return self.thread

    def sendData(self, data):
        if type(self.ip) == tuple:
            return self.socket.sendto(data, self.ip)
        self.socket.sendto(data, (self.ip, int(self.port)))

    def toString(self):
        return f'{self.ip}:{self.port}'


class DNSMessage:
    def __init__(self, byte_msg):
        self.__parse_message(byte_msg)

    def __parse_message(self, byte_msg):
        self.__extract_header(byte_msg[0:12])
        self.__extract_question(byte_msg[12:])

    def __extract_header(self, byte_array):
        print("Header (bytes)::", byte_array)
        message_id = byte_array[0:2]  # 2 bytes
        qrcode = 1  # Query => Response
        opcode = 1 if byte_array[2:3] == b'\x0D' else 0
        aa = 1  # Authoritative Answer
        tc = 0  # Truncate
        rd = 1  # Recursion Desired
        ra = 1  # Recursion Available
        z = 0  # Zeros
        rcode = 0  # Response Code: error will be thrown if one exists

        question_records_count = byte_array[4:6]

        header_as_bytes = bytes(b'')
        # Message ID
        header_as_bytes += message_id
        # QR, OpCode, AA, TC, and RD bits(1000 0101)
        header_as_bytes += b'\x85' if opcode == 0 else b'\x8D'
        # RA, Z, and RCode bits(1000 0000)
        header_as_bytes += b'\x80'  
        # QD Count
        header_as_bytes += question_records_count  
        # ANCount(1 for now)
        header_as_bytes += b'\x00\x01'  
         # NSCount
        header_as_bytes += b'\x00\x00' 
         # ARCount
        header_as_bytes += b'\x00\x00' 

        self.msg_header = {
            "bytes": header_as_bytes,
            "opcode": opcode
        }

    def __extract_question(self, byte_array):
        print("Question (bytes)::", byte_array)
        qname_bytes_offset = 0
        for byte in byte_array:
            if (byte == 0):
                break
            qname_bytes_offset += 8

        qname_bytes_offset = int(qname_bytes_offset // 8)
        qname = byte_array[0:qname_bytes_offset + 1]
        qtype = byte_array[qname_bytes_offset + 1:qname_bytes_offset + 3]
        qclass = byte_array[qname_bytes_offset + 3:qname_bytes_offset + 5]
        aa_records = byte_array[qname_bytes_offset + 5:]

        self.msg_question = {
            "bytes": byte_array,
            "qname": qname,
            "qtype": qtype,
            "qclass": qclass,
        }
        self.msg_authority = b''
        self.msg_answer = b''
        self.msg_additional = aa_records

    def getMessage(self):
        return {
            "header": self.msg_header,
            "question": self.msg_question,
            "answer": self.msg_answer,
            "authority": self.msg_authority,
            "additional": self.msg_additional,
        }


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class MainHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        try:
            rConn = Connection(
            self.request[1], self.client_address, None, currentThread())
            print(
                f'Handling {rConn.getIP()}\'s request on {rConn.getThread().getName()}')

            datagram = self.request[0]
            print("Original Datagram (bytes)::", datagram)

            dns_message = DNSMessage(datagram).getMessage()

            # A) Does the record exist in the Recursive Server's central cache?
            qname_ascii = get_proper_qname(dns_message["question"]["qname"])
            print("qname (ascii):", qname_ascii)
            if qname_ascii in DNS_ZONE_CACHE:
                print("Cache HIT")
                return rConn.sendData(build_response(dns_message, True, qname_ascii))
                
            print("Cache MISS")
            # B) If not, fetch the public IP address of the proper Name Server from the Root Server
            rsConn = Connection(
                None, ROOT_SERVER_HOST_IP, ROOT_SERVER_PORT, currentThread())
            print(
                f'Issuing Root Server IP fetch query to {rsConn.toString()}')

            rsConnData = qname_ascii + f':{str(dns_message["header"]["opcode"])}'
            rsConn.sendData(bytes(rsConnData, 'ascii'))
            print(
                f'Waiting for an UDP response from Root Server ({rsConn.toString()})')

            rsRes, server = rsConn.getSocket().recvfrom(4096)
            print(
                f'Response received from Root Server ({rsConn.toString()}): {rsRes}')
            if len(rsRes) == 0:
                return rConn.sendData(bytes("ERROR: Invalid UDP Size: 0", 'utf-8'))

            rsConn.getSocket().close()

            name_server_address = rsRes.decode("utf-8")
            print(f'name_server_address: {name_server_address}')

            ns_address_split = name_server_address.split(":")
            print("ns_address_split:", ns_address_split)
            if len(ns_address_split) != 2:
                return rConn.sendData(bytes(f'ERROR: Invalid NS Information received: {name_server_address}', 'utf-8'))

            # C) Issue request to Name Server
            nsConn = Connection(
                None, ns_address_split[0], int(ns_address_split[1]), currentThread())
            print(f'Issuing Name Server query to {nsConn.toString()}')

            nsConnData = bytearray(str(dns_message["header"]["opcode"]), 'ascii')
            nsConnData += dns_message["question"]["qname"]
            nsConn.sendData(nsConnData)
            print(
                f'Waiting on an UDP response from our Name Server ({nsConn.toString()})')

            nsRes, server = nsConn.getSocket().recvfrom(4096)
            print(
                f'Response received from {nsConn.toString()}: (answer) {nsRes}')
            if len(nsRes) == 0:
                return rConn.sendData(bytes("ERROR: Invalid UDP Size: 0", 'utf-8'))
            nsConn.getSocket().close()

            # D) Respond to Resolver...
            dns_message["answer"] = nsRes
            DNS_ZONE_CACHE[qname_ascii] = nsRes

            print("dns_message[answer]", dns_message["answer"])

            rConn.sendData(build_response(dns_message, False, None))
        except Exception as error:
            msg = f'Recursive server error raised while handling request: {error}'
            print(msg)
            clientConn.sendData(bytes(msg, 'ascii'))

with ThreadingUDPServer(('', int(PORT)), MainHandler) as server:
    print(f'Recursive server listening on port {PORT}')
    Timer(CACHE_FLUSH_TIMEOUT, flush_cache, None).start()
    server.serve_forever()
