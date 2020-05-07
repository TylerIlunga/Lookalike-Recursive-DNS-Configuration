# -----------------------------------------------------------
# Lookalike DNS Name Server
# 
# Responsible for receiving the iterative query from the 
# Lookalike Recursive Server and responding with the IP of the machine hosting the site.
# 
# (C) 2020 Tyler Ilunga
# -----------------------------------------------------------

import socketserver
import re
import json
from os import getenv
from threading import currentThread
from sys import byteorder, getsizeof
from time import sleep
from codecs import decode, encode


PORT = getenv("PORT", 56)

DNS_ZONE_MAP = {
    "bing.com": b'\xAC\xD9\x0B\xAE',
    "facebook.com": b'\x97\x65\x81\x8C',
    "uber.com": b'\x0D\x21\xE5\x81',
}


class Connection:
    def __init__(self, socket, ip, port=None, thread=None):
        self.socket = socket
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


def get_qname_data(new_qname, query_type):
    if query_type == 48:
        return (decode(new_qname.strip(), "ascii"), None)

    ip = decode(new_qname.strip(), "ascii")
    ip_hex_chars_list = ["%0.2X" % int(digit) for digit in ip.split(".")]
    print(ip_hex_chars_list)
    ip_hex_chars_string = ' '.join(ip_hex_chars_list)
    print(ip_hex_chars_string)
    new_ip_ba = bytearray.fromhex(ip_hex_chars_string)

    return (ip, new_ip_ba)


def get_domain_to_raw(domain):
    raw_domain_bytes = bytearray()
    for char in domain:
        if char == ".":
            raw_domain_bytes.append(3)
            continue
        raw_domain_bytes += bytes(char, "ascii")

    return bytes(raw_domain_bytes)


def build_answer(qname_as_bytes):
    new_qname = bytearray()
    query_type = 48  # ASCII Zero ==> Standard Query
    for (index, byte) in enumerate(qname_as_bytes):
        if index == 0:
            query_type = byte
            continue
        if index == 1:
            continue
        if byte == 0:
            continue
        if byte != 0 and (byte < 33 or byte > 172):
            new_qname.append(46)  # ASCII period
            continue
        new_qname.append(byte)

    qname_data = get_qname_data(new_qname, query_type)
    dm_ip_tmp_map = {
        qname_data[0]: b'\x00\x00\x00\x00'
    }

    print("dm_ip_tmp_map (pre)", dm_ip_tmp_map)

    for domain_ip_pair in DNS_ZONE_MAP.items():
        print("domain_ip_pair:", domain_ip_pair)
        if query_type == 48:  # Standard Query
            if domain_ip_pair[0] in dm_ip_tmp_map:
                dm_ip_tmp_map[qname_data[0]] = domain_ip_pair[1]
        else:  # Inverse Query
            if domain_ip_pair[1] == qname_data[1]:
                dm_ip_tmp_map[qname_data[0]] = get_domain_to_raw(
                    domain_ip_pair[0])

    print("dm_ip_tmp_map (post)", dm_ip_tmp_map)

    name = qname_as_bytes[1:]
    rdata = dm_ip_tmp_map[qname_data[0]]
    if query_type != 48:
        name = dm_ip_tmp_map[qname_data[0]]
        rdata = qname_data[1]
    print("name, rdata", name, rdata)

    answer = bytearray()
    answer += name  # (name)
    answer += b'\x00\x01'  # IP Address (Type A) (type)
    answer += b'\x00\x01'  # Internet (class)
    answer += b'\x00\x00\x00\x3C'  # 60 seconds(not cached) (ttl)
    answer += b'\x00\x04'  # 2 bytes for IP Addresses (rdlength)
    answer += rdata  # (rdata)

    print("answer:", answer)
    return answer


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class MainHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        try:
            clientConn = Connection(
            self.request[1], self.client_address, None, currentThread())
            print(
                f'Handling {clientConn.getIP()}\'s request on {clientConn.getThread().getName()}')

            qname_as_bytes = self.request[0]
            print("QNAME (bytes)::", qname_as_bytes)

            clientConn.sendData(build_answer(qname_as_bytes))
        except Exception as error:
            msg = f'Name server error raised while handling request: {error}'
            print(msg)
            clientConn.sendData(bytes(msg, 'ascii'))


with ThreadingUDPServer(('', int(PORT)), MainHandler) as server:
    print(f'Name server listening on port {PORT}')
    server.serve_forever()
