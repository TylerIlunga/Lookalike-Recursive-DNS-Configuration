# -----------------------------------------------------------
# Lookalike DNS Root Server
# 
# Responsible for receiving the iterative query from the
# Lookalike Recursive Server and responding with the IP of the Lookalike Name Server.
# 
# (C) 2020 Tyler Ilunga
# -----------------------------------------------------------

import socketserver
import re
from os import getenv
from threading import currentThread
from sys import byteorder, getsizeof
from time import sleep
from codecs import decode, encode

PORT = getenv("PORT", 55)
# Docker: name_server
NAME_SERVER_DOMAIN = getenv("NS_DOMAIN", "localhost")
NAME_SERVER_PORT = getenv("NS_PORT", "56")
DEFAULT_NAME_SERVER = f'{NAME_SERVER_DOMAIN}:{NAME_SERVER_PORT}'

DOMAIN_NS_MAP = {
    "bing.com": DEFAULT_NAME_SERVER,
    "facebook.com":  DEFAULT_NAME_SERVER,
    "uber.com":  DEFAULT_NAME_SERVER,
}

IP_NS_MAP = {
    "172.217.11.174": DEFAULT_NAME_SERVER,
    "151.101.129.140": DEFAULT_NAME_SERVER,
    "13.33.229.129": DEFAULT_NAME_SERVER
}


def getMapMissErrorMessage(query_type):
    source = "DOMAIN" if query_type == 0 else "IP"
    return bytes(f'ERROR: {source} does not exist within NS index.', 'utf-8')


def getNSRecord(dis_split):
    ns_map = DOMAIN_NS_MAP if dis_split[1] == '0' else IP_NS_MAP
    return bytes(ns_map[dis_split[0]], 'utf-8')


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

            domain_ip_str = str(self.request[0], 'ascii')
            print(f'domain_ip_str::{domain_ip_str}')
            dis_split = domain_ip_str.split(":")
            print("dis_split:", dis_split)
            if len(dis_split) != 2:
                return clientConn.sendData(bytes(f'ERROR: Invalid request format from client ({clientConn.toString()})', 'utf-8'))

            if dis_split[1] == '0':  # Standard Query
                if dis_split[0] not in DOMAIN_NS_MAP:
                    return clientConn.sendData(getMapMissErrorMessage(0))
            else: # Inverse Query
                if dis_split[0] not in IP_NS_MAP:
                    return clientConn.sendData(getMapMissErrorMessage(1))

            print(f'Sending over requested Name Server data: {dis_split[0]}')
            clientConn.sendData(getNSRecord(dis_split))
        except Exception as error:
            msg = f'Root server error raised while handling request: {error}'
            print(msg)
            clientConn.sendData(bytes(msg, 'ascii'))


with ThreadingUDPServer(('', int(PORT)), MainHandler) as server:
    print(f'Root server listening on port {PORT}')
    server.serve_forever()
