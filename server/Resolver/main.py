# -----------------------------------------------------------
# Lookalike DNS Resolver
# 
# Responsible for forwarding the client's query to Lookalike Recursive Server
#
# USE dig [HOST NAME] @127.0.0.1 +noedns
# Avoids "malformed" packages messages do to EDNS V0
# Due to changes to the original DNS protocol
#
# bing.com A 172.217.11.174(google.com)
# facebook.com A 151.101.129.140(reddit)
# uber.com A 13.33.229.129(lyft)
# 
# (C) 2020 Tyler Ilunga
# -----------------------------------------------------------

import socket
import socketserver
import re
from os import getenv
from threading import currentThread
from sys import byteorder, getsizeof
from codecs import decode, encode

PORT = getenv("PORT", 53)
# Docker: recursive_server
RECURSIVE_SERVER_DOMAIN = getenv("RS_DOMAIN", "localhost")
RECURSIVE_SERVER_PORT = getenv("RS_PORT", 54)


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

            datagram = self.request[0]
            print("Original Datagram (bytes)::", datagram)

            rpConn = Connection(
                None, RECURSIVE_SERVER_DOMAIN, RECURSIVE_SERVER_PORT, currentThread())
            print(
                f'Issuing recursive query to {rpConn.toString()}')

            rpConn.sendData(datagram)
            print(f'Waiting for an UDP response from {rpConn.toString()}')

            dns_message, server = rpConn.getSocket().recvfrom(4096)
            print(
                f'Response received from {rpConn.toString()}: {dns_message}')
            if len(dns_message) == 0:
                return clientConn.sendData(bytes("ERROR: Invalid UDP Size: 0", 'utf-8'))

            rpConn.getSocket().close()
            clientConn.sendData(dns_message)
        except Exception as error:
            msg = f'Resolver error raised while handling request: {error}'
            print(msg)
            clientConn.sendData(bytes(msg, 'ascii'))


with ThreadingUDPServer(('', int(PORT)), MainHandler) as server:
    print(f'Resolver listening on port {PORT}')
    server.serve_forever()
