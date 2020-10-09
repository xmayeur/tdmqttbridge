#!/usr/bin/env python

import socket

UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

ip = "192.168.0.52"
port = 4098
UDPSock.bind(('', port))

while 1:
    try:
        buf, addr = UDPSock.recvfrom(2048)
    except socket.error:
        print('socket error')
        continue
    print(buf.decode())
