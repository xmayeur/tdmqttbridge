#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Telldus Technologies AB. All rights reserved.
#
# Copyright: See COPYING file that comes with this distribution
#
#

import socket
import sys

import oyaml

FILE = r'devices.yaml'
devices = oyaml.load(open(FILE, 'r'), Loader=oyaml.Loader)

UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# UDPSock.setblocking(1)
# UDPSock.settimeout(3)

UDPSock.bind(('', 42314))
ip = '192.168.0.52'


# print("Autodiscover TellStick Net...")
# UDPSock.sendto(b"D", ('255.255.255.255', 30303))
#
# p = re.compile('(.+):(.+):(.+):(.+)')
# ip = None
#
# while 1:
#     try:
#         (buf, (ip, port)) = UDPSock.recvfrom(2048)
#     except socket.error:
#         break
#     m = p.match(buf.decode())
#     print("Found %s on ip %s firmware version %s" % (m.group(1), ip, m.group(4)))
#
# print("Send Arctech selflearning turn on to %s" % ip)

# protocol = 'arctech'
# model = 'selflearning'
# house = 8235966
# unit = 2
# method = 2


def send(devices, UDPSock, ip):
    d = devices['AmpliChambre']
    protocol = d['protocol']
    model = d['model']
    house = d['house']
    unit = d['unit']
    method = 1
    msg = "4:sendh8:protocol%X:%s5:model%X:%s5:housei%Xs4:uniti%Xs6:methodi%Xss" % (
        len(protocol), protocol, len(model), model, house, unit, method)
    UDPSock.sendto(bytes(msg, 'utf-8'), (ip, 42314))


def receive(UDPSock, ip):
    while True:
        (buf, (ip, port)) = UDPSock.recvfrom(2048)
        print(buf.decode())


# p1 = multiprocessing.Process(target=send, args=(devices, UDPSock, ip))
# p2 = multiprocessing.Process(target=receive, args=(UDPSock, ip))
#
# p1.start()
# p2.start()

# receive(UDPSock, ip)
send(devices, UDPSock, ip)
sys.exit(0)
