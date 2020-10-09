#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Telldus Technologies AB. All rights reserved.
#
# Copyright: See COPYING file that comes with this distribution
#
#

import re
import socket

UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
UDPSock.setblocking(True)
UDPSock.settimeout(3)

UDPSock.bind(('', 42314))
print("Autodiscover TellStick Net...")
UDPSock.sendto(b"D", ('255.255.255.255', 30303))

p = re.compile('(.+):(.+):(.+):(.+)')
ip = None

while 1:
    try:
        (buf, (ip, port)) = UDPSock.recvfrom(2048)
    except socket.error:
        break
    m = p.match(buf.decode())
    print("Found %s on ip %s firmware version %s" % (m.group(1), ip, m.group(4)))
