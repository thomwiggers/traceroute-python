#!/usr/bin/env python
from __future__ import print_function

import socket
import os
import sys
import struct
import time

ICMP_ECHO_REQUEST = 8

DESTINATION_REACHED = 1
SOCKET_TIMEOUT = 2


def checksum(str_):
    str_ = bytearray(str_)
    csum = 0
    countTo = (len(str_) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = str_[count+1] * 256 + str_[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    startTime = time.time()

    while (startTime + timeout - time.time()) > 0:
        try:
            recPacket, (addr, x) = mySocket.recvfrom(1024)
        except socket.timeout:
            break  # timed out
        timeReceived = time.time()

        # Fetch the ICMPHeader fromt the IP
        icmpHeader = recPacket[20:28]

        icmpType, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader)

        if icmpType == 11 and code == 0:
            return (timeReceived - startTime, addr, None)
        elif icmpType == 0 and code == 0:
            return (timeReceived - startTime, addr, DESTINATION_REACHED)

    return (None, None, SOCKET_TIMEOUT)


def sendOnePing(mySocket, destAddr, ID):

    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh",
                         ICMP_ECHO_REQUEST,  # type (byte)
                         0,                  # code (byte)
                         0,                  # checksum (halfword, 2 bytes)
                         ID,                 # ID (halfword)
                         1)                  # sequence (halfword)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # htons: Convert 16-bit integers from host to network  byte order
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    # AF_INET address must be tuple, not str
    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout, ttl):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:
    # http://sock-raw.org/papers/sock_raw

    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    mySocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    mySocket.settimeout(timeout)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def print_part(delay, address, prevaddr):
    if not delay:
        print('*', end=' ', flush=True)
        return

    delay *= 1000
    if not prevaddr == address:
        try:
            host, _, _ = socket.gethostbyaddr(address)
        except:
            host = address

        print('{} ({})  {:.3f} ms'.format(host, address, delay),
              end=' ', flush=True)
    else:
        print(' {:.3f} ms'.format(delay),
              end=' ', flush=True)


def traceroute(host, timeout, maxHops):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is
    # lost
    dest = socket.gethostbyname(host)
    print("traceroute to %s (%s), %d hops max" % (host, dest, maxHops))
    # Send ping requests to a server separated by approximately one second

    for ttl in range(1, maxHops+1):
        print('{:2} '.format(ttl), end=' ', flush=True)

        prevaddr = None
        for i in range(3):
            delay, address, info = doOnePing(dest, timeout, ttl)
            print_part(delay, address, prevaddr)
            prevaddr = address

        print()

        if info == DESTINATION_REACHED:
            break


def run():
    """
    Traceroute implementation in Python 3

    Usage:
        traceroute.py [options] <host>

    Options:
        -h,--max-hops=max_ttl   Specifies the maximum number of hops to probe.
        -w,--wait=waittime      Set the time (in seconds) to wait for a
                                response to a probe. (Default 5.0)
    """
    import docopt
    import textwrap
    import os
    args = docopt.docopt(textwrap.dedent(run.__doc__), sys.argv[1:])

    if not sys.version_info > (3, 4, 0):
        print("You need to use Python 3.4")
        exit(2)

    if not os.geteuid() == 0:
        print("You need to be root to run this program!")
        exit(1)

    traceroute(args['<host>'],
         float(args['--wait'] or 5.0),
         int(args['--max-hops'] or 30))

if __name__ == '__main__':
    run()
