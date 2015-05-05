#!/usr/bin/env python
import socket
import os
import sys
import struct
import time

ICMP_ECHO_REQUEST = 8


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
            recPacket, ancdata, flags, (addr, x) = mySocket.recvmsg(1024)
        except socket.timeout:
            break  # timed out
        timeReceived = time.time()
        print(recPacket, ancdata, flags, addr)

        # TODO parse thingy

        # Fetch the ICMPHeader fromt the IP
        icmpHeader = recPacket[20:28]
        TTL = ord(struct.unpack("s", recPacket[8:9])[0])

        icmpType, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader)

        if packetID == ID:
            b = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + b])[0]
            return "Reply from %s: bytes=%d time=%f5ms TTL=%d" % (
                destAddr, len(recPacket), (timeReceived - timeSent)*1000, TTL)

    return "Request timed out."


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


def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:
    # http://sock-raw.org/papers/sock_raw

    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    mySocket.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
    mySocket.settimeout(timeout)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=1.0):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is
    # lost
    dest = socket.gethostbyname(host)
    print("Pinging %s using Python:\n" % dest)
    # Send ping requests to a server separated by approximately one second
    while True:
        delay = doOnePing(dest, timeout)
        print(delay)
        time.sleep(1)  # one second
    return delay


if __name__ == '__main__':
    ping("what.cd")
