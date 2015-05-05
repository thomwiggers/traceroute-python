#!/usr/bin/env python
import socket
import os
import sys
import struct
import time
import binascii

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
            recPacket, addr = mySocket.recvfrom(1024)
        except socket.timeout:
            break  # timed out
        timeReceived = time.time()

        # Fetch the ICMPHeader fromt the IP
        print(binascii.hexlify(recPacket))
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

    # ip header
    ip_header_len = 5  # 5x4 bytes if we don't send options
    ip_version = 0x4
    ip_tos = 0x0
    ip_len = socket.htons(36//4)  # total packet length
    ip_id = ID
    ip_offset = 0x0
    ip_ttl = 64
    ip_proto = socket.getprotobyname('icmp')
    ip_checksum = 0x0
    ip_src = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
    ip_dest = socket.inet_aton(destAddr)
    ip_header = struct.pack('BBHHHBBH',
                            (ip_header_len << 4 | ip_version),
                            ip_tos,  # byte
                            ip_len,  # halfword
                            ip_id,   # halfword
                            ip_offset,  # halfword
                            ip_ttl,  # byte
                            ip_proto,  # byte
                            ip_checksum)  # halfword
    ip_header += ip_src + ip_dest
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('BBHHHBBH',
                            (ip_version << 4 | ip_header_len),
                            ip_tos,  # byte
                            ip_len,  # halfword
                            ip_id,   # halfword
                            ip_offset,  # halfword
                            ip_ttl,  # byte
                            ip_proto,  # byte
                            ip_checksum  # halfword
                            ) + ip_src + ip_dest

    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    icmp_header = struct.pack("bbHHh",
                              ICMP_ECHO_REQUEST,  # type (byte)
                              0,                  # code (byte)
                              0,                  # checksum (halfword)
                              ID,                 # ID (halfword)
                              1)                  # sequence (halfword)
    icmp_data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(icmp_header + icmp_data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # htons: Convert 16-bit integers from host to network  byte order
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)
    icmp_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    icmp_packet = icmp_header + icmp_data

    # AF_INET address must be tuple, not str
    print(binascii.hexlify(ip_header))
    mySocket.sendto(ip_header + icmp_packet, (destAddr, 1))


def doOnePing(destAddr, timeout):
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_RAW)
    mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    mySocket.settimeout(timeout)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=5.0):
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


def run():
    """
    Traceroute implementation in Python

    Usage:
        traceroute [options] <host>
        traceroute (-h | --help)

    Options:
        -m,--max-hops=max_ttl   Specifies the maximum number of hops to probe.
        -h,--help               Display this help
        -w,--wait=waittime      Set the time (in seconds) to wait for a
                                response to a probe. (Default 5.0)
    """
    import docopt
    import textwrap
    import os
    args = docopt.docopt(textwrap.dedent(run.__doc__), sys.argv[1:])

    if not os.geteuid() == 0:
        print("You need to be root to run this program!")
        exit(1)

    ping(args['<host>'], float(args['--wait'] or 5.0))


if __name__ == '__main__':
    run()
