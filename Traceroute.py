from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
NUM_PACKETS = 3


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    myChecksum = 0
    myID = os.getpid() & 0xFFFF

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())

    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet


def createSocket(dest, ttl):
    myID = os.getpid() & 0xFFFF
    myChecksum = 0
    header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())

    myChecksum = checksum(header + data)

    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data

    icmp = socket.getprotobyname("icmp")
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL,
                        struct.pack('I', ttl))
    mySocket.sendto(packet, (dest, 0))
    return mySocket


def traceroute(host, timeout=1):
    # Default address
    addr = "127.0.0.1"
    try:
        dest = gethostbyname(host)
    except:
        print("unable to resolve host")
    print("Getting route to " + dest + ":")
    print("")
    timeLeft = timeout
    for ttl in range(1, 128):
        output = str(ttl) + " "
        for i in range(NUM_PACKETS):
            try:
                mySocket = createSocket(dest, ttl)
                mySocket.settimeout(timeout)
                timeSent = time.time()
                startedSelect = time.time()
                # print(timeSent)
                whatReady = select.select([mySocket], [], [], timeLeft)

                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []:
                    output += "*\t"
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                # print(timeReceived)
                t = timeReceived-timeSent
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    output += "*\t"
                    continue

                else:
                    icmpHeader = recvPacket[20:28]
                    icmpType, code, checksum, packetID, sequence = struct.unpack(
                        "BBHHh", icmpHeader)
                    if icmpType == 11:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack(
                            "d", recvPacket[28:28 + bytes])[0]
                        output += " rtt=%.2f ms " % ((t*1000))
                    elif icmpType == 0:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack(
                            "d", recvPacket[28:28 + bytes])[0]
                        output += " rtt=%.2f ms " % (t*1000)
                        return
                    else:
                        print("error")
                        break

                mySocket.close()
            except:
                output += "*\t"
        try:
            output += str(socket.gethostbyaddr(addr[0]))
        except:
            output += str(addr[0])
        print(output)


if __name__ == '__main__':
    traceroute("google.com")
    print("=========")
    traceroute("cs.columbia.edu")
    print("=========")
    traceroute("cnn.com")
    print("=========")
    traceroute("stanford.edu")
