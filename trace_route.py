import os
from socket import *
import struct
import time
import select
from statistics import mean
import sys


class IcmpPacket:
    # ############################################################################################################ #
    # IcmpPacket Class Scope Variables                                                                             #
    # ############################################################################################################ #
    __icmpTarget = ""               # Remote Host
    __destinationIpAddress = ""     # Remote Host IP Address
    __header = b''                  # Header after byte packing
    __data = b''                    # Data after encoding
    __dataRaw = ""                  # Raw string data before encoding
    __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
    __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
    __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
    __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
    __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
    __ipTimeout = 30
    __rtt = 0


    # ############################################################################################################ #
    # IcmpPacket Class Getters                                                                                     #
    # ############################################################################################################ #
    def getIcmpTarget(self):
        return self.__icmpTarget

    def getDataRaw(self):
        return self.__dataRaw

    def getIcmpType(self):
        return self.__icmpType

    def getIcmpCode(self):
        return self.__icmpCode

    def getPacketChecksum(self):
        return self.__packetChecksum

    def getPacketIdentifier(self):
        return self.__packetIdentifier

    def getPacketSequenceNumber(self):
        return self.__packetSequenceNumber

    def getRtt(self):
        return self.__rtt
    # ############################################################################################################ #
    # IcmpPacket Class Setters                                                                                     #
    # ############################################################################################################ #
    def setIcmpTarget(self, icmpTarget):
        self.__icmpTarget = icmpTarget

        # Only attempt to get destination address if it is not whitespace
        if len(self.__icmpTarget.strip()) > 0:
            self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

    def setIcmpType(self, icmpType):
        self.__icmpType = icmpType

    def setIcmpCode(self, icmpCode):
        self.__icmpCode = icmpCode

    def setPacketChecksum(self, packetChecksum):
        self.__packetChecksum = packetChecksum

    def setPacketIdentifier(self, packetIdentifier):
        self.__packetIdentifier = packetIdentifier

    def setPacketSequenceNumber(self, sequenceNumber):
        self.__packetSequenceNumber = sequenceNumber

    def setRTT(self, rtt):
        self.__rtt = rtt
    # ############################################################################################################ #
    # IcmpPacket Class Private Functions                                                                           #
    # ############################################################################################################ #
    def __recalculateChecksum(self):
        packetAsByteData = b''.join([self.__header, self.__data])
        checksum = 0

        # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
        # 16 bit segment will be handled on the upper end of the 32 bit segment.
        countTo = (len(packetAsByteData) // 2) * 2

        # Calculate checksum for all paired segments
        count = 0
        while count < countTo:
            thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
            checksum = checksum + thisVal
            checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
            count = count + 2

        # Calculate checksum for remaining segment (if there are any)
        if countTo < len(packetAsByteData):
            thisVal = packetAsByteData[len(packetAsByteData) - 1]
            checksum = checksum + thisVal
            checksum = checksum & 0xffffffff        # Capture as 32 bit value

        # Add 1's Complement Rotation to original checksum
        checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
        checksum = (checksum >> 16) + checksum              # Rotate and add

        answer = ~checksum                  # Invert bits
        answer = answer & 0xffff            # Trim to 16 bit value
        answer = answer >> 8 | (answer << 8 & 0xff00)

        self.setPacketChecksum(answer)

    def __packHeader(self):
        # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
        # Type = 8 bits
        # Code = 8 bits
        # ICMP Header Checksum = 16 bits
        # Identifier = 16 bits
        # Sequence Number = 16 bits
        self.__header = struct.pack("!BBHHH",
                                self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                )

    def __encodeData(self):
        data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                # time.time() creates a 64 bit value of 8 bytes
        dataRawEncoded = self.getDataRaw().encode("utf-8")

        self.__data = data_time + dataRawEncoded

    def __packAndRecalculateChecksum(self):
        # Checksum is calculated with the following sequence to confirm data in up to date
        self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                            # locations, otherwise, the bit sequences are empty or incorrect.
        self.__encodeData()
        self.__recalculateChecksum()        # Result will set new checksum value
        self.__packHeader()                 # Header is rebuilt to include new checksum value

    # ############################################################################################################ #
    # IcmpPacket Class Public Functions                                                                            #
    #                                                                                                              #
    # ############################################################################################################ #
    def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
        self.setIcmpType(8)
        self.setIcmpCode(0)
        self.setPacketIdentifier(packetIdentifier)
        self.setPacketSequenceNumber(packetSequenceNumber)
        self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        self.__packAndRecalculateChecksum()

    def sendTrace(self):
        print("Tracing route to (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
        if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
            self.setIcmpTarget("127.0.0.1")

        ttl = 1
        cnt = 1
        max_hops = 30
        dest_reached = False
        while (not dest_reached) and (cnt <= max_hops):
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 5
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print(f"{cnt}  *        *        *        *        *    Request timed out.")
                    cnt += 1
                else:
                    recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                    timeReceived = time.time()
                    # Capture RTT
                    self.__rtt = (timeReceived - pingStartTime) * 1000
                    timeLeft = timeLeft - howLongInSelect
                    if timeLeft <= 0:
                        print("  *        *        *        *        *    Request timed out.")                    

                    else:
                        host_name = ''
                        try:
                            host_name = gethostbyaddr(addr[0])[0]
                        except:
                            host_name = addr[0]
                        print(f"{cnt}    {round(self.__rtt)}ms    {addr[0]}  [{host_name}]")
                        dest_reached = str(addr[0]) == self.__destinationIpAddress
                        ttl += 1
                        cnt += 1
                        pass
            except:
                break
            finally:
                mySocket.close()


def main():
    # host = "gaia.cs.umass.edu"
    host = '209.233.126.254'
    # host = 'google.com'
    hostIP = ''
    icmpPacket = IcmpPacket()
    randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                    # Some PIDs are larger than 16 bit
    packetIdentifier = randomIdentifier
    packetSequenceNumber = 1

    icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
    icmpPacket.setIcmpTarget(host)
    icmpPacket.sendTrace()

if __name__ == "__main__":
    main()