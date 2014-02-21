from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import socket, time, random, struct
import matplotlib.pyplot as plt
from matplotlib import figure
from Scan import Scan
from IP import IP


##################################
##################################
class IPScan(Scan):
    def __init__(self, output, filename, start_ip, end_ip):
        Scan(output, filename)
        self.setIPRange(start_ip, end_ip)
        self.active = []
        self.scan()
        self.getReport()

    def setIPRange(self, start_ip, end_ip):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        for i in range(4):
            if start[i] > end[i]:
                start, end = end, start
                break
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        self.ips = ip_range

    def scan(self):
        ICMP_ECHO_REQUEST = 8  
        ICMP_CODE = socket.getprotobyname('icmp')
        timeout = 0.05
        for ip in self.ips:
            try:
                my_socket = socket.socket(socket.AF_INET,
                                          socket.SOCK_RAW,
                                          ICMP_CODE)
            except socket.error as e:
                print e
                continue
            try:
                host = socket.gethostbyname(ip)
            except socket.gaierror:
                continue
            # Maximum for an unsigned short int c object counts to 65535 so
            # we have to sure that our packet id is not greater than that.
            packet_id = int((id(timeout) * random.random()) % 65535)
            packet = self.create_packet(packet_id, ICMP_ECHO_REQUEST)
            sent = my_socket.sendto(packet, (ip, 1))
            packet = packet[sent:]
            delay = self.receive_ping(my_socket,
                                      packet_id,
                                      time.time(),
                                      timeout)
            my_socket.close()
            if delay != None:
                self.active.append(IP(ip))
    
    def getReport(self):
        for ip in self.active:
            print ip
