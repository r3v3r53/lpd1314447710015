#!/usr/bin/python

import sys, getopt, argparse
import socket, time, random, struct
import select
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import figure

class Scan:
    def __init__ (self, output, filename):
        self.output = output
        self.filename = ("report." + str(output), filename)[filename != None]

    def create_packet(self, id, icmp):
        header = struct.pack('bbHHh', icmp, 0, 0, id, 1)
        data = 192 * 'Q'
        my_checksum = self.checksum(header + data)
        header = struct.pack('bbHHh', icmp, 0,
                             socket.htons(my_checksum), id, 1)
        return header + data

    def receive_ping(self, my_socket, packet_id, time_sent, timeout):
        time_left = timeout
        while True:
            started_select = time.time()
            ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = time.time() - started_select
            if ready[0] == []: # Timeout
                return
            time_received = time.time()
            rec_packet, addr = my_socket.recvfrom(1024)
            icmp_header = rec_packet[20:28]
            type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
            if p_id == packet_id:
                return time_received - time_sent
            time_left -= time_received - time_sent
            if time_left <= 0:
                return

    def checksum(self, source_string):
        sum = 0
        count_to = (len(source_string) / 2) * 2
        count = 0
        while count < count_to:
            this_val = ord(source_string[count + 1])*256+ord(source_string[count])
            sum = sum + this_val
            sum = sum & 0xffffffff # Necessary?
            count = count + 2
        if count_to < len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer






##################################
##################################
class IPScan(Scan):

    def __init__(self, output, filename, start_ip, end_ip):
        Scan.__init__(output, filename)
        self.setIPRange(start_ip, end_ip)
        self.active = []
        self.scan()

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
        ips = self.ipRange(self.start_ip, self.end_ip)
        for ip in ips:
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
            packet = Scan.create_packet(packet_id, ICMP_ECHO_REQUEST)
            sent = my_socket.sendto(packet, (ip, 1))
            packet = packet[sent:]
            delay = Scan.receive_ping(my_socket,
                                      packet_id,
                                      time.time(),
                                      timeout)
            my_socket.close()
            if delay != None:
                self.active.append(IP(ip))
    
    def genPReport(self):
        print self.ip, "open ports"
        for port in self.ports:
            print port


class PortScan:

    def __init__(self, output, filename, ip, start_port, end_port):
        self.output = output
        self.filename = ("report." + str(output), filename)[filename != None]
        self.ip = ip
        self.start_port = min(max(0, int(start_port)), 1024)
        self.end_port = min(1024, max(0, int(end_port)))
        self.scan()
        pass

    def scan(self):
        print self.ip, self.start_port, "-", self.end_port
        for port in range(self.start_port, self.end_port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    result = sock.connect_ex((self.ip, port))
                    socket.setdefaulttimeout(5)
                    if result == 0:
                        print "Port", port, "\t Open"
           
                except socket.error as f:
                    pass
                sock.close()
            except socket.error as e:
                print e
            
       
class IPScan2:

    def __init__(self, output, filename, start_ip, end_ip):
        self.output = output
        self.filename = ("report." + str(output), filename)[filename != None]
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.active = []
        pass

    def setPorts(self, start_port, end_port):
        self.start_port = min(max(0, int(start_port)), 1024)
        self.end_port = min(1024, max(0, int(end_port)))

    def genReport(self):
        for ip in self.active:
            print ip
       
        if self.output == None:
            return
           
        pdf = PdfPages(self.filename)
        fig = plt.figure()
        fig.patch.set_alpha(0.5)
        pdf.close()


    def portScan(self):
        ICMP_ECHO_REQUEST = 8  
        ICMP_CODE = socket.getprotobyname('icmp')
        timeout = 0.05
        ips = self.ipRange(self.start_ip, self.end_ip)
        try:
            my_socket = socket.socket(socket.AF_INET,
                                          socket.SOCK_RAW,
                                          ICMP_CODE)
        except socket.error as e:
            print e
            return
        try:
            host = socket.gethostbyname(ip)
        except socket.gaierror as e:
            print e

        packet_id = int((id(timeout) * random.random()) % 65535)
        packet = self.create_packet(packet_id, ICMP_ECHO_REQUEST)
        for port in range(self.start_port, self.end_port):
            sent = my_socket.sendto(packet, (ip, port))
            packet = packet[sent:]
            delay = self.receive_ping(my_socket,
                                      packet_id,
                                      time.time(),
                                      timeout)
            my_socket.close()
            if delay != None:
                self.ports.append(port)
        

    def scan(self):
        ICMP_ECHO_REQUEST = 8  
        ICMP_CODE = socket.getprotobyname('icmp')
        timeout = 0.05
        ips = self.ipRange(self.start_ip, self.end_ip)
        for ip in ips:
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
           
    def create_packet(self, id, icmp):
        header = struct.pack('bbHHh', icmp, 0, 0, id, 1)
        data = 192 * 'Q'
        my_checksum = self.checksum(header + data)
        header = struct.pack('bbHHh', icmp, 0,
                             socket.htons(my_checksum), id, 1)
        return header + data

    def receive_ping(self, my_socket, packet_id, time_sent, timeout):
        time_left = timeout
        while True:
            started_select = time.time()
            ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = time.time() - started_select
            if ready[0] == []: # Timeout
                return
            time_received = time.time()
            rec_packet, addr = my_socket.recvfrom(1024)
            icmp_header = rec_packet[20:28]
            type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
            if p_id == packet_id:
                return time_received - time_sent
            time_left -= time_received - time_sent
            if time_left <= 0:
                return

    def checksum(self, source_string):
        sum = 0
        count_to = (len(source_string) / 2) * 2
        count = 0
        while count < count_to:
            this_val = ord(source_string[count + 1])*256+ord(source_string[count])
            sum = sum + this_val
            sum = sum & 0xffffffff # Necessary?
            count = count + 2
        if count_to < len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def ipRange(self, start_ip, end_ip):
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

        return ip_range

class IP:
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return self.address

class Cnt:
    def __init__(self, local_port):
        self.local_port = local_port
        self.ips = {}
        pass
   
    def addIP(self, ip, port):
        pass

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--action",
                        required=True,
                        choices=["ipscan", "portscan", "conscan", "logscan"],
                        help="Perform a scan for ips in a network")
    parser.add_argument("-f", "--filename",
                        required=False,
                        help="Filename to save")
    parser.add_argument("-s", "--start",
                        required=False,
                        help="Port or IP to start")
    parser.add_argument("-e", "--end",
                        required=False,
                        help="Port or IP to end")
    parser.add_argument("-ip",
                        required=False,
                        help="IP to Port Scan")
    parser.add_argument("-g", "--group",
                        required=False,
                        help="How info is to be grouped in the report")
    parser.add_argument("-store", required=False,
                        help="store logs to database")
    parser.add_argument("-o", "--output",
                        required=False,
                        choices=["pdf", "csv"],
                        help="Output file format")
    args = parser.parse_args()
    if args.action == 'ipscan':
        print "Starting scan for IPs"
        scanner = IPScan(args.output, args.filename, args.start, args.end)
        scanner.scan()
        scanner.getReport()
    elif args.action == 'portscan':
        print "Starting Portscan:", args.start, "-", args.end
       
        scanner = IPScan(args.output, args.filename, args.ip, "0.0.0.0")
        scanner.setPorts(args.start, args.end)
        scanner.portScan()
        scanner.genPReport()
if __name__ == "__main__":
   main(sys.argv[1:])
