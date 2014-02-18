#!/usr/bin/python

import sys, getopt, argparse

class Scanner:
    def __init__(self, output, filename, group):
        self.output = output
        self.filename = filename
        self.group = group
        pass

    def ipscan(self, start_ip, end_ip):
        print "ipscan=", start_ip, end_ip
        pass

    def portscan(self, ip, start_port, end_port):
        print "portscan=", ip, start_port, end_port
        pass

    def conscan(self):
        print "conscan"
        pass

    def logscan(self, log_file, save_to_db):
        print "logscan=", log, save_to_db
        pass

class Ip:
    def __init__(self, address):
        self.address = address

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
    parser.add_argument("-f", required=False,
                        help="Filename to save")
    parser.add_argument("-s", required=False,
                        help="Port or IP to start")
    parser.add_argument("-e", required=False,
                        help="Port or IP to end")
    parser.add_argument("-g", required=False,
                        help="How info is to be grouped in the report")
    parser.add_argument("-store", required=False,
                        help="store logs to database")
    args = parser.parse_args()
    print args
if __name__ == "__main__":
   main(sys.argv[1:])
