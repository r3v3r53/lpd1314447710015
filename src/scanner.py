#!/usr/bin/python
import sys, getopt, argparse
from IPScan import IPScan
from PortScan import PortScan       

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
    elif args.action == 'portscan':
        print "Starting Portscan:", args.start, "-", args.end
       
        scanner = IPScan(args.output, args.filename, args.ip, "0.0.0.0")
        scanner.setPorts(args.start, args.end)
        scanner.portScan()
        scanner.genPReport()
if __name__ == "__main__":
   main(sys.argv[1:])
