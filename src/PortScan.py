from Scan import Scan
from IP import IP
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
