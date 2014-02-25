from Scan import Scan
from IP import IP
from socket import *
from threading import *

class PortScan(Scan):

    def __init__(self, output, filename, ip, start_port, end_port):
        Scan(output, filename)
        self.screenLock = Semaphore(value=1)
        self.ip = ip
        self.start_port = min(max(0, int(start_port)), 1024)
        self.end_port = min(1024, max(0, int(end_port)))
        self.portScan(self.ip, range(self.start_port, self.end_port))
        pass

    def scan(self):
        print self.ip, self.start_port, "-", self.end_port
        for port in range(self.start_port, self.end_port):
            try:
                connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.oigh
                setdefaulttimeout(3)
                connSkt.connect((self.ip, port))
                print '[+]%d/tcp open'% port
                connSkt.close()
            except:
                pass

    def connScan(self, tgtHost, tgtPort):
        try:
            connSkt = socket(AF_INET, SOCK_STREAM)
            connSkt.connect((tgtHost, tgtPort))
            connSkt.send('ViolentPython\r\n')
            results = connSkt.recv(100)
            self.screenLock.acquire()
            print '[+]%d/tcp open'% tgtPort
            #print '[+] ' + str(results)
        except:
            self.screenLock.acquire()
        finally:
            self.screenLock.release()
            connSkt.close()

    def portScan(self, tgtHost, tgtPorts):
        try:
            tgtIP = gethostbyname(tgtHost)
        except:
            return
        try:
            tgtName = gethostbyaddr(tgtIP)
            print '\n[+] Scan Results for: ' + tgtName[0]
        except:
            print '\n[+] Scan Results for: ' + tgtIP
            setdefaulttimeout(1)
        for tgtPort in tgtPorts:
            self.connScan(tgtHost, tgtPort)
            #t = Thread(target=self.connScan, args=(tgtHost, int(tgtPort)))
            #t.start()
