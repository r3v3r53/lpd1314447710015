# written by Benedikt Waldvogel (mail at bwaldvogel.de)

from __future__ import absolute_import, division, print_function
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import math

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

class YesWeScan:

    found = {}

    def long2net(self, arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))



    def to_CIDR_notation(self, bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            logger.warn("%s is too big. skipping" % net)
            return None
        return net


    def scan_and_print_neighbors(self, net, interface):
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=1, verbose=False)
        a = {}
        for s, r in ans.res:
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line = hostname[0]
            except socket.herror:
                line = ""
                # failed to resolve
                pass
            a[0] = r.sprintf("%Ether.src%")
            a[1] = r.sprintf("%ARP.psrc%")
            a[2] = line
            
            self.found.append(a)


    if __name__ == "__main__":
        for network, netmask, _, interface, address in scapy.config.conf.route.routes:

            # skip loopback network and default gw
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue

            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            net = to_CIDR_notation(network, netmask)

            if interface != scapy.config.conf.iface:
                # see http://trac.secdev.org/scapy/ticket/537
                logger.warn("skipping %s because scapy currently doesn't support arping on non-primary network interfaces", net)
                continue

            if net:
                scan_and_print_neighbors(net, interface)
