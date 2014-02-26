from IP import IP
from Connection import Connection

con = Connection("pedro", "moreira")

um = IP(id=6, address="192.168.1.1")
dois = IP(id=10, address="0.0.0.0")

con.add(um)
con.add(dois)
con.add(IP(address="000"))
con.commit

print um.address
