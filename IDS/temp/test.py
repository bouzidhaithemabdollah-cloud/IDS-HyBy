from scapy.all import *
pkt = Ether()/IP(dst="1.1.1.1")/TCP(dport=80)/"GET / HTTP/1.1\r\n\r\n"