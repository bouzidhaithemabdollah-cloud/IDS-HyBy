from scapy.all import sniff,TCP , IP , UDP , ICMP ,packet
import time

def packet_to_dict(pkt ) -> dict | None:
    if IP not in pkt :
        return
    packet_dict={
        "time" : float(pkt.time),
        "src_ip" : pkt[IP].src,
        "dst_ip" : pkt[IP].dst,
        "proto" : None,
        "srcport": None,
        "dstport": None,
        "flag": "",
        "length": len(pkt)
    }
    if TCP in pkt:
        packet_dict.update(proto= "TCP" , srcport =pkt[TCP].sport, dstport=pkt[TCP].dport,flag=str(pkt[TCP].flags) )
    elif UDP in pkt :
        packet_dict.update(proto= "UDP" , srcport =pkt[UDP].sport, dstport=pkt[UDP].dport )
    elif ICMP in pkt:
        packet_dict.update(proto="ICMP")
    else :
        return None
    return packet_dict



################################capture##########################################################

class Capture:
    def __init__(self,interface=None,bpf_filter="ip and (tcp or udp or icmp)",on_packet=print):
        self.interface=interface
        self.bpf_filter=bpf_filter
        self.on_packet=on_packet
        self.seen=0
        self.kept=0
        self.start_time=None
    def _handle(self,pkt):
        self.seen+=1
        d = packet_to_dict(pkt)
        if d is None:
            return
        self.kept+=1
        self.on_packet(d)
    def start(self,count=0):
        self.start_time=time.time()
        try:
             sniff(iface=self.interface, filter=self.bpf_filter,  prn=self._handle, store=False, count=count)
        except KeyboardInterrupt :
            pass
        finally:
             print(self.stats())
    def stats(self):
        duration=max(time.time()- self.start_time , 0.001)
        return {
            "seen":self.seen,
            "kept":self.kept,
            "ignored":self.seen - self.kept,
            "pps":round(self.seen / duration) #how much we treated packet per second
        }


