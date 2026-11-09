class FlowBuilder:
    def __init__(self,on_flow=print,timeout=5.0):
        self.on_flow=on_flow
        self.timeout=timeout
        self.flow : dict={}
    def _key(self,d:dict):
         return (d["src_ip"], d["srcport"], d["dst_ip"], d["dstport"], d["proto"])
    def add(self,d:dict):
            self._expire(d["time"])
            key = self._key(d)
            if key not in self.flow:
                self.flow[key] = {
                    "src_ip": d["src_ip"], "srcport": d["srcport"],
                    "dst_ip": d["dst_ip"], "dstport": d["dstport"],
                    "proto": d["proto"],
                    "start": d["time"], "last_seen": d["time"],"first_flag": d["flag"],
                    "packets": 0, "bytes": 0,
                    "syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0,
                }
            f = self.flow[key]
            f["packets"]+=1
            f["bytes"]+=d["length"]
            f["last_seen"]=d["time"] #time.time()
            if "S" in d["flag"]:
                 f["syn"]+=1     
            if "A" in d["flag"]:
                 f["ack"]+=1       
            if "F" in d["flag"]:
                 f["fin"]+=1      
            if "R" in d["flag"]:
                 f["rst"]+=1       
            if "P" in d["flag"]:
                f["psh"]+=1  
            if f["fin"] > 0 or f["rst"] > 0:
               self._close(key) 
    def _close(self,key):#pop the shit from flow dict packet
         f=self.flow.pop(key) #remve the itme
         f["duration"]=f["last_seen"] - f["start"] #add the durtion
         self.on_flow(f) #give the packet to the function that will handle detecting
    def _expire(self, now):#close the still open flows
         expired = []
         for key , f in self.flow.items():
              if (now - f["last_seen"] ) >= self.timeout:
                   expired.append(key)
         for key in expired:
              self._close(key)
    def flush(self):
         for key in list(self.flow):
              self._close(key)



