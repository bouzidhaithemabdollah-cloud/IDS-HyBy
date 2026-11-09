from detectors.base import BaseDetector

class PortScanDetector(BaseDetector):
    name="PortScan"
    def __init__(self,window=10.0,threshold=15):
        super().__init__()
        self.window=window
        self.threshold=threshold
        self.history={}
        self.last_alert={}
    def check(self, flow):
        if flow["first_flag"] != "S":
            return None
        t=flow["start"]
        key_ips=(flow["src_ip"],flow["dst_ip"])
        if key_ips not in self.history:
            self.history[key_ips]=[]
        notebook=self.history[key_ips]
        notebook.append((t,flow["dstport"]))
        cutoff=t-self.window
        notebook[:]=[line for line in notebook if line[0] >=cutoff]
        ports={line[1] for line in notebook }
        if ports:
          if len(ports) >= self.threshold:
              last_time=self.last_alert.get(key_ips)
              if last_time is None or t-last_time >=self.window:
                  self.last_alert[key_ips]=t
                  return {"time": t,#this is an alert
                        "attack": "port_scan",
                        "src_ip": flow["src_ip"],
                        "severity": "high",
                        "detector": self.name,
                        "details": {
                            "dst_ip": flow["dst_ip"],
                            "unique_ports": len(ports),
                            "window": self.window,
                        }
                        } 
        return None

        



# cutoff = t - self.window
# notebook[:] = [line for line in notebook if line[0] >= cutoff]