from detectors.base import BaseDetector

class FloodDetector(BaseDetector):
    name="Flood"
    def __init__(self,window=5.0,threshold=1000):
        super().__init__()
        self.window=window
        self.threshold=threshold
        self.history={}
        self.last_alert={}
    def check(self, flow):
        now=flow["start"]
        key_ips=(flow["src_ip"],flow["dst_ip"])
        if key_ips not in self.history:
            self.history[key_ips]=[]
        notebook=self.history[key_ips]
        duration = flow["duration"]
        if duration > self.window:
            weight=flow["packets"] * self.window/duration
        else:
            weight =flow["packets"]
        notebook.append((now,weight))
        cutoff=now-self.window
        notebook[:]=[line for line in notebook if line[0] >=cutoff]
        total_num_packets=sum(line[1] for line in notebook )
        if total_num_packets >= self.threshold:
            last_time=self.last_alert.get(key_ips)
            if last_time is None or now-last_time >=self.window:
                self.last_alert[key_ips]=now
                return {"time": now,#this is an alert
                        "attack": "flood",
                        "src_ip": flow["src_ip"],
                        "severity": "high",
                        "detector": self.name,
                        "details": {
                            "dst_ip": flow["dst_ip"],
                            "packets_in_window": round(total_num_packets) ,
                            "window": self.window,
                        }
                        } 
        return None

        


