from detectors.base import BaseDetector

AUTH_PORTS = {22: "ssh", 21: "ftp", 445: "smb", 3389: "rdp"}

class BruteForceDetector(BaseDetector):
    name="BruteForce"
    def __init__(self,window=10.0,threshold=8):
        super().__init__()
        self.window=window
        self.threshold=threshold
        self.history={}
        self.last_alert={}
    def check(self, flow):
        if flow["dstport"] not in AUTH_PORTS or flow["proto"] != "TCP":
            return None
        if flow["first_flag"] != "S" or flow["packets"] > 30:
            return None
        now=flow["start"]
        key_ips=(flow["src_ip"],flow["dst_ip"],flow["dstport"])
        if key_ips not in self.history:
            self.history[key_ips]=[]
        notebook=self.history[key_ips]
        notebook.append(now)
        cutoff=now - self.window
         #update remove the pais before 10 s
        notebook[:]=[line for line in notebook if line >=cutoff]
        if notebook:
          if len(notebook) >= self.threshold:
              last_time=self.last_alert.get(key_ips)
              if last_time is None or now-last_time >=self.window:
                  self.last_alert[key_ips]=now
                  return {"time": now,#this is an alert
                        "attack": "brute_force",
                        "src_ip": flow["src_ip"],
                        "severity": "high",
                        "detector": self.name,
                        "details": {
                            "dst_ip": flow["dst_ip"],
                            "service" :AUTH_PORTS[flow["dstport"]],
                            "attempts": len(notebook),
                            "window": self.window,
                        }
                        } 
        return None

        

