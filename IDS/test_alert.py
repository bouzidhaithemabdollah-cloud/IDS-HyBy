# from core.alert import AlertSink

# alert = {"time": 12.5, "attack": "port_scan", "src_ip": "10.0.0.9",
#          "severity": "high", "detector": "PortScan",
#          "details": {"unique_ports": 18, "window": 10}}

# s = AlertSink()      
# s(alert)
# s.close()


from core.engine import Engine
from core.alert import AlertSink
from detectors.base import BaseDetector


class Always(BaseDetector):
    name = "Always"
    def check(self, flow):
        return {"time": flow["start"], "attack": "test", "src_ip": flow["src_ip"],
                "severity": "low", "detector": self.name, "details": {}}


class Never(BaseDetector):
    name = "Never"
    def check(self, flow):
        return None


flow = {"start": 1.0, "src_ip": "1.1.1.1"}

Engine([Always(), Never()], on_alert=AlertSink())(flow)