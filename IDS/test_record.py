from core.capture import Capture
from core.recorder import Recorder   

rec = Recorder("data/normal.jsonl", "normal")
try:
    Capture(on_packet=rec).start()
finally:
    rec.close()
from core.replayer import Replayer
from run_capture import show

Replayer("data/normal.jsonl", on_packet=show).start(limit=5)
from core.flow_builder import FlowBuilder

p1 = {"time": 0.00, "src_ip": "10.0.0.5", "dst_ip": "20.1.1.1", "proto": "TCP",
      "srcport": 49671, "dstport": 443, "flag": "S", "length": 66}
reply = {"time": 0.01, "src_ip": "20.1.1.1", "dst_ip": "10.0.0.5", "proto": "TCP",
         "srcport": 443, "dstport": 49671, "flag": "SA", "length": 66}

if __name__ == "__main__":
    fb = FlowBuilder(on_flow=print)
    fb.add(p1)
    fb.add(reply)
    fb.flush()




# from detectors.port_scan import PortScanDetector

# def fake(t, port, src="10.0.0.9", dst="10.0.0.1", first="S"):
#     return {"start": t, "src_ip": src, "dst_ip": dst,
#             "dstport": port, "first_flag": first}

# def run(flows):
#     det = PortScanDetector(window=10, threshold=15)
#     return [a for f in flows if (a := det.check(f))]

# print("scan       :", len(run([fake(i * 0.15, 1000 + i) for i in range(20)])))
# print("same port  :", len(run([fake(i * 0.15, 443) for i in range(20)])))
# print("slow       :", len(run([fake(i * 3.0, 1000 + i) for i in range(20)])))
# print("replies    :", len(run([fake(i * 0.15, 1000 + i, first="SA") for i in range(20)])))
# print("20 targets :", len(run([fake(i * 0.15, 1000 + i, dst=f"10.0.0.{i}") for i in range(20)])))