# # # # from detectors.base import BaseDetector

# # # # # class Dummy(BaseDetector):
# # # # #     name = "Dummy"
# # # # #     def check(self, flow):
# # # # #         return None

# # # # # print(Dummy().name, Dummy().check({}))

# # # from detectors.port_scan import PortScanDetector
# # # from core.alert import AlertSink

# # # det = PortScanDetector(window=10, threshold=15)
# # # sink = AlertSink()          # بلا ملف، يطبع في الشاشة برك

# # # for i in range(100):
# # #     flow = {"start": i * 0.15, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1",
# # #             "dstport": 1000 + i, "first_flag": "S"}
# # #     alert = det.check(flow)
# # #     if alert:
# # #         sink(alert)
# # from detectors.brute_force import BruteForce

# # def make_flow(t, dstport=22, packets=6, first_flag="S"):
# #     return {
# #         "src_ip": "10.0.0.9", "srcport": 50000,
# #         "dst_ip": "10.0.0.1", "dstport": dstport,
# #         "proto": "TCP", "start": t, "last_seen": t + 0.2,
# #         "first_flag": first_flag, "packets": packets, "bytes": packets * 60,
# #         "syn": 1, "ack": 2, "fin": 1, "rst": 0, "psh": 1, "duration": 0.2
# #     }

# # print("=== 1) Normal long SSH session (150 packets) ===")
# # det = BruteForce(window=10.0, threshold=8)
# # alerts = [a for i in range(10) if (a := det.check(make_flow(t=i, packets=150)))]
# # print(f"alerts: {len(alerts)} | expected: 0 | {'PASS' if len(alerts) == 0 else 'FAIL'}")

# # print("\n=== 2) Fast SSH Brute Force (10 short attempts in 5s) ===")
# # det = BruteForce(window=10.0, threshold=8)
# # alerts = [a for i in range(10) if (a := det.check(make_flow(t=i * 0.5, packets=6)))]
# # print(f"alerts: {len(alerts)} | expected: 1 | {'PASS' if len(alerts) == 1 else 'FAIL'}")

# # print("\n=== 3) Slow retries (1 attempt every 3s) ===")
# # det = BruteForce(window=10.0, threshold=8)
# # alerts = [a for i in range(10) if (a := det.check(make_flow(t=i * 3.0, packets=6)))]
# # print(f"alerts: {len(alerts)} | expected: 0 | {'PASS' if len(alerts) == 0 else 'FAIL'}")


# """
# Tests for BruteForce and Flood detectors (fake flows, no network).

#     python test_detectors.py

# If your files/classes have other names, change ONLY the two import lines below.
# """
# from detectors.brute_force import BruteForceDetector      # <- your module / class name
# from detectors.floods import FloodDetector         # <- your module / class name

# REQUIRED_KEYS = {"time", "attack", "src_ip", "severity", "detector", "details"}


# def make_flow(start, src="10.0.0.9", dst="10.0.0.1", dstport=22, proto="TCP",
#               first_flag="S", packets=8, duration=0.2):
#     return {"src_ip": src, "srcport": 40000, "dst_ip": dst, "dstport": dstport,
#             "proto": proto, "start": start, "last_seen": start + duration,
#             "first_flag": first_flag, "packets": packets, "bytes": packets * 60,
#             "syn": 1, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "duration": duration}


# def alerts_from(detector, flows):
#     return [a for f in flows if (a := detector.check(f))]


# results = []


# def case(name, got, expected):
#     ok = got == expected
#     results.append(ok)
#     print(f"  {'PASS' if ok else 'FAIL'}  {name:<52} got={got} expected={expected}")


# print("\nBruteForce (window=10, threshold=8)")
# bf = lambda: BruteForceDetector(window=10, threshold=8)

# a = alerts_from(bf(), [make_flow(i * 0.25) for i in range(12)])
# case("12 SSH attempts in 3s -> exactly one alert", len(a), 1)
# case("alert has all contract keys", REQUIRED_KEYS.issubset(a[0].keys()) if a else False, True)
# case("non-auth port (8080) -> no alert",
#      len(alerts_from(bf(), [make_flow(i * 0.25, dstport=8080) for i in range(12)])), 0)
# case("12 attempts spread over 60s -> no alert",
#      len(alerts_from(bf(), [make_flow(i * 5.0) for i in range(12)])), 0)
# case("server replies (first_flag SA) -> no alert",
#      len(alerts_from(bf(), [make_flow(i * 0.25, first_flag="SA") for i in range(12)])), 0)
# case("long flows (200 packets) -> no alert",
#      len(alerts_from(bf(), [make_flow(i * 0.25, packets=200) for i in range(12)])), 0)
# case("2 different attackers, 5 attempts each -> no alert",
#      len(alerts_from(bf(), [make_flow(i * 0.25, src=f"10.0.0.{9 + i % 2}") for i in range(10)])), 0)
# mixed = [make_flow(i * 0.2, dstport=p) for i, p in enumerate([22, 21, 3389] * 3)]
# case("9 attempts mixed over ssh+ftp+rdp (3 each) -> no alert", len(alerts_from(bf(), mixed)), 0)

# print("\nFlood (window=5, threshold=1000)")
# fd = lambda: FloodDetector(window=5, threshold=1000)

# a = alerts_from(fd(), [make_flow(0.0, packets=50000, duration=5.0, proto="ICMP", dstport=None)])
# case("one flow of 50000 packets in 5s (icmp/udp flood)", len(a), 1)
# case("alert has all contract keys", REQUIRED_KEYS.issubset(a[0].keys()) if a else False, True)
# case("3000 one-packet SYN flows in 3s -> exactly one alert",
#      len(alerts_from(fd(), [make_flow(i * 0.001, dstport=80, packets=1, duration=0.0) for i in range(3000)])), 1)
# case("long flood flow (100000 packets over 20s) -> alert",
#      len(alerts_from(fd(), [make_flow(0.0, packets=100000, duration=20.0, proto="UDP")])), 1)
# case("normal browsing (25 flows x 10 packets over 10s)",
#      len(alerts_from(fd(), [make_flow(i * 0.4, packets=10, duration=0.3) for i in range(25)])), 0)
# case("normal big download (5000 packets over 60s)",
#      len(alerts_from(fd(), [make_flow(0.0, packets=5000, duration=60.0, dstport=443)])), 0)
# case("3000 one-packet flows spread over 300s",
#      len(alerts_from(fd(), [make_flow(i * 0.1, packets=1, duration=0.0) for i in range(3000)])), 0)
# case("2 sources, 600 SYN flows each in 3s -> no alert",
#      len(alerts_from(fd(), [make_flow(i * 0.0025, src=f"10.0.0.{9 + i % 2}", packets=1, duration=0.0)
#                             for i in range(1200)])), 0)

# print("\nALL PASSED" if all(results) else f"\n{results.count(False)} FAILED")

from detectors.brute_force import BruteForceDetector
from detectors.floods import FloodDetector

def make_flow(t, dstport=22, packets=6, duration=0.2, first_flag="S"):
    return {
        "src_ip": "10.0.0.9", "srcport": 50000,
        "dst_ip": "10.0.0.1", "dstport": dstport,
        "proto": "TCP", "start": t, "last_seen": t + duration,
        "first_flag": first_flag, "packets": packets, "bytes": packets * 60,
        "syn": 1, "ack": 2, "fin": 1, "rst": 0, "psh": 1, "duration": duration
    }

print("=== [BruteForce] 1) Normal long SSH session ===")
bf = BruteForceDetector(window=10.0, threshold=8)
alerts = [a for i in range(10) if (a := bf.check(make_flow(t=i, packets=150)))]
print(f"alerts: {len(alerts)} | expected: 0 | {'PASS' if len(alerts) == 0 else 'FAIL'}")

print("\n=== [BruteForce] 2) Fast SSH Brute Force ===")
bf = BruteForceDetector(window=10.0, threshold=8)
alerts = [a for i in range(10) if (a := bf.check(make_flow(t=i * 0.5, packets=6)))]
print(f"alerts: {len(alerts)} | expected: 1 | {'PASS' if len(alerts) == 1 else 'FAIL'}")

print("\n=== [Flood] 3) Normal long download (1500 pkts in 60s) ===")
fl = FloodDetector(window=5.0, threshold=1000)
a = fl.check(make_flow(t=0.0, dstport=80, packets=1500, duration=60.0))
print(f"alerts: {1 if a else 0} | expected: 0 | {'PASS' if a is None else 'FAIL'}")

print("\n=== [Flood] 4) SYN Flood (25 flows x 50 pkts in 2.5s = 1250 pkts) ===")
fl = FloodDetector(window=5.0, threshold=1000)
alerts = [a for i in range(25) if (a := fl.check(make_flow(t=i * 0.1, dstport=80, packets=50, duration=0.1)))]
print(f"alerts: {len(alerts)} | expected: 1 | {'PASS' if len(alerts) == 1 else 'FAIL'}")