"""
Run the detector on REAL recordings (.jsonl files made with the Recorder).

    python test_real.py                                  # uses data/normal.jsonl + data/portscan.jsonl
    python test_real.py data/a.jsonl data/b.jsonl        # or your own files

For each file it prints:
  1) a table: how many alerts at different thresholds (useful for the report)
  2) the colored alerts at the default threshold (15)
"""
import json
import sys
from pathlib import Path

from core.flow_builder import FlowBuilder
from core.engine import Engine
from core.alert import AlertSink
from detectors.port_scan import PortScanDetector

DEFAULT_FILES = ["data/normal.jsonl", "data/portscan.jsonl"]
THRESHOLDS = [5, 10, 15, 25]
WINDOW = 10


def read_packets(path):
    """Read one packet dict per line (the 'label' key is ignored)."""
    packets = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                packets.append(json.loads(line))
    packets.sort(key=lambda p: p["time"])
    return packets


def run(packets, threshold, sink=None):
    """Run the pipeline once. Returns (flow_count, alerts)."""
    alerts = []
    flows = [0]

    def on_alert(a):
        alerts.append(a)
        if sink:
            sink(a)

    detector = PortScanDetector(window=WINDOW, threshold=threshold)
    engine = Engine([detector], on_alert=on_alert)

    def on_flow(flow):
        flows[0] += 1
        engine(flow)

    fb = FlowBuilder(on_flow=on_flow, timeout=5.0)
    for p in packets:
        fb.add(p)
    fb.flush()
    return flows[0], alerts


def main(files):
    for path in files:
        print("\n" + "=" * 60)
        if not Path(path).exists():
            print(f"{path}: file not found (record it first)")
            continue

        packets = read_packets(path)
        if not packets:
            print(f"{path}: file is empty")
            continue

        label = packets[0].get("label", "?")
        duration = packets[-1]["time"] - packets[0]["time"]
        n_flows, _ = run(packets, threshold=15)
        print(f"{path} | label: {label} | packets: {len(packets)} | "
              f"flows: {n_flows} | duration: {duration:.1f}s")

        print("\n  threshold -> alerts")
        for th in THRESHOLDS:
            _, alerts = run(packets, threshold=th)
            print(f"  {th:>9} -> {len(alerts)}")

        print("\n  alerts at threshold 15:")
        _, alerts = run(packets, threshold=15, sink=AlertSink())
        if not alerts:
            print("  (none)")


if __name__ == "__main__":
    main(sys.argv[1:] or DEFAULT_FILES)