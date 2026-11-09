import argparse
from core.flow_builder import FlowBuilder
from core.engine import Engine
from core.alert import AlertSink
from core.capture import Capture
from core.replayer import Replayer
from detectors.port_scan import PortScanDetector
from detectors.brute_force import BruteForceDetector
from detectors.floods import FloodDetector
from colorama import Fore, Style, init

init()


def build_pipeline(alert_path=None):
    sink = AlertSink(alert_path)
    detectors = [PortScanDetector(), FloodDetector(), BruteForceDetector()]
    engine = Engine(detectors=detectors, on_alert=sink)
    flowbuilder = FlowBuilder(on_flow=engine)
    return flowbuilder, sink

def show(d):
    print(
        f"{Fore.RED}{d['proto']:4}{Style.RESET_ALL} "
        f"{Fore.BLUE}{d['src_ip']}:{d['srcport']}{Style.RESET_ALL} -> "
        f"{Fore.GREEN}{d['dst_ip']}:{d['dstport']}{Style.RESET_ALL} "
        f"[{d['flag']}] {d['length']}B"
    )


def run_live(iface, alert_path, limit=0, show_pkt=False):
    fb, sink = build_pipeline(alert_path)

    def handle(d):
        if show_pkt:
            show(d)
        fb.add(d)

    try:
        Capture(interface=iface, on_packet=handle).start(count=limit)
    finally:
        fb.flush()
        sink.close()


def run_replay(path, alert_path, show_pkt=False):
    fb, sink = build_pipeline(alert_path)

    def handle(d):
        if show_pkt:
            show(d)
        fb.add(d)

    try:
        Replayer(path, on_packet=handle).start()
    finally:
        fb.flush()
        sink.close()
import pyfiglet

if __name__ == "__main__":
    banner = pyfiglet.figlet_format("HyBu IDS", font="isometric1")
    print(Fore.CYAN + banner + Style.RESET_ALL)
    parser = argparse.ArgumentParser(description="HyBu IDS")

    parser.add_argument("--live", action="store_true", help="Run live capture")
    parser.add_argument("--replay", type=str, help="Path to .jsonl file to replay")
    parser.add_argument("--iface", type=str, default=None, help="Network interface")
    parser.add_argument("--alerts", type=str, default="data/alerts.jsonl", help="Alerts file")
    parser.add_argument("--limit", type=int, default=0, help="Max packets to capture (0 = unlimited)")
    parser.add_argument("--show", action="store_true", help="Show sniffed traffic in the terminal")

    args = parser.parse_args()

    if args.replay:
        run_replay(args.replay, args.alerts, args.show)
    elif args.live:
        run_live(args.iface, args.alerts, args.limit, args.show)
    else:

        parser.print_help()