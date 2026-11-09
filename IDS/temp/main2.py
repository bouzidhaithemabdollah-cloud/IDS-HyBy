
from scapy.all import sniff, IP, IPv6, TCP, ICMP
from colorama import Fore, Style, init
from collections import defaultdict, deque
from time import monotonic
from datetime import datetime

init(autoreset=True)

# Detection thresholds (tune for your lab)
SCAN_WINDOW = 10
SCAN_PORT_THRESHOLD = 15

SYN_WINDOW = 5
SYN_THRESHOLD = 40

ICMP_WINDOW = 5
ICMP_THRESHOLD = 30

# Event history
ports_seen = defaultdict(deque)
syn_seen = defaultdict(deque)
icmp_seen = defaultdict(deque)
last_alert = {}

ALERT_COOLDOWN = 10

def log_alert(kind, src, details):
    now = monotonic()
    key = (kind, src)

    if now - last_alert.get(key, 0) < ALERT_COOLDOWN:
        return

    last_alert[key] = now
    stamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"{Fore.RED}[ALERT] {stamp} | {kind} | "
        f"Source: {src} | {details}{Style.RESET_ALL}"
    )

def prune(events, cutoff):
    while events and events[0][0] < cutoff:
        events.popleft()

def inspect_packet(packet):
    now = monotonic()

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        return

    # Detect TCP port scanning and SYN bursts
    if TCP in packet:
        tcp = packet[TCP]

        # Ignore packets sourced by or destined for this host's
        # common ephemeral ports? No: retain all TCP packets.
        ports = ports_seen[src]
        prune(ports, now - SCAN_WINDOW)

        # Count distinct destination ports, not retransmissions.
        if not any(p == tcp.dport for _, p in ports):
            ports.append((now, tcp.dport))

        unique_ports = {p for _, p in ports}

        if len(unique_ports) >= SCAN_PORT_THRESHOLD:
            log_alert(
                "Possible TCP port scan",
                src,
                f"{len(unique_ports)} destination ports in "
                f"{SCAN_WINDOW}s; latest destination={dst}:{tcp.dport}"
            )

        # SYN set, without ACK, can indicate connection attempts.
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            syns = syn_seen[src]
            prune(syns, now - SYN_WINDOW)
            syns.append((now, dst))

            if len(syns) >= SYN_THRESHOLD:
                log_alert(
                    "Possible SYN flood / SYN burst",
                    src,
                    f"{len(syns)} SYN packets in {SYN_WINDOW}s"
                )

    # Detect unusually frequent IPv4 ICMP packets
    if ICMP in packet:
        events = icmp_seen[src]
        prune(events, now - ICMP_WINDOW)
        events.append((now, dst))

        if len(events) >= ICMP_THRESHOLD:
            log_alert(
                "Possible ICMP burst",
                src,
                f"{len(events)} ICMP packets in {ICMP_WINDOW}s"
            )

print(f"{Fore.CYAN}{'=' * 58}")
print(f"{Fore.CYAN}            MINI NETWORK IDS")
print(f"{Fore.CYAN}{'=' * 58}")
print(f"{Fore.GREEN}[+] Monitoring visible IP traffic")
print(f"{Fore.YELLOW}[+] TCP scan threshold: {SCAN_PORT_THRESHOLD} ports")
print(f"{Fore.YELLOW}[+] SYN threshold: {SYN_THRESHOLD} packets / {SYN_WINDOW}s")
print(f"{Fore.YELLOW}[+] ICMP threshold: {ICMP_THRESHOLD} packets / {ICMP_WINDOW}s")
print(f"{Fore.RED}[!] Ctrl+C to stop{Style.RESET_ALL}")

try:
    sniff(
        filter="ip or ip6",
        prn=inspect_packet,
        store=False
    )
except KeyboardInterrupt:
    print(f"\n{Fore.CYAN}[*] IDS stopped.{Style.RESET_ALL}")
