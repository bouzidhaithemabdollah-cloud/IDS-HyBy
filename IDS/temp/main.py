
from scapy.all import sniff, IP, IPv6, TCP
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

HTTPS_PORTS = {443, 8443}

def process_packet(packet):
    if TCP not in packet:
        return

    tcp = packet[TCP]

    if tcp.sport not in HTTPS_PORTS and tcp.dport not in HTTPS_PORTS:
        return

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        return

    if tcp.dport in HTTPS_PORTS:
        direction = f"{Fore.GREEN}OUTGOING{Style.RESET_ALL}"
        arrow = f"{Fore.GREEN}-->{Style.RESET_ALL}"
    else:
        direction = f"{Fore.CYAN}INCOMING{Style.RESET_ALL}"
        arrow = f"{Fore.CYAN}<--{Style.RESET_ALL}"

    timestamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"{Fore.YELLOW}[{timestamp}]{Style.RESET_ALL} "
        f"{direction} "
        f"{Fore.MAGENTA}{src}:{tcp.sport}{Style.RESET_ALL} "
        f"{arrow} "
        f"{Fore.BLUE}{dst}:{tcp.dport}{Style.RESET_ALL} "
        f"{Fore.WHITE}| Flags: {tcp.flags} "
        f"| Size: {len(packet)} bytes{Style.RESET_ALL}"
    )

print(f"{Fore.YELLOW}{'=' * 60}")
print(f"{Fore.CYAN}       HTTPS TRAFFIC SNIFFER")
print(f"{Fore.YELLOW}{'=' * 60}")
print(f"{Fore.GREEN}[+] Sniffing TCP ports 443 and 8443")
print(f"{Fore.RED}[!] Press Ctrl+C to stop{Style.RESET_ALL}")

try:
    sniff(
        filter="tcp and (port 443 or port 8443)",
        prn=process_packet,
        store=False
    )
except KeyboardInterrupt:
    print(f"\n{Fore.RED}[!] Sniffer stopped.{Style.RESET_ALL}")
