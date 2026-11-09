from core.capture import Capture
from colorama import Fore , init , Style
init()

def show(d):
    print( f"{Fore.RED}{d['proto']:4}{Style.RESET_ALL} "
        f"{Fore.BLUE}{d['src_ip']}:{d['srcport']}{Style.RESET_ALL} -> "
        f"{Fore.GREEN}{d['dst_ip']}:{d['dstport']}{Style.RESET_ALL} "
        f"[{d['flag']}] {d['length']}B")
if __name__=="__main__":
    x=int(input("enter the nubmer of packets you wanna do \n"))
    Capture(on_packet=show).start(x)