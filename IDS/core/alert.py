from pathlib import Path
import json
from colorama import Fore , init , Style
init()


class AlertSink:
    def __init__(self,path=None):
            self.f=None
            if path is None:
                return
            else:
                self.path=Path(path)
                self.path.parent.mkdir(exist_ok=True,parents=True)
                self.f=open(self.path,"a",encoding="utf-8")
    def display(self,d):
          print(f"{Fore.RED}[ALERT]{Style.RESET_ALL}"+
                "  " +
                f"{Fore.YELLOW}{d['attack']:10}{Style.RESET_ALL}" + " | "+
                f"src :{Fore.BLUE}{d["src_ip"]:10}{Style.RESET_ALL}"
                + f"| severity : {d["severity"]}")         
    def __call__(self,alert):
          self.display(alert)
          if self.f:
            self.f.write(json.dumps(alert) +"\n")
            self.f.flush()
    def close(self):
          if self.f:
           self.f.close()



