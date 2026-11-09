import json
from pathlib import Path

class Replayer:
    def __init__(self,path,on_packet):
        self.path=Path(path)
        self.on_packet=on_packet
    def start(self,limit=None):
        with open(self.path,"r",encoding="utf-8") as f:
            for i ,line in enumerate(f):
                if limit is not None and i >=limit:
                    break
                line=line.strip()
                if not line:
                    continue
                d=json.loads(line)
                self.on_packet(d)