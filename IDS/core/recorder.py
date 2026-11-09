from pathlib import Path
import json

class Recorder :
    def __init__(self,path,label):
         self.path=Path(path)
         self.label=label
         self.path.parent.mkdir(exist_ok=True,parents=True)
         self.f=open(self.path,"a",encoding="utf-8")

    def __call__(self,d :dict):
        d["label"]=self.label
        self.f.write(json.dumps(d) + "\n")
        self.f.flush() #move form mem to hd (file)
    def close(self):
        self.f.close()
        print("\nFinished successfully ")
        