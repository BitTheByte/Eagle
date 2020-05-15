import json
import os
import sys
import threading

class JsonDB():
    def __init__(self,name):
        if not os.path.isfile(name): open(name,"w").write("{}")
        self.data = json.loads(open(name,'r').read())
        self.__lock = threading.Lock()
        self.__name = name

    def save(self):
        with self.__lock:
            open(self.__name,"w").write(json.dumps(self.data))
