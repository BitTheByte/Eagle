from utils.status import *
from .helper import Plugin


class MyPlugin(Plugin):
    def __init__(self):
        self.name        = "Example Plugin"
        self.enable      = False
        self.description = ""

    def presquites(self, host):
        return True

    def main(self,host):
        return Result(SUCCESS,"This is test",None,None)