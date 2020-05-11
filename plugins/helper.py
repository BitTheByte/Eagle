import utils

class __PluginsManager(object):
    def __init__(self):
        self.loaded = []

    def load(self,instance):
        self.loaded.append(instance)
    
    def unload(self,instance):
        self.loaded.remove(instance)

class Plugin:
    pass

loader = __PluginsManager()