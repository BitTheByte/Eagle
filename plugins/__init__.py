from .helper import loader
from glob import glob
import importlib
import os

def main():
    for plugin in glob("plugins/*.py"):

        path   = plugin.replace("/",".").replace("\\",".").replace(".py",".")[:-1]
        plugin = os.path.basename(plugin).replace(".py","")

        if plugin in ["helper","__init__"]: continue

        lib  = getattr(__import__(path), plugin)
        for sub in dir(lib):
            if "__" in sub: continue
            plugin_class = getattr(lib,sub)
            try:
                if plugin_class.__base__.__name__ == "Plugin":
                    loader.load(plugin_class())
            except:
                pass

if __name__ == "plugins":
    main()