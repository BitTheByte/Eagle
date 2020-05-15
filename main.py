import os
import sys
from base64 import b64encode
from utils.db import JsonDB
from utils.status import *
import utils.multitask as multitask
import utils.console as console

targets  = [x.strip() for x in open(console.args.file,"r").readlines() if x.strip()]
dir_target = os.path.dirname(os.path.realpath(console.args.file))

os.chdir(sys.path[0])
import utils.data as data
import plugins
import scripts
import signal

console.banner( len(plugins.loader.loaded) )
os.chdir(dir_target)
channels = {}
db       = JsonDB(console.args.db)

def onexit(sig,frame):
    for plugin  in plugins.loader.loaded:
        try:
            channels[plugin].close()
        except:
            pass
    os._exit(0)

def dbsave(result):
    res   = result.ret
    host  = result.args[0]
    name  = result.channel.name
    if result.ret == None: return

    console.pprint(result)
    if name not in db.data: db.data[name] = {}

    db.data[name].update({
        host:{
            'status'  : res.status,
            'msg'     : res.msg,
            'response': data.compress(res.response),
            'request' : data.compress(res.request)
        }
    })

    db.save()

def scan(host):
    for plugin in plugins.loader.loaded:
        if not plugin.enable or not plugin.presquites(host):
            continue
        channels[plugin].append(host)

signal.signal(signal.SIGINT, onexit)
console.output(LOG, "checking live targets")
if console.args.ping:
    scripts.ping(targets,silent=False)
else:
    scripts.ping(targets,silent=True)
console.output(LOG, "preformed in-memory save for online targets")


for plugin  in plugins.loader.loaded:
    channel = multitask.Channel(plugin.name)
    channels.update({
        plugin: channel
    })
    multitask.workers(
        target   = plugin.main,
        channel  = channel,
        count    = console.args.workers,
        callback = dbsave
    )


queue = multitask.Channel('scan-queue')
multitask.workers(target=scan,channel=queue,count=console.args.workers)

for target in targets:
    queue.append(target)

queue.wait()
queue.close()

for plugin  in plugins.loader.loaded:
    channels[plugin].wait()

for plugin  in plugins.loader.loaded:
    channels[plugin].close()
