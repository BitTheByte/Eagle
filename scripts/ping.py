from utils.status import *
from utils.console import args
import utils.multitask as multitask 
import utils
import os

def pinger(host):
    if utils.isalive(utils.uri(host)):
        return Result(SUCCESS,utils.uri(host),None,None)
    return Result(FAILED,utils.uri(host),None,None)

def ping(hosts,silent=None):

    channel = multitask.Channel('ping')
    if not silent or args.verbose > 2:
        multitask.workers(pinger,channel,utils.console.args.workers, utils.console.pprint )
    else:
        multitask.workers(pinger,channel,utils.console.args.workers)

    for host in hosts:
        channel.append(host)

    channel.wait()
    channel.close()

    if not silent:
        os._exit(0)