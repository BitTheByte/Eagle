from utils.status import *
from .helper import Plugin,utils
from urllib.parse import urlparse
import threading
import utils.multitask as multitask

class SensitiveFiles(Plugin):
    def __init__(self):
        self.name        = "Sensitive Files"
        self.enable      = True
        self.description = ""
        self.concurrent  = 12
        self.__files = [
            line.strip()
            for line in open(
                f"{sys.path[0]}/plugins/files/senstivefiles.txt"
            ).readlines()
            if line.strip()
        ]
        self.__lock  = threading.Lock()
        self.__cache = {}
        self.__found = {}

    def presquites(self, host):
        return bool(utils.isalive( utils.uri(host) ))

    def check(self,host,path):
        base_len  = self.__cache[host]['base']
        dummy_len = self.__cache[host]['dummy']
        full      = utils.uri(host) + path
        request   = utils.requests.get(full, verify=False)

        if (
            request.status_code != 200
            or len(request.text.split("\n")) in [base_len, dummy_len]
            or host not in urlparse(request.url).hostname
        ):
            return

        with self.__lock:
            self.__found[host].append(full)

    def main(self,host):
        if host not in self.__cache.keys():
            self.__found.update({host: []})
            self.__cache.update(
                {
                    host: {
                        'base': len(
                            utils.requests.get(
                                utils.uri(host), verify=False
                            ).text.split("\n")
                        ),
                        'dummy': len(
                            utils.requests.get(
                                f"{utils.uri(host)}nofoundfile12345", verify=False
                            ).text.split("\n")
                        ),
                    }
                }
            )

        channel = multitask.Channel(self.name)
        multitask.workers(self.check,channel,self.concurrent)

        for path in self.__files:
            channel.append(host,path)

        channel.wait()
        channel.close()

        if self.__found[host]:
            return Result(
                status   = SUCCESS,
                msg      = self.__found[host],
                request  = None,
                response = None
            )

        return Result(FAILED,None,None,None)
