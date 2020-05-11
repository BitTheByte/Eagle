from utils.status import *
from .helper import Plugin,utils
from urllib.parse import urlparse
import tldextract

class FireBase(Plugin):
    def __init__(self):
        self.name        = "Firebase"
        self.enable      = True
        self.description = ""

    def presquites(self, host):
        return True

    def main(self,host):

        mutations = [
            host,
            tldextract.extract(host).domain,
            tldextract.extract(host).domain + "-dev",
            tldextract.extract(host).domain + "-staging",
            tldextract.extract(host).domain + "-test",
            tldextract.extract(host).domain + "-qa",
            tldextract.extract(host).domain + "dev",
            tldextract.extract(host).domain + "staging",
            tldextract.extract(host).domain + "test",
            tldextract.extract(host).domain + "qa",
        ]
        
        for mutated in mutations:
            firebase  = "https://%s.firebaseio.com" % mutated
            
            request_read  = utils.requests.get(firebase + "/.json")
            request_write = utils.requests.put(firebase + "/firebase/security.json",json={
                "msg": "vulnerable"
            })

            if request_read.status_code == 200 and request_write.status_code == 200:
                return Result(
                            status   = SUCCESS,
                            msg      = "%s has read-write enabled" % firebase,
                            request  = utils.dump_request(request_read),
                            response = utils.dump_response(request_read)
                        )
            if request_read.status_code == 200 and request_write.status_code != 200:
                return Result(
                            status   = SUCCESS,
                            msg      = "%s has read enabled" % firebase,
                            request  = utils.dump_request(request_read),
                            response = utils.dump_response(request_read)
                        )
            if request_read.status_code != 200 and request_write.status_code == 200:
                return Result(
                            status   = SUCCESS,
                            msg      = "%s has write enabled" % firebase,
                            request  = utils.dump_request(request_write),
                            response = utils.dump_response(request_write)
                        )
    
        return Result(FAILED,None,None,None)