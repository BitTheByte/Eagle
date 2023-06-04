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
            f"{tldextract.extract(host).domain}-dev",
            f"{tldextract.extract(host).domain}-staging",
            f"{tldextract.extract(host).domain}-test",
            f"{tldextract.extract(host).domain}-qa",
            f"{tldextract.extract(host).domain}dev",
            f"{tldextract.extract(host).domain}staging",
            f"{tldextract.extract(host).domain}test",
            f"{tldextract.extract(host).domain}qa",
        ]

        for mutated in mutations:
            firebase = f"https://{mutated}.firebaseio.com"

            request_read = utils.requests.get(f"{firebase}/.json")
            request_write = utils.requests.put(
                f"{firebase}/firebase/security.json", json={"msg": "vulnerable"}
            )

            if request_read.status_code == 200 and request_write.status_code == 200:
                return Result(
                    status=SUCCESS,
                    msg=f"{firebase} has read-write enabled",
                    request=utils.dump_request(request_read),
                    response=utils.dump_response(request_read),
                )
            if request_read.status_code == 200:
                return Result(
                    status=SUCCESS,
                    msg=f"{firebase} has read enabled",
                    request=utils.dump_request(request_read),
                    response=utils.dump_response(request_read),
                )
            if request_write.status_code == 200:
                return Result(
                    status=SUCCESS,
                    msg=f"{firebase} has write enabled",
                    request=utils.dump_request(request_write),
                    response=utils.dump_response(request_write),
                )

        return Result(FAILED,None,None,None)