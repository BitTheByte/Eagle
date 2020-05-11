from utils.status import *
from .helper import Plugin,utils

class CRLF(Plugin):
    def __init__(self):
        self.name        = "CRLF Scanner"
        self.enable      = True
        self.description = ""

    def presquites(self, host):
        if utils.isalive( utils.uri(host) ):
            return True
        return False

    def main(self,host):
        for payload in ["%0D%0A", "%E5%98%8A","%E5%98%8D"]:
            for scheme in utils.urlschemes(host):
                poc     = scheme + "://" + host + "/" + payload + "header:crlf"
                request = utils.requests.get(poc)

                for _, value in list(request.headers.items()):
                    if value == "crlf":
                        return Result(
                                status   = SUCCESS,
                                msg      = poc,
                                request  = utils.dump_request(request),
                                response = utils.dump_response(request)
                            )

                if request.history:
                    for history in request.history:
                        for _, value in list(history.headers.items()):
                            if value == "crlf":
                                return Result(
                                    status   = SUCCESS,
                                    msg      = poc,
                                    request  = utils.dump_request(request),
                                    response = utils.dump_response(request)
                                )
            
        return Result(FAILED,None,utils.dump_request(request),utils.dump_response(request))