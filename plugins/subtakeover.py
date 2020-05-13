from utils.status import *
from .helper import Plugin,utils
from dns import resolver
import json
import sys

class TakeOver(Plugin):
    def __init__(self):
        self.name         = "Subdomain Takeover"
        self.enable       = True
        self.description  = ""
        self.fingerprints = json.loads( open(sys.path[0]+"/plugins/files/fingerprints.json","r").read() )

    def presquites(self, host):
        if utils.isalive( utils.uri(host) ):
            return True
        return False

    def vuln(self,host,html):
        answers = resolver.query(host, 'CNAME')
        cnames  = [str(rdata.target) for rdata in answers]
        for fingerprint in self.fingerprints:
            service = fingerprint["service"]
            cname   = fingerprint["cname"]
            text    = fingerprint["fingerprint"]

            for ocname in cnames:
                for c in fingerprint["cname"]:
                    for t in text:
                        if (c in ocname) and (t in html):
                            return [service,ocname,t]

        return None




    def main(self,host):
        request = utils.requests.get(utils.uri(host))
        try:
            result = self.vuln(host,request.text)
        except:
            result = None

        if not result:
            return Result(FAILED,None,None,None)

        return Result(
            status   = SUCCESS,
            msg      = result,
            request  = None,
            response = None
        )
            
