from utils.status import *
from .helper import Plugin,utils

class SPF(Plugin):
    def __init__(self):
        self.name        = "SPF Record"
        self.enable      = True
        self.description = ""

    def presquites(self, host):
        return True

    def main(self,host):
        request = utils.requests.post('http://spf.myisp.ch/', data= {
            'host': utils.uri(host)
        })

        if "No SPF records found." in request.text:
            return Result(
                status   = SUCCESS,
                msg      = "Target as no SPF Record",
                request  = None,
                response = None
            )
            
        return Result(FAILED,None,None,None)