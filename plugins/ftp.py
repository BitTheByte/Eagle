from utils.status import *
from .helper import Plugin,utils
from utils.decorators import OnErrorReturnValue
import ftplib
import socket

class FTP(Plugin):
    def __init__(self):
        self.name        = "Anonymous FTP "
        self.enable      = True
        self.description = ""

    def presquites(self, host):
        return True

    @OnErrorReturnValue(Result(FAILED,None,None,None))
    def main(self,ftphost):
        
        ftp = ftplib.FTP(host=socket.gethostbyname(ftphost),timeout=10)
        ftp.login('anonymous', 'anonymous')

        return Result(
            status   = SUCCESS,
            msg      = 'FTP anonymous login is enabled',
            request  = None,
            response = None
        )