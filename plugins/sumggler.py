from urllib.parse import urlparse
from base64 import b64encode
from .helper import Plugin
from utils.status import *
import utils.multitask as multitask
import utils.data as data
import threading
import socket
import utils
import json
import time
import ssl


MAX_EXCEPTION = 10
MAX_VULNERABLE = 5

t_base_headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/60.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'close',
    'Content-Length': '0',
}

t_attacks_datas = [
    {'name':'CL:TE1', 'Content-Length':5, 'body':'1\r\nZ\r\nQ\r\n\r\n'},
    {'name':'CL:TE2', 'Content-Length':11, 'body':'1\r\nZ\r\nQ\r\n\r\n'},
    {'name':'TE:CL1', 'Content-Length':5, 'body':'0\r\n\r\n'},
    {'name':'TE:CL2', 'Content-Length':6, 'body':'0\r\n\r\nX'},
]

t_registered_method = [
    #'tabprefix1',
    #'vertprefix1',
    #'underjoin1',
    #'underscore2',
    #'space2',
    #'chunky',
    #'bodysplit',
    #'zdsuffix',
    #'tabsuffix',
    #'UPPERCASE',
    #'reversevanilla',
    #'spaceFF',
    #'accentTE',
    #'accentCH',
    #'unispace',
    #'connection',
    'vanilla',
    'dualchunk',
    'badwrap',
    'space1',
    'badsetupLF',
    'gareth1',
    'spacejoin1',
    'nameprefix1',
    'valueprefix1',
    'nospace1',
    'commaCow',
    'cowComma',
    'contentEnc',
    'linewrapped1',
    'quoted',
    'aposed',
    'badsetupCR',
    'vertwrap',
    'tabwrap',
    'lazygrep',
    'multiCase',
    'zdwrap',
    'zdspam',
    'revdualchunk',
    'nested',
    'spacefix1_0',
    'spacefix1_9',
    'spacefix1_11',
    'spacefix1_12',
    'spacefix1_13',
    'spacefix1_127',
    'spacefix1_160',
    'spacefix1_255',
    'prefix1_0',
    'prefix1_9',
    'prefix1_11',
    'prefix1_12',
    'prefix1_13',
    'prefix1_127',
    'prefix1_160',
    'prefix1_255',
    'suffix1_0',
    'suffix1_9',
    'suffix1_11',
    'suffix1_12',
    'suffix1_13',
    'suffix1_127',
    'suffix1_160',
    'suffix1_255',
]

class SmugglerAttacks:
    def update_content_length(self, msg, cl ):
        return msg.replace( 'Content-Length: 0', 'Content-Length: '+str(cl) )

    def underjoin1(self, msg):
        msg = msg.replace( 'Transfer-Encoding', 'Transfer_Encoding' )
        return msg
    
    def underscore2(self, msg):
        msg = msg.replace( 'Content-Length', 'Content_Length' )
        return msg

    def spacejoin1(self, msg):
        msg = msg.replace( 'Transfer-Encoding', 'Transfer Encoding' )
        return msg
    
    def space1(self, msg):
        msg = msg.replace( 'Transfer-Encoding', 'Transfer-Encoding ' )
        return msg
    
    def space2(self, msg):
        msg = msg.replace( 'Content-Length', 'Content-Length ' )
        return msg

    def nameprefix1(self, msg):
        msg = msg.replace( 'Transfer-Encoding', ' Transfer-Encoding' )
        return msg

    def valueprefix1(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:  ' )
        return msg

    def nospace1(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:' )
        return msg

    def tabprefix1(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:\t' )
        return msg

    def vertprefix1(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:\u000B' )
        return msg

    def commaCow(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked, identity' )
        return msg

    def cowComma(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: identity, ' )
        return msg

    def contentEnc(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Content-Encoding: ' )
        return msg

    def linewrapped1(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:\n' )
        return msg

    def gareth1(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding\n : ' )
        return msg

    def quoted(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: "chunked"' )
        return msg

    def aposed(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', "Transfer-Encoding: 'chunked'" )
        return msg

    def badwrap(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Foo: bar' )
        msg = msg.replace( 'HTTP/1.1\r\n', 'HTTP/1.1\r\n Transfer-Encoding: chunked\r\n' )
        return msg

    def badsetupCR(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Foo: bar' )
        msg = msg.replace( 'HTTP/1.1\r\n', 'HTTP/1.1\r\nFooz: bar\rTransfer-Encoding: chunked\r\n' )
        return msg

    def badsetupLF(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Foo: bar' )
        msg = msg.replace( 'HTTP/1.1\r\n', 'HTTP/1.1\r\nFooz: bar\nTransfer-Encoding: chunked\r\n' )
        return msg

    def vertwrap(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: \n\u000B' )
        return msg

    def tabwrap(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: \n\t' )
        return msg

    def dualchunk(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity' )
        return msg

    def lazygrep(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunk' )
        return msg

    def multiCase(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'TrAnSFer-EnCODinG: cHuNkeD' )
        return msg

    def UPPERCASE(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'TRANSFER-ENCODING: CHUNKED' )
        return msg

    def zdwrap(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Foo: bar' )
        msg = msg.replace( 'HTTP/1.1\r\n', 'HTTP/1.1\r\nFoo: bar\r\n\rTransfer-Encoding: chunked\r\n' )
        return msg

    def zdsuffix(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked\r' )
        return msg

    def zdsuffix(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked\t' )
        return msg

    def revdualchunk(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: identity\r\nTransfer-Encoding: chunked' )
        return msg

    def zdspam(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer\r-Encoding: chunked' )
        return msg

    def bodysplit(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Foo: barn\n\nTransfer-Encoding: chunked' )
        return msg

    def connection(self, msg):
        msg = msg.replace( 'Connection', 'Transfer-Encoding' )
        return msg

    def nested(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: cow chunked bar' )
        return msg

    def spaceFF(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(255) )
        return msg

    def unispace(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(160) )
        return msg

    def accentTE(self, msg):
        msg = msg.replace( 'Transfer-Encoding:', 'Transf'+chr(130)+'r-Encoding:' )
        return msg

    def accentCH(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfr-Encoding: ch'+chr(150)+'nked' )
        return msg

    def chunky(self, msg):
        pad_str = ''
        pad_chunk = "F\r\nAAAAAAAAAAAAAAA\r\n"
        for i in range(0,3000):
            pad_str = pad_str + pad_chunk
        msg = msg.replace( 'Transfer-Encoding: chunked\r\n\r\n', 'Transfer-Encoding: chunked\r\n\r\n'+pad_str )
        if 'Content-Length: 11' in msg:
            msg = msg.replace( 'Content-Length: ', 'Content-Length: 600' )
        else:
            msg = msg.replace( 'Content-Length: ', 'Content-Length: 6000' )
        return msg

    def vanilla(self, msg):
        return msg

    def reversevanilla(self, msg):
        return msg

    def spacefix1_0(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(0) )
        return msg
    
    def spacefix1_9(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(9) )
        return msg
    
    def spacefix1_11(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(11) )
        return msg
    
    def spacefix1_12(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(12) )
        return msg
    
    def spacefix1_13(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(13) )
        return msg
   
    def spacefix1_127(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(127) )
        return msg
   
    def spacefix1_160(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(160) )
        return msg
    
    def spacefix1_255(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding:'+chr(255) )
        return msg

    def prefix1_0(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(0) )
        return msg
    
    def prefix1_9(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(9) )
        return msg
    
    def prefix1_11(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(11) )
        return msg
    
    def prefix1_12(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(12) )
        return msg
   
    def prefix1_13(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(13) )
        return msg
    
    def prefix1_127(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(127) )
        return msg
   
    def prefix1_160(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(160) )
        return msg
    
    def prefix1_255(self, msg):
        msg = msg.replace( 'Transfer-Encoding: ', 'Transfer-Encoding: '+chr(255) )
        return msg

    def suffix1_0(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(0) )
        return msg
   
    def suffix1_9(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(9) )
        return msg
    
    def suffix1_11(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(11) )
        return msg
   
    def suffix1_12(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(12) )
        return msg
   
    def suffix1_13(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(13) )
        return msg
   
    def suffix1_127(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(127) )
        return msg
    
    def suffix1_160(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(160) )
        return msg
   
    def suffix1_255(self, msg):
        msg = msg.replace( 'Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'+chr(255) )
        return msg

class sockRequest:
    length          = 0
    time            = 0
    headers_length  = 0
    content_length  = 0
    headers         = ''
    status_reason   = ''
    url             = ''
    message         = ''
    response        = ''
    content         = ''
    t_headers       = {}
    status_code     = -1

    def __init__(self, url, message ):
        self.url = url
        self.message = message

    def receive_all(self, sock ):
        datas = ''
        for i in range(100):
            chunk = sock.recv( 4096 )
            if chunk:
                datas = datas + chunk.decode(errors='ignore')
                break
            else:
                break
        return datas

    def extractDatas(self):
        try:
            self.length = len(self.response )
            p = self.response.find( '\r\n'+'\r\n' )
            self.headers = self.response[0:p]
            self.headers_length = len(self.headers )
            self.content = self.response[p+len('\r\n'+'\r\n'):]
            self.content_length = len(self.content )

            tmp = self.headers.split( '\r\n' )
            
            first_line = tmp[0].split( ' ' )
            self.status_code = int(first_line[1])
            self.status_reason = first_line[2]

            for header in tmp:
                p = header.find( ': ' )
                k = header[0:p]
                v = header[p+2:]
                self.t_headers[ k ] = v
        except Exception as e:
            pass

    def send(self):
        t_urlparse = urlparse(self.url )
        
        if t_urlparse.port:
            port = t_urlparse.port
        elif t_urlparse.scheme == 'https':
            port = 443
        else:
            port = 80
        
        if ':' in t_urlparse.netloc:
            tmp = t_urlparse.netloc.split(':')
            netloc = tmp[0]
            port = tmp[1]
        else:
            netloc = t_urlparse.netloc

        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )

        if t_urlparse.scheme == 'https':
            context = ssl.SSLContext( ssl.PROTOCOL_SSLv23 )
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket( sock, server_hostname=netloc )

        sock.settimeout( 30 )

        try:
            sock.connect( (netloc, port) )
        except Exception as e:
            return False
        
        sock.sendall( str.encode(self.message) )
        start = time.time()

        try:
            datas = self.receive_all( sock )
        except Exception as e:
            return False
        
        end = time.time()
        sock.shutdown( socket.SHUT_RDWR )
        sock.close()

        self.response = datas
        self.time = (end - start) * 1000

        if len(datas):
            self.extractDatas()

def generateAttackMessage( base_message, method, attack_datas ):
    try:
        f = getattr( am, method )
    except Exception as e:
        return ''

    msg = base_message.strip() + '\r\n'
    msg = am.update_content_length( msg, attack_datas['Content-Length'] )
    msg = msg + 'Transfer-Encoding: chunked' + '\r\n'
    msg = msg + '\r\n' + attack_datas['body']
    msg = f( msg)
    return msg

def generateBaseMessage( url, t_evil_headers ):
    t_urlparse = urlparse( url )
    if t_urlparse.path:
        query = t_urlparse.path
    else:
        query = '/'
    if t_urlparse.query:
        query = query + '?' + t_urlparse.query
    if t_urlparse.fragment:
        query = query + '#' + t_urlparse.fragment

    msg = 'POST ' + query + ' HTTP/1.1' + '\r\n'
    msg = msg + 'Host: ' + t_urlparse.netloc + '\r\n'

    for k,v in t_evil_headers.items():
        msg = msg + k + ': ' + v + '\r\n'
    msg = msg + '\r\n'
    return msg


history = {}
lock    = threading.Lock()
am      =  SmugglerAttacks()
def check(url,base_message,method,attack_datas,output):
    if not url in history.keys():
        history[url] = 0
    
    if history[url] > MAX_VULNERABLE:
        return

    result = request( url, generateAttackMessage( base_message, method, attack_datas ) )
    if result.status_code < 0: return

    if result.time > 9000:
        r_type = True
        with lock: history[url] += 1
    else:
        r_type = False

    if 'Content-Type' in result.t_headers:
        content_type = result.t_headers['Content-Type']
    else:
        content_type = '-'

    if attack_datas:
        method = attack_datas['name'] + '|' + method
    
    output.append({
        'R':       result.url.ljust(0),
        'M':       method,
        'C':       result.status_code,
        'L':       result.length,
        'time':    result.time,
        'T':       content_type,
        'V':       r_type,
        'request': b64encode(result.message.encode('utf8')).decode('utf8')
    })

def request( url, message ):
    sock = sockRequest( url, message )
    sock.send()
    return sock

class Smuggler(Plugin):
    def __init__(self):
        self.name        = "Request Smuggler"
        self.enable      = True
        self.description = ""

    def presquites(self, host):
        if utils.isalive( utils.uri(host) ):
            return True
        return False

    def main(self,host):
        output  = []
        url     = utils.uri(host)
        channel = multitask.Channel()

        for method in t_registered_method:
            for attack_datas in t_attacks_datas:
                channel.append(
                    url,
                    generateBaseMessage( url, t_base_headers ),
                    method,
                    attack_datas,
                    output
                )

        multitask.workers(check,channel,10)
        channel.wait()
        channel.close()

        qtechniques = 0
        ntechniques = []
        rtechniques = []
        savename    = host + ".sumggler.txt"

        for scan in output:
            isvulnerable = scan['V']
            method       = scan['M']
            status       = scan['C']
            request      = scan['request']
            
            if isvulnerable == True:
                qtechniques += 1
                ntechniques.append(method)
                rtechniques.append( (request) )

                data.savetofile(
                    name    = savename,
                    content = json.dumps(scan) + "\n"
                )

        if qtechniques == 0:
            return Result(FAILED,None,None,None)
        
        return Result(SUCCESS,"%i of smuggling techniques worked: [%s] request(s) saved at: output/%s" % (qtechniques, ', '.join(ntechniques[:4]) + "..", savename),None,None)