from utils.status import *
from .helper import Plugin,utils
from urllib.parse import urlparse
from utils.decorators import OnErrorReturnValue
from bs4 import BeautifulSoup
import re
import urllib.parse
import utils.multitask as multitask



class Spider(Plugin):
    def __init__(self):
        self.name        = "Sensetive Informations Spider"
        self.enable      = True
        self.description = ""
        self.concurrent  = 8

        self.__secrets   = {}

    def get_secrets(self,content):
        regexs = {
            'google_api' : 'AIza[0-9A-Za-z-_]{35}',
            'google_oauth' : 'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id' : '([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}',
            'amazon_mws_auth_toke' : 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'amazon_aws_url' : 's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'firebase_url' : '.firebaseio.com[/]+|[a-zA-Z0-9_-]*\.firebaseio.com',
            'facebook_access_token' : 'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_bearer' : 'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
            'mailgun_api_key' : 'key-[0-9a-zA-Z]{32}',
            'twilio_api_key' : 'SK[0-9a-fA-F]{32}',
            'twilio_account_sid' : 'AC[a-zA-Z0-9_\-]{32}',
            'paypal_braintree_access_token' : 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'square_oauth_secret' : 'sq0csp-[ 0-9A-Za-z\-_]{43}',
            'square_access_token' : 'sqOatp-[0-9A-Za-z\-_]{22}',
            'stripe_standard_api' : 'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api' : 'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token' : '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key' : '-----BEGIN RSA PRIVATE KEY-----',
            'ssh_dsa_private_key' : '-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key' : '-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block' : '-----BEGIN PGP PRIVATE KEY BLOCK-----',
            '!debug_page': "Application-Trace|Routing Error|DEBUG\"? ?[=:] ?True|Caused by:|stack trace:|Microsoft .NET Framework|Traceback|[0-9]:in `|#!/us|WebApplicationException|java\\.lang\\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE",
            #'google_captcha' : '6L[0-9A-Za-z-_]{38}',
            #'authorization_api' : 'api[key|\s*]+[a-zA-Z0-9_\-]+',
            #'twilio_app_sid' : 'AP[a-zA-Z0-9_\-]{32}',
            #'authorization_basic' : 'basic\s*[a-zA-Z0-9=:_\+\/-]+',
            #'json_web_token' : 'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*'
        }

        regex = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
        for reg in regexs.items():
            if "!" in reg[0]:
                myreg  = re.compile(reg[1])
            else:
                myreg  = re.compile(regex.replace('%%regex%%',reg[1]))
            result = myreg.findall(content)
            if len(result) > 0:
                return {reg[0]: result}
        return None

    def sources(self,base,html):
        urls   = []
        soup = BeautifulSoup(html,features="lxml")
        for link in soup.findAll("a"):
            urls.append( urllib.parse.urljoin(base, link.get("href")) )

        for link in soup.findAll("script"):
            urls.append( urllib.parse.urljoin(base, link.get("src")) )

        return set(urls)

    def presquites(self, host):
        if utils.isalive( utils.uri(host) ):
            return True
        return False

    @OnErrorReturnValue(False)
    def sip(self,host,url):
        html   = utils.requests.get(url).text
        secret = self.get_secrets(html)

        if not secret: return
        self.__secrets[host].append(secret)

    def main(self,host):
        base    = utils.uri(host)
        html    = utils.requests.get(base).text
        srcs    = self.sources(base, html)
        index   = self.get_secrets(html)

        self.__secrets[host] = []

        if index:
            self.__secrets[host].append(index)

        channel = multitask.Channel(self.name)
        multitask.workers(self.sip,channel,self.concurrent)

        for src in srcs:
            channel.append(host,src)

        channel.wait()
        channel.close()

        if len(self.__secrets[host]) > 0:
            return Result(SUCCESS,self.__secrets[host],None,None)

        return Result(FAILED,None,None,None)