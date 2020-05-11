import requests
import hashlib
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

class Requests(object):
    def __init__(self):
        self.cache = {}
        self.enable = True

    def token(self,method,*args,**kwargs):
        if "url" in kwargs.keys():
            url = kwargs["url"].encode("utf-8")
        else:
            url = args[0].encode("utf-8")

        if "data" in kwargs.keys():
            data = str(kwargs["data"]).encode("utf-8")
        else:
            data = b""

        return hashlib.md5(method.encode("utf-8") + url + data).hexdigest()

    def pre_request(self,token, args, kwargs):
        kwargs.update({'verify': False})
        if (not self.enable)  or (not token in self.cache.keys()):
            return False
        return True

    def Request(self,*args,**kwargs):
        return requests.Request(*args,**kwargs)
    
    def Session(self,*args,**kwargs):
        return requests.Session(*args,**kwargs)

    def get(self,*args,**kwargs):
        token = self.token("get", *args,**kwargs)
        saved = self.pre_request(token,args,kwargs)

        if not saved:
            self.cache.update({
                token: requests.get(*args,**kwargs)
            })
        return self.cache[token]

    def post(self,*args,**kwargs):
        token = self.token("post", *args,**kwargs)
        saved = self.pre_request(token,args,kwargs)
        if not saved:
            self.cache.update({
                token: requests.post(*args,**kwargs)
            })
        return self.cache[token]

    def head(self,*args,**kwargs):
        token = self.token("head", *args,**kwargs)
        saved = self.pre_request(token,args,kwargs)
        if not saved:
            self.cache.update({
                token: requests.head(*args,**kwargs)
            })
        return self.cache[token]

    def put(self,*args,**kwargs):
        token = self.token("put", *args,**kwargs)
        saved = self.pre_request(token,args,kwargs)
        if not saved:
            self.cache.update({
                token: requests.put(*args,**kwargs)
            })
        return self.cache[token]

    def options(self,*args,**kwargs):
        token = self.token("options", *args,**kwargs)
        saved = self.pre_request(token,args,kwargs)
        if not saved:
            self.cache.update({
                token: requests.options(*args,**kwargs)
            })
        return self.cache[token]

wRequests = Requests()