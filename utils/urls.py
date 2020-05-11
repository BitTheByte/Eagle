from .wrappers import wRequests as requests
from .decorators import OnErrorReturnValue
from urllib.parse import urlparse,urlunparse
import dns.resolver


alive_cache = {}

def isalive(url):
    url = sanitize(url)
    if url in alive_cache.keys():
        return alive_cache[url]
    try:
        status = bool( requests.options(url,timeout=10,verify=False).status_code )
        alive_cache.update({url: status})
    except Exception as e :
        status = False
        alive_cache.update({url: status})
    return status

def sanitize(url):
    url_parsed = urlparse(url)  
    return urlunparse((url_parsed.scheme, url_parsed.netloc, '/'.join([part for part in url_parsed.path.split('/') if part]) , '', '', '')) + "/"

def urlschemes(host):
    schemes = []
    if isalive("http://%s" % host):
        schemes.append('http')
    if isalive("https://%s" % host):
        schemes.append('https')
    return schemes

def urlscheme(host):
    if isalive("https://%s" % host):
        return "https"
    return "http"

def uri(host):
    scheme = urlscheme(host)
    return sanitize( "{scheme}://{host}/".format(scheme=scheme,host=host) )

def dump_request(request):
    body = b""
    body += request.request.method.encode("utf8")
    body += b" "
    body += request.request.url.encode("utf8")
    body += b"\r\n"

    for header,value in request.request.headers.items():
        body += header.encode("utf8") + b": " + value.encode("utf8") + b"\r\n"

    if request.request.body != None:
        body +=  str(request.request.body).encode("utf8")
    return body

def dump_response(request):
    body = b"HTTP /1.1 "

    body += str(request.status_code).encode("utf8")
    body += b" "
    body += request.reason.encode("utf8")
    body += b"\r\n"

    for header,value in request.headers.items():
        body += header.encode("utf8") + b": " + value.encode("utf8") + b"\r\n"
    body += request.text.encode("utf8")
    return body