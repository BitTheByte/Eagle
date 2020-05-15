import zlib
import base64
import threading

def compress(data):
    if not data: return ''
    data = zlib.compress(data,9)
    return base64.b64encode(data).decode('utf8')

def decompress(data):
    if not data: return ''
    data = base64.b64decode(data.encode('utf8'))
    return zlib.decompress(data)

savelock = threading.Lock()
def savetofile(name,content):
    with savelock: open(sys.path[0]+"/output/"+name ,'a+').write(content)
