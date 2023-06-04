from utils.decorators import OnErrorReturnValue
from botocore.handlers import disable_signing
from botocore.config import Config
from .helper import Plugin,utils
from botocore import UNSIGNED
from utils.status import *
from io import StringIO
import threading
import boto3
import re


class S3Security(Plugin):
    def __init__(self):
        self.name        = "S3Security"
        self.enable      = True
        self.description = ""

        self.content     = "Uploaded by S3Security Plugin"
        self.path        = "S3Security.txt"
        self.lock        =  threading.Lock()
        self.__cache     = {}

    def presquites(self, host):
        return self.s3bucket(host) != False

    @OnErrorReturnValue(False)
    def s3bucket(self,host):
        if host in self.__cache.keys():
            return self.__cache[host]

        # Method 1
        s3_url = f"http://{host}.s3.amazonaws.com"

        if utils.requests.head(s3_url).status_code != 404:
            with self.lock:
                self.__cache.update({host:host})
            return host

        # Method 2
        request = utils.requests.get(
            f"{utils.uri(host)}notfoundfile.scan",
            params={
                "AWSAccessKeyId": "AKIAI4UZT4FCOF2OTJYQ",
                "Expires": "1766972005",
                "Signature": "helloworld",
            },
        ) 

        if request.status_code == 403 and "AWSAccessKeyId" in request.text:
            bucket = re.findall("/.+/notfoundfile.scan",request.text)[0]
            bucket = bucket.replace("/notfoundfile.scan","")[1::]
            with self.lock:
                self.__cache.update({host:bucket})
            return bucket

        return False

    @OnErrorReturnValue(False)
    def s3list(self,bucket):
        s3   = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        return len(s3.list_objects(Bucket=bucket,MaxKeys=10))

    @OnErrorReturnValue(False)
    def s3upload(self,bucket):
        s3   = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        path = f"http://{bucket}.s3.amazonaws.com/{self.path}"

        s3.put_object(
            Bucket  = bucket,
            Key     = self.path,
            ACL     = 'public-read',
            Body    = StringIO(self.content).read()
        )

        return False if self.content not in utils.requests.get(path).text else path

    def main(self,host):
        bucket  = self.s3bucket(host)
        upload  = self.s3upload(bucket)
        listing = self.s3list(bucket)

        if listing and upload:
            return Result(
                SUCCESS,
                f"Directory listing & File Upload: {bucket}, {upload}",
                None,
                None,
            )

        if listing:
            return Result(SUCCESS, f"Directory listing: {bucket}", None, None)

        if upload:
            return Result(SUCCESS, f"File Upload: {upload}", None, None)

        if bucket != False:
            return Result(INFO, f"S3: {bucket} is safe", None, None)

        return Result(FAILED,None,None,None)