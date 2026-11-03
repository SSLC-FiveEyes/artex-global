#!/usr/bin/env python3
"""Only for the named disposable local test network and synthetic RFC key."""
import base64, hashlib, hmac, http.cookiejar, re, struct, time
import urllib.request, urllib.parse, urllib.error
BASE='http://fiveeyes-scenario-mfa-web-20261103'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None
class Client:
    def __init__(self): self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),NoRedirect())
    def req(self,path,data=None):
        req=urllib.request.Request(BASE+path,data=urllib.parse.urlencode(data).encode() if data is not None else None)
        try: r=self.opener.open(req,timeout=10)
        except urllib.error.HTTPError as e: r=e
        with r: return r.status,dict(r.headers),r.read()
def value(body,name):
    match=re.search(rb'name="'+name.encode()+rb'" value="([a-f0-9]+)"',body)
    assert match, 'missing form value '+name
    return match.group(1).decode()
def pending():
    c=Client(); status,_,body=c.req('/login.php'); assert status==200
    status,headers,_=c.req('/login.php',{'csrf':value(body,'csrf'),'username':'scenario_a','password':'synthetic-test-only'})
    assert status==303 and headers.get('Location')=='/mfa.php'
    status,headers,_=c.req('/account/'); assert status==302 and headers.get('Location')=='/mfa.php'
    status,_,body=c.req('/mfa.php'); assert status==200
    return c,value(body,'csrf'),value(body,'challenge_token')
def otp():
    counter=int(time.time())//30; key=base64.b32decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
    digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest(); offset=digest[-1]&15
    return str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
a,csrf,token=pending(); code=otp()
status,_,_=a.req('/mfa.php',{'csrf':csrf,'otp':code}); assert status==403,('missing',status)
status,_,_=a.req('/mfa.php',{'csrf':csrf,'challenge_token':'b'*64,'otp':code}); assert status==403,('modified',status)
b,csrf_b,token_b=pending()
status,_,_=b.req('/mfa.php',{'csrf':csrf_b,'challenge_token':token,'otp':code}); assert status==403,('cross-session token',status)
status,headers,_=a.req('/mfa.php',{'csrf':csrf,'challenge_token':token,'otp':code}); assert status==303,('verified',status)
status,_,_=a.req('/account/'); assert status==200,('protected',status)
status,_,_=b.req('/mfa.php',{'csrf':csrf_b,'challenge_token':token_b,'otp':code}); assert status==403,('reused',status)
print('PASS: password pending, direct access blocked, missing/modified/cross-session token denied, OTP success and reuse denied')
