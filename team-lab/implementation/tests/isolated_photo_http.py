#!/usr/bin/env python3
"""Only for the named disposable test network; no external target arguments."""
import http.cookiejar
import re
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
BASE='http://fiveeyes-scenario-test-web-20261103'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): return None
class Client:
    def __init__(self): self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),NoRedirect())
    def req(self,path,data=None,headers=None):
        req=urllib.request.Request(BASE+path,data=data,headers=headers or {})
        try: res=self.opener.open(req,timeout=10)
        except urllib.error.HTTPError as e: res=e
        with res: return res.status,dict(res.headers),res.read()
def csrf(body):
    match=re.search(rb'name="csrf" value="([a-f0-9]+)"',body)
    assert match, 'missing CSRF token'
    return match.group(1).decode()
def post_form(client,path,fields): return client.req(path,urllib.parse.urlencode(fields).encode(),{'Content-Type':'application/x-www-form-urlencoded'})
def login(name):
    c=Client(); status,_,body=c.req('/login.php'); assert status==200
    status,_,_=post_form(c,'/login.php',{'csrf':csrf(body),'username':name,'password':'synthetic-test-only'})
    assert status==303,('login',name,status)
    return c
def upload(client,visibility,name,content):
    status,_,form=client.req('/customer/tickets.php?new=1'); assert status==200
    boundary='test-boundary-photo-20261103'
    parts=[]
    for key,val in {'csrf':csrf(form),'action':'create','category':'이용 문의','title':'합성 사진 문의','body':'격리 시험 문의','visibility':visibility}.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{val}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="{name}"\r\nContent-Type: image/png\r\n\r\n'.encode()+content+b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    return client.req('/customer/action.php',b''.join(parts),{'Content-Type':'multipart/form-data; boundary='+boundary})
owner=login('scenario_a'); other=login('scenario_b'); anon=Client()
image=Path('/work/public/assets/images/haneul-haru-v1.png').read_bytes()
status,h,_=upload(owner,'private','haneul-haru-v1.png',image); assert status==303,('private upload',status)
ticket_path=h['Location']; status,_,detail=owner.req(ticket_path); assert status==200
match=re.search(rb'/customer/photo.php\?id=(\d+)',detail); assert match
photo='/customer/photo.php?id='+match.group(1).decode()
status,h,received=owner.req(photo); assert status==200 and received==image and h.get('X-Content-Type-Options')=='nosniff'
assert anon.req(photo)[0]==404 and other.req(photo)[0]==404
assert upload(owner,'private','photo.php.png',image)[0]==422
status,h,_=upload(owner,'public','photo.png',image); assert status==303
status,_,detail=owner.req(h['Location']); match=re.search(rb'/customer/photo.php\?id=(\d+)',detail); assert status==200 and match
status,_,received=anon.req('/customer/photo.php?id='+match.group(1).decode()); assert status==200 and received==image
print('PASS: login, real PNG, private owner, anonymous/other denial, executable filename denial, public photo')
