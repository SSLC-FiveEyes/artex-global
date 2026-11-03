#!/usr/bin/env python3
"""Register inert example tools locally; never execute them or change existing tools."""
import json
from pathlib import Path
import urllib.request
import urllib.error
root=Path(__file__).resolve().parents[1]
secret_path=root/'.secrets/artex-login.txt'
if not secret_path.is_file(): raise SystemExit('Local ARTEX credentials are not available; no registration attempted')
fields={}
for line in secret_path.read_text().splitlines():
 if '=' in line:
  k,v=line.split('=',1); fields[k.strip()]=v.strip()
if fields.get('USERNAME')!='ARTEX' or not fields.get('PASSWORD'): raise SystemExit('Local login format not recognized')
base='http://127.0.0.1:8787'
def request(path, data=None, token=None):
 headers={'Content-Type':'application/json'}
 if token: headers['Authorization']='Bearer '+token
 r=urllib.request.Request(base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
 with urllib.request.urlopen(r,timeout=5) as res: return json.load(res)
try:
 token=request('/api/auth/login',{'username':fields['USERNAME'],'password':fields['PASSWORD']})['token']
 existing=request('/api/tools',token=token)
 if isinstance(existing,dict): existing=existing.get('tools',[])
 keys={row.get('key') for row in existing if isinstance(row,dict)}
 for name in ['fiveeyes_nmap_scan','fiveeyes_sqlmap_check']:
  spec=json.loads((root/'config'/'scan-tools'/f'{name}.example.json').read_text())
  assert spec['key']==name and spec['enabled'] is False and spec['agents']==[]
  assert 'APPROVED_IPV4 = []' in spec['exec']['code'] if name=='fiveeyes_nmap_scan' else 'APPROVED_URLS = []' in spec['exec']['code']
  if name in keys: print(name+': already present, unchanged'); continue
  result=request('/api/tools/custom',spec,token)
  if result.get('key')!=name: raise RuntimeError('Unexpected response')
  print(name+': registered disabled, no agents or targets')
except (urllib.error.URLError,ValueError,KeyError) as exc:
 raise SystemExit('Registration unavailable; no credentials or tokens printed: '+type(exc).__name__)
