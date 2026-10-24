"""Dummy-only HTTP checks; run in an isolated network namespace."""
import asyncio
import hashlib
import importlib.util
import sys
import time
from aiohttp.test_utils import TestClient, TestServer

spec=importlib.util.spec_from_file_location('panel',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Store:
    def list(self):
        return [{'token':'a'*48,'label':'<img src=x onerror=alert(1)>','unlocked_until':0},
                {'token':'b'*48,'label':'Second fixture','unlocked_until':int(time.time())+3600}]
    def pending_requests(self):
        return [{'token':'a'*48,'codigo':'111111','solicitado':int(time.time()),'label':'First'},
                {'token':'','codigo':'222222','solicitado':int(time.time()),'label':'Generic'}]
    def device(self,token):
        return next((d for d in self.list() if d['token']==token),None)

class Codes:
    def list(self):
        return [{'id':'999999','pending':True,'created_at':int(time.time())-3*86400,
                 'token':'a'*48,'origen':'movil'}]

async def main():
    calls=[]
    async def backend(path,body):
        calls.append((path,body))
        return 200,{'ok':True,'token':'a'*48,'ip':'PRIVATE_FIXTURE','unlocked_until':int(time.time())+3600,'hours':1}
    panel=module.Panel(Store(),Codes(),'DUMMY_ADMIN','', 'https://panel.example',backend=backend)
    panel.access_hash=hashlib.sha256(b'DUMMY_PRIVATE_LINK').hexdigest()
    async with TestClient(TestServer(panel.app())) as client:
        response=await client.get('/administracion/api/state')
        assert response.status==401 and 'Second fixture' not in await response.text()
        assert response.headers['Cache-Control']=='no-store'
        assert (await client.post('/administracion/api/session',json={'key':'DUMMY_PRIVATE_LINK'})).status==403
        response=await client.post('/administracion/api/session',json={'key':'wrong'},headers={'Origin':'https://panel.example'})
        assert response.status==401
        response=await client.post('/administracion/api/session',json={'key':'DUMMY_PRIVATE_LINK'},headers={'Origin':'https://panel.example'})
        assert response.status==200
        cookie=response.cookies[module.COOKIE]
        assert cookie['secure'] and cookie['httponly'] and cookie['samesite']=='Strict' and cookie['path']=='/administracion'
        headers={'Cookie':module.COOKIE+'='+cookie.value}
        response=await client.get('/administracion/api/state',headers=headers)
        data=await response.json();assert response.status==200
        assert data['pending'][0]['individual'] and not data['pending'][1]['individual']
        assert len(data['pending'])==2  # Expired phone requests are not presented as actionable.
        assert len(data['active'])==1 and data['device_count']==2
        assert 'DUMMY_ADMIN' not in str(data)
        assert (await client.post('/administracion/api/approve',json={'code':'111111','hours':1},headers=headers)).status==403
        headers.update({'Origin':'https://panel.example','X-IBLOKER-CSRF':data['csrf']})
        bad=dict(headers,Origin='https://evil.example')
        assert (await client.post('/administracion/api/approve',json={'code':'111111','hours':1},headers=bad)).status==403
        assert not calls
        assert (await client.post('/administracion/api/approve',json={'code':'111111','hours':True},headers=headers)).status==400
        response=await client.post('/administracion/api/approve',json={'code':'111111','hours':1,'individual_only':False},headers=headers)
        body=await response.json();assert response.status==200 and body['ok']
        assert calls[-1]==('/api/admin/ok',{'codigo':'111111','horas':1,'individual_only':True})
        assert 'token' not in body and 'ip' not in body
        response=await client.post('/administracion/api/revoke',json={'id':'b'*48},headers=headers)
        assert response.status==200 and calls[-1][0]=='/api/bloquear/'+'b'*48
        response=await client.post('/administracion/api/logout',json={},headers=headers)
        assert response.status==200
        assert (await client.get('/administracion/api/state',headers=headers)).status==401
        asset=await client.get('/administracion')
        assert asset.status==200 and 'DUMMY_ADMIN' not in await asset.text()
    print('PASS: private session, secure cookie, no inventory leakage, CSRF/origin, validation, individual-only approval, targeted revoke, logout.')

asyncio.run(main())
