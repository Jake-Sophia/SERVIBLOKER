"""Transporte HTTP real, sólo en namespace Linux aislado (ver linux_http.sh)."""
from pathlib import Path
import asyncio
import json
import plistlib
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiohttp.test_utils import TestClient, TestServer
from dnslib import DNSRecord, RCODE
from test_blockservi import configuration, Resolver
from blockservi.cli import Components


class HTTPTransport(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parts = Components(configuration(self.temp.name))
        self.parts.filter.upstream = Resolver()
        self.client = TestClient(TestServer(self.parts.service.build_app(), host='127.0.0.1'))
        await self.client.start_server()
        self.admin = {'X-Admin-Key': self.parts.config.admin_key}

    async def asyncTearDown(self):
        await self.client.close()
        self.temp.cleanup()

    async def test_profile_dns_and_revocation_over_http(self):
        r = await self.client.post('/api/virtual/devices', json={'label': 'transport'}, headers=self.admin)
        self.assertEqual(r.status, 201)
        token = (await r.json())['token']
        r = await self.client.get(f'/perfil/{token}.mobileconfig', headers=self.admin)
        self.assertEqual(r.status, 200)
        self.assertEqual(plistlib.loads(await r.read())['PayloadDisplayName'], 'IBLOKER')
        r = await self.client.get(f'/api/pedido/{token}?nuevo=1')
        code = (await r.json())['codigo']
        r = await self.client.post('/api/admin/ok', json={'codigo': code}, headers=self.admin)
        self.assertEqual(r.status, 200)
        wire = DNSRecord.question('example.net').pack()
        r = await self.client.post(f'/dns-query/{token}', data=wire, headers={'Content-Type': 'application/dns-message'})
        self.assertEqual(DNSRecord.parse(await r.read()).header.rcode, RCODE.NOERROR)
        r = await self.client.post('/api/admin/revocar', json={'codigo': code}, headers=self.admin)
        self.assertEqual(r.status, 200)
        r = await self.client.post(f'/dns-query/{token}', data=wire)
        self.assertEqual(DNSRecord.parse(await r.read()).header.rcode, RCODE.NXDOMAIN)

    async def test_body_limit_auth_and_login_cookie(self):
        r = await self.client.post('/api/virtual/devices', data='x' * (65 * 1024), headers={**self.admin, 'Content-Type':'application/json'})
        self.assertEqual(r.status, 413)
        r = await self.client.post('/login', json={'key': self.parts.config.admin_key})
        self.assertEqual(r.status, 200)
        cookie = r.cookies['iblocker_session']
        self.assertTrue(cookie['secure'])
        self.assertTrue(cookie['httponly'])
        r = await self.client.get('/api/virtual/devices?k='+self.parts.config.admin_key)
        self.assertEqual(r.status, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
