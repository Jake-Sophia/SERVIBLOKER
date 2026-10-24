"""Regresiones sin servicios externos. HTTP se despacha por el router aiohttp en memoria."""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from dnslib import A, AAAA, DNSHeader, DNSRecord, QTYPE, RCODE, RR, SOA

from blockservi.cli import Components
from blockservi.codes import Codes
from blockservi.config import load
from blockservi.controller import render_rules, sessions_from_vici
from blockservi.pki import Authority
from blockservi.plain import PlainBridge
from blockservi.portal import admin_page, device_page
from blockservi.profile import build_profile
from blockservi.rules import MODE_STRICT, MODE_UNLOCKED, Policy, SYSTEM_ESSENTIAL
from blockservi.store import Store
from blockservi.upstream import Upstream, UpstreamError
from blockservi.virtual import VirtualState

ROOT = Path(__file__).resolve().parents[1]


def configuration(directory):
    path = Path(directory) / 'test.ini'
    path.write_text(f'''[general]
domain=example.com
portal_host=portal.example.com
admin_key=test-admin-only
data_dir={directory}
policy_file={ROOT / "blockservi/policy.json"}
[network]
http_port=0
plain_port=0
[upstream]
doh=
udp=
''')
    return load(str(path))


class Resolver:
    def __init__(self):
        self.calls = 0

    async def resolve(self, wire):
        self.calls += 1
        query = DNSRecord.parse(wire)
        reply = query.reply()
        if query.q.qtype == QTYPE.A:
            reply.add_answer(RR(str(query.q.qname), QTYPE.A, rdata=A('8.8.4.4'), ttl=30))
        return reply.pack()

    def stats(self):
        return {'upstream_calls': self.calls}


class Client:
    """Despacho real de rutas/middleware, sin abrir sockets."""
    def __init__(self, app):
        self.app = app
        app.freeze()

    async def request(self, method, path, data=None, headers=None, remote='198.51.100.42'):
        merged = {'Host': 'portal.example.com', **(headers or {})}
        if data is not None:
            merged['Content-Type'] = 'application/json'
        request = make_mocked_request(method, path, headers=merged).clone(remote=remote)
        if data is not None:
            request._read_bytes = json.dumps(data).encode()
        try:
            return await self.app._handle(request)
        except web.HTTPException as response:
            return response


def body(response):
    return json.loads(response.body)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = configuration(self.temp.name)
        self.parts = Components(self.config)
        self.store = self.parts.store

    def test_identity_and_legacy_migration(self):
        device = self.store.add('Phone')
        self.assertEqual(len(device['token']), 48)
        self.assertTrue(device['profile_uuid'])
        self.assertEqual(self.store.state(device['token']), 'RESTRICTED')
        old = {'devices': {'aabbccddeeff': {'label': 'Old', 'unlocked_until': int(time.time()) + 500}}, 'ips': {}}
        legacy = Path(self.temp.name) / 'old.json'
        legacy.write_text(json.dumps(old))
        store = Store(str(legacy))
        self.assertEqual(store.mode('aabbccddeeff'), MODE_UNLOCKED)
        store.add('New')
        self.assertEqual(Store(str(legacy)).device('aabbccddeeff')['label'], 'Old')

    def test_expiry_revocation_and_reauthorization(self):
        token = self.store.add()['token']
        self.store.unlock(token, '', 1)
        self.assertEqual(self.store.state(token), 'UNLOCKED')
        self.store.set_unlocked_until(token, int(time.time()) - 1)
        self.assertEqual(self.store.state(token), 'EXPIRED')
        self.store.revoke_credential(token)
        self.assertEqual(Store(self.config.state_file).state(token), 'REVOKED')
        with self.assertRaises(ValueError):
            self.store.unlock(token, '', 1)
        self.store.set_unlocked_until(token, int(time.time()) + 100)
        self.assertEqual(self.store.mode(token), MODE_STRICT)

    def test_invalid_hours(self):
        token = self.store.add()['token']
        for hours in (0, -1, 2161):
            with self.assertRaises(ValueError):
                self.store.unlock(token, '', hours)

    def test_concurrent_store_instances(self):
        def add(i):
            return Store(self.config.state_file).add(str(i))['token']
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            tokens = list(pool.map(add, range(30)))
        self.assertEqual(len(set(tokens)), 30)
        self.assertEqual(len(self.store.list()), 30)
        self.assertEqual(os.stat(self.config.state_file).st_mode & 0o777, 0o600)

    def test_cross_process_writes(self):
        script = 'import sys; from blockservi.store import Store; s=Store(sys.argv[1]); [s.add() for _ in range(5)]'
        processes = [subprocess.Popen([sys.executable, '-c', script, self.config.state_file], cwd=ROOT) for _ in range(2)]
        for process in processes:
            self.assertEqual(process.wait(timeout=15), 0)
        self.assertEqual(len(self.store.list()), 10)

    def test_codes_one_use_under_concurrency(self):
        code = self.parts.codes.generate(3)['id']
        def redeem(i):
            return Codes(self.parts.codes.path).redeem(code, f'token{i}')[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(redeem, range(12)))
        self.assertEqual(sum(bool(value) for value in results), 1)

    def test_code_ownership(self):
        codes = self.parts.codes
        codes.register('123456', 'owner', '198.51.100.1')
        with self.assertRaises(ValueError):
            codes.register('123456', 'attacker', '198.51.100.1')
        self.assertFalse(codes.bind('123456', 'attacker'))
        generated = codes.generate(1)['id']
        with self.assertRaises(ValueError):
            codes.register(generated, 'attacker')

    def test_licenses_and_api_scopes(self):
        Path(self.config.licenses_file).write_text(json.dumps({'OK': {'status': 'active'}, 'NO': {'status': 'revoked'}}))
        self.assertTrue(self.parts.licenses.check('ok').ok)
        self.assertFalse(self.parts.licenses.check('NO').ok)
        entry, key = self.parts.api_keys.create('activar')
        self.assertNotIn(key, Path(self.parts.api_keys.path).read_text())
        self.assertIsNotNone(self.parts.api_keys.verify(key, 'activar'))
        self.assertIsNone(self.parts.api_keys.verify(key, 'revocar'))
        self.parts.api_keys.revoke(entry['id'])
        self.assertIsNone(self.parts.api_keys.verify(key))

    def test_persistent_limiter(self):
        for _ in range(3):
            self.assertTrue(VirtualState(self.temp.name).allow('dummy', 3))
        self.assertFalse(VirtualState(self.temp.name).allow('dummy', 3))

    def test_policy_lists_and_essential_services(self):
        policy = self.parts.policy
        for name in ('youtube.com', 'r1.googlevideo.com', *SYSTEM_ESSENTIAL):
            self.assertTrue(policy.decide(name, MODE_STRICT).allow, name)
        for name in ('t.me', 'telegram.org', 'cdn-telegram.org', 'messenger.com', 'whatsapp.net', 'facebook.com', 'instagram.com', 'threads.com'):
            self.assertFalse(policy.decide(name, MODE_STRICT).allow, name)
            self.assertTrue(policy.decide(name, MODE_UNLOCKED).allow, name)
        self.assertFalse(policy.decide('example.net', MODE_STRICT).allow)
        self.assertTrue(policy.decide('example.net', MODE_UNLOCKED).allow)
        self.assertFalse(policy.decide('dns.google', MODE_UNLOCKED).allow)
        old = Policy({'deny_always': ['icloud.com', 'ls.apple.com']})
        self.assertTrue(old.decide('p72-fmip.icloud.com', MODE_STRICT).allow)
        self.assertTrue(Policy({'strict_push': True, 'allow_strict_optional': ['push.example']}).decide('push.example', MODE_STRICT).allow)
        self.assertFalse(Policy({'allow_strict': ['bad.example'], 'deny_strict': ['bad.example']}).decide('bad.example', MODE_STRICT).allow)
        self.assertIsNotNone(Policy({'blocked_qtypes': ['AAAA']}).check_qtype('AAAA'))

    def test_dns_profile_schema_and_unique_ids(self):
        devices = [self.store.add() for _ in range(2)]
        profiles = [plistlib.loads(build_profile(self.config, d['token'], profile_uuid=d['profile_uuid'])) for d in devices]
        ids = []
        for profile, device in zip(profiles, devices):
            self.assertEqual(profile['PayloadUUID'], device['profile_uuid'])
            dns = profile['PayloadContent'][0]['DNSSettings']
            self.assertEqual(dns, {'DNSProtocol': 'HTTPS', 'ServerURL': f'https://portal.example.com/dns-query/{device["token"]}'})
            self.assertNotIn('SCEP', str(profile))
            self.assertNotIn(self.config.admin_key, str(profile))
            ids += [profile['PayloadUUID'], *[p['PayloadUUID'] for p in profile['PayloadContent']]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_optional_wifi(self):
        token = self.store.add()['token']
        profile = plistlib.loads(build_profile(self.config, token, wifi={'ssid': 'Office', 'security': 'WPA2', 'password': 'dummy-password', 'auto_join': False}))
        wifi = profile['PayloadContent'][-1]
        self.assertEqual(wifi['EncryptionType'], 'WPA2')
        self.assertFalse(wifi['AutoJoin'])
        with self.assertRaises(ValueError):
            build_profile(self.config, token, wifi={'ssid': 'Office', 'security': 'WEP'})

    def test_certificates_and_offline_profile(self):
        ca = Authority.initialize(str(Path(self.temp.name) / 'ca'))
        tokens = [self.store.add()['token'] for _ in range(2)]
        config = dataclasses.replace(self.config, vpn_enabled=True, vpn_address='vpn.example.com', vpn_remote='vpn.example.com', doh_server_addresses=('203.0.113.10',))
        Path(config.vpn_ca_file).write_bytes(ca.cert.public_bytes(__import__('cryptography').hazmat.primitives.serialization.Encoding.DER))
        identities = []
        for token in tokens:
            ca.provision(token, config.credentials_dir, os.getuid(), os.getgid())
            identity = json.loads((Path(config.credentials_dir) / (token + '.json')).read_text())
            identities.append(identity)
            key, cert, chain = pkcs12.load_key_and_certificates(base64.b64decode(identity['pkcs12']), identity['password'].encode())
            self.assertIsNotNone(key)
            cert.verify_directly_issued_by(ca.cert)
            self.assertEqual(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName), [token + '.iblocker.invalid'])
            profile = plistlib.loads(build_profile(config, token))
            payloads = profile['PayloadContent']
            self.assertEqual(len(payloads), 4)
            self.assertEqual(payloads[-1]['IKEv2']['PayloadCertificateUUID'], payloads[1]['PayloadUUID'])
            self.assertEqual(payloads[-1]['IKEv2']['AuthenticationMethod'], 'Certificate')
            self.assertNotIn('AuthPassword', payloads[-1]['IKEv2'])
            self.assertEqual(payloads[-1]['IKEv2']['IncludeAllNetworks'], 1)
            self.assertNotIn('OnDemandEnabled', payloads[-1])
            self.assertEqual(payloads[-1]['DNS']['ServerAddresses'], ['203.0.113.10'])
        self.assertNotEqual(identities[0]['serial'], identities[1]['serial'])
        self.assertNotEqual(identities[0]['password'], identities[1]['password'])
        crl_path = str(Path(self.temp.name) / 'revoked.der')
        ca.crl(set(tokens), {tokens[0]}, crl_path)
        crl = x509.load_der_x509_crl(Path(crl_path).read_bytes())
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(int(identities[0]['serial'])))
        self.assertIsNone(crl.get_revoked_certificate_by_serial_number(int(identities[1]['serial'])))
        with self.assertRaises(ValueError):
            Authority.initialize(str(Path(self.temp.name) / 'ca'))

    def test_firewall_policy_by_internal_identity(self):
        a, b = [self.store.add()['token'] for _ in range(2)]
        self.store.unlock(a, '', 1)
        sessions = [{'token': a, 'reqid': 1, 'virtual_ips': ['10.77.0.1'], 'public_ip': '198.51.100.42'},
                    {'token': b, 'reqid': 2, 'virtual_ips': ['10.77.0.2'], 'public_ip': '198.51.100.42'}]
        spec = {'pool4': '10.77.0.0/24', 'pool6': 'fd77:77::/120', 'portal_ips': ['203.0.113.10'], 'deny_networks': ['192.168.0.0/16']}
        rules = render_rules(self.store, sessions, spec, [], self.parts.policy)
        self.assertIn('ip saddr 10.77.0.1 ipsec in reqid 1', rules)
        self.assertIn('ip saddr 10.77.0.2 ipsec in reqid 2', rules)
        self.assertIn('10.77.0.1 timeout 15s', rules)
        self.assertNotIn('10.77.0.2 timeout', rules)
        self.assertNotIn('198.51.100.42', rules)
        self.assertNotIn('ct state established,related accept', rules)
        self.store.revoke_credential(a)
        closed = render_rules(self.store, sessions, spec, [], self.parts.policy)
        self.assertNotIn('ip saddr 10.77.0.1 ipsec in reqid 1', closed)
        self.assertNotIn('10.77.0.1 timeout', closed)
        self.assertIn('hook forward priority -20', closed)

    def test_vici_parser_and_counter(self):
        token = self.store.add()['token']
        fixture = {'iblocker': {'state': b'ESTABLISHED', 'remote-id': (token+'.iblocker.invalid').encode(),
                   'remote-host': b'198.51.100.42', 'uniqueid': b'17', 'remote-vips': [b'10.77.0.1'],
                   'child-sas': {'internet-1': {'state': b'INSTALLED', 'reqid': b'8', 'bytes-in': b'123'}}}}
        sessions = sessions_from_vici([fixture])
        self.assertEqual(sessions[0]['token'], token)
        self.assertEqual(sessions[0]['bytes_in'], 123)
        self.assertEqual(sessions[0]['reqid'], 8)

    def test_limiter_windows_do_not_reset_other_keys(self):
        state = VirtualState(self.temp.name)
        with patch('blockservi.virtual.time.time', return_value=10000):
            self.assertTrue(state.allow('login', 1, 900))
        with patch('blockservi.virtual.time.time', return_value=10100):
            self.assertTrue(state.allow('poll', 120, 60))
            self.assertFalse(state.allow('login', 1, 900))
        with patch('blockservi.virtual.time.time', return_value=10901):
            self.assertTrue(state.allow('login', 1, 900))

    def test_license_limits_effective_authorization(self):
        now = int(time.time())
        Path(self.config.licenses_file).write_text(json.dumps({'SHORT': {'status': 'active', 'expires_at': now+10}}))
        token = self.store.add()['token']
        self.store.unlock(token, 'SHORT', 24)
        self.assertEqual(self.store.effective_until(token), now+10)
        Path(self.config.licenses_file).write_text(json.dumps({'SHORT': {'status': 'revoked'}}))
        self.assertEqual(self.store.mode(token), MODE_STRICT)
        self.store.unlock(token, '', 1)
        self.assertEqual(self.store.mode(token), MODE_UNLOCKED)

    def test_firewall_learns_only_allowed_public_destinations(self):
        spec = {'pool4': '10.77.0.0/24', 'pool6': 'fd77:77::/120', 'portal_ips': ['203.0.113.10']}
        now = int(time.time())
        answers = [('youtube.com', '8.8.4.4', now+30), ('youtube.com','127.0.0.1',now+30),
                   ('example.net','9.9.9.9',now+30),('youtube.com','1.1.1.1',now-1)]
        rules = render_rules(self.store, [], spec, answers, self.parts.policy, now)
        self.assertIn('allowed4 { 8.8.4.4 timeout 30s }', rules)
        self.assertNotIn('9.9.9.9', rules)
        self.assertNotIn('1.1.1.1', rules)
        self.assertNotIn('127.0.0.1', rules)



class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = configuration(self.temp.name)
        self.parts = Components(self.config)
        self.parts.filter.upstream = Resolver()
        self.client = Client(self.parts.service.build_app())
        self.admin = {'X-Admin-Key': self.config.admin_key}
        self.a, self.b = [self.parts.store.add()['token'] for _ in range(2)]

    async def call(self, method, path, data=None, headers=None, **kwargs):
        return await self.client.request(method, path, data, headers, **kwargs)

    async def test_admin_auth_and_no_secret_in_html(self):
        self.assertEqual((await self.call('GET', '/api/virtual/devices?k=test-admin-only')).status, 401)
        response = await self.call('GET', '/panel', headers=self.admin)
        self.assertEqual(response.status, 200)
        self.assertNotIn(self.config.admin_key, response.text)
        self.assertIn('IBLOKER VIRTUAL', response.text)
        self.assertNotIn('Math.random', device_page({}, self.a))
        self.assertNotIn('?k=', response.text)

    async def test_session_cookie_and_csrf(self):
        response = await self.call('POST', '/login', {'key': self.config.admin_key})
        self.assertEqual(response.status, 200)
        morsel = response.cookies['iblocker_session']
        self.assertTrue(morsel['secure'])
        self.assertTrue(morsel['httponly'])
        cookie = {'Cookie': f'iblocker_session={morsel.value}'}
        self.assertEqual((await self.call('GET', '/api/virtual/devices', headers=cookie)).status, 200)
        self.assertEqual((await self.call('POST', '/api/virtual/devices', {'label': 'X'}, cookie)).status, 401)
        cookie['X-IBLOKER-Request'] = '1'
        self.assertEqual((await self.call('POST', '/api/virtual/devices', {'label': 'X'}, cookie)).status, 201)
        cookie['Origin'] = 'https://attacker.example'
        self.assertEqual((await self.call('POST', '/api/virtual/devices', {}, cookie)).status, 403)

    async def test_ip_headers_require_trusted_proxy(self):
        request = make_mocked_request('GET', '/', headers={'CF-Connecting-IP': '192.0.2.100', 'X-Forwarded-For': '192.0.2.200'}).clone(remote='198.51.100.42')
        self.assertEqual(self.parts.service._peer_ip(request), '198.51.100.42')
        proxied = request.clone(remote='127.0.0.1', headers={'X-Forwarded-For': '192.0.2.100, 198.51.100.42'})
        self.assertEqual(self.parts.service._peer_ip(proxied), '198.51.100.42')

    async def test_same_public_ip_authorization_and_revocation(self):
        response = await self.call('GET', f'/api/pedido/{self.a}?nuevo=1')
        code = body(response)['codigo']
        response = await self.call('POST', '/api/admin/ok', {'codigo': code, 'horas': 2}, self.admin)
        self.assertEqual(response.status, 200, response.text)
        self.assertEqual(self.parts.store.mode(self.a), MODE_UNLOCKED)
        self.assertEqual(self.parts.store.mode(self.b), MODE_STRICT)
        self.assertEqual(self.parts.store.mode_for('', '198.51.100.42'), MODE_STRICT)
        response = await self.call('POST', '/api/admin/revocar', {'codigo': code}, self.admin)
        self.assertEqual(response.status, 200)
        self.assertEqual(self.parts.store.mode(self.a), MODE_STRICT)

    async def test_concurrent_approval_and_replay(self):
        code = body(await self.call('GET', f'/api/pedido/{self.a}?nuevo=1'))['codigo']
        results = await asyncio.gather(*[self.call('POST', '/api/admin/ok', {'codigo': code}, self.admin) for _ in range(4)])
        self.assertEqual(sorted(r.status for r in results), [200, 409, 409, 409])
        self.assertEqual(self.parts.store.device(self.a)['unlock_count'], 1)

    async def test_redeem_and_revoke_api(self):
        code = self.parts.codes.generate(1)['id']
        response = await self.call('POST', '/api/canjear', {'codigo': code, 'token': self.a})
        self.assertEqual(response.status, 200)
        response = await self.call('POST', '/api/canjear', {'codigo': code, 'token': self.b})
        self.assertEqual(response.status, 403)
        _, key = self.parts.api_keys.create('revocar')
        response = await self.call('POST', '/api/v1/revocar', {'codigo': code}, {'X-API-Key': key})
        self.assertEqual(response.status, 200)
        self.assertEqual(self.parts.store.mode(self.a), MODE_STRICT)

    async def test_external_api_scope_and_activation(self):
        code = body(await self.call('GET', f'/api/pedido/{self.a}?nuevo=1'))['codigo']
        _, key = self.parts.api_keys.create('consultar')
        self.assertEqual((await self.call('POST', '/api/v1/activar', {'codigo': code}, {'X-API-Key': key})).status, 403)
        _, key = self.parts.api_keys.create('activar')
        response = await self.call('POST', '/api/v1/activar', {'codigo': code}, {'X-API-Key': key})
        self.assertEqual(response.status, 200)
        self.assertEqual(self.parts.store.mode(self.a), MODE_UNLOCKED)
        self.assertEqual(self.parts.store.mode_for('', '198.51.100.99'), MODE_STRICT)

    async def test_code_state_ownership(self):
        code = body(await self.call('GET', f'/api/pedido/{self.a}?nuevo=1'))['codigo']
        self.assertEqual((await self.call('GET', '/api/estado-codigo/'+code)).status, 404)
        self.assertEqual((await self.call('GET', '/api/estado-codigo/'+code, headers={'X-Device-Token': self.b})).status, 404)
        response = await self.call('GET', '/api/estado-codigo/'+code, headers={'X-Device-Token': self.a})
        self.assertEqual(response.status, 200)
        self.assertNotIn('token', body(response))

    async def test_revoke_credential_blocks_dns_and_profile(self):
        await self.call('POST', f'/api/virtual/devices/{self.a}/revoke', {}, self.admin)
        self.assertEqual((await self.call('GET', '/perfil/'+self.a+'.mobileconfig', headers=self.admin)).status, 403)
        self.assertEqual((await self.call('GET', f'/api/pedido/{self.a}?nuevo=1')).status, 403)
        wire = DNSRecord.question('youtube.com').pack()
        reply = await self.parts.filter.handle(wire, self.a, '198.51.100.42')
        self.assertEqual(DNSRecord.parse(reply).header.rcode, RCODE.REFUSED)

    async def test_dns_state_before_cache_and_no_ip_leak(self):
        wire = DNSRecord.question('example.net').pack()
        self.parts.store.unlock_ip('198.51.100.42', '', 2)
        restricted = await self.parts.filter.handle(wire, self.b, '198.51.100.42')
        self.assertEqual(DNSRecord.parse(restricted).header.rcode, RCODE.NXDOMAIN)
        self.parts.store.unlock(self.a, '', 1)
        self.assertEqual(DNSRecord.parse(await self.parts.filter.handle(wire, self.a)).header.rcode, 0)
        self.parts.store.set_unlocked_until(self.a, int(time.time()) - 1)
        self.assertEqual(DNSRecord.parse(await self.parts.filter.handle(wire, self.a)).header.rcode, RCODE.NXDOMAIN)
        empty = DNSRecord(DNSHeader()).pack()
        self.assertEqual(DNSRecord.parse(await self.parts.filter.handle(empty, None)).header.rcode, RCODE.FORMERR)
        self.assertIsNone(await self.parts.filter.handle(b'bad', None))

    async def test_doh_route_and_answers_learning(self):
        wire = DNSRecord.question('youtube.com').pack()
        encoded = base64.urlsafe_b64encode(wire).decode().rstrip('=')
        response = await self.call('GET', '/dns-query/'+self.a+'?dns='+encoded)
        self.assertEqual(response.status, 200)
        self.assertEqual(DNSRecord.parse(response.body).header.rcode, 0)
        self.assertTrue(self.parts.virtual.answers())
        self.assertEqual((await self.call('GET', '/api/virtual/devices')).status, 401)

    async def test_profile_and_provisioning_status(self):
        response = await self.call('GET', '/perfil/'+self.a+'.mobileconfig', headers=self.admin)
        self.assertEqual(response.status, 200)
        self.assertEqual(plistlib.loads(response.body)['PayloadDisplayName'], 'IBLOKER')
        self.assertEqual((await self.call('GET', '/config')).status, 410)
        response = await self.call('GET', '/api/virtual/devices', headers=self.admin)
        self.assertFalse(body(response)['controller']['healthy'])

    async def test_rejected_code_cannot_be_approved(self):
        code = body(await self.call('GET', f'/api/pedido/{self.a}?nuevo=1'))['codigo']
        self.assertEqual((await self.call('POST', '/api/admin/no', {'codigo': code}, self.admin)).status, 200)
        self.assertEqual((await self.call('POST', '/api/admin/ok', {'codigo': code}, self.admin)).status, 409)
        self.assertEqual(self.parts.store.mode(self.a), MODE_STRICT)

    async def test_request_collision_does_not_rebind_existing_code(self):
        self.parts.codes.register('123456', self.b, '198.51.100.42')
        with patch.object(self.parts.store, '_new_request_code', side_effect=['123456', '234567']):
            response = await self.call('GET', f'/api/pedido/{self.a}?nuevo=1')
        self.assertEqual(response.status, 200)
        self.assertEqual(body(response)['codigo'], '234567')
        self.assertEqual(self.parts.codes.get('123456')['token'], self.b)

    async def test_image_workflow_individual_approval(self):
        response = await self.call('GET', f'/api/pedido/{self.a}?nuevo=1')
        code = body(response)['codigo']
        self.assertRegex(code, r'^[0-9]{6}$')
        response = await self.call('POST', '/api/admin/ok', {'codigo': code, 'horas': 1, 'individual_only': True}, self.admin)
        self.assertEqual(response.status, 200)
        self.assertEqual(self.parts.store.mode(self.a), MODE_UNLOCKED)
        self.assertEqual(self.parts.store.mode(self.b), MODE_STRICT)
        unbound = self.parts.codes.generate(1)['id']
        response = await self.call('POST', '/api/admin/ok', {'codigo': unbound, 'individual_only': True}, self.admin)
        self.assertEqual(response.status, 403)

    async def test_invalid_json_and_duration(self):
        self.assertEqual((await self.call('POST', '/api/virtual/devices', [], self.admin)).status, 400)
        self.assertEqual((await self.call('POST', f'/api/virtual/devices/{self.a}/unlock', {'hours': -1}, self.admin)).status, 400)
        code = body(await self.call('GET', f'/api/pedido/{self.a}?nuevo=1'))['codigo']
        _, key = self.parts.api_keys.create('activar')
        self.assertEqual((await self.call('POST', '/api/v1/activar', {'codigo': code, 'ip': '198.51.100.99'}, {'X-API-Key': key})).status, 400)
        self.assertEqual(self.parts.store.mode(self.a), MODE_STRICT)

    async def test_persistent_redeem_rate_limit(self):
        for _ in range(10):
            response = await self.call('POST', '/api/canjear', {'codigo': '000000', 'token': self.a})
            self.assertEqual(response.status, 403)
        self.assertEqual((await self.call('POST', '/api/canjear', {'codigo': '000000', 'token': self.a})).status, 429)

    async def test_upstream_cache_expiry_ttl_and_inflight(self):
        upstream = Upstream((), (), cache_ttl=5)
        calls = []
        async def forward(request, wire):
            calls.append(1)
            await asyncio.sleep(0)
            return await Resolver().resolve(wire)
        upstream._forward = forward
        a, b = DNSRecord.question('test.example'), DNSRecord.question('test.example')
        a.header.id, b.header.id = 1, 2
        replies = await asyncio.gather(upstream.resolve(a.pack()), upstream.resolve(b.pack()))
        self.assertEqual(len(calls), 1)
        self.assertEqual([DNSRecord.parse(r).header.id for r in replies], [1, 2])
        self.assertLessEqual(upstream._cache_ttl_for(replies[0]), 5)
        original = time.monotonic()
        with patch('blockservi.upstream.time.monotonic', return_value=original + 2):
            cached = await upstream.resolve(a.pack())
            self.assertLess(DNSRecord.parse(cached).rr[0].ttl, 30)
        a.header.cd = 1
        await upstream.resolve(a.pack())
        self.assertEqual(len(calls), 2)
        reply = DNSRecord.parse(replies[0]); reply.rr[0].ttl = 0
        self.assertEqual(upstream._cache_ttl_for(reply.pack()), 0)
        mismatch = DNSRecord.question('wrong.example').reply().pack()
        with self.assertRaises(UpstreamError):
            upstream._check_matching(mismatch, b.pack())

    async def test_upstream_failure_and_duplicate_questions(self):
        async def failed(wire):
            raise UpstreamError('fixture failure')
        self.parts.filter.upstream.resolve = failed
        wire = DNSRecord.question('youtube.com').pack()
        reply = await self.parts.filter.handle(wire, self.a)
        self.assertEqual(DNSRecord.parse(reply).header.rcode, RCODE.SERVFAIL)
        query = DNSRecord.question('youtube.com');query.questions.append(query.q)
        self.assertEqual(DNSRecord.parse(await self.parts.filter.handle(query.pack(), self.a)).header.rcode, RCODE.FORMERR)
        log = Path(self.config.log_file).read_text()
        self.assertNotIn(self.a, log)


if __name__ == '__main__':
    unittest.main(verbosity=2)
