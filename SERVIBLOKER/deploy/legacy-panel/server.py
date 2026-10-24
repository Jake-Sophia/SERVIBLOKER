"""Panel privado adicional. El backend conserva toda decisión de autorización."""
import asyncio
from collections import defaultdict, deque
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import time

from aiohttp import ClientSession, ClientTimeout, web

BASE = '/administracion'
COOKIE = 'iblocker_admin_panel'
SESSION_SECONDS = 12 * 3600
ASSETS = Path(__file__).parent


class Panel:
    def __init__(self, store, codes, admin_key, access_hash, origin, port=8080, backend=None):
        self.store, self.codes = store, codes
        self.admin_key, self.access_hash = admin_key, access_hash
        self.origin, self.port = origin, port
        self.backend_override = backend
        self.sessions = {}
        self.failures = defaultdict(deque)
        self.client = None

    def session(self, request):
        sid = request.cookies.get(COOKIE, '')
        session = self.sessions.get(sid)
        if not session or session['until'] <= time.time():
            self.sessions.pop(sid, None)
            raise web.HTTPUnauthorized(text='sesion_requerida')
        return session

    def write_access(self, request):
        session = self.session(request)
        if (request.headers.get('Origin') != self.origin or
                not hmac.compare_digest(request.headers.get('X-IBLOKER-CSRF', ''), session['csrf'])):
            raise web.HTTPForbidden(text='origen_o_sesion_invalida')
        return session

    async def login(self, request):
        if request.headers.get('Origin') != self.origin:
            raise web.HTTPForbidden()
        peer = request.headers.get('X-Forwarded-For', request.remote or '').split(',')[-1].strip()
        now = time.time()
        # Unbounded client identifiers must not grow process memory indefinitely.
        if len(self.failures) > 2000:
            self.failures = defaultdict(deque, {k: v for k, v in self.failures.items()
                                               if v and v[-1] > now - 60})
        queue = self.failures[peer]
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= 10:
            raise web.HTTPTooManyRequests(headers={'Retry-After': '60'})
        data = await request.json()
        key = data.get('key', '') if isinstance(data, dict) else ''
        if not isinstance(key, str) or not hmac.compare_digest(
                hashlib.sha256(key.encode()).hexdigest(), self.access_hash):
            queue.append(now)
            raise web.HTTPUnauthorized(text='enlace_invalido')
        self.sessions = {k: v for k, v in self.sessions.items() if v['until'] > now}
        if len(self.sessions) >= 100:
            raise web.HTTPTooManyRequests()
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.sessions[sid] = {'until': now + SESSION_SECONDS, 'csrf': csrf}
        response = web.json_response({'ok': True})
        response.set_cookie(COOKIE, sid, max_age=SESSION_SECONDS, path=BASE,
                            secure=True, httponly=True, samesite='Strict')
        return response

    async def logout(self, request):
        self.write_access(request)
        self.sessions.pop(request.cookies.get(COOKIE, ''), None)
        response = web.json_response({'ok': True})
        response.del_cookie(COOKIE, path=BASE, secure=True, httponly=True, samesite='Strict')
        return response

    def snapshot(self):
        now = int(time.time())
        devices = {d['token']: d for d in self.store.list()}
        pending = {}
        for row in self.store.pending_requests():
            code = str(row.get('codigo', ''))
            if re.fullmatch(r'[0-9]{6}', code):
                owner = row.get('token', '')
                pending[code] = {'code': code, 'label': devices.get(owner, {}).get('label') or 'Sin perfil vinculado',
                                 'individual': owner in devices, 'requested_at': row.get('solicitado', 0)}
        for row in self.codes.list():
            if not row.get('pending') or row.get('usado_at') or row.get('vencido'):
                continue
            if int(row.get('created_at', 0)) < now - 12 * 3600:
                continue
            if row.get('valido_hasta') and row['valido_hasta'] <= now:
                continue
            code, owner = str(row.get('id', '')), row.get('token', '')
            if code in pending or not re.fullmatch(r'[0-9]{6}', code):
                continue
            # Only phone requests belong here; unredeemed inventory is different.
            if row.get('origen') not in ('movil', 'mobile', ''):
                continue
            pending[code] = {'code': code, 'label': devices.get(owner, {}).get('label') or 'Sin perfil vinculado',
                             'individual': owner in devices, 'requested_at': row.get('created_at', 0)}
        active = [{'id': d['token'], 'label': d.get('label') or 'iPhone',
                   'until': int(d.get('unlocked_until', 0))}
                  for d in devices.values() if int(d.get('unlocked_until', 0)) > now]
        return {'pending': sorted(pending.values(), key=lambda r: r['requested_at'], reverse=True)[:100],
                'active': sorted(active, key=lambda r: r['until']), 'device_count': len(devices),
                'updated_at': now}

    async def state(self, request):
        session = self.session(request)
        result = await asyncio.to_thread(self.snapshot)
        return web.json_response(dict(result, csrf=session['csrf']))

    async def backend(self, path, body):
        if self.backend_override:
            return await self.backend_override(path, body)
        async with self.client.post('http://127.0.0.1:' + str(self.port) + path,
                                    json=body, headers={'X-Admin-Key': self.admin_key}) as response:
            return response.status, await response.json()

    async def approve(self, request):
        self.write_access(request)
        data = await request.json()
        if not isinstance(data, dict):
            raise web.HTTPBadRequest()
        code, hours = str(data.get('code', '')).strip(), data.get('hours')
        if not re.fullmatch(r'[0-9]{6}', code) or type(hours) is not int or not 1 <= hours <= 2160:
            return web.json_response({'error': 'codigo_u_horas_invalidos'}, status=400)
        try:
            status, result = await self.backend('/api/admin/ok',
                                                {'codigo': code, 'horas': hours, 'individual_only': True})
        except (TimeoutError, OSError, ValueError):
            return web.json_response({'error': 'servidor_no_disponible'}, status=502)
        # Never return admin credentials, IP permissions or legacy browser identifiers.
        return web.json_response({k: result[k] for k in ('ok', 'error', 'unlocked_until', 'hours')
                                  if k in result}, status=status)

    async def revoke(self, request):
        self.write_access(request)
        data = await request.json()
        token = data.get('id', '') if isinstance(data, dict) else ''
        if not isinstance(token, str) or not re.fullmatch(r'[0-9a-f]{12,48}', token):
            raise web.HTTPBadRequest()
        if not await asyncio.to_thread(self.store.device, token):
            raise web.HTTPNotFound()
        status, result = await self.backend('/api/bloquear/' + token, {})
        return web.json_response({'ok': bool(result.get('ok'))}, status=status)

    async def asset(self, request):
        name = 'app.js' if request.path.endswith('/app.js') else 'index.html'
        return web.Response(body=(ASSETS / name).read_bytes(),
                            content_type='application/javascript' if name.endswith('.js') else 'text/html')

    def app(self):
        @web.middleware
        async def headers(request, handler):
            try:
                response = await handler(request)
            except web.HTTPException as exc:
                response = exc
            response.headers.update({'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                                     'X-Content-Type-Options': 'nosniff',
                                     'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
            return response
        app = web.Application(middlewares=[headers], client_max_size=8192)
        app.router.add_get(BASE, self.asset)
        app.router.add_get(BASE + '/', self.asset)
        app.router.add_get(BASE + '/app.js', self.asset)
        app.router.add_post(BASE + '/api/session', self.login)
        app.router.add_post(BASE + '/api/logout', self.logout)
        app.router.add_get(BASE + '/api/state', self.state)
        app.router.add_post(BASE + '/api/approve', self.approve)
        app.router.add_post(BASE + '/api/revoke', self.revoke)
        async def start(app):
            self.client = ClientSession(timeout=ClientTimeout(total=15), trust_env=False)
        async def stop(app):
            await self.client.close()
        app.on_startup.append(start)
        app.on_cleanup.append(stop)
        return app


def main():
    import sys
    sys.path.insert(0, '/opt/blockservi')
    from blockservi.config import load
    from blockservi.store import Store
    from blockservi.codes import Codes
    config = load('/etc/blockservi/blockservi.ini')
    credentials = json.loads(Path('/etc/iblocker-panel/access.json').read_text())
    panel = Panel(Store(config.state_file), Codes(str(Path(config.data_dir) / 'codes.json')),
                  config.admin_key, credentials['access_hash'], 'https://' + config.portal_host,
                  config.http_port)
    web.run_app(panel.app(), host='127.0.0.1', port=8091, access_log=None, print=None)


if __name__ == '__main__':
    main()
