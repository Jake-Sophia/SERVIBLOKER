"""Sólo para namespaces de prueba, sin leer estado de producción."""
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blockservi.controller import render_rules
from blockservi.store import Store
from blockservi.rules import Policy

with tempfile.TemporaryDirectory() as directory:
    store = Store(str(Path(directory) / 'devices.json'))
    token = store.add()['token']
    store.unlock(token, '', 1)
    sessions = [{'token': token, 'reqid': 77, 'virtual_ips': ['10.77.0.2']}]
    print(render_rules(store, sessions, {'pool4': '10.77.0.0/24', 'pool6': 'fd77:77::/120',
          'portal_ips': ['203.0.113.10']}, [], Policy({})))
