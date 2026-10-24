"""Run as root inside `unshare --net`, never in the host network namespace.

Uses two further disposable namespaces and documentation-only destinations.
"""
import importlib.util
import json
import os
import subprocess
import sys
import time

spec=importlib.util.spec_from_file_location('guard',sys.argv[1])
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=5)

def ns(pid,*args):
    return run('nsenter','-t',str(pid),'-n','--',*args)

children=[]
try:
    for unused in range(2):
        child=subprocess.Popen(['unshare','--net','sleep','40'])
        children.append(child)
    time.sleep(.2)
    client,server=[c.pid for c in children]
    assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Require isolated parent namespace'
    run('sysctl','-w','net.ipv6.conf.all.disable_ipv6=0','net.ipv6.conf.default.disable_ipv6=0')
    for pid in (client,server):ns(pid,'sysctl','-w','net.ipv6.conf.all.disable_ipv6=0','net.ipv6.conf.default.disable_ipv6=0')
    run('ip','link','set','lo','up')
    for name,pid in [('cl',client),('sv',server)]:
        run('ip','link','add',name+'a','type','veth','peer','name',name+'b')
        run('ip','link','set',name+'b','netns',str(pid))
        run('ip','link','set',name+'a','up')
        ns(pid,'ip','link','set','lo','up');ns(pid,'ip','link','set',name+'b','up')
    for dev,addr in [('cla','10.77.10.1/24'),('cla','fd77:77:10::1/120'),('sva','198.18.0.1/24'),('sva','2001:db8:2::1/64')]:
        run('ip','addr','add',addr,'dev',dev,*(['nodad'] if ':' in addr else []))
    for pid,dev,addr in [(client,'clb','10.77.10.10/24'),(client,'clb','fd77:77:10::10/120'),(server,'svb','198.18.0.2/24'),(server,'svb','2001:db8:2::2/64')]:
        ns(pid,'ip','addr','add',addr,'dev',dev,*(['nodad'] if ':' in addr else []))
    for pid,v4,v6 in [(client,'10.77.10.1','fd77:77:10::1'),(server,'198.18.0.1','2001:db8:2::1')]:
        ns(pid,'ip','route','add','default','via',v4)
        ns(pid,'ip','-6','route','add','default','via',v6)
    # An IPsec policy tunnel needs no NDP. Fix neighbours in the veth fixture
    # so its layer-2 discovery does not require extra production INPUT permits.
    router_mac=json.loads(run('ip','-json','link','show','cla').stdout)[0]['address']
    client_mac=json.loads(ns(client,'ip','-json','link','show','clb').stdout)[0]['address']
    ns(client,'ip','-6','neigh','replace','fd77:77:10::1','lladdr',router_mac,'nud','permanent','dev','clb')
    run('ip','-6','neigh','replace','fd77:77:10::10','lladdr',client_mac,'nud','permanent','dev','cla')
    run('sysctl','-w','net.ipv4.ip_forward=1','net.ipv6.conf.all.forwarding=1')
    time.sleep(1.2)  # IPv6 DAD, isolated namespace only.
    echo='''import socket,threading,time
+def serve(host,family):
+ s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((host,443));s.listen()
+ while True:
+  c,a=s.accept()
+  def handle(c):
+   try:
+    while True:
+     b=c.recv(100)
+     if not b:break
+     c.sendall(b)
+   finally:c.close()
+  threading.Thread(target=handle,args=(c,),daemon=True).start()
+for h,f in [('198.18.0.2',socket.AF_INET),('2001:db8:2::2',socket.AF_INET6)]:threading.Thread(target=serve,args=(h,f),daemon=True).start()
+time.sleep(35)
+'''.replace('\n+','\n')
    proc=subprocess.Popen(['nsenter','-t',str(server),'-n','--',sys.executable,'-c',echo]);children.append(proc)
    time.sleep(.3)
    def probe(host,allowed):
        code='import socket,sys\ntry:\n s=socket.create_connection((sys.argv[1],443),.5);s.sendall(b"OK");ok=s.recv(2)==b"OK"\nexcept OSError:ok=False\nassert ok==bool(int(sys.argv[2])),(sys.argv[1],ok)'
        ns(client,sys.executable,'-c',code,host,str(int(allowed)))
    guard.nft(guard.rules())
    guard.nft('add element inet iblocker_delivery unlocked4 { 10.77.10.10 timeout 5s }\nadd element inet iblocker_delivery unlocked6 { fd77:77:10::10 timeout 5s }')
    probe('198.18.0.2',False);probe('2001:db8:2::2',False)
    print('PASS: spoofed pool addresses without IPsec are rejected',flush=True)
    guard.nft('delete table inet iblocker_delivery\n'+guard.rules(require_ipsec=False))
    probe('198.18.0.2',False);probe('2001:db8:2::2',False)
    print('PASS: pending IPv4 and IPv6 traffic is blocked',flush=True)
    guard.nft('add element inet iblocker_delivery unlocked4 { 10.77.10.10 timeout 5s }\nadd element inet iblocker_delivery unlocked6 { fd77:77:10::10 timeout 5s }')
    probe('198.18.0.2',True);probe('2001:db8:2::2',True)
    print('PASS: authorised IPv4 and IPv6 traffic works',flush=True)
    # Keep a TCP connection alive across revocation: existing sessions must close.
    revoke='''import socket,sys,time
+s=socket.create_connection(('198.18.0.2',443),1);s.settimeout(.7);s.sendall(b'OK');assert s.recv(2)==b'OK'
+print('CONNECTED',flush=True)
+sys.stdin.readline()
+try:s.sendall(b'OK');allowed=s.recv(2)==b'OK'
+except OSError:allowed=False
+assert not allowed,'established TCP survived revocation'
+'''.replace('\n+','\n')
    live=subprocess.Popen(['nsenter','-t',str(client),'-n','--',sys.executable,'-c',revoke],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);children.append(live)
    assert live.stdout.readline().strip()=='CONNECTED'
    guard.nft('flush set inet iblocker_delivery unlocked4\nflush set inet iblocker_delivery unlocked6')
    live.communicate('\n',timeout=3);assert live.returncode==0
    probe('198.18.0.2',False);probe('2001:db8:2::2',False)
    print('PASS: revocation blocks new connections and established TCP',flush=True)
    guard.nft('add element inet iblocker_delivery unlocked4 { 10.77.10.10 timeout 1s }\nadd element inet iblocker_delivery unlocked6 { fd77:77:10::10 timeout 1s }')
    time.sleep(1.2)
    probe('198.18.0.2',False);probe('2001:db8:2::2',False)
    print('PASS: kernel timeout closes access if controller stops',flush=True)
finally:
    for child in reversed(children):
        if child.poll() is None:child.terminate()
    for child in children:
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:child.kill()
