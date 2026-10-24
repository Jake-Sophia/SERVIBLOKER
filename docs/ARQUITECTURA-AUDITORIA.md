# Etapa A: arquitectura observada antes de cambios

Revisión de main, con diagramas consultados en origin/feature/analisis: 01, 02,
03, 04, 04b, 05, 06, 06b y 07. El repositorio contiene el paquete dentro de
SERVIBLOKER/. No existe AGENTS.md. Esta revisión de código sirve a la implementación;
no certifica la infraestructura desplegada.

## Componentes existentes

- cli.py construye Policy, Store, Licenses, Codes, ApiKeys, QueryLog, Upstream,
  Filter y Service; inicia aiohttp y DNS UDP/TCP (PlainBridge). El mapa DNS está vacío.
- web.py sirve DoH por host individual o compartido, códigos, panel y API con scopes.
- profile.py produce plist DNS, un payload cautivo no verificado y VPN EAP compartida.
- store.py guarda devices/ips en JSON; códigos de solicitud y ventanas de autorización.
- codes.py mantiene códigos de seis dígitos pregenerados y del navegador en otro JSON.
- licenses.py lee licencias externas; no consume licencias ni controla cupos.
- apikeys.py guarda hashes SHA-256, permisos y revocación. Las claves son globales
  por servicio, no hay tenants: no se debe vender este panel como multiempresa aislada.
- rules.py decide deny_always, unlocked, deny_strict, allow_strict y opcionales.
- dnsfilter.py comprueba modo antes de Upstream; produce NXDOMAIN/cautivo/SERVFAIL.
- upstream.py implementa DoH/UDP, caché e inflight. querylog.py registra bloqueos.
- portal.py genera HTML responsive y JS; plain.py adapta UDP/TCP al bucle async.

## Fallos constatados por trazado de código

1. _activar abre token E IP: fuga entre clientes NAT. token_by_ip revela otro token.
2. handle_revoke no corta Store; API revoca IP pero omite token.
3. CF-Connecting-IP se acepta desde cualquier peer y XFF desde el extremo incorrecto.
4. admin_key en query y JS; registro de códigos permite cambiar propietario;
   estado de seis dígitos expone token y datos sin prueba de posesión.
5. RateLimiter no se utiliza y no es persistente. Códigos del navegador usan Math.random.
6. Store/Codes tienen RLock por instancia pero no exclusión entre CLI y servicio;
   JSON temporal se crea con permisos ambiente. Canje y activación en archivos distintos
   no forman una transacción. Se debe serializar y fallar cerrado ante fallos parciales.
7. DNSSettings usa DNSServerURLs en vez de DNSProtocol/ServerURL; cautivo no verificable.
   VPN usa usuario/password globales y promete garantías que iOS manual no proporciona.
8. Listas no incluyen YouTube/Telegram prometidos y bloquean Find My/localización.
9. Caché ignora CD/EDNS, no envejece TTL, impone mínimos y no acota al TTL configurado;
   UDP usa QTYPE entero donde dnslib espera nombre y no valida pregunta/ID.
10. Consulta sin preguntas causa error al intentar construir FORMERR.
11. Scripts históricos pueden detener nginx, copiar configuración y reiniciar servicios.
    No se han ejecutado. No existe servidor strongSwan/firewall implementado en main;
    llamadas a scripts externos ignoran sus errores y no prueban acceso efectivo.

## Plan e invariantes

B: preservar devices.json y tokens antiguos; nuevos tokens de 192 bits, profile UUID,
revocación persistente, identidad explícita. Compartido sólo opt-in de compatibilidad.
Perfil DoH en ruta individual del portal evita certificado TLS por teléfono nuevo.
C: CA y claves de firma fuera del proceso web, PKCS#12 por equipo, strongSwan pubkey
con SAN individual, inventario de sesiones VICI. No instalar SCEP ni descargar al instalar.
D: controlador root separado: inventario VICI + Store, nftables con timeout por autorización,
reglas antes de conntrack, aislamiento por IP INTERNA y reqid autenticado IPsec. Sin sudo web.
E: login con cookie Secure/HttpOnly/SameSite, operaciones del panel y descarga autenticadas,
sondeo de estado observado distinto del deseado. F: regresiones DNS/API/concurrencia,
plist, credenciales y reglas; prueba Linux aislada y pruebas físicas explícitas pendientes.

## Fuentes de esquema consultadas (23 octubre 2026)

- https://github.com/apple/device-management (schemas DNS, VPN, WiFi, certificados)
- https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary
- https://support.apple.com/en-us/101555 (conectividad y servicios Apple)
- https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html
- https://docs.strongswan.org/docs/latest/plugins/vici.html

Objetivo inicial: iOS 16–26, instalación manual removible. Validación plist y esquema
no equivale a prueba de instalación en iPhone. MDM/supervisión y Always On no están implementados.
