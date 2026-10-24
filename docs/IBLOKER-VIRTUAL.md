# Operación y despliegue IBLOKER VIRTUAL

## Qué se ha implementado

El paquete Python existente permanece en `SERVIBLOKER/blockservi`. Se mantienen
licencias JSON externas, códigos de seis dígitos, API con scopes, CLI, motor DNS,
registro de consultas y panel. Se añaden:

- Tokens nuevos de 192 bits, UUID por perfil y revocación persistente.
- Plist DoH con `DNSProtocol=HTTPS` y `ServerURL` individual. Sin SCEP ni descargas
  auxiliares al instalar. Ruta nueva `/dns-query/{token}`; hosts antiguos conservados.
- Certificados RSA individuales, SAN `<token>.iblocker.invalid`, PKCS#12 autocontenido,
  CA privada sólo root, CRL cargada en strongSwan mediante VICI.
- Controlador root que observa VICI en ciclos con pausa de cinco segundos, termina SA revocadas,
  duplicadas simultáneas o con credencial vencida, y actualiza su tabla `inet iblocker`.
- Guardia anterior al arranque de strongSwan, autorización por IP interna **y reqid
  IPsec**, políticas IPv4/IPv6, NAT y aislamiento lateral. No usa la IP pública como permiso.
- Sets de autorización con timeout máximo de 15 s, limitado por fecha de autorización
  y licencia. Una avería del controlador deja de renovar acceso; el cierre ocurre
  por timeout incluso si el proceso se detiene. No se borran otras tablas nft.
- Sesión administrativa de ocho horas, cabeceras para CLI/API, protección CSRF,
  límites persistentes SQLite y bloqueos JSON entre procesos.

La autorización pasa primero por validación y consumo del código; después se guarda
Store. DNS consulta el estado en cada petición antes de la caché. El controlador
aplica el estado al siguiente ciclo (pausa de 5 s más el tiempo de trabajo/VICI); el panel indica su estado observado. No hay
transacción distribuida entre dos JSON: ante interrupción después del consumo puede
quedar un código consumido sin conceder acceso. Se recupera autorizando directamente
la identidad desde el panel; nunca se debe reabrir el código usado.

## Preparar un VPS sin alterar producción

No se ha conectado ni modificado ningún VPS durante esta implementación. Usar primero
una VM Linux de laboratorio. Requisitos: Debian/Ubuntu con systemd, Python >=3.10,
strongSwan swanctl/VICI, nftables con expresiones `ipsec`, conectividad IPv4 y, para
salida IPv6, conectividad IPv6 en el VPS. No usar esta receta sin revisar otros
servicios, reglas FORWARD, NAT, pools, rutas Docker, proxy o una VPN ya instalada.

Desde la carpeta interna `SERVIBLOKER/`:

```sh
sudo bash deploy/virtual/prepare-vps.sh --check
```

El modo de inspección no instala ni cambia reglas. Guardar copias privadas de
`/etc/blockservi`, `/etc/swanctl`, configuración del proxy y datos del servicio, y
una captura de `nft list ruleset`/`ip xfrm policy` antes de la integración.

En un VPS preparado y revisado, el instalador base requiere confirmación explícita
mediante argumento; copia el código y reinicia **blockservi**:

```sh
# Crear blockservi.ini privado desde el ejemplo, con clave aleatoria y hosts reales.
sudo bash deploy/install.sh /ruta/privada/blockservi.ini --apply-reviewed
sudo bash deploy/virtual/prepare-vps.sh --apply-reviewed
```

El segundo comando puede instalar paquetes del sistema; sus scripts Debian pueden
iniciar el daemon stock. Se niega si detecta VPN activa o conexiones swanctl existentes.
En una máquina con VPN previa, integrar manualmente: no detenerla ni reemplazar sus
archivos. El despliegue antiguo que detenía nginx quedó deshabilitado. No ejecutar
`desplegar-vps.sh` como una receta de actualización.

## DNS y TLS públicos

Crear registros A/AAAA para `portal.example.com` y `vpn.example.com` apuntando al VPS.
Terminar HTTPS del portal con certificado público válido. Nuevos perfiles usan el
mismo certificado del portal; ya no necesitan emitir un certificado por token.
Conservar registros, certificados y proxy de `dev-<token>.dns...` de perfiles antiguos.

Integrar `deploy/Caddyfile` o `deploy/nginx.conf` con el proxy actual, validarlo con
`caddy validate` o `nginx -t` antes de recargar. Nunca copiar encima de la configuración
sin revisión. Deshabilitar access logs de las rutas de dispositivos: el token es una
credencial bearer y aparece en la URI. Desactivar también logs de esas URI en CDN,
WAF, balanceadores y monitorización. El backend deshabilita su access log y QueryLog
usa un hash de identidad. Los perfiles contienen claves privadas; no subirlos a Git,
logs, tickets ni un directorio web público.

`trusted_proxies` contiene sólo redes de proxies administrados. El código ignora
`CF-Connecting-IP` y examina XFF de derecha a izquierda. Si hay Cloudflare delante,
configurar la confianza y el saneado del proxy; no añadir rangos de clientes como
proxies confiables. Mantener el backend escuchando sólo en loopback.

## Configurar y emitir certificados

En `/etc/blockservi/blockservi.ini` configurar:

```ini
[general]
; además de las claves/rutas del ejemplo
trust_ip = false
legacy_admin_query = false
doh_server_addresses = IP_PUBLICA_REAL_DEL_PORTAL
[vpn]
vpn_enabled = true
vpn_address = vpn.example.com
vpn_remote = vpn.example.com
credentials_dir = /var/lib/blockservi/credentials
ca_file = /var/lib/blockservi/vpn-ca.der
```

No poner `vpn_auth_user` ni `vpn_auth_pass`: la configuración se rechaza si intenta
usar credenciales globales con VPN. La CA del VPN es distinta del certificado HTTPS.
Inicializarla una sola vez, en un directorio nuevo:

```sh
cd /opt/blockservi
sudo .venv/bin/python -m blockservi.provision --config /etc/blockservi/blockservi.ini
```

Produce CA privada root en `/var/lib/iblocker-pki`, servidor VPN en `/etc/swanctl`,
CA DER pública para los perfiles y SQLite privado del servicio. No imprime claves.
Respaldar la CA cifrada y fuera del repositorio. Los clientes duran 90 días; servidor,
365 días; CA, diez años. No existe renovación transparente de perfiles offline:
antes del vencimiento emitir una nueva identidad/perfil y retirar el anterior.
No eliminar el registro raíz de certificados cliente: permite revocar equipos borrados.
Si se interrumpe la emisión entre guardar certificado y publicar PKCS#12, falla
cerrado; revisar el certificado huérfano y emitir una identidad nueva.

Copiar/revisar `swanctl.conf.example` a `/etc/swanctl/conf.d/iblocker.conf`; sustituir
identificador del servidor. Verificar plugins `vici`, `revocation`, `x509`, `pubkey`,
`kernel-netlink`, `socket-default` y algoritmos RSA/AES/SHA compatibles. La plantilla
usa autenticación mutua pubkey y revocación estricta. No carga EAP compartido.

Copiar `firewall.json.example` a `/etc/blockservi/firewall.json`, root:root 0600.
Los pools deben coincidir exactamente con swanctl y no solaparse con redes existentes.
`portal_ips` incluye todas las direcciones A/AAAA del portal DoH. Revisar `deny_networks`
para impedir acceso a redes privadas/administrativas sin bloquear destinos esenciales.

## Guardia, arranque y puertos

Antes de cargar conexiones o habilitar forwarding, instalar guardia y dependencia:

```sh
sudo install -m 644 /ruta/SERVIBLOKER/deploy/virtual/iblocker-guard.service /etc/systemd/system/
sudo install -m 644 /ruta/SERVIBLOKER/deploy/virtual/iblocker-controller.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/strongswan.service.d
sudo install -m 644 /ruta/SERVIBLOKER/deploy/virtual/strongswan-guard.conf /etc/systemd/system/strongswan.service.d/iblocker-guard.conf
sudo systemctl daemon-reload
sudo systemctl enable --now iblocker-guard
```

La unidad presupone `strongswan.service` de charon-systemd. Adaptar dependencia si
el empaquetado usa otro nombre. No mezclar strongswan-starter/ipsec.conf y swanctl
sin un diseño de coexistencia. Ejecutar la prueba aislada Linux antes de activar:

```sh
sudo env PYTHON=/opt/blockservi/.venv/bin/python bash /ruta/SERVIBLOKER/tests/linux_firewall.sh
```

Después de comprobar impacto, permitir en el firewall existente UDP 500/4500 para
IKE/NAT-T, ESP si el camino no usa UDP encapsulado, y TCP 443 del portal. No abrir
8080 ni DNS recursivo UDP/TCP 5353 a internet. Las reglas de entrada al servicio
IKE pertenecen al firewall del host actual: el controlador sólo limita tráfico de
los pools VPN. Otros firewalls pueden seguir denegando tráfico aceptado por IBLOKER;
un veredicto accept de esta tabla no anula drops de otras tablas.

Sólo tras instalar la guardia y revisar reglas activar forwarding IPv4/IPv6 mediante
sysctl y persistirlo según la distribución. Mantener ICMP/ICMPv6 y PMTU de la red de
transporte. No se modifica sysctl automáticamente. Cargar certificados/conexión y
arrancar el controlador:

```sh
sudo swanctl --load-all
sudo systemctl enable --now iblocker-controller
sudo systemctl restart blockservi
sudo swanctl --list-sas
sudo nft list table inet iblocker
sudo journalctl -u iblocker-controller -n 50 --no-pager
```

Nunca probar `nft flush ruleset`. El controlador hace `nft --check` y aplica su
reemplazo en una transacción, con estados explícitos de error. Una excepción no se
presenta como firewall aplicado. La guardia se reinstala antes de strongSwan al
arrancar. No persistir snapshots de sets de autorizaciones como reglas de arranque.

## Panel y AirDrop

1. En iPhone A con internet, abrir `https://portal.example.com/login`; ingresar clave.
2. En **IBLOKER VIRTUAL**, generar equipo. Comienza RESTRICTED, sin autorización.
3. Si VPN está habilitada, esperar al certificado del controlador (hasta varios ciclos).
   Un fallo de emisión se muestra como pendiente/error; no se entrega un perfil VPN incompleto.
4. Descargar `.mobileconfig` individual. Guardar también la URL de activación del
   equipo; sólo se entrega a ese usuario. No compartir el mismo perfil entre equipos.
5. En A abrir Compartir → AirDrop → B. En B habilitar Wi-Fi/Bluetooth manualmente
   para AirDrop, sin necesidad de internet. AirDrop no demuestra la identidad hardware.
6. En B aceptar el archivo e instalar desde Ajustes → General → VPN y gestión del
   dispositivo. iOS puede pedir código de desbloqueo y consentimiento. No hay SCEP,
   inscripción remota ni ejecución arbitraria. Instalación offline requiere validación
   física por versión iOS; el archivo es autocontenido.
7. Si el dispositivo lo requiere para la CA manual, revisar Ajustes → General →
   Información → Ajustes de confianza de certificados. Verificar el nombre/huella
   de la CA por un canal propio. No habilitar confianza de una CA ajena.
8. B se conecta manualmente a Wi-Fi (o mediante el payload opcional). iOS intenta
   DoH y VPN On Demand; abrir la URL `/activar/{token}` entregada para solicitar código.
9. Administrador aprueba por panel/API o entrega código pregenerado de un solo uso.
   DNS aplica el cambio en consultas nuevas; firewall lo reconcilia en el siguiente
   ciclo. Confirmar estado operativo del controlador y la IP interna en el panel.
10. Revocar autorización vuelve a restringir. Revocar credencial invalida DoH y
    perfil y desencadena CRL/terminación de SA. Para reemitir, crear otra identidad.

Wi-Fi opcional desde CLI (archivo de contraseña privado, no argumento con secreto):

```sh
blockservi profile TOKEN -o /ruta/privada/iphone.mobileconfig \
  --wifi-ssid Oficina --wifi-security WPA2 --wifi-password-file /ruta/privada/wifi.txt
```

También `POST /perfil/{token}.mobileconfig` con `{ "wifi": { "ssid": "Oficina",
"security": "WPA2", "password": "...", "auto_join": true } }`, autenticado y por HTTPS.
La respuesta es el archivo, no una URL con contraseña. Métodos soportados: abierta,
WPA2 Personal y WPA3 Personal; no se implementa Wi-Fi Enterprise/802.1X.

## Migración y reversión

Respaldar `devices.json`, `codes.json`, `licenses.json` y `api_keys.json`. No se cambian
los tokens existentes; nuevas claves de metadatos son aditivas. Los JSON se mantienen
para compatibilidad. SQLite incorpora límites/observaciones y migra su columna de
vencimiento idempotentemente. Writers externos PHP deben respetar el mismo flock
o dejar de escribir directamente mientras el servicio opera: atomic replace por sí
solo no evita actualizaciones perdidas con writers ajenos.

Los teléfonos con perfil individual antiguo siguen usando su host; no retirar TLS.
El instalador conserva `policy.json` existente. Revisar e integrar las listas nuevas
para YouTube, conectividad y restricción de Meta/Telegram; no reemplazar reglas administrativas sin revisar.
Los servicios esenciales Apple se protegen también desde el motor, incluso con listas antiguas.

Los perfiles **compartidos** no admiten migración individual transparente: optar por
`trust_ip=true` temporalmente conserva ese comportamiento inseguro o entregar nuevos
perfiles individuales. El permiso por IP nunca se propaga a un token nuevo. La
aprobación vinculada a token nunca abre la IP pública. Registrar esta elección antes
de actualizar; no activar compatibilidad a ciegas.

`?k=` está deshabilitado; sustituir enlaces por `/login` y scripts por X-Admin-Key.
`legacy_admin_query=true` existe sólo como compatibilidad explícita y debe retirarse.
Los permisos API existentes siguen siendo por operador, no por organización/cliente.
La licencia se valida al aprobar y limita el vencimiento efectivo de DNS/VPN; no se
consume ni implementa una cuota de licencias que no existía.

El controlador puede detenerse con `deploy/virtual/rollback.sh --apply-reviewed`:
termina las SA propias y conserva guardia cerrada. No borra otras reglas. Antes de
retirar la tabla propia hay que descargar la conexión IBLOKER o cerrar IKE para
impedir sesiones nuevas. Restaurar código/configuración desde copias sólo después
de decidir cómo se conservará el aislamiento; nunca restaurar toda la tabla nft
en un servidor compartido sin revisar impacto.

## Límites explícitos

- Perfil removible: iOS manual permite al usuario quitarlo o desconectar VPN. On Demand
  no es Always On. Garantías de obligatoriedad requieren supervisión/MDM, no implementados.
- Un perfil estático no genera tokens al instalar ni activa el hardware Wi-Fi.
- Identidad bearer/certificado representa **el perfil**, no una huella hardware. Si se
  copia, comparte identidad. `unique=replace` sustituye SA previas; el controlador
  detecta simultaneidad que alcance a observar. No detecta clones alternándose ni
  garantiza ver solapamientos breves. Rekey/reconexión puede producir alertas conservadoras.
- El perfil incluye clave cliente exportable en su archivo. Revocar y reemitir ante fuga.
  No hay Secure Enclave ni atestación hardware offline.
- DNS sólo controla resolución; una IP memorizada, DoH externo o conexión ya existente
  puede evitarlo fuera del túnel. Dentro, el firewall controla destinos/IPsec, no apps.
- Lista restringida de servicios funciona por direcciones obtenidas de consultas DNS
  permitidas, con TTL y puertos 80/443/5223 TCP, 123/443 UDP. CDNs comparten IP y pueden
  habilitar servicios colaterales. Meta y Telegram están en deny_strict: restringidos
  sin código, permitidos durante autorización vigente. Las conexiones directas o ya
  abiertas pueden eludir DNS; su bloqueo de tráfico requiere el túnel operativo.
  YouTube, QUIC, push y servicios Apple se prueban por versión/región.
- Servicios esenciales Apple prevalecen sobre denies DNS, incluyendo iCloud y Find My.
  Esto concede infraestructura compartida amplia; no se usa para desactivar antirrobo.
- `deny_always` filtra nombres; sólo `deny_networks` impone bloqueos IP administrativos.
  No se promete bloqueo perfecto por dominio sobre conexiones a IP compartidas.
- Sondeo no es telemetría continua: DNS visto no equivale a teléfono conectado. VICI
  indica SA observada; tras 20 s sin observación el panel indica estado desconocido.
- Sin internet inicial no hay contacto VPS ni verificación remota de inscripción.
- No hay MDM, Always On, filtrado TLS, bloqueo de activación ni desactivación de Find My.
