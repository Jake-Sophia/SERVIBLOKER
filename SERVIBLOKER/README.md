# blockservi

Filtro de acceso a internet para iPhone que se instala como un **perfil `.mobileconfig`**, sin app y sin cuenta de Apple Developer. El iPhone resuelve todo su DNS contra este servicio, y el servicio decide que dominios funcionan segun el estado del dispositivo.

## Que hace

| Situacion | YouTube | Telegram | Pantalla del codigo | Cualquier otra app |
|---|---|---|---|---|
| Sin autorizacion | si | si | si | **cae en la pantalla del codigo** |
| Con autorizacion (24 h) | si | si | si | si |
| Con autorizacion, siempre | | | | **iTunes, App Store, Books y Buscar mi iPhone siguen bloqueados** |

Los tres ultimos dominios nunca se resuelven, tenga el dispositivo codigo o no. Tampoco se resuelven los resolventes DoH que usan algunas apps para saltarse el filtro.

## Como funciona

```
 iPhone abre una app bloqueada
            │
            ▼
   el DNS responde con la IP del VPS          ◀── en vez de NXDOMAIN
            │
            ▼
  el navegador abre la pantalla del codigo     ◀── el movil cae solo, sin links
            │
            ▼
  el movil genera un codigo de 6 digitos
             │
             ▼
  el administrador lo aprueba en /panel        ◀── 24 h de salida
```

Los estados son tres, y el tercero es fijo:

| Estado | Cuando | Que sale |
| --- | --- | --- |
| `strict` | perfil recien instalado, sin canjear | YouTube, Telegram y la pagina del codigo |
| `unlocked` | codigo canjeado y vigente | todo |
| `deny_always` | siempre | Libros, iTunes, Find My iPhone, DoH |

`deny_always` se comprueba **antes** que el modo, asi que autorizar un codigo
nunca abre esas tres: siguen vetadas mientras haya salida. Lo demas bloqueado en
`strict` no devuelve NXDOMAIN, resuelve a la IP del portal para que el movil
caiga en la pantalla del codigo.

Lo bloqueado **no falla en silencio**: resuelve a la IP del propio servidor, de
modo que al abrir una app el iPhone cae directamente en la pantalla del codigo.
El equipo se reconoce por su IP, asi que el empleado no tiene que buscar ningun
enlace ni escribir ninguna referencia. Si el DNS se consulta desde otra red, la
pantalla pide la referencia del equipo a mano.

El codigo lo genera **la propia pagina que ve el movil**, no el servidor, igual
que en la web de activacion que ya usaba tu personal. Al pulsar el boton genera
seis digitos, los registra y se queda esperando. Puede pulsar otra vez para
sacar un codigo nuevo: el anterior deja de valer.

El bloqueo permanente (App Store, Find My...) **no** usa ese truco: sigue
respondiendo NXDOMAIN, porque autorizar no lo arregla y mandar ahi a alguien a
pedir un codigo solo genera frustracion.

## Uso diario

**Tu, como administrador:**

```
https://vpnk.unlockersserver.com/panel?k=<admin_key>
```

Ahi ves cuatro bloques: las **solicitudes pendientes** (por si un equipo pidio
codigo por IP), los **equipos** y los **codigos** que han registrado los moviles,
con su estado y cuando caducan. Pulsas **Autorizar** y el equipo tiene acceso
completo las horas que elijas (24 por defecto). **Rechazar** descarta la
solicitud y el movil puede pedir otra. **Revocar** deja de valer un codigo sin
tocar el resto del equipo. **Bloquear** corta el acceso antes de tiempo.

La clave tambien va en la cabecera `X-Admin-Key` o en la query `?k=`, que es lo
que usan los scripts:

```sh
# autorizar
curl -X POST https://vpnk.unlockersserver.com/api/admin/ok \
  -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"codigo":"123456","horas":24}'

# bloquear
curl -X POST https://vpnk.unlockersserver.com/api/bloquear/<token> \
  -H "X-Admin-Key: $ADMIN_KEY"
```

Los codigos se guardan en `codes.json`, junto a `devices.json`. Cada equipo solo
puede consultar el estado del **suyo** (`/api/estado-codigo/<codigo>`), y la
lista completa (`/api/list`) pide la clave de administracion: en la web antigua
esa lista era publica y cualquiera que abriera la pagina veia los codigos de
todos los clientes.

**La persona con el telefono** no tiene que hacer nada: cuando le compensa,
abre el navegador, cae en la pantalla, pulsa *Pedir codigo de autorizacion*, te
dice los seis digitos y espera a que lo apruebes. La pantalla se refresca sola
cada 5 s y se recarga en cuanto le autorizas.


## Requisitos

- VPS con Ubuntu o Debian, root por SSH, puertos 80 y 443 libres.
- Un dominio en Cloudflare apuntando al VPS.
- Python 3.10 o superior en el servidor (lo instala el script).


## Instalacion

Todo en un paso. El script instala el servicio, instala Caddy, aparta nginx si
hace falta, pide los certificados y verifica que todo responde:

```bash
# Sube el codigo y las licencias
cd /ruta/al/proyecto
tar czf - --exclude=.venv --exclude=__pycache__ blockservi data/licenses.json \
  | ssh root@TU_VPS 'tar xzf - -C /tmp'

# Despliega
ssh root@TU_VPS 'bash /tmp/blockservi/deploy/desplegar-vps.sh tu@correo.com'
```

Despliegue manual, si prefieres paso a paso:

```bash
sudo ./deploy/install.sh deploy/blockservi.ini.produccion   # edita antes dominio y admin_key
sudo ./deploy/install.sh blockservi.ini                      # o con una config tuya
```

Y el proxy inverso, solo si no usas el script:

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile     # edita el dominio dentro
sudo systemctl reload caddy
```

## Registros DNS en Cloudflare

Tres registros, los tres en **nube gris**:

| Tipo | Nombre | Destino | Para que sirve |
|---|---|---|---|
| A | `app` | tu VPS | portal de activacion y perfiles |
| A | `dns` | tu VPS | validacion del certificado |
| A | `*.dns` | tu VPS | cada telefono: `dev-<token>.dns.tudominio.com` |

Si `dns` o `*.dns` los dejas proxysados, Cloudflare se interpone en las consultas DoH y el filtrado por token deja de funcionar.

El `dns` a secas no es un adorno: sin ese registro Let's Encrypt no puede validar el TLS y ningun telefono conecta.

### Por que no hay certificado comodin

Porque **Let's Encrypt solo ofrece dns-01 para los comodines**, y dns-01 obliga a crear un API token en Cloudflare. Caddy solo lo resolveria por su cuenta con ZeroSSL, que tiene la misma limitacion.

La solucion que se usa aqui es un host explicito por dispositivo. El DNS si es un comodin (solo resuelve, no pide certificado) y cada host concreto se pide por HTTP-01, sin credenciales. Al dar de alta un telefono:

```bash
sudo blockservi device add --label "Recepcion" --caddy-dir /etc/caddy/dispositivos
sudo systemctl reload caddy
```

Caddy emite el certificado en unos segundos. El Caddyfile principal hace `import /etc/caddy/dispositivos/*.caddy`, asi que no hay que tocarlo nunca.

## Dar de alta un telefono

Una linea por equipo:

Se instala **un solo perfil, el mismo en todos los iPhone**:

```
https://vpnk.unlockersserver.com/perfil/bloqueoservi.mobileconfig?k=<admin_key>
```

Este perfil no lleva token dentro: apunta a un unico DoH
(`https://vpnk.unlockersserver.com/dns-query`) y el telefono se reconoce por su
IP, asi que da igual en que iPhone se instale. Reinstalarlo en otro equipo no
arrastra el estado del anterior.

Cada telefono se registra solo en cuanto consulta por DNS, y a partir de ahi
aparece en el bloque **ACCESOS** del panel, con su IP, sus canjeos y si tiene
salida ahora mismo. Para cortarle el acceso: **Revocar** en esa fila, o
`POST /api/admin/ip/<ip>`. La revocacion deja la ventana a cero, no borra nada, y
vuelve al estado de espera sin reiniciar el servicio.

El token por telefono sigue existiendo para quien quiera un perfil propio
(`device add`, `dev-<token>.dns.*`). Es opcional: el perfil comun no lo usa.

En el iPhone: abre el enlace del perfil en **Safari**, pulsa **Instalar** y despues **Ajustes > General > VPN y Gestion del dispositivo > Instalar**. iOS pide un solo toque de consentimiento, sin contrasena ni codigo. En Ajustes > General > DNS aparece "Filtrado de acceso".

Listo. A partir de aqui no hay que hacer nada mas: cuando abra una app
bloqueada, el iPhone caera solo en la pantalla del codigo. El enlace
`/activar/<token>` tambien existe por si quieres mandarselo, y sirve para
comprobar que el equipo responde.

## Uso diario desde la consola

```bash
BS="sudo /opt/blockservi/.venv/bin/python -m blockservi --config /etc/blockservi/blockservi.ini"

$BS device list                      # estado, ultimo uso y cuantos codigos se gastaron
$BS device lock 7d57b0373487         # cortar el acceso ahora mismo
$BS device unlock 7d57b0373487       # dar 24 h sin pasar por el panel
$BS device delete 7d57b0373487       # dar de baja el equipo
$BS decide t.me itunes.apple.com     # como se resuelve un dominio, sin tocar la red
$BS log -n 50                        # consultas bloqueadas de las ultimas horas
```

El flujo normal ya no pasa por aqui: el movil pide su codigo y se aprueba desde
`/panel`. La consola es para el mantenimiento y para lasemeriencias.

## Codigos de licencia

El panel de `/panel` puede **consumir una licencia** al autorizar, para que el
control siga dependiendo del mismo `licenses.json` que genera tu panel PHP.
Eligiendo la opcion "Sin consumir licencia" se autoriza sin tocar el archivo.

Formato esperado:

```json
{
  "ABCD-1234": {
    "status": "active",
    "expires_at": 1790637933,
    "label": "Recepcion"
  }
}
```

Una licencia `revoked` o vencida no autoriza nada. Si el panel esta en otro
servidor, copia el fichero o monta la ruta en `licenses_file`; el servicio lo
relee solo cuando cambia, sin reiniciar.

Sincronizar: `deploy/sync-licencias.sh` (ver mas abajo).

## Ajustar las listas

Todo esta en `policy.json`. Copia el tuyo a `/var/lib/blockservi/policy.json` y reinicia el servicio.

```jsonc
"youtube.com",        // el dominio y todos sus subdominios
"=youtube.com",       // solo el nombre exacto
"re:^doh\\.",          // expresion regular

// deny_always      se aplica siempre, tenga codigo o no
// allow_strict     es lo unico que resuelve sin codigo
```

**Si algo no funciona, mira el registro antes de tocar nada:**

```bash
$BS log -n 100
```

Cada linea es un dominio que un telefono intento resolver y tu filtro rechazo. Si Telegram no carga y ves `cdn-telegram.org` ahi, lo anades a `allow_strict` y listo. Asi se mantiene la lista sin adivinar.

Cosas que probablementeayak que tocar segun como se comporte el telefono:

- `mzstatic.com` en `deny_always` es lo que corta iTunes y App Store, pero tambien lo usan some iconos del sistema. Si notas algo raro, quitalo.
- `allow_strict_optional` tiene la infraestructura de push de Google, para que las notificaciones de YouTube lleguen. Son endpoints compartidos: si prefieres cerrarlos, pon `strict_push: false` en el fichero.
- `captive.apple.com` y `time.apple.com` hacen falta para que iOS detecte la red y mantenga la hora. Sin `time.apple.com` el reloj puede derivar y las 24 h se descuadran.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_blockservi.py
```

Siete pruebas que cubren las reglas, el almacenamiento, el perfil, el filtro y el ciclo completo de activacion por HTTP. Sin dependencias de test: se ejecutan con `python` a pelo.

Contra un servicio ya desplegado:

```bash
.venv/bin/python tests/smoke.py --url http://127.0.0.1:8080 --token <TOKEN> --admin-key <CLAVE>
```

## Despliegue real (209.145.55.123 / unlockersserver.com)

Lo que quedo montado:

- `vpnk.unlockersserver.com` - portal de activacion y perfiles, con TLS de Let's Encrypt
- `dev-<token>.dns.unlockersserver.com` - un host y un certificado por telefono
- el puerto 80 abierto a todo (`Caddyfile`, bloque `:80`) para el portal cautivo
- `captive_ip = 209.145.55.123` en la configuracion, para que lo bloqueado caiga en la pantalla
- nginx parado, con su configuracion en `/root/nginx-backup` y las notas para volver atras en `/root/REVERTIR-NGINX.txt`
- `blockservi` como servicio systemd, reinicio automatico
- comando `blockservi` en `/usr/local/bin`, que baja al usuario del servicio

Sin API token de Cloudflare, sin tocar el panel PHP.

### Dar de alta un telefono nuevo

```bash
ssh root@209.145.55.123
blockservi device add --label "Almacen" --caddy-dir /etc/caddy/dispositivos
systemctl reload caddy
```

Imprime el token, la URL de activacion y el enlace al perfil. El perfil tambien se descarga desde el portal con la admin_key.

### Sincronizar los codigos del panel PHP

El panel escribe en tu Mac y el servicio lee en el VPS, asi que hay que copiar el fichero cuando generas codigos:

```bash
cd "/Users/james/Documents/ChatGPT/New project"
BLOCKSERVI_SSH_KEY=~/.ssh/servibloker_vps ./blockservi/deploy/sync-licencias.sh
```

La variable es para que use tu clave en vez de pedir la contraseña. Si prefieres
no escribirla, exporta `BLOCKSERVI_SSH_KEY` una vez en tu `~/.zshrc`.

El servicio lo relee solo al cambiar el mtime, sin reiniciar.

## Limitaciones que conviene conocer

- **Filtrado por dominio, no por app.** Una app con una IP memorizada puede seguir hablando con ella sin pasar por DNS.
- **El DNS se puede cambiar.** En un iPhoneProfile instalado a mano, el usuario puede borrar el perfil o volver a poner un DNS en Ajustes. Si necesitas que no se pueda, hace falta un dispositivo supervisado con MDM, que es otro proyecto.
- **DoH con IP fija.** Se bloquean los resolventes DoH por nombre, pero una app que traiga `1.1.1.1` escrito en el codigo no lo puede evitar el filtro.
- **Buscar mi iPhone.** Bloquear `ls.apple.com` y los hosts de Find My corta la localizacion, pero tambien te quita la proteccion antifurto de Apple. Para privacy real de los empleados conviene un Apple ID corporativo por dispositivo en lugar de desactivar Find My.
- **Actualizaciones de apps.** `xp.apple.com` esta bloqueado, asi que sin codigo las apps no se actualizan. Es intencionado: con codigo vuelve a funcionar.

## Ficheros

```
blockservi/
  rules.py       motor de reglas: listas, coincidencia, decisiones
  dnsfilter.py   aplica la politica a una consulta y construye la respuesta
  upstream.py    reenvio a 1.1.1.1/8.8.8.8 con cache y sin repetir consultas
  store.py       dispositivos y ventanas de 24 h, con escritura atomica
  licenses.py    lectura de licenses.json del panel PHP
  querylog.py    registro de consultas bloqueadas
  web.py         DoH, portal de activacion y API
  plain.py       DNS en claro para el propio VPS y pruebas
  profile.py     generacion del .mobileconfig
  cli.py         serve, device, profile, decide, log
  policy.json    las listas de dominios
deploy/          install.sh, blockservi.service, Caddyfile, nginx.conf
tests/           test_blockservi.py, smoke.py
```

## API para activarlo desde otro servidor

Tu servidor de `unlockersserver.com` puede activar codigos sin usar el panel.
Usa claves con permisos, que se revocan sin tocar nada mas:

```bash
blockservi apikey create --scope activar --note "mi servidor"
blockservi apikey list
blockservi apikey revoke <id>
```

La clave se manda **solo por cabecera**, nunca en la query, para que no acabe en
los registros de acceso de Caddy. De la clave solo se guarda el hash.

| Permiso | Endpoint | Que hace |
|---------|----------|----------|
| `activar` | `POST /api/v1/activar` | activa un codigo |
| `consultar` | `GET /api/v1/estado/{codigo}` | estado de un codigo |
| `revocar` | `POST /api/v1/revocar` | anula un codigo |

Activar, con el codigo tal cual lo teclea el usuario:

```bash
curl -X POST https://vpnk.unlockersserver.com/api/v1/activar \
  -H "X-API-Key: bsk_live_..." -H "Content-Type: application/json" \
  -d '{"codigo":"108587","horas":24}'
```

```json
{"ok":true,"token":"","ip":"203.0.113.42","label":"","unlocked_until":1790503604,
 "hours":24,"api_key":"eb61eaae1b06"}
```

No hace falta enviar la IP: se usa la que registro el codigo. Si la mandas, gana
la tuya. Un codigo desconocido devuelve `404`, y `licencia` es opcional para
validar contra `licenses.json`. El panel y la API comparten el mismo codigo
interno, asi que activan igual.
