# VPN individual compatible con el servidor existente

El perfil DNS entregado anteriormente no lleva tráfico IP al firewall. Se preparó
una conexión IKEv2 adicional para ese mismo perfil, sin reemplazar el backend ni
reiniciar strongSwan. No es el despliegue del controlador VICI de la rama nueva.

La conexión usa una credencial EAP aleatoria exclusiva del dispositivo y valida
el certificado público de `vpn.unlockersserver.com`. La contraseña VPN está dentro
del perfil privado; no es una clave administrativa ni se pide en el generador.
No copiar perfiles, cuentas, claves o tokens a este directorio ni al repositorio.

## Comportamiento

- Direcciones interiores fijas `10.77.10.10` y `fd77:77:10::10`; reqid IPsec `77010`.
- Tabla propia `inet iblocker_delivery`, sin vaciar cadenas de otros servicios.
- Pendiente: sólo HTTPS al VPS y DNS interno `10.77.10.1` por el túnel autenticado.
  Las conexiones externas TCP, UDP/QUIC e IPv6 se descartan, incluidas las ya abiertas.
- El DNS interno reenvía DoH al backend por loopback, con la identidad de este perfil.
- El controlador consulta `/api/pedido/{token}` por loopback cada dos segundos,
  sin `nuevo` ni `web_id`, igual que el sondeo del teléfono y sin generar códigos.
  Sólo acepta una respuesta válida, con token idéntico al configurado y modo `unlocked`.
  No consulta permisos por IP pública ni autorizaciones de otros navegadores.
- El permiso de kernel dura como máximo cinco segundos y nunca supera el vencimiento
  comunicado por el backend. Una respuesta inválida o un error cierra el permiso.
- Dentro de la VPN, `/generador` muestra la activación del perfil vinculado. Fuera
  de ese túnel se conserva la pantalla pública con web_id.
- El perfil solicita conexión bajo demanda y `IncludeAllNetworks=1`, con las
  exclusiones configurables de redes locales, APNs, servicios celulares y comunicación
  entre dispositivos desactivadas. Su identificador raíz y UUID reemplazan la entrega DNS.

## Archivos del despliegue

- `/etc/iblocker-delivery/config.json`: token privado, root:root, directorio 0700.
- `/usr/local/lib/iblocker-delivery/guard.py` y `iblocker-delivery.service`.
- `/etc/ipsec.d/iblocker-delivery.conf` y `.secrets`: configuración adicional y
  credencial root-only. Se agregan includes a la configuración anterior y se usa
  `ipsec update` y `ipsec rereadsecrets`; no se reinicia el daemon existente.
- Copias privadas previas: `/root/iblocker-vpn-fix-20261023/`.

La unidad conserva sus permisos originales `CAP_NET_ADMIN CAP_NET_BIND_SERVICE`.
No lee el archivo de dispositivos protegido ni requiere ampliaciones DAC.

## Verificación realizada

`test_packets.py` se ejecutó en un namespace sin interfaces externas, con dos
namespaces adicionales y destinos de documentación. Verificó paquetes reales:

1. Una dirección de pool sin la política IPsec requerida no obtiene acceso.
2. El modo pendiente bloquea IPv4 e IPv6.
3. Los permisos temporales permiten ambos protocolos.
4. La revocación bloquea conexiones nuevas y una conexión TCP ya establecida.
5. El vencimiento del set cierra ambos protocolos sin intervención del controlador.

Los casos 2–5 omiten únicamente la coincidencia IPsec para ejercitar el filtrado
con veth, sin instalar un segundo daemon IKE. Se comprobó aparte la sintaxis de
las reglas completas y el rechazo de tráfico sin IPsec. Estas pruebas no sustituyen
un handshake IKEv2 y una prueba de Meta/Telegram en el iPhone físico.

## Instalación y límites pendientes

Instalar `entrega-iblocker/IBLOKER-iPhone-VPN.mobileconfig` desde la carpeta privada
externa al repositorio; comprobar **IBLOKER VPN: Conectado**. Abrir el icono de
activación y comprobar, antes de autorizar, que no salen mensajes nuevos ni se
descarga contenido nuevo en WhatsApp, Instagram, Facebook, Messenger y Telegram.
El contenido guardado y las notificaciones previas no demuestran tráfico nuevo.

El bloqueo del servidor exige tráfico dentro de esta VPN. El perfil es removible;
la garantía de VPN obligatoria requiere una solución Always On en dispositivos
supervisados. Apple también reserva excepciones del sistema. No se afirma que
desaparezca la conexión Wi-Fi ni que este perfil controle Bluetooth/Buscar sin conexión.

El daemon strongSwan ya estaba iniciado fuera de systemd y su unidad estaba inactiva.
Se conservó ese estado; queda pendiente validar su arranque tras reiniciar el VPS.
El servicio nuevo sí queda habilitado. No reiniciar el servidor como prueba sin
revisar antes el arranque y el orden del firewall/VPN.

Si se retira este adaptador, terminar y retirar primero su conexión IKE y su
credencial específica. Detener el controlador deja la tabla cerrada tras cinco
segundos. No borrar la tabla mientras todavía pueda establecerse esa conexión;
no restaurar archivos compartidos completos sin comparar cambios posteriores.

Referencias: [Apple IKEv2](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary),
[enrutamiento de VPN](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic),
[VPN para despliegue de dispositivos](https://support.apple.com/guide/deployment/vpn-overview-depae3d361d0/1/web/1.0).
