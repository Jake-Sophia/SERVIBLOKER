# Validación y aceptación

## Ejecutado localmente

En macOS, entorno Python 3.14 independiente con aiohttp, dnslib, certifi,
cryptography y vici. Suite `SERVIBLOKER/tests/test_blockservi.py`: **37 pruebas**.
Ejecución bajo sandbox sin red, sin escritura en el repositorio, HOME/TMP privados,
límite de CPU 60 s, tamaño por archivo 20 MiB y 128 descriptores. No se ejecutaron
scripts de despliegue ni se conectó a producción. macOS no proporciona aquí un
namespace Linux ni validación del kernel nft/XFRM.

Cobertura verificada:

| Área | Evidencia |
|---|---|
| Identidad | Tokens distintos, UUID distintos, lectura de dispositivos antiguos |
| NAT | Autorizar A no autoriza B ni su IP pública compartida |
| Estados | RESTRICTED, UNLOCKED, EXPIRED, REVOKED; no reapertura tras revocación |
| Códigos | Un solo canje concurrente, rechazo, replay, propiedad, colisiones con históricos, aprobación concurrente |
| Persistencia | Instancias paralelas e hijos de proceso; archivo privado 0600 |
| Autenticación | Header, sesión, flags de cookie, CSRF, clave ausente en HTML/query |
| API | Scopes, activación y revocación del Store; no redirección arbitraria de IP |
| Límites | Reinicialización conserva intentos; ventanas distintas no se reinician entre sí |
| Licencias | Vencimiento efectivo acotado y revocación consultada dinámicamente |
| DNS | Errores FORMERR/SERVFAIL, revocación, estado antes de caché, aprendizaje permitido |
| Upstream | TTL/TTL cero, ID, CD, consultas inflight, coincidencia de respuesta |
| Perfiles | plist DNS/VPN/Wi-Fi, referencias UUID, clave global ausente |
| PKI | SAN y firma, seriales/contraseñas distintas, CRL por serial, CA no sobrescrita |
| Firewall | Render por IP interna+reqid, sin IP pública, timeout, revocación y destinos permitidos |
| VICI | Parseo de fixture de sesión realista, VIP, reqid y contadores |

La suite antigua contenía expectativas incompatibles con los requisitos nuevos:
aprobar simultáneamente token e IP pública, claves en query, payload DNS incorrecto
y bloqueos de Find My. Se sustituyó por regresiones de las mismas áreas con las
invariantes corregidas. HTTP se despachó por router y middleware aiohttp en memoria;
esto no sustituye prueba de socket, TLS o proxy.

## Automatizado, requiere Linux aislado: NO ejecutado aquí

Desde una VM de laboratorio, con dependencias instaladas:

```sh
sudo env PYTHON=/ruta/.venv/bin/python bash SERVIBLOKER/tests/linux_http.sh
sudo env PYTHON=/ruta/.venv/bin/python bash SERVIBLOKER/tests/linux_firewall.sh
```

`linux_http.sh` crea un namespace sin interfaces externas y ejecuta dos pruebas de
transporte aiohttp, límite de cuerpo, cookie, descarga plist y autorización → DNS →
revocación. No utiliza DNS externo. `linux_firewall.sh` crea namespaces/veth propios,
comprueba primero la ruta sin filtro, valida/aplica el batch con nft del kernel y
comprueba que una IP interna sin reqid IPsec no atraviesa el firewall. Borra sólo
sus namespaces. No prueba aceptación de un túnel autenticado ni sustituye la matriz
física siguiente. No se ha validado en este Mac la sintaxis del kernel nft.

## Pruebas físicas pendientes de aceptación

1. Instalar un perfil exclusivo mediante AirDrop en iPhone sin internet; comprobar
   que no aparece descarga/inscripción SCEP. Probar iOS 16 y la versión operativa actual.
2. Conectar Wi-Fi, comprobar HTTPS del portal/DoH y cadena del servidor IKEv2.
   Confirmar SA ESTABLISHED/INSTALLED, certificado, VIP IPv4/IPv6 y reqid reales.
3. Dos iPhone detrás del mismo NAT: autorizar sólo A. Abrir TCP, UDP/QUIC y destinos
   IP directos; B permanece limitado. Comprobar contadores y política nft observada.
4. En RESTRICTED: portal y dominios autorizados; verificar YouTube y comprobar restricción de Meta/Telegram; registrar
   endpoints reales faltantes. Probar APNs, conectividad, hora, cuenta y Find My sin
   desactivar protecciones. Registrar las excepciones IP que sean necesarias.
5. Mantener descarga TCP/QUIC de A y revocar autorización: verificar ambos sentidos,
   especialmente conexiones ESTABLISHED. Repetir con vencimiento corto, licencia
   vencida y revocación de licencia.
6. Revocar certificado A: comprobar CRL cargada, terminación de SA, rechazo de nueva
   autenticación y DoH REFUSED; B conserva identidad/estado. Repetir borrando A del Store.
7. Cambiar Wi-Fi ↔ datos móviles, suspender/despertar, rekey y caída de conexión;
   comprobar MOBIKE, reasignación VIP y actualización de las reglas sin abrir otro equipo.
8. Copiar un perfil a dos teléfonos: registrar sustitución de SA y alertas observadas.
   La ausencia de alerta no demuestra unicidad física. Evaluar falsos positivos en rekey.
9. Detener controlador con A autorizado: comprobar expiración de sets en <=15 s.
   Arrancar VPS en frío y reiniciar strongSwan: comprobar guardia previa y que no
   exista ventana de forwarding sin políticas. No persistir grants nft.
10. Validar backend no expuesto, saneado de proxies, HTTPS/Safari/cookies, cabecera CSRF,
    límites que sobreviven reinicio y ausencia de tokens/admin_key en logs del proxy/CDN.
11. Revisar coexistencia de nft/iptables/ufw/Docker y firewall de proveedor; verificar
    IKE, NAT-T, ESP, IPv6, PMTU, NAT y rutas. Nunca asumir que accept en una tabla
    anula un drop de otra.
12. Probar copia/restauración de datos y reversión conservando guardia cerrada. Confirmar
    que un writer PHP externo respeta flock o detener escrituras concurrentes.

Registrar fecha, versión de iOS/Linux/strongSwan/nft, resultado y evidencia sin
secretos. Hasta completar esta matriz, la VPN/firewall y AirDrop se consideran
implementados con aceptación de infraestructura/dispositivo pendiente; no certificados
para producción. Las capacidades que requieren MDM no se han implementado.

## Entrega posterior compatible con producción existente

Después de las pruebas locales se atendió una solicitud explícita de perfil y
generador. Se verificó el VPS y se añadieron rutas de entrega compatibles con su
backend anterior. Ver `ENTREGA-LEGACY.md`. Esa entrega valida DNS HTTPS y generación
real de códigos; no valida ni despliega la implementación nueva de VPN/firewall.

## Ajuste de política solicitado tras la entrega

Meta y Telegram pasan a deny_strict en ambos ejemplos de política. La suite conserva
37 pruebas correctas y verifica restricción sin código y permiso con autorización.
Este ajuste de fuente aún no se ha desplegado en el VPS. La pantalla de referencia
para activación requiere que el usuario adjunte la imagen mencionada.

## Activación de la captura, publicada y comprobada

Ver `ACTIVACION-POR-CODIGO.md`: 37 pruebas de la rama, cuatro pruebas del parche
legado y ciclo HTTP real con identidades temporales en el VPS. La comprobación no
modificó VPN ni firewall y no autoriza el código visible en la captura por sí sola.

## Adaptadores VPN y panel publicados posteriormente

Actualización de documentación: 24 de octubre de 2026, hora de Lima.

- VPN de compatibilidad: tabla nft propia y conexión IKEv2 individual adicional,
  con credencial EAP exclusiva. En namespaces Linux aislados se comprobaron bloqueo
  IPv4/IPv6 pendiente, apertura temporal, rechazo sin reqid IPsec, revocación de una
  conexión TCP establecida y cierre por timeout del kernel. Los casos de forwarding
  simulan el túnel con veth; no sustituyen el handshake físico del iPhone.
- Panel privado: pruebas HTTP aisladas de sesión, cookie, CSRF/origen, inventario,
  validación, aprobación individual, bloqueo y logout. Además, prueba HTTPS real
  con dos perfiles temporales: sólo uno autorizado, replay rechazado y posterior
  revocación. Se eliminaron sus registros y se comprobó que el acceso del iPhone
  real permaneciera igual. Interfaz revisada en navegador.
- El usuario comunicó funcionamiento satisfactorio del perfil VPN. Sigue pendiente
  completar y registrar la matriz física, los cambios de red y el arranque en frío.
- Antes de publicar en GitHub se repitió la suite de la rama: **37 pruebas correctas**,
  dentro del sandbox local sin red. Se revisaron los archivos a publicar contra
  credenciales de los perfiles y enlaces privados de entrega, sin coincidencias.

Fuentes y detalles: `SERVIBLOKER/deploy/legacy-vpn/README.md` y
`SERVIBLOKER/deploy/legacy-panel/README.md`. Los perfiles instalables y enlaces de
acceso del propietario permanecen fuera del repositorio.
