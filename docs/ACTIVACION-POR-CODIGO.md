# Activación según la captura del usuario

El flujo principal es una solicitud del teléfono, no un código pregenerado para
canjear. Se conserva la pantalla «Activación requerida», las seis casillas y el
estado PENDIENTE del diseño aportado.

1. El iPhone abre el icono **Activar IBLOKER** instalado por su perfil individual.
2. El servidor genera seis dígitos vinculados al token de ese perfil.
3. La autorización se realiza desde el panel administrativo existente.
   `/generador` es la pantalla pública de solicitudes y no pide clave administrativa.
4. La pantalla del teléfono consulta el estado y muestra ACTIVADO. La consulta
   continúa para detectar vencimiento o revocación.

La página pública `https://vpnk.unlockersserver.com/generador` vuelve al diseño
de la captura: seis dígitos, estado PENDIENTE y «Generar nuevo codigo». Usa el
flujo legado web_id del navegador. Para vincular una solicitud al perfil individual,
se abre el icono instalado por ese perfil. El formulario administrativo anterior
se conserva únicamente como archivo de referencia `deploy/legacy/administracion.html`;
no se publica en `/generador`. Los endpoints administrativos conservan su protección.

## Corrección puntual publicada en el backend existente

Se respaldaron y corrigieron `web.py` y `portal.py` conservando sus rutas y el
flujo legado web_id. Para perfiles registrados, la aprobación autoriza únicamente
el token; no concede una ventana de acceso a la IP pública ni a otra identidad web.
La API administrativa admite exigir un propietario registrado mediante `individual_only`.
Un código de una página genérica sin perfil no demuestra la identidad de un iPhone;
se debe abrir el acceso instalado por el perfil individual.

Se serializan aprobaciones en el proceso, se consume el código y se rechaza su
reutilización. La revocación del código de un perfil registrado cierra también su
ventana Store. Los demás flujos antiguos no se presentan como aislamiento seguro
por hardware ni sustituyen la migración completa del backend.

El código nuevo de la rama implementa igualmente la comprobación `individual_only`.
Los diffs de compatibilidad aplicados al backend instalado están en
`SERVIBLOKER/deploy/legacy/{web.py,portal.py}.patch`.

## Evidencia

- Suite de la rama: **37 pruebas correctas**.
- Cuatro pruebas del candidato exacto del backend legado: aprobación de solicitud,
  IP compartida, concurrencia/replay y conflicto de propietario.
- En el VPS: solicitudes, aprobación, sondeo, revocación y rechazo de replay
  comprobados por HTTP real con dos identidades temporales; no se abrió su IP
  pública compartida. Se eliminaron los registros de prueba.
- JavaScript de ambas pantallas compilado sin errores.
- Copias previas privadas en `/root/iblocker-activation-20261023-a81f/backup`.
  Se comprobó que los archivos originales no hubieran cambiado desde la revisión
  antes de aplicar el parche. El servicio pasó salud después del reinicio.

Esta actualización sólo conecta y corrige el ciclo de autorización. No activa
la nueva VPN, no modifica firewall ni convierte el perfil DNS en un bloqueo de
tráfico completo para Meta/Telegram.

## Restauración de la pantalla pública

Se reemplazó únicamente el HTML estático de `/generador`, guardando respaldo
privado. Se verificó en navegador que no pide contraseña y que el botón genera
otros seis dígitos manteniendo PENDIENTE. No hubo reinicio ni cambios en Caddy.
