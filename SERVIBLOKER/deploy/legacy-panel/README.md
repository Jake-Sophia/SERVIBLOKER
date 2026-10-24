# Panel de activaciones

Panel adicional en `https://vpnk.unlockersserver.com/administracion`, servido por
`iblocker-panel.service` en loopback `127.0.0.1:8091`. Caddy publica únicamente
esa ruta. No modifica los procesos del backend, strongSwan ni el firewall.

El propietario recibe un enlace privado con una capacidad aleatoria de 384 bits
en el fragmento `#acceso=...`. JavaScript quita el fragmento de la barra antes de
intercambiarlo por una sesión de 12 horas. El enlace es una credencial de acceso:
se guarda únicamente en la entrega privada, nunca en Git, y no debe compartirse.
En configuración sólo se almacena su SHA-256. El enlace no vence por el cierre de
sesión: puede reutilizarse para entrar de nuevo. Se revoca sustituyendo su hash
en `/etc/iblocker-panel/access.json` y reiniciando sólo este servicio; esto cierra
todas sus sesiones existentes.

La cookie es Secure, HttpOnly y SameSite=Strict, limitada a `/administracion`.
Las escrituras exigen origen HTTPS exacto y un token CSRF de sesión. No se acepta
la capacidad en query ni en cabeceras de otras rutas. El panel y sus respuestas
no se cachean; su ruta se excluye de los access logs de Caddy. La clave del VPS
no llega al navegador ni al enlace, y se usa solamente por loopback en el proxy.

El panel permite:

- Ver solicitudes recientes, distinguiendo perfiles individuales de códigos de navegador.
- Introducir seis dígitos y elegir 1–2160 horas (24 por defecto).
- Aprobar con `/api/admin/ok`, forzando siempre `individual_only=true`.
- Ver los accesos vigentes y bloquear exclusivamente el perfil seleccionado.
- Actualizar estado y cerrar la sesión. La lista se actualiza cada diez segundos.

El servicio lee el Store y Codes existentes como el usuario `blockservi`; no escribe
esos archivos. Todas las activaciones y bloqueos los decide y ejecuta el backend.
Las etiquetas se insertan en el DOM con `textContent`, sin HTML recibido del servidor.
Fechas y horas se muestran en `America/Lima`.

Archivos publicados en `/opt/iblocker-panel`; hash de acceso root:blockservi 0640
en un directorio 0750. La unidad no tiene capacidades de Linux ni directorios de
estado de escritura. Respaldos y metadatos privados en `/root/iblocker-panel-20261023`.

## Verificación

`test_panel.py` usa secretos y perfiles ficticios, HTTP por loopback en un namespace
sin interfaces externas. Comprueba autenticación, flags de cookie, privacidad de
inventario, CSRF/origen, validación, imposibilidad de omitir `individual_only`, bloqueo
por token, cierre de sesión y ocultación de solicitudes telefónicas antiguas.

Se probó además la ruta HTTPS publicada con dos perfiles temporales: solicitud,
activación de uno, aislamiento del segundo, rechazo del replay, bloqueo del primero
y logout. Se eliminaron los perfiles y códigos de prueba y se verificó que la
autorización del iPhone real no cambiara. La interfaz se revisó en navegador.

El generador público sigue disponible en `/generador`. Un código sin perfil no se
convierte silenciosamente en permiso por IP: el usuario debe obtener el código
desde «Activar IBLOKER» en su iPhone con la VPN conectada.
