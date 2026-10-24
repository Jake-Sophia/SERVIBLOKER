# SERVIBLOKER · IBLOKER VIRTUAL

Evolución del servicio existente: DNS por dispositivo, códigos de seis dígitos,
licencias, API con permisos y panel administrativo. Rama `feature/iblocker-vpn`.

Cada iPhone recibe un `.mobileconfig` individual que puede entregarse por AirDrop
antes de tener internet. El perfil incluye DoH; al habilitar VPN, incluye también
certificado cliente, clave y CA para IKEv2. No incluye credenciales administrativas.

El controlador Linux utiliza sesiones autenticadas de strongSwan y nftables. El
panel muestra autorización deseada y estado observado. Las pruebas locales verifican
Python, API en memoria, perfiles y PKI; la aceptación de tráfico IPsec, el arranque
Linux y la instalación iOS todavía requieren validación en equipos reales.

- [Arquitectura y revisión previa](../docs/ARQUITECTURA-AUDITORIA.md)
- [Instalación VPS, migración, AirDrop y límites](../docs/IBLOKER-VIRTUAL.md)
- [Matriz de pruebas y pendientes](../docs/VALIDACION.md)
- [Diagramas PlantUML](../docs/diagrams/README.md)

## Correcciones compatibles con el servidor existente

Además de la evolución del backend, se conservan los adaptadores publicados:

- [VPN individual y firewall con cierre por vencimiento](deploy/legacy-vpn/README.md).
- [Panel privado para activar y bloquear por dispositivo](deploy/legacy-panel/README.md).
- [Restauración del generador público y ciclo de activación](../docs/ACTIVACION-POR-CODIGO.md).

La entrega VPN de compatibilidad usa una credencial EAP exclusiva del dispositivo;
no equivale al despliegue nuevo con certificados descrito más abajo. No reemplazar
el backend existente sin revisar la migración y los pendientes de aceptación.

## Inicio local

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_blockservi.py
cp blockservi.ini.example blockservi.ini
# Editar admin_key, rutas de datos y hosts antes de ejecutar:
.venv/bin/python -m blockservi --config blockservi.ini serve
```

En producción: HTTPS en el proxy, backend en loopback, `/login` → `/panel`.
La cookie administrativa es Secure/HttpOnly/SameSite; no funciona por HTTP.
CLI y automatizaciones admiten `X-Admin-Key` o claves API con permisos.

## API conservada

| Operación | Ruta | Autenticación |
|---|---|---|
| Solicitar código individual | `GET /api/pedido/{token}?nuevo=1` | Token bearer individual |
| Canjear código pregenerado | `POST /api/canjear` con `codigo,token` | Token individual y código de un solo uso |
| Aprobar/rechazar | `POST /api/admin/ok`, `/api/admin/no` | Sesión administrativa o X-Admin-Key |
| Generar códigos | `POST /api/admin/generar` | Administrador |
| Revocar código y acceso asociado | `POST /api/admin/revocar` | Administrador |
| API externa | `/api/v1/activar`, `/api/v1/estado/{codigo}`, `/api/v1/revocar` | X-API-Key con permiso |
| Inventario individual | `GET /api/virtual/devices` | Administrador |
| Alta individual | `POST /api/virtual/devices` con `label` | Administrador |
| Autorizar/restringir/revocar credencial | `POST /api/virtual/devices/{token}/unlock\|lock\|revoke` | Administrador |
| Descargar perfil | `GET /perfil/{token}.mobileconfig` | Administrador |
| Perfil con Wi-Fi opcional | `POST /perfil/{token}.mobileconfig` con `wifi` | Administrador |
| Actividad | `GET /api/virtual/activity` | Administrador |

La API externa conserva los scopes `activar`, `consultar`, `revocar` y `*`.
Es un servicio de un único operador: los scopes no representan tenants independientes.
Una IP enviada a `/api/v1/activar` debe coincidir con el registro; nunca sustituye
la identidad de un token. Consultar un código público requiere `X-Device-Token` y
no devuelve el token ni datos de otro equipo.

`trust_ip=false` es el valor seguro predeterminado. El modo antiguo por IP requiere
opt-in explícito y no puede distinguir teléfonos detrás del mismo NAT. Los perfiles
individuales antiguos conservan sus hosts y tokens. Ver migración antes de actualizar.
