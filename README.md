# SERVIBLOKER · IBLOKER

Filtro de acceso individual con códigos de activación, perfiles iPhone, VPN y panel privado.

- [Código e instrucciones generales](SERVIBLOKER/README.md)
- [Panel privado de activaciones instalado](SERVIBLOKER/deploy/legacy-panel/README.md)
- [Adaptador VPN/firewall instalado](SERVIBLOKER/deploy/legacy-vpn/README.md)
- [Activación individual y compatibilidad con el backend existente](docs/ACTIVACION-POR-CODIGO.md)
- [Validación realizada y pendientes](docs/VALIDACION.md)
- [Arquitectura y diagramas](docs/ARQUITECTURA-AUDITORIA.md)

Los adaptadores `deploy/legacy-*` conservan el backend existente. La implementación
nueva de VPN con certificados está en la misma rama y tiene su propia matriz de
aceptación pendiente; no debe sustituir el backend instalado sin seguir la migración.

Los perfiles instalables, contraseñas, claves privadas y enlaces de administración
del propietario se entregan por separado. No forman parte de este repositorio.
