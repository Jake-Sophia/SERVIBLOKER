# Entrega individual compatible con el VPS existente — 23 octubre 2026

La implementación completa de feature/iblocker-vpn sigue pendiente de aceptación
Linux/iPhone. Para atender la entrega solicitada se comprobó el VPS existente por
SSH y se confirmó que aún utiliza el backend anterior.

Se registró una identidad nueva de 192 bits mediante su Store, con usuario de servicio,
sin autorizarla automáticamente. Se generó un perfil DNS individual autocontenido
con un Web Clip de activación, sin credenciales VPN compartidas ni admin_key.
El archivo, URL privada y código de entrega están fuera del repositorio, en la
carpeta local privada `entrega-iblocker`. No copiar estos datos a Git.

Cambios aditivos aplicados tras revisar configuración e impacto:

- `/generador`: HTML estático de `SERVIBLOKER/deploy/legacy/generador.html`.
  Pantalla pública restaurada de seis dígitos, sin clave administrativa.
  La autorización administrativa conserva sus endpoints protegidos.
- `/iblocker-dns/{identidad}`: adaptador Caddy que conserva el TLS del portal y
  reenvía `/dns-query` con el Host individual que entiende el backend existente.
- `/iblocker-perfil/{nombre_aleatorio}.mobileconfig`: entrega privada por URL de
  capacidad impredecible; sin listado de directorio, sin caché y sin access log.
- Exclusión de access logs para rutas con identidades y cabeceras administrativas.
  Caddyfile respaldado antes de validar y recargar; backend y demás rutas conservados.

No se desplegó el código Python nuevo, no se reinició blockservi ni se cambió VPN,
firewall, strongSwan o políticas de dominios. El perfil entregado conserva las
capacidades y limitaciones DNS del backend actual; no activa el nuevo IBLOKER VPN.

Verificación realizada contra el servicio real: Caddy validate/reload correctos,
health OK, consulta DoH HTTPS con NOERROR, perfil descargado idéntico al generado,
API de generación respondiendo con un código nuevo persistido y plist válido por
plutil. La instalación física en iPhone no se ha probado aquí. El mismo archivo
no debe reutilizarse en dos dispositivos.

## Actualización posterior: tráfico por VPN

Se preparó un perfil VPN adicional para sustituir la entrega DNS del mismo iPhone.
Los detalles, pruebas de paquetes y límites pendientes están en
`SERVIBLOKER/deploy/legacy-vpn/README.md`. El firewall queda instalado y cerrado,
pero la instalación y el handshake del iPhone siguen pendientes de validación.
Las afirmaciones anteriores de esta nota describen exclusivamente la entrega DNS inicial.
