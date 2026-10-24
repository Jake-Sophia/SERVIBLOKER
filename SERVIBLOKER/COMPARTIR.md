# Distribuir SERVIBLOKER

Compartir sólo el código y los ejemplos. No incluir datos del VPS, perfiles
mobileconfig generados, PKCS#12, claves privadas, CA privada, SQLite ni archivos
INI reales. `.gitignore` excluye esos formatos habituales; revisar igualmente el
contenido antes de publicar.

Instalar dependencias desde `requirements.txt`; probar con
`python tests/test_blockservi.py`. La instalación del servidor requiere una
configuración privada y revisión explícita: ver `../docs/IBLOKER-VIRTUAL.md`.
Las credenciales VPN compartidas ya no se usan: cada perfil lleva un certificado
propio. Entregar un perfil distinto por dispositivo.
