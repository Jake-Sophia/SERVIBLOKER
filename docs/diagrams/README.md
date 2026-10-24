# Diagramas del código actual

Se consultaron los nueve diagramas de `origin/feature/analisis` antes de modificar
el sistema. Los nombres 01–07 se conservaron y actualizaron para eliminar flujos
retirados (IP como identidad, clave en query, EAP compartido y payload cautivo).

- 01: arranque con guardia; 02: identidad y perfil; 03: reglas DNS.
- 04/04b: solicitudes y rechazo; 05: panel y observación real.
- 06/06b: API, revocación y claves; 07: persistencia y exclusión.
- 08: AirDrop offline; 09: certificados, IKEv2 y sesiones.
- 10: vencimiento/revocación; 11: arquitectura completa.

Fuentes: `SERVIBLOKER/blockservi/{web,store,profile,pki,controller,virtual}.py` y
`SERVIBLOKER/deploy/virtual/`. Los diagramas describen las rutas implementadas;
no afirman que la negociación iOS ni el firewall Linux se hayan probado aquí.
Renderizar con PlantUML local: `plantuml docs/diagrams/*.puml`.
