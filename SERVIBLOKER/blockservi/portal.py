"""Pantallas del portal cautivo y del panel de autorizacion.

El movil no recibe un NXDOMAIN: el DNS lo apunta aqui, asi que abre esta
pagina sin que el empleado tenga que buscar ningun enlace. La pantalla
muestra un codigo de 6 digitos y espera a que el administrador lo autorice.
"""

from __future__ import annotations

import time
from typing import Any

from .rules import MODE_UNLOCKED

STYLE = """
:root{--bg:#06111f;--panel:#0b1628;--line:rgba(76,237,224,.25);--teal:#59f1dd;--muted:#91a1b9;--amber:#ffc54a;--red:#ff7a7a}
*{box-sizing:border-box}
body{margin:0;min-height:100svh;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
color:#f5f9ff;background:radial-gradient(circle at 7% 15%,rgba(53,205,198,.19),transparent 29%),
radial-gradient(circle at 88% 5%,rgba(47,87,194,.22),transparent 31%),var(--bg);
display:grid;place-items:center;padding:24px;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.28;
background-image:linear-gradient(rgba(130,204,223,.13) 1px,transparent 1px),linear-gradient(90deg,rgba(130,204,223,.13) 1px,transparent 1px);
background-size:42px 42px;mask-image:linear-gradient(#000,transparent 85%)}
.page{width:min(100%,500px);position:relative}
.card{position:relative;overflow:hidden;padding:36px 30px 31px;border:1px solid var(--line);
border-radius:32px;background:linear-gradient(150deg,rgba(16,29,50,.98),rgba(6,14,28,.96));
box-shadow:0 30px 75px rgba(0,0,0,.38),inset 0 1px rgba(255,255,255,.04)}
.card:before{content:"";position:absolute;inset:0;pointer-events:none;
background:linear-gradient(130deg,rgba(80,240,220,.07),transparent 25%,transparent 75%,rgba(88,132,255,.07))}
.pending{color:#ffd157!important;background:rgba(255,191,51,.11);border:1px solid rgba(255,193,59,.45);
border-radius:999px;padding:7px 11px;font-size:11px!important;letter-spacing:1.3px;
box-shadow:0 0 18px rgba(255,193,59,.08)}
.footer i{color:#45ddff;font-style:normal;font-size:18px;vertical-align:-1px}
.brand,.hero,.activation,.device,.actions,.footer{position:relative;z-index:1}
.brand{display:flex;justify-content:center;align-items:center;gap:12px;font-size:clamp(30px,9vw,46px);
letter-spacing:-2px;font-weight:800}
.brand-mark{width:43px;height:43px;border-radius:14px;display:grid;place-items:center;
background:linear-gradient(135deg,#59f1dd,#167a93);box-shadow:0 0 24px rgba(89,241,221,.36);font-size:21px}
.brand strong{color:#fff}.brand em{font-style:normal;color:#88f5e7}
.hero{text-align:center;margin-top:38px}
.hero h1{font-size:clamp(25px,6vw,35px);line-height:1.12;margin:0}
.hero h1 span{color:var(--teal)}
.hero p{color:var(--muted);font-size:16px;line-height:1.6;margin:13px auto 0;max-width:340px}
.eyebrow{display:flex;align-items:center;gap:10px;color:#9aabc0;letter-spacing:4px;font-size:11px;justify-content:center;margin:37px 0 20px}
.eyebrow:before,.eyebrow:after{content:"";height:1px;width:48px;background:linear-gradient(90deg,transparent,var(--teal))}
.eyebrow:after{transform:scaleX(-1)}
.code-row{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
.slot{aspect-ratio:.74;display:grid;place-items:center;border:1px solid rgba(93,235,226,.35);
border-radius:16px;background:linear-gradient(155deg,rgba(12,26,47,.9),rgba(4,12,24,.95));
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:clamp(25px,8vw,40px);font-weight:800;
color:var(--teal);text-shadow:0 0 18px rgba(89,241,221,.4);box-shadow:inset 0 0 24px rgba(86,237,221,.035)}
.slot.wait{color:#3f5a72;text-shadow:none;border-style:dashed}
.progress{height:4px;background:#152b3b;margin:14px 12% 28px;border-radius:99px;overflow:hidden}
.progress span{display:block;width:100%;height:100%;background:linear-gradient(90deg,#4ee7dd,#9cf5e8);
box-shadow:0 0 12px var(--teal);animation:pulse 1.8s ease-in-out infinite}
.progress.done span{animation:none;background:linear-gradient(90deg,#59f1dd,#9cf5e8)}
@keyframes pulse{0%,100%{opacity:.35}50%{opacity:1}}
.device{border:1px solid rgba(255,255,255,.06);background:rgba(3,9,20,.47);border-radius:22px;padding:7px 19px}
.device-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;
border-bottom:1px solid rgba(255,255,255,.06);color:var(--muted);font-size:14px}
.device-row:last-child{border:0}
.device-row b{font-weight:600;color:#eff7ff;text-align:right;word-break:break-all}
.icon{color:var(--teal);margin-right:11px}
.pill{color:var(--amber);background:rgba(255,191,51,.11);border:1px solid rgba(255,193,59,.45);
border-radius:999px;padding:7px 11px;font-size:11px;letter-spacing:1.3px;box-shadow:0 0 18px rgba(255,193,59,.08)}
.pill.on{color:#53f7e0;background:rgba(83,247,224,.11);border-color:rgba(83,247,224,.45)}
.pill.off{color:#ff9d9d;background:rgba(255,122,122,.1);border-color:rgba(255,122,122,.4)}
.actions{margin-top:25px;text-align:center}
.actions p{color:var(--muted);line-height:1.55;margin:0 0 14px}
button{cursor:pointer;font:inherit}
.generate{border:0;border-radius:13px;background:linear-gradient(135deg,#64f0dd,#1ca7bb);color:#04202a;
font-weight:800;font-size:15px;padding:14px 20px;cursor:pointer;width:100%;
box-shadow:0 12px 28px rgba(39,213,197,.22);transition:transform .2s,filter .2s}
.generate:hover{filter:brightness(1.05);transform:translateY(-1px)}
.generate:disabled{opacity:.45;cursor:default;transform:none}
.footer{text-align:center;color:#9aaac0;font-size:12px;letter-spacing:1px;margin:29px 0 0}
.notice{padding:13px 15px;border-radius:14px;margin:0 0 18px;line-height:1.5;font-size:14px;
border:1px solid transparent}
.notice.ok{background:rgba(83,247,224,.11);border-color:rgba(83,247,224,.35);color:#8ff5e6}
.notice.warn{background:rgba(255,191,51,.11);border-color:rgba(255,193,59,.35);color:#ffd98a}
.notice.error{background:rgba(255,122,122,.1);border-color:rgba(255,122,122,.35);color:#ffb4b4}
.fineprint{margin:20px 0 0;color:#7f8ea6;font-size:12px;line-height:1.55}
.canjear{margin-top:26px;padding-top:22px;border-top:1px solid rgba(255,255,255,.08)}
.canjear .eyebrow{margin:0 0 12px}
.canjear p{color:var(--muted);font-size:14px;line-height:1.55;margin:0 0 14px}
#entrada{width:100%;padding:15px;border:1px solid rgba(93,235,226,.35);border-radius:13px;
background:rgba(4,12,24,.7);color:#eafffd;font:inherit;font-size:25px;letter-spacing:10px;
text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
#entrada::placeholder{color:#3f5a72;letter-spacing:10px}
#entrada:disabled{opacity:.5}
.aviso:empty{display:none}
.aviso{margin-top:12px;padding:12px 14px;border-radius:13px;font-size:14px;line-height:1.45;
background:rgba(255,122,122,.1);border:1px solid rgba(255,122,122,.35);color:#ffb4b4}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:410px){body{padding:14px}.card{padding:29px 20px 26px;border-radius:27px}.code-row{gap:6px}
.device{padding-inline:15px}.eyebrow{margin-top:29px}}
"""

ADMIN_STYLE = STYLE + """
.wide{width:min(100%,760px)}
table{width:100%;border-collapse:collapse;margin:6px 0 0}
th,td{text-align:left;padding:12px 8px;border-bottom:1px solid rgba(255,255,255,.07);font-size:14px}
th{color:#9aabc0;font-size:11px;letter-spacing:1.2px;font-weight:700}
td b{color:#eff7ff}
td{color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:17px;font-weight:800;color:var(--teal);
letter-spacing:2px}
.mini{border:1px solid rgba(83,247,224,.4);background:rgba(83,247,224,.1);color:#8ff5e6;border-radius:9px;
padding:8px 13px;font-size:12px;font-weight:700;letter-spacing:.4px}
.mini:hover{background:rgba(83,247,224,.2)}
.mini.no{border-color:rgba(255,122,122,.4);background:rgba(255,122,122,.1);color:#ffb4b4}
.mini.no:hover{background:rgba(255,122,122,.2)}
.row-actions{display:flex;gap:8px;flex-wrap:wrap}
.empty{padding:26px 8px;color:#7f8ea6;text-align:center;font-size:14px}
.hours{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:20px 0 0;padding-top:18px;
border-top:1px solid rgba(255,255,255,.08)}
.hours label{color:#9aabc0;font-size:12px;letter-spacing:1.2px;font-weight:700}
.hours input{width:74px;padding:10px;border:1px solid rgba(255,255,255,.14);border-radius:9px;
background:rgba(3,9,20,.6);color:#eff7ff;font:inherit;text-align:center}
.generador{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:20px;
border:1px solid rgba(83,247,224,.28);border-radius:20px;background:rgba(3,9,20,.4)}
.generador .campo{display:flex;flex-direction:column;gap:6px}
.generador label{color:#9aabc0;font-size:11px;letter-spacing:1.2px;font-weight:700}
.nuevos{margin-top:16px}
.nuevo{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 14px;
margin-bottom:8px;border:1px solid rgba(83,247,224,.3);border-radius:14px;background:rgba(83,247,224,.07)}
.nuevo code{font-size:22px;letter-spacing:5px}
.nuevo span{color:var(--muted);font-size:13px;text-align:right}
.copiar{border:1px solid rgba(83,247,224,.45);background:transparent;color:#8ff5e6;border-radius:8px;
padding:7px 12px;font-size:12px;font-weight:700;cursor:pointer}
.copiar:hover{background:rgba(83,247,224,.18)}
.origen{display:inline-block;padding:3px 8px;border-radius:99px;font-size:10px;letter-spacing:1px;
font-weight:700;border:1px solid rgba(255,255,255,.16);color:#9aabc0}
.origen.panel{border-color:rgba(89,241,221,.5);color:var(--teal)}
select{flex:1;min-width:190px;padding:10px;border:1px solid rgba(255,255,255,.14);border-radius:9px;
background:rgba(3,9,20,.6);color:#eff7ff;font:inherit}
"""


def _escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def device_page(
    info: dict[str, Any],
    token: str = "",
    banner: str = "",
    kind: str = "",
) -> str:
    """La pagina de activacion, portada de la web de siempre.

    Mantiene su comportamiento: el codigo se genera solo al abrir la pagina, el
    boton saca otro, la IP no se enseña y cada cinco segundos se mira si ya esta
    activado. La unica diferencia es que, en vez de mirar la lista global de
    codigos, consulta solo el suyo, que es lo unico que puede ver un movil.
    """
    code = str(info.get("codigo") or "")
    unlocked = info.get("modo") == MODE_UNLOCKED
    notice = f'<div class="notice {kind}">{banner}</div>' if banner else ""
    label = info.get("label") or "sin etiqueta"

    if unlocked:
        until = int(info.get("desbloqueado_hasta") or 0)
        left = max(0, until - int(time.time())) / 3600
        pill = '● ACTIVADO'
        message = f"Tienes internet completo durante {left:.1f} h mas."
    else:
        pill = "● PENDIENTE"
        message = "Envia este codigo al administrador para autorizar tu conexion."

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>Activacion</title>
  <style>{STYLE}</style>
</head>
<body>
  <main class="page">
    <section class="card" aria-label="Activacion de acceso">
      <div class="brand"><span class="brand-mark">&#9672;</span><span><strong>block</strong><em>servi</em></span></div>
      <div class="hero"><h1>Activacion <span>requerida</span></h1><p>Tu dispositivo necesita ser autorizado para acceder a internet.</p></div>
      {notice}
      <div class="activation"><div class="eyebrow">TU CODIGO DE ACTIVACION</div><div class="code-row" id="code-slots" aria-label="Codigo de activacion"></div><div class="progress"><span></span></div></div>
      <div class="device">
        <div class="device-row"><span><span class="icon">&#9678;</span>Equipo</span><b>{_escape(label)}</b></div>
        <div class="device-row"><span><span class="icon">&#9647;</span>Direccion IP</span><b>Protegida</b></div>
        <div class="device-row"><span><span class="icon">&#9677;</span>Modelo</span><b>Dispositivo movil</b></div>
        <div class="device-row"><span><span class="icon">&#9678;</span>Estado</span><b class="pending" id="estado">{pill}</b></div>
      </div>
      <div class="actions"><p>{_escape(message)}</p><button class="generate" id="btn-generate" type="button">Generar nuevo codigo</button></div>
      <div class="canjear">
        <div class="eyebrow">&#921; TIENES UN CODIGO?</div>
        <p>Escribe los seis digitos que te ha dado el administrador y tendras internet
completo durante las horas que indique.</p>
        <form id="forma-canje">
          <input id="entrada" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="off"
   autocapitalize="none" spellcheck="false" placeholder="000000" aria-label="Codigo de seis digitos">
          <button class="generate" type="submit">Canjear codigo</button>
        </form>
        <div id="aviso-canje" class="aviso" role="status"></div>
      </div>
      <div class="footer"><i>&#8226;</i> blockservi &#183; Control de acceso</div>
      <input id="code" class="sr-only" readonly aria-label="Codigo generado">
    </section>
  </main>
  <script>
    const codeEl=document.getElementById("code"),slots=document.getElementById("code-slots"),
          estadoEl=document.getElementById("estado"),equipo={_escape(token)!r};
    function display(code){{slots.innerHTML="";code.split("").forEach(function(ch){{
const el=document.createElement("span");el.className="slot";el.textContent=ch;slots.appendChild(el);}});}}
    function setStatus(status){{
      if(status==="active"){{estadoEl.textContent="\u25cf ACTIVADO";estadoEl.style.color="#22c55e";
        estadoEl.style.background="rgba(34,197,94,.16)";estadoEl.style.borderColor="rgba(34,197,94,.7)";}}
      else{{estadoEl.textContent="\u25cf PENDIENTE";estadoEl.style.color="#ffd157";
        estadoEl.style.background="rgba(255,191,51,.11)";estadoEl.style.borderColor="rgba(255,193,59,.45)";}}
    }}
    let statusTimer=null;
    function checkStatus(){{
      var code=codeEl.value;if(!code)return;
      fetch("/api/estado-codigo/"+code,{{cache:"no-store"}}).then(function(r){{return r.json()}})
        .then(function(d){{
          if(d&&d.error)return;
          setStatus(d.active?"active":"pending");
          if(d.active){{
            if(statusTimer)clearInterval(statusTimer);
            document.getElementById("btn-generate").disabled=true;
          }}
        }}).catch(function(){{}});
    }}
    function gen(){{
      const code=String(Math.floor(100000+Math.random()*900000));
      codeEl.value=code;display(code);setStatus("pendiente");
      const cuerpo={{code:code}};
      if(equipo)cuerpo.token=equipo;
      fetch("/api/register",{{method:"POST",headers:{{"Content-Type":"application/json"}},
        body:JSON.stringify(cuerpo)}}).then(function(r){{return r.json()}})
        .then(function(d){{if(d.error)console.error("Register error:",d.error);}});
      setTimeout(checkStatus,800);
    }}
    document.getElementById("btn-generate").addEventListener("click",gen);
    const previo={_escape(code)!r};
    if(previo){{display(previo);codeEl.value=previo;checkStatus();}}else{{gen();}}
    statusTimer=setInterval(checkStatus,5000);
    document.getElementById("forma-canje").addEventListener("submit",function(ev){{
      ev.preventDefault();
      const entrada=document.getElementById("entrada"),aviso=document.getElementById("aviso-canje");
      const valor=entrada.value.replace(/\\D/g,"").slice(0,6);
      if(valor.length!==6){{aviso.textContent="El codigo tiene seis digitos.";return;}}
      entrada.disabled=true;
      fetch("/api/canjear",{{method:"POST",headers:{{"Content-Type":"application/json"}},
        body:JSON.stringify({{codigo:valor,token:equipo}})}}).then(function(r){{return r.json()}})
        .then(function(d){{
          if(d&&d.ok){{location.reload();return;}}
          entrada.disabled=false;
          aviso.textContent=(d&&d.detalle)||"Ese codigo no vale.";
        }});
    }});
  </script>
</body>
</html>"""


def admin_page(
    requests: list[dict[str, Any]],
    devices: list[dict[str, Any]],
    licenses: list[dict[str, Any]],
    codigos: list[dict[str, Any]] | None = None,
    accesos: list[dict[str, Any]] | None = None,
    hours: int = 24,
    notice: str = "",
    kind: str = "",
    key: str = "",
) -> str:
    """Panel del administrador: autorizar, rechazar y revisar el estado.

    `key` es la clave de administracion que se ha usado para abrir la pagina.
    Se incrusta en el JavaScript porque, al venir en la query, el navegador no la
    manda sola en las llamadas a la API.
    """
    if requests:
        rows = ""
        for row in requests:
            when = int(row.get("solicitado") or 0)
            ago = _ago(when)
            rows += (
                f"<tr><td><code>{_escape(row['codigo'])}</code></td>"
                f"<td><b>{_escape(row.get('label') or 'Telefono')}</b><br>"
                f"<small>{_escape(row.get('token', ''))}</small></td>"
                f"<td>{_escape(row.get('ip') or '-')}</td>"
                f"<td>{ago}</td>"
                f'<td><div class="row-actions">'
                f'<button class="mini" data-code="{_escape(row["codigo"])}" data-act="ok">Autorizar</button>'
                f'<button class="mini no" data-code="{_escape(row["codigo"])}" data-act="no">Rechazar</button>'
                f"</div></td></tr>"
            )
        table = f"""<table><thead><tr><th>Codigo</th><th>Equipo</th><th>IP</th><th>Pedido</th>
<th></th></tr></thead><tbody>{rows}</tbody></table>"""
    else:
        table = '<p class="empty">No hay solicitudes pendientes.</p>'

    if devices:
        drows = ""
        for device in devices:
            until = int(device.get("unlocked_until") or 0)
            if until > 0:
                state = f'<span class="pill on">AUTORIZADO {_left(until)}</span>'
            else:
                state = '<span class="pill">RESTRINGIDO</span>'
            code = str(device.get("request_code") or "")
            pending = f"<code>{_escape(code)}</code>" if code else "<small>-</small>"
            drows += (
                f"<tr><td><b>{_escape(device.get('label') or 'sin etiqueta')}</b><br>"
                f"<small>{_escape(device.get('token', ''))}</small></td>"
                f"<td>{_escape(device.get('last_ip') or '-')}</td>"
                f"<td>{pending}</td><td>{state}</td>"
                f'<td><div class="row-actions">'
                f'<button class="mini" data-token="{_escape(device.get("token", ""))}" '
                f'data-act="lock">Bloquear</button>'
                f"</div></td></tr>"
            )
        dtable = f"""<table><thead><tr><th>Equipo</th><th>IP</th><th>Codigo</th><th>Estado</th>
<th></th></tr></thead><tbody>{drows}</tbody></table>"""
    else:
        dtable = '<p class="empty">No hay equipos dados de alta.</p>'

    if licenses:
        options = "".join(
            f'<option value="{_escape(item.get("codigo", ""))}">{_escape(item.get("codigo", ""))}'
            f'{" (usada)" if item.get("usada") else ""}</option>'
            for item in licenses
        )
    else:
        options = '<option value="">Sin licencias disponibles</option>'

    # Codigos registrados por los moviles. Primero los que siguen esperando,
    # despues los activos y por ultimo los que ya caducaron.
    pending_codes = [c for c in (codigos or []) if c.get("pending")]
    live_codes = [c for c in (codigos or []) if c.get("active")]
    dead_codes = [c for c in (codigos or []) if c.get("vencido")]
    if codigos:
        crows = ""
        for code in (pending_codes + live_codes + dead_codes)[:40]:
            if code.get("active"):
                estado = f'<span class="pill on">ACTIVO {_left(code["expires_at"])}</span>'
            elif code.get("vencido"):
                estado = '<span class="pill off">CADUCADO</span>'
            elif code.get("usado_at"):
                estado = '<span class="pill off">USADO</span>'
            elif code.get("origen") == "panel":
                estado = '<span class="pill">SIN USAR</span>'
            else:
                estado = '<span class="pill">PENDIENTE</span>'
            # Con el perfil unico no hay token: el telefono se identifica por su
            # IP, asi que se enseña eso en vez de un "sin atar" que no ayuda.
            equipo = (
                code.get("label")
                or code.get("token")
                or (f"IP {code['ip']}" if code.get("ip") else "sin atar")
            )
            origen = (
                '<span class="origen panel">GENERADO</span>'
                if code.get("origen") == "panel"
                else '<span class="origen">MOVIL</span>'
            )
            if code.get("origen") == "panel" and not code.get("active"):
                acciones = f'<button class="mini" data-act="ok" data-code="{_escape(code["id"])}">Autorizar</button>'
            elif code.get("active"):
                acciones = f'<button class="mini no" data-act="revocar" data-code="{_escape(code["id"])}">Revocar</button>'
            else:
                acciones = '<span class="mini no" style="opacity:.45;cursor:default">Sin uso</span>'
            crows += (
                f"<tr><td><code>{_escape(code['id'])}</code></td>"
                f"<td><b>{_escape(equipo)}</b></td>"
                f"<td>{_escape(code.get('ip') or '-')}</td>"
                f"<td>{origen}</td>"
                f"<td>{_ago(int(code.get('created_at') or 0))}</td>"
                f"<td>{estado}</td>"
                f'<td><div class="row-actions">{acciones}</div></td></tr>'
            )
        ctable = f"""<table><thead><tr><th>Codigo</th><th>Equipo</th><th>IP</th><th>Origen</th>
<th>Creado</th><th>Estado</th><th></th></tr></thead><tbody>{crows}</tbody></table>"""
    else:
        ctable = '<p class="empty">Todavia no hay codigos. Genera el primero arriba.</p>'

    # Con el perfil unico los telefonos no se distinguen por token, sino por la IP
    # desde la que consultan. Esta es la lista de quien tiene salida ahora mismo.
    if accesos:
        arows = ""
        for row in accesos:
            ip = _escape(str(row.get("ip", "")))
            if row.get("activo"):
                estado = (
                    f'<span class="estado ok">ACTIVO {_ago(int(row["unlocked_until"]))}</span>'
                )
                acciones = (
                    f'<button class="mini no" data-act="ip" data-ip="{ip}">Revocar</button>'
                )
            else:
                estado = '<span class="origen">SIN ACCESO</span>'
                acciones = '<span class="mini no" style="opacity:.45;cursor:default">-</span>'
            arows += (
                f"<tr><td><b>{ip}</b></td>"
                f"<td>{int(row.get('unlock_count', 0))}</td>"
                f"<td>{_ago(int(row.get('last_unlock_at') or 0))}</td>"
                f"<td>{_ago(int(row.get('last_seen') or 0))}</td>"
                f"<td>{estado}</td>"
                f'<td><div class="row-actions">{acciones}</div></td></tr>'
            )
        atable = f"""<table><thead><tr><th>IP</th><th>Canjeos</th><th>Ultimo canje</th>
<th>Ultima consulta</th><th>Estado</th><th></th></tr></thead><tbody>{arows}</tbody></table>"""
    else:
        atable = (
            '<p class="empty">Todavia no ha consultado ningun telefono. '
            "Aparecera aqui en cuanto instales el perfil.</p>"
        )

    banner = f'<div class="notice {kind}">{notice}</div>' if notice else ""
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>blockservi &#183; Panel</title><style>{ADMIN_STYLE}</style></head>
<body><main class="page wide"><section class="card">
<div class="brand"><span class="brand-mark">&#9672;</span><span><strong>block</strong><em>servi</em></span></div>
<div class="hero"><h1>Panel de <span>autorizacion</span></h1>
<p>Aprueba los codigos que envian los equipos. El acceso dura {hours} h por defecto.</p></div>
{banner}
<div class="activation"><div class="eyebrow">GENERAR CODIGO</div>
<div class="generador">
<div class="campo"><label>HORAS DE ACCESO</label>
<input id="gen-horas" type="number" min="1" max="2160" value="{hours}"></div>
<div class="campo"><label>CUANTOS</label>
<input id="gen-cantidad" type="number" min="1" max="50" value="1" style="width:74px"></div>
<div class="campo"><label>CADUCA EN DIAS</label>
<input id="gen-dias" type="number" min="1" max="365" value="30" style="width:74px"></div>
<button class="generate" id="generar" type="button" style="width:auto">Generar</button>
</div>
<div class="nuevos" id="nuevos"></div>
<p class="fineprint">Cada codigo abre la salida del telefono durante las horas que elijas.
Siguen vetados siempre Libros, iTunes y Find My iPhone. Antes de canjear, el
telefono solo tiene YouTube, Telegram y esta pagina.</p>
</div>
<div class="activation"><div class="eyebrow">SOLICITUDES PENDIENTES</div>{table}</div>
<div class="hours"><label>HORAS</label><input id="hours" type="number" min="1" max="720" value="{hours}">
<label>LICENCIA</label><select id="lic"><option value="">Sin consumir licencia</option>{options}</select></div>
<div class="activation"><div class="eyebrow">EQUIPOS</div>{dtable}</div>
<div class="activation"><div class="eyebrow">ACCESOS</div>{atable}</div>
<div class="activation"><div class="eyebrow">CODIGOS</div>{ctable}</div>
<p class="fineprint">Autentificado con la clave de administracion de este servicio.</p>
<div class="footer">&#8226; blockservi &#183; Panel local</div>
</section></main>
<script>
var clave={_escape(key)!r};
function api(ruta){{
  return ruta+(ruta.indexOf("?")>=0?"&":"?")+"k="+encodeURIComponent(clave);}}
function valor(id){{return document.getElementById(id).value;}}
document.getElementById("generar").addEventListener("click",function(){{
var boton=this;boton.disabled=true;boton.textContent="Generando...";
fetch(api("/api/admin/generar"),{{method:"POST",headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{horas:parseInt(valor("gen-horas")||"24",10),
cantidad:parseInt(valor("gen-cantidad")||"1",10),dias:parseInt(valor("gen-dias")||"30",10)}})}})
.then(function(r){{return r.json()}}).then(function(d){{
boton.disabled=false;boton.textContent="Generar";
if(!d||!d.ok){{document.getElementById("nuevos").innerHTML="";return;}}
var html="";
d.codigos.forEach(function(c){{
html+='<div class="nuevo"><code>'+c.id+'</code><span>'+c.horas+' h de acceso<br>vence para canjear en '+d.valido_dias+' d</span>'
+'<button class="copiar" data-codigo="'+c.id+'">Copiar</button></div>';}});
document.getElementById("nuevos").innerHTML=html;
document.querySelectorAll("button[data-codigo]").forEach(function(b){{
b.addEventListener("click",function(){{
navigator.clipboard.writeText(b.dataset.codigo).then(function(){{b.textContent="Copiado";}});}});}});
}}).catch(function(){{boton.disabled=false;boton.textContent="Reintentar";}});}});
function enviar(codigo,accion){{
var cuerpo={{codigo:codigo,horas:parseInt(document.getElementById("hours").value||"24",10)}};
if(accion==="ok")cuerpo.licencia=document.getElementById("lic").value;
var ruta=api("/api/admin/"+(accion==="revocar"?"revocar":accion));
if(accion==="ip"){{
  ruta=api("/api/admin/ip/"+encodeURIComponent(document.querySelector("button[data-act='ip'][data-ip='"+codigo+"']")?.dataset?.ip||codigo));
}}
fetch(ruta,{{method:"POST",headers:{{"Content-Type":"application/json"}},
body:JSON.stringify(cuerpo)}}).then(function(){{location.reload()}});}}
document.querySelectorAll("button[data-code]").forEach(function(b){{
b.addEventListener("click",function(){{enviar(b.dataset.code,b.dataset.act);}});}});
document.querySelectorAll("button[data-token]").forEach(function(b){{
b.addEventListener("click",function(){{
fetch(api("/api/bloquear/"+b.dataset.token),{{method:"POST"}}).then(function(){{location.reload()}});}});}});
</script></body></html>"""


def manual_page(ip: str = "") -> str:
    """Se muestra cuando el equipo no se puede identificar por su IP."""
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Acceso al servicio</title><style>{STYLE}</style></head>
<body><main class="page"><section class="card">
<div class="brand"><span class="brand-mark">&#9672;</span><span><strong>block</strong><em>servi</em></span></div>
<div class="hero"><h1>Identifica tu <span>equipo</span></h1>
<p>Introduce la referencia impresa en la hoja de entrega del equipo.</p></div>
<div class="device" style="margin-top:30px"><div class="device-row">
<span><span class="icon">&#9647;</span>Direccion IP</span><b>{_escape(ip or "-")}</b></div></div>
<form method="get" action="/activar"><div class="actions">
<label for="t" class="sr-only">Referencia del equipo</label>
<input id="t" name="t" maxlength="32" autocapitalize="none" autocomplete="off" required
style="width:100%;padding:13px;border:1px solid rgba(93,235,226,.35);border-radius:13px;
background:rgba(4,12,24,.7);color:#eafffd;font:inherit;letter-spacing:1px;margin-top:8px"
placeholder="dev-3ce1abaac4f1">
<button class="generate" style="margin-top:16px">Continuar</button></div></form>
<p class="fineprint">No solicitamos contrasenas, PINes, datos biometricos ni identificadores del equipo.</p>
<div class="footer">&#8226; blockservi &#183; Control de acceso</div>
</section></main></body></html>"""


def _left(until: int) -> str:
    hours = max(0, until - int(time.time())) / 3600
    return f"{hours:.1f} h"


def _ago(when: int) -> str:
    if not when:
        return "-"
    seconds = max(0, int(time.time()) - when)
    if seconds < 60:
        return "ahora"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} d"
