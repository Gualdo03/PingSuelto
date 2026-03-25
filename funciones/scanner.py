"""
Módulo SCANNER - Escaneo de red y fingerprinting
"""

import threading
from modulos.network_core import _scan_rango
from modulos.config import _estado, GATEWAY

class ScannerModule:
    """Módulo para escaneo de red y descubrimiento de dispositivos."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
    
    def scan_network(self, rango, timeout, write_callback, stop_callback):
        """Inicia el escaneo de red."""
        if not hasattr(self, '_scapy_available'):
            try:
                import scapy.all
                self._scapy_available = True
            except ImportError:
                self._scapy_available = False
                write_callback("✗ Scapy no disponible.\n")
                return False
        
        if not self._scapy_available:
            return False
        
        threading.Thread(target=self._scan_loop, args=(rango, timeout, write_callback, stop_callback), daemon=True).start()
        return True
    
    def _scan_loop(self, rango, timeout, write_callback, stop_callback):
        """Loop principal de escaneo."""
        self.logger.log(f"[SCAN] Iniciando en {rango}...", "info")
        try:
            hosts = _scan_rango(rango, timeout)
            write_callback(f"{'IP':<16}  {'MAC':<18}  {'OS':<10}  Rol\n" + "─"*60 + "\n")
            
            from scapy.all import IP, ICMP, sr1
            
            for ip, mac in hosts:
                rol = "★ Gateway" if ip == GATEWAY else "Dispositivo"
                os_guess = "Desconocido"
                
                try:
                    resp = sr1(IP(dst=ip)/ICMP(), timeout=0.3, verbose=0)
                    if resp and IP in resp:
                        ttl = resp[IP].ttl
                        if ttl <= 64:
                            os_guess = "Linux/Mac"
                        elif ttl <= 128:
                            os_guess = "Windows"
                        else:
                            os_guess = "Cisco/Rtr"
                except Exception:
                    pass
                
                line = f"{ip:<16}  {mac:<18}  {os_guess:<10}  {rol}\n"
                write_callback(line)
                self.logger.log(f"[SCAN] {ip}  {mac}  {os_guess}  {rol}", "ok")
            
            self.logger.log(f"[SCAN] Fin: {len(hosts)} hosts.", "ok")
        except Exception as e:
            write_callback(f"✗ Error durante escaneo: {e}\n")
            self.logger.log(f"[SCAN] Error: {e}", "err")
        finally:
            stop_callback()
    
    def get_default_range(self):
        """Obtiene el rango de red por defecto basado en el gateway."""
        from modulos.config import GATEWAY
        if GATEWAY and GATEWAY != "—":
            partes = GATEWAY.split(".")
            return f"{'.'.join(partes[:3])}.0/24"
        return "192.168.1.0/24"
