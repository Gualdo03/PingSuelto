"""
Módulo SCANNER - Escaneo de red, fingerprinting y resolución de hostnames
"""

import threading
import socket
from modulos.network_core import _scan_rango
from modulos.discovery import (
    _fabricante_mac, _resolver_hostname, _normalizar_mac,
)
from modulos.config import _estado, GATEWAY


class ScannerModule:
    """Módulo para escaneo de red y descubrimiento de dispositivos."""

    def __init__(self, logger_engine):
        self.logger = logger_engine

    def scan_network(self, rango, timeout, write_callback, stop_callback, result_callback=None):
        """Inicia el escaneo de red.
        
        Args:
            rango: Rango CIDR a escanear.
            timeout: Timeout por host (segundos).
            write_callback: Función para escribir texto en la salida (no usado, mantenido por compat).
            stop_callback: Se llama al terminar (restaura botón, etc.).
            result_callback: Opcional. Recibe lista de dicts con toda la info
                             para que la UI construya filas interactivas.
        """
        if not hasattr(self, '_scapy_available'):
            try:
                import scapy.all
                self._scapy_available = True
            except ImportError:
                self._scapy_available = False
                return False

        if not self._scapy_available:
            return False

        threading.Thread(
            target=self._scan_loop,
            args=(rango, timeout, write_callback, stop_callback, result_callback),
            daemon=True
        ).start()
        return True

    def _scan_loop(self, rango, timeout, write_callback, stop_callback, result_callback):
        """Loop principal de escaneo con detección de SO y resolución de hostname."""
        self.logger.log(f"[SCAN] Iniciando en {rango}...", "info")
        results = []
        try:
            hosts = _scan_rango(rango, timeout)

            from scapy.all import IP, ICMP, sr1

            total = len(hosts)
            for idx, (ip, mac) in enumerate(hosts, 1):
                from modulos.config import GATEWAY as GW_CURRENT
                rol = "★ Gateway" if ip == GW_CURRENT else "Dispositivo"
                fab = _fabricante_mac(mac)
                os_guess = "Desconocido"
                hostname = ""

                # 1. Detección de SO por TTL vía ICMP
                try:
                    resp = sr1(IP(dst=ip)/ICMP(), timeout=0.3, verbose=0)
                    if resp and IP in resp:
                        ttl = resp[IP].ttl
                        if ttl <= 64:
                            os_guess = "Mac" if fab == "Apple" else "Linux"
                        elif ttl <= 128:
                            os_guess = "Windows"
                        else:
                            os_guess = "Router"
                except Exception:
                    pass

                # 2. Detección de respaldo si ICMP está bloqueado
                if os_guess == "Desconocido":
                    if fab == "Apple":
                        os_guess = "Mac"
                    elif fab == "Microsoft":
                        os_guess = "Windows"
                    elif fab in ("Samsung", "Xiaomi"):
                        os_guess = "Linux"
                    elif ip == GW_CURRENT or fab in ("Router", "TP-Link"):
                        os_guess = "Router"
                    else:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(0.12)
                            code = s.connect_ex((ip, 445))
                            s.close()
                            if code in (0, 10061, 111):
                                os_guess = "Windows"
                        except Exception:
                            pass

                # 3. Resolución de hostname (mDNS / NetBIOS / LLMNR en paralelo)
                try:
                    # Reverse DNS primero (rápido)
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror, OSError):
                        pass

                    # Si no se obtuvo hostname o es genérico, intentar mDNS/NetBIOS/LLMNR
                    if not hostname or hostname == ip:
                        # Resolución rápida con timeout corto para no ralentizar mucho
                        from modulos.discovery import (
                            _netbios_resolver, _mdns_resolver, _llmnr_resolver
                        )
                        # Intentar NetBIOS primero (más rápido en Windows)
                        hostname = _netbios_resolver(ip, timeout=1) or ""
                        if not hostname:
                            # Intentar reverse mDNS — buscar en la caché ARP local
                            pass  # Se podría expandir en el futuro
                except Exception:
                    pass

                # Limpiar hostname
                if hostname and hostname == ip:
                    hostname = ""

                self.logger.log(
                    f"[SCAN] {idx}/{total}  {ip}  {mac}  {os_guess}  {hostname or '—'}",
                    "ok"
                )
                results.append({
                    "ip": ip,
                    "mac": mac,
                    "os": os_guess,
                    "os_icon": os_guess,
                    "hostname": hostname if hostname else "Desconocido",
                    "fabricante": fab,
                    "rol": rol,
                })

            self.logger.log(f"[SCAN] Fin: {len(hosts)} hosts.", "ok")
        except Exception as e:
            self.logger.log(f"[SCAN] Error: {e}", "err")
        finally:
            if result_callback and results:
                result_callback(results)
            stop_callback()

    def get_default_range(self):
        """Obtiene el rango de red por defecto basado en el gateway."""
        from modulos.config import GATEWAY
        if GATEWAY and GATEWAY != "—":
            partes = GATEWAY.split(".")
            return f"{'.'.join(partes[:3])}.0/24"
        return "192.168.1.0/24"
