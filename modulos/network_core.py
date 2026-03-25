"""
Funciones base de red - IP, Gateway, MAC, OUI lookup
"""

import uuid
import random
import socket
import time
import os

__all__ = [
    '_mac_propia', '_mac_aleatoria', '_gateway', '_ip_local', 
    '_obtener_mac', '_scan_rango'
]

def _mac_propia():
    """Obtiene la MAC propia del sistema."""
    node = uuid.getnode()
    return ':'.join(f'{(node >> i) & 0xff:02x}' for i in range(0, 48, 8))[::-1]

def _mac_aleatoria(oui=None):
    """Genera MAC aleatoria. Si oui='apple' usa prefijos Apple reales para más sigilo."""
    ouis = {
        "apple":   ["a4:c3:f0","3c:22:fb","00:cd:fe","f0:18:98","8c:85:90"],
        "samsung": ["00:07:ab","00:12:fb","00:1d:25","70:f9:27","d8:57:ef"],
        "generic": [f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"],
    }
    base = random.choice(ouis.get(oui or "generic", ouis["generic"]))
    tail = ':'.join(f'{random.randint(0, 255):02x}' for _ in range(3))
    return f"{base}:{tail}"

def _gateway():
    """Obtiene el gateway por defecto. Usa ruta del sistema como fallback rápido."""
    try:
        import subprocess
        # Método rápido sin necesidad de Scapy
        out = subprocess.check_output(
            ["powershell", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
            timeout=4, stderr=subprocess.DEVNULL, creationflags=0x08000000
        ).decode("utf-8", errors="ignore").strip()
        if out and out != "":  
            return out
    except Exception:
        pass
    try:
        from scapy.all import conf
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return "—"

def _ip_local():
    """Obtiene la IP local conectando a un servidor externo (con timeout)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _obtener_mac(ip, intentos=3):
    """ARP request con reintentos para mayor fiabilidad."""
    try:
        from scapy.all import srp, Ether, ARP
    except ImportError:
        return None
    
    for _ in range(intentos):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=1.5, verbose=0, retry=1)
            for _, r in ans:
                return r.hwsrc
        except Exception:
            pass
        time.sleep(0.3)
    return None

def _scan_rango(rango, timeout=3):
    """Escanea el rango ARP y devuelve lista de (ip, mac)."""
    try:
        from scapy.all import srp, Ether, ARP
    except ImportError:
        return []
    
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango),
                     timeout=timeout, verbose=0)
        return [(r.psrc, r.hwsrc) for _, r in ans]
    except Exception:
        return []
