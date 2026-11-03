"""
Descubrimiento de dispositivos con IP dinámica.

Permite localizar la IP *actual* de un equipo en la red local aunque su
IP cambie (DHCP), usando tres estrategias:

  1. Mapeo por dirección MAC de hardware (capa 2):
     La MAC física del adaptador es fija (salvo aleatorización MAC).
     Pipeline de búsqueda:
       a) Caché ARP local del SO (instantáneo, sin tráfico)
       b) ARP unicast a la última IP conocida (rápido, 1 paquete)
       c) ARP scan completo de la subred (lento pero exhaustivo)

  2. Inspección de nombres de host (mDNS / NetBIOS / LLMNR):
     Dispositivos como iPhones anuncian su nombre en la red
     (ej. "iPhone.local"). Se resuelve ese nombre vía
     mDNS (multicast 224.0.0.251:5353), NetBIOS/NBNS (broadcast
     UDP 137), o LLMNR (multicast 224.0.0.252:5355) para obtener
     la IP en tiempo real. Los tres protocolos se consultan en
     paralelo para máxima velocidad.

  3. Identificación de fabricante por OUI:
     A partir de los 3 primeros bytes de la MAC se identifica el
     fabricante (Apple, Samsung, etc.) para dar contexto al usuario.
"""

import os
import random
import socket
import struct
import subprocess
import ipaddress
import threading
import time

import modulos.config as _cfg
from modulos.network_core import _obtener_mac, _scan_rango

__all__ = [
    '_normalizar_mac', 'es_ip', 'es_mac', 'clasificar_objetivo',
    '_subred_local', '_buscar_ip_por_mac', '_buscar_ip_por_mac_cache',
    '_buscar_ip_por_mac_rapido', '_mdns_resolver',
    '_netbios_resolver', '_llmnr_resolver', '_resolver_hostname',
    '_resolver_objetivo', '_fabricante_mac',
]


# ── Tabla OUI de fabricantes comunes ──────────────────────────────────
# Prefijos MAC (3 bytes) → nombre del fabricante.
# Se usa para mostrar información útil al usuario durante el escaneo.
_OUI_TABLE = {
    # Apple
    "a4:c3:f0": "Apple", "3c:22:fb": "Apple", "00:cd:fe": "Apple",
    "f0:18:98": "Apple", "8c:85:90": "Apple", "dc:a9:04": "Apple",
    "f0:d4:f6": "Apple", "ac:bc:32": "Apple", "78:7b:8a": "Apple",
    "14:98:77": "Apple", "a8:5c:2c": "Apple", "d0:03:4b": "Apple",
    "b0:34:95": "Apple", "28:6a:ba": "Apple", "e0:b5:2d": "Apple",
    "88:66:a5": "Apple", "6c:4d:73": "Apple", "f4:5c:89": "Apple",
    "38:f9:d3": "Apple", "c8:69:cd": "Apple", "7c:d1:c3": "Apple",
    # Samsung
    "00:07:ab": "Samsung", "00:12:fb": "Samsung", "00:1d:25": "Samsung",
    "70:f9:27": "Samsung", "d8:57:ef": "Samsung", "8c:77:12": "Samsung",
    "50:01:bb": "Samsung", "a8:f2:74": "Samsung", "e4:7c:f9": "Samsung",
    "30:07:4d": "Samsung", "78:ab:bb": "Samsung", "5c:3c:27": "Samsung",
    # Xiaomi / Redmi
    "28:6c:07": "Xiaomi", "64:cc:2e": "Xiaomi", "7c:1c:4e": "Xiaomi",
    "9c:99:a0": "Xiaomi", "fc:64:ba": "Xiaomi", "34:ce:00": "Xiaomi",
    # Huawei
    "00:e0:fc": "Huawei", "48:46:fb": "Huawei", "70:72:3c": "Huawei",
    "88:66:39": "Huawei", "c0:70:09": "Huawei", "24:09:95": "Huawei",
    # Microsoft
    "00:50:f2": "Microsoft", "28:18:78": "Microsoft",
    "7c:1e:52": "Microsoft", "dc:b4:c4": "Microsoft",
    # Intel (portátiles Windows comunes)
    "00:1e:64": "Intel", "3c:97:0e": "Intel", "68:05:ca": "Intel",
    "a0:36:9f": "Intel", "b4:d5:bd": "Intel", "48:a4:72": "Intel",
    # Realtek (adaptadores USB Wi-Fi baratos)
    "00:e0:4c": "Realtek", "52:54:00": "Realtek",
    # TP-Link
    "50:c7:bf": "TP-Link", "c0:25:e9": "TP-Link", "54:c8:0f": "TP-Link",
    "18:a6:f7": "TP-Link", "60:32:b1": "TP-Link",
    # Routers / ISP comunes
    "00:1a:2b": "Router", "00:18:01": "Router",
}


def _fabricante_mac(mac):
    """Identifica el fabricante a partir del OUI (3 primeros bytes).

    Devuelve el nombre del fabricante o 'Desconocido'.
    """
    norm = _normalizar_mac(mac)
    if not norm:
        return "Desconocido"
    oui = norm[:8]  # "aa:bb:cc"
    return _OUI_TABLE.get(oui, "Desconocido")


# ── Clasificación y normalización ─────────────────────────────────────
def _normalizar_mac(texto):
    """Normaliza una MAC a formato aa:bb:cc:dd:ee:ff (minúsculas).

    Acepta separadores ':', '-' o '.' y también formato plano de 12 hex.
    Devuelve None si no es una MAC válida.
    """
    if not texto:
        return None
    t = str(texto).strip().lower().replace("-", ":").replace(".", ":")
    partes = t.split(":")
    if len(partes) == 1 and len(partes[0]) == 12:
        partes = [partes[0][i:i + 2] for i in range(0, 12, 2)]
    if len(partes) != 6 or any(len(p) != 2 for p in partes):
        return None
    try:
        bytes(int(p, 16) for p in partes)
    except ValueError:
        return None
    return ":".join(partes)


def es_ip(texto):
    """True si el texto es una dirección IPv4/IPv6 válida."""
    try:
        ipaddress.ip_address(str(texto).strip())
        return True
    except ValueError:
        return False


def es_mac(texto):
    """True si el texto es una MAC válida."""
    return _normalizar_mac(texto) is not None


def clasificar_objetivo(texto):
    """Clasifica la entrada del usuario: 'ip' | 'mac' | 'host' | None."""
    t = (texto or "").strip()
    if not t:
        return None
    if es_ip(t):
        return "ip"
    if es_mac(t):
        return "mac"
    return "host"


def _subred_local():
    """Rango CIDR de la subred local (a partir del gateway o IP local)."""
    gw = _cfg.GATEWAY
    if gw and gw != "—":
        partes = str(gw).split(".")
        if len(partes) == 4:
            return f"{'.'.join(partes[:3])}.0/24"
    ip = _cfg.IP_LOCAL
    if ip and ip != "127.0.0.1":
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            pass
    return "192.168.1.0/24"


# ══════════════════════════════════════════════════════════════════════
# ESTRATEGIA 1: MAPEO POR MAC DE HARDWARE (CAPA 2)
# ══════════════════════════════════════════════════════════════════════

def _buscar_ip_por_mac_cache(mac_objetivo):
    """Busca la IP asociada a una MAC en la caché ARP local del SO.

    Es instantáneo y no genera tráfico de red. Consulta la tabla ARP
    que el SO ya tiene en memoria (comando 'arp -a' en Windows).
    Devuelve la IP o None.
    """
    mac_norm = _normalizar_mac(mac_objetivo)
    if not mac_norm:
        return None
    try:
        out = subprocess.check_output(
            ["arp", "-a"], timeout=4,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        ).decode("utf-8", errors="ignore")
        # Formato Windows: "  192.168.1.50     aa-bb-cc-dd-ee-ff     dinámico"
        for linea in out.splitlines():
            partes = linea.split()
            if len(partes) >= 2:
                mac_linea = _normalizar_mac(partes[1])
                if mac_linea == mac_norm:
                    ip_cand = partes[0].strip()
                    if es_ip(ip_cand):
                        return ip_cand
    except Exception:
        pass
    return None


def _buscar_ip_por_mac_rapido(mac_objetivo, ultima_ip):
    """ARP unicast dirigido a la última IP conocida del objetivo.

    Envía un solo paquete ARP a la IP donde se vio por última vez.
    Si la MAC que responde coincide, la IP sigue siendo válida.
    Mucho más rápido que un scan completo de la subred.
    Devuelve la IP si coincide, None si no.
    """
    mac_norm = _normalizar_mac(mac_objetivo)
    if not mac_norm or not ultima_ip:
        return None
    try:
        mac_resp = _obtener_mac(ultima_ip, intentos=2)
        if mac_resp and _normalizar_mac(mac_resp) == mac_norm:
            return ultima_ip
    except Exception:
        pass
    return None


def _buscar_ip_por_mac(mac_objetivo, rango=None, timeout=3, ultima_ip=None):
    """Localiza la IP actual de un dispositivo por su MAC de hardware.

    Pipeline de búsqueda (de más rápido a más lento):
      1. Caché ARP local (instantáneo, sin tráfico de red)
      2. ARP unicast a la última IP conocida (1 paquete)
      3. ARP scan completo de la subred (broadcast a /24)

    Args:
        mac_objetivo: MAC a buscar (cualquier formato).
        rango: Rango CIDR a escanear (None = subred local).
        timeout: Timeout del scan completo.
        ultima_ip: Última IP conocida (para verificación rápida).

    Returns:
        (ip, metodo) — ip es None si no se encontró.
        metodo es 'cache' | 'unicast' | 'scan' | None.
    """
    mac_norm = _normalizar_mac(mac_objetivo)
    if not mac_norm:
        return None, None

    # 1) Caché ARP local (instantáneo)
    ip = _buscar_ip_por_mac_cache(mac_norm)
    if ip:
        return ip, "caché ARP"

    # 2) ARP unicast a última IP conocida (rápido, 1 pkt)
    if ultima_ip:
        ip = _buscar_ip_por_mac_rapido(mac_norm, ultima_ip)
        if ip:
            return ip, "unicast ARP"

    # 3) Scan completo de la subred (lento pero exhaustivo)
    rango = rango or _subred_local()
    try:
        for ip, mac in _scan_rango(rango, timeout):
            if _normalizar_mac(mac) == mac_norm:
                return ip, "scan L2"
    except Exception:
        pass
    return None, None


# Wrapper de compatibilidad: las llamadas antiguas que esperan solo IP
# siguen funcionando (devuelve solo la IP, ignora el método).
_buscar_ip_por_mac_simple = _buscar_ip_por_mac  # alias interno


# ══════════════════════════════════════════════════════════════════════
# ESTRATEGIA 2: INSPECCIÓN DE NOMBRES DE HOST
# ══════════════════════════════════════════════════════════════════════

# ── 2a: mDNS (Bonjour / Avahi) ──────────────────────────────────────
def _extraer_registros_a(respuesta):
    """Extrae las IPs (registros A) de una respuesta DNS cruda."""
    ips = []
    try:
        qd = struct.unpack(">H", respuesta[4:6])[0]
        an = struct.unpack(">H", respuesta[6:8])[0]
        off = 12

        def _saltar_nombre(o):
            """Avanza sobre un nombre DNS (con compresión de punteros)."""
            while o < len(respuesta):
                ln = respuesta[o]
                if ln & 0xC0 == 0xC0:          # puntero comprimido
                    return o + 2
                o += 1
                if ln == 0:
                    return o
                o += ln
            return o

        for _ in range(qd):                   # sección de preguntas
            off = _saltar_nombre(off) + 4
        for _ in range(an):                   # sección de respuestas
            off = _saltar_nombre(off)
            if off + 10 > len(respuesta):
                break
            rtype = struct.unpack(">H", respuesta[off:off + 2])[0]
            rdlen = struct.unpack(">H", respuesta[off + 8:off + 10])[0]
            rdata = respuesta[off + 10:off + 10 + rdlen]
            off += 10 + rdlen
            if rtype == 1 and rdlen == 4:     # registro A
                ips.append(".".join(str(b) for b in rdata))
    except Exception:
        pass
    return ips


def _mdns_resolver(nombre, timeout=3):
    """Resuelve un hostname vía mDNS (multicast 224.0.0.251:5353).

    Es el método habitual de iPhones, Macs y dispositivos Linux
    (ej. 'iPhone.local'). Devuelve la IP o None.
    """
    nombre = (nombre or "").strip().strip(".").lower()
    if not nombre:
        return None
    if not nombre.endswith(".local"):
        nombre += ".local"

    tid = random.randint(0, 0xFFFF)
    # mDNS estándar: flags 0x0000 (sin recursión), QU bit en clase
    cabecera = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    etiquetas = b"".join(
        bytes([len(l)]) + l.encode("ascii", "ignore")
        for l in nombre.split(".")
    )
    # Clase 0x8001 = unicast-response + IN (QU query, más fiable)
    consulta = cabecera + etiquetas + b"\x00" + struct.pack(">HH", 1, 0x8001)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        # Unirse al grupo multicast para recibir respuestas
        try:
            mreq = struct.pack("4s4s",
                               socket.inet_aton("224.0.0.251"),
                               socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass  # No fatal si falla el join
        sock.settimeout(timeout)
        # Enviar 2 veces para mayor fiabilidad (mDNS puede perder paquetes)
        sock.sendto(consulta, ("224.0.0.251", 5353))
        time.sleep(0.1)
        sock.sendto(consulta, ("224.0.0.251", 5353))
        while True:
            datos, _ = sock.recvfrom(4096)
            if len(datos) < 12:
                continue
            for ip in _extraer_registros_a(datos):
                return ip
    except (socket.timeout, OSError):
        pass
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return None


# ── 2b: NetBIOS / NBNS (broadcast UDP 137) ──────────────────────────
def _codificar_nombre_netbios(nombre):
    """Codifica un nombre al formato NetBIOS de 32 caracteres (16 bytes)."""
    limpio = (nombre or "").upper()[:15].replace("-", " ").replace("_", " ")
    raw = (limpio.ljust(15) + "\x00").encode("ascii", "ignore")
    return "".join(
        chr(65 + ((b >> 4) & 0x0F)) + chr(65 + (b & 0x0F)) for b in raw
    )


def _analizar_nbns(datos, tid):
    """Parsea una respuesta NBNS y extrae la IP del equipo (si la hay)."""
    try:
        if len(datos) < 61:
            return None
        if struct.unpack(">H", datos[:2])[0] != tid:
            return None
        if struct.unpack(">H", datos[6:8])[0] < 1:      # ANCOUNT
            return None
        # La respuesta empieza en 12 (cabecera) + 37 (pregunta NBNS)
        if datos[49] == 0xC0:                            # nombre comprimido
            rd = 61
        else:                                            # nombre completo (33 B)
            rd = 92
        if len(datos) < rd + 4:
            return None
        if struct.unpack(">H", datos[rd - 2:rd])[0] != 4:  # RDLENGTH
            return None
        return ".".join(str(b) for b in datos[rd:rd + 4])
    except Exception:
        return None


def _netbios_resolver(nombre, timeout=3):
    """Resuelve un hostname vía NetBIOS Name Service (broadcast UDP 137).

    Es el método habitual de equipos Windows (ej. 'DESKTOP-PC').
    Devuelve la IP o None.
    """
    nombre = (nombre or "").strip()
    if not nombre:
        return None

    # Quitar sufijo .local si viene
    if nombre.lower().endswith(".local"):
        nombre = nombre[:-6]

    tid = random.randint(0, 0xFFFF)
    cabecera = struct.pack(">HHHHHH", tid, 0x0110, 1, 0, 0, 0)
    pregunta = (b"\x20" + _codificar_nombre_netbios(nombre).encode("ascii")
                + struct.pack(">HH", 0x0020, 0x0001))
    paquete = cabecera + pregunta

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(paquete, ("255.255.255.255", 137))
        while True:
            datos, _ = sock.recvfrom(2048)
            ip = _analizar_nbns(datos, tid)
            if ip:
                return ip
    except (socket.timeout, OSError):
        pass
    finally:
        if sock:
            sock.close()
    return None


# ── 2c: LLMNR — Link-Local Multicast Name Resolution ────────────────
def _llmnr_resolver(nombre, timeout=3):
    """Resuelve un hostname vía LLMNR (multicast 224.0.0.252:5355).

    LLMNR es el protocolo de resolución de nombres usado por Windows
    cuando DNS falla. Muchos equipos Windows responden a LLMNR incluso
    si no responden a NetBIOS. Devuelve la IP o None.
    """
    nombre = (nombre or "").strip().strip(".")
    if not nombre:
        return None
    # Quitar sufijo .local si viene
    if nombre.lower().endswith(".local"):
        nombre = nombre[:-6]

    tid = random.randint(0, 0xFFFF)
    # LLMNR: flags 0x0000, 1 pregunta, 0 respuestas
    cabecera = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    etiquetas = b"".join(
        bytes([len(l)]) + l.encode("ascii", "ignore")
        for l in nombre.split(".")
    )
    # Tipo A (1), Clase IN (1)
    consulta = cabecera + etiquetas + b"\x00" + struct.pack(">HH", 1, 1)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.settimeout(timeout)
        sock.sendto(consulta, ("224.0.0.252", 5355))
        while True:
            datos, _ = sock.recvfrom(4096)
            if len(datos) < 12:
                continue
            resp_tid = struct.unpack(">H", datos[:2])[0]
            if resp_tid != tid:
                continue
            for ip in _extraer_registros_a(datos):
                return ip
    except (socket.timeout, OSError):
        pass
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return None


# ── Resolución concurrente de hostname ───────────────────────────────
def _resolver_hostname(nombre, timeout=3):
    """Resuelve un hostname por mDNS, NetBIOS y LLMNR en paralelo.

    Lanza los tres protocolos en hilos concurrentes y devuelve el
    primer resultado que llegue, sin esperar a que los demás terminen.
    Esto reduce drásticamente el tiempo de resolución comparado con
    intentar cada protocolo en serie.

    Devuelve (ip, metodo) — ip es None si no se resolvió.
    """
    nombre = (nombre or "").strip().strip(".")
    if not nombre:
        return None, None

    base = nombre[:-6] if nombre.lower().endswith(".local") else nombre

    # Resultado compartido entre hilos
    resultado = {"ip": None, "metodo": None}
    encontrado = threading.Event()

    def _intentar(fn, args, metodo_nombre):
        """Ejecuta un resolver y guarda el primer resultado."""
        try:
            ip = fn(*args)
            if ip and not encontrado.is_set():
                resultado["ip"] = ip
                resultado["metodo"] = metodo_nombre
                encontrado.set()
        except Exception:
            pass

    # Lanzar los 3 protocolos en paralelo
    hilos = [
        threading.Thread(target=_intentar,
                         args=(_mdns_resolver, (base, timeout), "mDNS"),
                         daemon=True),
        threading.Thread(target=_intentar,
                         args=(_netbios_resolver, (base, timeout), "NetBIOS"),
                         daemon=True),
        threading.Thread(target=_intentar,
                         args=(_llmnr_resolver, (base, timeout), "LLMNR"),
                         daemon=True),
    ]
    for h in hilos:
        h.start()

    # Esperar hasta que uno responda o todos expiren
    encontrado.wait(timeout=timeout + 1)

    if resultado["ip"]:
        return resultado["ip"], resultado["metodo"]

    # Último intento: mDNS con el nombre completo (por si tiene .local)
    if base != nombre:
        ip = _mdns_resolver(nombre, timeout=2)
        if ip:
            return ip, "mDNS"

    return None, None


# ══════════════════════════════════════════════════════════════════════
# RESOLUCIÓN UNIFICADA DE OBJETIVO
# ══════════════════════════════════════════════════════════════════════

def _resolver_objetivo(texto, rango=None, ultima_ip=None):
    """Resuelve cualquier tipo de objetivo (IP / MAC / hostname).

    Devuelve un dict {modo, ip, mac, detalle, fabricante} o None si
    la entrada está vacía.

    Args:
        texto: IP, MAC o hostname del objetivo.
        rango: Rango CIDR para escaneo MAC (None = autodetectar).
        ultima_ip: Última IP conocida (para verificación rápida MAC).
    """
    texto = (texto or "").strip()
    modo = clasificar_objetivo(texto)
    if modo is None:
        return None

    if modo == "ip":
        mac = _obtener_mac(texto)
        return {
            "modo": "ip",
            "ip": texto,
            "mac": mac,
            "detalle": "IP directa",
            "fabricante": _fabricante_mac(mac) if mac else "—",
        }

    if modo == "mac":
        mac = _normalizar_mac(texto)
        ip, metodo_busq = _buscar_ip_por_mac(mac, rango, ultima_ip=ultima_ip)
        return {
            "modo": "mac",
            "ip": ip,
            "mac": mac,
            "detalle": f"MAC → IP vía {metodo_busq}" if metodo_busq else "MAC (no encontrada)",
            "fabricante": _fabricante_mac(mac),
        }

    # modo == "host"
    ip, metodo = _resolver_hostname(texto)
    mac = _obtener_mac(ip) if ip else None
    return {
        "modo": "host",
        "ip": ip,
        "mac": mac,
        "detalle": f"Hostname ({metodo or 'sin resolver'})",
        "fabricante": _fabricante_mac(mac) if mac else "—",
    }
