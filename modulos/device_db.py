"""
Base de datos de dispositivos de red.

Almacena información de dispositivos descubiertos en escaneos:
  • MAC (clave primaria) — identifica al dispositivo de forma única
  • Última IP vista, SO, hostname, fabricante, rol
  • Alias y notas personalizadas del usuario
  • Timestamps de primera vez visto y última vez visto

Permite que al re-escanear la red, los dispositivos conocidos
muestren su alias/nombre personalizado automáticamente.
"""

import os
import json
import time
import threading

# Ruta del archivo de base de datos (JSON para simplicidad y portabilidad)
_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_DB_FILE = os.path.join(_DB_DIR, "devices.json")
_lock = threading.Lock()


def _load_db():
    """Carga la base de datos desde disco. Devuelve dict {mac: {...}}."""
    try:
        if os.path.exists(_DB_FILE):
            with open(_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_db(db):
    """Guarda la base de datos en disco."""
    try:
        os.makedirs(_DB_DIR, exist_ok=True)
        with open(_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def guardar_dispositivo(mac, ip=None, os_name=None, hostname=None,
                        fabricante=None, rol=None, alias=None, notas=None):
    """Guarda o actualiza un dispositivo en la base de datos.

    Si el dispositivo ya existe (misma MAC), actualiza los campos
    proporcionados y el timestamp de última vez visto.
    Si es nuevo, crea la entrada completa.

    Args:
        mac: MAC del dispositivo (clave primaria).
        ip: Última IP conocida.
        os_name: Sistema operativo detectado.
        hostname: Nombre de host resuelto.
        fabricante: Fabricante del adaptador de red (OUI).
        rol: Rol en la red (Gateway, Dispositivo, etc.).
        alias: Nombre personalizado del usuario.
        notas: Notas libres del usuario.
    """
    mac = (mac or "").strip().lower()
    if not mac:
        return

    with _lock:
        db = _load_db()
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if mac in db:
            # Actualizar dispositivo existente
            dev = db[mac]
            if ip is not None:
                dev["ip"] = ip
            if os_name is not None:
                dev["os"] = os_name
            if hostname is not None:
                dev["hostname"] = hostname
            if fabricante is not None:
                dev["fabricante"] = fabricante
            if rol is not None:
                dev["rol"] = rol
            if alias is not None:
                dev["alias"] = alias
            if notas is not None:
                dev["notas"] = notas
            dev["last_seen"] = now
        else:
            # Nuevo dispositivo
            db[mac] = {
                "mac": mac,
                "ip": ip or "",
                "os": os_name or "",
                "hostname": hostname or "",
                "fabricante": fabricante or "",
                "rol": rol or "",
                "alias": alias or "",
                "notas": notas or "",
                "first_seen": now,
                "last_seen": now,
            }

        _save_db(db)


def guardar_escaneo(results):
    """Guarda todos los dispositivos de un escaneo.

    Args:
        results: Lista de dicts con {ip, mac, os, hostname, rol, fabricante}.
    """
    for item in results:
        guardar_dispositivo(
            mac=item.get("mac", ""),
            ip=item.get("ip"),
            os_name=item.get("os"),
            hostname=item.get("hostname"),
            fabricante=item.get("fabricante"),
            rol=item.get("rol"),
        )


def obtener_dispositivo(mac):
    """Obtiene la información de un dispositivo por su MAC.

    Returns:
        Dict con toda la info del dispositivo, o None si no existe.
    """
    mac = (mac or "").strip().lower()
    if not mac:
        return None

    with _lock:
        db = _load_db()
        return db.get(mac)


def obtener_alias(mac):
    """Obtiene el alias de un dispositivo (o cadena vacía si no tiene).

    Returns:
        String con el alias, o "" si no tiene o no existe.
    """
    dev = obtener_dispositivo(mac)
    if dev:
        return dev.get("alias", "")
    return ""


def obtener_notas(mac):
    """Obtiene las notas de un dispositivo (o cadena vacía si no tiene)."""
    dev = obtener_dispositivo(mac)
    if dev:
        return dev.get("notas", "")
    return ""


def establecer_alias(mac, alias):
    """Establece o actualiza el alias de un dispositivo."""
    guardar_dispositivo(mac, alias=alias)


def establecer_notas(mac, notas):
    """Establece o actualiza las notas de un dispositivo."""
    guardar_dispositivo(mac, notas=notas)


def obtener_todos():
    """Devuelve todos los dispositivos de la base de datos.

    Returns:
        Dict {mac: {info...}}.
    """
    with _lock:
        return _load_db()


def enriquecer_resultados(results):
    """Enriquece resultados de escaneo con datos de la base de datos.

    Para cada dispositivo en results, busca en la BD por MAC y añade:
      - alias (si existe)
      - notas (si existen)
      - known (True si estaba en la BD)

    Args:
        results: Lista de dicts del escaneo.

    Returns:
        La misma lista con campos adicionales.
    """
    with _lock:
        db = _load_db()

    for item in results:
        mac = (item.get("mac", "") or "").strip().lower()
        if mac and mac in db:
            dev = db[mac]
            item["alias"] = dev.get("alias", "")
            item["notas"] = dev.get("notas", "")
            item["known"] = True
        else:
            item.setdefault("alias", "")
            item.setdefault("notas", "")
            item["known"] = False

    return results


def eliminar_dispositivo(mac):
    """Elimina un dispositivo de la base de datos."""
    mac = (mac or "").strip().lower()
    if not mac:
        return

    with _lock:
        db = _load_db()
        if mac in db:
            del db[mac]
            _save_db(db)
