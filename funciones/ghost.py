"""
Módulo GHOST - Ocultación y evasión avanzada
"""

import threading
import subprocess
from modulos.system_utils import (
    _is_admin, _win_registry_set_hostname, _win_registry_set_ttl, 
    _clean_network_traces, _win_registry_get_hostname, 
    _win_registry_get_ttl, _win_registry_delete_ttl
)

class GhostModule:
    """Módulo para ocultación y evasión de red."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
        self.original_hostname = _win_registry_get_hostname()
        self.original_ttl = _win_registry_get_ttl()
    
    def spoof_hostname(self, nuevo_nombre, write_callback):
        """Cambia el hostname del sistema."""
        if not nuevo_nombre:
            return "Introduce un nuevo nombre de host."
        
        if not _is_admin():
            write_callback("✗ ERROR: Se requieren privilegios de ADMINISTRADOR.\n")
            self.logger.log("[GHOST] Error: Sin privilegios admin", "err")
            return "Se requieren privilegios de administrador"
        
        write_callback(f"» Intentando cambiar hostname a '{nuevo_nombre}'...\n")
        try:
            _win_registry_set_hostname(nuevo_nombre)
            write_callback("✔ Hostname modificado en el registro. Requiere reinicio para tener efecto total.\n")
            self.logger.log(f"[GHOST] Hostname → {nuevo_nombre}", "ok")
            return "Hostname cambiado correctamente"
        except Exception as e:
            write_callback(f"✗ Error Registro: {e}\n")
            self.logger.log(f"[GHOST] Error Registro: {e}", "err")
            return f"Error: {e}"
    
    def emulate_ttl(self, write_callback):
        """Emula TTL de Linux (64)."""
        if not _is_admin():
            write_callback("✗ ERROR: Se requieren privilegios de ADMINISTRADOR.\n")
            return "Se requieren privilegios de administrador"
        
        write_callback("» Cambiando DefaultTTL a 64 (Emulación Linux)....\n")
        try:
            _win_registry_set_ttl(64)
            write_callback("✔ TTL a 64 aplicado. Los escáneres te verán como Linux.\n")
            self.logger.log("[GHOST] TTL → 64", "ok")
            return "TTL cambiado a 64"
        except Exception as e:
            write_callback(f"✗ Error Registro: {e}\n")
            return f"Error: {e}"
    
    def clean_traces(self, write_callback):
        """Limpia rastros de red."""
        write_callback("» Limpiando rastros de red globales...\n")
        self.logger.log("[GHOST] Limpieza de rastros", "warn")
        threading.Thread(target=self._clean_traces_thread, args=(write_callback,), daemon=True).start()
        return "Iniciando limpieza de rastros..."
    
    def _clean_traces_thread(self, write_callback):
        """Hilo para limpieza de rastros."""
        try:
            write_callback("  [+] Flush DNS...\n")
            admin_clean = _clean_network_traces()
            
            if admin_clean:
                write_callback("  [+] Borrando tabla ARP...\n")
                write_callback("  [+] Reiniciando NetBIOS...\n")
            else:
                write_callback("  [!] ARP/NetBIOS requieren ser Administrador. Se omite.\n")
                
            write_callback("✔ Limpieza completada.\n")
            self.logger.log("[GHOST] Limpieza fina", "ok")
        except Exception as e:
            write_callback(f"✗ Error limpiando: {e}\n")

    def restore_ghost(self, write_callback):
        """Restaura el Hostname y TTL originales."""
        if not _is_admin():
            write_callback("✗ ERROR: Se requieren privilegios de ADMINISTRADOR.\n")
            return
            
        write_callback("» Restaurando valores originales de fábrica...\n")
        try:
            if self.original_hostname:
                _win_registry_set_hostname(self.original_hostname)
                write_callback(f"✔ Hostname restaurado a '{self.original_hostname}'.\n")
            
            if self.original_ttl is not None:
                _win_registry_set_ttl(self.original_ttl)
                write_callback(f"✔ TTL restaurado a {self.original_ttl}.\n")
            else:
                _win_registry_delete_ttl()
                write_callback("✔ TTL restaurado al valor por defecto (clave eliminada).\n")
                
            self.logger.log("[GHOST] Parámetros originales restaurados", "ok")
            write_callback("📢 Requiere reinicio para tener efecto total.\n")
        except Exception as e:
            write_callback(f"✗ Error Restaurando: {e}\n")
            self.logger.log(f"[GHOST] Error Restaurando: {e}", "err")
