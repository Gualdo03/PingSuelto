"""
Módulo VEYON - Gestión de llaves y bloqueo de puertos
"""

import os
import glob
import subprocess
import socket
import threading
import time
from modulos.config import _estado
from modulos.system_utils import _is_admin

class VeyonModule:
    """Módulo para gestión de Veyon y Wake-on-LAN."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
        self._monitor_running = False
        self._persist_running = False

    
    def send_wol(self, mac, write_callback):
        """Envía un Magic Packet para Wake-on-LAN."""
        try:
            c = mac.replace(":","").replace("-","")
            if len(c) != 12: 
                raise ValueError("MAC inválida (12 hex dígitos)")
            payload = bytes.fromhex("FF"*6 + c*16)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(payload, ("255.255.255.255", 9))
            s.close()
            write_callback(f"✔ Magic Packet enviado a {mac}\n")
            self.logger.log(f"[WoL] Enviado → {mac}", "ok")
            return True
        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[WoL] Error: {e}", "err")
            return False
    
    def find_pem_keys(self, directory=None):
        """Busca archivos .pem en directorios comunes de Veyon."""
        dirs = [
            directory or "",
            os.path.dirname(os.path.abspath(__file__)).replace("funciones", ""),  # Directorio base
            r"C:\ProgramData\Veyon\keys",
            r"C:\Program Files\Veyon",
            os.path.expanduser("~"),
        ]
        claves = []
        for d in dirs:
            if d and os.path.isdir(d):
                claves.extend(glob.glob(os.path.join(d, "**", "*.pem"), recursive=True))
        # Eliminar duplicados conservando orden
        seen = set()
        result = []
        for c in claves:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result
    
    def freeze_veyon(self, write_callback):
        """Congela procesos Veyon."""
        psutil_available = False
        try:
            import psutil
            psutil_available = True
        except ImportError:
            write_callback("✗ psutil no instalado. Ejecuta: pip install psutil\n")
            return False
        
        try:
            enc = False
            for proc in psutil.process_iter(["name", "pid"]):
                if "veyon" in proc.info["name"].lower():
                    try:
                        proc.suspend()
                        msg = f"⏸ SUSPENDIDO: {proc.info['name']} (PID {proc.pid})\n"
                        write_callback(msg)
                        self.logger.log(f"[VEYON] Suspendido PID {proc.pid}", "warn")
                    except Exception as suspend_err:
                        write_callback(f"  ⚠ suspend() falló ({suspend_err}), usando taskkill /FI...\n")
                        try:
                            subprocess.run(
                                ["taskkill", "/PID", str(proc.pid), "/T"],
                                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                            )
                            write_callback(f"  ✔ taskkill enviado a PID {proc.pid}\n")
                        except Exception as tk_err:
                            write_callback(f"  ✗ taskkill también falló: {tk_err}\n")
                    enc = True
            
            if not enc:
                write_callback("✗ Ningún proceso Veyon encontrado en ejecución.\n")
                self.logger.log("[VEYON] Sin procesos activos.", "warn")
                return False
            
            return True
        except Exception as e:
            write_callback(f"✗ Error (¿Admin?): {e}\n")
            self.logger.log(f"[VEYON] Error: {e}", "err")
            return False
    
    def force_kill_veyon(self, write_callback):
        """Fuerza el cierre completo de todos los procesos Veyon."""
        if not _is_admin():
            write_callback("✗ Se requieren privilegios de Administrador para forzar cierre.\n")
            return False
        
        enc = False
        psutil_available = False
        try:
            import psutil
            psutil_available = True
        except ImportError:
            pass
        
        # Intentar primero con psutil si disponible
        if psutil_available:
            for proc in psutil.process_iter(["name", "pid"]):
                if "veyon" in proc.info["name"].lower():
                    try:
                        proc.kill()  # SIGKILL equivalente
                        write_callback(f"💀 FORZADO: {proc.info['name']} (PID {proc.pid}) eliminado.\n")
                        self.logger.log(f"[VEYON] Force-kill PID {proc.pid}", "err")
                        enc = True
                    except Exception as e:
                        write_callback(f"  ✗ kill() falló PID {proc.pid}: {e}\n")
        
        # Respaldo: taskkill /F /IM veyon*.exe
        for nombre_exe in ["veyon-service.exe", "veyon-worker.exe", "veyon-master.exe", "veyonservice.exe"]:
            try:
                r = subprocess.run(
                    ["taskkill", "/F", "/IM", nombre_exe, "/T"],
                    capture_output=True, text=True
                )
                if "SUCCESS" in r.stdout or "ÉXITO" in r.stdout or r.returncode == 0:
                    write_callback(f"  ✔ taskkill /F: {nombre_exe} terminado.\n")
                    enc = True
            except Exception:
                pass
        
        if not enc:
            write_callback("✗ No se encontraron procesos Veyon para forzar cierre.\n")
            self.logger.log("[VEYON] Forzar cierre: sin procesos.", "warn")
            return False
        
        return True
    
    def unfreeze_veyon(self, write_callback):
        """Descongela procesos Veyon."""
        try:
            import psutil
        except ImportError:
            return False
        
        try:
            for proc in psutil.process_iter(["name", "pid"]):
                if "veyon" in proc.info["name"].lower():
                    proc.resume()
                    write_callback(f"▶ REANUDADO: {proc.info['name']} (PID {proc.pid})\n")
                    self.logger.log(f"[VEYON] Reanudado PID {proc.pid}", "ok")
            return True
        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[VEYON] Error: {e}", "err")
            return False
    
    def block_veyon_port(self, write_callback):
        """Bloquea el puerto 11100 de Veyon en el firewall."""
        if not _is_admin():
            write_callback("✗ ERROR: Se requieren privilegios de Administrador para modificar el firewall.\n")
            return False
        
        cmd = 'netsh advfirewall firewall add rule name="Block_Veyon_11100" dir=in action=block protocol=TCP localport=11100'
        write_callback("» Ejecutando regla de firewall: bloqueando puerto 11100...\n")
        
        creationflags = 0
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            creationflags = subprocess.CREATE_NO_WINDOW
        
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
            write_callback("✔ Regla de bloqueo de Veyon aplicada silenciosamente.\n")
            self.logger.log("[VEYON] Bloqueo puerto 11100 aplicado.", "ok")
            return True
        except Exception as e:
            write_callback(f"✗ Error aplicando regla: {e}\n")
            return False
    
    def scan_veyon_keys(self, base_dir, write_callback):
        """Escanea en busca de llaves Veyon en múltiples ubicaciones."""
        paths = [r"C:\ProgramData\Veyon\keys", r"C:\Program Files\Veyon", base_dir]
        write_callback("» Buscando llaves Veyon...\n")
        enc = False
        
        for path in paths:
            if os.path.exists(path):
                for root_d, _, files in os.walk(path):
                    for f in files:
                        if f.endswith((".pem",".key",".pub")):
                            fp = os.path.join(root_d, f)
                            write_callback(f"  📄 {fp}\n")
                            self.logger.log(f"[VEYON] Llave: {fp}", "ok")
                            enc = True
        
        if not enc:
            write_callback("✗ No se encontraron llaves .pem/.key/.pub\n")
        
        return enc

    def start_monitor(self, write_callback, alert_callback=None):
        """Inicia monitoreo de puerto 11100 para detectar visualización de Veyon."""
        try:
            from scapy.all import sniff
        except ImportError:
            write_callback("✗ scapy no está instalado. No se puede monitorizar.\n")
            return False

        if self._monitor_running:
            write_callback("⚠ El monitor de Veyon ya está en ejecución.\n")
            return False

        self._monitor_running = True
        write_callback("» Iniciando sistema de alerta temprana Veyon (Puerto 11100)...\n")
        
        def _monitor_loop():
            def proc(pkt):
                if not self._monitor_running: return
                msg = "[!!] ⚠️ ALERTA: EL PROFESOR ESTÁ OBSERVANDO (Tráfico Veyon en pto 11100) [!!]"
                self.logger.log(msg, "err")
                if alert_callback:
                    alert_callback()

            try:
                # Store false is critical to prevent memory leak
                sniff(filter="tcp port 11100", prn=proc, stop_filter=lambda _: not self._monitor_running, store=False)
            except Exception as e:
                write_callback(f"✗ Error en monitor Scapy: {e}\n")
            finally:
                self._monitor_running = False

        threading.Thread(target=_monitor_loop, daemon=True).start()
        return True

    def stop_monitor(self, write_callback):
        if self._monitor_running:
            self._monitor_running = False
            write_callback("● Monitoreo de Veyon desactivado.\n")
        else:
            write_callback("⚠ El monitor no estaba activo.\n")

    def start_persistent_block(self, write_callback):
        """Bloquea puerto 11100 y lo mantiene bloqueado."""
        if not _is_admin():
            write_callback("✗ Se necesita ser Admin para bloqueo persistente de Firewall.\n")
            return False

        if self._persist_running: 
            write_callback("⚠ Guardián persistente ya activo.\n")
            return False

        self._persist_running = True
        write_callback("» Iniciando bloqueo persistente de Firewall (Guardián de conexión)...\n")
        self.block_veyon_port(write_callback) # Primer bloqueo
        
        def _persist_loop():
            creationflags = 0
            if hasattr(subprocess, 'CREATE_NO_WINDOW'): creationflags = subprocess.CREATE_NO_WINDOW
            check_cmd = 'netsh advfirewall firewall show rule name="Block_Veyon_11100"'
            
            while self._persist_running:
                time.sleep(5)
                # Verificar si existe la regla
                try:
                    r = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, creationflags=creationflags)
                    if "No rules match the specified criteria" in r.stdout or "No se encontraron reglas" in r.stdout:
                        self.logger.log("[VEYON] ⚠️ Alerta: Regla de firewall borrada por el sistema/profesor. Restaurando...", "warn")
                        self.block_veyon_port(lambda _: None)
                except Exception:
                    pass
        
        threading.Thread(target=_persist_loop, daemon=True).start()
        return True

    def stop_persistent_block(self, write_callback):
        if self._persist_running:
            self._persist_running = False
            write_callback("● Guardián persistente de Firewall desactivado.\n")
            
            # Optionally remove the rule to clean up
            if _is_admin():
                creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                cmd = 'netsh advfirewall firewall delete rule name="Block_Veyon_11100"'
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
                write_callback("✔ Regla de bloqueo Veyon eliminada.\n")
        else:
            write_callback("⚠ El guardián persistente no estaba activo.\n")
