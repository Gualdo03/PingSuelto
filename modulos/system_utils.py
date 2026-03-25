"""
Utilidades del sistema - elevación de privilegios y registro de Windows
"""

import os
import sys
import ctypes
import subprocess
import threading
import time
import socket

__all__ = [
    '_is_admin', '_auto_elevate', '_restart_admin', '_win_registry_set_hostname',
    '_win_registry_set_ttl', '_win_set_ip_forwarding', '_clean_network_traces', 'is_sandbox',
    '_win_registry_get_hostname', '_win_registry_get_ttl', '_win_registry_delete_ttl'
]

def _is_admin():
    """Verifica si el script se ejecuta con privilegios de administrador."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except Exception:
        return False

def _auto_elevate():
    """Si no somos admin en Windows, intentamos re-lanzar con runas."""
    try:
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1)
            if ret > 32:  # Éxito: la nueva instancia elevada se ha lanzado
                sys.exit(0)
    except Exception:
        pass  # Si falla, continuar sin admin

def _restart_admin():
    """Reinicia el programa con privilegios de administrador."""
    try:
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1)
    except Exception as e:
        raise Exception(f"No se pudo elevar privilegios: {e}")

def _win_registry_set_hostname(hostname):
    """Cambia el hostname en el registro de Windows."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "Hostname", 0, winreg.REG_SZ, hostname)
            winreg.SetValueEx(key, "NV Hostname", 0, winreg.REG_SZ, hostname)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "ComputerName", 0, winreg.REG_SZ, hostname)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "ComputerName", 0, winreg.REG_SZ, hostname)
        return True
    except Exception as e:
        raise Exception(f"Error en registro: {e}")

def _win_registry_get_hostname():
    """Obtiene el hostname original del registro de Windows."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as key:
            val, _ = winreg.QueryValueEx(key, "Hostname")
            return val
    except Exception:
        return None

def _win_registry_get_ttl():
    """Obtiene el TTL por defecto del registro (None si no existe)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as key:
            val, _ = winreg.QueryValueEx(key, "DefaultTTL")
            return val
    except Exception:
        return None

def _win_registry_delete_ttl():
    """Elimina la clave DefaultTTL para restaurar el comportamiento por defecto de Windows."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.DeleteValue(key, "DefaultTTL")
        return True
    except Exception:
        return False

def _win_registry_set_ttl(ttl=64):
    """Cambia el TTL por defecto en el registro de Windows."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, ttl)
        return True
    except Exception as e:
        raise Exception(f"Error en registro: {e}")

def _win_set_ip_forwarding(enable=True):
    """Activa/desactiva IP Forwarding en Windows."""
    try:
        import winreg
        value = 1 if enable else 0
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, value)
        return True
    except Exception:
        return False

def _clean_network_traces():
    """Limpia rastros de red (DNS, ARP, NetBIOS)."""
    try:
        # Flush DNS
        subprocess.run(["ipconfig", "/flushdns"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if _is_admin():
            # Borrar tabla ARP
            subprocess.run(["arp", "-d", "*"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Reiniciar NetBIOS
            subprocess.run(["nbtstat", "-R"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        return False
    except Exception:
        return False

def is_sandbox():
    """Detecta si el programa corre en una máquina virtual o sandbox."""
    try:
        # Procesos conocidos de VMs
        vm_procs = ['vboxservice.exe', 'vboxtray.exe', 'vmtoolsd.exe', 'vmusrvc.exe']
        tasklist_out = subprocess.check_output('tasklist', stderr=subprocess.DEVNULL, creationflags=0x08000000).decode('utf-8', 'ignore').lower()
        if any(p in tasklist_out for p in vm_procs):
            return True
            
        # OUI de adaptadores de red de VMs populares (ej: VirtualBox, VMWare)
        mac_out = subprocess.check_output('getmac', stderr=subprocess.DEVNULL, creationflags=0x08000000).decode('utf-8', 'ignore').lower()
        vm_ouis = ['08-00-27', '00-05-69', '00-0c-29', '00-50-56', '00-1c-42']
        if any(oui in mac_out for oui in vm_ouis):
            return True
            
        return False
    except Exception:
        return False
