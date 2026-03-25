"""
Módulo MAC - Implementación 1:1 de SpoofMAC para Windows.
"""

import os
import re
import random
import subprocess
import time

def _is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except:
        return False

class MACModule:
    """Módulo para cambio de dirección MAC - Lógica de SpoofMAC."""
    
    # Base registry path for Windows network adapters
    WIN_REGISTRY_PATH = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    
    # VM vendor MAC prefixes for random generation
    VM_OUIS = [
        (0x00, 0x05, 0x69), (0x00, 0x50, 0x56), (0x00, 0x0C, 0x29), # VMware
        (0x00, 0x16, 0x3E), # Xen
        (0x00, 0x03, 0xFF), # Hyper-V
        (0x00, 0x1C, 0x42), # Parallels
        (0x00, 0x0F, 0x4B), # Virtual Iron
        (0x08, 0x00, 0x27), # VirtualBox
    ]
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
    
    def normalize_mac(self, mac):
        """Normaliza la MAC al formato de 12 caracteres (AAAAAABBBBBB).
        Acepta formatos con :, -, . o sin separadores y valida que tenga 12 caracteres."""
        if not mac: return None
        clean = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
        return clean if len(clean) == 12 else None

    def _get_adapters_powershell(self):
        """Usa PowerShell para obtener adaptadores en un formato JSON 100% independiente del idioma."""
        try:
            import json
            cmd = 'powershell -NoProfile -Command "Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress | ConvertTo-Json"'
            # Windows: cp850 / mbcs encoding safe handling is done by text=True and python's default locale, 
            # but forcing utf-8 or decoding safely is better.
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            try:
                decoded = result.decode('utf-8')
            except Exception:
                decoded = result.decode('mbcs', errors='ignore')
                
            if not decoded.strip(): return []
            
            data = json.loads(decoded)
            if isinstance(data, dict): # if only 1 adapter, it returns dict instead of list
                data = [data]
            return data
        except Exception as e:
            self.logger.log(f"[MAC] Error get-netadapter: {e}", "err")
            return []

    def find_interfaces(self, targets=None, write_callback=None):
        """Detecta interfaces mapeando la salida JSON de PowerShell (Lógica robusta infalible)."""
        if os.name != "nt":
            return self._find_interfaces_linux(targets, write_callback)

        targets = [t.lower() for t in targets] if targets else []
        adapters = self._get_adapters_powershell()
        
        interfaces = []
        
        for adapter in adapters:
            name = adapter.get("Name", "")
            desc = adapter.get("InterfaceDescription", "")
            mac = adapter.get("MacAddress", "")
            
            if not name or not mac: continue
            
            mac_clean = mac.replace('-', ':')
            
            # Nombre limpio suele ser el mismo 'Name' en Get-NetAdapter ("Ethernet 3", "Wi-Fi"), 
            # netsh traga esto directamente.
            if not targets or any(t in name.lower() or t in desc.lower() for t in targets):
                interfaces.append({
                    'name': name,
                    'description': desc,
                    'address': mac_clean
                })
                if write_callback:
                    write_callback(f"  • {name} [{mac_clean}]\n    (Desc: {desc})\n")
        
        return interfaces

    def apply_mac_change(self, interface_name, new_mac, write_callback):
        """Flujo completo de cambio de MAC siguiendo la lógica estricta de SpoofMAC."""
        if not _is_admin():
            write_callback("✗ ERROR: Se requieren privilegios de ADMINISTRADOR (Acceso Denegado).\n")
            write_callback("👉 Por favor, eleva los privilegios de este script para continuar.\n")
            self.logger.log("[MAC] Error: Sin privilegios de admin", "err")
            return False

        # 1. Validar y normalizar MAC (12 caracteres)
        mac_registry = self.normalize_mac(new_mac)
        if not mac_registry:
            write_callback(f"✗ Error de Normalización: '{new_mac}' no es una MAC válida.\n")
            return False

        write_callback(f"» Paso 1: Detección - Localizando adaptador '{interface_name}' en ipconfig...\n")
        
        # 2. Mapeo Nombre -> Hardware Description
        ifaces = self.find_interfaces(targets=[interface_name])
        if not ifaces:
            write_callback(f"✗ Detección fallida: No se encontró el adaptador '{interface_name}'.\n")
            write_callback(f"  Asegúrate de escribir el nombre exacto listado arriba.\n")
            return False
        
        description = ifaces[0]['description']
        clean_iface_name = ifaces[0]['name']  # El nombre limpio para netsh
        write_callback(f"  + Hardware Description mapeado: {description}\n")

        # 3. Modificación del Registro
        write_callback("» Paso 2: Escritura en Registro (Iterando subclaves)...\n")
        try:
            import winreg
            reg_hdl = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(reg_hdl, self.WIN_REGISTRY_PATH)
            info = winreg.QueryInfoKey(key)

            found_path = None
            for x in range(info[0]):
                subkey = winreg.EnumKey(key, x)
                if subkey == 'Properties': continue
                
                path = f"{self.WIN_REGISTRY_PATH}\\{subkey}"
                try:
                    with winreg.OpenKey(reg_hdl, path) as sub:
                        driver_desc, _ = winreg.QueryValueEx(sub, "DriverDesc")
                        if driver_desc == description:
                            found_path = path
                            break
                except:
                    continue

            if not found_path:
                write_callback("✗ Error: No se halló la subclave coincidente por DriverDesc en el Registro.\n")
                winreg.CloseKey(key)
                return False

            write_callback(f"  + Subclave encontrada. Insertando NetworkAddress={mac_registry}...\n")
            
            # REG_SZ según lo pedido
            with winreg.OpenKey(reg_hdl, found_path, 0, winreg.KEY_SET_VALUE) as sub:
                winreg.SetValueEx(sub, "NetworkAddress", 0, winreg.REG_SZ, mac_registry)
            
            winreg.CloseKey(key)
            winreg.CloseKey(reg_hdl)
        except Exception as e:
            write_callback(f"✗ Acceso Denegado u Error en Registro: {e}\n")
            return False

        # 4. Reinicio de Adaptador a través de netsh
        write_callback(f"» Paso 3: Reinicio de Adaptador ('{clean_iface_name}')...\n")
        try:
            write_callback(f"  + Ejecutando: netsh interface set interface \"{clean_iface_name}\" disable...\n")
            subprocess.run(f'netsh interface set interface "{clean_iface_name}" disable', shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            
            write_callback(f"  + Ejecutando: netsh interface set interface \"{clean_iface_name}\" enable...\n")
            subprocess.run(f'netsh interface set interface "{clean_iface_name}" enable', shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            write_callback("  + Reinicio automático aplicado correctamente.\n")
        except subprocess.CalledProcessError as e:
            write_callback(f"⚠ Aviso netsh: No se pudo reiniciar automáticamente la interfaz (Puede estar en uso u oculto).\n")
            write_callback("  Por favor, deshabilita y habilita el adaptador manualmente desde las Propiedades de Red.\n")

        # 5. Conclusión Especial
        write_callback("» Paso 4: ¡MAC Spoofeada exitosamente!\n")
        write_callback("📢 NOTA IMPORTANTE (Windows 10/11):\n")
        write_callback("   A veces ipconfig sigue mostrando la MAC original aunque el cambio\n")
        write_callback("   se haya realizado correctamente en el Registro y en las\n")
        write_callback("   Propiedades del Adaptador (Panel de Control).\n")
        
        self.logger.log(f"[MAC] Éxito: {mac_registry} en {clean_iface_name}", "ok")
        return True

    def generate_random_mac(self, vendor=None):
        """Genera una MAC aleatoria, opcionalmente de un OUI predefinido."""
        ouis = {
            "apple": (0x00, 0x17, 0xF2),
            "samsung": (0x00, 0x07, 0xAB),
            "genérico": (0x00, 0x0C, 0x29) # Default genérico a VMWare para mayor probabilidad de aceptación
        }
        
        prefix = ouis.get(vendor) if vendor in ouis else random.choice(self.VM_OUIS)
        
        mac = [prefix[0], prefix[1], prefix[2],
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        
        # Activar el bit Locally Administered (necesario en Windows)
        mac[0] |= 2
        
        return ':'.join(f'{o:02X}' for o in mac)

    def _find_interfaces_linux(self, targets, write_callback):
        """Mock behavior for compatibility outside of Windows."""
        return []

if __name__ == "__main__":
    class MockLogger:
        def log(self, m, s): print(f"[{s.upper()}] {m}")
    mac = MACModule(MockLogger())
    mac.find_interfaces(write_callback=print)
