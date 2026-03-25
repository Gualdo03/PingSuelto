"""
Helpers de UI para CustomTkinter - 
Componentes UI reutilizables para CustomTkinter
"""

import customtkinter as ctk

__all__ = ['_pad', '_sep', '_btn_row', '_campo', '_out', '_btn']
from tkinter import scrolledtext

def _pad(p, h=8):
    """Espaciador vertical."""
    ctk.CTkFrame(p, height=h, fg_color="transparent").pack()

def _sep(p):
    """Separador horizontal."""
    ctk.CTkFrame(p, height=1, fg_color="#252525").pack(fill="x", pady=8)

def _btn_row(p, pady=6):
    """Fila para botones."""
    f = ctk.CTkFrame(p, fg_color="transparent")
    f.pack(fill="x", pady=pady)
    return f

def _campo(parent, label, placeholder="", valor="", width=220):
    """Campo de entrada con etiqueta."""
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
    """Área de texto con scroll."""
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

def _btn(parent, text, cmd, color="#1565c0", **kw):
    """Botón estándar con efecto hover."""
    def _dark(h):
        try:
            r,g,b = int(h[1:3],16), int(h[3:5],16), int(h[5:7],16)
            return f"#{max(r-35,0):02x}{max(g-35,0):02x}{max(b-35,0):02x}"
        except Exception: 
            return h
    
    height = kw.pop("height", 34)
    corner_radius = kw.pop("corner_radius", 7)
    
    return ctk.CTkButton(parent, text=text, fg_color=color,
                         hover_color=_dark(color),
                         font=ctk.CTkFont(size=12, weight="bold"),
                         height=height, corner_radius=corner_radius, command=cmd, **kw)
