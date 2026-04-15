# ⚡ PhantomIntelligence v5 — Stealth Edition

> Herramienta de auditoría y análisis de redes LAN con interfaz gráfica avanzada. Diseñada para entornos controlados de pruebas de seguridad y educación en ciberseguridad.

---

## 📋 Índice

1. [Descripción](#-descripción)
2. [Características principales](#-características-principales)
3. [Tecnologías utilizadas](#-tecnologías-utilizadas)
4. [Estructura del proyecto](#-estructura-del-proyecto)
5. [Requisitos del sistema](#-requisitos-del-sistema)
6. [Instalación](#-instalación)
7. [Uso](#-uso)
8. [Módulos funcionales](#-módulos-funcionales)
9. [Configuración](#-configuración)
10. [Roadmap](#-roadmap)
11. [Aviso legal](#-aviso-legal)
12. [Licencia](#-licencia)

---

## 📌 Descripción

**PhantomIntelligence v5** es una aplicación de escritorio para Windows con interfaz gráfica desarrollada en **CustomTkinter**. Integra en una sola herramienta modular diversas técnicas de auditoría de redes locales (LAN): intercepción de tráfico ARP, falsificación de identidad de red (MAC/hostname), escaneo de dispositivos, captura de paquetes, redirección DNS y control de herramientas de supervisión remota.

Pensada para **laboratorios de ciberseguridad**, **formación técnica** y **pruebas de penetración en entornos autorizados**.

---

## ✨ Características principales

| Módulo | Descripción |
|---|---|
| 👻 **GHOST** | Spoofing de hostname, emulación de TTL Linux (64), limpieza de rastros de red (DNS, ARP, NetBIOS) y restauración de valores originales |
| ⚡ **ARP Spoofing** | Intercepción de tráfico con rate limiting dinámico, jitter aleatorio y falsificación del fabricante MAC (Apple, Samsung, Genérico) |
| 🎭 **MAC Spoofing** | Cambio de dirección MAC por interfaz, generación aleatoria por OUI de fabricante |
| 🔍 **Escáner LAN** | Descubrimiento de dispositivos en la red local mediante ARP scanning con identificación de fabricante |
| 💥 **DDoS Local** | Ataques de prueba: SYN Flood, Ping Flood, UDP Flood, HTTP GET/POST Flood con multithreading y rotación de User-Agent |
| 📡 **Sniffer** | Captura de paquetes en tiempo real con filtros BPF (HTTP, DNS, HTTPS, ARP) y contador de paquetes |
| 🌐 **DNS/CAPTURA** | DNS Spoofing con reglas personalizables + Proxy Reverso Dinámico (estilo Evilginx) con soporte de phishlets JSON |
| 🖥 **Veyon** | Congelación/reanudación de procesos Veyon, bloqueo persistente del puerto 11100, monitor de alerta temprana y Wake-on-LAN |

**Otras funciones transversales:**
- Auto-elevación de privilegios al iniciar (UAC, Windows)
- Detección de entorno sandbox/máquina virtual (VirtualBox, VMware)
- Motor de logging centralizado con colas thread-safe y límite de memoria
- Interfaz en tema oscuro con pestañas por módulo

---

## 🛠 Tecnologías utilizadas

| Tecnología | Uso |
|---|---|
| **Python 3.10+** | Lenguaje principal |
| **CustomTkinter** | Interfaz gráfica moderna (tema oscuro) |
| **Scapy** | ARP Spoofing, escaneo LAN, sniffer, DNS Spoofing |
| **Npcap** | Driver de captura de paquetes (Windows) |
| **psutil** | Gestión de procesos (congelar/matar Veyon) |
| **requests** | Proxy reverso HTTP (forwarding al servidor original) |
| **winreg** | Modificación del registro de Windows (hostname, TTL) |
| **threading / queue** | Concurrencia thread-safe en todas las operaciones de red |
| **socketserver / http.server** | Servidor HTTP embebido para captura de credenciales |

---

## 📁 Estructura del proyecto

```
PhantomIntelligence_v5/
│
├── main.py                     # Punto de entrada. Clase PinguExit (UI principal)
│
├── modulos/                    # Módulos de soporte reutilizables
│   ├── config.py               # Variables globales, estado de hilos, colores de log
│   ├── logger_engine.py        # Motor de logging centralizado (thread-safe)
│   ├── network_core.py         # Funciones base de red: IP, gateway, MAC, ARP scan
│   ├── system_utils.py         # Elevación de privilegios, registro de Windows, sandbox check
│   └── ui_helpers.py           # Componentes UI reutilizables (botones, campos, áreas de texto)
│
├── funciones/                  # Módulos de funcionalidad por pestaña
│   ├── ghost.py                # Ocultación: hostname spoof, TTL, limpieza de rastros
│   ├── arp.py                  # ARP Spoofing con evasión (rate limiting, jitter, OUI)
│   ├── mac.py                  # MAC Spoofing y listado de interfaces
│   ├── scanner.py              # Escáner LAN (ARP scan por rango)
│   ├── ddos.py                 # Ataques de denegación de servicio locales
│   ├── sniffer.py              # Captura de paquetes con filtros BPF
│   ├── universal_proxy.py      # Proxy reverso dinámico con phishlets JSON
│   ├── moodle_capture.py       # Servidor HTTP de captura de credenciales
│   └── veyon.py                # Control de Veyon, Wake-on-LAN, firewall persistente
│
├── data/
│   ├── useragents.txt          # Lista de User-Agents para rotación en DDoS HTTP
│   └── phishlets/              # Configuraciones JSON de phishlets
│       ├── moodle.json         # Phishlet para plataformas Moodle
│       └── linkedin.json       # Phishlet para LinkedIn
│
├── requirements.txt            # Dependencias Python
├── .gitignore                  # Exclusiones de Git
└── README.md                   # Este archivo
```

---

## 💻 Requisitos del sistema

- **Sistema operativo:** Windows 10 / 11 (64-bit)
- **Python:** 3.10 o superior
- **Privilegios:** Administrador (requerido para ARP, DNS, Sniffer, Firewall, registro de Windows)
- **Npcap:** Obligatorio para Scapy en Windows → [Descargar Npcap](https://npcap.com/#download)
  > ⚠️ Al instalar Npcap, activa la opción **"WinPcap API-compatible mode"**

---

## 🚀 Instalación

### 1. Clona el repositorio

```bash
git clone https://github.com/tu-usuario/PhantomIntelligence_v5.git
cd PhantomIntelligence_v5
```

### 2. Crea y activa un entorno virtual (recomendado)

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instala las dependencias

```bash
pip install -r requirements.txt
```

### 4. Instala Npcap

Descarga e instala Npcap desde [https://npcap.com/#download](https://npcap.com/#download).
Activa **"WinPcap API-compatible mode"** durante la instalación.

---

## ▶️ Uso

Ejecuta el programa como **Administrador**:

```bash
python main.py
```

> La propia aplicación intentará auto-elevarse al iniciar mediante UAC (ShellExecuteW con `runas`). Si no lo hace automáticamente, ejecútala con clic derecho → *Ejecutar como administrador*.

La interfaz se abrirá con 8 pestañas. Selecciona el módulo que necesitas y sigue los controles en pantalla.

---

## 🧩 Módulos funcionales

### 👻 GHOST — Ocultación
- **Spoofear Hostname:** Cambia el nombre del equipo en el registro de Windows.
- **Emular TTL Linux:** Fija el DefaultTTL a 64 (los escáneres externos lo detectan como Linux).
- **Limpiar Rastros:** Flush DNS, borra tabla ARP, reinicia NetBIOS.
- **Restaurar Originales:** Revierte hostname y TTL a los valores previos a la ejecución.

### ⚡ ARP Spoofing
1. Introduce la **IP de la víctima** y el **Gateway** (se autodetecta).
2. Ajusta el intervalo, activa el rate limiting dinámico y el jitter aleatorio.
3. Elige opcionalmente spoofear el fabricante MAC (Apple, Samsung, Genérico).
4. Pulsa **▶ Iniciar ARP Spoof** → Pulsa **■ Detener + Restaurar** para limpiar.

### 🎭 MAC Spoofing
1. Introduce el nombre exacto de la interfaz (usa *📋 Listar Interfaces* si no lo sabes).
2. Escribe la MAC manualmente o genera una aleatoria por fabricante.
3. Pulsa **Aplicar MAC**.

### 🔍 Escáner LAN
1. El rango de red se autodetecta (ej. `192.168.1.0/24`).
2. Ajusta el timeout y pulsa **🔍 Escanear red**.
3. El resultado muestra IP, MAC y fabricante de cada dispositivo.

### 💥 DDoS Local
> ⚠️ Solo para entornos de laboratorio autorizados. Los modos SYN/UDP/Ping requieren Npcap.

1. Introduce la IP objetivo y el puerto.
2. Configura los hilos (1-1000) y el modo de ataque.
3. Activa la **Rotación U-A** para los modos HTTP.
4. Pulsa **▶ Lanzar DDoS** → **■ Detener** para parar.

### 📡 Sniffer
1. Escribe un filtro BPF o usa los presets (HTTP, DNS, HTTPS, ARP, Todo).
2. Pulsa **▶ Iniciar captura** → el contador de paquetes se actualiza en tiempo real.
3. Pulsa **■ Detener** para finalizar la captura.

### 🌐 DNS / CAPTURA
**DNS Spoofing:**
1. Introduce el dominio a interceptar y la IP falsa (tu IP local).
2. Pulsa **+ Añadir regla** → **▶ Activar DNS Spoof**.

**Proxy Reverso Dinámico:**
1. Introduce la URL real a clonar (ej. `https://moodle.ejemplo.com`).
2. Selecciona el phishlet JSON correspondiente (Moodle, LinkedIn…).
3. Pulsa **🎓 Activar Proxy Dinámico** → el proxy intercepta credenciales y cookies.
4. Los datos capturados se guardan en `logs/tokens.txt` y `logs/cookies.txt`.

### 🖥 Veyon
- **Wake-on-LAN:** Envía un Magic Packet a la MAC indicada.
- **Gestión de claves .pem:** Busca, carga y muestra claves Veyon del sistema.
- **Congelar / Descongelar:** Suspende o reanuda procesos Veyon con psutil.
- **Forzar Cierre:** Kill forzado (psutil + taskkill /F).
- **Bloquear puerto 11100:** Añade una regla de firewall con `netsh advfirewall`.
- **Monitor (Alerta temprana):** Captura tráfico TCP en el puerto 11100 y lanza una alerta visual.
- **Guardián Firewall (Persistente):** Reaplica la regla de firewall cada 5 segundos si es eliminada.

---

## ⚙️ Configuración

### Phishlets personalizados

Los phishlets son archivos JSON ubicados en `data/phishlets/`. Puedes añadir el tuyo propio con este formato:

```json
{
    "name": "NombreDelServicio",
    "intercept_domains": ["palabra-clave-del-dominio"],
    "username_fields": ["nombre_campo_usuario"],
    "password_fields": ["nombre_campo_contraseña"]
}
```

### Proxy HTTPS (opcional)

Para activar el proxy en modo HTTPS necesitas un certificado SSL:

```
data/cert.pem    ← Certificado
data/key.pem     ← Clave privada
```

Puedes generar un certificado autofirmado con OpenSSL:

```bash
openssl req -x509 -newkey rsa:4096 -keyout data/key.pem -out data/cert.pem -days 365 -nodes
```

### User-Agents personalizados

Edita `data/useragents.txt` para añadir o cambiar los User-Agents usados en los modos DDoS HTTP. Un User-Agent por línea.

---

## 🗺 Roadmap

- [ ] Exportación de capturas del sniffer a `.pcap`
- [ ] Soporte de phishlets con captura de tokens OAuth / Bearer
- [ ] Modo HTTPS nativo en el proxy sin cert externo (certificado autofirmado auto-generado)
- [ ] Detección automática de interfaces de red para ARP y sniffer
- [ ] Dashboard de estadísticas en tiempo real (paquetes/s, bytes interceptados)
- [ ] Empaquetado como ejecutable `.exe` con PyInstaller
- [ ] Soporte experimental para Linux/macOS

---

## ⚖️ Aviso legal

> **Esta herramienta está diseñada exclusivamente para uso en entornos de laboratorio, redes propias o redes en las que se disponga de autorización expresa por escrito.**
>
> El uso de esta herramienta contra sistemas o redes sin autorización es **ilegal** y puede acarrear responsabilidades penales y civiles según la legislación vigente.
>
> El autor no se hace responsable del uso indebido de este software.

---

## 👤 Autor / Créditos

Desarrollado como proyecto educativo de ciberseguridad.

- **Repositorio:** [github.com/tu-usuario/PhantomIntelligence_v5](https://github.com/tu-usuario/PhantomIntelligence_v5)
- **Contacto:** tu-email@ejemplo.com

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia **MIT**.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
