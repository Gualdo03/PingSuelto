# PhantomIntelligence_v5 - Stealth Edition

Herramienta de red avanzada con arquitectura modular separada en funciones y módulos de soporte.

## 📁 Estructura del Proyecto

```
PhantomIntelligence_v5/
│
├── posible_mejora2.py           # ARCHIVO PRINCIPAL (Lanzador y GUI)
│
├── 📂 funciones/                # LÓGICA DE LAS HERRAMIENTAS (Capa de acción)
│   ├── ghost.py                 # Cambio de Hostname, TTL y limpieza
│   ├── arp.py                   # Spoofing reactivo y evasión de iPhones
│   ├── mac.py                   # Cambio de MAC física y por registro
│   ├── scanner.py               # Escaneo de red y fingerprinting
│   ├── ddos.py                  # Lógica de inundación de paquetes
│   ├── sniffer.py               # Captura y análisis de tráfico
│   ├── moodle_capture.py        # Servidor de captura y spoofing DNS
│   └── veyon.py                 # Gestión de llaves y bloqueo de puertos
│
└── 📂 modulos/                  # SOPORTE E INFRAESTRUCTURA (Capa base)
    ├── config.py                # Variables globales, estados y temas
    ├── ui_helpers.py            # Componentes CTK (_campo, _btn, _out, etc.)
    ├── network_core.py          # Funciones base (IP local, Gateway, OUI MAC)
    ├── system_utils.py          # Elevación de admin, registro de Windows
    └── logger_engine.py         # Gestión de colas de hilos y consola global
```

## 🚀 Características Principales

### Módulos de Funciones
- **GHOST**: Ocultación y evasión avanzada (hostname, TTL, limpieza de rastros)
- **ARP**: Spoofing reactivo con evasión de iPhones y técnicas anti-detección
- **MAC**: Cambio de dirección MAC física y por registro de Windows
- **Scanner**: Descubrimiento de dispositivos en red local con fingerprinting
- **DDoS**: Ataques de denegación de servicio local (SYN, Ping, UDP Flood)
- **Sniffer**: Captura de paquetes en tiempo real con filtros BPF
- **Moodle Capture**: Servidor HTTP falso para captura de credenciales
- **Veyon**: Gestión de claves PEM y control de procesos Veyon

### Módulos de Soporte
- **Config**: Variables globales, configuración y HTML templates
- **UI Helpers**: Componentes reutilizables de CustomTkinter
- **Network Core**: Funciones base de red (IP, MAC, Gateway, escaneo)
- **System Utils**: Utilidades del sistema (admin, registro Windows)
- **Logger Engine**: Motor de logging thread-safe con colas

## 📋 Requisitos

### Dependencias Principales
```bash
pip install customtkinter
pip install scapy
pip install psutil
```

### Dependencias Opcionales
- **Npcap**: Requerido para funcionalidades de red avanzadas
  - Descargar: https://npcap.com/#download
  - Activar "WinPcap API-compatible mode" durante instalación

## 🔧 Uso

### Ejecución
```bash
python posible_mejora2.py
```

### Privilegios de Administrador
- **Recomendado**: Funciones avanzadas requieren privilegios de administrador
- **Auto-elevación**: El programa intenta reiniciarse con privilegios elevados
- **Modo limitado**: Funciona sin admin pero con capacidades reducidas

## 🛡️ Características de Seguridad

### Técnicas de Evasión
- **ARP Spoofing**: Rate limiting dinámico y jitter aleatorio
- **MAC Spoofing**: OUIs de fabricantes reales (Apple, Samsung)
- **TTL Emulation**: Simulación de sistemas Linux (TTL=64)
- **Limpieza de Rastros**: Flush DNS, limpieza ARP y NetBIOS

### Anti-detección
- Encapsulamiento en Capa 2 para ocultar MAC real
- Monitoreo reactivo contra recuperación de conexión
- Restauración invisible de tablas ARP

## 📊 Interfaz Gráfica

### Pestañas Principales
1. **👻 GHOST**: Ocultación y evasión
2. **⚡ ARP**: Spoofing de red
3. **🎭 MAC**: Cambio de identidad
4. **🔍 Escáner**: Descubrimiento de red
5. **💥 DDoS**: Ataques de denegación
6. **📡 Sniffer**: Captura de tráfico
7. **🌐 DNS/CAPTURA**: Spoofing DNS y captura de credenciales
8. **🖥 Veyon**: Gestión de claves y control

### Consola Global
- Logging en tiempo real con colores
- Diferentes niveles: info, ok, warn, err, pkt
- Borrado y filtrado de mensajes

## 🔄 Arquitectura Modular

### Ventajas
- **Mantenimiento**: Código organizado y fácil de mantener
- **Escalabilidad**: Simple añadir nuevos módulos
- **Reutilización**: Componentes independientes y reutilizables
- **Testing**: Módulos aislados para pruebas unitarias

### Flujo de Datos
1. **UI** → **Main App** → **Módulos de Función**
2. **Módulos de Función** → **Módulos de Soporte**
3. **Logger Engine** → **Consola Global**

## 🚨 Advertencias

### Uso Responsable
- Esta herramienta es para fines educativos y de investigación
- El uso no autorizado en redes ajenas es ilegal
- Utilizar solo en redes propias o con permiso explícito

### Riesgos
- Algunas funciones pueden ser detectadas por sistemas de seguridad
- El uso indebido puede resultar en consecuencias legales
- Siempre mantener respaldos del sistema antes de modificar

## 📝 Licencia

Proyecto educativo de código abierto. Uso bajo responsabilidad del usuario.

## 🤝 Contribuciones

Las mejoras y sugerencias son bienvenidas:
- Reporte de bugs
- Nuevas funcionalidades
- Optimización de código
- Mejoras en la documentación

---

**PhantomIntelligence_v5 - Stealth Edition**  
*Herramienta de red avanzada con arquitectura modular*
