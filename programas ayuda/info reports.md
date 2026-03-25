# Resumen de Herramientas de Auditoría y Control

Este documento detalla los repositorios clonados para el laboratorio de pruebas en Windows.

---

## 1. Evilginx2
* **Repositorio:** [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2.git)
* **Propósito:** Framework de **Phishing de Proxy Inverso**.
* **Capacidad Clave:** No solo roba contraseñas, sino que intercepta **tokens de sesión (cookies)**. Esto permite saltarse la autenticación de doble factor (2FA) sin que el usuario lo note.

## 2. SpoofMAC
* **Repositorio:** [feross/SpoofMAC](https://github.com/feross/SpoofMAC.git)
* **Propósito:** Gestión de identidades de red.
* **Capacidad Clave:** Permite cambiar la dirección MAC de cualquier interfaz de red en Windows de forma aleatoria o específica. Útil para evitar el rastreo en redes locales o saltar bloqueos por hardware.

## 3. MHDDoS
* **Repositorio:** [MatrixTM/MHDDoS](https://github.com/MatrixTM/MHDDoS.git)
* **Propósito:** Herramienta de **Pruebas de Estrés de Red**.
* **Capacidad Clave:** Ofrece más de 50 métodos de ataque (Capa 3, 4 y 7). Permite simular ataques masivos para comprobar la estabilidad de servidores y firewalls locales.

## 4. Veyon
* **Repositorio:** [veyon/veyon](https://github.com/veyon/veyon.git)
* **Propósito:** **Control de Aula y Monitorización**.
* **Capacidad Clave:** Visualización remota de pantallas en tiempo real, ejecución de comandos remotos, bloqueo de terminales y encendido de equipos mediante Wake-on-LAN (WOL).