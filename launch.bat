@echo off
:: Lanzador silencioso — usa pythonw para no mostrar ventana de consola
:: Si el ocultado por ShowWindow en main.py no fuera suficiente,
:: pythonw.exe garantiza que la consola nunca aparezca.
start "" pythonw "%~dp0main.py" %*
