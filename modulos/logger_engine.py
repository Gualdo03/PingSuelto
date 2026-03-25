"""
Motor de logging y gestión de colas thread-safe
"""

import threading
import queue
import time
import os

__all__ = ['LoggerEngine']

class LoggerEngine:
    """Motor centralizado de logging con colas thread-safe."""
    
    def __init__(self):
        self._log_q: queue.Queue = queue.Queue()
        self._write_q: dict = {}   # widget_id -> (widget, [mensajes])
        self._write_lock = threading.Lock()
        self._sniff_n = 0
        self._sniff_n_ui = 0
    
    def log(self, msg: str, tipo: str = "info"):
        """Añade mensaje a la cola de log global."""
        ts = time.strftime("%H:%M:%S")
        self._log_q.put((ts, msg, tipo))
    
    def write(self, widget, text):
        """Escribe en un widget de texto usando batching (cola)."""
        wid = id(widget)
        with self._write_lock:
            if wid not in self._write_q:
                self._write_q[wid] = (widget, [])
            self._write_q[wid][1].append(text)
    
    def flush_queues(self, root, consola, sniff_count_widget=None):
        """Vacía colas de mensajes en la UI cada ciclo."""
        # Vaciar cola de log global
        batch = []
        try:
            while not self._log_q.empty():
                batch.append(self._log_q.get_nowait())
                if len(batch) >= 40:   # máximo 40 líneas por ciclo
                    break
        except queue.Empty:
            pass
        
        if batch and consola:
            for ts, msg, tipo in batch:
                consola.insert("end", f"[{ts}] ", "info")
                consola.insert("end", msg + "\n", tipo)
                
            try:
                # Si pasa de 200 líneas, borrar las 50 más antiguas para liberar memoria de Tkinter sin colapsarlo
                # Esto previene los Crash de la UI reportados en mejorascli.txt
                end_idx = int(consola.index("end-1c").split(".")[0])
                if end_idx > 200:
                    consola.delete("1.0", f"{end_idx - 150}.0")
            except Exception:
                pass
            
            consola.see("end")

        # Vaciar colas de widgets individuales (_write)
        with self._write_lock:
            snapshot = list(self._write_q.items())
            self._write_q.clear()
        
        for wid, (widget, msgs) in snapshot:
            try:
                texto = "".join(msgs)
                widget.insert("end", texto)
                
                try:
                    # Aplicar límite estricto por cada log de pestanha para evitar congelamientos (Issue #2)
                    end_idx = int(widget.index("end-1c").split(".")[0])
                    if end_idx > 200:
                        widget.delete("1.0", f"{end_idx - 150}.0")
                except Exception:
                    pass
                
                widget.see("end")
            except Exception:
                pass

        # Actualizar contador de paquetes si cambió
        if self._sniff_n != self._sniff_n_ui and sniff_count_widget:
            self._sniff_n_ui = self._sniff_n
            try:
                sniff_count_widget.configure(text=f"{self._sniff_n_ui} pkts")
            except Exception:
                pass
    
    def increment_sniff_count(self):
        """Incrementa el contador de paquetes capturados."""
        self._sniff_n += 1
    
    def reset_sniff_count(self):
        """Resetea el contador de paquetes."""
        self._sniff_n = 0
        self._sniff_n_ui = 0
