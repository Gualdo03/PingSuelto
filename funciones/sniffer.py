"""
Módulo SNIFFER - Captura y análisis de tráfico
"""

import threading
from modulos.config import _estado

class SnifferModule:
    """Módulo para captura de paquetes de red."""
    
    def __init__(self, logger_engine):
        self.logger = logger_engine
    
    def start_capture(self, filtro, write_callback, stop_callback):
        """Inicia la captura de paquetes."""
        if not hasattr(self, '_scapy_available'):
            try:
                import scapy.all
                self._scapy_available = True
            except ImportError:
                self._scapy_available = False
                write_callback("✗ Scapy no disponible.\n")
                return False
        
        if not self._scapy_available:
            return False
        
        _estado["sniff"].set()
        threading.Thread(target=self._sniff_loop, args=(filtro, write_callback, stop_callback), daemon=True).start()
        return True
    
    def stop_capture(self, write_callback, packet_count):
        """Detiene la captura de paquetes."""
        _estado["sniff"].clear()
        write_callback(f"\n● Captura detenida. Total: {packet_count} paquetes.\n")
        self.logger.log(f"[SNIFF] Detenido. {packet_count} pkts.", "warn")
    
    def _sniff_loop(self, filtro, write_callback, stop_callback):
        """Loop principal de captura."""
        try:
            from scapy.all import sniff
        except ImportError:
            return
        
        packet_count = 0
        
        def proc(pkt):
            nonlocal packet_count
            if not _estado["sniff"].is_set(): 
                return
            packet_count += 1
            self.logger.increment_sniff_count()
            resumen = pkt.summary()
            write_callback(f"  [{packet_count:4d}] {resumen}\n")
            self.logger.log(f"[PKT] {resumen}", "pkt")
        
        try:
            sniff(filter=filtro or None, prn=proc,
                  stop_filter=lambda _: not _estado["sniff"].is_set(), store=False)
        except Exception as e:
            write_callback(f"✗ Error: {e}\n")
            self.logger.log(f"[SNIFF] Error: {e}", "err")
        finally:
            _estado["sniff"].clear()
            stop_callback(packet_count)
