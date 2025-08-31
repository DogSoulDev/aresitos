# -*- coding: utf-8 -*-
"""
ARESITOS - Logger Centralizado
Sistema de logging/mensajes para que todos los módulos, controladores y vistas puedan enviar mensajes
al terminal integrado, a la pantalla y a los reportes.
"""
import threading
import datetime

class LoggerAresitos:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.subscribers = []  # Callbacks para terminales integrados
        self.log_buffer = []   # Buffer para reportes

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = LoggerAresitos()
            return cls._instance

    def subscribe(self, callback):
        """Registrar un callback para recibir mensajes (ej: terminal integrado de una vista)."""
        if callback not in self.subscribers:
            self.subscribers.append(callback)

    def unsubscribe(self, callback):
        if callback in self.subscribers:
            self.subscribers.remove(callback)

    def log(self, mensaje, nivel="INFO", modulo="ARESITOS"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] [{modulo}] [{nivel}] {mensaje}"
        self.log_buffer.append(msg)
        for cb in self.subscribers:
            try:
                cb(msg)
            except Exception:
                pass

    def get_log(self):
        """Obtener todo el log para el módulo de reportes."""
        return list(self.log_buffer)

# Uso:
# logger = LoggerAresitos.get_instance()
# logger.log("Mensaje de prueba", nivel="INFO", modulo="ESCANEO")
# logger.subscribe(callback_func)
