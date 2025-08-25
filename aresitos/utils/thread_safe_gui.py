
# -*- coding: utf-8 -*-
# thread_safe_gui.py - Utilidad ARESITOS para manejo seguro de hilos en GUIs
# Previene crashes y deslogueos forzados en entornos como Kali Linux
# Principios: No usar sys.exit, os._exit ni forzar cierres desde la vista
# Uso: Crear un ThreadSafeFlag y usar .set() para cancelar, .is_set() para consultar

import threading

class ThreadSafeFlag:
	"""
	Wrapper seguro para cancelar hilos de monitoreo/red en GUIs.
	Utiliza threading.Event para comunicación thread-safe.
	"""
	def __init__(self):
		self._event = threading.Event()

	def set(self):
		self._event.set()

	def clear(self):
		self._event.clear()

	def is_set(self):
		return self._event.is_set()

	def wait(self, timeout=None):
		return self._event.wait(timeout)

# Ejemplo de uso en la vista:
#   self.flag_monitoreo = ThreadSafeFlag()
#   while not self.flag_monitoreo.is_set(): ...
