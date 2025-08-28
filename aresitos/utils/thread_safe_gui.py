
# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
"""

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
