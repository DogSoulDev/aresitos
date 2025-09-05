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
import os
import shutil
import datetime

class ModeloMantenimiento:
	def crear_backup(self, vista):
		fecha = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
		backup_dir = os.path.join(os.getcwd(), f"backup_aresitos_{fecha}")
		try:
			os.makedirs(backup_dir, exist_ok=True)
			# Copiar carpetas clave (configuración, data, logs)
			for carpeta in ["configuración", "data", "logs"]:
				if os.path.exists(carpeta):
					shutil.copytree(carpeta, os.path.join(backup_dir, carpeta))
			vista.mostrar_log(f"[OK] Copia de seguridad creada correctamente en: {backup_dir}")
		except Exception as e:
			vista.mostrar_log(f"[ERROR] No se pudo crear la copia de seguridad: {e}")

	def restaurar_backup(self, vista):
		import tkinter as tk
		from tkinter import filedialog
		# Buscar carpetas de backup en el directorio actual
		backups = [d for d in os.listdir(os.getcwd()) if d.startswith('backup_aresitos_') and os.path.isdir(os.path.join(os.getcwd(), d))]
		if not backups:
			vista.mostrar_log("[ERROR] No se encontraron copias de seguridad en el directorio actual.")
			return
		# Diálogo para seleccionar backup
		root = tk.Tk()
		root.withdraw()
		backup_dir = filedialog.askdirectory(title="Selecciona la copia de seguridad a restaurar", initialdir=os.getcwd())
		root.destroy()
		if not backup_dir or not os.path.basename(backup_dir).startswith('backup_aresitos_'):
			vista.mostrar_log("[ERROR] Selección inválida. Debes elegir una carpeta de backup válida.")
			return
		try:
			# Restaurar carpetas clave
			for carpeta in ["configuración", "data", "logs"]:
				origen = os.path.join(backup_dir, carpeta)
				destino = os.path.join(os.getcwd(), carpeta)
				if os.path.exists(origen):
					# Eliminar destino si existe y restaurar
					if os.path.exists(destino):
						if os.path.isdir(destino):
							shutil.rmtree(destino)
						else:
							os.remove(destino)
					shutil.copytree(origen, destino)
			vista.mostrar_log(f"[OK] Restauración completada desde: {backup_dir}")
		except Exception as e:
			vista.mostrar_log(f"[ERROR] No se pudo restaurar la copia de seguridad: {e}")

	def obtener_logs_actualizacion(self):
		# Leer logs de actualización si existen
		log_path = os.path.join("logs", "actualizacion.log")
		if os.path.exists(log_path):
			with open(log_path, "r", encoding="utf-8") as f:
				return f.read()
		return "No hay logs de actualización disponibles."
