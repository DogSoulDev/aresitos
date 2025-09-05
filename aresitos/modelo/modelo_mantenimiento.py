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
		from aresitos.utils.sudo_manager import get_sudo_manager
		import getpass
		fecha = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
		backup_root = os.path.join(os.getcwd(), "data", "backups")
		backup_dir = os.path.join(backup_root, f"backup_aresitos_{fecha}")
		sudo_manager = get_sudo_manager()
		try:
			if sudo_manager.is_sudo_active():
				# Crear carpeta backup_root y backup_dir con sudo
				resultado = sudo_manager.execute_sudo_command(f"mkdir -p '{backup_root}' '{backup_dir}'")
				if resultado.returncode != 0:
					vista.mostrar_log(f"[ERROR] No se pudo crear la carpeta de backups con permisos elevados: {resultado.stderr}")
					return {'error': resultado.stderr}
				# Copiar carpetas clave con sudo (usando tar para robustez)
				carpetas = ["configuración", "data", "logs"]
				for carpeta in carpetas:
					if os.path.exists(carpeta):
						comando = f"tar -cf '{backup_dir}/{carpeta}.tar' '{carpeta}'"
						resultado = sudo_manager.execute_sudo_command(comando)
						if resultado.returncode != 0:
							vista.mostrar_log(f"[ERROR] No se pudo copiar {carpeta} con permisos elevados: {resultado.stderr}")
							return {'error': resultado.stderr}
				vista.mostrar_log(f"[OK] Copia de seguridad creada correctamente en: {backup_dir} (con permisos elevados)")
				return {'ok': True, 'ruta': backup_dir}
			else:
				try:
					os.makedirs(backup_root, exist_ok=True)
					os.makedirs(backup_dir, exist_ok=True)
				except Exception as e:
					vista.mostrar_log(f"[ERROR] No se pudo crear la carpeta de backups: {e}")
					return {'error': str(e)}
				carpetas = ["configuración", "data", "logs"]
				for carpeta in carpetas:
					if os.path.exists(carpeta):
						shutil.copytree(carpeta, os.path.join(backup_dir, carpeta))
				vista.mostrar_log(f"[OK] Copia de seguridad creada correctamente en: {backup_dir} (sin permisos elevados)")
				return {'ok': True, 'ruta': backup_dir}
		except PermissionError as e:
			vista.mostrar_log(f"[ERROR] Permiso denegado al crear la copia de seguridad: {e}")
			return {'error': str(e)}
		except Exception as e:
			vista.mostrar_log(f"[ERROR] No se pudo crear la copia de seguridad: {e}")
			return {'error': str(e)}

	def restaurar_backup(self, vista):
		import tkinter as tk
		from tkinter import filedialog
		from aresitos.utils.sudo_manager import get_sudo_manager
		backup_root = os.path.join(os.getcwd(), "data", "backups")
		backups = [d for d in os.listdir(backup_root) if d.startswith('backup_aresitos_') and os.path.isdir(os.path.join(backup_root, d))]
		if not backups:
			vista.mostrar_log("[ERROR] No se encontraron copias de seguridad en data/backups.")
			return {'error': 'No hay backups'}
		# Diálogo para seleccionar backup
		root = tk.Tk()
		root.withdraw()
		backup_dir = filedialog.askdirectory(title="Selecciona la copia de seguridad a restaurar", initialdir=backup_root)
		root.destroy()
		if not backup_dir or not os.path.basename(backup_dir).startswith('backup_aresitos_'):
			vista.mostrar_log("[ERROR] Selección inválida. Debes elegir una carpeta de backup válida.")
			return {'error': 'Selección inválida'}
		sudo_manager = get_sudo_manager()
		try:
			carpetas = ["configuración", "data", "logs"]
			if sudo_manager.is_sudo_active():
				# Restaurar usando tar y permisos elevados
				for carpeta in carpetas:
					tar_path = os.path.join(backup_dir, f"{carpeta}.tar")
					destino = os.path.join(os.getcwd(), carpeta)
					if os.path.exists(tar_path):
						# Eliminar destino si existe
						if os.path.exists(destino):
							resultado = sudo_manager.execute_sudo_command(f"rm -rf '{destino}'")
							if resultado.returncode != 0:
								vista.mostrar_log(f"[ERROR] No se pudo eliminar {destino}: {resultado.stderr}")
								return {'error': resultado.stderr}
						# Crear carpeta destino si no existe
						resultado = sudo_manager.execute_sudo_command(f"mkdir -p '{destino}'")
						if resultado.returncode != 0:
							vista.mostrar_log(f"[ERROR] No se pudo crear la carpeta destino {destino}: {resultado.stderr}")
							return {'error': resultado.stderr}
						# Extraer backup con permisos elevados
						resultado = sudo_manager.execute_sudo_command(f"tar -xf '{tar_path}' -C '{os.getcwd()}'")
						if resultado.returncode != 0:
							vista.mostrar_log(f"[ERROR] No se pudo restaurar {carpeta}: {resultado.stderr}")
							return {'error': resultado.stderr}
				vista.mostrar_log(f"[OK] Restauración completada desde: {backup_dir} (con permisos elevados)")
				return {'ok': True}
			else:
				for carpeta in carpetas:
					origen = os.path.join(backup_dir, carpeta)
					destino = os.path.join(os.getcwd(), carpeta)
					if os.path.exists(origen):
						if os.path.exists(destino):
							if os.path.isdir(destino):
								shutil.rmtree(destino)
							else:
								os.remove(destino)
						os.makedirs(destino, exist_ok=True)
						shutil.copytree(origen, destino)
				vista.mostrar_log(f"[OK] Restauración completada desde: {backup_dir} (sin permisos elevados)")
				return {'ok': True}
		except PermissionError as e:
			vista.mostrar_log(f"[ERROR] Permiso denegado al restaurar la copia de seguridad: {e}")
			return {'error': str(e)}
		except Exception as e:
			vista.mostrar_log(f"[ERROR] No se pudo restaurar la copia de seguridad: {e}")
			return {'error': str(e)}

	def obtener_logs_actualizacion(self):
		# Leer logs de actualización si existen
		log_path = os.path.join("logs", "actualizacion.log")
		if os.path.exists(log_path):
			with open(log_path, "r", encoding="utf-8") as f:
				return f.read()
		return "No hay logs de actualización disponibles."
