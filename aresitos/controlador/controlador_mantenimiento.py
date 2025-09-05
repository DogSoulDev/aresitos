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
import sys
try:
    from aresitos.utils.mantenimiento_utils import ejecutar_comando_sistema
except ImportError:
    from utils.mantenimiento_utils import ejecutar_comando_sistema

class ControladorMantenimiento:
    def __init__(self, modelo=None):
        if modelo is None:
            from modelo import modelo_mantenimiento
            self.modelo = modelo_mantenimiento.ModeloMantenimiento()
        else:
            self.modelo = modelo

    def actualizar_aresitos(self, vista):
        import os
        vista.mostrar_log("[INFORMACIÓN] Iniciando la actualización de ARESITOS desde el repositorio oficial...")
        # Configurar el directorio como seguro para git
        repo_dir = os.getcwd()
        ejecutar_comando_sistema(["git", "config", "--global", "--add", "safe.directory", repo_dir])
        resultado = ejecutar_comando_sistema(["git", "pull", "origin", "master"])
        if resultado['stdout']:
            vista.mostrar_log(resultado['stdout'])
        if resultado['stderr']:
            vista.mostrar_log("[ADVERTENCIA] " + resultado['stderr'])
        ejecutar_comando_sistema(["chmod", "+x", "configurar_kali.sh"])
        ejecutar_comando_sistema(["chmod", "+x", "main.py"])
        vista.mostrar_log("[INFORMACIÓN] Permisos de los scripts actualizados.")

    def crear_backup(self, vista):
        vista.mostrar_log("[INFORMACIÓN] Creando copia de seguridad...")
        try:
            resultado = self.modelo.crear_backup(vista)
            if resultado and 'ok' in resultado:
                vista.mostrar_log("[INFORMACIÓN] Copia de seguridad creada correctamente.")
            else:
                vista.mostrar_log("[ADVERTENCIA] No se pudo crear la copia de seguridad.")
        except Exception as e:
            vista.mostrar_log(f"[ERROR] {str(e)}")

    def restaurar_backup(self, vista):
        vista.mostrar_log("[INFORMACIÓN] Restaurando copia de seguridad...")
        try:
            resultado = self.modelo.restaurar_backup(vista)
            if resultado and 'ok' in resultado:
                vista.mostrar_log("[INFORMACIÓN] Copia de seguridad restaurada correctamente.")
            else:
                vista.mostrar_log("[ADVERTENCIA] No se pudo restaurar la copia de seguridad.")
        except Exception as e:
            vista.mostrar_log(f"[ERROR] {str(e)}")


    def limpiar_temporales(self, vista):
        vista.mostrar_log("[INFORMACIÓN] Eliminando archivos temporales de ARESITOS...")
        resultado = ejecutar_comando_sistema(["find", "/tmp", "-name", "*aresitos*", "-delete"])
        if resultado['returncode'] == 0:
            vista.mostrar_log("[INFORMACIÓN] Archivos temporales eliminados correctamente.")
        else:
            vista.mostrar_log(f"[ADVERTENCIA] Error al eliminar temporales: {resultado['stderr']}")

    def reiniciar_aresitos(self, vista):
        vista.mostrar_log("[INFORMACIÓN] Reiniciando ARESITOS...")
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            vista.mostrar_log(f"[ERROR] No se pudo reiniciar: {str(e)}")
