import os
import sys
from utils.mantenimiento_utils import ejecutar_comando_sistema

class ControladorMantenimiento:
    def __init__(self, modelo=None):
        if modelo is None:
            from modelo.modelo_mantenimiento import ModeloMantenimiento
            self.modelo = ModeloMantenimiento()
        else:
            self.modelo = modelo

    def actualizar_aresitos(self, vista):
        vista.mostrar_log("[INFO] Iniciando actualización de ARESITOS desde el repositorio oficial...")
        # Verificar estado del repositorio
        resultado = ejecutar_comando_sistema(["git", "status"])
        if "modified" in resultado['stdout'] or "Untracked files" in resultado['stdout']:
            vista.mostrar_log("[ADVERTENCIA] Hay cambios locales o archivos no rastreados. Puede haber conflictos al actualizar.")
        # Descargar la última versión desde GitHub
        resultado = ejecutar_comando_sistema(["git", "pull", "origin", "master"])
        vista.mostrar_log(resultado['stdout'] or resultado['stderr'])
        # Actualizar permisos de scripts principales
        ejecutar_comando_sistema(["chmod", "+x", "configurar_kali.sh"])
        ejecutar_comando_sistema(["chmod", "+x", "main.py"])
        vista.mostrar_log("[INFO] Permisos de scripts actualizados.")

    def crear_backup(self, vista):
        vista.mostrar_log("[INFO] Creando copia de seguridad...")
        self.modelo.crear_backup(vista)

    def restaurar_backup(self, vista):
        vista.mostrar_log("[INFO] Restaurando copia de seguridad...")
        self.modelo.restaurar_backup(vista)

    def ver_logs_actualizacion(self, vista):
        logs = self.modelo.obtener_logs_actualizacion()
        vista.mostrar_log(logs)

    def limpiar_temporales(self, vista):
        resultado = ejecutar_comando_sistema(["find", "/tmp", "-name", "*aresitos*", "-delete"])
        vista.mostrar_log("[INFO] Archivos temporales eliminados correctamente.")

    def ver_estado_repositorio(self, vista):
        resultado = ejecutar_comando_sistema(["git", "status"])
        vista.mostrar_log(resultado['stdout'] or resultado['stderr'])

    def comprobar_integridad(self, vista):
        integridad = self.modelo.comprobar_integridad()
        vista.mostrar_log(integridad)

    def ver_informacion_version(self, vista):
        version = self.modelo.obtener_informacion_version()
        vista.mostrar_log(version)

    def reiniciar_aresitos(self, vista):
        vista.mostrar_log("[INFO] Reiniciando ARESITOS...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
