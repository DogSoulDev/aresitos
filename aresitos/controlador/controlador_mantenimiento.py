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
        vista.mostrar_log("[INFORMACIÓN] Iniciando la actualización de ARESITOS desde el repositorio oficial...")
        resultado = ejecutar_comando_sistema(["git", "pull", "origin", "master"])
        if resultado['stdout']:
            vista.mostrar_log(resultado['stdout'])
        if resultado['stderr']:
            vista.mostrar_log("[ADVERTENCIA] " + resultado['stderr'])
        ejecutar_comando_sistema(["chmod", "+x", "configurar_kali.sh"])
        ejecutar_comando_sistema(["chmod", "+x", "main.py"])
        vista.mostrar_log("[INFORMACIÓN] Permisos de los scripts actualizados.")

    def crear_backup(self, vista):
        vista.mostrar_log("[INFO] Creando copia de seguridad...")
        self.modelo.crear_backup(vista)

    def restaurar_backup(self, vista):
        vista.mostrar_log("[INFO] Restaurando copia de seguridad...")
        self.modelo.restaurar_backup(vista)


    def limpiar_temporales(self, vista):
        resultado = ejecutar_comando_sistema(["find", "/tmp", "-name", "*aresitos*", "-delete"])
        vista.mostrar_log("[INFO] Archivos temporales eliminados correctamente.")

    def reiniciar_aresitos(self, vista):
        vista.mostrar_log("[INFO] Reiniciando ARESITOS...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
