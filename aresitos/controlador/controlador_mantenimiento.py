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
            from aresitos.modelo import modelo_mantenimiento
            self.modelo = modelo_mantenimiento.ModeloMantenimiento()
        else:
            self.modelo = modelo

    def actualizar_aresitos(self, vista):
        import os
        from aresitos.utils.sudo_manager import get_sudo_manager
        sudo_manager = get_sudo_manager()
        vista.mostrar_log("[INFORMACIÓN] Forzando la actualización de ARESITOS desde el repositorio oficial...")
        repo_dir = os.getcwd()
        ejecutar_comando_sistema(["git", "config", "--global", "--add", "safe.directory", repo_dir])
        # 1. Fetch y reset
        if sudo_manager.is_sudo_active():
            resultado_fetch = sudo_manager.execute_sudo_command("git fetch origin master")
            resultado_reset = sudo_manager.execute_sudo_command("git reset --hard origin/master")
        else:
            resultado_fetch = ejecutar_comando_sistema(["git", "fetch", "origin", "master"])
            resultado_reset = ejecutar_comando_sistema(["git", "reset", "--hard", "origin/master"])
        # 2. Ver si hubo cambios
        if sudo_manager.is_sudo_active():
            resultado_diff = sudo_manager.execute_sudo_command("git diff --name-status HEAD@{1} HEAD")
            resultado_log = sudo_manager.execute_sudo_command("git log -n 3 origin/master --pretty=format:'%h %an %ad %s'")
            diff_out = resultado_diff.stdout.strip() if hasattr(resultado_diff, 'stdout') else str(resultado_diff)
            log_out = resultado_log.stdout.strip() if hasattr(resultado_log, 'stdout') else str(resultado_log)
        else:
            resultado_diff = ejecutar_comando_sistema(["git", "diff", "--name-status", "HEAD@{1}", "HEAD"])
            resultado_log = ejecutar_comando_sistema(["git", "log", "-n", "3", "origin/master", "--pretty=format:%h %an %ad %s"])
            diff_out = resultado_diff.get('stdout', '').strip()
            log_out = resultado_log.get('stdout', '').strip()
        # 3. Mensajes claros y simplificados para el usuario
        if diff_out:
            vista.mostrar_log("[INFORMACIÓN] El programa ARESITOS se ha actualizado correctamente.")
        else:
            vista.mostrar_log("[INFORMACIÓN] El programa ARESITOS ya estaba actualizado. No hay cambios nuevos.")
        vista.mostrar_log("Para más información visita el repositorio oficial: https://github.com/DogSoulDev/aresitos")
    # 4. Ocultar errores y advertencias irrelevantes para el usuario final
        # 5. Permisos de scripts
        if sudo_manager.is_sudo_active():
            sudo_manager.execute_sudo_command("chmod +x configurar_kali.sh")
            sudo_manager.execute_sudo_command("chmod +x main.py")
        else:
            ejecutar_comando_sistema(["chmod", "+x", "configurar_kali.sh"])
            ejecutar_comando_sistema(["chmod", "+x", "main.py"])
        vista.mostrar_log("[INFORMACIÓN] Permisos de los scripts actualizados.")

    def crear_backup(self, vista):
        vista.mostrar_log("[INFORMACIÓN] Creando copia de seguridad...")
        resultado = self.modelo.crear_backup(vista)
        if resultado and 'ok' in resultado:
            vista.mostrar_log(f"[INFORMACIÓN] Copia de seguridad creada correctamente en: {resultado.get('ruta', '')}")
        elif resultado and 'error' in resultado:
            vista.mostrar_log(f"[ERROR] No se pudo crear la copia de seguridad: {resultado['error']}")
        else:
            vista.mostrar_log("[ADVERTENCIA] No se pudo crear la copia de seguridad.")

    def restaurar_backup(self, vista):
        vista.mostrar_log("[INFORMACIÓN] Restaurando copia de seguridad...")
        resultado = self.modelo.restaurar_backup(vista)
        if resultado and 'ok' in resultado:
            vista.mostrar_log("[INFORMACIÓN] Copia de seguridad restaurada correctamente.")
        elif resultado and 'error' in resultado:
            vista.mostrar_log(f"[ERROR] No se pudo restaurar la copia de seguridad: {resultado['error']}")
        else:
            vista.mostrar_log("[ADVERTENCIA] No se pudo restaurar la copia de seguridad.")


    def limpiar_temporales(self, vista):
        from aresitos.utils.sudo_manager import get_sudo_manager
        vista.mostrar_log("[INFORMACIÓN] Eliminando archivos temporales de ARESITOS...")
        sudo_manager = get_sudo_manager()
        if sudo_manager.is_sudo_active():
            resultado = sudo_manager.execute_sudo_command("find /tmp -name '*aresitos*' -delete")
            if resultado.returncode == 0:
                vista.mostrar_log("[INFORMACIÓN] Archivos temporales eliminados correctamente (con permisos elevados).")
            else:
                vista.mostrar_log(f"[ADVERTENCIA] Error al eliminar temporales: {resultado.stderr}")
        else:
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
