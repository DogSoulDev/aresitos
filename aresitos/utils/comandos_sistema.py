
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.

Utilidades para verificación de comandos/herramientas en el sistema.
100% Python nativo, robusto, multiplataforma.
"""

import shutil
import subprocess
import platform


def existe_comando(comando: str) -> bool:
    """
    Verifica si un comando/herramienta está disponible en el sistema (PATH).
    Compatible con Linux, macOS y Windows.
    """
    # Preferencia: shutil.which (Python 3.3+), fallback a 'which' o 'where'
    path = shutil.which(comando)
    if path:
        return True
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['where', comando], capture_output=True, text=True, timeout=3)
        else:
            result = subprocess.run(['which', comando], capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False


