"""
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
    # Fallback robusto
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['where', comando], capture_output=True, text=True, timeout=3)
        else:
            result = subprocess.run(['which', comando], capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False
