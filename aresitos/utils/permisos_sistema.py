"""
Utilidades para verificación de permisos de root/administrador.
100% Python nativo, robusto, multiplataforma.
"""

import os
import platform
import subprocess

def es_root() -> bool:
    """
    Verifica si el usuario actual es root/administrador (Linux, Windows, Mac).
    """
    try:
        # Linux/Unix: getuid == 0
        if platform.system().lower() == 'linux':
            getuid = getattr(os, 'getuid', None)
            if getuid is not None:
                return getuid() == 0
        # Windows: usar ctypes
        if platform.system().lower() == 'windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                pass
        # Fallback: subprocess id -u
        try:
            result = subprocess.run(['id', '-u'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                return int(result.stdout.strip()) == 0
        except Exception:
            pass
        # Fallback: variable de entorno
        return os.environ.get('USER') == 'root' or os.environ.get('USERNAME') == 'root'
    except Exception:
        return False
