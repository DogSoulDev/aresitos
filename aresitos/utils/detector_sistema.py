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
import platform
import os

def es_kali_linux() -> bool:
    try:
        
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                contenido = f.read().lower()
                if 'id=kali' in contenido or 'kali' in contenido:
                    return True
        
        try:
            import subprocess
            resultado = subprocess.run(['lsb_release', '-i'], capture_output=True, text=True, timeout=3)
            if 'kali' in resultado.stdout.lower():
                return True
        except Exception:
            pass
        
        if 'kali' in platform.system().lower():
            return True
        return False
    except Exception:
        return False

def nombre_sistema() -> str:
    return platform.system()
