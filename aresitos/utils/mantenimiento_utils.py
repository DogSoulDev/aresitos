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
import subprocess

def ejecutar_comando_sistema(comando, cwd=None):
    try:
        resultado = subprocess.run(
            comando,
            cwd=cwd,
            capture_output=True,
            text=True
        )
        return {
            'stdout': resultado.stdout,
            'stderr': resultado.stderr,
            'returncode': resultado.returncode
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': str(e),
            'returncode': 1
        }
