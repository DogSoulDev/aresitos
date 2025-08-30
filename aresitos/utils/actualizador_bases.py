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
from typing import List, Dict

def actualizar_bases_datos(callback=None) -> Dict[str, str]:
    resultados = {}
    comandos = [
        ("ClamAV", ["freshclam"]),
        ("rkhunter", ["rkhunter", "--update"]),
        ("chkrootkit", ["chkrootkit", "-u"]),
        ("yara-rules", ["git", "-C", "/opt/yara-rules", "pull"]),
    ]
    for nombre, comando in comandos:
        try:
            if callback:
                callback(f"Actualizando {nombre}...")
            res = subprocess.run(comando, capture_output=True, text=True, timeout=180)
            if res.returncode == 0:
                resultados[nombre] = "OK"
                if callback:
                    callback(f"{nombre}: Actualización completada")
            else:
                resultados[nombre] = f"ERROR: {res.stderr.strip()}"
                if callback:
                    callback(f"{nombre}: Error: {res.stderr.strip()}")
        except Exception as e:
            resultados[nombre] = f"ERROR: {str(e)}"
            if callback:
                callback(f"{nombre}: Error: {str(e)}")
    return resultados
