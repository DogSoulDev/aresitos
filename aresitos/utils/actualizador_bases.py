import subprocess
from typing import List, Dict

def actualizar_bases_datos(callback=None) -> Dict[str, str]:
    """
    Actualiza todas las bases de datos de firmas y herramientas soportadas por ARESITOS.
    Cumple los principios de seguridad: no almacena contraseñas, no ejecuta comandos peligrosos sin validación.
    """
    resultados = {}
    comandos = [
        ("ClamAV", ["freshclam"]),
        ("rkhunter", ["rkhunter", "--update"]),
        ("chkrootkit", ["chkrootkit", "-u"]),
        ("yara-rules", ["git", "-C", "/opt/yara-rules", "pull"]),  # Si se usan reglas personalizadas
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
