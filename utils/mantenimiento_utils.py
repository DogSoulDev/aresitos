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
