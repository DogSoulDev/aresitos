#!/usr/bin/env python3
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
import platform
import subprocess
import shutil
from pathlib import Path

class ConfiguradorAresAegis:
    def __init__(self):
        self.sistema = platform.system()
        self.es_kali = self.detectar_kali()
        self.directorio_base = Path(__file__).parent
        print(" Configurador Automático de Ares Aegis")
        print("=" * 50)
        print(f"Sistema: {self.sistema}")
        print(f"Kali Linux: {'Sí' if self.es_kali else 'No'}")
        print(f"Directorio: {self.directorio_base}")
        print()

    def detectar_kali(self):
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    return 'kali' in f.read().lower()
            return False
        except Exception:
            return False

    def verificar_python(self):
        print(" Verificando Python...")
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 6):
            print("Se requiere Python 3.6 o superior")
            return False
        print(f"Python {version.major}.{version.minor}.{version.micro}")
        return True

    def verificar_permisos(self):
        print(" Verificando permisos...")
        try:
            if self.sistema == "Windows":
                import ctypes
                es_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                try:
                    result = subprocess.run(['id', '-u'], capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        uid = int(result.stdout.strip())
                        es_admin = uid == 0
                    else:
                        es_admin = False
                except Exception:
                    es_admin = False
                if not es_admin:
                    try:
                        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
                        sudo_disponible = result.returncode == 0
                        if sudo_disponible:
                            print("Sudo disponible")
                            return True
                    except Exception:
                        pass
            if es_admin:
                print("OK Permisos de administrador confirmados")
                return True
            else:
                print("WARNING Sin permisos de administrador")
                print(" Ejecute con: sudo python configurar.py")
                return False
        except Exception as e:
            print(f"ERROR verificando permisos: {e}")
            return False

    def instalar_dependencias_python(self):
        print(" Instalando dependencias de Python...")
        dependencias = ['tkinter']
        for dep in dependencias:
            try:
                import importlib
                importlib.import_module(dep)
                print(f"OK {dep} disponible")
            except ImportError:
                print(f"ERROR {dep} no encontrado")
                if dep == 'tkinter':
                    if self.sistema == "Linux":
                        print(" Instalando python3-tk...")
                        self.ejecutar_comando(['apt-get', 'install', '-y', 'python3-tk'])
                    else:
                        print("WARNING Instale tkinter manualmente")

    def verificar_herramientas_sistema(self):
        print(" Verificando herramientas del sistema...")
        herramientas_criticas = [
            'nmap', 'curl', 'wget', 'git', 'python3'
        ]
        disponibles = 0
        for herramienta in herramientas_criticas:
            if shutil.which(herramienta):
                print(f"OK {herramienta}")
                disponibles += 1
            else:
                print(f"ERROR {herramienta}")
        print(f" Herramientas: {disponibles}/{len(herramientas_criticas)}")
        return disponibles >= len(herramientas_criticas) // 2

    def instalar_herramientas_kali(self):
        if not self.es_kali:
            print("WARNING No es Kali Linux - saltando instalación específica")
            return True
        print(" Instalando herramientas de Kali Linux...")
        herramientas_esenciales = [
            'nmap', 'sqlmap', 'hydra', 'nikto',
            'metasploit-framework', 'john', 'hashcat', 'aircrack-ng',
            'gobuster', 'feroxbuster', 'wfuzz', 'whatweb', 'nuclei'
        ]
        print(" Actualizando repositorios...")
        if self.ejecutar_comando(['apt-get', 'update']):
            print("OK Repositorios actualizados")
        for herramienta in herramientas_esenciales[:10]:
            print(f" Instalando {herramienta}...")
            self.ejecutar_comando(['apt-get', 'install', '-y', herramienta])
        return True

    def configurar_directorios(self):
        print(" Configurando directorios...")
        directorios = [
            'logs',
            'data/wordlists/generadas',
            'resources/temp',
            'config/backup'
        ]
        for directorio in directorios:
            ruta = self.directorio_base / directorio
            try:
                ruta.mkdir(parents=True, exist_ok=True)
                print(f"OK {directorio}")
            except Exception as e:
                print(f"ERROR creando {directorio}: {e}")

    def configurar_permisos_archivos(self):
        if self.sistema == "Windows":
            print("WARNING Windows - saltando configuración de permisos Unix")
            return True
        print(" Configurando permisos de archivos...")
        ejecutables = [
            'main.py',
            'login.py',
            'login_gui.py',
            'verificar.py'
        ]
        for archivo in ejecutables:
            ruta = self.directorio_base / archivo
            if ruta.exists():
                try:
                    os.chmod(ruta, 0o755)
                    print(f"OK {archivo} (755)")
                except Exception as e:
                    print(f"ERROR en {archivo}: {e}")
        return True

    def crear_alias_sistema(self):
        if self.sistema == "Windows":
            print("WARNING Windows - crear acceso directo manualmente")
            return True
        print(" Configurando alias del sistema...")
        script_inicio = f"""#!/bin/bash\n# Ares Aegis Launcher\ncd \"{self.directorio_base}\"\npython3 login_gui.py \"$@\"\n"""
        try:
            ruta_launcher = Path('/usr/local/bin/ares-aegis')
            if os.access('/usr/local/bin', os.W_OK):
                with open(ruta_launcher, 'w') as f:
                    f.write(script_inicio)
                os.chmod(ruta_launcher, 0o755)
                print("OK Alias 'ares-aegis' creado")
            else:
                print("WARNING Sin permisos para crear alias global")
        except Exception as e:
            print(f"ERROR creando alias: {e}")
        return True

    def ejecutar_comando(self, comando):
        try:
            if not self.verificar_permisos() and comando[0] in ['apt-get', 'yum', 'pacman']:
                comando = ['sudo'] + comando
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300
            )
            return resultado.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"ERROR Timeout ejecutando: {' '.join(comando)}")
            return False
        except Exception as e:
            print(f"ERROR ejecutando comando: {e}")
            return False

    def verificar_configuracion(self):
        print(" Verificando configuración final...")
        verificaciones = [
            ("Python", self.verificar_python()),
            ("Directorios", self.directorio_base.exists()),
            ("Login GUI", (self.directorio_base / 'login_gui.py').exists()),
            ("Configuración", (self.directorio_base / 'configuración').exists())
        ]
        exitoso = 0
        for nombre, resultado in verificaciones:
            if resultado:
                print(f"OK {nombre}")
                exitoso += 1
            else:
                print(f"ERROR {nombre}")
        print(f" Configuración: {exitoso}/{len(verificaciones)} completada")
        return exitoso == len(verificaciones)

    def ejecutar_configuracion_completa(self):
        print(" Iniciando configuración automática de Ares Aegis...")
        print()
        pasos = [
            ("Verificar Python", self.verificar_python),
            ("Verificar permisos", self.verificar_permisos),
            ("Instalar dependencias Python", self.instalar_dependencias_python),
            ("Verificar herramientas", self.verificar_herramientas_sistema),
            ("Configurar directorios", self.configurar_directorios),
            ("Configurar permisos", self.configurar_permisos_archivos),
            ("Crear alias", self.crear_alias_sistema),
            ("Verificación final", self.verificar_configuracion)
        ]
        if self.es_kali:
            pasos.insert(-2, ("Instalar herramientas Kali", self.instalar_herramientas_kali))
        exitosos = 0
        for i, (nombre, funcion) in enumerate(pasos, 1):
            print(f"\n Paso {i}/{len(pasos)}: {nombre}")
            print("-" * 40)
            try:
                if funcion():
                    exitosos += 1
                    print(f"OK {nombre} completado")
                else:
                    print(f"WARNING {nombre} con advertencias")
            except Exception as e:
                print(f"ERROR en {nombre}: {e}")
        print("\n" + "=" * 50)
        print(" RESUMEN DE CONFIGURACIÓN")
        print("=" * 50)
        print(f" Pasos completados: {exitosos}/{len(pasos)}")
        if exitosos >= len(pasos) * 0.8:
            print("OK Configuración exitosa - Ares Aegis listo para usar")
            print("\n Para iniciar ejecute: python login_gui.py")
            if self.sistema != "Windows" and shutil.which('ares-aegis'):
                print(" O simplemente: ares-aegis")
            return True
        else:
            print("WARNING Configuración incompleta - revise los errores anteriores")
            return False

 
def main():
    configurador = ConfiguradorAresAegis()
    try:
        resultado = configurador.ejecutar_configuracion_completa()
        sys.exit(0 if resultado else 1)
    except KeyboardInterrupt:
        print("\n\n Configuración cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR crítico en configuración: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
