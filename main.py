# -*- coding: utf-8 -*-
"""
aresitos - Punto de Entrada Principal
==========================            print("[WARNING] MODO DESARROLLO: Ejecutando en entorno no-Kali")
            print("Algunas funcionalidades pueden no estar disponibles")
        else:
            print("ERROR: ARESITOS requiere Kali Linux")=======

Punto de entrada principal para aresitos que redirige al sistema
de login GUI para una mejor experiencia de usuario.

Exclusivamente para Kali Linux.

Autor: DogSoulDev
Fecha: 16 de Agosto de 2025
"""

import os
import sys
import platform
from pathlib import Path

def verificar_kali_linux():
    """Verificación básica de Kali Linux"""
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'kali' in content
        return False
    except (IOError, OSError, PermissionError):
        return False

def verificar_modo_desarrollo():
    """Verificar si estamos en modo desarrollo"""
    # Permitir modo desarrollo si se pasa argumento --dev
    if '--dev' in sys.argv or '--desarrollo' in sys.argv:
        return True
    return False

def configurar_permisos_basicos():
    """Configurar permisos básicos para archivos de configuración"""
    try:
        directorio_actual = Path(__file__).parent.resolve()
        config_dir = directorio_actual / 'configuración'
        # Asegurar que el directorio de configuración sea legible
        if config_dir.exists():
            os.chmod(config_dir, 0o755)
            # Asegurar que los archivos de configuración sean legibles
            for config_file in config_dir.glob('*.json'):
                try:
                    os.chmod(config_file, 0o644)
                except (OSError, PermissionError):
                    pass
        # Asegurar permisos en data
        data_dir = directorio_actual / 'data'
        if data_dir.exists():
            os.chmod(data_dir, 0o755)
    except Exception as e:
        print(f"Advertencia: No se pudieron configurar permisos básicos: {e}")

def verificar_tkinter():
    """Verificar que tkinter esté disponible"""
    try:
        import tkinter as tk
        # Crear una ventana de prueba para verificar DISPLAY
        test_root = tk.Tk()
        test_root.withdraw()  # Ocultar inmediatamente
        test_root.destroy()
        print("Tkinter disponible y funcional")
    except ImportError:
        raise ImportError("tkinter no está instalado. Ejecute: sudo apt install python3-tk")
    except Exception as e:
        if "DISPLAY" in str(e):
            raise Exception("No hay servidor X disponible. ¿Está ejecutando desde SSH? Use ssh -X o ejecute en entorno gráfico")
        else:
            raise Exception(f"Error con tkinter: {e}")

def main():
    """Función principal que redirige al login GUI con flujo escalonado"""
    print("ARESITOS - Sistema de Seguridad Cibernética")
    print("=" * 50)

    # Añadir la raíz del proyecto al sys.path para evitar errores de importación
    directorio_actual = Path(__file__).parent.resolve()
    if str(directorio_actual) not in sys.path:
        sys.path.insert(0, str(directorio_actual))

    # Issue 23/24: Verificación de estabilidad del sistema
    if "--verify" in sys.argv or "--verificar" in sys.argv:
        estable = verificacion_estabilidad_sistema()
        if not estable:
            sys.exit(1)
        else:
            print("Sistema verificado - continuando con inicio normal...")

    # Verificar Kali Linux antes de continuar
    if not verificar_kali_linux():
        if verificar_modo_desarrollo():
            print("[WARNING] MODO DESARROLLO: Ejecutando en entorno no-Kali")
            print("  Algunas funcionalidades pueden no estar disponibles")
        else:
            print("ERROR: ARESITOS requiere Kali Linux")
            print("  Sistema operativo no compatible detectado")
            print("  Para desarrollo: usar --dev o --desarrollo")
            sys.exit(1)

    # Configurar permisos básicos de archivos antes de continuar
    configurar_permisos_basicos()

    # Verificar si existe vista login
    vista_login_path = directorio_actual / 'aresitos' / 'vista' / 'vista_login.py'
    if vista_login_path.exists():
        print("Iniciando con interfaz de login...")
        try:
            # Verificar tkinter antes de importar
            verificar_tkinter()

            # Importar y ejecutar vista login directamente
            # sys.path.insert(0, str(directorio_actual))  # Ya añadido arriba

            # Importar la clase principal del login
            from aresitos.vista.vista_login import LoginAresitos

            # Crear y ejecutar login con flujo completo
            print("Creando aplicación de login...")
            app_login = LoginAresitos()
            print("Aplicación de login creada")

            print("Iniciando interfaz gráfica...")
            # Ejecutar GUI - esto manejará todo el flujo automáticamente
            try:
                app_login.root.mainloop()
            except KeyboardInterrupt:
                print("\nGracias por usar Aresitos, ¡nos vemos!")

            print("Sesión de login finalizada")
            return

        except ImportError as e:
            print(f"Error importando vista login: {e}")
            print(f"Detalles: {str(e)}")
            print("Intentando con método clásico...")
        except Exception as e:
            print(f"Error ejecutando vista login: {e}")
            print(f"Detalles: {str(e)}")
            print("Intentando con método clásico...")

    # Fallback al método original solo si falla el login
    print("Usando método de inicio clásico...")
    iniciar_aplicacion_clasica()

def iniciar_aplicacion_clasica():
    """Metodo de inicio clasico sin login GUI"""
    try:
        import tkinter as tk
        
        # Importar módulos principales
        from aresitos.vista.vista_principal import VistaPrincipal
        from aresitos.controlador.controlador_principal import ControladorPrincipal  
        from aresitos.modelo.modelo_principal import ModeloPrincipal
        
        print("Módulos principales cargados")
        
        # Crear aplicación principal con tema Burp Suite
        root = tk.Tk()
        root.title("ARESITOS - Sistema de Seguridad Cibernética")
        root.geometry("1400x900")
        
        # CRÍTICO: Configurar tema oscuro para la ventana principal
        root.configure(bg='#2b2b2b')
        
        # Inicializar MVC
        print("Inicializando componentes MVC...")
        modelo = ModeloPrincipal()
        vista = VistaPrincipal(root)
        
        # CRÍTICO: Hacer que la vista ocupe toda la ventana
        vista.pack(fill="both", expand=True)
        
        controlador = ControladorPrincipal(modelo)
        
        # CRÍTICO: Conectar controlador a la vista
        vista.set_controlador(controlador)
        
        # Centrar ventana
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (1400 // 2)
        y = (root.winfo_screenheight() // 2) - (900 // 2)
        root.geometry(f"1400x900+{x}+{y}")
        
        print("ARESITOS iniciado exitosamente")
        print("Dashboard completo cargado - Funcional")
        print("Tema Burp Suite aplicado")
        print("Herramientas Kali Linux configuradas")
        
        # Ejecutar aplicación
        try:
            root.mainloop()
        except KeyboardInterrupt:
            print("\nGracias por usar Aresitos, ¡nos vemos!")
        
    except ImportError as e:
        print(f"Error importando módulos: {e}")
        print("  Verifique la instalación de ARESITOS")
        print("  Ejecute: python configurar.py")
    except Exception as e:
        print(f"Error iniciando aplicación: {e}")
        import traceback
        traceback.print_exc()

def verificar_permisos_inicio():
    """Verificar permisos al inicio y mostrar recomendaciones."""
    if platform.system() == "Linux":
        try:
            import subprocess
            # Verificar si tenemos capacidades para herramientas de red
            result = subprocess.run(["getcap", "/usr/bin/nmap"], 
                                  capture_output=True, text=True, timeout=5)
            
            if "cap_net_raw" not in result.stdout:
                print("AVISO: nmap podría no tener permisos para SYN scan")
                print("  Para funcionalidad completa: sudo python configurar.py")
            
            # Verificar sudo sin contraseña
            result_sudo = subprocess.run(["sudo", "-n", "true"], 
                                       capture_output=True, timeout=5)
            if result_sudo.returncode != 0:
                print("sudo requiere contraseña - use el login GUI")
                print("  Ejecute: python -m aresitos.vista.vista_login")
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass  # No mostrar errores si no se puede verificar

def verificacion_estabilidad_sistema():
    """Issue 23/24: Verificación final de estabilidad del sistema"""
    """Verificar integridad y estabilidad de todos los componentes de aresitos"""
    print("\n=== VERIFICACIÓN DE ESTABILIDAD ARESITOS ===")
    
    verificaciones = []
    
    # Verificar estructura de archivos críticos
    base_dir = Path(__file__).parent.resolve()
    archivos_criticos = [
        base_dir / "aresitos" / "vista" / "vista_principal.py",
        base_dir / "aresitos" / "controlador" / "controlador_principal.py",
        base_dir / "aresitos" / "modelo" / "modelo_principal.py",
        base_dir / "aresitos" / "utils" / "sudo_manager.py",
        base_dir / "aresitos" / "vista" / "terminal_mixin.py"
    ]
    for archivo in archivos_criticos:
        if archivo.exists():
            verificaciones.append(f"Archivo crítico: {archivo}")
        else:
            verificaciones.append(f"Archivo faltante: {archivo}")
    # Verificar configuraciones (usar archivos que realmente existen)
    configs = [
        base_dir / "configuración" / "aresitos_config_completo.json",
        base_dir / "configuración" / "textos_castellano_corregido.json"
    ]
    for config in configs:
        if config.exists():
            verificaciones.append(f"Configuración: {config}")
        else:
            verificaciones.append(f"Configuración faltante: {config}")
    # Verificar directorios de datos
    directorios = [base_dir / "data", base_dir / "logs", base_dir / "data" / "cheatsheets", base_dir / "data" / "wordlists"]
    for directorio in directorios:
        if directorio.exists():
            verificaciones.append(f"Directorio: {directorio}")
        else:
            verificaciones.append(f"Directorio faltante: {directorio}")
    
    # Mostrar resultados
    for verificacion in verificaciones:
        print(f"  {verificacion}")
    
    errores = [v for v in verificaciones if "faltante" in v]
    if errores:
        print(f"\nERRORES DETECTADOS: {len(errores)}")
        return False
    else:
        print(f"\nSISTEMA ESTABLE: {len(verificaciones)} verificaciones completadas")
        return True

if __name__ == "__main__":
    main()

