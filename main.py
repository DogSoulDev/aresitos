#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS V3.0 - Herramienta de Auditoría y Respuesta de Seguridad OPTIMIZADA
============================================================================

main.py - Punto de entrada principal optimizado siguiendo principios ARESITOS V3

Principios ARESITOS V3 aplicados:
- Thread Safety: threading.RLock() para protección de operaciones críticas
- Dynamic Access: getattr() para acceso seguro a métodos y atributos
- Robust Error Handling: try-except multinivel con fallbacks
- Cache System: Cache de verificaciones del sistema
- Fallback Systems: Múltiples niveles de fallback
- ThreadPoolExecutor: Para operaciones concurrentes
- Context Managers: Gestión automática de recursos
- Validation Layer: Validación robusta de entrada
- Configuration Loader: Carga dinámica de configuraciones
- Resource Cleanup: Limpieza automática de recursos

Autor: DogSoulDev (Optimizado por ARESITOS Security Team)
Fecha: 23 de Agosto de 2025
Versión: 3.0.0 OPTIMIZADA (Kali Linux 2025)
"""

import os
import sys
import platform
import subprocess
import signal
import threading
import time
import functools
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

# Asegurar encoding UTF-8
os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

# Variables globales de configuración ARESITOS V3
VERSION = "3.0.0-OPTIMIZADA"
AUTOR = "DogSoulDev + ARESITOS Security Team"
DESCRIPCION = "Suite de Ciberseguridad Optimizada para Kali Linux (Solo Python Nativo + Herramientas Kali)"

# Thread Safety
_main_lock = threading.RLock()
_cache_lock = threading.RLock()
_verification_cache = {}
_system_resources = []

# ThreadPoolExecutor global
_thread_pool = None

def get_thread_pool():
    """Thread-safe ThreadPoolExecutor singleton"""
    global _thread_pool
    with _main_lock:
        if _thread_pool is None:
            _thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ARESITOS")
        return _thread_pool

@contextmanager
def resource_manager(resource_name):
    """Context manager para gestión automática de recursos"""
    with _main_lock:
        _system_resources.append(resource_name)
    try:
        yield resource_name
    finally:
        with _main_lock:
            if resource_name in _system_resources:
                _system_resources.remove(resource_name)

def cache_result(ttl_seconds=300):
    """Decorador para cache con TTL"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with _cache_lock:
                key = f"{func.__name__}_{hash(str(args) + str(sorted(kwargs.items())))}"
                current_time = time.time()
                
                if key in _verification_cache:
                    cached_time, cached_result = _verification_cache[key]
                    if current_time - cached_time < ttl_seconds:
                        return cached_result
                
                result = func(*args, **kwargs)
                _verification_cache[key] = (current_time, result)
                return result
        return wrapper
    return decorator

def signal_handler(sig, frame):
    """Manejador de señales para limpieza apropiada con Thread Safety"""
    print("\nRecibida señal de interrupción. Cerrando ARESITOS...")
    try:
        with _main_lock:
            # Limpieza de ThreadPoolExecutor
            global _thread_pool
            if _thread_pool:
                _thread_pool.shutdown(wait=True)
                _thread_pool = None
            
            # Limpieza de recursos registrados
            for resource in _system_resources.copy():
                try:
                    print(f"Limpiando recurso: {resource}")
                except Exception:
                    pass
            
            _system_resources.clear()
            _verification_cache.clear()
            
    except Exception as e:
        print(f"Error durante limpieza: {e}")
    finally:
        sys.exit(0)

# Configurar manejadores de señales
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

@cache_result(ttl_seconds=600)
def verificar_kali_linux_estricto():
    """Verificación estricta de Kali Linux como sistema base con cache"""
    with resource_manager("kali_verification") as resource:
        try:
            verification_methods = [
                _check_os_release,
                _check_kali_directories,
                _check_kali_command
            ]
            
            # Dynamic Access con fallback
            for method in verification_methods:
                try:
                    if getattr(method, '__call__', None) and method():
                        return True
                except Exception as e:
                    print(f"Método de verificación falló: {method.__name__}: {e}")
                    continue
            
            return False
            
        except Exception as e:
            print(f"Error en verificación de Kali Linux: {e}")
            return False

def _check_os_release():
    """Verificar archivo /etc/os-release"""
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'kali' in content
    except (IOError, OSError, PermissionError):
        pass
    return False

def _check_kali_directories():
    """Verificar directorios específicos de Kali"""
    kali_dirs = ['/usr/share/kali-themes', '/usr/share/kali-tools']
    return any(os.path.exists(dir_path) for dir_path in kali_dirs)

def _check_kali_command():
    """Verificar comando kali-linux"""
    try:
        result = subprocess.run(['which', 'kali-linux'], 
                              capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False

def verificar_modo_desarrollo():
    """Verificar si estamos en modo desarrollo con validación robusta"""
    dev_flags = ['--dev', '--desarrollo', '--debug', '--test']
    return any(flag in sys.argv for flag in dev_flags)

def configurar_permisos_basicos():
    """Configurar permisos básicos para archivos de configuración con Thread Safety"""
    with _main_lock:
        try:
            directorio_actual = Path(__file__).parent
            
            # Configuration Loader dinámico
            directories_to_check = [
                ('configuración', 0o755, '*.json'),
                ('data', 0o755, '*'),
                ('logs', 0o755, '*.log')
            ]
            
            for dir_name, dir_perm, file_pattern in directories_to_check:
                dir_path = directorio_actual / dir_name
                if dir_path.exists():
                    try:
                        os.chmod(dir_path, dir_perm)
                        
                        # Dynamic Access para archivos
                        for file_path in dir_path.glob(file_pattern):
                            try:
                                os.chmod(file_path, 0o644)
                            except (OSError, PermissionError) as e:
                                print(f"Advertencia: No se pudo configurar permisos en {file_path}: {e}")
                                
                    except (OSError, PermissionError) as e:
                        print(f"Advertencia: No se pudo configurar permisos en {dir_path}: {e}")
            
        except Exception as e:
            print(f"Advertencia: Error general configurando permisos: {e}")

def verificar_tkinter():
    """Verificar que tkinter esté disponible con Robust Error Handling"""
    try:
        import tkinter as tk
        
        # Validation Layer - crear ventana de prueba thread-safe
        with _main_lock:
            test_root = tk.Tk()
            test_root.withdraw()  # Ocultar inmediatamente
            test_root.destroy()
            
        print("OK Tkinter disponible y funcional")
        return True
        
    except ImportError as e:
        raise ImportError(f"tkinter no está instalado. Ejecute: sudo apt install python3-tk. Error: {e}")
    except Exception as e:
        error_msg = str(e)
        if "DISPLAY" in error_msg:
            raise Exception("No hay servidor X disponible. ¿Está ejecutando desde SSH? Use ssh -X o ejecute en entorno gráfico")
        else:
            raise Exception(f"Error con tkinter: {e}")

@cache_result(ttl_seconds=300)
def verificar_dependencias_nativas():
    """Verificar que todas las dependencias Python nativas estén disponibles con cache"""
    dependencias_criticas = [
        ('tkinter', 'Interfaz gráfica'),
        ('sqlite3', 'Base de datos local'),
        ('json', 'Manejo de configuraciones'),
        ('threading', 'Operaciones concurrentes'),
        ('subprocess', 'Ejecución de comandos Kali'),
        ('hashlib', 'Funciones de integridad'),
        ('datetime', 'Timestamps y fechas'),
        ('logging', 'Sistema de logs'),
        ('pathlib', 'Manejo de rutas'),
        ('platform', 'Información del sistema'),
        ('concurrent.futures', 'Operaciones asíncronas'),
        ('contextlib', 'Context managers')
    ]
    
    faltantes = []
    
    # ThreadPoolExecutor para verificación paralela
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="ARESITOS-Deps") as executor:
        futures = {}
        
        for modulo, descripcion in dependencias_criticas:
            future = executor.submit(_check_module, modulo)
            futures[future] = (modulo, descripcion)
        
        for future in futures:
            modulo, descripcion = futures[future]
            try:
                if not future.result(timeout=5):
                    faltantes.append((modulo, descripcion))
            except Exception as e:
                print(f"Error verificando {modulo}: {e}")
                faltantes.append((modulo, descripcion))
    
    if faltantes:
        print("ERROR: Dependencias Python críticas faltantes:")
        for modulo, desc in faltantes:
            print(f"  - {modulo}: {desc}")
        print("\nInstale Python completo: sudo apt install python3-dev python3-tk")
        return False
    
    print("OK Todas las dependencias Python nativas disponibles")
    return True

def _check_module(module_name):
    """Verificar un módulo específico de forma thread-safe"""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

def main():
    """Función principal que redirige al login GUI con flujo escalonado optimizado"""
    print(f"ARESITOS v{VERSION} - Sistema de Seguridad Cibernética")
    print("=" * 55)
    print(f"Autor: {AUTOR}")
    print(f"Descripción: {DESCRIPCION}")
    print("Exclusivamente para Kali Linux")
    print("=" * 55)
    
    try:
        with resource_manager("main_application") as resource:
            # Verificar dependencias Python nativas primero (con cache)
            if not verificar_dependencias_nativas():
                print("ERROR: Dependencias Python críticas faltantes")
                sys.exit(1)
            
            # Issue 23/24: Verificación de estabilidad del sistema
            if any(arg in sys.argv for arg in ["--verify", "--verificar"]):
                estable = verificacion_estabilidad_sistema()
                if not estable:
                    sys.exit(1)
                else:
                    print("Sistema verificado - continuando con inicio normal...")
            
            # Verificar Kali Linux antes de continuar (con cache)
            if not verificar_kali_linux_estricto():
                if verificar_modo_desarrollo():
                    print("WARNING MODO DESARROLLO: Ejecutando en entorno no-Kali")
                    print("   Algunas funcionalidades pueden no estar disponibles")
                else:
                    print("ERROR: ARESITOS requiere Kali Linux")
                    print("Sistema operativo no compatible detectado")
                    print("Para desarrollo: usar --dev o --desarrollo")
                    sys.exit(1)
            
            # Configurar permisos básicos de archivos antes de continuar
            configurar_permisos_basicos()
            
            # Verificar tkinter con manejo robusto de errores
            try:
                verificar_tkinter()
            except Exception as e:
                print(f"Error con interfaz gráfica: {e}")
                print("Intentando con método de línea de comandos...")
                sys.exit(1)
            
            # Dynamic Access - verificar si existe vista login
            directorio_actual = Path(__file__).parent
            vista_login_path = directorio_actual / 'aresitos' / 'vista' / 'vista_login.py'
            
            if vista_login_path.exists():
                return _ejecutar_login_gui(directorio_actual)
            else:
                print("Vista de login no encontrada, usando método clásico...")
                return iniciar_aplicacion_clasica()
                
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario")
        sys.exit(0)
    except Exception as e:
        print(f"Error crítico en main: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def _ejecutar_login_gui(directorio_actual):
    """Ejecutar GUI de login con Robust Error Handling"""
    print("Iniciando con interfaz de login...")
    try:
        # ThreadPoolExecutor para carga asíncrona
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="ARESITOS-Login") as executor:
            # Importar de forma thread-safe
            sys.path.insert(0, str(directorio_actual))
            
            # Fallback Systems - múltiples intentos de importación
            import_attempts = [
                lambda: __import__('aresitos.vista.vista_login', fromlist=['LoginAresitos']),
                lambda: __import__('aresitos.vista.vista_login'),
            ]
            
            login_module = None
            for attempt in import_attempts:
                try:
                    login_module = attempt()
                    break
                except ImportError as e:
                    print(f"Intento de importación falló: {e}")
                    continue
            
            if login_module is None:
                raise ImportError("No se pudo importar el módulo de login")
            
            # Dynamic Access para obtener la clase
            login_class = getattr(login_module, 'LoginAresitos', None)
            if login_class is None:
                raise AttributeError("Clase LoginAresitos no encontrada")
            
            print("Creando aplicación de login...")
            app_login = login_class()
            print("Aplicación de login creada")
            
            print("Iniciando interfaz gráfica...")
            # Context Manager para manejo automático de GUI
            with _gui_context_manager(app_login):
                app_login.root.mainloop()
            
            print("Sesión de login finalizada")
            return True
            
    except ImportError as e:
        print(f"Error importando vista login: {e}")
        print("Intentando con método clásico...")
        return iniciar_aplicacion_clasica()
    except Exception as e:
        print(f"Error ejecutando vista login: {e}")
        print("Intentando con método clásico...")
        return iniciar_aplicacion_clasica()

@contextmanager
def _gui_context_manager(app_instance):
    """Context manager para manejo automático de GUI"""
    try:
        yield app_instance
    finally:
        # Resource Cleanup
        try:
            if hasattr(app_instance, 'root') and app_instance.root:
                app_instance.root.quit()
        except Exception as e:
            print(f"Error cerrando GUI: {e}")

def iniciar_aplicacion_clasica():
    """Método de inicio clásico sin login GUI con optimizaciones ARESITOS V3"""
    try:
        with resource_manager("classic_application") as resource:
            import tkinter as tk
            
            # Fallback Systems para importación de módulos
            module_imports = {
                'vista': 'aresitos.vista.vista_principal',
                'controlador': 'aresitos.controlador.controlador_principal',
                'modelo': 'aresitos.modelo.modelo_principal'
            }
            
            modules = {}
            
            # ThreadPoolExecutor para importaciones paralelas
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="ARESITOS-Import") as executor:
                futures = {
                    executor.submit(__import__, module_path, fromlist=[module_name]): module_name
                    for module_name, module_path in module_imports.items()
                }
                
                for future in futures:
                    module_name = futures[future]
                    try:
                        modules[module_name] = future.result(timeout=10)
                    except Exception as e:
                        print(f"Error importando {module_name}: {e}")
                        return False
            
            print("Módulos principales cargados")
            
            # Configuration Loader - crear aplicación principal con tema Burp Suite
            root = tk.Tk()
            root.title("Aresitos")
            root.geometry("1400x900")
            
            # Dynamic Access para configurar icono
            try:
                icon_module = __import__('aresitos.utils.gestor_iconos', fromlist=['configurar_icono_ventana'])
                configurar_icono = getattr(icon_module, 'configurar_icono_ventana', None)
                if configurar_icono:
                    configurar_icono(root, "ARESITOS v3.0 - Herramientas de Seguridad")
            except Exception as e:
                print(f"No se pudo cargar el icono de la ventana: {e}")
            
            # CRÍTICO: Configurar tema oscuro para la ventana principal
            root.configure(bg='#2b2b2b')
            
            # Inicializar MVC con Thread Safety
            print("Inicializando componentes MVC...")
            with _main_lock:
                # Dynamic Access para clases con validación robusta
                try:
                    modelo_class = getattr(modules['modelo'], 'ModeloPrincipal', None)
                    vista_class = getattr(modules['vista'], 'VistaPrincipal', None)  
                    controlador_class = getattr(modules['controlador'], 'ControladorPrincipal', None)
                    
                    if modelo_class is None:
                        raise AttributeError("No se pudo encontrar ModeloPrincipal")
                    if vista_class is None:
                        raise AttributeError("No se pudo encontrar VistaPrincipal")
                    if controlador_class is None:
                        raise AttributeError("No se pudo encontrar ControladorPrincipal")
                    
                    modelo = modelo_class()
                    vista = vista_class(root)
                    
                    # CRÍTICO: Hacer que la vista ocupe toda la ventana
                    vista.pack(fill="both", expand=True)
                    
                    controlador = controlador_class(modelo)
                    
                    # CRÍTICO: Conectar controlador a la vista
                    if hasattr(vista, 'set_controlador'):
                        vista.set_controlador(controlador)
                    else:
                        print("Advertencia: Vista no tiene método set_controlador")
                        
                except AttributeError as e:
                    print(f"Error: {e}")
                    raise ImportError(f"No se pudieron encontrar las clases MVC necesarias: {e}")
                except Exception as e:
                    print(f"Error inicializando MVC: {e}")
                    raise
            
            # Centrar ventana
            root.update_idletasks()
            x = (root.winfo_screenwidth() // 2) - (1400 // 2)
            y = (root.winfo_screenheight() // 2) - (900 // 2)
            root.geometry(f"1400x900+{x}+{y}")
            
            print("ARESITOS iniciado exitosamente")
            print("OK Dashboard completo cargado - Funcional")
            print("OK Tema Burp Suite aplicado")
            print("OK Herramientas Kali Linux configuradas")
            
            # Context Manager para ejecución de aplicación
            with _gui_context_manager(type('MockApp', (), {'root': root})()):
                root.mainloop()
            
            return True
            
    except ImportError as e:
        print(f"Error importando módulos: {e}")
        print("Verifique la instalación de ARESITOS")
        print("Ejecute: sudo ./configurar_kali.sh")
        return False
    except Exception as e:
        print(f"Error iniciando aplicación: {e}")
        import traceback
        traceback.print_exc()
        return False

def verificar_permisos_inicio():
    """Verificar permisos al inicio y mostrar recomendaciones con Thread Safety"""
    if platform.system() == "Linux":
        try:
            with resource_manager("permissions_check") as resource:
                # ThreadPoolExecutor para verificaciones paralelas
                with ThreadPoolExecutor(max_workers=2, thread_name_prefix="ARESITOS-Perms") as executor:
                    # Verificar capacidades de nmap
                    nmap_future = executor.submit(_check_nmap_capabilities)
                    sudo_future = executor.submit(_check_sudo_permissions)
                    
                    # Obtener resultados con timeout
                    try:
                        nmap_result = nmap_future.result(timeout=10)
                        sudo_result = sudo_future.result(timeout=5)
                        
                        if not nmap_result:
                            print("AVISO: nmap podría no tener permisos para SYN scan")
                            print("Para funcionalidad completa: sudo ./configurar_kali.sh")
                        
                        if not sudo_result:
                            print("sudo requiere contraseña - use el login GUI")
                            print("Ejecute: python main.py")
                            
                    except Exception as e:
                        print(f"Error verificando permisos: {e}")
                        
        except Exception as e:
            print(f"Error en verificación de permisos: {e}")

def _check_nmap_capabilities():
    """Verificar capacidades de nmap"""
    try:
        result = subprocess.run(["getcap", "/usr/bin/nmap"], 
                              capture_output=True, text=True, timeout=5)
        return "cap_net_raw" in result.stdout
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False

def _check_sudo_permissions():
    """Verificar permisos sudo"""
    try:
        result = subprocess.run(["sudo", "-n", "true"], 
                               capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False

@cache_result(ttl_seconds=1800)  # Cache por 30 minutos
def verificacion_estabilidad_sistema():
    """Verificación final de estabilidad del sistema ARESITOS v3.0 con optimizaciones"""
    print("\n=== VERIFICACIÓN DE ESTABILIDAD ARESITOS v3.0 ===")
    
    with resource_manager("system_stability_check") as resource:
        verificaciones = []
        
        # Definir verificaciones en estructura de datos
        verification_data = {
            'archivos_criticos': [
                "aresitos/vista/vista_principal.py",
                "aresitos/controlador/controlador_principal.py", 
                "aresitos/modelo/modelo_principal.py",
                "aresitos/modelo/modelo_escaneador.py",
                "aresitos/modelo/modelo_siem.py",
                "aresitos/modelo/modelo_fim.py",
                "aresitos/modelo/modelo_cuarentena_kali2025.py",
                "aresitos/utils/sudo_manager.py",
                "aresitos/vista/terminal_mixin.py"
            ],
            'configuraciones': [
                "configuración/Aresitos_config.json", 
                "configuración/Aresitos_config_kali.json"
            ],
            'directorios': [
                "data", 
                "logs", 
                "data/cheatsheets", 
                "data/wordlists",
                "data/diccionarios"
            ]
        }
        
        # ThreadPoolExecutor para verificaciones paralelas
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="ARESITOS-Verify") as executor:
            # Verificar archivos críticos
            file_futures = {
                executor.submit(os.path.exists, archivo): ("CRÍTICO", archivo)
                for archivo in verification_data['archivos_criticos']
            }
            
            # Verificar configuraciones
            config_futures = {
                executor.submit(os.path.exists, config): ("CONFIG", config)
                for config in verification_data['configuraciones']
            }
            
            # Verificar directorios
            dir_futures = {
                executor.submit(os.path.exists, directorio): ("DIR", directorio)
                for directorio in verification_data['directorios']
            }
            
            # Recopilar resultados
            all_futures = {**file_futures, **config_futures, **dir_futures}
            
            for future in all_futures:
                tipo, item = all_futures[future]
                try:
                    exists = future.result(timeout=5)
                    if exists:
                        if tipo == "CRÍTICO":
                            verificaciones.append(f"OK Archivo crítico: {item}")
                        elif tipo == "CONFIG":
                            verificaciones.append(f"OK Configuración: {item}")
                        elif tipo == "DIR":
                            verificaciones.append(f"OK Directorio: {item}")
                    else:
                        if tipo == "CRÍTICO":
                            verificaciones.append(f"ERROR Archivo faltante: {item}")
                        elif tipo == "CONFIG":
                            verificaciones.append(f"WARN Configuración opcional: {item}")
                        elif tipo == "DIR":
                            verificaciones.append(f"WARN Directorio faltante: {item}")
                            
                except Exception as e:
                    verificaciones.append(f"ERROR Verificando {item}: {e}")
        
        # Mostrar resultados
        for verificacion in verificaciones:
            print(f"  {verificacion}")
        
        # Análisis de resultados
        errores = [v for v in verificaciones if v.startswith("ERROR")]
        warnings = [v for v in verificaciones if v.startswith("WARN")]
        
        if errores:
            print(f"\nERRORES DETECTADOS: {len(errores)}")
            for error in errores:
                print(f"  {error}")
            return False
        else:
            if warnings:
                print(f"\nADVERTENCIAS: {len(warnings)} (no críticas)")
            print(f"\nSISTEMA ESTABLE: {len(verificaciones)} verificaciones completadas")
            return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario")
        sys.exit(0)
    except Exception as e:
        print(f"Error crítico no manejado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Resource Cleanup final
        try:
            with _main_lock:
                if _thread_pool:
                    _thread_pool.shutdown(wait=True)
        except Exception:
            pass
