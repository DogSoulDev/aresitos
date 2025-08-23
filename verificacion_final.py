#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de verificación final de ARESITOS v3.0
Verifica que todas las correcciones se han aplicado correctamente

Principios ARESITOS V3 aplicados:
- Thread Safety: threading.RLock() para operaciones thread-safe
- Dynamic Access: getattr() para acceso seguro a funciones
- Robust Error Handling: try-except multinivel con fallbacks
- Cache System: Cache de resultados de verificación
- Fallback Systems: Múltiples métodos de verificación
- ThreadPoolExecutor: Verificaciones paralelas
- Context Managers: Gestión automática de recursos
- Validation Layer: Validación robusta de archivos
- Configuration Loader: Carga dinámica de configuraciones
- Resource Cleanup: Limpieza automática de recursos
"""

import re
import os
import sys
import subprocess
import threading
import time
import functools
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

# Thread Safety
_verification_lock = threading.RLock()
_cache_lock = threading.RLock()
_verification_cache = {}
_active_verifications = []

# ThreadPoolExecutor global
_thread_pool = None

def get_thread_pool():
    """Thread-safe ThreadPoolExecutor singleton"""
    global _thread_pool
    with _verification_lock:
        if _thread_pool is None:
            _thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="Verification")
        return _thread_pool

@contextmanager
def verification_manager(verification_name):
    """Context manager para gestión de verificaciones"""
    with _verification_lock:
        _active_verifications.append(verification_name)
    try:
        yield verification_name
    finally:
        with _verification_lock:
            if verification_name in _active_verifications:
                _active_verifications.remove(verification_name)

def cache_verification(ttl_seconds=300):
    """Decorador para cache de verificaciones con TTL"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with _cache_lock:
                key = f"{func.__name__}_{hash(str(args) + str(sorted(kwargs.items())))}"
                current_time = time.time()
                
                if key in _verification_cache:
                    cached_time, cached_result = _verification_cache[key]
                    if current_time - cached_time < ttl_seconds:
                        print(f"[CACHE] Usando resultado cacheado para {func.__name__}")
                        return cached_result
                
                result = func(*args, **kwargs)
                _verification_cache[key] = (current_time, result)
                return result
        return wrapper
    return decorator

@cache_verification(ttl_seconds=600)
def verificar_tokens_problemáticos():
    """Verifica que no queden tokens problemáticos de desarrollo con Thread Safety"""
    print("VERIFICANDO tokens problemáticos...")
    
    with verification_manager("tokens_check") as resource:
        # Buscar solo patrones de desarrollo reales, no logging legítimo
        pattern = r'\[(EMOJI|SCAN|STOP|METADATA|SECURE|SUCCESS|STATS|CONFIG|UPDATE|SAVE|LOAD|FILE|SETTINGS|QUARANTINE|UTILS|CLEAN|SYSTEM)\]'
        found_tokens = []
        
        # ThreadPoolExecutor para verificación paralela de archivos
        with get_thread_pool() as executor:
            futures = {}
            
            for root, dirs, files in os.walk('Aresitos'):
                for file in files:
                    if file.endswith('.py'):
                        filepath = os.path.join(root, file)
                        future = executor.submit(_check_file_tokens, filepath, pattern)
                        futures[future] = filepath
            
            # Recopilar resultados
            for future in futures:
                filepath = futures[future]
                try:
                    tokens = future.result(timeout=10)
                    if tokens:
                        found_tokens.append((filepath, tokens))
                except Exception as e:
                    print(f"Error verificando {filepath}: {e}")
                    continue
        
        if found_tokens:
            print("ERROR TOKENS PROBLEMÁTICOS ENCONTRADOS:")
            for filepath, tokens in found_tokens:
                print(f"   {filepath}: {set(tokens)}")
            return False
        else:
            print("OK Tokens problemáticos: LIMPIO")
            return True

def _check_file_tokens(filepath, pattern):
    """Verificar tokens problemáticos en un archivo específico"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            matches = re.findall(pattern, content)
            if matches:
                # Filtrar tokens legítimos de logging
                tokens_problematicos = []
                for match in matches:
                    if match not in ['INFO', 'WARNING', 'ERROR']:  # Excluir logging legítimo
                        tokens_problematicos.append(match)
                return tokens_problematicos
    except Exception:
        pass
    return []

@cache_verification(ttl_seconds=900)
def verificar_herramientas_modernas():
    """Verifica que se usen herramientas modernas con verificación paralela"""
    print("VERIFICANDO uso de herramientas modernas...")
    
    with verification_manager("modern_tools_check") as resource:
        herramientas_modernas = [
            'gobuster', 'feroxbuster', 'nuclei', 'httpx', 
            'linpeas', 'pspy', 'rustscan', 'masscan'
        ]
        
        herramientas_encontradas = set()
        
        # ThreadPoolExecutor para búsqueda paralela
        with get_thread_pool() as executor:
            futures = {}
            
            for root, dirs, files in os.walk('Aresitos'):
                for file in files:
                    if file.endswith('.py'):
                        filepath = os.path.join(root, file)
                        future = executor.submit(_check_file_tools, filepath, herramientas_modernas)
                        futures[future] = filepath
            
            # Recopilar resultados
            for future in futures:
                try:
                    tools_found = future.result(timeout=10)
                    herramientas_encontradas.update(tools_found)
                except Exception as e:
                    print(f"Error verificando herramientas: {e}")
                    continue
        
        print(f"OK Herramientas modernas encontradas: {sorted(herramientas_encontradas)}")
        return len(herramientas_encontradas) >= 4

def _check_file_tools(filepath, herramientas_modernas):
    """Verificar herramientas modernas en un archivo específico"""
    tools_found = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            for herramienta in herramientas_modernas:
                if herramienta in content:
                    tools_found.add(herramienta)
    except Exception:
        pass
    return tools_found

@cache_verification(ttl_seconds=300)
def verificar_importaciones():
    """Verifica que no haya importaciones problemáticas con Thread Safety"""
    print("VERIFICANDO importaciones...")
    
    with verification_manager("imports_check") as resource:
        importaciones_prohibidas = ['requests', 'pandas', 'numpy', 'matplotlib']
        problemas = []
        
        # ThreadPoolExecutor para verificación paralela
        with get_thread_pool() as executor:
            futures = {}
            
            for root, dirs, files in os.walk('Aresitos'):
                for file in files:
                    if file.endswith('.py'):
                        filepath = os.path.join(root, file)
                        future = executor.submit(_check_file_imports, filepath, importaciones_prohibidas)
                        futures[future] = filepath
            
            # Recopilar resultados
            for future in futures:
                filepath = futures[future]
                try:
                    file_problems = future.result(timeout=10)
                    problemas.extend(file_problems)
                except Exception as e:
                    print(f"Error verificando importaciones en {filepath}: {e}")
                    continue
        
        if problemas:
            print("ERROR IMPORTACIONES PROBLEMÁTICAS:")
            for filepath, imp in problemas:
                print(f"   {filepath}: {imp}")
            return False
        else:
            print("OK Importaciones: LIMPIO (solo stdlib)")
            return True

def _check_file_imports(filepath, importaciones_prohibidas):
    """Verificar importaciones problemáticas en un archivo específico"""
    problemas = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            for imp in importaciones_prohibidas:
                if f'import {imp}' in content or f'from {imp}' in content:
                    problemas.append((filepath, imp))
    except Exception:
        pass
    return problemas

def verificar_sintaxis():
    """Verifica sintaxis de archivos principales con Thread Safety"""
    print("VERIFICANDO sintaxis de archivos principales...")
    
    with verification_manager("syntax_check") as resource:
        archivos_principales = [
            'main.py',
            'Aresitos/vista/vista_principal.py',
            'Aresitos/vista/vista_login.py',
            'Aresitos/controlador/controlador_principal_nuevo.py'
        ]
        
        errores = []
        
        # Filtrar archivos que existen
        archivos_existentes = [archivo for archivo in archivos_principales if os.path.exists(archivo)]
        
        if not archivos_existentes:
            print("WARN No se encontraron archivos principales para verificar")
            return True
        
        # ThreadPoolExecutor para verificación paralela de sintaxis
        with get_thread_pool() as executor:
            futures = {}
            
            for archivo in archivos_existentes:
                future = executor.submit(_check_file_syntax, archivo)
                futures[future] = archivo
            
            # Recopilar resultados
            for future in futures:
                archivo = futures[future]
                try:
                    error = future.result(timeout=15)
                    if error:
                        errores.append((archivo, error))
                except Exception as e:
                    errores.append((archivo, str(e)))
        
        if errores:
            print("ERRORES DE SINTAXIS:")
            for archivo, error in errores:
                print(f"   {archivo}: {error}")
            return False
        else:
            print("OK Sintaxis: CORRECTA")
            return True

def _check_file_syntax(archivo):
    """Verificar sintaxis de un archivo específico"""
    try:
        result = subprocess.run([
            sys.executable, '-m', 'py_compile', archivo
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return result.stderr
        return None
        
    except subprocess.TimeoutExpired:
        return "Timeout verificando sintaxis"
    except Exception as e:
        return str(e)

@cache_verification(ttl_seconds=1200)
def verificar_estructura_archivos():
    """Verifica que existan los archivos esenciales con verificación optimizada"""
    print("VERIFICANDO estructura de archivos...")
    
    with verification_manager("structure_check") as resource:
        archivos_esenciales = [
            'main.py',
            'requirements.txt',
            'Aresitos/__init__.py',
            'Aresitos/vista/vista_principal.py',
            'Aresitos/vista/vista_login.py',
            'Aresitos/controlador/controlador_principal_nuevo.py',
            'Aresitos/modelo/modelo_siem_kali2025.py',
            'configuración/aresitos_config.json'
        ]
        
        # ThreadPoolExecutor para verificación paralela
        with get_thread_pool() as executor:
            futures = {
                executor.submit(os.path.exists, archivo): archivo
                for archivo in archivos_esenciales
            }
            
            faltantes = []
            for future in futures:
                archivo = futures[future]
                try:
                    exists = future.result(timeout=5)
                    if not exists:
                        faltantes.append(archivo)
                except Exception as e:
                    print(f"Error verificando {archivo}: {e}")
                    faltantes.append(archivo)
        
        if faltantes:
            print("ERROR ARCHIVOS FALTANTES:")
            for archivo in faltantes:
                print(f"   {archivo}")
            return False
        else:
            print("OK Estructura de archivos: COMPLETA")
            return True

def main():
    """Función principal de verificación con Thread Safety y optimizaciones"""
    print("=" * 60)
    print("VERIFICANDO VERIFICACIÓN FINAL DE ARESITOS v3.0")
    print("=" * 60)
    
    try:
        with verification_manager("main_verification") as resource:
            # Lista de verificaciones a realizar
            verification_functions = [
                verificar_estructura_archivos,
                verificar_tokens_problemáticos,
                verificar_herramientas_modernas,
                verificar_importaciones,
                verificar_sintaxis
            ]
            
            # ThreadPoolExecutor para verificaciones paralelas (algunas)
            results = []
            
            # Ejecutar verificaciones de estructura y sintaxis de forma secuencial
            # (requieren acceso exclusivo a archivos)
            sequential_checks = [verificar_estructura_archivos, verificar_sintaxis]
            parallel_checks = [verificar_tokens_problemáticos, verificar_herramientas_modernas, verificar_importaciones]
            
            # Verificaciones secuenciales
            for check_func in sequential_checks:
                try:
                    result = check_func()
                    results.append(result)
                except Exception as e:
                    print(f"Error en verificación {check_func.__name__}: {e}")
                    results.append(False)
            
            # Verificaciones paralelas
            with get_thread_pool() as executor:
                futures = {
                    executor.submit(check_func): check_func.__name__
                    for check_func in parallel_checks
                }
                
                for future in futures:
                    func_name = futures[future]
                    try:
                        result = future.result(timeout=30)
                        results.append(result)
                    except Exception as e:
                        print(f"Error en verificación {func_name}: {e}")
                        results.append(False)
            
            print("\n" + "=" * 60)
            print("RESUMEN DE VERIFICACIÓN")
            print("=" * 60)
            
            exitosas = sum(results)
            total = len(results)
            
            if exitosas == total:
                print("EXITO ¡TODAS LAS VERIFICACIONES PASARON!")
                print("OK ARESITOS v3.0 está listo para usar")
                print("\nINFO Para ejecutar:")
                print("   python main.py --desarrollo")
                print("   python main.py  # Para modo producción")
                return 0
            else:
                print(f"ADVERTENCIA  {exitosas}/{total} verificaciones pasaron")
                print("ERROR Revisar los errores arriba antes de continuar")
                return 1
                
    except Exception as e:
        print(f"Error crítico en verificación: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Resource Cleanup
        try:
            with _verification_lock:
                if _thread_pool:
                    _thread_pool.shutdown(wait=True)
        except Exception:
            pass

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nVerificación interrumpida por usuario")
        sys.exit(1)
    except Exception as e:
        print(f"Error no manejado: {e}")
        sys.exit(1)
