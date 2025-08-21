#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de verificación final de ARESITOS v2.0
Verifica que todas las correcciones se han aplicado correctamente
"""

import re
import os
import sys
import subprocess

def verificar_tokens_problemáticos():
    """Verifica que no queden tokens problemáticos"""
    print("🔍 Verificando tokens problemáticos...")
    
    pattern = r'\[(EMOJI|SCAN|STOP|METADATA|SECURE|INFO|WARNING|ERROR|SUCCESS|STATS|CONFIG|UPDATE|SAVE|LOAD|FILE|LOG|SETTINGS|QUARANTINE|UTILS|CLEAN|SYSTEM)\]'
    found_tokens = []
    
    for root, dirs, files in os.walk('aresitos'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        matches = re.findall(pattern, content)
                        if matches:
                            found_tokens.append((filepath, matches))
                except Exception as e:
                    continue
    
    if found_tokens:
        print("❌ TOKENS PROBLEMÁTICOS ENCONTRADOS:")
        for filepath, tokens in found_tokens:
            print(f"   {filepath}: {set(tokens)}")
        return False
    else:
        print("✅ Tokens problemáticos: LIMPIO")
        return True

def verificar_herramientas_modernas():
    """Verifica que se usen herramientas modernas"""
    print("🔍 Verificando uso de herramientas modernas...")
    
    herramientas_modernas = [
        'gobuster', 'feroxbuster', 'nuclei', 'httpx', 
        'linpeas', 'pspy', 'rustscan', 'masscan'
    ]
    
    herramientas_encontradas = set()
    
    for root, dirs, files in os.walk('aresitos'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                        for herramienta in herramientas_modernas:
                            if herramienta in content:
                                herramientas_encontradas.add(herramienta)
                except Exception as e:
                    continue
    
    print(f"✅ Herramientas modernas encontradas: {sorted(herramientas_encontradas)}")
    return len(herramientas_encontradas) >= 4

def verificar_importaciones():
    """Verifica que no haya importaciones problemáticas"""
    print("🔍 Verificando importaciones...")
    
    importaciones_prohibidas = ['requests', 'pandas', 'numpy', 'matplotlib']
    problemas = []
    
    for root, dirs, files in os.walk('aresitos'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for imp in importaciones_prohibidas:
                            if f'import {imp}' in content or f'from {imp}' in content:
                                problemas.append((filepath, imp))
                except Exception as e:
                    continue
    
    if problemas:
        print("❌ IMPORTACIONES PROBLEMÁTICAS:")
        for filepath, imp in problemas:
            print(f"   {filepath}: {imp}")
        return False
    else:
        print("✅ Importaciones: LIMPIO (solo stdlib)")
        return True

def verificar_sintaxis():
    """Verifica sintaxis de archivos principales"""
    print("🔍 Verificando sintaxis de archivos principales...")
    
    archivos_principales = [
        'main.py',
        'aresitos/vista/vista_principal.py',
        'aresitos/vista/vista_login.py',
        'aresitos/controlador/controlador_principal_nuevo.py'
    ]
    
    errores = []
    for archivo in archivos_principales:
        if os.path.exists(archivo):
            try:
                result = subprocess.run([
                    sys.executable, '-m', 'py_compile', archivo
                ], capture_output=True, text=True)
                if result.returncode != 0:
                    errores.append((archivo, result.stderr))
            except Exception as e:
                errores.append((archivo, str(e)))
    
    if errores:
        print("❌ ERRORES DE SINTAXIS:")
        for archivo, error in errores:
            print(f"   {archivo}: {error}")
        return False
    else:
        print("✅ Sintaxis: CORRECTA")
        return True

def verificar_estructura_archivos():
    """Verifica que existan los archivos esenciales"""
    print("🔍 Verificando estructura de archivos...")
    
    archivos_esenciales = [
        'main.py',
        'requirements.txt',
        'aresitos/__init__.py',
        'aresitos/vista/vista_principal.py',
        'aresitos/vista/vista_login.py',
        'aresitos/controlador/controlador_principal_nuevo.py',
        'aresitos/modelo/modelo_siem_kali2025.py',
        'configuración/aresitos_config.json'
    ]
    
    faltantes = []
    for archivo in archivos_esenciales:
        if not os.path.exists(archivo):
            faltantes.append(archivo)
    
    if faltantes:
        print("❌ ARCHIVOS FALTANTES:")
        for archivo in faltantes:
            print(f"   {archivo}")
        return False
    else:
        print("✅ Estructura de archivos: COMPLETA")
        return True

def main():
    """Función principal de verificación"""
    print("=" * 60)
    print("🔍 VERIFICACIÓN FINAL DE ARESITOS v2.0")
    print("=" * 60)
    
    verificaciones = [
        verificar_estructura_archivos(),
        verificar_tokens_problemáticos(),
        verificar_herramientas_modernas(),
        verificar_importaciones(),
        verificar_sintaxis()
    ]
    
    print("\n" + "=" * 60)
    print("📊 RESUMEN DE VERIFICACIÓN")
    print("=" * 60)
    
    exitosas = sum(verificaciones)
    total = len(verificaciones)
    
    if exitosas == total:
        print("🎉 ¡TODAS LAS VERIFICACIONES PASARON!")
        print("✅ ARESITOS v2.0 está listo para usar")
        print("\n📋 Para ejecutar:")
        print("   python main.py --desarrollo")
        print("   python main.py  # Para modo producción")
    else:
        print(f"⚠️  {exitosas}/{total} verificaciones pasaron")
        print("❌ Revisar los errores arriba antes de continuar")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
