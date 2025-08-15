#!/usr/bin/env python3
"""
ARESITOS 7.0 BETA - Script de Diagnóstico
==========================================
Script para verificar que todas las dependencias estén correctamente instaladas.
Ejecutar dentro del entorno virtual activado.

Uso: python diagnostico.py
"""

import sys
import os
import platform
from pathlib import Path

def verificar_python():
    """Verificar versión de Python."""
    version = sys.version_info
    print(f"🐍 Python: {version.major}.{version.minor}.{version.micro}")
    
    if version.major == 3 and version.minor >= 8:
        print("  ✅ Versión de Python compatible")
        return True
    else:
        print("  ❌ Versión de Python no compatible (requiere 3.8+)")
        return False

def verificar_entorno_virtual():
    """Verificar si está en entorno virtual."""
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    if in_venv:
        print("🔒 Entorno Virtual: ✅ Activo")
        return True
    else:
        print("🔒 Entorno Virtual: ⚠️  No detectado")
        if platform.system() == "Linux" and "kali" in platform.release().lower():
            print("  ⚠️  Recomendado usar entorno virtual en Kali Linux")
        return False

def verificar_modulo(nombre_modulo, nombre_display=None):
    """Verificar si un módulo está instalado."""
    if nombre_display is None:
        nombre_display = nombre_modulo
    
    try:
        __import__(nombre_modulo)
        print(f"📦 {nombre_display}: ✅ Instalado")
        return True
    except ImportError:
        print(f"📦 {nombre_display}: ❌ No encontrado")
        return False

def verificar_estructura_proyecto():
    """Verificar estructura de directorios del proyecto."""
    directorios_requeridos = [
        "ares_aegis",
        "data/wordlists",
        "data/diccionarios", 
        "configuracion",
        "ares_aegis/recursos"
    ]
    
    print("📁 Estructura del Proyecto:")
    todos_ok = True
    
    for directorio in directorios_requeridos:
        if Path(directorio).exists():
            print(f"  ✅ {directorio}")
        else:
            print(f"  ❌ {directorio}")
            todos_ok = False
    
    return todos_ok

def verificar_icono():
    """Verificar el archivo de icono."""
    ruta_icono = Path("ares_aegis/recursos/Aresitos.ico")
    
    if ruta_icono.exists():
        print("🎨 Icono: ✅ Encontrado")
        
        # Verificar si PIL está disponible para conversión en Linux
        if platform.system() == "Linux":
            try:
                # Intentar importar PIL usando el método verificar_modulo
                pil_disponible = verificar_modulo("PIL", None)
                if pil_disponible:
                    print("  ✅ PIL disponible para conversión de iconos")
                    return True
                else:
                    print("  ⚠️  PIL no disponible, el icono podría no mostrarse en Linux")
                    print("    💡 Instalar con: pip install Pillow")
                    return False
            except Exception:
                print("  ⚠️  PIL no disponible, el icono podría no mostrarse en Linux")
                print("    💡 Instalar con: pip install Pillow")
                return False
        return True
    else:
        print("🎨 Icono: ❌ No encontrado")
        return False

def verificar_herramientas_sistema():
    """Verificar herramientas del sistema (opcional)."""
    herramientas = ["nmap", "python3", "netstat", "ss"]
    
    print("🛠️  Herramientas del Sistema:")
    for herramienta in herramientas:
        try:
            import subprocess
            # Usar 'where' en Windows, 'which' en Unix
            comando = "where" if platform.system() == "Windows" else "which"
            result = subprocess.run([comando, herramienta], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"  ✅ {herramienta}")
            else:
                print(f"  ⚠️  {herramienta} no encontrado")
        except Exception:
            print(f"  ❓ {herramienta} (no se pudo verificar)")

def verificar_gestor_permisos():
    """Verificar si el gestor de permisos está disponible."""
    print("\n🔐 GESTOR DE PERMISOS:")
    try:
        from ares_aegis.utils.gestor_permisos import GestorPermisosSeguro
        gestor = GestorPermisosSeguro()
        
        print("  ✅ Gestor de permisos importado correctamente")
        
        # Verificar sudo en sistemas Unix
        if platform.system() != "Windows":
            if gestor.verificar_sudo_disponible():
                print("  ✅ sudo disponible y configurado")
            else:
                print("  ⚠️  sudo no disponible o requiere contraseña")
                print("    💡 Ejecutar: sudo ./configurar_kali.sh")
        
        return True
    except ImportError:
        print("  ❌ Gestor de permisos no encontrado")
        print("    💡 Verificar que ares_aegis/utils/gestor_permisos.py existe")
        return False
    except Exception as e:
        print(f"  ❌ Error inicializando gestor de permisos: {e}")
        return False

def main():
    """Función principal de diagnóstico."""
    print("🔱 ARESITOS 7.0 BETA - DIAGNÓSTICO DEL SISTEMA")
    print("=" * 50)
    print(f"💻 Sistema Operativo: {platform.system()} {platform.release()}")
    print(f"🏗️  Arquitectura: {platform.architecture()[0]}")
    print()
    
    resultados = []
    
    # Verificaciones críticas
    resultados.append(verificar_python())
    resultados.append(verificar_entorno_virtual())
    
    print("\n📋 DEPENDENCIAS PYTHON:")
    modulos_criticos = [
        ("tkinter", "tkinter (GUI)"),
        ("customtkinter", "CustomTkinter"),
        ("requests", "Requests"),
        ("psutil", "PSUtil"),
        ("pandas", "Pandas"),
        ("matplotlib", "Matplotlib"),
        ("PIL", "Pillow/PIL"),
        ("colorlog", "ColorLog"),
        ("watchdog", "Watchdog")
    ]
    
    for modulo, display in modulos_criticos:
        resultados.append(verificar_modulo(modulo, display))
    
    print("\n📂 VERIFICACIONES DEL PROYECTO:")
    resultados.append(verificar_estructura_proyecto())
    verificar_icono()
    
    print("\n🔧 HERRAMIENTAS OPCIONALES:")
    verificar_herramientas_sistema()
    
    print("\n🔐 VERIFICACIONES DE SEGURIDAD:")
    gestor_ok = verificar_gestor_permisos()
    
    # Resumen final
    print("\n" + "=" * 50)
    criticos_ok = sum(resultados)
    total_criticos = len(resultados)
    
    if criticos_ok == total_criticos:
        print("🎉 DIAGNÓSTICO: ✅ TODOS LOS COMPONENTES OK")
        print("🚀 Aresitos debería ejecutarse correctamente")
    elif criticos_ok >= total_criticos * 0.8:
        print("⚠️  DIAGNÓSTICO: 🟨 COMPONENTES MAYORMENTE OK")
        print("🔧 Algunos componentes opcionales faltan, pero Aresitos debería funcionar")
    else:
        print("❌ DIAGNÓSTICO: 🔴 FALTAN COMPONENTES CRÍTICOS")
        print("🛠️  Instalar dependencias faltantes antes de ejecutar Aresitos")
    
    print(f"📊 Puntuación: {criticos_ok}/{total_criticos} componentes OK")
    
    if platform.system() == "Linux":
        print("\n💡 CONSEJOS PARA LINUX:")
        print("  • Usar siempre entorno virtual en Kali Linux 2024+")
        print("  • sudo apt install -y python3-tk python3-dev")
        print("  • pip install -r requirements.txt")
        
        if "kali" in platform.release().lower():
            print("\n🔱 ESPECÍFICO PARA KALI LINUX:")
            print("  • Ejecutar: sudo ./configurar_kali.sh")
            print("  • Verificar: python3 verificacion_permisos.py")
            print("  • Para permisos completos: sudo python3 main.py")

if __name__ == "__main__":
    main()
