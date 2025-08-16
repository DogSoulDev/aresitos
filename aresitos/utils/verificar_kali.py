#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ares Aegis - Verificador de Compatibilidad Kali Linux
Este script verifica si el sistema está correctamente preparado para Kali Linux
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

def verificar_compatibilidad_kali():
    """
    Verificar compatibilidad completa con Kali Linux
    """
    print("🔍 VERIFICACIÓN DE COMPATIBILIDAD KALI LINUX")
    print("=" * 60)
    
    resultados = {
        'sistema_operativo': False,
        'herramientas_core': [],
        'herramientas_faltantes': [],
        'permisos': False,
        'sudo_disponible': False,
        'es_root': False
    }
    
    # 1. Verificar sistema operativo
    print("\n1️⃣ VERIFICACIÓN DEL SISTEMA OPERATIVO")
    print("-" * 40)
    
    sistema = platform.system()
    print(f"🖥️  Sistema detectado: {sistema}")
    
    if sistema == "Linux":
        print("✅ Sistema Linux detectado")
        resultados['sistema_operativo'] = True
        
        # Verificar si es Kali específicamente
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    os_info = f.read()
                    if 'kali' in os_info.lower():
                        print("🎯 Kali Linux detectado específicamente")
                    else:
                        print("📝 Linux genérico (compatible)")
        except:
            pass
    else:
        print("⚠️  No es un sistema Linux")
        print("💡 Ares Aegis está optimizado para Kali Linux")
    
    # 2. Verificar herramientas de Kali
    print("\n2️⃣ VERIFICACIÓN DE HERRAMIENTAS KALI")
    print("-" * 40)
    
    herramientas_kali = {
        'Escaneo': ['nmap', 'masscan', 'nikto'],
        'Análisis': ['netstat', 'ss', 'tcpdump'],
        'Auditoría': ['lynis', 'rkhunter', 'chkrootkit'],
        'Sistema': ['find', 'stat', 'md5sum', 'grep', 'tail'],
        'Básicas': ['cat', 'ls', 'ps', 'which']
    }
    
    for categoria, herramientas in herramientas_kali.items():
        print(f"\n📁 {categoria}:")
        for herramienta in herramientas:
            try:
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, 
                                         text=True, 
                                         timeout=3)
                if resultado.returncode == 0:
                    print(f"  ✅ {herramienta}: {resultado.stdout.strip()}")
                    resultados['herramientas_core'].append(herramienta)
                else:
                    print(f"  ❌ {herramienta}: No encontrado")
                    resultados['herramientas_faltantes'].append(herramienta)
            except:
                print(f"  ❌ {herramienta}: Error verificando")
                resultados['herramientas_faltantes'].append(herramienta)
    
    # 3. Verificar permisos
    print("\n3️⃣ VERIFICACIÓN DE PERMISOS")
    print("-" * 40)
    
    # Verificar si es root
    try:
        import getpass
        usuario = getpass.getuser()
        
        # Verificar root de manera compatible con diferentes sistemas
        es_root = usuario == 'root'
        
        resultados['es_root'] = es_root
        
        print(f"👤 Usuario actual: {usuario}")
        print(f"🔑 Es root: {'✅ Sí' if es_root else '❌ No'}")
        
    except:
        print("❌ Error verificando usuario")
    
    # Verificar sudo
    try:
        resultado_sudo = subprocess.run(['sudo', '-n', 'true'], 
                                       capture_output=True, 
                                       timeout=5)
        sudo_ok = resultado_sudo.returncode == 0
        resultados['sudo_disponible'] = sudo_ok
        
        print(f"⚡ Sudo disponible: {'✅ Sí' if sudo_ok else '❌ No'}")
        
    except:
        print("❌ Sudo no disponible")
    
    # 4. Verificar estructura de proyecto
    print("\n4️⃣ VERIFICACIÓN ESTRUCTURA PROYECTO")
    print("-" * 40)
    
    archivos_criticos = [
        'login.py',
        'main.py',
        'aresitos/utils/gestor_permisos.py',
        'aresitos/controlador/controlador_principal.py',
        'configurar_kali.sh'
    ]
    
    for archivo in archivos_criticos:
        if os.path.exists(archivo):
            print(f"  ✅ {archivo}")
        else:
            print(f"  ❌ {archivo}: Faltante")
    
    # 5. Resumen final
    print("\n5️⃣ RESUMEN DE COMPATIBILIDAD")
    print("-" * 40)
    
    total_herramientas = len(resultados['herramientas_core']) + len(resultados['herramientas_faltantes'])
    porcentaje_herramientas = (len(resultados['herramientas_core']) / total_herramientas * 100) if total_herramientas > 0 else 0
    
    print(f"🖥️  Sistema Linux: {'✅' if resultados['sistema_operativo'] else '❌'}")
    print(f"🔧 Herramientas: {len(resultados['herramientas_core'])}/{total_herramientas} ({porcentaje_herramientas:.1f}%)")
    print(f"🔑 Permisos: {'✅' if resultados['es_root'] or resultados['sudo_disponible'] else '❌'}")
    
    # Determinar nivel de preparación
    if resultados['sistema_operativo'] and porcentaje_herramientas >= 70 and (resultados['es_root'] or resultados['sudo_disponible']):
        print("\n🎉 SISTEMA LISTO PARA KALI LINUX")
        print("✅ Ares Aegis puede ejecutarse con funcionalidad completa")
    elif resultados['sistema_operativo'] and porcentaje_herramientas >= 50:
        print("\n⚠️  SISTEMA PARCIALMENTE PREPARADO")
        print("💡 Algunas funcionalidades estarán limitadas")
    else:
        print("\n❌ SISTEMA NO PREPARADO")
        print("🔧 Se requiere configuración adicional")
    
    # 6. Recomendaciones
    print("\n6️⃣ RECOMENDACIONES")
    print("-" * 40)
    
    if not resultados['sistema_operativo']:
        print("🐧 Usar Kali Linux o distribución Linux compatible")
    
    if not (resultados['es_root'] or resultados['sudo_disponible']):
        print("🔑 Configurar sudo o ejecutar como root")
    
    if resultados['herramientas_faltantes']:
        print("🛠️  Instalar herramientas faltantes:")
        if sistema == "Linux":
            print("   apt update && apt install -y \\")
            herramientas_install = ' '.join(resultados['herramientas_faltantes'][:10])  # Límite de 10
            print(f"     {herramientas_install}")
    
    print("\n🚀 Para configuración automática, ejecute:")
    print("   sudo bash configurar_kali.sh")
    
    return resultados

def main():
    """Función principal"""
    try:
        resultados = verificar_compatibilidad_kali()
        return 0 if resultados['sistema_operativo'] else 1
    except KeyboardInterrupt:
        print("\n\n👋 Verificación cancelada por el usuario")
        return 1
    except Exception as e:
        print(f"\n❌ Error durante verificación: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
