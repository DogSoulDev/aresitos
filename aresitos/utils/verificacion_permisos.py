#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Verificación de Permisos para Ares Aegis
==================================================

Este script verifica que el gestor de permisos esté funcionando
correctamente en Kali Linux y muestra un reporte detallado.

Autor: DogSoulDev
Fecha: 15 de Agosto de 2025
Versión: 1.0
"""

import sys
import os
import logging
from pathlib import Path

def configurar_logging():
    """Configurar logging para el script de verificación."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('verificacion_permisos.log')
        ]
    )
    return logging.getLogger(__name__)

def verificar_gestor_permisos():
    """Verificar que el gestor de permisos funciona correctamente."""
    logger = configurar_logging()
    
    logger.info("VERIFICANDO Iniciando verificación del gestor de permisos...")
    
    try:
        # Importar el gestor de permisos
        from aresitos.utils.gestor_permisos import GestorPermisosSeguro
        
        logger.info("[OK] Gestor de permisos importado correctamente")
        
        # Crear instancia
        gestor = GestorPermisosSeguro(logger)
        
        # Generar reporte completo
        logger.info("[REPORT] Generando reporte de permisos...")
        reporte = gestor.generar_reporte_permisos()
        
        # Mostrar reporte
        print("\n" + "="*60)
        print("[SHIELD] REPORTE DE PERMISOS ARES AEGIS")
        print("="*60)
        
        print(f"\n[USER] Usuario actual: {reporte['usuario']}")
        print(f" Es root: {'SÍ' if reporte['es_root'] else 'NO'}")
        print(f" Sudo disponible: {'SÍ' if reporte['sudo_disponible'] else 'NO'}")
        
        print(f"\n HERRAMIENTAS DE SEGURIDAD:")
        print("-" * 40)
        
        for herramienta, info in reporte['herramientas'].items():
            status_icon = "[OK]" if info['disponible'] and info['permisos_ok'] else "ERROR"
            sudo_text = " [SUDO]" if info.get('sudo_requerido', False) else ""
            
            print(f"{status_icon} {herramienta:<12} - {info['mensaje']}{sudo_text}")
            
            if info['disponible'] and info['path']:
                print(f"     Ruta: {info['path']}")
        
        if reporte['recomendaciones']:
            print(f"\n RECOMENDACIONES:")
            print("-" * 40)
            for i, rec in enumerate(reporte['recomendaciones'], 1):
                print(f"{i}. {rec}")
        
        # Realizar pruebas específicas
        print(f"\n[FORENSIC] PRUEBAS DE FUNCIONALIDAD:")
        print("-" * 40)
        
        # Prueba 1: Verificar nmap
        if 'nmap' in reporte['herramientas'] and reporte['herramientas']['nmap']['disponible']:
            logger.info("[FORENSIC] Probando ejecución de nmap...")
            exito, stdout, stderr = gestor.ejecutar_con_permisos('nmap', ['--version'])
            
            if exito:
                print("[OK] nmap ejecutado correctamente")
                version_line = stdout.split('\n')[0] if stdout else "Versión no detectada"
                print(f"    INFO {version_line}")
            else:
                print("ERROR ejecutando nmap")
                print(f"     Error: {stderr}")
        
        # Prueba 2: Verificar netstat/ss
        herramientas_red = ['ss', 'netstat']
        for herramienta in herramientas_red:
            if herramienta in reporte['herramientas'] and reporte['herramientas'][herramienta]['disponible']:
                logger.info(f"[FORENSIC] Probando ejecución de {herramienta}...")
                exito, stdout, stderr = gestor.ejecutar_con_permisos(herramienta, ['--help'])
                
                if exito:
                    print(f"OK {herramienta} ejecutado correctamente")
                else:
                    print(f"ERROR ejecutando {herramienta}")
                    print(f"     Error: {stderr}")
                break
        
        # Prueba 3: Verificar lectura de archivos del sistema
        archivos_sistema = ['/etc/passwd', '/etc/hosts']
        for archivo in archivos_sistema:
            if os.path.exists(archivo):
                logger.info(f"[FORENSIC] Probando lectura de {archivo}...")
                exito, contenido = gestor.leer_archivo_sistema(archivo)
                
                if exito:
                    lineas = len(contenido.split('\n'))
                    print(f"OK {archivo} leído correctamente ({lineas} líneas)")
                else:
                    print(f"ERROR leyendo {archivo}")
                    print(f"     Error: {contenido}")
                break
        
        print(f"\n ESTADO GENERAL:")
        print("-" * 40)
        
        herramientas_ok = sum(1 for info in reporte['herramientas'].values() 
                             if info['disponible'] and info['permisos_ok'])
        total_herramientas = len(reporte['herramientas'])
        
        if herramientas_ok == total_herramientas:
            print(" EXCELENTE: Todas las herramientas disponibles y funcionales")
        elif herramientas_ok >= total_herramientas * 0.7:
            print(" BUENO: La mayoría de herramientas están disponibles")
        else:
            print(" ATENCIÓN: Muchas herramientas no están disponibles")
        
        print(f" Funcionalidad: {herramientas_ok}/{total_herramientas} herramientas OK")
        
        # Sugerencias finales
        print(f"\n SUGERENCIAS:")
        print("-" * 40)
        
        if not reporte['es_root'] and not reporte['sudo_disponible']:
            print(" Para funcionamiento completo, ejecute:")
            print("   sudo python verificacion_permisos.py")
            print("   o configure sudo para su usuario")
        
        if herramientas_ok < total_herramientas:
            print(" Para instalar herramientas faltantes:")
            print("   sudo apt update && sudo apt install nmap netstat-nat net-tools")
        
        print(f"\nOK Verificación completada")
        logger.info("OK Verificación de permisos completada exitosamente")
        
        return True
        
    except ImportError as e:
        logger.error(f"ERROR importando gestor de permisos: {e}")
        print("ERROR: No se pudo importar el gestor de permisos")
        print("   Asegúrese de que el módulo esté correctamente instalado")
        return False
        
    except Exception as e:
        logger.error(f"ERROR inesperado: {e}")
        print(f"ERROR inesperado: {e}")
        return False

if __name__ == "__main__":
    print(" Ares Aegis - Verificación de Permisos")
    print("=" * 50)
    
    exito = verificar_gestor_permisos()
    
    print("\n" + "="*50)
    
    exit_code = 0 if exito else 1
    sys.exit(exit_code)

