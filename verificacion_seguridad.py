#!/usr/bin/env python3
"""
ARESITOS - Verificación de Seguridad y Sistema
Script de verificación automática para Kali Linux
"""

import os
import sys
import subprocess
import json
from pathlib import Path

class VerificacionSeguridad:
    def __init__(self):
        self.directorio_base = Path(__file__).parent
        self.errores = []
        self.warnings = []
        self.info = []
        
    def verificar_estructura_archivos(self):
        """Verificar que existan todos los archivos necesarios"""
        print("Verificando estructura de archivos...")
        
        archivos_criticos = [
            "main.py",
            "aresitos/controlador/controlador_principal.py",
            "aresitos/controlador/controlador_escaneo.py", 
            "aresitos/controlador/controlador_auditoria.py",
            "aresitos/controlador/controlador_reportes.py",
            "aresitos/vista/vista_principal.py",
            "aresitos/modelo/escaneador_avanzado.py",
            "configuracion/aresitos_config.json"
        ]
        
        for archivo in archivos_criticos:
            ruta_completa = self.directorio_base / archivo
            if ruta_completa.exists():
                print(f"✓ {archivo}")
            else:
                self.errores.append(f"Archivo faltante: {archivo}")
                print(f"✗ {archivo}")
                
    def verificar_herramientas_kali(self):
        """Verificar herramientas de Kali Linux disponibles"""
        print("\nVerificando herramientas de Kali Linux...")
        
        herramientas = [
            "nmap", "masscan", "nikto", "lynis", "rkhunter", 
            "chkrootkit", "john", "hashcat", "hydra", "sqlmap",
            "metasploit-framework", "netstat", "ss", "ps"
        ]
        
        instaladas = 0
        for herramienta in herramientas:
            try:
                result = subprocess.run(['which', herramienta], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    print(f"✓ {herramienta}")
                    instaladas += 1
                else:
                    print(f"✗ {herramienta} (no instalada)")
                    self.warnings.append(f"Herramienta no encontrada: {herramienta}")
            except Exception as e:
                print(f"? {herramienta} (error verificando)")
                
        print(f"\nHerramientas encontradas: {instaladas}/{len(herramientas)}")
        
    def verificar_permisos(self):
        """Verificar permisos de archivos y directorios"""
        print("\nVerificando permisos...")
        
        directorios = ["data", "configuracion", "logs"]
        for directorio in directorios:
            ruta = self.directorio_base / directorio
            if ruta.exists():
                if os.access(ruta, os.R_OK | os.W_OK):
                    print(f"✓ {directorio} (lectura/escritura)")
                else:
                    print(f"✗ {directorio} (sin permisos)")
                    self.errores.append(f"Permisos insuficientes: {directorio}")
            else:
                print(f"? {directorio} (no existe)")
                
    def verificar_configuracion(self):
        """Verificar archivos de configuración"""
        print("\nVerificando configuración...")
        
        config_files = [
            "configuracion/aresitos_config.json",
            "configuracion/aresitos_config_kali.json"
        ]
        
        for config_file in config_files:
            ruta = self.directorio_base / config_file
            if ruta.exists():
                try:
                    with open(ruta, 'r', encoding='utf-8') as f:
                        json.load(f)
                    print(f"✓ {config_file} (válido)")
                except json.JSONDecodeError:
                    print(f"✗ {config_file} (JSON inválido)")
                    self.errores.append(f"JSON inválido: {config_file}")
            else:
                print(f"✗ {config_file} (no encontrado)")
                self.warnings.append(f"Configuración faltante: {config_file}")
                
    def verificar_python_imports(self):
        """Verificar que se puedan importar los módulos necesarios"""
        print("\nVerificando imports de Python...")
        
        imports = [
            ("tkinter", "Interfaz gráfica"),
            ("psutil", "Información del sistema"),
            ("subprocess", "Ejecución de comandos"),
            ("threading", "Concurrencia"),
            ("json", "Configuración"),
            ("pathlib", "Rutas de archivos")
        ]
        
        for modulo, descripcion in imports:
            try:
                __import__(modulo)
                print(f"✓ {modulo} ({descripcion})")
            except ImportError:
                print(f"✗ {modulo} ({descripcion})")
                self.errores.append(f"Módulo faltante: {modulo}")
                
    def verificar_seguridad_codigo(self):
        """Verificar que no haya vulnerabilidades de seguridad conocidas"""
        print("\nVerificando seguridad del código...")
        
        # Buscar subprocess con shell=True (vulnerabilidad)
        try:
            result = subprocess.run(['grep', '-r', 'shell=True', 'aresitos/'], 
                                  capture_output=True, text=True, cwd=self.directorio_base)
            if result.returncode == 0:
                print("✗ Encontradas vulnerabilidades subprocess shell=True")
                self.errores.append("Vulnerabilidades subprocess encontradas")
            else:
                print("✓ Sin vulnerabilidades subprocess shell=True")
        except:
            print("? No se pudo verificar vulnerabilidades subprocess")
            
        # Buscar permisos 777 (inseguro)
        try:
            result = subprocess.run(['grep', '-r', '777', 'aresitos/'], 
                                  capture_output=True, text=True, cwd=self.directorio_base)
            if result.returncode == 0:
                print("✗ Encontrados permisos inseguros 777")
                self.errores.append("Permisos inseguros 777 encontrados")
            else:
                print("✓ Sin permisos inseguros 777")
        except:
            print("? No se pudo verificar permisos inseguros")
            
    def generar_reporte(self):
        """Generar reporte final"""
        print("\n" + "="*60)
        print("REPORTE DE VERIFICACIÓN DE SEGURIDAD")
        print("="*60)
        
        if not self.errores and not self.warnings:
            print("✅ SISTEMA VERIFICADO CORRECTAMENTE")
            print("Aresitos está listo para usar en Kali Linux")
        else:
            if self.errores:
                print(f"\n❌ ERRORES CRÍTICOS ({len(self.errores)}):")
                for error in self.errores:
                    print(f"  • {error}")
                    
            if self.warnings:
                print(f"\n⚠️  ADVERTENCIAS ({len(self.warnings)}):")
                for warning in self.warnings:
                    print(f"  • {warning}")
                    
        print("\n" + "="*60)
        
        # Código de salida
        if self.errores:
            return 1
        elif self.warnings:
            return 2  
        else:
            return 0

def main():
    print("ARESITOS - Verificación de Seguridad y Sistema")
    print("="*60)
    
    verificador = VerificacionSeguridad()
    
    verificador.verificar_estructura_archivos()
    verificador.verificar_herramientas_kali()
    verificador.verificar_permisos()
    verificador.verificar_configuracion()
    verificador.verificar_python_imports()
    verificador.verificar_seguridad_codigo()
    
    codigo_salida = verificador.generar_reporte()
    sys.exit(codigo_salida)

if __name__ == "__main__":
    main()
