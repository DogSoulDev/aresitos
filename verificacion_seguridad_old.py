#!/usr/bin/env python3
"""
ARESITOS v2.0 - Verificación de Seguridad y Sistema
==================================================

Script de verificación automática para validar que ARESITOS
esté correctamente configurado en Kali Linux.

Funciones:
- Verificar estructura de archivos del proyecto
- Validar herramientas de Kali Linux disponibles
- Comprobar permisos y configuraciones
- Verificar integridad del sistema MVC
- Generar reporte de estado del sistema

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
Versión: 2.0
Proyecto: ARESITOS - Suite de Ciberseguridad para Kali Linux
"""

import os
import sys
import subprocess
import json
import platform
from pathlib import Path
from datetime import datetime

class VerificacionSeguridad:
    """Sistema de verificación completa para ARESITOS v2.0"""
    
    def __init__(self):
        self.directorio_base = Path(__file__).parent
        self.errores = []
        self.warnings = []
        self.info = []
        self.version = "2.0.0"
        self.fecha_verificacion = datetime.now()
        
    def verificar_estructura_archivos(self):
        """Verificar que existan todos los archivos necesarios de ARESITOS v2.0"""
        print("🔍 Verificando estructura de archivos ARESITOS v2.0...")
        
        # Archivos críticos actualizados para v2.0
        archivos_criticos = [
            # Archivos principales
            "main.py",
            "requirements.txt",
            "pyproject.toml",
            ".gitignore",
            ".gitattributes",
            "configurar_kali.sh",
            
            # Controladores con nomenclatura estandarizada
            "aresitos/controlador/controlador_principal_nuevo.py",
            "aresitos/controlador/controlador_escaneo.py", 
            "aresitos/controlador/controlador_fim.py",
            "aresitos/controlador/controlador_monitoreo.py",
            "aresitos/controlador/controlador_reportes.py",
            "aresitos/controlador/controlador_siem_nuevo.py",
            "aresitos/controlador/controlador_cuarentena.py",
            "aresitos/controlador/controlador_gestor_componentes.py",
            "aresitos/controlador/controlador_gestor_configuracion.py",
            
            # Modelos con nomenclatura estandarizada
            "aresitos/modelo/modelo_escaneador_avanzado_real.py",
            "aresitos/modelo/modelo_fim.py",
            "aresitos/modelo/modelo_monitor.py",
            "aresitos/modelo/modelo_reportes.py",
            "aresitos/modelo/modelo_siem.py",
            "aresitos/modelo/modelo_cuarentena.py",
            "aresitos/modelo/modelo_constructor_wordlists.py",
            
            # Vistas
            "aresitos/vista/vista_login.py",
            "aresitos/vista/vista_principal.py",
            "aresitos/vista/vista_escaneador.py",
            "aresitos/vista/vista_fim.py",
            "aresitos/vista/vista_siem.py",
            "aresitos/vista/vista_dashboard.py",
            "aresitos/vista/vista_herramientas.py",
            
            # Utilidades
            "aresitos/utils/gestor_permisos.py",
            "aresitos/utils/ayuda_logging.py",
            "aresitos/utils/verificacion_permisos.py",
            
            # Configuración
            "configuracion/aresitos_config.json",
            "configuracion/aresitos_config_kali.json",
            "configuracion/textos_castellano_corregido.json"
        ]
        
        archivos_encontrados = 0
        archivos_faltantes = 0
        
        for archivo in archivos_criticos:
            ruta_completa = self.directorio_base / archivo
            if ruta_completa.exists():
                print(f"  ✅ {archivo}")
                archivos_encontrados += 1
            else:
                self.errores.append(f"Archivo crítico faltante: {archivo}")
                print(f"  ❌ {archivo}")
                archivos_faltantes += 1
        
        print(f"\n📊 Resumen estructura:")
        print(f"  ✅ Archivos encontrados: {archivos_encontrados}")
        print(f"  ❌ Archivos faltantes: {archivos_faltantes}")
        
        if archivos_faltantes == 0:
            self.info.append("Estructura de archivos completa")
        
        return archivos_faltantes == 0
                
    def verificar_herramientas_kali(self):
        """Verificar herramientas de Kali Linux disponibles para ARESITOS v2.0"""
        print("\n🛠️ Verificando herramientas de Kali Linux...")
        
        # Herramientas actualizadas para ARESITOS v2.0
        herramientas = {
            # Herramientas de escaneo principales
            "nmap": "Escaneo de puertos y detección de servicios",
            "masscan": "Escaneo masivo de puertos alta velocidad", 
            "nikto": "Análisis de vulnerabilidades web",
            "gobuster": "Fuzzing de directorios y archivos",
            "whatweb": "Fingerprinting de tecnologías web",
            
            # Herramientas de seguridad y análisis
            "lynis": "Auditoría completa de seguridad del sistema",
            "rkhunter": "Detección de rootkits y backdoors", 
            "chkrootkit": "Detección adicional de rootkits",
            "clamscan": "Escaneado antivirus/malware",
            
            # Herramientas de monitoreo
            "netstat": "Monitoreo de conexiones de red",
            "ss": "Información de sockets avanzada",
            "lsof": "Archivos y procesos abiertos",
            "ps": "Información de procesos",
            "tcpdump": "Captura de paquetes de red",
            
            # Herramientas del sistema
            "systemctl": "Gestión de servicios del sistema",
            "cat": "Lectura de archivos de configuración",
            "tail": "Lectura de logs en tiempo real",
            "head": "Lectura de inicio de archivos"
        }
        
        herramientas_disponibles = 0
        herramientas_faltantes = 0
        
        for herramienta, descripcion in herramientas.items():
            try:
                # Verificar si la herramienta está disponible
                result = subprocess.run(
                    ['which', herramienta], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                if result.returncode == 0:
                    print(f"  ✅ {herramienta:<15} - {descripcion}")
                    herramientas_disponibles += 1
                else:
                    print(f"  ❌ {herramienta:<15} - NO DISPONIBLE - {descripcion}")
                    self.warnings.append(f"Herramienta faltante: {herramienta}")
                    herramientas_faltantes += 1
                    
            except subprocess.TimeoutExpired:
                print(f"  ⚠️  {herramienta:<15} - TIMEOUT - {descripcion}")
                self.warnings.append(f"Timeout verificando: {herramienta}")
                herramientas_faltantes += 1
            except Exception as e:
                print(f"  ⚠️  {herramienta:<15} - ERROR: {str(e)}")
                self.warnings.append(f"Error verificando {herramienta}: {str(e)}")
                herramientas_faltantes += 1
        
        print(f"\n📊 Resumen herramientas:")
        print(f"  ✅ Disponibles: {herramientas_disponibles}")
        print(f"  ❌ Faltantes: {herramientas_faltantes}")
        
        # Verificar si estamos en Kali Linux
        self.verificar_entorno_kali()
        
        return herramientas_faltantes == 0
    
    def verificar_entorno_kali(self):
        """Verificar si estamos ejecutando en Kali Linux"""
        print("\n🐧 Verificando entorno Kali Linux...")
        
        es_kali = False
        
        # Verificar /etc/os-release
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'kali' in content:
                        es_kali = True
                        print("  ✅ Kali Linux detectado en /etc/os-release")
                    else:
                        print("  ⚠️  No es Kali Linux según /etc/os-release")
        except Exception as e:
            print(f"  ❌ Error leyendo /etc/os-release: {e}")
        
        # Verificar indicadores típicos de Kali
        indicadores_kali = [
            '/usr/share/kali-defaults',
            '/etc/kali_version',
            '/usr/bin/kali-undercover'
        ]
        
        indicadores_encontrados = 0
        for indicador in indicadores_kali:
            if os.path.exists(indicador):
                indicadores_encontrados += 1
                print(f"  ✅ Indicador Kali encontrado: {indicador}")
        
        if indicadores_encontrados > 0:
            es_kali = True
        
        # Información del sistema
        sistema = platform.system()
        version = platform.release()
        arquitectura = platform.machine()
        
        print(f"  📋 Sistema: {sistema} {version} ({arquitectura})")
        
        if es_kali:
            print("  ✅ Entorno Kali Linux confirmado")
            self.info.append("Ejecutándose en Kali Linux")
        else:
            print("  ⚠️  No se detectó Kali Linux - funcionalidad limitada")
            self.warnings.append("No se ejecuta en Kali Linux - algunas funciones pueden no estar disponibles")
        
        return es_kali
        
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
        
    def generar_reporte(self):
        """Generar reporte final de verificación"""
        print("\n" + "="*70)
        print("🎯 REPORTE DE VERIFICACIÓN DE SEGURIDAD - ARESITOS v2.0")
        print("="*70)
        
        # Información general
        print(f"📅 Fecha: {self.fecha_verificacion.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🏷️  Versión: ARESITOS {self.version}")
        print(f"💻 Sistema: {platform.system()} {platform.release()}")
        print(f"🐍 Python: {sys.version.split()[0]}")
        
        # Estadísticas
        total_errores = len(self.errores)
        total_warnings = len(self.warnings) 
        total_info = len(self.info)
        
        print(f"\n📊 ESTADÍSTICAS:")
        print(f"  ✅ Información: {total_info}")
        print(f"  ⚠️  Advertencias: {total_warnings}")
        print(f"  ❌ Errores: {total_errores}")
        
        # Estado general
        if total_errores == 0 and total_warnings == 0:
            print(f"\n🎉 ESTADO: ✅ EXCELENTE")
            print("   ARESITOS está completamente configurado y listo para usar")
        elif total_errores == 0:
            print(f"\n📋 ESTADO: ⚠️ BUENO CON ADVERTENCIAS")
            print("   ARESITOS funcionará, pero hay algunas mejoras recomendadas")
        else:
            print(f"\n🚨 ESTADO: ❌ REQUIERE ATENCIÓN")
            print("   Se encontraron errores que deben corregirse")
        
        # Detalles de errores
        if self.errores:
            print(f"\n❌ ERRORES ENCONTRADOS ({len(self.errores)}):")
            for i, error in enumerate(self.errores, 1):
                print(f"  {i}. {error}")
        
        # Detalles de advertencias  
        if self.warnings:
            print(f"\n⚠️ ADVERTENCIAS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
        
        # Información positiva
        if self.info:
            print(f"\n✅ INFORMACIÓN POSITIVA ({len(self.info)}):")
            for i, info in enumerate(self.info, 1):
                print(f"  {i}. {info}")
        
        # Recomendaciones
        print(f"\n💡 RECOMENDACIONES:")
        if total_errores > 0:
            print("  🔧 Ejecute: sudo ./configurar_kali.sh")
            print("  📦 Instale herramientas faltantes: sudo apt install <herramienta>")
        
        if total_warnings > 0:
            print("  📋 Revise las advertencias arriba")
            print("  🔍 Verifique configuraciones específicas")
        
        if total_errores == 0:
            print("  🚀 Ejecute: python3 main.py")
            print("  📖 Consulte documentación en ./documentacion/")
        
        print(f"\n🏁 Verificación completada")
        print("="*70)
        
        return total_errores == 0


def main():
    """Función principal del verificador"""
    print("🛡️ ARESITOS v2.0 - VERIFICADOR DE SEGURIDAD Y SISTEMA")
    print("=" * 65)
    print("Suite de Ciberseguridad para Kali Linux")
    print("Verificando configuración del sistema...\n")
    
    verificador = VerificacionSeguridad()
    
    try:
        # Ejecutar todas las verificaciones
        verificador.verificar_estructura_archivos()
        verificador.verificar_herramientas_kali()
        verificador.verificar_permisos()
        verificador.verificar_configuracion() 
        verificador.verificar_python_imports()
        verificador.verificar_seguridad_codigo()
        
        # Generar reporte final
        sistema_ok = verificador.generar_reporte()
        
        # Código de salida apropiado
        sys.exit(0 if sistema_ok else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Verificación interrumpida por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Error inesperado durante la verificación: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
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
