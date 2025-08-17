#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS - Verificación de Optimización para Kali Linux
Versión: 2.0.0-kali-optimized
Autor: Equipo ARESITOS

Script para verificar que todas las optimizaciones específicas de Kali Linux
están funcionando correctamente en el sistema ARESITOS.
"""

import os
import sys
import subprocess
import importlib.util
import json
from pathlib import Path

class VerificadorOptimizacionKali:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.errores = []
        self.warnings = []
        self.exitosos = []
        
    def log_error(self, mensaje):
        self.errores.append(f"❌ ERROR: {mensaje}")
        print(f"❌ ERROR: {mensaje}")
    
    def log_warning(self, mensaje):
        self.warnings.append(f"⚠️ WARNING: {mensaje}")
        print(f"⚠️ WARNING: {mensaje}")
    
    def log_success(self, mensaje):
        self.exitosos.append(f"✅ SUCCESS: {mensaje}")
        print(f"✅ SUCCESS: {mensaje}")
        
    def verificar_sistema_kali(self):
        """Verificar que estamos ejecutando en Kali Linux"""
        print("\n🔍 VERIFICANDO SISTEMA KALI LINUX...")
        
        try:
            # Verificar /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    contenido = f.read().lower()
                    if 'kali' in contenido:
                        self.log_success("Sistema Kali Linux detectado correctamente")
                        return True
                    else:
                        self.log_warning("Sistema no detectado como Kali Linux")
                        return False
            else:
                self.log_warning("Archivo /etc/os-release no encontrado")
                return False
                
        except Exception as e:
            self.log_error(f"Error verificando sistema: {str(e)}")
            return False
    
    def verificar_herramientas_kali_nativas(self):
        """Verificar que las herramientas nativas de Kali estén disponibles"""
        print("\n🔧 VERIFICANDO HERRAMIENTAS NATIVAS DE KALI...")
        
        herramientas_criticas = {
            # Herramientas básicas del sistema
            'dd': 'data duplicator',
            'dcfldd': 'forensic dd enhancement',
            'head': 'display file head', 
            'tail': 'display file tail',
            'grep': 'pattern matching',
            'awk': 'text processing',
            'sed': 'stream editor',
            'find': 'file search',
            'wc': 'word count',
            'sha256sum': 'SHA256 hash calculation',
            'stat': 'file statistics',
            'lsof': 'list open files',
            
            # Herramientas de red y monitoreo
            'ss': 'socket statistics',
            'netstat': 'network statistics', 
            'journalctl': 'systemd journal',
            'dmesg': 'kernel messages',
            'ps': 'process status',
            
            # Herramientas de auditoría y forense
            'ausearch': 'audit log search',
            'strings': 'extract strings',
            'osqueryi': 'osquery interactive',
            
            # Herramientas específicas de Kali
            'lynis': 'security auditing',
            'nmap': 'network scanner',
            'john': 'password cracker'
        }
        
        disponibles = 0
        faltantes = []
        
        for herramienta, descripcion in herramientas_criticas.items():
            try:
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    self.log_success(f"{herramienta} - {descripcion}")
                    disponibles += 1
                else:
                    self.log_warning(f"{herramienta} - {descripcion} (FALTANTE)")
                    faltantes.append(herramienta)
                    
            except Exception as e:
                self.log_error(f"Error verificando {herramienta}: {str(e)}")
                faltantes.append(herramienta)
        
        total = len(herramientas_criticas)
        porcentaje = (disponibles / total) * 100
        
        print(f"\n📊 RESUMEN HERRAMIENTAS: {disponibles}/{total} disponibles ({porcentaje:.1f}%)")
        
        if porcentaje >= 90:
            self.log_success(f"Excelente cobertura de herramientas ({porcentaje:.1f}%)")
        elif porcentaje >= 75:
            self.log_warning(f"Buena cobertura de herramientas ({porcentaje:.1f}%)")
        else:
            self.log_error(f"Cobertura insuficiente de herramientas ({porcentaje:.1f}%)")
        
        if faltantes:
            print("💡 RECOMENDACIONES DE INSTALACIÓN:")
            for herramienta in faltantes[:5]:  # Solo las 5 primeras
                if herramienta == 'dcfldd':
                    print("  sudo apt install dcfldd")
                elif herramienta == 'ausearch':
                    print("  sudo apt install auditd")
                elif herramienta == 'osqueryi':
                    print("  sudo apt install osquery")
                elif herramienta == 'lynis':
                    print("  sudo apt install lynis")
        
        return porcentaje >= 75
    
    def verificar_modulos_aresitos(self):
        """Verificar que los módulos principales de ARESITOS están presentes y compilables"""
        print("\n📦 VERIFICANDO MÓDULOS ARESITOS...")
        
        modulos_criticos = [
            'aresitos/controlador/controlador_fim.py',
            'aresitos/vista/vista_siem.py', 
            'aresitos/controlador/controlador_cuarentena.py',
            'aresitos/controlador/controlador_principal.py',
            'aresitos/vista/vista_herramientas_kali.py'
        ]
        
        for modulo_path in modulos_criticos:
            ruta_completa = self.base_dir / modulo_path
            
            if ruta_completa.exists():
                try:
                    # Verificar sintaxis Python
                    with open(ruta_completa, 'r', encoding='utf-8') as f:
                        contenido = f.read()
                        compile(contenido, str(ruta_completa), 'exec')
                    
                    self.log_success(f"Módulo {modulo_path} - Sintaxis válida")
                    
                except SyntaxError as e:
                    self.log_error(f"Módulo {modulo_path} - Error de sintaxis: {str(e)}")
                    
                except Exception as e:
                    self.log_error(f"Módulo {modulo_path} - Error: {str(e)}")
                    
            else:
                self.log_error(f"Módulo {modulo_path} - Archivo no encontrado")
    
    def verificar_optimizaciones_especificas(self):
        """Verificar que las optimizaciones específicas para Kali estén implementadas"""
        print("\n🚀 VERIFICANDO OPTIMIZACIONES ESPECÍFICAS DE KALI...")
        
        # Verificar FIM con monitoreo PAM
        try:
            ruta_fim = self.base_dir / 'aresitos/controlador/controlador_fim.py'
            if ruta_fim.exists():
                with open(ruta_fim, 'r', encoding='utf-8') as f:
                    contenido_fim = f.read()
                    
                    if 'monitorear_pam_especifico' in contenido_fim:
                        self.log_success("FIM - Monitoreo PAM específico implementado")
                    else:
                        self.log_error("FIM - Monitoreo PAM específico no encontrado")
                        
                    if 'verificar_compatibilidad_kali' in contenido_fim:
                        self.log_success("FIM - Verificación compatibilidad Kali implementada")
                    else:
                        self.log_error("FIM - Verificación compatibilidad Kali no encontrada")
        except Exception as e:
            self.log_error(f"Error verificando optimizaciones FIM: {str(e)}")
        
        # Verificar SIEM con herramientas nativas
        try:
            ruta_siem = self.base_dir / 'aresitos/vista/vista_siem.py'
            if ruta_siem.exists():
                with open(ruta_siem, 'r', encoding='utf-8') as f:
                    contenido_siem = f.read()
                    
                    if 'usar_dd' in contenido_siem and 'dcfldd' in contenido_siem:
                        self.log_success("SIEM - Herramientas DD/DCFLDD implementadas")
                    else:
                        self.log_error("SIEM - Herramientas DD/DCFLDD no encontradas")
                        
                    if 'monitorear_tiempo_real_kali' in contenido_siem:
                        self.log_success("SIEM - Monitoreo tiempo real Kali implementado")
                    else:
                        self.log_error("SIEM - Monitoreo tiempo real Kali no encontrado")
                        
                    if 'integrar_osquery_kali' in contenido_siem:
                        self.log_success("SIEM - Integración OSQuery implementada")
                    else:
                        self.log_error("SIEM - Integración OSQuery no encontrada")
        except Exception as e:
            self.log_error(f"Error verificando optimizaciones SIEM: {str(e)}")
        
        # Verificar Vista Herramientas Kali
        try:
            ruta_herramientas = self.base_dir / 'aresitos/vista/vista_herramientas_kali.py'
            if ruta_herramientas.exists():
                with open(ruta_herramientas, 'r', encoding='utf-8') as f:
                    contenido = f.read()
                    
                    # Contar herramientas implementadas
                    herramientas_count = contenido.count('tk.Button')
                    if herramientas_count >= 50:
                        self.log_success(f"Vista Herramientas Kali - {herramientas_count} herramientas implementadas")
                    else:
                        self.log_warning(f"Vista Herramientas Kali - Solo {herramientas_count} herramientas encontradas")
            else:
                self.log_error("Vista Herramientas Kali - Archivo no encontrado")
        except Exception as e:
            self.log_error(f"Error verificando Vista Herramientas Kali: {str(e)}")
    
    def verificar_configuraciones_kali(self):
        """Verificar configuraciones específicas de Kali"""
        print("\n⚙️ VERIFICANDO CONFIGURACIONES KALI...")
        
        # Verificar configuración Kali
        config_kali = self.base_dir / 'configuracion/ares_aegis_config_kali.json'
        if config_kali.exists():
            try:
                with open(config_kali, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                    if 'kali_optimization' in config:
                        self.log_success("Configuración Kali - Optimización específica habilitada")
                    else:
                        self.log_warning("Configuración Kali - Sin optimización específica")
                        
                    if 'native_tools' in config:
                        tools_count = len(config['native_tools'])
                        self.log_success(f"Configuración Kali - {tools_count} herramientas nativas configuradas")
                    else:
                        self.log_warning("Configuración Kali - Sin herramientas nativas configuradas")
                        
            except Exception as e:
                self.log_error(f"Error leyendo configuración Kali: {str(e)}")
        else:
            self.log_warning("Configuración Kali - Archivo no encontrado")
        
        # Verificar plan de optimización
        plan_optimizacion = self.base_dir / 'PLAN_OPTIMIZACION_KALI.md'
        if plan_optimizacion.exists():
            self.log_success("Plan de Optimización Kali - Documentación presente")
        else:
            self.log_warning("Plan de Optimización Kali - Documentación no encontrada")
    
    def ejecutar_verificacion_completa(self):
        """Ejecutar verificación completa del sistema"""
        print("🔥 ARESITOS - VERIFICACIÓN OPTIMIZACIÓN KALI LINUX 🔥")
        print("=" * 60)
        
        # Ejecutar todas las verificaciones
        sistema_ok = self.verificar_sistema_kali()
        herramientas_ok = self.verificar_herramientas_kali_nativas()
        self.verificar_modulos_aresitos()
        self.verificar_optimizaciones_especificas()
        self.verificar_configuraciones_kali()
        
        # Generar resumen final
        print("\n" + "=" * 60)
        print("📊 RESUMEN FINAL DE VERIFICACIÓN")
        print("=" * 60)
        
        print(f"\n✅ ÉXITOS: {len(self.exitosos)}")
        for exito in self.exitosos[-5:]:  # Últimos 5
            print(f"  {exito}")
        
        if self.warnings:
            print(f"\n⚠️ ADVERTENCIAS: {len(self.warnings)}")
            for warning in self.warnings[:5]:  # Primeras 5
                print(f"  {warning}")
        
        if self.errores:
            print(f"\n❌ ERRORES: {len(self.errores)}")
            for error in self.errores[:5]:  # Primeros 5
                print(f"  {error}")
        
        # Evaluación final
        total_checks = len(self.exitosos) + len(self.warnings) + len(self.errores)
        success_rate = (len(self.exitosos) / total_checks * 100) if total_checks > 0 else 0
        
        print(f"\n🎯 TASA DE ÉXITO: {success_rate:.1f}%")
        
        if success_rate >= 90:
            print("🏆 ESTADO: EXCELENTE - Sistema totalmente optimizado para Kali Linux")
            return True
        elif success_rate >= 75:
            print("👍 ESTADO: BUENO - Sistema bien optimizado, algunas mejoras menores")
            return True
        elif success_rate >= 60:
            print("⚠️ ESTADO: ACEPTABLE - Optimización parcial, requiere atención")
            return False
        else:
            print("❌ ESTADO: CRÍTICO - Optimización insuficiente, requiere revisión completa")
            return False

def main():
    """Función principal"""
    try:
        verificador = VerificadorOptimizacionKali()
        resultado = verificador.ejecutar_verificacion_completa()
        
        print("\n" + "=" * 60)
        if resultado:
            print("🎉 VERIFICACIÓN COMPLETADA EXITOSAMENTE")
            print("🚀 ARESITOS está listo para uso en Kali Linux!")
        else:
            print("⚠️ VERIFICACIÓN COMPLETADA CON OBSERVACIONES")
            print("🔧 Revisar las advertencias y errores reportados")
        print("=" * 60)
        
        return 0 if resultado else 1
        
    except KeyboardInterrupt:
        print("\n⚠️ Verificación cancelada por el usuario")
        return 2
    except Exception as e:
        print(f"\n❌ Error crítico en verificación: {str(e)}")
        return 3

if __name__ == "__main__":
    sys.exit(main())
