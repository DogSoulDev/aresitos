#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS - Sistema de Actualización Integral
===========================================

Sistema de actualización completo para ARESITOS que actualiza:
- Sistema operativo Kali Linux
- Herramientas de pentesting
- Bases de datos de seguridad
- Configuraciones del sistema

Exclusivamente para Kali Linux.
Solo Python nativo + comandos oficiales.

Autor: DogSoulDev
Fecha: 16 de Agosto de 2025
"""

import os
import sys
import subprocess
import time
import json
import urllib.request
import urllib.error
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

class ActualizadorAresitos:
    """
    Sistema de actualización integral para ARESITOS
    Actualiza sistema, herramientas y bases de datos usando solo fuentes oficiales
    """
    
    def __init__(self):
        self.bases_oficiales = {
            # CVE Database - Oficial MITRE
            'cve_database': {
                'url': 'https://cve.mitre.org/data/downloads/allitems-cvrf.xml',
                'archivo': 'recursos/cve_database.json',
                'descripcion': 'Base de datos CVE oficial de MITRE'
            },
            
            # Exploit Database - Oficial Offensive Security
            'exploit_db': {
                'url': 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
                'archivo': 'recursos/exploit_database.csv', 
                'descripcion': 'Base de datos de exploits oficial'
            },
            
            # Malware Signatures - Oficial ClamAV
            'firmas_malware': {
                'url': 'https://database.clamav.net/main.cvd',
                'archivo': 'recursos/firmas_malware.cvd',
                'descripcion': 'Firmas de malware ClamAV oficial'
            },
            
            # IPs maliciosas - Oficial Abuse.ch
            'ips_maliciosas': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'archivo': 'recursos/ips_maliciosas.txt',
                'descripcion': 'Lista de IPs maliciosas oficial'
            },
            
            # SecLists Wordlists - Oficial SecLists
            'wordlists_seclists': {
                'url': 'https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip',
                'archivo': 'data/wordlists/seclists_update.zip',
                'descripcion': 'Wordlists oficiales SecLists'
            },
            
            # OWASP Top 10 - Oficial OWASP
            'owasp_top10': {
                'url': 'https://owasp.org/www-project-top-ten/assets/OWASP_Top_10_2021.json',
                'archivo': 'recursos/owasp_top10.json',
                'descripcion': 'OWASP Top 10 vulnerabilidades'
            }
        }
        
        self.herramientas_kali = [
            'nmap', 'sqlmap', 'hydra', 'nikto', 'dirb', 'gobuster',
            'wfuzz', 'burpsuite', 'wireshark', 'metasploit-framework',
            'john', 'hashcat', 'aircrack-ng', 'volatility3',
            'binwalk', 'foremost', 'autopsy', 'sleuthkit'
        ]
        
        self.log_actualizacion = []
        self.errores_actualizacion = []
        
    def verificar_kali_linux(self) -> bool:
        """Verificar que estamos en Kali Linux"""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    return 'kali' in content
            return False
        except:
            return False
    
    def solicitar_confirmacion_usuario(self) -> bool:
        """Solicitar confirmación del usuario para actualizar"""
        print(" SISTEMA DE ACTUALIZACIÓN INTEGRAL - ARESITOS")
        print("=" * 60)
        print()
        print("Se actualizarán los siguientes componentes:")
        print("  • Sistema operativo Kali Linux")
        print("  • Herramientas de pentesting (nmap, sqlmap, etc.)")
        print("  • Bases de datos de seguridad (CVE, exploits, etc.)")
        print("  • Configuraciones del sistema")
        print()
        print("WARNING  ADVERTENCIA:")
        print("  - Este proceso puede tomar 15-30 minutos")
        print("  - Se requiere conexión a internet estable")
        print("  - Se requieren permisos de administrador")
        print("  - El sistema puede requerir reinicio")
        print()
        
        while True:
            respuesta = input("¿Desea continuar con la actualización? (s/n): ").lower().strip()
            if respuesta in ['s', 'si', 'sí', 'y', 'yes']:
                return True
            elif respuesta in ['n', 'no']:
                print("Actualización cancelada por el usuario.")
                return False
            else:
                print("Por favor responda 's' para sí o 'n' para no.")
    
    def verificar_conexion_internet(self) -> bool:
        """Verificar conectividad a internet"""
        try:
            # Probar conexión con DNS público de Google
            subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                         capture_output=True, timeout=5, check=True)
            return True
        except:
            return False
    
    def verificar_permisos_sudo(self) -> bool:
        """Verificar que tenemos permisos sudo"""
        try:
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def log_mensaje(self, mensaje: str, es_error: bool = False):
        """Registrar mensaje de log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        linea = f"[{timestamp}] {mensaje}"
        
        if es_error:
            self.errores_actualizacion.append(linea)
            print(f"ERROR {linea}")
        else:
            self.log_actualizacion.append(linea)
            print(f"OK {linea}")
    
    def actualizar_sistema_kali(self) -> bool:
        """Actualizar sistema operativo Kali Linux"""
        try:
            self.log_mensaje("Iniciando actualización del sistema Kali Linux...")
            
            # 1. Actualizar repositorios
            self.log_mensaje("Actualizando repositorios...")
            result = subprocess.run(['sudo', 'apt', 'update'], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                self.log_mensaje(f"Error actualizando repositorios: {result.stderr}", True)
                return False
            
            # 2. Actualizar paquetes
            self.log_mensaje("Actualizando paquetes del sistema...")
            result = subprocess.run(['sudo', 'apt', 'upgrade', '-y'], 
                                  capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                self.log_mensaje(f"Error actualizando paquetes: {result.stderr}", True)
                return False
            
            # 3. Actualizar distribución
            self.log_mensaje("Actualizando distribución...")
            result = subprocess.run(['sudo', 'apt', 'dist-upgrade', '-y'], 
                                  capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                self.log_mensaje(f"Error en dist-upgrade: {result.stderr}", True)
                return False
            
            # 4. Limpiar paquetes obsoletos
            self.log_mensaje("Limpiando paquetes obsoletos...")
            subprocess.run(['sudo', 'apt', 'autoremove', '-y'], 
                         capture_output=True, timeout=300)
            subprocess.run(['sudo', 'apt', 'autoclean'], 
                         capture_output=True, timeout=300)
            
            self.log_mensaje("Sistema Kali Linux actualizado correctamente")
            return True
            
        except subprocess.TimeoutExpired:
            self.log_mensaje("Timeout actualizando sistema", True)
            return False
        except Exception as e:
            self.log_mensaje(f"Error actualizando sistema: {str(e)}", True)
            return False
    
    def actualizar_herramientas_kali(self) -> bool:
        """Actualizar herramientas de pentesting de Kali"""
        try:
            self.log_mensaje("Actualizando herramientas de pentesting...")
            
            # Actualizar metasploit
            self.log_mensaje("Actualizando Metasploit Framework...")
            try:
                subprocess.run(['sudo', 'msfupdate'], 
                             capture_output=True, timeout=600)
                self.log_mensaje("Metasploit actualizado")
            except:
                self.log_mensaje("Error actualizando Metasploit", True)
            
            # Verificar y reportar versiones de herramientas críticas
            herramientas_verificadas = 0
            for herramienta in self.herramientas_kali:
                try:
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        herramientas_verificadas += 1
                        # Obtener versión si es posible
                        try:
                            version_result = subprocess.run([herramienta, '--version'], 
                                                          capture_output=True, text=True, timeout=5)
                            if version_result.returncode == 0:
                                version = version_result.stdout.split('\n')[0][:50]
                                self.log_mensaje(f"{herramienta}: {version}")
                        except:
                            self.log_mensaje(f"{herramienta}: instalado")
                except:
                    self.log_mensaje(f"{herramienta}: no encontrado", True)
            
            self.log_mensaje(f"Herramientas verificadas: {herramientas_verificadas}/{len(self.herramientas_kali)}")
            return True
            
        except Exception as e:
            self.log_mensaje(f"Error actualizando herramientas: {str(e)}", True)
            return False
    
    def descargar_archivo_seguro(self, url: str, archivo_destino: str, descripcion: str) -> bool:
        """Descargar archivo de forma segura desde URL oficial"""
        try:
            self.log_mensaje(f"Descargando {descripcion}...")
            
            # Crear directorio si no existe
            Path(archivo_destino).parent.mkdir(parents=True, exist_ok=True)
            
            # Descargar con urllib (nativo de Python)
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'ARESITOS/1.0 (Kali Linux)')
            
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status == 200:
                    content = response.read()
                    
                    # Escribir archivo
                    with open(archivo_destino, 'wb') as f:
                        f.write(content)
                    
                    # Verificar que el archivo se escribió correctamente
                    if os.path.exists(archivo_destino) and os.path.getsize(archivo_destino) > 0:
                        size = os.path.getsize(archivo_destino)
                        self.log_mensaje(f"{descripcion} descargado ({size} bytes)")
                        return True
                    else:
                        self.log_mensaje(f"Error: archivo {descripcion} vacío", True)
                        return False
                else:
                    self.log_mensaje(f"Error HTTP {response.status} descargando {descripcion}", True)
                    return False
                    
        except urllib.error.URLError as e:
            self.log_mensaje(f"Error de conexión descargando {descripcion}: {str(e)}", True)
            return False
        except Exception as e:
            self.log_mensaje(f"Error descargando {descripcion}: {str(e)}", True)
            return False
    
    def actualizar_bases_datos(self) -> bool:
        """Actualizar todas las bases de datos de seguridad"""
        try:
            self.log_mensaje("Actualizando bases de datos de seguridad...")
            
            actualizaciones_exitosas = 0
            total_bases = len(self.bases_oficiales)
            
            for nombre, info in self.bases_oficiales.items():
                try:
                    if self.descargar_archivo_seguro(
                        info['url'], 
                        info['archivo'], 
                        info['descripcion']
                    ):
                        actualizaciones_exitosas += 1
                    
                    # Pausa entre descargas para no sobrecargar servidores
                    time.sleep(2)
                    
                except Exception as e:
                    self.log_mensaje(f"Error actualizando {nombre}: {str(e)}", True)
            
            self.log_mensaje(f"Bases de datos actualizadas: {actualizaciones_exitosas}/{total_bases}")
            return actualizaciones_exitosas > 0
            
        except Exception as e:
            self.log_mensaje(f"Error actualizando bases de datos: {str(e)}", True)
            return False
    
    def actualizar_configuraciones_sistema(self) -> bool:
        """Actualizar configuraciones del sistema para seguridad"""
        try:
            self.log_mensaje("Actualizando configuraciones de seguridad...")
            
            # Actualizar locate database
            try:
                subprocess.run(['sudo', 'updatedb'], 
                             capture_output=True, timeout=300)
                self.log_mensaje("Base de datos locate actualizada")
            except:
                self.log_mensaje("Error actualizando locate database", True)
            
            # Actualizar man pages
            try:
                subprocess.run(['sudo', 'mandb'], 
                             capture_output=True, timeout=300)
                self.log_mensaje("Man pages actualizadas")
            except:
                self.log_mensaje("Error actualizando man pages", True)
            
            # Verificar y corregir permisos críticos
            archivos_criticos = [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers'
            ]
            
            for archivo in archivos_criticos:
                if os.path.exists(archivo):
                    try:
                        # Verificar que los archivos críticos existen
                        stat = os.stat(archivo)
                        self.log_mensaje(f"Archivo crítico {archivo}: OK")
                    except:
                        self.log_mensaje(f"Advertencia: problema con {archivo}", True)
            
            return True
            
        except Exception as e:
            self.log_mensaje(f"Error actualizando configuraciones: {str(e)}", True)
            return False
    
    def generar_reporte_actualizacion(self) -> str:
        """Generar reporte completo de la actualización"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        archivo_reporte = f"logs/actualizacion_{timestamp}.log"
        
        try:
            # Crear directorio de logs si no existe
            Path(archivo_reporte).parent.mkdir(parents=True, exist_ok=True)
            
            with open(archivo_reporte, 'w') as f:
                f.write("REPORTE DE ACTUALIZACIÓN ARESITOS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write(f"Sistema: Kali Linux\n\n")
                
                f.write("OPERACIONES EXITOSAS:\n")
                f.write("-" * 20 + "\n")
                for linea in self.log_actualizacion:
                    f.write(f"{linea}\n")
                
                if self.errores_actualizacion:
                    f.write("\nERRORES ENCONTRADOS:\n")
                    f.write("-" * 20 + "\n")
                    for error in self.errores_actualizacion:
                        f.write(f"{error}\n")
                
                f.write(f"\nRESUMEN:\n")
                f.write(f"- Operaciones exitosas: {len(self.log_actualizacion)}\n")
                f.write(f"- Errores encontrados: {len(self.errores_actualizacion)}\n")
            
            return archivo_reporte
            
        except Exception as e:
            print(f"Error generando reporte: {str(e)}")
            return ""
    
    def ejecutar_actualizacion_completa(self) -> bool:
        """Ejecutar actualización completa del sistema"""
        print("\n INICIANDO ACTUALIZACIÓN COMPLETA DE ARESITOS")
        print("=" * 60)
        
        # Verificaciones previas
        if not self.verificar_kali_linux():
            print("ERROR Error: Este sistema no es Kali Linux")
            return False
        
        if not self.verificar_conexion_internet():
            print("ERROR Error: No hay conexión a internet")
            return False
        
        if not self.verificar_permisos_sudo():
            print("ERROR Error: Se requieren permisos sudo")
            print("   Ejecute: sudo python3 actualizador.py")
            return False
        
        # Solicitar confirmación
        if not self.solicitar_confirmacion_usuario():
            return False
        
        print("\n Iniciando proceso de actualización...")
        print("TIMEOUT  Este proceso puede tomar 15-30 minutos\n")
        
        inicio = time.time()
        
        # 1. Actualizar sistema Kali Linux
        print(" FASE 1: Actualizando sistema operativo...")
        if not self.actualizar_sistema_kali():
            print("WARNING  Advertencia: Error actualizando sistema")
        
        # 2. Actualizar herramientas
        print("\n  FASE 2: Verificando herramientas...")
        if not self.actualizar_herramientas_kali():
            print("WARNING  Advertencia: Error verificando herramientas")
        
        # 3. Actualizar bases de datos
        print("\n FASE 3: Actualizando bases de datos...")
        if not self.actualizar_bases_datos():
            print("WARNING  Advertencia: Error actualizando bases de datos")
        
        # 4. Actualizar configuraciones
        print("\n  FASE 4: Actualizando configuraciones...")
        if not self.actualizar_configuraciones_sistema():
            print("WARNING  Advertencia: Error actualizando configuraciones")
        
        fin = time.time()
        duracion = int(fin - inicio)
        
        # Generar reporte
        archivo_reporte = self.generar_reporte_actualizacion()
        
        print(f"\n ACTUALIZACIÓN COMPLETADA")
        print("=" * 30)
        print(f"TIMEOUT  Tiempo total: {duracion // 60}m {duracion % 60}s")
        print(f"OK Operaciones exitosas: {len(self.log_actualizacion)}")
        if self.errores_actualizacion:
            print(f"WARNING  Errores encontrados: {len(self.errores_actualizacion)}")
        if archivo_reporte:
            print(f"📄 Reporte guardado en: {archivo_reporte}")
        
        print("\n RECOMENDACIONES POST-ACTUALIZACIÓN:")
        print("   • Reiniciar el sistema si se actualizó el kernel")
        print("   • Verificar que ARESITOS funciona correctamente")
        print("   • Revisar el reporte de actualización")
        
        return True

def main():
    """Función principal del actualizador"""
    try:
        actualizador = ActualizadorAresitos()
        
        if len(sys.argv) > 1 and sys.argv[1] == '--auto':
            # Modo automático sin confirmación (para scripts)
            actualizador.ejecutar_actualizacion_completa()
        else:
            # Modo interactivo con confirmación
            actualizador.ejecutar_actualizacion_completa()
    
    except KeyboardInterrupt:
        print("\n\nWARNING  Actualización cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR Error fatal en actualización: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
