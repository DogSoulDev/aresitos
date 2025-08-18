# -*- coding: utf-8 -*-
"""
ARESITOS - Extensión Cuarentena Kali Linux 2025
===============================================

Extensión del módulo de cuarentena ARESITOS con herramientas modernas de Kali Linux 2025.
Integra herramientas avanzadas de análisis de malware y forense digital.

Herramientas integradas:
- yara: Detección avanzada de patrones de malware
- volatility3: Análisis de memoria RAM
- binwalk: Análisis de firmware y archivos binarios
- foremost: Recuperación de archivos
- autopsy: Análisis forense
- sleuthkit: Herramientas forenses
- chkrootkit: Detección de rootkits
- rkhunter: Hunter de rootkits

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
"""

import subprocess
import json
import os
import shutil
import tempfile
import hashlib
import datetime
import threading
import sqlite3
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

# Importar el modelo base de cuarentena
from .modelo_cuarentena import Cuarentena

class CuarentenaKali2025(Cuarentena):
    """
    Extensión del módulo de cuarentena ARESITOS con herramientas de Kali Linux 2025.
    Mejora las capacidades de análisis de malware y forense digital.
    """
    
    def __init__(self, directorio_cuarentena: Optional[str] = None, configuracion: Optional[Dict[str, Any]] = None):
        # Usar directorio por defecto si no se especifica
        directorio_base = directorio_cuarentena or "/var/lib/aresitos/cuarentena_kali2025"
        
        # Llamar al constructor padre
        super().__init__(directorio_base=directorio_base)
        
        # Configuración específica para Kali 2025
        self.configuracion_kali2025 = configuracion or {}
        
        # Configuración de herramientas de cuarentena Kali 2025
        self.herramientas_cuarentena_kali2025 = {
            'yara': {
                'comando': 'yara',
                'disponible': self._verificar_herramienta('yara'),
                'uso': 'Detección avanzada de patrones de malware'
            },
            'volatility3': {
                'comando': 'vol',
                'disponible': self._verificar_herramienta('vol'),
                'uso': 'Análisis de memoria RAM'
            },
            'binwalk': {
                'comando': 'binwalk',
                'disponible': self._verificar_herramienta('binwalk'),
                'uso': 'Análisis de firmware y archivos binarios'
            },
            'foremost': {
                'comando': 'foremost',
                'disponible': self._verificar_herramienta('foremost'),
                'uso': 'Recuperación de archivos'
            },
            'chkrootkit': {
                'comando': 'chkrootkit',
                'disponible': self._verificar_herramienta('chkrootkit'),
                'uso': 'Detección de rootkits'
            },
            'rkhunter': {
                'comando': 'rkhunter',
                'disponible': self._verificar_herramienta('rkhunter'),
                'uso': 'Hunter de rootkits'
            },
            'strings': {
                'comando': 'strings',
                'disponible': self._verificar_herramienta('strings'),
                'uso': 'Extracción de cadenas de texto'
            },
            'hexdump': {
                'comando': 'hexdump',
                'disponible': self._verificar_herramienta('hexdump'),
                'uso': 'Análisis hexadecimal'
            }
        }
        
        # Directorios especializados
        self.directorio_analisis = os.path.join(self.directorio_cuarentena, "analisis_kali2025")
        self.directorio_memoria = os.path.join(self.directorio_cuarentena, "analisis_memoria")
        self.directorio_forense = os.path.join(self.directorio_cuarentena, "forense")
        self.directorio_reglas_yara = os.path.join(self.directorio_cuarentena, "yara_rules_malware")
        
        # Crear directorios
        for directorio in [self.directorio_analisis, self.directorio_memoria, 
                          self.directorio_forense, self.directorio_reglas_yara]:
            os.makedirs(directorio, exist_ok=True)
        
        # Base de datos de análisis
        self.db_path = os.path.join(self.directorio_cuarentena, "analisis_kali2025.db")
        self._inicializar_base_datos()
        
        # Estadísticas de análisis
        self.estadisticas_kali2025 = {
            'archivos_analizados': 0,
            'malware_detectado': 0,
            'memoria_analizada_mb': 0,
            'archivos_recuperados': 0,
            'rootkits_detectados': 0
        }
        
        self.logger.info("Cuarentena Kali 2025 inicializada")
        self._log_herramientas_cuarentena_disponibles()
        self._crear_reglas_yara_malware()
    
    def _verificar_herramienta(self, herramienta: str) -> bool:
        """Verificar si una herramienta está disponible."""
        try:
            resultado = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
            return resultado.returncode == 0
        except Exception:
            return False
    
    def _log_herramientas_cuarentena_disponibles(self):
        """Registrar herramientas de cuarentena disponibles."""
        disponibles = [h for h, info in self.herramientas_cuarentena_kali2025.items() if info['disponible']]
        no_disponibles = [h for h, info in self.herramientas_cuarentena_kali2025.items() if not info['disponible']]
        
        self.logger.info(f"Herramientas Cuarentena Kali 2025 disponibles: {', '.join(disponibles)}")
        if no_disponibles:
            self.logger.warning(f"Herramientas Cuarentena no disponibles: {', '.join(no_disponibles)}")
    
    def _inicializar_base_datos(self):
        """Inicializar base de datos de análisis."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS analisis_malware (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        archivo_hash TEXT UNIQUE,
                        ruta_original TEXT,
                        ruta_cuarentena TEXT,
                        fecha_analisis TEXT,
                        herramienta TEXT,
                        resultado TEXT,
                        es_malware INTEGER,
                        puntuacion_riesgo INTEGER,
                        metadatos TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS analisis_memoria (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        dump_hash TEXT,
                        fecha_analisis TEXT,
                        herramienta TEXT,
                        procesos_sospechosos TEXT,
                        conexiones_red TEXT,
                        artefactos_malware TEXT,
                        metadatos TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS deteccion_rootkits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fecha_analisis TEXT,
                        herramienta TEXT,
                        rootkits_detectados TEXT,
                        archivos_modificados TEXT,
                        procesos_ocultos TEXT,
                        metadatos TEXT
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error inicializando base de datos: {e}")
    
    def _crear_reglas_yara_malware(self):
        """Crear reglas YARA especializadas para malware."""
        if not self.herramientas_cuarentena_kali2025['yara']['disponible']:
            return
        
        reglas_malware = {
            'ransomware.yar': '''
rule Ransomware_Indicators {
    meta:
        description = "Indicadores genéricos de ransomware"
        author = "ARESITOS Cuarentena"
        date = "2025-08-18"
        
    strings:
        $ransom1 = "Your files have been encrypted"
        $ransom2 = "pay the ransom"
        $ransom3 = "bitcoin address"
        $ransom4 = "decryption key"
        $ransom5 = "files are locked"
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
        $crypto3 = "CryptImportKey"
        
    condition:
        any of ($ransom*) or 2 of ($crypto*)
}

rule Ransomware_Extensions {
    meta:
        description = "Extensiones comunes de ransomware"
        
    strings:
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".crypto"
        $ext4 = ".wannacry"
        $ext5 = ".cerber"
        
    condition:
        any of them
}
''',
            'banking_trojan.yar': '''
rule Banking_Trojan {
    meta:
        description = "Troyanos bancarios"
        author = "ARESITOS Cuarentena"
        
    strings:
        $bank1 = "keylogger"
        $bank2 = "screenshot"
        $bank3 = "credential"
        $bank4 = "banking"
        $api1 = "GetWindowTextA"
        $api2 = "GetKeyState"
        $api3 = "SetWindowsHookEx"
        
    condition:
        2 of ($bank*) and any of ($api*)
}
''',
            'backdoor.yar': '''
rule Generic_Backdoor {
    meta:
        description = "Backdoors genéricos"
        author = "ARESITOS Cuarentena"
        
    strings:
        $back1 = "cmd.exe"
        $back2 = "reverse shell"
        $back3 = "bind shell"
        $back4 = "backdoor"
        $net1 = "socket"
        $net2 = "connect"
        $net3 = "listen"
        
    condition:
        any of ($back*) and 2 of ($net*)
}
''',
            'persistence.yar': '''
rule Persistence_Mechanisms {
    meta:
        description = "Mecanismos de persistencia"
        author = "ARESITOS Cuarentena"
        
    strings:
        $reg1 = "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $reg2 = "HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $sch1 = "schtasks"
        $sch2 = "at.exe"
        $srv1 = "CreateService"
        $srv2 = "StartService"
        
    condition:
        any of them
}
'''
        }
        
        for nombre_archivo, contenido in reglas_malware.items():
            ruta_regla = os.path.join(self.directorio_reglas_yara, nombre_archivo)
            if not os.path.exists(ruta_regla):
                try:
                    with open(ruta_regla, 'w', encoding='utf-8') as f:
                        f.write(contenido)
                    self.logger.info(f"Regla YARA de malware creada: {nombre_archivo}")
                except Exception as e:
                    self.logger.error(f"Error creando regla YARA {nombre_archivo}: {e}")
    
    def analisis_malware_completo(self, ruta_archivo: str, usar_todas_herramientas: bool = True) -> Dict[str, Any]:
        """
        Análisis completo de malware usando múltiples herramientas.
        
        Args:
            ruta_archivo: Ruta del archivo a analizar
            usar_todas_herramientas: Si usar todas las herramientas disponibles
            
        Returns:
            Dict con resultados completos del análisis
        """
        if not os.path.exists(ruta_archivo):
            return {'error': f'Archivo no encontrado: {ruta_archivo}'}
        
        # Calcular hash del archivo
        archivo_hash = self._calcular_hash_archivo(ruta_archivo)
        
        # Verificar si ya fue analizado
        analisis_previo = self._obtener_analisis_previo(archivo_hash)
        if analisis_previo:
            self.logger.info(f"Usando análisis previo para archivo: {archivo_hash}")
            return analisis_previo
        
        # Crear directorio de trabajo temporal
        directorio_trabajo = os.path.join(self.directorio_analisis, archivo_hash)
        os.makedirs(directorio_trabajo, exist_ok=True)
        
        # Copiar archivo a zona segura
        ruta_copia_segura = os.path.join(directorio_trabajo, f"muestra_{archivo_hash}")
        shutil.copy2(ruta_archivo, ruta_copia_segura)
        
        resultado_completo = {
            'archivo_original': ruta_archivo,
            'archivo_hash': archivo_hash,
            'ruta_analisis': directorio_trabajo,
            'timestamp': datetime.datetime.now().isoformat(),
            'analisis': {},
            'puntuacion_riesgo': 0,
            'es_malware': False,
            'recomendaciones': []
        }
        
        try:
            # 1. Análisis YARA
            if self.herramientas_cuarentena_kali2025['yara']['disponible']:
                resultado_completo['analisis']['yara'] = self._analisis_yara_malware(ruta_copia_segura)
            
            # 2. Análisis de strings
            if self.herramientas_cuarentena_kali2025['strings']['disponible']:
                resultado_completo['analisis']['strings'] = self._analisis_strings(ruta_copia_segura)
            
            # 3. Análisis hexadecimal
            if self.herramientas_cuarentena_kali2025['hexdump']['disponible']:
                resultado_completo['analisis']['hexdump'] = self._analisis_hexadecimal(ruta_copia_segura)
            
            # 4. Análisis con binwalk si es binario
            if self.herramientas_cuarentena_kali2025['binwalk']['disponible']:
                resultado_completo['analisis']['binwalk'] = self._analisis_binwalk(ruta_copia_segura)
            
            # Evaluar resultados y calcular puntuación
            self._evaluar_resultados_malware(resultado_completo)
            
            # Guardar en base de datos
            self._guardar_analisis_malware(resultado_completo)
            
            self.estadisticas_kali2025['archivos_analizados'] += 1
            if resultado_completo['es_malware']:
                self.estadisticas_kali2025['malware_detectado'] += 1
            
            return resultado_completo
            
        except Exception as e:
            self.logger.error(f"Error en análisis completo: {e}")
            resultado_completo['error'] = str(e)
            return resultado_completo
    
    def _analisis_yara_malware(self, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis YARA especializado en malware."""
        try:
            comando = ['yara', '-r', '-s', '-m', self.directorio_reglas_yara, ruta_archivo]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            detecciones = []
            if resultado.stdout.strip():
                for linea in resultado.stdout.strip().split('\n'):
                    if linea.strip():
                        partes = linea.split(' ', 1)
                        if len(partes) >= 2:
                            detecciones.append({
                                'regla': partes[0],
                                'archivo': partes[1] if len(partes) > 1 else ruta_archivo,
                                'descripcion': linea
                            })
            
            return {
                'herramienta': 'yara_malware',
                'detecciones': detecciones,
                'total_detecciones': len(detecciones),
                'malware_score': min(len(detecciones) * 20, 100),
                'success': resultado.returncode == 0
            }
            
        except Exception as e:
            return {
                'herramienta': 'yara_malware',
                'error': str(e),
                'detecciones': [],
                'malware_score': 0
            }
    
    def _analisis_strings(self, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis de strings para detectar indicadores."""
        try:
            comando = ['strings', '-a', '-n', '4', ruta_archivo]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if resultado.returncode != 0:
                return {'error': 'Error ejecutando strings'}
            
            strings_encontrados = resultado.stdout.strip().split('\n')
            
            # Buscar strings sospechosos
            strings_sospechosos = []
            patrones_malware = [
                'password', 'keylog', 'encrypt', 'decrypt', 'ransom', 'bitcoin',
                'shell', 'backdoor', 'trojan', 'virus', 'payload', 'exploit',
                'cmd.exe', 'powershell', 'wget', 'curl', 'download'
            ]
            
            for string in strings_encontrados:
                string_lower = string.lower()
                for patron in patrones_malware:
                    if patron in string_lower and len(string) > 3:
                        strings_sospechosos.append({
                            'string': string,
                            'patron': patron,
                            'posicion': strings_encontrados.index(string)
                        })
                        break
            
            return {
                'herramienta': 'strings',
                'total_strings': len(strings_encontrados),
                'strings_sospechosos': strings_sospechosos[:50],  # Limitar salida
                'malware_score': min(len(strings_sospechosos) * 5, 50),
                'success': True
            }
            
        except Exception as e:
            return {
                'herramienta': 'strings',
                'error': str(e),
                'malware_score': 0
            }
    
    def _analisis_hexadecimal(self, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis hexadecimal básico."""
        try:
            comando = ['hexdump', '-C', '-n', '1024', ruta_archivo]  # Solo primeros 1KB
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if resultado.returncode != 0:
                return {'error': 'Error ejecutando hexdump'}
            
            # Detectar header de archivo
            headers_conocidos = {
                'MZ': 'PE Executable',
                '7f454c46': 'ELF Binary',
                '504b0304': 'ZIP Archive',
                '25504446': 'PDF Document',
                'ffd8ffe0': 'JPEG Image',
                '89504e47': 'PNG Image'
            }
            
            primeras_lineas = resultado.stdout.split('\n')[:5]
            header_detectado = None
            
            for linea in primeras_lineas:
                if '|' in linea:
                    hex_parte = linea.split('|')[0].strip()
                    for header, tipo in headers_conocidos.items():
                        if header.lower() in hex_parte.replace(' ', '').lower():
                            header_detectado = tipo
                            break
                    if header_detectado:
                        break
            
            return {
                'herramienta': 'hexdump',
                'header_detectado': header_detectado,
                'primeras_lineas': primeras_lineas,
                'malware_score': 0,  # Hexdump no da score directo
                'success': True
            }
            
        except Exception as e:
            return {
                'herramienta': 'hexdump',
                'error': str(e),
                'malware_score': 0
            }
    
    def _analisis_binwalk(self, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis con binwalk para archivos binarios."""
        try:
            comando = ['binwalk', ruta_archivo]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if resultado.returncode != 0:
                return {'error': 'Error ejecutando binwalk'}
            
            # Parsear salida de binwalk
            componentes_encontrados = []
            for linea in resultado.stdout.strip().split('\n'):
                if linea.strip() and not linea.startswith('DECIMAL'):
                    componentes_encontrados.append(linea.strip())
            
            # Buscar componentes sospechosos
            componentes_sospechosos = []
            patrones_sospechosos = ['executable', 'compressed', 'encrypted', 'obfuscated']
            
            for componente in componentes_encontrados:
                componente_lower = componente.lower()
                for patron in patrones_sospechosos:
                    if patron in componente_lower:
                        componentes_sospechosos.append(componente)
                        break
            
            return {
                'herramienta': 'binwalk',
                'total_componentes': len(componentes_encontrados),
                'componentes_encontrados': componentes_encontrados[:20],  # Limitar salida
                'componentes_sospechosos': componentes_sospechosos,
                'malware_score': min(len(componentes_sospechosos) * 10, 30),
                'success': True
            }
            
        except Exception as e:
            return {
                'herramienta': 'binwalk',
                'error': str(e),
                'malware_score': 0
            }
    
    def analisis_memoria_volatility(self, dump_memoria: str, perfil: str = "auto") -> Dict[str, Any]:
        """
        Análisis de memoria con Volatility3.
        
        Args:
            dump_memoria: Ruta del dump de memoria
            perfil: Perfil del sistema operativo
            
        Returns:
            Dict con resultados del análisis
        """
        if not self.herramientas_cuarentena_kali2025['volatility3']['disponible']:
            return self._fallback_analisis_memoria(dump_memoria)
        
        if not os.path.exists(dump_memoria):
            return {'error': f'Dump de memoria no encontrado: {dump_memoria}'}
        
        resultado = {
            'herramienta': 'volatility3',
            'dump_memoria': dump_memoria,
            'analisis': {},
            'procesos_sospechosos': [],
            'conexiones_red': [],
            'artefactos_malware': [],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # 1. Listar procesos
            resultado['analisis']['procesos'] = self._vol_procesos(dump_memoria)
            
            # 2. Conexiones de red
            resultado['analisis']['conexiones'] = self._vol_conexiones_red(dump_memoria)
            
            # 3. Buscar procesos ocultos
            resultado['analisis']['procesos_ocultos'] = self._vol_procesos_ocultos(dump_memoria)
            
            # 4. Analizar DLLs
            resultado['analisis']['dlls'] = self._vol_dlls(dump_memoria)
            
            # Evaluar hallazgos
            self._evaluar_analisis_memoria(resultado)
            
            # Guardar en base de datos
            self._guardar_analisis_memoria(resultado)
            
            # Actualizar estadísticas
            tamaño_mb = os.path.getsize(dump_memoria) // (1024 * 1024)
            self.estadisticas_kali2025['memoria_analizada_mb'] += tamaño_mb
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en análisis de memoria: {e}")
            resultado['error'] = str(e)
            return resultado
    
    def _vol_procesos(self, dump_memoria: str) -> Dict[str, Any]:
        """Listar procesos con Volatility."""
        try:
            comando = ['vol', '-f', dump_memoria, 'windows.pslist']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            procesos = []
            if resultado.returncode == 0:
                lineas = resultado.stdout.strip().split('\n')
                for linea in lineas[2:]:  # Skip header
                    if linea.strip():
                        partes = linea.split()
                        if len(partes) >= 6:
                            procesos.append({
                                'pid': partes[0],
                                'ppid': partes[1],
                                'nombre': partes[2],
                                'threads': partes[3] if len(partes) > 3 else 'N/A',
                                'handles': partes[4] if len(partes) > 4 else 'N/A'
                            })
            
            return {
                'comando': 'windows.pslist',
                'total_procesos': len(procesos),
                'procesos': procesos[:50],  # Limitar salida
                'success': resultado.returncode == 0
            }
            
        except Exception as e:
            return {
                'comando': 'windows.pslist',
                'error': str(e),
                'procesos': []
            }
    
    def _vol_conexiones_red(self, dump_memoria: str) -> Dict[str, Any]:
        """Analizar conexiones de red con Volatility."""
        try:
            comando = ['vol', '-f', dump_memoria, 'windows.netstat']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            conexiones = []
            if resultado.returncode == 0:
                lineas = resultado.stdout.strip().split('\n')
                for linea in lineas[2:]:  # Skip header
                    if linea.strip():
                        conexiones.append(linea.strip())
            
            return {
                'comando': 'windows.netstat',
                'total_conexiones': len(conexiones),
                'conexiones': conexiones[:30],  # Limitar salida
                'success': resultado.returncode == 0
            }
            
        except Exception as e:
            return {
                'comando': 'windows.netstat',
                'error': str(e),
                'conexiones': []
            }
    
    def _vol_procesos_ocultos(self, dump_memoria: str) -> Dict[str, Any]:
        """Buscar procesos ocultos con Volatility."""
        try:
            comando = ['vol', '-f', dump_memoria, 'windows.psscan']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            procesos_ocultos = []
            if resultado.returncode == 0:
                lineas = resultado.stdout.strip().split('\n')
                for linea in lineas[2:]:  # Skip header
                    if linea.strip():
                        procesos_ocultos.append(linea.strip())
            
            return {
                'comando': 'windows.psscan',
                'total_procesos_ocultos': len(procesos_ocultos),
                'procesos': procesos_ocultos[:20],  # Limitar salida
                'success': resultado.returncode == 0
            }
            
        except Exception as e:
            return {
                'comando': 'windows.psscan',
                'error': str(e),
                'procesos': []
            }
    
    def _vol_dlls(self, dump_memoria: str) -> Dict[str, Any]:
        """Analizar DLLs con Volatility."""
        try:
            comando = ['vol', '-f', dump_memoria, 'windows.dlllist']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=90
            )
            
            dlls = []
            if resultado.returncode == 0:
                lineas = resultado.stdout.strip().split('\n')
                for linea in lineas[2:]:  # Skip header
                    if linea.strip():
                        dlls.append(linea.strip())
            
            return {
                'comando': 'windows.dlllist',
                'total_dlls': len(dlls),
                'dlls': dlls[:40],  # Limitar salida
                'success': resultado.returncode == 0
            }
            
        except Exception as e:
            return {
                'comando': 'windows.dlllist',
                'error': str(e),
                'dlls': []
            }
    
    def deteccion_rootkits_completa(self) -> Dict[str, Any]:
        """
        Detección completa de rootkits usando múltiples herramientas.
        
        Returns:
            Dict con resultados de detección
        """
        resultado = {
            'timestamp': datetime.datetime.now().isoformat(),
            'herramientas_utilizadas': [],
            'rootkits_detectados': [],
            'archivos_modificados': [],
            'procesos_ocultos': [],
            'recomendaciones': []
        }
        
        # 1. chkrootkit
        if self.herramientas_cuarentena_kali2025['chkrootkit']['disponible']:
            resultado_chkrootkit = self._ejecutar_chkrootkit()
            resultado['herramientas_utilizadas'].append('chkrootkit')
            resultado['chkrootkit'] = resultado_chkrootkit
            
            if 'rootkits' in resultado_chkrootkit:
                resultado['rootkits_detectados'].extend(resultado_chkrootkit['rootkits'])
        
        # 2. rkhunter
        if self.herramientas_cuarentena_kali2025['rkhunter']['disponible']:
            resultado_rkhunter = self._ejecutar_rkhunter()
            resultado['herramientas_utilizadas'].append('rkhunter')
            resultado['rkhunter'] = resultado_rkhunter
            
            if 'warnings' in resultado_rkhunter:
                resultado['archivos_modificados'].extend(resultado_rkhunter['warnings'])
        
        # Evaluar nivel de amenaza
        total_detecciones = len(resultado['rootkits_detectados']) + len(resultado['archivos_modificados'])
        
        if total_detecciones == 0:
            resultado['nivel_amenaza'] = 'bajo'
            resultado['recomendaciones'].append('Sistema parece limpio de rootkits')
        elif total_detecciones <= 3:
            resultado['nivel_amenaza'] = 'medio'
            resultado['recomendaciones'].append('Verificar detecciones manualmente')
        else:
            resultado['nivel_amenaza'] = 'alto'
            resultado['recomendaciones'].append('Posible compromiso - investigación profunda requerida')
        
        # Guardar en base de datos
        self._guardar_deteccion_rootkits(resultado)
        
        # Actualizar estadísticas
        self.estadisticas_kali2025['rootkits_detectados'] += len(resultado['rootkits_detectados'])
        
        return resultado
    
    def _ejecutar_chkrootkit(self) -> Dict[str, Any]:
        """Ejecutar chkrootkit."""
        try:
            comando = ['sudo', 'chkrootkit']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            rootkits_detectados = []
            lineas = resultado.stdout.strip().split('\n')
            
            for linea in lineas:
                if 'INFECTED' in linea or 'infected' in linea:
                    rootkits_detectados.append(linea.strip())
            
            return {
                'herramienta': 'chkrootkit',
                'rootkits': rootkits_detectados,
                'output_completo': lineas[:100],  # Limitar salida
                'success': resultado.returncode == 0
            }
            
        except Exception as e:
            return {
                'herramienta': 'chkrootkit',
                'error': str(e),
                'rootkits': []
            }
    
    def _ejecutar_rkhunter(self) -> Dict[str, Any]:
        """Ejecutar rkhunter."""
        try:
            comando = ['sudo', 'rkhunter', '--check', '--skip-keypress', '--report-warnings-only']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            warnings = []
            lineas = resultado.stdout.strip().split('\n')
            
            for linea in lineas:
                if 'Warning:' in linea or 'WARNING:' in linea:
                    warnings.append(linea.strip())
            
            return {
                'herramienta': 'rkhunter',
                'warnings': warnings,
                'output_completo': lineas[:100],  # Limitar salida
                'success': resultado.returncode in [0, 1]  # rkhunter returns 1 for warnings
            }
            
        except Exception as e:
            return {
                'herramienta': 'rkhunter',
                'error': str(e),
                'warnings': []
            }
    
    # Métodos auxiliares
    def _calcular_hash_archivo(self, ruta_archivo: str) -> str:
        """Calcular hash SHA256 de un archivo."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(ruta_archivo, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculando hash: {e}")
            return "error_hash"
    
    def _obtener_analisis_previo(self, archivo_hash: str) -> Optional[Dict[str, Any]]:
        """Obtener análisis previo de la base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM analisis_malware WHERE archivo_hash = ?",
                    (archivo_hash,)
                )
                resultado = cursor.fetchone()
                
                if resultado:
                    return {
                        'es_analisis_previo': True,
                        'fecha_analisis_original': resultado[4],
                        'es_malware': bool(resultado[7]),
                        'puntuacion_riesgo': resultado[8],
                        'metadatos': json.loads(resultado[9]) if resultado[9] else {}
                    }
        except Exception as e:
            self.logger.error(f"Error obteniendo análisis previo: {e}")
        
        return None
    
    def _evaluar_resultados_malware(self, resultado: Dict[str, Any]):
        """Evaluar resultados y asignar puntuación de riesgo."""
        puntuacion_total = 0
        
        # Puntuación de YARA
        if 'yara' in resultado['analisis']:
            puntuacion_total += resultado['analisis']['yara'].get('malware_score', 0)
        
        # Puntuación de strings
        if 'strings' in resultado['analisis']:
            puntuacion_total += resultado['analisis']['strings'].get('malware_score', 0)
        
        # Puntuación de binwalk
        if 'binwalk' in resultado['analisis']:
            puntuacion_total += resultado['analisis']['binwalk'].get('malware_score', 0)
        
        resultado['puntuacion_riesgo'] = min(puntuacion_total, 100)
        
        # Determinar si es malware
        if puntuacion_total >= 70:
            resultado['es_malware'] = True
            resultado['recomendaciones'].append('CRÍTICO: Archivo identificado como malware')
        elif puntuacion_total >= 40:
            resultado['es_malware'] = False
            resultado['recomendaciones'].append('SOSPECHOSO: Verificación manual recomendada')
        else:
            resultado['es_malware'] = False
            resultado['recomendaciones'].append('LIMPIO: No se detectaron indicadores de malware')
    
    def _evaluar_analisis_memoria(self, resultado: Dict[str, Any]):
        """Evaluar resultados de análisis de memoria."""
        # Buscar procesos sospechosos
        if 'procesos' in resultado['analisis']:
            procesos_sospechosos = []
            procesos_conocidos_malware = ['svchost.exe', 'winlogon.exe', 'csrss.exe']
            
            for proceso in resultado['analisis']['procesos'].get('procesos', []):
                nombre = proceso.get('nombre', '').lower()
                if any(malware in nombre for malware in ['backdoor', 'trojan', 'keylog']):
                    procesos_sospechosos.append(proceso)
            
            resultado['procesos_sospechosos'] = procesos_sospechosos
    
    def _guardar_analisis_malware(self, resultado: Dict[str, Any]):
        """Guardar análisis de malware en base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO analisis_malware 
                    (archivo_hash, ruta_original, ruta_cuarentena, fecha_analisis, 
                     herramienta, resultado, es_malware, puntuacion_riesgo, metadatos)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    resultado['archivo_hash'],
                    resultado['archivo_original'],
                    resultado.get('ruta_analisis', ''),
                    resultado['timestamp'],
                    'kali2025_completo',
                    json.dumps(resultado['analisis']),
                    1 if resultado['es_malware'] else 0,
                    resultado['puntuacion_riesgo'],
                    json.dumps(resultado.get('recomendaciones', []))
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error guardando análisis: {e}")
    
    def _guardar_analisis_memoria(self, resultado: Dict[str, Any]):
        """Guardar análisis de memoria en base de datos."""
        try:
            dump_hash = self._calcular_hash_archivo(resultado['dump_memoria'])
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO analisis_memoria 
                    (dump_hash, fecha_analisis, herramienta, procesos_sospechosos, 
                     conexiones_red, artefactos_malware, metadatos)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    dump_hash,
                    resultado['timestamp'],
                    'volatility3',
                    json.dumps(resultado.get('procesos_sospechosos', [])),
                    json.dumps(resultado.get('conexiones_red', [])),
                    json.dumps(resultado.get('artefactos_malware', [])),
                    json.dumps(resultado.get('analisis', {}))
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error guardando análisis de memoria: {e}")
    
    def _guardar_deteccion_rootkits(self, resultado: Dict[str, Any]):
        """Guardar detección de rootkits en base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO deteccion_rootkits 
                    (fecha_analisis, herramienta, rootkits_detectados, 
                     archivos_modificados, procesos_ocultos, metadatos)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    resultado['timestamp'],
                    ','.join(resultado['herramientas_utilizadas']),
                    json.dumps(resultado['rootkits_detectados']),
                    json.dumps(resultado['archivos_modificados']),
                    json.dumps(resultado.get('procesos_ocultos', [])),
                    json.dumps({
                        'nivel_amenaza': resultado.get('nivel_amenaza', 'desconocido'),
                        'recomendaciones': resultado.get('recomendaciones', [])
                    })
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error guardando detección de rootkits: {e}")
    
    # Métodos fallback
    def _fallback_analisis_memoria(self, dump_memoria: str) -> Dict[str, Any]:
        """Fallback para análisis de memoria sin Volatility."""
        return {
            'herramienta': 'fallback_memoria',
            'dump_memoria': dump_memoria,
            'mensaje': 'Volatility3 no disponible - análisis limitado',
            'analisis': {},
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def obtener_capacidades_cuarentena_kali2025(self) -> Dict[str, Any]:
        """
        Obtener información sobre las capacidades de cuarentena de Kali 2025.
        
        Returns:
            Dict con información sobre herramientas disponibles
        """
        return {
            'herramientas_disponibles': {
                nombre: info['disponible'] 
                for nombre, info in self.herramientas_cuarentena_kali2025.items()
            },
            'total_herramientas': len(self.herramientas_cuarentena_kali2025),
            'herramientas_activas': sum(1 for info in self.herramientas_cuarentena_kali2025.values() if info['disponible']),
            'estadisticas': self.estadisticas_kali2025,
            'capacidades_mejoradas': [
                'Análisis de malware con YARA avanzado',
                'Análisis de memoria con Volatility3',
                'Análisis forense con binwalk',
                'Detección de rootkits con múltiples herramientas',
                'Análisis de strings y hexadecimal',
                'Base de datos de análisis persistente'
            ],
            'directorios': {
                'cuarentena': self.directorio_cuarentena,
                'analisis': self.directorio_analisis,
                'memoria': self.directorio_memoria,
                'forense': self.directorio_forense,
                'reglas_yara': self.directorio_reglas_yara
            },
            'base_datos': self.db_path
        }
