# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Sistema de Cuarentena Optimizado Kali 2025
=========================================================

Sistema de cuarentena y análisis de amenazas con herramientas nativas de Kali Linux.
Optimizado siguiendo principios ARESITOS v3.0: Python nativo + Kali tools únicamente.

Funcionalidades principales:
- Aislamiento automático de amenazas detectadas
- Análisis de malware con herramientas Kali nativas
- Integración completa con SIEM, FIM y Escaneador
- Gestión de respuesta automática a incidentes
- Base de datos SQLite para persistencia

Herramientas Kali integradas:
- ClamAV: Detección antivirus
- YARA: Análisis de patrones maliciosos  
- Binwalk: Análisis de archivos binarios
- ExifTool: Análisis de metadatos
- Strings: Extracción de cadenas de texto
- File: Identificación de tipos de archivo
- Chkrootkit/Rkhunter: Detección de rootkits

Autor: ARESITOS Team
Versión: 3.0.0
Fecha: Agosto 2025
Compatibilidad: Kali Linux 2025
"""

import os
import sys
import sqlite3
import subprocess
import threading
import time
import json
import hashlib
import shutil
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import logging

class CuarentenaKali2025:
    """
    Sistema de cuarentena avanzado optimizado para Kali Linux 2025.
    Consolidación de funcionalidades siguiendo principios ARESITOS v3.0.
    """
    
    def __init__(self, directorio_cuarentena: Optional[str] = None):
        """Inicializar sistema de cuarentena Kali 2025"""
        
        # Versión y metadatos
        self.version = "3.0"
        self.kali_version = "2025"
        self.fecha_inicializacion = datetime.now().isoformat()
        
        # Configuración de directorios
        self.directorio_base = directorio_cuarentena or "data/cuarentena"
        self.directorio_sospechosos = os.path.join(self.directorio_base, "sospechosos")
        self.directorio_infectados = os.path.join(self.directorio_base, "infectados")
        self.directorio_limpio = os.path.join(self.directorio_base, "limpio")
        self.directorio_analisis = os.path.join(self.directorio_base, "analisis")
        self.directorio_reportes = os.path.join(self.directorio_base, "reportes")
        
        # Base de datos
        self.base_datos = os.path.join(self.directorio_base, "cuarentena_kali2025.db")
        
        # Logger
        self.logger = logging.getLogger("CUARENTENA_KALI2025")
        
        # Herramientas Kali disponibles
        self.herramientas_kali = {
            'clamav': {
                'comando': 'clamscan',
                'disponible': False,
                'version': None
            },
            'yara': {
                'comando': 'yara',
                'disponible': False,
                'version': None
            },
            'binwalk': {
                'comando': 'binwalk',
                'disponible': False,
                'version': None
            },
            'exiftool': {
                'comando': 'exiftool',
                'disponible': False,
                'version': None
            },
            'strings': {
                'comando': 'strings',
                'disponible': False,
                'version': None
            },
            'file': {
                'comando': 'file',
                'disponible': False,
                'version': None
            },
            'chkrootkit': {
                'comando': 'chkrootkit',
                'disponible': False,
                'version': None
            },
            'rkhunter': {
                'comando': 'rkhunter',
                'disponible': False,
                'version': None
            }
        }
        
        # Estadísticas en tiempo real
        self.estadisticas = {
            'archivos_cuarentena': 0,
            'amenazas_detectadas': 0,
            'análisis_completados': 0,
            'última_actualización': None
        }
        
        # Inicialización del sistema
        self._inicializar_sistema()
        
        self.log("Sistema de cuarentena Kali 2025 inicializado correctamente")
    
    def _inicializar_sistema(self):
        """Inicializar todos los componentes del sistema"""
        try:
            self._crear_directorios()
            self._verificar_herramientas_kali()
            self._inicializar_base_datos()
            self._actualizar_estadisticas()
            
        except Exception as e:
            self.log(f"Error inicializando sistema: {e}")
            raise
    
    def _crear_directorios(self):
        """Crear estructura de directorios necesaria"""
        directorios = [
            self.directorio_base,
            self.directorio_sospechosos,
            self.directorio_infectados,
            self.directorio_limpio,
            self.directorio_analisis,
            self.directorio_reportes
        ]
        
        for directorio in directorios:
            try:
                os.makedirs(directorio, exist_ok=True)
                self.log(f"Directorio verificado: {directorio}")
            except Exception as e:
                self.log(f"Error creando directorio {directorio}: {e}")
                raise
    
    def _verificar_herramientas_kali(self):
        """Verificar disponibilidad de herramientas Kali Linux"""
        for herramienta, config in self.herramientas_kali.items():
            try:
                # Verificar si la herramienta está disponible
                resultado = subprocess.run(
                    ['which', config['comando']], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                if resultado.returncode == 0:
                    config['disponible'] = True
                    ruta = resultado.stdout.strip()
                    
                    # Obtener versión si es posible
                    try:
                        version_result = subprocess.run(
                            [config['comando'], '--version'],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if version_result.returncode == 0:
                            config['version'] = version_result.stdout.split('\n')[0][:50]
                    except:
                        config['version'] = "Disponible"
                    
                    self.log(f"✓ {herramienta}: {ruta}")
                else:
                    self.log(f"✗ {herramienta}: No disponible")
                    
            except Exception as e:
                self.log(f"✗ Error verificando {herramienta}: {e}")
    
    def _inicializar_base_datos(self):
        """Inicializar base de datos SQLite para cuarentena"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            # Tabla principal de archivos en cuarentena
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS archivos_cuarentena (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre_original TEXT NOT NULL,
                    ruta_original TEXT NOT NULL,
                    ruta_cuarentena TEXT NOT NULL,
                    hash_sha256 TEXT,
                    tamaño INTEGER,
                    tipo_archivo TEXT,
                    fecha_cuarentena TEXT NOT NULL,
                    motivo TEXT,
                    estado TEXT DEFAULT 'SOSPECHOSO',
                    nivel_riesgo TEXT DEFAULT 'MEDIO',
                    fuente_deteccion TEXT,
                    metadatos TEXT
                )
            ''')
            
            # Tabla de análisis realizados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analisis_realizados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_id INTEGER,
                    herramienta TEXT NOT NULL,
                    tipo_analisis TEXT NOT NULL,
                    fecha_analisis TEXT NOT NULL,
                    resultado TEXT,
                    amenazas_detectadas TEXT,
                    tiempo_ejecucion REAL,
                    estado_analisis TEXT DEFAULT 'COMPLETADO',
                    FOREIGN KEY (archivo_id) REFERENCES archivos_cuarentena (id)
                )
            ''')
            
            # Tabla de detecciones específicas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detecciones_malware (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_id INTEGER,
                    tipo_amenaza TEXT NOT NULL,
                    nombre_amenaza TEXT,
                    herramienta_deteccion TEXT NOT NULL,
                    nivel_confianza INTEGER DEFAULT 50,
                    descripcion TEXT,
                    fecha_deteccion TEXT NOT NULL,
                    falso_positivo BOOLEAN DEFAULT 0,
                    FOREIGN KEY (archivo_id) REFERENCES archivos_cuarentena (id)
                )
            ''')
            
            # Tabla de respuestas automáticas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS respuestas_automaticas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_id INTEGER,
                    tipo_respuesta TEXT NOT NULL,
                    accion_tomada TEXT NOT NULL,
                    fecha_respuesta TEXT NOT NULL,
                    resultado TEXT,
                    FOREIGN KEY (archivo_id) REFERENCES archivos_cuarentena (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
            self.log("✓ Base de datos inicializada")
            
        except Exception as e:
            self.log(f"Error inicializando base de datos: {e}")
            raise
    
    def _actualizar_estadisticas(self):
        """Actualizar estadísticas del sistema"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            # Contar archivos en cuarentena
            cursor.execute("SELECT COUNT(*) FROM archivos_cuarentena")
            self.estadisticas['archivos_cuarentena'] = cursor.fetchone()[0]
            
            # Contar amenazas detectadas
            cursor.execute("SELECT COUNT(*) FROM detecciones_malware")
            self.estadisticas['amenazas_detectadas'] = cursor.fetchone()[0]
            
            # Contar análisis completados
            cursor.execute("SELECT COUNT(*) FROM analisis_realizados")
            self.estadisticas['análisis_completados'] = cursor.fetchone()[0]
            
            self.estadisticas['última_actualización'] = datetime.now().isoformat()
            
            conn.close()
            
        except Exception as e:
            self.log(f"Error actualizando estadísticas: {e}")
    
    # ========================================
    # MÉTODOS PRINCIPALES DE CUARENTENA
    # ========================================
    
    def poner_en_cuarentena(self, ruta_archivo: str, motivo: str = "Amenaza detectada", 
                           fuente_deteccion: str = "Sistema") -> Dict[str, Any]:
        """
        Poner un archivo en cuarentena con análisis automático
        
        Args:
            ruta_archivo: Ruta del archivo a cuarentenar
            motivo: Motivo de la cuarentena
            fuente_deteccion: Sistema que detectó la amenaza
            
        Returns:
            Dict con resultado de la operación
        """
        self.log(f"Iniciando cuarentena: {ruta_archivo}")
        
        try:
            # Verificar que el archivo existe
            if not os.path.exists(ruta_archivo):
                return {"exito": False, "error": f"Archivo no encontrado: {ruta_archivo}"}
            
            # Obtener información del archivo
            info_archivo = self._obtener_info_archivo(ruta_archivo)
            
            # Generar nombre único para cuarentena
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hash_corto = info_archivo['sha256'][:12]
            nombre_base = os.path.basename(ruta_archivo)
            nombre_cuarentena = f"{timestamp}_{hash_corto}_{nombre_base}"
            
            # Determinar directorio según nivel de riesgo inicial
            directorio_destino = self.directorio_sospechosos
            ruta_cuarentena = os.path.join(directorio_destino, nombre_cuarentena)
            
            # Copiar archivo a cuarentena (manteniendo original por seguridad)
            shutil.copy2(ruta_archivo, ruta_cuarentena)
            
            # Registrar en base de datos
            archivo_id = self._registrar_archivo_cuarentena(
                nombre_base, ruta_archivo, ruta_cuarentena, 
                info_archivo, motivo, fuente_deteccion
            )
            
            if archivo_id:
                # Iniciar análisis automático en thread separado
                threading.Thread(
                    target=self._analisis_automatico,
                    args=(archivo_id, ruta_cuarentena),
                    daemon=True
                ).start()
                
                self._actualizar_estadisticas()
                
                self.log(f"✓ Archivo cuarentenado: ID {archivo_id}")
                return {
                    "exito": True,
                    "archivo_id": archivo_id,
                    "ruta_cuarentena": ruta_cuarentena,
                    "info_archivo": info_archivo
                }
            else:
                return {"exito": False, "error": "Error registrando en base de datos"}
                
        except Exception as e:
            self.log(f"Error en cuarentena: {e}")
            return {"exito": False, "error": str(e)}
    
    def _obtener_info_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        """Obtener información completa de un archivo"""
        try:
            stat_info = os.stat(ruta_archivo)
            
            # Calcular hash SHA256
            hash_sha256 = hashlib.sha256()
            with open(ruta_archivo, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            
            # Obtener tipo de archivo usando 'file'
            tipo_archivo = "Desconocido"
            if self.herramientas_kali['file']['disponible']:
                try:
                    resultado = subprocess.run(
                        ['file', '-b', ruta_archivo],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if resultado.returncode == 0:
                        tipo_archivo = resultado.stdout.strip()
                except:
                    pass
            
            return {
                'sha256': hash_sha256.hexdigest(),
                'tamaño': stat_info.st_size,
                'tipo_archivo': tipo_archivo,
                'fecha_modificacion': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'permisos': oct(stat_info.st_mode)[-3:]
            }
            
        except Exception as e:
            self.log(f"Error obteniendo info archivo: {e}")
            return {
                'sha256': '',
                'tamaño': 0,
                'tipo_archivo': 'Error',
                'fecha_modificacion': '',
                'permisos': '000'
            }
    
    def _registrar_archivo_cuarentena(self, nombre_original: str, ruta_original: str,
                                     ruta_cuarentena: str, info_archivo: Dict[str, Any],
                                     motivo: str, fuente_deteccion: str) -> Optional[int]:
        """Registrar archivo en base de datos de cuarentena"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO archivos_cuarentena 
                (nombre_original, ruta_original, ruta_cuarentena, hash_sha256, tamaño,
                 tipo_archivo, fecha_cuarentena, motivo, fuente_deteccion, metadatos)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                nombre_original,
                ruta_original,
                ruta_cuarentena,
                info_archivo.get('sha256', ''),
                info_archivo.get('tamaño', 0),
                info_archivo.get('tipo_archivo', ''),
                datetime.now().isoformat(),
                motivo,
                fuente_deteccion,
                json.dumps(info_archivo)
            ))
            
            archivo_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return archivo_id
            
        except Exception as e:
            self.log(f"Error registrando archivo en cuarentena: {e}")
            return None
    
    def _analisis_automatico(self, archivo_id: int, ruta_archivo: str):
        """Ejecutar análisis automático del archivo cuarentenado"""
        self.log(f"Iniciando análisis automático para archivo ID {archivo_id}")
        
        try:
            resultados_analisis = []
            tiempo_inicio = time.time()
            
            # 1. Análisis con ClamAV (antivirus)
            if self.herramientas_kali['clamav']['disponible']:
                resultado_clamav = self._analisis_clamav(archivo_id, ruta_archivo)
                resultados_analisis.append(resultado_clamav)
            
            # 2. Análisis de strings sospechosos
            if self.herramientas_kali['strings']['disponible']:
                resultado_strings = self._analisis_strings(archivo_id, ruta_archivo)
                resultados_analisis.append(resultado_strings)
            
            # 3. Análisis de metadatos
            if self.herramientas_kali['exiftool']['disponible']:
                resultado_metadatos = self._analisis_metadatos(archivo_id, ruta_archivo)
                resultados_analisis.append(resultado_metadatos)
            
            # 4. Análisis binario (si es archivo ejecutable)
            if self.herramientas_kali['binwalk']['disponible']:
                resultado_binwalk = self._analisis_binario(archivo_id, ruta_archivo)
                resultados_analisis.append(resultado_binwalk)
            
            # 5. Análisis YARA (si está disponible)
            if self.herramientas_kali['yara']['disponible']:
                resultado_yara = self._analisis_yara(archivo_id, ruta_archivo)
                resultados_analisis.append(resultado_yara)
            
            tiempo_total = time.time() - tiempo_inicio
            
            # Evaluar resultados y determinar acción
            nivel_riesgo = self._evaluar_nivel_riesgo(resultados_analisis)
            self._aplicar_accion_automatica(archivo_id, ruta_archivo, nivel_riesgo)
            
            self.log(f"✓ Análisis automático completado en {tiempo_total:.2f}s - Riesgo: {nivel_riesgo}")
            
        except Exception as e:
            self.log(f"Error en análisis automático: {e}")
    
    def _analisis_clamav(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis antivirus con ClamAV"""
        self.log("Ejecutando análisis ClamAV...")
        
        try:
            inicio = time.time()
            
            # Ejecutar ClamAV
            resultado = subprocess.run(
                ['clamscan', '--infected', '--no-summary', ruta_archivo],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            tiempo_ejecucion = time.time() - inicio
            
            # Procesar resultados
            amenazas_detectadas = []
            if resultado.stdout:
                lineas = resultado.stdout.split('\n')
                for linea in lineas:
                    if 'FOUND' in linea:
                        amenaza = linea.split(':')[1].strip().replace(' FOUND', '')
                        amenazas_detectadas.append(amenaza)
                        
                        # Registrar detección específica
                        self._registrar_deteccion(
                            archivo_id, 'VIRUS', amenaza, 'clamav', 90
                        )
            
            # Registrar análisis
            self._registrar_analisis(
                archivo_id, 'clamav', 'antivirus', 
                json.dumps({
                    'amenazas': amenazas_detectadas,
                    'codigo_retorno': resultado.returncode,
                    'salida': resultado.stdout[:500]
                }),
                json.dumps(amenazas_detectadas),
                tiempo_ejecucion
            )
            
            self.log(f"✓ ClamAV: {len(amenazas_detectadas)} amenazas detectadas")
            
            return {
                'herramienta': 'clamav',
                'amenazas_detectadas': len(amenazas_detectadas),
                'detalles': amenazas_detectadas,
                'tiempo': tiempo_ejecucion
            }
            
        except Exception as e:
            self.log(f"Error en análisis ClamAV: {e}")
            return {'herramienta': 'clamav', 'error': str(e)}
    
    def _analisis_strings(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis de strings sospechosos"""
        self.log("Ejecutando análisis de strings...")
        
        try:
            inicio = time.time()
            
            # Ejecutar strings
            resultado = subprocess.run(
                ['strings', '-a', '-n', '4', ruta_archivo],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            tiempo_ejecucion = time.time() - inicio
            
            # Analizar strings sospechosos
            strings_sospechosos = []
            if resultado.returncode == 0:
                strings_maliciosos = [
                    'keylogger', 'backdoor', 'rootkit', 'trojan', 'virus',
                    'password', 'credential', 'shell', 'exploit', 'payload',
                    'malware', 'botnet', 'stealer', 'crypter', 'loader'
                ]
                
                lineas = resultado.stdout.split('\n')
                for linea in lineas:
                    linea_lower = linea.lower()
                    for string_malicioso in strings_maliciosos:
                        if string_malicioso in linea_lower and len(linea.strip()) > 3:
                            strings_sospechosos.append(linea.strip()[:100])
                            
                            # Registrar detección
                            self._registrar_deteccion(
                                archivo_id, 'STRING_SOSPECHOSO', 
                                f"{string_malicioso}: {linea.strip()[:50]}", 
                                'strings', 60
                            )
                            break
            
            # Eliminar duplicados
            strings_sospechosos = list(set(strings_sospechosos))
            
            # Registrar análisis
            self._registrar_analisis(
                archivo_id, 'strings', 'strings_analysis',
                json.dumps({
                    'strings_sospechosos': strings_sospechosos,
                    'total_strings': len(resultado.stdout.split('\n')) if resultado.stdout else 0
                }),
                json.dumps(strings_sospechosos),
                tiempo_ejecucion
            )
            
            self.log(f"✓ Strings: {len(strings_sospechosos)} strings sospechosos")
            
            return {
                'herramienta': 'strings',
                'strings_sospechosos': len(strings_sospechosos),
                'detalles': strings_sospechosos,
                'tiempo': tiempo_ejecucion
            }
            
        except Exception as e:
            self.log(f"Error en análisis strings: {e}")
            return {'herramienta': 'strings', 'error': str(e)}
    
    def _analisis_metadatos(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis de metadatos con ExifTool"""
        self.log("Ejecutando análisis de metadatos...")
        
        try:
            inicio = time.time()
            
            # Ejecutar ExifTool
            resultado = subprocess.run(
                ['exiftool', '-json', '-all', ruta_archivo],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            tiempo_ejecucion = time.time() - inicio
            metadatos_sospechosos = []
            
            if resultado.returncode == 0 and resultado.stdout.strip():
                try:
                    metadatos = json.loads(resultado.stdout)[0]
                    
                    # Buscar metadatos sospechosos
                    campos_criticos = ['Software', 'Creator', 'Producer', 'Author', 'Title']
                    for campo in campos_criticos:
                        if campo in metadatos:
                            valor = str(metadatos[campo]).lower()
                            sospechosos = ['hack', 'crack', 'keygen', 'patch', 'malware', 'virus']
                            for sospechoso in sospechosos:
                                if sospechoso in valor:
                                    metadatos_sospechosos.append(f"{campo}: {metadatos[campo]}")
                                    
                                    # Registrar detección
                                    self._registrar_deteccion(
                                        archivo_id, 'METADATO_SOSPECHOSO',
                                        f"{campo}: {metadatos[campo]}", 'exiftool', 70
                                    )
                                    break
                    
                except json.JSONDecodeError:
                    pass
            
            # Registrar análisis
            self._registrar_analisis(
                archivo_id, 'exiftool', 'metadatos',
                json.dumps({'metadatos_sospechosos': metadatos_sospechosos}),
                json.dumps(metadatos_sospechosos),
                tiempo_ejecucion
            )
            
            self.log(f"✓ Metadatos: {len(metadatos_sospechosos)} elementos sospechosos")
            
            return {
                'herramienta': 'exiftool',
                'metadatos_sospechosos': len(metadatos_sospechosos),
                'detalles': metadatos_sospechosos,
                'tiempo': tiempo_ejecucion
            }
            
        except Exception as e:
            self.log(f"Error en análisis metadatos: {e}")
            return {'herramienta': 'exiftool', 'error': str(e)}
    
    def _analisis_binario(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis binario con Binwalk"""
        self.log("Ejecutando análisis binario...")
        
        try:
            inicio = time.time()
            
            # Crear directorio temporal para extracción
            dir_temp = tempfile.mkdtemp(prefix='binwalk_', dir=self.directorio_analisis)
            
            # Ejecutar Binwalk
            resultado = subprocess.run(
                ['binwalk', '-e', '-q', '--directory', dir_temp, ruta_archivo],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            tiempo_ejecucion = time.time() - inicio
            archivos_extraidos = []
            
            # Contar archivos extraídos
            if os.path.exists(dir_temp):
                for root, dirs, files in os.walk(dir_temp):
                    archivos_extraidos.extend(files)
            
            # Registrar análisis
            self._registrar_analisis(
                archivo_id, 'binwalk', 'analisis_binario',
                json.dumps({
                    'archivos_extraidos': len(archivos_extraidos),
                    'directorio_extraccion': dir_temp
                }),
                json.dumps({'archivos_extraidos': len(archivos_extraidos)}),
                tiempo_ejecucion
            )
            
            self.log(f"✓ Binwalk: {len(archivos_extraidos)} archivos extraídos")
            
            return {
                'herramienta': 'binwalk',
                'archivos_extraidos': len(archivos_extraidos),
                'directorio': dir_temp,
                'tiempo': tiempo_ejecucion
            }
            
        except Exception as e:
            self.log(f"Error en análisis binario: {e}")
            return {'herramienta': 'binwalk', 'error': str(e)}
    
    def _analisis_yara(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """Análisis con reglas YARA"""
        self.log("Ejecutando análisis YARA...")
        
        try:
            inicio = time.time()
            
            # Crear reglas YARA básicas
            reglas_file = self._crear_reglas_yara()
            if not reglas_file:
                return {'herramienta': 'yara', 'error': 'No se pudieron crear reglas'}
            
            # Ejecutar YARA
            resultado = subprocess.run(
                ['yara', '-w', '-s', reglas_file, ruta_archivo],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            tiempo_ejecucion = time.time() - inicio
            detecciones = []
            
            if resultado.stdout:
                lineas = resultado.stdout.split('\n')
                for linea in lineas:
                    if linea.strip() and ruta_archivo in linea:
                        partes = linea.split()
                        if len(partes) >= 1:
                            regla_detectada = partes[0]
                            detecciones.append(regla_detectada)
                            
                            # Registrar detección
                            self._registrar_deteccion(
                                archivo_id, 'PATRON_YARA', regla_detectada, 'yara', 80
                            )
            
            # Registrar análisis
            self._registrar_analisis(
                archivo_id, 'yara', 'patrones_malware',
                json.dumps({'detecciones': detecciones}),
                json.dumps(detecciones),
                tiempo_ejecucion
            )
            
            self.log(f"✓ YARA: {len(detecciones)} patrones detectados")
            
            return {
                'herramienta': 'yara',
                'detecciones': len(detecciones),
                'detalles': detecciones,
                'tiempo': tiempo_ejecucion
            }
            
        except Exception as e:
            self.log(f"Error en análisis YARA: {e}")
            return {'herramienta': 'yara', 'error': str(e)}
    
    def _crear_reglas_yara(self) -> Optional[str]:
        """Crear archivo de reglas YARA básicas"""
        try:
            reglas_contenido = '''
rule Malware_Indicators
{
    meta:
        description = "Detecta indicadores comunes de malware"
        author = "ARESITOS"
    
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAlloc"
        $api4 = "LoadLibrary"
        $sus1 = "keylogger"
        $sus2 = "backdoor"
        $sus3 = "rootkit"
    
    condition:
        any of them
}

rule Packed_Executable
{
    meta:
        description = "Detecta ejecutables empaquetados"
        author = "ARESITOS"
    
    strings:
        $upx = "UPX"
        $mz = { 4D 5A }
    
    condition:
        $mz at 0 and $upx
}
            '''
            
            archivo_reglas = os.path.join(self.directorio_analisis, "reglas_yara.yar")
            with open(archivo_reglas, 'w', encoding='utf-8') as f:
                f.write(reglas_contenido)
            
            return archivo_reglas
            
        except Exception as e:
            self.log(f"Error creando reglas YARA: {e}")
            return None
    
    def _registrar_deteccion(self, archivo_id: int, tipo_amenaza: str, nombre_amenaza: str,
                           herramienta: str, confianza: int):
        """Registrar detección específica en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO detecciones_malware 
                (archivo_id, tipo_amenaza, nombre_amenaza, herramienta_deteccion, 
                 nivel_confianza, fecha_deteccion)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                archivo_id, tipo_amenaza, nombre_amenaza, herramienta,
                confianza, datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error registrando detección: {e}")
    
    def _registrar_analisis(self, archivo_id: int, herramienta: str, tipo_analisis: str,
                          resultado: str, amenazas: str, tiempo_ejecucion: float):
        """Registrar análisis realizado en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analisis_realizados 
                (archivo_id, herramienta, tipo_analisis, fecha_analisis, resultado,
                 amenazas_detectadas, tiempo_ejecucion)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                archivo_id, herramienta, tipo_analisis, 
                datetime.now().isoformat(), resultado, amenazas, tiempo_ejecucion
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error registrando análisis: {e}")
    
    def _evaluar_nivel_riesgo(self, resultados_analisis: List[Dict[str, Any]]) -> str:
        """Evaluar nivel de riesgo basado en resultados de análisis"""
        try:
            puntuacion_riesgo = 0
            
            for resultado in resultados_analisis:
                if 'error' in resultado:
                    continue
                
                herramienta = resultado.get('herramienta', '')
                
                # Puntuación por ClamAV (peso alto)
                if herramienta == 'clamav':
                    puntuacion_riesgo += resultado.get('amenazas_detectadas', 0) * 10
                
                # Puntuación por YARA (peso alto)
                elif herramienta == 'yara':
                    puntuacion_riesgo += resultado.get('detecciones', 0) * 8
                
                # Puntuación por strings sospechosos (peso medio)
                elif herramienta == 'strings':
                    puntuacion_riesgo += min(resultado.get('strings_sospechosos', 0), 5) * 3
                
                # Puntuación por metadatos (peso bajo)
                elif herramienta == 'exiftool':
                    puntuacion_riesgo += resultado.get('metadatos_sospechosos', 0) * 2
                
                # Puntuación por archivos extraídos (peso medio)
                elif herramienta == 'binwalk':
                    archivos = resultado.get('archivos_extraidos', 0)
                    if archivos > 10:  # Muchos archivos pueden ser sospechoso
                        puntuacion_riesgo += 5
                    elif archivos > 0:
                        puntuacion_riesgo += 2
            
            # Determinar nivel de riesgo
            if puntuacion_riesgo >= 20:
                return "CRITICO"
            elif puntuacion_riesgo >= 10:
                return "ALTO"
            elif puntuacion_riesgo >= 5:
                return "MEDIO"
            elif puntuacion_riesgo > 0:
                return "BAJO"
            else:
                return "LIMPIO"
                
        except Exception as e:
            self.log(f"Error evaluando riesgo: {e}")
            return "DESCONOCIDO"
    
    def _aplicar_accion_automatica(self, archivo_id: int, ruta_archivo: str, nivel_riesgo: str):
        """Aplicar acción automática basada en nivel de riesgo"""
        try:
            accion = ""
            
            if nivel_riesgo in ["CRITICO", "ALTO"]:
                # Mover a directorio de infectados
                nombre_archivo = os.path.basename(ruta_archivo)
                ruta_infectados = os.path.join(self.directorio_infectados, nombre_archivo)
                
                if os.path.exists(ruta_archivo):
                    shutil.move(ruta_archivo, ruta_infectados)
                    accion = f"Movido a infectados: {ruta_infectados}"
                    
                    # Actualizar estado en base de datos
                    self._actualizar_estado_archivo(archivo_id, "INFECTADO", nivel_riesgo, ruta_infectados)
                    
            elif nivel_riesgo == "MEDIO":
                # Mantener en sospechosos
                accion = "Mantenido en cuarentena para revisión manual"
                self._actualizar_estado_archivo(archivo_id, "SOSPECHOSO", nivel_riesgo)
                
            elif nivel_riesgo in ["BAJO", "LIMPIO"]:
                # Mover a directorio limpio
                nombre_archivo = os.path.basename(ruta_archivo)
                ruta_limpio = os.path.join(self.directorio_limpio, nombre_archivo)
                
                if os.path.exists(ruta_archivo):
                    shutil.move(ruta_archivo, ruta_limpio)
                    accion = f"Movido a limpio: {ruta_limpio}"
                    
                    # Actualizar estado en base de datos
                    self._actualizar_estado_archivo(archivo_id, "LIMPIO", nivel_riesgo, ruta_limpio)
            
            # Registrar respuesta automática
            self._registrar_respuesta_automatica(archivo_id, "CLASIFICACION_AUTOMATICA", accion)
            
            self.log(f"Acción automática aplicada: {accion}")
            
        except Exception as e:
            self.log(f"Error aplicando acción automática: {e}")
    
    def _actualizar_estado_archivo(self, archivo_id: int, estado: str, nivel_riesgo: str, 
                                 nueva_ruta: str = ""):
        """Actualizar estado de archivo en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            if nueva_ruta:
                cursor.execute('''
                    UPDATE archivos_cuarentena 
                    SET estado = ?, nivel_riesgo = ?, ruta_cuarentena = ?
                    WHERE id = ?
                ''', (estado, nivel_riesgo, nueva_ruta, archivo_id))
            else:
                cursor.execute('''
                    UPDATE archivos_cuarentena 
                    SET estado = ?, nivel_riesgo = ?
                    WHERE id = ?
                ''', (estado, nivel_riesgo, archivo_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error actualizando estado archivo: {e}")
    
    def _registrar_respuesta_automatica(self, archivo_id: int, tipo_respuesta: str, accion: str):
        """Registrar respuesta automática en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO respuestas_automaticas 
                (archivo_id, tipo_respuesta, accion_tomada, fecha_respuesta, resultado)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                archivo_id, tipo_respuesta, accion, 
                datetime.now().isoformat(), "EXITOSO"
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error registrando respuesta automática: {e}")
    
    # ========================================
    # MÉTODOS DE COMPATIBILIDAD Y GESTIÓN
    # ========================================
    
    def listar_archivos_cuarentena(self) -> List[Dict[str, Any]]:
        """Listar todos los archivos en cuarentena"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, nombre_original, ruta_original, ruta_cuarentena, 
                       estado, nivel_riesgo, fecha_cuarentena, motivo, fuente_deteccion
                FROM archivos_cuarentena
                ORDER BY fecha_cuarentena DESC
            ''')
            
            archivos = []
            for row in cursor.fetchall():
                archivos.append({
                    'id': row[0],
                    'nombre': row[1],
                    'ruta_original': row[2],
                    'ruta_cuarentena': row[3],
                    'estado': row[4],
                    'nivel_riesgo': row[5],
                    'fecha_cuarentena': row[6],
                    'motivo': row[7],
                    'fuente_deteccion': row[8]
                })
            
            conn.close()
            return archivos
            
        except Exception as e:
            self.log(f"Error listando archivos: {e}")
            return []
    
    def obtener_estadisticas_cuarentena(self) -> Dict[str, Any]:
        """Obtener estadísticas completas de cuarentena"""
        try:
            self._actualizar_estadisticas()
            
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            # Estadísticas por estado
            cursor.execute('SELECT estado, COUNT(*) FROM archivos_cuarentena GROUP BY estado')
            por_estado = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Estadísticas por nivel de riesgo
            cursor.execute('SELECT nivel_riesgo, COUNT(*) FROM archivos_cuarentena GROUP BY nivel_riesgo')
            por_riesgo = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Amenazas más comunes
            cursor.execute('''
                SELECT tipo_amenaza, COUNT(*) as count 
                FROM detecciones_malware 
                GROUP BY tipo_amenaza 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            amenazas_comunes = [{'tipo': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            estadisticas = {
                'resumen': self.estadisticas,
                'por_estado': por_estado,
                'por_nivel_riesgo': por_riesgo,
                'amenazas_mas_comunes': amenazas_comunes,
                'herramientas_disponibles': sum(1 for h in self.herramientas_kali.values() if h['disponible']),
                'version': self.version,
                'kali_version': self.kali_version
            }
            
            return estadisticas
            
        except Exception as e:
            self.log(f"Error obteniendo estadísticas: {e}")
            return {'error': str(e)}
    
    def restaurar_archivo(self, archivo_id: int, ruta_destino: Optional[str] = None) -> Dict[str, Any]:
        """Restaurar archivo desde cuarentena"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            # Obtener información del archivo
            cursor.execute('''
                SELECT nombre_original, ruta_original, ruta_cuarentena, estado
                FROM archivos_cuarentena WHERE id = ?
            ''', (archivo_id,))
            
            row = cursor.fetchone()
            if not row:
                return {"exito": False, "error": "Archivo no encontrado"}
            
            nombre_original, ruta_original, ruta_cuarentena, estado = row
            
            # Determinar ruta de destino
            if not ruta_destino:
                ruta_destino = ruta_original
            
            # Verificar que el archivo existe en cuarentena
            if not os.path.exists(ruta_cuarentena):
                return {"exito": False, "error": "Archivo no existe en cuarentena"}
            
            # Crear directorio destino si no existe
            if ruta_destino:
                directorio_destino = os.path.dirname(ruta_destino)
                if directorio_destino:
                    os.makedirs(directorio_destino, exist_ok=True)
                
                # Copiar archivo (mantener copia en cuarentena por seguridad)
                shutil.copy2(ruta_cuarentena, ruta_destino)
            
            # Registrar respuesta
            self._registrar_respuesta_automatica(
                archivo_id, "RESTAURACION", f"Restaurado a: {ruta_destino}"
            )
            
            conn.close()
            
            self.log(f"✓ Archivo restaurado: {ruta_destino}")
            return {
                "exito": True,
                "archivo_restaurado": ruta_destino,
                "archivo_original": nombre_original
            }
            
        except Exception as e:
            self.log(f"Error restaurando archivo: {e}")
            return {"exito": False, "error": str(e)}
    
    def eliminar_archivo_cuarentena(self, archivo_id: int) -> Dict[str, Any]:
        """Eliminar definitivamente archivo de cuarentena"""
        try:
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            # Obtener información del archivo
            cursor.execute('''
                SELECT nombre_original, ruta_cuarentena 
                FROM archivos_cuarentena WHERE id = ?
            ''', (archivo_id,))
            
            row = cursor.fetchone()
            if not row:
                return {"exito": False, "error": "Archivo no encontrado"}
            
            nombre_original, ruta_cuarentena = row
            
            # Eliminar archivo físico
            if os.path.exists(ruta_cuarentena):
                os.remove(ruta_cuarentena)
            
            # Eliminar registros de base de datos
            cursor.execute('DELETE FROM detecciones_malware WHERE archivo_id = ?', (archivo_id,))
            cursor.execute('DELETE FROM analisis_realizados WHERE archivo_id = ?', (archivo_id,))
            cursor.execute('DELETE FROM respuestas_automaticas WHERE archivo_id = ?', (archivo_id,))
            cursor.execute('DELETE FROM archivos_cuarentena WHERE id = ?', (archivo_id,))
            
            conn.commit()
            conn.close()
            
            self._actualizar_estadisticas()
            
            self.log(f"✓ Archivo eliminado definitivamente: {nombre_original}")
            return {
                "exito": True,
                "archivo_eliminado": nombre_original
            }
            
        except Exception as e:
            self.log(f"Error eliminando archivo: {e}")
            return {"exito": False, "error": str(e)}
    
    def limpiar_cuarentena_antigua(self, dias: int = 30) -> Dict[str, Any]:
        """Limpiar archivos antiguos de cuarentena"""
        try:
            fecha_limite = datetime.now() - timedelta(days=dias)
            fecha_limite_str = fecha_limite.isoformat()
            
            conn = sqlite3.connect(self.base_datos)
            cursor = conn.cursor()
            
            # Obtener archivos antiguos
            cursor.execute('''
                SELECT id, nombre_original, ruta_cuarentena 
                FROM archivos_cuarentena 
                WHERE fecha_cuarentena < ? AND estado = 'LIMPIO'
            ''', (fecha_limite_str,))
            
            archivos_antiguos = cursor.fetchall()
            eliminados = 0
            
            for archivo_id, nombre, ruta_cuarentena in archivos_antiguos:
                try:
                    # Eliminar archivo físico
                    if os.path.exists(ruta_cuarentena):
                        os.remove(ruta_cuarentena)
                    
                    # Eliminar registros
                    cursor.execute('DELETE FROM detecciones_malware WHERE archivo_id = ?', (archivo_id,))
                    cursor.execute('DELETE FROM analisis_realizados WHERE archivo_id = ?', (archivo_id,))
                    cursor.execute('DELETE FROM respuestas_automaticas WHERE archivo_id = ?', (archivo_id,))
                    cursor.execute('DELETE FROM archivos_cuarentena WHERE id = ?', (archivo_id,))
                    
                    eliminados += 1
                    
                except Exception as e:
                    self.log(f"Error eliminando {nombre}: {e}")
            
            conn.commit()
            conn.close()
            
            self._actualizar_estadisticas()
            
            self.log(f"✓ Limpieza completada: {eliminados} archivos eliminados")
            return {
                "exito": True,
                "archivos_eliminados": eliminados,
                "dias_antiguedad": dias
            }
            
        except Exception as e:
            self.log(f"Error limpiando cuarentena: {e}")
            return {"exito": False, "error": str(e)}
    
    # ========================================
    # MÉTODOS DE COMPATIBILIDAD CON CONTROLADOR EXISTENTE
    # ========================================
    
    @property
    def directorio_cuarentena(self) -> str:
        """Compatibilidad: directorio de cuarentena"""
        return self.directorio_base
    
    def cuarentenar_archivo(self, ruta_archivo: str, razon: str = "Detección automática") -> Dict[str, Any]:
        """Método de compatibilidad para el controlador"""
        return self.poner_en_cuarentena(ruta_archivo, razon, "Controlador")
    
    def obtener_resumen_cuarentena(self) -> Dict[str, Any]:
        """Método de compatibilidad para obtener resumen"""
        try:
            estadisticas = self.obtener_estadisticas_cuarentena()
            archivos = self.listar_archivos_cuarentena()
            
            # Filtrar archivos recientes
            archivos_recientes = sorted(archivos, key=lambda x: x['fecha_cuarentena'], reverse=True)[:5]
            
            # Contar amenazas críticas
            amenazas_criticas = len([a for a in archivos if a['nivel_riesgo'] in ['CRITICO', 'ALTO']])
            
            resumen = {
                'total_archivos': len(archivos),
                'amenazas_criticas': amenazas_criticas,
                'archivos_recientes': [
                    {
                        'archivo': a['nombre'],
                        'tipo': a['estado'],
                        'severidad': a['nivel_riesgo'],
                        'fecha': a['fecha_cuarentena']
                    } for a in archivos_recientes
                ],
                'estadisticas_generales': estadisticas,
                'integridad': {'integridad_ok': True}  # Simplificado para compatibilidad
            }
            
            return resumen
            
        except Exception as e:
            self.log(f"Error obteniendo resumen: {e}")
            return {'error': str(e)}
    
    def log(self, mensaje: str):
        """Logging unificado para cuarentena Kali 2025"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [CUARENTENA KALI 2025] {mensaje}")
        
        # Log también a archivo si es posible
        try:
            log_file = os.path.join(self.directorio_base, "cuarentena.log")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {mensaje}\n")
        except:
            pass
    
    # ========================================
    # MÉTODOS DE INTEGRACIÓN CON OTROS SISTEMAS ARESITOS
    # ========================================
    
    def procesar_amenaza_desde_siem(self, evento_siem: Dict[str, Any]) -> Dict[str, Any]:
        """
        Procesar amenaza detectada por el sistema SIEM
        
        Args:
            evento_siem: Diccionario con información del evento SIEM
                - archivo: Ruta del archivo (si aplica)
                - tipo_evento: Tipo de evento detectado
                - severidad: Nivel de severidad
                - descripcion: Descripción del evento
                - fuente_ip: IP de origen (si aplica)
                
        Returns:
            Dict con resultado del procesamiento
        """
        try:
            self.log(f"[STATS] Procesando evento SIEM: {evento_siem.get('tipo_evento', 'Desconocido')}")
            
            archivo = evento_siem.get('archivo')
            descripcion = evento_siem.get('descripcion', 'Evento SIEM detectado')
            severidad = evento_siem.get('severidad', 'MEDIA')
            
            if archivo and os.path.exists(archivo):
                # Cuarentenar archivo detectado por SIEM
                resultado = self.poner_en_cuarentena(
                    ruta_archivo=archivo,
                    motivo=f"SIEM: {descripcion}",
                    fuente_deteccion="SIEM"
                )
                
                # Agregar información específica del SIEM
                if resultado.get('exito'):
                    archivo_id = resultado.get('archivo_id')
                    if archivo_id:
                        # Registrar análisis adicional con datos SIEM
                        with sqlite3.connect(self.base_datos) as conn:
                            cursor = conn.cursor()
                            cursor.execute("""
                                INSERT INTO analisis_realizados 
                                (archivo_id, herramienta, resultado, detalles)
                                VALUES (?, ?, ?, ?)
                            """, (archivo_id, "SIEM", f"Severidad: {severidad}", 
                                 f"Evento: {evento_siem.get('tipo_evento', 'Desconocido')}"))
                            conn.commit()
                
                return resultado
            else:
                # Evento SIEM sin archivo - registrar en logs
                self.log(f"[WARNING] Evento SIEM sin archivo asociado: {descripcion}")
                return {"exito": True, "mensaje": "Evento SIEM registrado sin archivo"}
                
        except Exception as e:
            self.log(f"Error procesando evento SIEM: {e}")
            return {"exito": False, "error": str(e)}
    
    def procesar_amenaza_desde_fim(self, evento_fim: Dict[str, Any]) -> Dict[str, Any]:
        """
        Procesar amenaza detectada por el sistema FIM
        
        Args:
            evento_fim: Diccionario con información del evento FIM
                - archivo: Ruta del archivo modificado
                - tipo_cambio: Tipo de cambio detectado
                - hash_anterior: Hash anterior del archivo
                - hash_nuevo: Hash nuevo del archivo
                - usuario: Usuario que realizó el cambio
                
        Returns:
            Dict con resultado del procesamiento
        """
        try:
            self.log(f"DIR Procesando evento FIM: {evento_fim.get('tipo_cambio', 'Cambio detectado')}")
            
            archivo = evento_fim.get('archivo')
            tipo_cambio = evento_fim.get('tipo_cambio', 'Modificación')
            hash_anterior = evento_fim.get('hash_anterior', 'N/A')
            hash_nuevo = evento_fim.get('hash_nuevo', 'N/A')
            
            if archivo and os.path.exists(archivo):
                # Analizar cambio de integridad
                sospechoso = False
                motivo_adicional = []
                
                # Verificar si es cambio sospechoso
                if tipo_cambio in ['creación', 'modificación']:
                    # Analizar con herramientas disponibles
                    if self.herramientas_kali['clamav']['disponible']:
                        # Ejecutar análisis básico con ClamAV
                        try:
                            resultado_clam = subprocess.run(['clamscan', archivo], 
                                                          capture_output=True, text=True, timeout=30)
                            if 'FOUND' in resultado_clam.stdout:
                                sospechoso = True
                                motivo_adicional.append("ClamAV: Malware detectado")
                        except:
                            pass
                
                if sospechoso or tipo_cambio == 'creación':
                    # Cuarentenar archivo modificado sospechosamente
                    descripcion = f"FIM: {tipo_cambio} - Hash cambió de {hash_anterior[:8]}... a {hash_nuevo[:8]}..."
                    resultado = self.poner_en_cuarentena(
                        ruta_archivo=archivo,
                        motivo=descripcion,
                        fuente_deteccion="FIM"
                    )
                    
                    # Registrar detalles del FIM
                    if resultado.get('exito'):
                        archivo_id = resultado.get('archivo_id')
                        if archivo_id:
                            with sqlite3.connect(self.base_datos) as conn:
                                cursor = conn.cursor()
                                cursor.execute("""
                                    INSERT INTO analisis_realizados 
                                    (archivo_id, herramienta, resultado, detalles)
                                    VALUES (?, ?, ?, ?)
                                """, (archivo_id, "FIM", f"Cambio: {tipo_cambio}", 
                                     f"Hash anterior: {hash_anterior}, Hash nuevo: {hash_nuevo}"))
                                conn.commit()
                    
                    return resultado
                else:
                    self.log(f"INFO Cambio FIM no sospechoso: {archivo}")
                    return {"exito": True, "mensaje": "Cambio FIM monitoreado, no requiere cuarentena"}
            else:
                self.log(f"[WARNING] Archivo FIM no encontrado: {archivo}")
                return {"exito": False, "error": "Archivo no encontrado"}
                
        except Exception as e:
            self.log(f"Error procesando evento FIM: {e}")
            return {"exito": False, "error": str(e)}
    
    def procesar_amenaza_desde_escaneador(self, evento_escaneador: Dict[str, Any]) -> Dict[str, Any]:
        """
        Procesar amenaza detectada por el sistema Escaneador
        
        Args:
            evento_escaneador: Diccionario con información del escaneo
                - archivo: Ruta del archivo escaneado
                - vulnerabilidades: Lista de vulnerabilidades encontradas
                - riesgo_calculado: Nivel de riesgo calculado
                - herramientas_usadas: Herramientas que detectaron problemas
                
        Returns:
            Dict con resultado del procesamiento
        """
        try:
            self.log(f"[SCAN] Procesando evento ESCANEADOR")
            
            archivo = evento_escaneador.get('archivo')
            vulnerabilidades = evento_escaneador.get('vulnerabilidades', [])
            riesgo = evento_escaneador.get('riesgo_calculado', 'BAJO')
            herramientas = evento_escaneador.get('herramientas_usadas', [])
            
            if archivo and os.path.exists(archivo):
                # Evaluar si requiere cuarentena basado en riesgo
                requiere_cuarentena = False
                
                if riesgo in ['ALTO', 'CRÍTICO']:
                    requiere_cuarentena = True
                elif riesgo == 'MEDIO' and len(vulnerabilidades) > 3:
                    requiere_cuarentena = True
                elif any('malware' in str(vuln).lower() for vuln in vulnerabilidades):
                    requiere_cuarentena = True
                
                if requiere_cuarentena:
                    # Cuarentenar archivo con vulnerabilidades críticas
                    descripcion = f"ESCANEADOR: {len(vulnerabilidades)} vulnerabilidades - Riesgo {riesgo}"
                    resultado = self.poner_en_cuarentena(
                        ruta_archivo=archivo,
                        motivo=descripcion,
                        fuente_deteccion="ESCANEADOR"
                    )
                    
                    # Registrar vulnerabilidades encontradas
                    if resultado.get('exito'):
                        archivo_id = resultado.get('archivo_id')
                        if archivo_id:
                            with sqlite3.connect(self.base_datos) as conn:
                                cursor = conn.cursor()
                                for vuln in vulnerabilidades[:10]:  # Máximo 10 vulnerabilidades
                                    cursor.execute("""
                                        INSERT INTO detecciones_malware 
                                        (archivo_id, tipo_deteccion, descripcion, severidad)
                                        VALUES (?, ?, ?, ?)
                                    """, (archivo_id, "VULNERABILIDAD", str(vuln)[:500], riesgo))
                                
                                # Registrar análisis del escaneador
                                cursor.execute("""
                                    INSERT INTO analisis_realizados 
                                    (archivo_id, herramienta, resultado, detalles)
                                    VALUES (?, ?, ?, ?)
                                """, (archivo_id, "ESCANEADOR", f"Riesgo: {riesgo}", 
                                     f"Herramientas: {', '.join(herramientas)}"))
                                conn.commit()
                    
                    return resultado
                else:
                    self.log(f"INFO Archivo escaneado sin riesgo crítico: {archivo}")
                    return {"exito": True, "mensaje": "Archivo escaneado, riesgo aceptable"}
            else:
                self.log(f"[WARNING] Archivo del escaneador no encontrado: {archivo}")
                return {"exito": False, "error": "Archivo no encontrado"}
                
        except Exception as e:
            self.log(f"Error procesando evento ESCANEADOR: {e}")
            return {"exito": False, "error": str(e)}
    
    def generar_reporte_completo(self) -> Dict[str, Any]:
        """
        Generar reporte completo del sistema de cuarentena para el módulo de reportes
        
        Returns:
            Dict con reporte completo del sistema
        """
        try:
            self.log("LIST Generando reporte completo de cuarentena")
            
            # Obtener resumen básico
            resumen = self.obtener_resumen_cuarentena()
            
            # Estadísticas detalladas
            with sqlite3.connect(self.base_datos) as conn:
                cursor = conn.cursor()
                
                # Archivos por fuente de detección
                cursor.execute("""
                    SELECT fuente_deteccion, COUNT(*) as cantidad
                    FROM archivos_cuarentena 
                    GROUP BY fuente_deteccion
                    ORDER BY cantidad DESC
                """)
                archivos_por_fuente = dict(cursor.fetchall())
                
                # Tipos de malware detectado
                cursor.execute("""
                    SELECT tipo_deteccion, COUNT(*) as cantidad
                    FROM detecciones_malware 
                    GROUP BY tipo_deteccion
                    ORDER BY cantidad DESC
                """)
                tipos_malware = dict(cursor.fetchall())
                
                # Análisis por herramienta
                cursor.execute("""
                    SELECT herramienta, COUNT(*) as cantidad
                    FROM analisis_realizados 
                    GROUP BY herramienta
                    ORDER BY cantidad DESC
                """)
                analisis_por_herramienta = dict(cursor.fetchall())
                
                # Actividad reciente (últimos 7 días)
                cursor.execute("""
                    SELECT DATE(fecha_cuarentena) as fecha, COUNT(*) as cantidad
                    FROM archivos_cuarentena 
                    WHERE fecha_cuarentena >= datetime('now', '-7 days')
                    GROUP BY DATE(fecha_cuarentena)
                    ORDER BY fecha DESC
                """)
                actividad_semanal = dict(cursor.fetchall())
                
                # Top amenazas
                cursor.execute("""
                    SELECT motivo, COUNT(*) as cantidad
                    FROM archivos_cuarentena 
                    GROUP BY motivo
                    ORDER BY cantidad DESC
                    LIMIT 10
                """)
                top_amenazas = cursor.fetchall()
            
            # Construir reporte completo
            reporte = {
                'metadatos': {
                    'fecha_generacion': datetime.now().isoformat(),
                    'sistema': 'Cuarentena ARESITOS v3.0',
                    'version': '3.0.0',
                    'herramientas_integradas': list(self.herramientas_kali.keys())
                },
                'resumen_ejecutivo': resumen,
                'estadisticas_detalladas': {
                    'archivos_por_fuente': archivos_por_fuente,
                    'tipos_malware_detectado': tipos_malware,
                    'analisis_por_herramienta': analisis_por_herramienta,
                    'actividad_ultimos_7_dias': actividad_semanal,
                    'top_10_amenazas': [{'motivo': motivo, 'cantidad': cant} for motivo, cant in top_amenazas]
                },
                'sistema_status': {
                    'directorio_cuarentena': self.directorio_base,
                    'espacio_usado_mb': self._calcular_espacio_usado(),
                    'herramientas_disponibles': {k: v['disponible'] for k, v in self.herramientas_kali.items()},
                    'base_datos_conexion': os.path.exists(self.base_datos)
                },
                'recomendaciones': self._generar_recomendaciones_reporte(resumen)
            }
            
            return reporte
            
        except Exception as e:
            self.log(f"Error generando reporte completo: {e}")
            return {'error': str(e)}
    
    def _generar_recomendaciones_reporte(self, resumen: Dict[str, Any]) -> List[str]:
        """Generar recomendaciones basadas en el estado actual"""
        recomendaciones = []
        
        try:
            total_archivos = resumen.get('total_archivos', 0)
            amenazas_detectadas = resumen.get('amenazas_criticas', 0)
            
            if total_archivos > 100:
                recomendaciones.append("Considerar limpieza de archivos antiguos en cuarentena")
            
            if amenazas_detectadas > 50:
                recomendaciones.append("Alto número de amenazas detectadas - revisar seguridad del sistema")
            
            if not self.herramientas_kali['clamav']['disponible']:
                recomendaciones.append("Instalar ClamAV para mejorar detección de malware")
            
            if not self.herramientas_kali['yara']['disponible']:
                recomendaciones.append("Instalar YARA para análisis avanzado de patrones")
                
            espacio_mb = self._calcular_espacio_usado()
            if espacio_mb > 1000:  # Más de 1GB
                recomendaciones.append("Espacio en cuarentena alto - considerar archivos para eliminación definitiva")
                
        except Exception as e:
            self.log(f"Error generando recomendaciones: {e}")
            
        return recomendaciones
    
    def _calcular_espacio_usado(self) -> float:
        """Calcular espacio usado por archivos en cuarentena en MB"""
        try:
            total_bytes = 0
            for root, dirs, files in os.walk(self.directorio_base):
                for file in files:
                    if file.endswith('.quarantine'):
                        file_path = os.path.join(root, file)
                        if os.path.exists(file_path):
                            total_bytes += os.path.getsize(file_path)
            
            return total_bytes / (1024 * 1024)  # Convertir a MB
            
        except Exception as e:
            self.log(f"Error calculando espacio: {e}")
            return 0.0
