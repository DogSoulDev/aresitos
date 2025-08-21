# -*- coding: utf-8 -*-
"""
ARESITOS - Modelo Cuarentena Kali Linux 2025
===========================================

Sistema de cuarentena y análisis de malware con herramientas modernas de Kali Linux 2025.
Solo herramientas que se instalan fácilmente con 'apt install'.

Herramientas integradas:
- clamav: Antivirus y detección de malware
- yara: Análisis de patrones maliciosos
- binwalk: Análisis de archivos binarios
- volatility3: Análisis de memoria
- exiftool: Análisis de metadatos
- john: Cracking de passwords
- hashcat: Cracking GPU de hashes

Autor: DogSoulDev
Fecha: 19 de Agosto de 2025
"""

import subprocess
import threading
import json
import os
import time
import shutil
import hashlib
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime
import sqlite3
from pathlib import Path

# Evitar warnings de typing - usar fallback directo
class _CuarentenaAvanzada:
    def __init__(self, gestor_permisos=None):
        self.gestor_permisos = gestor_permisos
        self.configuracion = {}
    
    def log(self, mensaje: str):
        print(f"[CUARENTENA] {mensaje}")

class CuarentenaKali2025(_CuarentenaAvanzada):  # type: ignore
    """
    Sistema de cuarentena avanzado con herramientas Kali Linux 2025
    """
    
    def __init__(self, gestor_permisos=None):
        super().__init__(gestor_permisos)
        self.herramientas_cuarentena = {
            'clamscan': '/usr/bin/clamscan',
            'yara': '/usr/bin/yara',
            'binwalk': '/usr/bin/binwalk',
            'volatility3': '/usr/bin/vol',
            'exiftool': '/usr/bin/exiftool',
            'john': '/usr/bin/john',
            'hashcat': '/usr/bin/hashcat',
            'strings': '/usr/bin/strings',
            'file': '/usr/bin/file',
            'hexdump': '/usr/bin/hexdump'
        }
        self.directorio_cuarentena = "data/cuarentena"
        self.directorio_analisis = "data/analisis"
        self.base_datos_cuarentena = "data/cuarentena_kali2025.db"
        self.verificar_herramientas()
        self.inicializar_directorios()
        self.inicializar_base_datos()
    
    def verificar_herramientas(self):
        """Verifica qué herramientas de cuarentena están disponibles"""
        self.herramientas_disponibles = {}
        
        for herramienta, ruta in self.herramientas_cuarentena.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.herramientas_disponibles[herramienta] = result.stdout.strip()
                    self.log(f"Herramienta {herramienta} disponible en {result.stdout.strip()}")
                else:
                    self.log(f"Herramienta {herramienta} no encontrada")
            except subprocess.TimeoutExpired:
                self.log(f"Timeout verificando {herramienta}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                self.log(f"Error verificando {herramienta}: {e}")
    
    def inicializar_directorios(self):
        """Inicializa directorios de cuarentena y análisis"""
        try:
            os.makedirs(self.directorio_cuarentena, exist_ok=True)
            os.makedirs(self.directorio_analisis, exist_ok=True)
            os.makedirs(f"{self.directorio_cuarentena}/sospechosos", exist_ok=True)
            os.makedirs(f"{self.directorio_cuarentena}/infectados", exist_ok=True)
            os.makedirs(f"{self.directorio_cuarentena}/limpio", exist_ok=True)
            os.makedirs(f"{self.directorio_analisis}/reportes", exist_ok=True)
            os.makedirs(f"{self.directorio_analisis}/extracciones", exist_ok=True)
            
            self.log("Directorios de cuarentena inicializados")
        except (OSError, PermissionError) as e:
            self.log(f"Error inicializando directorios: {e}")
    
    def inicializar_base_datos(self):
        """Inicializa base de datos SQLite para cuarentena"""
        try:
            conn = sqlite3.connect(self.base_datos_cuarentena)
            cursor = conn.cursor()
            
            # Tabla para archivos en cuarentena
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS archivos_cuarentena (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre_original TEXT,
                    ruta_original TEXT,
                    ruta_cuarentena TEXT,
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    tamaño INTEGER,
                    tipo_archivo TEXT,
                    fecha_cuarentena TEXT,
                    motivo_cuarentena TEXT,
                    estado TEXT,
                    riesgo TEXT
                )
            ''')
            
            # Tabla para análisis realizados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analisis_malware (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_id INTEGER,
                    herramienta TEXT,
                    tipo_analisis TEXT,
                    timestamp TEXT,
                    resultado TEXT,
                    amenazas_detectadas TEXT,
                    metadatos TEXT,
                    FOREIGN KEY (archivo_id) REFERENCES archivos_cuarentena (id)
                )
            ''')
            
            # Tabla para detecciones específicas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detecciones_malware (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_id INTEGER,
                    tipo_amenaza TEXT,
                    nombre_amenaza TEXT,
                    herramienta_deteccion TEXT,
                    confianza INTEGER,
                    descripcion TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (archivo_id) REFERENCES archivos_cuarentena (id)
                )
            ''')
            
            # Tabla para análisis de memoria
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analisis_memoria (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_dump TEXT,
                    timestamp TEXT,
                    procesos_sospechosos TEXT,
                    conexiones_red TEXT,
                    artefactos_malware TEXT,
                    sistema_operativo TEXT,
                    herramientas_utilizadas TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            self.log("Base de datos cuarentena inicializada")
            
        except (sqlite3.Error, OSError) as e:
            self.log(f"Error inicializando base de datos cuarentena: {e}")
    
    def poner_en_cuarentena(self, ruta_archivo: str, motivo: str = "Análisis de seguridad") -> Dict[str, Any]:
        """
        Pone un archivo en cuarentena y realiza análisis inicial
        """
        self.log(f"🔒 Poniendo en cuarentena: {ruta_archivo}")
        
        try:
            if not os.path.exists(ruta_archivo):
                return {"error": f"Archivo no existe: {ruta_archivo}"}
            
            # Generar información del archivo
            info_archivo = self._obtener_info_archivo(ruta_archivo)
            
            # Crear nombre único para cuarentena usando SHA256 (seguro)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_cuarentena = f"{timestamp}_{info_archivo['sha256'][:12]}_{os.path.basename(ruta_archivo)}"
            ruta_cuarentena = os.path.join(self.directorio_cuarentena, "sospechosos", nombre_cuarentena)
            
            # Copiar archivo a cuarentena
            shutil.copy2(ruta_archivo, ruta_cuarentena)
            
            # Guardar en base de datos
            archivo_id = self._guardar_archivo_cuarentena(
                os.path.basename(ruta_archivo),
                ruta_archivo,
                ruta_cuarentena,
                info_archivo,
                motivo
            )
            
            # Análisis inicial automático
            self._analisis_inicial_automatico(archivo_id, ruta_cuarentena)
            
            self.log(f"Archivo en cuarentena: ID {archivo_id}")
            return {
                "exito": True,
                "archivo_id": archivo_id,
                "ruta_cuarentena": ruta_cuarentena,
                "info_archivo": info_archivo
            }
            
        except (OSError, PermissionError, FileNotFoundError) as e:
            self.log(f"Error poniendo en cuarentena: {e}")
            return {"error": str(e)}
    
    def _analisis_inicial_automatico(self, archivo_id: int, ruta_archivo: str):
        """Realiza análisis inicial automático del archivo en cuarentena"""
        try:
            # 1. Análisis con ClamAV
            if 'clamscan' in self.herramientas_disponibles:
                self.analisis_antivirus_clamav(archivo_id, ruta_archivo)
            
            # 2. Análisis de tipo de archivo
            if 'file' in self.herramientas_disponibles:
                self.analisis_tipo_archivo(archivo_id, ruta_archivo)
            
            # 3. Análisis de strings
            if 'strings' in self.herramientas_disponibles:
                self.analisis_strings(archivo_id, ruta_archivo)
            
            # 4. Análisis de metadatos
            if 'exiftool' in self.herramientas_disponibles:
                self.analisis_metadatos_exiftool(archivo_id, ruta_archivo)
            
        except Exception as e:
            self.log(f"Error en análisis inicial automático: {e}")
    
    def analisis_antivirus_clamav(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis antivirus con ClamAV
        """
        self.log(f"[SECURITY] Análisis ClamAV: {ruta_archivo}")
        
        if 'clamscan' not in self.herramientas_disponibles:
            return {"error": "clamscan no disponible"}
        
        try:
            cmd = [
                'clamscan',
                '--infected',
                '--no-summary',
                ruta_archivo
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Procesar resultados
            amenazas = self._procesar_resultados_clamav(result.stdout)
            
            # Guardar análisis
            self._guardar_analisis(archivo_id, 'clamav', 'antivirus', {
                'amenazas_detectadas': amenazas,
                'codigo_retorno': result.returncode,
                'salida_completa': result.stdout
            })
            
            # Si hay amenazas, mover a infectados
            if amenazas:
                self._mover_a_infectados(archivo_id, ruta_archivo)
            
            self.log(f"✓ ClamAV completado: {len(amenazas)} amenazas detectadas")
            return {
                "exito": True,
                "amenazas_detectadas": amenazas,
                "herramienta": "clamav"
            }
            
        except Exception as e:
            self.log(f"✓ Error análisis ClamAV: {e}")
            return {"error": str(e)}
    
    def analisis_yara_malware(self, archivo_id: int, ruta_archivo: str, reglas_yara: Optional[str] = None) -> Dict[str, Any]:
        """
        Análisis de malware con reglas YARA
        """
        self.log(f"[TARGET] Análisis YARA: {ruta_archivo}")
        
        if 'yara' not in self.herramientas_disponibles:
            return {"error": "yara no disponible"}
        
        try:
            # Reglas YARA por defecto o personalizadas
            if not reglas_yara:
                reglas_yara = self._crear_reglas_yara_malware()
            
            cmd = [
                'yara',
                '-w',  # No warnings
                '-s',  # Show matching strings
                reglas_yara,
                ruta_archivo
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Procesar resultados
            detecciones = self._procesar_resultados_yara(result.stdout, ruta_archivo)
            
            # Guardar análisis
            self._guardar_analisis(archivo_id, 'yara', 'patrones_malware', {
                'detecciones': detecciones,
                'reglas_utilizadas': reglas_yara,
                'salida_completa': result.stdout
            })
            
            self.log(f"✓ YARA completado: {len(detecciones)} patrones detectados")
            return {
                "exito": True,
                "detecciones": detecciones,
                "herramienta": "yara"
            }
            
        except Exception as e:
            self.log(f"✓ Error análisis YARA: {e}")
            return {"error": str(e)}
    
    def analisis_binario_binwalk(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis de archivo binario con binwalk
        """
        self.log(f"🔍 Análisis binwalk: {ruta_archivo}")
        
        if 'binwalk' not in self.herramientas_disponibles:
            return {"error": "binwalk no disponible"}
        
        try:
            # Directorio de extracción
            dir_extraccion = f"{self.directorio_analisis}/extracciones/{archivo_id}_binwalk"
            os.makedirs(dir_extraccion, exist_ok=True)
            
            # Análisis con extracción
            cmd = [
                'binwalk',
                '-e',  # Extract
                '-M',  # Recursive extraction
                '--dd=.*',  # Extract all
                '-C', dir_extraccion,
                ruta_archivo
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Procesar resultados
            archivos_extraidos = self._procesar_resultados_binwalk(result.stdout, dir_extraccion)
            
            # Guardar análisis
            self._guardar_analisis(archivo_id, 'binwalk', 'analisis_binario', {
                'archivos_extraidos': archivos_extraidos,
                'directorio_extraccion': dir_extraccion,
                'salida_completa': result.stdout
            })
            
            self.log(f"✓ Binwalk completado: {len(archivos_extraidos)} archivos extraídos")
            return {
                "exito": True,
                "archivos_extraidos": archivos_extraidos,
                "directorio_extraccion": dir_extraccion,
                "herramienta": "binwalk"
            }
            
        except Exception as e:
            self.log(f"✓ Error análisis binwalk: {e}")
            return {"error": str(e)}
    
    def analisis_memoria_volatility(self, archivo_dump: str, perfil: str = "auto") -> Dict[str, Any]:
        """
        Análisis de memoria con Volatility3
        """
        self.log(f"[MEMORY] Análisis memoria Volatility: {archivo_dump}")
        
        if 'volatility3' not in self.herramientas_disponibles:
            return {"error": "volatility3 no disponible"}
        
        try:
            resultados_analisis = {}
            
            # Lista de plugins de Volatility3 para análisis
            plugins = [
                'windows.pslist',      # Procesos
                'windows.psscan',      # Escaneo de procesos
                'windows.netstat',     # Conexiones de red
                'windows.malfind',     # Código malicioso
                'windows.handles',     # Handles abiertos
                'windows.cmdline'      # Líneas de comando
            ]
            
            for plugin in plugins:
                try:
                    cmd = [
                        'vol',
                        '-f', archivo_dump,
                        plugin
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    
                    if result.returncode == 0:
                        resultados_analisis[plugin] = result.stdout
                        self.log(f"✓ Plugin {plugin} ejecutado")
                    else:
                        self.log(f"✓ Error en plugin {plugin}: {result.stderr}")
                        
                except Exception as e:
                    self.log(f"✓ Error ejecutando plugin {plugin}: {e}")
            
            # Procesar y analizar resultados
            analisis_procesado = self._procesar_resultados_volatility(resultados_analisis)
            
            # Guardar en base de datos
            self._guardar_analisis_memoria(archivo_dump, analisis_procesado)
            
            self.log(f"✓ Volatility completado: {len(plugins)} plugins ejecutados")
            return {
                "exito": True,
                "analisis": analisis_procesado,
                "plugins_ejecutados": len(resultados_analisis),
                "herramienta": "volatility3"
            }
            
        except Exception as e:
            self.log(f"✓ Error análisis Volatility: {e}")
            return {"error": str(e)}
    
    def analisis_metadatos_exiftool(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis de metadatos con ExifTool
        """
        self.log(f"📋 Análisis metadatos: {ruta_archivo}")
        
        if 'exiftool' not in self.herramientas_disponibles:
            return {"error": "exiftool no disponible"}
        
        try:
            cmd = [
                'exiftool',
                '-json',
                '-all',
                ruta_archivo
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Parsear JSON
                metadatos = json.loads(result.stdout)[0]
                
                # Analizar metadatos sospechosos
                metadatos_sospechosos = self._analizar_metadatos_sospechosos(metadatos)
                
                # Guardar análisis
                self._guardar_analisis(archivo_id, 'exiftool', 'metadatos', {
                    'metadatos_completos': metadatos,
                    'metadatos_sospechosos': metadatos_sospechosos
                })
                
                self.log(f"✓ ExifTool completado: {len(metadatos)} campos de metadatos")
                return {
                    "exito": True,
                    "metadatos": metadatos,
                    "metadatos_sospechosos": metadatos_sospechosos,
                    "herramienta": "exiftool"
                }
            else:
                return {"error": result.stderr}
                
        except Exception as e:
            self.log(f"✓ Error análisis ExifTool: {e}")
            return {"error": str(e)}
    
    def analisis_strings(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis de strings en archivo
        """
        self.log(f"📝 Análisis strings: {ruta_archivo}")
        
        if 'strings' not in self.herramientas_disponibles:
            return {"error": "strings no disponible"}
        
        try:
            cmd = [
                'strings',
                '-a',  # All bytes
                '-n', '4',  # Minimum length 4
                ruta_archivo
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Analizar strings sospechosos
                strings_sospechosos = self._analizar_strings_sospechosos(result.stdout)
                
                # Guardar análisis
                self._guardar_analisis(archivo_id, 'strings', 'strings_analysis', {
                    'strings_sospechosos': strings_sospechosos,
                    'total_strings': len(result.stdout.split('\n'))
                })
                
                self.log(f"✓ Strings completado: {len(strings_sospechosos)} strings sospechosos")
                return {
                    "exito": True,
                    "strings_sospechosos": strings_sospechosos,
                    "herramienta": "strings"
                }
            else:
                return {"error": result.stderr}
                
        except Exception as e:
            self.log(f"✓ Error análisis strings: {e}")
            return {"error": str(e)}
    
    def analisis_tipo_archivo(self, archivo_id: int, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis de tipo de archivo
        """
        self.log(f"📁 Análisis tipo archivo: {ruta_archivo}")
        
        if 'file' not in self.herramientas_disponibles:
            return {"error": "file no disponible"}
        
        try:
            cmd = ['file', '-b', ruta_archivo]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                tipo_archivo = result.stdout.strip()
                
                # Detectar tipos sospechosos
                tipo_sospechoso = self._es_tipo_sospechoso(tipo_archivo)
                
                # Guardar análisis
                self._guardar_analisis(archivo_id, 'file', 'tipo_archivo', {
                    'tipo_archivo': tipo_archivo,
                    'es_sospechoso': tipo_sospechoso
                })
                
                self.log(f"✓ Tipo archivo: {tipo_archivo}")
                return {
                    "exito": True,
                    "tipo_archivo": tipo_archivo,
                    "es_sospechoso": tipo_sospechoso,
                    "herramienta": "file"
                }
            else:
                return {"error": result.stderr}
                
        except Exception as e:
            self.log(f"✓ Error análisis tipo archivo: {e}")
            return {"error": str(e)}
    
    def analisis_completo_cuarentena_kali2025(self, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis completo de malware con todas las herramientas Kali 2025
        """
        self.log(f"[START] INICIANDO ANÁLISIS COMPLETO CUARENTENA: {ruta_archivo}")
        
        # 1. Poner en cuarentena
        resultado_cuarentena = self.poner_en_cuarentena(ruta_archivo, "Análisis completo")
        if not resultado_cuarentena.get("exito"):
            return resultado_cuarentena
        
        archivo_id = resultado_cuarentena["archivo_id"]
        ruta_cuarentena = resultado_cuarentena["ruta_cuarentena"]
        
        resultados = {
            "timestamp": datetime.now().isoformat(),
            "archivo_original": ruta_archivo,
            "archivo_id": archivo_id,
            "herramientas_utilizadas": [],
            "analisis": {}
        }
        
        # 2. Análisis YARA
        self.log("FASE 1: Análisis YARA")
        yara_result = self.analisis_yara_malware(archivo_id, ruta_cuarentena)
        resultados["analisis"]["yara"] = yara_result
        if yara_result.get("exito"):
            resultados["herramientas_utilizadas"].append("yara")
        
        # 3. Análisis binario
        self.log("FASE 2: Análisis binario")
        binwalk_result = self.analisis_binario_binwalk(archivo_id, ruta_cuarentena)
        resultados["analisis"]["binwalk"] = binwalk_result
        if binwalk_result.get("exito"):
            resultados["herramientas_utilizadas"].append("binwalk")
        
        # 4. Análisis metadatos
        self.log("FASE 3: Análisis metadatos")
        exif_result = self.analisis_metadatos_exiftool(archivo_id, ruta_cuarentena)
        resultados["analisis"]["exiftool"] = exif_result
        if exif_result.get("exito"):
            resultados["herramientas_utilizadas"].append("exiftool")
        
        # Resumen final
        total_amenazas = len(yara_result.get("detecciones", []))
        total_extracciones = len(binwalk_result.get("archivos_extraidos", []))
        metadatos_sospechosos = len(exif_result.get("metadatos_sospechosos", []))
        
        resultados["resumen"] = {
            "amenazas_detectadas": total_amenazas,
            "archivos_extraidos": total_extracciones,
            "metadatos_sospechosos": metadatos_sospechosos,
            "herramientas_utilizadas": len(set(resultados["herramientas_utilizadas"])),
            "riesgo_general": self._calcular_riesgo_general(resultados)
        }
        
        self.log("✓ ANÁLISIS COMPLETO CUARENTENA FINALIZADO")
        return resultados
    
    def _obtener_info_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        """Obtiene información completa de un archivo"""
        try:
            stat = os.stat(ruta_archivo)
            
            # Calcular hash SHA256 (seguro)
            sha256_hash = hashlib.sha256()
            
            with open(ruta_archivo, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            return {
                'sha256': sha256_hash.hexdigest(),
                'tamaño': stat.st_size,
                'modificado': datetime.fromtimestamp(stat.st_mtime).isoformat()
            }
        except Exception as e:
            self.log(f"Error obteniendo info archivo: {e}")
            return {}
    
    def _guardar_archivo_cuarentena(self, nombre_original: str, ruta_original: str, 
                                   ruta_cuarentena: str, info_archivo: Dict[str, Any], motivo: str) -> int:
        """Guarda información del archivo en cuarentena en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_cuarentena)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO archivos_cuarentena 
                (nombre_original, ruta_original, ruta_cuarentena, hash_md5, hash_sha256, 
                 tamaño, fecha_cuarentena, motivo_cuarentena, estado, riesgo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                nombre_original,
                ruta_original,
                ruta_cuarentena,
                '',  # MD5 eliminado por seguridad
                info_archivo.get('sha256', ''),
                info_archivo.get('tamaño', 0),
                datetime.now().isoformat(),
                motivo,
                'EN_ANALISIS',
                'DESCONOCIDO'
            ))
            
            archivo_id = cursor.lastrowid or 0
            conn.commit()
            conn.close()
            
            return archivo_id
            
        except Exception as e:
            self.log(f"Error guardando archivo cuarentena: {e}")
            return 0
    
    def _guardar_analisis(self, archivo_id: int, herramienta: str, tipo_analisis: str, resultado: Dict[str, Any]):
        """Guarda resultado de análisis en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_cuarentena)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analisis_malware 
                (archivo_id, herramienta, tipo_analisis, timestamp, resultado, metadatos)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                archivo_id,
                herramienta,
                tipo_analisis,
                datetime.now().isoformat(),
                json.dumps(resultado),
                json.dumps(resultado)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error guardando análisis: {e}")
    
    def _crear_reglas_yara_malware(self) -> str:
        """Crea archivo de reglas YARA para detección de malware"""
        reglas_contenido = '''
rule Windows_Malware_Indicators
{
    meta:
        description = "Detecta indicadores comunes de malware Windows"
        author = "ARESITOS"
    
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAlloc"
        $api4 = "LoadLibrary"
        $api5 = "GetProcAddress"
        $suspicious1 = "keylogger"
        $suspicious2 = "backdoor"
        $suspicious3 = "rootkit"
    
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
        $packed1 = "This program cannot be run"
        $packed2 = { 4D 5A } // MZ header
    
    condition:
        $packed2 at 0 and ($upx or $packed1)
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detecta actividad de red sospechosa"
        author = "ARESITOS"
    
    strings:
        $net1 = "socket"
        $net2 = "connect"
        $net3 = "send"
        $net4 = "recv"
        $suspicious = "https"
    
    condition:
        3 of ($net*) and $suspicious
}
        '''
        
        archivo_reglas = f"{self.directorio_analisis}/yara_malware_rules.yar"
        try:
            with open(archivo_reglas, 'w') as f:
                f.write(reglas_contenido)
            return archivo_reglas
        except (IOError, OSError, PermissionError, FileNotFoundError):
            return ""
    
    def _procesar_resultados_clamav(self, output: str) -> List[str]:
        """Procesa resultados de ClamAV"""
        amenazas = []
        lines = output.split('\n')
        for line in lines:
            if 'FOUND' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    amenaza = parts[1].strip().replace(' FOUND', '')
                    amenazas.append(amenaza)
        return amenazas
    
    def _procesar_resultados_yara(self, output: str, archivo: str) -> List[Dict[str, Any]]:
        """Procesa resultados de YARA"""
        detecciones = []
        lines = output.split('\n')
        for line in lines:
            if line.strip() and archivo in line:
                parts = line.split()
                if len(parts) >= 1:
                    detecciones.append({
                        'regla': parts[0],
                        'archivo': archivo,
                        'tipo': 'malware_pattern'
                    })
        return detecciones
    
    def _mover_a_infectados(self, archivo_id: int, ruta_actual: str):
        """Mueve archivo infectado al directorio de infectados"""
        try:
            nombre_archivo = os.path.basename(ruta_actual)
            ruta_infectados = os.path.join(self.directorio_cuarentena, "infectados", nombre_archivo)
            shutil.move(ruta_actual, ruta_infectados)
            
            # Actualizar base de datos
            conn = sqlite3.connect(self.base_datos_cuarentena)
            cursor = conn.cursor()
            cursor.execute('UPDATE archivos_cuarentena SET estado = ?, riesgo = ?, ruta_cuarentena = ? WHERE id = ?', 
                          ('INFECTADO', 'ALTO', ruta_infectados, archivo_id))
            conn.commit()
            conn.close()
            
            self.log(f"[ALERT] Archivo movido a infectados: {ruta_infectados}")
            
        except Exception as e:
            self.log(f"Error moviendo a infectados: {e}")
    
    # Métodos auxiliares adicionales...
    def _procesar_resultados_binwalk(self, output: str, dir_extraccion: str) -> List[str]:
        """Procesa resultados de binwalk"""
        archivos_extraidos = []
        if os.path.exists(dir_extraccion):
            for root, dirs, files in os.walk(dir_extraccion):
                for file in files:
                    archivos_extraidos.append(os.path.join(root, file))
        return archivos_extraidos
    
    def _analizar_metadatos_sospechosos(self, metadatos: Dict[str, Any]) -> List[str]:
        """Analiza metadatos en busca de elementos sospechosos"""
        sospechosos = []
        campos_criticos = ['Software', 'Creator', 'Producer', 'Author']
        
        for campo in campos_criticos:
            if campo in metadatos:
                valor = str(metadatos[campo]).lower()
                if any(sospechoso in valor for sospechoso in ['hack', 'crack', 'keygen', 'patch']):
                    sospechosos.append(f"{campo}: {metadatos[campo]}")
        
        return sospechosos
    
    def _analizar_strings_sospechosos(self, output: str) -> List[str]:
        """Analiza strings en busca de contenido sospechoso"""
        sospechosos = []
        strings_maliciosos = [
            'keylogger', 'backdoor', 'rootkit', 'trojan', 'virus',
            'password', 'credential', 'admin', 'debug', 'shell'
        ]
        
        lines = output.split('\n')
        for line in lines:
            line_lower = line.lower()
            for string_malicioso in strings_maliciosos:
                if string_malicioso in line_lower:
                    sospechosos.append(line.strip())
                    break
        
        return list(set(sospechosos))  # Eliminar duplicados
    
    def _es_tipo_sospechoso(self, tipo_archivo: str) -> bool:
        """Determina si un tipo de archivo es sospechoso"""
        tipos_sospechosos = [
            'executable', 'PE32', 'ELF', 'script', 'batch',
            'compressed', 'encrypted', 'password protected'
        ]
        
        tipo_lower = tipo_archivo.lower()
        return any(sospechoso in tipo_lower for sospechoso in tipos_sospechosos)
    
    def _calcular_riesgo_general(self, resultados: Dict[str, Any]) -> str:
        """Calcula el riesgo general basado en todos los análisis"""
        puntuacion_riesgo = 0
        
        # Puntuación por amenazas YARA
        amenazas_yara = len(resultados.get("analisis", {}).get("yara", {}).get("detecciones", []))
        puntuacion_riesgo += amenazas_yara * 3
        
        # Puntuación por extracciones binwalk
        extracciones = len(resultados.get("analisis", {}).get("binwalk", {}).get("archivos_extraidos", []))
        puntuacion_riesgo += min(extracciones, 5)  # Máximo 5 puntos
        
        # Puntuación por metadatos sospechosos
        metadatos_sospechosos = len(resultados.get("analisis", {}).get("exiftool", {}).get("metadatos_sospechosos", []))
        puntuacion_riesgo += metadatos_sospechosos * 2
        
        # Determinar nivel de riesgo
        if puntuacion_riesgo >= 10:
            return "ALTO"
        elif puntuacion_riesgo >= 5:
            return "MEDIO"
        elif puntuacion_riesgo > 0:
            return "BAJO"
        else:
            return "LIMPIO"
    
    def log(self, mensaje: str):
        """Log de actividades de cuarentena"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[CUARENTENA KALI2025] {timestamp}: {mensaje}")
        
        # También llamar al log del padre si existe
        try:
            if hasattr(super(), 'log'):
                super().log(mensaje)  # type: ignore
        except (ValueError, TypeError, AttributeError):
            pass
    
    def _procesar_resultados_volatility(self, resultados: Dict[str, str]) -> Dict[str, Any]:
        """Procesa y analiza resultados de Volatility"""
        try:
            analisis = {
                'procesos_sospechosos': [],
                'conexiones_red': [],
                'artefactos_malware': [],
                'resumen': {}
            }
            
            # Procesar cada plugin
            for plugin, output in resultados.items():
                if 'pslist' in plugin or 'psscan' in plugin:
                    # Procesar lista de procesos
                    lines = output.split('\n')
                    for line in lines:
                        if 'suspicious' in line.lower() or 'malware' in line.lower():
                            analisis['procesos_sospechosos'].append(line.strip())
                
                elif 'netstat' in plugin:
                    # Procesar conexiones de red
                    lines = output.split('\n')
                    for line in lines:
                        if 'ESTABLISHED' in line or 'LISTEN' in line:
                            analisis['conexiones_red'].append(line.strip())
                
                elif 'malfind' in plugin:
                    # Procesar código malicioso
                    lines = output.split('\n')
                    for line in lines:
                        if line.strip():
                            analisis['artefactos_malware'].append(line.strip())
            
            # Generar resumen
            analisis['resumen'] = {
                'total_procesos_sospechosos': len(analisis['procesos_sospechosos']),
                'total_conexiones': len(analisis['conexiones_red']),
                'total_artefactos': len(analisis['artefactos_malware'])
            }
            
            return analisis
            
        except Exception as e:
            self.log(f"Error procesando resultados Volatility: {e}")
            return {
                'error': str(e),
                'procesos_sospechosos': [],
                'conexiones_red': [],
                'artefactos_malware': [],
                'resumen': {}
            }
    
    def _guardar_analisis_memoria(self, archivo_dump: str, analisis: Dict[str, Any]):
        """Guarda análisis de memoria en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_cuarentena)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analisis_memoria 
                (archivo_dump, timestamp, procesos_sospechosos, conexiones_red, 
                 artefactos_malware, sistema_operativo, herramientas_utilizadas)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                archivo_dump,
                datetime.now().isoformat(),
                json.dumps(analisis.get('procesos_sospechosos', [])),
                json.dumps(analisis.get('conexiones_red', [])),
                json.dumps(analisis.get('artefactos_malware', [])),
                'Unknown',
                'volatility3'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error guardando análisis memoria: {e}")
