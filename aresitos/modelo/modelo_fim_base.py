
# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
"""

import logging
import os
import hashlib
import json
import time
import sqlite3
from typing import Dict, List, Any, Optional
from datetime import datetime


class FIMBase:
    """
    Clase base para File Integrity Monitoring (FIM).
    Proporciona funcionalidad común para monitoreo de integridad de archivos.
    """
    
    def __init__(self, gestor_permisos=None):
        """
        Inicializar FIM base.
        
        Args:
            gestor_permisos: Gestor de permisos del sistema (opcional)
        """
        self.gestor_permisos = gestor_permisos
        self.logger = logging.getLogger(f"aresitos.{self.__class__.__name__}")
        
        # Configuración de base de datos
        self.db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'fim_kali2025.db')
        self.backup_db_path = f"{self.db_path}.backup"
        
        # Configuración básica
        self.configuracion = {
            'hash_algorithm': 'sha256',
            'backup_enabled': True,
            'log_changes': True,
            'monitor_intervals': 300,  # 5 minutos
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'exclude_extensions': ['.tmp', '.log', '.cache'],
            'exclude_directories': ['/tmp', '/var/log', '/proc', '/sys']
        }
        
        # Estado interno
        self.baseline_created = False
        self.monitoring_active = False
        self.file_baseline = {}
        self.detected_changes = []
        
        # Inicializar base de datos
        self._inicializar_base_datos()
        
        self.logger.info(f"FIM Base inicializado: {self.db_path}")
    
    def _inicializar_base_datos(self):
        """Crear tablas de base de datos si no existen."""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabla de archivos baseline
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_baseline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    permissions TEXT NOT NULL,
                    modified_time TEXT NOT NULL,
                    created_time TEXT NOT NULL,
                    baseline_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Tabla de cambios detectados
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    old_size INTEGER,
                    new_size INTEGER,
                    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT DEFAULT 'medium'
                )
                ''')
                
                # Tabla de directorios monitoreados
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitored_directories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    directory_path TEXT UNIQUE NOT NULL,
                    recursive BOOLEAN DEFAULT 1,
                    enabled BOOLEAN DEFAULT 1,
                    added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Tabla de estadísticas
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS fim_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    files_monitored INTEGER DEFAULT 0,
                    changes_detected INTEGER DEFAULT 0,
                    last_scan_time TIMESTAMP,
                    scan_duration_seconds REAL DEFAULT 0,
                    scan_type TEXT DEFAULT 'manual'
                )
                ''')
                
                conn.commit()
                self.logger.info("Base de datos FIM inicializada correctamente")
                
        except Exception as e:
            self.logger.error(f"Error inicializando base de datos FIM: {e}")
            raise
    
    def log(self, mensaje: str, nivel: str = 'info'):
        """
        Sistema de logging unificado.
        
        Args:
            mensaje: Mensaje a loggear
            nivel: Nivel de log (info, warning, error)
        """
        if self.configuracion.get('log_changes', True):
            if nivel == 'warning':
                self.logger.warning(mensaje)
            elif nivel == 'error':
                self.logger.error(mensaje)
            else:
                self.logger.info(mensaje)
        
        print(f"[FIM] {mensaje}")
    
    def calcular_hash_archivo(self, ruta_archivo: str) -> Optional[str]:
        """
        Calcular hash de un archivo.
        
        Args:
            ruta_archivo: Ruta al archivo
            
        Returns:
            Hash del archivo o None si hay error
        """
        try:
            if not os.path.exists(ruta_archivo) or not os.path.isfile(ruta_archivo):
                return None
            
            # Verificar tamaño del archivo
            tamaño = os.path.getsize(ruta_archivo)
            if tamaño > self.configuracion['max_file_size']:
                self.log(f"Archivo muy grande para hash: {ruta_archivo} ({tamaño} bytes)", 'warning')
                return None
            
            algoritmo = self.configuracion['hash_algorithm']
            hash_obj = hashlib.new(algoritmo)
            
            with open(ruta_archivo, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
            
        except (OSError, IOError) as e:
            self.log(f"Error calculando hash para {ruta_archivo}: {e}", 'error')
            return None
        except Exception as e:
            self.log(f"Error inesperado calculando hash: {e}", 'error')
            return None
    
    def obtener_metadatos_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        """
        Obtener metadatos completos de un archivo.
        
        Args:
            ruta_archivo: Ruta al archivo
            
        Returns:
            Diccionario con metadatos del archivo
        """
        try:
            if not os.path.exists(ruta_archivo):
                return {}
            
            stat = os.stat(ruta_archivo)
            
            return {
                'path': ruta_archivo,
                'size': stat.st_size,
                'permissions': oct(stat.st_mode)[-3:],
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'hash': self.calcular_hash_archivo(ruta_archivo)
            }
            
        except Exception as e:
            self.log(f"Error obteniendo metadatos de {ruta_archivo}: {e}", 'error')
            return {}
    
    def crear_baseline(self, directorios: List[str], recursivo: bool = True) -> Dict[str, Any]:
        """
        Crear baseline de archivos para monitoreo.
        
        Args:
            directorios: Lista de directorios a incluir en baseline
            recursivo: Si incluir subdirectorios
            
        Returns:
            Diccionario con resultado de la operación
        """
        self.log(f"Iniciando creación de baseline para {len(directorios)} directorios")
        
        resultado = {
            'exito': False,
            'archivos_procesados': 0,
            'archivos_añadidos': 0,
            'errores': [],
            'tiempo_ejecucion': 0
        }
        
        tiempo_inicio = time.time()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Limpiar baseline anterior
                cursor.execute('DELETE FROM file_baseline')
                cursor.execute('DELETE FROM monitored_directories')
                
                # Agregar directorios a monitorear
                for directorio in directorios:
                    if os.path.exists(directorio):
                        cursor.execute('''
                        INSERT OR REPLACE INTO monitored_directories 
                        (directory_path, recursive) VALUES (?, ?)
                        ''', (directorio, recursivo))
                
                # Procesar archivos
                for directorio in directorios:
                    if not os.path.exists(directorio):
                        resultado['errores'].append(f"Directorio no existe: {directorio}")
                        continue
                    
                    for archivo in self._obtener_archivos_directorio(directorio, recursivo):
                        resultado['archivos_procesados'] += 1
                        
                        # Filtrar archivos excluidos
                        if self._archivo_excluido(archivo):
                            continue
                        
                        metadatos = self.obtener_metadatos_archivo(archivo)
                        if metadatos and metadatos['hash']:
                            try:
                                cursor.execute('''
                                INSERT OR REPLACE INTO file_baseline
                                (file_path, file_hash, file_size, permissions, 
                                 modified_time, created_time) 
                                VALUES (?, ?, ?, ?, ?, ?)
                                ''', (
                                    metadatos['path'],
                                    metadatos['hash'],
                                    metadatos['size'],
                                    metadatos['permissions'],
                                    metadatos['modified_time'],
                                    metadatos['created_time']
                                ))
                                resultado['archivos_añadidos'] += 1
                                
                            except sqlite3.Error as e:
                                resultado['errores'].append(f"Error DB para {archivo}: {e}")
                
                conn.commit()
                self.baseline_created = True
                resultado['exito'] = True
                
        except Exception as e:
            resultado['errores'].append(f"Error creando baseline: {e}")
            self.log(f"Error creando baseline: {e}", 'error')
        
        resultado['tiempo_ejecucion'] = round(time.time() - tiempo_inicio, 2)
        
        self.log(f"Baseline creado: {resultado['archivos_añadidos']} archivos, "
                f"{len(resultado['errores'])} errores, {resultado['tiempo_ejecucion']}s")
        
        return resultado
    
    def _obtener_archivos_directorio(self, directorio: str, recursivo: bool = True) -> List[str]:
        """Obtener lista de archivos en directorio."""
        archivos = []
        
        try:
            if recursivo:
                for root, dirs, files in os.walk(directorio):
                    # Filtrar directorios excluidos
                    dirs[:] = [d for d in dirs if not self._directorio_excluido(os.path.join(root, d))]
                    
                    for archivo in files:
                        ruta_completa = os.path.join(root, archivo)
                        archivos.append(ruta_completa)
            else:
                if os.path.exists(directorio):
                    for item in os.listdir(directorio):
                        ruta_completa = os.path.join(directorio, item)
                        if os.path.isfile(ruta_completa):
                            archivos.append(ruta_completa)
        
        except (OSError, PermissionError) as e:
            self.log(f"Error accediendo a directorio {directorio}: {e}", 'warning')
        
        return archivos
    
    def _archivo_excluido(self, ruta_archivo: str) -> bool:
        """Verificar si un archivo debe ser excluido."""
        # Verificar extensiones excluidas
        _, ext = os.path.splitext(ruta_archivo)
        if ext.lower() in self.configuracion['exclude_extensions']:
            return True
        
        # Verificar directorios excluidos
        for dir_excluido in self.configuracion['exclude_directories']:
            if ruta_archivo.startswith(dir_excluido):
                return True
        
        return False
    
    def _directorio_excluido(self, ruta_directorio: str) -> bool:
        """Verificar si un directorio debe ser excluido."""
        for dir_excluido in self.configuracion['exclude_directories']:
            if ruta_directorio.startswith(dir_excluido):
                return True
        return False
    
    def verificar_integridad(self) -> Dict[str, Any]:
        """
        Verificar integridad de archivos contra baseline.
        
        Returns:
            Diccionario con resultado de verificación
        """
        if not self.baseline_created:
            return {
                'exito': False,
                'error': 'No existe baseline. Crear baseline primero.'
            }
        
        self.log("Iniciando verificación de integridad")
        
        resultado = {
            'exito': False,
            'archivos_verificados': 0,
            'cambios_detectados': 0,
            'archivos_nuevos': 0,
            'archivos_eliminados': 0,
            'archivos_modificados': 0,
            'cambios': [],
            'tiempo_ejecucion': 0
        }
        
        tiempo_inicio = time.time()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Obtener baseline
                cursor.execute('SELECT file_path, file_hash, file_size FROM file_baseline')
                baseline = {row[0]: {'hash': row[1], 'size': row[2]} for row in cursor.fetchall()}
                
                # Obtener directorios monitoreados
                cursor.execute('SELECT directory_path, recursive FROM monitored_directories WHERE enabled = 1')
                directorios = cursor.fetchall()
                
                archivos_actuales = set()
                
                # Verificar archivos actuales
                for directorio, recursivo in directorios:
                    for archivo in self._obtener_archivos_directorio(directorio, bool(recursivo)):
                        if self._archivo_excluido(archivo):
                            continue
                        
                        archivos_actuales.add(archivo)
                        resultado['archivos_verificados'] += 1
                        
                        # Verificar contra baseline
                        metadatos = self.obtener_metadatos_archivo(archivo)
                        if not metadatos or not metadatos['hash']:
                            continue
                        
                        if archivo in baseline:
                            # Archivo existe en baseline
                            if (metadatos['hash'] != baseline[archivo]['hash'] or
                                metadatos['size'] != baseline[archivo]['size']):
                                # Archivo modificado
                                cambio = {
                                    'tipo': 'modificado',
                                    'archivo': archivo,
                                    'hash_anterior': baseline[archivo]['hash'],
                                    'hash_actual': metadatos['hash'],
                                    'tamaño_anterior': baseline[archivo]['size'],
                                    'tamaño_actual': metadatos['size']
                                }
                                resultado['cambios'].append(cambio)
                                resultado['archivos_modificados'] += 1
                                
                                # Registrar en BD
                                cursor.execute('''
                                INSERT INTO file_changes 
                                (file_path, change_type, old_hash, new_hash, old_size, new_size)
                                VALUES (?, ?, ?, ?, ?, ?)
                                ''', (archivo, 'modificado', baseline[archivo]['hash'],
                                     metadatos['hash'], baseline[archivo]['size'], metadatos['size']))
                        else:
                            # Archivo nuevo
                            cambio = {
                                'tipo': 'nuevo',
                                'archivo': archivo,
                                'hash_actual': metadatos['hash'],
                                'tamaño_actual': metadatos['size']
                            }
                            resultado['cambios'].append(cambio)
                            resultado['archivos_nuevos'] += 1
                            
                            cursor.execute('''
                            INSERT INTO file_changes 
                            (file_path, change_type, new_hash, new_size)
                            VALUES (?, ?, ?, ?)
                            ''', (archivo, 'nuevo', metadatos['hash'], metadatos['size']))
                
                # Detectar archivos eliminados
                archivos_baseline = set(baseline.keys())
                archivos_eliminados = archivos_baseline - archivos_actuales
                
                for archivo in archivos_eliminados:
                    cambio = {
                        'tipo': 'eliminado',
                        'archivo': archivo,
                        'hash_anterior': baseline[archivo]['hash']
                    }
                    resultado['cambios'].append(cambio)
                    resultado['archivos_eliminados'] += 1
                    
                    cursor.execute('''
                    INSERT INTO file_changes 
                    (file_path, change_type, old_hash)
                    VALUES (?, ?, ?)
                    ''', (archivo, 'eliminado', baseline[archivo]['hash']))
                
                conn.commit()
                resultado['cambios_detectados'] = len(resultado['cambios'])
                resultado['exito'] = True
                
        except Exception as e:
            self.log(f"Error verificando integridad: {e}", 'error')
            resultado['error'] = str(e)
        
        resultado['tiempo_ejecucion'] = round(time.time() - tiempo_inicio, 2)
        
        self.log(f"Verificación completada: {resultado['cambios_detectados']} cambios detectados "
                f"en {resultado['tiempo_ejecucion']}s")
        
        return resultado
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtener estadísticas del sistema FIM.
        
        Returns:
            Diccionario con estadísticas
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Contar archivos en baseline
                cursor.execute('SELECT COUNT(*) FROM file_baseline')
                archivos_baseline = cursor.fetchone()[0]
                
                # Contar cambios detectados
                cursor.execute('SELECT COUNT(*) FROM file_changes')
                total_cambios = cursor.fetchone()[0]
                
                # Cambios por tipo
                cursor.execute('''
                SELECT change_type, COUNT(*) 
                FROM file_changes 
                GROUP BY change_type
                ''')
                cambios_por_tipo = dict(cursor.fetchall())
                
                # Directorios monitoreados
                cursor.execute('SELECT COUNT(*) FROM monitored_directories WHERE enabled = 1')
                directorios_activos = cursor.fetchone()[0]
                
                return {
                    'baseline_creado': self.baseline_created,
                    'archivos_en_baseline': archivos_baseline,
                    'directorios_monitoreados': directorios_activos,
                    'total_cambios_detectados': total_cambios,
                    'cambios_por_tipo': cambios_por_tipo,
                    'configuracion': self.configuracion.copy(),
                    'estado_base_datos': os.path.exists(self.db_path),
                    'tamaño_base_datos_mb': round(os.path.getsize(self.db_path) / 1024 / 1024, 2) if os.path.exists(self.db_path) else 0
                }
                
        except Exception as e:
            self.log(f"Error obteniendo estadísticas: {e}", 'error')
            return {
                'error': str(e),
                'baseline_creado': self.baseline_created
            }
