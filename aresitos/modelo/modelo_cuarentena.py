# -*- coding: utf-8 -*-
"""
ARESITOS - Modelo de Cuarentena
Gestión segura de archivos en cuarentena usando herramientas nativas de Kali Linux
"""

import os
import shutil
import hashlib
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class CuarentenaKali2025:
    """
    Modelo de cuarentena nativo para ARESITOS.
    Utiliza herramientas nativas de Kali Linux sin dependencias externas.
    """
    
    def __init__(self, directorio_base: Optional[str] = None):
        """
        Inicializar sistema de cuarentena.
        
        Args:
            directorio_base: Directorio base para almacenar archivos en cuarentena
        """
        self.logger = logging.getLogger(f"aresitos.{self.__class__.__name__}")

        # Determinar ruta base del proyecto (siempre relativa al workspace)
        ruta_workspace = Path(__file__).resolve().parent.parent
        ruta_data = ruta_workspace / "data"
        ruta_cuarentena_default = ruta_data / "cuarentena"

        # Validar y corregir directorio_base si es necesario
        if directorio_base:
            directorio_base_path = Path(directorio_base).resolve()
            # Si el path NO está dentro del workspace, forzar ruta relativa
            try:
                directorio_base_path.relative_to(ruta_workspace)
                self.directorio_cuarentena = str(directorio_base_path)
            except ValueError:
                self.logger.warning(f"[ARESITOS] Ruta de cuarentena fuera del proyecto: {directorio_base_path}. Se usará la ruta estándar: {ruta_cuarentena_default}")
                self.directorio_cuarentena = str(ruta_cuarentena_default)
        else:
            self.directorio_cuarentena = str(ruta_cuarentena_default)

        # Crear estructura de directorios
        self._crear_estructura_directorios()

        # Base de datos de cuarentena
        self.db_path = os.path.join(self.directorio_cuarentena, "cuarentena_kali2025.db")
        self._inicializar_base_datos()

        self.logger.info(f"Cuarentena inicializada en: {self.directorio_cuarentena}")
    
    def _crear_estructura_directorios(self):
        """Solo crear el directorio principal de cuarentena si es estrictamente necesario. No crear subdirectorios automáticamente."""
        try:
            if not os.path.isdir(self.directorio_cuarentena):
                os.makedirs(self.directorio_cuarentena, mode=0o750, exist_ok=True)
        except PermissionError as e:
            self.logger.error(f"Permiso denegado al crear la carpeta de cuarentena: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error creando estructura de cuarentena: {e}")
            raise
    
    def _inicializar_base_datos(self):
        """Inicializar base de datos SQLite para tracking de cuarentena."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS archivos_cuarentena (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ruta_original TEXT NOT NULL,
                        ruta_cuarentena TEXT NOT NULL,
                        hash_sha256 TEXT NOT NULL,
                        tipo_amenaza TEXT,
                        razon TEXT,
                        fecha_cuarentena TEXT NOT NULL,
                        tamano_bytes INTEGER,
                        estado TEXT DEFAULT 'activo',
                        metadatos TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS operaciones_cuarentena (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        archivo_id INTEGER,
                        operacion TEXT NOT NULL,
                        fecha TEXT NOT NULL,
                        usuario TEXT,
                        resultado TEXT,
                        FOREIGN KEY (archivo_id) REFERENCES archivos_cuarentena (id)
                    )
                ''')
                
                conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error inicializando base de datos de cuarentena: {e}")
            raise
    
    def _calcular_hash_archivo(self, ruta_archivo: str) -> str:
        """Calcular hash SHA256 de un archivo."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(ruta_archivo, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculando hash de {ruta_archivo}: {e}")
            return ""
    
    def poner_en_cuarentena(self, ruta_archivo: str, tipo_amenaza: str = "desconocido", razon: str = "") -> Dict[str, Any]:
        """
        Poner un archivo en cuarentena de forma segura.
        
        Args:
            ruta_archivo: Ruta del archivo a poner en cuarentena
            tipo_amenaza: Tipo de amenaza detectada
            razon: Razón específica para la cuarentena
            
        Returns:
            Diccionario con resultado de la operación
        """
        resultado = {
            'exito': False,
            'mensaje': '',
            'ruta_cuarentena': '',
            'hash_archivo': '',
            'id_cuarentena': None
        }
        
        try:
            # Validar que el archivo existe
            if not os.path.exists(ruta_archivo):
                resultado['mensaje'] = f"Archivo no encontrado: {ruta_archivo}"
                return resultado
            
            # Calcular hash del archivo
            hash_archivo = self._calcular_hash_archivo(ruta_archivo)
            if not hash_archivo:
                resultado['mensaje'] = "Error calculando hash del archivo"
                return resultado
            
            # Generar nombre único para cuarentena
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_archivo = os.path.basename(ruta_archivo)
            nombre_cuarentena = f"{timestamp}_{hash_archivo[:16]}_{nombre_archivo}"
            ruta_cuarentena = os.path.join(self.directorio_cuarentena, "archivos", nombre_cuarentena)
            
            # Copiar archivo a cuarentena (no mover para preservar evidencia)
            shutil.copy2(ruta_archivo, ruta_cuarentena)
            
            # Cambiar permisos restrictivos
            os.chmod(ruta_cuarentena, 0o600)
            
            # Obtener metadatos
            stat_info = os.stat(ruta_archivo)
            metadatos = {
                'tamano': stat_info.st_size,
                'fecha_modificacion': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'fecha_acceso': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'permisos': oct(stat_info.st_mode)[-3:]
            }
            
            # Registrar en base de datos
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO archivos_cuarentena 
                    (ruta_original, ruta_cuarentena, hash_sha256, tipo_amenaza, razon, 
                     fecha_cuarentena, tamano_bytes, metadatos)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ruta_archivo,
                    ruta_cuarentena,
                    hash_archivo,
                    tipo_amenaza,
                    razon,
                    datetime.now().isoformat(),
                    stat_info.st_size,
                    json.dumps(metadatos)
                ))
                
                archivo_id = cursor.lastrowid
                
                # Registrar operación
                cursor.execute('''
                    INSERT INTO operaciones_cuarentena 
                    (archivo_id, operacion, fecha, usuario, resultado)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    archivo_id,
                    "CUARENTENA",
                    datetime.now().isoformat(),
                    os.getenv('USER', 'unknown'),
                    "EXITOSO"
                ))
                
                conn.commit()
            
            # Eliminar archivo original después de verificar copia
            if os.path.exists(ruta_cuarentena) and self._verificar_integridad_archivo(ruta_cuarentena, hash_archivo):
                os.remove(ruta_archivo)
                
                resultado.update({
                    'exito': True,
                    'mensaje': f"Archivo puesto en cuarentena exitosamente",
                    'ruta_cuarentena': ruta_cuarentena,
                    'hash_archivo': hash_archivo,
                    'id_cuarentena': archivo_id
                })
                
                self.logger.info(f"Archivo {ruta_archivo} puesto en cuarentena: {nombre_cuarentena}")
            else:
                resultado['mensaje'] = "Error verificando integridad del archivo en cuarentena"
            
        except Exception as e:
            resultado['mensaje'] = f"Error poniendo archivo en cuarentena: {str(e)}"
            self.logger.error(f"Error en cuarentena de {ruta_archivo}: {e}")
        
        return resultado
    
    def _verificar_integridad_archivo(self, ruta_archivo: str, hash_esperado: str) -> bool:
        """Verificar integridad de archivo comparando hashes."""
        try:
            hash_actual = self._calcular_hash_archivo(ruta_archivo)
            return hash_actual == hash_esperado
        except Exception:
            return False
    
    def quitar_de_cuarentena(self, id_cuarentena: Optional[int] = None, ruta_original: Optional[str] = None, restaurar: bool = True) -> Dict[str, Any]:
        """
        Quitar archivo de cuarentena y opcionalmente restaurarlo.
        
        Args:
            id_cuarentena: ID del archivo en cuarentena
            ruta_original: Ruta original del archivo (alternativo al ID)
            restaurar: Si True, restaurar archivo; si False, eliminarlo
            
        Returns:
            Diccionario con resultado de la operación
        """
        resultado = {
            'exito': False,
            'mensaje': '',
            'accion_realizada': ''
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Buscar archivo por ID o ruta original
                if id_cuarentena:
                    cursor.execute('''
                        SELECT id, ruta_original, ruta_cuarentena, hash_sha256, estado
                        FROM archivos_cuarentena WHERE id = ? AND estado = 'activo'
                    ''', (id_cuarentena,))
                elif ruta_original:
                    cursor.execute('''
                        SELECT id, ruta_original, ruta_cuarentena, hash_sha256, estado
                        FROM archivos_cuarentena WHERE ruta_original = ? AND estado = 'activo'
                    ''', (ruta_original,))
                else:
                    resultado['mensaje'] = "Debe proporcionar ID de cuarentena o ruta original"
                    return resultado
                
                archivo_info = cursor.fetchone()
                if not archivo_info:
                    resultado['mensaje'] = "Archivo no encontrado en cuarentena activa"
                    return resultado
                
                archivo_id, ruta_orig, ruta_cuarentena, hash_archivo, estado = archivo_info
                
                # Verificar que el archivo en cuarentena existe
                if not os.path.exists(ruta_cuarentena):
                    resultado['mensaje'] = f"Archivo en cuarentena no encontrado: {ruta_cuarentena}"
                    return resultado
                
                if restaurar:
                    # Restaurar archivo a ubicación original
                    os.makedirs(os.path.dirname(ruta_orig), exist_ok=True)
                    shutil.copy2(ruta_cuarentena, ruta_orig)
                    
                    # Verificar integridad después de restaurar
                    if self._verificar_integridad_archivo(ruta_orig, hash_archivo):
                        accion = "RESTAURADO"
                        resultado['accion_realizada'] = "restaurado"
                        resultado['mensaje'] = f"Archivo restaurado exitosamente a {ruta_orig}"
                    else:
                        os.remove(ruta_orig)  # Limpiar si falló verificación
                        resultado['mensaje'] = "Error: Integridad del archivo no verificada"
                        return resultado
                else:
                    # Solo marcar como eliminado, mantener en cuarentena por auditoría
                    accion = "ELIMINADO"
                    resultado['accion_realizada'] = "eliminado"
                    resultado['mensaje'] = "Archivo marcado como eliminado en cuarentena"
                
                # Eliminar archivo de cuarentena físicamente
                os.remove(ruta_cuarentena)
                
                # Actualizar estado en base de datos
                cursor.execute('''
                    UPDATE archivos_cuarentena SET estado = ? WHERE id = ?
                ''', ('eliminado' if not restaurar else 'restaurado', archivo_id))
                
                # Registrar operación
                cursor.execute('''
                    INSERT INTO operaciones_cuarentena 
                    (archivo_id, operacion, fecha, usuario, resultado)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    archivo_id,
                    accion,
                    datetime.now().isoformat(),
                    os.getenv('USER', 'unknown'),
                    "EXITOSO"
                ))
                
                conn.commit()
                resultado['exito'] = True
                
                self.logger.info(f"Archivo {ruta_orig} {accion.lower()} de cuarentena")
                
        except Exception as e:
            resultado['mensaje'] = f"Error quitando archivo de cuarentena: {str(e)}"
            self.logger.error(f"Error en operación de cuarentena: {e}")
        
        return resultado
    
    def listar_archivos_cuarentena(self, estado: str = "activo") -> List[Dict[str, Any]]:
        """
        Listar archivos en cuarentena.
        
        Args:
            estado: Estado de los archivos ('activo', 'restaurado', 'eliminado', 'todos')
            
        Returns:
            Lista de diccionarios con información de archivos
        """
        archivos = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if estado == "todos":
                    cursor.execute('''
                        SELECT id, ruta_original, ruta_cuarentena, hash_sha256, tipo_amenaza,
                               razon, fecha_cuarentena, tamano_bytes, estado, metadatos
                        FROM archivos_cuarentena ORDER BY fecha_cuarentena DESC
                    ''')
                else:
                    cursor.execute('''
                        SELECT id, ruta_original, ruta_cuarentena, hash_sha256, tipo_amenaza,
                               razon, fecha_cuarentena, tamano_bytes, estado, metadatos
                        FROM archivos_cuarentena WHERE estado = ? ORDER BY fecha_cuarentena DESC
                    ''', (estado,))
                
                for fila in cursor.fetchall():
                    archivo_info = {
                        'id': fila[0],
                        'ruta_original': fila[1],
                        'ruta_cuarentena': fila[2],
                        'hash_sha256': fila[3],
                        'tipo_amenaza': fila[4],
                        'razon': fila[5],
                        'fecha_cuarentena': fila[6],
                        'tamano_bytes': fila[7],
                        'estado': fila[8],
                        'metadatos': json.loads(fila[9]) if fila[9] else {}
                    }
                    archivos.append(archivo_info)
                    
        except Exception as e:
            self.logger.error(f"Error listando archivos en cuarentena: {e}")
        
        return archivos
    
    def verificar_integridad(self) -> Dict[str, Any]:
        """
        Verificar integridad de todos los archivos en cuarentena.
        
        Returns:
            Diccionario con estadísticas de verificación
        """
        resultado = {
            'exito': False,
            'archivos_verificados': 0,
            'archivos_corruptos': 0,
            'archivos_faltantes': 0,
            'errores': []
        }
        
        try:
            archivos = self.listar_archivos_cuarentena("activo")
            
            for archivo in archivos:
                try:
                    ruta_cuarentena = archivo['ruta_cuarentena']
                    hash_esperado = archivo['hash_sha256']
                    
                    if not os.path.exists(ruta_cuarentena):
                        resultado['archivos_faltantes'] += 1
                        resultado['errores'].append(f"Archivo faltante: {ruta_cuarentena}")
                        continue
                    
                    if not self._verificar_integridad_archivo(ruta_cuarentena, hash_esperado):
                        resultado['archivos_corruptos'] += 1
                        resultado['errores'].append(f"Archivo corrupto: {ruta_cuarentena}")
                    
                    resultado['archivos_verificados'] += 1
                    
                except Exception as e:
                    resultado['errores'].append(f"Error verificando {archivo['ruta_original']}: {str(e)}")
            
            resultado['exito'] = resultado['archivos_corruptos'] == 0 and resultado['archivos_faltantes'] == 0
            
            self.logger.info(f"Verificación de integridad completada: {resultado['archivos_verificados']} archivos verificados")
            
        except Exception as e:
            resultado['errores'].append(f"Error general en verificación: {str(e)}")
            self.logger.error(f"Error en verificación de integridad: {e}")
        
        return resultado
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtener estadísticas del sistema de cuarentena.
        
        Returns:
            Diccionario con estadísticas
        """
        estadisticas = {
            'total_archivos': 0,
            'archivos_activos': 0,
            'archivos_restaurados': 0,
            'archivos_eliminados': 0,
            'tipos_amenaza': {},
            'tamano_total_bytes': 0,
            'espacio_utilizado': 0
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Estadísticas generales
                cursor.execute('SELECT COUNT(*), SUM(tamano_bytes) FROM archivos_cuarentena')
                total, tamano_total = cursor.fetchone()
                estadisticas['total_archivos'] = total or 0
                estadisticas['tamano_total_bytes'] = tamano_total or 0
                
                # Por estado
                cursor.execute('''
                    SELECT estado, COUNT(*) FROM archivos_cuarentena GROUP BY estado
                ''')
                for estado, count in cursor.fetchall():
                    estadisticas[f'archivos_{estado}'] = count
                
                # Por tipo de amenaza
                cursor.execute('''
                    SELECT tipo_amenaza, COUNT(*) FROM archivos_cuarentena 
                    WHERE estado = 'activo' GROUP BY tipo_amenaza
                ''')
                for tipo, count in cursor.fetchall():
                    estadisticas['tipos_amenaza'][tipo] = count
                
                # Espacio utilizado físicamente
                try:
                    directorio_archivos = os.path.join(self.directorio_cuarentena, "archivos")
                    if os.path.exists(directorio_archivos):
                        total_size = sum(
                            os.path.getsize(os.path.join(directorio_archivos, f))
                            for f in os.listdir(directorio_archivos)
                            if os.path.isfile(os.path.join(directorio_archivos, f))
                        )
                        estadisticas['espacio_utilizado'] = total_size
                except Exception:
                    estadisticas['espacio_utilizado'] = 0
                    
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
        
        return estadisticas
    
    def limpiar_cuarentena_antigua(self, dias_antiguedad: int = 30) -> Dict[str, Any]:
        """
        Limpiar archivos en cuarentena más antiguos que X días.
        
        Args:
            dias_antiguedad: Días de antigüedad para eliminar
            
        Returns:
            Diccionario con resultado de la operación
        """
        resultado = {
            'exito': False,
            'archivos_eliminados': 0,
            'espacio_liberado': 0,
            'errores': []
        }
        
        try:
            from datetime import timedelta
            fecha_limite = datetime.now() - timedelta(days=dias_antiguedad)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Buscar archivos antiguos
                cursor.execute('''
                    SELECT id, ruta_cuarentena, tamano_bytes FROM archivos_cuarentena 
                    WHERE fecha_cuarentena < ? AND estado IN ('restaurado', 'eliminado')
                ''', (fecha_limite.isoformat(),))
                
                archivos_antiguos = cursor.fetchall()
                
                for archivo_id, ruta_cuarentena, tamano in archivos_antiguos:
                    try:
                        if os.path.exists(ruta_cuarentena):
                            os.remove(ruta_cuarentena)
                            resultado['espacio_liberado'] += tamano or 0
                        
                        # Eliminar registro de base de datos
                        cursor.execute('DELETE FROM archivos_cuarentena WHERE id = ?', (archivo_id,))
                        cursor.execute('DELETE FROM operaciones_cuarentena WHERE archivo_id = ?', (archivo_id,))
                        
                        resultado['archivos_eliminados'] += 1
                        
                    except Exception as e:
                        resultado['errores'].append(f"Error eliminando {ruta_cuarentena}: {str(e)}")
                
                conn.commit()
                resultado['exito'] = True
                
                self.logger.info(f"Limpieza completada: {resultado['archivos_eliminados']} archivos eliminados, "
                               f"{resultado['espacio_liberado']} bytes liberados")
                
        except Exception as e:
            resultado['errores'].append(f"Error en limpieza: {str(e)}")
            self.logger.error(f"Error en limpieza de cuarentena: {e}")
        
        return resultado
