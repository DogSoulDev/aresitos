# -*- coding: utf-8 -*-
"""
Ares Aegis - Sistema de Cuarentena
Gestión de archivos en cuarentena para amenazas detectadas
"""

import os
import shutil
import json
import hashlib
import datetime
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

@dataclass
class ArchivoEnCuarentena:
    """Información de un archivo en cuarentena."""
    ruta_original: str
    ruta_cuarentena: str
    hash_md5: str
    hash_sha256: str
    fecha_cuarentena: datetime.datetime
    motivo: str
    tipo_amenaza: str
    severidad: str
    tamano: int
    metadatos: Dict[str, Any]

class Cuarentena:
    """
    Sistema de cuarentena para aislar archivos peligrosos detectados por el escáner.
    """
    
    def __init__(self, directorio_base: str = None):
        """
        Inicializa el sistema de cuarentena.
        
        Args:
            directorio_base: Directorio base para la cuarentena
        """
        self.logger = logging.getLogger(f"AresAegis.{self.__class__.__name__}")
        
        # Configurar directorio de cuarentena
        if directorio_base:
            self.directorio_cuarentena = directorio_base
        else:
            # Directorio por defecto
            self.directorio_cuarentena = os.path.join(
                os.path.expanduser("~"), 
                ".aresitos", 
                "cuarentena"
            )
        
        # Lista de archivos en cuarentena
        self.archivos_cuarentena = []
        
        # Archivo de índice
        self.archivo_indice = os.path.join(self.directorio_cuarentena, "indice_cuarentena.json")
        
        # Inicializar sistema
        self._inicializar_sistema()
    
    def _inicializar_sistema(self):
        """Inicializa el sistema de cuarentena."""
        try:
            # Crear directorio si no existe
            os.makedirs(self.directorio_cuarentena, exist_ok=True)
            
            # Cargar índice existente
            self._cargar_indice()
            
            self.logger.info(f"Sistema de cuarentena inicializado en: {self.directorio_cuarentena}")
            
        except Exception as e:
            self.logger.error(f"Error inicializando sistema de cuarentena: {e}")
            raise
    
    def _cargar_indice(self):
        """Carga el índice de archivos en cuarentena."""
        try:
            if os.path.exists(self.archivo_indice):
                with open(self.archivo_indice, 'r', encoding='utf-8') as f:
                    datos = json.load(f)
                    
                self.archivos_cuarentena = []
                for item in datos.get('archivos', []):
                    # Convertir string a datetime
                    item['fecha_cuarentena'] = datetime.datetime.fromisoformat(item['fecha_cuarentena'])
                    archivo = ArchivoEnCuarentena(**item)
                    self.archivos_cuarentena.append(archivo)
                    
                self.logger.info(f"Cargados {len(self.archivos_cuarentena)} archivos del índice")
            else:
                self.archivos_cuarentena = []
                
        except Exception as e:
            self.logger.error(f"Error cargando índice de cuarentena: {e}")
            self.archivos_cuarentena = []
    
    def _guardar_indice(self):
        """Guarda el índice de archivos en cuarentena."""
        try:
            datos = {
                'version': '1.0',
                'fecha_actualizacion': datetime.datetime.now().isoformat(),
                'total_archivos': len(self.archivos_cuarentena),
                'archivos': []
            }
            
            for archivo in self.archivos_cuarentena:
                archivo_dict = asdict(archivo)
                # Convertir datetime a string
                archivo_dict['fecha_cuarentena'] = archivo.fecha_cuarentena.isoformat()
                datos['archivos'].append(archivo_dict)
            
            with open(self.archivo_indice, 'w', encoding='utf-8') as f:
                json.dump(datos, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"Error guardando índice de cuarentena: {e}")
    
    def _calcular_hash(self, archivo_path: str) -> tuple:
        """
        Calcula los hashes MD5 y SHA256 de un archivo.
        
        Args:
            archivo_path: Ruta del archivo
            
        Returns:
            tuple: (md5, sha256)
        """
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(archivo_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculando hash de {archivo_path}: {e}")
            return "", ""
    
    def poner_en_cuarentena(self, archivo_path: str, motivo: str = "Amenaza detectada", 
                           tipo_amenaza: str = "Desconocido", severidad: str = "Media",
                           metadatos: Dict[str, Any] = None) -> bool:
        """
        Pone un archivo en cuarentena.
        
        Args:
            archivo_path: Ruta del archivo a poner en cuarentena
            motivo: Motivo de la cuarentena
            tipo_amenaza: Tipo de amenaza detectada
            severidad: Severidad de la amenaza (Baja, Media, Alta, Crítica)
            metadatos: Metadatos adicionales
            
        Returns:
            bool: True si se puso en cuarentena exitosamente
        """
        try:
            # Verificar que el archivo existe
            if not os.path.exists(archivo_path):
                self.logger.warning(f"Archivo no existe: {archivo_path}")
                return False
            
            # Verificar que no esté ya en cuarentena
            for archivo_cuarentena in self.archivos_cuarentena:
                if archivo_cuarentena.ruta_original == archivo_path:
                    self.logger.warning(f"Archivo ya está en cuarentena: {archivo_path}")
                    return False
            
            # Calcular hashes
            md5_hash, sha256_hash = self._calcular_hash(archivo_path)
            
            # Crear nombre único para el archivo en cuarentena
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_archivo = f"{timestamp}_{os.path.basename(archivo_path)}_{md5_hash[:8]}"
            ruta_cuarentena = os.path.join(self.directorio_cuarentena, nombre_archivo)
            
            # Copiar archivo a cuarentena
            shutil.copy2(archivo_path, ruta_cuarentena)
            
            # Crear registro
            archivo_en_cuarentena = ArchivoEnCuarentena(
                ruta_original=archivo_path,
                ruta_cuarentena=ruta_cuarentena,
                hash_md5=md5_hash,
                hash_sha256=sha256_hash,
                fecha_cuarentena=datetime.datetime.now(),
                motivo=motivo,
                tipo_amenaza=tipo_amenaza,
                severidad=severidad,
                tamano=os.path.getsize(archivo_path),
                metadatos=metadatos or {}
            )
            
            # Agregar a la lista
            self.archivos_cuarentena.append(archivo_en_cuarentena)
            
            # Guardar índice
            self._guardar_indice()
            
            # Eliminar archivo original (opcional - configurable)
            # Por seguridad, por defecto no eliminamos el original
            # shutil.move(archivo_path, ruta_cuarentena)
            
            self.logger.info(f"Archivo puesto en cuarentena: {archivo_path} -> {ruta_cuarentena}")
            self.logger.info(f"Motivo: {motivo}, Tipo: {tipo_amenaza}, Severidad: {severidad}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error poniendo archivo en cuarentena {archivo_path}: {e}")
            return False
    
    def quitar_de_cuarentena(self, archivo_path: str, restaurar: bool = False) -> bool:
        """
        Quita un archivo de la cuarentena.
        
        Args:
            archivo_path: Ruta original del archivo
            restaurar: Si True, restaura el archivo a su ubicación original
            
        Returns:
            bool: True si se quitó exitosamente
        """
        try:
            # Buscar el archivo en cuarentena
            archivo_encontrado = None
            for i, archivo in enumerate(self.archivos_cuarentena):
                if archivo.ruta_original == archivo_path:
                    archivo_encontrado = archivo
                    indice = i
                    break
            
            if not archivo_encontrado:
                self.logger.warning(f"Archivo no encontrado en cuarentena: {archivo_path}")
                return False
            
            if restaurar:
                # Restaurar archivo a ubicación original
                if os.path.exists(archivo_encontrado.ruta_cuarentena):
                    # Crear directorio padre si no existe
                    os.makedirs(os.path.dirname(archivo_path), exist_ok=True)
                    shutil.copy2(archivo_encontrado.ruta_cuarentena, archivo_path)
                    self.logger.info(f"Archivo restaurado: {archivo_path}")
            
            # Eliminar archivo de cuarentena
            if os.path.exists(archivo_encontrado.ruta_cuarentena):
                os.remove(archivo_encontrado.ruta_cuarentena)
            
            # Quitar de la lista
            self.archivos_cuarentena.pop(indice)
            
            # Guardar índice
            self._guardar_indice()
            
            self.logger.info(f"Archivo quitado de cuarentena: {archivo_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error quitando archivo de cuarentena {archivo_path}: {e}")
            return False
    
    def listar_archivos_cuarentena(self, filtro_severidad: str = None) -> List[ArchivoEnCuarentena]:
        """
        Lista archivos en cuarentena.
        
        Args:
            filtro_severidad: Filtrar por severidad (Baja, Media, Alta, Crítica)
            
        Returns:
            List[ArchivoEnCuarentena]: Lista de archivos en cuarentena
        """
        if filtro_severidad:
            return [a for a in self.archivos_cuarentena if a.severidad == filtro_severidad]
        return self.archivos_cuarentena.copy()
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas de la cuarentena.
        
        Returns:
            Dict[str, Any]: Estadísticas de cuarentena
        """
        if not self.archivos_cuarentena:
            return {
                'total_archivos': 0,
                'por_severidad': {},
                'por_tipo_amenaza': {},
                'tamano_total': 0,
                'archivo_mas_reciente': None,
                'archivo_mas_antiguo': None
            }
        
        # Contar por severidad
        por_severidad = {}
        for archivo in self.archivos_cuarentena:
            severidad = archivo.severidad
            por_severidad[severidad] = por_severidad.get(severidad, 0) + 1
        
        # Contar por tipo de amenaza
        por_tipo_amenaza = {}
        for archivo in self.archivos_cuarentena:
            tipo = archivo.tipo_amenaza
            por_tipo_amenaza[tipo] = por_tipo_amenaza.get(tipo, 0) + 1
        
        # Calcular tamaño total
        tamano_total = sum(archivo.tamano for archivo in self.archivos_cuarentena)
        
        # Fechas
        fechas = [archivo.fecha_cuarentena for archivo in self.archivos_cuarentena]
        archivo_mas_reciente = max(fechas)
        archivo_mas_antiguo = min(fechas)
        
        return {
            'total_archivos': len(self.archivos_cuarentena),
            'por_severidad': por_severidad,
            'por_tipo_amenaza': por_tipo_amenaza,
            'tamano_total': tamano_total,
            'tamano_total_mb': round(tamano_total / (1024 * 1024), 2),
            'archivo_mas_reciente': archivo_mas_reciente.isoformat(),
            'archivo_mas_antiguo': archivo_mas_antiguo.isoformat(),
            'directorio_cuarentena': self.directorio_cuarentena
        }
    
    def limpiar_cuarentena(self, dias_antiguedad: int = 30, confirmar: bool = False) -> int:
        """
        Limpia archivos antiguos de la cuarentena.
        
        Args:
            dias_antiguedad: Eliminar archivos más antiguos que estos días
            confirmar: Confirmación de seguridad
            
        Returns:
            int: Número de archivos eliminados
        """
        if not confirmar:
            self.logger.warning("Limpieza de cuarentena cancelada - se requiere confirmación")
            return 0
        
        try:
            fecha_limite = datetime.datetime.now() - datetime.timedelta(days=dias_antiguedad)
            archivos_eliminados = 0
            
            archivos_a_eliminar = []
            for i, archivo in enumerate(self.archivos_cuarentena):
                if archivo.fecha_cuarentena < fecha_limite:
                    archivos_a_eliminar.append((i, archivo))
            
            # Eliminar en orden inverso para mantener índices
            for i, archivo in reversed(archivos_a_eliminar):
                try:
                    if os.path.exists(archivo.ruta_cuarentena):
                        os.remove(archivo.ruta_cuarentena)
                    self.archivos_cuarentena.pop(i)
                    archivos_eliminados += 1
                except Exception as e:
                    self.logger.error(f"Error eliminando archivo de cuarentena: {e}")
            
            # Guardar índice actualizado
            self._guardar_indice()
            
            self.logger.info(f"Limpieza de cuarentena completada: {archivos_eliminados} archivos eliminados")
            return archivos_eliminados
            
        except Exception as e:
            self.logger.error(f"Error en limpieza de cuarentena: {e}")
            return 0
    
    def verificar_integridad(self) -> Dict[str, Any]:
        """
        Verifica la integridad de los archivos en cuarentena.
        
        Returns:
            Dict[str, Any]: Resultado de la verificación
        """
        try:
            archivos_corruptos = []
            archivos_faltantes = []
            archivos_ok = 0
            
            for archivo in self.archivos_cuarentena:
                if not os.path.exists(archivo.ruta_cuarentena):
                    archivos_faltantes.append(archivo.ruta_original)
                    continue
                
                # Verificar hash
                md5_actual, sha256_actual = self._calcular_hash(archivo.ruta_cuarentena)
                
                if md5_actual != archivo.hash_md5 or sha256_actual != archivo.hash_sha256:
                    archivos_corruptos.append({
                        'archivo': archivo.ruta_original,
                        'hash_esperado_md5': archivo.hash_md5,
                        'hash_actual_md5': md5_actual,
                        'hash_esperado_sha256': archivo.hash_sha256,
                        'hash_actual_sha256': sha256_actual
                    })
                else:
                    archivos_ok += 1
            
            resultado = {
                'total_archivos': len(self.archivos_cuarentena),
                'archivos_ok': archivos_ok,
                'archivos_corruptos': len(archivos_corruptos),
                'archivos_faltantes': len(archivos_faltantes),
                'detalles_corruptos': archivos_corruptos,
                'detalles_faltantes': archivos_faltantes,
                'integridad_ok': len(archivos_corruptos) == 0 and len(archivos_faltantes) == 0
            }
            
            self.logger.info(f"Verificación de integridad: {archivos_ok} OK, {len(archivos_corruptos)} corruptos, {len(archivos_faltantes)} faltantes")
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error verificando integridad de cuarentena: {e}")
            return {'error': str(e)}
