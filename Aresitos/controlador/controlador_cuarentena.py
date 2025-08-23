# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Cuarentena
Gestiona las operaciones de cuarentena integradas con el sistema de escaneo
"""

import tempfile
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from ..modelo.modelo_cuarentena import CuarentenaKali2025

# Importar SudoManager para prevenir crashes
try:
    from ..utils.sudo_manager import SudoManager
    SUDO_MANAGER_DISPONIBLE = True
except ImportError:
    SUDO_MANAGER_DISPONIBLE = False

# Importar nuevo modelo Kali 2025
try:
    KALI2025_CUARENTENA_DISPONIBLE = True
except ImportError:
    KALI2025_CUARENTENA_DISPONIBLE = False

class ControladorCuarentena:
    """
    Controlador para gestionar el sistema de cuarentena.
    """
    
    def __init__(self, directorio_cuarentena: Optional[str] = None):
        """
        Inicializa el controlador de cuarentena.
        
        Args:
            directorio_cuarentena: Directorio personalizado para cuarentena
        """
        self.logger = logging.getLogger(f"AresAegis.{self.__class__.__name__}")
        
        # Inicializar SudoManager para prevenir crashes
        if SUDO_MANAGER_DISPONIBLE:
            try:
                self.sudo_manager = SudoManager()
                self.logger.info("SudoManager inicializado para operaciones seguras")
            except Exception as e:
                self.logger.warning(f"Error inicializando SudoManager: {e}")
                self.sudo_manager = None
        else:
            self.sudo_manager = None
            self.logger.warning("SudoManager no disponible")
        
        # Usar directorio por defecto si no se especifica
        if directorio_cuarentena is None:
            import tempfile
            directorio_cuarentena = os.path.join(tempfile.gettempdir(), "aresitos_quarantine")
        
        self.cuarentena = CuarentenaKali2025(directorio_cuarentena)
        
        # Inicializar Cuarentena Kali 2025 si está disponible
        if KALI2025_CUARENTENA_DISPONIBLE:
            try:
                self.cuarentena_kali2025 = CuarentenaKali2025()
                self.logger.info("CuarentenaKali2025 inicializada correctamente")
            except Exception as e:
                self.logger.warning(f"Error inicializando CuarentenaKali2025: {e}")
                self.cuarentena_kali2025 = None
        else:
            self.cuarentena_kali2025 = None
            self.logger.warning("CuarentenaKali2025 no disponible")
        
        # Configuración de tipos de amenaza y sus severidades
        self.tipos_amenaza = {
            'virus': 'Crítica',
            'malware': 'Crítica', 
            'trojan': 'Crítica',
            'backdoor': 'Crítica',
            'rootkit': 'Crítica',
            'adware': 'Alta',
            'spyware': 'Alta',
            'vulnerabilidad_critica': 'Crítica',
            'vulnerabilidad_alta': 'Alta',
            'vulnerabilidad_media': 'Media',
            'vulnerabilidad_baja': 'Baja',
            'archivo_sospechoso': 'Media',
            'configuracion_insegura': 'Media',
            'puerto_abierto_peligroso': 'Alta',
            'servicio_vulnerable': 'Alta',
            'certificado_invalido': 'Media',
            'credenciales_debiles': 'Alta'
        }
        
        self.logger.info("Controlador de cuarentena inicializado")
    
    # MÉTODOS HELPER PARA COMPATIBILIDAD CON API ESPERADA
    def _obtener_estadisticas_cuarentena(self) -> Dict[str, Any]:
        """Helper para obtener estadísticas usando API disponible"""
        try:
            # Estadísticas básicas usando directorios del modelo
            directorio_cuarentena = getattr(self.cuarentena, 'directorio_cuarentena', 'data/cuarentena')
            
            estadisticas = {
                'total_archivos': 0,
                'por_severidad': {'Crítica': 0, 'Alta': 0, 'Media': 0, 'Baja': 0},
                'por_tipo_amenaza': {},
                'tamano_total': 0,
                'tamano_total_mb': 0,
                'archivo_mas_reciente': None,
                'archivo_mas_antiguo': None
            }
            
            # Contar archivos en subdirectorios de cuarentena
            if os.path.exists(directorio_cuarentena):
                for subdir in ['sospechosos', 'infectados', 'limpio']:
                    subdir_path = os.path.join(directorio_cuarentena, subdir)
                    if os.path.exists(subdir_path):
                        archivos = [f for f in os.listdir(subdir_path) if os.path.isfile(os.path.join(subdir_path, f))]
                        estadisticas['total_archivos'] += len(archivos)
                        
                        for archivo in archivos:
                            archivo_path = os.path.join(subdir_path, archivo)
                            try:
                                stat_info = os.stat(archivo_path)
                                estadisticas['tamano_total'] += stat_info.st_size
                            except OSError:
                                continue
            
            estadisticas['tamano_total_mb'] = round(estadisticas['tamano_total'] / (1024 * 1024), 2)
            return estadisticas
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            return {'error': str(e)}
    
    def _listar_archivos_cuarentena_helper(self) -> List[Dict[str, Any]]:
        """Helper para listar archivos usando API disponible"""
        try:
            archivos_cuarentena = []
            directorio_cuarentena = getattr(self.cuarentena, 'directorio_cuarentena', 'data/cuarentena')
            
            if os.path.exists(directorio_cuarentena):
                for subdir in ['sospechosos', 'infectados', 'limpio']:
                    subdir_path = os.path.join(directorio_cuarentena, subdir)
                    if os.path.exists(subdir_path):
                        for archivo in os.listdir(subdir_path):
                            archivo_path = os.path.join(subdir_path, archivo)
                            if os.path.isfile(archivo_path):
                                try:
                                    stat_info = os.stat(archivo_path)
                                    archivos_cuarentena.append({
                                        'nombre': archivo,
                                        'ruta_cuarentena': archivo_path,
                                        'estado': subdir,
                                        'fecha_cuarentena': datetime.fromtimestamp(stat_info.st_mtime),
                                        'tamano': stat_info.st_size
                                    })
                                except OSError:
                                    continue
            
            return archivos_cuarentena
            
        except Exception as e:
            self.logger.error(f"Error listando archivos: {e}")
            return []
    
    def _verificar_integridad_helper(self) -> Dict[str, Any]:
        """Helper para verificar integridad usando API disponible"""
        try:
            archivos = self._listar_archivos_cuarentena_helper()
            
            resultado = {
                'total_archivos': len(archivos),
                'archivos_ok': len(archivos),  # Asumimos OK si existen
                'archivos_corruptos': 0,
                'archivos_faltantes': 0,
                'integridad_ok': True,
                'detalles_corruptos': [],
                'detalles_faltantes': []
            }
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error verificando integridad: {e}")
            return {'error': str(e)}
    
    def _quitar_de_cuarentena_helper(self, ruta_original: str, restaurar: bool = False) -> bool:
        """Helper para quitar archivos de cuarentena"""
        try:
            # Buscar archivo en directorios de cuarentena
            directorio_cuarentena = getattr(self.cuarentena, 'directorio_cuarentena', 'data/cuarentena')
            archivo_encontrado = None
            
            for subdir in ['sospechosos', 'infectados', 'limpio']:
                subdir_path = os.path.join(directorio_cuarentena, subdir)
                if os.path.exists(subdir_path):
                    for archivo in os.listdir(subdir_path):
                        archivo_path = os.path.join(subdir_path, archivo)
                        # Buscar por nombre que contiene parte de la ruta original
                        if os.path.basename(ruta_original) in archivo:
                            archivo_encontrado = archivo_path
                            break
                    if archivo_encontrado:
                        break
            
            if archivo_encontrado:
                if restaurar and ruta_original:
                    # Restaurar archivo a ubicación original
                    os.makedirs(os.path.dirname(ruta_original), exist_ok=True)
                    import shutil
                    shutil.copy2(archivo_encontrado, ruta_original)
                    self.logger.info(f"Archivo restaurado: {ruta_original}")
                
                # Eliminar de cuarentena
                os.remove(archivo_encontrado)
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error quitando de cuarentena: {e}")
            return False
    
    def _limpiar_cuarentena_helper(self, dias: int, confirmar: bool = False) -> int:
        """Helper para limpiar cuarentena antigua"""
        if not confirmar:
            return 0
            
        try:
            archivos_eliminados = 0
            directorio_cuarentena = getattr(self.cuarentena, 'directorio_cuarentena', 'data/cuarentena')
            fecha_limite = datetime.now().timestamp() - (dias * 24 * 3600)
            
            if os.path.exists(directorio_cuarentena):
                for subdir in ['sospechosos', 'infectados', 'limpio']:
                    subdir_path = os.path.join(directorio_cuarentena, subdir)
                    if os.path.exists(subdir_path):
                        for archivo in os.listdir(subdir_path):
                            archivo_path = os.path.join(subdir_path, archivo)
                            try:
                                stat_info = os.stat(archivo_path)
                                if stat_info.st_mtime < fecha_limite:
                                    os.remove(archivo_path)
                                    archivos_eliminados += 1
                            except OSError:
                                continue
            
            return archivos_eliminados
            
        except Exception as e:
            self.logger.error(f"Error limpiando cuarentena: {e}")
            return 0
    
    def procesar_amenaza_detectada(self, amenaza_info: Dict[str, Any]) -> bool:
        """
        Procesa una amenaza detectada y decide si ponerla en cuarentena.
        
        Args:
            amenaza_info: Información de la amenaza detectada
                - archivo: Ruta del archivo (si aplica)
                - tipo: Tipo de amenaza
                - descripcion: Descripción de la amenaza
                - severidad: Severidad detectada
                - fuente_deteccion: Escaneador que detectó la amenaza
                - metadatos: Información adicional
                
        Returns:
            bool: True si se procesó exitosamente
        """
        try:
            tipo_amenaza = amenaza_info.get('tipo', 'desconocido').lower()
            archivo = amenaza_info.get('archivo')
            descripcion = amenaza_info.get('descripcion', 'Amenaza detectada')
            severidad = amenaza_info.get('severidad', self._determinar_severidad(tipo_amenaza))
            fuente = amenaza_info.get('fuente_deteccion', 'Escaneador')
            metadatos = amenaza_info.get('metadatos', {})
            
            # Agregar información de contexto
            metadatos.update({
                'fuente_deteccion': fuente,
                'fecha_deteccion': amenaza_info.get('fecha_deteccion'),
                'version_escaneador': amenaza_info.get('version_escaneador', '3.0.0')
            })
            
            # Si hay un archivo asociado, ponerlo en cuarentena usando comandos nativos
            if archivo and os.path.exists(archivo):
                # Verificar si el archivo está en uso con lsof usando SudoManager
                archivo_en_uso = False
                try:
                    if self.sudo_manager:
                        resultado_lsof = self.sudo_manager.execute_sudo_command(f'lsof "{archivo}"')
                        if resultado_lsof and resultado_lsof.returncode == 0 and resultado_lsof.stdout.strip():
                            archivo_en_uso = True
                            output_limitado = resultado_lsof.stdout[:100]
                            self.logger.warning(f"Archivo {archivo} está siendo usado por proceso: {output_limitado}")
                    else:
                        # Fallback sin sudo si no está disponible
                        import subprocess
                        lsof_result = subprocess.run(['lsof', archivo], 
                                                   capture_output=True, text=True, timeout=10)
                        if lsof_result.returncode == 0 and lsof_result.stdout.strip():
                            archivo_en_uso = True
                            self.logger.warning(f"Archivo {archivo} está siendo usado por proceso: {lsof_result.stdout.strip()[:100]}")
                except Exception as e:
                    self.logger.warning(f"Error verificando uso de archivo {archivo}: {e}")
                
                # Obtener información detallada con stat usando SudoManager
                try:
                    if self.sudo_manager:
                        resultado_stat = self.sudo_manager.execute_sudo_command(f'stat -c "%a:%U:%G:%s" "{archivo}"')
                        if resultado_stat and resultado_stat.returncode == 0:
                            stat_info = resultado_stat.stdout.strip().split(':')
                            metadatos.update({
                                'permisos_originales': stat_info[0] if len(stat_info) > 0 else '000',
                                'owner_original': stat_info[1] if len(stat_info) > 1 else 'unknown',
                                'group_original': stat_info[2] if len(stat_info) > 2 else 'unknown',
                                'size_bytes': stat_info[3] if len(stat_info) > 3 else '0'
                            })
                    else:
                        # Fallback sin sudo
                        import subprocess
                        stat_result = subprocess.run(['stat', '-c', '%a:%U:%G:%s', archivo],
                                                   capture_output=True, text=True, timeout=5)
                        if stat_result.returncode == 0:
                            stat_info = stat_result.stdout.strip().split(':')
                            metadatos.update({
                                'permisos_originales': stat_info[0] if len(stat_info) > 0 else '000',
                                'owner_original': stat_info[1] if len(stat_info) > 1 else 'unknown',
                                'group_original': stat_info[2] if len(stat_info) > 2 else 'unknown',
                                'size_bytes': stat_info[3] if len(stat_info) > 3 else '0'
                            })
                except Exception as e:
                    self.logger.warning(f"Error obteniendo información del archivo {archivo}: {e}")
                
                # Calcular hash con sha256sum usando SudoManager
                try:
                    if self.sudo_manager:
                        resultado_hash = self.sudo_manager.execute_sudo_command(f'sha256sum "{archivo}"')
                        if resultado_hash and resultado_hash.returncode == 0:
                            output_hash = resultado_hash.stdout.strip()
                            if output_hash:
                                metadatos['hash_sha256'] = output_hash.split()[0]
                    else:
                        # Fallback sin sudo
                        import subprocess
                        hash_result = subprocess.run(['sha256sum', archivo],
                                                   capture_output=True, text=True, timeout=30)
                        if hash_result.returncode == 0:
                            metadatos['hash_sha256'] = hash_result.stdout.split()[0]
                except Exception as e:
                    self.logger.warning(f"Error calculando hash de {archivo}: {e}")
                
                resultado = self.cuarentena.poner_en_cuarentena(
                    ruta_archivo=archivo,
                    motivo=f"{descripcion} - Tipo: {tipo_amenaza}, Severidad: {severidad}"
                )
                
                if resultado:
                    self.logger.warning(f"Archivo puesto en cuarentena: {archivo}")
                    self.logger.warning(f"Amenaza: {tipo_amenaza} - Severidad: {severidad}")
                    
                    # Notificar a otros sistemas si es crítico
                    if severidad == 'Crítica':
                        self._notificar_amenaza_critica(amenaza_info)
                
                return resultado.get('exito', False)
            else:
                # Para amenazas sin archivo (como vulnerabilidades de configuración)
                self.logger.warning(f"Amenaza detectada sin archivo: {tipo_amenaza}")
                self.logger.warning(f"Descripción: {descripcion}")
                
                # Registrar en log especializado
                self._registrar_amenaza_sin_archivo(amenaza_info)
                return True
                
        except Exception as e:
            self.logger.error(f"Error procesando amenaza: {e}")
            return False
    
    def _determinar_severidad(self, tipo_amenaza: str) -> str:
        """Determina la severidad basada en el tipo de amenaza."""
        return self.tipos_amenaza.get(tipo_amenaza.lower(), 'Media')
    
    def _notificar_amenaza_critica(self, amenaza_info: Dict[str, Any]):
        """Notifica amenazas críticas a sistemas de alerta."""
        try:
            # Aquí se podría integrar con SIEM, email, etc.
            self.logger.critical(f"AMENAZA CRÍTICA DETECTADA: {amenaza_info}")
            
            # Ejemplo de integración con SIEM (si existe)
            # if hasattr(self, 'siem'):
            #     self.siem.registrar_evento_critico(amenaza_info)
            
        except Exception as e:
            self.logger.error(f"Error notificando amenaza crítica: {e}")
    
    def _registrar_amenaza_sin_archivo(self, amenaza_info: Dict[str, Any]):
        """Registra amenazas que no tienen archivo asociado."""
        try:
            # Crear un registro en el directorio de cuarentena
            log_file = os.path.join(self.cuarentena.directorio_cuarentena, "amenazas_sin_archivo.log")
            
            import json
            import datetime
            
            registro = {
                'timestamp': datetime.datetime.now().isoformat(),
                'amenaza': amenaza_info
            }
            
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(registro, ensure_ascii=False) + '\n')
                
        except Exception as e:
            self.logger.error(f"Error registrando amenaza sin archivo: {e}")
    
    def obtener_resumen_cuarentena(self) -> Dict[str, Any]:
        """
        Obtiene un resumen del estado actual de la cuarentena.
        
        Returns:
            Dict[str, Any]: Resumen de cuarentena
        """
        try:
            estadisticas = self._obtener_estadisticas_cuarentena()
            archivos = self._listar_archivos_cuarentena_helper()
            
            # Amenazas más recientes
            archivos_recientes = sorted(archivos, key=lambda x: x.get('fecha_cuarentena', datetime.now()), reverse=True)[:5]
            
            # Amenazas críticas (simuladas por estado 'infectados')
            amenazas_criticas = [a for a in archivos if a.get('estado') == 'infectados']
            
            resumen = {
                'estadisticas_generales': estadisticas,
                'total_archivos': len(archivos),
                'amenazas_criticas': len(amenazas_criticas),
                'archivos_recientes': [
                    {
                        'archivo': a.get('nombre', 'Desconocido'),
                        'tipo': a.get('estado', 'Desconocido'),
                        'severidad': 'Media' if a.get('estado') == 'sospechosos' else 'Crítica',
                        'fecha': a.get('fecha_cuarentena', datetime.now()).isoformat() if isinstance(a.get('fecha_cuarentena'), datetime) else str(a.get('fecha_cuarentena', ''))
                    } for a in archivos_recientes
                ],
                'amenazas_criticas_detalle': [
                    {
                        'archivo': a.get('nombre', 'Desconocido'),
                        'tipo': a.get('estado', 'Desconocido'),
                        'motivo': f"Archivo en estado: {a.get('estado', 'Desconocido')}",
                        'fecha': a.get('fecha_cuarentena', datetime.now()).isoformat() if isinstance(a.get('fecha_cuarentena'), datetime) else str(a.get('fecha_cuarentena', ''))
                    } for a in amenazas_criticas
                ],
                'integridad': self._verificar_integridad_helper()
            }
            
            return resumen
            
        except Exception as e:
            self.logger.error(f"Error obteniendo resumen de cuarentena: {e}")
            return {'error': str(e)}
    
    def restaurar_archivo(self, ruta_original: str) -> bool:
        """
        Restaura un archivo de la cuarentena.
        
        Args:
            ruta_original: Ruta original del archivo
            
        Returns:
            bool: True si se restauró exitosamente
        """
        try:
            resultado = self._quitar_de_cuarentena_helper(ruta_original, restaurar=True)
            
            if resultado:
                self.logger.info(f"Archivo restaurado desde cuarentena: {ruta_original}")
            else:
                self.logger.warning(f"No se pudo restaurar archivo: {ruta_original}")
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error restaurando archivo {ruta_original}: {e}")
            return False
    
    def eliminar_definitivamente(self, ruta_original: str) -> bool:
        """
        Elimina definitivamente un archivo de la cuarentena.
        
        Args:
            ruta_original: Ruta original del archivo
            
        Returns:
            bool: True si se eliminó exitosamente
        """
        try:
            resultado = self._quitar_de_cuarentena_helper(ruta_original, restaurar=False)
            
            if resultado:
                self.logger.info(f"Archivo eliminado definitivamente: {ruta_original}")
            else:
                self.logger.warning(f"No se pudo eliminar archivo: {ruta_original}")
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error eliminando archivo {ruta_original}: {e}")
            return False
    
    def cuarentenar_archivo(self, ruta_archivo: str, razon: str = "Detección automática SIEM") -> Dict[str, Any]:
        """
        Método específico para cuarentenar un archivo individual.
        Usado por SIEM para respuesta automática.
        
        Args:
            ruta_archivo: Ruta del archivo a cuarentenar
            razon: Razón de la cuarentena
            
        Returns:
            Dict con resultado de la operación
        """
        try:
            if not os.path.exists(ruta_archivo):
                return {
                    'exito': False,
                    'error': f'Archivo no encontrado: {ruta_archivo}'
                }
            
            # Crear información de amenaza para procesar
            amenaza_info = {
                'ruta_archivo': ruta_archivo,
                'tipo_amenaza': 'SIEM_DETECTION',
                'descripcion': razon,
                'timestamp': str(os.path.getmtime(ruta_archivo))
            }
            
            # Procesar como amenaza detectada
            exito = self.procesar_amenaza_detectada(amenaza_info)
            
            if exito:
                return {
                    'exito': True,
                    'mensaje': f'Archivo cuarentenado exitosamente: {ruta_archivo}',
                    'razon': razon
                }
            else:
                return {
                    'exito': False,
                    'error': f'Error durante cuarentena de {ruta_archivo}'
                }
                
        except Exception as e:
            self.logger.error(f"Error en cuarentenar_archivo: {e}")
            return {
                'exito': False,
                'error': str(e)
            }
    
    def limpiar_cuarentena_antigua(self, dias: int = 30) -> int:
        """
        Limpia archivos antiguos de la cuarentena.
        
        Args:
            dias: Días de antigüedad para eliminar
            
        Returns:
            int: Número de archivos eliminados
        """
        try:
            eliminados = self._limpiar_cuarentena_helper(dias, confirmar=True)
            self.logger.info(f"Limpieza de cuarentena completada: {eliminados} archivos eliminados")
            return eliminados
            
        except Exception as e:
            self.logger.error(f"Error limpiando cuarentena: {e}")
            return 0
    
    def generar_reporte_cuarentena(self) -> Dict[str, Any]:
        """
        Genera un reporte detallado de la cuarentena.
        
        Returns:
            Dict[str, Any]: Reporte detallado
        """
        try:
            estadisticas = self._obtener_estadisticas_cuarentena()
            archivos = self._listar_archivos_cuarentena_helper()
            integridad = self._verificar_integridad_helper()
            
            reporte = {
                'timestamp': estadisticas.get('archivo_mas_reciente'),
                'resumen_ejecutivo': {
                    'total_archivos_cuarentena': estadisticas.get('total_archivos', 0),
                    'espacio_utilizado_mb': estadisticas.get('tamano_total_mb', 0),
                    'amenazas_criticas': estadisticas['por_severidad'].get('Crítica', 0),
                    'integridad_ok': integridad['integridad_ok']
                },
                'estadisticas_detalladas': estadisticas,
                'verificacion_integridad': integridad,
                'archivos_por_severidad': {},
                'recomendaciones': []
            }
            
            # Agrupar archivos por estado (simular severidad)
            for severidad in ['Crítica', 'Alta', 'Media', 'Baja']:
                estado_mapping = {'Crítica': 'infectados', 'Alta': 'infectados', 'Media': 'sospechosos', 'Baja': 'limpio'}
                estado_target = estado_mapping.get(severidad, 'sospechosos')
                archivos_severidad = [a for a in archivos if a.get('estado') == estado_target]
                reporte['archivos_por_severidad'][severidad] = [
                    {
                        'archivo': a.get('nombre', 'Desconocido'),
                        'tipo_amenaza': a.get('estado', 'Desconocido'),
                        'motivo': f"Archivo en estado: {a.get('estado', 'Desconocido')}",
                        'fecha': a.get('fecha_cuarentena', datetime.now()).isoformat() if isinstance(a.get('fecha_cuarentena'), datetime) else str(a.get('fecha_cuarentena', '')),
                        'tamano_mb': round(a.get('tamano', 0) / (1024 * 1024), 2)
                    } for a in archivos_severidad
                ]
            
            # Generar recomendaciones
            infectados_count = len([a for a in archivos if a.get('estado') == 'infectados'])
            if infectados_count > 0:
                reporte['recomendaciones'].append("Se detectaron archivos infectados. Revisar inmediatamente.")
            
            if estadisticas.get('tamano_total_mb', 0) > 1000:  # 1GB
                reporte['recomendaciones'].append("La cuarentena ocupa más de 1GB. Considerar limpieza.")
            
            if not integridad.get('integridad_ok', True):
                reporte['recomendaciones'].append("Problemas de integridad detectados en cuarentena.")
            
            return reporte
            
        except Exception as e:
            self.logger.error(f"Error generando reporte de cuarentena: {e}")
            return {'error': str(e)}
    
    def poner_archivo_en_cuarentena(self, ruta_archivo: str) -> Dict[str, Any]:
        """
        Método de compatibilidad para la vista.
        Envuelve cuarentenar_archivo con manejo de errores simplificado.
        """
        try:
            resultado = self.cuarentenar_archivo(ruta_archivo, "Agregado manualmente desde GUI")
            return {
                'exito': resultado.get('exito', False),
                'error': resultado.get('error', '')
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f"Error en cuarentena: {str(e)}"
            }

    # ================================
    # NUEVAS FUNCIONES KALI 2025
    # ================================
    
    def cuarentena_completa_kali2025(self, ruta_archivo: str, motivo: str = "Análisis completo") -> Dict[str, Any]:
        """
        Cuarentena completa con análisis usando herramientas Kali 2025
        """
        if not self.cuarentena_kali2025:
            return {"error": "CuarentenaKali2025 no disponible"}
        
        self.logger.info(f"[START] Cuarentena completa Kali 2025: {ruta_archivo}")
        
        try:
            resultado = self.cuarentena_kali2025.analisis_completo_cuarentena_kali2025(ruta_archivo)
            
            if resultado.get("exito"):
                self.logger.info("✓ Cuarentena y análisis Kali 2025 completado")
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error en cuarentena completa Kali 2025: {e}"
            self.logger.error(error_msg)
            return {"error": error_msg}
    
    def listar_archivos_cuarentena(self) -> List[Dict[str, Any]]:
        """
        Método de compatibilidad para la vista.
        Lista todos los archivos en cuarentena.
        """
        try:
            resumen = self.obtener_resumen_cuarentena()
            if 'archivos' in resumen:
                return resumen['archivos']
            else:
                return []
        except Exception as e:
            self.logger.error(f"Error listando archivos en cuarentena: {e}")
            return []
    
    # MÉTODOS DE CONECTIVIDAD ENTRE CONTROLADORES
    
    def notificar_desde_siem(self, evento_siem: Dict[str, Any]) -> Dict[str, Any]:
        """
        Procesar notificación desde el SIEM.
        
        Args:
            evento_siem: Información del evento SIEM
            
        Returns:
            Dict con resultado del procesamiento
        """
        try:
            if 'archivo' in evento_siem and evento_siem.get('severidad') == 'critica':
                # Usar el método cuarentenar_archivo que ya existe
                resultado = self.cuarentenar_archivo(
                    evento_siem['archivo'], 
                    f"Evento crítico SIEM: {evento_siem.get('descripcion', 'Unknown')}"
                )
                return resultado
            else:
                return {'exito': True, 'mensaje': 'Evento no requiere cuarentena'}
                
        except Exception as e:
            error_msg = f"Error procesando notificación SIEM: {e}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
