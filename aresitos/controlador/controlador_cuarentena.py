# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Cuarentena
Gestiona las operaciones de cuarentena integradas con el sistema de escaneo
"""

import logging
import os
from typing import Dict, List, Any, Optional
from ..modelo.cuarentena import Cuarentena, ArchivoEnCuarentena

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
        
        # Usar directorio por defecto si no se especifica
        if directorio_cuarentena is None:
            import tempfile
            directorio_cuarentena = os.path.join(tempfile.gettempdir(), "aresitos_quarantine")
        
        self.cuarentena = Cuarentena(directorio_cuarentena)
        
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
                # Verificar si el archivo está en uso con lsof
                import subprocess
                archivo_en_uso = False
                try:
                    lsof_result = subprocess.run(['lsof', archivo], 
                                               capture_output=True, text=True, timeout=10)
                    if lsof_result.returncode == 0 and lsof_result.stdout.strip():
                        archivo_en_uso = True
                        self.logger.warning(f"Archivo {archivo} está siendo usado por proceso: {lsof_result.stdout.strip()[:100]}")
                except:
                    pass  # lsof no disponible o error, continuar
                
                # Obtener información detallada con stat
                try:
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
                except:
                    pass
                
                # Calcular hash con sha256sum
                try:
                    hash_result = subprocess.run(['sha256sum', archivo],
                                               capture_output=True, text=True, timeout=30)
                    if hash_result.returncode == 0:
                        metadatos['hash_sha256'] = hash_result.stdout.split()[0]
                except:
                    pass
                
                resultado = self.cuarentena.poner_en_cuarentena(
                    archivo_path=archivo,
                    motivo=descripcion,
                    tipo_amenaza=tipo_amenaza,
                    severidad=severidad,
                    metadatos=metadatos
                )
                
                if resultado:
                    self.logger.warning(f"Archivo puesto en cuarentena: {archivo}")
                    self.logger.warning(f"Amenaza: {tipo_amenaza} - Severidad: {severidad}")
                    
                    # Notificar a otros sistemas si es crítico
                    if severidad == 'Crítica':
                        self._notificar_amenaza_critica(amenaza_info)
                
                return resultado
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
            estadisticas = self.cuarentena.obtener_estadisticas()
            archivos = self.cuarentena.listar_archivos_cuarentena()
            
            # Amenazas más recientes
            archivos_recientes = sorted(archivos, key=lambda x: x.fecha_cuarentena, reverse=True)[:5]
            
            # Amenazas críticas
            amenazas_criticas = [a for a in archivos if a.severidad == 'Crítica']
            
            resumen = {
                'estadisticas_generales': estadisticas,
                'total_archivos': len(archivos),
                'amenazas_criticas': len(amenazas_criticas),
                'archivos_recientes': [
                    {
                        'archivo': a.ruta_original,
                        'tipo': a.tipo_amenaza,
                        'severidad': a.severidad,
                        'fecha': a.fecha_cuarentena.isoformat()
                    } for a in archivos_recientes
                ],
                'amenazas_criticas_detalle': [
                    {
                        'archivo': a.ruta_original,
                        'tipo': a.tipo_amenaza,
                        'motivo': a.motivo,
                        'fecha': a.fecha_cuarentena.isoformat()
                    } for a in amenazas_criticas
                ],
                'integridad': self.cuarentena.verificar_integridad()
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
            resultado = self.cuarentena.quitar_de_cuarentena(ruta_original, restaurar=True)
            
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
            resultado = self.cuarentena.quitar_de_cuarentena(ruta_original, restaurar=False)
            
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
            eliminados = self.cuarentena.limpiar_cuarentena(dias, confirmar=True)
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
            estadisticas = self.cuarentena.obtener_estadisticas()
            archivos = self.cuarentena.listar_archivos_cuarentena()
            integridad = self.cuarentena.verificar_integridad()
            
            reporte = {
                'timestamp': estadisticas.get('archivo_mas_reciente'),
                'resumen_ejecutivo': {
                    'total_archivos_cuarentena': estadisticas['total_archivos'],
                    'espacio_utilizado_mb': estadisticas['tamano_total_mb'],
                    'amenazas_criticas': estadisticas['por_severidad'].get('Crítica', 0),
                    'integridad_ok': integridad['integridad_ok']
                },
                'estadisticas_detalladas': estadisticas,
                'verificacion_integridad': integridad,
                'archivos_por_severidad': {},
                'recomendaciones': []
            }
            
            # Agrupar archivos por severidad
            for severidad in ['Crítica', 'Alta', 'Media', 'Baja']:
                archivos_severidad = [a for a in archivos if a.severidad == severidad]
                reporte['archivos_por_severidad'][severidad] = [
                    {
                        'archivo': a.ruta_original,
                        'tipo_amenaza': a.tipo_amenaza,
                        'motivo': a.motivo,
                        'fecha': a.fecha_cuarentena.isoformat(),
                        'tamano_mb': round(a.tamano / (1024 * 1024), 2)
                    } for a in archivos_severidad
                ]
            
            # Generar recomendaciones
            if estadisticas['por_severidad'].get('Crítica', 0) > 0:
                reporte['recomendaciones'].append("Se detectaron amenazas críticas. Revisar inmediatamente.")
            
            if estadisticas['tamano_total_mb'] > 1000:  # 1GB
                reporte['recomendaciones'].append("La cuarentena ocupa más de 1GB. Considerar limpieza.")
            
            if not integridad['integridad_ok']:
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
                'error': str(e)
            }
    
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
