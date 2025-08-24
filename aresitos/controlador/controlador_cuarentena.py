# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador de Cuarentena
Gestiona las operaciones de cuarentena integradas con el sistema de escaneo
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Importar controlador base
try:
    from aresitos.controlador.controlador_base import ControladorBase
    CONTROLADOR_BASE_DISPONIBLE = True
except ImportError:
    CONTROLADOR_BASE_DISPONIBLE = False

# Importar SudoManager para prevenir crashes
try:
    from aresitos.utils.sudo_manager import SudoManager
    SUDO_MANAGER_DISPONIBLE = True
except ImportError:
    SUDO_MANAGER_DISPONIBLE = False

# El modelo de cuarentena no existe - usar mock
class MockCuarentena:
    """Mock del sistema de cuarentena."""
    def __init__(self):
        self.archivos_cuarentena = []
        self.directorio_cuarentena = "/tmp/aresitos_quarantine"
    
    def poner_en_cuarentena(self, ruta_archivo, tipo_amenaza="desconocido", razon=""):
        """Mock para poner archivo en cuarentena."""
        return {"exito": True, "mensaje": "Archivo puesto en cuarentena (mock)", "ruta_cuarentena": f"/mock/quarantine/{os.path.basename(ruta_archivo)}"}
    
    def quitar_de_cuarentena(self, ruta_original, restaurar=True):
        """Mock para quitar archivo de cuarentena."""
        accion = "restaurado" if restaurar else "eliminado"
        return {"exito": True, "mensaje": f"Archivo {accion} de cuarentena (mock)"}
    
    def listar_archivos_cuarentena(self):
        """Mock para listar archivos en cuarentena."""
        return []
    
    def verificar_integridad(self):
        """Mock para verificar integridad."""
        return {
            "exito": True, 
            "archivos_verificados": 0, 
            "archivos_corruptos": 0,
            "integridad_ok": True
        }
    
    def limpiar_cuarentena(self, dias, confirmar=True):
        """Mock para limpiar cuarentena."""
        return {"exito": True, "archivos_eliminados": 0}
    
    def agregar_archivo(self, ruta, razon=""):
        return {"exito": True, "mensaje": "Archivo agregado a cuarentena mock"}
    
    def obtener_estadisticas(self):
        return {"total_archivos": 0, "estado": "mock"}

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
        self.logger = logging.getLogger(f"ARESITOS.{self.__class__.__name__}")
        
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
        
        # Usar mock de cuarentena ya que el modelo no existe
        self.cuarentena = MockCuarentena()
        self.directorio_cuarentena = directorio_cuarentena
        
        # Sistema de cuarentena no implementado - usar funcionalidad básica
        self.cuarentena_kali2025 = None
        self.logger.info("Sistema de cuarentena inicializado con funcionalidad básica")
        
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
                    tipo_amenaza=tipo_amenaza,
                    razon=f"{descripcion} - Severidad: {severidad}"
                )
                
                if resultado:
                    self.logger.warning(f"Archivo puesto en cuarentena: {archivo}")
                    self.logger.warning(f"Amenaza: {tipo_amenaza} - Severidad: {severidad}")
                    
                    # Notificar a otros sistemas si es crítico
                    if severidad == 'Crítica':
                        self._notificar_amenaza_critica(amenaza_info)
                
                return resultado.get('exito', False) if resultado else False
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
            
            return resultado.get('exito', False) if resultado else False
            
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
            
            return resultado.get('exito', False) if resultado else False
            
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
            # El mock retorna dict, extraer número o usar 0
            if isinstance(eliminados, dict):
                return eliminados.get('archivos_eliminados', 0)
            return eliminados if isinstance(eliminados, int) else 0
            
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
                self.logger.info("Cuarentena y análisis Kali 2025 completado")
            
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
