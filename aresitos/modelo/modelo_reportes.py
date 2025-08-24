# -*- coding: utf-8 -*-

import os
import json
import datetime
import logging
import re
from typing import Dict, List, Any, Optional

class ModeloReportes:
    
    def __init__(self):
        self.directorio_reportes = self._crear_directorio_reportes()
        self.patron_nombre_seguro = re.compile(r'^[a-zA-Z0-9_-]+\.(json|txt)$')
        self.extensiones_permitidas = {'.json', '.txt'}
        
    def _validar_nombre_archivo_seguro(self, nombre_archivo):
        """Valida que el nombre de archivo sea completamente seguro"""
        if not nombre_archivo:
            return False
            
        # Verificar patrón seguro
        if not self.patron_nombre_seguro.match(nombre_archivo):
            return False
            
        # Verificar que no contenga secuencias peligrosas
        secuencias_peligrosas = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        if any(seq in nombre_archivo for seq in secuencias_peligrosas):
            return False
            
        return True
        
    def _normalizar_path(self, path):
        """Normaliza y valida paths de forma segura"""
        normalized = os.path.normpath(path)
        # Verificar que no escape del directorio base
        if '..' in normalized:
            raise ValueError("Path traversal detectado")
        return normalized
    
    def _crear_directorio_reportes(self) -> str:
        """Crea directorio de reportes dentro del proyecto de forma segura"""
        try:
            # Usar directorio de reportes dentro del proyecto Aresitos
            # Obtener directorio base del proyecto
            proyecto_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            directorio = os.path.join(proyecto_dir, "reportes")
            
            # Normalizar el path
            directorio = self._normalizar_path(directorio)
            
            # Crear directorio si no existe
            if not os.path.exists(directorio):
                os.makedirs(directorio, mode=0o755)
                logging.info(f"Directorio de reportes creado: {directorio}")
            
            # Verificar permisos de escritura
            if not os.access(directorio, os.W_OK):
                logging.error(f"Sin permisos de escritura en directorio de reportes: {directorio}")
                raise PermissionError(f"Sin permisos de escritura: {directorio}")
            
            # Verificar que es realmente un directorio
            if not os.path.isdir(directorio):
                raise OSError(f"La ruta no es un directorio válido: {directorio}")
                
            return directorio
            
        except Exception as e:
            logging.error(f"Error creando directorio de reportes: {e}")
            # Fallback a directorio temporal del sistema
            directorio_temporal = os.path.join(os.path.expanduser("~"), ".aresitos", "reportes")
            os.makedirs(directorio_temporal, exist_ok=True)
            logging.warning(f"Usando directorio temporal: {directorio_temporal}")
            return directorio_temporal

    def generar_reporte_completo(self, datos_escaneo: Dict, datos_monitoreo: Dict, datos_utilidades: Dict, datos_fim: Optional[Dict] = None, datos_siem: Optional[Dict] = None, datos_cuarentena: Optional[Dict] = None, datos_auditoria: Optional[Dict] = None, datos_wordlists: Optional[Dict] = None, datos_herramientas_kali: Optional[Dict] = None, datos_logs_centralizados: Optional[Dict] = None, datos_configuracion_sistema: Optional[Dict] = None, datos_terminal_principal: Optional[Dict] = None) -> Dict[str, Any]:
        """Genera un reporte completo con TODOS los módulos de ARESITOS v3.0"""
        
        # Validar datos de entrada
        if not self.validar_datos_reporte({'escaneo': datos_escaneo, 'monitoreo': datos_monitoreo, 'utilidades': datos_utilidades}):
            raise ValueError("Datos de entrada inválidos para generar reporte")
        
        timestamp = datetime.datetime.now()
        fecha_formateada = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        reporte = {
            'version': 'ARESITOS v3.0',
            'fecha_generacion': fecha_formateada,
            'timestamp': timestamp.isoformat(),
            'tipo': 'completo',
            'resumen': {
                'total_herramientas': len(datos_utilidades.get('herramientas_disponibles', [])),
                'servicios_activos': len(datos_monitoreo.get('servicios', [])),
                'problemas_permisos': len(datos_utilidades.get('problemas_permisos', [])),
                'alertas_escaneo': len(datos_escaneo.get('alertas', [])),
                'eventos_monitoreo': len(datos_monitoreo.get('eventos', [])),
                'cambios_fim': len(datos_fim.get('cambios', [])) if datos_fim else 0,
                'alertas_siem': len(datos_siem.get('alertas', [])) if datos_siem else 0,
                'archivos_cuarentena': len(datos_cuarentena.get('archivos', [])) if datos_cuarentena else 0,
                'auditorias_ejecutadas': len(datos_auditoria.get('auditorias_ejecutadas', [])) if datos_auditoria else 0,
                'wordlists_disponibles': len(datos_wordlists.get('archivos_cargados', [])) if datos_wordlists else 0,
                'herramientas_kali_verificadas': len(datos_herramientas_kali.get('herramientas_verificadas', [])) if datos_herramientas_kali else 0,
                'archivos_log_encontrados': len(datos_logs_centralizados.get('archivos_log_encontrados', [])) if datos_logs_centralizados else 0,
                'terminales_capturados': datos_terminal_principal.get('total_terminales', 0) if datos_terminal_principal else 0,
                'memoria_sistema_gb': datos_configuracion_sistema.get('rendimiento_sistema', {}).get('memoria_total_gb', 0) if datos_configuracion_sistema else 0
            },
            'detalles': {
                'escaneo': datos_escaneo,
                'monitoreo': datos_monitoreo,
                'utilidades': datos_utilidades,
                'fim': datos_fim,
                'siem': datos_siem,
                'cuarentena': datos_cuarentena,
                'auditoria': datos_auditoria,
                'wordlists': datos_wordlists,
                'herramientas_kali': datos_herramientas_kali,
                'logs_centralizados': datos_logs_centralizados,
                'configuracion_sistema': datos_configuracion_sistema,
                'terminal_principal': datos_terminal_principal
            }
        }
        
        return reporte

    def generar_reporte_texto(self, reporte: Dict) -> str:
        """Genera version en texto plano del reporte"""
        version = reporte.get('version', 'ARESITOS')
        texto = f"""
REPORTE DE SEGURIDAD {version}
===============================
Fecha: {reporte.get('fecha_generacion', 'No disponible')}

RESUMEN EJECUTIVO
-----------------
Herramientas verificadas: {reporte['resumen']['total_herramientas']}
Servicios activos: {reporte['resumen']['servicios_activos']}
Problemas de permisos: {reporte['resumen']['problemas_permisos']}
Alertas de escaneo: {reporte['resumen']['alertas_escaneo']}
Eventos de monitoreo: {reporte['resumen']['eventos_monitoreo']}
Cambios FIM detectados: {reporte['resumen'].get('cambios_fim', 0)}
Alertas SIEM generadas: {reporte['resumen'].get('alertas_siem', 0)}
Archivos en cuarentena: {reporte['resumen'].get('archivos_cuarentena', 0)}
Terminal principal - lineas: {reporte['resumen'].get('terminal_principal_lineas', 0)}
"""
        return texto

    def validar_datos_reporte(self, datos):
        """Valida datos para reporte (principio de Seguridad)"""
        if not isinstance(datos, dict):
            return False
        
        # Validar estructura minima
        if not datos:
            return False
            
        # Validar que contiene al menos algunos datos válidos
        campos_requeridos = ['escaneo', 'monitoreo', 'utilidades']
        if not any(campo in datos for campo in campos_requeridos):
            return False
            
        return True

    def validar_formato_salida(self, formato):
        """Valida formato de salida permitido"""
        formatos_permitidos = ['json', 'txt']
        return formato.lower() in formatos_permitidos

    def obtener_estadisticas_reportes(self) -> Dict[str, Any]:
        """Obtiene estadísticas de reportes generados"""
        try:
            reportes = self.listar_reportes()
            
            total_reportes = len(reportes)
            tipos_reportes = {}
            reportes_por_fecha = {}
            
            for reporte_info in reportes:
                # Contar por tipo si existe el campo
                tipo = reporte_info.get('tipo', 'desconocido')
                tipos_reportes[tipo] = tipos_reportes.get(tipo, 0) + 1
                
                # Contar por fecha
                fecha = reporte_info.get('fecha_creacion', '').split(' ')[0]  # Solo la fecha
                if fecha:
                    reportes_por_fecha[fecha] = reportes_por_fecha.get(fecha, 0) + 1
            
            return {
                'total_reportes': total_reportes,
                'tipos_reportes': tipos_reportes,
                'reportes_por_fecha': reportes_por_fecha,
                'directorio_reportes': self.directorio_reportes
            }
            
        except Exception as e:
            logging.error(f"Error obteniendo estadísticas de reportes: {e}")
            return {
                'total_reportes': 0,
                'tipos_reportes': {},
                'reportes_por_fecha': {},
                'directorio_reportes': self.directorio_reportes,
                'error': str(e)
            }

    def limpiar_reportes_antiguos(self, dias_antiguedad: int = 30) -> int:
        """Limpia reportes más antiguos que el número de días especificado"""
        try:
            reportes_eliminados = 0
            fecha_limite = datetime.datetime.now() - datetime.timedelta(days=dias_antiguedad)
            
            for archivo in os.listdir(self.directorio_reportes):
                ruta_archivo = os.path.join(self.directorio_reportes, archivo)
                
                # Validar que es un archivo y no un directorio
                if not os.path.isfile(ruta_archivo):
                    continue
                
                # Verificar extensión
                if not any(archivo.endswith(ext) for ext in ['.json', '.txt']):
                    continue
                
                # Verificar fecha de modificación
                fecha_modificacion = datetime.datetime.fromtimestamp(os.path.getmtime(ruta_archivo))
                
                if fecha_modificacion < fecha_limite:
                    try:
                        os.remove(ruta_archivo)
                        reportes_eliminados += 1
                        logging.info(f"Reporte antiguo eliminado: {archivo}")
                    except Exception as e:
                        logging.error(f"Error eliminando reporte {archivo}: {e}")
            
            logging.info(f"Limpieza completada. Reportes eliminados: {reportes_eliminados}")
            return reportes_eliminados
            
        except Exception as e:
            logging.error(f"Error en limpieza de reportes antiguos: {e}")
            return 0

    def guardar_reporte_json(self, reporte: Dict, nombre_archivo: Optional[str] = None) -> bool:
        """Guarda reporte JSON con validaciones de seguridad"""
        try:
            if not nombre_archivo:
                timestamp = reporte.get('timestamp', datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
                nombre_archivo = f"reporte_{timestamp}.json"
            
            # Validar nombre de archivo
            if not self._validar_nombre_archivo_seguro(nombre_archivo):
                logging.warning(f"Nombre de archivo inseguro bloqueado: {nombre_archivo}")
                return False
            
            ruta_archivo = os.path.join(self.directorio_reportes, nombre_archivo)
            ruta_archivo = self._normalizar_path(ruta_archivo)
            
            # Verificar que el archivo está dentro del directorio de reportes
            if not ruta_archivo.startswith(self.directorio_reportes):
                logging.error("Intento de path traversal bloqueado")
                return False
            
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                json.dump(reporte, f, indent=2, ensure_ascii=False, default=str)
            
            logging.info(f"Reporte JSON guardado exitosamente: {ruta_archivo}")
            return True
            
        except Exception as e:
            logging.error(f"Error guardando reporte JSON: {e}")
            return False

    def guardar_reporte_texto(self, reporte: Dict, nombre_archivo: Optional[str] = None) -> bool:
        """Guarda reporte texto con validaciones de seguridad"""
        try:
            if not nombre_archivo:
                timestamp = reporte.get('timestamp', datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
                nombre_archivo = f"reporte_{timestamp}.txt"
            
            # Validar nombre de archivo
            if not self._validar_nombre_archivo_seguro(nombre_archivo):
                logging.warning(f"Nombre de archivo inseguro bloqueado: {nombre_archivo}")
                return False
            
            ruta_archivo = os.path.join(self.directorio_reportes, nombre_archivo)
            ruta_archivo = self._normalizar_path(ruta_archivo)
            
            # Verificar que el archivo está dentro del directorio de reportes
            if not ruta_archivo.startswith(self.directorio_reportes):
                logging.error("Intento de path traversal bloqueado")
                return False
            
            texto_reporte = self.generar_reporte_texto(reporte)
            
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                f.write(texto_reporte)
            
            logging.info(f"Reporte texto guardado exitosamente: {ruta_archivo}")
            return True
            
        except Exception as e:
            logging.error(f"Error guardando reporte texto: {e}")
            return False

    def listar_reportes(self) -> List[Dict[str, Any]]:
        """Lista reportes con validaciones de seguridad"""
        reportes = []
        
        try:
            if not os.path.exists(self.directorio_reportes):
                logging.warning(f"Directorio de reportes no existe: {self.directorio_reportes}")
                return reportes
            
            for archivo in os.listdir(self.directorio_reportes):
                try:
                    ruta_archivo = os.path.join(self.directorio_reportes, archivo)
                    
                    # Validaciones de seguridad
                    if not os.path.isfile(ruta_archivo):
                        continue
                    
                    if not self._validar_nombre_archivo_seguro(archivo):
                        continue
                    
                    # Obtener información del archivo
                    stat_info = os.stat(ruta_archivo)
                    fecha_creacion = datetime.datetime.fromtimestamp(stat_info.st_ctime)
                    fecha_modificacion = datetime.datetime.fromtimestamp(stat_info.st_mtime)
                    tamaño = stat_info.st_size
                    
                    # Determinar tipo por extensión
                    if archivo.endswith('.json'):
                        tipo = 'json'
                        # Intentar obtener tipo desde el contenido JSON
                        try:
                            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                                contenido = json.load(f)
                                tipo = contenido.get('tipo', 'json')
                        except (FileNotFoundError, PermissionError, OSError) as e:
                            logging.debug(f'Error en excepción: {e}')
                            pass
                    elif archivo.endswith('.txt'):
                        tipo = 'texto'
                    else:
                        tipo = 'desconocido'
                    
                    reporte_info = {
                        'nombre_archivo': archivo,
                        'ruta_completa': ruta_archivo,
                        'tipo': tipo,
                        'tamaño_bytes': tamaño,
                        'fecha_creacion': fecha_creacion.strftime("%Y-%m-%d %H:%M:%S"),
                        'fecha_modificacion': fecha_modificacion.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    reportes.append(reporte_info)
                    
                except Exception as e:
                    logging.warning(f"Error procesando archivo {archivo}: {e}")
                    continue
            
            # Ordenar por fecha de modificación (más recientes primero)
            reportes.sort(key=lambda x: x['fecha_modificacion'], reverse=True)
            
        except Exception as e:
            logging.error(f"Error listando reportes: {e}")
        
        return reportes
