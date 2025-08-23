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
            
            # Verificar que estamos dentro del proyecto
            if not directorio.startswith(proyecto_dir):
                raise ValueError("Directorio fuera del proyecto")
            
            if not os.path.exists(directorio):
                os.makedirs(directorio, mode=0o755)  # Permisos normales para el proyecto
                
            return directorio
        except Exception as e:
            logging.error(f"Error creando directorio de reportes: {str(e)}")
            # Fallback a directorio temporal dentro del proyecto
            try:
                proyecto_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                temp_dir = os.path.join(proyecto_dir, "reportes_temp")
                os.makedirs(temp_dir, exist_ok=True)
                return temp_dir
            except:
                import tempfile
                return tempfile.mkdtemp(prefix="aresitos_reportes_")
    
    def generar_reporte_completo(self, datos_escaneo: Dict, datos_monitoreo: Dict, datos_utilidades: Dict, datos_fim: Optional[Dict] = None, datos_siem: Optional[Dict] = None, datos_cuarentena: Optional[Dict] = None, datos_terminal_principal: Optional[Dict] = None) -> Dict[str, Any]:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Inicializar datos opcionales - Issue 20/24
        datos_fim = datos_fim or {}
        datos_siem = datos_siem or {}
        datos_cuarentena = datos_cuarentena or {}
        datos_terminal_principal = datos_terminal_principal or {}
        
        reporte = {
            "timestamp": timestamp,
            "fecha_generacion": datetime.datetime.now().isoformat(),
            "version": "ARESITOS v2.0.0-kali-optimized",
            "resumen": {
                "total_herramientas": len(datos_utilidades.get('herramientas', [])),
                "servicios_activos": len(datos_utilidades.get('servicios', [])),
                "problemas_permisos": len(datos_utilidades.get('permisos_archivos', [])),
                "alertas_escaneo": len(datos_escaneo.get('alertas', [])),
                "eventos_monitoreo": len(datos_monitoreo.get('eventos', [])),
                "cambios_fim": len(datos_fim.get('cambios_detectados', [])),
                "alertas_siem": len(datos_siem.get('alertas_generadas', [])),
                "archivos_cuarentena": len(datos_cuarentena.get('archivos_aislados', [])),
                "terminal_principal_lineas": datos_terminal_principal.get('terminal_lines', 0)
            },
            "datos": {
                "escaneo": datos_escaneo,
                "monitoreo": datos_monitoreo,
                "utilidades": datos_utilidades,
                "fim": datos_fim,
                "siem": datos_siem,
                "cuarentena": datos_cuarentena,
                "terminal_principal": datos_terminal_principal
            }
        }
        
        return reporte
    
    def generar_reporte_texto(self, reporte: Dict) -> str:
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

DETALLES
--------
"""
        return texto

    def validar_datos_reporte(self, datos):
        """Valida datos para reporte (principio de Seguridad)."""
        if not isinstance(datos, dict):
            return False
        
        # Validar estructura mínima
        if 'tipo' not in datos or 'contenido' not in datos:
            return False
        
        # Validar tipo de reporte
        tipos_validos = ['escaneo', 'monitoreo', 'fim', 'siem', 'auditoria']
        if datos['tipo'] not in tipos_validos:
            return False
        
        return True

    def validar_formato_salida(self, formato):
        """Valida formato de salida (principio de Seguridad)."""
        formatos_validos = ['json', 'txt', 'html', 'pdf']
        return formato.lower() in formatos_validos if formato else False

"""
        
        if reporte['datos']['utilidades'].get('herramientas'):
            texto += "\nHerramientas del Sistema:\n"
            for herramienta in reporte['datos']['utilidades']['herramientas']:
                texto += f"- {herramienta}\n"
        
        if reporte['datos']['utilidades'].get('servicios'):
            texto += "\nServicios Activos:\n"
            for servicio in reporte['datos']['utilidades']['servicios']:
                texto += f"- {servicio}\n"
        
        # Agregar información de FIM
        if reporte['datos'].get('fim') and reporte['datos']['fim'].get('cambios_detectados'):
            texto += "\nCambios de Integridad de Archivos (FIM):\n"
            for cambio in reporte['datos']['fim']['cambios_detectados']:
                texto += f"- {cambio}\n"
        
        # Agregar información de SIEM
        if reporte['datos'].get('siem') and reporte['datos']['siem'].get('alertas_generadas'):
            texto += "\nAlertas del Sistema SIEM:\n"
            for alerta in reporte['datos']['siem']['alertas_generadas']:
                texto += f"- {alerta}\n"
        
        # Agregar información de cuarentena
        if reporte['datos'].get('cuarentena') and reporte['datos']['cuarentena'].get('archivos_aislados'):
            texto += "\nArchivos en Cuarentena:\n"
            for archivo in reporte['datos']['cuarentena']['archivos_aislados']:
                texto += f"- {archivo}\n"
        
        # Agregar información del terminal principal - Issue 20/24
        if reporte['datos'].get('terminal_principal'):
            terminal_data = reporte['datos']['terminal_principal']
            if terminal_data.get('estado') == 'captura_completa':
                texto += "\nTerminal Principal de Aresitos:\n"
                if terminal_data.get('eventos_sistema'):
                    texto += "Eventos del Sistema:\n"
                    for evento in terminal_data['eventos_sistema'][:10]:  # Limitar a 10 eventos
                        texto += f"- {evento}\n"
                if terminal_data.get('comandos_ejecutados'):
                    texto += "Comandos Ejecutados:\n"
                    for comando in terminal_data['comandos_ejecutados'][:10]:  # Limitar a 10 comandos
                        texto += f"- {comando}\n"
                estadisticas = terminal_data.get('estadisticas', {})
                texto += f"Estadísticas Terminal: {estadisticas.get('lineas_terminal', 0)} líneas, "
                texto += f"{estadisticas.get('eventos_sistema', 0)} eventos, "
                texto += f"{estadisticas.get('comandos_ejecutados', 0)} comandos\n"
        
        return texto
    
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
                json.dump(reporte, f, indent=2, ensure_ascii=False)
            
            return True
        except PermissionError:
            logging.error("Sin permisos para escribir archivo JSON")
            return False
        except IOError:
            logging.error("Error de E/S al escribir archivo JSON")
            return False
        except Exception as e:
            logging.error(f"Error no específico guardando JSON: {type(e).__name__}")
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
            
            return True
        except PermissionError:
            logging.error("Sin permisos para escribir archivo de texto")
            return False
        except IOError:
            logging.error("Error de E/S al escribir archivo de texto")
            return False
        except Exception as e:
            logging.error(f"Error no específico guardando texto: {type(e).__name__}")
            return False
    
    def listar_reportes(self) -> List[Dict[str, Any]]:
        """Lista reportes con validaciones de seguridad"""
        reportes = []
        
        try:
            # Verificar que el directorio existe y es accesible
            if not os.path.exists(self.directorio_reportes):
                logging.warning("Directorio de reportes no existe")
                return reportes
                
            if not os.path.isdir(self.directorio_reportes):
                logging.error("Ruta de reportes no es un directorio")
                return reportes
            
            for archivo in os.listdir(self.directorio_reportes):
                # Validar extensión permitida
                extension = os.path.splitext(archivo)[1]
                if extension not in self.extensiones_permitidas:
                    continue
                
                # Validar nombre de archivo completo
                if not self._validar_nombre_archivo_seguro(archivo):
                    logging.warning(f"Archivo con nombre inseguro omitido: {archivo}")
                    continue
                
                ruta_completa = os.path.join(self.directorio_reportes, archivo)
                ruta_completa = self._normalizar_path(ruta_completa)
                
                # Verificar que el archivo está dentro del directorio permitido
                if not ruta_completa.startswith(self.directorio_reportes):
                    logging.warning(f"Archivo fuera del directorio permitido: {archivo}")
                    continue
                
                try:
                    stat_info = os.stat(ruta_completa)
                    
                    reportes.append({
                        'nombre': archivo,
                        'ruta': ruta_completa,
                        'tamaño': stat_info.st_size,
                        'modificado': datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
                except (OSError, PermissionError):
                    logging.warning(f"No se pudo acceder al archivo: {archivo}")
                    continue
                    
        except PermissionError:
            logging.error("Sin permisos para acceder al directorio de reportes")
        except OSError:
            logging.error("Error de sistema al listar reportes")
        except Exception as e:
            logging.error(f"Error no específico listando reportes: {type(e).__name__}")
        
        return sorted(reportes, key=lambda x: x['modificado'], reverse=True)

    def validar_datos_reporte(self, datos):
        """Valida datos para reporte (principio de Seguridad)."""
        if not isinstance(datos, dict):
            return False
        
        # Validar estructura mínima
        if 'tipo' not in datos or 'contenido' not in datos:
            return False
        
        # Validar tipo de reporte
        tipos_validos = ['escaneo', 'monitoreo', 'fim', 'siem', 'auditoria']
        if datos['tipo'] not in tipos_validos:
            return False
        
        return True

    def validar_formato_salida(self, formato):
        """Valida formato de salida (principio de Seguridad)."""
        formatos_validos = ['json', 'txt', 'html', 'pdf']
        return formato.lower() in formatos_validos if formato else False
