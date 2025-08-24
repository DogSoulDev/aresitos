# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador de Reportes
Controlador de Reportes para ARESITOS v3.0 - Sistema de Ciberseguridad Integral.
"""

import os
import re
import json
import logging
from typing import Optional
from aresitos.controlador.controlador_base import ControladorBase
from aresitos.modelo.modelo_reportes import ModeloReportes


class ControladorReportes(ControladorBase):
    """
    Controlador de Reportes para ARESITOS v3.0 - Sistema de Ciberseguridad Integral.
    
    Este controlador implementa los 8 principios fundamentales de ARESITOS
    para la generación, gestión y distribución de reportes de seguridad:
    
    1. Automatización: Generación automática de reportes programados
    2. Robustez: Manejo robusto de grandes volúmenes de datos
    3. Eficiencia: Optimización en procesamiento y renderizado
    4. Seguridad: Protección de datos sensibles en reportes
    5. Integración: Conexión con todos los módulos del sistema
    6. Transparencia: Reportes claros y comprensibles
    7. Optimización: Formatos optimizados para diferentes usos
    8. Simplicidad: Interfaz simple para generación de reportes
    
    Funcionalidades principales:
    - Generación de reportes de vulnerabilidades
    - Reportes de monitoreo en tiempo real
    - Análisis de tendencias de seguridad
    - Exportación en múltiples formatos (PDF, HTML, JSON)
    - Programación automática de reportes
    - Dashboard ejecutivo con métricas clave
    
    Attributes:
        modelo_reportes: Instancia del modelo de datos
        vista_reportes: Instancia de la vista de reportes
        logger: Sistema de logging integrado
        configuracion: Parámetros de configuración
    
    Methods:
        inicializar(): Inicializa el controlador según principios ARESITOS
        generar_reporte(): Genera reportes específicos
        programar_reporte(): Programa reportes automáticos
        exportar_reporte(): Exporta reportes en diferentes formatos
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorReportes")
        self.reportes = ModeloReportes()
        
        # Validaciones de seguridad
        self.formatos_permitidos = {'json', 'txt'}
        self.patron_nombre_archivo = re.compile(r'^[a-zA-Z0-9_-]+$')
        
        # Registrar inicialización exitosa
        self.logger.info("ControladorReportes v3.0 inicializado correctamente")
    
    def inicializar(self):
        """
        Inicializa el controlador (requerido por principios ARESITOS).
        
        Returns:
            bool: True si la inicialización es exitosa
        """
        try:
            self.logger.info("Inicializando ControladorReportes")
            return True
        except Exception as e:
            self.logger.error(f"Error en inicializar(): {e}")
            return False
    
    async def _inicializar_impl(self):
        """
        Implementación específica de inicialización para ControladorReportes.
        
        Returns:
            Dict con resultado de la inicialización específica
        """
        try:
            # Inicializar componentes específicos del controlador de reportes
            self.logger.info("Ejecutando inicialización específica de ControladorReportes")
            
            # Verificar que el modelo de reportes esté disponible
            if not self.reportes:
                return {'exito': False, 'error': 'Modelo de reportes no disponible'}
            
            # Verificar directorio de reportes usando ruta relativa
            directorio_reportes = os.path.join(os.path.dirname(__file__), '..', '..', 'reportes')
            directorio_reportes = os.path.abspath(directorio_reportes)
            
            if not os.path.exists(directorio_reportes):
                os.makedirs(directorio_reportes, exist_ok=True)
                self.logger.info(f"Directorio de reportes creado: {directorio_reportes}")
            
            return {'exito': True, 'mensaje': 'ControladorReportes inicializado correctamente'}
            
        except Exception as e:
            error_msg = f"Error en inicialización específica de ControladorReportes: {e}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
        
    def _validar_nombre_archivo(self, nombre_archivo):
        """Valida que el nombre de archivo sea seguro"""
        if not nombre_archivo:
            return False
        
        # Remover extensión para validar solo el nombre base
        nombre_base = os.path.splitext(nombre_archivo)[0]
        
        # Verificar patrón seguro
        if not self.patron_nombre_archivo.match(nombre_base):
            return False
            
        # Verificar que no contenga secuencias de path traversal
        if '..' in nombre_archivo or '/' in nombre_archivo or '\\' in nombre_archivo:
            return False
            
        return True
        
    def _validar_formato(self, formato):
        """Valida que el formato sea permitido"""
        return formato.lower() in self.formatos_permitidos
    
    def generar_reporte_completo(self, datos_escaneo=None, datos_monitoreo=None, datos_utilidades=None, datos_fim=None, datos_siem=None, datos_cuarentena=None, datos_auditoria=None, datos_wordlists=None, datos_herramientas_kali=None, datos_logs_centralizados=None, datos_configuracion_sistema=None, datos_terminal_principal=None):
        """Genera reporte completo incluyendo TODOS los módulos de ARESITOS v3.0 - Issue 20/24"""
        return self.reportes.generar_reporte_completo(
            datos_escaneo or {}, 
            datos_monitoreo or {}, 
            datos_utilidades or {},
            datos_fim or {},
            datos_siem or {},
            datos_cuarentena or {},
            datos_auditoria or {},
            datos_wordlists or {},
            datos_herramientas_kali or {},
            datos_logs_centralizados or {},
            datos_configuracion_sistema or {},
            datos_terminal_principal or {}
        )
    
    def guardar_reporte_json(self, reporte, nombre_archivo=None):
        """Guarda reporte en formato JSON con validación de seguridad"""
        if nombre_archivo and not self._validar_nombre_archivo(nombre_archivo):
            logging.warning("Nombre de archivo inválido bloqueado")
            return {'exito': False, 'error': 'Nombre de archivo no válido'}
            
        return self.reportes.guardar_reporte_json(reporte, nombre_archivo)
    
    def guardar_reporte_texto(self, reporte, nombre_archivo=None):
        """Guarda reporte en formato texto con validación de seguridad"""
        if nombre_archivo and not self._validar_nombre_archivo(nombre_archivo):
            logging.warning("Nombre de archivo inválido bloqueado")
            return {'exito': False, 'error': 'Nombre de archivo no válido'}
            
        return self.reportes.guardar_reporte_texto(reporte, nombre_archivo)
    
    def listar_reportes_guardados(self):
        return self.reportes.listar_reportes()
    
    def exportar_reporte_personalizado(self, datos, formato='json', nombre_archivo=None):
        """Exporta reporte personalizado con validaciones de seguridad"""
        import datetime
        
        # Validar formato
        if not self._validar_formato(formato):
            logging.warning(f"Formato no permitido: {formato}")
            return {'exito': False, 'error': 'Formato no soportado'}
        
        # Validar nombre de archivo si se proporciona
        if nombre_archivo and not self._validar_nombre_archivo(nombre_archivo):
            logging.warning("Nombre de archivo inválido en exportación")
            return {'exito': False, 'error': 'Nombre de archivo no válido'}
        
        reporte_personalizado = {
            'titulo': 'Reporte Personalizado Aresitos',
            'fecha_generacion': datetime.datetime.now().isoformat(),
            'datos': datos,
            'tipo': 'personalizado'
        }
        
        if formato.lower() == 'json':
            return self.guardar_reporte_json(reporte_personalizado, nombre_archivo)
        elif formato.lower() == 'txt':
            return self.guardar_reporte_texto(reporte_personalizado, nombre_archivo)
        else:
            return {'exito': False, 'error': 'Formato no soportado'}
    
    def generar_resumen_reportes(self):
        reportes = self.listar_reportes_guardados()
        if not isinstance(reportes, list):
            return {'exito': False, 'error': 'No se pudieron obtener reportes'}
        
        return {
            'exito': True,
            'total_reportes': len(reportes),
            'tipos_disponibles': ['json', 'txt'],
            'ultimo_reporte': reportes[-1] if reportes else None,
            'reportes_recientes': reportes[-5:] if len(reportes) >= 5 else reportes
        }
    
    def obtener_estadisticas_reportes(self):
        reportes = self.listar_reportes_guardados()
        if not isinstance(reportes, list):
            return {'exito': False, 'error': 'No se pudieron obtener reportes'}
        
        tipos_archivo = {}
        
        for reporte in reportes:
            nombre = reporte.get('nombre', '') if isinstance(reporte, dict) else str(reporte)
            extension = nombre.split('.')[-1] if '.' in nombre else 'sin_extension'
            tipos_archivo[extension] = tipos_archivo.get(extension, 0) + 1
        
        return {
            'exito': True,
            'total_reportes': len(reportes),
            'tipos_archivo': tipos_archivo,
            'espacio_utilizado': self._calcular_espacio_reportes()
        }
    
    def _calcular_espacio_reportes(self):
        """Calcula espacio utilizado por reportes con manejo seguro de errores"""
        try:
            import os
            directorio = self.reportes.directorio_reportes
            
            # Validar que el directorio existe y es seguro
            if not os.path.exists(directorio):
                return "Directorio no encontrado"
                
            if not os.path.isdir(directorio):
                return "Ruta no es directorio"
            
            total_size = 0
            
            for archivo in os.listdir(directorio):
                ruta_completa = os.path.join(directorio, archivo)
                if os.path.isfile(ruta_completa):
                    total_size += os.path.getsize(ruta_completa)
            
            return f"{total_size / 1024:.2f} KB"
        except PermissionError:
            logging.error("Sin permisos para acceder al directorio de reportes")
            return "Sin permisos"
        except OSError:
            logging.error("Error de sistema al calcular espacio")
            return "Error de sistema"
        except Exception:
            logging.error("Error no específico al calcular espacio")
            return "No disponible"
    
    def generar_reporte(self, tipo_reporte: str, datos: Optional[dict] = None, formato: str = "json") -> dict:
        """
        Generar reporte específico con datos proporcionados.
        
        Args:
            tipo_reporte: Tipo de reporte (escaneo, auditoria, monitoreo, siem, fim)
            datos: Datos para incluir en el reporte
            formato: Formato de salida (json, txt, html)
            
        Returns:
            Dict con resultado de la generación
        """
        try:
            # Validar parámetros
            if not tipo_reporte:
                return {'exito': False, 'error': 'Tipo de reporte requerido'}
            
            if formato not in ['json', 'txt', 'html']:
                return {'exito': False, 'error': 'Formato no válido'}
            
            # Usar datos vacío si no se proporciona
            if datos is None:
                datos = {}
            
            # Generar datos del reporte
            datos_reporte = {
                'tipo': tipo_reporte,
                'timestamp': self._obtener_timestamp(),
                'formato': formato,
                'datos': datos,
                'version': 'ARESITOS v3.0',
                'fecha_generacion': self._obtener_fecha_legible(),
                'sistema': 'ARESITOS - Sistema de Ciberseguridad'
            }
            
            # Generar contenido específico según tipo
            if tipo_reporte == 'escaneo':
                datos_reporte['resumen'] = self._generar_resumen_escaneo(datos)
            elif tipo_reporte == 'auditoria':
                datos_reporte['resumen'] = self._generar_resumen_auditoria(datos)
            elif tipo_reporte == 'monitoreo':
                datos_reporte['resumen'] = self._generar_resumen_monitoreo(datos)
            elif tipo_reporte == 'siem':
                datos_reporte['resumen'] = self._generar_resumen_siem(datos)
            elif tipo_reporte == 'fim':
                datos_reporte['resumen'] = self._generar_resumen_fim(datos)
            else:
                datos_reporte['resumen'] = f'Reporte general de {tipo_reporte}'
            
            # Generar nombre de archivo único
            nombre_archivo = f"reporte_{tipo_reporte}_{self._obtener_timestamp_archivo()}"
            
            # Guardar usando el modelo
            if formato == 'json':
                nombre_completo = f"{nombre_archivo}.json"
                exito = self.reportes.guardar_reporte_json(datos_reporte, nombre_completo)
            elif formato == 'txt':
                nombre_completo = f"{nombre_archivo}.txt"
                exito = self.reportes.guardar_reporte_texto(datos_reporte, nombre_completo)
            else:
                # Para HTML, guardamos como texto
                nombre_completo = f"{nombre_archivo}.txt"
                datos_reporte['contenido_html'] = self._convertir_a_html(datos_reporte)
                exito = self.reportes.guardar_reporte_texto(datos_reporte, nombre_completo)
            
            if exito:
                ruta_completa = os.path.join(self.reportes.directorio_reportes, nombre_completo)
                tamaño = self._obtener_tamaño_archivo(ruta_completa)
                
                return {
                    'exito': True,
                    'nombre_archivo': nombre_completo,
                    'ruta': ruta_completa,
                    'tipo': tipo_reporte,
                    'formato': formato,
                    'tamaño': tamaño
                }
            else:
                return {'exito': False, 'error': 'Error guardando el reporte'}
                
        except Exception as e:
            self.logger.error(f"Error generando reporte: {e}")
            return {'exito': False, 'error': f'Error generando reporte: {str(e)}'}
    
    def listar_reportes(self, filtro: str = "todos") -> dict:
        """
        Listar reportes disponibles con filtros opcionales.
        
        Args:
            filtro: Filtro para reportes (todos, recientes, por_tipo)
            
        Returns:
            Dict con lista de reportes
        """
        try:
            reportes = self.reportes.listar_reportes()
            
            if not reportes:
                return {
                    'exito': True,
                    'reportes': [],
                    'total': 0,
                    'mensaje': 'No hay reportes disponibles'
                }
            
            # Aplicar filtros
            if filtro == "recientes":
                # Obtener reportes de los últimos 7 días
                from datetime import datetime, timedelta
                hace_semana = datetime.now() - timedelta(days=7)
                reportes_filtrados = []
                
                for r in reportes:
                    try:
                        fecha_mod = datetime.strptime(r.get('fecha_modificacion', ''), "%Y-%m-%d %H:%M:%S")
                        if fecha_mod > hace_semana:
                            reportes_filtrados.append(r)
                    except (ValueError, TypeError) as e:
                        # Si no se puede parsear la fecha, incluir el reporte
                        self.logger.debug(f"Error parseando fecha: {e}")
                        reportes_filtrados.append(r)
                        
            elif filtro.startswith("tipo_"):
                tipo_buscado = filtro.replace("tipo_", "")
                reportes_filtrados = [
                    r for r in reportes 
                    if r.get('tipo', '').lower() == tipo_buscado.lower()
                ]
            else:
                reportes_filtrados = reportes
            
            # Los reportes ya vienen ordenados por fecha del modelo
            
            return {
                'exito': True,
                'reportes': reportes_filtrados,
                'total': len(reportes_filtrados),
                'filtro_aplicado': filtro
            }
            
        except Exception as e:
            self.logger.error(f"Error listando reportes: {e}")
            return {'exito': False, 'error': f'Error listando reportes: {str(e)}'}
    
    def exportar_reporte(self, nombre_reporte: str, formato_destino: str) -> dict:
        """
        Exportar reporte existente a otro formato.
        
        Args:
            nombre_reporte: Nombre del reporte a exportar
            formato_destino: Formato de destino (json, txt, html)
            
        Returns:
            Dict con resultado de la exportación
        """
        try:
            # Validar formato
            if formato_destino not in ['json', 'txt', 'html']:
                return {'exito': False, 'error': 'Formato de destino no válido'}
            
            # Buscar el reporte en la lista
            reportes = self.reportes.listar_reportes()
            reporte_encontrado = None
            
            for reporte in reportes:
                if reporte['nombre_archivo'] == nombre_reporte:
                    reporte_encontrado = reporte
                    break
            
            if not reporte_encontrado:
                return {'exito': False, 'error': 'Reporte no encontrado'}
            
            # Leer contenido del reporte original
            ruta_original = reporte_encontrado['ruta_completa']
            
            try:
                if nombre_reporte.endswith('.json'):
                    with open(ruta_original, 'r', encoding='utf-8') as f:
                        contenido_original = json.load(f)
                else:
                    with open(ruta_original, 'r', encoding='utf-8') as f:
                        contenido_text = f.read()
                        # Crear estructura similar a JSON para procesamiento
                        contenido_original = {
                            'tipo': 'texto_importado',
                            'contenido': contenido_text,
                            'timestamp': self._obtener_timestamp()
                        }
            except Exception as e:
                return {'exito': False, 'error': f'Error leyendo reporte original: {str(e)}'}
            
            # Generar nuevo nombre
            timestamp = self._obtener_timestamp_archivo()
            base_name = nombre_reporte.split('.')[0]
            nombre_exportado = f"{base_name}_export_{timestamp}"
            
            # Exportar según formato
            if formato_destino == 'json':
                nombre_final = f"{nombre_exportado}.json"
                exito = self.reportes.guardar_reporte_json(contenido_original, nombre_final)
            elif formato_destino == 'txt':
                nombre_final = f"{nombre_exportado}.txt"
                exito = self.reportes.guardar_reporte_texto(contenido_original, nombre_final)
            else:  # html
                nombre_final = f"{nombre_exportado}.txt"
                contenido_original['contenido_html'] = self._convertir_a_html(contenido_original)
                exito = self.reportes.guardar_reporte_texto(contenido_original, nombre_final)
            
            if exito:
                ruta_exportada = os.path.join(self.reportes.directorio_reportes, nombre_final)
                return {
                    'exito': True,
                    'reporte_original': nombre_reporte,
                    'reporte_exportado': nombre_final,
                    'formato_destino': formato_destino,
                    'ruta': ruta_exportada
                }
            else:
                return {'exito': False, 'error': 'Error guardando reporte exportado'}
                
        except Exception as e:
            self.logger.error(f"Error exportando reporte: {e}")
            return {'exito': False, 'error': f'Error exportando reporte: {str(e)}'}
    
    def obtener_estadisticas(self) -> dict:
        """
        Obtener estadísticas generales de reportes.
        
        Returns:
            Dict con estadísticas completas
        """
        try:
            # Usar el método del modelo
            estadisticas_modelo = self.reportes.obtener_estadisticas_reportes()
            
            if estadisticas_modelo.get('error'):
                return {
                    'exito': False, 
                    'error': estadisticas_modelo['error']
                }
            
            reportes = self.reportes.listar_reportes()
            
            # Calcular estadísticas adicionales
            ultimo_reporte = None
            espacio_total = 0
            
            if reportes:
                # El primer reporte es el más reciente (ya ordenado)
                ultimo_reporte = reportes[0]['nombre_archivo']
                
                # Calcular espacio total
                for reporte in reportes:
                    espacio_total += reporte.get('tamaño_bytes', 0)
            
            return {
                'exito': True,
                'total_reportes': estadisticas_modelo['total_reportes'],
                'tipos_reportes': estadisticas_modelo['tipos_reportes'],
                'reportes_por_fecha': estadisticas_modelo['reportes_por_fecha'],
                'espacio_utilizado': self._formatear_tamaño(espacio_total),
                'ultimo_reporte': ultimo_reporte,
                'directorio_reportes': estadisticas_modelo['directorio_reportes']
            }
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            return {'exito': False, 'error': f'Error obteniendo estadísticas: {str(e)}'}
    
    def _generar_resumen_escaneo(self, datos: dict) -> str:
        """Generar resumen específico para reportes de escaneo."""
        if not datos:
            return "Reporte de escaneo sin datos específicos"
        
        puertos = datos.get('puertos', [])
        vulnerabilidades = datos.get('vulnerabilidades', [])
        objetivo = datos.get('objetivo', 'No especificado')
        
        return f"Escaneo de {objetivo}: {len(puertos)} puertos, {len(vulnerabilidades)} vulnerabilidades"
    
    def _generar_resumen_auditoria(self, datos: dict) -> str:
        """Generar resumen específico para reportes de auditoría."""
        if not datos:
            return "Reporte de auditoría sin datos específicos"
        
        problemas = datos.get('problemas_encontrados', [])
        puntuacion = datos.get('puntuacion_seguridad', 'No disponible')
        
        return f"Auditoría completada: {len(problemas)} problemas encontrados, puntuación: {puntuacion}"
    
    def _generar_resumen_monitoreo(self, datos: dict) -> str:
        """Generar resumen específico para reportes de monitoreo."""
        if not datos:
            return "Reporte de monitoreo sin datos específicos"
        
        procesos = datos.get('procesos_monitoreados', 0)
        alertas = datos.get('alertas_generadas', 0)
        
        return f"Monitoreo: {procesos} procesos monitoreados, {alertas} alertas generadas"
    
    def _generar_resumen_siem(self, datos: dict) -> str:
        """Generar resumen específico para reportes SIEM."""
        if not datos:
            return "Reporte SIEM sin datos específicos"
        
        eventos = datos.get('total_eventos', 0)
        correlaciones = datos.get('correlaciones', 0)
        
        return f"SIEM: {eventos} eventos analizados, {correlaciones} correlaciones detectadas"
    
    def _generar_resumen_fim(self, datos: dict) -> str:
        """Generar resumen específico para reportes FIM."""
        if not datos:
            return "Reporte FIM sin datos específicos"
        
        archivos = datos.get('archivos_monitoreados', 0)
        cambios = datos.get('cambios_detectados', 0)
        
        return f"FIM: {archivos} archivos monitoreados, {cambios} cambios detectados"
    
    def _obtener_timestamp(self) -> str:
        """Obtener timestamp en formato ISO."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _obtener_timestamp_archivo(self) -> str:
        """Obtener timestamp para nombres de archivo."""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _timestamp_a_fecha(self, timestamp: float) -> str:
        """Convertir timestamp a fecha legible."""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    
    def _convertir_a_html(self, datos: dict) -> str:
        """Convertir datos del reporte a formato HTML básico."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reporte ARESITOS</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2b2b2b; color: #ff6633; padding: 10px; }}
                .content {{ margin: 20px 0; }}
                .data {{ background-color: #f5f5f5; padding: 10px; border-left: 3px solid #ff6633; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>ARESITOS - Reporte de Seguridad</h1>
                <p>Tipo: {datos.get('tipo', 'General')}</p>
                <p>Fecha: {datos.get('timestamp', 'No disponible')}</p>
            </div>
            <div class="content">
                <h2>Resumen</h2>
                <p>{datos.get('resumen', 'Sin resumen disponible')}</p>
                <h2>Datos</h2>
                <div class="data">
                    <pre>{self._formatear_datos_html(datos.get('datos', {}))}</pre>
                </div>
            </div>
        </body>
        </html>
        """
        return html
    
    def _formatear_datos_html(self, datos: dict) -> str:
        """Formatear datos para mostrar en HTML."""
        try:
            import json
            return json.dumps(datos, indent=2, ensure_ascii=False)
        except (ValueError, TypeError, KeyError) as e:
            logging.debug(f'Error en excepción: {e}')
            return str(datos)
    
    def _crear_pdf_basico(self, datos: dict) -> str:
        """Crear PDF básico (simplificado, retorna contenido de texto)."""
        # Como no podemos usar librerías externas, retornamos formato de texto
        contenido = f"""
ARESITOS - Reporte de Seguridad
================================

Tipo: {datos.get('tipo', 'General')}
Fecha: {datos.get('timestamp', 'No disponible')}
Sistema: {datos.get('sistema', 'ARESITOS')}

RESUMEN:
{datos.get('resumen', 'Sin resumen disponible')}

DATOS DETALLADOS:
{self._formatear_datos_texto(datos.get('datos', {}))}

Generado por ARESITOS v3.0
"""
        return contenido
    
    def _formatear_datos_texto(self, datos: dict) -> str:
        """Formatear datos para mostrar en texto plano."""
        try:
            return json.dumps(datos, indent=2, ensure_ascii=False)
        except (ValueError, TypeError, KeyError) as e:
            logging.debug(f'Error en excepción: {e}')
            return str(datos)
    
    def _obtener_fecha_legible(self) -> str:
        """Obtener fecha en formato legible."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _obtener_tamaño_archivo(self, ruta: str) -> str:
        """Obtener tamaño de archivo en formato legible."""
        try:
            if os.path.exists(ruta):
                tamaño_bytes = os.path.getsize(ruta)
                return self._formatear_tamaño(tamaño_bytes)
            return "No disponible"
        except Exception as e:
            self.logger.error(f"Error obteniendo tamaño de archivo: {e}")
            return "Error"
    
    def _formatear_tamaño(self, bytes_size: int) -> str:
        """Formatear tamaño en bytes a formato legible."""
        try:
            if bytes_size == 0:
                return "0 B"
            
            unidades = ['B', 'KB', 'MB', 'GB', 'TB']
            i = 0
            tamaño = float(bytes_size)
            
            while tamaño >= 1024 and i < len(unidades) - 1:
                tamaño /= 1024
                i += 1
            
            return f"{tamaño:.1f} {unidades[i]}"
        except (ValueError, TypeError, OSError) as e:
            logging.debug(f'Error en excepción: {e}')
            return f"{bytes_size} B"

# RESUMEN TÉCNICO: Controlador de gestión de reportes de seguridad para Aresitos. 
# Coordina generación, almacenamiento y exportación de reportes en múltiples formatos 
# (JSON, TXT, HTML). Arquitectura MVC con responsabilidad única, sin dependencias 
# externas, optimizado para documentación profesional de análisis de ciberseguridad.

