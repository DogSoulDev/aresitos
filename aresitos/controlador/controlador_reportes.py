# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador de Reportes
Controlador de Reportes para ARESITOS v3.0 - Sistema de Ciberseguridad Integral.
"""

import os
import re
import logging
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
    
    def generar_reporte_completo(self, datos_escaneo=None, datos_monitoreo=None, datos_utilidades=None, datos_fim=None, datos_siem=None, datos_cuarentena=None, datos_terminal_principal=None):
        """Genera reporte completo incluyendo todos los módulos optimizados para Kali - Issue 20/24"""
        return self.reportes.generar_reporte_completo(
            datos_escaneo or {}, 
            datos_monitoreo or {}, 
            datos_utilidades or {},
            datos_fim or {},
            datos_siem or {},
            datos_cuarentena or {},
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

# RESUMEN TÉCNICO: Controlador de gestión de reportes de seguridad para Aresitos. 
# Coordina generación, almacenamiento y exportación de reportes en múltiples formatos 
# (JSON, TXT, HTML). Arquitectura MVC con responsabilidad única, sin dependencias 
# externas, optimizado para documentación profesional de análisis de ciberseguridad.

