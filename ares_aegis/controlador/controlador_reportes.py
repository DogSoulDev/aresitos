# -*- coding: utf-8 -*-

from ares_aegis.modelo.modelo_reportes import ModeloReportes

class ControladorReportes:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.reportes = ModeloReportes()
    
    def generar_reporte_completo(self, datos_escaneo=None, datos_monitoreo=None, datos_utilidades=None):
        return self.reportes.generar_reporte_completo(
            datos_escaneo or {}, 
            datos_monitoreo or {}, 
            datos_utilidades or {}
        )
    
    def guardar_reporte_json(self, reporte, nombre_archivo=None):
        return self.reportes.guardar_reporte_json(reporte, nombre_archivo)
    
    def guardar_reporte_texto(self, reporte, nombre_archivo=None):
        return self.reportes.guardar_reporte_texto(reporte, nombre_archivo)
    
    def listar_reportes_guardados(self):
        return self.reportes.listar_reportes()
    
    def exportar_reporte_personalizado(self, datos, formato='json', nombre_archivo=None):
        import datetime
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
        try:
            import os
            directorio = self.reportes.directorio_reportes
            total_size = 0
            
            for archivo in os.listdir(directorio):
                ruta_completa = os.path.join(directorio, archivo)
                if os.path.isfile(ruta_completa):
                    total_size += os.path.getsize(ruta_completa)
            
            return f"{total_size / 1024:.2f} KB"
        except:
            return "No disponible"

# RESUMEN TÉCNICO: Controlador de gestión de reportes de seguridad para Aresitos. 
# Coordina generación, almacenamiento y exportación de reportes en múltiples formatos 
# (JSON, TXT, HTML). Arquitectura MVC con responsabilidad única, sin dependencias 
# externas, optimizado para documentación profesional de análisis de ciberseguridad.
