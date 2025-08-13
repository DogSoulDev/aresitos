# -*- coding: utf-8 -*-

import os
import json
import datetime
from typing import Dict, List, Any, Optional

class ModeloReportes:
    
    def __init__(self):
        self.directorio_reportes = self._crear_directorio_reportes()
    
    def _crear_directorio_reportes(self) -> str:
        directorio = os.path.join(os.path.expanduser("~"), "ares_reportes")
        if not os.path.exists(directorio):
            os.makedirs(directorio)
        return directorio
    
    def generar_reporte_completo(self, datos_escaneo: Dict, datos_monitoreo: Dict, datos_utilidades: Dict) -> Dict[str, Any]:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        reporte = {
            "timestamp": timestamp,
            "fecha_generacion": datetime.datetime.now().isoformat(),
            "resumen": {
                "total_herramientas": len(datos_utilidades.get('herramientas', [])),
                "servicios_activos": len(datos_utilidades.get('servicios', [])),
                "problemas_permisos": len(datos_utilidades.get('permisos_archivos', [])),
                "alertas_escaneo": len(datos_escaneo.get('alertas', [])),
                "eventos_monitoreo": len(datos_monitoreo.get('eventos', []))
            },
            "datos": {
                "escaneo": datos_escaneo,
                "monitoreo": datos_monitoreo,
                "utilidades": datos_utilidades
            }
        }
        
        return reporte
    
    def generar_reporte_texto(self, reporte: Dict) -> str:
        texto = f"""
REPORTE DE SEGURIDAD ARES AEGIS
===============================
Fecha: {reporte.get('fecha_generacion', 'No disponible')}

RESUMEN EJECUTIVO
-----------------
Herramientas verificadas: {reporte['resumen']['total_herramientas']}
Servicios activos: {reporte['resumen']['servicios_activos']}
Problemas de permisos: {reporte['resumen']['problemas_permisos']}
Alertas de escaneo: {reporte['resumen']['alertas_escaneo']}
Eventos de monitoreo: {reporte['resumen']['eventos_monitoreo']}

DETALLES
--------
"""
        
        if reporte['datos']['utilidades'].get('herramientas'):
            texto += "\nHerramientas del Sistema:\n"
            for herramienta in reporte['datos']['utilidades']['herramientas']:
                texto += f"- {herramienta}\n"
        
        if reporte['datos']['utilidades'].get('servicios'):
            texto += "\nServicios Activos:\n"
            for servicio in reporte['datos']['utilidades']['servicios']:
                texto += f"- {servicio}\n"
        
        return texto
    
    def guardar_reporte_json(self, reporte: Dict, nombre_archivo: Optional[str] = None) -> bool:
        try:
            if not nombre_archivo:
                nombre_archivo = f"reporte_{reporte.get('timestamp', 'sin_fecha')}.json"
            
            ruta_archivo = os.path.join(self.directorio_reportes, nombre_archivo)
            
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                json.dump(reporte, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception:
            return False
    
    def guardar_reporte_texto(self, reporte: Dict, nombre_archivo: Optional[str] = None) -> bool:
        try:
            if not nombre_archivo:
                nombre_archivo = f"reporte_{reporte.get('timestamp', 'sin_fecha')}.txt"
            
            ruta_archivo = os.path.join(self.directorio_reportes, nombre_archivo)
            texto_reporte = self.generar_reporte_texto(reporte)
            
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                f.write(texto_reporte)
            
            return True
        except Exception:
            return False
    
    def listar_reportes(self) -> List[Dict[str, Any]]:
        reportes = []
        
        try:
            for archivo in os.listdir(self.directorio_reportes):
                if archivo.endswith(('.json', '.txt')):
                    ruta_completa = os.path.join(self.directorio_reportes, archivo)
                    stat_info = os.stat(ruta_completa)
                    
                    reportes.append({
                        'nombre': archivo,
                        'ruta': ruta_completa,
                        'tamaño': stat_info.st_size,
                        'modificado': datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
        except Exception:
            pass
        
        return sorted(reportes, key=lambda x: x['modificado'], reverse=True)
