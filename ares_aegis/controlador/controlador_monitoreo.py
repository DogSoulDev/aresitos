# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Monitoreo Avanzado
Controlador especializado en monitoreo integral del sistema
Integra funcionalidad avanzada de detección de anomalías y procesos sospechosos
"""

import os
import subprocess
from typing import Dict, Any, List, Optional
from ares_aegis.modelo.modelo_monitor import MonitorAvanzado, Monitor
from ares_aegis.modelo.modelo_siem import SIEM

class ControladorMonitoreo:
    """
    Controlador de monitoreo que integra capacidades avanzadas de análisis
    mientras mantiene compatibilidad con la interfaz gráfica actual.
    """
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        
        # Usar Monitor de compatibilidad que incluye funcionalidad avanzada
        self.monitor = Monitor()
        
        # Crear SIEM si no existe para integración
        if not hasattr(self.modelo_principal, 'siem'):
            self.siem = SIEM()
            self.monitor.siem = self.siem
        else:
            self.siem = self.modelo_principal.siem
    
    def iniciar_monitoreo(self) -> Dict[str, Any]:
        """Iniciar monitoreo completo del sistema."""
        resultado = self.monitor.iniciar_monitoreo_completo()
        
        # Iniciar procesamiento SIEM si está disponible
        if hasattr(self.monitor, 'siem') and self.monitor.siem:
            try:
                self.monitor.siem.iniciar_procesamiento()
            except:
                pass
        
        return resultado
    
    def detener_monitoreo(self) -> Dict[str, Any]:
        """Detener monitoreo del sistema."""
        resultado = self.monitor.detener_monitoreo()
        
        # Detener procesamiento SIEM si está disponible
        if hasattr(self.monitor, 'siem') and self.monitor.siem:
            try:
                self.monitor.siem.detener_procesamiento()
            except:
                pass
        
        return resultado
    
    def obtener_estado_monitoreo(self) -> Dict[str, Any]:
        """Obtener estado actual del monitoreo."""
        estado_base = {
            "activo": self.monitor.monitoreando,
            "datos_recientes": self.monitor.obtener_datos_sistema_recientes(10)
        }
        
        # Agregar métricas avanzadas si están disponibles
        if hasattr(self.monitor, 'obtener_metricas_resumen'):
            try:
                estado_base["metricas_avanzadas"] = self.monitor.obtener_metricas_resumen()
            except:
                pass
        
        return estado_base
    
    def obtener_metricas_sistema(self) -> List[Dict[str, Any]]:
        """Obtener métricas del sistema."""
        return self.monitor.obtener_datos_sistema_recientes(1)
    
    def monitorear_red(self) -> List[Dict[str, Any]]:
        """Obtener datos de monitoreo de red."""
        return self.monitor.obtener_datos_red_recientes(10)
    
    def obtener_procesos_activos(self) -> List[Dict[str, Any]]:
        """Obtener información de procesos activos."""
        datos = self.monitor.obtener_datos_sistema_recientes(1)
        
        # Agregar información de procesos sospechosos si está disponible
        if hasattr(self.monitor, 'obtener_procesos_sospechosos'):
            try:
                procesos_sospechosos = self.monitor.obtener_procesos_sospechosos()
                if datos:
                    datos[0]['procesos_sospechosos'] = procesos_sospechosos
            except:
                pass
        
        return datos
    
    def obtener_conexiones_red(self) -> List[Dict[str, Any]]:
        """Obtener información de conexiones de red."""
        return self.monitor.obtener_datos_red_recientes(1)
    
    def obtener_estadisticas_sistema(self) -> Dict[str, Any]:
        """Obtener estadísticas completas del sistema."""
        datos_sistema = self.monitor.obtener_datos_sistema_recientes(1)
        datos_red = self.monitor.obtener_datos_red_recientes(1)
        
        estadisticas = {
            'sistema': datos_sistema,
            'red': datos_red,
            'activo': self.monitor.monitoreando
        }
        
        # Agregar métricas avanzadas si están disponibles
        if hasattr(self.monitor, 'obtener_metricas_resumen'):
            try:
                estadisticas['metricas_avanzadas'] = self.monitor.obtener_metricas_resumen()
            except:
                pass
        
        return estadisticas
    
    def obtener_procesos_sospechosos(self) -> List[Dict[str, Any]]:
        """Obtener lista de procesos sospechosos detectados."""
        if hasattr(self.monitor, 'obtener_procesos_sospechosos'):
            try:
                return self.monitor.obtener_procesos_sospechosos()
            except:
                pass
        return []
    
    def obtener_alertas_sistema(self) -> List[Dict[str, Any]]:
        """Obtener alertas del sistema si están disponibles."""
        alertas = []
        
        if hasattr(self.monitor, 'siem') and self.monitor.siem:
            try:
                alertas_siem = self.monitor.siem.obtener_alertas_activas()
                for alerta in alertas_siem:
                    alertas.append({
                        'id': alerta.id,
                        'titulo': alerta.titulo,
                        'descripcion': alerta.descripcion,
                        'severidad': alerta.severidad.value,
                        'timestamp': alerta.timestamp.isoformat(),
                        'estado': alerta.estado
                    })
            except:
                pass
        
        return alertas
    
    def generar_reporte_monitoreo(self) -> str:
        """Generar reporte completo de monitoreo."""
        if hasattr(self.monitor, 'generar_reporte_monitor'):
            try:
                return self.monitor.generar_reporte_monitor()
            except:
                pass
        
        # Reporte básico si no hay funcionalidad avanzada
        datos_sistema = self.monitor.obtener_datos_sistema_recientes(1)
        datos_red = self.monitor.obtener_datos_red_recientes(1)
        
        reporte = "#  REPORTE DE MONITOREO - ARES AEGIS\n\n"
        
        if datos_sistema:
            sistema = datos_sistema[0].get('sistema', {})
            reporte += f"##  ESTADO DEL SISTEMA\n"
            reporte += f"- **CPU**: {sistema.get('cpu', 'N/A')}%\n"
            reporte += f"- **Memoria**: {sistema.get('memoria', 'N/A')}%\n"
            reporte += f"- **Disco**: {sistema.get('disco', 'N/A')}%\n\n"
        
        if datos_red:
            red = datos_red[0]
            reporte += f"##  ESTADO DE RED\n"
            reporte += f"- **Conexiones**: {red.get('conexiones_activas', 'N/A')}\n"
            reporte += f"- **Tráfico**: {red.get('trafico_total', {}).get('bytes_recibidos', 'N/A')} bytes\n\n"
        
        return reporte
    
    def configurar_umbrales_alertas(self, umbrales: Dict[str, float]) -> Dict[str, Any]:
        """Configurar umbrales de alerta para el monitoreo."""
        if hasattr(self.monitor, 'umbrales'):
            try:
                self.monitor.umbrales.update(umbrales)
                return {
                    'exito': True,
                    'mensaje': 'Umbrales actualizados correctamente',
                    'umbrales': self.monitor.umbrales
                }
            except:
                pass
        
        return {
            'exito': False,
            'mensaje': 'No se pudieron actualizar los umbrales'
        }

# RESUMEN TÉCNICO: Controlador de monitoreo avanzado que integra detección de anomalías,
# análisis de procesos sospechosos y correlación de eventos de seguridad. Mantiene
# compatibilidad con la interfaz gráfica original mientras proporciona capacidades
# avanzadas del proyecto original. Arquitectura MVC con integración SIEM para
# análisis profesional de seguridad en entornos Kali Linux.