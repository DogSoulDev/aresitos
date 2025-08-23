# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Controlador de Monitoreo Avanzado
Controlador especializado en monitoreo integral del sistema
Integra funcionalidad avanzada de detección de anomalías y procesos sospechosos
"""

import os
import time
import subprocess
from typing import Dict, Any, List, Optional
from aresitos.modelo.modelo_monitor import Monitor
from aresitos.modelo.modelo_siem import SIEMKali2025

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
            self.siem = SIEMKali2025()
            self.monitor.siem = self.siem
        else:
            self.siem = self.modelo_principal.siem
    

    def inicializar(self):
        """
        Inicializa el controlador (requerido por principios ARESITOS).
        
        Returns:
            bool: True si la inicialización es exitosa
        """
        try:
            self.logger.info("ControladorMonitoreo v3.0 inicializado correctamente")
            return True
        except Exception as e:
            self.logger.error(f"Error en inicializar(): {e}")
            return False
    def iniciar_monitoreo(self) -> Dict[str, Any]:
        """Iniciar monitoreo completo del sistema."""
        resultado = self.monitor.iniciar_monitoreo_completo()
        
        # Iniciar procesamiento SIEM si está disponible
        if hasattr(self.monitor, 'siem') and self.monitor.siem:
            try:
                self.monitor.siem.iniciar_procesamiento()
            except (ValueError, TypeError, AttributeError):
                pass
        
        return resultado
    
    def detener_monitoreo(self) -> Dict[str, Any]:
        """Detener monitoreo del sistema."""
        resultado = self.monitor.detener_monitoreo()
        
        # Detener procesamiento SIEM si está disponible
        if hasattr(self.monitor, 'siem') and self.monitor.siem:
            try:
                self.monitor.siem.detener_procesamiento()
            except (ValueError, TypeError, AttributeError):
                pass
        
        return resultado
    
    def obtener_estado_monitoreo(self) -> Dict[str, Any]:
        """Obtener estado actual del monitoreo."""
        estado_base = {
            "activo": self.monitor.monitoreando,
            "datos_recientes": self.monitor.obtener_datos_sistema_recientes(10)
        }
        
        # Agregar métricas avanzadas si están disponibles
        # Obtener métricas avanzadas si está disponible
        try:
            # Intentar diferentes formas de obtener métricas
            for metodo in ['obtener_metricas_resumen', 'obtener_estadisticas', 'get_stats']:
                if hasattr(self.monitor, metodo):
                    estado_base["metricas_avanzadas"] = getattr(self.monitor, metodo)()
                    break
            else:
                estado_base["metricas_avanzadas"] = {"disponible": False}
        except (ValueError, TypeError, AttributeError):
            estado_base["metricas_avanzadas"] = {"error": "No disponible"}
        
        return estado_base
    
    def obtener_metricas_sistema(self) -> List[Dict[str, Any]]:
        """Obtener métricas del sistema."""
        return self.monitor.obtener_datos_sistema_recientes(1)
    
    def monitorear_red(self) -> List[Dict[str, Any]]:
        """Obtener datos de monitoreo de red."""
        return self._obtener_datos_red_seguros(10)
    
    def _obtener_datos_red_seguros(self, limite: int = 1) -> List[Dict[str, Any]]:
        """Método auxiliar para obtener datos de red de forma segura."""
        try:
            # Intentar diferentes métodos disponibles
            for metodo in ['obtener_datos_red_recientes', 'obtener_datos_red', 'get_network_data']:
                if hasattr(self.monitor, metodo):
                    return getattr(self.monitor, metodo)(limite)
            
            # Fallback: datos básicos de red
            return [{
                'timestamp': time.time(),
                'conexiones': 0,
                'trafico': {'entrada': 0, 'salida': 0},
                'estado': 'monitoreo_basico'
            }]
        except (ValueError, TypeError, AttributeError):
            return []
    
    def obtener_procesos_activos(self) -> List[Dict[str, Any]]:
        """Obtener información de procesos activos."""
        datos = self.monitor.obtener_datos_sistema_recientes(1)
        
        # Agregar información de procesos sospechosos si está disponible
        if hasattr(self.monitor, 'obtener_procesos_sospechosos'):
            try:
                procesos_sospechosos = self.monitor.obtener_procesos_sospechosos()
                if datos:
                    datos[0]['procesos_sospechosos'] = procesos_sospechosos
            except (ValueError, TypeError, AttributeError):
                pass
        
        return datos
    
    def obtener_conexiones_red(self) -> List[Dict[str, Any]]:
        """Obtener información de conexiones de red."""
        return self._obtener_datos_red_seguros(1)
    
    def obtener_estadisticas_sistema(self) -> Dict[str, Any]:
        """Obtener estadísticas completas del sistema."""
        datos_sistema = self.monitor.obtener_datos_sistema_recientes(1)
        datos_red = self._obtener_datos_red_seguros(1)
        
        estadisticas = {
            'sistema': datos_sistema,
            'red': datos_red,
            'activo': self.monitor.monitoreando
        }
        
        # Agregar métricas avanzadas si están disponibles
        try:
            for metodo in ['obtener_metricas_resumen', 'obtener_estadisticas', 'get_stats']:
                if hasattr(self.monitor, metodo):
                    estadisticas['metricas_avanzadas'] = getattr(self.monitor, metodo)()
                    break
        except (ValueError, TypeError, AttributeError):
            estadisticas['metricas_avanzadas'] = {"error": "No disponible"}
        
        return estadisticas
    
    def obtener_procesos_sospechosos(self) -> List[Dict[str, Any]]:
        """Obtener lista de procesos sospechosos detectados."""
        if hasattr(self.monitor, 'obtener_procesos_sospechosos'):
            try:
                return self.monitor.obtener_procesos_sospechosos()
            except (ValueError, TypeError, AttributeError):
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
            except (ValueError, TypeError, AttributeError):
                pass
        
        return alertas
    
    def generar_reporte_monitoreo(self) -> str:
        """Generar reporte completo de monitoreo."""
        if hasattr(self.monitor, 'generar_reporte_monitor'):
            try:
                return self.monitor.generar_reporte_monitor()
            except (ValueError, TypeError, AttributeError):
                pass
        
        # Reporte básico si no hay funcionalidad avanzada
        datos_sistema = self.monitor.obtener_datos_sistema_recientes(1)
        datos_red = self._obtener_datos_red_seguros(1)
        
        reporte = "# REPORTE DE MONITOREO - ARESITOS\n\n"
        
        if datos_sistema:
            sistema = datos_sistema[0].get('sistema', {})
            reporte += f"## ESTADO DEL SISTEMA\n"
            reporte += f"- **CPU**: {sistema.get('cpu', 'N/A')}%\n"
            reporte += f"- **Memoria**: {sistema.get('memoria', 'N/A')}%\n"
            reporte += f"- **Disco**: {sistema.get('disco', 'N/A')}%\n\n"
        
        if datos_red:
            red = datos_red[0]
            reporte += f"## ESTADO DE RED\n"
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
            except (ValueError, TypeError, AttributeError):
                pass
        
        return {
            'exito': False,
            'mensaje': 'No se pudieron actualizar los umbrales'
        }
    
    def listar_archivos_cuarentena(self) -> List[Dict[str, Any]]:
        """
        Listar archivos en cuarentena.
        
        Returns:
            Lista de archivos en cuarentena con sus metadatos
        """
        try:
            # Directorio de cuarentena por defecto
            directorio_cuarentena = os.path.join(os.path.expanduser("~"), ".aresitos", "cuarentena")
            
            if not os.path.exists(directorio_cuarentena):
                return []
            
            archivos_cuarentena = []
            
            for archivo in os.listdir(directorio_cuarentena):
                ruta_archivo = os.path.join(directorio_cuarentena, archivo)
                if os.path.isfile(ruta_archivo):
                    stat_info = os.stat(ruta_archivo)
                    
                    archivos_cuarentena.append({
                        'nombre': archivo,
                        'ruta': ruta_archivo,
                        'tamaño': stat_info.st_size,
                        'fecha_cuarentena': stat_info.st_mtime,
                        'hash_sha256': self._calcular_hash_archivo(ruta_archivo),
                        'razon_cuarentena': 'Archivo sospechoso detectado'
                    })
            
            return archivos_cuarentena
            
        except Exception as e:
            return []
    
    def limpiar_cuarentena_completa(self) -> Dict[str, Any]:
        """
        Limpiar completamente la cuarentena de archivos.
        
        Returns:
            Dict con resultado de la operación
        """
        try:
            directorio_cuarentena = "/var/quarantine"
            
            if not os.path.exists(directorio_cuarentena):
                return {
                    'exito': True,
                    'mensaje': 'Directorio de cuarentena no existe',
                    'archivos_eliminados': 0
                }
            
            # Contar archivos antes de eliminar
            archivos_eliminados = 0
            errores = []
            
            # Eliminar todos los archivos en cuarentena
            for archivo in os.listdir(directorio_cuarentena):
                ruta_archivo = os.path.join(directorio_cuarentena, archivo)
                try:
                    if os.path.isfile(ruta_archivo):
                        os.remove(ruta_archivo)
                        archivos_eliminados += 1
                    elif os.path.isdir(ruta_archivo):
                        import shutil
                        shutil.rmtree(ruta_archivo)
                        archivos_eliminados += 1
                except Exception as e:
                    errores.append(f"Error eliminando {archivo}: {str(e)}")
            
            # Registrar evento en SIEM si está disponible
            try:
                if hasattr(self, 'monitor') and hasattr(self.monitor, 'siem') and self.monitor.siem:
                    self.monitor.siem.registrar_evento({
                        'tipo': 'CUARENTENA',
                        'severidad': 'INFO',
                        'mensaje': f'Cuarentena limpiada: {archivos_eliminados} archivos eliminados',
                        'origen': 'ControladorMonitoreo',
                        'detalles': {
                            'archivos_eliminados': archivos_eliminados,
                            'errores': len(errores)
                        }
                    })
            except Exception as e:
                # Registro fallido del evento, pero no debe afectar la operación principal
                pass
            
            return {
                'exito': True,
                'mensaje': f'Cuarentena limpiada exitosamente',
                'archivos_eliminados': archivos_eliminados,
                'errores': errores if errores else None
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error limpiando cuarentena: {str(e)}',
                'archivos_eliminados': 0
            }
    
    def _calcular_hash_archivo(self, ruta_archivo: str) -> str:
        """Calcular hash SHA256 de un archivo."""
        try:
            import hashlib
            with open(ruta_archivo, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (IOError, OSError, PermissionError, FileNotFoundError):
            return "hash_no_disponible"

# RESUMEN TÉCNICO: Controlador de monitoreo avanzado que integra detección de anomalías,
# análisis de procesos sospechosos y correlación de eventos de seguridad. Mantiene
# compatibilidad con la interfaz gráfica original mientras proporciona capacidades
# avanzadas del proyecto original. Arquitectura MVC con integración SIEM para
# análisis profesional de seguridad en entornos Kali Linux.
