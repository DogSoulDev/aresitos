# -*- coding: utf-8 -*-
"""
Aresitos V3 - Controlador Dashboard Optimizado
===============================================

Controlador optimizado para gestionar la vista del panel principal siguiendo
los principios ARESITOS V3: Python nativo + herramientas Kali Linux.

Autor: ARESITOS Security Team
Versión: 3.0
Fecha: 2025-08-23
"""

import logging
import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
from aresitos.controlador.controlador_base import ControladorBase


class ControladorDashboard(ControladorBase):
    """
    Controlador optimizado para el dashboard principal del sistema ARESITOS V3.
    Gestiona métricas del sistema, estado de componentes y navegación principal.
    """
    
    def __init__(self, modelo_principal: Any):
        """
        Inicializar controlador del dashboard optimizado.
        
        Args:
            modelo_principal: Instancia del modelo principal del sistema
        """
        super().__init__(modelo_principal, "Dashboard")
        
        # Estado del dashboard
        self.metricas_activas = {}
        self.widgets_activos = []
        self.actualizaciones_pendientes = []
        self.cache_metricas = {}
        self.cache_timeout = 5  # 5 segundos de cache
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Auto-actualización
        self.actualizacion_automatica = True
        self.intervalo_actualizacion = 3  # 3 segundos
        self.thread_actualizacion = None
        
        # Métricas del sistema Kali
        self.modelo_dashboard = None
        if hasattr(modelo_principal, 'dashboard') and modelo_principal.dashboard:
            self.modelo_dashboard = modelo_principal.dashboard
    
    

    def inicializar(self):
        """
        Inicializa ControladorDashboard según principios ARESITOS v3.0.
        """
        try:
            self.logger.info("Inicializando ControladorDashboard v3.0")
            return True
        except Exception as e:
            self.logger.error(f"Error en ControladorDashboard: {e}")
            return False
    def _inicializar_widgets_v3(self) -> None:
        """
        Inicializar widgets optimizados del dashboard ARESITOS V3.
        """
        widgets_v3 = [
            {
                'nombre': 'estado_sistema_kali',
                'tipo': 'metricas_sistema',
                'activo': True,
                'fuente': 'comandos_nativos',
                'refresh_rate': 3
            },
            {
                'nombre': 'seguridad_red',
                'tipo': 'seguridad',
                'activo': True,
                'fuente': 'herramientas_kali',
                'refresh_rate': 5
            },
            {
                'nombre': 'monitoreo_procesos',
                'tipo': 'monitoreo',
                'activo': True,
                'fuente': 'comandos_sistema',
                'refresh_rate': 2
            },
            {
                'nombre': 'alertas_siem',
                'tipo': 'alertas',
                'activo': True,
                'fuente': 'siem_interno',
                'refresh_rate': 1
            },
            {
                'nombre': 'resumen_escaneos',
                'tipo': 'escaneos',
                'activo': True,
                'fuente': 'escaneador_interno',
                'refresh_rate': 10
            },
            {
                'nombre': 'estado_fim',
                'tipo': 'integridad',
                'activo': True,
                'fuente': 'fim_interno',
                'refresh_rate': 5
            }
        ]
        
        with self._lock:
            self.widgets_activos = widgets_v3
            
        self.logger.info(f"[OK] {len(widgets_v3)} widgets ARESITOS V3 inicializados")
    
    def _configurar_metricas_sistema(self) -> None:
        """
        Configurar métricas del sistema usando herramientas nativas de Kali.
        """
        metricas_v3 = {
            # Métricas del sistema base
            'sistema': {
                'cpu_porcentaje': 0.0,
                'memoria_porcentaje': 0.0,
                'disco_porcentaje': 0.0,
                'uptime_horas': 0.0,
                'carga_promedio': [0.0, 0.0, 0.0]
            },
            
            # Métricas de red y seguridad
            'red': {
                'conexiones_activas': 0,
                'conexiones_establecidas': 0,
                'puertos_escucha': 0,
                'trafico_bytes': 0,
                'ip_publica': 'No disponible'
            },
            
            # Métricas de seguridad
            'seguridad': {
                'procesos_sospechosos': 0,
                'alertas_activas': 0,
                'escaneos_completados': 0,
                'amenazas_detectadas': 0,
                'fim_archivos_monitoreados': 0
            },
            
            # Métricas de componentes ARESITOS
            'componentes': {
                'monitor_activo': False,
                'siem_activo': False,
                'fim_activo': False,
                'escaneador_activo': False,
                'cuarentena_activa': False
            }
        }
        
        with self._lock:
            self.metricas_activas = metricas_v3
        
        self.logger.info("[OK] Métricas del sistema ARESITOS V3 configuradas")
    
    def _iniciar_actualizacion_automatica(self) -> None:
        """
        Iniciar thread de actualización automática de métricas.
        """
        if self.actualizacion_automatica and not self.thread_actualizacion:
            self.thread_actualizacion = threading.Thread(
                target=self._loop_actualizacion,
                daemon=True
            )
            self.thread_actualizacion.start()
            self.logger.info("🔄 Auto-actualización del dashboard iniciada")
    
    def _loop_actualizacion(self) -> None:
        """
        Loop principal de actualización automática de métricas.
        """
        while self.actualizacion_automatica:
            try:
                # Actualizar métricas usando el modelo dashboard
                if self.modelo_dashboard:
                    self._actualizar_metricas_desde_modelo()
                else:
                    self._actualizar_metricas_directas()
                
                time.sleep(self.intervalo_actualizacion)
                
            except Exception as e:
                self.logger.error(f"Error en loop de actualización: {e}")
                time.sleep(self.intervalo_actualizacion * 2)  # Esperar más en caso de error
    
    def _actualizar_metricas_desde_modelo(self) -> None:
        """
        Actualizar métricas usando el modelo dashboard optimizado.
        """
        try:
            if not self.modelo_dashboard:
                return
                
            # Obtener métricas del sistema
            metricas_sistema = self.modelo_dashboard.obtener_metricas_sistema()
            if metricas_sistema and 'error' not in metricas_sistema:
                with self._lock:
                    if 'cpu' in metricas_sistema:
                        self.metricas_activas['sistema']['cpu_porcentaje'] = metricas_sistema['cpu'].get('uso_porcentaje', 0.0)
                        self.metricas_activas['sistema']['carga_promedio'] = metricas_sistema['cpu'].get('carga_promedio', [0.0, 0.0, 0.0])
                    
                    if 'memoria' in metricas_sistema:
                        self.metricas_activas['sistema']['memoria_porcentaje'] = metricas_sistema['memoria'].get('porcentaje_uso', 0.0)
                    
                    if 'disco' in metricas_sistema:
                        self.metricas_activas['sistema']['disco_porcentaje'] = metricas_sistema['disco'].get('porcentaje_uso', 0.0)
                    
                    if 'uptime' in metricas_sistema:
                        self.metricas_activas['sistema']['uptime_horas'] = metricas_sistema['uptime'].get('horas', 0.0)
            
            # Obtener información de red
            info_red = self.modelo_dashboard.obtener_informacion_red()
            if info_red and 'error' not in info_red:
                with self._lock:
                    self.metricas_activas['red']['conexiones_activas'] = info_red.get('conexiones', {}).get('total', 0)
                    self.metricas_activas['red']['conexiones_establecidas'] = info_red.get('conexiones', {}).get('establecidas', 0)
                    self.metricas_activas['red']['ip_publica'] = info_red.get('ip_publica', 'No disponible')
            
            # Actualizar estado de componentes
            self._actualizar_estado_componentes()
            
        except Exception as e:
            self.logger.warning(f"Error actualizando métricas desde modelo: {e}")
    
    def _actualizar_metricas_directas(self) -> None:
        """
        Actualizar métricas usando comandos directos cuando no hay modelo.
        """
        try:
            # Placeholder para actualización directa
            with self._lock:
                self.metricas_activas['sistema']['cpu_porcentaje'] = 0.0
                self.metricas_activas['sistema']['memoria_porcentaje'] = 0.0
                self.metricas_activas['sistema']['disco_porcentaje'] = 0.0
        except Exception as e:
            self.logger.warning(f"Error en actualización directa: {e}")
    
    def _actualizar_estado_componentes(self) -> None:
        """
        Actualizar estado de componentes ARESITOS.
        """
        try:
            with self._lock:
                # Verificar estado del monitor
                if hasattr(self.modelo_principal, 'monitor_avanzado') and self.modelo_principal.monitor_avanzado:
                    self.metricas_activas['componentes']['monitor_activo'] = getattr(
                        self.modelo_principal.monitor_avanzado, 'monitoreando', False
                    )
                
                # Verificar estado del SIEM
                if hasattr(self.modelo_principal, 'siem_avanzado') and self.modelo_principal.siem_avanzado:
                    self.metricas_activas['componentes']['siem_activo'] = True
                
                # Verificar estado del FIM
                if hasattr(self.modelo_principal, 'fim_avanzado') and self.modelo_principal.fim_avanzado:
                    self.metricas_activas['componentes']['fim_activo'] = True
                
                # Verificar estado del escaneador
                if hasattr(self.modelo_principal, 'escaneador_avanzado') and self.modelo_principal.escaneador_avanzado:
                    self.metricas_activas['componentes']['escaneador_activo'] = True
                
                # Verificar estado de cuarentena
                if hasattr(self.modelo_principal, 'cuarentena') and self.modelo_principal.cuarentena:
                    self.metricas_activas['componentes']['cuarentena_activa'] = True
                    
        except Exception as e:
            self.logger.warning(f"Error actualizando estado de componentes: {e}")
    
    def _registrar_con_modelo_principal(self) -> None:
        """
        Registrar dashboard con el modelo principal para recibir notificaciones.
        """
        try:
            if hasattr(self.modelo_principal, '_estado_sistema'):
                # Dashboard registrado exitosamente
                self.logger.info("[OK] Dashboard registrado con modelo principal")
        except Exception as e:
            self.logger.warning(f"No se pudo registrar con modelo principal: {e}")
    
    def obtener_estado_sistema(self) -> Dict[str, Any]:
        """
        Obtener estado actual completo del sistema ARESITOS V3.
        
        Returns:
            Dict con estado completo del sistema
        """
        try:
            with self._lock:
                estado = {
                    'timestamp': datetime.now().isoformat(),
                    'sistema_activo': True,
                    'dashboard_version': '3.0',
                    'metricas': self.metricas_activas.copy(),
                    'widgets': self.widgets_activos.copy(),
                    'actualizacion_automatica': self.actualizacion_automatica,
                    'ultima_actualizacion': datetime.now().isoformat()
                }
            
            # Obtener estadísticas del modelo principal
            if hasattr(self.modelo_principal, 'obtener_estadisticas_generales'):
                try:
                    estadisticas = self.modelo_principal.obtener_estadisticas_generales()
                    estado['estadisticas_generales'] = estadisticas
                except Exception as e:
                    self.logger.warning(f"Error obteniendo estadísticas generales: {e}")
            
            return estado
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estado del sistema: {e}")
            return {
                'sistema_activo': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def obtener_metricas_tiempo_real(self) -> Dict[str, Any]:
        """
        Obtener métricas en tiempo real del sistema.
        
        Returns:
            Dict con métricas actualizadas
        """
        try:
            # Verificar cache
            cache_key = 'metricas_tiempo_real'
            cached_time = self.cache_metricas.get(f"{cache_key}_time", 0)
            
            if time.time() - cached_time < self.cache_timeout:
                return self.cache_metricas.get(cache_key, {})
            
            # Obtener métricas frescas
            with self._lock:
                metricas = {
                    'timestamp': datetime.now().isoformat(),
                    'sistema': self.metricas_activas['sistema'].copy(),
                    'red': self.metricas_activas['red'].copy(),
                    'seguridad': self.metricas_activas['seguridad'].copy(),
                    'componentes': self.metricas_activas['componentes'].copy()
                }
            
            # Guardar en cache
            self.cache_metricas[cache_key] = metricas
            self.cache_metricas[f"{cache_key}_time"] = time.time()
            
            return metricas
            
        except Exception as e:
            self.logger.error(f"Error obteniendo métricas tiempo real: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def actualizar_widget(self, nombre_widget: str, datos: Dict[str, Any]) -> Dict[str, Any]:
        """
        Actualizar datos de un widget específico.
        
        Args:
            nombre_widget: Nombre del widget a actualizar
            datos: Nuevos datos para el widget
            
        Returns:
            Dict con resultado de la actualización
        """
        try:
            with self._lock:
                widget_encontrado = None
                for widget in self.widgets_activos:
                    if widget['nombre'] == nombre_widget:
                        widget_encontrado = widget
                        break
                
                if widget_encontrado:
                    widget_encontrado.update(datos)
                    widget_encontrado['ultima_actualizacion'] = datetime.now().isoformat()
                    
                    # Agregar a actualizaciones pendientes
                    self.actualizaciones_pendientes.append({
                        'tipo': 'widget_actualizado',
                        'widget': nombre_widget,
                        'datos': datos,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    return {
                        'exito': True,
                        'mensaje': f'Widget {nombre_widget} actualizado correctamente'
                    }
                else:
                    return {
                        'exito': False,
                        'error': f'Widget {nombre_widget} no encontrado'
                    }
                    
        except Exception as e:
            self.logger.error(f"Error actualizando widget {nombre_widget}: {e}")
            return {
                'exito': False,
                'error': str(e)
            }
    
    def detener_dashboard(self) -> Dict[str, Any]:
        """
        Detener dashboard y limpiar recursos.
        
        Returns:
            Dict con resultado de la operación
        """
        try:
            self.logger.info("🛑 Deteniendo Dashboard ARESITOS V3...")
            
            # Detener actualización automática
            self.actualizacion_automatica = False
            
            if self.thread_actualizacion and self.thread_actualizacion.is_alive():
                self.thread_actualizacion.join(timeout=3)
            
            # Limpiar caches
            with self._lock:
                self.cache_metricas.clear()
                self.actualizaciones_pendientes.clear()
            
            self.logger.info("[OK] Dashboard detenido correctamente")
            
            return {
                'exito': True,
                'mensaje': 'Dashboard detenido correctamente',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"[FAIL] Error deteniendo dashboard: {e}")
            return {
                'exito': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
