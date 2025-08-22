# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Dashboard
Controlador para gestionar la vista del panel principal de control
"""

import logging
from typing import Dict, Any, Optional, List
from Aresitos.controlador.controlador_base import ControladorBase


class ControladorDashboard(ControladorBase):
    """
    Controlador para el dashboard principal del sistema.
    Gestiona métricas, estado del sistema y navegación principal.
    """
    
    def __init__(self, modelo_principal: Any):
        """
        Inicializar controlador del dashboard.
        
        Args:
            modelo_principal: Instancia del modelo principal del sistema
        """
        super().__init__(modelo_principal, "Dashboard")
        self.metricas_activas = {}
        self.widgets_activos = []
        self.actualizaciones_pendientes = []
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """
        Implementación específica de inicialización del dashboard.
        
        Returns:
            Dict con resultado de la inicialización
        """
        try:
            # Inicializar widgets del dashboard
            await self._inicializar_widgets()
            
            # Configurar métricas básicas
            await self._configurar_metricas_basicas()
            
            # Registrar listeners para actualizaciones
            await self._registrar_listeners()
            
            return {
                'exito': True,
                'mensaje': 'Dashboard inicializado correctamente',
                'widgets_cargados': len(self.widgets_activos),
                'metricas_configuradas': len(self.metricas_activas)
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error en inicialización del dashboard: {str(e)}'
            }
    
    async def _inicializar_widgets(self) -> None:
        """
        Inicializar widgets básicos del dashboard.
        """
        widgets_basicos = [
            'estado_sistema',
            'metricas_seguridad',
            'alertas_recientes',
            'resumen_escaneos',
            'estado_servicios'
        ]
        
        for widget in widgets_basicos:
            self.widgets_activos.append({
                'nombre': widget,
                'activo': True,
                'ultima_actualizacion': None
            })
    
    async def _configurar_metricas_basicas(self) -> None:
        """
        Configurar métricas básicas del sistema.
        """
        metricas_sistema = {
            'cpu_uso': 0.0,
            'memoria_uso': 0.0,
            'disco_uso': 0.0,
            'conexiones_red': 0,
            'procesos_monitoreados': 0,
            'alertas_activas': 0,
            'escaneos_completados': 0,
            'amenazas_detectadas': 0
        }
        
        self.metricas_activas.update(metricas_sistema)
    
    async def _registrar_listeners(self) -> None:
        """
        Registrar listeners para actualizaciones automáticas.
        """
        # Registrar con el modelo principal para recibir actualizaciones
        if hasattr(self.modelo_principal, 'registrar_listener'):
            await self.modelo_principal.registrar_listener('dashboard', self.actualizar_metricas)
    
    async def obtener_estado_sistema(self) -> Dict[str, Any]:
        """
        Obtener estado actual del sistema.
        
        Returns:
            Dict con estado completo del sistema
        """
        try:
            estado = {
                'sistema_activo': True,
                'servicios_funcionando': 0,
                'servicios_total': 0,
                'ultima_actualizacion': self._obtener_timestamp(),
                'metricas': self.metricas_activas.copy(),
                'widgets': self.widgets_activos.copy()
            }
            
            # Obtener estado de servicios del modelo principal
            if hasattr(self.modelo_principal, 'obtener_estado_servicios'):
                servicios = await self.modelo_principal.obtener_estado_servicios()
                estado['servicios_funcionando'] = servicios.get('activos', 0)
                estado['servicios_total'] = servicios.get('total', 0)
            
            return estado
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estado del sistema: {str(e)}")
            return {
                'sistema_activo': False,
                'error': str(e),
                'ultima_actualizacion': self._obtener_timestamp()
            }
    
    async def actualizar_metricas(self, nuevas_metricas: Dict[str, Any]) -> Dict[str, Any]:
        """
        Actualizar métricas del dashboard.
        
        Args:
            nuevas_metricas: Dict con nuevas métricas a actualizar
            
        Returns:
            Dict con resultado de la actualización
        """
        try:
            metricas_actualizadas = []
            
            for clave, valor in nuevas_metricas.items():
                if clave in self.metricas_activas:
                    self.metricas_activas[clave] = valor
                    metricas_actualizadas.append(clave)
            
            # Notificar a la vista si hay cambios
            if metricas_actualizadas:
                self.actualizaciones_pendientes.append({
                    'tipo': 'metricas',
                    'datos': {k: nuevas_metricas[k] for k in metricas_actualizadas},
                    'timestamp': self._obtener_timestamp()
                })
            
            return {
                'exito': True,
                'metricas_actualizadas': len(metricas_actualizadas),
                'actualizaciones_pendientes': len(self.actualizaciones_pendientes)
            }
            
        except Exception as e:
            self.logger.error(f"Error actualizando métricas: {str(e)}")
            return {
                'exito': False,
                'error': str(e)
            }
    
    async def obtener_actualizaciones_pendientes(self) -> List[Dict[str, Any]]:
        """
        Obtener y limpiar actualizaciones pendientes para la vista.
        
        Returns:
            Lista de actualizaciones pendientes
        """
        actualizaciones = self.actualizaciones_pendientes.copy()
        self.actualizaciones_pendientes.clear()
        return actualizaciones
    
    async def configurar_widget(self, nombre_widget: str, configuración: Dict[str, Any]) -> Dict[str, Any]:
        """
        Configurar un widget específico del dashboard.
        
        Args:
            nombre_widget: Nombre del widget a configurar
            configuración: Configuración del widget
            
        Returns:
            Dict con resultado de la configuración
        """
        try:
            # Buscar widget existente
            widget_encontrado = None
            for widget in self.widgets_activos:
                if widget['nombre'] == nombre_widget:
                    widget_encontrado = widget
                    break
            
            if widget_encontrado:
                # Actualizar configuración existente
                widget_encontrado.update(configuración)
                widget_encontrado['ultima_actualizacion'] = self._obtener_timestamp()
                
                return {
                    'exito': True,
                    'mensaje': f'Widget {nombre_widget} configurado correctamente'
                }
            else:
                return {
                    'exito': False,
                    'error': f'Widget {nombre_widget} no encontrado'
                }
                
        except Exception as e:
            self.logger.error(f"Error configurando widget {nombre_widget}: {str(e)}")
            return {
                'exito': False,
                'error': str(e)
            }
    
    def _obtener_timestamp(self) -> str:
        """
        Obtener timestamp actual en formato ISO.
        
        Returns:
            Timestamp como string
        """
        from datetime import datetime
        return datetime.now().isoformat()
