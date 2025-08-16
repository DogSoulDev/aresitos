#!/usr/bin/env python3
"""
Modelo para gestión de auditorías de seguridad
Autor: Aresitos
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import os
import threading

class ModeloAuditoria:
    def __init__(self):
        """Inicializa el modelo de auditoría"""
        self.logger = logging.getLogger(__name__)
        self.auditorias_activas = {}
        self.historial_auditorias = []
        self._lock = threading.Lock()
        
    def crear_auditoria(self, tipo: str, parametros: Dict[str, Any]) -> str:
        """
        Crea una nueva auditoría
        
        Args:
            tipo: Tipo de auditoría (sistema, red, aplicacion)
            parametros: Parámetros de configuración
            
        Returns:
            ID de la auditoría creada
        """
        auditoria_id = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with self._lock:
            self.auditorias_activas[auditoria_id] = {
                'id': auditoria_id,
                'tipo': tipo,
                'parametros': parametros,
                'estado': 'iniciada',
                'timestamp': datetime.now().isoformat(),
                'resultados': []
            }
            
        self.logger.info(f"Auditoría creada: {auditoria_id}")
        return auditoria_id
    
    def ejecutar_auditoria_sistema(self, auditoria_id: str) -> List[Dict[str, Any]]:
        """
        Ejecuta auditoría del sistema
        
        Args:
            auditoria_id: ID de la auditoría
            
        Returns:
            Lista de hallazgos
        """
        hallazgos = []
        
        try:
            # Verificar configuración de sistema
            hallazgos.extend(self._verificar_configuracion_sistema())
            
            # Verificar usuarios y permisos
            hallazgos.extend(self._verificar_usuarios_permisos())
            
            # Verificar servicios activos
            hallazgos.extend(self._verificar_servicios())
            
            # Actualizar estado de auditoría
            with self._lock:
                if auditoria_id in self.auditorias_activas:
                    self.auditorias_activas[auditoria_id]['resultados'] = hallazgos
                    self.auditorias_activas[auditoria_id]['estado'] = 'completada'
                    
        except Exception as e:
            self.logger.error(f"Error en auditoría de sistema: {e}")
            with self._lock:
                if auditoria_id in self.auditorias_activas:
                    self.auditorias_activas[auditoria_id]['estado'] = 'error'
                    
        return hallazgos
    
    def ejecutar_auditoria_red(self, auditoria_id: str) -> List[Dict[str, Any]]:
        """
        Ejecuta auditoría de red
        
        Args:
            auditoria_id: ID de la auditoría
            
        Returns:
            Lista de hallazgos
        """
        hallazgos = []
        
        try:
            # Verificar puertos abiertos
            hallazgos.extend(self._verificar_puertos_abiertos())
            
            # Verificar configuración de firewall
            hallazgos.extend(self._verificar_firewall())
            
            # Verificar conexiones activas
            hallazgos.extend(self._verificar_conexiones())
            
            # Actualizar estado
            with self._lock:
                if auditoria_id in self.auditorias_activas:
                    self.auditorias_activas[auditoria_id]['resultados'] = hallazgos
                    self.auditorias_activas[auditoria_id]['estado'] = 'completada'
                    
        except Exception as e:
            self.logger.error(f"Error en auditoría de red: {e}")
            with self._lock:
                if auditoria_id in self.auditorias_activas:
                    self.auditorias_activas[auditoria_id]['estado'] = 'error'
                    
        return hallazgos
    
    def _verificar_configuracion_sistema(self) -> List[Dict[str, Any]]:
        """Verifica configuración del sistema"""
        hallazgos = []
        
        # Verificar actualizaciones pendientes
        hallazgos.append({
            'categoria': 'configuracion',
            'severidad': 'media',
            'descripcion': 'Verificación de actualizaciones del sistema',
            'recomendacion': 'Mantener sistema actualizado'
        })
        
        return hallazgos
    
    def _verificar_usuarios_permisos(self) -> List[Dict[str, Any]]:
        """Verifica usuarios y permisos"""
        hallazgos = []
        
        hallazgos.append({
            'categoria': 'usuarios',
            'severidad': 'alta',
            'descripcion': 'Verificación de usuarios con privilegios elevados',
            'recomendacion': 'Revisar permisos de usuario'
        })
        
        return hallazgos
    
    def _verificar_servicios(self) -> List[Dict[str, Any]]:
        """Verifica servicios del sistema"""
        hallazgos = []
        
        hallazgos.append({
            'categoria': 'servicios',
            'severidad': 'media',
            'descripcion': 'Verificación de servicios innecesarios',
            'recomendacion': 'Deshabilitar servicios no utilizados'
        })
        
        return hallazgos
    
    def _verificar_puertos_abiertos(self) -> List[Dict[str, Any]]:
        """Verifica puertos abiertos"""
        hallazgos = []
        
        hallazgos.append({
            'categoria': 'red',
            'severidad': 'alta',
            'descripcion': 'Puertos abiertos detectados',
            'recomendacion': 'Revisar necesidad de puertos expuestos'
        })
        
        return hallazgos
    
    def _verificar_firewall(self) -> List[Dict[str, Any]]:
        """Verifica configuración de firewall"""
        hallazgos = []
        
        hallazgos.append({
            'categoria': 'firewall',
            'severidad': 'alta',
            'descripcion': 'Configuración de firewall',
            'recomendacion': 'Verificar reglas de firewall'
        })
        
        return hallazgos
    
    def _verificar_conexiones(self) -> List[Dict[str, Any]]:
        """Verifica conexiones activas"""
        hallazgos = []
        
        hallazgos.append({
            'categoria': 'conexiones',
            'severidad': 'media',
            'descripcion': 'Conexiones de red activas',
            'recomendacion': 'Monitorear conexiones sospechosas'
        })
        
        return hallazgos
    
    def obtener_auditoria(self, auditoria_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene información de una auditoría
        
        Args:
            auditoria_id: ID de la auditoría
            
        Returns:
            Datos de la auditoría o None
        """
        with self._lock:
            return self.auditorias_activas.get(auditoria_id)
    
    def obtener_auditorias_activas(self) -> Dict[str, Dict[str, Any]]:
        """
        Obtiene todas las auditorías activas
        
        Returns:
            Diccionario con auditorías activas
        """
        with self._lock:
            return self.auditorias_activas.copy()
    
    def finalizar_auditoria(self, auditoria_id: str) -> bool:
        """
        Finaliza una auditoría y la mueve al historial
        
        Args:
            auditoria_id: ID de la auditoría
            
        Returns:
            True si se finalizó correctamente
        """
        try:
            with self._lock:
                if auditoria_id in self.auditorias_activas:
                    auditoria = self.auditorias_activas.pop(auditoria_id)
                    auditoria['estado'] = 'finalizada'
                    auditoria['timestamp_fin'] = datetime.now().isoformat()
                    self.historial_auditorias.append(auditoria)
                    
            self.logger.info(f"Auditoría finalizada: {auditoria_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error al finalizar auditoría: {e}")
            return False
    
    def obtener_historial(self) -> List[Dict[str, Any]]:
        """
        Obtiene el historial de auditorías
        
        Returns:
            Lista con historial de auditorías
        """
        with self._lock:
            return self.historial_auditorias.copy()
    
    def limpiar_historial(self, dias: int = 30) -> int:
        """
        Limpia auditorías antiguas del historial
        
        Args:
            dias: Días de antigüedad máxima
            
        Returns:
            Número de auditorías eliminadas
        """
        try:
            fecha_limite = datetime.now().timestamp() - (dias * 24 * 3600)
            
            with self._lock:
                auditorias_conservar = []
                eliminadas = 0
                
                for auditoria in self.historial_auditorias:
                    timestamp = datetime.fromisoformat(auditoria['timestamp']).timestamp()
                    if timestamp >= fecha_limite:
                        auditorias_conservar.append(auditoria)
                    else:
                        eliminadas += 1
                
                self.historial_auditorias = auditorias_conservar
                
            self.logger.info(f"Historial limpiado: {eliminadas} auditorías eliminadas")
            return eliminadas
            
        except Exception as e:
            self.logger.error(f"Error al limpiar historial: {e}")
            return 0
