# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Base
Clase base abstracta para todos los controladores del sistema
"""

import logging
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional, List, Union

class ControladorBase(ABC):
    """
    Clase base abstracta para todos los controladores de Ares Aegis.
    Proporciona funcionalidad común como logging, manejo de errores,
    métricas y gestión del ciclo de vida.
    """
    
    def __init__(self, modelo_principal: Any, nombre_controlador: str):
        """
        Inicializar controlador base.
        
        Args:
            modelo_principal: Instancia del modelo principal
            nombre_controlador: Nombre identificativo del controlador
        """
        self.modelo_principal = modelo_principal
        self.nombre_controlador = nombre_controlador
        self._inicializado = False
        self._activo = False
        self._metricas = {}
        self._eventos_siem = []
        self._lock = threading.Lock()
        
        # Configurar logger específico para el controlador
        self.logger = self._configurar_logger()
        
        # Inicializar métricas básicas
        self._inicializar_metricas()
        
        self.logger.info(f"Controlador {self.nombre_controlador} creado")
    
    def _configurar_logger(self) -> logging.Logger:
        """Configurar logger específico para el controlador."""
        logger = logging.getLogger(f"aresitos.{self.nombre_controlador}")
        
        if not logger.handlers:
            # Configurar formato y handler si no existe
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            
            # Handler para consola
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            
            # Nivel de logging
            logger.setLevel(logging.INFO)
        
        return logger
    
    def _inicializar_metricas(self) -> None:
        """Inicializar sistema de métricas del controlador."""
        self._metricas = {
            'tiempo_inicio': time.time(),
            'operaciones_exitosas': 0,
            'operaciones_fallidas': 0,
            'ultima_actividad': None,
            'tiempo_total_operaciones': 0.0,
            'promedio_tiempo_operacion': 0.0
        }
    
    async def inicializar(self) -> Dict[str, Any]:
        """
        Inicializar el controlador de manera asíncrona.
        
        Returns:
            Dict con resultado de la inicialización
        """
        try:
            self.logger.info(f"Iniciando inicialización de {self.nombre_controlador}")
            
            # Llamar implementación específica del controlador
            resultado = await self._inicializar_impl()
            
            if resultado.get('exito', False):
                self._inicializado = True
                self._activo = True
                self._actualizar_metrica('ultima_actividad', datetime.now().isoformat())
                self.logger.info(f"Controlador {self.nombre_controlador} inicializado correctamente")
                self._registrar_evento_siem("INICIALIZACION", "Controlador inicializado", "info")
            else:
                self.logger.error(f"Error en inicialización de {self.nombre_controlador}: {resultado.get('error', 'Error desconocido')}")
                self._registrar_evento_siem("ERROR_INICIALIZACION", f"Error al inicializar: {resultado.get('error', '')}", "error")
            
            return resultado
            
        except Exception as e:
            error_msg = f"Excepción durante inicialización: {str(e)}"
            self.logger.error(error_msg)
            self._registrar_evento_siem("EXCEPCION_INICIALIZACION", error_msg, "critical")
            return {'exito': False, 'error': error_msg}
    
    @abstractmethod
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """
        Implementación específica de inicialización para cada controlador.
        Debe ser implementado por cada controlador hijo.
        
        Returns:
            Dict con resultado de la inicialización específica
        """
        pass
    
    async def finalizar(self) -> Dict[str, Any]:
        """
        Finalizar el controlador y liberar recursos.
        
        Returns:
            Dict con resultado de la finalización
        """
        try:
            self.logger.info(f"Iniciando finalización de {self.nombre_controlador}")
            
            # Llamar implementación específica
            resultado = await self._finalizar_impl()
            
            self._activo = False
            self._inicializado = False
            self.logger.info(f"Controlador {self.nombre_controlador} finalizado")
            self._registrar_evento_siem("FINALIZACION", "Controlador finalizado", "info")
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error durante finalización: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    async def _finalizar_impl(self) -> Dict[str, Any]:
        """
        Implementación específica de finalización.
        Puede ser sobrescrita por controladores que necesiten limpieza específica.
        """
        return {'exito': True, 'mensaje': 'Finalización básica completada'}
    
    def ejecutar_operacion_segura(self, operacion, *args, **kwargs) -> Dict[str, Any]:
        """
        Ejecutar una operación con manejo de errores y métricas.
        
        Args:
            operacion: Función a ejecutar
            *args: Argumentos posicionales para la función
            **kwargs: Argumentos por palabra clave para la función
        
        Returns:
            Dict con resultado de la operación
        """
        tiempo_inicio = time.time()
        
        try:
            self.logger.debug(f"Ejecutando operación: {operacion.__name__}")
            
            # Ejecutar operación
            resultado = operacion(*args, **kwargs)
            
            # Actualizar métricas de éxito
            tiempo_operacion = time.time() - tiempo_inicio
            self._actualizar_metricas_operacion(True, tiempo_operacion)
            
            self.logger.debug(f"Operación {operacion.__name__} completada en {tiempo_operacion:.3f}s")
            
            # Asegurar que el resultado sea un diccionario
            if not isinstance(resultado, dict):
                resultado = {'exito': True, 'resultado': resultado}
            
            return resultado
            
        except Exception as e:
            # Actualizar métricas de error
            tiempo_operacion = time.time() - tiempo_inicio
            self._actualizar_metricas_operacion(False, tiempo_operacion)
            
            error_msg = f"Error en operación {operacion.__name__}: {str(e)}"
            self.logger.error(error_msg)
            self._registrar_evento_siem("ERROR_OPERACION", error_msg, "error")
            
            return {'exito': False, 'error': error_msg}
    
    def _actualizar_metricas_operacion(self, exitosa: bool, tiempo_operacion: float) -> None:
        """Actualizar métricas después de una operación."""
        with self._lock:
            if exitosa:
                self._metricas['operaciones_exitosas'] += 1
            else:
                self._metricas['operaciones_fallidas'] += 1
            
            self._metricas['tiempo_total_operaciones'] += tiempo_operacion
            total_operaciones = self._metricas['operaciones_exitosas'] + self._metricas['operaciones_fallidas']
            
            if total_operaciones > 0:
                self._metricas['promedio_tiempo_operacion'] = (
                    self._metricas['tiempo_total_operaciones'] / total_operaciones
                )
            
            self._metricas['ultima_actividad'] = datetime.now().isoformat()
    
    def _actualizar_metrica(self, clave: str, valor: Any) -> None:
        """Actualizar una métrica específica de forma thread-safe."""
        with self._lock:
            self._metricas[clave] = valor
    
    def _registrar_evento_siem(self, tipo: str, mensaje: str, nivel: str = "info") -> None:
        """
        Registrar un evento en el sistema SIEM.
        
        Args:
            tipo: Tipo de evento
            mensaje: Mensaje descriptivo
            nivel: Nivel de severidad (info, warning, error, critical)
        """
        evento = {
            'timestamp': datetime.now().isoformat(),
            'controlador': self.nombre_controlador,
            'tipo': tipo,
            'mensaje': mensaje,
            'nivel': nivel
        }
        
        with self._lock:
            self._eventos_siem.append(evento)
            # Mantener solo los últimos 100 eventos
            if len(self._eventos_siem) > 100:
                self._eventos_siem = self._eventos_siem[-100:]
        
        # Log del evento
        log_method = getattr(self.logger, nivel, self.logger.info)
        log_method(f"[{tipo}] {mensaje}")
    
    def obtener_metricas(self) -> Dict[str, Any]:
        """
        Obtener métricas del controlador.
        
        Returns:
            Dict con métricas actuales
        """
        with self._lock:
            metricas_copia = self._metricas.copy()
        
        # Calcular tiempo de actividad
        if self._inicializado:
            tiempo_actividad = time.time() - metricas_copia['tiempo_inicio']
            metricas_copia['tiempo_actividad_segundos'] = tiempo_actividad
        
        metricas_copia['estado'] = {
            'inicializado': self._inicializado,
            'activo': self._activo
        }
        
        return metricas_copia
    
    def obtener_eventos_siem(self, limite: int = 50) -> List[Dict[str, Any]]:
        """
        Obtener eventos SIEM recientes.
        
        Args:
            limite: Número máximo de eventos a retornar
        
        Returns:
            Lista de eventos SIEM
        """
        with self._lock:
            eventos = self._eventos_siem[-limite:] if limite else self._eventos_siem.copy()
        
        return eventos
    
    def obtener_estado(self) -> Dict[str, Any]:
        """
        Obtener estado completo del controlador.
        
        Returns:
            Dict con estado completo
        """
        return {
            'nombre': self.nombre_controlador,
            'inicializado': self._inicializado,
            'activo': self._activo,
            'metricas': self.obtener_metricas(),
            'eventos_recientes': self.obtener_eventos_siem(10)
        }
    
    def verificar_salud(self) -> Dict[str, Any]:
        """
        Verificar el estado de salud del controlador.
        
        Returns:
            Dict con información de salud
        """
        metricas = self.obtener_metricas()
        total_operaciones = metricas['operaciones_exitosas'] + metricas['operaciones_fallidas']
        
        # Calcular porcentaje de éxito
        if total_operaciones > 0:
            porcentaje_exito = (metricas['operaciones_exitosas'] / total_operaciones) * 100
        else:
            porcentaje_exito = 100
        
        # Determinar estado de salud
        if not self._inicializado:
            estado_salud = "no_inicializado"
        elif not self._activo:
            estado_salud = "inactivo"
        elif porcentaje_exito >= 95:
            estado_salud = "excelente"
        elif porcentaje_exito >= 85:
            estado_salud = "bueno"
        elif porcentaje_exito >= 70:
            estado_salud = "regular"
        else:
            estado_salud = "critico"
        
        return {
            'estado_salud': estado_salud,
            'porcentaje_exito': round(porcentaje_exito, 2),
            'total_operaciones': total_operaciones,
            'tiempo_actividad': metricas.get('tiempo_actividad_segundos', 0),
            'ultima_actividad': metricas.get('ultima_actividad')
        }
    
    @property
    def esta_inicializado(self) -> bool:
        """Verificar si el controlador está inicializado."""
        return self._inicializado
    
    @property
    def esta_activo(self) -> bool:
        """Verificar si el controlador está activo."""
        return self._activo

# RESUMEN TÉCNICO: Clase base abstracta para arquitectura de controladores en Ares Aegis.
# Implementa patrón Template Method con inicialización asíncrona, sistema de métricas en tiempo real,
# logging especializado, eventos SIEM integrados y verificación de salud. Diseño thread-safe con
# manejo robusto de errores siguiendo principios SOLID para escalabilidad profesional.
