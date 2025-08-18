# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal Simplificado
Sistema principal de coordinación simplificado y optimizado para Kali Linux
"""

import threading
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.controlador.gestor_configuracion import GestorConfiguracion
from aresitos.controlador.gestor_componentes import GestorComponentes

class ControladorPrincipal(ControladorBase):
    """
    Controlador principal simplificado que coordina los componentes esenciales.
    Enfoque en funcionalidad robusta con manejo de errores mejorado.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorPrincipal")
        
        self.modelo_principal = modelo_principal
        
        # Validación del modelo principal
        if not modelo_principal:
            raise ValueError("Modelo principal es requerido")
        
        # Inicializar gestor de componentes
        try:
            self.gestor_componentes = GestorComponentes(modelo_principal)
            self.logger.info("Gestor de componentes inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando gestor de componentes: {e}")
            self.gestor_componentes = None
        
        # Estado general del sistema
        self._estado_sistema = {
            'iniciado': False,
            'tiempo_inicio': None,
            'componentes_activos': 0,
            'ultima_verificacion_salud': None,
            'modo_operacion': 'normal'  # normal, mantenimiento, emergencia
        }
        
        # Inicializar controladores específicos
        try:
            from .controlador_escaneo import ControladorEscaneo
            from .controlador_auditoria import ControladorAuditoria  
            from .controlador_reportes import ControladorReportes
            from .controlador_monitoreo import ControladorMonitoreo
            from .controlador_fim import ControladorFIM
            from .controlador_siem_nuevo import ControladorSIEM
            
            self.controlador_escaneador = ControladorEscaneo(modelo_principal)
            self.controlador_auditoria = ControladorAuditoria(modelo_principal)
            self.controlador_reportes = ControladorReportes(modelo_principal)
            self.controlador_monitoreo = ControladorMonitoreo(modelo_principal)
            self.controlador_fim = ControladorFIM(modelo_principal)
            self.controlador_siem = ControladorSIEM(modelo_principal)
            
            self.logger.info("Controladores específicos inicializados")
        except Exception as e:
            self.logger.error(f"Error inicializando controladores específicos: {e}")
            self.controlador_escaneador = None
            self.controlador_auditoria = None
            self.controlador_reportes = None
            self.controlador_monitoreo = None
            self.controlador_fim = None
            self.controlador_siem = None
        
        # Lock para thread safety
        self._lock = threading.RLock()
        
        # Operaciones activas
        self._operaciones_activas = set()
        
        self.logger.info("Controlador Principal Ares Aegis inicializado")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación de inicialización del controlador principal."""
        try:
            self.logger.info("Iniciando controlador principal...")
            
            # 1. Verificar sistema básico
            if self.gestor_componentes:
                resultado_basico = self.gestor_componentes.inicializar_sistema_basico()
                if not resultado_basico.get('exito'):
                    return {
                        'exito': False,
                        'error': f"Error en inicialización básica: {resultado_basico.get('error')}",
                        'fase': 'sistema_basico'
                    }
            
            # 2. Inicializar componentes principales
            if self.gestor_componentes:
                resultado_componentes = self.gestor_componentes.inicializar_componentes_ordenado()
                componentes_exitosos = resultado_componentes.get('componentes_exitosos', 0)
                
                if componentes_exitosos == 0:
                    return {
                        'exito': False,
                        'error': 'No se pudo inicializar ningún componente',
                        'fase': 'componentes',
                        'detalles': resultado_componentes
                    }
                
                # Aceptar inicialización parcial si al menos algunos componentes funcionan
                self.logger.info(f"Componentes inicializados: {componentes_exitosos}")
            
            # 3. Actualizar estado del sistema
            with self._lock:
                self._estado_sistema['iniciado'] = True
                self._estado_sistema['tiempo_inicio'] = datetime.now()
                if self.gestor_componentes:
                    estado_componentes = self.gestor_componentes.obtener_estado_componentes()
                    self._estado_sistema['componentes_activos'] = estado_componentes.get('resumen', {}).get('componentes_iniciados', 0)
            
            resultado_final = {
                'exito': True,
                'mensaje': 'Controlador principal inicializado correctamente',
                'timestamp': datetime.now().isoformat(),
                'componentes_activos': self._estado_sistema['componentes_activos']
            }
            
            if self.gestor_componentes:
                resultado_final['detalles_componentes'] = resultado_componentes
            
            self.logger.info("Controlador principal inicializado exitosamente")
            return resultado_final
            
        except Exception as e:
            error_msg = f"Error inicializando controlador principal: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def obtener_estado_sistema(self) -> Dict[str, Any]:
        """Obtener estado completo del sistema."""
        try:
            with self._lock:
                estado_base = self._estado_sistema.copy()
            
            # Agregar información de componentes si está disponible
            if self.gestor_componentes:
                estado_componentes = self.gestor_componentes.obtener_estado_componentes()
                estado_base['componentes'] = estado_componentes
            
            # Agregar tiempo de actividad
            if estado_base['tiempo_inicio']:
                tiempo_actividad = datetime.now() - estado_base['tiempo_inicio']
                estado_base['tiempo_actividad_segundos'] = tiempo_actividad.total_seconds()
                estado_base['tiempo_actividad_formateado'] = str(tiempo_actividad).split('.')[0]
            
            # Operaciones activas
            estado_base['operaciones_activas'] = len(self._operaciones_activas)
            estado_base['lista_operaciones'] = list(self._operaciones_activas)
            
            return {
                'exito': True,
                'estado': estado_base,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo estado del sistema: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def verificar_salud_sistema(self) -> Dict[str, Any]:
        """Verificar salud general del sistema."""
        try:
            self.logger.info("Verificando salud del sistema...")
            
            verificaciones = {
                'sistema_iniciado': self._estado_sistema['iniciado'],
                'gestor_componentes_disponible': self.gestor_componentes is not None,
                'tiempo_actividad_ok': True,
                'componentes_disponibles': 0,
                'errores_detectados': []
            }
            
            # Verificar componentes si está disponible el gestor
            if self.gestor_componentes:
                try:
                    estado_componentes = self.gestor_componentes.obtener_estado_componentes()
                    if estado_componentes.get('exito'):
                        resumen = estado_componentes.get('resumen', {})
                        verificaciones['componentes_disponibles'] = resumen.get('componentes_disponibles', 0)
                        verificaciones['componentes_iniciados'] = resumen.get('componentes_iniciados', 0)
                    else:
                        verificaciones['errores_detectados'].append("Error obteniendo estado de componentes")
                except Exception as e:
                    verificaciones['errores_detectados'].append(f"Error verificando componentes: {str(e)}")
            
            # Verificar tiempo de actividad
            if self._estado_sistema['tiempo_inicio']:
                tiempo_actividad = datetime.now() - self._estado_sistema['tiempo_inicio']
                if tiempo_actividad.total_seconds() < 10:  # Menos de 10 segundos
                    verificaciones['tiempo_actividad_ok'] = False
                    verificaciones['errores_detectados'].append("Sistema recientemente iniciado")
            
            # Evaluar salud general
            salud_general = (
                verificaciones['sistema_iniciado'] and
                verificaciones['gestor_componentes_disponible'] and
                verificaciones['componentes_disponibles'] > 0 and
                len(verificaciones['errores_detectados']) == 0
            )
            
            # Actualizar timestamp de verificación
            with self._lock:
                self._estado_sistema['ultima_verificacion_salud'] = datetime.now()
            
            return {
                'exito': True,
                'salud_general': salud_general,
                'verificaciones': verificaciones,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error verificando salud del sistema: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg,
                'salud_general': False
            }
    
    def obtener_componente(self, nombre_componente: str) -> Optional[Any]:
        """Obtener referencia a un componente específico."""
        try:
            if self.gestor_componentes:
                return self.gestor_componentes.obtener_componente(nombre_componente)
            return None
        except Exception as e:
            self.logger.error(f"Error obteniendo componente {nombre_componente}: {e}")
            return None
    
    def registrar_operacion_activa(self, nombre_operacion: str) -> None:
        """Registrar una operación como activa."""
        try:
            with self._lock:
                self._operaciones_activas.add(nombre_operacion)
            self.logger.debug(f"Operación registrada: {nombre_operacion}")
        except Exception as e:
            self.logger.error(f"Error registrando operación {nombre_operacion}: {e}")
    
    def finalizar_operacion_activa(self, nombre_operacion: str) -> None:
        """Finalizar una operación activa."""
        try:
            with self._lock:
                self._operaciones_activas.discard(nombre_operacion)
            self.logger.debug(f"Operación finalizada: {nombre_operacion}")
        except Exception as e:
            self.logger.error(f"Error finalizando operación {nombre_operacion}: {e}")
    
    def cambiar_modo_operacion(self, nuevo_modo: str) -> Dict[str, Any]:
        """Cambiar modo de operación del sistema."""
        modos_validos = ['normal', 'mantenimiento', 'emergencia']
        
        if nuevo_modo not in modos_validos:
            return {
                'exito': False,
                'error': f'Modo inválido. Modos válidos: {modos_validos}'
            }
        
        try:
            modo_anterior = self._estado_sistema['modo_operacion']
            
            with self._lock:
                self._estado_sistema['modo_operacion'] = nuevo_modo
            
            self.logger.info(f"Modo de operación cambiado: {modo_anterior} -> {nuevo_modo}")
            
            return {
                'exito': True,
                'modo_anterior': modo_anterior,
                'modo_nuevo': nuevo_modo,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error cambiando modo de operación: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Implementación de finalización del controlador principal."""
        try:
            self.logger.info("Finalizando controlador principal...")
            
            # Finalizar componentes
            if self.gestor_componentes:
                resultado_finalizacion = self.gestor_componentes.finalizar_componentes()
                self.logger.info("Componentes finalizados")
            
            # Actualizar estado
            with self._lock:
                self._estado_sistema['iniciado'] = False
                self._operaciones_activas.clear()
            
            return {
                'exito': True,
                'mensaje': 'Controlador principal finalizado correctamente'
            }
            
        except Exception as e:
            error_msg = f"Error finalizando controlador principal: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    # =================== MÉTODOS DE COMPATIBILIDAD ===================
    # Para mantener compatibilidad con código existente
    
    def obtener_estado_salud(self) -> Dict[str, Any]:
        """Alias para verificar_salud_sistema (compatibilidad)."""
        return self.verificar_salud_sistema()
    
    def get_estado_sistema(self) -> Dict[str, Any]:
        """Alias para obtener_estado_sistema (compatibilidad)."""
        return self.obtener_estado_sistema()
    
    def inicializar(self) -> Dict[str, Any]:
        """Alias para inicialización (compatibilidad)."""
        return self._ejecutar_sincrono(self._inicializar_impl())
    
    def finalizar(self) -> Dict[str, Any]:
        """Alias para finalización (compatibilidad)."""
        return self._ejecutar_sincrono(self._finalizar_impl())
    
    def _ejecutar_sincrono(self, resultado):
        """Ejecutar resultado de forma síncrona."""
        return resultado if resultado else {'exito': True}
