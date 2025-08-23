# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador Escaneador Unificado v3.0
===============================================

Controlador especializado en operaciones de escaneo de seguridad unificado
siguiendo los principios ARESITOS V3: Python nativo + herramientas Kali Linux.

Consolida toda la lógica de control de escaneos en un único archivo optimizado.

Principios ARESITOS aplicados:
- Código limpio sin emoticonos/tokens
- Manejo robusto de errores
- Arquitectura MVC respetada
- Python nativo + Kali tools únicamente
- Validación estricta de tipos
- Manejo seguro de objetos None

Autor: DogSoulDev
Versión: 3.0
Fecha: Agosto 2025
"""

import threading
import time
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Union

from aresitos.controlador.controlador_base import ControladorBase

# Importar modelo escaneador unificado
try:
    from aresitos.modelo.modelo_escaneador import EscaneadorCompleto
    ESCANEADOR_DISPONIBLE = True
except ImportError:
    ESCANEADOR_DISPONIBLE = False
    EscaneadorCompleto = None


class ValidadorObjetivos:
    """Utilidades para validación de objetivos de escaneo."""
    
    @staticmethod
    def validar_ip(ip_str: str) -> bool:
        """Validar dirección IP."""
        try:
            partes = ip_str.split('.')
            if len(partes) != 4:
                return False
            for parte in partes:
                if not 0 <= int(parte) <= 255:
                    return False
            return True
        except (ValueError, TypeError, AttributeError):
            return False
    
    @staticmethod
    def validar_cidr(cidr_str: str) -> bool:
        """Validar notación CIDR."""
        try:
            if '/' not in cidr_str:
                return False
            ip, prefijo = cidr_str.split('/')
            if not ValidadorObjetivos.validar_ip(ip):
                return False
            prefijo_int = int(prefijo)
            return 0 <= prefijo_int <= 32
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validar_hostname(hostname: str) -> bool:
        """Validar hostname básico."""
        if not hostname or len(hostname) > 253:
            return False
        
        # No debe parecer una IP inválida
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            return False  # Parece IP, debe validarse como IP
            
        # Patrón básico para hostname
        patron = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(patron, hostname) is not None


class ControladorEscaneador(ControladorBase):
    """
    Controlador unificado para operaciones de escaneo de seguridad.
    
    Gestiona todos los tipos de escaneo siguiendo principios ARESITOS:
    - Manejo robusto de errores
    - Validación estricta de entradas
    - Logging detallado
    - Arquitectura limpia
    - Verificación de None en todos los métodos
    """
    
    def __init__(self, modelo_principal=None, gestor_permisos=None):
        super().__init__(modelo_principal, "ControladorEscaneador")
        self.modelo_principal = modelo_principal
        self.gestor_permisos = gestor_permisos
        
        # Configuración del controlador
        self.configuracion = {
            'timeout_escaneo': 600,
            'max_threads': 10,
            'auto_guardar': True,
            'validacion_estricta': True,
            'log_detallado': True
        }
        
        # Estado del controlador
        self.escaneo_activo = False
        self.thread_escaneo = None
        self.resultados_cache = {}
        self.callbacks = {
            'progreso': [],
            'completado': [],
            'error': []
        }
        
        # Inicializar escaneador
        self.escaneador = None
        self._inicializar_escaneador()
        
        self.logger.info("ControladorEscaneador v3.0 inicializado correctamente")


    def inicializar(self):
        """
        Inicializa el controlador (requerido por principios ARESITOS).
        
        Returns:
            bool: True si la inicialización es exitosa
        """
        try:
            self.logger.info("ControladorEscaneador v3.0 inicializado correctamente")
            return True
        except Exception as e:
            self.logger.error(f"Error en inicializar(): {e}")
            return False
    def _inicializar_impl(self):
        """Implementación de inicialización requerida por ControladorBase."""
        self.logger.debug("Inicialización específica del controlador escaneador")

    def _inicializar_escaneador(self):
        """Inicializar el escaneador con manejo robusto de errores."""
        if not ESCANEADOR_DISPONIBLE or not EscaneadorCompleto:
            self.logger.error("EscaneadorCompleto no está disponible")
            self.escaneador = None
            return
            
        try:
            self.escaneador = EscaneadorCompleto(self.gestor_permisos)
            self.logger.info("EscaneadorCompleto inicializado correctamente")
        except Exception as e:
            self.logger.error(f"Error inicializando escaneador: {e}")
            self.escaneador = None

    def registrar_callback(self, evento: str, callback):
        """Registrar callback para eventos del controlador."""
        if evento not in self.callbacks:
            self.logger.warning(f"Evento desconocido: {evento}")
            return False
            
        if callable(callback):
            self.callbacks[evento].append(callback)
            self.logger.debug(f"Callback registrado para evento: {evento}")
            return True
        else:
            self.logger.error("El callback debe ser una función callable")
            return False

    def _notificar_evento(self, evento: str, datos: Any):
        """Notificar evento a callbacks registrados con manejo de errores."""
        for callback in self.callbacks.get(evento, []):
            try:
                callback(datos)
            except Exception as e:
                self.logger.error(f"Error ejecutando callback para {evento}: {e}")

    def escanear_objetivo(self, objetivo: str, tipo_escaneo: str = "completo", 
                         asincrono: bool = True) -> Dict[str, Any]:
        """
        Escanear objetivo especificado con validación robusta.
        
        Args:
            objetivo: IP, rango CIDR o hostname a escanear
            tipo_escaneo: Tipo (red, sistema, vulnerabilidades, web, completo)
            asincrono: Si ejecutar en hilo separado
            
        Returns:
            Dict con resultado del escaneo o información del proceso
        """
        # Verificar disponibilidad del escaneador
        if self.escaneador is None:
            error_msg = "Escaneador no disponible o no inicializado"
            self.logger.error(error_msg)
            
            # Notificar error a callbacks
            self._notificar_evento('error', {
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'error': error_msg,
                'codigo_error': 'ESCANEADOR_NO_DISPONIBLE'
            })
            
            return {
                'exito': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
        
        # Verificar si hay escaneo en progreso
        if self.escaneo_activo:
            error_msg = "Ya hay un escaneo en progreso"
            self.logger.warning(error_msg)
            
            # Notificar error a callbacks
            self._notificar_evento('error', {
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'error': error_msg,
                'codigo_error': 'ESCANEO_EN_PROGRESO'
            })
            
            return {
                'exito': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }
        
        # Validar y sanitizar objetivo
        objetivo_validado = self._validar_objetivo(objetivo)
        if not objetivo_validado:
            error_msg = f"Objetivo no válido: {objetivo}"
            self.logger.error(error_msg)
            
            # Notificar error a callbacks
            self._notificar_evento('error', {
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'error': error_msg,
                'codigo_error': 'OBJETIVO_INVALIDO'
            })
            
            return {
                'exito': False,
                'error': error_msg,
                'objetivo_original': objetivo,
                'timestamp': datetime.now().isoformat()
            }
        
        # Validar tipo de escaneo
        tipos_validos = ["red", "sistema", "vulnerabilidades", "web", "completo"]
        if tipo_escaneo not in tipos_validos:
            error_msg = f"Tipo de escaneo no válido: {tipo_escaneo}"
            self.logger.error(error_msg)
            
            # Notificar error a callbacks
            self._notificar_evento('error', {
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'error': error_msg,
                'codigo_error': 'TIPO_ESCANEO_INVALIDO',
                'tipos_validos': tipos_validos
            })
            
            return {
                'exito': False,
                'error': error_msg,
                'tipos_validos': tipos_validos,
                'timestamp': datetime.now().isoformat()
            }
        
        self.logger.info(f"Iniciando escaneo: {objetivo_validado} (tipo: {tipo_escaneo})")
        
        if asincrono:
            return self._ejecutar_escaneo_asincrono(objetivo_validado, tipo_escaneo)
        else:
            return self._ejecutar_escaneo_sincrono(objetivo_validado, tipo_escaneo)

    def _validar_objetivo(self, objetivo: str) -> Optional[str]:
        """Validar y sanitizar objetivo de escaneo."""
        if not objetivo or not objetivo.strip():
            return None
        
        objetivo = objetivo.strip()
        
        # Validar IP
        if ValidadorObjetivos.validar_ip(objetivo):
            self.logger.debug(f"Objetivo validado como IP: {objetivo}")
            return objetivo
        
        # Validar rango CIDR
        if ValidadorObjetivos.validar_cidr(objetivo):
            self.logger.debug(f"Objetivo validado como CIDR: {objetivo}")
            return objetivo
        
        # Validar hostname
        if ValidadorObjetivos.validar_hostname(objetivo):
            self.logger.debug(f"Objetivo validado como hostname: {objetivo}")
            return objetivo
        
        self.logger.warning(f"Objetivo no válido: {objetivo}")
        return None

    def _ejecutar_escaneo_asincrono(self, objetivo: str, tipo_escaneo: str) -> Dict[str, Any]:
        """Ejecutar escaneo en modo asíncrono."""
        try:
            self.thread_escaneo = threading.Thread(
                target=self._worker_escaneo_asincrono,
                args=(objetivo, tipo_escaneo),
                name=f"EscaneoThread-{int(time.time())}"
            )
            self.thread_escaneo.daemon = True
            self.thread_escaneo.start()
            
            return {
                'exito': True,
                'mensaje': 'Escaneo iniciado en modo asíncrono',
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'thread_id': self.thread_escaneo.name,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error iniciando escaneo asíncrono: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }

    def _worker_escaneo_asincrono(self, objetivo: str, tipo_escaneo: str):
        """Worker para escaneo asíncrono con manejo completo de errores."""
        self.escaneo_activo = True
        
        try:
            self.logger.info(f"Ejecutando escaneo asíncrono: {objetivo}")
            
            # Verificar que el escaneador sigue disponible
            if self.escaneador is None:
                raise RuntimeError("Escaneador no disponible durante ejecución")
            
            resultado = self.escaneador.escanear(objetivo, tipo_escaneo)
            
            # Convertir resultado a diccionario si es necesario
            if hasattr(resultado, 'to_dict'):
                resultado_dict = resultado.to_dict()
            elif isinstance(resultado, dict):
                resultado_dict = resultado
            else:
                resultado_dict = {'resultado': str(resultado)}
            
            # Guardar en cache
            cache_key = f"{objetivo}_{tipo_escaneo}_{int(time.time())}"
            self.resultados_cache[cache_key] = resultado_dict
            
            # Guardar en modelo principal si está disponible
            if self.configuracion['auto_guardar'] and self.modelo_principal:
                self._guardar_resultado_seguro(resultado_dict)
                
            # Notificar completado
            self._notificar_evento('completado', {
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'resultado': resultado_dict,
                'cache_key': cache_key
            })
            
            self.logger.info(f"Escaneo asíncrono completado: {objetivo}")
            
        except Exception as e:
            error_msg = f"Error en escaneo asíncrono: {str(e)}"
            self.logger.error(error_msg)
            
            self._notificar_evento('error', {
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'error': error_msg,
                'excepcion': type(e).__name__
            })
        finally:
            self.escaneo_activo = False

    def _ejecutar_escaneo_sincrono(self, objetivo: str, tipo_escaneo: str) -> Dict[str, Any]:
        """Ejecutar escaneo en modo síncrono."""
        self.escaneo_activo = True
        
        try:
            self.logger.info(f"Ejecutando escaneo síncrono: {objetivo}")
            
            # Verificar que el escaneador sigue disponible
            if self.escaneador is None:
                raise RuntimeError("Escaneador no disponible durante ejecución")
            
            resultado = self.escaneador.escanear(objetivo, tipo_escaneo)
            
            # Convertir resultado a diccionario si es necesario
            if hasattr(resultado, 'to_dict'):
                resultado_dict = resultado.to_dict()
            elif isinstance(resultado, dict):
                resultado_dict = resultado
            else:
                resultado_dict = {'resultado': str(resultado)}
            
            # Guardar en cache
            cache_key = f"{objetivo}_{tipo_escaneo}_{int(time.time())}"
            self.resultados_cache[cache_key] = resultado_dict
            
            # Guardar en modelo principal si está disponible
            if self.configuracion['auto_guardar'] and self.modelo_principal:
                self._guardar_resultado_seguro(resultado_dict)
            
            self.logger.info(f"Escaneo síncrono completado: {objetivo}")
            
            return {
                'exito': True,
                'resultado': resultado_dict,
                'cache_key': cache_key,
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error en escaneo síncrono: {str(e)}"
            self.logger.error(error_msg)
            
            return {
                'exito': False,
                'error': error_msg,
                'objetivo': objetivo,
                'tipo': tipo_escaneo,
                'excepcion': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        finally:
            self.escaneo_activo = False

    def _guardar_resultado_seguro(self, resultado: Dict[str, Any]):
        """Guardar resultado en modelo principal con manejo de errores."""
        try:
            if self.modelo_principal is not None and hasattr(self.modelo_principal, 'guardar_resultado_escaneo'):
                self.modelo_principal.guardar_resultado_escaneo(resultado)
                self.logger.debug("Resultado guardado en modelo principal")
            else:
                self.logger.warning("Modelo principal no disponible o sin método guardar_resultado_escaneo")
        except Exception as e:
            self.logger.error(f"Error guardando resultado: {e}")

    def obtener_progreso(self) -> Dict[str, Any]:
        """Obtener progreso del escaneo actual."""
        if self.escaneador is None:
            return {
                'disponible': False,
                'error': 'Escaneador no disponible'
            }
        
        try:
            progreso = self.escaneador.obtener_progreso()
            esta_escaneando = self.escaneador.esta_escaneando()
            
            return {
                'disponible': True,
                'escaneando': esta_escaneando,
                'progreso': progreso,
                'activo': self.escaneo_activo,
                'thread_activo': self.thread_escaneo is not None and self.thread_escaneo.is_alive()
            }
        except Exception as e:
            self.logger.error(f"Error obteniendo progreso: {e}")
            return {
                'disponible': False,
                'error': str(e)
            }

    def detener_escaneo(self) -> Dict[str, Any]:
        """Detener escaneo en progreso."""
        if not self.escaneo_activo:
            return {
                'exito': False,
                'mensaje': 'No hay escaneo activo para detener'
            }
        
        try:
            if self.escaneador is not None:
                self.escaneador.detener_escaneo()
                self.logger.info("Señal de detener enviada al escaneador")
            
            self.escaneo_activo = False
            
            return {
                'exito': True,
                'mensaje': 'Escaneo detenido correctamente',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            error_msg = f"Error deteniendo escaneo: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg
            }

    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas completas del controlador."""
        estadisticas = {
            'version': '3.0',
            'escaneador_disponible': self.escaneador is not None,
            'escaneo_activo': self.escaneo_activo,
            'thread_activo': self.thread_escaneo is not None and self.thread_escaneo.is_alive(),
            'resultados_cache': len(self.resultados_cache),
            'callbacks_registrados': {
                evento: len(callbacks) for evento, callbacks in self.callbacks.items()
            },
            'configuracion': self.configuracion.copy(),
            'timestamp': datetime.now().isoformat()
        }
        
        if self.escaneador is not None:
            try:
                estadisticas.update(self.escaneador.obtener_estadisticas())
            except Exception as e:
                self.logger.error(f"Error obteniendo estadísticas del escaneador: {e}")
        
        return estadisticas

    def obtener_capacidades(self) -> List[str]:
        """Obtener lista de capacidades del escaneador."""
        if self.escaneador is None:
            return ['Escaneador no disponible']
        
        try:
            return self.escaneador.obtener_capacidades()
        except Exception as e:
            self.logger.error(f"Error obteniendo capacidades: {e}")
            return [f'Error: {str(e)}']

    def obtener_resultados_cache(self, limite: int = 10) -> List[Dict[str, Any]]:
        """Obtener resultados del cache con límite opcional."""
        try:
            resultados = list(self.resultados_cache.values())
            if limite > 0:
                return resultados[-limite:]
            return resultados
        except Exception as e:
            self.logger.error(f"Error obteniendo cache: {e}")
            return []

    def limpiar_cache(self) -> Dict[str, Any]:
        """Limpiar cache de resultados."""
        try:
            count = len(self.resultados_cache)
            self.resultados_cache.clear()
            
            self.logger.info(f"Cache limpiado: {count} resultados eliminados")
            
            return {
                'exito': True,
                'mensaje': f'Cache limpiado: {count} resultados eliminados',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            error_msg = f"Error limpiando cache: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg
            }

    def configurar_integraciones(self, **kwargs) -> Dict[str, Any]:
        """Configurar integraciones del escaneador."""
        return self.configurar(**kwargs)

    def configurar(self, **kwargs) -> Dict[str, Any]:
        """Configurar parámetros del controlador."""
        try:
            configuracion_anterior = self.configuracion.copy()
            
            for key, value in kwargs.items():
                if key in self.configuracion:
                    self.configuracion[key] = value
                    self.logger.debug(f"Configuración actualizada: {key} = {value}")
                else:
                    self.logger.warning(f"Parámetro de configuración desconocido: {key}")
            
            return {
                'exito': True,
                'configuracion_anterior': configuracion_anterior,
                'configuracion_actual': self.configuracion.copy(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            error_msg = f"Error configurando controlador: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg
            }

    def estado(self) -> Dict[str, Any]:
        """Obtener estado completo del controlador."""
        return {
            'version': '3.0',
            'clase': 'ControladorEscaneador',
            'escaneador_disponible': self.escaneador is not None,
            'escaneo_activo': self.escaneo_activo,
            'thread_activo': self.thread_escaneo is not None and self.thread_escaneo.is_alive(),
            'resultados_cache': len(self.resultados_cache),
            'configuracion': self.configuracion.copy(),
            'capacidades': self.obtener_capacidades(),
            'timestamp': datetime.now().isoformat()
        }

    # MÉTODOS DE COMPATIBILIDAD LEGACY
    def escanear_red_completa(self, objetivo: str) -> Dict[str, Any]:
        """Escanear red completa (interfaz de compatibilidad)."""
        return self.escanear_objetivo(objetivo, "red", asincrono=False)

    def escanear_sistema_local(self) -> Dict[str, Any]:
        """Escanear sistema local (interfaz de compatibilidad)."""
        return self.escanear_objetivo("localhost", "sistema", asincrono=False)

    def escanear_vulnerabilidades(self, objetivo: str) -> Dict[str, Any]:
        """Escanear vulnerabilidades (interfaz de compatibilidad)."""
        return self.escanear_objetivo(objetivo, "vulnerabilidades", asincrono=False)

    def generar_reporte(self, formato: str = "dict") -> Dict[str, Any]:
        """Generar reporte de último escaneo."""
        if self.escaneador is None:
            return {
                'error': 'Escaneador no disponible'
            }
        
        try:
            reporte = self.escaneador.generar_reporte_completo()
            
            if formato == "dict":
                return reporte
            else:
                return {
                    'error': f'Formato {formato} no soportado'
                }
                
        except Exception as e:
            error_msg = f'Error generando reporte: {str(e)}'
            self.logger.error(error_msg)
            return {
                'error': error_msg
            }
