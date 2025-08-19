# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal Base
Funcionalidades básicas y configuración del controlador principal
"""

import threading
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.controlador.controlador_gestor_configuracion import GestorConfiguracion

class ControladorPrincipalBase(ControladorBase):
    """
    Clase base para el controlador principal con funcionalidades fundamentales.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorPrincipalBase")
        
        self.modelo_principal = modelo_principal
        
        # Validación del modelo principal
        if not modelo_principal:
            raise ValueError("Modelo principal es requerido")
        
        # Configuración básica del sistema
        self._configuracion_sistema = {
            'verificacion_kali_requerida': True,
            'timeout_operaciones_segundos': 300,
            'max_intentos_reconexion': 3,
            'logging_detallado': True,
            'modo_seguro': True
        }
        
        # Estado del controlador
        self._estado_controlador = {
            'inicializado': False,
            'conectividad_ok': False,
            'permisos_validados': False,
            'kali_verificado': False,
            'servicios_activos': set()
        }
        
        # Métricas básicas
        self._metricas_basicas = {
            'tiempo_inicio': datetime.now(),
            'operaciones_completadas': 0,
            'errores_registrados': 0,
            'ultima_verificacion': None
        }
        
        # Lock para thread safety
        self._lock = threading.RLock()
        
        # Inicializar gestor de configuración
        try:
            self.gestor_config = GestorConfiguracion()
            self.logger.info("Gestor de configuración inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando gestor de configuración: {e}")
            self.gestor_config = None
        
        self.logger.info("Controlador Principal Base inicializado")
    
    def verificar_estado_sistema(self) -> Dict[str, Any]:
        """Verificar estado general del sistema."""
        try:
            with self._lock:
                estado = {
                    'timestamp': datetime.now().isoformat(),
                    'sistema_iniciado': self._estado_controlador['inicializado'],
                    'kali_verificado': self._estado_controlador['kali_verificado'],
                    'permisos_ok': self._estado_controlador['permisos_validados'],
                    'conectividad_ok': self._estado_controlador['conectividad_ok'],
                    'servicios_activos': len(self._estado_controlador['servicios_activos']),
                    'tiempo_actividad': self._calcular_tiempo_actividad(),
                    'metricas': self._metricas_basicas.copy()
                }
                
                # Actualizar última verificación
                self._estado_controlador['ultima_verificacion'] = datetime.now()
                
                return {
                    'exito': True,
                    'estado': estado
                }
                
        except Exception as e:
            error_msg = f"Error verificando estado del sistema: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def _calcular_tiempo_actividad(self) -> float:
        """Calcular tiempo de actividad en segundos."""
        try:
            tiempo_inicio = self._metricas_basicas['tiempo_inicio']
            if isinstance(tiempo_inicio, datetime):
                delta = datetime.now() - tiempo_inicio
                return delta.total_seconds()
            return 0.0
        except (ValueError, TypeError, AttributeError):
            return 0.0
    
    def obtener_configuracion_sistema(self) -> Dict[str, Any]:
        """Obtener configuración actual del sistema."""
        try:
            configuración = {
                'configuracion_controlador': self._configuracion_sistema.copy(),
                'estado_actual': self._estado_controlador.copy(),
                'metricas': self._metricas_basicas.copy()
            }
            
            # Agregar configuración del gestor si está disponible
            if self.gestor_config:
                try:
                    config_gestor = self.gestor_config.obtener_configuracion_completa()
                    configuración['configuracion_gestor'] = config_gestor
                except Exception as e:
                    self.logger.warning(f"Error obteniendo configuración del gestor: {e}")
            
            return {
                'exito': True,
                'configuración': configuración
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo configuración: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def validar_permisos_sistema(self) -> Dict[str, Any]:
        """Validar permisos necesarios del sistema."""
        try:
            import subprocess
            import os
            
            resultados = {
                'permisos_lectura': False,
                'permisos_ejecucion': False,
                'acceso_proc': False,
                'acceso_etc': False,
                'comando_ps': False,
                'comando_ss': False
            }
            
            # Verificar acceso de lectura a /etc
            try:
                if os.access('/etc', os.R_OK):
                    resultados['acceso_etc'] = True
            except (ValueError, TypeError, AttributeError):
                pass
            
            # Verificar acceso a /proc
            try:
                if os.access('/proc', os.R_OK):
                    resultados['acceso_proc'] = True
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Verificar comando ps
            try:
                result = subprocess.run(['ps', '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    resultados['comando_ps'] = True
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Verificar comando ss
            try:
                result = subprocess.run(['ss', '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    resultados['comando_ss'] = True
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Evaluar permisos generales
            permisos_ok = (resultados['acceso_etc'] and 
                          resultados['comando_ps'] and 
                          resultados['comando_ss'])
            
            with self._lock:
                self._estado_controlador['permisos_validados'] = permisos_ok
            
            return {
                'exito': True,
                'permisos_validados': permisos_ok,
                'detalles': resultados
            }
            
        except Exception as e:
            error_msg = f"Error validando permisos: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def verificar_kali_linux(self) -> Dict[str, Any]:
        """Verificar que el sistema es Kali Linux."""
        try:
            es_kali = False
            version_kali = "desconocida"
            distribucion = "desconocida"
            
            # Verificar /etc/os-release
            try:
                with open('/etc/os-release', 'r') as f:
                    contenido = f.read().lower()
                    if 'kali' in contenido:
                        es_kali = True
                        # Buscar versión
                        for linea in contenido.split('\n'):
                            if 'version=' in linea:
                                version_kali = linea.split('=')[1].strip('"')
                                break
                    elif 'debian' in contenido:
                        distribucion = "debian"
                    elif 'ubuntu' in contenido:
                        distribucion = "ubuntu"
            except (ValueError, TypeError, AttributeError):
                pass
            
            # Verificar indicadores específicos de Kali
            indicadores_kali = []
            
            # Verificar directorio de herramientas Kali
            import os
            if os.path.exists('/usr/share/kali-themes'):
                indicadores_kali.append('kali-themes')
                es_kali = True
            
            if os.path.exists('/etc/kali_version'):
                indicadores_kali.append('kali_version')
                es_kali = True
                try:
                    with open('/etc/kali_version', 'r') as f:
                        version_kali = f.read().strip()
                except (IOError, OSError, PermissionError, FileNotFoundError):
                    pass
            
            # Verificar herramientas típicas de Kali
            herramientas_kali = ['nmap', 'nikto', 'gobuster', 'masscan']
            herramientas_encontradas = []
            
            import subprocess
            for herramienta in herramientas_kali:
                try:
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        herramientas_encontradas.append(herramienta)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            # Si tiene varias herramientas de Kali, probablemente es Kali
            if len(herramientas_encontradas) >= 2:
                es_kali = True
            
            with self._lock:
                self._estado_controlador['kali_verificado'] = es_kali
            
            return {
                'exito': True,
                'es_kali': es_kali,
                'version': version_kali,
                'distribucion': distribucion,
                'indicadores_encontrados': indicadores_kali,
                'herramientas_kali': herramientas_encontradas,
                'total_herramientas': len(herramientas_encontradas)
            }
            
        except Exception as e:
            error_msg = f"Error verificando Kali Linux: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def inicializar_sistema_basico(self) -> Dict[str, Any]:
        """Inicializar sistemas básicos necesarios."""
        try:
            self.logger.info("Iniciando sistemas básicos...")
            
            # 1. Verificar Kali Linux
            resultado_kali = self.verificar_kali_linux()
            if not resultado_kali.get('exito'):
                return {'exito': False, 'error': 'Error verificando Kali Linux'}
            
            # 2. Validar permisos
            resultado_permisos = self.validar_permisos_sistema()
            if not resultado_permisos.get('exito'):
                return {'exito': False, 'error': 'Error validando permisos'}
            
            # 3. Marcar como inicializado
            with self._lock:
                self._estado_controlador['inicializado'] = True
                self._metricas_basicas['operaciones_completadas'] += 1
            
            resultado = {
                'exito': True,
                'mensaje': 'Sistemas básicos inicializados correctamente',
                'kali_info': resultado_kali,
                'permisos_info': resultado_permisos,
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info("Sistemas básicos inicializados correctamente")
            return resultado
            
        except Exception as e:
            error_msg = f"Error inicializando sistemas básicos: {str(e)}"
            self.logger.error(error_msg)
            with self._lock:
                self._metricas_basicas['errores_registrados'] += 1
            return {'exito': False, 'error': error_msg}
    
    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Finalizar controlador principal base."""
        try:
            self.logger.info("Finalizando controlador principal base...")
            
            with self._lock:
                self._estado_controlador['inicializado'] = False
                self._estado_controlador['servicios_activos'].clear()
            
            return {'exito': True, 'mensaje': 'Controlador base finalizado'}
            
        except Exception as e:
            error_msg = f"Error finalizando controlador base: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
