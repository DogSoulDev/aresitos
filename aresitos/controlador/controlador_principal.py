# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal
Controlador central que coordina todos los módulos del sistema
"""

import asyncio
import logging
import threading
import time
import re
import os
from typing import Dict, Any, Optional, List
from datetime import datetime

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.controlador.gestor_configuracion import GestorConfiguracion
from aresitos.controlador.controlador_escaneador_cuarentena import ControladorEscaneadorCuarentena
from aresitos.controlador.controlador_monitoreo import ControladorMonitoreo
from aresitos.controlador.controlador_utilidades import ControladorUtilidades
from aresitos.controlador.controlador_auditoria import ControladorAuditoria
from aresitos.controlador.controlador_herramientas import ControladorHerramientas
from aresitos.controlador.controlador_reportes import ControladorReportes
from aresitos.controlador.controlador_wordlists import ControladorWordlists
from aresitos.controlador.controlador_diccionarios import ControladorDiccionarios
from aresitos.controlador.controlador_fim import ControladorFIM
from aresitos.controlador.controlador_siem import ControladorSIEM
from aresitos.controlador.controlador_actualizacion import ControladorActualizacion

class ControladorPrincipal(ControladorBase):
    """
    Controlador principal que coordina todos los componentes del sistema Ares Aegis.
    Actúa como fachada principal y gestor de estado global.
    """
    
    def __init__(self, modelo, vista):
        super().__init__(modelo, "ControladorPrincipal")
        
        self.modelo = modelo
        self.vista = vista
        
        # Inicializar gestor de configuración
        self.gestor_config = GestorConfiguracion()
        
        # Estado del sistema
        self._estado_sistema = {
            'iniciado': False,
            'tiempo_inicio': None,
            'componentes_activos': 0,
            'ultima_verificacion_salud': None
        }
        
        # Métricas del sistema
        self._metricas_sistema = {
            'operaciones_totales': 0,
            'errores_totales': 0,
            'tiempo_actividad': 0.0,
            'componentes_saludables': 0,
            'controladores': {}
        }
        
        # Controladores especializados
        self._controladores = {}
        self._inicializar_controladores()
        
        # Lock para operaciones thread-safe
        self._lock = threading.Lock()
        
        # SECURITY: Controladores permitidos para acceso (SECURITY FIX)
        self._controladores_permitidos = {
            'escaneador', 'monitoreo', 'utilidades', 'auditoria', 
            'herramientas', 'reportes', 'wordlists', 'diccionarios', 
            'fim', 'siem', 'actualizacion'
        }
        
        # SECURITY: Claves de configuración permitidas (SECURITY FIX)
        self._config_keys_permitidas = {
            'sistema.log_level', 'sistema.timeout', 'sistema.max_threads',
            'kali.herramientas_path', 'kali.entorno_trabajo',
            'escaneo.puerto_inicial', 'escaneo.puerto_final',
            'fim.intervalo_escaneo', 'siem.intervalo_analisis'
        }
        
        # Configurar logging avanzado
        self._configurar_logging_avanzado()
        
        self.logger.info("Controlador Principal de Ares Aegis inicializado")

    def _validar_objetivo_principal(self, objetivo: str) -> Dict[str, Any]:
        """
        Valida objetivo para escaneo avanzado en el controlador principal.
        KALI OPTIMIZATION: Delega validación a controladores especializados.
        """
        if not objetivo or not isinstance(objetivo, str):
            return {'valido': False, 'error': 'Objetivo no válido'}
        
        # Limpiar espacios y caracteres peligrosos
        objetivo = objetivo.strip()
        
        # SECURITY FIX: Prevenir command injection básico
        if re.search(r'[;&|`$(){}[\]<>]', objetivo):
            return {'valido': False, 'error': 'Objetivo contiene caracteres no seguros'}
        
        # Validación de longitud razonable
        if len(objetivo) > 253:  # RFC 1035 - máximo para hostname
            return {'valido': False, 'error': 'Objetivo demasiado largo'}
        
        # KALI SECURITY: Delegar validación específica al controlador de escaneo
        # El controlador de escaneo tiene validaciones más robustas
        controlador_escaneo = self._controladores.get('escaneo')
        if controlador_escaneo and hasattr(controlador_escaneo, '_validar_objetivo_escaneo'):
            return controlador_escaneo._validar_objetivo_escaneo(objetivo)
        
        # Validación básica si no hay controlador de escaneo
        return {
            'valido': True,
            'objetivo_sanitizado': objetivo,
            'tipo': 'basic_validation',
            'nota': 'Validación básica - use controlador específico para validación completa'
        }
    
    def _validar_nombre_controlador(self, nombre: str) -> Dict[str, Any]:
        """
        Valida nombre de controlador antes de acceso.
        KALI OPTIMIZATION: Solo permite controladores autorizados.
        """
        if not nombre or not isinstance(nombre, str):
            return {'valido': False, 'error': 'Nombre de controlador no válido'}
        
        # Limpiar espacios y convertir a lowercase
        nombre = nombre.strip().lower()
        
        # SECURITY FIX: Prevenir command injection y path traversal
        if re.search(r'[;&|`$(){}[\]<>/\\.]', nombre):
            return {'valido': False, 'error': 'Nombre contiene caracteres no seguros'}
        
        # KALI SECURITY: Verificar que esté en whitelist
        if nombre not in self._controladores_permitidos:
            return {
                'valido': False,
                'error': f'Controlador {nombre} no está en la lista de controladores permitidos'
            }
        
        return {
            'valido': True,
            'nombre_sanitizado': nombre
        }
    
    def _validar_clave_configuracion(self, clave: str) -> Dict[str, Any]:
        """
        Valida clave de configuración antes de acceso/modificación.
        KALI OPTIMIZATION: Solo permite claves de configuración seguras.
        """
        if not clave or not isinstance(clave, str):
            return {'valido': False, 'error': 'Clave de configuración no válida'}
        
        # Limpiar espacios
        clave = clave.strip()
        
        # SECURITY FIX: Prevenir command injection y path traversal
        if re.search(r'[;&|`$(){}[\]<>\\]', clave):
            return {'valido': False, 'error': 'Clave contiene caracteres no seguros'}
        
        # KALI SECURITY: Verificar que esté en whitelist
        if clave not in self._config_keys_permitidas:
            return {
                'valido': False,
                'error': f'Clave {clave} no está en la lista de configuraciones permitidas'
            }
        
        return {
            'valido': True,
            'clave_sanitizada': clave
        }

    def _inicializar_controladores(self) -> None:
        """Inicializar todos los controladores especializados."""
        try:
            self._controladores = {
                'escaneador': ControladorEscaneadorCuarentena(),
                'monitoreo': ControladorMonitoreo(self.modelo),
                'utilidades': ControladorUtilidades(self.modelo),
                'auditoria': ControladorAuditoria(self.modelo),
                'herramientas': ControladorHerramientas(self.modelo),
                'reportes': ControladorReportes(self.modelo),
                'wordlists': ControladorWordlists(self.modelo),
                'diccionarios': ControladorDiccionarios(self.modelo),
                'fim': ControladorFIM(self.modelo),
                'siem': ControladorSIEM(self.modelo),
                'actualizacion': ControladorActualizacion(self.modelo)
            }
            
            # IMPORTANTE: Asegurar que los controladores usen las instancias del modelo principal
            if hasattr(self.modelo, 'fim_avanzado') and self.modelo.fim_avanzado:
                self._controladores['fim'].fim = self.modelo.fim_avanzado
            
            if hasattr(self.modelo, 'siem_avanzado') and self.modelo.siem_avanzado:
                self._controladores['siem'].siem = self.modelo.siem_avanzado
            
            self.logger.info(f"Inicializados {len(self._controladores)} controladores especializados")
            
            # NUEVA FUNCIONALIDAD: Configurar conectividad entre controladores
            self._configurar_conectividad_controladores()
            
        except Exception as e:
            self.logger.error(f"Error inicializando controladores: {e}")
            self._controladores = {}

    def _configurar_conectividad_controladores(self) -> None:
        """
        Configurar conectividad y referencias cruzadas entre controladores.
        MÉTODO CLAVE para asegurar que SIEM puede responder automáticamente
        activando Cuarentena y FIM cuando detecta amenazas.
        """
        try:
            self.logger.info("Configurando conectividad entre controladores...")
            
            # 1. Configurar SIEM con referencias a Cuarentena y FIM
            if 'siem' in self._controladores:
                siem = self._controladores['siem']
                cuarentena = self._obtener_controlador_cuarentena_para_siem()
                fim = self._controladores.get('fim')
                
                if hasattr(siem, 'configurar_referencias_controladores'):
                    siem.configurar_referencias_controladores(
                        controlador_principal=self,
                        controlador_cuarentena=cuarentena,
                        controlador_fim=fim
                    )
                    self.logger.info("SIEM configurado con respuesta automática a Cuarentena y FIM")
            
            # 2. Configurar FIM con notificaciones a SIEM
            if 'fim' in self._controladores and 'siem' in self._controladores:
                fim = self._controladores['fim']
                if hasattr(fim, 'configurar_notificacion_siem'):
                    fim.configurar_notificacion_siem(self._controladores['siem'])
                    self.logger.info("FIM configurado para notificar cambios a SIEM")
            
            # 3. Configurar Escaneador con integración a Cuarentena (ya existe)
            if 'escaneador' in self._controladores:
                self.logger.info("Escaneador ya tiene integración con Cuarentena")
            
            # 4. Registrar métricas de conectividad
            self._metricas_sistema['conectividad_configurada'] = True
            self._metricas_sistema['integraciones_activas'] = self._contar_integraciones_activas()
            
            self.logger.info("Conectividad entre controladores configurada exitosamente")
            
        except Exception as e:
            self.logger.error(f"Error configurando conectividad entre controladores: {e}")

    def _obtener_controlador_cuarentena_para_siem(self):
        """Obtener controlador de cuarentena para integración con SIEM."""
        try:
            # El escaneador ya tiene cuarentena integrada
            if 'escaneador' in self._controladores:
                escaneador = self._controladores['escaneador']
                if hasattr(escaneador, 'cuarentena') and escaneador.cuarentena:
                    return escaneador.cuarentena
                # Si no tiene atributo cuarentena, usar el escaneador mismo si tiene métodos de cuarentena
                elif hasattr(escaneador, 'cuarentenar_archivo'):
                    return escaneador
            
            # Buscar en el modelo si hay gestor de cuarentena
            if hasattr(self.modelo, 'gestor_cuarentena'):
                return self.modelo.gestor_cuarentena
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error obteniendo controlador de cuarentena: {e}")
            return None

    def _contar_integraciones_activas(self) -> int:
        """Contar número de integraciones activas entre controladores."""
        try:
            integraciones = 0
            
            # SIEM con respuesta automática
            if 'siem' in self._controladores:
                siem = self._controladores['siem']
                if hasattr(siem, '_respuesta_automatica_habilitada') and siem._respuesta_automatica_habilitada:
                    integraciones += 1
            
            # Escaneador con cuarentena
            if 'escaneador' in self._controladores:
                integraciones += 1  # Ya sabemos que tiene cuarentena integrada
            
            # FIM disponible
            if 'fim' in self._controladores:
                integraciones += 1
            
            return integraciones
            
        except Exception as e:
            self.logger.error(f"Error contando integraciones: {e}")
            return 0

    def registrar_evento_sistema(self, tipo_evento: str, datos_evento: Dict[str, Any]) -> None:
        """
        Registrar evento del sistema para coordinación entre controladores.
        Permite que los controladores se notifiquen entre sí.
        """
        try:
            evento_sistema = {
                'tipo': tipo_evento,
                'timestamp': datetime.now().isoformat(),
                'datos': datos_evento,
                'origen': 'ControladorPrincipal'
            }
            
            # Log del evento
            self.logger.info(f"Evento del sistema registrado: {tipo_evento}")
            
            # Notificar a controladores interesados
            self._notificar_evento_sistema(evento_sistema)
            
        except Exception as e:
            self.logger.error(f"Error registrando evento del sistema: {e}")

    def _notificar_evento_sistema(self, evento: Dict[str, Any]) -> None:
        """Notificar evento del sistema a controladores relevantes."""
        try:
            tipo_evento = evento['tipo']
            
            # Notificar según tipo de evento
            if tipo_evento == 'SIEM_RESPUESTA_AUTOMATICA':
                # Puede interesar a reportes, auditoría
                for nombre in ['reportes', 'auditoria']:
                    if nombre in self._controladores:
                        controlador = self._controladores[nombre]
                        if hasattr(controlador, 'procesar_evento_sistema'):
                            try:
                                controlador.procesar_evento_sistema(evento)
                            except Exception as e:
                                self.logger.warning(f"Error notificando a {nombre}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error notificando evento del sistema: {e}")
    
    def _configurar_logging_avanzado(self) -> None:
        """Configurar sistema de logging avanzado."""
        try:
            # Configurar nivel de logging desde configuración
            nivel_log = self.gestor_config.obtener("sistema.log_level", "INFO")
            
            if hasattr(logging, nivel_log):
                self.logger.setLevel(getattr(logging, nivel_log))
            
            # Configurar formato personalizado
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s'
            )
            
            # Aplicar formato a handlers existentes
            for handler in self.logger.handlers:
                handler.setFormatter(formatter)
                
        except Exception as e:
            print(f"Error configurando logging: {e}")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación específica de inicialización del controlador principal."""
        try:
            self.logger.info("Iniciando inicialización completa del sistema")
            
            # Verificar configuración
            validacion_config = self.gestor_config.validar_configuracion()
            if not validacion_config['valida']:
                self.logger.warning(f"Configuración con errores: {validacion_config['errores']}")
            
            # Inicializar componentes críticos
            resultados_inicializacion = await self._inicializar_componentes_criticos()
            
            # Verificar herramientas del sistema
            verificacion_herramientas = self._verificar_herramientas_sistema()
            
            # Iniciar monitoreo del sistema
            resultado_monitoreo = self._iniciar_monitoreo_sistema()
            
            # Actualizar estado del sistema
            with self._lock:
                self._estado_sistema.update({
                    'iniciado': True,
                    'tiempo_inicio': datetime.now().isoformat(),
                    'componentes_activos': len([r for r in resultados_inicializacion.values() if r.get('exito')]),
                    'ultima_verificacion_salud': datetime.now().isoformat()
                })
            
            resultado_final = {
                'exito': True,
                'mensaje': 'Sistema Ares Aegis inicializado correctamente',
                'componentes': resultados_inicializacion,
                'herramientas': verificacion_herramientas,
                'monitoreo': resultado_monitoreo,
                'configuracion': validacion_config
            }
            
            self.logger.info("Inicialización completa del sistema finalizada exitosamente")
            return resultado_final
            
        except Exception as e:
            error_msg = f"Error crítico durante inicialización: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    async def _inicializar_componentes_criticos(self) -> Dict[str, Any]:
        """Inicializar componentes críticos del sistema."""
        resultados = {}
        
        for nombre, controlador in self._controladores.items():
            try:
                self.logger.debug(f"Inicializando componente: {nombre}")
                
                # Si el controlador tiene método de inicialización asíncrona
                if hasattr(controlador, 'inicializar') and asyncio.iscoroutinefunction(controlador.inicializar):
                    resultado = await controlador.inicializar()
                else:
                    # Inicialización síncrona básica
                    resultado = {'exito': True, 'mensaje': f'Componente {nombre} inicializado'}
                
                resultados[nombre] = resultado
                
                if resultado.get('exito'):
                    self.logger.debug(f"Componente {nombre} inicializado correctamente")
                else:
                    self.logger.warning(f"Error inicializando {nombre}: {resultado.get('error', 'Error desconocido')}")
                    
            except Exception as e:
                error_msg = f"Excepción inicializando {nombre}: {str(e)}"
                self.logger.error(error_msg)
                resultados[nombre] = {'exito': False, 'error': error_msg}
        
        return resultados
    
    def _verificar_herramientas_sistema(self) -> Dict[str, Any]:
        """Verificar herramientas disponibles en el sistema."""
        try:
            if 'herramientas' in self._controladores:
                return self.ejecutar_operacion_segura(
                    self._controladores['herramientas'].verificar_herramientas_disponibles
                )
            else:
                return {'exito': False, 'error': 'Controlador de herramientas no disponible'}
                
        except Exception as e:
            return {'exito': False, 'error': f'Error verificando herramientas: {str(e)}'}
    
    def _iniciar_monitoreo_sistema(self) -> Dict[str, Any]:
        """Iniciar monitoreo del sistema."""
        try:
            if 'monitoreo' in self._controladores:
                return self.ejecutar_operacion_segura(
                    self._controladores['monitoreo'].iniciar_monitoreo
                )
            else:
                return {'exito': False, 'error': 'Controlador de monitoreo no disponible'}
                
        except Exception as e:
            return {'exito': False, 'error': f'Error iniciando monitoreo: {str(e)}'}
    
    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Implementación específica de finalización."""
        try:
            self.logger.info("Iniciando finalización del sistema")
            
            # Detener monitoreo
            if 'monitoreo' in self._controladores:
                self.ejecutar_operacion_segura(
                    self._controladores['monitoreo'].detener_monitoreo
                )
            
            # Finalizar controladores
            for nombre, controlador in self._controladores.items():
                try:
                    if hasattr(controlador, 'finalizar'):
                        if asyncio.iscoroutinefunction(controlador.finalizar):
                            await controlador.finalizar()
                        else:
                            controlador.finalizar()
                except Exception as e:
                    self.logger.warning(f"Error finalizando {nombre}: {e}")
            
            # Actualizar estado
            with self._lock:
                self._estado_sistema.update({
                    'iniciado': False,
                    'componentes_activos': 0
                })
            
            self.logger.info("Sistema finalizado correctamente")
            return {'exito': True, 'mensaje': 'Sistema finalizado correctamente'}
            
        except Exception as e:
            error_msg = f"Error durante finalización: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def obtener_estado_sistema_completo(self) -> Dict[str, Any]:
        """Obtener estado completo del sistema."""
        with self._lock:
            estado_base = self._estado_sistema.copy()
        
        # Obtener estado de controladores
        estado_controladores = {}
        for nombre, controlador in self._controladores.items():
            try:
                if hasattr(controlador, 'obtener_estado'):
                    estado_controladores[nombre] = controlador.obtener_estado()
                else:
                    estado_controladores[nombre] = {
                        'nombre': nombre,
                        'disponible': True,
                        'estado': 'activo'
                    }
            except Exception as e:
                estado_controladores[nombre] = {
                    'nombre': nombre,
                    'disponible': False,
                    'error': str(e)
                }
        
        # Obtener métricas del sistema
        metricas = self.obtener_metricas()
        
        # Verificación de salud
        salud_sistema = self.verificar_salud_sistema()
        
        return {
            'estado_general': estado_base,
            'controladores': estado_controladores,
            'metricas_sistema': metricas,
            'salud': salud_sistema,
            'configuracion': {
                'version': self.gestor_config.obtener('sistema.version'),
                'debug': self.gestor_config.obtener('sistema.debug'),
                'max_hilos': self.gestor_config.obtener('sistema.max_hilos')
            }
        }
    
    def verificar_salud_sistema(self) -> Dict[str, Any]:
        """Verificar estado de salud del sistema completo."""
        try:
            # Verificar salud de componentes
            componentes_saludables = 0
            total_componentes = len(self._controladores)
            problemas = []
            
            for nombre, controlador in self._controladores.items():
                try:
                    if hasattr(controlador, 'verificar_salud'):
                        salud = controlador.verificar_salud()
                        if salud.get('estado_salud') in ['excelente', 'bueno']:
                            componentes_saludables += 1
                        elif salud.get('estado_salud') in ['critico', 'inactivo']:
                            problemas.append(f"Componente {nombre}: {salud.get('estado_salud')}")
                    else:
                        componentes_saludables += 1  # Asumir saludable si no hay verificación
                except Exception as e:
                    problemas.append(f"Error verificando {nombre}: {str(e)}")
            
            # Calcular porcentaje de salud
            if total_componentes > 0:
                porcentaje_salud = (componentes_saludables / total_componentes) * 100
            else:
                porcentaje_salud = 0
            
            # Determinar estado general
            if porcentaje_salud >= 90:
                estado_general = 'excelente'
            elif porcentaje_salud >= 75:
                estado_general = 'bueno'
            elif porcentaje_salud >= 50:
                estado_general = 'regular'
            else:
                estado_general = 'critico'
            
            # Actualizar métricas
            with self._lock:
                self._metricas_sistema['componentes_saludables'] = componentes_saludables
                self._estado_sistema['ultima_verificacion_salud'] = datetime.now().isoformat()
            
            return {
                'estado_general': estado_general,
                'porcentaje_salud': round(porcentaje_salud, 2),
                'componentes_saludables': componentes_saludables,
                'total_componentes': total_componentes,
                'problemas': problemas,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'estado_general': 'error',
                'error': f'Error verificando salud: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def ejecutar_analisis_completo(self) -> Dict[str, Any]:
        """Ejecutar análisis completo del sistema."""
        return self.ejecutar_operacion_segura(self._ejecutar_analisis_completo_impl)
    
    def _ejecutar_analisis_completo_impl(self) -> Dict[str, Any]:
        """Implementación del análisis completo."""
        self.logger.info("Iniciando análisis completo del sistema")
        resultados = {}
        
        # Análisis de auditoría
        if 'auditoria' in self._controladores:
            self.logger.debug("Ejecutando auditoría completa")
            resultados['auditoria'] = self.ejecutar_operacion_segura(
                self._controladores['auditoria'].ejecutar_auditoria_completa
            )
        
        # Análisis de escaneo
        if 'escaneador' in self._controladores:
            self.logger.debug("Ejecutando escaneo completo")
            resultados['escaneo'] = self.ejecutar_operacion_segura(
                self._controladores['escaneador'].ejecutar_escaneo_completo
            )
        
        # Información del sistema
        if 'utilidades' in self._controladores:
            self.logger.debug("Obteniendo información del sistema")
            resultados['sistema'] = self.ejecutar_operacion_segura(
                self._controladores['utilidades'].obtener_informacion_hardware
            )
        
        # Generar reporte final
        if 'reportes' in self._controladores:
            self.logger.debug("Generando reporte final")
            reporte_final = self.ejecutar_operacion_segura(
                self._controladores['reportes'].generar_reporte_completo,
                resultados.get('escaneo', {}),
                {},  # datos_monitoreo
                resultados.get('sistema', {})
            )
        else:
            reporte_final = {'exito': False, 'error': 'Controlador de reportes no disponible'}
        
        self.logger.info("Análisis completo finalizado")
        
        return {
            'exito': True,
            'resultados_individuales': resultados,
            'reporte_generado': reporte_final,
            'timestamp': datetime.now().isoformat()
        }
    
    def inicializar_sistema(self) -> Dict[str, Any]:
        """Inicializar sistema de forma síncrona."""
        try:
            # Ejecutar inicialización asíncrona en loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            resultado = loop.run_until_complete(self.inicializar())
            loop.close()
            
            return resultado
            
        except Exception as e:
            return {'exito': False, 'error': f'Error en inicialización síncrona: {str(e)}'}
    
    def detener_sistema(self) -> Dict[str, Any]:
        """Detener sistema de forma síncrona."""
        try:
            # Ejecutar finalización asíncrona en loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            resultado = loop.run_until_complete(self.finalizar())
            loop.close()
            
            return resultado
            
        except Exception as e:
            return {'exito': False, 'error': f'Error en detención síncrona: {str(e)}'}
    
    def obtener_controlador(self, nombre: str):
        """
        Obtener referencia a un controlador específico con validación.
        KALI OPTIMIZATION: Solo permite acceso a controladores autorizados.
        """
        # SECURITY FIX: Validar nombre del controlador
        validacion = self._validar_nombre_controlador(nombre)
        if not validacion['valido']:
            self.logger.warning(f"Acceso a controlador rechazado: {validacion['error']}")
            return None
        
        nombre_seguro = validacion['nombre_sanitizado']
        return self._controladores.get(nombre_seguro)
    
    def listar_controladores(self) -> List[str]:
        """Listar nombres de controladores disponibles."""
        return list(self._controladores.keys())
    
    def obtener_configuracion(self, clave: Optional[str] = None) -> Any:
        """
        Obtener configuración del sistema con validación.
        KALI OPTIMIZATION: Solo permite acceso a configuraciones seguras.
        """
        if clave:
            # SECURITY FIX: Validar clave de configuración
            validacion = self._validar_clave_configuracion(clave)
            if not validacion['valido']:
                self.logger.warning(f"Acceso a configuración rechazado: {validacion['error']}")
                return None
            
            clave_segura = validacion['clave_sanitizada']
            return self.gestor_config.obtener(clave_segura)
        else:
            # SECURITY: Solo retornar configuraciones permitidas
            config_completa = self.gestor_config.obtener_configuracion_completa()
            config_filtrada = {}
            for key in self._config_keys_permitidas:
                if key in config_completa:
                    config_filtrada[key] = config_completa[key]
            return config_filtrada
    
    def establecer_configuracion(self, clave: str, valor: Any) -> bool:
        """
        Establecer configuración del sistema con validación.
        KALI OPTIMIZATION: Solo permite modificar configuraciones seguras.
        """
        # SECURITY FIX: Validar clave de configuración
        validacion = self._validar_clave_configuracion(clave)
        if not validacion['valido']:
            self.logger.warning(f"Modificación de configuración rechazada: {validacion['error']}")
            return False
        
        clave_segura = validacion['clave_sanitizada']
        
        # SECURITY: Validar tipo de valor según la clave
        valores_permitidos = {
            'sistema.log_level': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            'sistema.timeout': lambda x: isinstance(x, (int, float)) and 1 <= x <= 300,
            'sistema.max_threads': lambda x: isinstance(x, int) and 1 <= x <= 100,
        }
        
        if clave_segura in valores_permitidos:
            validador = valores_permitidos[clave_segura]
            if isinstance(validador, list):
                if valor not in validador:
                    self.logger.warning(f"Valor no permitido para {clave_segura}: {valor}")
                    return False
            elif callable(validador):
                if not validador(valor):
                    self.logger.warning(f"Valor inválido para {clave_segura}: {valor}")
                    return False
        
        return self.gestor_config.establecer(clave_segura, valor)
    
    def obtener_metricas_sistema(self) -> Dict[str, Any]:
        """Obtener métricas específicas del sistema."""
        with self._lock:
            metricas_sistema = self._metricas_sistema.copy()
        
        # Añadir métricas calculadas
        if self._estado_sistema.get('tiempo_inicio'):
            try:
                inicio = datetime.fromisoformat(self._estado_sistema['tiempo_inicio'])
                tiempo_actividad = (datetime.now() - inicio).total_seconds()
                metricas_sistema['tiempo_actividad'] = tiempo_actividad
            except Exception:
                metricas_sistema['tiempo_actividad'] = 0
        
        # Añadir métricas de controladores
        metricas_controladores = {}
        for nombre, controlador in self._controladores.items():
            try:
                if hasattr(controlador, 'obtener_metricas'):
                    metricas_controladores[nombre] = controlador.obtener_metricas()
            except Exception:
                pass
        
        metricas_sistema['controladores'] = metricas_controladores
        
        return metricas_sistema
    
    # ======= MÉTODOS PARA ACCESO A FUNCIONALIDAD AVANZADA =======
    
    def obtener_escaneador_avanzado(self):
        """Obtener acceso al escaneador avanzado."""
        try:
            return self._controladores['escaneador'].escaneador
        except:
            return None
    
    def obtener_monitor_avanzado(self):
        """Obtener acceso al monitor avanzado."""
        try:
            return self._controladores['monitoreo'].monitor
        except:
            return None
    
    def obtener_siem_avanzado(self):
        """Obtener acceso al SIEM avanzado."""
        try:
            # Intentar desde el escaneador primero
            if hasattr(self._controladores['escaneador'], 'siem'):
                return self._controladores['escaneador'].siem
            # Luego desde el monitor
            elif hasattr(self._controladores['monitoreo'], 'siem'):
                return self._controladores['monitoreo'].siem
        except:
            pass
        return None
    
    def ejecutar_escaneo_avanzado(self, objetivo: str, tipo_escaneo: str = "PUERTOS_AVANZADO") -> Dict[str, Any]:
        """
        Ejecutar escaneo avanzado con validación de seguridad.
        KALI OPTIMIZATION: Validación robusta antes de delegar a controladores.
        """
        # SECURITY FIX: Validar objetivo antes de cualquier operación
        validacion = self._validar_objetivo_principal(objetivo)
        if not validacion['valido']:
            self.logger.warning(f"Objetivo rechazado en escaneo avanzado: {validacion['error']}")
            return {
                'exito': False,
                'error': f"Objetivo no válido: {validacion['error']}",
                'objetivo_rechazado': "[SANITIZADO]"  # SECURITY: No loggear objetivo sin validar
            }
        
        objetivo_seguro = validacion['objetivo_sanitizado']
        
        try:
            escaneador = self.obtener_escaneador_avanzado()
            if escaneador and hasattr(escaneador, 'escanear_avanzado'):
                from aresitos.modelo.modelo_escaneador import TipoEscaneo
                
                # SECURITY: Validar tipo de escaneo
                tipos_permitidos = {
                    "PUERTOS_BASICO": TipoEscaneo.PUERTOS_BASICO,
                    "PUERTOS_AVANZADO": TipoEscaneo.PUERTOS_AVANZADO,
                    "VULNERABILIDADES": TipoEscaneo.VULNERABILIDADES,
                    "RED_COMPLETA": TipoEscaneo.RED_COMPLETA,
                    "SERVICIOS": TipoEscaneo.SERVICIOS,
                    "OS_DETECTION": TipoEscaneo.OS_DETECTION,
                    "STEALTH": TipoEscaneo.STEALTH
                }
                
                if tipo_escaneo not in tipos_permitidos:
                    return {
                        'exito': False,
                        'error': f'Tipo de escaneo no permitido: {tipo_escaneo}',
                        'tipos_permitidos': list(tipos_permitidos.keys())
                    }
                
                tipo_enum = tipos_permitidos[tipo_escaneo]
                resultado = escaneador.escanear_avanzado(objetivo_seguro, tipo_enum)  # SECURITY: Usar objetivo validado
                
                # Convertir resultado a formato de diccionario para la interfaz
                return {
                    'exito': True,
                    'objetivo': objetivo_seguro,  # SECURITY: Usar objetivo validado
                    'objetivo_validacion': validacion,  # SECURITY: Info de validación
                    'tipo_escaneo': resultado.tipo_escaneo.value,
                    'inicio': resultado.inicio.isoformat(),
                    'fin': resultado.fin.isoformat() if resultado.fin else None,
                    'estado': resultado.estado,
                    'puertos_abiertos': resultado.puertos_abiertos or [],
                    'vulnerabilidades': [
                        {
                            'tipo': v.tipo,
                            'descripcion': v.descripcion,
                            'criticidad': v.criticidad.value,
                            'puerto': v.puerto,
                            'servicio': v.servicio,
                            'cve': v.cve,
                            'solucion': v.solucion
                        } for v in (resultado.vulnerabilidades or [])
                    ],
                    'servicios_detectados': resultado.servicios_detectados or [],
                    'sistema_operativo': resultado.sistema_operativo,
                    'errores': resultado.errores or []
                }
            else:
                # Fallback al método original
                return self._controladores['escaneador'].ejecutar_escaneo_basico(objetivo)
                
        except Exception as e:
            self.logger.error(f"Error en escaneo avanzado: {e}")
            return {
                'exito': False,
                'error': str(e)
            }
    
    def obtener_procesos_sospechosos(self) -> List[Dict[str, Any]]:
        """Obtener lista de procesos sospechosos detectados."""
        try:
            monitor = self.obtener_monitor_avanzado()
            if monitor and hasattr(monitor, 'obtener_procesos_sospechosos'):
                return monitor.obtener_procesos_sospechosos()
        except:
            pass
        return []
    
    def obtener_alertas_seguridad(self) -> List[Dict[str, Any]]:
        """Obtener alertas de seguridad del SIEM."""
        try:
            siem = self.obtener_siem_avanzado()
            if siem and hasattr(siem, 'obtener_alertas_activas'):
                alertas = siem.obtener_alertas_activas()
                return [
                    {
                        'id': alerta.id,
                        'titulo': alerta.titulo,
                        'descripcion': alerta.descripcion,
                        'severidad': alerta.severidad.value,
                        'timestamp': alerta.timestamp.isoformat(),
                        'estado': alerta.estado
                    } for alerta in alertas
                ]
        except:
            pass
        return []
    
    def generar_reporte_completo(self) -> str:
        """Generar reporte completo del sistema."""
        try:
            reportes = []
            
            # Reporte del escaneador
            escaneador = self.obtener_escaneador_avanzado()
            if escaneador and hasattr(escaneador, 'obtener_estadisticas_escaneos'):
                stats = escaneador.obtener_estadisticas_escaneos()
                reportes.append(f"##  ESCANEADOR\n- Escaneos activos: {stats.get('escaneos_activos', 0)}\n- Herramientas disponibles: {stats.get('herramientas_disponibles', 0)}/{stats.get('total_herramientas', 0)}")
            
            # Reporte del monitor
            monitor = self.obtener_monitor_avanzado()
            if monitor and hasattr(monitor, 'generar_reporte_monitor'):
                reporte_monitor = monitor.generar_reporte_monitor()
                reportes.append(reporte_monitor)
            
            # Reporte del SIEM
            siem = self.obtener_siem_avanzado()
            if siem and hasattr(siem, 'generar_reporte_siem'):
                reporte_siem = siem.generar_reporte_siem()
                reportes.append(reporte_siem)
            
            if reportes:
                return "\n\n".join(reportes)
            else:
                return "#  REPORTE BÁSICO - ARES AEGIS\n\nSistema funcionando con funcionalidad básica."
                
        except Exception as e:
            return f"#  ERROR GENERANDO REPORTE\n\n{str(e)}"
    
    def obtener_metricas_avanzadas(self) -> Dict[str, Any]:
        """Obtener métricas avanzadas de todos los componentes."""
        metricas = {
            'sistema': self.obtener_metricas(),
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Métricas del escaneador
            escaneador = self.obtener_escaneador_avanzado()
            if escaneador and hasattr(escaneador, 'obtener_estadisticas_escaneos'):
                metricas['escaneador'] = escaneador.obtener_estadisticas_escaneos()
            
            # Métricas del monitor
            monitor = self.obtener_monitor_avanzado()
            if monitor and hasattr(monitor, 'obtener_metricas_resumen'):
                metricas['monitor'] = monitor.obtener_metricas_resumen()
            
            # Métricas del SIEM
            siem = self.obtener_siem_avanzado()
            if siem and hasattr(siem, 'obtener_metricas'):
                metricas['siem'] = siem.obtener_metricas()
        except Exception as e:
            metricas['error_metricas_avanzadas'] = str(e)
        
        return metricas

    # === MÉTODOS DE ACCESO A DATOS ===
    
    def obtener_wordlists_disponibles(self) -> dict:
        """Obtiene todas las wordlists disponibles"""
        try:
            if self.modelo.gestor_wordlists:
                return {
                    'exito': True,
                    'wordlists': self.modelo.gestor_wordlists.wordlists_predefinidas,
                    'total': len(self.modelo.gestor_wordlists.wordlists_predefinidas)
                }
            else:
                return {'exito': False, 'error': 'Gestor de wordlists no disponible'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def obtener_diccionarios_disponibles(self) -> dict:
        """Obtiene todos los diccionarios disponibles"""
        try:
            if self.modelo.gestor_diccionarios:
                return {
                    'exito': True,
                    'diccionarios': self.modelo.gestor_diccionarios.diccionarios_predefinidos,
                    'total': len(self.modelo.gestor_diccionarios.diccionarios_predefinidos)
                }
            else:
                return {'exito': False, 'error': 'Gestor de diccionarios no disponible'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def buscar_en_wordlists(self, termino: str, categoria: Optional[str] = None) -> dict:
        """Busca un término en las wordlists"""
        try:
            if self.modelo.gestor_wordlists:
                return self.modelo.gestor_wordlists.buscar_coincidencias(termino, categoria)
            else:
                return {'exito': False, 'error': 'Gestor de wordlists no disponible'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def buscar_en_diccionarios(self, termino: str, categoria: Optional[str] = None) -> dict:
        """Busca un término en los diccionarios"""
        try:
            if self.modelo.gestor_diccionarios:
                return self.modelo.gestor_diccionarios.buscar_en_diccionarios(termino, categoria)
            else:
                return {'exito': False, 'error': 'Gestor de diccionarios no disponible'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def obtener_estadisticas_datos(self) -> dict:
        """Obtiene estadísticas completas de todos los datos cargados"""
        try:
            estadisticas = self.modelo.obtener_estadisticas_generales()
            verificacion = self.modelo.verificar_integridad_datos()
            
            return {
                'exito': True,
                'estadisticas': estadisticas,
                'integridad': verificacion,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def recargar_datos_automaticos(self) -> dict:
        """Recarga todos los datos automáticos desde las carpetas data/"""
        try:
            self.logger.info("Recargando datos automáticos...")
            
            # Reinicializar gestores
            self.modelo._inicializar_gestores()
            
            estadisticas = self.modelo.obtener_estadisticas_generales()
            
            self.logger.info("Datos automáticos recargados exitosamente")
            return {
                'exito': True,
                'mensaje': 'Datos recargados exitosamente',
                'estadisticas': estadisticas
            }
        except Exception as e:
            self.logger.error(f"Error recargando datos: {e}")
            return {'exito': False, 'error': str(e)}

    # === PROPIEDADES DE ACCESO A CONTROLADORES ===
    
    @property
    def controlador_wordlists(self):
        """Acceso al controlador de wordlists."""
        return self._controladores.get('wordlists')
    
    @property
    def controlador_diccionarios(self):
        """Acceso al controlador de diccionarios."""
        return self._controladores.get('diccionarios')
    
    @property
    def controlador_escaneador(self):
        """Acceso al controlador de escaneador."""
        return self._controladores.get('escaneador')
    
    @property
    def controlador_monitoreo(self):
        """Acceso al controlador de monitoreo."""
        return self._controladores.get('monitoreo')
    
    @property
    def controlador_utilidades(self):
        """Acceso al controlador de utilidades."""
        return self._controladores.get('utilidades')
    
    @property
    def controlador_auditoria(self):
        """Acceso al controlador de auditoría."""
        return self._controladores.get('auditoria')
    
    @property
    def controlador_herramientas(self):
        """Acceso al controlador de herramientas."""
        return self._controladores.get('herramientas')
    
    @property
    def controlador_reportes(self):
        """Acceso al controlador de reportes."""
        return self._controladores.get('reportes')
    
    @property
    def controlador_fim(self):
        """Acceso al controlador de FIM."""
        return self._controladores.get('fim')
    
    @property
    def controlador_siem(self):
        """Acceso al controlador de SIEM."""
        return self._controladores.get('siem')
    
    @property
    def controlador_actualizacion(self):
        """Acceso al controlador de actualización."""
        return self._controladores.get('actualizacion')

# RESUMEN TÉCNICO: Controlador Principal avanzado para Ares Aegis con arquitectura asíncrona,
# gestión centralizada de configuración, coordinación de múltiples controladores especializados,
# sistema de métricas en tiempo real, verificación de salud automática, logging profesional
# y manejo robusto de errores. Implementa patrón Facade con inicialización por fases siguiendo
# principios SOLID para escalabilidad y mantenibilidad en entornos de ciberseguridad.
