# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.

Ares Aegis - Controlador Principal Simplificado
Sistema principal de coordinación simplificado y optimizado para Kali Linux
"""

import threading
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.controlador.controlador_configuracion import GestorConfiguracion
from aresitos.controlador.controlador_componentes import GestorComponentes

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
            self.logger.error(
                f"Error inicializando gestor de componentes: {e}"
            )
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
            from .controlador_herramientas import ControladorHerramientas
            from .controlador_fim import ControladorFIM
            from .controlador_siem import ControladorSIEM
            from .controlador_cuarentena import ControladorCuarentena

            self.controlador_escaneador = ControladorEscaneo(modelo_principal)
            self.controlador_auditoria = ControladorAuditoria(modelo_principal)
            self.controlador_reportes = ControladorReportes(modelo_principal)
            self.controlador_monitoreo = ControladorMonitoreo(modelo_principal)
            self.controlador_herramientas = ControladorHerramientas(
                modelo_principal
            )
            self.controlador_fim = ControladorFIM(modelo_principal)
            self.controlador_siem = ControladorSIEM(modelo_principal)
            self.controlador_cuarentena = ControladorCuarentena(
                modelo_principal
            )

            self.logger.info(
                "Controladores específicos inicializados correctamente."
            )
        except Exception as e:
            import traceback
            mensaje_error = f"[ARESITOS] Error crítico al inicializar los controladores específicos: {e}\n" \
                            + traceback.format_exc()
            print(mensaje_error)
            self.logger.error(mensaje_error)
            self.controlador_escaneador = None
            self.controlador_auditoria = None
            self.controlador_reportes = None
            self.controlador_monitoreo = None
            self.controlador_herramientas = None
            self.controlador_fim = None
            self.controlador_siem = None
            self.controlador_cuarentena = None
        
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
                resultado_basico = self.gestor_componentes.inicializar_componentes_ordenado()
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
            
            # 4. Configurar conexiones entre controladores
            resultado_conexiones = self.configurar_conexiones_controladores()
            
            resultado_final = {
                'exito': True,
                'mensaje': 'Controlador principal inicializado correctamente',
                'timestamp': datetime.now().isoformat(),
                'componentes_activos': self._estado_sistema['componentes_activos'],
                'conexiones_configuradas': resultado_conexiones.get('conexiones_configuradas', 0)
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
            
            verificaciones: Dict[str, Any] = {
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
            
            self.logger.info(f"Modo de operación cambiado: {modo_anterior} → {nuevo_modo}")
            
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
                self.logger.info(f"Componentes finalizados: {resultado_finalizacion}")
            
            # Actualizar estado
            with self._lock:
                self._estado_sistema['iniciado'] = False
                self._estado_sistema['tiempo_inicio'] = None
                self._operaciones_activas.clear()
            
            self.logger.info("Controlador principal finalizado")
            return {
                'exito': True,
                'mensaje': 'Controlador principal finalizado correctamente',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error finalizando controlador principal: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def configurar_conexiones_controladores(self):
        """Configurar conexiones entre controladores para integración."""
        try:
            self.logger.info("Configurando conexiones entre controladores...")
            
            conexiones_exitosas = 0
            
            # Configurar conexión SIEM → Cuarentena + FIM
            if self.controlador_siem and self.controlador_cuarentena and self.controlador_fim:
                try:
                    self.controlador_siem.configurar_referencias_controladores(
                        controlador_cuarentena=self.controlador_cuarentena,
                        controlador_fim=self.controlador_fim
                    )
                    conexiones_exitosas += 1
                    self.logger.info("SIEM → Cuarentena + FIM configurado")
                except Exception as e:
                    self.logger.error(f"Error configurando SIEM → Cuarentena + FIM: {e}")
            
            # Configurar conexión FIM → SIEM
            if self.controlador_fim and self.controlador_siem:
                try:
                    self.controlador_fim.configurar_notificacion_siem(self.controlador_siem)
                    conexiones_exitosas += 1
                    self.logger.info("FIM → SIEM configurado")
                except Exception as e:
                    self.logger.error(f"Error configurando FIM → SIEM: {e}")
            
            # Configurar conexión Escaneador → SIEM + Cuarentena + FIM
            if hasattr(self, 'controlador_escaneador') and self.controlador_escaneador:
                try:
                    if hasattr(self.controlador_escaneador, 'configurar_integraciones'):
                        self.controlador_escaneador.configurar_integraciones(
                            controlador_siem=self.controlador_siem,
                            controlador_fim=self.controlador_fim,
                            controlador_cuarentena=self.controlador_cuarentena
                        )
                        conexiones_exitosas += 1
                        self.logger.info("Escaneador → SIEM + FIM + Cuarentena configurado")
                except Exception as e:
                    self.logger.error(f"Error configurando integraciones del escaneador: {e}")
            
            # Verificar integraciones activas
            self.logger.info(f"Conexiones configuradas exitosamente: {conexiones_exitosas}")
            
            return {
                'exito': True,
                'conexiones_configuradas': conexiones_exitosas,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error configurando conexiones entre controladores: {e}"
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
    
    def obtener_wordlists_disponibles(self) -> Dict[str, Any]:
        """Obtener información de wordlists disponibles."""
        try:
            if hasattr(self.modelo_principal, 'gestor_wordlists'):
                gestor = self.modelo_principal.gestor_wordlists
                if hasattr(gestor, 'obtener_informacion_completa'):
                    return gestor.obtener_informacion_completa()
                elif hasattr(gestor, 'wordlists_predefinidas'):
                    wordlists = gestor.wordlists_predefinidas
                    return {
                        'total_wordlists': len(wordlists),
                        'categorias': list(wordlists.keys()),
                        'total_entradas': sum(len(wl) for wl in wordlists.values()),
                        'disponibles': True
                    }
            
            # Intentar desde controlador de wordlists si existe en gestor de componentes  
            # Por ahora usamos datos básicos del modelo
            return {
                'total_wordlists': 0,
                'categorias': [],
                'total_entradas': 0,
                'disponibles': False,
                'mensaje': 'Controlador de wordlists no configurado en esta versión'
            }
            
        except Exception as e:
            self.logger.error(f"Error obteniendo wordlists disponibles: {e}")
            return {
                'total_wordlists': 0,
                'categorias': [],
                'total_entradas': 0,
                'disponibles': False,
                'error': str(e)
            }
    
    def obtener_diccionarios_disponibles(self) -> Dict[str, Any]:
        """Obtener información de diccionarios disponibles."""
        try:
            if hasattr(self.modelo_principal, 'gestor_diccionarios'):
                gestor = self.modelo_principal.gestor_diccionarios
                if hasattr(gestor, 'obtener_informacion_completa'):
                    return gestor.obtener_informacion_completa()
                elif hasattr(gestor, 'diccionarios_cargados'):
                    diccionarios = gestor.diccionarios_cargados
                    return {
                        'total_diccionarios': len(diccionarios),
                        'categorias': list(diccionarios.keys()),
                        'total_entradas': sum(len(d) for d in diccionarios.values() if isinstance(d, dict)),
                        'disponibles': True
                    }
            
            # Intentar desde controlador de diccionarios si existe en gestor de componentes
            # Por ahora usamos datos básicos del modelo
            return {
                'total_diccionarios': 0,
                'categorias': [],
                'total_entradas': 0,
                'disponibles': False,
                'mensaje': 'Controlador de diccionarios no configurado en esta versión'
            }
            
        except Exception as e:
            self.logger.error(f"Error obteniendo diccionarios disponibles: {e}")
            return {
                'total_diccionarios': 0,
                'categorias': [],
                'total_entradas': 0,
                'disponibles': False,
                'error': str(e)
            }
    
    def estabilizar_sistema_completo(self):
        """Issue 23/24: Estabilización final del sistema - Verificar y estabilizar todos los componentes del sistema"""
        try:
            estabilizaciones = []
            
            # Verificar estado de todos los controladores
            controladores = [
                ('dashboard', getattr(self, 'controlador_dashboard', None)),
                ('escaneo', self.controlador_escaneador),
                ('monitoreo', self.controlador_monitoreo),
                ('auditoria', self.controlador_auditoria),
                ('reportes', self.controlador_reportes),
                ('fim', self.controlador_fim),
                ('siem', self.controlador_siem)
            ]
            
            for nombre, controlador in controladores:
                if controlador is not None:
                    # Verificar que el controlador responde
                    try:
                        if hasattr(controlador, 'verificar_estado'):
                            estado = controlador.verificar_estado()
                            estabilizaciones.append(f"{nombre}: {estado}")
                        else:
                            estabilizaciones.append(f"{nombre}: Operativo")
                    except Exception as e:
                        estabilizaciones.append(f"{nombre}: Error - {str(e)}")
                else:
                    estabilizaciones.append(f"{nombre}: No disponible")
            
            # Verificar memoria y recursos
            try:
                import gc
                collected = gc.collect()
                estabilizaciones.append(f"Memoria: {collected} objetos liberados")
            except Exception as e:
                estabilizaciones.append(f"Memoria: Error - {str(e)}")
            
            # Verificar integraciones activas
            integraciones_activas = 0
            try:
                resultado_conexiones = self.configurar_conexiones_controladores()
                if resultado_conexiones.get('exito'):
                    integraciones_activas = resultado_conexiones.get('conexiones_configuradas', 0)
            except Exception as e:
                estabilizaciones.append(f"Integraciones: Error - {str(e)}")
            
            estabilizaciones.append(f"Integraciones: {integraciones_activas} configuradas")
            
            # Log resultado
            self.logger.info(f"Estabilización completada: {len(estabilizaciones)} verificaciones")
            for est in estabilizaciones:
                self.logger.debug(f"  {est}")
            
            return {
                'exito': True,
                'estabilizaciones': estabilizaciones,
                'total_verificaciones': len(estabilizaciones)
            }
            
        except Exception as e:
            self.logger.error(f"Error en estabilización del sistema: {e}")
            return {
                'exito': False,
                'error': str(e),
                'estabilizaciones': ['Error general en estabilización']
            }

