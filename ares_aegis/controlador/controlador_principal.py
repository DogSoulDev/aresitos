# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal
Controlador central que coordina todos los módulos del sistema
"""

import asyncio
import logging
import threading
import time
from typing import Dict, Any, Optional, List
from datetime import datetime

from ares_aegis.controladores.controlador_base import ControladorBase
from ares_aegis.controladores.gestor_configuracion import GestorConfiguracion
from ares_aegis.controlador.controlador_escaneo import ControladorEscaneo
from ares_aegis.controlador.controlador_monitoreo import ControladorMonitoreo
from ares_aegis.controlador.controlador_utilidades import ControladorUtilidades
from ares_aegis.controlador.controlador_auditoria import ControladorAuditoria
from ares_aegis.controlador.controlador_herramientas import ControladorHerramientas
from ares_aegis.controlador.controlador_reportes import ControladorReportes

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
        
        # Controladores especializados
        self._controladores = {}
        self._inicializar_controladores()
        
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
        
        # Lock para operaciones thread-safe
        self._lock = threading.Lock()
        
        # Configurar logging avanzado
        self._configurar_logging_avanzado()
        
        self.logger.info("Controlador Principal de Ares Aegis inicializado")
    
    def _inicializar_controladores(self) -> None:
        """Inicializar todos los controladores especializados."""
        try:
            self._controladores = {
                'escaneo': ControladorEscaneo(self.modelo),
                'monitoreo': ControladorMonitoreo(self.modelo),
                'utilidades': ControladorUtilidades(self.modelo),
                'auditoria': ControladorAuditoria(self.modelo),
                'herramientas': ControladorHerramientas(self.modelo),
                'reportes': ControladorReportes(self.modelo)
            }
            
            self.logger.info(f"Inicializados {len(self._controladores)} controladores especializados")
            
        except Exception as e:
            self.logger.error(f"Error inicializando controladores: {e}")
            self._controladores = {}
    
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
        if 'escaneo' in self._controladores:
            self.logger.debug("Ejecutando escaneo completo")
            resultados['escaneo'] = self.ejecutar_operacion_segura(
                self._controladores['escaneo'].ejecutar_escaneo_completo
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
        """Obtener referencia a un controlador específico."""
        return self._controladores.get(nombre)
    
    def listar_controladores(self) -> List[str]:
        """Listar nombres de controladores disponibles."""
        return list(self._controladores.keys())
    
    def obtener_configuracion(self, clave: Optional[str] = None) -> Any:
        """Obtener configuración del sistema."""
        if clave:
            return self.gestor_config.obtener(clave)
        else:
            return self.gestor_config.obtener_configuracion_completa()
    
    def establecer_configuracion(self, clave: str, valor: Any) -> bool:
        """Establecer configuración del sistema."""
        return self.gestor_config.establecer(clave, valor)
    
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
            return self._controladores['escaneo'].escaneador
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
            if hasattr(self._controladores['escaneo'], 'siem'):
                return self._controladores['escaneo'].siem
            # Luego desde el monitor
            elif hasattr(self._controladores['monitoreo'], 'siem'):
                return self._controladores['monitoreo'].siem
        except:
            pass
        return None
    
    def ejecutar_escaneo_avanzado(self, objetivo: str, tipo_escaneo: str = "PUERTOS_AVANZADO") -> Dict[str, Any]:
        """Ejecutar escaneo avanzado usando la nueva funcionalidad."""
        try:
            escaneador = self.obtener_escaneador_avanzado()
            if escaneador and hasattr(escaneador, 'escanear_avanzado'):
                from ares_aegis.modelo.modelo_escaneador import TipoEscaneo
                
                # Mapear string a enum
                tipo_map = {
                    "PUERTOS_BASICO": TipoEscaneo.PUERTOS_BASICO,
                    "PUERTOS_AVANZADO": TipoEscaneo.PUERTOS_AVANZADO,
                    "VULNERABILIDADES": TipoEscaneo.VULNERABILIDADES,
                    "RED_COMPLETA": TipoEscaneo.RED_COMPLETA,
                    "SERVICIOS": TipoEscaneo.SERVICIOS,
                    "OS_DETECTION": TipoEscaneo.OS_DETECTION,
                    "STEALTH": TipoEscaneo.STEALTH
                }
                
                tipo_enum = tipo_map.get(tipo_escaneo, TipoEscaneo.PUERTOS_AVANZADO)
                resultado = escaneador.escanear_avanzado(objetivo, tipo_enum)
                
                # Convertir resultado a formato de diccionario para la interfaz
                return {
                    'exito': True,
                    'objetivo': resultado.objetivo,
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
                return self._controladores['escaneo'].ejecutar_escaneo_basico(objetivo)
                
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
                reportes.append(f"## 🔍 ESCANEADOR\n- Escaneos activos: {stats.get('escaneos_activos', 0)}\n- Herramientas disponibles: {stats.get('herramientas_disponibles', 0)}/{stats.get('total_herramientas', 0)}")
            
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
                return "# 📊 REPORTE BÁSICO - ARES AEGIS\n\nSistema funcionando con funcionalidad básica."
                
        except Exception as e:
            return f"# ❌ ERROR GENERANDO REPORTE\n\n{str(e)}"
    
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

# RESUMEN TÉCNICO: Controlador Principal avanzado para Ares Aegis con arquitectura asíncrona,
# gestión centralizada de configuración, coordinación de múltiples controladores especializados,
# sistema de métricas en tiempo real, verificación de salud automática, logging profesional
# y manejo robusto de errores. Implementa patrón Facade con inicialización por fases siguiendo
# principios SOLID para escalabilidad y mantenibilidad en entornos de ciberseguridad.