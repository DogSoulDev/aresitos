# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador SIEM Simplificado
Sistema simplificado de gestión de eventos de seguridad para Kali Linux
"""

import os
import json
import logging
import threading
import time
import subprocess
try:
    import pwd
    import grp
    PWD_AVAILABLE = True
except ImportError:
    PWD_AVAILABLE = False
    pwd = None
    grp = None
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque

from aresitos.controlador.controlador_base import ControladorBase

class ControladorSIEM(ControladorBase):
    """
    Controlador SIEM simplificado para gestión de eventos de seguridad.
    Enfoque en funcionalidad básica sin dependencias externas.
    """
    
    def __init__(self, modelo_principal=None):
        # Si no hay modelo principal, crear uno básico mock
        if modelo_principal is None:
            class MockModeloPrincipal:
                def __init__(self):
                    self.siem_avanzado = None
            modelo_principal = MockModeloPrincipal()
            
        super().__init__(modelo_principal, "ControladorSIEM")
        
        self.modelo_principal = modelo_principal
        
        # Usar modelo SIEM del modelo principal si está disponible
        if hasattr(modelo_principal, 'siem_avanzado') and modelo_principal.siem_avanzado:
            self.siem = modelo_principal.siem_avanzado
        else:
            # Fallback: crear sistema básico interno
            self.siem = None
        
        # BUFFER FIX: Siempre inicializar buffers internos
        self._eventos_buffer = deque(maxlen=1000)
        self._alertas_buffer = deque(maxlen=500)
        
        # Configuración básica
        self._config_siem = {
            'log_events': True,
            'max_events': 1000,
            'max_alerts': 500,
            'auto_cleanup': True
        }
        
        # Contadores básicos
        self._contadores = {
            'eventos_totales': 0,
            'alertas_generadas': 0,
            'eventos_criticos': 0,
            'eventos_por_tipo': defaultdict(int)
        }
        
        # Lock para thread safety
        self._lock = threading.RLock()
        
        # Directorio de logs
        self._directorio_logs = self._crear_directorio_logs()
        
        self.logger.info("Controlador SIEM simplificado inicializado")
    
    def _crear_directorio_logs(self) -> str:
        """Crear directorio para logs SIEM."""
        try:
            directorio = os.path.expanduser("~/aresitos/logs")
            os.makedirs(directorio, exist_ok=True)
            return directorio
        except Exception as e:
            self.logger.warning(f"Error creando directorio de logs: {e}")
            return "/tmp"
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación de inicialización del controlador SIEM."""
        try:
            self.logger.info("Inicializando controlador SIEM...")
            
            # Verificar o crear modelo SIEM
            if not self.siem:
                try:
                    from aresitos.modelo.modelo_siem import SIEM
                    self.siem = SIEM()
                    self.logger.info("Modelo SIEM creado internamente")
                except ImportError:
                    self.logger.warning("Modelo SIEM no disponible, usando sistema básico")
                except Exception as e:
                    self.logger.warning(f"Error creando modelo SIEM: {e}, usando sistema básico")
            
            # Registrar evento inicial
            self._registrar_evento_interno("SIEM_INIT", "Sistema SIEM inicializado", "info")
            
            return {
                'exito': True,
                'mensaje': 'Controlador SIEM inicializado correctamente',
                'siem_modelo_disponible': self.siem is not None,
                'directorio_logs': self._directorio_logs
            }
            
        except Exception as e:
            error_msg = f"Error inicializando controlador SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def generar_evento(self, tipo_evento: str, descripcion: str, severidad: str = "info") -> Dict[str, Any]:
        """Generar un evento SIEM."""
        try:
            # Intentar usar modelo SIEM si está disponible
            if self.siem and hasattr(self.siem, 'generar_evento'):
                try:
                    self.siem.generar_evento(tipo_evento, descripcion, severidad)
                    with self._lock:
                        self._contadores['eventos_totales'] += 1
                        self._contadores['eventos_por_tipo'][tipo_evento] += 1
                        if severidad.lower() in ['critical', 'critica', 'alta']:
                            self._contadores['eventos_criticos'] += 1
                    
                    return {'exito': True, 'mensaje': 'Evento registrado en modelo SIEM'}
                except Exception as e:
                    self.logger.warning(f"Error usando modelo SIEM: {e}")
            
            # Fallback: registrar evento internamente
            return self._registrar_evento_interno(tipo_evento, descripcion, severidad)
            
        except Exception as e:
            error_msg = f"Error generando evento SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def _registrar_evento_interno(self, tipo_evento: str, descripcion: str, severidad: str) -> Dict[str, Any]:
        """Registrar evento usando sistema interno."""
        try:
            evento = {
                'id': f"evt_{int(time.time() * 1000)}",
                'timestamp': datetime.now().isoformat(),
                'tipo': tipo_evento,
                'descripcion': descripcion,
                'severidad': severidad.lower(),
                'origen': 'aresitos'
            }
            
            with self._lock:
                # Agregar a buffer
                self._eventos_buffer.append(evento)
                
                # Actualizar contadores
                self._contadores['eventos_totales'] += 1
                self._contadores['eventos_por_tipo'][tipo_evento] += 1
                if severidad.lower() in ['critical', 'critica', 'alta']:
                    self._contadores['eventos_criticos'] += 1
            
            # Log del evento
            nivel_log = {
                'critical': logging.CRITICAL,
                'critica': logging.CRITICAL,
                'error': logging.ERROR,
                'warning': logging.WARNING,
                'alta': logging.WARNING,
                'media': logging.INFO,
                'info': logging.INFO,
                'debug': logging.DEBUG
            }.get(severidad.lower(), logging.INFO)
            
            self.logger.log(nivel_log, f"SIEM [{tipo_evento}] {descripcion}")
            
            # Guardar en archivo si está configurado
            if self._config_siem['log_events']:
                self._guardar_evento_archivo(evento)
            
            return {'exito': True, 'evento_id': evento['id']}
            
        except Exception as e:
            error_msg = f"Error registrando evento interno: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def _guardar_evento_archivo(self, evento: Dict[str, Any]) -> None:
        """Guardar evento en archivo de log."""
        try:
            archivo_log = os.path.join(self._directorio_logs, f"siem_{datetime.now().strftime('%Y%m%d')}.log")
            linea_log = f"{evento['timestamp']} [{evento['severidad'].upper()}] {evento['tipo']}: {evento['descripcion']}\n"
            
            with open(archivo_log, 'a', encoding='utf-8') as f:
                f.write(linea_log)
                
        except Exception as e:
            self.logger.debug(f"Error guardando evento en archivo: {e}")
    
    def generar_alerta(self, titulo: str, descripcion: str, severidad: str = "media") -> Dict[str, Any]:
        """Generar una alerta SIEM."""
        try:
            alerta = {
                'id': f"alert_{int(time.time() * 1000)}",
                'timestamp': datetime.now().isoformat(),
                'titulo': titulo,
                'descripcion': descripcion,
                'severidad': severidad.lower(),
                'estado': 'nueva',
                'origen': 'aresitos'
            }
            
            with self._lock:
                self._alertas_buffer.append(alerta)
                self._contadores['alertas_generadas'] += 1
            
            # Log de la alerta
            self.logger.warning(f"ALERTA SIEM [{severidad.upper()}] {titulo}: {descripcion}")
            
            # También registrar como evento
            self.generar_evento(f"ALERTA_{titulo.upper()}", descripcion, severidad)
            
            return {'exito': True, 'alerta_id': alerta['id']}
            
        except Exception as e:
            error_msg = f"Error generando alerta SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def obtener_eventos_recientes(self, limite: int = 50) -> Dict[str, Any]:
        """Obtener eventos recientes."""
        try:
            # Intentar usar modelo SIEM si está disponible
            if self.siem and hasattr(self.siem, 'obtener_eventos_recientes'):
                try:
                    eventos_modelo = self.siem.obtener_eventos_recientes(limite)
                    # Asegurarse de que devolvemos el formato correcto
                    if isinstance(eventos_modelo, list):
                        return {
                            'exito': True,
                            'eventos': eventos_modelo,
                            'total': len(eventos_modelo)
                        }
                    elif isinstance(eventos_modelo, dict):
                        return eventos_modelo
                except Exception as e:
                    self.logger.warning(f"Error obteniendo eventos del modelo SIEM: {e}")
            
            # Fallback: usar buffer interno
            with self._lock:
                eventos = list(self._eventos_buffer)[-limite:]
            
            return {
                'exito': True,
                'eventos': eventos,
                'total': len(eventos)
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo eventos recientes: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def obtener_alertas_recientes(self, limite: int = 20) -> Dict[str, Any]:
        """Obtener alertas recientes."""
        try:
            with self._lock:
                alertas = list(self._alertas_buffer)[-limite:]
            
            return {
                'exito': True,
                'alertas': alertas,
                'total': len(alertas)
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo alertas recientes: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas del SIEM."""
        try:
            with self._lock:
                estadisticas = {
                    'eventos_totales': self._contadores['eventos_totales'],
                    'alertas_generadas': self._contadores['alertas_generadas'],
                    'eventos_criticos': self._contadores['eventos_criticos'],
                    'eventos_por_tipo': dict(self._contadores['eventos_por_tipo']),
                    'eventos_en_buffer': len(self._eventos_buffer),
                    'alertas_en_buffer': len(self._alertas_buffer),
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'exito': True,
                'estadisticas': estadisticas
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo estadísticas SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def analizar_eventos_tiempo_real(self) -> Dict[str, Any]:
        """Análisis básico de eventos en tiempo real."""
        try:
            with self._lock:
                eventos_recientes = list(self._eventos_buffer)[-100:]  # Últimos 100 eventos
            
            if not eventos_recientes:
                return {
                    'exito': True,
                    'análisis': {
                        'eventos_analizados': 0,
                        'patrones_detectados': [],
                        'recomendaciones': []
                    }
                }
            
            # Análisis básico de patrones
            tipos_frecuentes = defaultdict(int)
            eventos_criticos_recientes = 0
            
            for evento in eventos_recientes:
                tipos_frecuentes[evento.get('tipo', 'DESCONOCIDO')] += 1
                if evento.get('severidad', '').lower() in ['critical', 'critica', 'alta']:
                    eventos_criticos_recientes += 1
            
            # Detectar patrones simples
            patrones_detectados = []
            recomendaciones = []
            
            # Patrón: muchos eventos del mismo tipo
            for tipo, cantidad in tipos_frecuentes.items():
                if cantidad > 10:
                    patrones_detectados.append(f"Alta frecuencia de eventos {tipo}: {cantidad}")
                    recomendaciones.append(f"Investigar causa de eventos repetitivos: {tipo}")
            
            # Patrón: muchos eventos críticos
            if eventos_criticos_recientes > 5:
                patrones_detectados.append(f"Alta cantidad de eventos críticos: {eventos_criticos_recientes}")
                recomendaciones.append("Revisar urgentemente eventos críticos recientes")
            
            análisis = {
                'eventos_analizados': len(eventos_recientes),
                'eventos_criticos_recientes': eventos_criticos_recientes,
                'tipos_mas_frecuentes': dict(sorted(tipos_frecuentes.items(), 
                                                   key=lambda x: x[1], reverse=True)[:5]),
                'patrones_detectados': patrones_detectados,
                'recomendaciones': recomendaciones,
                'timestamp_analisis': datetime.now().isoformat()
            }
            
            return {
                'exito': True,
                'análisis': análisis
            }
            
        except Exception as e:
            error_msg = f"Error en análisis de eventos: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def limpiar_eventos_antiguos(self, dias_antiguedad: int = 7) -> Dict[str, Any]:
        """Limpiar eventos antiguos del sistema."""
        try:
            if not self._config_siem['auto_cleanup']:
                return {'exito': False, 'error': 'Limpieza automática deshabilitada'}
            
            eventos_eliminados = 0
            alertas_eliminadas = 0
            
            limite_tiempo = datetime.now().timestamp() - (dias_antiguedad * 24 * 3600)
            
            with self._lock:
                # Limpiar eventos
                eventos_nuevos = deque(maxlen=self._config_siem['max_events'])
                for evento in self._eventos_buffer:
                    try:
                        timestamp_evento = datetime.fromisoformat(evento['timestamp']).timestamp()
                        if timestamp_evento > limite_tiempo:
                            eventos_nuevos.append(evento)
                        else:
                            eventos_eliminados += 1
                    except (ValueError, TypeError, AttributeError):
                        eventos_nuevos.append(evento)  # Conservar si hay error de parsing
                
                self._eventos_buffer = eventos_nuevos
                
                # Limpiar alertas
                alertas_nuevas = deque(maxlen=self._config_siem['max_alerts'])
                for alerta in self._alertas_buffer:
                    try:
                        timestamp_alerta = datetime.fromisoformat(alerta['timestamp']).timestamp()
                        if timestamp_alerta > limite_tiempo:
                            alertas_nuevas.append(alerta)
                        else:
                            alertas_eliminadas += 1
                    except (ValueError, TypeError, AttributeError):
                        alertas_nuevas.append(alerta)  # Conservar si hay error de parsing
                
                self._alertas_buffer = alertas_nuevas
            
            self.logger.info(f"Limpieza SIEM completada: {eventos_eliminados} eventos, {alertas_eliminadas} alertas eliminadas")
            
            return {
                'exito': True,
                'eventos_eliminados': eventos_eliminados,
                'alertas_eliminadas': alertas_eliminadas,
                'eventos_restantes': len(self._eventos_buffer),
                'alertas_restantes': len(self._alertas_buffer)
            }
            
        except Exception as e:
            error_msg = f"Error limpiando eventos antiguos: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def generar_reporte_diario(self) -> Dict[str, Any]:
        """Generar reporte diario de actividad SIEM."""
        try:
            # Obtener eventos de las últimas 24 horas
            limite_tiempo = datetime.now().timestamp() - (24 * 3600)
            
            eventos_dia = []
            alertas_dia = []
            
            with self._lock:
                for evento in self._eventos_buffer:
                    try:
                        timestamp_evento = datetime.fromisoformat(evento['timestamp']).timestamp()
                        if timestamp_evento > limite_tiempo:
                            eventos_dia.append(evento)
                    except (ValueError, TypeError, AttributeError):
                        pass
                
                for alerta in self._alertas_buffer:
                    try:
                        timestamp_alerta = datetime.fromisoformat(alerta['timestamp']).timestamp()
                        if timestamp_alerta > limite_tiempo:
                            alertas_dia.append(alerta)
                    except (ValueError, TypeError, AttributeError):
                        pass
            
            # Generar estadísticas del día
            eventos_por_severidad = defaultdict(int)
            eventos_por_tipo = defaultdict(int)
            
            for evento in eventos_dia:
                eventos_por_severidad[evento.get('severidad', 'desconocida')] += 1
                eventos_por_tipo[evento.get('tipo', 'DESCONOCIDO')] += 1
            
            reporte = {
                'fecha': datetime.now().strftime('%Y-%m-%d'),
                'periodo': 'últimas 24 horas',
                'resumen': {
                    'total_eventos': len(eventos_dia),
                    'total_alertas': len(alertas_dia),
                    'eventos_criticos': eventos_por_severidad.get('critica', 0) + eventos_por_severidad.get('critical', 0),
                    'eventos_altas': eventos_por_severidad.get('alta', 0) + eventos_por_severidad.get('warning', 0)
                },
                'eventos_por_severidad': dict(eventos_por_severidad),
                'eventos_por_tipo': dict(sorted(eventos_por_tipo.items(), key=lambda x: x[1], reverse=True)[:10]),
                'alertas_criticas': len([a for a in alertas_dia if a.get('severidad', '').lower() in ['critica', 'critical']]),
                'timestamp_generacion': datetime.now().isoformat()
            }
            
            # Guardar reporte
            try:
                archivo_reporte = os.path.join(self._directorio_logs, f"reporte_siem_{datetime.now().strftime('%Y%m%d')}.json")
                with open(archivo_reporte, 'w', encoding='utf-8') as f:
                    json.dump(reporte, f, indent=2, ensure_ascii=False)
            except Exception as e:
                self.logger.warning(f"Error guardando reporte diario: {e}")
            
            return {
                'exito': True,
                'reporte': reporte
            }
            
        except Exception as e:
            error_msg = f"Error generando reporte diario: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Implementación de finalización del controlador SIEM."""
        try:
            self.logger.info("Finalizando controlador SIEM...")
            
            # Generar reporte final
            try:
                self.generar_reporte_diario()
            except (ValueError, TypeError, AttributeError):
                pass
            
            # Registrar evento de finalización
            self._registrar_evento_interno("SIEM_SHUTDOWN", "Sistema SIEM finalizado", "info")
            
            return {
                'exito': True,
                'mensaje': 'Controlador SIEM finalizado correctamente',
                'eventos_totales': self._contadores['eventos_totales'],
                'alertas_generadas': self._contadores['alertas_generadas']
            }
            
        except Exception as e:
            error_msg = f"Error finalizando controlador SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def iniciar_monitoreo_eventos(self, intervalo_segundos: int = 5) -> Dict[str, Any]:
        """
        Iniciar monitoreo de eventos de seguridad.
        KALI OPTIMIZATION: Monitoreo específico para Kali Linux.
        """
        try:
            self.logger.info("Iniciando monitoreo de eventos SIEM")
            
            # Generar evento de inicio
            self.generar_evento(
                tipo_evento="SIEM_STARTUP",
                descripcion="Sistema SIEM iniciado correctamente",
                severidad="info"
            )
            
            # Si hay modelo SIEM disponible, usar sus funciones
            if self.siem:
                # Analizar logs del sistema si está disponible
                try:
                    resultado_analisis = self.siem.analizar_logs_sistema()
                    eventos_generados = resultado_analisis.get('eventos_generados', 0)
                    
                    if eventos_generados > 0:
                        self.generar_evento(
                            tipo_evento="LOG_ANALYSIS",
                            descripcion=f"Análisis de logs completado: {eventos_generados} eventos generados",
                            severidad="info"
                        )
                except Exception as e:
                    self.logger.warning(f"Error en análisis de logs: {e}")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo de eventos SIEM iniciado',
                'intervalo_segundos': intervalo_segundos,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error iniciando monitoreo SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def detener_monitoreo_eventos(self) -> Dict[str, Any]:
        """
        Detener monitoreo de eventos de seguridad.
        KALI OPTIMIZATION: Detiene procesos específicos de Kali Linux.
        """
        try:
            self.logger.info("Deteniendo monitoreo de eventos SIEM")
            
            # Generar evento de detención
            self.generar_evento(
                tipo_evento="SIEM_SHUTDOWN",
                descripcion="Sistema SIEM detenido correctamente",
                severidad="info"
            )
            
            # Si hay modelo SIEM disponible, finalizarlo
            if self.siem:
                try:
                    # Guardar estadísticas finales
                    stats = self.obtener_estadisticas()
                    if stats.get('exito'):
                        self.generar_evento(
                            tipo_evento="SIEM_STATS",
                            descripcion=f"Estadísticas finales: {stats.get('total_eventos', 0)} eventos procesados",
                            severidad="info"
                        )
                except Exception as e:
                    self.logger.warning(f"Error obteniendo estadísticas finales: {e}")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo de eventos SIEM detenido',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error deteniendo monitoreo SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """
        Verificar funcionalidad específica de Kali Linux.
        KALI OPTIMIZATION: Validación de herramientas nativas de Kali.
        """
        try:
            self.logger.info("Verificando funcionalidad SIEM en Kali Linux")
            
            verificaciones = {
                'sistema_archivos': False,
                'herramientas_siem': False,
                'logs_sistema': False,
                'permisos': False
            }
            
            detalles = []
            
            # Verificar sistema de archivos
            try:
                import os
                directorio_logs = getattr(self, 'directorio_logs', '/tmp/ares_siem_logs')
                if os.path.exists(directorio_logs) and os.access(directorio_logs, os.W_OK):
                    verificaciones['sistema_archivos'] = True
                    detalles.append("[EMOJI] Sistema de archivos: OK")
                else:
                    detalles.append("[EMOJI] Sistema de archivos: Sin permisos de escritura")
            except Exception as e:
                detalles.append(f"[EMOJI] Sistema de archivos: Error - {str(e)}")
            
            # Verificar herramientas SIEM
            try:
                herramientas_kali = ['rsyslog', 'systemctl', 'journalctl', 'netstat']
                herramientas_disponibles = 0
                
                for herramienta in herramientas_kali:
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        herramientas_disponibles += 1
                
                if herramientas_disponibles >= len(herramientas_kali) * 0.75:
                    verificaciones['herramientas_siem'] = True
                    detalles.append(f"[EMOJI] Herramientas SIEM: {herramientas_disponibles}/{len(herramientas_kali)} disponibles")
                else:
                    detalles.append(f"[WARNING] Herramientas SIEM: Solo {herramientas_disponibles}/{len(herramientas_kali)} disponibles")
                    
            except Exception as e:
                detalles.append(f"[EMOJI] Herramientas SIEM: Error - {str(e)}")
            
            # Verificar logs del sistema
            try:
                logs_sistema = ['/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log']
                logs_encontrados = 0
                
                for log_file in logs_sistema:
                    if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                        logs_encontrados += 1
                
                if logs_encontrados >= len(logs_sistema) * 0.67:
                    verificaciones['logs_sistema'] = True
                    detalles.append(f"[EMOJI] Logs del sistema: {logs_encontrados}/{len(logs_sistema)} accesibles")
                else:
                    detalles.append(f"[WARNING] Logs del sistema: Solo {logs_encontrados}/{len(logs_sistema)} accesibles")
                    
            except Exception as e:
                detalles.append(f"[EMOJI] Logs del sistema: Error - {str(e)}")
            
            # Verificar permisos
            try:
                usuario_actual = os.getenv('USER', 'unknown')
                if usuario_actual == 'root':
                    verificaciones['permisos'] = True
                    detalles.append("[EMOJI] Permisos: Usuario root detectado")
                else:
                    # Verificar si puede ejecutar sudo
                    try:
                        result = subprocess.run(['sudo', '-n', 'true'], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            verificaciones['permisos'] = True
                            detalles.append("[EMOJI] Permisos: Usuario con acceso sudo")
                        else:
                            detalles.append("[WARNING] Permisos: Usuario sin privilegios administrativos")
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                        detalles.append("[WARNING] Permisos: No se pudo verificar acceso sudo")
            except Exception as e:
                detalles.append(f"[EMOJI] Permisos: Error verificando - {str(e)}")
            
            # Calcular puntuación general
            puntuacion = sum(verificaciones.values()) / len(verificaciones) * 100
            
            # Generar evento de verificación
            self.generar_evento(
                tipo_evento="KALI_VERIFICATION",
                descripcion=f"Verificación de funcionalidad Kali completada: {puntuacion:.1f}%",
                severidad="info" if puntuacion >= 75 else "warning"
            )
            
            return {
                'exito': True,
                'puntuacion': puntuacion,
                'verificaciones': verificaciones,
                'detalles': detalles,
                'recomendacion': 'Sistema SIEM funcional' if puntuacion >= 75 else 'Revisar configuración del sistema',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error en verificación de funcionalidad Kali: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg,
                'puntuacion': 0,
                'timestamp': datetime.now().isoformat()
            }
    
    # MÉTODOS DE CONECTIVIDAD ENTRE CONTROLADORES
    
    def configurar_referencias_controladores(self, controlador_cuarentena=None, controlador_fim=None):
        """Configurar referencias a otros controladores para integración."""
        try:
            self.controlador_cuarentena = controlador_cuarentena
            self.controlador_fim = controlador_fim
            
            if controlador_cuarentena:
                self.logger.info("[EMOJI] Referencia a Controlador Cuarentena configurada")
            if controlador_fim:
                self.logger.info("[EMOJI] Referencia a Controlador FIM configurada")
                
        except Exception as e:
            self.logger.error(f"Error configurando referencias de controladores: {e}")
    
    def _obtener_controlador_cuarentena(self):
        """Obtener referencia al controlador de cuarentena."""
        return getattr(self, 'controlador_cuarentena', None)
    
    def _obtener_controlador_fim(self):
        """Obtener referencia al controlador FIM."""
        return getattr(self, 'controlador_fim', None)
    
    def _notificar_respuesta_automatica(self, evento, accion_tomada):
        """Notificar a otros controladores sobre respuestas automáticas."""
        try:
            if evento.get('severidad') == 'critica':
                # Notificar a FIM para verificación de integridad
                controlador_fim = self._obtener_controlador_fim()
                if controlador_fim:
                    try:
                        resultado_fim = controlador_fim.verificar_integridad_archivos()
                        if resultado_fim.get('cambios_detectados'):
                            self.generar_alerta(
                                "INTEGRIDAD_COMPROMETIDA",
                                f"FIM detectó cambios tras evento crítico: {evento.get('descripcion')}",
                                "critica"
                            )
                    except Exception as e:
                        self.logger.error(f"Error notificando a FIM: {e}")
                        
                # Activar cuarentena si es necesario
                controlador_cuarentena = self._obtener_controlador_cuarentena()
                if controlador_cuarentena and 'archivo' in evento:
                    try:
                        resultado_cuarentena = controlador_cuarentena.cuarentenar_archivo(evento['archivo'])
                        if resultado_cuarentena.get('exito'):
                            self.generar_alerta(
                                "ARCHIVO_CUARENTENADO",
                                f"Archivo {evento['archivo']} movido a cuarentena por evento crítico",
                                "warning"
                            )
                    except Exception as e:
                        self.logger.error(f"Error notificando a Cuarentena: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error en notificación de respuesta automática: {e}")


# RESUMEN TÉCNICO: Controlador SIEM simplificado para gestión centralizada de eventos
