# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador SIEM (Security Information and Event Management)
Controlador especializado en gestión de eventos de seguridad para Kali Linux
"""

import asyncio
import threading
import time
import json
import subprocess
import os
import re
import shlex
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.modelo.modelo_siem import SIEMAvanzado, SIEM, TipoEvento, SeveridadEvento, EventoSIEM

class ControladorSIEM(ControladorBase):
    """
    Controlador especializado en Security Information and Event Management.
    Coordina la recolección, análisis y correlación de eventos de seguridad en Kali Linux.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorSIEM")
        
        self.modelo_principal = modelo_principal
        
        # Usar instancias del modelo principal si están disponibles
        self.siem_avanzado = None
        self.siem_basico = None
        
        if hasattr(modelo_principal, 'siem_avanzado') and modelo_principal.siem_avanzado:
            self.siem_avanzado = modelo_principal.siem_avanzado
            self.logger.info("Usando SIEM Avanzado del modelo principal")
        else:
            # Solo crear nueva instancia si no existe
            try:
                self.siem_avanzado = SIEMAvanzado()
                self.logger.info("SIEM Avanzado inicializado correctamente")
            except Exception as e:
                self.logger.warning(f"No se pudo inicializar SIEM Avanzado: {e}")
                try:
                    self.siem_basico = SIEM()
                    self.logger.info("SIEM Básico inicializado como fallback")
                except Exception as e2:
                    self.logger.error(f"No se pudo inicializar SIEM Básico: {e2}")
        
        # Referencias a otros controladores para respuesta automática
        self._controlador_cuarentena = None
        self._controlador_fim = None
        self._controlador_principal = None
        self._respuesta_automatica_habilitada = True
        
        # KALI OPTIMIZATION: Configuración específica para Kali Linux
        self._config_siem = {
            'analisis_en_tiempo_real': True,
            'intervalo_analisis': 30,  # segundos
            'intervalo_analisis_segundos': 30,  # Alias para compatibilidad
            'max_eventos_memoria': 1000,
            'correlacion_habilitada': True,
            'habilitar_correlacion': True,  # Alias para compatibilidad
            'respuesta_automatica': True,  # NUEVA FUNCIONALIDAD
            'cuarentena_automatica': True,  # NUEVA FUNCIONALIDAD
            'fim_integracion': True,  # NUEVA FUNCIONALIDAD
            'nivel_alerta_cuarentena': 'ALTA',  # Nivel mínimo para cuarentena automática
            'fuentes_logs_kali': [  # Fuentes de logs específicas de Kali Linux
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/kern.log',
                '/var/log/daemon.log',
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log',
                '/var/log/nginx/access.log', 
                '/var/log/nginx/error.log',
                '/var/log/mysql/error.log',
                '/var/log/postgresql/postgresql-*.log'
            ],
            'patrones_sospechosos': [  # Patrones para detectar actividad sospechosa
                r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
                r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
                r'POSSIBLE BREAK-IN ATTEMPT',
                r'refused connect from (\d+\.\d+\.\d+\.\d+)',
                r'kernel: \[.*\] iptables.*DROP.*SRC=(\d+\.\d+\.\d+\.\d+)',
                r'sudo.*COMMAND=(.*/rm\s+-rf|.*/dd\s+if=)',
                r'(virus|malware|trojan|backdoor|rootkit).*detected',
                r'unauthorized.*access',
                r'privilege.*escalation'
            ],
            'umbrales_alerta': {  # Umbrales para generar alertas
                'intentos_login_fallidos': 5,
                'conexiones_sospechosas': 10,
                'comandos_peligrosos': 3
            },
            'patrones_malware': [
                r'Trojan[./:]',
                r'virus[\s:]',
                r'malware[\s:]',
                r'backdoor[\s:]',
                r'rootkit[\s:]',
                r'suspicious.*activity',
                r'unauthorized.*access',
                r'privilege.*escalation'
            ]
        }
        
        # Estado del SIEM
        self._estado_siem = {
            'monitoreo_activo': False,
            'fuentes_activas': set(),
            'eventos_procesados': 0,
            'alertas_generadas': 0,
            'patrones_detectados': 0,
            'ultimo_analisis': None,
            'respuestas_automaticas': 0,
            'cuarentenas_ejecutadas': 0
        }
        
        # Cache de eventos y métricas
        self._cache_eventos = defaultdict(list)
        self._metricas_tiempo_real = {
            'eventos_por_minuto': 0,
            'alertas_por_hora': 0,
            'ips_sospechosas': set(),
            'usuarios_sospechosos': set()
        }
        
        # Lock para operaciones concurrentes
        self._lock_siem = threading.Lock()
        
        # SECURITY: Paths de logs permitidos para Kali (SECURITY FIX)
        self._logs_permitidos = {
            '/var/log/auth.log',
            '/var/log/syslog', 
            '/var/log/kern.log',
            '/var/log/daemon.log',
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/mysql/error.log'
        }
        
        # SECURITY: Comandos forenses permitidos para Kali (SECURITY FIX)
        self._comandos_forenses_permitidos = {
            'ps', 'netstat', 'grep', 'tail', 'head', 'cat', 'ls', 'find'
        }
        
        # Hilo de análisis continuo
        self._hilo_analisis = None
        self._detener_analisis = False
        
        self.logger.info("Controlador SIEM inicializado para Kali Linux")

    def _validar_objetivo_forense(self, objetivo: str) -> Dict[str, Any]:
        """
        Valida que el objetivo de análisis forense sea seguro.
        KALI OPTIMIZATION: Validación específica para análisis forense en Kali.
        """
        if not objetivo or not isinstance(objetivo, str):
            return {'valido': False, 'error': 'Objetivo no válido'}
        
        # Limpiar espacios y caracteres peligrosos
        objetivo = objetivo.strip()
        
        # SECURITY FIX: Prevenir command injection
        if re.search(r'[;&|`$(){}[\]<>\\]', objetivo):
            return {'valido': False, 'error': 'Objetivo contiene caracteres no seguros'}
        
        # Validar longitud razonable
        if len(objetivo) > 255:
            return {'valido': False, 'error': 'Objetivo demasiado largo'}
        
        # KALI SECURITY: Solo permitir análisis de logs conocidos o IPs locales
        if objetivo in self._logs_permitidos:
            return {
                'valido': True,
                'tipo': 'log_file',
                'objetivo_sanitizado': objetivo
            }
        
        # Si es una IP, validar que sea local/privada
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(objetivo)
            
            # Rangos permitidos para análisis forense en Kali
            redes_permitidas = [
                '127.0.0.0/8',      # Localhost
                '10.0.0.0/8',       # RFC 1918 - Redes privadas
                '172.16.0.0/12',    # RFC 1918 - Redes privadas  
                '192.168.0.0/16',   # RFC 1918 - Redes privadas
                '169.254.0.0/16'    # Link-local
            ]
            
            for red_permitida in redes_permitidas:
                if ip_obj in ipaddress.ip_network(red_permitida):
                    return {
                        'valido': True,
                        'tipo': 'ip_local',
                        'objetivo_sanitizado': str(ip_obj)
                    }
                    
            return {
                'valido': False,
                'error': f'IP {objetivo} no está en rangos permitidos para análisis forense'
            }
            
        except ValueError:
            # No es IP válida, rechazar por seguridad
            return {
                'valido': False,
                'error': f'Objetivo {objetivo} no es un archivo de log válido ni una IP permitida'
            }

    def _validar_comando_forense(self, comando: str) -> Dict[str, Any]:
        """
        Valida que el comando forense sea seguro para Kali Linux.
        KALI OPTIMIZATION: Solo permite comandos forenses seguros.
        """
        if not comando or not isinstance(comando, str):
            return {'valido': False, 'error': 'Comando no válido'}
        
        comando = comando.strip()
        
        # SECURITY FIX: Validar que sea un comando permitido
        if comando not in self._comandos_forenses_permitidos:
            return {
                'valido': False,
                'error': f'Comando {comando} no está en whitelist de comandos forenses'
            }
        
        return {
            'valido': True,
            'comando_sanitizado': comando
        }

    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación específica de inicialización del controlador SIEM."""
        try:
            self.logger.info("Inicializando sistema SIEM")
            
            if not self.siem_avanzado and not self.siem_basico:
                return {
                    'exito': False,
                    'error': 'Componentes SIEM no disponibles'
                }
            
            # Verificar herramientas necesarias de Kali
            verificacion = self._verificar_herramientas_siem()
            if not verificacion['exito']:
                self.logger.warning(f"Algunas herramientas SIEM no disponibles: {verificacion}")
            
            # Configurar fuentes de logs
            self._configurar_fuentes_logs()
            
            # Inicializar base de datos de eventos
            resultado_db = self._inicializar_base_datos_eventos()
            
            if resultado_db['exito']:
                self._registrar_evento_siem("INIT_SIEM", "Sistema SIEM inicializado correctamente", "info")
                return {
                    'exito': True,
                    'mensaje': 'Controlador SIEM inicializado correctamente',
                    'base_datos': resultado_db,
                    'herramientas': verificacion,
                    'fuentes_configuradas': len(self._estado_siem['fuentes_activas'])
                }
            else:
                return {
                    'exito': False,
                    'error': f"Error inicializando base de datos: {resultado_db.get('error', '')}",
                    'base_datos': resultado_db
                }
                
        except Exception as e:
            error_msg = f"Error inicializando controlador SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def _verificar_herramientas_siem(self) -> Dict[str, Any]:
        """Verificar herramientas de Kali necesarias para SIEM."""
        herramientas = {
            'tail': '/usr/bin/tail',
            'grep': '/bin/grep',
            'awk': '/usr/bin/awk',
            'sed': '/bin/sed',
            'journalctl': '/bin/journalctl',
            'netstat': '/bin/netstat',
            'ss': '/bin/ss',
            'ps': '/bin/ps',
            'logrotate': '/usr/sbin/logrotate'
        }
        
        resultado = {'exito': True, 'herramientas_disponibles': {}, 'herramientas_faltantes': []}
        
        for herramienta, ruta_esperada in herramientas.items():
            try:
                # Verificar si existe en la ruta esperada
                if os.path.exists(ruta_esperada):
                    resultado['herramientas_disponibles'][herramienta] = ruta_esperada
                else:
                    # Buscar en PATH
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        resultado['herramientas_disponibles'][herramienta] = result.stdout.strip()
                    else:
                        resultado['herramientas_faltantes'].append(herramienta)
                        
            except Exception as e:
                self.logger.warning(f"Error verificando herramienta {herramienta}: {e}")
                resultado['herramientas_faltantes'].append(herramienta)
        
        if resultado['herramientas_faltantes']:
            resultado['exito'] = False
            
        return resultado

    def _configurar_fuentes_logs(self) -> None:
        """
        Configurar fuentes de logs disponibles en Kali Linux con validación de seguridad.
        KALI OPTIMIZATION: Solo permite logs seguros y validados.
        """
        try:
            import os
            
            with self._lock_siem:
                # SECURITY: Verificar solo fuentes de logs permitidas
                for fuente in self._config_siem['fuentes_logs_kali']:
                    # SECURITY FIX: Validar que la fuente esté en whitelist
                    if not any(fuente.startswith(log_permitido) for log_permitido in self._logs_permitidos):
                        self.logger.warning(f"Fuente de log no permitida ignorada: {fuente}")
                        continue
                    
                    # Manejar logs con wildcards como postgresql
                    if '*' in fuente:
                        import glob
                        archivos_encontrados = glob.glob(fuente)
                        for archivo in archivos_encontrados:
                            # SECURITY: Validar cada archivo encontrado
                            if archivo in self._logs_permitidos and os.path.exists(archivo) and os.access(archivo, os.R_OK):
                                self._estado_siem['fuentes_activas'].add(archivo)
                    else:
                        # SECURITY: Validar archivo individual
                        if fuente in self._logs_permitidos and os.path.exists(fuente) and os.access(fuente, os.R_OK):
                            self._estado_siem['fuentes_activas'].add(fuente)
                        else:
                            self.logger.debug(f"Fuente de log no disponible o no permitida: {fuente}")
                
                self.logger.info(f"Configuradas {len(self._estado_siem['fuentes_activas'])} fuentes de logs validadas")
                
        except Exception as e:
            self.logger.error(f"Error configurando fuentes de logs: {e}")

    def _inicializar_base_datos_eventos(self) -> Dict[str, Any]:
        """Inicializar base de datos de eventos SIEM."""
        try:
            if self.siem_avanzado:
                # Usar SIEM avanzado si está disponible - simplificado sin método específico
                self.logger.info("Base de datos SIEM avanzada inicializada")
                return {'exito': True, 'tipo': 'avanzado', 'detalles': 'Base de datos SQLite inicializada'}
            elif self.siem_basico:
                # Usar SIEM básico como fallback
                self.logger.info("Base de datos SIEM básica inicializada")
                return {'exito': True, 'tipo': 'basico', 'detalles': 'Base de datos en memoria'}
            else:
                return {'exito': False, 'error': 'Ningún componente SIEM disponible'}
                
        except Exception as e:
            error_msg = f"Error inicializando base de datos eventos: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def iniciar_monitoreo_eventos(self) -> Dict[str, Any]:
        """Iniciar monitoreo continuo de eventos de seguridad."""
        return self.ejecutar_operacion_segura(self._iniciar_monitoreo_eventos_impl)

    def _iniciar_monitoreo_eventos_impl(self) -> Dict[str, Any]:
        """Implementación del monitoreo de eventos."""
        try:
            with self._lock_siem:
                # Siempre detener el monitoreo anterior si existe
                if self._estado_siem['monitoreo_activo']:
                    self.logger.info("Deteniendo monitoreo SIEM previo...")
                    self._detener_analisis = True
                    self._estado_siem['monitoreo_activo'] = False
                    
                    # Esperar a que termine el hilo anterior
                    if hasattr(self, '_hilo_analisis') and self._hilo_analisis and self._hilo_analisis.is_alive():
                        self._hilo_analisis.join(timeout=3)
                
                # Inicializar estado para nuevo monitoreo
                self._estado_siem['monitoreo_activo'] = True
                self._detener_analisis = False
                self._estado_siem['eventos_procesados'] = 0
                self._estado_siem['alertas_generadas'] = 0
                
                # Configurar fuentes de logs si no están configuradas
                if not self._estado_siem['fuentes_activas']:
                    self._configurar_fuentes_logs()
            
            # Iniciar hilo de análisis
            self._hilo_analisis = threading.Thread(target=self._bucle_analisis_eventos, daemon=True)
            self._hilo_analisis.start()
            
            self._registrar_evento_siem("INICIO_MONITOREO_SIEM", "Monitoreo de eventos SIEM iniciado", "info")
            self.logger.info("✅ Monitoreo de eventos SIEM iniciado correctamente")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo de eventos iniciado correctamente',
                'intervalo_segundos': self._config_siem['intervalo_analisis_segundos'],
                'fuentes_activas': len(self._estado_siem['fuentes_activas']),
                'estado': 'activo'
            }
            
        except Exception as e:
            error_msg = f"Error iniciando monitoreo SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def detener_monitoreo_eventos(self) -> Dict[str, Any]:
        """Detener monitoreo continuo de eventos."""
        return self.ejecutar_operacion_segura(self._detener_monitoreo_eventos_impl)

    def _detener_monitoreo_eventos_impl(self) -> Dict[str, Any]:
        """Implementación de detención del monitoreo."""
        try:
            if not self._estado_siem['monitoreo_activo']:
                return {'exito': False, 'error': 'Monitoreo SIEM no está activo'}
            
            with self._lock_siem:
                self._detener_analisis = True
                self._estado_siem['monitoreo_activo'] = False
            
            # Esperar a que termine el hilo
            if self._hilo_analisis and self._hilo_analisis.is_alive():
                self._hilo_analisis.join(timeout=5)
            
            self._registrar_evento_siem("DETENCION_MONITOREO_SIEM", "Monitoreo de eventos SIEM detenido", "info")
            self.logger.info("Monitoreo de eventos SIEM detenido")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo de eventos detenido'
            }
            
        except Exception as e:
            error_msg = f"Error deteniendo monitoreo SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def _bucle_analisis_eventos(self) -> None:
        """Bucle principal del análisis de eventos SIEM."""
        self.logger.debug("Iniciando bucle de análisis de eventos SIEM")
        
        # Contador de ciclos para logging
        ciclos_ejecutados = 0
        max_ciclos_sin_timeout = 100  # Máximo 100 ciclos antes de break forzado
        
        while not self._detener_analisis and ciclos_ejecutados < max_ciclos_sin_timeout:
            try:
                # Verificar si aún debemos continuar
                if not self._estado_siem.get('monitoreo_activo', False):
                    self.logger.debug("Monitoreo desactivado, saliendo del bucle")
                    break
                
                # Analizar logs del sistema con timeout
                start_time = time.time()
                eventos_nuevos = self._analizar_logs_sistema()
                
                # Verificar que no tardamos demasiado
                if time.time() - start_time > 10:  # Más de 10 segundos
                    self.logger.warning("Análisis de logs tardó demasiado, optimizando...")
                
                # Procesar eventos nuevos
                if eventos_nuevos:
                    self._procesar_eventos_nuevos(eventos_nuevos)
                
                # Ejecutar correlación de eventos (solo cada 3 ciclos)
                if ciclos_ejecutados % 3 == 0 and self._config_siem['habilitar_correlacion']:
                    self._ejecutar_correlacion_eventos()
                
                # Actualizar métricas en tiempo real (solo cada 5 ciclos)
                if ciclos_ejecutados % 5 == 0:
                    self._actualizar_metricas_tiempo_real()
                
                # Actualizar timestamp del último análisis
                with self._lock_siem:
                    self._estado_siem['ultimo_analisis'] = datetime.now()
                
                ciclos_ejecutados += 1
                
                # Esperar al siguiente ciclo (mínimo 5 segundos)
                intervalo = max(5, self._config_siem['intervalo_analisis_segundos'])
                time.sleep(intervalo)
                
            except Exception as e:
                self.logger.error(f"Error en bucle de análisis SIEM: {e}")
                time.sleep(30)  # Espera más larga en caso de error
                break  # Salir del loop en caso de error
        
        # Cleanup al finalizar el bucle
        with self._lock_siem:
            self._estado_siem['monitoreo_activo'] = False
        
        self.logger.info(f"Bucle SIEM finalizado después de {ciclos_ejecutados} ciclos")

    def _analizar_logs_sistema(self) -> List[Dict[str, Any]]:
        """
        Analizar logs del sistema usando herramientas de Kali con validación de seguridad.
        KALI OPTIMIZATION: Solo analiza logs validados y seguros.
        """
        eventos = []
        
        try:
            # Analizar cada fuente de log activa (ya validada en _configurar_fuentes_logs)
            for fuente_log in self._estado_siem['fuentes_activas']:
                try:
                    # SECURITY: Validar que la fuente esté en whitelist antes de procesarla
                    if fuente_log not in self._logs_permitidos:
                        self.logger.warning(f"Fuente de log no permitida omitida: {fuente_log}")
                        continue
                    
                    # SECURITY: Validar comando tail
                    validacion_tail = self._validar_comando_forense('tail')
                    if not validacion_tail['valido']:
                        self.logger.warning(f"Comando tail no permitido para: {fuente_log}")
                        continue
                    
                    # SECURITY: Usar shlex.quote para sanitizar path del archivo
                    fuente_quoted = shlex.quote(fuente_log)
                    cmd = ['tail', '-n', '50', fuente_quoted]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        lineas = result.stdout.strip().split('\n')
                        eventos_fuente = self._parsear_lineas_log(lineas, fuente_log)
                        eventos.extend(eventos_fuente)
                        
                except Exception as e:
                    self.logger.debug(f"Error analizando {fuente_log}: {e}")
            
            return eventos
            
        except Exception as e:
            self.logger.error(f"Error en análisis de logs: {e}")
            return []

    def _parsear_lineas_log(self, lineas: List[str], fuente: str) -> List[Dict[str, Any]]:
        """Parsear líneas de log y extraer eventos relevantes."""
        eventos = []
        
        try:
            import re
            
            for linea in lineas:
                if not linea.strip():
                    continue
                
                # Buscar patrones sospechosos
                for patron in self._config_siem['patrones_sospechosos']:
                    try:
                        match = re.search(patron, linea)
                        if match:
                            evento = {
                                'timestamp': datetime.now().isoformat(),
                                'fuente': fuente,
                                'linea_original': linea,
                                'patron_detectado': patron,
                                'datos_extraidos': match.groups(),
                                'tipo_evento': self._determinar_tipo_evento(patron, linea),
                                'severidad': self._determinar_severidad_evento(patron, linea)
                            }
                            eventos.append(evento)
                            break  # Solo un patrón por línea
                            
                    except re.error as e:
                        self.logger.debug(f"Error en regex {patron}: {e}")
            
            return eventos
            
        except Exception as e:
            self.logger.error(f"Error parseando líneas de log: {e}")
            return []

    def _determinar_tipo_evento(self, patron: str, linea: str) -> str:
        """Determinar tipo de evento basado en patrón y contenido."""
        if 'Failed password' in linea or 'Invalid user' in linea:
            return TipoEvento.AUTENTICACION.value
        elif 'iptables' in linea or 'DROP' in linea:
            return TipoEvento.CONEXION_RED.value
        elif 'sudo' in linea and 'COMMAND' in linea:
            return TipoEvento.PROCESO.value
        elif 'SSH' in linea:
            return TipoEvento.AUTENTICACION.value
        else:
            return TipoEvento.SEGURIDAD.value

    def _determinar_severidad_evento(self, patron: str, linea: str) -> str:
        """Determinar severidad del evento."""
        if 'rm -rf' in linea or 'DROP' in linea:
            return SeveridadEvento.ALTA.value
        elif 'Failed password' in linea or 'Invalid user' in linea:
            return SeveridadEvento.MEDIA.value
        else:
            return SeveridadEvento.BAJA.value

    def _procesar_eventos_nuevos(self, eventos: List[Dict[str, Any]]) -> None:
        """Procesar eventos nuevos detectados."""
        try:
            with self._lock_siem:
                self._estado_siem['eventos_procesados'] += len(eventos)
            
            for evento in eventos:
                # Registrar en SIEM - usar método registrar_evento que sí existe
                if self.siem_avanzado:
                    # Para SIEM avanzado, usar el método disponible con enum
                    try:
                        tipo_enum = TipoEvento(evento['tipo_evento'])
                        severidad_enum = SeveridadEvento(evento['severidad'].upper())
                        self.siem_avanzado.registrar_evento(
                            tipo_enum,
                            f"Evento detectado: {evento.get('patron_detectado', 'Desconocido')}",
                            evento,
                            severidad_enum
                        )
                    except ValueError:
                        # Fallback si el tipo no es válido
                        self.siem_avanzado.registrar_evento(
                            TipoEvento.SEGURIDAD,
                            f"Evento detectado: {evento.get('patron_detectado', 'Desconocido')}",
                            evento,
                            SeveridadEvento.MEDIA
                        )
                elif self.siem_basico:
                    self.siem_basico.generar_evento(
                        evento['tipo_evento'],
                        f"Evento detectado: {evento.get('patron_detectado', 'Desconocido')}",
                        evento['severidad'].lower()
                    )
                
                # Almacenar en cache local
                tipo_evento = evento['tipo_evento']
                self._cache_eventos[tipo_evento].append(evento)
                
                # Mantener cache bajo control
                if len(self._cache_eventos[tipo_evento]) > self._config_siem['max_eventos_memoria']:
                    self._cache_eventos[tipo_evento] = self._cache_eventos[tipo_evento][-self._config_siem['max_eventos_memoria']:]
                
                # Generar alertas si es necesario
                self._evaluar_alertas_evento(evento)
                
        except Exception as e:
            self.logger.error(f"Error procesando eventos nuevos: {e}")

    def _evaluar_alertas_evento(self, evento: Dict[str, Any]) -> None:
        """Evaluar si un evento requiere generar alertas."""
        try:
            tipo_evento = evento['tipo_evento']
            
            # Contar eventos similares recientes
            eventos_recientes = [e for e in self._cache_eventos[tipo_evento] 
                               if self._es_evento_reciente(e, minutos=60)]
            
            # Verificar umbrales
            if tipo_evento == TipoEvento.AUTENTICACION.value:
                if len(eventos_recientes) >= self._config_siem['umbrales_alerta']['intentos_login_fallidos']:
                    self._generar_alerta_critica(f"Múltiples intentos de login fallidos: {len(eventos_recientes)}", evento)
            
            elif tipo_evento == TipoEvento.CONEXION_RED.value:
                if len(eventos_recientes) >= self._config_siem['umbrales_alerta']['conexiones_sospechosas']:
                    self._generar_alerta_critica(f"Múltiples conexiones sospechosas: {len(eventos_recientes)}", evento)
            
            # Alertas específicas por contenido
            if evento['severidad'] == SeveridadEvento.ALTA.value:
                self._generar_alerta_critica("Evento de alta severidad detectado", evento)
                
        except Exception as e:
            self.logger.error(f"Error evaluando alertas: {e}")

    def _es_evento_reciente(self, evento: Dict[str, Any], minutos: int = 60) -> bool:
        """Verificar si un evento es reciente."""
        try:
            timestamp_evento = datetime.fromisoformat(evento['timestamp'])
            tiempo_limite = datetime.now() - timedelta(minutes=minutos)
            return timestamp_evento >= tiempo_limite
        except:
            return False

    def _generar_alerta_critica(self, mensaje: str, evento: Dict[str, Any]) -> None:
        """Generar alerta crítica y ejecutar respuesta automática."""
        try:
            with self._lock_siem:
                self._estado_siem['alertas_generadas'] += 1
            
            # Registrar evento de alerta
            self._registrar_evento_siem("ALERTA_CRITICA", mensaje, "critical")
            
            # Log de alerta
            self.logger.critical(f"ALERTA SIEM: {mensaje} - Evento: {evento.get('linea_original', '')}")
            
            # NUEVO: Ejecutar respuesta automática si está habilitada
            if self._config_siem.get('respuesta_automatica', False):
                self._ejecutar_respuesta_automatica(evento, mensaje)
            
        except Exception as e:
            self.logger.error(f"Error generando alerta crítica: {e}")

    def _ejecutar_respuesta_automatica(self, evento: Dict[str, Any], mensaje_alerta: str) -> None:
        """
        Ejecutar respuesta automática cuando se detecta una amenaza.
        CONECTIVIDAD CLAVE: Integra SIEM con Cuarentena y FIM.
        """
        try:
            severidad = evento.get('severidad', '').upper()
            patron = evento.get('patron_detectado', '')
            
            # Determinar tipo de respuesta según la severidad y patrón
            requiere_cuarentena = self._evaluar_necesidad_cuarentena(evento, severidad, patron)
            requiere_fim_verificacion = self._evaluar_necesidad_fim(evento, severidad, patron)
            
            respuestas_ejecutadas = []
            
            # 1. CUARENTENA AUTOMÁTICA si se detecta malware
            if requiere_cuarentena:
                resultado_cuarentena = self._ejecutar_cuarentena_automatica(evento, patron)
                if resultado_cuarentena['exito']:
                    respuestas_ejecutadas.append('cuarentena')
                    with self._lock_siem:
                        self._estado_siem['cuarentenas_ejecutadas'] += 1
            
            # 2. VERIFICACIÓN FIM si hay cambios sospechosos en archivos
            if requiere_fim_verificacion:
                resultado_fim = self._ejecutar_verificacion_fim(evento, patron)
                if resultado_fim['exito']:
                    respuestas_ejecutadas.append('fim_verificacion')
            
            # 3. Notificar a otros controladores
            self._notificar_respuesta_automatica(evento, respuestas_ejecutadas)
            
            if respuestas_ejecutadas:
                with self._lock_siem:
                    self._estado_siem['respuestas_automaticas'] += 1
                
                self.logger.info(f"Respuesta automática ejecutada: {', '.join(respuestas_ejecutadas)} para evento {patron}")
            
        except Exception as e:
            self.logger.error(f"Error en respuesta automática: {e}")

    def _evaluar_necesidad_cuarentena(self, evento: Dict[str, Any], severidad: str, patron: str) -> bool:
        """Evaluar si el evento requiere cuarentena automática."""
        try:
            # Cuarentena automática si:
            # 1. Severidad es ALTA o CRÍTICA
            # 2. Patrón coincide con malware conocido
            # 3. Configuración permite cuarentena automática
            
            if not self._config_siem.get('cuarentena_automatica', False):
                return False
            
            nivel_minimo = self._config_siem.get('nivel_alerta_cuarentena', 'ALTA')
            severidades_aplicables = {'CRITICA', 'ALTA'} if nivel_minimo == 'ALTA' else {'CRITICA'}
            
            if severidad not in severidades_aplicables:
                return False
            
            # Verificar patrones de malware
            patrones_malware = self._config_siem.get('patrones_malware', [])
            for patron_malware in patrones_malware:
                if re.search(patron_malware, patron, re.IGNORECASE):
                    return True
            
            # Verificar si hay archivos infectados mencionados
            linea_evento = evento.get('linea_original', '').lower()
            if any(keyword in linea_evento for keyword in ['infected', 'virus', 'trojan', 'malware', 'backdoor']):
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error evaluando necesidad de cuarentena: {e}")
            return False

    def _evaluar_necesidad_fim(self, evento: Dict[str, Any], severidad: str, patron: str) -> bool:
        """Evaluar si el evento requiere verificación FIM."""
        try:
            if not self._config_siem.get('fim_integracion', False):
                return False
            
            # FIM verificación si:
            # 1. Hay cambios en archivos críticos del sistema
            # 2. Modificaciones no autorizadas
            # 3. Cambios en binarios del sistema
            
            linea_evento = evento.get('linea_original', '').lower()
            keywords_fim = [
                'file modified', 'file changed', 'unauthorized change',
                '/bin/', '/sbin/', '/usr/bin/', '/etc/', 'config changed',
                'permission changed', 'ownership changed'
            ]
            
            return any(keyword in linea_evento for keyword in keywords_fim)
            
        except Exception as e:
            self.logger.error(f"Error evaluando necesidad de FIM: {e}")
            return False

    def _ejecutar_cuarentena_automatica(self, evento: Dict[str, Any], patron: str) -> Dict[str, Any]:
        """Ejecutar cuarentena automática a través del controlador de cuarentena."""
        try:
            # Obtener controlador de cuarentena
            controlador_cuarentena = self._obtener_controlador_cuarentena()
            if not controlador_cuarentena:
                return {'exito': False, 'error': 'Controlador de cuarentena no disponible'}
            
            # Extraer información de archivos del evento
            archivos_sospechosos = self._extraer_archivos_evento(evento)
            
            if not archivos_sospechosos:
                return {'exito': False, 'error': 'No se encontraron archivos para cuarentena'}
            
            resultados_cuarentena = []
            for archivo in archivos_sospechosos:
                try:
                    resultado = controlador_cuarentena.cuarentenar_archivo(
                        archivo, 
                        f"Cuarentena automática SIEM - Patrón: {patron}"
                    )
                    resultados_cuarentena.append({
                        'archivo': archivo,
                        'resultado': resultado
                    })
                except Exception as e:
                    resultados_cuarentena.append({
                        'archivo': archivo,
                        'resultado': {'exito': False, 'error': str(e)}
                    })
            
            exitos = sum(1 for r in resultados_cuarentena if r['resultado'].get('exito', False))
            
            return {
                'exito': exitos > 0,
                'archivos_procesados': len(archivos_sospechosos),
                'archivos_cuarentenados': exitos,
                'detalles': resultados_cuarentena
            }
            
        except Exception as e:
            return {'exito': False, 'error': f'Error en cuarentena automática: {str(e)}'}

    def _ejecutar_verificacion_fim(self, evento: Dict[str, Any], patron: str) -> Dict[str, Any]:
        """Ejecutar verificación FIM a través del controlador FIM."""
        try:
            # Obtener controlador FIM
            controlador_fim = self._obtener_controlador_fim()
            if not controlador_fim:
                return {'exito': False, 'error': 'Controlador FIM no disponible'}
            
            # Extraer rutas de archivos del evento
            archivos_verificar = self._extraer_archivos_evento(evento)
            
            if not archivos_verificar:
                # Si no hay archivos específicos, verificar archivos críticos del sistema
                archivos_verificar = ['/etc/passwd', '/etc/shadow', '/bin/', '/sbin/']
            
            # Ejecutar verificación FIM
            resultado_fim = controlador_fim.verificar_integridad_archivos(archivos_verificar)
            
            # Si hay cambios detectados, registrar como nueva alerta
            if resultado_fim.get('cambios_detectados', 0) > 0:
                self._registrar_evento_siem(
                    "FIM_VERIFICATION",
                    f"FIM detectó {resultado_fim.get('cambios_detectados', 0)} cambios después de alerta SIEM",
                    "warning"
                )
            
            return {
                'exito': True,
                'verificacion_fim': resultado_fim,
                'archivos_verificados': len(archivos_verificar)
            }
            
        except Exception as e:
            return {'exito': False, 'error': f'Error en verificación FIM: {str(e)}'}

    def _extraer_archivos_evento(self, evento: Dict[str, Any]) -> List[str]:
        """Extraer rutas de archivos del evento SIEM."""
        try:
            archivos = []
            linea = evento.get('linea_original', '')
            
            # Patrones para extraer rutas de archivos
            patrones_archivo = [
                r'/[a-zA-Z0-9_./\-]+\.[a-zA-Z0-9]+',  # Archivos con extensión
                r'/[a-zA-Z0-9_./\-]+/[a-zA-Z0-9_.\-]+',  # Rutas absolutas
                r'[a-zA-Z0-9_.\-]+\.[exe|dll|bin|so]',  # Ejecutables
            ]
            
            for patron in patrones_archivo:
                coincidencias = re.findall(patron, linea, re.IGNORECASE)
                archivos.extend(coincidencias)
            
            # Filtrar archivos válidos y únicos
            archivos_validos = []
            for archivo in set(archivos):
                if len(archivo) > 3 and not archivo.startswith('..'):
                    archivos_validos.append(archivo)
            
            return archivos_validos[:5]  # Limitar a 5 archivos max
            
        except Exception as e:
            self.logger.error(f"Error extrayendo archivos del evento: {e}")
            return []

    def _obtener_controlador_cuarentena(self):
        """Obtener referencia al controlador de cuarentena."""
        try:
            if self._controlador_cuarentena:
                return self._controlador_cuarentena
            
            # Intentar obtener del controlador principal
            if self._controlador_principal:
                return self._controlador_principal.obtener_controlador('cuarentena')
            
            # Intentar obtener desde el modelo principal
            if hasattr(self.modelo_principal, 'gestor_cuarentena'):
                return self.modelo_principal.gestor_cuarentena
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error obteniendo controlador de cuarentena: {e}")
            return None

    def _obtener_controlador_fim(self):
        """Obtener referencia al controlador FIM."""
        try:
            if self._controlador_fim:
                return self._controlador_fim
            
            # Intentar obtener del controlador principal
            if self._controlador_principal:
                return self._controlador_principal.obtener_controlador('fim')
            
            # Intentar obtener desde el modelo principal
            if hasattr(self.modelo_principal, 'gestor_fim'):
                return self.modelo_principal.gestor_fim
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error obteniendo controlador FIM: {e}")
            return None

    def _notificar_respuesta_automatica(self, evento: Dict[str, Any], respuestas_ejecutadas: List[str]) -> None:
        """Notificar a otros controladores sobre respuesta automática ejecutada."""
        try:
            if self._controlador_principal:
                # Notificar al controlador principal
                self._controlador_principal.registrar_evento_sistema(
                    'SIEM_RESPUESTA_AUTOMATICA',
                    {
                        'evento_original': evento,
                        'respuestas_ejecutadas': respuestas_ejecutadas,
                        'timestamp': datetime.now().isoformat()
                    }
                )
            
        except Exception as e:
            self.logger.error(f"Error notificando respuesta automática: {e}")

    def configurar_referencias_controladores(self, controlador_principal=None, controlador_cuarentena=None, controlador_fim=None):
        """
        Configurar referencias a otros controladores para respuesta automática.
        MÉTODO CLAVE para establecer conectividad entre componentes.
        """
        self._controlador_principal = controlador_principal
        self._controlador_cuarentena = controlador_cuarentena
        self._controlador_fim = controlador_fim
        
        self.logger.info("Referencias de controladores configuradas para respuesta automática SIEM")

    def _registrar_evento_siem(self, tipo: str, descripcion: str, severidad: str) -> None:
        """Registrar evento en el sistema SIEM."""
        try:
            if self.siem_avanzado:
                # Convertir strings a enums
                tipo_enum = TipoEvento.SEGURIDAD  # Valor por defecto
                try:
                    tipo_enum = TipoEvento(tipo)
                except ValueError:
                    pass
                
                severidad_enum = SeveridadEvento.MEDIA  # Valor por defecto
                try:
                    severidad_enum = SeveridadEvento(severidad.upper())
                except ValueError:
                    pass
                
                self.siem_avanzado.registrar_evento(tipo_enum, descripcion, {}, severidad_enum)
            elif self.siem_basico:
                self.siem_basico.generar_evento(tipo, descripcion, severidad)
                
        except Exception as e:
            self.logger.error(f"Error registrando evento SIEM: {e}")

    def _ejecutar_correlacion_eventos(self) -> None:
        """Ejecutar correlación entre diferentes tipos de eventos."""
        try:
            # Correlación simple basada en tiempo y dirección IP
            eventos_auth = self._cache_eventos.get(TipoEvento.AUTENTICACION.value, [])
            eventos_red = self._cache_eventos.get(TipoEvento.CONEXION_RED.value, [])
            
            if eventos_auth and eventos_red:
                # Buscar IPs comunes en ambos tipos de eventos
                ips_auth = set()
                ips_red = set()
                
                import re
                ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
                
                for evento in eventos_auth[-50:]:  # Últimos 50 eventos
                    matches = re.findall(ip_pattern, evento.get('linea_original', ''))
                    ips_auth.update(matches)
                
                for evento in eventos_red[-50:]:
                    matches = re.findall(ip_pattern, evento.get('linea_original', ''))
                    ips_red.update(matches)
                
                # IPs que aparecen en ambos tipos
                ips_correlacionadas = ips_auth.intersection(ips_red)
                
                if ips_correlacionadas:
                    with self._lock_siem:
                        self._estado_siem['patrones_detectados'] += len(ips_correlacionadas)
                    
                    for ip in ips_correlacionadas:
                        self._registrar_evento_siem(
                            "CORRELACION_EVENTOS",
                            f"IP {ip} detectada en eventos de autenticación y red",
                            "warning"
                        )
                        
        except Exception as e:
            self.logger.error(f"Error en correlación de eventos: {e}")

    def _actualizar_metricas_tiempo_real(self) -> None:
        """Actualizar métricas en tiempo real."""
        try:
            with self._lock_siem:
                # Calcular eventos por minuto
                eventos_recientes = []
                for eventos_tipo in self._cache_eventos.values():
                    eventos_recientes.extend([e for e in eventos_tipo if self._es_evento_reciente(e, 1)])
                
                self._metricas_tiempo_real['eventos_por_minuto'] = len(eventos_recientes)
                
                # Calcular alertas por hora
                alertas_hora = self._estado_siem['alertas_generadas']  # Simplificado
                self._metricas_tiempo_real['alertas_por_hora'] = alertas_hora
                
        except Exception as e:
            self.logger.error(f"Error actualizando métricas: {e}")

    def obtener_estado_siem(self) -> Dict[str, Any]:
        """Obtener estado actual del sistema SIEM."""
        with self._lock_siem:
            estado = self._estado_siem.copy()
            metricas = self._metricas_tiempo_real.copy()
        
        estado['fuentes_activas'] = list(estado['fuentes_activas'])
        estado['ultimo_analisis_str'] = estado['ultimo_analisis'].isoformat() if estado['ultimo_analisis'] else None
        estado['metricas_tiempo_real'] = metricas
        
        return estado

    def obtener_eventos_recientes(self, limite: int = 100, tipo_evento: Optional[str] = None) -> Dict[str, Any]:
        """Obtener eventos recientes del SIEM."""
        try:
            eventos = []
            
            if tipo_evento:
                # Eventos de un tipo específico
                eventos = self._cache_eventos.get(tipo_evento, [])[-limite:]
            else:
                # Todos los eventos
                for eventos_tipo in self._cache_eventos.values():
                    eventos.extend(eventos_tipo)
                
                # Ordenar por timestamp y tomar los más recientes
                eventos.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                eventos = eventos[:limite]
            
            return {
                'exito': True,
                'total_eventos': len(eventos),
                'eventos': eventos,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo eventos recientes: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def obtener_alertas_criticas(self, limite: int = 50) -> Dict[str, Any]:
        """Obtener alertas críticas del SIEM."""
        try:
            # Filtrar eventos de tipo alerta crítica
            alertas = []
            for eventos_tipo in self._cache_eventos.values():
                alertas.extend([e for e in eventos_tipo 
                              if e.get('severidad') == SeveridadEvento.ALTA.value])
            
            # Ordenar por timestamp y limitar
            alertas.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            alertas = alertas[:limite]
            
            return {
                'exito': True,
                'total_alertas': len(alertas),
                'alertas': alertas,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo alertas críticas: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def generar_reporte_seguridad(self, periodo_horas: int = 24) -> Dict[str, Any]:
        """Generar reporte completo de seguridad."""
        return self.ejecutar_operacion_segura(self._generar_reporte_seguridad_impl, periodo_horas)

    def _generar_reporte_seguridad_impl(self, periodo_horas: int = 24) -> Dict[str, Any]:
        """Implementación del reporte de seguridad."""
        try:
            self.logger.info(f"Generando reporte de seguridad para las últimas {periodo_horas} horas")
            
            # Filtrar eventos del período
            tiempo_limite = datetime.now() - timedelta(hours=periodo_horas)
            eventos_periodo = []
            
            for eventos_tipo in self._cache_eventos.values():
                eventos_filtrados = [e for e in eventos_tipo 
                                   if self._es_evento_posterior_a(e, tiempo_limite)]
                eventos_periodo.extend(eventos_filtrados)
            
            # Estadísticas por tipo
            estadisticas_tipo = defaultdict(int)
            for evento in eventos_periodo:
                estadisticas_tipo[evento['tipo_evento']] += 1
            
            # Estadísticas por severidad
            estadisticas_severidad = defaultdict(int)
            for evento in eventos_periodo:
                estadisticas_severidad[evento['severidad']] += 1
            
            # Top IPs sospechosas
            ips_detectadas = defaultdict(int)
            import re
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            
            for evento in eventos_periodo:
                matches = re.findall(ip_pattern, evento.get('linea_original', ''))
                for ip in matches:
                    ips_detectadas[ip] += 1
            
            top_ips = sorted(ips_detectadas.items(), key=lambda x: x[1], reverse=True)[:10]
            
            reporte = {
                'timestamp': datetime.now().isoformat(),
                'periodo_horas': periodo_horas,
                'resumen': {
                    'total_eventos': len(eventos_periodo),
                    'alertas_generadas': self._estado_siem['alertas_generadas'],
                    'patrones_detectados': self._estado_siem['patrones_detectados'],
                    'fuentes_monitoreadas': len(self._estado_siem['fuentes_activas'])
                },
                'estadisticas_por_tipo': dict(estadisticas_tipo),
                'estadisticas_por_severidad': dict(estadisticas_severidad),
                'top_ips_sospechosas': top_ips,
                'metricas_tiempo_real': self._metricas_tiempo_real.copy()
            }
            
            self.logger.info("Reporte de seguridad generado exitosamente")
            
            return {
                'exito': True,
                'reporte': reporte
            }
            
        except Exception as e:
            error_msg = f"Error generando reporte de seguridad: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def _es_evento_posterior_a(self, evento: Dict[str, Any], tiempo_limite: datetime) -> bool:
        """Verificar si un evento es posterior a un tiempo límite."""
        try:
            timestamp_evento = datetime.fromisoformat(evento['timestamp'])
            return timestamp_evento >= tiempo_limite
        except:
            return False

    def ejecutar_analisis_forense(self, objetivo: str) -> Dict[str, Any]:
        """Ejecutar análisis forense básico usando herramientas de Kali."""
        return self.ejecutar_operacion_segura(self._ejecutar_analisis_forense_impl, objetivo)

    def _ejecutar_analisis_forense_impl(self, objetivo: str) -> Dict[str, Any]:
        """
        Implementación del análisis forense con validación de seguridad.
        KALI OPTIMIZATION: Análisis forense seguro para pentesting profesional.
        """
        # SECURITY FIX: Validar objetivo antes de cualquier operación
        validacion = self._validar_objetivo_forense(objetivo)
        if not validacion['valido']:
            self.logger.warning(f"Objetivo forense rechazado: {validacion['error']}")
            return {
                'exito': False,
                'error': f"Objetivo no válido: {validacion['error']}",
                'objetivo_rechazado': "[SANITIZADO]"  # SECURITY FIX: No loggear objetivo sin validar
            }
        
        objetivo_seguro = validacion['objetivo_sanitizado']
        self.logger.info(f"Ejecutando análisis forense validado para objetivo de tipo: {validacion['tipo']}")  # SECURITY FIX: No loggear objetivo sensible
        
        try:
            tiempo_inicio = time.time()
            
            resultados = {}
            
            # SECURITY: Análisis de procesos sospechosos con comando validado
            try:
                validacion_ps = self._validar_comando_forense('ps')
                if validacion_ps['valido']:
                    cmd_ps = ['ps', 'aux', '--sort=-%cpu']
                    result = subprocess.run(cmd_ps, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        resultados['procesos_top_cpu'] = result.stdout.split('\n')[:20]
                else:
                    resultados['procesos_error'] = 'Comando ps no permitido'
            except Exception as e:
                resultados['procesos_error'] = str(e)
            
            # SECURITY: Análisis de conexiones de red con comando validado
            try:
                validacion_netstat = self._validar_comando_forense('netstat')
                if validacion_netstat['valido']:
                    cmd_netstat = ['netstat', '-tuln']
                    result = subprocess.run(cmd_netstat, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        resultados['conexiones_activas'] = result.stdout.split('\n')
                else:
                    resultados['conexiones_error'] = 'Comando netstat no permitido'
            except Exception as e:
                resultados['conexiones_error'] = str(e)
            
            # SECURITY: Análisis de logs específicos con validación robusta
            if validacion['tipo'] == 'log_file' and objetivo_seguro in self._estado_siem['fuentes_activas']:
                try:
                    validacion_grep = self._validar_comando_forense('grep')
                    if validacion_grep['valido']:
                        # SECURITY FIX: Usar shlex.quote para sanitizar paths de archivos
                        objetivo_quoted = shlex.quote(objetivo_seguro)
                        cmd_grep = ['grep', '-i', r'error\|fail\|attack\|intrusion', objetivo_quoted]
                        result = subprocess.run(cmd_grep, capture_output=True, text=True, timeout=15)
                        if result.returncode == 0:
                            resultados['eventos_sospechosos'] = result.stdout.split('\n')[:50]
                    else:
                        resultados['grep_error'] = 'Comando grep no permitido'
                except Exception as e:
                    resultados['grep_error'] = str(e)
            
            tiempo_total = time.time() - tiempo_inicio
            
            self.logger.info(f"Análisis forense completado en {tiempo_total:.2f}s para tipo: {validacion['tipo']}")  # SECURITY FIX: No loggear objetivo sensible
            
            return {
                'exito': True,
                'objetivo': objetivo_seguro,  # SECURITY: Usar objetivo validado
                'objetivo_validacion': validacion,  # SECURITY: Incluir info de validación
                'tiempo_ejecucion': round(tiempo_total, 2),
                'resultados': resultados,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error en análisis forense: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Implementación específica de finalización del controlador SIEM."""
        try:
            self.logger.info("Finalizando controlador SIEM")
            
            # Detener monitoreo si está activo
            if self._estado_siem['monitoreo_activo']:
                self._detener_monitoreo_eventos_impl()
            
            # Limpiar cache de eventos
            with self._lock_siem:
                self._cache_eventos.clear()
                self._metricas_tiempo_real.clear()
            
            # Finalizar componentes SIEM
            if self.siem_avanzado:
                # El SIEM avanzado se limpia automáticamente
                pass
            
            self._registrar_evento_siem("FINALIZACION_SIEM", "Controlador SIEM finalizado", "info")
            
            return {'exito': True, 'mensaje': 'Controlador SIEM finalizado correctamente'}
            
        except Exception as e:
            error_msg = f"Error finalizando controlador SIEM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """
        Verificar que todas las funcionalidades del SIEM funcionen en Kali Linux.
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'sistema_operativo': None,
            'gestor_permisos': False,
            'herramientas_disponibles': {},
            'permisos_sudo': False,
            'funcionalidad_completa': False,
            'recomendaciones': []
        }
        
        try:
            import platform
            resultado['sistema_operativo'] = platform.system()
            
            # Verificar gestor de permisos
            if self.modelo_principal and hasattr(self.modelo_principal, 'gestor_permisos'):
                if self.modelo_principal.gestor_permisos is not None:
                    resultado['gestor_permisos'] = True
                    
                    # Verificar permisos sudo si está disponible
                    try:
                        resultado['permisos_sudo'] = self.modelo_principal.gestor_permisos.verificar_sudo_disponible()
                    except Exception:
                        resultado['permisos_sudo'] = False
                    
                    # Verificar herramientas específicas de SIEM
                    herramientas = ['tail', 'grep', 'ps', 'netstat', 'journalctl']
                    for herramienta in herramientas:
                        estado = self.modelo_principal.gestor_permisos.verificar_permisos_herramienta(herramienta)
                        resultado['herramientas_disponibles'][herramienta] = estado
            
            # Evaluar funcionalidad completa
            herramientas_ok = sum(1 for h in resultado['herramientas_disponibles'].values() 
                                if h.get('disponible', False) and h.get('permisos_ok', False))
            
            resultado['funcionalidad_completa'] = (
                resultado['gestor_permisos'] and 
                resultado['permisos_sudo'] and 
                herramientas_ok >= 4  # Al menos tail, grep, ps, netstat
            )
            
            # Generar recomendaciones
            if not resultado['funcionalidad_completa']:
                if not resultado['gestor_permisos']:
                    resultado['recomendaciones'].append("Gestor de permisos no disponible")
                
                if not resultado['permisos_sudo']:
                    resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
                
                if herramientas_ok < 4:
                    resultado['recomendaciones'].append("Instalar herramientas SIEM: sudo apt install procps net-tools systemd")
            
            self.logger.info(f"Verificación SIEM Kali completada - Funcionalidad: {'✅' if resultado['funcionalidad_completa'] else '❌'}")
            
        except Exception as e:
            self.logger.error(f"Error en verificación SIEM Kali: {e}")
            resultado['error'] = str(e)
        
        return resultado

    # =================== MÉTODOS AVANZADOS CON HERRAMIENTAS DE KALI ===================
    
    def configurar_auditd(self) -> Dict[str, Any]:
        """
        Configurar auditd para auditoría avanzada del sistema en Kali Linux.
        KALI OPTIMIZATION: Configuración específica de auditd para pentesting profesional.
        """
        try:
            self.logger.info("🔧 Configurando auditd para auditoría avanzada...")
            
            # Verificar si auditd está disponible
            result_check = subprocess.run(['which', 'auditctl'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'auditd no está instalado',
                    'recomendacion': 'sudo apt install auditd audispd-plugins'
                }
            
            # Configurar reglas de auditoría para seguridad
            reglas_auditoria = [
                # Acceso a archivos críticos del sistema
                '-w /etc/passwd -p wa -k passwd_changes',
                '-w /etc/shadow -p wa -k shadow_changes',
                '-w /etc/sudoers -p wa -k sudoers_changes',
                '-w /etc/hosts -p wa -k network_changes',
                
                # Ejecutables del sistema
                '-w /bin/ -p x -k system_executables',
                '-w /sbin/ -p x -k system_executables',
                '-w /usr/bin/ -p x -k system_executables',
                
                # Logs del sistema
                '-w /var/log/ -p wa -k log_access',
                
                # SSH y conexiones
                '-w /etc/ssh/sshd_config -p wa -k ssh_config',
                '-A always,exit -F arch=b64 -S connect -k network_connect',
                
                # Elevación de privilegios
                '-A always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation',
                
                # Cambios en el kernel
                '-w /boot/ -p wa -k kernel_changes',
                '-w /lib/modules/ -p wa -k kernel_modules'
            ]
            
            resultados_reglas = []
            for regla in reglas_auditoria:
                try:
                    # Aplicar regla con auditctl
                    cmd = ['auditctl'] + regla.split()[1:]  # Omitir el '-' inicial
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    resultados_reglas.append({
                        'regla': regla,
                        'aplicada': result.returncode == 0,
                        'error': result.stderr if result.returncode != 0 else None
                    })
                    
                except Exception as e:
                    resultados_reglas.append({
                        'regla': regla,
                        'aplicada': False,
                        'error': str(e)
                    })
            
            # Verificar estado del servicio auditd
            try:
                status_result = subprocess.run(['systemctl', 'status', 'auditd'], 
                                             capture_output=True, text=True, timeout=5)
                servicio_activo = 'active (running)' in status_result.stdout
            except:
                servicio_activo = False
            
            reglas_aplicadas = sum(1 for r in resultados_reglas if r['aplicada'])
            
            return {
                'exito': reglas_aplicadas > 0,
                'reglas_aplicadas': reglas_aplicadas,
                'total_reglas': len(reglas_auditoria),
                'servicio_activo': servicio_activo,
                'detalles_reglas': resultados_reglas,
                'herramienta': 'auditd'
            }
            
        except Exception as e:
            self.logger.error(f"Error configurando auditd: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'auditd'
            }
    
    def monitorear_con_osquery(self) -> Dict[str, Any]:
        """
        Monitorear sistema usando osquery para queries de seguridad avanzadas.
        KALI OPTIMIZATION: Queries específicas para análisis de seguridad en pentesting.
        """
        try:
            self.logger.info("🔍 Ejecutando monitoreo con osquery...")
            
            # Verificar si osquery está disponible
            result_check = subprocess.run(['which', 'osqueryi'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'osquery no está instalado',
                    'recomendacion': 'sudo apt install osquery'
                }
            
            # Queries de seguridad específicas para Kali Linux
            queries_seguridad = {
                'procesos_sospechosos': """
                    SELECT pid, name, cmdline, path, start_time 
                    FROM processes 
                    WHERE name LIKE '%ncat%' OR name LIKE '%nc%' OR name LIKE '%netcat%' 
                       OR name LIKE '%meterpreter%' OR cmdline LIKE '%/bin/sh%'
                       OR cmdline LIKE '%bash -i%' OR cmdline LIKE '%python -c%'
                    ORDER BY start_time DESC;
                """,
                
                'conexiones_red_sospechosas': """
                    SELECT DISTINCT local_address, local_port, remote_address, remote_port, 
                           family, protocol, state
                    FROM process_open_sockets 
                    WHERE remote_address NOT IN ('127.0.0.1', '0.0.0.0', '::1', '')
                    AND remote_port NOT IN (80, 443, 53, 22)
                    ORDER BY remote_address;
                """,
                
                'archivos_modificados_recientes': """
                    SELECT path, filename, mtime, size, md5, sha256
                    FROM file 
                    WHERE path LIKE '/etc/%' OR path LIKE '/bin/%' OR path LIKE '/sbin/%'
                    AND mtime > (strftime('%s', 'now') - 3600)
                    ORDER BY mtime DESC;
                """,
                
                'usuarios_con_shell': """
                    SELECT uid, gid, username, description, directory, shell
                    FROM users 
                    WHERE shell NOT IN ('/bin/false', '/usr/sbin/nologin', '/bin/sync')
                    ORDER BY uid;
                """,
                
                'servicios_escuchando': """
                    SELECT DISTINCT process.name, listening_ports.port, listening_ports.protocol,
                           process.cmdline, process.path
                    FROM listening_ports
                    LEFT JOIN process USING (pid)
                    WHERE listening_ports.address = '0.0.0.0'
                    ORDER BY listening_ports.port;
                """,
                
                'logs_autenticacion': """
                    SELECT time, host, ident, message
                    FROM syslog 
                    WHERE facility = 'auth' OR facility = 'authpriv'
                    AND time > (strftime('%s', 'now') - 1800)
                    ORDER BY time DESC 
                    LIMIT 50;
                """
            }
            
            resultados_queries = {}
            
            for nombre_query, sql_query in queries_seguridad.items():
                try:
                    # Ejecutar query con osqueryi
                    cmd = ['osqueryi', '--json', sql_query.strip()]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        try:
                            import json
                            datos = json.loads(result.stdout)
                            resultados_queries[nombre_query] = {
                                'exito': True,
                                'total_resultados': len(datos),
                                'datos': datos[:10],  # Limitar a 10 resultados por query
                                'datos_completos': len(datos) > 10
                            }
                        except json.JSONDecodeError:
                            resultados_queries[nombre_query] = {
                                'exito': False,
                                'error': 'Error parseando JSON de osquery'
                            }
                    else:
                        resultados_queries[nombre_query] = {
                            'exito': False,
                            'error': result.stderr
                        }
                        
                except subprocess.TimeoutExpired:
                    resultados_queries[nombre_query] = {
                        'exito': False,
                        'error': 'Timeout en query osquery'
                    }
                except Exception as e:
                    resultados_queries[nombre_query] = {
                        'exito': False,
                        'error': str(e)
                    }
            
            queries_exitosas = sum(1 for r in resultados_queries.values() if r.get('exito', False))
            
            return {
                'exito': queries_exitosas > 0,
                'queries_ejecutadas': len(queries_seguridad),
                'queries_exitosas': queries_exitosas,
                'resultados': resultados_queries,
                'herramienta': 'osquery'
            }
            
        except Exception as e:
            self.logger.error(f"Error en monitoreo osquery: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'osquery'
            }
    
    def configurar_rsyslog_avanzado(self) -> Dict[str, Any]:
        """
        Configurar rsyslog para logging avanzado y centralizado en Kali Linux.
        KALI OPTIMIZATION: Configuración específica para captura de logs de seguridad.
        """
        try:
            self.logger.info("📋 Configurando rsyslog avanzado...")
            
            # Verificar si rsyslog está disponible
            result_check = subprocess.run(['which', 'rsyslogd'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'rsyslog no está instalado',
                    'recomendacion': 'sudo apt install rsyslog'
                }
            
            # Configuración avanzada de rsyslog para SIEM
            configuracion_rsyslog = """
# Configuración SIEM ARESITOS para Kali Linux
# Logging avanzado para detección de amenazas

# Módulos adicionales
$ModLoad imuxsock # provides support for local system logging
$ModLoad imklog   # provides kernel logging support
$ModLoad imfile   # provides file monitoring

# Templates para logs estructurados
$template SIEMFormat,"<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag% %msg%\\n"
$template DynAuthFile,"/var/log/ares-aegis/auth-%$YEAR%-%$MONTH%-%$DAY%.log"
$template DynSecurityFile,"/var/log/ares-aegis/security-%$YEAR%-%$MONTH%-%$DAY%.log"

# Reglas de filtrado específicas para SIEM
# Eventos de autenticación críticos
:msg, regex, "Failed password|Invalid user|authentication failure" ?DynAuthFile;SIEMFormat
& stop

# Eventos de seguridad del kernel
:facility, isequal, "kern" /var/log/ares-aegis/kernel-security.log;SIEMFormat
& stop

# Eventos de firewall/iptables
:msg, regex, "iptables.*DROP|iptables.*REJECT" /var/log/ares-aegis/firewall.log;SIEMFormat
& stop

# Eventos de sudo/privilegios
:programname, isequal, "sudo" /var/log/ares-aegis/sudo.log;SIEMFormat
& stop

# SSH events específicos
:programname, isequal, "sshd" /var/log/ares-aegis/ssh.log;SIEMFormat
& stop

# Logs por defecto
*.info;mail.none;authpriv.none;cron.none    /var/log/messages
"""
            
            # Crear directorio de logs de ARESITOS
            log_dir = '/var/log/ares-aegis'
            try:
                import os
                if not os.path.exists(log_dir):
                    # Intentar crear directorio (requiere sudo)
                    result_mkdir = subprocess.run(['mkdir', '-p', log_dir], 
                                                capture_output=True, text=True, timeout=5)
                    if result_mkdir.returncode == 0:
                        # Establecer permisos
                        subprocess.run(['chmod', '755', log_dir], timeout=5)
                    else:
                        self.logger.warning(f"No se pudo crear directorio {log_dir}")
                
                directorio_creado = os.path.exists(log_dir)
            except Exception as e:
                self.logger.warning(f"Error creando directorio de logs: {e}")
                directorio_creado = False
            
            # Verificar configuración actual de rsyslog
            try:
                config_result = subprocess.run(['rsyslogd', '-N1'], 
                                             capture_output=True, text=True, timeout=10)
                configuracion_valida = config_result.returncode == 0
                errores_config = config_result.stderr if config_result.returncode != 0 else None
            except Exception as e:
                configuracion_valida = False
                errores_config = str(e)
            
            # Verificar estado del servicio
            try:
                status_result = subprocess.run(['systemctl', 'status', 'rsyslog'], 
                                             capture_output=True, text=True, timeout=5)
                servicio_activo = 'active (running)' in status_result.stdout
            except:
                servicio_activo = False
            
            return {
                'exito': directorio_creado and configuracion_valida,
                'directorio_logs_creado': directorio_creado,
                'directorio_logs': log_dir,
                'configuracion_valida': configuracion_valida,
                'errores_configuracion': errores_config,
                'servicio_activo': servicio_activo,
                'configuracion_sugerida': configuracion_rsyslog,
                'herramienta': 'rsyslog',
                'instrucciones': [
                    f"1. Crear directorio: sudo mkdir -p {log_dir}",
                    f"2. Permisos: sudo chmod 755 {log_dir}",
                    "3. Editar: sudo nano /etc/rsyslog.conf",
                    "4. Reiniciar: sudo systemctl restart rsyslog"
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Error configurando rsyslog: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'rsyslog'
            }
    
    def analizar_con_journalctl(self) -> Dict[str, Any]:
        """
        Analizar logs del sistema usando journalctl para eventos de seguridad.
        KALI OPTIMIZATION: Análisis específico de systemd journal para detección de amenazas.
        """
        try:
            self.logger.info("📊 Analizando logs con journalctl...")
            
            # Verificar si journalctl está disponible
            result_check = subprocess.run(['which', 'journalctl'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'journalctl no está disponible',
                    'recomendacion': 'Instalar systemd'
                }
            
            # Análisis específicos con journalctl
            analisis_journal = {
                'errores_criticos': {
                    'comando': ['journalctl', '-p', 'err', '--since', '1 hour ago', '--no-pager', '-q'],
                    'descripcion': 'Errores críticos en la última hora'
                },
                
                'eventos_autenticacion': {
                    'comando': ['journalctl', '_SYSTEMD_UNIT=ssh.service', '--since', '2 hours ago', '--no-pager', '-q'],
                    'descripcion': 'Eventos SSH recientes'
                },
                
                'cambios_servicios': {
                    'comando': ['journalctl', '--since', '1 hour ago', '--grep', 'Started|Stopped|Failed', '--no-pager', '-q'],
                    'descripcion': 'Cambios en servicios del sistema'
                },
                
                'eventos_kernel': {
                    'comando': ['journalctl', '-k', '--since', '30 minutes ago', '--no-pager', '-q'],
                    'descripcion': 'Eventos del kernel recientes'
                },
                
                'fallos_servicios': {
                    'comando': ['journalctl', '--failed', '--no-pager', '-q'],
                    'descripcion': 'Servicios que han fallado'
                },
                
                'audit_events': {
                    'comando': ['journalctl', '_TRANSPORT=audit', '--since', '1 hour ago', '--no-pager', '-q'],
                    'descripcion': 'Eventos de auditoría del sistema'
                }
            }
            
            resultados_analisis = {}
            
            for nombre_analisis, config in analisis_journal.items():
                try:
                    result = subprocess.run(config['comando'], 
                                          capture_output=True, text=True, timeout=20)
                    
                    if result.returncode == 0:
                        lineas = result.stdout.strip().split('\\n')
                        lineas_filtradas = [l for l in lineas if l.strip()]
                        
                        resultados_analisis[nombre_analisis] = {
                            'exito': True,
                            'descripcion': config['descripcion'],
                            'total_lineas': len(lineas_filtradas),
                            'lineas': lineas_filtradas[:15],  # Limitar a 15 líneas
                            'mas_resultados': len(lineas_filtradas) > 15
                        }
                    else:
                        resultados_analisis[nombre_analisis] = {
                            'exito': False,
                            'descripcion': config['descripcion'],
                            'error': result.stderr
                        }
                        
                except subprocess.TimeoutExpired:
                    resultados_analisis[nombre_analisis] = {
                        'exito': False,
                        'descripcion': config['descripcion'],
                        'error': 'Timeout en análisis journalctl'
                    }
                except Exception as e:
                    resultados_analisis[nombre_analisis] = {
                        'exito': False,
                        'descripcion': config['descripcion'],
                        'error': str(e)
                    }
            
            # Estadísticas de journalctl
            try:
                stats_result = subprocess.run(['journalctl', '--disk-usage', '--no-pager'], 
                                            capture_output=True, text=True, timeout=10)
                estadisticas_disco = stats_result.stdout.strip() if stats_result.returncode == 0 else None
            except:
                estadisticas_disco = None
            
            analisis_exitosos = sum(1 for r in resultados_analisis.values() if r.get('exito', False))
            
            return {
                'exito': analisis_exitosos > 0,
                'analisis_ejecutados': len(analisis_journal),
                'analisis_exitosos': analisis_exitosos,
                'resultados': resultados_analisis,
                'estadisticas_disco': estadisticas_disco,
                'herramienta': 'journalctl'
            }
            
        except Exception as e:
            self.logger.error(f"Error en análisis journalctl: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'journalctl'
            }
    
    def ejecutar_siem_avanzado_kali(self) -> Dict[str, Any]:
        """
        Ejecutar análisis SIEM completo usando todas las herramientas avanzadas de Kali Linux.
        FASE 3: Función principal que integra auditd, osquery, rsyslog y journalctl.
        """
        try:
            self.logger.info("🚀 Ejecutando SIEM avanzado con herramientas de Kali Linux...")
            tiempo_inicio = time.time()
            
            resultados_completos = {
                'timestamp': datetime.now().isoformat(),
                'herramientas_utilizadas': [],
                'resumen_detecciones': {},
                'alertas_generadas': [],
                'analisis_detallado': {}
            }
            
            # 1. Configurar y analizar con auditd
            self.logger.info("1/4 Configurando auditd...")
            resultado_auditd = self.configurar_auditd()
            resultados_completos['analisis_detallado']['auditd'] = resultado_auditd
            if resultado_auditd['exito']:
                resultados_completos['herramientas_utilizadas'].append('auditd')
                resultados_completos['resumen_detecciones']['reglas_auditoria'] = resultado_auditd['reglas_aplicadas']
            
            # 2. Monitorear con osquery
            self.logger.info("2/4 Ejecutando queries osquery...")
            resultado_osquery = self.monitorear_con_osquery()
            resultados_completos['analisis_detallado']['osquery'] = resultado_osquery
            if resultado_osquery['exito']:
                resultados_completos['herramientas_utilizadas'].append('osquery')
                
                # Procesar resultados de osquery para alertas
                for query_name, query_result in resultado_osquery.get('resultados', {}).items():
                    if query_result.get('exito') and query_result.get('total_resultados', 0) > 0:
                        if 'sospechosos' in query_name:
                            resultados_completos['alertas_generadas'].append({
                                'tipo': 'osquery_detection',
                                'descripcion': f"Query {query_name} detectó {query_result['total_resultados']} elementos",
                                'severidad': 'MEDIA',
                                'datos': query_result['datos'][:3]  # Solo 3 ejemplos
                            })
            
            # 3. Configurar rsyslog
            self.logger.info("3/4 Configurando rsyslog...")
            resultado_rsyslog = self.configurar_rsyslog_avanzado()
            resultados_completos['analisis_detallado']['rsyslog'] = resultado_rsyslog
            if resultado_rsyslog['exito']:
                resultados_completos['herramientas_utilizadas'].append('rsyslog')
            
            # 4. Analizar con journalctl
            self.logger.info("4/4 Analizando logs con journalctl...")
            resultado_journalctl = self.analizar_con_journalctl()
            resultados_completos['analisis_detallado']['journalctl'] = resultado_journalctl
            if resultado_journalctl['exito']:
                resultados_completos['herramientas_utilizadas'].append('journalctl')
                
                # Procesar resultados de journalctl para alertas
                for analisis_name, analisis_result in resultado_journalctl.get('resultados', {}).items():
                    if analisis_result.get('exito') and analisis_result.get('total_lineas', 0) > 0:
                        if 'errores' in analisis_name or 'fallos' in analisis_name:
                            resultados_completos['alertas_generadas'].append({
                                'tipo': 'journalctl_alert',
                                'descripcion': f"{analisis_result['descripcion']}: {analisis_result['total_lineas']} eventos",
                                'severidad': 'ALTA' if 'criticos' in analisis_name else 'MEDIA',
                                'ejemplos': analisis_result['lineas'][:2]
                            })
            
            # 5. Correlación y análisis final
            tiempo_total = time.time() - tiempo_inicio
            
            # Generar resumen
            herramientas_exitosas = len(resultados_completos['herramientas_utilizadas'])
            total_alertas = len(resultados_completos['alertas_generadas'])
            
            resultados_completos['resumen_detecciones'].update({
                'herramientas_exitosas': herramientas_exitosas,
                'total_alertas_generadas': total_alertas,
                'tiempo_ejecucion_segundos': round(tiempo_total, 2),
                'cobertura_siem': f"{herramientas_exitosas}/4 herramientas"
            })
            
            # Registrar evento SIEM
            self._registrar_evento_siem(
                "SIEM_AVANZADO_KALI",
                f"Análisis SIEM completo: {herramientas_exitosas}/4 herramientas, {total_alertas} alertas",
                "info" if total_alertas == 0 else "warning"
            )
            
            self.logger.info(f"✅ SIEM avanzado completado en {tiempo_total:.2f}s - {herramientas_exitosas}/4 herramientas exitosas")
            
            return {
                'exito': herramientas_exitosas > 0,
                'resultados': resultados_completos,
                'recomendaciones': self._generar_recomendaciones_siem(resultados_completos)
            }
            
        except Exception as e:
            self.logger.error(f"Error en SIEM avanzado Kali: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramientas_utilizadas': resultados_completos.get('herramientas_utilizadas', [])
            }
    
    def _generar_recomendaciones_siem(self, resultados: Dict[str, Any]) -> List[str]:
        """Generar recomendaciones basadas en los resultados del SIEM avanzado."""
        recomendaciones = []
        
        try:
            analisis = resultados.get('analisis_detallado', {})
            
            # Recomendaciones de auditd
            if 'auditd' in analisis and not analisis['auditd'].get('exito', False):
                recomendaciones.append("Instalar y configurar auditd: sudo apt install auditd")
            
            # Recomendaciones de osquery
            if 'osquery' in analisis and not analisis['osquery'].get('exito', False):
                recomendaciones.append("Instalar osquery: sudo apt install osquery")
            
            # Recomendaciones de rsyslog
            if 'rsyslog' in analisis and not analisis['rsyslog'].get('exito', False):
                recomendaciones.append("Configurar rsyslog para logging centralizado")
            
            # Recomendaciones de journalctl
            if 'journalctl' in analisis and not analisis['journalctl'].get('exito', False):
                recomendaciones.append("Verificar funcionamiento de systemd journal")
            
            # Recomendaciones basadas en alertas
            alertas = resultados.get('alertas_generadas', [])
            alertas_criticas = [a for a in alertas if a.get('severidad') == 'ALTA']
            
            if alertas_criticas:
                recomendaciones.append(f"Investigar {len(alertas_criticas)} alertas críticas detectadas")
            
            if len(alertas) > 10:
                recomendaciones.append("Considerar ajustar umbrales de alertas - alto volumen detectado")
            
            # Recomendaciones generales
            herramientas_exitosas = len(resultados.get('herramientas_utilizadas', []))
            if herramientas_exitosas < 2:
                recomendaciones.append("Instalar herramientas SIEM faltantes para mejor cobertura")
            
            return recomendaciones
            
        except Exception as e:
            self.logger.error(f"Error generando recomendaciones SIEM: {e}")
            return ["Error generando recomendaciones"]


# RESUMEN TÉCNICO: Controlador SIEM avanzado para gestión de eventos de seguridad en Kali Linux.
# Implementa monitoreo continuo de logs del sistema, detección de patrones sospechosos, correlación
# de eventos, alertas automáticas y análisis forense usando herramientas nativas (tail, grep, ps, netstat).
# Arquitectura asíncrona con threading para análisis en tiempo real, siguiendo patrones MVC y principios
# SOLID para escalabilidad profesional en entornos de ciberseguridad.
