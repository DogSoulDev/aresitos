# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Escaneo
Controlador especializado en operaciones de escaneo de seguridad
"""

import asyncio
import threading
import time
import re
import ipaddress
import socket
from datetime import datetime
from typing import Dict, Any, List, Optional

from ares_aegis.controlador.controlador_base import ControladorBase
from ares_aegis.modelo.modelo_escaneador import EscaneadorAvanzado, Escaneador, TipoEscaneo, NivelCriticidad
from ares_aegis.modelo.modelo_siem import SIEMAvanzado, SIEM, TipoEvento, SeveridadEvento

class ControladorEscaneo(ControladorBase):
    """
    Controlador especializado en operaciones de escaneo de seguridad.
    Coordina escaneadores de puertos, vulnerabilidades y análisis de red.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorEscaneo")
        
        self.modelo_principal = modelo_principal
        
        # Inicializar componentes inmediatamente para compatibilidad
        try:
            self.siem = SIEM()  # Usar clase de compatibilidad
            self.escaneador = Escaneador(self.siem)  # Usar clase de compatibilidad
            
            # Verificar que el escaneador tenga gestor de permisos
            if hasattr(self.escaneador, 'gestor_permisos') and self.escaneador.gestor_permisos:
                self.logger.info("✅ Escaneador inicializado con gestor de permisos")
            else:
                self.logger.warning("⚠️  Escaneador sin gestor de permisos - funcionalidad limitada")
                
        except Exception as e:
            self.logger.error(f"❌ Error inicializando componentes: {e}")
            self.escaneador = None
            self.siem = None
        
        # Estado específico del escaneo
        self._estado_escaneo = {
            'escaneo_en_progreso': False,
            'ultimo_objetivo': None,
            'ultimos_resultados': None,
            'total_escaneos_realizados': 0
        }
        
        # SECURITY: Lock para operaciones concurrentes (SECURITY FIX)
        self._lock_escaneo = threading.Lock()
        
        # Configuración de escaneo
        self._config_escaneo = {
            'timeout_conexion': 3,
            'max_hilos': 50,
            'puerto_inicial': 1,
            'puerto_final': 1000,
            'intentos_maximos': 3
        }
        
        # SECURITY: Herramientas permitidas para escaneo en Kali (SECURITY FIX)
        self._herramientas_escaneo_permitidas = {
            'nmap', 'netstat', 'ss', 'lsof', 'arp-scan', 'masscan'
        }
        
        # SECURITY: Rangos de IP permitidos para Kali (pentesting ético)
        self._redes_permitidas = [
            '127.0.0.0/8',      # Localhost
            '10.0.0.0/8',       # RFC 1918 - Redes privadas
            '172.16.0.0/12',    # RFC 1918 - Redes privadas  
            '192.168.0.0/16',   # RFC 1918 - Redes privadas
            '169.254.0.0/16'    # Link-local
        ]
        
        self.logger.info("Controlador de Escaneo inicializado")
    
    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """
        Verificar que todas las funcionalidades del escaneador funcionen en Kali Linux.
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
            if self.escaneador and hasattr(self.escaneador, 'gestor_permisos'):
                if self.escaneador.gestor_permisos is not None:
                    resultado['gestor_permisos'] = True
                    
                    # Verificar sudo
                    resultado['permisos_sudo'] = self.escaneador.gestor_permisos.verificar_sudo_disponible()
                    
                    # Verificar herramientas
                    herramientas = ['nmap', 'netstat', 'ss']
                    for herramienta in herramientas:
                        estado = self.escaneador.gestor_permisos.verificar_permisos_herramienta(herramienta)
                        resultado['herramientas_disponibles'][herramienta] = estado
            
            # Evaluar funcionalidad completa
            herramientas_ok = sum(1 for h in resultado['herramientas_disponibles'].values() 
                                if h.get('disponible', False) and h.get('permisos_ok', False))
            
            resultado['funcionalidad_completa'] = (
                resultado['gestor_permisos'] and 
                resultado['permisos_sudo'] and 
                herramientas_ok >= 2
            )
            
            # Generar recomendaciones
            if not resultado['funcionalidad_completa']:
                if not resultado['gestor_permisos']:
                    resultado['recomendaciones'].append("Gestor de permisos no disponible")
                
                if not resultado['permisos_sudo']:
                    resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
                
                if herramientas_ok < 2:
                    resultado['recomendaciones'].append("Instalar herramientas: sudo apt install nmap netstat-nat net-tools")
            
            self.logger.info(f"Verificación Kali completada - Funcionalidad: {'✅' if resultado['funcionalidad_completa'] else '❌'}")
            
        except Exception as e:
            self.logger.error(f"Error en verificación Kali: {e}")
            resultado['error'] = str(e)
        
        return resultado
    
    def _validar_objetivo_escaneo(self, objetivo: str) -> Dict[str, Any]:
        """
        Valida que el objetivo de escaneo sea seguro y ético.
        KALI OPTIMIZATION: Validación específica para pentesting ético.
        """
        if not objetivo or not isinstance(objetivo, str):
            return {'valido': False, 'error': 'Objetivo no válido'}
        
        # Limpiar espacios y caracteres peligrosos
        objetivo = objetivo.strip()
        
        # SECURITY FIX: Prevenir command injection
        if re.search(r'[;&|`$(){}[\]<>]', objetivo):
            return {'valido': False, 'error': 'Objetivo contiene caracteres no seguros'}
        
        # Validar longitud razonable
        if len(objetivo) > 253:  # RFC 1035 - máximo para hostname
            return {'valido': False, 'error': 'Objetivo demasiado largo'}
        
        try:
            # Intentar parsear como IP
            ip_obj = ipaddress.ip_address(objetivo)
            
            # KALI SECURITY: Verificar que la IP esté en rangos permitidos
            for red_permitida in self._redes_permitidas:
                if ip_obj in ipaddress.ip_network(red_permitida):
                    return {
                        'valido': True, 
                        'tipo': 'ip', 
                        'objetivo_sanitizado': str(ip_obj),
                        'red_permitida': red_permitida
                    }
            
            # Si no está en rangos permitidos, rechazar
            return {
                'valido': False, 
                'error': f'IP {objetivo} no está en rangos de pentesting ético permitidos'
            }
            
        except ValueError:
            # No es una IP, validar como hostname
            return self._validar_hostname(objetivo)
    
    def _validar_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Valida hostname para escaneo ético en Kali Linux.
        KALI OPTIMIZATION: Solo permite hostnames seguros para pentesting.
        """
        # Validar formato de hostname
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            return {'valido': False, 'error': 'Hostname contiene caracteres no válidos'}
        
        # No permitir hostnames que podrían ser problemáticos
        hostnames_prohibidos = [
            'google.com', 'facebook.com', 'microsoft.com', 'amazon.com',
            'apple.com', 'twitter.com', 'github.com', 'stackoverflow.com'
        ]
        
        if hostname.lower() in hostnames_prohibidos:
            return {
                'valido': False, 
                'error': f'Hostname {hostname} no permitido para pentesting'
            }
        
        # Intentar resolver DNS para verificar que es local/privado
        try:
            ip_resueltas = socket.getaddrinfo(hostname, None)
            for ip_info in ip_resueltas:
                ip_str = str(ip_info[4][0])  # SECURITY FIX: Convertir a string
                
                # Verificar que las IPs resueltas estén en rangos permitidos
                validacion_ip = self._validar_objetivo_escaneo(ip_str)
                if not validacion_ip['valido']:
                    return {
                        'valido': False,
                        'error': f'Hostname {hostname} resuelve a IP no permitida: {ip_str}'
                    }
            
            return {
                'valido': True,
                'tipo': 'hostname',
                'objetivo_sanitizado': hostname.lower(),
                'ips_resueltas': [str(ip[4][0]) for ip in ip_resueltas]
            }
            
        except socket.gaierror:
            return {'valido': False, 'error': f'No se puede resolver hostname: {hostname}'}
        
        # Lock para operaciones concurrentes
        self._lock_escaneo = threading.Lock()
        
        self.logger.info("Controlador de Escaneo inicializado")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación específica de inicialización del controlador de escaneo."""
        try:
            self.logger.info("Inicializando componentes de escaneo")
            
            # Inicializar escaneador
            self.escaneador = Escaneador()
            self.logger.debug("Escaneador inicializado")
            
            # Inicializar SIEM
            self.siem = SIEM()
            self.logger.debug("SIEM inicializado")
            
            # Cargar configuración específica
            self._cargar_configuracion_escaneo()
            
            # Verificar herramientas necesarias
            verificacion = self._verificar_herramientas_escaneo()
            
            if verificacion['exito']:
                self._registrar_evento_siem("INIT_ESCANEADOR", "Controlador de escaneo listo", "info")
                return {
                    'exito': True,
                    'mensaje': 'Controlador de escaneo inicializado correctamente',
                    'herramientas': verificacion
                }
            else:
                return {
                    'exito': False,
                    'error': f"Error verificando herramientas: {verificacion.get('error', '')}",
                    'herramientas': verificacion
                }
                
        except Exception as e:
            error_msg = f"Error inicializando controlador de escaneo: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def _cargar_configuracion_escaneo(self) -> None:
        """Cargar configuración específica de escaneo."""
        try:
            # Intentar obtener configuración del gestor principal
            if hasattr(self.modelo_principal, 'gestor_config'):
                config = self.modelo_principal.gestor_config
                
                self._config_escaneo = {
                    'timeout_conexion': config.obtener('escaneador.timeout_conexion', 3),
                    'max_hilos': config.obtener('escaneador.max_puertos_simultaneos', 50),
                    'puerto_inicial': config.obtener('escaneador.puerto_inicial', 1),
                    'puerto_final': config.obtener('escaneador.puerto_final', 1000),
                    'intentos_maximos': config.obtener('escaneador.intentos_maximos', 3)
                }
                
                self.logger.debug(f"Configuración de escaneo cargada: {self._config_escaneo}")
            else:
                self.logger.warning("Gestor de configuración no disponible, usando valores por defecto")
                
        except Exception as e:
            self.logger.warning(f"Error cargando configuración: {e}")
    
    def _verificar_herramientas_escaneo(self) -> Dict[str, Any]:
        """Verificar herramientas necesarias para el escaneo."""
        try:
            herramientas_necesarias = ['nmap', 'netstat', 'ss', 'lsof']
            herramientas_disponibles = []
            herramientas_faltantes = []
            
            import subprocess
            
            for herramienta in herramientas_necesarias:
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, timeout=5)
                    if resultado.returncode == 0:
                        herramientas_disponibles.append(herramienta)
                    else:
                        herramientas_faltantes.append(herramienta)
                except Exception:
                    herramientas_faltantes.append(herramienta)
            
            return {
                'exito': len(herramientas_faltantes) == 0,
                'disponibles': herramientas_disponibles,
                'faltantes': herramientas_faltantes,
                'total_disponibles': len(herramientas_disponibles),
                'total_necesarias': len(herramientas_necesarias)
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def ejecutar_escaneo_basico(self, objetivo: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Ejecutar escaneo básico de un objetivo.
        
        Args:
            objetivo: IP o hostname del objetivo
        
        Returns:
            Dict con resultados del escaneo
        """
        return self.ejecutar_operacion_segura(self._ejecutar_escaneo_basico_impl, objetivo)
    
    def _ejecutar_escaneo_basico_impl(self, objetivo: str) -> Dict[str, Any]:
        """
        Implementación del escaneo básico con validación de seguridad.
        KALI OPTIMIZATION: Escaneo seguro para pentesting ético.
        """
        # SECURITY FIX: Validar objetivo antes de cualquier operación
        validacion = self._validar_objetivo_escaneo(objetivo)
        if not validacion['valido']:
            self.logger.warning(f"Objetivo rechazado: {validacion['error']}")
            return {
                'exito': False, 
                'error': f"Objetivo no válido: {validacion['error']}",
                'objetivo_rechazado': objetivo
            }
        
        objetivo_seguro = validacion['objetivo_sanitizado']
        self.logger.info(f"🔍 Iniciando escaneo básico validado de {objetivo_seguro}")
        
        if not self.escaneador or not self.siem:
            return {'exito': False, 'error': 'Componentes no inicializados correctamente'}
        
        # Verificar funcionalidad en Kali Linux antes del escaneo
        verificacion_kali = self.verificar_funcionalidad_kali()
        if not verificacion_kali['funcionalidad_completa']:
            self.logger.warning("⚠️  Funcionalidad limitada detectada en Kali Linux")
            for rec in verificacion_kali['recomendaciones']:
                self.logger.warning(f"💡 {rec}")
        
        with self._lock_escaneo:
            self._estado_escaneo['escaneo_en_progreso'] = True
            self._estado_escaneo['ultimo_objetivo'] = objetivo_seguro  # SECURITY: Solo guardar objetivo validado
        
        try:
            tiempo_inicio = time.time()
            
            # SECURITY: Usar objetivo validado en todas las operaciones
            # Escaneo de puertos con objetivo seguro
            self.logger.info(f"🔧 Ejecutando escaneo de puertos para {objetivo_seguro}")
            puertos_resultado = self.escaneador.escanear_puertos_basico(objetivo_seguro)
            
            # Obtener conexiones activas
            conexiones_resultado = self.escaneador.obtener_conexiones_activas()
            
            # Análisis de logs del sistema
            analisis_logs = self.siem.analizar_logs_sistema()
            
            tiempo_total = time.time() - tiempo_inicio
            
            resultados = {
                'objetivo': objetivo_seguro,  # SECURITY: Usar objetivo validado
                'objetivo_validacion': validacion,  # SECURITY: Incluir info de validación
                'timestamp': datetime.now().isoformat(),
                'tiempo_ejecucion': round(tiempo_total, 2),
                'puertos': puertos_resultado,
                'conexiones': conexiones_resultado,
                'analisis_logs': analisis_logs,
                'tipo_escaneo': 'basico'
            }
            
            # Actualizar estado y métricas
            with self._lock_escaneo:
                self._estado_escaneo['escaneo_en_progreso'] = False
                self._estado_escaneo['ultimos_resultados'] = resultados
                self._estado_escaneo['total_escaneos_realizados'] += 1
            
            # Registrar evento SIEM
            self.siem.generar_evento("ESCANEO_BASICO", f"Escaneo básico completado para {objetivo}", "info")
            
            self.logger.info(f"Escaneo básico de {objetivo} completado en {tiempo_total:.2f}s")
            
            return {'exito': True, 'resultados': resultados}
            
        except Exception as e:
            with self._lock_escaneo:
                self._estado_escaneo['escaneo_en_progreso'] = False
            
            error_msg = f"Error en escaneo básico: {str(e)}"
            self.logger.error(error_msg)
            if self.siem:
                self.siem.generar_evento("ERROR_ESCANEO_BASICO", error_msg, "error")
            raise e
    
    def ejecutar_escaneo_completo(self, objetivo: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Ejecutar escaneo completo con detección de servicios y vulnerabilidades.
        
        Args:
            objetivo: IP o hostname del objetivo
        
        Returns:
            Dict con resultados del escaneo completo
        """
        return self.ejecutar_operacion_segura(self._ejecutar_escaneo_completo_impl, objetivo)
    
    def _ejecutar_escaneo_completo_impl(self, objetivo: str) -> Dict[str, Any]:
        """
        Implementación del escaneo completo con validación de seguridad.
        KALI OPTIMIZATION: Escaneo completo seguro para pentesting profesional.
        """
        # SECURITY FIX: Validar objetivo antes de cualquier operación
        validacion = self._validar_objetivo_escaneo(objetivo)
        if not validacion['valido']:
            self.logger.warning(f"Objetivo rechazado en escaneo completo: {validacion['error']}")
            return {
                'exito': False, 
                'error': f"Objetivo no válido: {validacion['error']}",
                'objetivo_rechazado': objetivo
            }
        
        objetivo_seguro = validacion['objetivo_sanitizado']
        self.logger.info(f"Iniciando escaneo completo validado de {objetivo_seguro}")
        
        if not self.escaneador or not self.siem:
            return {'exito': False, 'error': 'Componentes no inicializados correctamente'}
        
        with self._lock_escaneo:
            self._estado_escaneo['escaneo_en_progreso'] = True
            self._estado_escaneo['ultimo_objetivo'] = objetivo_seguro  # SECURITY: Solo guardar objetivo validado
        
        try:
            tiempo_inicio = time.time()
            
            # SECURITY: Usar objetivo validado en todas las operaciones
            # Escaneo básico con objetivo seguro
            escaneo_basico = self._ejecutar_escaneo_basico_impl(objetivo_seguro)
            
            # Escaneo de servicios con objetivo seguro
            servicios = self.escaneador.escanear_servicios(objetivo_seguro)
            
            # Detección de sistema operativo con objetivo seguro
            deteccion_os = self.escaneador.detectar_sistema_operativo(objetivo_seguro)
            
            # Búsqueda de vulnerabilidades básicas con objetivo seguro
            vulnerabilidades = self.escaneador.buscar_vulnerabilidades_basicas(objetivo_seguro)
            
            tiempo_total = time.time() - tiempo_inicio
            
            resultados = {
                'objetivo': objetivo_seguro,  # SECURITY: Usar objetivo validado
                'objetivo_validacion': validacion,  # SECURITY: Incluir info de validación
                'timestamp': datetime.now().isoformat(),
                'tiempo_ejecucion': round(tiempo_total, 2),
                'escaneo_basico': escaneo_basico.get('resultados', {}),
                'servicios': servicios,
                'deteccion_os': deteccion_os,
                'vulnerabilidades': vulnerabilidades,
                'tipo_escaneo': 'completo'
            }
            
            # Analizar criticidad
            criticidad = self._analizar_criticidad_resultados(resultados)
            resultados['criticidad'] = criticidad
            
            # Actualizar estado
            with self._lock_escaneo:
                self._estado_escaneo['escaneo_en_progreso'] = False
                self._estado_escaneo['ultimos_resultados'] = resultados
                self._estado_escaneo['total_escaneos_realizados'] += 1
            
            # Registrar evento SIEM
            nivel_evento = "warning" if criticidad['nivel'] in ['alto', 'critico'] else "info"
            self.siem.generar_evento("ESCANEO_COMPLETO", 
                                   f"Escaneo completo de {objetivo} - Criticidad: {criticidad['nivel']}", 
                                   nivel_evento)
            
            self.logger.info(f"Escaneo completo de {objetivo} completado en {tiempo_total:.2f}s")
            
            return {'exito': True, 'resultados': resultados}
            
        except Exception as e:
            with self._lock_escaneo:
                self._estado_escaneo['escaneo_en_progreso'] = False
            
            error_msg = f"Error en escaneo completo: {str(e)}"
            self.logger.error(error_msg)
            if self.siem:
                self.siem.generar_evento("ERROR_ESCANEO_COMPLETO", error_msg, "error")
            raise e
    
    def ejecutar_escaneo_red(self, rango_red: str = "192.168.1.0/24") -> Dict[str, Any]:
        """
        Ejecutar escaneo de red para descubrir hosts activos.
        
        Args:
            rango_red: Rango de red en formato CIDR
        
        Returns:
            Dict con resultados del escaneo de red
        """
        return self.ejecutar_operacion_segura(self._ejecutar_escaneo_red_impl, rango_red)
    
    def _validar_rango_red(self, rango_red: str) -> Dict[str, Any]:
        """
        Valida que el rango de red sea seguro para pentesting ético.
        KALI OPTIMIZATION: Validación específica para escaneo de redes en Kali.
        """
        if not rango_red or not isinstance(rango_red, str):
            return {'valido': False, 'error': 'Rango de red no válido'}
        
        # Limpiar espacios y caracteres peligrosos
        rango_red = rango_red.strip()
        
        # SECURITY FIX: Prevenir command injection
        if re.search(r'[;&|`$(){}[\]<>]', rango_red):
            return {'valido': False, 'error': 'Rango contiene caracteres no seguros'}
        
        try:
            # Intentar parsear como red CIDR
            red_obj = ipaddress.ip_network(rango_red, strict=False)
            
            # KALI SECURITY: Verificar que la red esté en rangos permitidos
            for red_permitida in self._redes_permitidas:
                try:
                    red_permitida_obj = ipaddress.ip_network(red_permitida)
                    
                    # Verificar si hay solapamiento (más simple y seguro)
                    if red_obj.version == red_permitida_obj.version and red_obj.overlaps(red_permitida_obj):
                        return {
                            'valido': True,
                            'rango_sanitizado': str(red_obj),
                            'red_permitida': red_permitida,
                            'total_hosts': red_obj.num_addresses - 2  # Excluir red y broadcast
                        }
                except Exception:
                    continue
            
            return {
                'valido': False,
                'error': f'Rango de red {rango_red} no está en rangos de pentesting ético permitidos'
            }
            
        except ValueError as e:
            return {'valido': False, 'error': f'Formato de red inválido: {str(e)}'}

    def _ejecutar_escaneo_red_impl(self, rango_red: str) -> Dict[str, Any]:
        """
        Implementación del escaneo de red con validación de seguridad.
        KALI OPTIMIZATION: Escaneo seguro de redes para pentesting profesional.
        """
        # SECURITY FIX: Validar rango de red antes de cualquier operación
        validacion = self._validar_rango_red(rango_red)
        if not validacion['valido']:
            self.logger.warning(f"Rango de red rechazado: {validacion['error']}")
            return {
                'exito': False,
                'error': f"Rango de red no válido: {validacion['error']}",
                'rango_rechazado': rango_red
            }
        
        rango_seguro = validacion['rango_sanitizado']
        self.logger.info(f"Iniciando escaneo de red validado {rango_seguro}")
        
        if not self.escaneador or not self.siem:
            return {'exito': False, 'error': 'Componentes no inicializados correctamente'}
        
        try:
            tiempo_inicio = time.time()
            
            # SECURITY: Usar rango seguro para descubrir hosts
            hosts_activos = self.escaneador.descubrir_hosts_red(rango_seguro)
            
            resultados_hosts = []
            hosts_procesados = 0
            max_hosts = min(len(hosts_activos), 10)  # Limitar para no sobrecargar
            
            for host in hosts_activos[:max_hosts]:
                try:
                    # SECURITY: Cada host será validado en _ejecutar_escaneo_basico_impl
                    resultado_host = self._ejecutar_escaneo_basico_impl(host)
                    if resultado_host.get('exito'):
                        resultado_host['resultados']['host'] = host
                        resultados_hosts.append(resultado_host['resultados'])
                        hosts_procesados += 1
                except Exception as e:
                    self.logger.warning(f"Error escaneando host {host}: {e}")
            
            tiempo_total = time.time() - tiempo_inicio
            
            resultados = {
                'rango_red': rango_seguro,  # SECURITY: Usar rango validado
                'rango_validacion': validacion,  # SECURITY: Incluir info de validación
                'timestamp': datetime.now().isoformat(),
                'tiempo_ejecucion': round(tiempo_total, 2),
                'hosts_descubiertos': len(hosts_activos),
                'hosts_escaneados': hosts_procesados,
                'resultados_hosts': resultados_hosts,
                'tipo_escaneo': 'red'
            }
            
            # Registrar evento SIEM
            self.siem.generar_evento("ESCANEO_RED", 
                                   f"Escaneo de red {rango_red} - {len(hosts_activos)} hosts descubiertos", 
                                   "info")
            
            self.logger.info(f"Escaneo de red completado: {len(hosts_activos)} hosts en {tiempo_total:.2f}s")
            
            return {'exito': True, 'resultados': resultados}
            
        except Exception as e:
            error_msg = f"Error en escaneo de red: {str(e)}"
            self.logger.error(error_msg)
            if self.siem:
                self.siem.generar_evento("ERROR_ESCANEO_RED", error_msg, "error")
            raise e
    
    def _analizar_criticidad_resultados(self, resultados: Dict[str, Any]) -> Dict[str, Any]:
        """Analizar criticidad de los resultados de escaneo."""
        try:
            puntuacion = 0
            factores = []
            
            # Analizar puertos abiertos
            puertos = resultados.get('escaneo_basico', {}).get('puertos', [])
            if isinstance(puertos, list) and len(puertos) > 10:
                puntuacion += 30
                factores.append(f"Muchos puertos abiertos ({len(puertos)})")
            
            # Analizar vulnerabilidades
            vulnerabilidades = resultados.get('vulnerabilidades', [])
            if isinstance(vulnerabilidades, list):
                puntuacion += len(vulnerabilidades) * 10
                if vulnerabilidades:
                    factores.append(f"Vulnerabilidades detectadas ({len(vulnerabilidades)})")
            
            # Analizar servicios críticos
            servicios = resultados.get('servicios', [])
            servicios_criticos = ['ssh', 'ftp', 'telnet', 'http', 'https', 'mysql', 'postgresql']
            for servicio in servicios_criticos:
                if any(servicio.lower() in str(s).lower() for s in servicios):
                    puntuacion += 15
                    factores.append(f"Servicio crítico detectado: {servicio}")
            
            # Determinar nivel de criticidad
            if puntuacion >= 80:
                nivel = 'critico'
            elif puntuacion >= 60:
                nivel = 'alto'
            elif puntuacion >= 30:
                nivel = 'medio'
            elif puntuacion > 0:
                nivel = 'bajo'
            else:
                nivel = 'ninguno'
            
            return {
                'nivel': nivel,
                'puntuacion': puntuacion,
                'factores': factores,
                'total_factores': len(factores)
            }
            
        except Exception as e:
            self.logger.warning(f"Error analizando criticidad: {e}")
            return {'nivel': 'desconocido', 'puntuacion': 0, 'factores': [], 'error': str(e)}
    
    def obtener_estado_escaneo(self) -> Dict[str, Any]:
        """Obtener estado actual del escaneador."""
        with self._lock_escaneo:
            estado = self._estado_escaneo.copy()
        
        # Añadir configuración actual
        estado['configuracion'] = self._config_escaneo.copy()
        
        # Añadir métricas
        estado['metricas'] = self.obtener_metricas()
        
        return estado
    
    def detener_escaneo_actual(self) -> Dict[str, Any]:
        """Detener escaneo en progreso."""
        try:
            with self._lock_escaneo:
                if self._estado_escaneo['escaneo_en_progreso']:
                    self._estado_escaneo['escaneo_en_progreso'] = False
                    self.logger.info("Escaneo detenido por solicitud del usuario")
                    if self.siem:
                        self.siem.generar_evento("ESCANEO_DETENIDO", "Escaneo detenido manualmente", "warning")
                    return {'exito': True, 'mensaje': 'Escaneo detenido'}
                else:
                    return {'exito': False, 'mensaje': 'No hay escaneo en progreso'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def obtener_logs_escaneo(self, limite: int = 20) -> List[Dict[str, Any]]:
        """Obtener logs recientes de escaneo."""
        return self.obtener_eventos_siem(limite)
    
    def generar_reporte_escaneo(self, resultados_escaneo: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generar reporte detallado de escaneo.
        
        Args:
            resultados_escaneo: Resultados del escaneo
        
        Returns:
            Dict con reporte generado
        """
        return self.ejecutar_operacion_segura(self._generar_reporte_escaneo_impl, resultados_escaneo)
    
    def _generar_reporte_escaneo_impl(self, resultados: Dict[str, Any]) -> Dict[str, Any]:
        """Implementación de generación de reporte."""
        try:
            reporte = {
                'titulo': 'Reporte de Escaneo - Ares Aegis',
                'timestamp': datetime.now().isoformat(),
                'version': '2.0.0',
                'objetivo': resultados.get('objetivo', 'No especificado'),
                'tipo_escaneo': resultados.get('tipo_escaneo', 'desconocido'),
                'resumen_ejecutivo': self._generar_resumen_ejecutivo(resultados),
                'detalles_tecnicos': resultados,
                'recomendaciones': self._generar_recomendaciones(resultados),
                'metadatos': {
                    'generado_por': 'Ares Aegis - Controlador de Escaneo',
                    'tiempo_generacion': datetime.now().isoformat(),
                    'version_controlador': '2.0.0'
                }
            }
            
            return {'exito': True, 'reporte': reporte}
            
        except Exception as e:
            error_msg = f"Error generando reporte: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def _generar_resumen_ejecutivo(self, resultados: Dict[str, Any]) -> Dict[str, Any]:
        """Generar resumen ejecutivo del escaneo."""
        try:
            puertos_abiertos = 0
            servicios_detectados = 0
            vulnerabilidades_encontradas = 0
            
            # Contar puertos abiertos
            if 'puertos' in resultados:
                puertos_abiertos = len(resultados['puertos'])
            elif 'escaneo_basico' in resultados and 'puertos' in resultados['escaneo_basico']:
                puertos_abiertos = len(resultados['escaneo_basico']['puertos'])
            
            # Contar servicios
            if 'servicios' in resultados:
                servicios_detectados = len(resultados['servicios'])
            
            # Contar vulnerabilidades
            if 'vulnerabilidades' in resultados:
                vulnerabilidades_encontradas = len(resultados['vulnerabilidades'])
            
            # Determinar estado general
            if vulnerabilidades_encontradas > 0:
                estado_seguridad = 'critico'
            elif puertos_abiertos > 20:
                estado_seguridad = 'alto_riesgo'
            elif puertos_abiertos > 10:
                estado_seguridad = 'riesgo_medio'
            elif puertos_abiertos > 0:
                estado_seguridad = 'riesgo_bajo'
            else:
                estado_seguridad = 'seguro'
            
            return {
                'puertos_abiertos': puertos_abiertos,
                'servicios_detectados': servicios_detectados,
                'vulnerabilidades_encontradas': vulnerabilidades_encontradas,
                'estado_seguridad': estado_seguridad,
                'tiempo_ejecucion': resultados.get('tiempo_ejecucion', 0),
                'criticidad': resultados.get('criticidad', {})
            }
            
        except Exception as e:
            self.logger.warning(f"Error generando resumen ejecutivo: {e}")
            return {'error': str(e)}
    
    def _generar_recomendaciones(self, resultados: Dict[str, Any]) -> List[str]:
        """Generar recomendaciones basadas en los resultados."""
        recomendaciones = []
        
        try:
            # Recomendaciones por puertos abiertos
            puertos = resultados.get('puertos', [])
            if isinstance(puertos, list) and len(puertos) > 10:
                recomendaciones.append("Considere cerrar puertos innecesarios para reducir la superficie de ataque")
            
            # Recomendaciones por vulnerabilidades
            vulnerabilidades = resultados.get('vulnerabilidades', [])
            if isinstance(vulnerabilidades, list) and len(vulnerabilidades) > 0:
                recomendaciones.append("Priorice la corrección de las vulnerabilidades encontradas")
                recomendaciones.append("Implemente un programa regular de actualización de seguridad")
            
            # Recomendaciones por servicios
            servicios = resultados.get('servicios', [])
            servicios_inseguros = ['telnet', 'ftp', 'rsh', 'rlogin']
            for servicio in servicios_inseguros:
                if any(servicio.lower() in str(s).lower() for s in servicios):
                    recomendaciones.append(f"Reemplace el servicio {servicio} por alternativas más seguras")
            
            # Recomendaciones generales
            if not recomendaciones:
                recomendaciones.append("Mantenga un monitoreo continuo de la seguridad del sistema")
                recomendaciones.append("Implemente un programa de auditorías regulares")
            
            recomendaciones.append("Configure un sistema de detección de intrusos (IDS)")
            recomendaciones.append("Mantenga logs de auditoría para todas las actividades críticas")
            
        except Exception as e:
            self.logger.warning(f"Error generando recomendaciones: {e}")
            recomendaciones.append("Error generando recomendaciones específicas")
        
        return recomendaciones

# RESUMEN TÉCNICO: Controlador de Escaneo avanzado para Ares Aegis con arquitectura asíncrona,
# herencia de ControladorBase, operaciones thread-safe, análisis de criticidad automático,
# integración SIEM completa, configuración dinámica, generación de reportes profesionales
# y manejo robusto de errores. Optimizado para escaneados de seguridad en Kali Linux.