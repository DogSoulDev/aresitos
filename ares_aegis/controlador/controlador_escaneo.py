# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Escaneo
Controlador especializado en operaciones de escaneo de seguridad
"""

import asyncio
import threading
import time
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
        except Exception as e:
            self.logger.error(f"Error inicializando componentes: {e}")
            self.escaneador = None
            self.siem = None
        
        # Estado específico del escaneo
        self._estado_escaneo = {
            'escaneo_en_progreso': False,
            'ultimo_objetivo': None,
            'ultimos_resultados': None,
            'total_escaneos_realizados': 0
        }
        
        # Configuración de escaneo
        self._config_escaneo = {
            'timeout_conexion': 3,
            'max_hilos': 50,
            'puerto_inicial': 1,
            'puerto_final': 1000,
            'intentos_maximos': 3
        }
        
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
        """Implementación del escaneo básico."""
        self.logger.info(f"Iniciando escaneo básico de {objetivo}")
        
        if not self.escaneador or not self.siem:
            return {'exito': False, 'error': 'Componentes no inicializados correctamente'}
        
        with self._lock_escaneo:
            self._estado_escaneo['escaneo_en_progreso'] = True
            self._estado_escaneo['ultimo_objetivo'] = objetivo
        
        try:
            tiempo_inicio = time.time()
            
            # Escaneo de puertos
            puertos_resultado = self.escaneador.escanear_puertos_basico(objetivo)
            
            # Obtener conexiones activas
            conexiones_resultado = self.escaneador.obtener_conexiones_activas()
            
            # Análisis de logs del sistema
            analisis_logs = self.siem.analizar_logs_sistema()
            
            tiempo_total = time.time() - tiempo_inicio
            
            resultados = {
                'objetivo': objetivo,
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
        """Implementación del escaneo completo."""
        self.logger.info(f"Iniciando escaneo completo de {objetivo}")
        
        if not self.escaneador or not self.siem:
            return {'exito': False, 'error': 'Componentes no inicializados correctamente'}
        
        with self._lock_escaneo:
            self._estado_escaneo['escaneo_en_progreso'] = True
            self._estado_escaneo['ultimo_objetivo'] = objetivo
        
        try:
            tiempo_inicio = time.time()
            
            # Escaneo básico
            escaneo_basico = self._ejecutar_escaneo_basico_impl(objetivo)
            
            # Escaneo de servicios
            servicios = self.escaneador.escanear_servicios(objetivo)
            
            # Detección de sistema operativo
            deteccion_os = self.escaneador.detectar_sistema_operativo(objetivo)
            
            # Búsqueda de vulnerabilidades básicas
            vulnerabilidades = self.escaneador.buscar_vulnerabilidades_basicas(objetivo)
            
            tiempo_total = time.time() - tiempo_inicio
            
            resultados = {
                'objetivo': objetivo,
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
    
    def _ejecutar_escaneo_red_impl(self, rango_red: str) -> Dict[str, Any]:
        """Implementación del escaneo de red."""
        self.logger.info(f"Iniciando escaneo de red {rango_red}")
        
        if not self.escaneador or not self.siem:
            return {'exito': False, 'error': 'Componentes no inicializados correctamente'}
        
        try:
            tiempo_inicio = time.time()
            
            # Descubrir hosts activos
            hosts_activos = self.escaneador.descubrir_hosts_red(rango_red)
            
            resultados_hosts = []
            hosts_procesados = 0
            max_hosts = min(len(hosts_activos), 10)  # Limitar para no sobrecargar
            
            for host in hosts_activos[:max_hosts]:
                try:
                    resultado_host = self._ejecutar_escaneo_basico_impl(host)
                    if resultado_host.get('exito'):
                        resultado_host['resultados']['host'] = host
                        resultados_hosts.append(resultado_host['resultados'])
                        hosts_procesados += 1
                except Exception as e:
                    self.logger.warning(f"Error escaneando host {host}: {e}")
            
            tiempo_total = time.time() - tiempo_inicio
            
            resultados = {
                'rango_red': rango_red,
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