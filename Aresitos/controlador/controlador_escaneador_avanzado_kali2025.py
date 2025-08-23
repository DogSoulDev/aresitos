#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador Escaneador Avanzado Kali 2025
====================================================

Controlador que integra el nuevo sistema de escaneo avanzado con las mejores 
herramientas de Kali Linux 2025 y técnicas modernas de scanning.

Características:
- Integración con RustScan, Nuclei, Masscan y herramientas Kali
- Estrategias de escaneo adaptativas
- Detección automática de herramientas disponibles
- Reportes unificados y detallados
- Compatibilidad con arquitectura ARESITOS v3.0

Autor: DogSoulDev
Proyecto: ARESITOS v3.0
Fecha: 2025
"""

import logging
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
import json

# Importaciones ARESITOS
from Aresitos.controlador.controlador_base import ControladorBase
from Aresitos.modelo.modelo_escaneador_avanzado_kali2025 import (
    EscaneadorAvanzadoKali2025, 
    ScannerConfig, 
    ScanResult,
    crear_escaneador_configurado,
    escaneo_rapido_aresitos,
    escaneo_completo_aresitos
)

class ControladorEscaneadorAvanzado(ControladorBase):
    """
    Controlador para el sistema de escaneo avanzado que integra
    las mejores herramientas de Kali Linux 2025
    """
    
    def __init__(self, *args, **kwargs):
        """Inicializar controlador del escaneador avanzado"""
        super().__init__(*args, **kwargs)
        
        # Configuración del escaneador
        self.scanner_config = ScannerConfig(
            timeout=300,
            max_workers=3,
            rate_limit=1000,
            enable_service_detection=True,
            enable_vuln_scan=True,
            enable_web_scan=True
        )
        
        # Instancia del escaneador
        self.escaneador = None
        self._inicializar_escaneador()
        
        # Estado del controlador
        self.scan_in_progress = False
        self.current_scan_thread = None
        self.scan_results_cache = {}
        self.callback_progress = None
        
        # Estadísticas
        self.stats: Dict[str, Any] = {
            'total_scans': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'total_ports_found': 0,
            'total_vulnerabilities': 0,
            'total_scan_time': 0.0
        }
        
        self.logger.info("Controlador Escaneador Avanzado Kali 2025 inicializado")

    def _inicializar_impl(self) -> bool:
        """Implementación del método abstracto de ControladorBase"""
        return self._inicializar_escaneador()

    def _inicializar_escaneador(self) -> bool:
        """Inicializar el escaneador con verificación de herramientas"""
        try:
            self.escaneador = EscaneadorAvanzadoKali2025(self.scanner_config)
            
            herramientas_disponibles = list(self.escaneador.tools_available.keys())
            herramientas_activas = [k for k, v in self.escaneador.tools_available.items() if v]
            
            self.logger.info(f"Herramientas disponibles: {herramientas_activas}")
            
            if not herramientas_activas:
                self.logger.warning("No se encontraron herramientas de escaneo especializadas")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error inicializando escaneador: {e}")
            return False

    def escanear_objetivo(self, objetivo: str, tipo_escaneo: str = 'rapido', 
                         callback_progress: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Escanear un objetivo específico
        
        Args:
            objetivo: IP, dominio o rango a escanear
            tipo_escaneo: 'rapido', 'completo', 'sigiloso', 'agresivo'
            callback_progress: Función callback para actualizaciones de progreso
        """
        if self.scan_in_progress:
            return {
                'exito': False,
                'error': 'Ya hay un escaneo en progreso',
                'codigo_error': 'SCAN_IN_PROGRESS'
            }
        
        self.callback_progress = callback_progress
        self.scan_in_progress = True
        
        try:
            inicio = time.time()
            self.logger.info(f"Iniciando escaneo {tipo_escaneo} de {objetivo}")
            
            if callback_progress:
                callback_progress("Inicializando escaneo...", 0)
            
            # Mapear tipos de escaneo
            scan_type_map = {
                'rapido': 'fast',
                'completo': 'complete', 
                'sigiloso': 'stealth',
                'agresivo': 'aggressive'
            }
            
            scan_type = scan_type_map.get(tipo_escaneo, 'fast')
            
            if callback_progress:
                callback_progress(f"Ejecutando escaneo {tipo_escaneo}...", 25)
            
            # Ejecutar escaneo
            if self.escaneador is None:
                raise RuntimeError("Escaneador no inicializado correctamente")
                
            resultado = self.escaneador.scan_target(objetivo, scan_type)
            
            if callback_progress:
                callback_progress("Procesando resultados...", 75)
            
            # Procesar y formatear resultados
            resultado_procesado = self._procesar_resultado_escaneo(resultado)
            
            # Actualizar estadísticas
            self._actualizar_estadisticas(resultado)
            
            # Guardar en caché
            cache_key = f"{objetivo}_{tipo_escaneo}_{datetime.now().strftime('%Y%m%d_%H%M')}"
            self.scan_results_cache[cache_key] = resultado_procesado
            
            duracion = time.time() - inicio
            
            if callback_progress:
                callback_progress("Escaneo completado", 100)
            
            self.logger.info(f"Escaneo completado en {duracion:.2f} segundos")
            
            return resultado_procesado
            
        except Exception as e:
            self.logger.error(f"Error en escaneo: {e}")
            return {
                'exito': False,
                'error': str(e),
                'codigo_error': 'SCAN_ERROR',
                'objetivo': objetivo,
                'tipo_escaneo': tipo_escaneo
            }
        finally:
            self.scan_in_progress = False
            self.callback_progress = None

    def escanear_objetivo_async(self, objetivo: str, tipo_escaneo: str = 'rapido',
                               callback_complete: Optional[Callable] = None,
                               callback_progress: Optional[Callable] = None) -> bool:
        """
        Escanear un objetivo de forma asíncrona
        
        Args:
            objetivo: IP, dominio o rango a escanear
            tipo_escaneo: Tipo de escaneo a realizar
            callback_complete: Función llamada al completar
            callback_progress: Función llamada para progreso
        """
        if self.scan_in_progress:
            self.logger.warning("Ya hay un escaneo en progreso")
            return False
        
        def scan_worker():
            resultado = self.escanear_objetivo(objetivo, tipo_escaneo, callback_progress)
            if callback_complete:
                callback_complete(resultado)
        
        self.current_scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.current_scan_thread.start()
        
        return True

    def escanear_multiples_objetivos(self, objetivos: List[str], 
                                   tipo_escaneo: str = 'rapido',
                                   callback_progress: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """
        Escanear múltiples objetivos en paralelo
        
        Args:
            objetivos: Lista de objetivos a escanear
            tipo_escaneo: Tipo de escaneo a realizar
            callback_progress: Función callback para progreso
        """
        if self.scan_in_progress:
            return [{
                'exito': False,
                'error': 'Ya hay un escaneo en progreso',
                'codigo_error': 'SCAN_IN_PROGRESS'
            }]
        
        self.scan_in_progress = True
        resultados = []
        
        try:
            self.logger.info(f"Escaneando {len(objetivos)} objetivos en paralelo")
            
            if callback_progress:
                callback_progress(f"Iniciando escaneo de {len(objetivos)} objetivos...", 0)
            
            # Mapear tipo de escaneo
            scan_type_map = {
                'rapido': 'fast',
                'completo': 'complete',
                'sigiloso': 'stealth', 
                'agresivo': 'aggressive'
            }
            scan_type = scan_type_map.get(tipo_escaneo, 'fast')
            
            # Ejecutar escaneos en paralelo
            if self.escaneador is None:
                raise RuntimeError("Escaneador no inicializado correctamente")
                
            scan_results = self.escaneador.scan_multiple_targets(objetivos, scan_type)
            
            # Procesar cada resultado
            for i, resultado in enumerate(scan_results):
                if callback_progress:
                    progreso = int((i + 1) / len(scan_results) * 80) + 10
                    callback_progress(f"Procesando resultado {i+1}/{len(scan_results)}", progreso)
                
                resultado_procesado = self._procesar_resultado_escaneo(resultado)
                resultados.append(resultado_procesado)
                
                # Actualizar estadísticas
                self._actualizar_estadisticas(resultado)
            
            if callback_progress:
                callback_progress("Escaneos completados", 100)
            
            self.logger.info(f"Completados {len(resultados)} escaneos")
            
        except Exception as e:
            self.logger.error(f"Error en escaneo múltiple: {e}")
            resultados.append({
                'exito': False,
                'error': str(e),
                'codigo_error': 'MULTI_SCAN_ERROR'
            })
        finally:
            self.scan_in_progress = False
        
        return resultados

    def _procesar_resultado_escaneo(self, resultado: ScanResult) -> Dict[str, Any]:
        """Procesar y formatear resultado de escaneo para compatibilidad ARESITOS"""
        
        # Clasificar puertos por criticidad
        puertos_criticos = []
        puertos_normales = []
        
        # Puertos críticos conocidos (fallback si escaneador no disponible)
        critical_tcp_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443
        ]
        
        for puerto in resultado.ports:
            puerto_num = puerto.get('port', 0)
            # Usar puertos críticos del escaneador si está disponible, sino usar fallback
            critical_ports = (self.escaneador.critical_ports['tcp'] 
                            if self.escaneador else critical_tcp_ports)
            
            if puerto_num in critical_ports:
                puerto['criticidad'] = 'ALTA'
                puerto['descripcion_riesgo'] = self._obtener_descripcion_riesgo(puerto_num)
                puertos_criticos.append(puerto)
            else:
                puerto['criticidad'] = 'MEDIA'
                puertos_normales.append(puerto)
        
        # Clasificar vulnerabilidades por severidad
        vulnerabilidades_criticas = []
        vulnerabilidades_altas = []
        vulnerabilidades_medias = []
        
        for vuln in resultado.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in ['critical', 'high']:
                if severity == 'critical':
                    vulnerabilidades_criticas.append(vuln)
                else:
                    vulnerabilidades_altas.append(vuln)
            else:
                vulnerabilidades_medias.append(vuln)
        
        # Generar recomendaciones de seguridad
        recomendaciones = self._generar_recomendaciones(
            puertos_criticos, vulnerabilidades_criticas + vulnerabilidades_altas
        )
        
        # Calcular puntuación de riesgo
        puntuacion_riesgo = self._calcular_puntuacion_riesgo(
            puertos_criticos, vulnerabilidades_criticas, vulnerabilidades_altas
        )
        
        return {
            'exito': resultado.success,
            'objetivo': resultado.target,
            'tipo_escaneo': resultado.scan_type,
            'herramienta_principal': resultado.tool,
            'timestamp': resultado.timestamp.isoformat(),
            'duracion': resultado.duration,
            
            # Información de puertos
            'puertos_encontrados': resultado.ports,
            'puertos_criticos': puertos_criticos,
            'puertos_normales': puertos_normales,
            'total_puertos': len(resultado.ports),
            'total_puertos_criticos': len(puertos_criticos),
            
            # Información de servicios
            'servicios_detectados': resultado.services,
            'total_servicios': len(resultado.services),
            
            # Información de vulnerabilidades
            'vulnerabilidades': resultado.vulnerabilities,
            'vulnerabilidades_criticas': vulnerabilidades_criticas,
            'vulnerabilidades_altas': vulnerabilidades_altas,
            'vulnerabilidades_medias': vulnerabilidades_medias,
            'total_vulnerabilidades': len(resultado.vulnerabilities),
            'total_vulnerabilidades_criticas': len(vulnerabilidades_criticas),
            
            # Análisis de riesgo
            'puntuacion_riesgo': puntuacion_riesgo,
            'nivel_riesgo': self._obtener_nivel_riesgo(puntuacion_riesgo),
            'recomendaciones': recomendaciones,
            
            # Metadatos
            'metadata': resultado.metadata,
            'herramientas_usadas': resultado.metadata.get('tools_used', [resultado.tool]),
            
            # Error si existe
            'error': resultado.error,
            'codigo_error': 'SCAN_FAILED' if resultado.error else None
        }

    def _obtener_descripcion_riesgo(self, puerto: int) -> str:
        """Obtener descripción del riesgo para un puerto específico"""
        descripciones_riesgo = {
            21: "FTP - Protocolo inseguro, riesgo de transferencia no cifrada",
            22: "SSH - Acceso remoto, objetivo común de ataques de fuerza bruta",
            23: "Telnet - Protocolo muy inseguro, comunicación en texto plano",
            25: "SMTP - Servidor de correo, riesgo de relay y spam",
            53: "DNS - Servidor de nombres, riesgo de envenenamiento DNS",
            80: "HTTP - Servidor web inseguro, comunicación no cifrada",
            135: "RPC Windows - Servicio crítico Windows, objetivo de exploits",
            139: "NetBIOS - Compartición Windows insegura",
            143: "IMAP - Correo inseguro, credenciales en texto plano",
            443: "HTTPS - Servidor web, verificar certificados y configuración",
            445: "SMB - Compartición archivos Windows, objetivo crítico",
            993: "IMAPS - Correo cifrado, verificar implementación SSL/TLS",
            995: "POP3S - Correo cifrado, verificar configuración",
            1433: "SQL Server - Base de datos, riesgo de inyección SQL",
            1521: "Oracle DB - Base de datos crítica",
            3306: "MySQL - Base de datos, configuración crítica",
            3389: "RDP - Escritorio remoto Windows, objetivo de ataques",
            5432: "PostgreSQL - Base de datos crítica",
            5900: "VNC - Control remoto inseguro",
            6379: "Redis - Base de datos NoSQL, configuración crítica",
            8080: "HTTP alternativo - Aplicaciones web, posibles paneles admin",
            8443: "HTTPS alternativo - Verificar configuración SSL/TLS"
        }
        
        return descripciones_riesgo.get(puerto, f"Puerto {puerto} - Revisar servicio y configuración")

    def _generar_recomendaciones(self, puertos_criticos: List[Dict[str, Any]], 
                               vulnerabilidades_criticas: List[Dict[str, Any]]) -> List[str]:
        """Generar recomendaciones de seguridad basadas en hallazgos"""
        recomendaciones = []
        
        # Recomendaciones por puertos críticos
        if puertos_criticos:
            recomendaciones.append("🔒 PUERTOS CRÍTICOS DETECTADOS:")
            
            for puerto_info in puertos_criticos[:5]:  # Top 5 más críticos
                puerto = puerto_info.get('port')
                servicio = puerto_info.get('service', 'unknown')
                
                if puerto == 23:  # Telnet
                    recomendaciones.append("  • Deshabilitar Telnet inmediatamente y usar SSH")
                elif puerto == 21:  # FTP
                    recomendaciones.append("  • Configurar FTP con cifrado o usar SFTP/SCP")
                elif puerto == 22:  # SSH
                    recomendaciones.append("  • Configurar autenticación por clave y fail2ban")
                elif puerto == 135:  # RPC
                    recomendaciones.append("  • Restringir acceso RPC solo a redes internas")
                elif puerto == 445:  # SMB
                    recomendaciones.append("  • Actualizar SMB y configurar autenticación fuerte")
                elif puerto in [3306, 1433, 5432]:  # Bases de datos
                    recomendaciones.append(f"  • Restringir acceso a BD {servicio} solo a aplicaciones")
                elif puerto == 3389:  # RDP
                    recomendaciones.append("  • Configurar RDP con NLA y VPN")
        
        # Recomendaciones por vulnerabilidades
        if vulnerabilidades_criticas:
            recomendaciones.append("⚠️ VULNERABILIDADES CRÍTICAS:")
            
            for vuln in vulnerabilidades_criticas[:3]:  # Top 3 más críticas
                vuln_name = vuln.get('name', vuln.get('description', 'Vulnerabilidad desconocida'))
                recomendaciones.append(f"  • {vuln_name}")
                
                # Recomendaciones específicas por tipo
                if 'CVE-' in str(vuln):
                    recomendaciones.append("  • Aplicar parches de seguridad inmediatamente")
                if 'default' in str(vuln).lower():
                    recomendaciones.append("  • Cambiar credenciales por defecto")
                if 'ssl' in str(vuln).lower() or 'tls' in str(vuln).lower():
                    recomendaciones.append("  • Actualizar configuración SSL/TLS")
        
        # Recomendaciones generales
        recomendaciones.extend([
            "🛡️ RECOMENDACIONES GENERALES:",
            "  • Implementar firewall restrictivo",
            "  • Configurar monitoreo de logs de seguridad",
            "  • Realizar auditorías regulares de seguridad",
            "  • Mantener sistemas actualizados",
            "  • Configurar backup y plan de recuperación"
        ])
        
        return recomendaciones

    def _calcular_puntuacion_riesgo(self, puertos_criticos: List[Dict[str, Any]],
                                   vuln_criticas: List[Dict[str, Any]], 
                                   vuln_altas: List[Dict[str, Any]]) -> int:
        """Calcular puntuación de riesgo (0-100)"""
        puntuacion = 0
        
        # Puntos por puertos críticos (máximo 40 puntos)
        puntos_puertos = min(len(puertos_criticos) * 8, 40)
        puntuacion += puntos_puertos
        
        # Puntos por vulnerabilidades críticas (máximo 40 puntos)
        puntos_vuln_criticas = min(len(vuln_criticas) * 15, 40)
        puntuacion += puntos_vuln_criticas
        
        # Puntos por vulnerabilidades altas (máximo 20 puntos)
        puntos_vuln_altas = min(len(vuln_altas) * 5, 20)
        puntuacion += puntos_vuln_altas
        
        return min(puntuacion, 100)

    def _obtener_nivel_riesgo(self, puntuacion: int) -> str:
        """Obtener nivel de riesgo basado en puntuación"""
        if puntuacion >= 80:
            return "CRÍTICO"
        elif puntuacion >= 60:
            return "ALTO"
        elif puntuacion >= 40:
            return "MEDIO"
        elif puntuacion >= 20:
            return "BAJO"
        else:
            return "MÍNIMO"

    def _actualizar_estadisticas(self, resultado: ScanResult):
        """Actualizar estadísticas del controlador"""
        self.stats['total_scans'] += 1
        
        if resultado.success:
            self.stats['successful_scans'] += 1
        else:
            self.stats['failed_scans'] += 1
        
        self.stats['total_ports_found'] += len(resultado.ports)
        self.stats['total_vulnerabilities'] += len(resultado.vulnerabilities)
        self.stats['total_scan_time'] += resultado.duration

    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas del controlador"""
        stats = self.stats.copy()
        
        # Calcular métricas adicionales
        if stats['total_scans'] > 0:
            stats['tasa_exito'] = (stats['successful_scans'] / stats['total_scans']) * 100
            stats['promedio_puertos_por_scan'] = stats['total_ports_found'] / stats['total_scans']
            stats['promedio_vulns_por_scan'] = stats['total_vulnerabilities'] / stats['total_scans']
            stats['tiempo_promedio_scan'] = stats['total_scan_time'] / stats['total_scans']
        else:
            stats['tasa_exito'] = 0
            stats['promedio_puertos_por_scan'] = 0
            stats['promedio_vulns_por_scan'] = 0
            stats['tiempo_promedio_scan'] = 0
        
        # Información del escaneador
        if self.escaneador:
            stats['herramientas_disponibles'] = list(self.escaneador.tools_available.keys())
            stats['herramientas_activas'] = [
                k for k, v in self.escaneador.tools_available.items() if v
            ]
        
        return stats

    def obtener_herramientas_disponibles(self) -> Dict[str, bool]:
        """Obtener estado de herramientas disponibles"""
        if self.escaneador:
            return self.escaneador.tools_available.copy()
        return {}

    def configurar_escaneador(self, nueva_config: Dict[str, Any]) -> bool:
        """Configurar parámetros del escaneador"""
        try:
            # Actualizar configuración
            if 'timeout' in nueva_config:
                self.scanner_config.timeout = nueva_config['timeout']
            if 'max_workers' in nueva_config:
                self.scanner_config.max_workers = nueva_config['max_workers']
            if 'rate_limit' in nueva_config:
                self.scanner_config.rate_limit = nueva_config['rate_limit']
            if 'enable_service_detection' in nueva_config:
                self.scanner_config.enable_service_detection = nueva_config['enable_service_detection']
            if 'enable_vuln_scan' in nueva_config:
                self.scanner_config.enable_vuln_scan = nueva_config['enable_vuln_scan']
            if 'enable_web_scan' in nueva_config:
                self.scanner_config.enable_web_scan = nueva_config['enable_web_scan']
            
            # Reinicializar escaneador con nueva configuración
            self.escaneador = EscaneadorAvanzadoKali2025(self.scanner_config)
            
            self.logger.info("Configuración del escaneador actualizada")
            return True
            
        except Exception as e:
            self.logger.error(f"Error configurando escaneador: {e}")
            return False

    def cancelar_escaneo(self) -> bool:
        """Cancelar escaneo en progreso"""
        if not self.scan_in_progress:
            return False
        
        try:
            if self.current_scan_thread and self.current_scan_thread.is_alive():
                # Nota: No hay forma segura de matar threads en Python
                # El escaneo se completará pero se marcará como cancelado
                self.scan_in_progress = False
                self.logger.info("Solicitud de cancelación enviada")
                return True
        except Exception as e:
            self.logger.error(f"Error cancelando escaneo: {e}")
        
        return False

    def generar_reporte_detallado(self, resultados: List[Dict[str, Any]], 
                                formato: str = 'json') -> str:
        """Generar reporte detallado de múltiples escaneos"""
        try:
            if self.escaneador:
                # Convertir resultados a formato ScanResult para el generador
                scan_results = []
                for resultado in resultados:
                    if resultado.get('exito'):
                        scan_result = ScanResult(
                            target=resultado.get('objetivo', ''),
                            scan_type=resultado.get('tipo_escaneo', ''),
                            tool=resultado.get('herramienta_principal', ''),
                            timestamp=datetime.fromisoformat(resultado.get('timestamp', datetime.now().isoformat())),
                            duration=resultado.get('duracion', 0),
                            ports=resultado.get('puertos_encontrados', []),
                            vulnerabilities=resultado.get('vulnerabilidades', []),
                            services=resultado.get('servicios_detectados', []),
                            metadata=resultado.get('metadata', {}),
                            success=resultado.get('exito', False),
                            error=resultado.get('error')
                        )
                        scan_results.append(scan_result)
                
                return self.escaneador.generate_report(scan_results, formato)
            
        except Exception as e:
            self.logger.error(f"Error generando reporte: {e}")
        
        return json.dumps({'error': 'No se pudo generar reporte'}, indent=2)

    def obtener_cache_resultados(self) -> Dict[str, Any]:
        """Obtener resultados en caché"""
        return self.scan_results_cache.copy()

    def limpiar_cache(self):
        """Limpiar caché de resultados"""
        self.scan_results_cache.clear()
        self.logger.info("Caché de resultados limpiado")

# Funciones de utilidad para compatibilidad con ARESITOS existente

def crear_controlador_escaneador_avanzado() -> ControladorEscaneadorAvanzado:
    """Crear instancia del controlador con configuración por defecto"""
    return ControladorEscaneadorAvanzado()

def escaneo_rapido_compatible(objetivo: str) -> Dict[str, Any]:
    """Función de escaneo rápido compatible con sistema existente"""
    controlador = crear_controlador_escaneador_avanzado()
    return controlador.escanear_objetivo(objetivo, 'rapido')

def escaneo_completo_compatible(objetivo: str) -> Dict[str, Any]:
    """Función de escaneo completo compatible con sistema existente"""
    controlador = crear_controlador_escaneador_avanzado()
    return controlador.escanear_objetivo(objetivo, 'completo')

if __name__ == "__main__":
    # Prueba del controlador
    print("ARESITOS - Controlador Escaneador Avanzado Kali 2025")
    print("=====================================================")
    
    controlador = crear_controlador_escaneador_avanzado()
    
    # Mostrar herramientas disponibles
    herramientas = controlador.obtener_herramientas_disponibles()
    print(f"Herramientas disponibles: {list(herramientas.keys())}")
    
    # Estadísticas iniciales
    stats = controlador.obtener_estadisticas()
    print(f"Estadísticas iniciales: {stats}")
