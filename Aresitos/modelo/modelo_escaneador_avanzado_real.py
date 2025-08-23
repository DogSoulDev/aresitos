# -*- coding: utf-8 -*-
"""
Ares Aegis - Escaneador Avanzado Real
====================================

Implementación del escaneador avanzado principal para Aresitos.
Sistema de escaneo completo con capacidades de análisis y detección.

Autor: DogSoulDev
Fecha: Diciembre 2024
"""

import subprocess
import threading
import json
import os
import time
import socket
import hashlib
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

# Clase de datos para resultados de escaneo
@dataclass
class ResultadoEscaneo:
    """Resultado de un escaneo completo."""
    objetivo: str
    tiempo_inicio: datetime
    tiempo_fin: Optional[datetime] = None
    puertos_abiertos: Optional[List[Dict[str, Any]]] = None
    servicios_detectados: Optional[List[Dict[str, Any]]] = None
    vulnerabilidades: Optional[List[Dict[str, Any]]] = None
    procesos_sospechosos: Optional[List[Dict[str, Any]]] = None
    archivos_sospechosos: Optional[List[str]] = None
    alertas: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.puertos_abiertos is None:
            self.puertos_abiertos = []
        if self.servicios_detectados is None:
            self.servicios_detectados = []
        if self.vulnerabilidades is None:
            self.vulnerabilidades = []
        if self.procesos_sospechosos is None:
            self.procesos_sospechosos = []
        if self.archivos_sospechosos is None:
            self.archivos_sospechosos = []
        if self.alertas is None:
            self.alertas = []

class EscaneadorAvanzadoReal:
    """
    Escaneador avanzado principal de Aresitos.
    Sistema completo de análisis y detección de amenazas.
    """
    
    def __init__(self, siem=None, cuarentena=None):
        """Inicializa el escáner avanzado."""
        self.logger = logging.getLogger("aresitos.modelo.escaneador_avanzado")
        
        # Componentes opcionales
        self.siem = siem
        self.cuarentena = cuarentena
        
        # Estado del escáner
        self._escaneando = False
        self._cancelar = False
        
        # Sistema de caché para optimizar escaneos
        self._cache_resultados = {
            'escaneos': {},
            'metadatos': {
                'hits': 0,
                'misses': 0,
                'size_limit': 100,
                'ttl_default': 3600
            }
        }
        
        # Métricas de seguridad
        self._metricas_seguridad = {
            'sesion_iniciada': datetime.now(),
            'alertas_seguridad': [],
            'ips_consultadas': set(),
            'dominios_consultados': set(),
            'patrones_anomalos': [],
            'comandos_bloqueados': 0,
            'operaciones_por_minuto': []
        }
        
        # Puertos comunes para escaneo
        self.puertos_comunes = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        # Herramientas disponibles
        self._herramientas_disponibles = self._verificar_herramientas()
        
        # Base de datos de vulnerabilidades conocidas
        self._db_vulnerabilidades = self._cargar_base_vulnerabilidades()
        
        self.logger.info("Sistema de cuarentena automática activado")
        self.logger.info("Escaneador Avanzado Real Ares Aegis inicializado")
        self.logger.info(f"Herramientas disponibles: {len(self._herramientas_disponibles)}/10")
    
    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verificar disponibilidad de herramientas de escaneo."""
        herramientas = {
            'nmap': False,
            'masscan': False,
            'gobuster': False,
            'nikto': False,
            'nuclei': False,
            'ffuf': False,
            'sqlmap': False,
            'hydra': False,
            'ss': False,
            'ps': False
        }
        
        for herramienta in herramientas:
            try:
                result = subprocess.run(
                    ['which', herramienta], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                herramientas[herramienta] = result.returncode == 0
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                herramientas[herramienta] = False
        
        return herramientas
    
    def _cargar_base_vulnerabilidades(self) -> Dict[str, Any]:
        """Cargar base de datos de vulnerabilidades conocidas."""
        try:
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'vulnerability_database.json')
            if os.path.exists(db_path):
                with open(db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"No se pudo cargar base de vulnerabilidades: {e}")
        
        # Base de datos básica por defecto
        return {
            'puertos_riesgosos': [22, 23, 21, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900],
            'servicios_vulnerables': ['ssh', 'telnet', 'ftp', 'http', 'https', 'mysql', 'postgresql', 'vnc'],
            'patrones_malware': ['malware', 'virus', 'trojan', 'backdoor', 'rootkit']
        }
    
    def escanear_completo(self, objetivo: str = "localhost") -> ResultadoEscaneo:
        """
        Ejecutar escaneo completo del objetivo.
        
        Args:
            objetivo: IP o dominio a escanear
            
        Returns:
            ResultadoEscaneo: Resultado completo del análisis
        """
        self.logger.info(f"🎯 Iniciando escaneo completo de: {objetivo}")
        
        resultado = ResultadoEscaneo(
            objetivo=objetivo,
            tiempo_inicio=datetime.now()
        )
        
        try:
            self._escaneando = True
            
            # 1. Escaneo de puertos
            self.logger.info("Fase 1: Escaneando puertos...")
            puertos = self._escanear_puertos(objetivo)
            resultado.puertos_abiertos = puertos
            
            # 2. Análisis de procesos
            self.logger.info("Fase 2: Analizando procesos...")
            procesos = self._analizar_procesos()
            resultado.procesos_sospechosos = procesos
            
            # 3. Escaneo de archivos sospechosos
            self.logger.info("Fase 3: Buscando archivos sospechosos...")
            archivos = self._buscar_archivos_sospechosos()
            resultado.archivos_sospechosos = archivos
            
            # 4. Análisis de vulnerabilidades
            self.logger.info("Fase 4: Analizando vulnerabilidades...")
            vulns = self._analizar_vulnerabilidades(puertos, procesos)
            resultado.vulnerabilidades = vulns
            
            # 5. Generar alertas
            self.logger.info("Fase 5: Generando alertas...")
            alertas = self._generar_alertas(resultado)
            resultado.alertas = alertas
            
            resultado.tiempo_fin = datetime.now()
            duracion = (resultado.tiempo_fin - resultado.tiempo_inicio).total_seconds()
            
            self.logger.info(f"✅ Escaneo completado en {duracion:.2f} segundos")
            self.logger.info(f"📊 Puertos encontrados: {len(puertos)}")
            self.logger.info(f"⚠️ Vulnerabilidades detectadas: {len(vulns)}")
            
            # Registrar en SIEM si está disponible
            if self.siem:
                try:
                    self.siem.registrar_evento(
                        tipo="ESCANEO_COMPLETADO",
                        mensaje=f"Escaneo de {objetivo} completado",
                        detalles={
                            'objetivo': objetivo,
                            'puertos_encontrados': len(puertos),
                            'vulnerabilidades': len(vulns),
                            'duracion': duracion
                        }
                    )
                except Exception as e:
                    self.logger.warning(f"Error registrando en SIEM: {e}")
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"❌ Error en escaneo: {e}")
            if resultado.alertas is None:
                resultado.alertas = []
            resultado.alertas.append(f"Error en escaneo: {str(e)}")
            resultado.tiempo_fin = datetime.now()
            return resultado
        finally:
            self._escaneando = False
    
    def _escanear_puertos(self, objetivo: str) -> List[Dict[str, Any]]:
        """Escanear puertos del objetivo."""
        puertos_encontrados = []
        
        try:
            if self._herramientas_disponibles.get('nmap'):
                # Usar nmap si está disponible
                cmd = ['nmap', '-sS', '-T4', '--top-ports', '1000', objetivo]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Parsear salida de nmap
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                puerto_info = parts[0].split('/')[0]
                                estado = parts[1]
                                servicio = parts[2] if len(parts) > 2 else 'unknown'
                                
                                puertos_encontrados.append({
                                    'puerto': int(puerto_info),
                                    'estado': estado,
                                    'servicio': servicio,
                                    'protocolo': 'tcp'
                                })
            
            else:
                # Fallback usando netstat/ss
                self.logger.info("📡 Usando herramientas del sistema para escaneo...")
                puertos_encontrados = self._escanear_puertos_sistema()
                
        except subprocess.TimeoutExpired:
            self.logger.warning("⏰ Timeout en escaneo de puertos")
        except Exception as e:
            self.logger.error(f"❌ Error escaneando puertos: {e}")
        
        return puertos_encontrados
    
    def _escanear_puertos_sistema(self) -> List[Dict[str, Any]]:
        """Escanear puertos usando herramientas del sistema."""
        puertos = []
        
        try:
            # Usar ss si está disponible
            if self._herramientas_disponibles.get('ss'):
                cmd = ['ss', '-tuln']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[1:]  # Saltar header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 5:
                                proto = parts[0]
                                estado = parts[1]
                                local_addr = parts[4]
                                
                                if ':' in local_addr:
                                    try:
                                        puerto = int(local_addr.split(':')[-1])
                                        puertos.append({
                                            'puerto': puerto,
                                            'estado': estado,
                                            'servicio': 'unknown',
                                            'protocolo': proto.lower()
                                        })
                                    except ValueError:
                                        continue
            
        except Exception as e:
            self.logger.error(f"❌ Error en escaneo del sistema: {e}")
        
        return puertos
    
    def _analizar_procesos(self) -> List[Dict[str, Any]]:
        """Analizar procesos en busca de actividad sospechosa."""
        procesos_sospechosos = []
        
        try:
            cmd = ['ps', 'aux']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Saltar header
                
                for line in lines:
                    if line.strip():
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            user = parts[0]
                            pid = parts[1]
                            cpu = parts[2]
                            mem = parts[3]
                            command = parts[10]
                            
                            # Detectar procesos sospechosos
                            if self._es_proceso_sospechoso(command, user, float(cpu)):
                                procesos_sospechosos.append({
                                    'pid': pid,
                                    'user': user,
                                    'cpu': cpu,
                                    'mem': mem,
                                    'command': command,
                                    'razon': self._obtener_razon_sospecha(command, user, float(cpu))
                                })
        
        except Exception as e:
            self.logger.error(f"❌ Error analizando procesos: {e}")
        
        return procesos_sospechosos
    
    def _es_proceso_sospechoso(self, command: str, user: str, cpu: float) -> bool:
        """Determinar si un proceso es sospechoso."""
        command_lower = command.lower()
        
        # Patrones sospechosos
        patrones_malware = ['miner', 'xmrig', 'cpuminer', 'malware', 'virus']
        patrones_red = ['nc ', 'netcat', 'reverse', 'shell']
        
        # Alto uso de CPU
        if cpu > 90.0:
            return True
        
        # Comandos sospechosos
        for patron in patrones_malware + patrones_red:
            if patron in command_lower:
                return True
        
        # Procesos corriendo como root con nombres extraños
        if user == 'root' and len(command.split('/')[0]) < 3:
            return True
        
        return False
    
    def _obtener_razon_sospecha(self, command: str, user: str, cpu: float) -> str:
        """Obtener razón por la que un proceso es sospechoso."""
        if cpu > 90.0:
            return f"Alto uso de CPU: {cpu}%"
        
        command_lower = command.lower()
        if 'miner' in command_lower:
            return "Posible cryptominer"
        if 'nc ' in command_lower or 'netcat' in command_lower:
            return "Herramienta de red sospechosa"
        if user == 'root':
            return "Proceso root con nombre inusual"
        
        return "Patrón de comportamiento anómalo"
    
    def _buscar_archivos_sospechosos(self) -> List[str]:
        """Buscar archivos potencialmente sospechosos."""
        archivos_sospechosos = []
        
        # Directorios a revisar
        directorios = ['/tmp', '/var/tmp', '/home']
        
        try:
            for directorio in directorios:
                if os.path.exists(directorio):
                    for root, dirs, files in os.walk(directorio):
                        for file in files:
                            filepath = os.path.join(root, file)
                            
                            # Verificar si el archivo es sospechoso
                            if self._es_archivo_sospechoso(file, filepath):
                                archivos_sospechosos.append(filepath)
                            
                            # Limitar a primeros 100 archivos para evitar sobrecarga
                            if len(archivos_sospechosos) >= 100:
                                break
                        
                        if len(archivos_sospechosos) >= 100:
                            break
                    
                    if len(archivos_sospechosos) >= 100:
                        break
        
        except Exception as e:
            self.logger.error(f"❌ Error buscando archivos: {e}")
        
        return archivos_sospechosos
    
    def _es_archivo_sospechoso(self, filename: str, filepath: str) -> bool:
        """Determinar si un archivo es sospechoso."""
        filename_lower = filename.lower()
        
        # Extensiones sospechosas
        ext_sospechosas = ['.exe', '.scr', '.bat', '.cmd', '.vbs']
        
        # Nombres sospechosos
        nombres_sospechosos = ['malware', 'virus', 'trojan', 'backdoor', 'keylog']
        
        # Verificar extensión
        for ext in ext_sospechosas:
            if filename_lower.endswith(ext):
                return True
        
        # Verificar nombres
        for nombre in nombres_sospechosos:
            if nombre in filename_lower:
                return True
        
        # Archivos ocultos en /tmp
        if filepath.startswith('/tmp') and filename.startswith('.'):
            return True
        
        return False
    
    def _analizar_vulnerabilidades(self, puertos: List[Dict], procesos: List[Dict]) -> List[Dict[str, Any]]:
        """Analizar vulnerabilidades basándose en puertos y procesos."""
        vulnerabilidades = []
        
        # Analizar puertos riesgosos
        puertos_riesgosos = self._db_vulnerabilidades.get('puertos_riesgosos', [])
        
        for puerto_info in puertos:
            puerto = puerto_info.get('puerto')
            if puerto in puertos_riesgosos:
                vulnerabilidades.append({
                    'tipo': 'puerto_riesgoso',
                    'severidad': 'media',
                    'descripcion': f"Puerto {puerto} abierto ({puerto_info.get('servicio', 'unknown')})",
                    'recomendacion': f"Revisar necesidad del servicio en puerto {puerto}"
                })
        
        # Analizar servicios conocidos como vulnerables
        servicios_vulnerables = self._db_vulnerabilidades.get('servicios_vulnerables', [])
        
        for puerto_info in puertos:
            servicio = puerto_info.get('servicio', '').lower()
            if servicio in servicios_vulnerables:
                vulnerabilidades.append({
                    'tipo': 'servicio_vulnerable',
                    'severidad': 'alta' if servicio in ['telnet', 'ftp'] else 'media',
                    'descripcion': f"Servicio {servicio} detectado en puerto {puerto_info.get('puerto')}",
                    'recomendacion': f"Actualizar o asegurar servicio {servicio}"
                })
        
        # Analizar procesos sospechosos como vulnerabilidades
        for proceso in procesos:
            vulnerabilidades.append({
                'tipo': 'proceso_sospechoso',
                'severidad': 'alta',
                'descripcion': f"Proceso sospechoso: {proceso.get('command', '')[:50]}...",
                'recomendacion': "Investigar y eliminar proceso si es malicioso"
            })
        
        return vulnerabilidades
    
    def _generar_alertas(self, resultado: ResultadoEscaneo) -> List[str]:
        """Generar alertas basándose en los resultados del escaneo."""
        alertas = []
        
        # Alertas por puertos
        if resultado.puertos_abiertos and len(resultado.puertos_abiertos) > 20:
            alertas.append(f"⚠️ Gran cantidad de puertos abiertos: {len(resultado.puertos_abiertos)}")
        
        # Alertas por vulnerabilidades
        if resultado.vulnerabilidades:
            vulns_altas = [v for v in resultado.vulnerabilidades if v.get('severidad') == 'alta']
            if vulns_altas:
                alertas.append(f"🚨 {len(vulns_altas)} vulnerabilidades de severidad alta detectadas")
        
        # Alertas por procesos
        if resultado.procesos_sospechosos:
            alertas.append(f"👤 {len(resultado.procesos_sospechosos)} procesos sospechosos detectados")
        
        # Alertas por archivos
        if resultado.archivos_sospechosos:
            alertas.append(f"📁 {len(resultado.archivos_sospechosos)} archivos potencialmente maliciosos")
        
        return alertas
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas del escáner."""
        return {
            'herramientas_disponibles': sum(self._herramientas_disponibles.values()),
            'total_herramientas': len(self._herramientas_disponibles),
            'estado': 'escaneando' if self._escaneando else 'inactivo',
            'db_vulnerabilidades_cargada': bool(self._db_vulnerabilidades)
        }
    
    def cancelar_escaneo(self):
        """Cancelar escaneo en progreso."""
        self._cancelar = True
        self.logger.info("Cancelación de escaneo solicitada")
    
    # ===============================================
    # FUNCIONALIDADES DE SEGURIDAD Y CACHÉ AVANZADAS
    # ===============================================
    
    def _validar_objetivo_seguro(self, objetivo: str) -> bool:
        """Validar que el objetivo es seguro para escanear."""
        # Lista de IPs/dominios prohibidos
        ips_prohibidas = ['127.0.0.1', 'localhost', '::1', '0.0.0.0']
        dominios_prohibidos = ['localhost.localdomain', 'local']
        
        # Verificar IPs prohibidas
        if objetivo.lower() in [ip.lower() for ip in ips_prohibidas]:
            self._registrar_alerta('alta', f'Intento de escaneo a IP prohibida: {objetivo}')
            return False
        
        # Verificar dominios prohibidos
        if objetivo.lower() in [dom.lower() for dom in dominios_prohibidos]:
            self._registrar_alerta('alta', f'Intento de escaneo a dominio prohibido: {objetivo}')
            return False
        
        # Registrar objetivo consultado
        if self._es_ip(objetivo):
            self._metricas_seguridad['ips_consultadas'].add(objetivo)
        else:
            self._metricas_seguridad['dominios_consultados'].add(objetivo)
        
        return True
    
    def _es_ip(self, objetivo: str) -> bool:
        """Verificar si el objetivo es una dirección IP."""
        try:
            socket.inet_aton(objetivo)
            return True
        except socket.error:
            return False
    
    def _detectar_anomalias(self, tipo_escaneo: str, objetivo: str):
        """Detectar patrones anómalos en los escaneos."""
        ahora = datetime.now()
        
        # Registrar operación para análisis de frecuencia
        self._metricas_seguridad['operaciones_por_minuto'].append(ahora)
        
        # Limpiar operaciones de más de un minuto
        limite_tiempo = ahora.timestamp() - 60
        self._metricas_seguridad['operaciones_por_minuto'] = [
            op for op in self._metricas_seguridad['operaciones_por_minuto'] 
            if op.timestamp() > limite_tiempo
        ]
        
        # Detectar alta frecuencia de operaciones
        if len(self._metricas_seguridad['operaciones_por_minuto']) > 30:
            self._registrar_alerta('alta', f'Alta frecuencia de operaciones: {len(self._metricas_seguridad["operaciones_por_minuto"])}/min')
        
        # Detectar patrones sospechosos
        patron_actual = f"{tipo_escaneo}_{objetivo}"
        self._metricas_seguridad['patrones_anomalos'].append(patron_actual)
        
        # Mantener solo los últimos 100 patrones
        if len(self._metricas_seguridad['patrones_anomalos']) > 100:
            self._metricas_seguridad['patrones_anomalos'] = self._metricas_seguridad['patrones_anomalos'][-100:]
    
    def _registrar_alerta(self, severidad: str, mensaje: str):
        """Registrar alerta de seguridad."""
        alerta = {
            'timestamp': datetime.now(),
            'severidad': severidad,
            'mensaje': mensaje
        }
        
        self._metricas_seguridad['alertas_seguridad'].append(alerta)
        
        # Log según severidad
        if severidad == 'alta':
            self.logger.warning(f"ALERTA SEGURIDAD: {mensaje}")
        else:
            self.logger.info(f"Alerta: {mensaje}")
        
        # Notificar SIEM si está disponible
        if self.siem:
            try:
                self.siem.registrar_evento('alerta_seguridad', alerta)
            except Exception as e:
                self.logger.debug(f"Error notificando SIEM: {e}")

    def _generar_hash_cache(self, operacion: str, parametros: Dict[str, Any]) -> str:
        """Generar hash único para operaciones de caché."""
        datos_cache = f"{operacion}_{str(sorted(parametros.items()))}"
        return hashlib.md5(datos_cache.encode()).hexdigest()

    def _guardar_en_cache(self, cache_key: str, resultado: Dict[str, Any], ttl: Optional[int] = None):
        """Guardar resultado en caché."""
        if ttl is None:
            ttl = self._cache_resultados['metadatos']['ttl_default']
        
        # Verificar límite de tamaño
        if len(self._cache_resultados['escaneos']) >= self._cache_resultados['metadatos']['size_limit']:
            # Eliminar entrada más antigua
            entrada_mas_antigua = min(
                self._cache_resultados['escaneos'].keys(),
                key=lambda k: self._cache_resultados['escaneos'][k]['timestamp']
            )
            del self._cache_resultados['escaneos'][entrada_mas_antigua]
        
        self._cache_resultados['escaneos'][cache_key] = {
            'resultado': resultado,
            'timestamp': datetime.now(),
            'ttl': ttl
        }
        
        self.logger.debug(f"Resultado guardado en caché: {cache_key}")

    def _obtener_desde_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Obtener resultado desde caché si está disponible y válido."""
        if cache_key in self._cache_resultados['escaneos']:
            entrada = self._cache_resultados['escaneos'][cache_key]
            tiempo_transcurrido = (datetime.now() - entrada['timestamp']).total_seconds()
            
            if tiempo_transcurrido < entrada['ttl']:
                self._cache_resultados['metadatos']['hits'] += 1
                self.logger.debug(f"Cache HIT para {cache_key}")
                return entrada['resultado']
            else:
                # Eliminar entrada expirada
                del self._cache_resultados['escaneos'][cache_key]
        
        self._cache_resultados['metadatos']['misses'] += 1
        self.logger.debug(f"Cache MISS para {cache_key}")
        return None

    def escaneo_con_cache(self, tipo_escaneo: str, objetivo: str, **parametros) -> Dict[str, Any]:
        """Realizar escaneo con sistema de caché."""
        # Verificar anomalías primero
        self._detectar_anomalias(tipo_escaneo, objetivo)
        
        # Generar clave de caché
        cache_key = self._generar_hash_cache(tipo_escaneo, {'objetivo': objetivo, **parametros})
        
        # Verificar caché primero
        resultado_cache = self._obtener_desde_cache(cache_key)
        if resultado_cache:
            resultado_cache['desde_cache'] = True
            return resultado_cache
        
        # Realizar escaneo real
        try:
            if tipo_escaneo == "puertos_basico":
                resultado = self._escaneo_puertos_basico(objetivo, **parametros)
            elif tipo_escaneo == "servicios":
                resultado = self._escaneo_servicios(objetivo, **parametros)
            else:
                resultado = {'exito': False, 'error': f'Tipo de escaneo no reconocido: {tipo_escaneo}'}
            
            # Guardar en caché si fue exitoso
            if resultado.get('exito'):
                self._guardar_en_cache(cache_key, resultado)
            
            resultado['desde_cache'] = False
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en escaneo {tipo_escaneo}: {e}")
            return {'exito': False, 'error': str(e), 'desde_cache': False}

    def _escaneo_puertos_basico(self, objetivo: str, **parametros) -> Dict[str, Any]:
        """Escaneo básico de puertos usando herramientas del sistema."""
        if not self._validar_objetivo_seguro(objetivo):
            return {'exito': False, 'error': 'Objetivo no válido para escaneo'}
        
        puertos_escanear = parametros.get('puertos', self.puertos_comunes)
        puertos_abiertos = []
        
        for puerto in puertos_escanear:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                resultado = sock.connect_ex((objetivo, puerto))
                
                if resultado == 0:
                    puertos_abiertos.append({
                        'puerto': puerto,
                        'estado': 'abierto',
                        'protocolo': 'tcp'
                    })
                
                sock.close()
                
            except Exception as e:
                self.logger.debug(f"Error escaneando puerto {puerto}: {e}")
        
        return {
            'exito': True,
            'objetivo': objetivo,
            'puertos_abiertos': puertos_abiertos,
            'total_puertos_escaneados': len(puertos_escanear),
            'timestamp': datetime.now().isoformat()
        }

    def _escaneo_servicios(self, objetivo: str, **parametros) -> Dict[str, Any]:
        """Identificar servicios en puertos abiertos."""
        # Primero obtener puertos abiertos
        resultado_puertos = self._escaneo_puertos_basico(objetivo, **parametros)
        
        if not resultado_puertos.get('exito'):
            return resultado_puertos
        
        servicios_identificados = []
        
        for puerto_info in resultado_puertos['puertos_abiertos']:
            puerto = puerto_info['puerto']
            servicio = self._identificar_servicio(puerto)
            
            servicios_identificados.append({
                'puerto': puerto,
                'servicio': servicio,
                'estado': 'identificado'
            })
        
        return {
            'exito': True,
            'objetivo': objetivo,
            'servicios': servicios_identificados,
            'total_servicios': len(servicios_identificados),
            'timestamp': datetime.now().isoformat()
        }

    def _identificar_servicio(self, puerto: int) -> str:
        """Identificar servicio común por puerto."""
        servicios_comunes = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL'
        }
        
        return servicios_comunes.get(puerto, f'Desconocido-{puerto}')

    def obtener_estadisticas_seguridad(self) -> Dict[str, Any]:
        """Obtener estadísticas detalladas de seguridad."""
        tiempo_sesion = (datetime.now() - self._metricas_seguridad['sesion_iniciada']).total_seconds()
        
        return {
            'tiempo_sesion_segundos': tiempo_sesion,
            'total_alertas': len(self._metricas_seguridad['alertas_seguridad']),
            'ips_consultadas': len(self._metricas_seguridad['ips_consultadas']),
            'dominios_consultados': len(self._metricas_seguridad['dominios_consultados']),
            'comandos_bloqueados': self._metricas_seguridad['comandos_bloqueados'],
            'cache_hits': self._cache_resultados['metadatos']['hits'],
            'cache_misses': self._cache_resultados['metadatos']['misses'],
            'cache_size': len(self._cache_resultados['escaneos']),
            'operaciones_ultimo_minuto': len(self._metricas_seguridad['operaciones_por_minuto'])
        }

    def limpiar_sesion_segura(self):
        """Limpiar sesión de forma segura."""
        # Limpiar caché
        self._cache_resultados['escaneos'].clear()
        
        # Limpiar métricas sensibles
        self._metricas_seguridad['ips_consultadas'].clear()
        self._metricas_seguridad['dominios_consultados'].clear()
        self._metricas_seguridad['patrones_anomalos'].clear()
        
        # Mantener alertas para análisis posterior
        self.logger.info("Sesión limpiada de forma segura")

    def _limpiar_recursos(self):
        """Limpiar archivos temporales y recursos."""
        self.limpiar_sesion_segura()

    def __del__(self):
        """Destructor para limpieza automática."""
        try:
            self._limpiar_recursos()
        except Exception:
            pass  # No generar errores en el destructor
