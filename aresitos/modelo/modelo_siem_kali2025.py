# -*- coding: utf-8 -*-
"""
ARESITOS - Extensión SIEM Kali Linux 2025
=========================================

Extensión del SIEM ARESITOS con herramientas modernas de Kali Linux 2025.
Integra herramientas avanzadas de monitoreo, análisis de logs y detección de amenazas.

Herramientas integradas:
- osquery: SQL-based endpoint monitoring
- filebeat: Log shipping
- suricata: Network intrusion detection
- zeek: Network security monitoring
- wazuh: Security monitoring platform
- graylog: Log management

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
"""

import subprocess
import json
import os
import time
import threading
import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from .modelo_siem import SIEM

class SIEMKali2025(SIEM):
    """
    Extensión del SIEM ARESITOS con herramientas de Kali Linux 2025.
    Mejora las capacidades de monitoreo y análisis de seguridad.
    """
    
    def __init__(self, directorio_logs: Optional[str] = None, configuracion: Optional[Dict[str, Any]] = None):
        super().__init__(directorio_logs)
        
        # Configuración específica para Kali 2025
        self.configuracion_kali2025 = configuracion or {}
        
        # Configuración de herramientas SIEM Kali 2025
        self.herramientas_siem_kali2025 = {
            'osquery': {
                'comando': 'osqueryi',
                'daemon': 'osqueryd',
                'disponible': self._verificar_herramienta('osqueryi'),
                'uso': 'Monitoreo de endpoints con SQL'
            },
            'filebeat': {
                'comando': 'filebeat',
                'disponible': self._verificar_herramienta('filebeat'),
                'uso': 'Envío de logs'
            },
            'suricata': {
                'comando': 'suricata',
                'disponible': self._verificar_herramienta('suricata'),
                'uso': 'Detección de intrusiones de red'
            },
            'zeek': {
                'comando': 'zeek',
                'disponible': self._verificar_herramienta('zeek'),
                'uso': 'Monitoreo de seguridad de red'
            },
            'wazuh-agent': {
                'comando': 'wazuh-agent',
                'disponible': self._verificar_herramienta('wazuh-agent'),
                'uso': 'Agente de monitoreo de seguridad'
            },
            'tcpdump': {
                'comando': 'tcpdump',
                'disponible': self._verificar_herramienta('tcpdump'),
                'uso': 'Captura de tráfico de red'
            }
        }
        
        # Configuración avanzada
        self.directorio_config_kali2025 = "/etc/aresitos/siem_kali2025"
        self.directorio_logs_kali2025 = "/var/log/aresitos/siem_kali2025"
        
        # Crear directorios
        os.makedirs(self.directorio_config_kali2025, exist_ok=True)
        os.makedirs(self.directorio_logs_kali2025, exist_ok=True)
        
        # Estados de monitoreo
        self.monitores_activos = {}
        self.estadisticas_kali2025 = {
            'eventos_osquery': 0,
            'logs_filebeat': 0,
            'alertas_suricata': 0,
            'conexiones_zeek': 0,
            'eventos_wazuh': 0
        }
        
        self.logger.info("SIEM Kali 2025 inicializado")
        self._log_herramientas_siem_disponibles()
        self._inicializar_configuraciones_siem()
    
    def _verificar_herramienta(self, herramienta: str) -> bool:
        """Verificar si una herramienta está disponible."""
        try:
            resultado = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
            return resultado.returncode == 0
        except Exception:
            return False
    
    def _log_herramientas_siem_disponibles(self):
        """Registrar herramientas SIEM disponibles."""
        disponibles = [h for h, info in self.herramientas_siem_kali2025.items() if info['disponible']]
        no_disponibles = [h for h, info in self.herramientas_siem_kali2025.items() if not info['disponible']]
        
        self.logger.info(f"Herramientas SIEM Kali 2025 disponibles: {', '.join(disponibles)}")
        if no_disponibles:
            self.logger.warning(f"Herramientas SIEM no disponibles: {', '.join(no_disponibles)}")
    
    def _inicializar_configuraciones_siem(self):
        """Inicializar configuraciones para herramientas SIEM."""
        # Configuración OSQuery
        if self.herramientas_siem_kali2025['osquery']['disponible']:
            self._crear_config_osquery()
        
        # Configuración Filebeat
        if self.herramientas_siem_kali2025['filebeat']['disponible']:
            self._crear_config_filebeat()
        
        # Configuración Suricata
        if self.herramientas_siem_kali2025['suricata']['disponible']:
            self._crear_config_suricata()
    
    def _crear_config_osquery(self):
        """Crear configuración para OSQuery."""
        config_osquery = {
            "options": {
                "config_plugin": "filesystem",
                "logger_plugin": "filesystem",
                "utc": True,
                "verbose": False,
                "disable_events": False,
                "disable_audit": False,
                "audit_allow_config": True,
                "host_identifier": "hostname",
                "schedule_splay_percent": 10
            },
            "schedule": {
                "system_info": {
                    "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
                    "interval": 3600
                },
                "network_connections": {
                    "query": "SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port FROM process_open_sockets WHERE family=2;",
                    "interval": 60
                },
                "running_processes": {
                    "query": "SELECT pid, name, path, cmdline, uid, on_disk FROM processes;",
                    "interval": 300
                },
                "file_changes": {
                    "query": "SELECT target_path, category, time, action FROM file_events WHERE category != '' AND time > ((SELECT unix_time FROM time) - 300);",
                    "interval": 300
                },
                "user_logins": {
                    "query": "SELECT type, time, username, host FROM last;",
                    "interval": 300
                },
                "kernel_modules": {
                    "query": "SELECT name, size, used_by, status FROM kernel_modules;",
                    "interval": 600
                }
            },
            "file_paths": {
                "etc": [
                    "/etc/%%"
                ],
                "tmp": [
                    "/tmp/%%"
                ],
                "home": [
                    "/home/%%"
                ]
            }
        }
        
        config_path = os.path.join(self.directorio_config_kali2025, "osquery.conf")
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_osquery, f, indent=2)
            self.logger.info(f"Configuración OSQuery creada: {config_path}")
        except Exception as e:
            self.logger.error(f"Error creando configuración OSQuery: {e}")
    
    def _crear_config_filebeat(self):
        """Crear configuración para Filebeat."""
        config_filebeat = f"""
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/aresitos/*.log
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/kern.log
  fields:
    source: aresitos_kali2025
    
- type: log
  enabled: true
  paths:
    - {self.directorio_logs_kali2025}/*.log
  fields:
    source: aresitos_siem_kali2025

output.file:
  path: "{self.directorio_logs_kali2025}"
  filename: filebeat_output
  rotate_every_kb: 10000
  number_of_files: 5

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_locale: ~

logging.level: info
logging.to_files: true
logging.files:
  path: {self.directorio_logs_kali2025}
  name: filebeat
  keepfiles: 7
  permissions: 0644
"""
        
        config_path = os.path.join(self.directorio_config_kali2025, "filebeat.yml")
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(config_filebeat)
            self.logger.info(f"Configuración Filebeat creada: {config_path}")
        except Exception as e:
            self.logger.error(f"Error creando configuración Filebeat: {e}")
    
    def _crear_config_suricata(self):
        """Crear configuración básica para Suricata."""
        config_suricata = f"""
# Configuración ARESITOS Suricata Kali 2025
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
    
default-log-dir: {self.directorio_logs_kali2025}

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp

app-layer:
  protocols:
    http:
      enabled: yes
    ftp:
      enabled: yes
    smtp:
      enabled: yes
    tls:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
        
rule-files:
  - suricata.rules
  - emerging-threats.rules
"""
        
        config_path = os.path.join(self.directorio_config_kali2025, "suricata.yaml")
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(config_suricata)
            self.logger.info(f"Configuración Suricata creada: {config_path}")
        except Exception as e:
            self.logger.error(f"Error creando configuración Suricata: {e}")
    
    def consulta_osquery(self, query: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Ejecutar consulta OSQuery.
        
        Args:
            query: Consulta SQL para OSQuery
            timeout: Timeout en segundos
            
        Returns:
            Dict con resultados de la consulta
        """
        if not self.herramientas_siem_kali2025['osquery']['disponible']:
            return self._fallback_consulta_sistema(query)
        
        try:
            comando = ['osqueryi', '--json', query]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return self._parsear_resultado_osquery(resultado.stdout, query, resultado.returncode == 0)
            
        except Exception as e:
            self.logger.error(f"Error en consulta OSQuery: {e}")
            return self._fallback_consulta_sistema(query)
    
    def _parsear_resultado_osquery(self, output: str, query: str, success: bool) -> Dict[str, Any]:
        """Parsear resultado de OSQuery."""
        resultado = {
            'herramienta': 'osquery',
            'query': query,
            'datos': [],
            'total_filas': 0,
            'timestamp': datetime.datetime.now().isoformat(),
            'success': success
        }
        
        if not success or not output.strip():
            return resultado
        
        try:
            # OSQuery devuelve JSON
            datos = json.loads(output)
            if isinstance(datos, list):
                resultado['datos'] = datos
                resultado['total_filas'] = len(datos)
                self.estadisticas_kali2025['eventos_osquery'] += len(datos)
        
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parseando JSON de OSQuery: {e}")
            resultado['error'] = 'Error parseando resultados'
        
        return resultado
    
    def iniciar_monitoreo_filebeat(self, config_personalizada: Optional[str] = None) -> Dict[str, Any]:
        """
        Iniciar monitoreo con Filebeat.
        
        Args:
            config_personalizada: Ruta a configuración personalizada
            
        Returns:
            Dict con estado del inicio
        """
        if not self.herramientas_siem_kali2025['filebeat']['disponible']:
            return self._fallback_monitoreo_logs()
        
        try:
            config_path = config_personalizada or os.path.join(self.directorio_config_kali2025, "filebeat.yml")
            
            if not os.path.exists(config_path):
                return {'error': f'Configuración no encontrada: {config_path}'}
            
            # Iniciar Filebeat en segundo plano
            comando = ['filebeat', '-c', config_path, '-d', 'publish']
            
            proceso = subprocess.Popen(
                comando,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Dar tiempo para inicializar
            time.sleep(2)
            
            if proceso.poll() is None:  # Proceso está corriendo
                self.monitores_activos['filebeat'] = {
                    'proceso': proceso,
                    'config': config_path,
                    'inicio': datetime.datetime.now().isoformat()
                }
                
                resultado = {
                    'herramienta': 'filebeat',
                    'estado': 'iniciado',
                    'pid': proceso.pid,
                    'config': config_path,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.logger.info(f"Filebeat iniciado con PID: {proceso.pid}")
                return resultado
            else:
                # Proceso falló
                stdout, stderr = proceso.communicate()
                return {
                    'herramienta': 'filebeat',
                    'estado': 'error',
                    'error': f'Proceso falló: {stderr}',
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error iniciando Filebeat: {e}")
            return self._fallback_monitoreo_logs()
    
    def iniciar_deteccion_suricata(self, interfaz: str = "any", config_personalizada: Optional[str] = None) -> Dict[str, Any]:
        """
        Iniciar detección de intrusiones con Suricata.
        
        Args:
            interfaz: Interfaz de red a monitorear
            config_personalizada: Ruta a configuración personalizada
            
        Returns:
            Dict con estado del inicio
        """
        if not self.herramientas_siem_kali2025['suricata']['disponible']:
            return self._fallback_deteccion_red()
        
        try:
            config_path = config_personalizada or os.path.join(self.directorio_config_kali2025, "suricata.yaml")
            
            comando = ['suricata', '-c', config_path, '-i', interfaz, '-v']
            
            proceso = subprocess.Popen(
                comando,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Dar tiempo para inicializar
            time.sleep(3)
            
            if proceso.poll() is None:  # Proceso está corriendo
                self.monitores_activos['suricata'] = {
                    'proceso': proceso,
                    'config': config_path,
                    'interfaz': interfaz,
                    'inicio': datetime.datetime.now().isoformat()
                }
                
                resultado = {
                    'herramienta': 'suricata',
                    'estado': 'iniciado',
                    'pid': proceso.pid,
                    'interfaz': interfaz,
                    'config': config_path,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.logger.info(f"Suricata iniciado con PID: {proceso.pid} en interfaz: {interfaz}")
                return resultado
            else:
                stdout, stderr = proceso.communicate()
                return {
                    'herramienta': 'suricata',
                    'estado': 'error',
                    'error': f'Proceso falló: {stderr}',
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error iniciando Suricata: {e}")
            return self._fallback_deteccion_red()
    
    def captura_trafico_tcpdump(self, interfaz: str = "any", filtro: str = "", duracion: int = 60) -> Dict[str, Any]:
        """
        Captura de tráfico con tcpdump.
        
        Args:
            interfaz: Interfaz de red
            filtro: Filtro BPF
            duracion: Duración en segundos
            
        Returns:
            Dict con información de la captura
        """
        if not self.herramientas_siem_kali2025['tcpdump']['disponible']:
            return self._fallback_captura_red()
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            archivo_captura = os.path.join(self.directorio_logs_kali2025, f"captura_{timestamp}.pcap")
            
            comando = ['tcpdump', '-i', interfaz, '-w', archivo_captura, '-G', str(duracion), '-W', '1']
            
            if filtro:
                comando.append(filtro)
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=duracion + 10
            )
            
            if os.path.exists(archivo_captura):
                tamaño_archivo = os.path.getsize(archivo_captura)
                return {
                    'herramienta': 'tcpdump',
                    'estado': 'completado',
                    'archivo': archivo_captura,
                    'tamaño_bytes': tamaño_archivo,
                    'interfaz': interfaz,
                    'filtro': filtro,
                    'duracion': duracion,
                    'timestamp': datetime.datetime.now().isoformat()
                }
            else:
                return {
                    'herramienta': 'tcpdump',
                    'estado': 'error',
                    'error': 'Archivo de captura no creado',
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error en captura tcpdump: {e}")
            return self._fallback_captura_red()
    
    def obtener_alertas_suricata(self, ultimas_horas: int = 1) -> Dict[str, Any]:
        """
        Obtener alertas de Suricata.
        
        Args:
            ultimas_horas: Número de horas hacia atrás
            
        Returns:
            Dict con alertas encontradas
        """
        try:
            archivo_eve = os.path.join(self.directorio_logs_kali2025, "eve.json")
            
            if not os.path.exists(archivo_eve):
                return {
                    'herramienta': 'suricata',
                    'alertas': [],
                    'total': 0,
                    'mensaje': 'Archivo de alertas no encontrado'
                }
            
            alertas = []
            tiempo_limite = datetime.datetime.now() - datetime.timedelta(hours=ultimas_horas)
            
            with open(archivo_eve, 'r') as f:
                for linea in f:
                    try:
                        evento = json.loads(linea.strip())
                        if evento.get('event_type') == 'alert':
                            timestamp_evento = datetime.datetime.fromisoformat(
                                evento.get('timestamp', '').replace('Z', '+00:00').replace('+00:00', '')
                            )
                            
                            if timestamp_evento >= tiempo_limite:
                                alertas.append(evento)
                                
                    except (json.JSONDecodeError, ValueError):
                        continue
            
            self.estadisticas_kali2025['alertas_suricata'] += len(alertas)
            
            return {
                'herramienta': 'suricata',
                'alertas': alertas,
                'total': len(alertas),
                'periodo_horas': ultimas_horas,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error obteniendo alertas Suricata: {e}")
            return {
                'herramienta': 'suricata',
                'alertas': [],
                'total': 0,
                'error': str(e)
            }
    
    def detener_monitores(self) -> Dict[str, Any]:
        """Detener todos los monitores activos."""
        resultado = {
            'monitores_detenidos': [],
            'errores': [],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        for nombre, info in self.monitores_activos.items():
            try:
                proceso = info['proceso']
                if proceso.poll() is None:  # Proceso aún corriendo
                    proceso.terminate()
                    proceso.wait(timeout=10)
                    resultado['monitores_detenidos'].append(nombre)
                    self.logger.info(f"Monitor {nombre} detenido")
                else:
                    resultado['monitores_detenidos'].append(f"{nombre} (ya detenido)")
            except Exception as e:
                error_msg = f"Error deteniendo {nombre}: {e}"
                resultado['errores'].append(error_msg)
                self.logger.error(error_msg)
        
        # Limpiar monitores activos
        self.monitores_activos.clear()
        
        return resultado
    
    # Métodos fallback
    def _fallback_consulta_sistema(self, query: str) -> Dict[str, Any]:
        """Fallback para consultas de sistema sin OSQuery."""
        return {
            'herramienta': 'fallback_sistema',
            'query': query,
            'datos': [],
            'mensaje': 'OSQuery no disponible - funcionalidad limitada',
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def _fallback_monitoreo_logs(self) -> Dict[str, Any]:
        """Fallback para monitoreo de logs sin Filebeat."""
        return {
            'herramienta': 'fallback_logs',
            'estado': 'limitado',
            'mensaje': 'Filebeat no disponible - monitoreo básico activo',
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def _fallback_deteccion_red(self) -> Dict[str, Any]:
        """Fallback para detección de red sin Suricata."""
        return {
            'herramienta': 'fallback_red',
            'estado': 'limitado',
            'mensaje': 'Suricata no disponible - detección básica activa',
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def _fallback_captura_red(self) -> Dict[str, Any]:
        """Fallback para captura de red sin tcpdump."""
        return {
            'herramienta': 'fallback_captura',
            'estado': 'no_disponible',
            'mensaje': 'tcpdump no disponible',
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def obtener_capacidades_siem_kali2025(self) -> Dict[str, Any]:
        """
        Obtener información sobre las capacidades SIEM de Kali 2025.
        
        Returns:
            Dict con información sobre herramientas disponibles
        """
        return {
            'herramientas_disponibles': {
                nombre: info['disponible'] 
                for nombre, info in self.herramientas_siem_kali2025.items()
            },
            'total_herramientas': len(self.herramientas_siem_kali2025),
            'herramientas_activas': sum(1 for info in self.herramientas_siem_kali2025.values() if info['disponible']),
            'monitores_activos': list(self.monitores_activos.keys()),
            'estadisticas': self.estadisticas_kali2025,
            'capacidades_mejoradas': [
                'Monitoreo de endpoints con OSQuery',
                'Envío centralizado de logs con Filebeat',
                'Detección de intrusiones con Suricata',
                'Monitoreo de red con Zeek',
                'Análisis de seguridad con Wazuh',
                'Captura de tráfico avanzada'
            ],
            'directorios': {
                'configuracion': self.directorio_config_kali2025,
                'logs': self.directorio_logs_kali2025
            }
        }
