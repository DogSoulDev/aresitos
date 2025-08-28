
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
"""

import logging
import os
import json
import time
import sqlite3
import subprocess
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class SIEMBase:
    """
    Clase base para Security Information and Event Management (SIEM).
    Proporciona funcionalidad común para análisis de seguridad y gestión de eventos.
    """
    
    def __init__(self, gestor_permisos=None):
        """
        Inicializar SIEM base.
        
        Args:
            gestor_permisos: Gestor de permisos del sistema (opcional)
        """
        self.gestor_permisos = gestor_permisos
        self.logger = logging.getLogger(f"aresitos.{self.__class__.__name__}")
        
        # Configuración de base de datos
        self.db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem_kali2025.db')
        
        # Configuración básica
        self.configuracion = {
            'log_retention_days': 30,
            'alert_threshold': 10,
            'monitoring_interval': 60,  # segundos
            'max_events_per_hour': 1000,
            'enable_real_time': True,
            'log_sources': [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/kern.log',
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log'
            ]
        }
        
        # Estado interno
        self.eventos_cache = defaultdict(list)
        self.alertas_activas = []
        self.estadisticas = {
            'eventos_procesados': 0,
            'alertas_generadas': 0,
            'ultimo_analisis': None
        }
        
        # Inicializar base de datos
        self._inicializar_base_datos()
        
        self.logger.info(f"SIEM Base inicializado: {self.db_path}")
    
    def _inicializar_base_datos(self):
        """Crear tablas de base de datos si no existen."""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabla de eventos de seguridad
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    description TEXT,
                    ip_source TEXT,
                    user_involved TEXT,
                    raw_log TEXT,
                    processed BOOLEAN DEFAULT 0
                )
                ''')
                
                # Tabla de alertas
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    affected_resource TEXT,
                    status TEXT DEFAULT 'active',
                    resolved_time TIMESTAMP
                )
                ''')
                
                # Tabla de análisis de logs
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    log_source TEXT NOT NULL,
                    lines_processed INTEGER DEFAULT 0,
                    events_found INTEGER DEFAULT 0,
                    alerts_generated INTEGER DEFAULT 0,
                    analysis_duration REAL DEFAULT 0
                )
                ''')
                
                # Tabla de estadísticas por IP
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_events INTEGER DEFAULT 1,
                    failed_logins INTEGER DEFAULT 0,
                    successful_logins INTEGER DEFAULT 0,
                    blocked_count INTEGER DEFAULT 0,
                    threat_score INTEGER DEFAULT 0
                )
                ''')
                
                # Tabla de reglas de detección
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT UNIQUE NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    enabled BOOLEAN DEFAULT 1,
                    description TEXT,
                    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                conn.commit()
                self.logger.info("Base de datos SIEM inicializada correctamente")
                
        except Exception as e:
            self.logger.error(f"Error inicializando base de datos SIEM: {e}")
            raise
    
    def log(self, mensaje: str, nivel: str = 'info'):
        """
        Sistema de logging unificado.
        
        Args:
            mensaje: Mensaje a loggear
            nivel: Nivel de log (info, warning, error)
        """
        if nivel == 'warning':
            self.logger.warning(mensaje)
        elif nivel == 'error':
            self.logger.error(mensaje)
        else:
            self.logger.info(mensaje)
        
        print(f"[SIEM] {mensaje}")
    
    def procesar_evento_seguridad(self, evento: Dict[str, Any]) -> bool:
        """
        Procesar un evento de seguridad y almacenarlo.
        
        Args:
            evento: Diccionario con datos del evento
            
        Returns:
            True si se procesó correctamente
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                INSERT INTO security_events 
                (source, event_type, severity, description, ip_source, user_involved, raw_log)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    evento.get('source', 'unknown'),
                    evento.get('event_type', 'generic'),
                    evento.get('severity', 'medium'),
                    evento.get('description', ''),
                    evento.get('ip_source'),
                    evento.get('user_involved'),
                    evento.get('raw_log', '')
                ))
                
                conn.commit()
                self.estadisticas['eventos_procesados'] += 1
                
                # Verificar si genera alerta
                self._evaluar_alertas(evento)
                
                return True
                
        except Exception as e:
            self.log(f"Error procesando evento: {e}", 'error')
            return False
    
    def _evaluar_alertas(self, evento: Dict[str, Any]):
        """Evaluar si un evento debe generar una alerta."""
        # Reglas básicas de alertas
        alertas = []
        
        # Alerta por múltiples fallos de login
        if evento.get('event_type') == 'failed_login':
            ip = evento.get('ip_source')
            if ip:
                # Contar fallos recientes de esta IP
                recent_fails = self._contar_eventos_recientes(
                    'failed_login', ip, minutos=10
                )
                if recent_fails >= 5:
                    alertas.append({
                        'type': 'brute_force_attempt',
                        'severity': 'high',
                        'title': f'Intento de fuerza bruta detectado desde {ip}',
                        'description': f'{recent_fails} fallos de login en 10 minutos'
                    })
        
        # Alerta por acceso con privilegios elevados
        if evento.get('event_type') == 'privilege_escalation':
            alertas.append({
                'type': 'privilege_escalation',
                'severity': 'critical',
                'title': 'Escalada de privilegios detectada',
                'description': evento.get('description', '')
            })
        
        # Generar alertas
        for alerta in alertas:
            self._generar_alerta(alerta)
    
    def _contar_eventos_recientes(self, tipo_evento: str, ip: str, minutos: int = 10) -> int:
        """Contar eventos recientes de un tipo específico."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                tiempo_limite = datetime.now() - timedelta(minutes=minutos)
                
                cursor.execute('''
                SELECT COUNT(*) FROM security_events 
                WHERE event_type = ? AND ip_source = ? 
                AND timestamp >= ?
                ''', (tipo_evento, ip, tiempo_limite.isoformat()))
                
                return cursor.fetchone()[0]
                
        except Exception as e:
            self.log(f"Error contando eventos recientes: {e}", 'error')
            return 0
    
    def _generar_alerta(self, alerta: Dict[str, Any]):
        """Generar una nueva alerta de seguridad."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                INSERT INTO security_alerts 
                (alert_type, severity, title, description, affected_resource)
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    alerta['type'],
                    alerta['severity'],
                    alerta['title'],
                    alerta['description'],
                    alerta.get('affected_resource')
                ))
                
                conn.commit()
                self.estadisticas['alertas_generadas'] += 1
                
                self.log(f"ALERTA {alerta['severity'].upper()}: {alerta['title']}")
                
        except Exception as e:
            self.log(f"Error generando alerta: {e}", 'error')
    
    def analizar_logs_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        """
        Analizar un archivo de log específico.
        
        Args:
            ruta_archivo: Ruta al archivo de log
            
        Returns:
            Diccionario con resultado del análisis
        """
        resultado = {
            'exito': False,
            'archivo': ruta_archivo,
            'lineas_procesadas': 0,
            'eventos_encontrados': 0,
            'alertas_generadas': 0,
            'tiempo_analisis': 0
        }
        
        if not os.path.exists(ruta_archivo):
            resultado['error'] = 'Archivo no existe'
            return resultado
        
        tiempo_inicio = time.time()
        
        try:
            with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    resultado['lineas_procesadas'] += 1
                    
                    # Analizar línea en busca de eventos
                    eventos = self._parsear_linea_log(linea, ruta_archivo)
                    
                    for evento in eventos:
                        if self.procesar_evento_seguridad(evento):
                            resultado['eventos_encontrados'] += 1
            
            resultado['exito'] = True
            
        except Exception as e:
            resultado['error'] = str(e)
            self.log(f"Error analizando {ruta_archivo}: {e}", 'error')
        
        resultado['tiempo_analisis'] = round(time.time() - tiempo_inicio, 2)
        
        # Registrar análisis en BD
        self._registrar_analisis(ruta_archivo, resultado)
        
        return resultado
    
    def _parsear_linea_log(self, linea: str, fuente: str) -> List[Dict[str, Any]]:
        """Parsear una línea de log para extraer eventos."""
        eventos = []
        
        # Patrones básicos de seguridad
        patrones = {
            'failed_login': [
                r'Failed password for .+ from ([\d.]+)',
                r'authentication failure.*rhost=([\d.]+)',
                r'Invalid user .+ from ([\d.]+)'
            ],
            'successful_login': [
                r'Accepted password for (\w+) from ([\d.]+)',
                r'session opened for user (\w+)'
            ],
            'privilege_escalation': [
                r'sudo:.*COMMAND=',
                r'su:.*session opened'
            ],
            'network_anomaly': [
                r'iptables.*DROP',
                r'Connection refused',
                r'Port scan detected'
            ]
        }
        
        for tipo_evento, regexes in patrones.items():
            for regex in regexes:
                match = re.search(regex, linea, re.IGNORECASE)
                if match:
                    evento = {
                        'source': fuente,
                        'event_type': tipo_evento,
                        'description': linea.strip(),
                        'raw_log': linea,
                        'severity': self._determinar_severidad(tipo_evento)
                    }
                    
                    # Extraer IP si está disponible
                    if match.groups():
                        if tipo_evento in ['failed_login', 'successful_login']:
                            if len(match.groups()) >= 1 and match.group(1):
                                evento['ip_source'] = match.group(1)
                            if len(match.groups()) >= 2 and match.group(2):
                                evento['user_involved'] = match.group(2)
                        else:
                            if match.group(1):
                                evento['ip_source'] = match.group(1)
                    
                    eventos.append(evento)
                    break  # Solo un patrón por línea
        
        return eventos
    
    def _determinar_severidad(self, tipo_evento: str) -> str:
        """Determinar severidad basada en el tipo de evento."""
        severidades = {
            'failed_login': 'medium',
            'successful_login': 'low',
            'privilege_escalation': 'high',
            'network_anomaly': 'medium',
            'brute_force_attempt': 'high',
            'unauthorized_access': 'critical'
        }
        return severidades.get(tipo_evento, 'medium')
    
    def _registrar_analisis(self, fuente: str, resultado: Dict[str, Any]):
        """Registrar análisis de log en base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                INSERT INTO log_analysis 
                (log_source, lines_processed, events_found, analysis_duration)
                VALUES (?, ?, ?, ?)
                ''', (
                    fuente,
                    resultado['lineas_procesadas'],
                    resultado['eventos_encontrados'],
                    resultado['tiempo_analisis']
                ))
                
                conn.commit()
                
        except Exception as e:
            self.log(f"Error registrando análisis: {e}", 'error')
    
    def obtener_alertas_activas(self) -> List[Dict[str, Any]]:
        """
        Obtener alertas activas del sistema.
        
        Returns:
            Lista de alertas activas
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT alert_type, severity, title, description, 
                       affected_resource, alert_time
                FROM security_alerts 
                WHERE status = 'active'
                ORDER BY alert_time DESC
                LIMIT 50
                ''')
                
                alertas = []
                for row in cursor.fetchall():
                    alertas.append({
                        'type': row[0],
                        'severity': row[1],
                        'title': row[2],
                        'description': row[3],
                        'affected_resource': row[4],
                        'alert_time': row[5]
                    })
                
                return alertas
                
        except Exception as e:
            self.log(f"Error obteniendo alertas: {e}", 'error')
            return []
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtener estadísticas del sistema SIEM.
        
        Returns:
            Diccionario con estadísticas
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Contar eventos por tipo
                cursor.execute('''
                SELECT event_type, COUNT(*) 
                FROM security_events 
                GROUP BY event_type
                ''')
                eventos_por_tipo = dict(cursor.fetchall())
                
                # Contar alertas por severidad
                cursor.execute('''
                SELECT severity, COUNT(*) 
                FROM security_alerts 
                WHERE status = 'active'
                GROUP BY severity
                ''')
                alertas_por_severidad = dict(cursor.fetchall())
                
                # Estadísticas generales
                cursor.execute('SELECT COUNT(*) FROM security_events')
                total_eventos = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM security_alerts WHERE status = "active"')
                alertas_activas = cursor.fetchone()[0]
                
                return {
                    'total_eventos': total_eventos,
                    'alertas_activas': alertas_activas,
                    'eventos_por_tipo': eventos_por_tipo,
                    'alertas_por_severidad': alertas_por_severidad,
                    'configuracion': self.configuracion.copy(),
                    'estadisticas_internas': self.estadisticas.copy(),
                    'estado_base_datos': os.path.exists(self.db_path),
                    'fuentes_log_configuradas': len(self.configuracion['log_sources'])
                }
                
        except Exception as e:
            self.log(f"Error obteniendo estadísticas: {e}", 'error')
            return {
                'error': str(e),
                'estadisticas_internas': self.estadisticas.copy()
            }
