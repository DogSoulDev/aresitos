#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM AVANZADO ARES AEGIS - VERSIÓN NATIVA LINUX
===============================================

Sistema de Información y Gestión de Eventos de Seguridad
que usa ÚNICAMENTE herramientas nativas de Linux y Python estándar.

FUNCIONALIDADES IMPLEMENTADAS:
-  Gestión de eventos de seguridad
-  Análisis de logs del sistema
-  Correlación básica de eventos
-  Alertas y notificaciones
-  Solo Python estándar + comandos Linux

Autor: Ares Aegis Security Suite
Fecha: 2025-08-17
"""

import json
import datetime
import os
import logging
import threading
import time
import hashlib
import uuid
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set
from pathlib import Path

class TipoEvento(Enum):
    """Tipos de eventos SIEM."""
    AUTENTICACION = "AUTENTICACION"
    ACCESO_ARCHIVO = "ACCESO_ARCHIVO"
    CONEXION_RED = "CONEXION_RED"
    PROCESO = "PROCESO"
    VULNERABILIDAD = "VULNERABILIDAD"
    SISTEMA_INICIADO = "SISTEMA_INICIADO"
    SISTEMA_DETENIDO = "SISTEMA_DETENIDO"
    ALERTAS = "ALERTAS"
    AUDITORIA = "AUDITORIA"
    SEGURIDAD = "SEGURIDAD"

class SeveridadEvento(Enum):
    """Niveles de severidad."""
    CRITICA = "CRITICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"
    INFO = "INFO"

@dataclass
class EventoSIEM:
    """Representa un evento SIEM completo."""
    id: str
    timestamp: datetime.datetime
    tipo: TipoEvento
    severidad: SeveridadEvento
    origen: str
    mensaje: str
    detalles: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    procesado: bool = False

@dataclass
class Alerta:
    """Alerta generada por el SIEM."""
    id: str
    timestamp: datetime.datetime
    titulo: str
    descripcion: str
    severidad: SeveridadEvento
    eventos_relacionados: List[str] = field(default_factory=list)
    estado: str = "nueva"

class SIEMAvanzadoNativo:
    """
    SIEM Avanzado que usa herramientas nativas de Linux.
    Diseñado específicamente para Kali Linux con máxima compatibilidad.
    """
    
    def __init__(self, directorio_logs: Optional[str] = None):
        self.logger = logging.getLogger("aresitos.modelo.siem_avanzado")
        
        # Directorio de logs
        if directorio_logs:
            self.directorio_logs = directorio_logs
        else:
            self.directorio_logs = self._crear_directorio_logs()
        
        # Buffer de eventos para correlación
        self.buffer_eventos = deque(maxlen=10000)
        self.eventos_por_tipo = defaultdict(deque)
        
        # Alertas activas
        self.alertas_activas = {}
        
        # Métricas
        self.metricas = {
            'eventos_procesados': 0,
            'alertas_generadas': 0,
            'correlaciones_encontradas': 0,
            'eventos_por_severidad': defaultdict(int),
            'eventos_por_tipo': defaultdict(int)
        }
        
        # Thread para procesamiento en background
        self._procesando = False
        self._thread_procesamiento = None
        
        # Lock para thread safety
        self._lock = threading.RLock()
        
        # Reglas de análisis de logs
        self.reglas_logs = self._cargar_reglas_logs()
        
        # Archivos de log del sistema a monitorear
        self.archivos_sistema = self._obtener_archivos_sistema()
        
        self.logger.info(" SIEM Avanzado Nativo Ares Aegis inicializado")
        self.logger.info(f"Directorio de logs: {self.directorio_logs}")

    def _crear_directorio_logs(self) -> str:
        """Crear directorio para logs."""
        directorio = os.path.join(os.path.expanduser("~"), "aresitos", "logs")
        try:
            os.makedirs(directorio, exist_ok=True)
            return directorio
        except Exception as e:
            self.logger.warning(f"Error creando directorio logs: {e}")
            import tempfile
            directorio = os.path.join(tempfile.gettempdir(), "ares_siem_logs")
            os.makedirs(directorio, exist_ok=True)
            return directorio

    def _cargar_reglas_logs(self) -> Dict[str, Dict[str, Any]]:
        """Cargar reglas para análisis de logs del sistema."""
        return {
            'ssh_failure': {
                'nombre': 'Fallos de autenticación SSH',
                'patrones': ['Failed password', 'authentication failure', 'Invalid user'],
                'severidad': SeveridadEvento.ALTA,
                'tipo': TipoEvento.AUTENTICACION,
                'archivos': ['/var/log/auth.log', '/var/log/secure']
            },
            'sudo_usage': {
                'nombre': 'Uso de sudo',
                'patrones': ['sudo:', 'COMMAND='],
                'severidad': SeveridadEvento.MEDIA,
                'tipo': TipoEvento.AUDITORIA,
                'archivos': ['/var/log/auth.log', '/var/log/secure']
            },
            'system_error': {
                'nombre': 'Errores del sistema',
                'patrones': ['ERROR', 'CRITICAL', 'FATAL', 'segfault'],
                'severidad': SeveridadEvento.ALTA,
                'tipo': TipoEvento.SISTEMA_INICIADO,
                'archivos': ['/var/log/syslog', '/var/log/messages']
            },
            'network_anomaly': {
                'nombre': 'Anomalías de red',
                'patrones': ['connection refused', 'port scan', 'flood'],
                'severidad': SeveridadEvento.MEDIA,
                'tipo': TipoEvento.CONEXION_RED,
                'archivos': ['/var/log/syslog', '/var/log/kern.log']
            },
            'file_access': {
                'nombre': 'Acceso a archivos sensibles',
                'patrones': ['/etc/passwd', '/etc/shadow', '/etc/sudoers'],
                'severidad': SeveridadEvento.ALTA,
                'tipo': TipoEvento.ACCESO_ARCHIVO,
                'archivos': ['/var/log/audit/audit.log', '/var/log/syslog']
            }
        }

    def _obtener_archivos_sistema(self) -> List[str]:
        """Obtener lista de archivos de log del sistema disponibles."""
        archivos_candidatos = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/secure',
            '/var/log/kern.log',
            '/var/log/audit/audit.log'
        ]
        
        archivos_disponibles = []
        for archivo in archivos_candidatos:
            if os.path.exists(archivo) and os.access(archivo, os.R_OK):
                archivos_disponibles.append(archivo)
        
        self.logger.info(f"Archivos de log disponibles: {len(archivos_disponibles)}")
        return archivos_disponibles

    def iniciar_procesamiento(self):
        """Iniciar procesamiento en background."""
        with self._lock:
            if not self._procesando:
                self._procesando = True
                self._thread_procesamiento = threading.Thread(
                    target=self._loop_procesamiento,
                    daemon=True
                )
                self._thread_procesamiento.start()
                self.logger.info(" Procesamiento SIEM iniciado")

    def detener_procesamiento(self):
        """Detener procesamiento en background."""
        with self._lock:
            self._procesando = False
            if self._thread_procesamiento:
                self._thread_procesamiento.join(timeout=5)
                self.logger.info(" Procesamiento SIEM detenido")

    def registrar_evento(self, tipo: str, mensaje: str, detalles: Optional[Dict[str, Any]] = None, 
                        severidad: str = "INFO", origen: str = "sistema", tags: Optional[Set[str]] = None) -> str:
        """Registrar un nuevo evento en el SIEM."""
        
        # Convertir strings a enums
        try:
            tipo_enum = TipoEvento(tipo.upper()) if hasattr(TipoEvento, tipo.upper()) else TipoEvento.SISTEMA_INICIADO
            severidad_enum = SeveridadEvento(severidad.upper()) if hasattr(SeveridadEvento, severidad.upper()) else SeveridadEvento.INFO
        except (ValueError, TypeError, AttributeError):
            tipo_enum = TipoEvento.SISTEMA_INICIADO
            severidad_enum = SeveridadEvento.INFO
        
        evento = EventoSIEM(
            id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(),
            tipo=tipo_enum,
            severidad=severidad_enum,
            origen=origen,
            mensaje=mensaje,
            detalles=detalles or {},
            tags=tags or set()
        )
        
        # Agregar al buffer
        with self._lock:
            self.buffer_eventos.append(evento)
            self.eventos_por_tipo[tipo_enum].append(evento)
            
            # Actualizar métricas
            self.metricas['eventos_procesados'] += 1
            self.metricas['eventos_por_severidad'][severidad_enum.value] += 1
            self.metricas['eventos_por_tipo'][tipo_enum.value] += 1
        
        # Persistir evento
        self._persistir_evento(evento)
        
        # Verificar correlaciones
        self._verificar_correlaciones_simples(evento)
        
        return evento.id

    def _persistir_evento(self, evento: EventoSIEM):
        """Persistir evento en archivo JSON."""
        try:
            fecha_actual = evento.timestamp.strftime('%Y-%m-%d')
            archivo_log = os.path.join(self.directorio_logs, f"siem_eventos_{fecha_actual}.json")
            
            # Preparar datos del evento
            evento_data = {
                'id': evento.id,
                'timestamp': evento.timestamp.isoformat(),
                'tipo': evento.tipo.value,
                'severidad': evento.severidad.value,
                'origen': evento.origen,
                'mensaje': evento.mensaje,
                'detalles': evento.detalles,
                'tags': list(evento.tags),
                'procesado': evento.procesado
            }
            
            # Leer eventos existentes
            eventos_existentes = []
            if os.path.exists(archivo_log):
                try:
                    with open(archivo_log, 'r', encoding='utf-8') as f:
                        eventos_existentes = json.load(f)
                except (IOError, OSError, PermissionError, FileNotFoundError):
                    eventos_existentes = []
            
            # Agregar nuevo evento
            eventos_existentes.append(evento_data)
            
            # Mantener solo los últimos 1000 eventos por día
            if len(eventos_existentes) > 1000:
                eventos_existentes = eventos_existentes[-1000:]
            
            # Guardar eventos actualizados
            with open(archivo_log, 'w', encoding='utf-8') as f:
                json.dump(eventos_existentes, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"Error persistiendo evento: {e}")

    def _loop_procesamiento(self):
        """Loop principal de procesamiento en background."""
        while self._procesando:
            try:
                # Analizar logs del sistema
                self._analizar_logs_sistema()
                
                # Limpiar eventos antiguos del buffer
                self._limpiar_buffer()
                
                # Verificar alertas
                self._verificar_alertas()
                
                time.sleep(30)  # Procesar cada 30 segundos
                
            except Exception as e:
                self.logger.error(f"Error en loop de procesamiento: {e}")
                time.sleep(60)

    def _analizar_logs_sistema(self):
        """Analizar logs del sistema buscando patrones sospechosos."""
        for regla_id, regla in self.reglas_logs.items():
            for archivo_log in regla['archivos']:
                if archivo_log in self.archivos_sistema:
                    self._procesar_archivo_log(archivo_log, regla_id, regla)

    def _procesar_archivo_log(self, archivo_log: str, regla_id: str, regla: Dict[str, Any]):
        """Procesar un archivo de log específico."""
        try:
            # Usar tail para obtener las últimas líneas
            cmd = ['tail', '-n', '100', archivo_log]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')
                
                for linea in lineas:
                    if linea.strip():
                        # Verificar patrones
                        for patron in regla['patrones']:
                            if patron.lower() in linea.lower():
                                self._generar_evento_desde_log(linea, regla_id, regla, archivo_log)
                                break
                                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout procesando {archivo_log}")
        except Exception as e:
            self.logger.warning(f"Error procesando {archivo_log}: {e}")

    def _generar_evento_desde_log(self, linea: str, regla_id: str, regla: Dict[str, Any], archivo: str):
        """Generar evento SIEM desde línea de log."""
        # Evitar duplicados verificando si ya procesamos esta línea recientemente
        hash_linea = hashlib.sha256(linea.encode()).hexdigest()
        
        # Verificar si ya procesamos esta línea en los últimos 5 minutos
        tiempo_limite = datetime.datetime.now() - datetime.timedelta(minutes=5)
        with self._lock:
            for evento in reversed(list(self.buffer_eventos)):
                if evento.timestamp < tiempo_limite:
                    break
                if evento.detalles.get('hash_linea') == hash_linea:
                    return  # Ya procesado
        
        # Generar evento
        evento_id = self.registrar_evento(
            tipo=regla['tipo'].value,
            mensaje=f"{regla['nombre']}: {linea.strip()[:200]}",
            severidad=regla['severidad'].value,
            origen=archivo,
            detalles={
                'regla_id': regla_id,
                'archivo_log': archivo,
                'linea_completa': linea.strip(),
                'hash_linea': hash_linea
            },
            tags={regla_id, 'auto_detectado'}
        )

    def _verificar_correlaciones_simples(self, evento: EventoSIEM):
        """Verificar correlaciones simples entre eventos."""
        try:
            # Buscar eventos similares en los últimos 5 minutos
            tiempo_limite = evento.timestamp - datetime.timedelta(minutes=5)
            eventos_similares = []
            
            with self._lock:
                for evento_buffer in self.buffer_eventos:
                    if (evento_buffer.timestamp >= tiempo_limite and
                        evento_buffer.tipo == evento.tipo and
                        evento_buffer.id != evento.id):
                        eventos_similares.append(evento_buffer)
            
            # Si hay muchos eventos similares, generar alerta
            if len(eventos_similares) >= 5:
                self._generar_alerta_correlacion(evento, eventos_similares)
                
        except Exception as e:
            self.logger.error(f"Error verificando correlaciones: {e}")

    def _generar_alerta_correlacion(self, evento_trigger: EventoSIEM, eventos_relacionados: List[EventoSIEM]):
        """Generar alerta por correlación de eventos."""
        alerta_id = str(uuid.uuid4())
        
        alerta = Alerta(
            id=alerta_id,
            timestamp=datetime.datetime.now(),
            titulo=f"Correlación detectada: {evento_trigger.tipo.value}",
            descripcion=f"Se detectaron {len(eventos_relacionados) + 1} eventos similares de tipo {evento_trigger.tipo.value} en los últimos 5 minutos.",
            severidad=SeveridadEvento.ALTA,
            eventos_relacionados=[e.id for e in eventos_relacionados] + [evento_trigger.id]
        )
        
        with self._lock:
            self.alertas_activas[alerta_id] = alerta
            self.metricas['alertas_generadas'] += 1
            self.metricas['correlaciones_encontradas'] += 1
        
        # Persistir alerta
        self._persistir_alerta(alerta)
        
        self.logger.warning(f"✓  ALERTA CORRELACIÓN: {alerta.titulo} - {len(eventos_relacionados) + 1} eventos")

    def _persistir_alerta(self, alerta: Alerta):
        """Persistir alerta en archivo JSON."""
        try:
            fecha_actual = alerta.timestamp.strftime('%Y-%m-%d')
            archivo_alertas = os.path.join(self.directorio_logs, f"siem_alertas_{fecha_actual}.json")
            
            # Preparar datos de la alerta
            alerta_data = {
                'id': alerta.id,
                'timestamp': alerta.timestamp.isoformat(),
                'titulo': alerta.titulo,
                'descripcion': alerta.descripcion,
                'severidad': alerta.severidad.value,
                'eventos_relacionados': alerta.eventos_relacionados,
                'estado': alerta.estado
            }
            
            # Leer alertas existentes
            alertas_existentes = []
            if os.path.exists(archivo_alertas):
                try:
                    with open(archivo_alertas, 'r', encoding='utf-8') as f:
                        alertas_existentes = json.load(f)
                except (IOError, OSError, PermissionError, FileNotFoundError):
                    alertas_existentes = []
            
            # Agregar nueva alerta
            alertas_existentes.append(alerta_data)
            
            # Guardar alertas actualizadas
            with open(archivo_alertas, 'w', encoding='utf-8') as f:
                json.dump(alertas_existentes, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"Error persistiendo alerta: {e}")

    def _limpiar_buffer(self):
        """Limpiar eventos antiguos del buffer."""
        with self._lock:
            limite_tiempo = datetime.datetime.now() - datetime.timedelta(hours=1)
            
            # Limpiar buffer principal
            while (self.buffer_eventos and 
                   self.buffer_eventos[0].timestamp < limite_tiempo):
                self.buffer_eventos.popleft()
            
            # Limpiar buffers por tipo
            for tipo, buffer in self.eventos_por_tipo.items():
                while buffer and buffer[0].timestamp < limite_tiempo:
                    buffer.popleft()

    def _verificar_alertas(self):
        """Verificar estado de alertas activas."""
        # Implementación básica - marcar alertas antiguas como procesadas
        tiempo_limite = datetime.datetime.now() - datetime.timedelta(hours=24)
        alertas_a_remover = []
        
        with self._lock:
            for alerta_id, alerta in self.alertas_activas.items():
                if alerta.timestamp < tiempo_limite:
                    alertas_a_remover.append(alerta_id)
            
            for alerta_id in alertas_a_remover:
                del self.alertas_activas[alerta_id]

    def obtener_eventos(self, limite: int = 100, filtro_tipo: Optional[str] = None, 
                       filtro_severidad: Optional[str] = None,
                       desde: Optional[datetime.datetime] = None) -> List[Dict[str, Any]]:
        """Obtener eventos del SIEM con filtros."""
        try:
            eventos = []
            
            # Buscar en archivos de eventos
            fecha_actual = datetime.datetime.now().strftime('%Y-%m-%d')
            archivo_log = os.path.join(self.directorio_logs, f"siem_eventos_{fecha_actual}.json")
            
            if os.path.exists(archivo_log):
                with open(archivo_log, 'r', encoding='utf-8') as f:
                    eventos_archivo = json.load(f)
                    
                    for evento_data in eventos_archivo:
                        # Aplicar filtros
                        if filtro_tipo and evento_data.get('tipo') != filtro_tipo.upper():
                            continue
                        if filtro_severidad and evento_data.get('severidad') != filtro_severidad.upper():
                            continue
                        if desde:
                            evento_timestamp = datetime.datetime.fromisoformat(evento_data['timestamp'])
                            if evento_timestamp < desde:
                                continue
                        
                        eventos.append(evento_data)
            
            # Ordenar por timestamp descendente y limitar
            eventos.sort(key=lambda x: x['timestamp'], reverse=True)
            return eventos[:limite]
            
        except Exception as e:
            self.logger.error(f"Error obteniendo eventos: {e}")
            return []

    def obtener_alertas_activas(self) -> List[Dict[str, Any]]:
        """Obtener alertas activas."""
        with self._lock:
            alertas = []
            for alerta in self.alertas_activas.values():
                alertas.append({
                    'id': alerta.id,
                    'timestamp': alerta.timestamp.isoformat(),
                    'titulo': alerta.titulo,
                    'descripcion': alerta.descripcion,
                    'severidad': alerta.severidad.value,
                    'eventos_relacionados': len(alerta.eventos_relacionados),
                    'estado': alerta.estado
                })
            return alertas

    def obtener_metricas(self) -> Dict[str, Any]:
        """Obtener métricas del SIEM."""
        with self._lock:
            return {
                'eventos_procesados': self.metricas['eventos_procesados'],
                'alertas_generadas': self.metricas['alertas_generadas'],
                'correlaciones_encontradas': self.metricas['correlaciones_encontradas'],
                'alertas_activas': len(self.alertas_activas),
                'eventos_en_buffer': len(self.buffer_eventos),
                'archivos_monitoreados': len(self.archivos_sistema),
                'reglas_activas': len(self.reglas_logs),
                'eventos_por_severidad': dict(self.metricas['eventos_por_severidad']),
                'eventos_por_tipo': dict(self.metricas['eventos_por_tipo']),
                'timestamp': datetime.datetime.now().isoformat()
            }

    def generar_reporte_siem(self, periodo_horas: int = 24) -> str:
        """Generar reporte del SIEM."""
        desde = datetime.datetime.now() - datetime.timedelta(hours=periodo_horas)
        eventos = self.obtener_eventos(limite=1000, desde=desde)
        alertas = self.obtener_alertas_activas()
        metricas = self.obtener_metricas()
        
        reporte = f"""
#  REPORTE SIEM - ARES AEGIS

##  RESUMEN EJECUTIVO (Últimas {periodo_horas} horas)
- **Eventos Procesados**: {len(eventos)}
- **Alertas Activas**: {len(alertas)}
- **Correlaciones Encontradas**: {metricas['correlaciones_encontradas']}
- **Archivos Monitoreados**: {metricas['archivos_monitoreados']}

##  EVENTOS POR SEVERIDAD
"""
        
        eventos_por_severidad = defaultdict(int)
        for evento in eventos:
            eventos_por_severidad[evento.get('severidad', 'INFO')] += 1
        
        for severidad, cantidad in eventos_por_severidad.items():
            emoji = {"CRITICA": "", "ALTA": "", "MEDIA": "", "BAJA": "", "INFO": "✓"}
            reporte += f"- {emoji.get(severidad, '✓')} **{severidad}**: {cantidad}\n"
        
        reporte += f"\n## ✓ ALERTAS ACTIVAS ({len(alertas)})\n"
        
        for alerta in alertas[:10]:  # Primeras 10 alertas
            emoji = {"CRITICA": "", "ALTA": "", "MEDIA": "", "BAJA": "", "INFO": "✓"}
            severidad = alerta.get('severidad', 'INFO')
            titulo = alerta.get('titulo', 'Sin título')
            timestamp_str = alerta.get('timestamp', datetime.datetime.now().isoformat())
            reporte += f"{emoji.get(str(severidad), '✓')} **{titulo}**\n"
            timestamp = datetime.datetime.fromisoformat(timestamp_str)
            reporte += f"   {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            reporte += f"   {alerta.get('descripcion', 'Sin descripción')}\n\n"
        
        reporte += f"\n##  EVENTOS RECIENTES\n"
        
        for evento in eventos[:20]:  # Primeros 20 eventos
            emoji = {"CRITICA": "", "ALTA": "", "MEDIA": "", "BAJA": "", "INFO": "✓"}
            severidad = evento.get('severidad', 'INFO')
            tipo = evento.get('tipo', 'DESCONOCIDO')
            mensaje = evento.get('mensaje', '')
            timestamp_str = evento.get('timestamp', datetime.datetime.now().isoformat())
            timestamp = datetime.datetime.fromisoformat(timestamp_str)
            reporte += f"{emoji.get(str(severidad), '✓')} {timestamp.strftime('%H:%M:%S')} - {tipo}: {str(mensaje)[:100]}\n"
        
        reporte += f"\n---\n*Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return reporte


# Clase de compatibilidad
class SIEM(SIEMAvanzadoNativo):
    """Clase de compatibilidad con la interfaz original."""
    
    def __init__(self, directorio_logs: Optional[str] = None):
        super().__init__(directorio_logs)
        self.reglas_alertas = self._cargar_reglas_basicas()

    def _cargar_reglas_basicas(self) -> List[Dict[str, Any]]:
        """Cargar reglas básicas para compatibilidad."""
        return [
            {
                'id': 'ssh_failure',
                'nombre': 'Fallos de autenticación SSH',
                'patron': 'Failed password',
                'severidad': 'media',
                'archivo': '/var/log/auth.log'
            },
            {
                'id': 'sudo_usage',
                'nombre': 'Uso de sudo',
                'patron': 'sudo:',
                'severidad': 'baja',
                'archivo': '/var/log/auth.log'
            },
            {
                'id': 'system_error',
                'nombre': 'Errores del sistema',
                'patron': 'ERROR',
                'severidad': 'alta',
                'archivo': '/var/log/syslog'
            }
        ]

    def generar_evento(self, tipo: str, mensaje: str, severidad: str = 'info', 
                       origen: str = 'sistema') -> Dict[str, Any]:
        """Método de compatibilidad con la interfaz original."""
        try:
            evento_id = self.registrar_evento(
                tipo=tipo,
                mensaje=mensaje,
                severidad=severidad,
                origen=origen
            )
            
            return {
                'id': evento_id,
                'timestamp': datetime.datetime.now().isoformat(),
                'tipo': tipo,
                'mensaje': mensaje,
                'severidad': severidad,
                'origen': origen,
                'procesado': True
            }
            
        except Exception as e:
            self.logger.error(f"Error generando evento compatible: {e}")
            return {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.datetime.now().isoformat(),
                'tipo': tipo,
                'mensaje': mensaje,
                'severidad': severidad,
                'origen': origen,
                'error': str(e),
                'procesado': False
            }

    def obtener_eventos_recientes(self, limite: int = 100) -> List[Dict[str, Any]]:
        """Obtiene eventos recientes del SIEM."""
        return self.obtener_eventos(limite=limite)

    def analizar_logs_sistema(self) -> Dict[str, Any]:
        """Análisis básico de logs del sistema."""
        resultados = {
            'eventos_encontrados': 0,
            'alertas_generadas': 0,
            'archivos_analizados': [],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Forzar análisis inmediato de logs
        self._analizar_logs_sistema()
        
        # Obtener métricas actuales
        metricas = self.obtener_metricas()
        resultados['eventos_encontrados'] = metricas['eventos_procesados']
        resultados['alertas_generadas'] = metricas['alertas_generadas']
        resultados['archivos_analizados'] = [{'archivo': f, 'analizado': True} for f in self.archivos_sistema]
        
        return resultados

    def obtener_timestamp(self) -> str:
        """Obtiene timestamp actual en formato ISO."""
        return datetime.datetime.now().isoformat()

    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtiene estadísticas del SIEM."""
        return self.obtener_metricas()
