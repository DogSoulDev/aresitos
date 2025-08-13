# -*- coding: utf-8 -*-
"""
Ares Aegis - SIEM Avanzado
Sistema de Información y Gestión de Eventos de Seguridad
Integra funcionalidad avanzada del proyecto original con capacidades de correlación y análisis
"""

import json
import datetime
import os
import logging
import threading
import time
import hashlib
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Callable
from pathlib import Path
import sqlite3

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
    correlacion_id: Optional[str] = None
    procesado: bool = False

@dataclass
class ReglaCorrelacion:
    """Regla de correlación de eventos."""
    id: str
    nombre: str
    descripcion: str
    patron_eventos: List[str]
    ventana_tiempo: int  # segundos
    umbral_eventos: int
    severidad_resultado: SeveridadEvento
    accion: str
    activa: bool = True

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
    asignado_a: Optional[str] = None
    resolucion: Optional[str] = None

class SIEMAvanzado:
    """
    SIEM Avanzado con capacidades de correlación, análisis y respuesta automática.
    Integra funcionalidad del proyecto original con mejoras profesionales.
    """
    
    def __init__(self, base_datos_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Configurar base de datos
        self.db_path = base_datos_path or os.path.join(
            os.path.expanduser("~"), "ares_aegis", "siem.db"
        )
        self._inicializar_base_datos()
        
        # Directorio de logs
        self.directorio_logs = self._crear_directorio_logs()
        
        # Buffer de eventos para correlación
        self.buffer_eventos = deque(maxlen=10000)
        self.eventos_por_tipo = defaultdict(deque)
        
        # Reglas de correlación
        self.reglas_correlacion = {}
        self._cargar_reglas_correlacion()
        
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
        
        # Funciones de callback para respuesta automática
        self.callbacks_respuesta = {}
        
        # Thread para procesamiento en background
        self._procesando = False
        self._thread_procesamiento = None
        
        # Lock para thread safety
        self._lock = threading.RLock()
        
        self.logger.info("🛡️ SIEM Avanzado Ares Aegis inicializado")
    
    def _inicializar_base_datos(self):
        """Inicializar base de datos SQLite para persistencia."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS eventos (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        tipo TEXT NOT NULL,
                        severidad TEXT NOT NULL,
                        origen TEXT NOT NULL,
                        mensaje TEXT NOT NULL,
                        detalles TEXT,
                        tags TEXT,
                        correlacion_id TEXT,
                        procesado BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS alertas (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        titulo TEXT NOT NULL,
                        descripcion TEXT NOT NULL,
                        severidad TEXT NOT NULL,
                        eventos_relacionados TEXT,
                        estado TEXT DEFAULT 'nueva',
                        asignado_a TEXT,
                        resolucion TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_eventos_timestamp 
                    ON eventos(timestamp)
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_eventos_tipo 
                    ON eventos(tipo)
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_eventos_severidad 
                    ON eventos(severidad)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error inicializando base de datos SIEM: {e}")
    
    def _crear_directorio_logs(self) -> str:
        """Crear directorio para logs."""
        directorio = os.path.join(os.path.expanduser("~"), "ares_aegis", "logs")
        try:
            os.makedirs(directorio, exist_ok=True)
            return directorio
        except Exception as e:
            self.logger.warning(f"Error creando directorio logs: {e}")
            import tempfile
            directorio = os.path.join(tempfile.gettempdir(), "ares_siem_logs")
            os.makedirs(directorio, exist_ok=True)
            return directorio
    
    def _cargar_reglas_correlacion(self):
        """Cargar reglas de correlación predefinidas."""
        reglas_basicas = [
            ReglaCorrelacion(
                id="auth_brute_force",
                nombre="Intento de fuerza bruta SSH",
                descripcion="Múltiples fallos de autenticación SSH desde la misma IP",
                patron_eventos=["AUTENTICACION"],
                ventana_tiempo=300,  # 5 minutos
                umbral_eventos=5,
                severidad_resultado=SeveridadEvento.ALTA,
                accion="bloquear_ip"
            ),
            ReglaCorrelacion(
                id="escalada_privilegios",
                nombre="Posible escalada de privilegios",
                descripcion="Uso sospechoso de sudo tras fallo de autenticación",
                patron_eventos=["AUTENTICACION", "PROCESO"],
                ventana_tiempo=600,  # 10 minutos
                umbral_eventos=3,
                severidad_resultado=SeveridadEvento.CRITICA,
                accion="alerta_inmediata"
            ),
            ReglaCorrelacion(
                id="acceso_archivos_sensibles",
                nombre="Acceso masivo a archivos sensibles",
                descripcion="Múltiples accesos a archivos de configuración críticos",
                patron_eventos=["ACCESO_ARCHIVO"],
                ventana_tiempo=180,  # 3 minutos
                umbral_eventos=10,
                severidad_resultado=SeveridadEvento.ALTA,
                accion="monitorear_usuario"
            ),
            ReglaCorrelacion(
                id="conexiones_sospechosas",
                nombre="Conexiones de red sospechosas",
                descripcion="Múltiples conexiones a IPs externas desconocidas",
                patron_eventos=["CONEXION_RED"],
                ventana_tiempo=300,
                umbral_eventos=20,
                severidad_resultado=SeveridadEvento.MEDIA,
                accion="analizar_trafico"
            )
        ]
        
        for regla in reglas_basicas:
            self.reglas_correlacion[regla.id] = regla
        
        self.logger.info(f"Cargadas {len(reglas_basicas)} reglas de correlación")
    
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
                self.logger.info("Procesamiento SIEM iniciado")
    
    def detener_procesamiento(self):
        """Detener procesamiento en background."""
        with self._lock:
            self._procesando = False
            if self._thread_procesamiento:
                self._thread_procesamiento.join(timeout=5)
                self.logger.info("Procesamiento SIEM detenido")
    
    def registrar_evento(self, tipo: TipoEvento, mensaje: str, detalles: Optional[Dict[str, Any]] = None, 
                        severidad: SeveridadEvento = SeveridadEvento.INFO, 
                        origen: str = "sistema", tags: Optional[Set[str]] = None) -> str:
        """Registrar un nuevo evento en el SIEM."""
        
        evento = EventoSIEM(
            id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(),
            tipo=tipo,
            severidad=severidad,
            origen=origen,
            mensaje=mensaje,
            detalles=detalles or {},
            tags=tags or set()
        )
        
        # Agregar al buffer
        with self._lock:
            self.buffer_eventos.append(evento)
            self.eventos_por_tipo[tipo].append(evento)
            
            # Actualizar métricas
            self.metricas['eventos_procesados'] += 1
            severidad_str = severidad.value if hasattr(severidad, 'value') else str(severidad)
            tipo_str = tipo.value if hasattr(tipo, 'value') else str(tipo)
            self.metricas['eventos_por_severidad'][severidad_str] += 1
            self.metricas['eventos_por_tipo'][tipo_str] += 1
        
        # Persistir en base de datos
        self._persistir_evento(evento)
        
        # Log del evento
        self._log_evento(evento)
        
        # Procesar correlaciones si está activo
        if self._procesando:
            self._procesar_correlaciones(evento)
        
        return evento.id
    
    def _persistir_evento(self, evento: EventoSIEM):
        """Persistir evento en base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO eventos 
                    (id, timestamp, tipo, severidad, origen, mensaje, detalles, tags, correlacion_id, procesado)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    evento.id,
                    evento.timestamp.isoformat(),
                    evento.tipo.value,
                    evento.severidad.value,
                    evento.origen,
                    evento.mensaje,
                    json.dumps(evento.detalles),
                    json.dumps(list(evento.tags)),
                    evento.correlacion_id,
                    evento.procesado
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error persistiendo evento: {e}")
    
    def _log_evento(self, evento: EventoSIEM):
        """Escribir evento a archivo de log."""
        try:
            archivo_log = os.path.join(
                self.directorio_logs,
                f"siem_{evento.timestamp.strftime('%Y-%m-%d')}.log"
            )
            
            log_entry = {
                'timestamp': evento.timestamp.isoformat(),
                'id': evento.id,
                'tipo': evento.tipo.value,
                'severidad': evento.severidad.value,
                'origen': evento.origen,
                'mensaje': evento.mensaje,
                'detalles': evento.detalles,
                'tags': list(evento.tags)
            }
            
            with open(archivo_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
                
        except Exception as e:
            self.logger.error(f"Error escribiendo log: {e}")
    
    def _loop_procesamiento(self):
        """Loop principal de procesamiento en background."""
        while self._procesando:
            try:
                # Limpiar eventos antiguos del buffer
                self._limpiar_buffer()
                
                # Procesar correlaciones pendientes
                self._procesar_correlaciones_batch()
                
                # Verificar alertas
                self._verificar_alertas()
                
                time.sleep(5)  # Procesar cada 5 segundos
                
            except Exception as e:
                self.logger.error(f"Error en loop de procesamiento: {e}")
                time.sleep(10)
    
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
    
    def _procesar_correlaciones(self, evento: EventoSIEM):
        """Procesar correlaciones para un evento específico."""
        for regla in self.reglas_correlacion.values():
            if not regla.activa:
                continue
                
            if evento.tipo.value in regla.patron_eventos:
                self._evaluar_regla_correlacion(regla, evento)
    
    def _procesar_correlaciones_batch(self):
        """Procesar correlaciones en lote."""
        for regla in self.reglas_correlacion.values():
            if regla.activa:
                self._evaluar_regla_correlacion_batch(regla)
    
    def _evaluar_regla_correlacion(self, regla: ReglaCorrelacion, evento: EventoSIEM):
        """Evaluar una regla de correlación específica."""
        try:
            limite_tiempo = evento.timestamp - datetime.timedelta(seconds=regla.ventana_tiempo)
            eventos_relevantes = []
            
            # Buscar eventos relevantes en la ventana de tiempo
            with self._lock:
                for evento_buffer in self.buffer_eventos:
                    if (evento_buffer.timestamp >= limite_tiempo and
                        evento_buffer.tipo.value in regla.patron_eventos):
                        eventos_relevantes.append(evento_buffer)
            
            # Verificar si se cumple el umbral
            if len(eventos_relevantes) >= regla.umbral_eventos:
                self._generar_alerta_correlacion(regla, eventos_relevantes)
                
        except Exception as e:
            self.logger.error(f"Error evaluando regla {regla.id}: {e}")
    
    def _evaluar_regla_correlacion_batch(self, regla: ReglaCorrelacion):
        """Evaluar regla de correlación en modo batch."""
        # Implementación simplificada para el batch
        pass
    
    def _generar_alerta_correlacion(self, regla: ReglaCorrelacion, eventos: List[EventoSIEM]):
        """Generar alerta por correlación de eventos."""
        alerta_id = str(uuid.uuid4())
        
        alerta = Alerta(
            id=alerta_id,
            timestamp=datetime.datetime.now(),
            titulo=f"Correlación detectada: {regla.nombre}",
            descripcion=f"{regla.descripcion}. {len(eventos)} eventos correlacionados.",
            severidad=regla.severidad_resultado,
            eventos_relacionados=[e.id for e in eventos]
        )
        
        with self._lock:
            self.alertas_activas[alerta_id] = alerta
            self.metricas['alertas_generadas'] += 1
            self.metricas['correlaciones_encontradas'] += 1
        
        # Persistir alerta
        self._persistir_alerta(alerta)
        
        # Ejecutar acción automática
        self._ejecutar_accion_respuesta(regla.accion, alerta, eventos)
        
        self.logger.warning(f"🚨 ALERTA CORRELACIÓN: {regla.nombre} - {len(eventos)} eventos")
    
    def _persistir_alerta(self, alerta: Alerta):
        """Persistir alerta en base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO alertas 
                    (id, timestamp, titulo, descripcion, severidad, eventos_relacionados, estado, asignado_a, resolucion)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alerta.id,
                    alerta.timestamp.isoformat(),
                    alerta.titulo,
                    alerta.descripcion,
                    alerta.severidad.value,
                    json.dumps(alerta.eventos_relacionados),
                    alerta.estado,
                    alerta.asignado_a,
                    alerta.resolucion
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error persistiendo alerta: {e}")
    
    def _ejecutar_accion_respuesta(self, accion: str, alerta: Alerta, eventos: List[EventoSIEM]):
        """Ejecutar acción de respuesta automática."""
        if accion in self.callbacks_respuesta:
            try:
                self.callbacks_respuesta[accion](alerta, eventos)
            except Exception as e:
                self.logger.error(f"Error ejecutando acción {accion}: {e}")
    
    def _verificar_alertas(self):
        """Verificar estado de alertas activas."""
        # Implementación para verificar alertas que requieren seguimiento
        pass
    
    def registrar_callback_respuesta(self, accion: str, callback: Callable):
        """Registrar callback para respuesta automática."""
        self.callbacks_respuesta[accion] = callback
        self.logger.info(f"Callback registrado para acción: {accion}")
    
    def obtener_eventos(self, limite: int = 100, filtro_tipo: Optional[TipoEvento] = None, 
                       filtro_severidad: Optional[SeveridadEvento] = None,
                       desde: Optional[datetime.datetime] = None,
                       hasta: Optional[datetime.datetime] = None) -> List[EventoSIEM]:
        """Obtener eventos del SIEM con filtros."""
        try:
            query = "SELECT * FROM eventos WHERE 1=1"
            params = []
            
            if filtro_tipo:
                query += " AND tipo = ?"
                params.append(filtro_tipo.value)
            
            if filtro_severidad:
                query += " AND severidad = ?"
                params.append(filtro_severidad.value)
            
            if desde:
                query += " AND timestamp >= ?"
                params.append(desde.isoformat())
            
            if hasta:
                query += " AND timestamp <= ?"
                params.append(hasta.isoformat())
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limite)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                eventos = []
                
                for row in cursor.fetchall():
                    evento = EventoSIEM(
                        id=row[0],
                        timestamp=datetime.datetime.fromisoformat(row[1]),
                        tipo=TipoEvento(row[2]),
                        severidad=SeveridadEvento(row[3]),
                        origen=row[4],
                        mensaje=row[5],
                        detalles=json.loads(row[6]) if row[6] else {},
                        tags=set(json.loads(row[7])) if row[7] else set(),
                        correlacion_id=row[8],
                        procesado=bool(row[9])
                    )
                    eventos.append(evento)
                
                return eventos
                
        except Exception as e:
            self.logger.error(f"Error obteniendo eventos: {e}")
            return []
    
    def obtener_alertas_activas(self) -> List[Alerta]:
        """Obtener alertas activas."""
        with self._lock:
            return list(self.alertas_activas.values())
    
    def obtener_metricas(self) -> Dict[str, Any]:
        """Obtener métricas del SIEM."""
        with self._lock:
            return {
                'metricas_basicas': self.metricas.copy(),
                'alertas_activas': len(self.alertas_activas),
                'eventos_en_buffer': len(self.buffer_eventos),
                'reglas_activas': sum(1 for r in self.reglas_correlacion.values() if r.activa),
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def generar_reporte_siem(self, periodo_horas: int = 24) -> str:
        """Generar reporte del SIEM."""
        desde = datetime.datetime.now() - datetime.timedelta(hours=periodo_horas)
        eventos = self.obtener_eventos(limite=1000, desde=desde)
        alertas = self.obtener_alertas_activas()
        
        reporte = f"""
# 🛡️ REPORTE SIEM - ARES AEGIS

## 📊 RESUMEN EJECUTIVO (Últimas {periodo_horas} horas)
- **Eventos Procesados**: {len(eventos)}
- **Alertas Activas**: {len(alertas)}
- **Correlaciones Encontradas**: {self.metricas['correlaciones_encontradas']}

## 📈 EVENTOS POR SEVERIDAD
"""
        
        eventos_por_severidad = defaultdict(int)
        for evento in eventos:
            eventos_por_severidad[evento.severidad.value] += 1
        
        for severidad, cantidad in eventos_por_severidad.items():
            emoji = {"CRITICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢", "INFO": "🔵"}
            reporte += f"- {emoji.get(severidad, '❓')} **{severidad}**: {cantidad}\n"
        
        reporte += f"\n## 🚨 ALERTAS ACTIVAS ({len(alertas)})\n"
        
        for alerta in alertas[:10]:  # Primeras 10 alertas
            emoji = {"CRITICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢", "INFO": "🔵"}
            reporte += f"{emoji.get(alerta.severidad.value, '❓')} **{alerta.titulo}**\n"
            reporte += f"  📅 {alerta.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            reporte += f"  📝 {alerta.descripcion}\n\n"
        
        reporte += f"\n## 📋 EVENTOS RECIENTES\n"
        
        for evento in eventos[:20]:  # Primeros 20 eventos
            emoji = {"CRITICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢", "INFO": "🔵"}
            reporte += f"{emoji.get(evento.severidad.value, '❓')} {evento.timestamp.strftime('%H:%M:%S')} - {evento.tipo.value}: {evento.mensaje}\n"
        
        reporte += f"\n---\n*Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return reporte


# Mantener compatibilidad con la interfaz actual
class SIEM(SIEMAvanzado):
    """
    Clase de compatibilidad que mantiene la interfaz original 
    pero proporciona toda la funcionalidad avanzada del SIEM.
    """
    
    def __init__(self, base_datos_path: Optional[str] = None):
        super().__init__(base_datos_path)
        # Mantener compatibilidad con código existente
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
            # Mapear tipos string a enum
            tipo_enum = TipoEvento(tipo.upper()) if hasattr(TipoEvento, tipo.upper()) else TipoEvento.SISTEMA_INICIADO
            severidad_enum = SeveridadEvento(severidad.upper()) if hasattr(SeveridadEvento, severidad.upper()) else SeveridadEvento.INFO
            
            evento_id = self.registrar_evento(
                tipo=tipo_enum,
                mensaje=mensaje,
                severidad=severidad_enum,
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
        """Genera un evento SIEM."""
        evento = {
            'id': f"{tipo}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'timestamp': datetime.datetime.now().isoformat(),
            'tipo': tipo,
            'mensaje': mensaje,
            'severidad': severidad,
            'origen': origen,
            'procesado': False
        }
        
        # Guardar evento
        self._guardar_evento(evento)
        
        return evento
    
    def _guardar_evento(self, evento: Dict[str, Any]):
        """Guarda un evento en el sistema de logs."""
        try:
            fecha_actual = datetime.datetime.now().strftime('%Y-%m-%d')
            archivo_log = os.path.join(self.directorio_logs, f"eventos_{fecha_actual}.json")
            
            # Leer eventos existentes
            eventos = []
            if os.path.exists(archivo_log):
                try:
                    with open(archivo_log, 'r', encoding='utf-8') as f:
                        eventos = json.load(f)
                except:
                    eventos = []
            
            # Agregar nuevo evento
            eventos.append(evento)
            
            # Guardar eventos actualizados
            with open(archivo_log, 'w', encoding='utf-8') as f:
                json.dump(eventos, f, indent=2, ensure_ascii=False)
                
        except Exception:
            pass  # Fallo silencioso para no interrumpir el flujo
    
    def obtener_eventos_recientes(self, limite: int = 100) -> List[Dict[str, Any]]:
        """Obtiene eventos recientes del SIEM."""
        eventos = []
        
        try:
            fecha_actual = datetime.datetime.now().strftime('%Y-%m-%d')
            archivo_log = os.path.join(self.directorio_logs, f"eventos_{fecha_actual}.json")
            
            if os.path.exists(archivo_log):
                with open(archivo_log, 'r', encoding='utf-8') as f:
                    todos_eventos = json.load(f)
                    eventos = todos_eventos[-limite:] if len(todos_eventos) > limite else todos_eventos
        except:
            pass
        
        return eventos
    
    def analizar_logs_sistema(self) -> Dict[str, Any]:
        """Análisis básico de logs del sistema."""
        resultados = {
            'eventos_encontrados': 0,
            'alertas_generadas': 0,
            'archivos_analizados': [],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        for regla in self.reglas_alertas:
            archivo_log = regla['archivo']
            
            if os.path.exists(archivo_log) and os.access(archivo_log, os.R_OK):
                try:
                    with open(archivo_log, 'r', encoding='utf-8', errors='ignore') as f:
                        # Leer últimas 1000 líneas
                        lineas = f.readlines()[-1000:]
                        
                        for linea in lineas:
                            if regla['patron'] in linea:
                                # Generar evento SIEM
                                self.generar_evento(
                                    tipo=regla['id'],
                                    mensaje=f"Detectado: {regla['nombre']} - {linea.strip()}",
                                    severidad=regla['severidad'],
                                    origen=archivo_log
                                )
                                resultados['eventos_encontrados'] += 1
                                resultados['alertas_generadas'] += 1
                        
                        resultados['archivos_analizados'].append({
                            'archivo': archivo_log,
                            'lineas_analizadas': len(lineas),
                            'regla': regla['nombre']
                        })
                        
                except Exception:
                    pass
        
        return resultados
    
    def obtener_timestamp(self) -> str:
        """Obtiene timestamp actual en formato ISO."""
        return datetime.datetime.now().isoformat()
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtiene estadísticas del SIEM."""
        try:
            eventos_hoy = self.obtener_eventos_recientes(1000)
            
            # Contar por severidad
            contadores = {'baja': 0, 'media': 0, 'alta': 0, 'critica': 0}
            for evento in eventos_hoy:
                severidad = evento.get('severidad', 'baja')
                if severidad in contadores:
                    contadores[severidad] += 1
            
            return {
                'eventos_total': len(eventos_hoy),
                'eventos_por_severidad': contadores,
                'ultimo_evento': eventos_hoy[-1]['timestamp'] if eventos_hoy else None,
                'directorio_logs': self.directorio_logs,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
        except Exception:
            return {
                'eventos_total': 0,
                'eventos_por_severidad': {'baja': 0, 'media': 0, 'alta': 0, 'critica': 0},
                'ultimo_evento': None,
                'directorio_logs': self.directorio_logs,
                'timestamp': datetime.datetime.now().isoformat()
            }

# RESUMEN: Sistema SIEM básico que genera eventos, analiza logs del sistema con reglas
# predefinidas, mantiene estadísticas y almacena eventos en formato JSON.
