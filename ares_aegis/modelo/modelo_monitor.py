# -*- coding: utf-8 -*-
"""
Ares Aegis - Monitor Avanzado del Sistema
Sistema de monitoreo integral que combina monitoreo de procesos, red y recursos del sistema
Integra funcionalidad avanzada del proyecto original con análisis de comportamiento
"""

import subprocess
import time
import datetime
import os
import psutil
import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set
import json

class TipoRecurso(Enum):
    """Tipos de recursos monitoreados."""
    CPU = "CPU"
    MEMORIA = "MEMORIA"
    DISCO = "DISCO"
    RED = "RED"
    PROCESOS = "PROCESOS"

class EstadoAlerta(Enum):
    """Estados de alerta del monitoreo."""
    NORMAL = "NORMAL"
    ADVERTENCIA = "ADVERTENCIA"
    CRITICO = "CRITICO"

@dataclass
class MetricaSistema:
    """Métrica individual del sistema."""
    timestamp: datetime.datetime
    tipo: TipoRecurso
    valor: float
    unidad: str
    estado: EstadoAlerta = EstadoAlerta.NORMAL
    detalles: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ProcesoInfo:
    """Información detallada de un proceso."""
    pid: int
    nombre: str
    usuario: str
    uso_cpu: float
    uso_memoria: int  # MB
    estado: str
    tiempo_inicio: datetime.datetime
    conexiones_red: List[Dict] = field(default_factory=list)
    archivos_abiertos: int = 0
    pid_padre: Optional[int] = None

@dataclass
class EstadisticasRed:
    """Estadísticas de red completas."""
    timestamp: datetime.datetime
    interfaces: Dict[str, Dict] = field(default_factory=dict)
    conexiones_activas: int = 0
    conexiones_establecidas: int = 0
    puertos_escucha: List[int] = field(default_factory=list)
    trafico_total: Dict[str, int] = field(default_factory=dict)
    conexiones_sospechosas: List[Dict] = field(default_factory=list)

class MonitorAvanzado:
    """
    Monitor avanzado del sistema que integra toda la funcionalidad 
    del proyecto original con análisis de comportamiento y alertas.
    """
    
    def __init__(self, siem=None):
        self.logger = logging.getLogger(__name__)
        self.siem = siem
        
        # Estado del monitoreo
        self.monitoreando = False
        self.thread_monitoreo = None
        
        # Configuración de umbrales
        self.umbrales = {
            'cpu_advertencia': 70.0,
            'cpu_critico': 90.0,
            'memoria_advertencia': 80.0,
            'memoria_critico': 95.0,
            'disco_advertencia': 85.0,
            'disco_critico': 95.0,
            'conexiones_max': 100,
            'procesos_sospechosos_max': 5
        }
        
        # Almacenamiento de datos históricos
        self.metricas_historicas = defaultdict(lambda: deque(maxlen=1000))
        self.procesos_monitoreados = {}
        self.estadisticas_red_historicas = deque(maxlen=500)
        
        # Lock para thread safety
        self._lock = threading.RLock()
        
        # Patrones de comportamiento sospechoso
        self.patrones_malware = {
            'cryptominer': ['miner', 'xmrig', 'cpuminer', 'minerd', 'ccminer'],
            'backdoor': ['nc', 'netcat', 'ncat', 'socat', 'reverse_tcp'],
            'rootkit': ['rootkit', 'stealth', 'hide', 'invisible'],
            'botnet': ['bot', 'drone', 'slave', 'c2', 'command']
        }
        
        self.ubicaciones_sospechosas = {
            '/tmp/', '/var/tmp/', '/dev/shm/', '/home/.*/.cache/',
            '/home/.*/Downloads/', '/tmp/.', '/var/tmp/.', '\\\\tmp\\\\'
        }
        
        self.procesos_sistema_legitimos = {
            'systemd', 'kernel', 'kthreadd', 'init', 'ksoftirqd', 'migration',
            'swapper', 'watchdog', 'NetworkManager', 'sshd', 'cron', 'rsyslog'
        }
        
        self.logger.info("🔍 Monitor Avanzado Ares Aegis inicializado")
    
    def iniciar_monitoreo_completo(self) -> Dict[str, Any]:
        """Iniciar monitoreo completo del sistema."""
        try:
            with self._lock:
                if self.monitoreando:
                    return {
                        'exito': False,
                        'error': 'El monitoreo ya está activo',
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                
                self.monitoreando = True
                
                # Iniciar thread de monitoreo continuo
                self.thread_monitoreo = threading.Thread(
                    target=self._loop_monitoreo_continuo,
                    daemon=True
                )
                self.thread_monitoreo.start()
                
                # Obtener datos iniciales
                datos_iniciales = self._obtener_estado_sistema_completo()
                
                if self.siem:
                    self.siem.registrar_evento(
                        tipo="SISTEMA_INICIADO",
                        mensaje="Monitoreo avanzado del sistema iniciado",
                        detalles={'umbrales': self.umbrales}
                    )
                
                self.logger.info("🟢 Monitoreo completo iniciado")
                
                return {
                    'exito': True,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'estado_inicial': datos_iniciales,
                    'message': 'Monitoreo iniciado correctamente'
                }
                
        except Exception as e:
            self.logger.error(f"Error iniciando monitoreo: {e}")
            return {
                'exito': False,
                'error': str(e),
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def detener_monitoreo(self) -> Dict[str, Any]:
        """Detener monitoreo del sistema."""
        try:
            with self._lock:
                if not self.monitoreando:
                    return {
                        'exito': False,
                        'error': 'El monitoreo no está activo',
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                
                self.monitoreando = False
                
                # Esperar a que termine el thread
                if self.thread_monitoreo and self.thread_monitoreo.is_alive():
                    self.thread_monitoreo.join(timeout=5)
                
                if self.siem:
                    self.siem.registrar_evento(
                        tipo="SISTEMA_DETENIDO",
                        mensaje="Monitoreo del sistema detenido"
                    )
                
                self.logger.info("🔴 Monitoreo detenido")
                
                return {
                    'exito': True,
                    'mensaje': 'Monitoreo detenido correctamente',
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error deteniendo monitoreo: {e}")
            return {
                'exito': False,
                'error': str(e),
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def _loop_monitoreo_continuo(self):
        """Loop principal de monitoreo continuo."""
        while self.monitoreando:
            try:
                # Recopilar métricas del sistema
                self._recopilar_metricas_sistema()
                
                # Monitorear procesos
                self._monitorear_procesos()
                
                # Monitorear red
                self._monitorear_red()
                
                # Analizar anomalías
                self._analizar_anomalias()
                
                # Esperar antes del siguiente ciclo
                time.sleep(5)  # Monitoreo cada 5 segundos
                
            except Exception as e:
                self.logger.error(f"Error en loop de monitoreo: {e}")
                time.sleep(10)
    
    def _recopilar_metricas_sistema(self):
        """Recopilar métricas básicas del sistema."""
        timestamp = datetime.datetime.now()
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_metric = MetricaSistema(
                timestamp=timestamp,
                tipo=TipoRecurso.CPU,
                valor=cpu_percent,
                unidad="%",
                estado=self._determinar_estado_cpu(cpu_percent)
            )
            
            with self._lock:
                self.metricas_historicas[TipoRecurso.CPU].append(cpu_metric)
            
            # Memoria
            memoria = psutil.virtual_memory()
            memoria_metric = MetricaSistema(
                timestamp=timestamp,
                tipo=TipoRecurso.MEMORIA,
                valor=memoria.percent,
                unidad="%",
                estado=self._determinar_estado_memoria(memoria.percent),
                detalles={
                    'total_mb': memoria.total // (1024 * 1024),
                    'disponible_mb': memoria.available // (1024 * 1024),
                    'usado_mb': memoria.used // (1024 * 1024)
                }
            )
            
            with self._lock:
                self.metricas_historicas[TipoRecurso.MEMORIA].append(memoria_metric)
            
            # Disco
            disco = psutil.disk_usage('/')
            disco_percent = (disco.used / disco.total) * 100
            disco_metric = MetricaSistema(
                timestamp=timestamp,
                tipo=TipoRecurso.DISCO,
                valor=disco_percent,
                unidad="%",
                estado=self._determinar_estado_disco(disco_percent),
                detalles={
                    'total_gb': disco.total // (1024 ** 3),
                    'usado_gb': disco.used // (1024 ** 3),
                    'libre_gb': disco.free // (1024 ** 3)
                }
            )
            
            with self._lock:
                self.metricas_historicas[TipoRecurso.DISCO].append(disco_metric)
            
            # Generar alertas si es necesario
            self._verificar_alertas_recursos([cpu_metric, memoria_metric, disco_metric])
            
        except Exception as e:
            self.logger.error(f"Error recopilando métricas: {e}")
    
    def _monitorear_procesos(self):
        """Monitorear procesos del sistema y detectar comportamiento sospechoso."""
        try:
            procesos_actuales = {}
            procesos_sospechosos = []
            
            for proceso in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                                'memory_info', 'status', 'create_time', 'ppid']):
                try:
                    info = proceso.info
                    pid = info['pid']
                    
                    # Obtener información de conexiones de red
                    conexiones = []
                    try:
                        conexiones_proc = []
                        for conn in proceso.connections():
                            if conn.laddr:
                                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                            else:
                                local_addr = "unknown"
                            
                            if conn.raddr:
                                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                            else:
                                remote_addr = ""
                            
                            conexiones_proc.append({
                                'local': local_addr,
                                'remoto': remote_addr,
                                'estado': conn.status
                            })
                        conexiones = conexiones_proc
                    except:
                        pass
                    
                    # Obtener archivos abiertos
                    archivos_abiertos = 0
                    try:
                        archivos_abiertos = len(proceso.open_files())
                    except:
                        pass
                    
                    proceso_info = ProcesoInfo(
                        pid=pid,
                        nombre=info['name'],
                        usuario=info['username'] or 'desconocido',
                        uso_cpu=info['cpu_percent'] or 0.0,
                        uso_memoria=info['memory_info'].rss // (1024 * 1024) if info['memory_info'] else 0,
                        estado=info['status'],
                        tiempo_inicio=datetime.datetime.fromtimestamp(info['create_time']) if info['create_time'] else datetime.datetime.now(),
                        conexiones_red=conexiones,
                        archivos_abiertos=archivos_abiertos,
                        pid_padre=info['ppid']
                    )
                    
                    procesos_actuales[pid] = proceso_info
                    
                    # Analizar si es sospechoso
                    if self._es_proceso_sospechoso(proceso_info):
                        procesos_sospechosos.append(proceso_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            with self._lock:
                self.procesos_monitoreados = procesos_actuales
            
            # Registrar procesos sospechosos
            if procesos_sospechosos and self.siem:
                for proceso in procesos_sospechosos:
                    self.siem.registrar_evento(
                        tipo="PROCESO",
                        mensaje=f"Proceso sospechoso detectado: {proceso.nombre} (PID: {proceso.pid})",
                        severidad="ALTA",
                        detalles={
                            'proceso': proceso.nombre,
                            'pid': proceso.pid,
                            'usuario': proceso.usuario,
                            'uso_cpu': proceso.uso_cpu,
                            'uso_memoria': proceso.uso_memoria,
                            'conexiones_red': len(proceso.conexiones_red)
                        }
                    )
            
        except Exception as e:
            self.logger.error(f"Error monitoreando procesos: {e}")
    
    def _monitorear_red(self):
        """Monitorear conexiones y estadísticas de red."""
        try:
            # Obtener interfaces de red
            interfaces = {}
            for interface, stats in psutil.net_io_counters(pernic=True).items():
                interfaces[interface] = {
                    'bytes_enviados': stats.bytes_sent,
                    'bytes_recibidos': stats.bytes_recv,
                    'paquetes_enviados': stats.packets_sent,
                    'paquetes_recibidos': stats.packets_recv,
                    'errores_entrada': stats.errin,
                    'errores_salida': stats.errout
                }
            
            # Obtener conexiones activas
            conexiones = psutil.net_connections()
            conexiones_establecidas = len([c for c in conexiones if c.status == 'ESTABLISHED'])
            
            # Obtener puertos en escucha
            puertos_escucha = []
            for c in conexiones:
                if c.status == 'LISTEN' and c.laddr:
                    puertos_escucha.append(c.laddr.port)
            puertos_escucha = list(set(puertos_escucha))
            
            # Detectar conexiones sospechosas
            conexiones_sospechosas = self._detectar_conexiones_sospechosas(conexiones)
            
            # Crear estadísticas de red
            estadisticas = EstadisticasRed(
                timestamp=datetime.datetime.now(),
                interfaces=interfaces,
                conexiones_activas=len(conexiones),
                conexiones_establecidas=conexiones_establecidas,
                puertos_escucha=sorted(puertos_escucha),
                trafico_total={
                    'bytes_enviados': sum(i['bytes_enviados'] for i in interfaces.values()),
                    'bytes_recibidos': sum(i['bytes_recibidos'] for i in interfaces.values())
                },
                conexiones_sospechosas=conexiones_sospechosas
            )
            
            with self._lock:
                self.estadisticas_red_historicas.append(estadisticas)
            
            # Registrar conexiones sospechosas
            if conexiones_sospechosas and self.siem:
                for conexion in conexiones_sospechosas:
                    self.siem.registrar_evento(
                        tipo="CONEXION_RED",
                        mensaje=f"Conexión sospechosa detectada: {conexion.get('descripcion', 'Desconocida')}",
                        severidad="MEDIA",
                        detalles=conexion
                    )
            
        except Exception as e:
            self.logger.error(f"Error monitoreando red: {e}")
    
    def _es_proceso_sospechoso(self, proceso: ProcesoInfo) -> bool:
        """Determinar si un proceso es sospechoso."""
        try:
            # Verificar patrones de malware en el nombre
            nombre_lower = proceso.nombre.lower()
            for categoria, patrones in self.patrones_malware.items():
                if any(patron in nombre_lower for patron in patrones):
                    return True
            
            # Verificar uso excesivo de recursos
            if proceso.uso_cpu > 80.0 or proceso.uso_memoria > 500:
                return True
            
            # Verificar demasiadas conexiones de red
            if len(proceso.conexiones_red) > 20:
                return True
            
            # Verificar procesos huérfanos sospechosos
            if (proceso.pid_padre == 1 and 
                proceso.nombre not in self.procesos_sistema_legitimos):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _detectar_conexiones_sospechosas(self, conexiones: List) -> List[Dict]:
        """Detectar conexiones de red sospechosas."""
        sospechosas = []
        
        try:
            # Contar conexiones por IP remota
            conexiones_por_ip = defaultdict(int)
            
            for conexion in conexiones:
                if conexion.raddr and conexion.status == 'ESTABLISHED':
                    ip_remota = conexion.raddr.ip
                    puerto_remoto = conexion.raddr.port
                    puerto_local = conexion.laddr.port if conexion.laddr else 0
                    
                    conexiones_por_ip[ip_remota] += 1
                    
                    # Verificar si la IP es sospechosa
                    if self._es_ip_sospechosa(ip_remota):
                        sospechosas.append({
                            'tipo': 'IP_SOSPECHOSA',
                            'ip_remota': ip_remota,
                            'puerto_remoto': puerto_remoto,
                            'puerto_local': puerto_local,
                            'descripcion': f'Conexión a IP potencialmente maliciosa: {ip_remota}'
                        })
            
            # Detectar demasiadas conexiones desde una IP
            for ip, cantidad in conexiones_por_ip.items():
                if cantidad > 10:
                    sospechosas.append({
                        'tipo': 'MULTIPLES_CONEXIONES',
                        'ip_remota': ip,
                        'cantidad': cantidad,
                        'descripcion': f'Demasiadas conexiones desde {ip}: {cantidad}'
                    })
            
        except Exception as e:
            self.logger.error(f"Error detectando conexiones sospechosas: {e}")
        
        return sospechosas
    
    def _es_ip_sospechosa(self, ip: str) -> bool:
        """Verificar si una IP es sospechosa."""
        # IPs privadas generalmente no son sospechosas
        if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                         '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                         '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                         '172.29.', '172.30.', '172.31.', '127.')):
            return False
        
        # Aquí se podrían agregar verificaciones adicionales
        return False
    
    def _determinar_estado_cpu(self, cpu_percent: float) -> EstadoAlerta:
        """Determinar estado de alerta para CPU."""
        if cpu_percent >= self.umbrales['cpu_critico']:
            return EstadoAlerta.CRITICO
        elif cpu_percent >= self.umbrales['cpu_advertencia']:
            return EstadoAlerta.ADVERTENCIA
        return EstadoAlerta.NORMAL
    
    def _determinar_estado_memoria(self, mem_percent: float) -> EstadoAlerta:
        """Determinar estado de alerta para memoria."""
        if mem_percent >= self.umbrales['memoria_critico']:
            return EstadoAlerta.CRITICO
        elif mem_percent >= self.umbrales['memoria_advertencia']:
            return EstadoAlerta.ADVERTENCIA
        return EstadoAlerta.NORMAL
    
    def _determinar_estado_disco(self, disk_percent: float) -> EstadoAlerta:
        """Determinar estado de alerta para disco."""
        if disk_percent >= self.umbrales['disco_critico']:
            return EstadoAlerta.CRITICO
        elif disk_percent >= self.umbrales['disco_advertencia']:
            return EstadoAlerta.ADVERTENCIA
        return EstadoAlerta.NORMAL
    
    def _verificar_alertas_recursos(self, metricas: List[MetricaSistema]):
        """Verificar y generar alertas de recursos."""
        for metrica in metricas:
            if metrica.estado in [EstadoAlerta.ADVERTENCIA, EstadoAlerta.CRITICO] and self.siem:
                severidad = "ALTA" if metrica.estado == EstadoAlerta.CRITICO else "MEDIA"
                
                self.siem.registrar_evento(
                    tipo=metrica.tipo.value,
                    mensaje=f"Alerta de {metrica.tipo.value}: {metrica.valor:.1f}{metrica.unidad}",
                    severidad=severidad,
                    detalles={
                        'valor': metrica.valor,
                        'unidad': metrica.unidad,
                        'estado': metrica.estado.value,
                        'detalles': metrica.detalles
                    }
                )
    
    def _analizar_anomalias(self):
        """Analizar patrones anómalos en el sistema."""
        # Esta función puede implementar análisis más sofisticados
        # Por ahora, hacemos verificaciones básicas
        pass
    
    def _obtener_estado_sistema_completo(self) -> Dict[str, Any]:
        """Obtener estado completo del sistema."""
        return {
            'sistema': self._obtener_datos_sistema(),
            'red': self._obtener_datos_red(),
            'procesos': self._obtener_resumen_procesos()
        }
    
    def _obtener_datos_sistema(self) -> Dict[str, Any]:
        """Obtener datos básicos del sistema."""
        try:
            cpu_info = psutil.cpu_percent(interval=1, percpu=True)
            memoria = psutil.virtual_memory()
            disco = psutil.disk_usage('/')
            
            return {
                'cpu_promedio': sum(cpu_info) / len(cpu_info),
                'cpu_cores': cpu_info,
                'memoria_total_mb': memoria.total // (1024 * 1024),
                'memoria_disponible_mb': memoria.available // (1024 * 1024),
                'memoria_porcentaje': memoria.percent,
                'disco_total_gb': disco.total // (1024 ** 3),
                'disco_usado_gb': disco.used // (1024 ** 3),
                'disco_porcentaje': (disco.used / disco.total) * 100,
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _obtener_datos_red(self) -> Dict[str, Any]:
        """Obtener datos de red."""
        try:
            conexiones = psutil.net_connections()
            stats = psutil.net_io_counters()
            
            return {
                'conexiones_totales': len(conexiones),
                'conexiones_establecidas': len([c for c in conexiones if c.status == 'ESTABLISHED']),
                'puertos_escucha': len([c for c in conexiones if c.status == 'LISTEN']),
                'bytes_enviados': stats.bytes_sent,
                'bytes_recibidos': stats.bytes_recv,
                'paquetes_enviados': stats.packets_sent,
                'paquetes_recibidos': stats.packets_recv,
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _obtener_resumen_procesos(self) -> Dict[str, Any]:
        """Obtener resumen de procesos."""
        try:
            procesos = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            
            # Top 5 procesos por CPU
            top_cpu = sorted(
                [p for p in procesos if p.info['cpu_percent']], 
                key=lambda x: x.info['cpu_percent'], 
                reverse=True
            )[:5]
            
            # Top 5 procesos por memoria
            top_memoria = sorted(
                [p for p in procesos if p.info['memory_percent']], 
                key=lambda x: x.info['memory_percent'], 
                reverse=True
            )[:5]
            
            return {
                'total_procesos': len(procesos),
                'top_cpu': [{'pid': p.info['pid'], 'nombre': p.info['name'], 'cpu': p.info['cpu_percent']} for p in top_cpu],
                'top_memoria': [{'pid': p.info['pid'], 'nombre': p.info['name'], 'memoria': p.info['memory_percent']} for p in top_memoria],
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def obtener_datos_sistema_recientes(self, limite: int = 10) -> List[Dict[str, Any]]:
        """Obtener datos históricos del sistema."""
        with self._lock:
            datos = []
            
            # Combinar métricas por timestamp
            timestamps = set()
            for metricas in self.metricas_historicas.values():
                timestamps.update(m.timestamp for m in list(metricas)[-limite:])
            
            for timestamp in sorted(timestamps)[-limite:]:
                datos_timestamp = {'timestamp': timestamp.isoformat()}
                
                # Buscar métricas para este timestamp
                for tipo, metricas in self.metricas_historicas.items():
                    for metrica in metricas:
                        if metrica.timestamp == timestamp:
                            datos_timestamp[tipo.value.lower()] = {
                                'valor': metrica.valor,
                                'unidad': metrica.unidad,
                                'estado': metrica.estado.value,
                                'detalles': metrica.detalles
                            }
                
                if len(datos_timestamp) > 1:  # Solo agregar si tiene datos además del timestamp
                    datos.append(datos_timestamp)
            
            return datos
    
    def obtener_datos_red_recientes(self, limite: int = 10) -> List[Dict[str, Any]]:
        """Obtener datos históricos de red."""
        with self._lock:
            return [
                {
                    'timestamp': stats.timestamp.isoformat(),
                    'conexiones_activas': stats.conexiones_activas,
                    'conexiones_establecidas': stats.conexiones_establecidas,
                    'puertos_escucha': stats.puertos_escucha,
                    'trafico_total': stats.trafico_total,
                    'conexiones_sospechosas': len(stats.conexiones_sospechosas)
                }
                for stats in list(self.estadisticas_red_historicas)[-limite:]
            ]
    
    def obtener_procesos_sospechosos(self) -> List[Dict[str, Any]]:
        """Obtener lista de procesos sospechosos actuales."""
        with self._lock:
            sospechosos = []
            
            for proceso in self.procesos_monitoreados.values():
                if self._es_proceso_sospechoso(proceso):
                    sospechosos.append({
                        'pid': proceso.pid,
                        'nombre': proceso.nombre,
                        'usuario': proceso.usuario,
                        'uso_cpu': proceso.uso_cpu,
                        'uso_memoria': proceso.uso_memoria,
                        'conexiones_red': len(proceso.conexiones_red),
                        'tiempo_inicio': proceso.tiempo_inicio.isoformat()
                    })
            
            return sospechosos
    
    def obtener_metricas_resumen(self) -> Dict[str, Any]:
        """Obtener resumen de métricas del monitor."""
        with self._lock:
            return {
                'monitoreando': self.monitoreando,
                'metricas_recopiladas': {
                    tipo.value: len(metricas) for tipo, metricas in self.metricas_historicas.items()
                },
                'procesos_monitoreados': len(self.procesos_monitoreados),
                'estadisticas_red': len(self.estadisticas_red_historicas),
                'umbrales_configurados': self.umbrales.copy(),
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def generar_reporte_monitor(self) -> str:
        """Generar reporte completo del monitor."""
        datos_sistema = self._obtener_datos_sistema()
        datos_red = self._obtener_datos_red()
        procesos_sospechosos = self.obtener_procesos_sospechosos()
        
        reporte = f"""
# 🔍 REPORTE DE MONITOREO - ARES AEGIS

## 📊 ESTADO DEL SISTEMA
- **CPU Promedio**: {datos_sistema.get('cpu_promedio', 'N/A'):.1f}%
- **Memoria Usada**: {datos_sistema.get('memoria_porcentaje', 'N/A'):.1f}%
- **Disco Usado**: {datos_sistema.get('disco_porcentaje', 'N/A'):.1f}%

## 🌐 ESTADO DE RED
- **Conexiones Totales**: {datos_red.get('conexiones_totales', 'N/A')}
- **Conexiones Establecidas**: {datos_red.get('conexiones_establecidas', 'N/A')}
- **Puertos en Escucha**: {datos_red.get('puertos_escucha', 'N/A')}

## 🚨 PROCESOS SOSPECHOSOS ({len(procesos_sospechosos)})
"""
        
        if procesos_sospechosos:
            for proceso in procesos_sospechosos[:10]:  # Primeros 10
                reporte += f"- **{proceso['nombre']}** (PID: {proceso['pid']}) - CPU: {proceso['uso_cpu']:.1f}%, RAM: {proceso['uso_memoria']}MB\n"
        else:
            reporte += "✅ No se detectaron procesos sospechosos.\n"
        
        reporte += f"\n---\n*Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return reporte


# Mantener compatibilidad con la interfaz actual
class Monitor(MonitorAvanzado):
    """
    Clase de compatibilidad que mantiene la interfaz original 
    pero proporciona toda la funcionalidad avanzada del monitor.
    """
    
    def __init__(self, siem=None):
        super().__init__(siem)
        # Mantener compatibilidad
        self.datos_historicos = []
    
    def obtener_datos_sistema_recientes(self, limite: int = 10) -> List[Dict[str, Any]]:
        """Método de compatibilidad que combina los datos del monitor avanzado."""
        datos_avanzados = super().obtener_datos_sistema_recientes(limite)
        
        # Convertir al formato esperado por la interfaz original
        datos_compatibles = []
        for dato in datos_avanzados:
            datos_compatibles.append({
                'timestamp': dato['timestamp'],
                'sistema': {
                    'cpu': dato.get('cpu', {}).get('valor', 0),
                    'memoria': dato.get('memoria', {}).get('valor', 0),
                    'disco': dato.get('disco', {}).get('valor', 0)
                },
                'exito': True
            })
        
        # Actualizar datos_historicos para compatibilidad
        self.datos_historicos = datos_compatibles
        
        return datos_compatibles
        return [d for d in datos_red if d]
    
    def _obtener_datos_sistema(self) -> Dict[str, Any]:
        try:
            resultado_ps = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
            resultado_free = subprocess.run(['free', '-h'], capture_output=True, text=True, timeout=10)
            resultado_df = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=10)
            
            procesos = len(resultado_ps.stdout.split('\n')) - 1 if resultado_ps.returncode == 0 else 0
            
            return {
                'procesos_activos': procesos,
                'memoria': resultado_free.stdout if resultado_free.returncode == 0 else 'No disponible',
                'almacenamiento': resultado_df.stdout if resultado_df.returncode == 0 else 'No disponible',
                'carga_sistema': self._obtener_carga_sistema()
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _obtener_datos_red(self) -> Dict[str, Any]:
        try:
            resultado_ss = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
            resultado_ip = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            
            conexiones = len(resultado_ss.stdout.split('\n')) - 1 if resultado_ss.returncode == 0 else 0
            
            return {
                'conexiones_activas': conexiones,
                'interfaces': resultado_ip.stdout if resultado_ip.returncode == 0 else 'No disponible',
                'puertos_escucha': self._parsear_puertos_escucha(resultado_ss.stdout) if resultado_ss.returncode == 0 else []
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _obtener_carga_sistema(self) -> str:
        try:
            with open('/proc/loadavg', 'r') as f:
                return f.read().strip()
        except:
            return 'No disponible'
    
    def _parsear_puertos_escucha(self, salida_ss: str) -> List[str]:
        puertos = []
        for linea in salida_ss.split('\n')[1:]:
            if 'LISTEN' in linea:
                partes = linea.split()
                if len(partes) >= 5:
                    puerto = partes[4].split(':')[-1]
                    if puerto not in puertos:
                        puertos.append(puerto)
        return puertos[:20]

# RESUMEN TÉCNICO: Modelo de monitorización de sistema y red para Kali Linux. Utiliza 
# herramientas nativas como ps, free, df, ss e ip para recolectar métricas en tiempo real. 
# Arquitectura SOLID con responsabilidad única de monitoreo, sin dependencias externas, 
# optimizado para análisis de seguridad y detección de anomalías en pentesting profesional.
