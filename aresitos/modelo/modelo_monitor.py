#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MONITOR AVANZADO ARES AEGIS - VERSIÓN NATIVA LINUX
===============================================

Monitor de sistema que usa ÚNICAMENTE herramientas nativas de Linux
y comandos estándar para análisis de recursos y seguridad.

FUNCIONALIDADES IMPLEMENTADAS:
-  Monitoreo de recursos con free/ps/df
-  Análisis de procesos con ps
-  Monitoreo de red con ss/netstat
-  Detección de anomalías
-  Solo Python estándar + comandos Linux

Autor: Ares Aegis Security Suite
Fecha: 2025-08-17
"""

import os
import re
import json
import time
import subprocess
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import shutil

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
    timestamp: datetime
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
    tiempo_inicio: Optional[datetime] = None
    conexiones_red: List[Dict] = field(default_factory=list)
    archivos_abiertos: int = 0
    pid_padre: Optional[int] = None

@dataclass
class EstadisticasRed:
    """Estadísticas de red completas."""
    timestamp: datetime
    interfaces: Dict[str, Dict] = field(default_factory=dict)
    conexiones_activas: int = 0
    conexiones_establecidas: int = 0
    puertos_escucha: List[int] = field(default_factory=list)
    trafico_total: Dict[str, int] = field(default_factory=dict)
    conexiones_sospechosas: List[Dict] = field(default_factory=list)

class MonitorAvanzadoNativo:
    """
    Monitor avanzado del sistema que usa herramientas nativas de Linux.
    Diseñado específicamente para Kali Linux con máxima compatibilidad.
    """
    
    def __init__(self, siem=None):
        self.logger = logging.getLogger("aresitos.modelo.monitor_avanzado")
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
        
        self.procesos_sistema_legitimos = {
            'systemd', 'kernel', 'kthreadd', 'init', 'ksoftirqd', 'migration',
            'swapper', 'watchdog', 'NetworkManager', 'sshd', 'cron', 'rsyslog'
        }
        
        # Verificar herramientas disponibles
        self._herramientas = self._verificar_herramientas()
        
        self.logger.info("� Monitor Avanzado Nativo Ares Aegis inicializado")
        self.logger.info(f"Herramientas disponibles: {len([h for h in self._herramientas.values() if h])}/8")

    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verifica qué herramientas de Linux están disponibles."""
        herramientas = {
            'ps': shutil.which('ps') is not None,
            'free': shutil.which('free') is not None,
            'df': shutil.which('df') is not None,
            'ss': shutil.which('ss') is not None,
            'netstat': shutil.which('netstat') is not None,
            'top': shutil.which('top') is not None,
            'awk': shutil.which('awk') is not None,
            'grep': shutil.which('grep') is not None
        }
        
        disponibles = sum(1 for disponible in herramientas.values() if disponible)
        self.logger.info(f"Herramientas verificadas: {disponibles}/8 disponibles")
        
        return herramientas

    def iniciar_monitoreo_completo(self) -> Dict[str, Any]:
        """Iniciar monitoreo completo del sistema."""
        try:
            with self._lock:
                if self.monitoreando:
                    return {
                        'exito': False,
                        'error': 'El monitoreo ya está activo',
                        'timestamp': datetime.now().isoformat()
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
                
                self.logger.info("� Monitoreo completo iniciado")
                
                return {
                    'exito': True,
                    'timestamp': datetime.now().isoformat(),
                    'estado_inicial': datos_iniciales,
                    'message': 'Monitoreo iniciado correctamente'
                }
                
        except Exception as e:
            self.logger.error(f"Error iniciando monitoreo: {e}")
            return {
                'exito': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def detener_monitoreo(self) -> Dict[str, Any]:
        """Detener monitoreo del sistema."""
        try:
            with self._lock:
                if not self.monitoreando:
                    return {
                        'exito': False,
                        'error': 'El monitoreo no está activo',
                        'timestamp': datetime.now().isoformat()
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
                
                self.logger.info("� Monitoreo detenido")
                
                return {
                    'exito': True,
                    'mensaje': 'Monitoreo detenido correctamente',
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error deteniendo monitoreo: {e}")
            return {
                'exito': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
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
        """Recopilar métricas básicas del sistema usando comandos nativos."""
        timestamp = datetime.now()
        
        try:
            # CPU usando top
            cpu_percent = self._obtener_uso_cpu()
            if cpu_percent is not None:
                cpu_metric = MetricaSistema(
                    timestamp=timestamp,
                    tipo=TipoRecurso.CPU,
                    valor=cpu_percent,
                    unidad="%",
                    estado=self._determinar_estado_cpu(cpu_percent)
                )
                
                with self._lock:
                    self.metricas_historicas[TipoRecurso.CPU].append(cpu_metric)
            
            # Memoria usando free
            memoria_data = self._obtener_uso_memoria()
            if memoria_data:
                memoria_metric = MetricaSistema(
                    timestamp=timestamp,
                    tipo=TipoRecurso.MEMORIA,
                    valor=memoria_data['porcentaje'],
                    unidad="%",
                    estado=self._determinar_estado_memoria(memoria_data['porcentaje']),
                    detalles=memoria_data
                )
                
                with self._lock:
                    self.metricas_historicas[TipoRecurso.MEMORIA].append(memoria_metric)
            
            # Disco usando df
            disco_data = self._obtener_uso_disco()
            if disco_data:
                disco_metric = MetricaSistema(
                    timestamp=timestamp,
                    tipo=TipoRecurso.DISCO,
                    valor=disco_data['porcentaje'],
                    unidad="%",
                    estado=self._determinar_estado_disco(disco_data['porcentaje']),
                    detalles=disco_data
                )
                
                with self._lock:
                    self.metricas_historicas[TipoRecurso.DISCO].append(disco_metric)
            
            # Generar alertas si es necesario
            metricas = [cpu_metric, memoria_metric, disco_metric]
            self._verificar_alertas_recursos([m for m in metricas if m])
            
        except Exception as e:
            self.logger.error(f"Error recopilando métricas: {e}")

    def _obtener_uso_cpu(self) -> Optional[float]:
        """Obtener uso de CPU usando comandos nativos."""
        try:
            # Método 1: usar top
            if self._herramientas.get('top', False):
                cmd = ['top', '-bn1']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '%Cpu(s):' in line or 'Cpu(s):' in line:
                            # Buscar el valor de CPU idle
                            match = re.search(r'(\d+\.\d+)%?\s*id', line)
                            if match:
                                idle = float(match.group(1))
                                return 100.0 - idle
                            
                            # Fallback: buscar uso total
                            match = re.search(r'(\d+\.\d+)%?\s*us', line)
                            if match:
                                return float(match.group(1))
            
            # Método 2: leer /proc/stat
            try:
                with open('/proc/stat', 'r') as f:
                    line = f.readline()
                    cpu_times = [int(x) for x in line.split()[1:]]
                    idle_time = cpu_times[3]
                    total_time = sum(cpu_times)
                    
                    if total_time > 0:
                        return ((total_time - idle_time) / total_time) * 100.0
            except (IOError, OSError, PermissionError, FileNotFoundError):
                pass
                
        except Exception as e:
            self.logger.warning(f"Error obteniendo uso de CPU: {e}")
        
        return None

    def _obtener_uso_memoria(self) -> Optional[Dict[str, Any]]:
        """Obtener uso de memoria usando free."""
        try:
            if self._herramientas.get('free', False):
                cmd = ['free', '-b']  # En bytes
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.startswith('Mem:'):
                            parts = line.split()
                            if len(parts) >= 7:
                                total = int(parts[1])
                                used = int(parts[2])
                                available = int(parts[6]) if len(parts) > 6 else int(parts[3])
                                
                                porcentaje = (used / total) * 100.0
                                
                                return {
                                    'total_mb': total // (1024 * 1024),
                                    'usado_mb': used // (1024 * 1024),
                                    'disponible_mb': available // (1024 * 1024),
                                    'porcentaje': porcentaje
                                }
            
            # Fallback: leer /proc/meminfo
            try:
                with open('/proc/meminfo', 'r') as f:
                    mem_info = f.read()
                
                total_match = re.search(r'MemTotal:\s+(\d+) kB', mem_info)
                available_match = re.search(r'MemAvailable:\s+(\d+) kB', mem_info)
                
                if total_match and available_match:
                    total_kb = int(total_match.group(1))
                    available_kb = int(available_match.group(1))
                    used_kb = total_kb - available_kb
                    
                    porcentaje = (used_kb / total_kb) * 100.0
                    
                    return {
                        'total_mb': total_kb // 1024,
                        'usado_mb': used_kb // 1024,
                        'disponible_mb': available_kb // 1024,
                        'porcentaje': porcentaje
                    }
            except (ValueError, TypeError, AttributeError):
                pass
                
        except Exception as e:
            self.logger.warning(f"Error obteniendo uso de memoria: {e}")
        
        return None

    def _obtener_uso_disco(self) -> Optional[Dict[str, Any]]:
        """Obtener uso de disco usando df."""
        try:
            if self._herramientas.get('df', False):
                cmd = ['df', '/']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) >= 2:
                        parts = lines[1].split()
                        if len(parts) >= 6:
                            total_kb = int(parts[1])
                            usado_kb = int(parts[2])
                            disponible_kb = int(parts[3])
                            porcentaje = float(parts[4].rstrip('%'))
                            
                            return {
                                'total_gb': total_kb // (1024 * 1024),
                                'usado_gb': usado_kb // (1024 * 1024),
                                'disponible_gb': disponible_kb // (1024 * 1024),
                                'porcentaje': porcentaje
                            }
                            
        except Exception as e:
            self.logger.warning(f"Error obteniendo uso de disco: {e}")
        
        return None

    def _monitorear_procesos(self):
        """Monitorear procesos del sistema y detectar comportamiento sospechoso."""
        try:
            procesos_actuales = {}
            procesos_sospechosos = []
            
            if self._herramientas.get('ps', False):
                cmd = ['ps', 'aux']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    
                    for line in lines:
                        partes = line.split(None, 10)
                        if len(partes) >= 11:
                            try:
                                usuario = partes[0]
                                pid = int(partes[1])
                                cpu = float(partes[2])
                                mem_kb = float(partes[5])  # VSZ en KB
                                comando = partes[10]
                                estado = partes[7] if len(partes) > 7 else 'unknown'
                                
                                # Extraer nombre del proceso
                                nombre = comando.split()[0] if comando else 'unknown'
                                nombre = os.path.basename(nombre)
                                
                                proceso_info = ProcesoInfo(
                                    pid=pid,
                                    nombre=nombre,
                                    usuario=usuario,
                                    uso_cpu=cpu,
                                    uso_memoria=int(mem_kb // 1024),  # Convertir a MB
                                    estado=estado
                                )
                                
                                procesos_actuales[pid] = proceso_info
                                
                                # Analizar si es sospechoso
                                if self._es_proceso_sospechoso(proceso_info):
                                    procesos_sospechosos.append(proceso_info)
                                    
                            except (ValueError, IndexError):
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
                                'uso_memoria': proceso.uso_memoria
                            }
                        )
                
        except Exception as e:
            self.logger.error(f"Error monitoreando procesos: {e}")

    def _monitorear_red(self):
        """Monitorear conexiones y estadísticas de red."""
        try:
            # Usar ss (preferido) o netstat como fallback
            conexiones_info = []
            
            if self._herramientas.get('ss', False):
                try:
                    cmd = ['ss', '-tuln']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        conexiones_info = self._parsear_salida_ss(result.stdout)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            # Fallback con netstat
            if not conexiones_info and self._herramientas.get('netstat', False):
                try:
                    cmd = ['netstat', '-tuln']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        conexiones_info = self._parsear_salida_netstat(result.stdout)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            # Procesar conexiones
            puertos_escucha = []
            conexiones_establecidas = 0
            
            for conn in conexiones_info:
                if conn.get('estado') == 'LISTEN':
                    puerto = conn.get('puerto_local')
                    if puerto and puerto not in puertos_escucha:
                        puertos_escucha.append(puerto)
                elif conn.get('estado') == 'ESTABLISHED':
                    conexiones_establecidas += 1
            
            # Crear estadísticas de red
            estadisticas = EstadisticasRed(
                timestamp=datetime.now(),
                conexiones_activas=len(conexiones_info),
                conexiones_establecidas=conexiones_establecidas,
                puertos_escucha=sorted(puertos_escucha),
                conexiones_sospechosas=[]  # Placeholder para análisis futuro
            )
            
            with self._lock:
                self.estadisticas_red_historicas.append(estadisticas)
            
        except Exception as e:
            self.logger.error(f"Error monitoreando red: {e}")

    def _parsear_salida_ss(self, salida: str) -> List[Dict[str, Any]]:
        """Parsear salida del comando ss."""
        conexiones = []
        
        for line in salida.split('\n')[1:]:  # Skip header
            if line.strip():
                partes = line.split()
                if len(partes) >= 4:
                    estado = partes[0]
                    direccion_local = partes[3]
                    
                    # Extraer puerto local
                    puerto_local = None
                    if ':' in direccion_local:
                        try:
                            puerto_local = int(direccion_local.split(':')[-1])
                        except ValueError:
                            pass
                    
                    conexiones.append({
                        'estado': estado,
                        'direccion_local': direccion_local,
                        'puerto_local': puerto_local
                    })
        
        return conexiones

    def _parsear_salida_netstat(self, salida: str) -> List[Dict[str, Any]]:
        """Parsear salida del comando netstat."""
        conexiones = []
        
        for line in salida.split('\n')[2:]:  # Skip headers
            if line.strip():
                partes = line.split()
                if len(partes) >= 6:
                    direccion_local = partes[3]
                    estado = partes[5] if len(partes) > 5 else 'UNKNOWN'
                    
                    # Extraer puerto local
                    puerto_local = None
                    if ':' in direccion_local:
                        try:
                            puerto_local = int(direccion_local.split(':')[-1])
                        except ValueError:
                            pass
                    
                    conexiones.append({
                        'estado': estado,
                        'direccion_local': direccion_local,
                        'puerto_local': puerto_local
                    })
        
        return conexiones

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
            
            return False
            
        except (ValueError, TypeError, AttributeError):
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
        # Placeholder para análisis más sofisticados
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
            datos = {
                'timestamp': datetime.now().isoformat()
            }
            
            # CPU
            cpu = self._obtener_uso_cpu()
            if cpu is not None:
                datos['cpu_porcentaje'] = float(cpu)
            
            # Memoria
            memoria = self._obtener_uso_memoria()
            if memoria:
                datos.update(memoria)
            
            # Disco
            disco = self._obtener_uso_disco()
            if disco:
                datos.update(disco)
            
            return datos
            
        except Exception as e:
            return {'error': str(e)}

    def _obtener_datos_red(self) -> Dict[str, Any]:
        """Obtener datos de red."""
        try:
            with self._lock:
                if self.estadisticas_red_historicas:
                    ultima_stat = list(self.estadisticas_red_historicas)[-1]
                    return {
                        'conexiones_totales': ultima_stat.conexiones_activas,
                        'conexiones_establecidas': ultima_stat.conexiones_establecidas,
                        'puertos_escucha': len(ultima_stat.puertos_escucha),
                        'timestamp': ultima_stat.timestamp.isoformat()
                    }
            
            return {
                'conexiones_totales': 0,
                'conexiones_establecidas': 0,
                'puertos_escucha': 0,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'error': str(e)}

    def _obtener_resumen_procesos(self) -> Dict[str, Any]:
        """Obtener resumen de procesos."""
        try:
            with self._lock:
                procesos = list(self.procesos_monitoreados.values())
            
            if not procesos:
                return {
                    'total_procesos': 0,
                    'top_cpu': [],
                    'top_memoria': [],
                    'timestamp': datetime.now().isoformat()
                }
            
            # Top 5 procesos por CPU
            top_cpu = sorted(
                procesos, 
                key=lambda x: x.uso_cpu, 
                reverse=True
            )[:5]
            
            # Top 5 procesos por memoria
            top_memoria = sorted(
                procesos, 
                key=lambda x: x.uso_memoria, 
                reverse=True
            )[:5]
            
            return {
                'total_procesos': len(procesos),
                'top_cpu': [{'pid': p.pid, 'nombre': p.nombre, 'cpu': p.uso_cpu} for p in top_cpu],
                'top_memoria': [{'pid': p.pid, 'nombre': p.nombre, 'memoria': p.uso_memoria} for p in top_memoria],
                'timestamp': datetime.now().isoformat()
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
                        'uso_memoria': proceso.uso_memoria
                    })
            
            return sospechosos

    def generar_reporte_monitor(self) -> str:
        """Generar reporte completo del monitor."""
        datos_sistema = self._obtener_datos_sistema()
        datos_red = self._obtener_datos_red()
        procesos_sospechosos = self.obtener_procesos_sospechosos()
        
        reporte = f"""
#  REPORTE DE MONITOREO - ARES AEGIS

##  ESTADO DEL SISTEMA
- **CPU**: {datos_sistema.get('cpu_porcentaje', 'N/A'):.1f}%
- **Memoria Usada**: {datos_sistema.get('porcentaje', 'N/A'):.1f}%
- **Disco Usado**: {datos_sistema.get('porcentaje', 'N/A'):.1f}%

##  ESTADO DE RED
- **Conexiones Totales**: {datos_red.get('conexiones_totales', 'N/A')}
- **Conexiones Establecidas**: {datos_red.get('conexiones_establecidas', 'N/A')}
- **Puertos en Escucha**: {datos_red.get('puertos_escucha', 'N/A')}

## ✓ PROCESOS SOSPECHOSOS ({len(procesos_sospechosos)})
"""
        
        if procesos_sospechosos:
            for proceso in procesos_sospechosos[:10]:  # Primeros 10
                reporte += f"- **{proceso['nombre']}** (PID: {proceso['pid']}) - CPU: {proceso['uso_cpu']:.1f}%, RAM: {proceso['uso_memoria']}MB\n"
        else:
            reporte += " No se detectaron procesos sospechosos.\n"
        
        reporte += f"\n---\n*Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return reporte


# Clase de compatibilidad
class Monitor(MonitorAvanzadoNativo):
    """Clase de compatibilidad con la interfaz original."""
    
    def __init__(self, siem=None):
        super().__init__(siem)
        self.datos_historicos = []
    
    def obtener_datos_sistema_recientes(self, limite: int = 10) -> List[Dict[str, Any]]:
        """Método de compatibilidad que convierte al formato esperado."""
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
