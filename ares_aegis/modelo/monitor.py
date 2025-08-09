# -*- coding: utf-8 -*-

import subprocess
import platform
import threading
import time
import os
import json
import re
from typing import Dict, List, Any, Optional
from collections import deque

class Monitor:
    def __init__(self):
        self.es_kali = self._detectar_kali()
        self.monitoreando = False
        self.monitoreando_red = False
        self.datos_monitoreo = deque(maxlen=1000)
        self.datos_red = deque(maxlen=500)
        self.alertas = deque(maxlen=100)
        self.hilo_monitor_sistema = None
        self.hilo_monitor_red = None
        
        # Configuración de alertas
        self.umbrales = {
            'cpu_alto': 80.0,
            'memoria_alta': 85.0,
            'conexiones_sospechosas': 50,
            'procesos_consumo_alto': 10
        }
        
        # Lista de procesos y conexiones sospechosos
        self.procesos_sospechosos = ['nc', 'netcat', 'ncat', 'telnet', 'ftp']
        self.puertos_sospechosos = [1234, 4444, 5555, 6666, 7777, 8888, 9999]
    
    def _detectar_kali(self) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            with open('/etc/os-release', 'r') as f:
                contenido = f.read().lower()
                return 'kali' in contenido or 'debian' in contenido
        except:
            return False
    
    def iniciar_monitoreo_completo(self) -> bool:
        resultado_sistema = self.iniciar_monitoreo_sistema()
        resultado_red = self.iniciar_monitoreo_red()
        return resultado_sistema and resultado_red
    
    def iniciar_monitoreo_sistema(self) -> bool:
        if self.monitoreando:
            return False
            
        self.monitoreando = True
        self.hilo_monitor_sistema = threading.Thread(target=self._monitorear_sistema, daemon=True)
        self.hilo_monitor_sistema.start()
        return True
    
    def iniciar_monitoreo_red(self) -> bool:
        if self.monitoreando_red:
            return False
            
        self.monitoreando_red = True
        self.hilo_monitor_red = threading.Thread(target=self._monitorear_red, daemon=True)
        self.hilo_monitor_red.start()
        return True
    
    def detener_monitoreo(self):
        self.monitoreando = False
        self.monitoreando_red = False
        
        if self.hilo_monitor_sistema and self.hilo_monitor_sistema.is_alive():
            self.hilo_monitor_sistema.join(timeout=3)
        if self.hilo_monitor_red and self.hilo_monitor_red.is_alive():
            self.hilo_monitor_red.join(timeout=3)
    
    def _monitorear_sistema(self):
        while self.monitoreando:
            try:
                datos = self._obtener_metricas_avanzadas()
                self.datos_monitoreo.append(datos)
                self._analizar_alertas_sistema(datos)
                time.sleep(3)
                
            except Exception as e:
                self.datos_monitoreo.append({
                    'timestamp': time.time(),
                    'error': str(e)
                })
                time.sleep(10)
    
    def _monitorear_red(self):
        while self.monitoreando_red:
            try:
                datos_red = self._obtener_metricas_red()
                self.datos_red.append(datos_red)
                self._analizar_alertas_red(datos_red)
                time.sleep(5)
                
            except Exception as e:
                self.datos_red.append({
                    'timestamp': time.time(),
                    'error': str(e)
                })
                time.sleep(15)
    
    def _obtener_metricas_avanzadas(self) -> Dict[str, Any]:
        timestamp = time.time()
        datos = {
            'timestamp': timestamp,
            'cpu_porcentaje': 0.0,
            'memoria_total': 0,
            'memoria_usada': 0,
            'memoria_porcentaje': 0.0,
            'procesos_activos': 0,
            'carga_sistema': [0.0, 0.0, 0.0],
            'disco_uso': 0.0,
            'procesos_cpu_alto': [],
            'procesos_memoria_alta': []
        }
        
        if not self.es_kali:
            return datos
        
        try:
            # Memoria usando free
            mem_cmd = ["free", "-m"]
            mem_result = subprocess.run(mem_cmd, capture_output=True, text=True, timeout=5)
            
            if mem_result.returncode == 0:
                for linea in mem_result.stdout.split('\n'):
                    if 'Mem:' in linea:
                        partes = linea.split()
                        if len(partes) >= 3:
                            total = int(partes[1])
                            usado = int(partes[2])
                            datos['memoria_total'] = total
                            datos['memoria_usada'] = usado
                            datos['memoria_porcentaje'] = (usado / total) * 100
                        break
            
            # Carga del sistema
            with open('/proc/loadavg', 'r') as f:
                carga = f.read().strip().split()[:3]
                datos['carga_sistema'] = [float(x) for x in carga]
            
            # CPU usando vmstat
            cpu_cmd = ["vmstat", "1", "2"]
            cpu_result = subprocess.run(cpu_cmd, capture_output=True, text=True, timeout=10)
            
            if cpu_result.returncode == 0:
                lineas = cpu_result.stdout.strip().split('\n')
                if len(lineas) >= 4:
                    ultima_linea = lineas[-1].split()
                    if len(ultima_linea) >= 15:
                        idle = float(ultima_linea[14])
                        datos['cpu_porcentaje'] = 100.0 - idle
            
            # Procesos con alto consumo
            proc_cmd = ["ps", "aux", "--sort=-%cpu", "--no-headers"]
            proc_result = subprocess.run(proc_cmd, capture_output=True, text=True, timeout=10)
            
            if proc_result.returncode == 0:
                lineas = proc_result.stdout.strip().split('\n')
                datos['procesos_activos'] = len(lineas)
                
                for linea in lineas[:10]:
                    partes = linea.split(None, 10)
                    if len(partes) >= 11:
                        cpu_uso = float(partes[2])
                        mem_uso = float(partes[3])
                        
                        if cpu_uso > 10.0:
                            datos['procesos_cpu_alto'].append({
                                'pid': partes[1],
                                'usuario': partes[0],
                                'cpu': cpu_uso,
                                'comando': partes[10][:50]
                            })
                        
                        if mem_uso > 5.0:
                            datos['procesos_memoria_alta'].append({
                                'pid': partes[1],
                                'usuario': partes[0],
                                'memoria': mem_uso,
                                'comando': partes[10][:50]
                            })
            
            # Uso de disco
            disk_cmd = ["df", "-h", "/"]
            disk_result = subprocess.run(disk_cmd, capture_output=True, text=True, timeout=5)
            
            if disk_result.returncode == 0:
                lineas = disk_result.stdout.split('\n')
                if len(lineas) >= 2:
                    partes = lineas[1].split()
                    if len(partes) >= 5:
                        uso_str = partes[4].replace('%', '')
                        datos['disco_uso'] = float(uso_str)
                        
        except Exception:
            pass
        
        return datos
    
    def _obtener_metricas_red(self) -> Dict[str, Any]:
        timestamp = time.time()
        datos = {
            'timestamp': timestamp,
            'conexiones_activas': [],
            'conexiones_escuchando': [],
            'conexiones_sospechosas': [],
            'estadisticas_interfaces': {},
            'total_conexiones': 0
        }
        
        if not self.es_kali:
            return datos
        
        try:
            # Conexiones usando ss
            ss_cmd = ["ss", "-tuap"]
            ss_result = subprocess.run(ss_cmd, capture_output=True, text=True, timeout=10)
            
            if ss_result.returncode == 0:
                for linea in ss_result.stdout.split('\n')[1:]:
                    if linea.strip():
                        partes = linea.split()
                        if len(partes) >= 5:
                            protocolo = partes[0]
                            estado = partes[1]
                            local = partes[4]
                            remoto = partes[5] if len(partes) > 5 else ''
                            
                            conexion = {
                                'protocolo': protocolo,
                                'estado': estado,
                                'local': local,
                                'remoto': remoto
                            }
                            
                            if 'LISTEN' in estado:
                                datos['conexiones_escuchando'].append(conexion)
                                # Verificar puertos sospechosos
                                puerto_local = self._extraer_puerto(local)
                                if puerto_local in self.puertos_sospechosos:
                                    datos['conexiones_sospechosas'].append({
                                        **conexion,
                                        'razon': f'Puerto sospechoso: {puerto_local}'
                                    })
                            elif 'ESTAB' in estado:
                                datos['conexiones_activas'].append(conexion)
                
                datos['total_conexiones'] = len(datos['conexiones_activas']) + len(datos['conexiones_escuchando'])
            
            # Estadísticas de interfaces usando ip
            ip_cmd = ["ip", "-s", "link"]
            ip_result = subprocess.run(ip_cmd, capture_output=True, text=True, timeout=5)
            
            if ip_result.returncode == 0:
                interfaces = self._parsear_estadisticas_interfaces(ip_result.stdout)
                datos['estadisticas_interfaces'] = interfaces
                
        except Exception:
            pass
        
        return datos
    
    def _extraer_puerto(self, direccion: str) -> int:
        try:
            if ':' in direccion:
                return int(direccion.split(':')[-1])
        except:
            pass
        return 0
    
    def _parsear_estadisticas_interfaces(self, salida_ip: str) -> Dict[str, Dict[str, int]]:
        interfaces = {}
        lineas = salida_ip.split('\n')
        interfaz_actual = None
        
        for i, linea in enumerate(lineas):
            if re.match(r'^\d+:', linea):
                match = re.search(r'(\w+):', linea)
                if match:
                    interfaz_actual = match.group(1)
                    interfaces[interfaz_actual] = {}
            
            elif interfaz_actual and 'RX:' in linea and i + 1 < len(lineas):
                try:
                    stats_line = lineas[i + 1].strip().split()
                    if len(stats_line) >= 2:
                        interfaces[interfaz_actual]['rx_bytes'] = int(stats_line[0])
                        interfaces[interfaz_actual]['rx_packets'] = int(stats_line[1])
                except:
                    pass
            
            elif interfaz_actual and 'TX:' in linea and i + 1 < len(lineas):
                try:
                    stats_line = lineas[i + 1].strip().split()
                    if len(stats_line) >= 2:
                        interfaces[interfaz_actual]['tx_bytes'] = int(stats_line[0])
                        interfaces[interfaz_actual]['tx_packets'] = int(stats_line[1])
                except:
                    pass
        
        return interfaces
    
    def _analizar_alertas_sistema(self, datos: Dict[str, Any]):
        alertas_nuevas = []
        
        # Alerta por CPU alta
        if datos['cpu_porcentaje'] > self.umbrales['cpu_alto']:
            alertas_nuevas.append({
                'tipo': 'CPU_ALTA',
                'timestamp': datos['timestamp'],
                'valor': datos['cpu_porcentaje'],
                'umbral': self.umbrales['cpu_alto'],
                'mensaje': f"CPU alta: {datos['cpu_porcentaje']:.1f}%"
            })
        
        # Alerta por memoria alta
        if datos['memoria_porcentaje'] > self.umbrales['memoria_alta']:
            alertas_nuevas.append({
                'tipo': 'MEMORIA_ALTA',
                'timestamp': datos['timestamp'],
                'valor': datos['memoria_porcentaje'],
                'umbral': self.umbrales['memoria_alta'],
                'mensaje': f"Memoria alta: {datos['memoria_porcentaje']:.1f}%"
            })
        
        # Alerta por procesos sospechosos
        for proceso in datos['procesos_cpu_alto']:
            comando = proceso['comando'].lower()
            for sospechoso in self.procesos_sospechosos:
                if sospechoso in comando:
                    alertas_nuevas.append({
                        'tipo': 'PROCESO_SOSPECHOSO',
                        'timestamp': datos['timestamp'],
                        'proceso': proceso,
                        'mensaje': f"Proceso sospechoso detectado: {proceso['comando'][:30]}"
                    })
        
        for alerta in alertas_nuevas:
            self.alertas.append(alerta)
    
    def _analizar_alertas_red(self, datos: Dict[str, Any]):
        alertas_nuevas = []
        
        # Alerta por muchas conexiones
        if datos['total_conexiones'] > self.umbrales['conexiones_sospechosas']:
            alertas_nuevas.append({
                'tipo': 'CONEXIONES_ALTAS',
                'timestamp': datos['timestamp'],
                'valor': datos['total_conexiones'],
                'umbral': self.umbrales['conexiones_sospechosas'],
                'mensaje': f"Muchas conexiones activas: {datos['total_conexiones']}"
            })
        
        # Alertas por conexiones sospechosas
        for conexion in datos['conexiones_sospechosas']:
            alertas_nuevas.append({
                'tipo': 'CONEXION_SOSPECHOSA',
                'timestamp': datos['timestamp'],
                'conexion': conexion,
                'mensaje': f"Conexión sospechosa: {conexion['razon']}"
            })
        
        for alerta in alertas_nuevas:
            self.alertas.append(alerta)
    
    def obtener_datos_sistema_recientes(self, limite: int = 50) -> List[Dict[str, Any]]:
        return list(self.datos_monitoreo)[-limite:]
    
    def obtener_datos_red_recientes(self, limite: int = 30) -> List[Dict[str, Any]]:
        return list(self.datos_red)[-limite:]
    
    def obtener_alertas_recientes(self, limite: int = 20) -> List[Dict[str, Any]]:
        return list(self.alertas)[-limite:]
    
    def obtener_resumen_estado(self) -> Dict[str, Any]:
        datos_recientes = self.obtener_datos_sistema_recientes(1)
        alertas_recientes = self.obtener_alertas_recientes(10)
        
        if not datos_recientes:
            return {'error': 'No hay datos de monitoreo disponibles'}
        
        ultimo_dato = datos_recientes[0]
        
        return {
            'estado_general': 'CRITICO' if len(alertas_recientes) > 5 else 'NORMAL',
            'cpu_actual': ultimo_dato.get('cpu_porcentaje', 0),
            'memoria_actual': ultimo_dato.get('memoria_porcentaje', 0),
            'procesos_activos': ultimo_dato.get('procesos_activos', 0),
            'alertas_activas': len(alertas_recientes),
            'monitoreando_sistema': self.monitoreando,
            'monitoreando_red': self.monitoreando_red,
            'timestamp': ultimo_dato.get('timestamp', time.time())
        }

# RESUMEN: Monitor avanzado de sistema y red que utiliza herramientas nativas de Linux para
# supervisión en tiempo real, detección de anomalías y generación de alertas automatizadas.