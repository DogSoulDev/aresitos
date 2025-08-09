# -*- coding: utf-8 -*-

import subprocess
import os
import platform
import json
import time
from typing import Dict, List, Any, Optional

class Escaneador:
    def __init__(self):
        self.es_kali = self._detectar_kali()
        self.herramientas_kali = {
            'nmap': '/usr/bin/nmap',
            'netstat': '/bin/netstat', 
            'ss': '/bin/ss',
            'lsof': '/usr/bin/lsof',
            'ps': '/bin/ps',
            'nikto': '/usr/bin/nikto',
            'dirb': '/usr/bin/dirb',
            'gobuster': '/usr/bin/gobuster'
        }
    
    def _detectar_kali(self) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            with open('/etc/os-release', 'r') as f:
                contenido = f.read().lower()
                return 'kali' in contenido or 'debian' in contenido
        except:
            return False
    
    def _verificar_herramienta(self, herramienta: str) -> bool:
        try:
            subprocess.run(['which', herramienta], capture_output=True, check=True)
            return True
        except:
            return False
    
    def escanear_puertos_nmap(self, host: str = "127.0.0.1", puertos: str = "1-1000") -> Dict[str, Any]:
        if not self.es_kali or not self._verificar_herramienta('nmap'):
            return {'error': 'nmap unavailable', 'resultados': []}
        
        try:
            cmd = ['nmap', '-sS', '-sV', '-p', puertos, host]
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if resultado.returncode == 0:
                return {
                    'host': host,
                    'puertos_escaneados': puertos,
                    'salida_completa': resultado.stdout,
                    'puertos_abiertos': self._parsear_puertos_nmap(resultado.stdout),
                    'timestamp': time.time()
                }
            else:
                return {'error': f'nmap falló: {resultado.stderr}', 'resultados': []}
                
        except subprocess.TimeoutExpired:
            return {'error': 'nmap scan timeout', 'resultados': []}
        except Exception as e:
            return {'error': f'Error ejecutando nmap: {str(e)}', 'resultados': []}
    
    def _parsear_puertos_nmap(self, salida_nmap: str) -> List[Dict[str, str]]:
        puertos = []
        for linea in salida_nmap.split('\n'):
            if '/tcp' in linea and 'open' in linea:
                partes = linea.split()
                if len(partes) >= 3:
                    puerto = partes[0].split('/')[0]
                    estado = partes[1]
                    servicio = partes[2] if len(partes) > 2 else 'desconocido'
                    puertos.append({
                        'puerto': puerto,
                        'estado': estado,
                        'servicio': servicio
                    })
        return puertos
    
    def escanear_puertos_ss(self) -> Dict[str, Any]:
        if not self.es_kali:
            return {'error': 'Unsupported system', 'resultados': []}
        
        try:
            cmd = ['ss', '-tuln']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if resultado.returncode == 0:
                puertos_tcp = []
                puertos_udp = []
                
                for linea in resultado.stdout.split('\n')[1:]:
                    if linea.strip():
                        partes = linea.split()
                        if len(partes) >= 5:
                            protocolo = partes[0]
                            estado = partes[1]
                            direccion_local = partes[4]
                            
                            if protocolo.startswith('tcp'):
                                puertos_tcp.append({
                                    'protocolo': protocolo,
                                    'estado': estado,
                                    'direccion': direccion_local
                                })
                            elif protocolo.startswith('udp'):
                                puertos_udp.append({
                                    'protocolo': protocolo,
                                    'estado': estado,
                                    'direccion': direccion_local
                                })
                
                return {
                    'puertos_tcp': puertos_tcp,
                    'puertos_udp': puertos_udp,
                    'total_tcp': len(puertos_tcp),
                    'total_udp': len(puertos_udp),
                    'timestamp': time.time()
                }
            else:
                return {'error': f'ss falló: {resultado.stderr}', 'resultados': []}
                
        except Exception as e:
            return {'error': f'Error ejecutando ss: {str(e)}', 'resultados': []}
    
    def escanear_procesos_avanzado(self) -> Dict[str, Any]:
        if not self.es_kali:
            return {'error': 'Unsupported system', 'resultados': []}
        
        try:
            cmd = ['ps', 'aux', '--sort=-%cpu']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if resultado.returncode == 0:
                procesos = []
                lineas = resultado.stdout.split('\n')[1:]
                
                for linea in lineas[:50]:
                    if linea.strip():
                        partes = linea.split(None, 10)
                        if len(partes) >= 11:
                            procesos.append({
                                'usuario': partes[0],
                                'pid': partes[1],
                                'cpu': partes[2],
                                'memoria': partes[3],
                                'comando': partes[10]
                            })
                
                return {
                    'procesos': procesos,
                    'total_procesos': len(procesos),
                    'timestamp': time.time()
                }
            else:
                return {'error': f'ps falló: {resultado.stderr}', 'resultados': []}
                
        except Exception as e:
            return {'error': f'Error ejecutando ps: {str(e)}', 'resultados': []}
    
    def escanear_conexiones_red(self) -> Dict[str, Any]:
        if not self.es_kali:
            return {'error': 'Unsupported system', 'resultados': []}
        
        try:
            cmd = ['ss', '-tuap']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if resultado.returncode == 0:
                conexiones = []
                for linea in resultado.stdout.split('\n')[1:]:
                    if 'ESTAB' in linea or 'LISTEN' in linea:
                        partes = linea.split()
                        if len(partes) >= 5:
                            conexiones.append({
                                'protocolo': partes[0],
                                'estado': partes[1],
                                'local': partes[4],
                                'remoto': partes[5] if len(partes) > 5 else 'N/A'
                            })
                
                return {
                    'conexiones': conexiones,
                    'total_conexiones': len(conexiones),
                    'timestamp': time.time()
                }
            else:
                return {'error': f'ss falló: {resultado.stderr}', 'resultados': []}
                
        except Exception as e:
            return {'error': f'Error ejecutando ss: {str(e)}', 'resultados': []}
    
    def escanear_servicios_activos(self) -> Dict[str, Any]:
        if not self.es_kali:
            return {'error': 'Unsupported system', 'resultados': []}
        
        try:
            cmd = ['systemctl', 'list-units', '--type=service', '--state=active']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if resultado.returncode == 0:
                servicios = []
                for linea in resultado.stdout.split('\n')[1:]:
                    if '.service' in linea and 'active' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            servicios.append({
                                'servicio': partes[0],
                                'estado': partes[2],
                                'sub_estado': partes[3],
                                'descripcion': ' '.join(partes[4:]) if len(partes) > 4 else ''
                            })
                
                return {
                    'servicios': servicios,
                    'total_servicios': len(servicios),
                    'timestamp': time.time()
                }
            else:
                return {'error': f'systemctl falló: {resultado.stderr}', 'resultados': []}
                
        except Exception as e:
            return {'error': f'Error ejecutando systemctl: {str(e)}', 'resultados': []}
    
    def escanear_vulnerabilidades_web(self, url: str) -> Dict[str, Any]:
        if not self.es_kali or not self._verificar_herramienta('nikto'):
            return {'error': 'nikto no disponible', 'resultados': []}
        
        try:
            cmd = ['nikto', '-h', url, '-Format', 'txt']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if resultado.returncode == 0:
                return {
                    'url': url,
                    'reporte_nikto': resultado.stdout,
                    'timestamp': time.time()
                }
            else:
                return {'error': f'nikto falló: {resultado.stderr}', 'resultados': []}
                
        except subprocess.TimeoutExpired:
            return {'error': 'Timeout en escaneo nikto', 'resultados': []}
        except Exception as e:
            return {'error': f'Error ejecutando nikto: {str(e)}', 'resultados': []}

# RESUMEN: Escaneador profesional optimizado para Kali Linux que utiliza nmap, ss, nikto y
# herramientas nativas para escaneos avanzados de puertos, procesos, servicios y vulnerabilidades web.

