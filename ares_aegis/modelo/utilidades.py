# -*- coding: utf-8 -*-

import subprocess
import os
import platform
import json
import datetime
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

class Utilidades:
    def __init__(self):
        self.es_kali = self._detectar_kali()
        self.herramientas_kali = self._definir_herramientas_kali()
        self.archivos_criticos = self._definir_archivos_criticos()
        self.servicios_criticos = self._definir_servicios_criticos()
    
    def _detectar_kali(self) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            with open('/etc/os-release', 'r') as f:
                contenido = f.read().lower()
                return any(distro in contenido for distro in ['kali', 'debian', 'ubuntu'])
        except:
            return False
    
    def _definir_herramientas_kali(self) -> Dict[str, Dict[str, Any]]:
        return {
            'red': {
                'nmap': {'descripcion': 'Escaneador de puertos y servicios', 'critico': True},
                'netstat': {'descripcion': 'Estadísticas de red', 'critico': True},
                'ss': {'descripcion': 'Utilidad moderna para sockets', 'critico': True},
                'iptables': {'descripcion': 'Firewall de Linux', 'critico': True},
                'wireshark': {'descripcion': 'Analizador de protocolos', 'critico': False},
                'tcpdump': {'descripcion': 'Capturador de paquetes', 'critico': True},
                'netcat': {'descripcion': 'Navaja suiza de TCP/IP', 'critico': True}
            },
            'seguridad': {
                'lynis': {'descripcion': 'Auditor de seguridad del sistema', 'critico': True},
                'chkrootkit': {'descripcion': 'Detector de rootkits', 'critico': True},
                'rkhunter': {'descripcion': 'Cazador de rootkits', 'critico': True},
                'fail2ban': {'descripcion': 'Prevención de intrusiones', 'critico': False},
                'aide': {'descripcion': 'Detector de intrusiones', 'critico': False}
            },
            'web': {
                'nikto': {'descripcion': 'Escaneador de vulnerabilidades web', 'critico': False},
                'sqlmap': {'descripcion': 'Herramienta de inyección SQL', 'critico': False},
                'dirb': {'descripcion': 'Escaneador de directorios web', 'critico': False},
                'gobuster': {'descripcion': 'Enumerador de directorios', 'critico': False}
            },
            'forense': {
                'dd': {'descripcion': 'Copia bit a bit', 'critico': True},
                'file': {'descripcion': 'Identificador de tipos de archivo', 'critico': True},
                'strings': {'descripcion': 'Extractor de cadenas', 'critico': True},
                'hexdump': {'descripcion': 'Volcado hexadecimal', 'critico': True}
            }
        }
    
    def _definir_archivos_criticos(self) -> Dict[str, Dict[str, Any]]:
        return {
            '/etc/passwd': {'descripcion': 'Base de datos de usuarios', 'permisos_esperados': '644'},
            '/etc/shadow': {'descripcion': 'Contraseñas cifradas', 'permisos_esperados': '640'},
            '/etc/group': {'descripcion': 'Grupos del sistema', 'permisos_esperados': '644'},
            '/etc/sudoers': {'descripcion': 'Configuración sudo', 'permisos_esperados': '440'},
            '/etc/ssh/sshd_config': {'descripcion': 'Configuración SSH', 'permisos_esperados': '644'},
            '/etc/hosts': {'descripcion': 'Resolución local de nombres', 'permisos_esperados': '644'},
            '/etc/fstab': {'descripcion': 'Sistemas de archivos', 'permisos_esperados': '644'},
            '/etc/crontab': {'descripcion': 'Tareas programadas', 'permisos_esperados': '644'},
            '/etc/hosts.allow': {'descripcion': 'Hosts permitidos', 'permisos_esperados': '644'},
            '/etc/hosts.deny': {'descripcion': 'Hosts denegados', 'permisos_esperados': '644'}
        }
    
    def _definir_servicios_criticos(self) -> Dict[str, str]:
        return {
            'ssh': 'Servicio SSH',
            'systemd-networkd': 'Gestión de red',
            'systemd-resolved': 'Resolución DNS',
            'cron': 'Tareas programadas',
            'rsyslog': 'Sistema de logs',
            'ufw': 'Firewall no complicado',
            'fail2ban': 'Prevención de intrusiones'
        }
    
    def verificar_herramientas_kali_completo(self) -> Dict[str, Any]:
        resultados = {
            'resumen': {'total': 0, 'disponibles': 0, 'criticas_disponibles': 0, 'criticas_total': 0},
            'categorias': {},
            'recomendaciones': []
        }
        
        for categoria, herramientas in self.herramientas_kali.items():
            resultados['categorias'][categoria] = {
                'herramientas': {},
                'disponibles': 0,
                'total': len(herramientas),
                'criticas_disponibles': 0,
                'criticas_total': 0
            }
            
            for herramienta, info in herramientas.items():
                disponible = self._verificar_herramienta_disponible(herramienta)
                version = self._obtener_version_herramienta(herramienta) if disponible else None
                
                resultados['categorias'][categoria]['herramientas'][herramienta] = {
                    'disponible': disponible,
                    'descripcion': info['descripcion'],
                    'critico': info['critico'],
                    'version': version,
                    'ruta': self._obtener_ruta_herramienta(herramienta) if disponible else None
                }
                
                resultados['resumen']['total'] += 1
                resultados['categorias'][categoria]['total'] = len(herramientas)
                
                if disponible:
                    resultados['resumen']['disponibles'] += 1
                    resultados['categorias'][categoria]['disponibles'] += 1
                
                if info['critico']:
                    resultados['resumen']['criticas_total'] += 1
                    resultados['categorias'][categoria]['criticas_total'] += 1
                    if disponible:
                        resultados['resumen']['criticas_disponibles'] += 1
                        resultados['categorias'][categoria]['criticas_disponibles'] += 1
        
        # Generar recomendaciones
        resultados['recomendaciones'] = self._generar_recomendaciones_herramientas(resultados)
        
        return resultados
    
    def _verificar_herramienta_disponible(self, herramienta: str) -> bool:
        try:
            resultado = subprocess.run(['which', herramienta], 
                                     capture_output=True, timeout=5)
            return resultado.returncode == 0
        except:
            return False
    
    def _obtener_version_herramienta(self, herramienta: str) -> Optional[str]:
        comandos_version = {
            'nmap': ['nmap', '--version'],
            'nikto': ['nikto', '-Version'],
            'lynis': ['lynis', '--version'],
            'default': [herramienta, '--version']
        }
        
        cmd = comandos_version.get(herramienta, comandos_version['default'])
        
        try:
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if resultado.returncode == 0:
                # Extraer número de versión
                patron_version = r'(\d+\.\d+(?:\.\d+)?)'
                match = re.search(patron_version, resultado.stdout)
                return match.group(1) if match else 'Detectada'
        except:
            pass
        return None
    
    def _obtener_ruta_herramienta(self, herramienta: str) -> Optional[str]:
        try:
            resultado = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
            return resultado.stdout.strip() if resultado.returncode == 0 else None
        except:
            return None
    
    def _generar_recomendaciones_herramientas(self, resultados: Dict[str, Any]) -> List[str]:
        recomendaciones = []
        
        if resultados['resumen']['criticas_disponibles'] < resultados['resumen']['criticas_total']:
            faltantes = resultados['resumen']['criticas_total'] - resultados['resumen']['criticas_disponibles']
            recomendaciones.append(f"AVISO: Faltan {faltantes} herramientas críticas. Instalar con: apt install <herramienta>")
        
        for categoria, info in resultados['categorias'].items():
            if info['criticas_disponibles'] < info['criticas_total']:
                recomendaciones.append(f"Categoria {categoria}: Instalar herramientas faltantes")
        
        if resultados['resumen']['disponibles'] == resultados['resumen']['total']:
            recomendaciones.append("Todas las herramientas están disponibles")
        
        return recomendaciones
    
    def ejecutar_auditoria_completa_lynis(self) -> Dict[str, Any]:
        if not self._verificar_herramienta_disponible('lynis'):
            return {'exito': False, 'error': 'lynis unavailable'}
        
        try:
            # Ejecutar auditoría completa con opciones avanzadas
            cmd = ['sudo', 'lynis', 'audit', 'system', '--auditor', 'Aresitos', 
                   '--pentest', '--quick', '--quiet']
            
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if resultado.returncode == 0:
                analisis = self._parsear_salida_lynis(resultado.stdout)
                return {
                    'exito': True,
                    'analisis': analisis,
                    'salida_completa': resultado.stdout,
                    'warnings': resultado.stderr
                }
            else:
                return {
                    'exito': False,
                    'error': f'Lynis falló con código {resultado.returncode}',
                    'salida': resultado.stderr
                }
        except subprocess.TimeoutExpired:
            return {'exito': False, 'error': 'lynis timeout (5min)'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def _parsear_salida_lynis(self, salida: str) -> Dict[str, Any]:
        analisis = {
            'puntuacion': None,
            'warnings': [],
            'sugerencias': [],
            'hardening_index': None,
            'tests_realizados': 0,
            'categorias': defaultdict(list)
        }
        
        lineas = salida.split('\n')
        
        for linea in lineas:
            # Extraer puntuación
            if 'Hardening index' in linea:
                match = re.search(r'(\d+)', linea)
                if match:
                    analisis['hardening_index'] = int(match.group(1))
            
            # Extraer warnings
            elif '[WARNING]' in linea:
                analisis['warnings'].append(linea.replace('[WARNING]', '').strip())
            
            # Extraer sugerencias
            elif '[SUGGESTION]' in linea:
                analisis['sugerencias'].append(linea.replace('[SUGGESTION]', '').strip())
            
            # Contar tests
            elif 'Performing test ID' in linea:
                analisis['tests_realizados'] += 1
        
        return analisis
    
    def ejecutar_deteccion_rootkits_completa(self) -> Dict[str, Any]:
        herramientas = ['chkrootkit', 'rkhunter']
        resultados = {}
        
        for herramienta in herramientas:
            if self._verificar_herramienta_disponible(herramienta):
                resultados[herramienta] = self._ejecutar_detector_rootkit(herramienta)
            else:
                resultados[herramienta] = {'disponible': False}
        
        # Análisis combinado
        analisis_combinado = self._analizar_resultados_rootkits(resultados)
        
        return {
            'herramientas': resultados,
            'analisis_combinado': analisis_combinado
        }
    
    def _ejecutar_detector_rootkit(self, herramienta: str) -> Dict[str, Any]:
        comandos = {
            'chkrootkit': ['sudo', 'chkrootkit', '-q'],
            'rkhunter': ['sudo', 'rkhunter', '--check', '--skip-keypress', '--quiet']
        }
        
        try:
            cmd = comandos[herramienta]
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            return {
                'disponible': True,
                'exito': True,
                'codigo_salida': resultado.returncode,
                'salida': resultado.stdout,
                'detecciones': self._parsear_detecciones_rootkit(herramienta, resultado.stdout),
                'tiempo_ejecucion': time.time()
            }
        except subprocess.TimeoutExpired:
            return {'disponible': True, 'exito': False, 'error': 'timeout (2min)'}
        except Exception as e:
            return {'disponible': True, 'exito': False, 'error': str(e)}
    
    def _parsear_detecciones_rootkit(self, herramienta: str, salida: str) -> List[Dict[str, str]]:
        detecciones = []
        lineas = salida.split('\n')
        
        if herramienta == 'chkrootkit':
            for linea in lineas:
                if 'INFECTED' in linea or 'infected' in linea:
                    detecciones.append({
                        'tipo': 'ROOTKIT_DETECTADO',
                        'descripcion': linea.strip(),
                        'severidad': 'CRITICA'
                    })
        
        elif herramienta == 'rkhunter':
            for linea in lineas:
                if 'Warning:' in linea or 'WARNING:' in linea:
                    detecciones.append({
                        'tipo': 'WARNING',
                        'descripcion': linea.strip(),
                        'severidad': 'MEDIA'
                    })
        
        return detecciones
    
    def _analizar_resultados_rootkits(self, resultados: Dict[str, Any]) -> Dict[str, Any]:
        analisis = {
            'estado_general': 'LIMPIO',
            'total_detecciones': 0,
            'detecciones_criticas': 0,
            'herramientas_ejecutadas': 0,
            'recomendaciones': []
        }
        
        for herramienta, resultado in resultados.items():
            if resultado.get('disponible'):
                analisis['herramientas_ejecutadas'] += 1
                
                if resultado.get('exito'):
                    detecciones = resultado.get('detecciones', [])
                    analisis['total_detecciones'] += len(detecciones)
                    
                    for deteccion in detecciones:
                        if deteccion['severidad'] == 'CRITICA':
                            analisis['detecciones_criticas'] += 1
                            analisis['estado_general'] = 'COMPROMETIDO'
        
        if analisis['detecciones_criticas'] > 0:
            analisis['recomendaciones'].append("🚨 CRÍTICO: Posibles rootkits detectados. Análisis forense necesario.")
        elif analisis['total_detecciones'] > 0:
            analisis['recomendaciones'].append("AVISO: Warnings detectados. Revisar manualmente.")
        else:
            analisis['recomendaciones'].append("No se detectaron rootkits.")
        
        return analisis
    
    def analizar_servicios_sistema_avanzado(self) -> Dict[str, Any]:
        analisis = {
            'servicios_activos': [],
            'servicios_criticos': {},
            'servicios_sospechosos': [],
            'puertos_abiertos': [],
            'recomendaciones': []
        }
        
        # Obtener servicios activos
        servicios_activos = self._obtener_servicios_activos()
        analisis['servicios_activos'] = servicios_activos
        
        # Analizar servicios críticos
        for servicio, descripcion in self.servicios_criticos.items():
            estado = self._verificar_estado_servicio(servicio)
            analisis['servicios_criticos'][servicio] = {
                'descripcion': descripcion,
                'activo': estado['activo'],
                'habilitado': estado['habilitado'],
                'estado_detallado': estado
            }
        
        # Detectar servicios sospechosos
        analisis['servicios_sospechosos'] = self._detectar_servicios_sospechosos(servicios_activos)
        
        # Obtener puertos abiertos
        analisis['puertos_abiertos'] = self._obtener_puertos_abiertos()
        
        # Generar recomendaciones
        analisis['recomendaciones'] = self._generar_recomendaciones_servicios(analisis)
        
        return analisis
    
    def _obtener_servicios_activos(self) -> List[Dict[str, Any]]:
        try:
            cmd = ['systemctl', 'list-units', '--type=service', '--state=active', '--no-pager']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            servicios = []
            if resultado.returncode == 0:
                lineas = resultado.stdout.split('\n')
                for linea in lineas:
                    if '.service' in linea and 'active' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            servicios.append({
                                'nombre': partes[0].replace('.service', ''),
                                'load': partes[1],
                                'active': partes[2],
                                'sub': partes[3],
                                'descripcion': ' '.join(partes[4:]) if len(partes) > 4 else ''
                            })
            return servicios
        except Exception:
            return []
    
    def _verificar_estado_servicio(self, servicio: str) -> Dict[str, Any]:
        try:
            # Verificar si está activo
            cmd_activo = ['systemctl', 'is-active', servicio]
            resultado_activo = subprocess.run(cmd_activo, capture_output=True, text=True, timeout=10)
            
            # Verificar si está habilitado
            cmd_habilitado = ['systemctl', 'is-enabled', servicio]
            resultado_habilitado = subprocess.run(cmd_habilitado, capture_output=True, text=True, timeout=10)
            
            return {
                'activo': resultado_activo.returncode == 0,
                'habilitado': resultado_habilitado.returncode == 0,
                'estado_activo': resultado_activo.stdout.strip(),
                'estado_habilitado': resultado_habilitado.stdout.strip()
            }
        except Exception:
            return {'activo': False, 'habilitado': False, 'error': True}
    
    def _detectar_servicios_sospechosos(self, servicios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        patrones_sospechosos = [
            r'.*backdoor.*', r'.*malware.*', r'.*trojan.*',
            r'.*tmp.*', r'.*\.sh$', r'.*nc$', r'.*netcat.*'
        ]
        
        sospechosos = []
        for servicio in servicios:
            nombre = servicio['nombre'].lower()
            for patron in patrones_sospechosos:
                if re.match(patron, nombre):
                    sospechosos.append({
                        'servicio': servicio,
                        'razon': f'Coincide con patrón sospechoso: {patron}',
                        'severidad': 'ALTA'
                    })
                    break
        
        return sospechosos
    
    def _obtener_puertos_abiertos(self) -> List[Dict[str, Any]]:
        try:
            cmd = ['ss', '-tuln']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            puertos = []
            if resultado.returncode == 0:
                lineas = resultado.stdout.split('\n')[1:]  # Saltar cabecera
                for linea in lineas:
                    if linea.strip():
                        partes = linea.split()
                        if len(partes) >= 5:
                            puertos.append({
                                'protocolo': partes[0],
                                'estado': partes[1],
                                'local': partes[4],
                                'peer': partes[5] if len(partes) > 5 else ''
                            })
            return puertos
        except Exception:
            return []
    
    def _generar_recomendaciones_servicios(self, analisis: Dict[str, Any]) -> List[str]:
        recomendaciones = []
        
        if analisis['servicios_sospechosos']:
            recomendaciones.append(f"🚨 {len(analisis['servicios_sospechosos'])} servicios sospechosos detectados")
        
        servicios_criticos_inactivos = [
            s for s, info in analisis['servicios_criticos'].items() 
            if not info['activo']
        ]
        
        if servicios_criticos_inactivos:
            recomendaciones.append(f"AVISO: Servicios críticos inactivos: {', '.join(servicios_criticos_inactivos)}")
        
        puertos_abiertos_count = len(analisis['puertos_abiertos'])
        if puertos_abiertos_count > 20:
            recomendaciones.append(f"REVISION: {puertos_abiertos_count} puertos abiertos. Revisar si son necesarios.")
        
        return recomendaciones
    
    def verificar_permisos_archivos_criticos_avanzado(self) -> Dict[str, Any]:
        resultados = {
            'archivos_analizados': [],
            'problemas_permisos': [],
            'archivos_faltantes': [],
            'recomendaciones': []
        }
        
        for archivo, info in self.archivos_criticos.items():
            analisis_archivo = self._analizar_archivo_critico(archivo, info)
            resultados['archivos_analizados'].append(analisis_archivo)
            
            if not analisis_archivo['existe']:
                resultados['archivos_faltantes'].append(analisis_archivo)
            elif analisis_archivo.get('problema_permisos'):
                resultados['problemas_permisos'].append(analisis_archivo)
        
        resultados['recomendaciones'] = self._generar_recomendaciones_archivos(resultados)
        
        return resultados
    
    def _analizar_archivo_critico(self, archivo: str, info: Dict[str, Any]) -> Dict[str, Any]:
        try:
            stat_info = os.stat(archivo)
            permisos_actuales = oct(stat_info.st_mode)[-3:]
            permisos_esperados = info['permisos_esperados']
            
            analisis = {
                'archivo': archivo,
                'descripcion': info['descripcion'],
                'existe': True,
                'permisos_actuales': permisos_actuales,
                'permisos_esperados': permisos_esperados,
                'uid': stat_info.st_uid,
                'gid': stat_info.st_gid,
                'tamaño': stat_info.st_size,
                'modificado': datetime.datetime.fromtimestamp(stat_info.st_mtime),
                'problema_permisos': permisos_actuales != permisos_esperados
            }
            
            # Verificar propietario
            if stat_info.st_uid != 0:  # No es root
                analisis['problema_propietario'] = True
                analisis['problema_permisos'] = True
            
            return analisis
            
        except FileNotFoundError:
            return {
                'archivo': archivo,
                'descripcion': info['descripcion'],
                'existe': False,
                'error': 'Archivo no encontrado'
            }
        except Exception as e:
            return {
                'archivo': archivo,
                'descripcion': info['descripcion'],
                'existe': False,
                'error': str(e)
            }
    
    def _generar_recomendaciones_archivos(self, resultados: Dict[str, Any]) -> List[str]:
        recomendaciones = []
        
        if resultados['archivos_faltantes']:
            archivos = [a['archivo'] for a in resultados['archivos_faltantes']]
            recomendaciones.append(f"📁 Archivos críticos faltantes: {', '.join(archivos)}")
        
        if resultados['problemas_permisos']:
            count = len(resultados['problemas_permisos'])
            recomendaciones.append(f"🔐 {count} archivos con permisos incorrectos")
        
        if not resultados['problemas_permisos'] and not resultados['archivos_faltantes']:
            recomendaciones.append("Todos los archivos críticos tienen permisos correctos")
        
        return recomendaciones
    
    def obtener_info_hardware_completa(self) -> Dict[str, Any]:
        info = {
            'cpu': self._obtener_info_cpu(),
            'memoria': self._obtener_info_memoria(),
            'disco': self._obtener_info_disco(),
            'red': self._obtener_info_red(),
            'sistema': self._obtener_info_sistema()
        }
        
        return info
    
    def _obtener_info_cpu(self) -> Dict[str, Any]:
        info_cpu = {'nucleos': 0, 'modelo': 'Desconocido', 'frecuencia': 'Desconocida'}
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                contenido = f.read()
                
                # Contar núcleos
                info_cpu['nucleos'] = contenido.count('processor')
                
                # Obtener modelo
                for linea in contenido.split('\n'):
                    if 'model name' in linea:
                        info_cpu['modelo'] = linea.split(':')[1].strip()
                        break
                
                # Obtener frecuencia
                for linea in contenido.split('\n'):
                    if 'cpu MHz' in linea:
                        mhz = float(linea.split(':')[1].strip())
                        info_cpu['frecuencia'] = f"{mhz:.0f} MHz"
                        break
        except Exception:
            pass
        
        return info_cpu
    
    def _obtener_info_memoria(self) -> Dict[str, Any]:
        info_memoria = {}
        
        try:
            with open('/proc/meminfo', 'r') as f:
                contenido = f.read()
                
                for linea in contenido.split('\n'):
                    if 'MemTotal' in linea:
                        kb = int(linea.split()[1])
                        info_memoria['total'] = f"{kb // 1024} MB"
                    elif 'MemAvailable' in linea:
                        kb = int(linea.split()[1])
                        info_memoria['disponible'] = f"{kb // 1024} MB"
                    elif 'SwapTotal' in linea:
                        kb = int(linea.split()[1])
                        info_memoria['swap_total'] = f"{kb // 1024} MB"
        except Exception:
            info_memoria = {'error': 'No se pudo obtener información de memoria'}
        
        return info_memoria
    
    def _obtener_info_disco(self) -> Dict[str, Any]:
        info_disco = {}
        
        try:
            cmd = ['df', '-h', '/']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if resultado.returncode == 0:
                lineas = resultado.stdout.split('\n')
                if len(lineas) > 1:
                    partes = lineas[1].split()
                    if len(partes) >= 6:
                        info_disco = {
                            'dispositivo': partes[0],
                            'total': partes[1],
                            'usado': partes[2],
                            'disponible': partes[3],
                            'porcentaje_uso': partes[4],
                            'punto_montaje': partes[5]
                        }
        except Exception:
            info_disco = {'error': 'No se pudo obtener información de disco'}
        
        return info_disco
    
    def _obtener_info_red(self) -> Dict[str, Any]:
        info_red = {'interfaces': []}
        
        try:
            cmd = ['ip', 'addr', 'show']
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if resultado.returncode == 0:
                lineas = resultado.stdout.split('\n')
                interfaz_actual = None
                
                for linea in lineas:
                    if re.match(r'^\d+:', linea):
                        if interfaz_actual:
                            info_red['interfaces'].append(interfaz_actual)
                        
                        partes = linea.split()
                        interfaz_actual = {
                            'nombre': partes[1].rstrip(':'),
                            'estado': 'UP' if 'UP' in linea else 'DOWN',
                            'ips': []
                        }
                    elif 'inet ' in linea and interfaz_actual:
                        ip = linea.strip().split()[1]
                        interfaz_actual['ips'].append(ip)
                
                if interfaz_actual:
                    info_red['interfaces'].append(interfaz_actual)
                    
        except Exception:
            info_red = {'error': 'No se pudo obtener información de red'}
        
        return info_red
    
    def _obtener_info_sistema(self) -> Dict[str, Any]:
        info_sistema = {}
        
        try:
            # Información del kernel
            info_sistema['kernel'] = platform.release()
            info_sistema['arquitectura'] = platform.machine()
            
            # Uptime
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                uptime_days = int(uptime_seconds // 86400)
                uptime_hours = int((uptime_seconds % 86400) // 3600)
                info_sistema['uptime'] = f"{uptime_days} días, {uptime_hours} horas"
            
            # Load average
            with open('/proc/loadavg', 'r') as f:
                loads = f.read().split()[:3]
                info_sistema['load_average'] = f"{loads[0]} {loads[1]} {loads[2]}"
                
        except Exception:
            info_sistema = {'error': 'No se pudo obtener información del sistema'}
        
        return info_sistema
    
    def ejecutar_limpieza_sistema_avanzada(self) -> Dict[str, Any]:
        operaciones_limpieza = {
            'limpiar_cache_apt': ['sudo', 'apt', 'clean'],
            'autoremover_paquetes': ['sudo', 'apt', 'autoremove', '-y'],
            'limpiar_logs_antiguos': ['sudo', 'journalctl', '--vacuum-time=7d'],
            'limpiar_tmp': ['find', '/tmp', '-type', 'f', '-atime', '+1', '-delete'],
            'limpiar_cache_usuario': ['find', os.path.expanduser('~/.cache'), '-type', 'f', '-atime', '+7', '-delete']
        }
        
        resultados = {
            'operaciones': {},
            'espacio_liberado': 0,
            'errores': [],
            'tiempo_total': 0
        }
        
        inicio = time.time()
        
        for operacion, cmd in operaciones_limpieza.items():
            try:
                espacio_antes = self._obtener_espacio_disponible()
                
                resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                espacio_despues = self._obtener_espacio_disponible()
                espacio_liberado = espacio_despues - espacio_antes
                
                resultados['operaciones'][operacion] = {
                    'exito': resultado.returncode == 0,
                    'espacio_liberado_mb': max(0, espacio_liberado),
                    'salida': resultado.stdout[:200] if resultado.stdout else '',
                    'tiempo': time.time()
                }
                
                if espacio_liberado > 0:
                    resultados['espacio_liberado'] += espacio_liberado
                    
            except subprocess.TimeoutExpired:
                resultados['operaciones'][operacion] = {'exito': False, 'error': 'Timeout'}
                resultados['errores'].append(f"{operacion}: Timeout")
            except Exception as e:
                resultados['operaciones'][operacion] = {'exito': False, 'error': str(e)}
                resultados['errores'].append(f"{operacion}: {str(e)}")
        
        resultados['tiempo_total'] = time.time() - inicio
        
        return resultados
    
    def _obtener_espacio_disponible(self) -> int:
        try:
            if platform.system() == "Linux":
                # Usar df en lugar de statvfs para compatibilidad
                cmd = ['df', '--output=avail', '/']
                resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lines = resultado.stdout.strip().split('\n')
                    if len(lines) > 1:
                        # Convertir de KB a MB
                        kb_disponibles = int(lines[1])
                        return kb_disponibles // 1024
            return 0
        except:
            return 0

# RESUMEN: Utilidades avanzadas del sistema con verificación de herramientas Kali, auditorías de seguridad,
# análisis de servicios, detección de rootkits y limpieza del sistema usando herramientas nativas de Linux.
