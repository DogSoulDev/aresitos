# -*- coding: utf-8 -*-
"""
ARESITOS - Escaneador de Red y Servicios
=======================================

Escaneador especializado para análisis de red, IPs, puertos, DNS y servicios.
Utiliza únicamente Python nativo + herramientas nativas de Kali Linux.

Funcionalidades:
- Escaneo de puertos (TCP/UDP)
- Detección de servicios en red
- Análisis de DNS y resolución
- Escaneo de subredes y discovery
- Detección de vulnerabilidades de red
- Análisis de tráfico básico
- Fingerprinting de sistemas
- Detección de servicios web

Principios ARESITOS aplicados:
- Python nativo + Kali tools únicamente
- Sin dependencias externas
- Código limpio y conciso (SOLID/DRY)
- MVC arquitectura respetada
- Sin emojis/tokens (excepto Aresitos.ico/png)

Autor: DogSoulDev
Fecha: Agosto 2025
"""

import subprocess
import socket
import threading
import time
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

# Importar modelo dashboard para autodetección de red
from .modelo_dashboard import ModeloDashboard

@dataclass
class ResultadoEscaneoRed:
    """Resultado de escaneo completo de red."""
    objetivo: str
    timestamp: datetime
    puertos_abiertos: List[Dict[str, Any]]
    servicios_detectados: List[Dict[str, Any]]
    informacion_dns: Dict[str, Any]
    vulnerabilidades_detectadas: List[Dict[str, Any]]
    hosts_descubiertos: List[Dict[str, Any]]
    fingerprint_sistema: Dict[str, Any]
    servicios_web: List[Dict[str, Any]]
    tiempo_total: float
    
    def __post_init__(self):
        if not self.puertos_abiertos:
            self.puertos_abiertos = []
        if not self.servicios_detectados:
            self.servicios_detectados = []
        if not self.informacion_dns:
            self.informacion_dns = {}
        if not self.vulnerabilidades_detectadas:
            self.vulnerabilidades_detectadas = []
        if not self.hosts_descubiertos:
            self.hosts_descubiertos = []
        if not self.fingerprint_sistema:
            self.fingerprint_sistema = {}
        if not self.servicios_web:
            self.servicios_web = []

class EscaneadorRed:
    """
    Escaneador especializado para análisis de red, IPs, puertos y servicios.
    Utiliza herramientas nativas de Kali Linux y Python.
    """
    
    def __init__(self):
        self.logger = self._configurar_logger()
        self.herramientas_red = self._verificar_herramientas()
        self.dashboard = ModeloDashboard()
        self.puertos_comunes = {
            'tcp': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 27017],
            'udp': [53, 67, 68, 69, 123, 161, 162, 514]
        }
        self.timeout_default = 3
    
    def _configurar_logger(self) -> Any:
        """Configurar logger para el escaneador."""
        import logging
        logger = logging.getLogger('EscaneadorRed')
        logger.setLevel(logging.INFO)
        return logger
    
    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verificar disponibilidad de herramientas de red."""
        herramientas = {
            'nmap': 'nmap',
            'masscan': 'masscan',
            'nc': 'nc',
            'netcat': 'netcat',
            'dig': 'dig',
            'nslookup': 'nslookup',
            'ping': 'ping',
            'traceroute': 'traceroute',
            'curl': 'curl',
            'wget': 'wget',
            'nikto': 'nikto',
            'gobuster': 'gobuster',
            'ffuf': 'ffuf'
        }
        
        disponibles = {}
        for nombre, comando in herramientas.items():
            try:
                result = subprocess.run(['which', comando], 
                                      capture_output=True, text=True, timeout=5)
                disponibles[nombre] = result.returncode == 0
                if disponibles[nombre]:
                    self.logger.info(f"Herramienta {nombre} disponible")
            except Exception:
                disponibles[nombre] = False
        
        return disponibles
    
    def _ejecutar_comando_seguro(self, comando: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Ejecutar comando del sistema de forma segura."""
        try:
            result = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            return {
                'exito': result.returncode == 0,
                'salida': result.stdout,
                'error': result.stderr,
                'codigo': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'salida': '',
                'error': f'Timeout después de {timeout}s',
                'codigo': -1
            }
        except Exception as e:
            return {
                'exito': False,
                'salida': '',
                'error': str(e),
                'codigo': -2
            }
    
    def _autodetectar_objetivo(self) -> str:
        """Autodetectar objetivo de red usando dashboard."""
        try:
            info_red = self.dashboard.obtener_informacion_red()
            
            # Buscar la IP de la gateway o una IP local válida
            if 'gateway' in info_red:
                return info_red['gateway']
            
            # Fallback a interfaz activa
            if 'interfaces' in info_red:
                for interfaz in info_red['interfaces']:
                    if interfaz.get('estado') == 'ACTIVA' and interfaz.get('ip'):
                        ip = interfaz['ip'].split('/')[0]  # Remover máscara si existe
                        if not ip.startswith('127.'):  # No loopback
                            return ip
            
            # Último fallback
            return '127.0.0.1'
            
        except Exception as e:
            self.logger.warning(f"Error en autodetección: {e}")
            return '127.0.0.1'
    
    def _validar_objetivo(self, objetivo: str) -> Tuple[bool, str]:
        """Validar que el objetivo sea una IP o hostname válido."""
        if not objetivo or objetivo.strip() == '':
            return False, "Objetivo vacío"
        
        objetivo = objetivo.strip()
        
        # Validar IP
        try:
            socket.inet_aton(objetivo)
            return True, "IP válida"
        except socket.error:
            pass
        
        # Validar hostname
        try:
            socket.gethostbyname(objetivo)
            return True, "Hostname válido"
        except socket.error:
            return False, "IP o hostname inválido"
    
    def escanear_puertos_tcp(self, objetivo: str, puertos: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Escanear puertos TCP del objetivo."""
        self.logger.info(f"Iniciando escaneo TCP en {objetivo}")
        puertos_abiertos = []
        
        if puertos is None:
            puertos = self.puertos_comunes['tcp']
        
        # Usar nmap si está disponible (más rápido y confiable)
        if self.herramientas_red.get('nmap'):
            puertos_str = ','.join(map(str, puertos))
            resultado = self._ejecutar_comando_seguro([
                'nmap', '-sT', '-p', puertos_str, '--open', objetivo
            ], timeout=120)
            
            if resultado['exito']:
                lineas = resultado['salida'].split('\n')
                for linea in lineas:
                    if '/tcp' in linea and 'open' in linea:
                        partes = linea.split()
                        if len(partes) >= 3:
                            puerto_info = partes[0].split('/')[0]
                            estado = partes[1]
                            servicio = partes[2] if len(partes) > 2 else 'unknown'
                            
                            try:
                                puerto_num = int(puerto_info)
                                puertos_abiertos.append({
                                    'puerto': puerto_num,
                                    'protocolo': 'tcp',
                                    'estado': estado,
                                    'servicio': servicio,
                                    'metodo': 'nmap'
                                })
                            except ValueError:
                                continue
        else:
            # Fallback a escaneo manual con socket
            for puerto in puertos:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout_default)
                    
                    result = sock.connect_ex((objetivo, puerto))
                    if result == 0:
                        puertos_abiertos.append({
                            'puerto': puerto,
                            'protocolo': 'tcp',
                            'estado': 'open',
                            'servicio': 'unknown',
                            'metodo': 'socket'
                        })
                    
                    sock.close()
                except Exception:
                    continue
        
        self.logger.info(f"Escaneo TCP completado: {len(puertos_abiertos)} puertos abiertos")
        return puertos_abiertos
    
    def escanear_puertos_udp(self, objetivo: str, puertos: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Escanear puertos UDP del objetivo."""
        self.logger.info(f"Iniciando escaneo UDP en {objetivo}")
        puertos_abiertos = []
        
        if puertos is None:
            puertos = self.puertos_comunes['udp']
        
        # UDP scanning requiere nmap para ser efectivo
        if self.herramientas_red.get('nmap'):
            puertos_str = ','.join(map(str, puertos))
            resultado = self._ejecutar_comando_seguro([
                'nmap', '-sU', '-p', puertos_str, '--open', objetivo
            ], timeout=180)  # UDP es más lento
            
            if resultado['exito']:
                lineas = resultado['salida'].split('\n')
                for linea in lineas:
                    if '/udp' in linea and ('open' in linea or 'open|filtered' in linea):
                        partes = linea.split()
                        if len(partes) >= 2:
                            puerto_info = partes[0].split('/')[0]
                            estado = partes[1]
                            servicio = partes[2] if len(partes) > 2 else 'unknown'
                            
                            try:
                                puerto_num = int(puerto_info)
                                puertos_abiertos.append({
                                    'puerto': puerto_num,
                                    'protocolo': 'udp',
                                    'estado': estado,
                                    'servicio': servicio,
                                    'metodo': 'nmap'
                                })
                            except ValueError:
                                continue
        
        self.logger.info(f"Escaneo UDP completado: {len(puertos_abiertos)} puertos detectados")
        return puertos_abiertos
    
    def detectar_servicios_avanzados(self, objetivo: str, puertos_abiertos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detectar información detallada de servicios."""
        self.logger.info(f"Detectando servicios en {objetivo}")
        servicios_detectados = []
        
        for puerto_info in puertos_abiertos:
            puerto = puerto_info['puerto']
            protocolo = puerto_info['protocolo']
            
            # Solo procesar TCP para detección de servicios
            if protocolo != 'tcp':
                continue
            
            servicio_detectado = {
                'puerto': puerto,
                'protocolo': protocolo,
                'nombre': puerto_info.get('servicio', 'unknown'),
                'version': 'unknown',
                'banner': '',
                'vulnerabilidades': []
            }
            
            # Usar nmap para detección de versiones si está disponible
            if self.herramientas_red.get('nmap'):
                resultado = self._ejecutar_comando_seguro([
                    'nmap', '-sV', '-p', str(puerto), objetivo
                ], timeout=60)
                
                if resultado['exito']:
                    lineas = resultado['salida'].split('\n')
                    for linea in lineas:
                        if f'{puerto}/tcp' in linea and 'open' in linea:
                            # Extraer información de versión
                            if len(linea.split()) > 3:
                                info_servicio = ' '.join(linea.split()[2:])
                                servicio_detectado['version'] = info_servicio
                                servicio_detectado['nombre'] = linea.split()[2]
            
            # Intentar obtener banner manualmente para servicios comunes
            elif puerto in [21, 22, 25, 80, 110, 143, 443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((objetivo, puerto))
                    
                    if puerto in [21, 22, 25]:  # Servicios que envían banner
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        servicio_detectado['banner'] = banner
                        
                        # Extraer información básica del banner
                        if 'SSH' in banner:
                            servicio_detectado['nombre'] = 'ssh'
                            servicio_detectado['version'] = banner
                        elif 'FTP' in banner:
                            servicio_detectado['nombre'] = 'ftp'
                            servicio_detectado['version'] = banner
                        elif 'SMTP' in banner:
                            servicio_detectado['nombre'] = 'smtp'
                            servicio_detectado['version'] = banner
                    
                    elif puerto in [80, 443]:  # HTTP/HTTPS
                        if puerto == 80:
                            servicio_detectado['nombre'] = 'http'
                        else:
                            servicio_detectado['nombre'] = 'https'
                        
                        # Intentar obtener headers HTTP
                        if self.herramientas_red.get('curl'):
                            protocolo_http = 'https' if puerto == 443 else 'http'
                            resultado_curl = self._ejecutar_comando_seguro([
                                'curl', '-I', f'{protocolo_http}://{objetivo}:{puerto}/', '-m', '10'
                            ])
                            
                            if resultado_curl['exito']:
                                headers = resultado_curl['salida']
                                # Extraer servidor
                                for linea in headers.split('\n'):
                                    if linea.lower().startswith('server:'):
                                        servicio_detectado['version'] = linea.split(':', 1)[1].strip()
                                        break
                    
                    sock.close()
                except Exception:
                    pass
            
            servicios_detectados.append(servicio_detectado)
        
        self.logger.info(f"Detectados {len(servicios_detectados)} servicios")
        return servicios_detectados
    
    def resolver_dns(self, objetivo: str) -> Dict[str, Any]:
        """Resolver información DNS del objetivo."""
        self.logger.info(f"Resolviendo DNS para {objetivo}")
        informacion_dns = {
            'objetivo': objetivo,
            'ip_resueltas': [],
            'registros_dns': {},
            'dns_reverso': ''
        }
        
        # Resolver IP si es hostname
        try:
            ip_resuelta = socket.gethostbyname(objetivo)
            informacion_dns['ip_resueltas'].append(ip_resuelta)
            
            # DNS reverso
            try:
                hostname_reverso = socket.gethostbyaddr(ip_resuelta)[0]
                informacion_dns['dns_reverso'] = hostname_reverso
            except:
                pass
        except:
            # Es posible que ya sea una IP
            try:
                socket.inet_aton(objetivo)
                informacion_dns['ip_resueltas'].append(objetivo)
                
                # DNS reverso para IP
                try:
                    hostname_reverso = socket.gethostbyaddr(objetivo)[0]
                    informacion_dns['dns_reverso'] = hostname_reverso
                except:
                    pass
            except:
                pass
        
        # Usar dig para información avanzada si está disponible
        if self.herramientas_red.get('dig'):
            tipos_registro = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for tipo in tipos_registro:
                resultado = self._ejecutar_comando_seguro([
                    'dig', '+short', objetivo, tipo
                ], timeout=30)
                
                if resultado['exito'] and resultado['salida'].strip():
                    registros = resultado['salida'].strip().split('\n')
                    informacion_dns['registros_dns'][tipo] = [r.strip() for r in registros if r.strip()]
        
        self.logger.info(f"Resolución DNS completada para {objetivo}")
        return informacion_dns
    
    def descubrir_hosts_red(self, objetivo: str) -> List[Dict[str, Any]]:
        """Descubrir hosts activos en la red del objetivo."""
        self.logger.info(f"Descubriendo hosts en la red de {objetivo}")
        hosts_descubiertos = []
        
        try:
            # Determinar subred
            if '/' in objetivo:  # CIDR notation
                red_base = objetivo
            else:
                # Asumir /24 para IP individual
                ip_partes = objetivo.split('.')
                if len(ip_partes) == 4:
                    red_base = f"{'.'.join(ip_partes[:3])}.0/24"
                else:
                    return hosts_descubiertos
            
            # Usar nmap para host discovery si está disponible
            if self.herramientas_red.get('nmap'):
                resultado = self._ejecutar_comando_seguro([
                    'nmap', '-sn', red_base
                ], timeout=120)
                
                if resultado['exito']:
                    lineas = resultado['salida'].split('\n')
                    for linea in lineas:
                        if 'Nmap scan report for' in linea:
                            # Extraer IP/hostname
                            partes = linea.split()
                            if len(partes) >= 5:
                                host_info = partes[4]
                                
                                # Si hay paréntesis, extraer IP
                                if '(' in host_info and ')' in host_info:
                                    ip = host_info.split('(')[1].split(')')[0]
                                    hostname = partes[4].split('(')[0]
                                else:
                                    ip = host_info
                                    hostname = ''
                                
                                hosts_descubiertos.append({
                                    'ip': ip,
                                    'hostname': hostname,
                                    'estado': 'activo',
                                    'metodo': 'nmap_discovery'
                                })
            
            else:
                # Ping sweep manual (solo para /24)
                if red_base.endswith('/24'):
                    base_ip = red_base.split('/')[0].rsplit('.', 1)[0]
                    
                    # Probar solo algunos IPs para no ser intrusivo
                    for i in [1, 2, 3, 4, 5, 10, 20, 50, 100, 254]:
                        ip_test = f"{base_ip}.{i}"
                        
                        resultado_ping = self._ejecutar_comando_seguro([
                            'ping', '-c', '1', '-W', '2', ip_test
                        ], timeout=5)
                        
                        if resultado_ping['exito']:
                            hosts_descubiertos.append({
                                'ip': ip_test,
                                'hostname': '',
                                'estado': 'activo',
                                'metodo': 'ping'
                            })
        
        except Exception as e:
            self.logger.warning(f"Error en discovery: {e}")
        
        self.logger.info(f"Descubiertos {len(hosts_descubiertos)} hosts activos")
        return hosts_descubiertos
    
    def detectar_servicios_web(self, objetivo: str, puertos_web: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Detectar y analizar servicios web."""
        self.logger.info(f"Detectando servicios web en {objetivo}")
        servicios_web = []
        
        if puertos_web is None:
            puertos_web = [80, 443, 8080, 8443, 8000, 8001, 9000]
        
        for puerto in puertos_web:
            try:
                # Verificar si el puerto está abierto
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((objetivo, puerto))
                sock.close()
                
                if result != 0:
                    continue  # Puerto cerrado
                
                # Determinar protocolo
                protocolo = 'https' if puerto in [443, 8443] else 'http'
                url_base = f"{protocolo}://{objetivo}:{puerto}"
                
                servicio_web = {
                    'puerto': puerto,
                    'protocolo': protocolo,
                    'url': url_base,
                    'servidor': 'unknown',
                    'tecnologias': [],
                    'estado_http': 0,
                    'titulo': '',
                    'directorios_encontrados': []
                }
                
                # Obtener información básica con curl
                if self.herramientas_red.get('curl'):
                    resultado_curl = self._ejecutar_comando_seguro([
                        'curl', '-I', url_base, '-m', '10', '-k'  # -k para HTTPS sin verificar
                    ])
                    
                    if resultado_curl['exito']:
                        headers = resultado_curl['salida']
                        
                        # Extraer código de estado
                        primera_linea = headers.split('\n')[0]
                        if 'HTTP' in primera_linea:
                            try:
                                codigo = int(primera_linea.split()[1])
                                servicio_web['estado_http'] = codigo
                            except:
                                pass
                        
                        # Extraer servidor y tecnologías
                        for linea in headers.split('\n'):
                            linea_lower = linea.lower()
                            if linea_lower.startswith('server:'):
                                servicio_web['servidor'] = linea.split(':', 1)[1].strip()
                            elif linea_lower.startswith('x-powered-by:'):
                                servicio_web['tecnologias'].append(linea.split(':', 1)[1].strip())
                
                # Obtener título de la página
                if self.herramientas_red.get('curl'):
                    resultado_body = self._ejecutar_comando_seguro([
                        'curl', url_base, '-m', '10', '-k', '-s'
                    ])
                    
                    if resultado_body['exito']:
                        body = resultado_body['salida']
                        # Extraer título
                        import re
                        titulo_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
                        if titulo_match:
                            servicio_web['titulo'] = titulo_match.group(1).strip()
                
                # Escaneo básico de directorios con gobuster
                if self.herramientas_red.get('gobuster'):
                    # Lista de directorios comunes básica
                    directorios_comunes = ['admin', 'login', 'dashboard', 'api', 'docs', 'test']
                    
                    for directorio in directorios_comunes:
                        url_dir = f"{url_base}/{directorio}"
                        resultado_dir = self._ejecutar_comando_seguro([
                            'curl', '-I', url_dir, '-m', '5', '-k', '-s'
                        ])
                        
                        if resultado_dir['exito']:
                            if '200 OK' in resultado_dir['salida']:
                                servicio_web['directorios_encontrados'].append(directorio)
                
                servicios_web.append(servicio_web)
                
            except Exception as e:
                self.logger.warning(f"Error analizando puerto web {puerto}: {e}")
                continue
        
        self.logger.info(f"Detectados {len(servicios_web)} servicios web")
        return servicios_web
    
    def fingerprint_sistema(self, objetivo: str) -> Dict[str, Any]:
        """Realizar fingerprinting del sistema objetivo."""
        self.logger.info(f"Realizando fingerprinting de {objetivo}")
        fingerprint = {
            'sistema_operativo': 'unknown',
            'version_os': 'unknown',
            'tipo_dispositivo': 'unknown',
            'stack_tcp': {},
            'servicios_caracteristicos': []
        }
        
        # Usar nmap para OS detection si está disponible
        if self.herramientas_red.get('nmap'):
            resultado = self._ejecutar_comando_seguro([
                'nmap', '-O', objetivo, '--osscan-guess'
            ], timeout=120)
            
            if resultado['exito']:
                lineas = resultado['salida'].split('\n')
                for linea in lineas:
                    if 'Running:' in linea:
                        fingerprint['sistema_operativo'] = linea.split('Running:')[1].strip()
                    elif 'OS details:' in linea:
                        fingerprint['version_os'] = linea.split('OS details:')[1].strip()
                    elif 'Device type:' in linea:
                        fingerprint['tipo_dispositivo'] = linea.split('Device type:')[1].strip()
        
        # Análisis de TTL para estimación de OS
        resultado_ping = self._ejecutar_comando_seguro([
            'ping', '-c', '3', objetivo
        ])
        
        if resultado_ping['exito']:
            import re
            ttl_matches = re.findall(r'ttl=(\d+)', resultado_ping['salida'])
            if ttl_matches:
                ttl = int(ttl_matches[0])
                if ttl <= 64:
                    fingerprint['estimacion_ttl'] = 'Linux/Unix (TTL ~64)'
                elif ttl <= 128:
                    fingerprint['estimacion_ttl'] = 'Windows (TTL ~128)'
                else:
                    fingerprint['estimacion_ttl'] = f'Unknown (TTL {ttl})'
        
        self.logger.info(f"Fingerprinting completado para {objetivo}")
        return fingerprint
    
    def escanear_red_completo(self, objetivo: Optional[str] = None, tipo: str = "completo") -> ResultadoEscaneoRed:
        """Realizar escaneo completo de red."""
        inicio = datetime.now()
        
        # Autodetectar objetivo si no se proporciona
        if not objetivo:
            objetivo = self._autodetectar_objetivo()
        
        # Validar objetivo
        valido, mensaje = self._validar_objetivo(objetivo)
        if not valido:
            raise ValueError(f"Objetivo inválido: {mensaje}")
        
        self.logger.info(f"=== INICIANDO ESCANEO COMPLETO DE RED: {objetivo} ===")
        
        # Componentes del escaneo según el tipo
        puertos_abiertos = []
        servicios_detectados = []
        informacion_dns = {}
        vulnerabilidades_detectadas = []
        hosts_descubiertos = []
        fingerprint_sistema = {}
        servicios_web = []
        
        if tipo in ["completo", "puertos"]:
            self.logger.info("Fase 1: Escaneando puertos TCP")
            puertos_tcp = self.escanear_puertos_tcp(objetivo)
            puertos_abiertos.extend(puertos_tcp)
            
            self.logger.info("Fase 2: Escaneando puertos UDP (principales)")
            puertos_udp = self.escanear_puertos_udp(objetivo, [53, 67, 123, 161])
            puertos_abiertos.extend(puertos_udp)
        
        if tipo in ["completo", "servicios"]:
            self.logger.info("Fase 3: Detectando servicios")
            servicios_detectados = self.detectar_servicios_avanzados(objetivo, puertos_abiertos)
        
        if tipo in ["completo", "dns"]:
            self.logger.info("Fase 4: Resolviendo DNS")
            informacion_dns = self.resolver_dns(objetivo)
        
        if tipo in ["completo", "discovery"]:
            self.logger.info("Fase 5: Descubriendo hosts en red")
            hosts_descubiertos = self.descubrir_hosts_red(objetivo)
        
        if tipo in ["completo", "web"]:
            self.logger.info("Fase 6: Detectando servicios web")
            servicios_web = self.detectar_servicios_web(objetivo)
        
        if tipo in ["completo", "fingerprint"]:
            self.logger.info("Fase 7: Fingerprinting del sistema")
            fingerprint_sistema = self.fingerprint_sistema(objetivo)
        
        fin = datetime.now()
        tiempo_total = (fin - inicio).total_seconds()
        
        self.logger.info(f"=== ESCANEO COMPLETO FINALIZADO en {tiempo_total:.2f} segundos ===")
        
        return ResultadoEscaneoRed(
            objetivo=objetivo,
            timestamp=inicio,
            puertos_abiertos=puertos_abiertos,
            servicios_detectados=servicios_detectados,
            informacion_dns=informacion_dns,
            vulnerabilidades_detectadas=vulnerabilidades_detectadas,
            hosts_descubiertos=hosts_descubiertos,
            fingerprint_sistema=fingerprint_sistema,
            servicios_web=servicios_web,
            tiempo_total=tiempo_total
        )
    
    def log(self, mensaje: str):
        """Método de logging compatible con la interfaz existente."""
        self.logger.info(mensaje)
