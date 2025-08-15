# -*- coding: utf-8 -*-
"""
Ares Aegis - Escaneador Avanzado
Sistema completo de escaneo de vulnerabilidades y redes para Kali Linux
Integra funcionalidad avanzada del proyecto original manteniendo compatibilidad con la interfaz actual
"""

import subprocess
import json
import datetime
import logging
import time
import socket
import threading
import ipaddress
import re
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

# Importar el gestor de permisos seguro
try:
    from ..utils.gestor_permisos import obtener_gestor_permisos, ejecutar_comando_seguro
    GESTOR_PERMISOS_DISPONIBLE = True
except ImportError:
    # Fallback si no está disponible
    GESTOR_PERMISOS_DISPONIBLE = False
    obtener_gestor_permisos = None
    ejecutar_comando_seguro = None

class TipoEscaneo(Enum):
    """Tipos de escaneo disponibles."""
    PUERTOS_BASICO = "puertos_basico"
    PUERTOS_AVANZADO = "puertos_avanzado"
    VULNERABILIDADES = "vulnerabilidades"
    RED_COMPLETA = "red_completa"
    SERVICIOS = "servicios"
    OS_DETECTION = "os_detection"
    STEALTH = "stealth"

class NivelCriticidad(Enum):
    """Niveles de criticidad para vulnerabilidades."""
    CRITICA = "CRITICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"
    INFO = "INFO"

@dataclass
class VulnerabilidadEncontrada:
    """Representa una vulnerabilidad encontrada."""
    tipo: str
    descripcion: str
    criticidad: NivelCriticidad
    puerto: Optional[int] = None
    servicio: Optional[str] = None
    cve: Optional[str] = None
    solucion: Optional[str] = None
    referencias: Optional[List[str]] = None

@dataclass
class ResultadoEscaneo:
    """Resultado completo de un escaneo."""
    objetivo: str
    tipo_escaneo: TipoEscaneo
    inicio: datetime.datetime
    fin: Optional[datetime.datetime] = None
    puertos_abiertos: List[Dict] = field(default_factory=list)
    vulnerabilidades: List[VulnerabilidadEncontrada] = field(default_factory=list)
    servicios_detectados: List[Dict] = field(default_factory=list)
    sistema_operativo: Optional[str] = None
    estado: str = "en_progreso"
    errores: List[str] = field(default_factory=list)

class EscaneadorAvanzado:
    """
    Escaneador avanzado integrado con funcionalidad del proyecto original.
    Optimizado para Kali Linux y herramientas de penetration testing.
    """
    
    def __init__(self, siem=None):
        self.logger = logging.getLogger(__name__)
        self.siem = siem
        self.herramientas_disponibles = self._verificar_herramientas()
        
        # Inicializar gestor de permisos
        if GESTOR_PERMISOS_DISPONIBLE and obtener_gestor_permisos is not None:
            self.gestor_permisos = obtener_gestor_permisos()
            self.logger.info("✅ Gestor de permisos inicializado")
        else:
            self.gestor_permisos = None
            self.logger.warning("⚠️ Gestor de permisos no disponible - funcionalidad limitada")
        
        # Base de datos de vulnerabilidades (simulada por ahora)
        self.base_vulnerabilidades = self._cargar_base_vulnerabilidades()
        
        # Puertos más comunes para escaneo rápido
        self.puertos_comunes = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        # Escaneos en progreso
        self.escaneos_activos = {}
        
        # Configuración por defecto
        self.config = {
            'timeout_conexion': 5,
            'max_threads': 50,
            'delay_escaneo': 0.1,
            'intentos_maximos': 3
        }
        
        # Validaciones de seguridad
        self.herramientas_permitidas = {
            'nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'sqlmap', 'whatweb'
        }
        self.patron_ip = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
        self.patron_hostname = re.compile(r'^[a-zA-Z0-9.-]+$')
        self.patron_puertos = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')
        
        self.logger.info("🔍 Escaneador Avanzado Ares Aegis inicializado")
        
    def _validar_objetivo_seguro(self, objetivo: str) -> bool:
        """Valida que el objetivo sea seguro"""
        if not objetivo:
            return False
            
        # Verificar IP válida
        if self.patron_ip.match(objetivo):
            try:
                # Verificar que no sea IP reservada/privada crítica
                ip = ipaddress.ip_address(objetivo.split('/')[0])
                if ip.is_loopback and objetivo != '127.0.0.1':
                    return False
                return True
            except:
                return False
                
        # Verificar hostname válido
        if self.patron_hostname.match(objetivo):
            return True
            
        return False
        
    def _validar_puertos_seguros(self, puertos: str) -> bool:
        """Valida que el rango de puertos sea seguro"""
        if not puertos or not self.patron_puertos.match(puertos):
            return False
            
        # Verificar que no exceda límites razonables
        rangos = puertos.replace(' ', '').split(',')
        for rango in rangos:
            if '-' in rango:
                inicio, fin = rango.split('-')
                if int(fin) - int(inicio) > 10000:  # Máximo 10k puertos por rango
                    return False
            if int(rango.split('-')[0]) > 65535:
                return False
                
        return True
        
    def _sanitizar_comando(self, comando: List[str]) -> List[str]:
        """Sanitiza comando para subprocess"""
        comando_sanitizado = []
        for arg in comando:
            if not isinstance(arg, str):
                continue
            # Escapar argumentos potencialmente peligrosos
            arg_seguro = shlex.quote(str(arg))
            comando_sanitizado.append(arg_seguro.strip("'\""))
        return comando_sanitizado
    
    def _cargar_base_vulnerabilidades(self) -> Dict[str, Any]:
        """Cargar base de datos de vulnerabilidades conocidas."""
        try:
            # Intentar cargar desde archivo si existe
            vulnerabilidades_file = Path("recursos/cve_database.json")
            if vulnerabilidades_file.exists():
                with open(vulnerabilidades_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"No se pudo cargar base de vulnerabilidades: {e}")
        
        # Base de datos básica incorporada
        return {
            'servicios_vulnerables': {
                'ssh': {
                    '22': ['SSH-1.99-OpenSSH_2.9p2', 'SSH-2.0-OpenSSH_3.4'],
                    'vulnerabilidades': ['CVE-2016-0777', 'CVE-2016-0778']
                },
                'ftp': {
                    '21': ['vsftpd 2.3.4'],
                    'vulnerabilidades': ['CVE-2011-2523']
                },
                'http': {
                    '80': ['Apache/2.2.8', 'nginx/1.4.6'],
                    'vulnerabilidades': ['CVE-2017-7679', 'CVE-2013-4547']
                },
                'https': {
                    '443': ['Apache/2.2.8', 'nginx/1.4.6'],
                    'vulnerabilidades': ['CVE-2014-0160', 'CVE-2014-3566']
                }
            },
            'puertos_criticos': [21, 22, 23, 135, 139, 445, 1433, 3389],
            'servicios_riesgosos': ['telnet', 'ftp', 'rsh', 'rlogin']
        }
    
    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verificar herramientas disponibles en Kali Linux."""
        herramientas = {
            'nmap': ['nmap', '--version'],
            'netstat': ['netstat', '--version'],  
            'ss': ['ss', '--version'],
            'lsof': ['lsof', '-v'],
            'masscan': ['masscan', '--version'],
            'nikto': ['nikto', '-Version'],
            'dirb': ['dirb'],
            'gobuster': ['gobuster', 'version'],
            'sqlmap': ['sqlmap', '--version'],
            'whatweb': ['whatweb', '--version']
        }
        
        disponibles = {}
        for herramienta, comando in herramientas.items():
            try:
                resultado = subprocess.run(comando, 
                                         capture_output=True, text=True, timeout=5)
                disponibles[herramienta] = resultado.returncode == 0
                if disponibles[herramienta]:
                    self.logger.debug(f" {herramienta} disponible")
            except Exception as e:
                disponibles[herramienta] = False
                self.logger.debug(f" {herramienta} no disponible: {e}")
        
        return disponibles
    
    def escanear_puertos_basico(self, objetivo: str, puertos: str = "1-1000") -> Dict[str, Any]:
        """Escaneo básico de puertos usando nmap con validación de seguridad."""
        try:
            # Validar objetivo
            if not self._validar_objetivo_seguro(objetivo):
                self.logger.warning(f"Objetivo inseguro bloqueado: {objetivo}")
                return {
                    'exito': False,
                    'error': 'Objetivo no válido o no permitido',
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
            # Validar puertos
            if not self._validar_puertos_seguros(puertos):
                self.logger.warning(f"Rango de puertos inseguro: {puertos}")
                return {
                    'exito': False,
                    'error': 'Rango de puertos no válido',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            # Verificar disponibilidad de nmap
            if not self.herramientas_disponibles.get('nmap', False):
                return {
                    'exito': False,
                    'error': 'nmap no está disponible',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            # Usar gestor de permisos si está disponible
            if self.gestor_permisos is not None:
                self.logger.info(f"🔧 Ejecutando escaneo con permisos elevados: {objetivo}:{puertos}")
                argumentos = ['-sS', '-p', puertos, objetivo]
                exito, stdout, stderr = self.gestor_permisos.ejecutar_con_permisos('nmap', argumentos, 60)
                
                return {
                    'exito': exito,
                    'salida': stdout,
                    'error': stderr if not exito else None,
                    'comando': 'nmap [ejecutado con permisos elevados]',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            else:
                # Fallback a ejecución tradicional (sin sudo)
                self.logger.warning("⚠️ Ejecutando escaneo sin permisos elevados - resultados limitados")
                comando = ['nmap', '-sT', '-p', puertos, objetivo]  # TCP connect sin sudo
                comando_seguro = self._sanitizar_comando(comando)
                
                resultado = subprocess.run(comando_seguro, capture_output=True, text=True, timeout=60)
                
                return {
                    'exito': resultado.returncode == 0,
                    'salida': resultado.stdout,
                    'error': resultado.stderr if resultado.returncode != 0 else None,
                    'comando': 'nmap [sin permisos elevados]',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en escaneo de puertos',
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"❌ Error en escaneo: {str(e)}")
            return {
                'exito': False,
                'error': f'Error en escaneo: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def obtener_conexiones_activas(self) -> Dict[str, Any]:
        """Obtiene conexiones de red activas usando permisos elevados si es necesario."""
        try:
            # Determinar herramienta a usar
            herramienta = None
            argumentos = []
            
            if self.herramientas_disponibles.get('ss', False):
                herramienta = 'ss'
                argumentos = ['-tuln']
            elif self.herramientas_disponibles.get('netstat', False):
                herramienta = 'netstat'
                argumentos = ['-tuln']
            else:
                return {
                    'exito': False,
                    'error': 'No hay herramientas de red disponibles',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            # Usar gestor de permisos si está disponible
            if self.gestor_permisos is not None:
                self.logger.info(f"🔧 Obteniendo conexiones con permisos elevados usando {herramienta}")
                exito, stdout, stderr = self.gestor_permisos.ejecutar_con_permisos(herramienta, argumentos, 30)
                
                return {
                    'exito': exito,
                    'conexiones': stdout,
                    'herramienta_usada': herramienta,
                    'permisos_elevados': True,
                    'error': stderr if not exito else None,
                    'timestamp': datetime.datetime.now().isoformat()
                }
            else:
                # Fallback a ejecución sin sudo
                self.logger.warning("⚠️ Obteniendo conexiones sin permisos elevados - información limitada")
                comando = [herramienta] + argumentos
                resultado = subprocess.run(comando, capture_output=True, text=True, timeout=30)
                
                return {
                    'exito': resultado.returncode == 0,
                    'conexiones': resultado.stdout,
                    'herramienta_usada': herramienta,
                    'permisos_elevados': False,
                    'error': resultado.stderr if resultado.returncode != 0 else None,
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
        except Exception as e:
            self.logger.error(f"❌ Error obteniendo conexiones: {str(e)}")
            return {
                'exito': False,
                'error': f'Error obteniendo conexiones: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }

    def escanear_servicios(self, objetivo: str) -> Dict[str, Any]:
        """Escaneo de servicios usando nmap."""
        try:
            if not self.herramientas_disponibles.get('nmap', False):
                return {
                    'exito': False,
                    'error': 'nmap no está disponible',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            comando = ['nmap', '-sV', '-T4', '--top-ports', '100', objetivo]
            
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=120)
            
            return {
                'exito': resultado.returncode == 0,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None,
                'comando': ' '.join(comando),
                'timestamp': datetime.datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en escaneo de servicios',
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error en escaneo de servicios: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def detectar_sistema_operativo(self, objetivo: str) -> Dict[str, Any]:
        """Detección de sistema operativo usando nmap."""
        try:
            if not self.herramientas_disponibles.get('nmap', False):
                return {
                    'exito': False,
                    'error': 'nmap no está disponible',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            comando = ['nmap', '-O', '-T4', objetivo]
            
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=60)
            
            return {
                'exito': resultado.returncode == 0,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None,
                'comando': ' '.join(comando),
                'timestamp': datetime.datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en detección de OS',
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error en detección de OS: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def buscar_vulnerabilidades_basicas(self, objetivo: str) -> Dict[str, Any]:
        """Búsqueda básica de vulnerabilidades usando nmap scripts."""
        try:
            if not self.herramientas_disponibles.get('nmap', False):
                return {
                    'exito': False,
                    'error': 'nmap no está disponible',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            comando = ['nmap', '--script', 'vuln', '-T4', '--top-ports', '50', objetivo]
            
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=180)
            
            return {
                'exito': resultado.returncode == 0,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None,
                'comando': ' '.join(comando),
                'timestamp': datetime.datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en búsqueda de vulnerabilidades',
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error en búsqueda de vulnerabilidades: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def descubrir_hosts_red(self, rango_red: str) -> List[str]:
        """Descubrir hosts activos en un rango de red."""
        try:
            if not self.herramientas_disponibles.get('nmap', False):
                return []
            
            comando = ['nmap', '-sn', rango_red]
            
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=120)
            
            if resultado.returncode != 0:
                return []
            
            # Extraer IPs de la salida
            hosts = []
            for linea in resultado.stdout.split('\n'):
                if 'Nmap scan report for' in linea:
                    # Extraer IP de la línea
                    partes = linea.split()
                    if len(partes) >= 5:
                        ip = partes[-1].strip('()')
                        hosts.append(ip)
            
            return hosts
            
        except Exception as e:
            return []

    # ======= FUNCIONES AVANZADAS INTEGRADAS DEL PROYECTO ORIGINAL =======
    
    def escanear_avanzado(self, objetivo: str, tipo_escaneo: TipoEscaneo = TipoEscaneo.PUERTOS_AVANZADO) -> ResultadoEscaneo:
        """
        Función principal de escaneo avanzado con integración completa.
        Mantiene compatibilidad con la interfaz actual pero añade funcionalidad del proyecto original.
        """
        escaneo_id = f"scan_{int(time.time())}"
        resultado = ResultadoEscaneo(
            objetivo=objetivo,
            tipo_escaneo=tipo_escaneo,
            inicio=datetime.datetime.now(),
            puertos_abiertos=[],
            vulnerabilidades=[],
            servicios_detectados=[],
            errores=[]
        )
        
        self.escaneos_activos[escaneo_id] = resultado
        
        try:
            self.logger.info(f" Iniciando escaneo {tipo_escaneo.value} en {objetivo}")
            
            if self.siem:
                self.siem.registrar_evento(
                    "AUDITORIA",
                    f"Escaneo {tipo_escaneo.value} iniciado en {objetivo}",
                    {"objetivo": objetivo, "tipo": tipo_escaneo.value},
                    "INFO"
                )
            
            # Ejecutar escaneo según el tipo
            if tipo_escaneo == TipoEscaneo.PUERTOS_BASICO:
                self._escanear_puertos_basico_avanzado(resultado)
            elif tipo_escaneo == TipoEscaneo.PUERTOS_AVANZADO:
                self._escanear_puertos_avanzado(resultado)
            elif tipo_escaneo == TipoEscaneo.VULNERABILIDADES:
                self._escanear_vulnerabilidades(resultado)
            elif tipo_escaneo == TipoEscaneo.RED_COMPLETA:
                self._escanear_red_completa(resultado)
            elif tipo_escaneo == TipoEscaneo.SERVICIOS:
                self._escanear_servicios(resultado)
            elif tipo_escaneo == TipoEscaneo.OS_DETECTION:
                self._detectar_sistema_operativo(resultado)
            elif tipo_escaneo == TipoEscaneo.STEALTH:
                self._escanear_stealth(resultado)
            
            resultado.fin = datetime.datetime.now()
            resultado.estado = "completado"
            
            # Analizar vulnerabilidades encontradas
            self._analizar_vulnerabilidades(resultado)
            
            self.logger.info(f" Escaneo {tipo_escaneo.value} completado en {objetivo}")
            
        except Exception as e:
            self.logger.error(f" Error en escaneo {tipo_escaneo.value}: {e}")
            resultado.errores.append(str(e))
            resultado.estado = "error"
            resultado.fin = datetime.datetime.now()
        
        finally:
            if escaneo_id in self.escaneos_activos:
                del self.escaneos_activos[escaneo_id]
        
        return resultado
    
    def _escanear_puertos_basico_avanzado(self, resultado: ResultadoEscaneo):
        """Escaneo básico mejorado con análisis de servicios."""
        if not self.herramientas_disponibles.get('nmap'):
            resultado.errores.append("nmap no disponible")
            return
        
        try:
            # Escaneo rápido de puertos comunes
            comando = [
                'nmap', '-sS', '-T4', '-p', 
                ','.join(map(str, self.puertos_comunes)),
                '--open', resultado.objetivo
            ]
            
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=120)
            
            if proceso.returncode == 0:
                resultado.puertos_abiertos = self._parsear_nmap_puertos(proceso.stdout)
            else:
                resultado.errores.append(f"Error nmap: {proceso.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo básico")
        except Exception as e:
            resultado.errores.append(f"Error escaneo básico: {e}")
    
    def _escanear_puertos_avanzado(self, resultado: ResultadoEscaneo):
        """Escaneo avanzado con detección de servicios y versiones."""
        if not self.herramientas_disponibles.get('nmap'):
            resultado.errores.append("nmap no disponible")
            return
        
        try:
            # Escaneo completo con detección de servicios
            comando = [
                'nmap', '-sS', '-sV', '-sC', '-T4', 
                '-p1-65535', '--open', resultado.objetivo
            ]
            
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=600)
            
            if proceso.returncode == 0:
                resultado.puertos_abiertos = self._parsear_nmap_puertos(proceso.stdout)
                resultado.servicios_detectados = self._parsear_nmap_servicios(proceso.stdout)
            else:
                resultado.errores.append(f"Error nmap avanzado: {proceso.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo avanzado")
        except Exception as e:
            resultado.errores.append(f"Error escaneo avanzado: {e}")
    
    def _escanear_vulnerabilidades(self, resultado: ResultadoEscaneo):
        """Escaneo específico de vulnerabilidades usando scripts NSE."""
        if not self.herramientas_disponibles.get('nmap'):
            resultado.errores.append("nmap no disponible")
            return
        
        try:
            # Primero obtener puertos abiertos
            self._escanear_puertos_avanzado(resultado)
            
            if not resultado.puertos_abiertos:
                return
            
            # Escaneo de vulnerabilidades con scripts NSE
            puertos_str = ','.join([str(p['puerto']) for p in resultado.puertos_abiertos])
            
            comando = [
                'nmap', '--script', 'vuln', '-p', puertos_str,
                resultado.objetivo
            ]
            
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=900)
            
            if proceso.returncode == 0:
                vulns = self._parsear_nmap_vulnerabilidades(proceso.stdout)
                resultado.vulnerabilidades.extend(vulns)
            else:
                resultado.errores.append(f"Error scripts vuln: {proceso.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo de vulnerabilidades")
        except Exception as e:
            resultado.errores.append(f"Error escaneo vulnerabilidades: {e}")
    
    def _escanear_red_completa(self, resultado: ResultadoEscaneo):
        """Escaneo completo de red con descubrimiento de hosts."""
        try:
            # Primero descubrir hosts en la red
            hosts = self.descubrir_hosts_red(resultado.objetivo)
            
            resultado.servicios_detectados = []
            
            for host in hosts:
                try:
                    # Escaneo rápido por host
                    host_resultado = self.escanear_avanzado(host, TipoEscaneo.PUERTOS_AVANZADO)
                    
                    # Agregar resultados
                    if host_resultado.puertos_abiertos:
                        resultado.puertos_abiertos.extend([
                            {**puerto, 'host': host} for puerto in host_resultado.puertos_abiertos
                        ])
                    
                    if host_resultado.servicios_detectados:
                        resultado.servicios_detectados.extend([
                            {**servicio, 'host': host} for servicio in host_resultado.servicios_detectados
                        ])
                    
                    if host_resultado.vulnerabilidades:
                        resultado.vulnerabilidades.extend(host_resultado.vulnerabilidades)
                        
                except Exception as e:
                    resultado.errores.append(f"Error escaneando host {host}: {e}")
                    
        except Exception as e:
            resultado.errores.append(f"Error escaneo red completa: {e}")
    
    def _detectar_sistema_operativo(self, resultado: ResultadoEscaneo):
        """Detección de sistema operativo."""
        if not self.herramientas_disponibles.get('nmap'):
            resultado.errores.append("nmap no disponible")
            return
        
        try:
            comando = ['nmap', '-O', '--osscan-guess', resultado.objetivo]
            
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=300)
            
            if proceso.returncode == 0:
                os_info = self._parsear_nmap_os(proceso.stdout)
                resultado.sistema_operativo = os_info
            else:
                resultado.errores.append(f"Error detección OS: {proceso.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en detección OS")
        except Exception as e:
            resultado.errores.append(f"Error detección OS: {e}")
    
    def _escanear_servicios(self, resultado: ResultadoEscaneo):
        """Escaneo específico de servicios y versiones."""
        if not self.herramientas_disponibles.get('nmap'):
            resultado.errores.append("nmap no disponible")
            return
        
        try:
            # Primero escaneo básico para encontrar puertos
            self._escanear_puertos_basico_avanzado(resultado)
            
            if not resultado.puertos_abiertos:
                return
            
            # Escaneo detallado de servicios en puertos encontrados
            puertos_str = ','.join([str(p['puerto']) for p in resultado.puertos_abiertos])
            
            comando = [
                'nmap', '-sV', '--version-intensity', '9',
                '-p', puertos_str, resultado.objetivo
            ]
            
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=300)
            
            if proceso.returncode == 0:
                resultado.servicios_detectados = self._parsear_nmap_servicios(proceso.stdout)
            else:
                resultado.errores.append(f"Error escaneo servicios: {proceso.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo de servicios")
        except Exception as e:
            resultado.errores.append(f"Error escaneo servicios: {e}")
    
    def _escanear_stealth(self, resultado: ResultadoEscaneo):
        """Escaneo sigiloso para evadir detección."""
        if not self.herramientas_disponibles.get('nmap'):
            resultado.errores.append("nmap no disponible")
            return
        
        try:
            # Escaneo SYN sigiloso con timing lento
            comando = [
                'nmap', '-sS', '-T2', '-f', '--scan-delay', '1s',
                '-p', ','.join(map(str, self.puertos_comunes)),
                '--open', resultado.objetivo
            ]
            
            proceso = subprocess.run(comando, capture_output=True, text=True, timeout=600)
            
            if proceso.returncode == 0:
                resultado.puertos_abiertos = self._parsear_nmap_puertos(proceso.stdout)
            else:
                resultado.errores.append(f"Error escaneo stealth: {proceso.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo stealth")
        except Exception as e:
            resultado.errores.append(f"Error escaneo stealth: {e}")
    
    def _parsear_nmap_puertos(self, salida: str) -> List[Dict[str, Any]]:
        """Parsear salida de nmap para extraer puertos abiertos."""
        puertos = []
        
        for linea in salida.split('\n'):
            if '/tcp' in linea or '/udp' in linea:
                partes = linea.split()
                if len(partes) >= 3 and 'open' in linea:
                    puerto_info = partes[0].split('/')
                    if len(puerto_info) == 2:
                        puerto = {
                            'puerto': int(puerto_info[0]),
                            'protocolo': puerto_info[1],
                            'estado': 'abierto',
                            'servicio': partes[2] if len(partes) > 2 else 'desconocido'
                        }
                        puertos.append(puerto)
        
        return puertos
    
    def _parsear_nmap_servicios(self, salida: str) -> List[Dict[str, Any]]:
        """Parsear servicios detectados por nmap."""
        servicios = []
        
        for linea in salida.split('\n'):
            if '/tcp' in linea or '/udp' in linea:
                partes = linea.split()
                if len(partes) >= 4 and 'open' in linea:
                    puerto_info = partes[0].split('/')
                    if len(puerto_info) == 2:
                        servicio = {
                            'puerto': int(puerto_info[0]),
                            'protocolo': puerto_info[1],
                            'servicio': partes[2],
                            'version': ' '.join(partes[3:]) if len(partes) > 3 else 'desconocida'
                        }
                        servicios.append(servicio)
        
        return servicios
    
    def _parsear_nmap_vulnerabilidades(self, salida: str) -> List[VulnerabilidadEncontrada]:
        """Parsear vulnerabilidades encontradas por scripts NSE."""
        vulnerabilidades = []
        
        # Buscar secciones de vulnerabilidades
        lineas = salida.split('\n')
        for i, linea in enumerate(lineas):
            if 'CVE-' in linea:
                cve = linea.split('CVE-')[1].split()[0]
                descripcion = linea.strip()
                
                vuln = VulnerabilidadEncontrada(
                    tipo="CVE",
                    descripcion=descripcion,
                    criticidad=self._determinar_criticidad(cve),
                    cve=f"CVE-{cve}",
                    referencias=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{cve}"]
                )
                vulnerabilidades.append(vuln)
        
        return vulnerabilidades
    
    def _parsear_nmap_os(self, salida: str) -> str:
        """Parsear información del sistema operativo."""
        for linea in salida.split('\n'):
            if 'Running:' in linea:
                return linea.replace('Running:', '').strip()
            elif 'OS details:' in linea:
                return linea.replace('OS details:', '').strip()
        
        return "Sistema operativo no detectado"
    
    def _analizar_vulnerabilidades(self, resultado: ResultadoEscaneo):
        """Analizar y clasificar vulnerabilidades encontradas."""
        if not resultado.puertos_abiertos:
            return
        
        # Analizar puertos críticos
        for puerto_info in resultado.puertos_abiertos:
            puerto = puerto_info['puerto']
            servicio = puerto_info.get('servicio', '')
            
            # Verificar puertos críticos
            if puerto in self.base_vulnerabilidades['puertos_criticos']:
                vuln = VulnerabilidadEncontrada(
                    tipo="PUERTO_CRITICO",
                    descripcion=f"Puerto crítico {puerto} ({servicio}) abierto",
                    criticidad=NivelCriticidad.ALTA,
                    puerto=puerto,
                    servicio=servicio,
                    solucion=f"Considerar cerrar el puerto {puerto} si no es necesario"
                )
                resultado.vulnerabilidades.append(vuln)
            
            # Verificar servicios riesgosos
            if servicio.lower() in self.base_vulnerabilidades['servicios_riesgosos']:
                vuln = VulnerabilidadEncontrada(
                    tipo="SERVICIO_RIESGOSO",
                    descripcion=f"Servicio riesgoso {servicio} en puerto {puerto}",
                    criticidad=NivelCriticidad.MEDIA,
                    puerto=puerto,
                    servicio=servicio,
                    solucion=f"Reemplazar {servicio} por alternativa segura"
                )
                resultado.vulnerabilidades.append(vuln)
    
    def _determinar_criticidad(self, cve: str) -> NivelCriticidad:
        """Determinar criticidad de una CVE (básico)."""
        # En una implementación real, consultaríamos una base de datos de CVE
        # Por ahora, usamos heurísticas básicas
        if any(keyword in cve.lower() for keyword in ['remote', 'execute', 'overflow']):
            return NivelCriticidad.CRITICA
        elif any(keyword in cve.lower() for keyword in ['injection', 'bypass']):
            return NivelCriticidad.ALTA
        else:
            return NivelCriticidad.MEDIA
    
    def obtener_estadisticas_escaneos(self) -> Dict[str, Any]:
        """Obtener estadísticas de los escaneos realizados."""
        return {
            'escaneos_activos': len(self.escaneos_activos),
            'herramientas_disponibles': sum(1 for v in self.herramientas_disponibles.values() if v),
            'total_herramientas': len(self.herramientas_disponibles),
            'herramientas': self.herramientas_disponibles
        }
    
    def generar_reporte_avanzado(self, resultado: ResultadoEscaneo) -> str:
        """Generar reporte avanzado del escaneo."""
        reporte = f"""
#  REPORTE DE ESCANEO AVANZADO - ARES AEGIS

##  INFORMACIÓN GENERAL
- **Objetivo**: {resultado.objetivo}
- **Tipo de Escaneo**: {resultado.tipo_escaneo.value}
- **Inicio**: {resultado.inicio.strftime('%Y-%m-%d %H:%M:%S')}
- **Fin**: {resultado.fin.strftime('%Y-%m-%d %H:%M:%S') if resultado.fin else 'En progreso'}
- **Estado**: {resultado.estado}

##  PUERTOS ABIERTOS ({len(resultado.puertos_abiertos or [])})
"""
        
        if resultado.puertos_abiertos:
            for puerto in resultado.puertos_abiertos:
                reporte += f"- **Puerto {puerto['puerto']}/{puerto['protocolo']}**: {puerto['servicio']}\n"
        else:
            reporte += "No se encontraron puertos abiertos.\n"
        
        reporte += f"\n##  SERVICIOS DETECTADOS ({len(resultado.servicios_detectados or [])})\n"
        
        if resultado.servicios_detectados:
            for servicio in resultado.servicios_detectados:
                reporte += f"- **{servicio['servicio']}** en puerto {servicio['puerto']}: {servicio.get('version', 'Versión desconocida')}\n"
        
        reporte += f"\n##  VULNERABILIDADES ({len(resultado.vulnerabilidades or [])})\n"
        
        if resultado.vulnerabilidades:
            for vuln in resultado.vulnerabilidades:
                emoji = {"CRITICA": "", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢", "INFO": ""}
                reporte += f"{emoji.get(vuln.criticidad.value, '')} **{vuln.criticidad.value}**: {vuln.descripcion}\n"
                if vuln.solucion:
                    reporte += f"   *Solución*: {vuln.solucion}\n"
        else:
            reporte += " No se detectaron vulnerabilidades críticas.\n"
        
        if resultado.sistema_operativo:
            reporte += f"\n##  SISTEMA OPERATIVO\n{resultado.sistema_operativo}\n"
        
        if resultado.errores:
            reporte += f"\n##  ERRORES\n"
            for error in resultado.errores:
                reporte += f"- {error}\n"
        
        reporte += f"\n---\n*Generado por Ares Aegis - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return reporte


# Mantener compatibilidad con la interfaz actual
class Escaneador(EscaneadorAvanzado):
    """
    Clase de compatibilidad que mantiene la interfaz original 
    pero proporciona toda la funcionalidad avanzada.
    """
    
    def __init__(self, siem=None):
        super().__init__(siem)
        # Propiedades de compatibilidad
        self.es_kali = self._detectar_kali()
    
    def _detectar_kali(self) -> bool:
        """Detecta si estamos ejecutando en Kali Linux"""
        try:
            import platform
            if platform.system() == "Linux":
                with open("/etc/os-release", "r") as f:
                    content = f.read()
                    return "kali" in content.lower()
            return False
        except:
            return False
    
    def escanear_puertos_ss(self) -> Dict[str, Any]:
        """Método de compatibilidad para escanear puertos usando ss"""
        if not self.es_kali:
            return {
                "exito": False,
                "error": "Este método solo funciona en Kali Linux",
                "puertos": []
            }
        
        try:
            resultado = self.obtener_conexiones_activas()
            return {
                "exito": resultado.get("exito", False),
                "puertos": resultado.get("conexiones", []),
                "datos": resultado
            }
        except Exception as e:
            return {
                "exito": False,
                "error": str(e),
                "puertos": []
            }
    
    def escanear_procesos_avanzado(self) -> Dict[str, Any]:
        """Método de compatibilidad para escanear procesos"""
        try:
            import psutil
            procesos = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    procesos.append({
                        'pid': info['pid'],
                        'nombre': info['name'],
                        'cpu': info['cpu_percent'],
                        'memoria': info['memory_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                "exito": True,
                "procesos": procesos,
                "total": len(procesos)
            }
            
        except Exception as e:
            return {
                "exito": False,
                "error": str(e),
                "procesos": []
            }
