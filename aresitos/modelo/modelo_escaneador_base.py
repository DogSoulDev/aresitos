# -*- coding: utf-8 -*-
"""
Ares Aegis - Escaneador Base
Funcionalidades base y configuración del sistema de escaneo
"""

import subprocess
import json
import datetime
import logging
import time
import socket
import re
import shlex
import os
from enum import Enum
from typing import Dict, List, Any, Optional
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

class SecurityError(Exception):
    """Excepción personalizada para errores de seguridad."""
    pass

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

class EscaneadorBase:
    """
    Clase base para el escáner con funcionalidades fundamentales.
    
    Características principales:
    - Configuración de seguridad básica
    - Validación de entrada
    - Gestión de herramientas
    - Logging seguro
    """
    
    def __init__(self, siem=None):
        self.logger = logging.getLogger(__name__)
        self.siem = siem
        self.herramientas_disponibles = self._verificar_herramientas()
        
        # Configuración de seguridad base
        self.config_seguridad = {
            'timeout_comando_defecto': 120,
            'timeout_maximo': 900,
            'max_conexiones_concurrentes': 50,
            'max_intentos_reconexion': 3,
            'intervalo_throttling': 0.1,
            'rutas_herramientas_permitidas': [
                '/usr/bin', '/bin', '/usr/sbin', '/sbin',
                '/usr/local/bin', '/opt/kali/bin'
            ],
            'patrones_salida_sensible': [
                r'password[:\s]*\w+',
                r'token[:\s]*\w+',
                r'api[_-]?key[:\s]*\w+',
                r'secret[:\s]*\w+'
            ]
        }
        
        # Inicializar contadores básicos
        self._contador_operaciones = {}
        self._ultima_operacion = {}
        self._archivos_temporales = set()
        
        # Inicializar escaneos activos
        self.escaneos_activos = {}
        
        # Patrones de validación
        self.patron_ip = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
        self.patron_hostname = re.compile(r'^[a-zA-Z0-9.-]+$')
        self.patron_puertos = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')
        
        # Lista de herramientas permitidas (MODERNIZADAS)
        self.herramientas_permitidas = {
            'nmap', 'rustscan', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'sqlmap', 'httpx', 'nuclei', 'whatweb',
            'ss', 'netstat', 'lsof', 'ping', 'dig', 'nslookup', 'host'
        }
        
        # Inicializar gestor de permisos
        if GESTOR_PERMISOS_DISPONIBLE and obtener_gestor_permisos is not None:
            self.gestor_permisos = obtener_gestor_permisos()
            self.logger.info("Gestor de permisos inicializado")
        else:
            self.gestor_permisos = None
            self.logger.warning("Gestor de permisos no disponible - funcionalidad limitada")
        
        # Base de datos de vulnerabilidades
        self.base_vulnerabilidades = self._cargar_base_vulnerabilidades()
        
        # Puertos más comunes para escaneo rápido
        self.puertos_comunes = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        # Configuración específica
        self.configuracion_escaneo = {
            'delay_escaneo': 0.1,
            'intentos_maximos': 3
        }
        
        self.logger.info("Escaneador Base Ares Aegis inicializado")
    
    def _validar_entrada_segura(self, entrada: str, tipo: str = "general") -> bool:
        """
        Validación de entrada para diferentes tipos de datos.
        
        Args:
            entrada: Cadena a validar
            tipo: Tipo de validación (ip, hostname, puerto, comando)
            
        Returns:
            bool: True si la entrada es válida
            
        Raises:
            SecurityError: Si la entrada no es válida
        """
        if not entrada or not isinstance(entrada, str):
            raise SecurityError("Entrada vacía o tipo inválido")
        
        # Verificar longitud máxima
        if len(entrada) > 1000:
            raise SecurityError("Entrada excede longitud máxima permitida")
        
        # Validaciones específicas por tipo
        if tipo == "ip":
            try:
                if self._es_ip_valida(entrada):
                    if self._es_loopback(entrada) and not self._permitir_loopback():
                        raise SecurityError("Dirección loopback no permitida")
                    if self._es_privada(entrada) and not self._permitir_privadas():
                        raise SecurityError("Dirección privada no permitida")
                    return True
                else:
                    raise ValueError("IP inválida")
            except ValueError:
                raise SecurityError(f"Dirección IP inválida: {entrada}")
        
        elif tipo == "hostname":
            patron = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(patron, entrada):
                raise SecurityError(f"Hostname inválido: {entrada}")
            return True
        
        elif tipo == "puerto":
            try:
                puerto = int(entrada)
                if not (1 <= puerto <= 65535):
                    raise SecurityError(f"Puerto fuera de rango: {puerto}")
                return True
            except ValueError:
                raise SecurityError(f"Puerto inválido: {entrada}")
        
        elif tipo == "comando":
            # Verificar caracteres peligrosos
            caracteres_peligrosos = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '\\']
            for char in caracteres_peligrosos:
                if char in entrada:
                    raise SecurityError(f"Carácter peligroso detectado: {char}")
            return True
        
        return True

    def _es_ip_valida(self, ip):
        """Valida si una dirección IP es válida"""
        try:
            partes = ip.split('.')
            if len(partes) != 4:
                return False
            for parte in partes:
                if not 0 <= int(parte) <= 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def _es_loopback(self, ip):
        """Verifica si es dirección loopback (127.x.x.x)"""
        try:
            return ip.startswith('127.')
        except AttributeError:
            return False
    
    def _es_privada(self, ip):
        """Verifica si es dirección privada"""
        try:
            partes = [int(x) for x in ip.split('.')]
            # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            return (partes[0] == 10 or 
                   (partes[0] == 172 and 16 <= partes[1] <= 31) or
                   (partes[0] == 192 and partes[1] == 168))
        except (ValueError, IndexError):
            return False

    def _es_multicast(self, ip):
        """Verifica si es dirección multicast (224.0.0.0-239.255.255.255)"""
        try:
            partes = [int(x) for x in ip.split('.')]
            return 224 <= partes[0] <= 239
        except (ValueError, IndexError):
            return False
    
    def _es_reservada(self, ip):
        """Verifica si es dirección reservada"""
        try:
            partes = [int(x) for x in ip.split('.')]
            # 0.0.0.0/8, 240.0.0.0/4 (Class E), 255.255.255.255
            return (partes[0] == 0 or 
                   partes[0] >= 240 or
                   ip == "255.255.255.255")
        except (ValueError, IndexError):
            return False

    def _permitir_loopback(self) -> bool:
        """Determinar si se permiten direcciones loopback."""
        return True  # Configurable según política de seguridad

    def _permitir_privadas(self) -> bool:
        """Determinar si se permiten direcciones privadas."""
        return True  # Configurable según política de seguridad

    def _throttling_operaciones(self, tipo_operacion: str):
        """
        Implementar throttling para prevenir abuse.
        
        Args:
            tipo_operacion: Tipo de operación para throttling
        """
        ahora = time.time()
        ultima = self._ultima_operacion.get(tipo_operacion, 0)
        
        # Aplicar delay mínimo entre operaciones
        tiempo_transcurrido = ahora - ultima
        if tiempo_transcurrido < self.config_seguridad['intervalo_throttling']:
            delay = self.config_seguridad['intervalo_throttling'] - tiempo_transcurrido
            time.sleep(delay)
        
        self._ultima_operacion[tipo_operacion] = time.time()

    def _filtrar_salida_sensible(self, output: str) -> str:
        """
        Filtrar información sensible de la salida de comandos.
        
        Args:
            output: Salida original del comando
            
        Returns:
            str: Salida filtrada
        """
        salida_filtrada = output
        
        for patron in self.config_seguridad['patrones_salida_sensible']:
            salida_filtrada = re.sub(patron, '[CENSURADO]', salida_filtrada, flags=re.IGNORECASE)
        
        return salida_filtrada

    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verificar herramientas disponibles en el sistema."""
        herramientas = {
            'nmap': ['nmap', '--version'],
            'netstat': ['netstat', '--version'],  
            'ss': ['ss', '--version'],
            'lsof': ['lsof', '-v'],
            'rustscan': ['rustscan', '--version'],
            'masscan': ['masscan', '--version'],
            'nikto': ['nikto', '-Version'],
            'gobuster': ['gobuster', 'version'],
            'feroxbuster': ['feroxbuster', '--version'],
            'httpx': ['httpx', '-version'],
            'nuclei': ['nuclei', '-version'],
            'sqlmap': ['sqlmap', '--version'],
            'whatweb': ['whatweb', '--version']
        }
        
        disponibles = {}
        for herramienta, comando in herramientas.items():
            try:
                # Aplicar throttling y validación
                self._throttling_operaciones('verificacion_herramientas')
                
                # Validar comando antes de ejecución
                self._validar_entrada_segura(comando[0], "comando")
                
                # Ejecución con timeout reducido y environment controlado
                resultado = subprocess.run(
                    comando, 
                    capture_output=True, 
                    text=True, 
                    timeout=5,
                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
                )
                disponibles[herramienta] = resultado.returncode == 0
                if disponibles[herramienta]:
                    self.logger.debug(f"Herramienta {herramienta} disponible")
                else:
                    self.logger.debug(f"Herramienta {herramienta} no disponible (código: {resultado.returncode})")
            except SecurityError as e:
                disponibles[herramienta] = False
                self.logger.warning(f"Herramienta {herramienta} bloqueada por seguridad: {e}")
            except subprocess.TimeoutExpired:
                disponibles[herramienta] = False
                self.logger.warning(f"Herramienta {herramienta} timeout en verificación")
            except Exception as e:
                disponibles[herramienta] = False
                self.logger.debug(f"Herramienta {herramienta} no disponible: {e}")
        
        return disponibles
    
    def _validar_objetivo_seguro(self, objetivo: str) -> bool:
        """Validar que el objetivo sea seguro para escanear."""
        if not objetivo:
            return False
            
        # Verificar IP válida
        if self.patron_ip.match(objetivo):
            try:
                # Verificar que no sea IP reservada/privada crítica
                ip_limpia = objetivo.split('/')[0]
                if self._es_ip_valida(ip_limpia):
                    if self._es_multicast(ip_limpia) or self._es_reservada(ip_limpia):
                        return False
                    return True
                else:
                    return False
            except ValueError:
                return False
        
        # Verificar hostname válido
        if self.patron_hostname.match(objetivo):
            return True
            
        return False
        
    def _validar_puertos_seguros(self, puertos: str) -> bool:
        """Validar que el rango de puertos sea seguro."""
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
        """Sanitizar comando para subprocess."""
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
            vulnerabilidades_file = Path("data/diccionarios/cve_database_english.json")
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

    def obtener_configuracion(self) -> Dict[str, Any]:
        """Obtener configuración actual del sistema."""
        return {
            'herramientas_disponibles': self.herramientas_disponibles,
            'configuracion_seguridad': self.config_seguridad,
            'herramientas_permitidas': list(self.herramientas_permitidas),
            'total_escaneos_activos': len(self.escaneos_activos)
        }

    def obtener_estadisticas_basicas(self) -> Dict[str, Any]:
        """Obtener estadísticas básicas del sistema."""
        return {
            'operaciones_realizadas': sum(self._contador_operaciones.values()),
            'por_tipo': dict(self._contador_operaciones),
            'herramientas_funcionales': len([h for h, disponible in self.herramientas_disponibles.items() if disponible]),
            'archivos_temporales_activos': len(self._archivos_temporales)
        }
