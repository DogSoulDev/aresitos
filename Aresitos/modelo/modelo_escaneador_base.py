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
    BASICO = "basico"
    COMPLETO = "completo"
    PUERTOS = "puertos"
    VULNERABILIDADES = "vulnerabilidades"
    RED = "red"

class NivelCriticidad(Enum):
    """Niveles de criticidad para vulnerabilidades."""
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"

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
        
        # Lista de herramientas permitidas (MODERNIZADAS) - DEBE DEFINIRSE ANTES DE _verificar_herramientas
        self.herramientas_permitidas = {
            'nmap', 'rustscan', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'sqlmap', 'httpx', 'nuclei', 'whatweb',
            'ss', 'netstat', 'lsof', 'ping', 'dig', 'nslookup', 'host'
        }
        
        # Ahora verificar herramientas (después de definir herramientas_permitidas)
        self.herramientas_disponibles = self._verificar_herramientas()
        
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
        """Validar entrada del usuario de forma segura."""
        if not entrada or not isinstance(entrada, str):
            return False
        
        # Patrones maliciosos básicos
        patrones_maliciosos = [
            r'[;&|`$<>]',  # Caracteres de shell
            r'\.\.',       # Directory traversal
            r'^\s*$'       # Solo espacios
        ]
        
        for patron in patrones_maliciosos:
            if re.search(patron, entrada):
                self.logger.warning(f"Entrada rechazada por patrón malicioso: {patron}")
                return False
        
        # Validaciones específicas por tipo
        if tipo == "ip":
            return bool(self.patron_ip.match(entrada))
        elif tipo == "hostname":
            return bool(self.patron_hostname.match(entrada))
        elif tipo == "puertos":
            return bool(self.patron_puertos.match(entrada))
        
        return True

    def _es_ip_valida(self, ip):
        """Valida si una dirección IP es válida"""
        try:
            partes = ip.split('.')
            if len(partes) != 4:
                return False
            for parte in partes:
                if not (0 <= int(parte) <= 255):
                    return False
            return True
        except ValueError:
            return False

    def _es_loopback(self, ip):
        """Verifica si es dirección loopback (127.x.x.x)"""
        return ip.startswith('127.')

    def _es_privada(self, ip):
        """Verifica si es dirección privada"""
        return (
            ip.startswith('10.') or 
            ip.startswith('192.168.') or 
            (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)
        )

    def _es_multicast(self, ip):
        """Verifica si es dirección multicast (224.0.0.0-239.255.255.255)"""
        try:
            primer_octeto = int(ip.split('.')[0])
            return 224 <= primer_octeto <= 239
        except (ValueError, IndexError):
            return False

    def _es_reservada(self, ip):
        """Verifica si es dirección reservada"""
        reservadas = [
            '0.0.0.0', '255.255.255.255', '169.254.'
        ]
        for reservada in reservadas:
            if ip.startswith(reservada):
                return True
        return False

    def _permitir_loopback(self) -> bool:
        """Determinar si se permiten direcciones loopback."""
        return True  # Permitir loopback para testing local

    def _permitir_privadas(self) -> bool:
        """Determinar si se permiten direcciones privadas."""
        return True  # Permitir redes privadas para pentesting ético

    def _throttling_operaciones(self, tipo_operacion: str):
        """Implementar throttling entre operaciones."""
        tiempo_actual = time.time()
        if tipo_operacion in self._ultima_operacion:
            tiempo_transcurrido = tiempo_actual - self._ultima_operacion[tipo_operacion]
            if tiempo_transcurrido < self.config_seguridad['intervalo_throttling']:
                time.sleep(self.config_seguridad['intervalo_throttling'] - tiempo_transcurrido)
        
        self._ultima_operacion[tipo_operacion] = tiempo_actual

    def _filtrar_salida_sensible(self, output: str) -> str:
        """Filtrar información sensible de la salida."""
        if not output:
            return output
        
        salida_filtrada = output
        for patron in self.config_seguridad['patrones_salida_sensible']:
            salida_filtrada = re.sub(patron, '[FILTRADO]', salida_filtrada, flags=re.IGNORECASE)
        
        return salida_filtrada

    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verificar herramientas disponibles en el sistema."""
        herramientas_estado = {}
        
        for herramienta in self.herramientas_permitidas:
            try:
                # Verificar si la herramienta está disponible
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, 
                                         text=True, 
                                         timeout=5)
                herramientas_estado[herramienta] = resultado.returncode == 0
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                herramientas_estado[herramienta] = False
        
        # Logging del estado de herramientas
        disponibles = sum(1 for estado in herramientas_estado.values() if estado)
        total = len(herramientas_estado)
        self.logger.info(f"Herramientas verificadas: {disponibles}/{total} disponibles")
        
        return herramientas_estado

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
        
        # Verificar rangos individuales
        rangos = puertos.split(',')
        for rango in rangos:
            if '-' in rango:
                inicio, fin = map(int, rango.split('-'))
                if inicio > fin or inicio < 1 or fin > 65535:
                    return False
            else:
                puerto = int(rango)
                if puerto < 1 or puerto > 65535:
                    return False
        
        return True

    def _cargar_base_vulnerabilidades(self) -> Dict[str, Any]:
        """Cargar base de datos de vulnerabilidades."""
        try:
            ruta_base = Path(__file__).parent.parent / "data" / "vulnerability_database.json"
            if ruta_base.exists():
                with open(ruta_base, 'r', encoding='utf-8') as archivo:
                    base_datos = json.load(archivo)
                    self.logger.info(f"Base de vulnerabilidades cargada: {len(base_datos.get('vulnerabilidades', {}))} entradas")
                    return base_datos
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"No se pudo cargar base de vulnerabilidades: {e}")
        
        # Retornar base mínima si no se puede cargar
        return {
            'vulnerabilidades': {},
            'version': '1.0.0',
            'ultima_actualizacion': datetime.datetime.now().isoformat()
        }

    def limpiar_recursos(self):
        """Limpiar recursos y archivos temporales."""
        for archivo_temp in self._archivos_temporales:
            try:
                if os.path.exists(archivo_temp):
                    os.remove(archivo_temp)
                    self.logger.debug(f"Archivo temporal eliminado: {archivo_temp}")
            except OSError as e:
                self.logger.warning(f"Error eliminando archivo temporal {archivo_temp}: {e}")
        
        self._archivos_temporales.clear()
        self.logger.info("Recursos limpiados")

    def __del__(self):
        """Destructor para limpieza automática."""
        try:
            self.limpiar_recursos()
        except Exception:
            pass  # No generar errores en el destructor
