#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS - Modelo Escaneador Avanzado Kali 2025
==================================================

Escaneador de nueva generación que integra las mejores herramientas de Kali Linux 2025
con técnicas modernas de scanning y detección de vulnerabilidades.

Herramientas integradas:
- RustScan: Scanner ultrarrápido para descubrimiento de puertos
- Nuclei: Scanner de vulnerabilidades con templates YAML
- Masscan: Scanner asíncrono de alta velocidad  
- Nmap: Scanner tradicional con scripts avanzados
- Gobuster: Fuzzer de directorios y archivos
- Nikto: Scanner de vulnerabilidades web
- Whatweb: Identificador de tecnologías web

Principios ARESITOS v3.0:
- Python nativo + herramientas Kali
- Sin dependencias externas complejas
- Arquitectura MVC y SOLID
- Logging comprehensivo
- Manejo de errores robusto

Autor: DogSoulDev
Proyecto: ARESITOS v3.0
Fecha: 2025
"""

import subprocess
import socket
import json
import time
import threading
import concurrent.futures
import logging
import re
import os
import sys
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime

@dataclass
class ConfiguracionEscaneo:
    """Configuración para escaneos avanzados."""
    tipo_escaneo: str = "completo"
    herramientas_habilitadas: List[str] = field(default_factory=lambda: ["nmap", "rustscan"])
    timing: str = "-T3"
    max_paralelo: int = 50
    timeout: int = 300
    puertos_personalizados: Optional[str] = None
    fragmentacion: bool = False
    evasion_ids: bool = False
    randomize_hosts: bool = False
    scripts_nmap: List[str] = field(default_factory=list)
    opciones_adicionales: Dict[str, Any] = field(default_factory=dict)
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
import queue

@dataclass
class ScanResult:
    """Resultado de escaneo unificado"""
    target: str
    scan_type: str
    tool: str
    timestamp: datetime
    duration: float
    ports: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    success: bool
    error: Optional[str] = None

@dataclass
class ScannerConfig:
    """Configuración del escaneador"""
    timeout: int = 300
    max_workers: int = 4
    rate_limit: int = 1000
    enable_service_detection: bool = True
    enable_vuln_scan: bool = True
    enable_web_scan: bool = True
    custom_wordlists: Optional[List[str]] = None
    excluded_targets: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.custom_wordlists is None:
            self.custom_wordlists = []
        if self.excluded_targets is None:
            self.excluded_targets = []

class EscaneadorAvanzadoKali2025:
    """
    Escaneador avanzado que integra las mejores herramientas de Kali Linux 2025
    con técnicas modernas de scanning y análisis de vulnerabilidades.
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """Inicializar el escaneador avanzado"""
        self.config = config or ScannerConfig()
        self.logger = logging.getLogger(__name__)
        
        # Configurar el logger
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
        # Verificar herramientas disponibles
        self.tools_available = self._check_tools_availability()
        
        # Puertos críticos para ciberataques (Top 100)
        self.critical_ports = {
            'tcp': [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 2049, 2121, 2375, 3306, 3389, 5432, 5900, 6379, 8080,
                8443, 9200, 27017, 50070, 1723, 3128, 5060, 5061, 6667, 8888, 9090,
                10000, 11211, 27018, 50000, 1080, 1194, 1352, 1414, 1883, 2181,
                2222, 3000, 4444, 5000, 5001, 5432, 5984, 6000, 6379, 7000, 7001,
                8000, 8008, 8081, 8090, 8181, 8500, 9000, 9001, 9043, 9080, 9443,
                10051, 10080, 15672, 16992, 20000, 25565, 26257, 28017, 32400
            ],
            'udp': [
                53, 67, 68, 69, 123, 161, 162, 500, 1434, 4500, 5060, 31337,
                1900, 5353, 11211, 137, 138, 445, 631, 1701, 4789, 6881
            ]
        }
        
        # Templates de vulnerabilidades comunes
        self.vuln_templates = {
            'web': [
                'cves/', 'default-logins/', 'exposures/', 'misconfiguration/',
                'takeovers/', 'technologies/', 'vulnerabilities/'
            ],
            'network': [
                'network/', 'dns/', 'ssl/', 'iot/'
            ]
        }
        
        # Wordlists comunes de Kali
        self.wordlists = {
            'directories': [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt'
            ],
            'files': [
                '/usr/share/wordlists/dirb/extensions_common.txt',
                '/usr/share/seclists/Discovery/Web-Content/web-extensions.txt'
            ]
        }
        
        self.logger.info(f"Escaneador Avanzado Kali 2025 inicializado")
        self.logger.info(f"Herramientas disponibles: {list(self.tools_available.keys())}")

    def _check_tools_availability(self) -> Dict[str, bool]:
        """Verificar qué herramientas están disponibles en el sistema"""
        tools = {
            'rustscan': 'rustscan',
            'nuclei': 'nuclei',
            'masscan': 'masscan',
            'nmap': 'nmap',
            'gobuster': 'gobuster',
            'dirb': 'dirb',
            'nikto': 'nikto',
            'whatweb': 'whatweb',
            'ffuf': 'ffuf',
            'feroxbuster': 'feroxbuster',
            'httpx': 'httpx',
            'subfinder': 'subfinder'
        }
        
        available = {}
        for tool_name, command in tools.items():
            try:
                result = subprocess.run([command, '--version'], 
                                      capture_output=True, timeout=5)
                available[tool_name] = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                try:
                    # Intentar con -V o -h
                    result = subprocess.run([command, '-h'], 
                                          capture_output=True, timeout=5)
                    available[tool_name] = result.returncode == 0
                except:
                    available[tool_name] = False
        
        return available

    def scan_target(self, target: str, scan_type: str = 'complete') -> ScanResult:
        """
        Escanear un objetivo usando la estrategia más efectiva
        
        Args:
            target: IP, dominio o rango a escanear
            scan_type: 'fast', 'complete', 'stealth', 'aggressive'
        """
        start_time = time.time()
        self.logger.info(f"Iniciando escaneo {scan_type} en {target}")
        
        try:
            # Validar objetivo
            if not self._validate_target(target):
                raise ValueError(f"Objetivo inválido: {target}")
            
            # Estrategia de escaneo según tipo
            if scan_type == 'fast':
                result = self._fast_scan(target)
            elif scan_type == 'complete':
                result = self._complete_scan(target)
            elif scan_type == 'stealth':
                result = self._stealth_scan(target)
            elif scan_type == 'aggressive':
                result = self._aggressive_scan(target)
            else:
                raise ValueError(f"Tipo de escaneo no soportado: {scan_type}")
            
            duration = time.time() - start_time
            result.duration = duration
            result.timestamp = datetime.now()
            
            self.logger.info(f"Escaneo completado en {duration:.2f} segundos")
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Error en escaneo: {e}")
            
            return ScanResult(
                target=target,
                scan_type=scan_type,
                tool='escaneador_avanzado',
                timestamp=datetime.now(),
                duration=duration,
                ports=[],
                vulnerabilities=[],
                services=[],
                metadata={'error': str(e)},
                success=False,
                error=str(e)
            )

    def _validate_target(self, target: str) -> bool:
        """Validar que el objetivo sea válido"""
        # Verificar si está en la lista de exclusión
        if self.config.excluded_targets and target in self.config.excluded_targets:
            return False
        
        # Validar formato IP o dominio
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            # Validar dominio
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
                return True
            return False

    def _fast_scan(self, target: str) -> ScanResult:
        """Escaneo rápido usando RustScan o Masscan"""
        self.logger.info(f"Ejecutando escaneo rápido en {target}")
        
        ports = []
        vulnerabilities = []
        services = []
        metadata: Dict[str, Any] = {}
        tool_used = 'nmap'  # fallback
        
        try:
            # Prioridad: RustScan > Masscan > Nmap
            if self.tools_available.get('rustscan'):
                result = self._run_rustscan(target, top_ports=1000)
                tool_used = 'rustscan'
                ports.extend(result.get('ports', []))
                metadata.update(result.get('metadata', {}))
                
            elif self.tools_available.get('masscan'):
                result = self._run_masscan(target, top_ports=1000)
                tool_used = 'masscan'
                ports.extend(result.get('ports', []))
                metadata.update(result.get('metadata', {}))
                
            else:
                # Fallback a Nmap rápido
                result = self._run_nmap_fast(target)
                tool_used = 'nmap'
                ports.extend(result.get('ports', []))
                services.extend(result.get('services', []))
                metadata.update(result.get('metadata', {}))
            
            # Análisis básico de servicios si hay puertos abiertos
            if ports and self.config.enable_service_detection:
                services.extend(self._identify_services(target, ports[:10]))
            
        except Exception as e:
            self.logger.error(f"Error en escaneo rápido: {e}")
            metadata['error'] = str(e)
        
        return ScanResult(
            target=target,
            scan_type='fast',
            tool=tool_used,
            timestamp=datetime.now(),
            duration=0,  # Se calcula después
            ports=ports,
            vulnerabilities=vulnerabilities,
            services=services,
            metadata=metadata,
            success=len(ports) > 0 or not metadata.get('error')
        )

    def _complete_scan(self, target: str) -> ScanResult:
        """Escaneo completo usando múltiples herramientas"""
        self.logger.info(f"Ejecutando escaneo completo en {target}")
        
        ports = []
        vulnerabilities = []
        services = []
        metadata: Dict[str, Any] = {'tools_used': []}
        
        try:
            # 1. Descubrimiento de puertos rápido
            if self.tools_available.get('rustscan'):
                self.logger.info("Fase 1: Descubrimiento rápido con RustScan")
                result = self._run_rustscan(target)
                ports.extend(result.get('ports', []))
                metadata['tools_used'].append('rustscan')
                metadata['rustscan_results'] = result.get('metadata', {})
            
            # 2. Escaneo detallado con Nmap
            if self.tools_available.get('nmap'):
                self.logger.info("Fase 2: Análisis detallado con Nmap")
                if ports:
                    # Solo escanear puertos encontrados
                    port_list = [p['port'] for p in ports if 'port' in p]
                    result = self._run_nmap_detailed(target, port_list)
                else:
                    # Escaneo completo si no se encontraron puertos
                    result = self._run_nmap_detailed(target)
                
                services.extend(result.get('services', []))
                vulnerabilities.extend(result.get('vulnerabilities', []))
                metadata['tools_used'].append('nmap')
                metadata['nmap_results'] = result.get('metadata', {})
            
            # 3. Análisis de vulnerabilidades con Nuclei
            if self.tools_available.get('nuclei') and self.config.enable_vuln_scan:
                self.logger.info("Fase 3: Análisis de vulnerabilidades con Nuclei")
                result = self._run_nuclei(target, ports)
                vulnerabilities.extend(result.get('vulnerabilities', []))
                metadata['tools_used'].append('nuclei')
                metadata['nuclei_results'] = result.get('metadata', {})
            
            # 4. Análisis web si hay servicios HTTP
            web_ports = [p for p in ports if p.get('service') in ['http', 'https', 'web']]
            if web_ports and self.config.enable_web_scan:
                self.logger.info("Fase 4: Análisis web especializado")
                web_result = self._web_analysis(target, web_ports)
                vulnerabilities.extend(web_result.get('vulnerabilities', []))
                services.extend(web_result.get('services', []))
                metadata['web_analysis'] = web_result.get('metadata', {})
            
        except Exception as e:
            self.logger.error(f"Error en escaneo completo: {e}")
            metadata['error'] = str(e)
        
        return ScanResult(
            target=target,
            scan_type='complete',
            tool='multi_tool',
            timestamp=datetime.now(),
            duration=0,
            ports=ports,
            vulnerabilities=vulnerabilities,
            services=services,
            metadata=metadata,
            success=len(ports) > 0 or len(vulnerabilities) > 0
        )

    def _stealth_scan(self, target: str) -> ScanResult:
        """Escaneo sigiloso para evitar detección"""
        self.logger.info(f"Ejecutando escaneo sigiloso en {target}")
        
        ports = []
        services = []
        metadata: Dict[str, Any] = {'stealth_techniques': []}
        
        try:
            # Técnicas de evasión
            if self.tools_available.get('nmap'):
                # Escaneo SYN con técnicas de evasión
                result = self._run_nmap_stealth(target)
                ports.extend(result.get('ports', []))
                services.extend(result.get('services', []))
                metadata['stealth_techniques'].extend([
                    'syn_scan', 'random_delay', 'decoy_scan', 'fragment_packets'
                ])
            
            # Análisis pasivo si es posible
            passive_result = self._passive_reconnaissance(target)
            services.extend(passive_result.get('services', []))
            metadata['passive_recon'] = passive_result.get('metadata', {})
            
        except Exception as e:
            self.logger.error(f"Error en escaneo sigiloso: {e}")
            metadata['error'] = str(e)
        
        return ScanResult(
            target=target,
            scan_type='stealth',
            tool='nmap_stealth',
            timestamp=datetime.now(),
            duration=0,
            ports=ports,
            vulnerabilities=[],
            services=services,
            metadata=metadata,
            success=len(ports) > 0
        )

    def escaneo_rapido(self, target: str, config: Optional[ConfiguracionEscaneo] = None) -> 'ScanResult':
        """Método de compatibilidad para escaneo rápido."""
        return self._fast_scan(target)

    def _aggressive_scan(self, target: str) -> ScanResult:
        """Escaneo agresivo para máxima información"""
        self.logger.info(f"Ejecutando escaneo agresivo en {target}")
        
        ports = []
        vulnerabilities = []
        services = []
        metadata: Dict[str, Any] = {'scan_intensity': 'aggressive'}
        
        try:
            # Escaneo paralelo con múltiples herramientas
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = []
                
                # RustScan para descubrimiento rápido
                if self.tools_available.get('rustscan'):
                    futures.append(executor.submit(self._run_rustscan, target, all_ports=True))
                
                # Masscan como alternativa
                if self.tools_available.get('masscan'):
                    futures.append(executor.submit(self._run_masscan, target, all_ports=True))
                
                # Recopilar resultados
                for future in concurrent.futures.as_completed(futures, timeout=self.config.timeout):
                    try:
                        result = future.result()
                        ports.extend(result.get('ports', []))
                    except Exception as e:
                        self.logger.warning(f"Error en tarea paralela: {e}")
            
            # Análisis detallado de todos los puertos encontrados
            if ports:
                port_list = list(set([p['port'] for p in ports if 'port' in p]))
                
                # Nmap agresivo
                if self.tools_available.get('nmap'):
                    result = self._run_nmap_aggressive(target, port_list)
                    services.extend(result.get('services', []))
                    vulnerabilities.extend(result.get('vulnerabilities', []))
                
                # Nuclei completo
                if self.tools_available.get('nuclei'):
                    result = self._run_nuclei_aggressive(target, port_list)
                    vulnerabilities.extend(result.get('vulnerabilities', []))
            
        except Exception as e:
            self.logger.error(f"Error en escaneo agresivo: {e}")
            metadata['error'] = str(e)
        
        return ScanResult(
            target=target,
            scan_type='aggressive',
            tool='multi_aggressive',
            timestamp=datetime.now(),
            duration=0,
            ports=ports,
            vulnerabilities=vulnerabilities,
            services=services,
            metadata=metadata,
            success=len(ports) > 0 or len(vulnerabilities) > 0
        )

    def _run_rustscan(self, target: str, top_ports: Optional[int] = None, all_ports: bool = False) -> Dict[str, Any]:
        """Ejecutar RustScan para descubrimiento rápido de puertos"""
        self.logger.info(f"Ejecutando RustScan en {target}")
        
        try:
            cmd = ['rustscan', '-a', target, '--json']
            
            if all_ports:
                cmd.extend(['-p', '1-65535'])
            elif top_ports:
                cmd.extend(['--top'])
            
            # Configurar velocidad
            cmd.extend(['-b', str(min(self.config.rate_limit, 4000))])
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self.config.timeout)
            
            ports = []
            metadata: Dict[str, Any] = {'raw_output': result.stdout, 'command': ' '.join(cmd)}
            
            if result.returncode == 0:
                try:
                    # RustScan devuelve JSON
                    data = json.loads(result.stdout)
                    for item in data:
                        if 'ports' in item:
                            for port in item['ports']:
                                ports.append({
                                    'port': port['port'],
                                    'protocol': 'tcp',  # RustScan principalmente TCP
                                    'state': 'open',
                                    'service': 'unknown',
                                    'tool': 'rustscan'
                                })
                except json.JSONDecodeError:
                    # Fallback a parsing manual
                    for line in result.stdout.split('\n'):
                        if 'Open' in line and target in line:
                            match = re.search(r'(\d+)', line)
                            if match:
                                ports.append({
                                    'port': int(match.group(1)),
                                    'protocol': 'tcp',
                                    'state': 'open',
                                    'service': 'unknown',
                                    'tool': 'rustscan'
                                })
                
                metadata['ports_found'] = len(ports)
                self.logger.info(f"RustScan encontró {len(ports)} puertos")
                
            else:
                metadata['error'] = result.stderr
                self.logger.warning(f"RustScan falló: {result.stderr}")
            
            return {'ports': ports, 'metadata': metadata}
            
        except subprocess.TimeoutExpired:
            self.logger.warning("RustScan timeout")
            return {'ports': [], 'metadata': {'error': 'timeout'}}
        except Exception as e:
            self.logger.error(f"Error ejecutando RustScan: {e}")
            return {'ports': [], 'metadata': {'error': str(e)}}

    def _run_masscan(self, target: str, top_ports: Optional[int] = None, all_ports: bool = False) -> Dict[str, Any]:
        """Ejecutar Masscan para escaneo de alta velocidad"""
        self.logger.info(f"Ejecutando Masscan en {target}")
        
        try:
            cmd = ['masscan', target]
            
            if all_ports:
                cmd.extend(['-p', '1-65535'])
            elif top_ports:
                # Usar puertos críticos
                critical_ports_str = ','.join(map(str, self.critical_ports['tcp'][:top_ports]))
                cmd.extend(['-p', critical_ports_str])
            else:
                cmd.extend(['-p', '1-1000'])
            
            # Configurar velocidad
            cmd.extend(['--rate', str(min(self.config.rate_limit, 10000))])
            cmd.extend(['--wait', '3'])  # Esperar 3 segundos para respuestas
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.timeout)
            
            ports = []
            metadata: Dict[str, Any] = {'raw_output': result.stdout, 'command': ' '.join(cmd)}
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'open' in line.lower() and target in line:
                        # Formato: "Discovered open port 22/tcp on 192.168.1.1"
                        match = re.search(r'(\d+)/(tcp|udp)', line)
                        if match:
                            ports.append({
                                'port': int(match.group(1)),
                                'protocol': match.group(2),
                                'state': 'open',
                                'service': 'unknown',
                                'tool': 'masscan'
                            })
                
                metadata['ports_found'] = len(ports)
                self.logger.info(f"Masscan encontró {len(ports)} puertos")
                
            else:
                metadata['error'] = result.stderr
                self.logger.warning(f"Masscan falló: {result.stderr}")
            
            return {'ports': ports, 'metadata': metadata}
            
        except subprocess.TimeoutExpired:
            self.logger.warning("Masscan timeout")
            return {'ports': [], 'metadata': {'error': 'timeout'}}
        except Exception as e:
            self.logger.error(f"Error ejecutando Masscan: {e}")
            return {'ports': [], 'metadata': {'error': str(e)}}

    def _run_nmap_fast(self, target: str) -> Dict[str, Any]:
        """Ejecutar Nmap en modo rápido"""
        self.logger.info(f"Ejecutando Nmap rápido en {target}")
        
        try:
            cmd = ['nmap', '-T4', '-F', '--open', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.timeout // 2)
            
            return self._parse_nmap_output(result.stdout, 'nmap_fast')
            
        except Exception as e:
            self.logger.error(f"Error ejecutando Nmap rápido: {e}")
            return {'ports': [], 'services': [], 'metadata': {'error': str(e)}}

    def _run_nmap_detailed(self, target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Ejecutar Nmap detallado con detección de servicios"""
        self.logger.info(f"Ejecutando Nmap detallado en {target}")
        
        try:
            cmd = ['nmap', '-sS', '-sV', '-O', '--script=default', target]
            
            if ports:
                port_str = ','.join(map(str, ports))
                cmd.extend(['-p', port_str])
            else:
                cmd.append('--top-ports=1000')
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.timeout)
            
            return self._parse_nmap_output(result.stdout, 'nmap_detailed')
            
        except Exception as e:
            self.logger.error(f"Error ejecutando Nmap detallado: {e}")
            return {'ports': [], 'services': [], 'metadata': {'error': str(e)}}

    def _run_nmap_stealth(self, target: str) -> Dict[str, Any]:
        """Ejecutar Nmap en modo sigiloso"""
        self.logger.info(f"Ejecutando Nmap sigiloso en {target}")
        
        try:
            cmd = [
                'nmap', '-sS', '-T2', '--randomize-hosts',
                '-f', '-D', 'RND:10', target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.timeout * 2)
            
            return self._parse_nmap_output(result.stdout, 'nmap_stealth')
            
        except Exception as e:
            self.logger.error(f"Error ejecutando Nmap sigiloso: {e}")
            return {'ports': [], 'services': [], 'metadata': {'error': str(e)}}

    def _run_nmap_aggressive(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Ejecutar Nmap en modo agresivo"""
        self.logger.info(f"Ejecutando Nmap agresivo en {target}")
        
        try:
            port_str = ','.join(map(str, ports))
            cmd = [
                'nmap', '-A', '-T4', '--script=vuln', 
                '-p', port_str, target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.timeout * 2)
            
            return self._parse_nmap_output(result.stdout, 'nmap_aggressive')
            
        except Exception as e:
            self.logger.error(f"Error ejecutando Nmap agresivo: {e}")
            return {'ports': [], 'services': [], 'vulnerabilities': [], 'metadata': {'error': str(e)}}

    def _parse_nmap_output(self, output: str, scan_type: str) -> Dict[str, Any]:
        """Parsear salida de Nmap"""
        ports = []
        services = []
        vulnerabilities = []
        metadata = {'raw_output': output, 'scan_type': scan_type}
        
        try:
            lines = output.split('\n')
            for line in lines:
                # Parsear puertos
                if '/tcp' in line and ('open' in line or 'filtered' in line):
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0].split('/')[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        try:
                            port_num = int(port_info)
                            port_data = {
                                'port': port_num,
                                'protocol': 'tcp',
                                'state': state,
                                'service': service,
                                'tool': 'nmap'
                            }
                            
                            # Información adicional si está disponible
                            if len(parts) > 3:
                                port_data['version'] = ' '.join(parts[3:])
                            
                            ports.append(port_data)
                            
                            # Agregar a servicios si es relevante
                            if service != 'unknown':
                                services.append({
                                    'port': port_num,
                                    'service': service,
                                    'version': port_data.get('version', ''),
                                    'tool': 'nmap'
                                })
                                
                        except ValueError:
                            continue
                
                # Parsear vulnerabilidades de scripts
                if 'VULNERABLE' in line or 'CVE-' in line:
                    vulnerabilities.append({
                        'type': 'nmap_script',
                        'description': line.strip(),
                        'severity': 'medium',
                        'tool': 'nmap'
                    })
        
        except Exception as e:
            metadata['parse_error'] = str(e)
        
        return {
            'ports': ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'metadata': metadata
        }

    def _run_nuclei(self, target: str, ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ejecutar Nuclei para detección de vulnerabilidades"""
        self.logger.info(f"Ejecutando Nuclei en {target}")
        
        vulnerabilities = []
        metadata: Dict[str, Any] = {}
        
        try:
            # Construir lista de URLs basada en puertos encontrados
            urls = []
            for port_info in ports:
                port = port_info.get('port')
                service = port_info.get('service', '')
                
                if port in [80, 8080, 3000, 5000, 8000]:
                    urls.append(f"http://{target}:{port}")
                elif port in [443, 8443]:
                    urls.append(f"https://{target}:{port}")
                elif 'http' in service.lower():
                    urls.append(f"http://{target}:{port}")
            
            # Si no hay URLs específicas, probar puertos web comunes
            if not urls:
                urls = [f"http://{target}", f"https://{target}"]
            
            for url in urls:
                try:
                    cmd = [
                        'nuclei', '-u', url, '-json', '-silent',
                        '-t', '/usr/share/nuclei-templates/'
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True,
                                          timeout=120)
                    
                    if result.returncode == 0 and result.stdout:
                        for line in result.stdout.strip().split('\n'):
                            if line:
                                try:
                                    vuln_data = json.loads(line)
                                    vulnerabilities.append({
                                        'type': 'nuclei',
                                        'template_id': vuln_data.get('template-id', ''),
                                        'severity': vuln_data.get('info', {}).get('severity', 'info'),
                                        'name': vuln_data.get('info', {}).get('name', ''),
                                        'description': vuln_data.get('info', {}).get('description', ''),
                                        'url': url,
                                        'tool': 'nuclei'
                                    })
                                except json.JSONDecodeError:
                                    continue
                
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Nuclei timeout para {url}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Error ejecutando Nuclei para {url}: {e}")
                    continue
            
            metadata['urls_tested'] = len(urls)
            metadata['vulnerabilities_found'] = len(vulnerabilities)
            self.logger.info(f"Nuclei encontró {len(vulnerabilities)} vulnerabilidades")
            
        except Exception as e:
            self.logger.error(f"Error general ejecutando Nuclei: {e}")
            metadata['error'] = str(e)
        
        return {'vulnerabilities': vulnerabilities, 'metadata': metadata}

    def _run_nuclei_aggressive(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Ejecutar Nuclei en modo agresivo con todos los templates"""
        self.logger.info(f"Ejecutando Nuclei agresivo en {target}")
        
        vulnerabilities = []
        
        try:
            # Usar todos los templates disponibles
            cmd = [
                'nuclei', '-u', f"http://{target}", '-json', '-silent',
                '-t', '/usr/share/nuclei-templates/',
                '-severity', 'critical,high,medium'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.timeout)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities.append({
                                'type': 'nuclei_aggressive',
                                'template_id': vuln_data.get('template-id', ''),
                                'severity': vuln_data.get('info', {}).get('severity', 'info'),
                                'name': vuln_data.get('info', {}).get('name', ''),
                                'description': vuln_data.get('info', {}).get('description', ''),
                                'tool': 'nuclei'
                            })
                        except json.JSONDecodeError:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error ejecutando Nuclei agresivo: {e}")
        
        return {'vulnerabilities': vulnerabilities, 'metadata': {}}

    def _web_analysis(self, target: str, web_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Análisis especializado de servicios web"""
        self.logger.info(f"Ejecutando análisis web en {target}")
        
        vulnerabilities = []
        services = []
        metadata: Dict[str, Any] = {}
        
        for port_info in web_ports:
            port = port_info.get('port')
            
            try:
                # Determinar protocolo
                if port in [443, 8443] or 'https' in port_info.get('service', ''):
                    base_url = f"https://{target}:{port}"
                else:
                    base_url = f"http://{target}:{port}"
                
                # Nikto para vulnerabilidades web
                if self.tools_available.get('nikto'):
                    nikto_result = self._run_nikto(base_url)
                    vulnerabilities.extend(nikto_result.get('vulnerabilities', []))
                
                # Whatweb para identificación de tecnologías
                if self.tools_available.get('whatweb'):
                    whatweb_result = self._run_whatweb(base_url)
                    services.extend(whatweb_result.get('services', []))
                
                # Gobuster para fuzzing de directorios
                if self.tools_available.get('gobuster'):
                    gobuster_result = self._run_gobuster(base_url)
                    services.extend(gobuster_result.get('directories', []))
                
            except Exception as e:
                self.logger.warning(f"Error en análisis web del puerto {port}: {e}")
                continue
        
        metadata['ports_analyzed'] = len(web_ports)
        
        return {
            'vulnerabilities': vulnerabilities,
            'services': services,
            'metadata': metadata
        }

    def _run_nikto(self, url: str) -> Dict[str, Any]:
        """Ejecutar Nikto para análisis de vulnerabilidades web"""
        try:
            cmd = ['nikto', '-h', url, '-Format', 'txt']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            vulnerabilities = []
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '+ ' in line and any(word in line.lower() for word in 
                                         ['vuln', 'error', 'exposed', 'default']):
                        vulnerabilities.append({
                            'type': 'web_vulnerability',
                            'description': line.strip(),
                            'severity': 'medium',
                            'url': url,
                            'tool': 'nikto'
                        })
            
            return {'vulnerabilities': vulnerabilities}
            
        except Exception as e:
            self.logger.warning(f"Error ejecutando Nikto: {e}")
            return {'vulnerabilities': []}

    def _run_whatweb(self, url: str) -> Dict[str, Any]:
        """Ejecutar Whatweb para identificación de tecnologías"""
        try:
            cmd = ['whatweb', '--color=never', '--no-errors', url]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            services = []
            if result.returncode == 0:
                # Parsear salida de whatweb
                for line in result.stdout.split('\n'):
                    if url in line:
                        # Extraer tecnologías detectadas
                        technologies = re.findall(r'\[([^\]]+)\]', line)
                        for tech in technologies:
                            services.append({
                                'technology': tech,
                                'url': url,
                                'tool': 'whatweb'
                            })
            
            return {'services': services}
            
        except Exception as e:
            self.logger.warning(f"Error ejecutando Whatweb: {e}")
            return {'services': []}

    def _run_gobuster(self, url: str) -> Dict[str, Any]:
        """Ejecutar Gobuster para fuzzing de directorios"""
        try:
            # Usar wordlist común
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            if not os.path.exists(wordlist):
                wordlist = '/usr/share/seclists/Discovery/Web-Content/common.txt'
            
            if os.path.exists(wordlist):
                cmd = [
                    'gobuster', 'dir', '-u', url, '-w', wordlist,
                    '-t', '20', '--quiet'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                
                directories = []
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '(Status:' in line and '200' in line:
                            path = line.split()[0]
                            directories.append({
                                'path': path,
                                'url': url + path,
                                'status': '200',
                                'tool': 'gobuster'
                            })
                
                return {'directories': directories}
            
        except Exception as e:
            self.logger.warning(f"Error ejecutando Gobuster: {e}")
        
        return {'directories': []}

    def _identify_services(self, target: str, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identificar servicios en puertos específicos"""
        services = []
        
        for port_info in ports[:5]:  # Limitar a primeros 5 puertos
            port = port_info.get('port')
            
            if port is None:
                continue
                
            try:
                # Intentar conexión básica para identificar servicio
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                if sock.connect_ex((target, port)) == 0:
                    # Enviar datos específicos según el puerto
                    service_info = self._probe_service(sock, port)
                    if service_info:
                        services.append({
                            'port': port,
                            'service': service_info.get('service', 'unknown'),
                            'version': service_info.get('version', ''),
                            'banner': service_info.get('banner', ''),
                            'tool': 'manual_probe'
                        })
                
                sock.close()
                
            except Exception:
                continue
        
        return services

    def _probe_service(self, sock: socket.socket, port: int) -> Optional[Dict[str, Any]]:
        """Probar servicio específico en un puerto"""
        try:
            if port == 22:  # SSH
                sock.recv(1024)
                return {'service': 'ssh', 'banner': 'SSH detected'}
            elif port == 80:  # HTTP
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                return {'service': 'http', 'banner': response[:100]}
            elif port == 21:  # FTP
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                return {'service': 'ftp', 'banner': response.strip()}
            
        except Exception:
            pass
        
        return None

    def _passive_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Reconocimiento pasivo del objetivo"""
        services = []
        metadata: Dict[str, Any] = {}
        
        try:
            # DNS lookup
            import socket
            try:
                ip = socket.gethostbyname(target)
                hostname = socket.gethostbyaddr(ip)[0]
                services.append({
                    'type': 'dns_resolution',
                    'ip': ip,
                    'hostname': hostname,
                    'tool': 'passive_recon'
                })
            except:
                pass
            
            # Subdomain enumeration si está disponible
            if self.tools_available.get('subfinder'):
                subdomains = self._run_subfinder(target)
                services.extend(subdomains.get('subdomains', []))
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return {'services': services, 'metadata': metadata}

    def _run_subfinder(self, target: str) -> Dict[str, Any]:
        """Ejecutar Subfinder para enumeración de subdominios"""
        try:
            cmd = ['subfinder', '-d', target, '-silent']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            subdomains = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '.' in line:
                        subdomains.append({
                            'subdomain': line.strip(),
                            'type': 'subdomain',
                            'tool': 'subfinder'
                        })
            
            return {'subdomains': subdomains}
            
        except Exception as e:
            self.logger.warning(f"Error ejecutando Subfinder: {e}")
            return {'subdomains': []}

    def scan_multiple_targets(self, targets: List[str], scan_type: str = 'fast') -> List[ScanResult]:
        """Escanear múltiples objetivos en paralelo"""
        self.logger.info(f"Escaneando {len(targets)} objetivos en paralelo")
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Enviar tareas
            future_to_target = {
                executor.submit(self.scan_target, target, scan_type): target 
                for target in targets
            }
            
            # Recopilar resultados
            for future in concurrent.futures.as_completed(future_to_target, 
                                                         timeout=self.config.timeout * len(targets)):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Completado escaneo de {target}")
                except Exception as e:
                    self.logger.error(f"Error escaneando {target}: {e}")
                    # Crear resultado de error
                    results.append(ScanResult(
                        target=target,
                        scan_type=scan_type,
                        tool='error',
                        timestamp=datetime.now(),
                        duration=0,
                        ports=[],
                        vulnerabilities=[],
                        services=[],
                        metadata={'error': str(e)},
                        success=False,
                        error=str(e)
                    ))
        
        return results

    def generate_report(self, results: Union[ScanResult, List[ScanResult]], 
                       format: str = 'json') -> str:
        """Generar reporte de resultados"""
        if isinstance(results, ScanResult):
            results = [results]
        
        report_data = {
            'scan_summary': {
                'total_targets': len(results),
                'successful_scans': len([r for r in results if r.success]),
                'total_ports_found': sum(len(r.ports) for r in results),
                'total_vulnerabilities': sum(len(r.vulnerabilities) for r in results),
                'scan_timestamp': datetime.now().isoformat(),
                'scanner_version': 'ARESITOS Escaneador Avanzado Kali 2025 v1.0'
            },
            'results': []
        }
        
        for result in results:
            result_data = {
                'target': result.target,
                'scan_type': result.scan_type,
                'tool': result.tool,
                'timestamp': result.timestamp.isoformat(),
                'duration': result.duration,
                'success': result.success,
                'ports': result.ports,
                'vulnerabilities': result.vulnerabilities,
                'services': result.services,
                'metadata': result.metadata
            }
            
            if result.error:
                result_data['error'] = result.error
            
            report_data['results'].append(result_data)
        
        if format == 'json':
            return json.dumps(report_data, indent=2, ensure_ascii=False)
        elif format == 'summary':
            return self._generate_summary_report(report_data)
        else:
            return str(report_data)

    def _generate_summary_report(self, report_data: Dict[str, Any]) -> str:
        """Generar reporte resumido"""
        summary = report_data['scan_summary']
        
        report = f"""
========================================
ARESITOS - REPORTE DE ESCANEO AVANZADO
========================================

Fecha: {summary['scan_timestamp']}
Objetivos escaneados: {summary['total_targets']}
Escaneos exitosos: {summary['successful_scans']}
Puertos encontrados: {summary['total_ports_found']}
Vulnerabilidades detectadas: {summary['total_vulnerabilities']}

RESULTADOS POR OBJETIVO:
"""
        
        for result in report_data['results']:
            report += f"""
----------------------------------------
Objetivo: {result['target']}
Tipo de escaneo: {result['scan_type']}
Herramienta: {result['tool']}
Duración: {result['duration']:.2f}s
Estado: {'ÉXITO' if result['success'] else 'ERROR'}

Puertos abiertos: {len(result['ports'])}
"""
            for port in result['ports'][:5]:  # Primeros 5 puertos
                report += f"  - {port['port']}/{port['protocol']} ({port['service']})\n"
            
            if result['vulnerabilities']:
                report += f"Vulnerabilidades: {len(result['vulnerabilities'])}\n"
                for vuln in result['vulnerabilities'][:3]:  # Primeras 3
                    report += f"  - {vuln.get('name', vuln.get('description', 'N/A'))}\n"
            
            if result.get('error'):
                report += f"Error: {result['error']}\n"
        
        return report

    def _verificar_herramienta(self, herramienta: str) -> bool:
        """Verificar si una herramienta está disponible en el sistema."""
        return self.tools_available.get(herramienta, False)

# Funciones de utilidad para integración con ARESITOS

def crear_escaneador_configurado() -> EscaneadorAvanzadoKali2025:
    """Crear instancia del escaneador con configuración optimizada para ARESITOS"""
    config = ScannerConfig(
        timeout=300,
        max_workers=3,
        rate_limit=1000,
        enable_service_detection=True,
        enable_vuln_scan=True,
        enable_web_scan=True
    )
    
    return EscaneadorAvanzadoKali2025(config)

def escaneo_rapido_aresitos(target: str) -> Dict[str, Any]:
    """Función helper para escaneo rápido compatible con ARESITOS"""
    escaneador = crear_escaneador_configurado()
    resultado = escaneador.scan_target(target, 'fast')
    
    # Convertir a formato compatible con ARESITOS
    return {
        'exito': resultado.success,
        'objetivo': resultado.target,
        'puertos_encontrados': resultado.ports,
        'servicios_detectados': resultado.services,
        'vulnerabilidades': resultado.vulnerabilities,
        'herramienta': resultado.tool,
        'duracion': resultado.duration,
        'timestamp': resultado.timestamp.isoformat(),
        'metadata': resultado.metadata,
        'error': resultado.error
    }

def escaneo_completo_aresitos(target: str) -> Dict[str, Any]:
    """Función helper para escaneo completo compatible con ARESITOS"""
    escaneador = crear_escaneador_configurado()
    resultado = escaneador.scan_target(target, 'complete')
    
    return {
        'exito': resultado.success,
        'objetivo': resultado.target,
        'puertos_encontrados': resultado.ports,
        'servicios_detectados': resultado.services,
        'vulnerabilidades': resultado.vulnerabilities,
        'herramienta': resultado.tool,
        'duracion': resultado.duration,
        'timestamp': resultado.timestamp.isoformat(),
        'metadata': resultado.metadata,
        'error': resultado.error
    }

if __name__ == "__main__":
    # Prueba rápida del escaneador
    print("ARESITOS - Escaneador Avanzado Kali 2025")
    print("=========================================")
    
    escaneador = crear_escaneador_configurado()
    print(f"Herramientas disponibles: {list(escaneador.tools_available.keys())}")
    
    # Prueba básica
    resultado = escaneo_rapido_aresitos('127.0.0.1')
    print(f"\nPrueba en localhost:")
    print(f"Éxito: {resultado['exito']}")
    print(f"Puertos encontrados: {len(resultado['puertos_encontrados'])}")
    print(f"Herramienta usada: {resultado['herramienta']}")
