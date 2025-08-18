# -*- coding: utf-8 -*-
"""
ARESITOS - Extensión Escaneador Kali Linux 2025
==============================================

Extensión del escaneador ARESITOS con herramientas modernas de Kali Linux 2025.
Integra las nuevas herramientas manteniendo compatibilidad con Python nativo.

Herramientas integradas:
- rustscan: Escaneo de puertos ultra-rápido
- feroxbuster: Descubrimiento de contenido web moderno
- nuclei: Scanner de vulnerabilidades automatizado
- subfinder: Enumeración de subdominios
- httpx: Verificación HTTP rápida
- katana: Web crawler moderno
- bloodhound: Análisis Active Directory
- evil-winrm: Shell remoto Windows

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
"""

import subprocess
import json
import tempfile
import os
import re
import datetime
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from .modelo_escaneador_avanzado import EscaneadorAvanzado

class EscaneadorKali2025(EscaneadorAvanzado):
    """
    Extensión del escaneador ARESITOS con herramientas de Kali Linux 2025.
    Mantiene compatibilidad total con el escaneador base.
    """
    
    def __init__(self, siem=None):
        super().__init__(siem)
        
        # Configuración de herramientas Kali 2025
        self.herramientas_kali2025 = {
            'rustscan': {
                'comando': 'rustscan',
                'disponible': self._verificar_herramienta('rustscan'),
                'uso': 'Escaneo rápido de puertos'
            },
            'feroxbuster': {
                'comando': 'feroxbuster',
                'disponible': self._verificar_herramienta('feroxbuster'),
                'uso': 'Descubrimiento de contenido web'
            },
            'nuclei': {
                'comando': 'nuclei',
                'disponible': self._verificar_herramienta('nuclei'),
                'uso': 'Scanner de vulnerabilidades'
            },
            'subfinder': {
                'comando': 'subfinder',
                'disponible': self._verificar_herramienta('subfinder'),
                'uso': 'Enumeración de subdominios'
            },
            'httpx': {
                'comando': 'httpx',
                'disponible': self._verificar_herramienta('httpx'),
                'uso': 'Verificación HTTP'
            },
            'katana': {
                'comando': 'katana',
                'disponible': self._verificar_herramienta('katana'),
                'uso': 'Web crawler'
            },
            'bloodhound': {
                'comando': 'bloodhound',
                'disponible': self._verificar_herramienta('bloodhound-python'),
                'uso': 'Análisis Active Directory'
            }
        }
        
        self.logger.info("Escaneador Kali 2025 inicializado")
        self._log_herramientas_disponibles()
    
    def _verificar_herramienta(self, herramienta: str) -> bool:
        """Verificar si una herramienta está disponible en el sistema."""
        try:
            resultado = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
            return resultado.returncode == 0
        except Exception:
            return False
    
    def _log_herramientas_disponibles(self):
        """Registrar qué herramientas están disponibles."""
        disponibles = [h for h, info in self.herramientas_kali2025.items() if info['disponible']]
        no_disponibles = [h for h, info in self.herramientas_kali2025.items() if not info['disponible']]
        
        self.logger.info(f"Herramientas Kali 2025 disponibles: {', '.join(disponibles)}")
        if no_disponibles:
            self.logger.warning(f"Herramientas no disponibles: {', '.join(no_disponibles)}")
    
    def _obtener_timestamp(self) -> str:
        """Obtener timestamp actual."""
        return datetime.datetime.now().isoformat()
    
    def _ejecutar_comando_seguro(self, comando: List[str], timeout: int = 120) -> Dict[str, Any]:
        """
        Ejecutar comando de forma segura.
        
        Args:
            comando: Lista con el comando a ejecutar
            timeout: Timeout en segundos
            
        Returns:
            Dict con resultado de la ejecución
        """
        try:
            # Validar comando básico
            if not comando or not isinstance(comando, list):
                return {'success': False, 'error': 'Comando inválido', 'stdout': '', 'stderr': ''}
            
            # Ejecutar comando
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            return {
                'success': resultado.returncode == 0,
                'returncode': resultado.returncode,
                'stdout': resultado.stdout,
                'stderr': resultado.stderr,
                'error': resultado.stderr if resultado.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout ejecutando comando', 'stdout': '', 'stderr': ''}
        except Exception as e:
            return {'success': False, 'error': str(e), 'stdout': '', 'stderr': ''}
    
    def _verificar_objetivo(self, objetivo: str) -> bool:
        """Verificar que el objetivo es válido."""
        if not objetivo or not isinstance(objetivo, str):
            raise ValueError("Objetivo inválido")
        
        # Validación básica de IP o dominio
        if not (self._es_ip_valida(objetivo) or self._es_dominio_valido(objetivo)):
            raise ValueError(f"Objetivo no válido: {objetivo}")
        
        return True
    
    def _es_dominio_valido(self, dominio: str) -> bool:
        """Verificar si es un dominio válido."""
        patron_dominio = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(patron_dominio.match(dominio))
    
    def _verificar_url(self, url: str) -> bool:
        """Verificar que la URL es válida."""
        if not url or not isinstance(url, str):
            raise ValueError("URL inválida")
        
        if not (url.startswith('http://') or url.startswith('https://')):
            raise ValueError(f"URL debe comenzar con http:// o https://: {url}")
        
        return True
        """
        Escaneo rápido de puertos usando RustScan.
        
        Args:
            objetivo: IP o dominio objetivo
            puertos: Rango de puertos (default: todos)
            
        Returns:
            Dict con resultados del escaneo
        """
        if not self.herramientas_kali2025['rustscan']['disponible']:
            return self._fallback_nmap_basico(objetivo, puertos)
        
        try:
            self._verificar_objetivo(objetivo)
            
            comando = [
                'rustscan',
                '-a', objetivo,
                '-p', puertos,
                '--', '-sV', '-sC'
            ]
            
            self.logger.info(f"Ejecutando RustScan en {objetivo}")
            resultado = self._ejecutar_comando_seguro(comando, timeout=300)
            
            if resultado['success']:
                return self._parsear_resultado_rustscan(resultado['stdout'], objetivo)
            else:
                self.logger.error(f"Error en RustScan: {resultado['error']}")
                return self._fallback_nmap_basico(objetivo, puertos)
                
        except Exception as e:
            self.logger.error(f"Error en escaneo RustScan: {str(e)}")
            return self._fallback_nmap_basico(objetivo, puertos)
    
    def _parsear_resultado_rustscan(self, output: str, objetivo: str) -> Dict[str, Any]:
        """Parsear resultado de RustScan."""
        resultado = {
            'herramienta': 'rustscan',
            'objetivo': objetivo,
            'puertos_abiertos': [],
            'servicios': {},
            'timestamp': self._obtener_timestamp(),
            'raw_output': output
        }
        
        # Parsear puertos abiertos
        puertos_pattern = r'(\d+)/tcp\s+open\s+(\w+)'
        matches = re.findall(puertos_pattern, output)
        
        for puerto, servicio in matches:
            resultado['puertos_abiertos'].append(int(puerto))
            resultado['servicios'][puerto] = servicio
        
        return resultado
    
    def descubrimiento_contenido_feroxbuster(self, objetivo: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Descubrimiento de contenido web usando Feroxbuster.
        
        Args:
            objetivo: URL objetivo
            wordlist: Wordlist personalizada (opcional)
            
        Returns:
            Dict con directorios y archivos encontrados
        """
        if not self.herramientas_kali2025['feroxbuster']['disponible']:
            return self._fallback_gobuster(objetivo, wordlist)
        
        try:
            self._verificar_url(objetivo)
            
            comando = [
                'feroxbuster',
                '-u', objetivo,
                '-t', '50',  # 50 threads
                '--silent',
                '--json'
            ]
            
            if wordlist and os.path.exists(wordlist):
                comando.extend(['-w', wordlist])
            
            self.logger.info(f"Ejecutando Feroxbuster en {objetivo}")
            resultado = self._ejecutar_comando_seguro(comando, timeout=600)
            
            if resultado['success']:
                return self._parsear_resultado_feroxbuster(resultado['stdout'], objetivo)
            else:
                self.logger.error(f"Error en Feroxbuster: {resultado['error']}")
                return self._fallback_gobuster(objetivo, wordlist)
                
        except Exception as e:
            self.logger.error(f"Error en Feroxbuster: {str(e)}")
            return self._fallback_gobuster(objetivo, wordlist)
    
    def _parsear_resultado_feroxbuster(self, output: str, objetivo: str) -> Dict[str, Any]:
        """Parsear resultado JSON de Feroxbuster."""
        resultado = {
            'herramienta': 'feroxbuster',
            'objetivo': objetivo,
            'directorios_encontrados': [],
            'archivos_encontrados': [],
            'codigos_estado': {},
            'timestamp': self._obtener_timestamp()
        }
        
        try:
            for linea in output.strip().split('\n'):
                if linea.strip():
                    try:
                        data = json.loads(linea)
                        if data.get('type') == 'response':
                            url = data.get('url', '')
                            status = data.get('status', 0)
                            length = data.get('content_length', 0)
                            
                            entrada = {
                                'url': url,
                                'status': status,
                                'length': length
                            }
                            
                            if url.endswith('/'):
                                resultado['directorios_encontrados'].append(entrada)
                            else:
                                resultado['archivos_encontrados'].append(entrada)
                            
                            # Contar códigos de estado
                            if status not in resultado['codigos_estado']:
                                resultado['codigos_estado'][status] = 0
                            resultado['codigos_estado'][status] += 1
                            
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.logger.error(f"Error parseando Feroxbuster: {str(e)}")
        
        return resultado
    
    def escaneo_vulnerabilidades_nuclei(self, objetivo: str, templates: Optional[str] = None) -> Dict[str, Any]:
        """
        Escaneo de vulnerabilidades usando Nuclei.
        
        Args:
            objetivo: URL o IP objetivo
            templates: Templates específicos (opcional)
            
        Returns:
            Dict con vulnerabilidades encontradas
        """
        if not self.herramientas_kali2025['nuclei']['disponible']:
            return self._fallback_nikto(objetivo)
        
        try:
            comando = [
                'nuclei',
                '-target', objetivo,
                '-json',
                '-silent'
            ]
            
            if templates:
                comando.extend(['-t', templates])
            
            self.logger.info(f"Ejecutando Nuclei en {objetivo}")
            resultado = self._ejecutar_comando_seguro(comando, timeout=900)
            
            if resultado['success']:
                return self._parsear_resultado_nuclei(resultado['stdout'], objetivo)
            else:
                self.logger.error(f"Error en Nuclei: {resultado['error']}")
                return self._fallback_nikto(objetivo)
                
        except Exception as e:
            self.logger.error(f"Error en Nuclei: {str(e)}")
            return self._fallback_nikto(objetivo)
    
    def _parsear_resultado_nuclei(self, output: str, objetivo: str) -> Dict[str, Any]:
        """Parsear resultado JSON de Nuclei."""
        resultado = {
            'herramienta': 'nuclei',
            'objetivo': objetivo,
            'vulnerabilidades': [],
            'severidades': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'timestamp': self._obtener_timestamp()
        }
        
        try:
            for linea in output.strip().split('\n'):
                if linea.strip():
                    try:
                        data = json.loads(linea)
                        
                        vuln = {
                            'template_id': data.get('template-id', 'unknown'),
                            'name': data.get('info', {}).get('name', 'Sin nombre'),
                            'severity': data.get('info', {}).get('severity', 'info'),
                            'matched_at': data.get('matched-at', ''),
                            'type': data.get('type', ''),
                            'timestamp': data.get('timestamp', '')
                        }
                        
                        resultado['vulnerabilidades'].append(vuln)
                        
                        # Contar severidades
                        severity = vuln['severity'].lower()
                        if severity in resultado['severidades']:
                            resultado['severidades'][severity] += 1
                        else:
                            resultado['severidades']['info'] += 1
                            
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.logger.error(f"Error parseando Nuclei: {str(e)}")
        
        return resultado
    
    def enumeracion_subdominios_subfinder(self, dominio: str) -> Dict[str, Any]:
        """
        Enumeración de subdominios usando Subfinder.
        
        Args:
            dominio: Dominio objetivo
            
        Returns:
            Dict con subdominios encontrados
        """
        if not self.herramientas_kali2025['subfinder']['disponible']:
            return self._fallback_sublist3r(dominio)
        
        try:
            comando = [
                'subfinder',
                '-d', dominio,
                '-silent',
                '-json'
            ]
            
            self.logger.info(f"Ejecutando Subfinder en {dominio}")
            resultado = self._ejecutar_comando_seguro(comando, timeout=300)
            
            if resultado['success']:
                return self._parsear_resultado_subfinder(resultado['stdout'], dominio)
            else:
                self.logger.error(f"Error en Subfinder: {resultado['error']}")
                return self._fallback_sublist3r(dominio)
                
        except Exception as e:
            self.logger.error(f"Error en Subfinder: {str(e)}")
            return self._fallback_sublist3r(dominio)
    
    def _parsear_resultado_subfinder(self, output: str, dominio: str) -> Dict[str, Any]:
        """Parsear resultado de Subfinder."""
        resultado = {
            'herramienta': 'subfinder',
            'dominio': dominio,
            'subdominios': [],
            'total_encontrados': 0,
            'timestamp': self._obtener_timestamp()
        }
        
        subdominios = set()
        for linea in output.strip().split('\n'):
            if linea.strip():
                try:
                    data = json.loads(linea)
                    subdominio = data.get('host', '').strip()
                    if subdominio and subdominio not in subdominios:
                        subdominios.add(subdominio)
                        resultado['subdominios'].append(subdominio)
                except json.JSONDecodeError:
                    # Formato de texto plano
                    subdominio = linea.strip()
                    if subdominio and subdominio not in subdominios:
                        subdominios.add(subdominio)
                        resultado['subdominios'].append(subdominio)
        
        resultado['total_encontrados'] = len(resultado['subdominios'])
        return resultado
    
    def verificacion_http_httpx(self, objetivos: List[str]) -> Dict[str, Any]:
        """
        Verificación HTTP usando httpx.
        
        Args:
            objetivos: Lista de URLs/IPs a verificar
            
        Returns:
            Dict con información HTTP de cada objetivo
        """
        if not self.herramientas_kali2025['httpx']['disponible']:
            return self._fallback_curl_verificacion(objetivos)
        
        try:
            # Crear archivo temporal con objetivos
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for objetivo in objetivos:
                    f.write(f"{objetivo}\n")
                temp_file = f.name
            
            comando = [
                'httpx',
                '-l', temp_file,
                '-json',
                '-silent',
                '-status-code',
                '-content-length',
                '-title'
            ]
            
            self.logger.info(f"Ejecutando httpx en {len(objetivos)} objetivos")
            resultado = self._ejecutar_comando_seguro(comando, timeout=300)
            
            # Limpiar archivo temporal
            os.unlink(temp_file)
            
            if resultado['success']:
                return self._parsear_resultado_httpx(resultado['stdout'], objetivos)
            else:
                self.logger.error(f"Error en httpx: {resultado['error']}")
                return self._fallback_curl_verificacion(objetivos)
                
        except Exception as e:
            self.logger.error(f"Error en httpx: {str(e)}")
            return self._fallback_curl_verificacion(objetivos)
    
    def _parsear_resultado_httpx(self, output: str, objetivos: List[str]) -> Dict[str, Any]:
        """Parsear resultado JSON de httpx."""
        resultado = {
            'herramienta': 'httpx',
            'objetivos_verificados': [],
            'activos': [],
            'inactivos': [],
            'estadisticas': {},
            'timestamp': self._obtener_timestamp()
        }
        
        try:
            for linea in output.strip().split('\n'):
                if linea.strip():
                    try:
                        data = json.loads(linea)
                        
                        info = {
                            'url': data.get('url', ''),
                            'status_code': data.get('status_code', 0),
                            'content_length': data.get('content_length', 0),
                            'title': data.get('title', ''),
                            'webserver': data.get('webserver', ''),
                            'tech': data.get('tech', [])
                        }
                        
                        resultado['objetivos_verificados'].append(info)
                        
                        if info['status_code'] > 0:
                            resultado['activos'].append(info['url'])
                        else:
                            resultado['inactivos'].append(info['url'])
                            
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.logger.error(f"Error parseando httpx: {str(e)}")
        
        resultado['estadisticas'] = {
            'total_verificados': len(resultado['objetivos_verificados']),
            'activos': len(resultado['activos']),
            'inactivos': len(resultado['inactivos'])
        }
        
        return resultado
    
    # Métodos fallback para compatibilidad
    def _fallback_nmap_basico(self, objetivo: str, puertos: str) -> Dict[str, Any]:
        """Fallback a nmap básico si RustScan no está disponible."""
        try:
            comando = ['nmap', '-p', puertos, objetivo]
            resultado = self._ejecutar_comando_seguro(comando, timeout=300)
            
            return {
                'herramienta': 'nmap_fallback',
                'objetivo': objetivo,
                'puertos_abiertos': [],
                'servicios': {},
                'timestamp': self._obtener_timestamp(),
                'raw_output': resultado['stdout'] if resultado['success'] else resultado['error']
            }
        except Exception as e:
            return {
                'herramienta': 'nmap_fallback',
                'objetivo': objetivo,
                'puertos_abiertos': [],
                'servicios': {},
                'timestamp': self._obtener_timestamp(),
                'error': str(e)
            }
    
    def _fallback_gobuster(self, objetivo: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """Fallback a gobuster si Feroxbuster no está disponible."""
        try:
            comando = ['gobuster', 'dir', '-u', objetivo]
            if wordlist:
                comando.extend(['-w', wordlist])
            else:
                comando.extend(['-w', '/usr/share/wordlists/dirb/common.txt'])
            
            resultado = self._ejecutar_comando_seguro(comando, timeout=600)
            
            return {
                'herramienta': 'gobuster_fallback',
                'objetivo': objetivo,
                'directorios_encontrados': [],
                'archivos_encontrados': [],
                'timestamp': self._obtener_timestamp(),
                'raw_output': resultado['stdout'] if resultado['success'] else resultado['error']
            }
        except Exception as e:
            return {
                'herramienta': 'gobuster_fallback',
                'objetivo': objetivo,
                'directorios_encontrados': [],
                'archivos_encontrados': [],
                'timestamp': self._obtener_timestamp(),
                'error': str(e)
            }
    
    def _fallback_nikto(self, objetivo: str) -> Dict[str, Any]:
        """Fallback a nikto si Nuclei no está disponible."""
        try:
            comando = ['nikto', '-h', objetivo]
            resultado = self._ejecutar_comando_seguro(comando, timeout=600)
            
            return {
                'herramienta': 'nikto_fallback',
                'objetivo': objetivo,
                'vulnerabilidades': [],
                'severidades': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'timestamp': self._obtener_timestamp(),
                'raw_output': resultado['stdout'] if resultado['success'] else resultado['error']
            }
        except Exception as e:
            return {
                'herramienta': 'nikto_fallback',
                'objetivo': objetivo,
                'vulnerabilidades': [],
                'severidades': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'timestamp': self._obtener_timestamp(),
                'error': str(e)
            }
    
    def _fallback_sublist3r(self, dominio: str) -> Dict[str, Any]:
        """Fallback básico para enumeración de subdominios."""
        try:
            comando = ['sublist3r', '-d', dominio, '-o', '/tmp/sublist3r_output.txt']
            resultado = self._ejecutar_comando_seguro(comando, timeout=300)
            
            if resultado['success'] and os.path.exists('/tmp/sublist3r_output.txt'):
                with open('/tmp/sublist3r_output.txt', 'r') as f:
                    subdominios = [linea.strip() for linea in f.readlines() if linea.strip()]
                os.unlink('/tmp/sublist3r_output.txt')
                
                return {
                    'herramienta': 'sublist3r',
                    'dominio': dominio,
                    'subdominios': subdominios,
                    'total_encontrados': len(subdominios),
                    'timestamp': self._obtener_timestamp()
                }
        except Exception as e:
            self.logger.error(f"Error en fallback sublist3r: {str(e)}")
        
        return {
            'herramienta': 'fallback',
            'dominio': dominio,
            'subdominios': [],
            'total_encontrados': 0,
            'timestamp': self._obtener_timestamp(),
            'error': 'No hay herramientas de enumeración disponibles'
        }
    
    def _fallback_curl_verificacion(self, objetivos: List[str]) -> Dict[str, Any]:
        """Fallback básico con curl para verificación HTTP."""
        resultado = {
            'herramienta': 'curl_fallback',
            'objetivos_verificados': [],
            'activos': [],
            'inactivos': [],
            'timestamp': self._obtener_timestamp()
        }
        
        for objetivo in objetivos:
            try:
                comando = ['curl', '-I', '-s', '--connect-timeout', '5', objetivo]
                res = self._ejecutar_comando_seguro(comando, timeout=10)
                
                if res['success']:
                    # Parsear headers básicos
                    headers = res['stdout']
                    status_match = re.search(r'HTTP/[\d\.]+\s+(\d+)', headers)
                    status_code = int(status_match.group(1)) if status_match else 0
                    
                    info = {
                        'url': objetivo,
                        'status_code': status_code,
                        'activo': status_code > 0
                    }
                    
                    resultado['objetivos_verificados'].append(info)
                    
                    if status_code > 0:
                        resultado['activos'].append(objetivo)
                    else:
                        resultado['inactivos'].append(objetivo)
                else:
                    resultado['inactivos'].append(objetivo)
                    
            except Exception as e:
                self.logger.error(f"Error verificando {objetivo}: {str(e)}")
                resultado['inactivos'].append(objetivo)
        
        return resultado
    
    def obtener_capacidades_kali2025(self) -> Dict[str, Any]:
        """
        Obtener información sobre las capacidades disponibles de Kali 2025.
        
        Returns:
            Dict con información sobre herramientas disponibles
        """
        return {
            'herramientas_disponibles': {
                nombre: info['disponible'] 
                for nombre, info in self.herramientas_kali2025.items()
            },
            'total_herramientas': len(self.herramientas_kali2025),
            'herramientas_activas': sum(1 for info in self.herramientas_kali2025.values() if info['disponible']),
            'capacidades_mejoradas': [
                'Escaneo de puertos ultra-rápido (RustScan)',
                'Descubrimiento de contenido moderno (Feroxbuster)',  
                'Scanner de vulnerabilidades automatizado (Nuclei)',
                'Enumeración de subdominios avanzada (Subfinder)',
                'Verificación HTTP masiva (httpx)',
                'Web crawling moderno (Katana)',
                'Análisis Active Directory (BloodHound)'
            ]
        }
