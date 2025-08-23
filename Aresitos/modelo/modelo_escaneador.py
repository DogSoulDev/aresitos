# -*- coding: utf-8 -*-
"""
ARESITOS - Modelo Escaneador Unificado v3.0
==========================================

Sistema de escaneo unificado que consolida todas las funcionalidades 
de escaneo de seguridad en un único archivo optimizado.

Funcionalidades integradas:
- Escaneo de sistema (procesos, servicios, integridad)
- Escaneo de red (puertos, servicios, DNS)
- Herramientas Kali Linux (nmap, rustscan, nuclei, masscan, nikto)
- Análisis de vulnerabilidades
- Detección de servicios web
- Análisis forense básico

Principios ARESITOS aplicados:
- Archivo único consolidado
- Python nativo + Kali tools únicamente
- Sin dependencias externas
- Código limpio y optimizado
- MVC arquitectura respetada
- Sin emoticonos/tokens decorativos

Autor: DogSoulDev
Fecha: Agosto 2025
Versión: ARESITOS v3.0
"""

import subprocess
import socket
import threading
import json
import time
import logging
import os
import sys
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict


class TipoEscaneo(Enum):
    """Tipos de escaneo disponibles."""
    RED = "red"
    SISTEMA = "sistema" 
    VULNERABILIDADES = "vulnerabilidades"
    WEB = "web"
    COMPLETO = "completo"


class NivelCriticidad(Enum):
    """Niveles de criticidad para vulnerabilidades."""
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"


@dataclass
class ResultadoEscaneo:
    """Estructura para resultados de escaneo."""
    timestamp: datetime
    objetivo: str
    tipo: TipoEscaneo
    hosts_detectados: List[Dict[str, Any]]
    puertos_abiertos: List[Dict[str, Any]]
    vulnerabilidades: List[Dict[str, Any]]
    servicios_detectados: List[Dict[str, Any]]
    errores: List[str]
    herramientas_usadas: List[str]
    duracion: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario."""
        resultado = asdict(self)
        resultado['timestamp'] = self.timestamp.isoformat()
        resultado['tipo'] = self.tipo.value if hasattr(self.tipo, 'value') else str(self.tipo)
        return resultado


@dataclass 
class ConfiguracionEscaneo:
    """Configuración para escaneos."""
    tipo: TipoEscaneo = TipoEscaneo.COMPLETO
    timeout: int = 300
    threads: int = 10
    incluir_vulns: bool = True
    escaneo_web: bool = True
    usar_sudo: bool = False


class EscaneadorCompleto:
    """
    Escaneador completo y unificado ARESITOS v3.0
    
    Integra todas las funcionalidades de escaneo de seguridad
    en una clase unificada y optimizada.
    """
    
    def __init__(self, gestor_permisos=None):
        self.version = "3.0"
        self.gestor_permisos = gestor_permisos
        self.logger = logging.getLogger(__name__)
        self.escaneando = False
        self.progreso = 0
        self.ultimo_resultado = None
        
        # Configuración por defecto
        self.configuracion = {
            'timeout_comandos': 300,
            'max_threads': 10,
            'usar_sudo': False,
            'herramientas_disponibles': []
        }
        
        # Verificar herramientas disponibles
        self._verificar_herramientas()
        
        self.logger.info(f"EscaneadorCompleto v{self.version} inicializado")
        self.logger.info(f"Herramientas disponibles: {len(self.configuracion['herramientas_disponibles'])}")

    def _verificar_herramientas(self):
        """Verificar disponibilidad de herramientas."""
        herramientas = [
            'nmap', 'rustscan', 'masscan', 'nuclei', 
            'nikto', 'whatweb', 'gobuster', 'dig'
        ]
        
        disponibles = []
        for herramienta in herramientas:
            try:
                resultado = subprocess.run(
                    ['which', herramienta] if os.name != 'nt' else ['where', herramienta],
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                if resultado.returncode == 0:
                    disponibles.append(herramienta)
            except:
                pass
        
        self.configuracion['herramientas_disponibles'] = disponibles
        self.logger.debug(f"Herramientas verificadas: {disponibles}")

    def escanear(self, objetivo: str, tipo_escaneo: str = "completo", 
                configuracion: Optional[ConfiguracionEscaneo] = None) -> ResultadoEscaneo:
        """
        Realizar escaneo según tipo especificado.
        
        Args:
            objetivo: IP, rango o hostname a escanear
            tipo_escaneo: Tipo de escaneo (red, sistema, vulnerabilidades, web, completo)
            configuracion: Configuración específica del escaneo
            
        Returns:
            ResultadoEscaneo: Resultado del escaneo realizado
        """
        if self.escaneando:
            raise RuntimeError("Ya hay un escaneo en progreso")
            
        self.escaneando = True
        self.progreso = 0
        inicio = time.time()
        
        try:
            if configuracion is None:
                configuracion = ConfiguracionEscaneo()
            
            resultado = ResultadoEscaneo(
                timestamp=datetime.now(),
                objetivo=objetivo,
                tipo=TipoEscaneo(tipo_escaneo) if tipo_escaneo in [t.value for t in TipoEscaneo] else TipoEscaneo.COMPLETO,
                hosts_detectados=[],
                puertos_abiertos=[],
                vulnerabilidades=[],
                servicios_detectados=[],
                errores=[],
                herramientas_usadas=[],
                duracion=0.0
            )
            
            # Ejecutar escaneos según tipo
            if tipo_escaneo in ["red", "completo"]:
                self._escanear_red(objetivo, resultado, configuracion)
                self.progreso = 30
                
            if tipo_escaneo in ["sistema", "completo"]:
                self._escanear_sistema(resultado, configuracion)
                self.progreso = 60
                
            if tipo_escaneo in ["vulnerabilidades", "completo"]:
                self._escanear_vulnerabilidades(objetivo, resultado, configuracion)
                self.progreso = 80
                
            if tipo_escaneo in ["web", "completo"]:
                self._escanear_web(objetivo, resultado, configuracion)
                
            self.progreso = 100
            resultado.duracion = time.time() - inicio
            self.ultimo_resultado = resultado.to_dict()
            
            self.logger.info(f"Escaneo completado en {resultado.duracion:.2f}s")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en escaneo: {e}")
            raise
        finally:
            self.escaneando = False

    def _escanear_red(self, objetivo: str, resultado: ResultadoEscaneo, 
                     configuracion: ConfiguracionEscaneo):
        """Escanear red con herramientas disponibles."""
        self.logger.info(f"Iniciando escaneo de red: {objetivo}")
        
        # Resolver DNS primero
        self._resolver_dns(objetivo, resultado)
        
        # Escanear con herramientas disponibles
        if 'nmap' in self.configuracion['herramientas_disponibles']:
            self._escanear_con_nmap(objetivo, resultado)
        
        if 'rustscan' in self.configuracion['herramientas_disponibles']:
            self._escanear_con_rustscan(objetivo, resultado)
        elif 'masscan' in self.configuracion['herramientas_disponibles']:
            self._escanear_con_masscan(objetivo, resultado)
            
        # Detectar servicios en puertos encontrados
        if resultado.puertos_abiertos:
            self._detectar_servicios(objetivo, resultado)

    def _escanear_sistema(self, resultado: ResultadoEscaneo, 
                         configuracion: ConfiguracionEscaneo):
        """Escanear sistema local."""
        self.logger.info("Iniciando escaneo de sistema")
        
        try:
            # Analizar procesos
            self._analizar_procesos(resultado)
            
            # Obtener métricas del sistema
            self._obtener_metricas_sistema(resultado)
            
        except Exception as e:
            resultado.errores.append(f"Error en escaneo de sistema: {str(e)}")

    def _escanear_vulnerabilidades(self, objetivo: str, resultado: ResultadoEscaneo,
                                  configuracion: ConfiguracionEscaneo):
        """Escanear vulnerabilidades con nuclei."""
        if 'nuclei' in self.configuracion['herramientas_disponibles']:
            self._escanear_con_nuclei(objetivo, resultado)

    def _escanear_web(self, objetivo: str, resultado: ResultadoEscaneo,
                     configuracion: ConfiguracionEscaneo):
        """Escanear servicios web."""
        if 'nikto' in self.configuracion['herramientas_disponibles']:
            self._escanear_con_nikto(objetivo, resultado)
            
        if 'whatweb' in self.configuracion['herramientas_disponibles']:
            self._detectar_tecnologias_web(objetivo, resultado)

    def _escanear_con_nmap(self, objetivo: str, resultado: ResultadoEscaneo):
        """Escanear con nmap."""
        try:
            cmd = ['nmap', '-sS', '-O', '-sV', '--top-ports', '1000', objetivo]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.configuracion['timeout_comandos'])
            resultado.herramientas_usadas.append('nmap')
            
            # Parsear resultados nmap
            lineas = proc.stdout.split('\n')
            for linea in lineas:
                if '/tcp' in linea and 'open' in linea:
                    partes = linea.split()
                    if len(partes) >= 3:
                        puerto = partes[0].split('/')[0]
                        servicio = partes[2] if len(partes) > 2 else 'unknown'
                        resultado.puertos_abiertos.append({
                            'puerto': int(puerto),
                            'protocolo': 'tcp',
                            'estado': 'abierto',
                            'servicio': servicio
                        })
                        
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo nmap")
        except Exception as e:
            resultado.errores.append(f"Error con nmap: {str(e)}")

    def _escanear_con_rustscan(self, objetivo: str, resultado: ResultadoEscaneo):
        """Escanear con rustscan."""
        try:
            cmd = ['rustscan', '-a', objetivo, '--', '-sV']
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            resultado.herramientas_usadas.append('rustscan')
            
            # Parsear resultados
            lineas = proc.stdout.split('\n')
            for linea in lineas:
                if 'Open' in linea and ':' in linea:
                    try:
                        puerto = int(linea.split(':')[1].strip())
                        resultado.puertos_abiertos.append({
                            'puerto': puerto,
                            'protocolo': 'tcp',
                            'estado': 'abierto',
                            'servicio': 'unknown'
                        })
                    except:
                        continue
                        
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo rustscan")
        except Exception as e:
            resultado.errores.append(f"Error con rustscan: {str(e)}")

    def _escanear_con_masscan(self, objetivo: str, resultado: ResultadoEscaneo):
        """Escanear con masscan."""
        try:
            cmd = ['masscan', objetivo, '-p1-1000', '--rate=1000']
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            resultado.herramientas_usadas.append('masscan')
            
            # Parsear resultados
            self._parsear_masscan_output(proc.stdout, resultado)
            
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo masscan")
        except Exception as e:
            resultado.errores.append(f"Error con masscan: {str(e)}")

    def _escanear_con_nuclei(self, objetivo: str, resultado: ResultadoEscaneo):
        """Escanear vulnerabilidades con nuclei."""
        try:
            cmd = ['nuclei', '-t', '/usr/share/nuclei-templates/', '-u', objetivo, '-j']
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            resultado.herramientas_usadas.append('nuclei')
            
            # Parsear resultados JSON
            lineas = proc.stdout.split('\n')
            for linea in lineas:
                if linea.strip():
                    try:
                        vuln = json.loads(linea)
                        resultado.vulnerabilidades.append({
                            'tipo': vuln.get('info', {}).get('name', 'Unknown'),
                            'severidad': vuln.get('info', {}).get('severity', 'low'),
                            'descripcion': vuln.get('info', {}).get('description', ''),
                            'url': vuln.get('matched-at', ''),
                            'cvss': 0.0
                        })
                    except:
                        continue
                        
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo nuclei")
        except Exception as e:
            resultado.errores.append(f"Error con nuclei: {str(e)}")

    def _escanear_con_nikto(self, objetivo: str, resultado: ResultadoEscaneo):
        """Escanear con nikto."""
        try:
            cmd = ['nikto', '-h', objetivo, '-Format', 'txt']
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            resultado.herramientas_usadas.append('nikto')
            
            # Parsear resultados
            lineas = proc.stdout.split('\n')
            for linea in lineas:
                if '+ ' in linea and ('OSVDB' in linea or 'CVE' in linea):
                    resultado.vulnerabilidades.append({
                        'tipo': 'web_vulnerability',
                        'descripcion': linea.strip(),
                        'severidad': 'media',
                        'cvss': 5.0
                    })
                    
        except subprocess.TimeoutExpired:
            resultado.errores.append("Timeout en escaneo nikto")
        except Exception as e:
            resultado.errores.append(f"Error con nikto: {str(e)}")

    def _detectar_tecnologias_web(self, objetivo: str, resultado: ResultadoEscaneo):
        """Detectar tecnologías web con whatweb."""
        try:
            cmd = ['whatweb', '--log-json=/tmp/whatweb_out.json', objetivo]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            resultado.herramientas_usadas.append('whatweb')
            
            # Leer resultados JSON
            try:
                with open('/tmp/whatweb_out.json', 'r') as f:
                    for line in f:
                        data = json.loads(line)
                        if 'plugins' in data:
                            for plugin, info in data['plugins'].items():
                                if isinstance(info, dict) and info:
                                    resultado.servicios_detectados.append({
                                        'tecnologia': plugin,
                                        'version': info.get('version', [''])[0] if 'version' in info else '',
                                        'descripcion': str(info),
                                        'url': objetivo
                                    })
            except:
                pass
                
        except Exception as e:
            resultado.errores.append(f"Error con whatweb: {str(e)}")

    def _resolver_dns(self, objetivo: str, resultado: ResultadoEscaneo):
        """Resolver DNS del objetivo."""
        try:
            import socket
            ip = socket.gethostbyname(objetivo)
            hostname = socket.gethostbyaddr(ip)[0]
            
            resultado.hosts_detectados.append({
                'ip': ip,
                'hostname': hostname,
                'estado': 'activo'
            })
            
        except Exception as e:
            # Si falla DNS, asumir que es IP directa
            resultado.hosts_detectados.append({
                'ip': objetivo,
                'hostname': '',
                'estado': 'activo'
            })

    def _analizar_procesos(self, resultado: ResultadoEscaneo):
        """Analizar procesos del sistema."""
        try:
            procesos_sospechosos = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    # Detectar procesos con alto uso de recursos
                    if info['cpu_percent'] > 80 or info['memory_percent'] > 50:
                        procesos_sospechosos.append({
                            'pid': info['pid'],
                            'nombre': info['name'],
                            'cpu': info['cpu_percent'],
                            'memoria': info['memory_percent']
                        })
                except:
                    continue
            
            if procesos_sospechosos:
                resultado.vulnerabilidades.append({
                    'tipo': 'system_high_resource_usage',
                    'descripcion': f"Procesos con alto uso de recursos detectados: {len(procesos_sospechosos)}",
                    'severidad': 'media',
                    'detalles': procesos_sospechosos
                })
                
        except Exception as e:
            resultado.errores.append(f"Error analizando procesos: {str(e)}")

    def _obtener_metricas_sistema(self, resultado: ResultadoEscaneo):
        """Obtener métricas del sistema."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memoria = psutil.virtual_memory()
            disco = psutil.disk_usage('/')
            
            metricas = {
                'cpu_uso': cpu_percent,
                'memoria_uso': memoria.percent,
                'disco_uso': disco.percent,
                'procesos_activos': len(psutil.pids())
            }
            
            # Alertas por alto uso de recursos
            if cpu_percent > 90:
                resultado.vulnerabilidades.append({
                    'tipo': 'high_cpu_usage',
                    'descripcion': f"Alto uso de CPU: {cpu_percent}%",
                    'severidad': 'alta'
                })
                
            if memoria.percent > 90:
                resultado.vulnerabilidades.append({
                    'tipo': 'high_memory_usage', 
                    'descripcion': f"Alto uso de memoria: {memoria.percent}%",
                    'severidad': 'alta'
                })
                
        except Exception as e:
            resultado.errores.append(f"Error obteniendo métricas: {str(e)}")

    def _detectar_servicios(self, objetivo: str, resultado: ResultadoEscaneo):
        """Detectar servicios en puertos abiertos."""
        servicios_comunes = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 993: "imaps", 995: "pop3s"
        }
        
        for puerto_info in resultado.puertos_abiertos:
            puerto = puerto_info.get("puerto")
            if puerto in servicios_comunes:
                puerto_info["servicio"] = servicios_comunes[puerto]
                resultado.servicios_detectados.append({
                    "puerto": puerto,
                    "servicio": servicios_comunes[puerto],
                    "version": "detectando...",
                    "banner": ""
                })

    def _parsear_masscan_output(self, output: str, resultado: ResultadoEscaneo):
        """Parsear salida de masscan."""
        lineas = output.split('\n')
        
        for linea in lineas:
            if 'open' in linea.lower():
                partes = linea.split()
                if len(partes) >= 4:
                    try:
                        puerto = int(partes[3].split('/')[0])
                        protocolo = partes[3].split('/')[1] if '/' in partes[3] else 'tcp'
                        
                        resultado.puertos_abiertos.append({
                            "puerto": puerto,
                            "protocolo": protocolo,
                            "estado": "abierto",
                            "servicio": "unknown"
                        })
                    except (ValueError, IndexError):
                        continue

    # MÉTODOS DE COMPATIBILIDAD LEGACY
    def escanear_completo(self, objetivo, tipo_escaneo="completo"):
        """Interfaz de compatibilidad."""
        resultado = self.escanear(objetivo, tipo_escaneo)
        return resultado.to_dict()
    
    def escanear_sistema(self, tipo_escaneo="completo"):
        """Interfaz de compatibilidad para escaneo de sistema."""
        resultado = self.escanear("localhost", "sistema")
        return resultado.to_dict()
    
    def escanear_red(self, objetivo):
        """Interfaz de compatibilidad para escaneo de red."""
        resultado = self.escanear(objetivo, "red")
        return resultado.to_dict()
    
    def escanear_puertos(self, objetivo, protocolo="tcp"):
        """Interfaz de compatibilidad para escaneo de puertos."""
        resultado = self.escanear(objetivo, "red")
        return resultado.to_dict()

    def generar_reporte_completo(self):
        """Generar reporte completo del último escaneo."""
        if not self.ultimo_resultado:
            return {"error": "No hay resultados de escaneo disponibles"}
        
        reporte = {
            "timestamp": datetime.now().isoformat(),
            "tipo": "reporte_completo",
            "resumen": {
                "hosts_detectados": len(self.ultimo_resultado.get("hosts_detectados", [])),
                "puertos_abiertos": len([p for p in self.ultimo_resultado.get("puertos_abiertos", []) 
                                       if p.get("estado") == "abierto"]),
                "vulnerabilidades": len(self.ultimo_resultado.get("vulnerabilidades", []))
            },
            "detalles": self.ultimo_resultado
        }
        
        return reporte

    def detener_escaneo(self):
        """Detener escaneo en progreso."""
        self.escaneando = False
        
    def esta_escaneando(self) -> bool:
        """Verificar si está escaneando."""
        return self.escaneando

    def obtener_progreso(self) -> int:
        """Obtener progreso actual."""
        return self.progreso

    def obtener_capacidades(self) -> List[str]:
        """Obtener capacidades del escaneador."""
        return [
            "Escaneo de puertos TCP/UDP",
            "Detección de servicios",
            "Análisis de vulnerabilidades", 
            "Escaneo de sistema",
            "Resolución DNS",
            "Métricas de sistema",
            f"Herramientas disponibles: {len(self.configuracion['herramientas_disponibles'])}"
        ]

    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas del escaneador."""
        return {
            'version': self.version,
            'herramientas_disponibles': self.configuracion['herramientas_disponibles'],
            'ultimo_escaneo': self.ultimo_resultado.get('timestamp') if self.ultimo_resultado else None,
            'capacidades': len(self.obtener_capacidades())
        }
    
    # Métodos CRUD para ARESITOS
    def crear(self, datos):
        """Crea una nueva configuración de escaneo."""
        try:
            if not isinstance(datos, dict):
                raise ValueError("Los datos deben ser un diccionario")
            # Implementar creación específica
            return True
        except Exception as e:
            raise Exception(f'Error en crear(): {e}')
    
    def obtener(self, identificador):
        """Obtiene configuración por identificador."""
        try:
            # Implementar búsqueda específica
            return None
        except Exception as e:
            raise Exception(f'Error en obtener(): {e}')
    
    def actualizar(self, identificador, datos):
        """Actualiza configuración existente."""
        try:
            if not isinstance(datos, dict):
                raise ValueError("Los datos deben ser un diccionario")
            # Implementar actualización específica
            return True
        except Exception as e:
            raise Exception(f'Error en actualizar(): {e}')
    
    def eliminar(self, identificador):
        """Elimina configuración por identificador."""
        try:
            # Implementar eliminación específica
            return True
        except Exception as e:
            raise Exception(f'Error en eliminar(): {e}')


# Aliases para compatibilidad
EscaneadorSistema = EscaneadorCompleto
EscaneadorRed = EscaneadorCompleto
class EscaneadorCRUD:
    def guardar_datos(self, datos):
        """Guarda datos en el modelo (método CRUD)."""
        try:
            # Implementar guardado específico del modelo
            return True
        except Exception as e:
            raise Exception(f'Error guardando datos: {e}')

    def obtener_datos(self, filtros=None):
        """Obtiene datos del modelo (método CRUD)."""
        try:
            # Implementar consulta específica del modelo
            return []
        except Exception as e:
            raise Exception(f'Error obteniendo datos: {e}')

    def validar_datos_entrada(self, datos):
        """Valida datos de entrada (principio de Seguridad ARESITOS)."""
        if not isinstance(datos, dict):
            return False
        # Implementar validaciones específicas del modelo
        return True
