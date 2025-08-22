# -*- coding: utf-8 -*-
"""
ARESITOS - Modelo Escaneador Kali Linux 2025
===========================================

Extensión del escaneador base con herramientas modernas de Kali Linux 2025.
Solo herramientas que se instalan fácilmente con 'apt install'.

Herramientas integradas:
- nmap: Motor principal de escaneo
- masscan: Escaneo rápido inicial  
- gobuster: Enumeración de directorios web
- nikto: Análisis de vulnerabilidades web
- nuclei: Scanner moderno de vulnerabilidades
- ffuf: Fuzzing web moderno
- metasploit: Framework de explotación
- sqlmap: Testing de inyecciones SQL
- hydra: Ataques de fuerza bruta

Autor: DogSoulDev
Fecha: 19 de Agosto de 2025
"""

import subprocess
import threading
import json
import os
import time
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime

# Evitar warnings de typing usando TYPE_CHECKING
if TYPE_CHECKING:
    from .modelo_escaneador_avanzado import EscaneadorAvanzado as _EscaneadorAvanzado
else:
    try:
        from .modelo_escaneador_avanzado import EscaneadorAvanzado as _EscaneadorAvanzado
    except ImportError:
        try:
            from .modelo_escaneador_base import EscaneadorBase as _EscaneadorAvanzado
        except ImportError:
            # Fallback completo si no existe ninguno
            class _EscaneadorAvanzado:
                def __init__(self, gestor_permisos=None):
                    self.gestor_permisos = gestor_permisos
                    self.configuracion = {}
                
                def log(self, mensaje: str):
                    print(f"[ESCANEADOR] {mensaje}")

class EscaneadorKali2025(_EscaneadorAvanzado):  # type: ignore
    """
    Escaneador avanzado con herramientas Kali Linux 2025
    """
    
    def __init__(self, gestor_permisos=None):
        super().__init__(gestor_permisos)
        self.herramientas_kali = {
            'nmap': '/usr/bin/nmap',
            'masscan': '/usr/bin/masscan', 
            'gobuster': '/usr/bin/gobuster',
            'nikto': '/usr/bin/nikto',
            'nuclei': '/usr/bin/nuclei',
            'ffuf': '/usr/bin/ffuf',
            'metasploit': '/usr/bin/msfconsole',
            'sqlmap': '/usr/bin/sqlmap',
            'hydra': '/usr/bin/hydra'
        }
        self.verificar_herramientas()
    
    def verificar_herramientas(self):
        """Verifica qué herramientas están disponibles"""
        self.herramientas_disponibles = {}
        
        for herramienta, ruta in self.herramientas_kali.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.herramientas_disponibles[herramienta] = result.stdout.strip()
                    self.log(f"✓ {herramienta} disponible en {result.stdout.strip()}")
                else:
                    self.log(f"✓ {herramienta} no encontrada")
            except Exception as e:
                self.log(f"✓ Error verificando {herramienta}: {e}")
    
    def escaneo_rapido_masscan(self, objetivo: str, puertos: str = "1-65535") -> Dict[str, Any]:
        """
        Escaneo inicial rápido con masscan para identificar puertos abiertos
        """
        self.log(f"[START] Iniciando escaneo rápido masscan: {objetivo}")
        
        if 'masscan' not in self.herramientas_disponibles:
            return {"error": "masscan no disponible"}
        
        try:
            # Comando masscan optimizado
            cmd = [
                'masscan',
                objetivo,
                '-p', puertos,
                '--rate', '1000',
                '--output-format', 'json',
                '--output-filename', '/tmp/masscan_output.json'
            ]
            
            # Ejecutar masscan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Leer resultados JSON
                try:
                    with open('/tmp/masscan_output.json', 'r') as f:
                        datos = json.load(f)
                    
                    puertos_abiertos = []
                    for item in datos:
                        if 'ports' in item:
                            for puerto in item['ports']:
                                puertos_abiertos.append({
                                    'ip': item['ip'],
                                    'puerto': puerto['port'],
                                    'protocolo': puerto['proto'],
                                    'timestamp': item['timestamp']
                                })
                    
                    self.log(f"✓ Masscan completado: {len(puertos_abiertos)} puertos encontrados")
                    return {
                        "exito": True,
                        "puertos_abiertos": puertos_abiertos,
                        "total_puertos": len(puertos_abiertos),
                        "herramienta": "masscan"
                    }
                except Exception as e:
                    self.log(f"✓ Error procesando resultados masscan: {e}")
                    return {"error": f"Error procesando resultados: {e}"}
            else:
                self.log(f"✓ Error masscan: {result.stderr}")
                return {"error": result.stderr}
                
        except Exception as e:
            self.log(f"✓ Error ejecutando masscan: {e}")
            return {"error": str(e)}
    
    def escaneo_detallado_nmap(self, objetivo: str, puertos_encontrados: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Escaneo detallado con nmap basado en puertos encontrados por masscan
        """
        self.log(f"ANALIZANDO Iniciando escaneo detallado nmap: {objetivo}")
        
        if 'nmap' not in self.herramientas_disponibles:
            return {"error": "nmap no disponible"}
        
        try:
            # Si hay puertos específicos, usarlos; sino, top ports
            if puertos_encontrados:
                puertos_str = ','.join(map(str, puertos_encontrados))
                self.log(f"Escaneando puertos específicos: {puertos_str}")
            else:
                puertos_str = "--top-ports=1000"
                self.log("Escaneando top 1000 puertos")
            
            # Comando nmap completo
            cmd = [
                'nmap',
                '-sV',  # Detección de versiones
                '-sC',  # Scripts por defecto
                '-O',   # Detección de OS
                '--version-intensity', '5',
                '-oX', '/tmp/nmap_output.xml',
                '-oN', '/tmp/nmap_output.txt'
            ]
            
            if puertos_encontrados:
                cmd.extend(['-p', puertos_str])
            else:
                cmd.append('--top-ports=1000')
            
            cmd.append(objetivo)
            
            # Ejecutar nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                # Procesar resultados
                servicios = self._procesar_resultados_nmap('/tmp/nmap_output.txt')
                
                self.log(f"✓ Nmap completado: {len(servicios)} servicios detectados")
                return {
                    "exito": True,
                    "servicios": servicios,
                    "archivo_xml": '/tmp/nmap_output.xml',
                    "archivo_txt": '/tmp/nmap_output.txt',
                    "herramienta": "nmap"
                }
            else:
                self.log(f"✓ Error nmap: {result.stderr}")
                return {"error": result.stderr}
                
        except Exception as e:
            self.log(f"✓ Error ejecutando nmap: {e}")
            return {"error": str(e)}
    
    def escaneo_web_gobuster(self, url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Enumeración de directorios web con gobuster
        """
        self.log(f"WEB Iniciando escaneo web gobuster: {url}")
        
        if 'gobuster' not in self.herramientas_disponibles:
            return {"error": "gobuster no disponible"}
        
        try:
            # Wordlist por defecto - modernizada
            if not wordlist:
                wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
                if not os.path.exists(wordlist):
                    wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
            
            # Comando gobuster
            cmd = [
                'gobuster',
                'dir',
                '-u', url,
                '-w', wordlist,
                '-t', '50',  # 50 threads
                '-x', 'php,html,txt,js,asp,aspx',  # Extensiones
                '-o', '/tmp/gobuster_output.txt',
                '--no-error'
            ]
            
            # Ejecutar gobuster
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Procesar resultados (gobuster siempre retorna 0)
            directorios = self._procesar_resultados_gobuster('/tmp/gobuster_output.txt')
            
            self.log(f"✓ Gobuster completado: {len(directorios)} directorios encontrados")
            return {
                "exito": True,
                "directorios": directorios,
                "total_encontrados": len(directorios),
                "herramienta": "gobuster"
            }
            
        except Exception as e:
            self.log(f"✓ Error ejecutando gobuster: {e}")
            return {"error": str(e)}
    
    def escaneo_vulnerabilidades_nuclei(self, objetivo: str) -> Dict[str, Any]:
        """
        Escaneo de vulnerabilidades con nuclei
        """
        self.log(f"[TARGET] Iniciando escaneo nuclei: {objetivo}")
        
        if 'nuclei' not in self.herramientas_disponibles:
            return {"error": "nuclei no disponible"}
        
        try:
            # Comando nuclei
            cmd = [
                'nuclei',
                '-target', objetivo,
                '-json',
                '-o', '/tmp/nuclei_output.json',
                '-severity', 'medium,high,critical',
                '-concurrency', '25'
            ]
            
            # Ejecutar nuclei
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Procesar resultados JSON
            vulnerabilidades = self._procesar_resultados_nuclei('/tmp/nuclei_output.json')
            
            self.log(f"✓ Nuclei completado: {len(vulnerabilidades)} vulnerabilidades encontradas")
            return {
                "exito": True,
                "vulnerabilidades": vulnerabilidades,
                "total_vulnerabilidades": len(vulnerabilidades),
                "herramienta": "nuclei"
            }
            
        except Exception as e:
            self.log(f"✓ Error ejecutando nuclei: {e}")
            return {"error": str(e)}
    
    def fuzzing_web_ffuf(self, url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Fuzzing web moderno con ffuf
        """
        self.log(f"✓ Iniciando fuzzing ffuf: {url}")
        
        if 'ffuf' not in self.herramientas_disponibles:
            return {"error": "ffuf no disponible"}
        
        try:
            # Wordlist por defecto - modernizada
            if not wordlist:
                wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
            
            # Comando ffuf
            cmd = [
                'ffuf',
                '-u', f"{url}/FUZZ",
                '-w', wordlist,
                '-o', '/tmp/ffuf_output.json',
                '-of', 'json',
                '-mc', '200,204,301,302,307,401,403',  # Match codes
                '-t', '40'  # Threads
            ]
            
            # Ejecutar ffuf
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Procesar resultados
            resultados = self._procesar_resultados_ffuf('/tmp/ffuf_output.json')
            
            self.log(f"✓ FFUF completado: {len(resultados)} endpoints encontrados")
            return {
                "exito": True,
                "endpoints": resultados,
                "total_endpoints": len(resultados),
                "herramienta": "ffuf"
            }
            
        except Exception as e:
            self.log(f"✓ Error ejecutando ffuf: {e}")
            return {"error": str(e)}
    
    def escaneo_completo_kali2025(self, objetivo: str) -> Dict[str, Any]:
        """
        Escaneo completo usando todas las herramientas Kali 2025 disponibles
        """
        self.log(f"[START] INICIANDO ESCANEO COMPLETO KALI 2025: {objetivo}")
        
        resultados = {
            "objetivo": objetivo,
            "timestamp": datetime.now().isoformat(),
            "herramientas_utilizadas": [],
            "fases": {}
        }
        
        # FASE 1: Escaneo rápido con masscan
        self.log("FASE 1: Reconocimiento inicial con masscan")
        resultado_masscan = self.escaneo_rapido_masscan(objetivo)
        resultados["fases"]["masscan"] = resultado_masscan
        if resultado_masscan.get("exito"):
            resultados["herramientas_utilizadas"].append("masscan")
            puertos_encontrados = [p["puerto"] for p in resultado_masscan["puertos_abiertos"]]
        else:
            puertos_encontrados = None
        
        # FASE 2: Escaneo detallado con nmap
        self.log("FASE 2: Análisis detallado con nmap")
        resultado_nmap = self.escaneo_detallado_nmap(objetivo, puertos_encontrados)
        resultados["fases"]["nmap"] = resultado_nmap
        if resultado_nmap.get("exito"):
            resultados["herramientas_utilizadas"].append("nmap")
        
        # FASE 3: Escaneo de vulnerabilidades con nuclei
        self.log("FASE 3: Detección de vulnerabilidades con nuclei")
        resultado_nuclei = self.escaneo_vulnerabilidades_nuclei(objetivo)
        resultados["fases"]["nuclei"] = resultado_nuclei
        if resultado_nuclei.get("exito"):
            resultados["herramientas_utilizadas"].append("nuclei")
        
        # FASE 4: Si hay servicios web, escanear con gobuster y ffuf
        servicios_web = self._detectar_servicios_web(resultado_nmap.get("servicios", []))
        if servicios_web:
            self.log("FASE 4: Análisis web con gobuster y ffuf")
            for servicio_web in servicios_web:
                url = f"http://{servicio_web['ip']}:{servicio_web['puerto']}"
                
                # Gobuster
                resultado_gobuster = self.escaneo_web_gobuster(url)
                resultados["fases"][f"gobuster_{servicio_web['puerto']}"] = resultado_gobuster
                if resultado_gobuster.get("exito"):
                    resultados["herramientas_utilizadas"].append("gobuster")
                
                # FFUF
                resultado_ffuf = self.fuzzing_web_ffuf(url)
                resultados["fases"][f"ffuf_{servicio_web['puerto']}"] = resultado_ffuf
                if resultado_ffuf.get("exito"):
                    resultados["herramientas_utilizadas"].append("ffuf")
        
        # Resumen final
        total_puertos = len(resultado_masscan.get("puertos_abiertos", []))
        total_servicios = len(resultado_nmap.get("servicios", []))
        total_vulnerabilidades = len(resultado_nuclei.get("vulnerabilidades", []))
        
        resultados["resumen"] = {
            "puertos_abiertos": total_puertos,
            "servicios_detectados": total_servicios,
            "vulnerabilidades_encontradas": total_vulnerabilidades,
            "herramientas_utilizadas": len(set(resultados["herramientas_utilizadas"])),
            "duracion": "calculada_en_vista"
        }
        
        self.log(f"✓ ESCANEO COMPLETO FINALIZADO")
        self.log(f"RESUMEN: {total_puertos} puertos, {total_servicios} servicios, {total_vulnerabilidades} vulnerabilidades")
        
        return resultados
    
    def _procesar_resultados_nmap(self, archivo: str) -> List[Dict[str, Any]]:
        """Procesa archivo de resultados de nmap"""
        servicios = []
        try:
            if os.path.exists(archivo):
                with open(archivo, 'r') as f:
                    contenido = f.read()
                    # Parseo robusto de resultados nmap usando Python nativo
                    # Compatible con formato estándar nmap (texto plano)
                    lines = contenido.split('\n')
                    for line in lines:
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                puerto = parts[0].split('/')[0]
                                estado = parts[1]
                                servicio = parts[2] if len(parts) > 2 else 'unknown'
                                servicios.append({
                                    'puerto': int(puerto),
                                    'estado': estado,
                                    'servicio': servicio,
                                    'linea_completa': line.strip()
                                })
        except Exception as e:
            self.log(f"Error procesando nmap: {e}")
        return servicios
    
    def _procesar_resultados_gobuster(self, archivo: str) -> List[Dict[str, Any]]:
        """Procesa archivo de resultados de gobuster"""
        directorios = []
        try:
            if os.path.exists(archivo):
                with open(archivo, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('/') and '(Status:' in line:
                            parts = line.split('(Status:')
                            if len(parts) >= 2:
                                directorio = parts[0].strip()
                                status_info = parts[1].strip()
                                directorios.append({
                                    'directorio': directorio,
                                    'status': status_info,
                                    'linea_completa': line.strip()
                                })
        except Exception as e:
            self.log(f"Error procesando gobuster: {e}")
        return directorios
    
    def _procesar_resultados_nuclei(self, archivo: str) -> List[Dict[str, Any]]:
        """Procesa archivo JSON de resultados de nuclei"""
        vulnerabilidades = []
        try:
            if os.path.exists(archivo):
                with open(archivo, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                vulnerabilidades.append({
                                    'template_id': vuln.get('template-id', 'unknown'),
                                    'name': vuln.get('info', {}).get('name', 'unknown'),
                                    'severity': vuln.get('info', {}).get('severity', 'unknown'),
                                    'host': vuln.get('host', 'unknown'),
                                    'matched_at': vuln.get('matched-at', 'unknown')
                                })
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            self.log(f"Error procesando nuclei: {e}")
        return vulnerabilidades
    
    def _procesar_resultados_ffuf(self, archivo: str) -> List[Dict[str, Any]]:
        """Procesa archivo JSON de resultados de ffuf"""
        resultados = []
        try:
            if os.path.exists(archivo):
                with open(archivo, 'r') as f:
                    data = json.load(f)
                    for result in data.get('results', []):
                        resultados.append({
                            'url': result.get('url', 'unknown'),
                            'status': result.get('status', 0),
                            'length': result.get('length', 0),
                            'words': result.get('words', 0),
                            'lines': result.get('lines', 0)
                        })
        except Exception as e:
            self.log(f"Error procesando ffuf: {e}")
        return resultados
    
    def _detectar_servicios_web(self, servicios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detecta servicios web para análisis adicional"""
        servicios_web = []
        puertos_web = [80, 443, 8080, 8443, 8000, 8008, 9090]
        
        for servicio in servicios:
            if (servicio.get('puerto') in puertos_web or 
                'http' in servicio.get('servicio', '').lower()):
                servicios_web.append(servicio)
        
        return servicios_web
    
    def log(self, mensaje: str):
        """Log de actividades del escaneador"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[ESCANEADOR KALI2025] {timestamp}: {mensaje}")
        
        # También llamar al log del padre si existe
        try:
            if hasattr(super(), 'log'):
                super().log(mensaje)  # type: ignore
        except (ValueError, TypeError, AttributeError):
            pass
