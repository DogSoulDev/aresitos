
# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
"""
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
import tempfile
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from .modelo_escaneador_base import EscaneadorBase as _EscaneadorBase
else:
    from .modelo_escaneador_base import EscaneadorBase as _EscaneadorBase

class EscaneadorKali2025(_EscaneadorBase):  # type: ignore
    def _get_temp_file(self, name: str) -> str:
        """Devuelve una ruta temporal segura y multiplataforma para archivos de salida."""
        import tempfile, os
        return os.path.join(tempfile.gettempdir(), name)

    def _get_default_wordlist(self, tipo: str = "web") -> str:
        """Devuelve la ruta de wordlist por defecto, buscando en ubicaciones estándar."""
        import os
        posibles = []
        if tipo == "web":
            posibles = [
                os.path.join("/usr/share/wordlists/seclists/Discovery/Web-Content", "directory-list-2.3-medium.txt"),
                os.path.join("/usr/share/wordlists/seclists/Discovery/Web-Content", "common.txt"),
            ]
        elif tipo == "fuzz":
            posibles = [
                os.path.join("/usr/share/wordlists/seclists/Discovery/Web-Content", "common.txt"),
            ]
        for ruta in posibles:
            if os.path.exists(ruta):
                return ruta
        # Fallback: usar una ruta temporal vacía
        return self._get_temp_file("empty_wordlist.txt")

    def escaneo_rapido_masscan(self, objetivo: str, puertos: str = "1-65535", callback_terminal=None, callback_progreso=None) -> Dict[str, Any]:
        """
        Escaneo inicial rápido con masscan usando SudoManager para identificar puertos abiertos, mostrando el comando y progreso en tiempo real.
        """
        import json
        from aresitos.utils.sudo_manager import get_sudo_manager
        self.log(f"[START] Iniciando escaneo rápido masscan: {objetivo}")
        output_file = self._get_temp_file("masscan_output.json")
        if 'masscan' not in self.herramientas_disponibles:
            return {"error": "masscan no disponible"}
        try:
            cmd = [
                'masscan',
                objetivo,
                '-p', puertos,
                '--rate', '10000',
                '--open',
                '--output-format', 'json',
                '--output-filename', output_file
            ]
            cmd_str = ' '.join(cmd)
            if callback_terminal:
                callback_terminal(f"[MASSCAN] Ejecutando: {cmd_str}\n")
            if callback_progreso:
                callback_progreso(10)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=300)
            if callback_progreso:
                callback_progreso(30)
            if hasattr(result, 'returncode') and result.returncode == 0:
                try:
                    with open(output_file, 'r') as f:
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
                    self.log(f"OK Masscan completado: {len(puertos_abiertos)} puertos encontrados")
                    if callback_progreso:
                        callback_progreso(40)
                    return {
                        "exito": True,
                        "puertos_abiertos": puertos_abiertos,
                        "total_puertos": len(puertos_abiertos),
                        "herramienta": "masscan"
                    }
                except Exception as e:
                    self.log(f"OK Error procesando resultados masscan: {e}")
                    return {"error": f"Error procesando resultados: {e}"}
            else:
                error_msg = getattr(result, 'stderr', 'Error desconocido')
                self.log(f"OK Error masscan: {error_msg}")
                return {"error": error_msg}
        except Exception as e:
            self.log(f"OK Error ejecutando masscan: {e}")
            return {"error": str(e)}
    """
    Escaneador avanzado con herramientas Kali Linux 2025.
    Hereda de EscaneadorBase para funcionalidad común.
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
            'hydra': '/usr/bin/hydra',
            'netstat': '/bin/netstat',
            'lsof': '/usr/bin/lsof',
            'ps': '/bin/ps',
            'ss': '/usr/bin/ss',
        }
        # Combinar herramientas base con herramientas Kali
        self.herramientas_base.update(self.herramientas_kali)
        self._verificar_herramientas_base()

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
    
    def escaneo_detallado_nmap(self, objetivo: str, puertos_encontrados: Optional[List[int]] = None, callback_terminal=None, callback_progreso=None) -> Dict[str, Any]:
        """
        Escaneo detallado con nmap basado en puertos encontrados por masscan, mostrando el comando y progreso en tiempo real.
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
            # Archivos temporales
            output_xml = self._get_temp_file("nmap_output.xml")
            output_txt = self._get_temp_file("nmap_output.txt")
            # Comando nmap avanzado
            cmd = [
                'nmap',
                '-sS',  # SYN scan (stealth)
                '-sV',  # Detección de versiones
                '-sC',  # Scripts por defecto
                '-O',   # Detección de OS
                '--script', 'vuln',  # Scripts de vulnerabilidad
                '--reason',  # Mostrar razón de estado de puerto
                '--traceroute',  # Trazado de ruta
                '--version-intensity', '9',  # Intensidad máxima
                '-T4',  # Velocidad alta
                '-oX', output_xml,
                '-oN', output_txt
            ]
            if puertos_encontrados:
                cmd.extend(['-p', puertos_str])
            else:
                cmd.append('--top-ports=1000')
            cmd.append(objetivo)
            if callback_terminal:
                callback_terminal(f"[NMAP] Ejecutando: {' '.join(cmd)}\n")
            if callback_progreso:
                callback_progreso(50)
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=900)
            if callback_progreso:
                callback_progreso(80)
            if hasattr(result, 'returncode') and result.returncode == 0:
                # Procesar resultados
                servicios = self._procesar_resultados_nmap(output_txt)
                self.log(f"OK Nmap completado: {len(servicios)} servicios detectados")
                if callback_progreso:
                    callback_progreso(90)
                return {
                    "exito": True,
                    "servicios": servicios,
                    "archivo_xml": output_xml,
                    "archivo_txt": output_txt,
                    "herramienta": "nmap"
                }
            else:
                error_msg = getattr(result, 'stderr', 'Error desconocido')
                self.log(f"OK Error nmap: {error_msg}")
                return {"error": error_msg}
        except Exception as e:
            self.log(f"OK Error ejecutando nmap: {e}")
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
                wordlist = self._get_default_wordlist("web")
            output_file = self._get_temp_file("gobuster_output.txt")
            # Comando gobuster
            cmd = [
                'gobuster',
                'dir',
                '-u', url,
                '-w', wordlist,
                '-t', '50',  # 50 threads
                '-x', 'php,html,txt,js,asp,aspx',  # Extensiones
                '-o', output_file,
                '--no-error'
            ]
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=300)
            # Procesar resultados (gobuster siempre retorna 0)
            directorios = self._procesar_resultados_gobuster(output_file)
            self.log(f"OK Gobuster completado: {len(directorios)} directorios encontrados")
            return {
                "exito": True,
                "directorios": directorios,
                "total_encontrados": len(directorios),
                "herramienta": "gobuster"
            }
        except Exception as e:
            self.log(f"OK Error ejecutando gobuster: {e}")
            return {"error": str(e)}
    
    def escaneo_vulnerabilidades_nuclei(self, objetivo: str) -> Dict[str, Any]:
        """
        Escaneo de vulnerabilidades con nuclei
        """
        self.log(f"[TARGET] Iniciando escaneo nuclei: {objetivo}")
        if 'nuclei' not in self.herramientas_disponibles:
            return {"error": "nuclei no disponible"}
        try:
            output_file = self._get_temp_file("nuclei_output.json")
            # Comando nuclei
            cmd = [
                'nuclei',
                '-target', objetivo,
                '-json',
                '-o', output_file,
                '-severity', 'medium,high,critical',
                '-concurrency', '25'
            ]
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=600)
            # Procesar resultados JSON
            vulnerabilidades = self._procesar_resultados_nuclei(output_file)
            self.log(f"OK Nuclei completado: {len(vulnerabilidades)} vulnerabilidades encontradas")
            return {
                "exito": True,
                "vulnerabilidades": vulnerabilidades,
                "total_vulnerabilidades": len(vulnerabilidades),
                "herramienta": "nuclei"
            }
        except Exception as e:
            self.log(f"OK Error ejecutando nuclei: {e}")
            return {"error": str(e)}
    
    def fuzzing_web_ffuf(self, url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Fuzzing web moderno con ffuf
        """
        self.log(f"OK Iniciando fuzzing ffuf: {url}")
        if 'ffuf' not in self.herramientas_disponibles:
            return {"error": "ffuf no disponible"}
        try:
            # Wordlist por defecto - modernizada
            if not wordlist:
                wordlist = self._get_default_wordlist("fuzz")
            output_file = self._get_temp_file("ffuf_output.json")
            # Comando ffuf
            cmd = [
                'ffuf',
                '-u', f"{url}/FUZZ",
                '-w', wordlist,
                '-o', output_file,
                '-of', 'json',
                '-mc', '200,204,301,302,307,401,403',  # Match codes
                '-t', '40'  # Threads
            ]
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=300)
            # Procesar resultados
            resultados = self._procesar_resultados_ffuf(output_file)
            self.log(f"OK FFUF completado: {len(resultados)} endpoints encontrados")
            return {
                "exito": True,
                "endpoints": resultados,
                "total_endpoints": len(resultados),
                "herramienta": "ffuf"
            }
        except Exception as e:
            self.log(f"OK Error ejecutando ffuf: {e}")
            return {"error": str(e)}
    
    def escaneo_completo_kali2025(self, objetivo: str, callback_terminal=None, callback_progreso=None) -> Dict[str, Any]:
        """
        Escaneo completo usando todas las herramientas Kali 2025 disponibles, mostrando comandos y progreso en tiempo real.
        """
        self.log(f"[START] INICIANDO ESCANEO COMPLETO KALI 2025: {objetivo}")
        resultados = {
            "objetivo": objetivo,
            "timestamp": datetime.now().isoformat(),
            "herramientas_utilizadas": [],
            "fases": {}
        }
        try:
            # FASE 1: Escaneo rápido con masscan
            self.log("FASE 1: Reconocimiento inicial con masscan")
            if callback_progreso:
                callback_progreso(0)
            resultado_masscan = self.escaneo_rapido_masscan(objetivo, puertos="1-65535", callback_terminal=callback_terminal, callback_progreso=callback_progreso)
            resultados["fases"]["masscan"] = resultado_masscan
            if resultado_masscan.get("exito"):
                resultados["herramientas_utilizadas"].append("masscan")
                puertos_encontrados = [p["puerto"] for p in resultado_masscan["puertos_abiertos"]]
            else:
                puertos_encontrados = None
            # FASE 2: Escaneo detallado con nmap
            self.log("FASE 2: Análisis detallado con nmap")
            resultado_nmap = self.escaneo_detallado_nmap(objetivo, puertos_encontrados, callback_terminal=callback_terminal, callback_progreso=callback_progreso)
            resultados["fases"]["nmap"] = resultado_nmap
            if resultado_nmap.get("exito"):
                resultados["herramientas_utilizadas"].append("nmap")
            # FASE 3: Escaneo de vulnerabilidades con nuclei
            self.log("FASE 3: Detección de vulnerabilidades con nuclei")
            if callback_terminal:
                callback_terminal(f"[NUCLEI] Ejecutando: nuclei -target {objetivo} -json -severity medium,high,critical\n")
            if callback_progreso:
                callback_progreso(92)
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
                    if callback_terminal:
                        callback_terminal(f"[GOBUSTER] Ejecutando: gobuster dir -u {url} ...\n")
                    resultado_gobuster = self.escaneo_web_gobuster(url)
                    resultados["fases"][f"gobuster_{servicio_web['puerto']}"] = resultado_gobuster
                    if resultado_gobuster.get("exito"):
                        resultados["herramientas_utilizadas"].append("gobuster")
                    if callback_terminal:
                        callback_terminal(f"[FFUF] Ejecutando: ffuf -u {url}/FUZZ ...\n")
                    resultado_ffuf = self.fuzzing_web_ffuf(url)
                    resultados["fases"][f"ffuf_{servicio_web['puerto']}"] = resultado_ffuf
                    if resultado_ffuf.get("exito"):
                        resultados["herramientas_utilizadas"].append("ffuf")
                # FASE 5: Análisis de red y procesos locales con netstat, ss, lsof, ps
                self.log("FASE 5: Análisis de red y procesos locales con netstat, ss, lsof, ps")
                if callback_terminal:
                    callback_terminal(f"[NETSTAT] Ejecutando: netstat -tunlp\n")
                resultado_netstat = self.escaneo_netstat()
                resultados["fases"]["netstat"] = resultado_netstat
                if resultado_netstat.get("exito"):
                    resultados["herramientas_utilizadas"].append("netstat")
            if callback_progreso:
                callback_progreso(100)
            return resultados
        except Exception as e:
            self.log(f"Error en escaneo_completo_kali2025: {e}")
            resultados["error"] = str(e)
            return resultados

            resultado_ss = self.escaneo_ss()
            resultados["fases"]["ss"] = resultado_ss
            if resultado_ss.get("exito"):
                resultados["herramientas_utilizadas"].append("ss")

            resultado_lsof = self.escaneo_lsof()
            resultados["fases"]["lsof"] = resultado_lsof
            if resultado_lsof.get("exito"):
                resultados["herramientas_utilizadas"].append("lsof")

            resultado_ps = self.escaneo_ps()
            resultados["fases"]["ps"] = resultado_ps
            if resultado_ps.get("exito"):
                resultados["herramientas_utilizadas"].append("ps")
        
        # Resumen final
        total_puertos = len(resultado_masscan.get("puertos_abiertos", []))
        total_servicios = len(resultado_nmap.get("servicios", []))
        total_vulnerabilidades = len(resultado_nuclei.get("vulnerabilidades", []))
    def escaneo_netstat(self) -> Dict[str, Any]:
        """Escaneo de conexiones de red con netstat"""
        self.log("Iniciando escaneo netstat")
        if 'netstat' not in self.herramientas_disponibles:
            return {"error": "netstat no disponible"}
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd = ['netstat', '-tunlp']
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=30)
            conexiones = []
            stdout = getattr(result, 'stdout', '')
            for line in stdout.splitlines():
                if line.startswith('tcp') or line.startswith('udp'):
                    partes = line.split()
                    if len(partes) >= 7:
                        conexiones.append({
                            'protocolo': partes[0],
                            'direccion_local': partes[3],
                            'direccion_remota': partes[4],
                            'estado': partes[5] if partes[0].startswith('tcp') else '',
                            'pid_programa': partes[6]
                        })
            return {"exito": True, "conexiones": conexiones, "total_conexiones": len(conexiones), "herramienta": "netstat"}
        except Exception as e:
            self.log(f"Error ejecutando netstat: {e}")
            return {"error": str(e)}

    def escaneo_ss(self) -> Dict[str, Any]:
        """Escaneo de conexiones de red con ss"""
        self.log("Iniciando escaneo ss")
        if 'ss' not in self.herramientas_disponibles:
            return {"error": "ss no disponible"}
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd = ['ss', '-tunlp']
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=30)
            conexiones = []
            stdout = getattr(result, 'stdout', '')
            for line in stdout.splitlines():
                if line.startswith('tcp') or line.startswith('udp'):
                    partes = line.split()
                    if len(partes) >= 6:
                        conexiones.append({
                            'protocolo': partes[0],
                            'direccion_local': partes[4],
                            'direccion_remota': partes[5],
                            'estado': partes[1] if partes[0].startswith('tcp') else '',
                            'pid_programa': partes[-1]
                        })
            return {"exito": True, "conexiones": conexiones, "total_conexiones": len(conexiones), "herramienta": "ss"}
        except Exception as e:
            self.log(f"Error ejecutando ss: {e}")
            return {"error": str(e)}

    def escaneo_lsof(self) -> Dict[str, Any]:
        """Escaneo de archivos y sockets abiertos con lsof"""
        self.log("Iniciando escaneo lsof")
        if 'lsof' not in self.herramientas_disponibles:
            return {"error": "lsof no disponible"}
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd = ['lsof', '-i']
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=30)
            archivos = []
            stdout = getattr(result, 'stdout', '')
            for line in stdout.splitlines():
                if not line.startswith('COMMAND') and line:
                    partes = line.split()
                    if len(partes) >= 9:
                        archivos.append({
                            'comando': partes[0],
                            'pid': partes[1],
                            'usuario': partes[2],
                            'tipo': partes[7],
                            'nombre': partes[8]
                        })
            return {"exito": True, "archivos": archivos, "total_archivos": len(archivos), "herramienta": "lsof"}
        except Exception as e:
            self.log(f"Error ejecutando lsof: {e}")
            return {"error": str(e)}

    def escaneo_ps(self) -> Dict[str, Any]:
        """Escaneo de procesos activos con ps"""
        self.log("Iniciando escaneo ps")
        if 'ps' not in self.herramientas_disponibles:
            return {"error": "ps no disponible"}
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            cmd = ['ps', 'aux']
            cmd_str = ' '.join(cmd)
            sudo_manager = get_sudo_manager()
            result = sudo_manager.execute_sudo_command(cmd_str, timeout=30)
            procesos = []
            stdout = getattr(result, 'stdout', '')
            for line in stdout.splitlines():
                if not line.startswith('USER') and line:
                    partes = line.split(None, 10)
                    if len(partes) == 11:
                        procesos.append({
                            'usuario': partes[0],
                            'pid': partes[1],
                            'cpu': partes[2],
                            'mem': partes[3],
                            'comando': partes[10]
                        })
            return {"exito": True, "procesos": procesos, "total_procesos": len(procesos), "herramienta": "ps"}
        except Exception as e:
            self.log(f"Error ejecutando ps: {e}")
            return {"error": str(e)}
        
        resultados["resumen"] = {
            "puertos_abiertos": total_puertos,
            "servicios_detectados": total_servicios,
            "vulnerabilidades_encontradas": total_vulnerabilidades,
            "herramientas_utilizadas": len(set(resultados["herramientas_utilizadas"])),
            "duracion": "calculada_en_vista"
        }
        
        self.log(f"OK ESCANEO COMPLETO FINALIZADO")
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
