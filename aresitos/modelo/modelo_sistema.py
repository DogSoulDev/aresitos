
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

import os
import subprocess
import platform
import json
import datetime
import stat
import tempfile
from typing import Dict, List, Any, Optional, Tuple

class ModeloUtilidadesSistema:
    
    def __init__(self):
        # Herramientas Kali Linux modernas - fácil instalación con apt
        self.herramientas_kali = {
            'escaneo_red': ['nmap', 'rustscan', 'masscan', 'naabu'],
            'auditoria_sistema': ['lynis', 'linpeas', 'pspy', 'chkrootkit'],
            'monitoreo_red': ['netstat', 'ss', 'lsof', 'tcpdump', 'iftop'],
            'firewall': ['iptables', 'ufw', 'firewalld', 'nftables'],
            'forensics': ['binwalk', 'foremost', 'exiftool', 'strings'],
            'web_testing': ['nikto', 'gobuster', 'feroxbuster', 'httpx'],
            'password_tools': ['john', 'hashcat', 'hydra', 'medusa'],
            'explotacion': ['metasploit-framework', 'sqlmap', 'searchsploit'],
            'analisis_vulnerabilidades': ['nuclei', 'nmap', 'whatweb', 'wpscan'],
            'herramientas_sistema': ['systemctl', 'ps', 'top', 'htop', 'iotop']
        }
        
        self.archivos_criticos = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/hosts', '/etc/hostname',
            '/etc/fstab', '/etc/crontab', '/var/log/auth.log',
            '/var/log/syslog', '/etc/resolv.conf', '/etc/networks'
        ]
        
        self.servicios_criticos = [
            'ssh', 'sshd', 'apache2', 'nginx', 'mysql', 'postgresql',
            'bind9', 'named', 'postfix', 'dovecot', 'vsftpd',
            'iptables', 'firewalld', 'ufw', 'fail2ban'
        ]
    
    def verificar_herramientas_kali_completo(self) -> Dict[str, Any]:
        """Verifica todas las herramientas de Kali Linux disponibles en el sistema."""
        disponibles = []
        no_disponibles = []
        total = 0
        
        try:
            for categoria, herramientas in self.herramientas_kali.items():
                for herramienta in herramientas:
                    total += 1
                    try:
                        resultado = subprocess.run(
                            ['which', herramienta],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        if resultado.returncode == 0:
                            ruta = resultado.stdout.strip()
                            disponibles.append({
                                'nombre': herramienta,
                                'categoria': categoria,
                                'ruta': ruta,
                                'version': self._obtener_version_herramienta(herramienta)
                            })
                        else:
                            no_disponibles.append({
                                'nombre': herramienta,
                                'categoria': categoria,
                                'motivo': 'No encontrada en PATH'
                            })
                    
                    except subprocess.TimeoutExpired:
                        no_disponibles.append({
                            'nombre': herramienta,
                            'categoria': categoria,
                            'motivo': 'Timeout al verificar'
                        })
                    except Exception as e:
                        no_disponibles.append({
                            'nombre': herramienta,
                            'categoria': categoria,
                            'motivo': f'Error: {str(e)}'
                        })
            
            return {
                'disponibles': disponibles,
                'no_disponibles': no_disponibles,
                'total': total,
                'porcentaje_disponible': round((len(disponibles) / total) * 100, 2) if total > 0 else 0,
                'timestamp': datetime.datetime.now().isoformat(),
                'sistema': platform.system(),
                'distribucion': self._obtener_distribucion()
            }
        
        except Exception as e:
            return {
                'disponibles': [],
                'no_disponibles': [],
                'total': 0,
                'error': f'Error general al verificar herramientas: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def ejecutar_auditoria_completa_lynis(self) -> Dict[str, Any]:
        """Ejecuta una auditoría completa del sistema usando Lynis."""
        try:
            # Verificar si Lynis está disponible
            which_result = subprocess.run(['which', 'lynis'], capture_output=True, text=True)
            if which_result.returncode != 0:
                return {
                    'exito': False,
                    'error': 'Lynis no está instalado en el sistema',
                    'sugerencia': 'Instalar con: sudo apt install lynis'
                }
            
            # Crear directorio temporal para el reporte
            temp_dir = tempfile.mkdtemp()
            reporte_path = os.path.join(temp_dir, 'lynis_audit.log')
            
            # Ejecutar auditoría Lynis
            comando = ['sudo', 'lynis', 'audit', 'system', '--logfile', reporte_path, '--quick']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos timeout
            )
            
            # Leer el archivo de log si existe
            salida_completa = ""
            if os.path.exists(reporte_path):
                try:
                    with open(reporte_path, 'r', encoding='utf-8') as f:
                        salida_completa = f.read()
                except (IOError, OSError, PermissionError, FileNotFoundError):
                    salida_completa = resultado.stdout
            else:
                salida_completa = resultado.stdout
            
            # Limpiar directorio temporal
            try:
                os.remove(reporte_path)
                os.rmdir(temp_dir)
            except (ValueError, TypeError, AttributeError):
                pass
            
            if resultado.returncode == 0:
                return {
                    'exito': True,
                    'salida': salida_completa,
                    'codigo_salida': resultado.returncode,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'comando_ejecutado': ' '.join(comando),
                    'resumen': self._analizar_salida_lynis(salida_completa)
                }
            else:
                return {
                    'exito': False,
                    'error': resultado.stderr or 'Error desconocido',
                    'codigo_salida': resultado.returncode,
                    'salida_parcial': resultado.stdout
                }
        
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout: La auditoría de Lynis tardó más de 5 minutos',
                'codigo_salida': -1
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error ejecutando Lynis: {str(e)}',
                'codigo_salida': -1
            }
    
    def ejecutar_deteccion_rootkits_completa(self) -> Dict[str, Any]:
        """Ejecuta detección de rootkits usando chkrootkit y rkhunter."""
        resultados = {}
        
        # Ejecutar chkrootkit
        chkrootkit_result = self._ejecutar_chkrootkit()
        resultados['chkrootkit'] = chkrootkit_result
        
        # Ejecutar rkhunter
        rkhunter_result = self._ejecutar_rkhunter()
        resultados['rkhunter'] = rkhunter_result
        
        # Determinar resultado general
        exito_general = (
            chkrootkit_result.get('exito', False) or
            rkhunter_result.get('exito', False)
        )
        
        return {
            'exito': exito_general,
            'herramientas_ejecutadas': list(resultados.keys()),
            'resultados': resultados,
            'timestamp': datetime.datetime.now().isoformat(),
            'resumen': self._generar_resumen_rootkits(resultados)
        }
    
    def analizar_servicios_sistema_avanzado(self) -> Dict[str, Any]:
        """Analiza servicios activos del sistema de forma avanzada."""
        try:
            servicios_encontrados = []
            
            # Usar systemctl para obtener servicios
            try:
                resultado_systemctl = subprocess.run(
                    ['systemctl', 'list-units', '--type=service', '--state=active', '--no-pager'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if resultado_systemctl.returncode == 0:
                    servicios_systemctl = self._parsear_servicios_systemctl(resultado_systemctl.stdout)
                    servicios_encontrados.extend(servicios_systemctl)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Usar ps para procesos adicionales
            try:
                resultado_ps = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if resultado_ps.returncode == 0:
                    procesos_ps = self._parsear_procesos_ps(resultado_ps.stdout)
                    servicios_encontrados.extend(procesos_ps)
            except (ValueError, TypeError, AttributeError):
                pass
            
            # Verificar puertos abiertos
            puertos_abiertos = self._obtener_puertos_abiertos()
            
            # Identificar servicios críticos
            servicios_criticos_activos = [
                s for s in servicios_encontrados 
                if any(critico in s.get('nombre', '').lower() for critico in self.servicios_criticos)
            ]
            
            return {
                'exito': True,
                'servicios': servicios_encontrados,
                'total_servicios': len(servicios_encontrados),
                'servicios_criticos': servicios_criticos_activos,
                'puertos_abiertos': puertos_abiertos,
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error analizando servicios: {str(e)}',
                'servicios': [],
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def verificar_permisos_archivos_criticos_avanzado(self) -> Dict[str, Any]:
        """Verifica permisos de archivos críticos del sistema."""
        try:
            archivos_analizados = []
            problemas_encontrados = []
            
            for archivo in self.archivos_criticos:
                análisis = self._analizar_archivo_critico(archivo)
                archivos_analizados.append(análisis)
                
                if análisis.get('problemas'):
                    problemas_encontrados.extend(análisis['problemas'])
            
            return {
                'exito': True,
                'archivos_analizados': archivos_analizados,
                'total_archivos': len(archivos_analizados),
                'problemas_encontrados': problemas_encontrados,
                'total_problemas': len(problemas_encontrados),
                'nivel_seguridad': self._calcular_nivel_seguridad(problemas_encontrados),
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error verificando permisos: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    def obtener_info_hardware_completa(self) -> Dict[str, Any]:
        """Obtiene información completa del hardware del sistema."""
        try:
            info_hardware = {
                'cpu': self._obtener_info_cpu(),
                'memoria': self._obtener_info_memoria(),
                'almacenamiento': self._obtener_info_almacenamiento(),
                'red': self._obtener_info_red(),
                'sistema': self._obtener_info_sistema(),
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            return info_hardware
        
        except Exception as e:
            return {
                'error': f'Error obteniendo información de hardware: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            }
    
    # Métodos auxiliares privados
    
    def _obtener_version_herramienta(self, herramienta: str) -> str:
        """Obtiene la versión de una herramienta."""
        comandos_version = ['--version', '-V', '-v', 'version']
        
        for cmd_version in comandos_version:
            try:
                resultado = subprocess.run(
                    [herramienta, cmd_version],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultado.returncode == 0 and resultado.stdout:
                    return resultado.stdout.split('\n')[0][:100]
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        return 'Versión no disponible'
    
    def _obtener_distribucion(self) -> str:
        """Obtiene información de la distribución del sistema."""
        try:
            with open('/etc/os-release', 'r') as f:
                for linea in f:
                    if linea.startswith('PRETTY_NAME='):
                        return linea.split('=')[1].strip().strip('"')
        except (IOError, OSError, PermissionError, FileNotFoundError):
            return platform.system() + ' ' + platform.release()
        
        return 'Distribución desconocida'
    
    def _analizar_salida_lynis(self, salida: str) -> Dict[str, Any]:
        """Analiza la salida de Lynis para extraer información relevante."""
        resumen = {
            'warnings': [],
            'suggestions': [],
            'hardening_index': 0
        }
        
        lineas = salida.split('\n')
        for linea in lineas:
            if 'WARNING' in linea:
                resumen['warnings'].append(linea.strip())
            elif 'SUGGESTION' in linea:
                resumen['suggestions'].append(linea.strip())
            elif 'Hardening index' in linea:
                try:
                    index = linea.split(':')[1].strip()
                    resumen['hardening_index'] = index
                except (ValueError, TypeError, AttributeError):
                    pass
        
        return resumen
    
    def _ejecutar_chkrootkit(self) -> Dict[str, Any]:
        """Ejecuta chkrootkit."""
        try:
            resultado = subprocess.run(
                ['sudo', 'chkrootkit'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'exito': resultado.returncode == 0,
                'salida': resultado.stdout,
                'codigo_salida': resultado.returncode,
                'herramienta': 'chkrootkit'
            }
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout ejecutando chkrootkit',
                'herramienta': 'chkrootkit'
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error ejecutando chkrootkit: {str(e)}',
                'herramienta': 'chkrootkit'
            }
    
    def _ejecutar_rkhunter(self) -> Dict[str, Any]:
        """Ejecuta rkhunter."""
        try:
            resultado = subprocess.run(
                ['sudo', 'rkhunter', '--check', '--skip-keypress'],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            return {
                'exito': True,  # rkhunter puede retornar códigos no-zero normalmente
                'salida': resultado.stdout,
                'codigo_salida': resultado.returncode,
                'herramienta': 'rkhunter'
            }
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout ejecutando rkhunter',
                'herramienta': 'rkhunter'
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error ejecutando rkhunter: {str(e)}',
                'herramienta': 'rkhunter'
            }
    
    def _generar_resumen_rootkits(self, resultados: Dict) -> Dict[str, Any]:
        """Genera resumen de la detección de rootkits."""
        resumen = {
            'herramientas_exitosas': 0,
            'alertas_encontradas': 0,
            'nivel_amenaza': 'bajo'
        }
        
        for herramienta, resultado in resultados.items():
            if resultado.get('exito'):
                resumen['herramientas_exitosas'] += 1
                
                salida = resultado.get('salida', '')
                if 'INFECTED' in salida.upper() or 'WARNING' in salida.upper():
                    resumen['alertas_encontradas'] += 1
        
        if resumen['alertas_encontradas'] > 3:
            resumen['nivel_amenaza'] = 'alto'
        elif resumen['alertas_encontradas'] > 0:
            resumen['nivel_amenaza'] = 'medio'
        
        return resumen
    
    def _parsear_servicios_systemctl(self, salida: str) -> List[Dict[str, Any]]:
        """Parsea la salida de systemctl."""
        servicios = []
        lineas = salida.split('\n')[1:]  # Saltar header
        
        for linea in lineas:
            if linea.strip() and not linea.startswith(''):
                partes = linea.split()
                if len(partes) >= 4:
                    servicios.append({
                        'nombre': partes[0],
                        'estado': partes[2],
                        'descripcion': ' '.join(partes[4:]) if len(partes) > 4 else '',
                        'tipo': 'systemd_service'
                    })
        
        return servicios
    
    def _parsear_procesos_ps(self, salida: str) -> List[Dict[str, Any]]:
        """Parsea la salida de ps."""
        procesos = []
        lineas = salida.split('\n')[1:]  # Saltar header
        
        for linea in lineas[:50]:  # Limitar a los primeros 50 procesos
            if linea.strip():
                partes = linea.split(None, 10)
                if len(partes) >= 11:
                    procesos.append({
                        'nombre': partes[10].split()[0] if partes[10] else '',
                        'usuario': partes[0],
                        'pid': partes[1],
                        'cpu': partes[2],
                        'memoria': partes[3],
                        'tipo': 'proceso'
                    })
        
        return procesos
    
    def _obtener_puertos_abiertos(self) -> List[Dict[str, Any]]:
        """Obtiene lista de puertos abiertos."""
        puertos = []
        
        try:
            # Usar ss si está disponible
            resultado = subprocess.run(
                ['ss', '-tuln'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if resultado.returncode == 0:
                lineas = resultado.stdout.split('\n')[1:]
                for linea in lineas:
                    if linea.strip():
                        partes = linea.split()
                        if len(partes) >= 5:
                            puertos.append({
                                'protocolo': partes[0],
                                'estado': partes[1],
                                'direccion_local': partes[4],
                                'puerto': partes[4].split(':')[-1] if ':' in partes[4] else ''
                            })
        except (ValueError, TypeError, AttributeError):
            pass
        
        return puertos
    
    def _analizar_archivo_critico(self, archivo: str) -> Dict[str, Any]:
        """Analiza un archivo crítico específico."""
        análisis = {
            'archivo': archivo,
            'existe': False,
            'legible': False,
            'permisos': '',
            'propietario': '',
            'grupo': '',
            'problemas': []
        }
        
        try:
            if os.path.exists(archivo):
                análisis['existe'] = True
                
                # Obtener información del archivo
                stat_info = os.stat(archivo)
                análisis['permisos'] = oct(stat_info.st_mode)[-3:]
                análisis['propietario'] = stat_info.st_uid
                análisis['grupo'] = stat_info.st_gid
                
                # Verificar si es legible
                análisis['legible'] = os.access(archivo, os.R_OK)
                
                # Verificar problemas de seguridad
                if archivo in ['/etc/passwd', '/etc/group']:
                    if stat_info.st_mode & stat.S_IWOTH:
                        análisis['problemas'].append('Archivo escribible por otros usuarios')
                
                elif archivo == '/etc/shadow':
                    if stat_info.st_mode & (stat.S_IRGRP | stat.S_IROTH):
                        análisis['problemas'].append('Archivo legible por grupo u otros')
                
                elif archivo == '/etc/sudoers':
                    if stat_info.st_mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                        análisis['problemas'].append('Permisos incorrectos en sudoers')
            
            else:
                análisis['problemas'].append('Archivo no existe')
        
        except Exception as e:
            análisis['problemas'].append(f'Error analizando: {str(e)}')
        
        return análisis
    
    def _calcular_nivel_seguridad(self, problemas: List[str]) -> str:
        """Calcula el nivel de seguridad basado en problemas encontrados."""
        if len(problemas) == 0:
            return 'alto'
        elif len(problemas) <= 3:
            return 'medio'
        else:
            return 'bajo'
    
    def _obtener_info_cpu(self) -> Dict[str, Any]:
        """Obtiene información del CPU."""
        info_cpu = {}
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for linea in f:
                    if linea.startswith('model name'):
                        info_cpu['modelo'] = linea.split(':')[1].strip()
                        break
        except (IOError, OSError, PermissionError, FileNotFoundError):
            info_cpu['modelo'] = 'No disponible'
        
        return info_cpu
    
    def _obtener_info_memoria(self) -> Dict[str, Any]:
        """Obtiene información de memoria."""
        info_memoria = {}
        
        try:
            with open('/proc/meminfo', 'r') as f:
                for linea in f:
                    if linea.startswith('MemTotal'):
                        total_kb = int(linea.split()[1])
                        info_memoria['total_mb'] = round(total_kb / 1024, 2)
                        break
        except (IOError, OSError, PermissionError, FileNotFoundError):
            info_memoria['total_mb'] = 'No disponible'
        
        return info_memoria
    
    def _obtener_info_almacenamiento(self) -> Dict[str, Any]:
        """Obtiene información de almacenamiento."""
        info_almacenamiento = {}
        
        try:
            resultado = subprocess.run(
                ['df', '-h'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                info_almacenamiento['df_output'] = resultado.stdout
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            info_almacenamiento['df_output'] = 'No disponible'
        
        return info_almacenamiento
    
    def _obtener_info_red(self) -> Dict[str, Any]:
        """Obtiene información de red."""
        info_red = {}
        
        try:
            resultado = subprocess.run(
                ['ip', 'addr', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                info_red['interfaces'] = resultado.stdout
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            info_red['interfaces'] = 'No disponible'
        
        return info_red
    
    def _obtener_info_sistema(self) -> Dict[str, Any]:
        """Obtiene información general del sistema."""
        return {
            'sistema': platform.system(),
            'version': platform.release(),
            'arquitectura': platform.machine(),
            'hostname': platform.node(),
            'distribucion': self._obtener_distribucion()
        }

# RESUMEN: Clase Utilidades para análisis completo de sistemas Kali Linux con verificación
# de herramientas de ciberseguridad, auditorías Lynis, detección de rootkits, análisis de
# servicios, verificación de permisos críticos e información completa de hardware.
