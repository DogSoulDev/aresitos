# -*- coding: utf-8 -*-

import subprocess
import re
import shlex
from aresitos.modelo.modelo_utilidades_sistema import ModeloUtilidadesSistema

class ControladorHerramientas:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.utilidades_sistema = ModeloUtilidadesSistema()
        
        # Lista blanca de herramientas de Kali Linux (SECURITY FIX)
        # KALI OPTIMIZATION: Herramientas modernas de fácil instalación
        self.herramientas_permitidas = {
            # Reconocimiento y Escaneo (MODERNAS)
            'nmap', 'rustscan', 'masscan', 'naabu', 'hping3',
            'traceroute', 'ping', 'fping', 'arping', 'nbtscan',
            
            # Aplicaciones Web (ACTUALIZADAS)
            'sqlmap', 'gobuster', 'feroxbuster', 'nikto', 'httpx',
            'wpscan', 'whatweb', 'nuclei', 'ffuf', 'dirsearch',
            'zaproxy', 'wapiti', 'ghauri', 'xsser', 'sublist3r',
            
            # Passwords y Hashing
            'hydra', 'medusa', 'patator', 'hashcat', 'john',
            'crunch', 'cewl', 'rsmangler', 'maskprocessor',
            
            # Wireless
            'aircrack-ng', 'aireplay-ng', 'airodump-ng', 'airmon-ng',
            'reaver', 'pixiewps', 'wash', 'bully', 'cowpatty',
            
            # Network Tools (SIMPLIFICADAS)
            'netcat', 'nc', 'socat', 'netdiscover', 'arp-scan',
            'tcpdump', 'iftop', 'nload', 'iperf3', 'curl',
            
            # Metasploit Framework
            'msfconsole', 'msfvenom', 'msfdb', 'searchsploit',
            
            # Forense y Análisis (ESENCIALES)
            'binwalk', 'foremost', 'exiftool', 'strings', 'file',
            'hexdump', 'xxd', 'grep', 'find', 'locate',
            
            # Exploits y Post-Explotación
            'searchsploit', 'exploitdb', 'linpeas', 'pspy',
            
            # OSINT y Reconocimiento (SIMPLES)
            'theharvester', 'dmitry', 'dnsrecon', 'dnsutils',
            'whois', 'dig', 'nslookup', 'host', 'amass',
            
            # Utilidades del Sistema Kali
            'apt-get', 'apt', 'dpkg', 'systemctl', 'service',
            'which', 'whereis', 'locate', 'find', 'grep',
            
            # Social Engineering
            'setoolkit', 'social-engineer-toolkit', 'king-phisher',
            
            # Misc Tools
            'enum4linux', 'smbclient', 'rpcclient', 'showmount',
            'snmpwalk', 'onesixtyone', 'sslscan', 'sslyze'
        }
        
        # Argumentos seguros permitidos (SECURITY FIX)
        self.argumentos_seguros = {
            '--help', '-h', '--version', '-v', '-V', 'version',
            '--target', '-t', '--port', '-p', '--output', '-o',
            '--verbose', '--scan', '--list', '--info'
        }
    
    def _validar_nombre_herramienta(self, nombre_herramienta):
        """
        Valida que el nombre de herramienta sea seguro y esté en la lista blanca.
        SECURITY FIX: Previene command injection
        """
        if not nombre_herramienta or not isinstance(nombre_herramienta, str):
            return False
            
        # Solo permitir caracteres alfanuméricos, guiones y guiones bajos
        if not re.match(r'^[a-zA-Z0-9_-]+$', nombre_herramienta):
            return False
            
        # Verificar que esté en la lista blanca
        return nombre_herramienta.lower() in self.herramientas_permitidas
    
    def _validar_argumentos(self, argumentos):
        """
        Valida que los argumentos sean seguros.
        SECURITY FIX: Previene command injection via argumentos
        """
        if not argumentos:
            return True
            
        if not isinstance(argumentos, list):
            return False
            
        for arg in argumentos:
            if not isinstance(arg, str):
                return False
            # Verificar caracteres peligrosos
            if re.search(r'[;&|`$(){}[\]<>]', arg):
                return False
            # Verificar que no contenga rutas absolutas peligrosas
            if arg.startswith('/') and not arg.startswith('/tmp/'):
                return False
                
        return True
    
    def _verificar_entorno_kali(self):
        """
        Verifica que estamos ejecutándose en Kali Linux.
        KALI OPTIMIZATION: Validación específica del entorno.
        """
        import os
        
        try:
            # Verificar /etc/os-release para confirmar Kali
            with open('/etc/os-release', 'r') as f:
                os_info = f.read().lower()
                if 'kali' in os_info and 'linux' in os_info:
                    return True
            
            # Verificar /etc/debian_version (Kali está basado en Debian)
            with open('/etc/debian_version', 'r') as f:
                debian_info = f.read()
                if debian_info.strip():
                    # Verificar si existen herramientas típicas de Kali
                    kali_indicators = ['/usr/bin/nmap', '/usr/bin/sqlmap', '/usr/bin/hydra']
                    return any(os.path.exists(tool) for tool in kali_indicators)
                    
        except FileNotFoundError:
            pass
            
        return False
    
    def obtener_info_sistema_kali(self):
        """
        Obtiene información específica del sistema Kali Linux.
        KALI OPTIMIZATION: Información del entorno de trabajo.
        """
        if not self._verificar_entorno_kali():
            return {
                'es_kali': False,
                'error': 'Aresitos requiere Kali Linux para funcionar correctamente'
            }
        
        # Crear diccionario de información del sistema
        info = {}
        info['es_kali'] = True
        
        try:
            # Versión de Kali
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('VERSION='):
                        info['version_kali'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('PRETTY_NAME='):
                        info['nombre_sistema'] = line.split('=')[1].strip().strip('"')
            
            # Kernel
            import platform
            info['kernel'] = platform.release()
            info['arquitectura'] = platform.machine()
            
            # Herramientas de Kali instaladas (MODERNAS)
            herramientas_instaladas = []
            herramientas_core = ['nmap', 'rustscan', 'sqlmap', 'gobuster', 'nikto', 'httpx', 'nuclei']
            
            for herramienta in herramientas_core:
                try:
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, timeout=2)
                    if result.returncode == 0:
                        herramientas_instaladas.append(herramienta)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            info['herramientas_core_disponibles'] = herramientas_instaladas
            info['total_herramientas_core'] = len(herramientas_instaladas)
            
        except Exception as e:
            info['error_info'] = str(e)
        
        return info
        return self.utilidades_sistema.verificar_herramientas_kali_completo()
    
    def verificar_herramienta_especifica(self, nombre_herramienta):
        # SECURITY FIX: Validar entrada antes de ejecutar comando
        if not self._validar_nombre_herramienta(nombre_herramienta):
            return {
                'disponible': False, 
                'error': 'Nombre de herramienta no válido o no permitido'
            }
            
        try:
            # Usar shlex.quote para escapar el nombre de herramienta (SECURITY FIX)
            herramienta_segura = shlex.quote(nombre_herramienta)
            resultado = subprocess.run(['which', herramienta_segura], 
                                     capture_output=True, text=True, timeout=5)
            
            if resultado.returncode == 0:
                version = self._obtener_version_herramienta(nombre_herramienta)
                return {
                    'disponible': True,
                    'ruta': resultado.stdout.strip(),
                    'version': version
                }
            else:
                return {'disponible': False, 'error': 'Herramienta no encontrada'}
                
        except Exception as e:
            return {'disponible': False, 'error': str(e)}
    
    def instalar_herramienta(self, nombre_herramienta):
        """
        Instala herramienta específica en Kali Linux.
        OPTIMIZADO PARA KALI: Asume entorno Kali Linux con privilegios apropiados.
        """
        # SECURITY FIX: Validar entrada
        if not self._validar_nombre_herramienta(nombre_herramienta):
            return {
                'exito': False, 
                'error': 'Nombre de herramienta no válido o no permitido en Kali Linux'
            }
        
        # KALI OPTIMIZATION: Verificar que estamos en Kali Linux
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read()
                if 'kali' not in os_info.lower():
                    return {
                        'exito': False,
                        'error': 'Aresitos está diseñado exclusivamente para Kali Linux'
                    }
        except FileNotFoundError:
            return {
                'exito': False,
                'error': 'Sistema no compatible: Se requiere Kali Linux'
            }
        
        # KALI OPTIMIZATION: En Kali, asumir usuario con privilegios
        # Los usuarios de Kali generalmente tienen sudo o son root
        import os
        import subprocess as sp
        
        # Verificar privilegios de manera compatible con Kali Linux
        try:
            # Intentar verificar si somos root mediante whoami
            whoami_result = sp.run(['whoami'], capture_output=True, text=True, timeout=2)
            is_root = (whoami_result.stdout.strip() == 'root')
            
            if not is_root:
                # En Kali, usar sudo para instalaciones
                comando_instalacion = ['sudo', 'apt-get', 'install', '-y', nombre_herramienta]
            else:
                comando_instalacion = ['apt-get', 'install', '-y', nombre_herramienta]
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            # Fallback seguro para Kali: asumir que tenemos sudo disponible
            comando_instalacion = ['sudo', 'apt-get', 'install', '-y', nombre_herramienta]
            
        try:
            resultado = subprocess.run(comando_instalacion,
                                     capture_output=True, text=True, timeout=300)
            
            return {
                'exito': resultado.returncode == 0,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {'exito': False, 'error': 'Tiempo de instalación agotado (5 minutos)'}
        except Exception as e:
            return {'exito': False, 'error': f'Error de instalación: {str(e)}'}
    
    def actualizar_herramientas_sistema(self):
        comandos = [
            ('apt-get', 'update'),
            ('apt-get', 'upgrade', '-y')
        ]
        
        resultados = []
        for comando in comandos:
            try:
                resultado = subprocess.run(comando, capture_output=True, 
                                         text=True, timeout=600)
                resultados.append({
                    'comando': ' '.join(comando),
                    'exito': resultado.returncode == 0,
                    'salida': resultado.stdout[:500],
                    'error': resultado.stderr[:500] if resultado.returncode != 0 else None
                })
            except Exception as e:
                resultados.append({
                    'comando': ' '.join(comando),
                    'exito': False,
                    'error': str(e)
                })
        
        return {'resultados': resultados}
    
    def ejecutar_comando_herramienta(self, herramienta, argumentos):
        """
        Ejecuta herramienta de Kali Linux con argumentos validados.
        OPTIMIZADO PARA KALI: Validación específica para herramientas de pentesting.
        """
        # SECURITY FIX: Validar herramienta y argumentos
        if not self._validar_nombre_herramienta(herramienta):
            return {
                'exito': False,
                'error': f'Herramienta {herramienta} no está permitida o no es válida para Kali Linux'
            }
        
        if not self._validar_argumentos(argumentos):
            return {
                'exito': False,
                'error': 'Argumentos contienen caracteres no seguros'
            }
        
        try:
            # KALI OPTIMIZATION: Construir comando seguro para herramientas Kali
            comando = [herramienta] + argumentos
            
            # SECURITY FIX: Timeout apropiado para herramientas de pentesting
            # Algunas herramientas Kali pueden tardar más tiempo
            timeout = 300  # 5 minutos para herramientas complejas como nmap
            
            resultado = subprocess.run(comando, capture_output=True, 
                                     text=True, timeout=timeout)
            
            return {
                'exito': resultado.returncode == 0,
                'codigo_salida': resultado.returncode,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None,
                'herramienta': herramienta,
                'argumentos_usados': argumentos
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exito': False, 
                'error': f'Herramienta {herramienta} agotó tiempo de ejecución (5 minutos)'
            }
        except FileNotFoundError:
            return {
                'exito': False, 
                'error': f'Herramienta {herramienta} no encontrada en Kali Linux'
            }
        except Exception as e:
            return {
                'exito': False, 
                'error': f'Error ejecutando {herramienta}: {str(e)}'
            }
    
    def _obtener_version_herramienta(self, herramienta):
        comandos_version = ['--version', '-v', '-V', 'version']
        
        for cmd in comandos_version:
            try:
                resultado = subprocess.run([herramienta, cmd], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0 and resultado.stdout:
                    return resultado.stdout.split('\n')[0]
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        return 'Versión no disponible'

# RESUMEN TÉCNICO: Controlador de gestión de herramientas de Kali Linux. Maneja 
# verificación, instalación y ejecución de herramientas de ciberseguridad. Integración 
# directa con apt-get y comandos del sistema, arquitectura MVC con principios SOLID, 
# sin dependencias externas para administración profesional de herramientas.
