
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
ARESITOS - Escaneador Base
Clase base para todos los escaneadores del sistema
"""

import logging
import os
import subprocess
import time
from typing import Dict, List, Any, Optional
from datetime import datetime


class EscaneadorBase:
    """
    Clase base para todos los escaneadores ARESITOS.
    Proporciona funcionalidad común y herramientas nativas de Kali Linux.
    """
    
    def __init__(self, gestor_permisos=None):
        """
        Inicializar escaneador base.
        
        Args:
            gestor_permisos: Gestor de permisos del sistema (opcional)
        """
        self.gestor_permisos = gestor_permisos
        self.logger = logging.getLogger(f"aresitos.{self.__class__.__name__}")
        
        # Configuración básica
        self.configuracion = {
            'timeout_comando': 300,
            'max_intentos': 3,
            'rate_limiting': True,
            'log_detallado': True
        }
        
        # Herramientas base disponibles en Kali Linux
        self.herramientas_base = {
            'nmap': '/usr/bin/nmap',
            'netstat': '/bin/netstat',
            'ss': '/bin/ss',
            'ping': '/bin/ping',
            'curl': '/usr/bin/curl',
            'wget': '/usr/bin/wget'
        }
        
        # Verificar herramientas disponibles
        self.herramientas_disponibles = {}
        self._verificar_herramientas_base()
        
        self.logger.info(f"Escaneador base inicializado: {len(self.herramientas_disponibles)} herramientas disponibles")
    
    def _verificar_herramientas_base(self):
        """Verificar qué herramientas base están disponibles."""
        for herramienta, ruta in self.herramientas_base.items():
            try:
                # Verificar si existe el archivo ejecutable
                if os.path.exists(ruta):
                    self.herramientas_disponibles[herramienta] = ruta
                else:
                    # Intentar encontrar con 'which'
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.herramientas_disponibles[herramienta] = result.stdout.strip()
                        
            except Exception as e:
                self.logger.debug(f"Error verificando {herramienta}: {e}")
    
    def log(self, mensaje: str):
        """
        Sistema de logging unificado.
        
        Args:
            mensaje: Mensaje a loggear
        """
        if self.configuracion.get('log_detallado', True):
            self.logger.info(mensaje)
        print(f"[ESCANEADOR] {mensaje}")
    
    def _ejecutar_comando_seguro(self, comando: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Ejecutar comando de forma segura con manejo de errores.
        
        Args:
            comando: Lista con comando y argumentos
            timeout: Timeout en segundos (opcional)
            
        Returns:
            Diccionario con resultado de la ejecución
        """
        if timeout is None:
            timeout = self.configuracion.get('timeout_comando', 300)
        
        resultado = {
            'exito': False,
            'codigo_retorno': -1,
            'stdout': '',
            'stderr': '',
            'comando_ejecutado': ' '.join(comando),
            'tiempo_ejecucion': 0
        }
        
        try:
            tiempo_inicio = time.time()
            
            # Validar que el comando está en herramientas permitidas
            comando_base = comando[0]
            if comando_base not in self.herramientas_disponibles:
                resultado['stderr'] = f"Herramienta no disponible: {comando_base}"
                return resultado
            
            # Ejecutar comando
            result = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            tiempo_ejecucion = time.time() - tiempo_inicio
            
            resultado.update({
                'exito': result.returncode == 0,
                'codigo_retorno': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'tiempo_ejecucion': round(tiempo_ejecucion, 2)
            })
            
            if resultado['exito']:
                self.log(f"Comando ejecutado exitosamente: {comando_base} ({tiempo_ejecucion:.2f}s)")
            else:
                self.log(f"Error ejecutando comando {comando_base}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            resultado['stderr'] = f"Timeout ejecutando comando ({timeout}s)"
            self.log(f"Timeout en comando: {comando_base}")
        except FileNotFoundError:
            resultado['stderr'] = f"Comando no encontrado: {comando_base}"
            self.log(f"Comando no encontrado: {comando_base}")
        except Exception as e:
            resultado['stderr'] = str(e)
            self.log(f"Error inesperado en comando {comando_base}: {e}")
        
        return resultado
    
    def escanear_puertos_basico(self, objetivo: str, puertos: str = "1-1000") -> Dict[str, Any]:
        """
        Escaneo básico de puertos usando herramientas nativas.
        
        Args:
            objetivo: IP o hostname a escanear
            puertos: Rango de puertos (ej: "1-1000", "80,443,22")
            
        Returns:
            Diccionario con resultados del escaneo
        """
        self.log(f"Iniciando escaneo básico de puertos: {objetivo}")
        
        resultado = {
            'exito': False,
            'objetivo': objetivo,
            'puertos_abiertos': [],
            'puertos_cerrados': [],
            'total_puertos_escaneados': 0,
            'herramienta_utilizada': '',
            'tiempo_ejecucion': 0
        }
        
        # Intentar con nmap si está disponible
        if 'nmap' in self.herramientas_disponibles:
            return self._escanear_con_nmap(objetivo, puertos)
        
        # Fallback: escaneo básico con netcat o telnet
        return self._escanear_basico_nativo(objetivo, puertos)
    
    def _escanear_con_nmap(self, objetivo: str, puertos: str) -> Dict[str, Any]:
        """Escaneo usando nmap."""
        comando = ['nmap', '-p', puertos, objetivo]
        resultado_cmd = self._ejecutar_comando_seguro(comando)
        
        resultado = {
            'exito': resultado_cmd['exito'],
            'objetivo': objetivo,
            'puertos_abiertos': [],
            'puertos_cerrados': [],
            'herramienta_utilizada': 'nmap',
            'tiempo_ejecucion': resultado_cmd['tiempo_ejecucion']
        }
        
        if resultado_cmd['exito']:
            # Parsear salida de nmap
            lines = resultado_cmd['stdout'].split('\n')
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    try:
                        puerto = line.split('/')[0].strip()
                        if puerto.isdigit():
                            resultado['puertos_abiertos'].append({
                                'puerto': int(puerto),
                                'protocolo': 'tcp',
                                'estado': 'open'
                            })
                    except (ValueError, IndexError):
                        continue
        
        resultado['total_puertos_escaneados'] = len(resultado['puertos_abiertos']) + len(resultado['puertos_cerrados'])
        return resultado
    
    def _escanear_basico_nativo(self, objetivo: str, puertos: str) -> Dict[str, Any]:
        """Escaneo básico usando herramientas nativas del sistema."""
        self.log("Usando escaneo básico nativo (sin nmap)")
        
        # Convertir rango de puertos a lista
        if '-' in puertos:
            inicio, fin = map(int, puertos.split('-'))
            lista_puertos = list(range(inicio, min(fin + 1, inicio + 50)))  # Limitar a 50 puertos
        else:
            lista_puertos = [int(p.strip()) for p in puertos.split(',') if p.strip().isdigit()]
        
        resultado = {
            'exito': True,
            'objetivo': objetivo,
            'puertos_abiertos': [],
            'puertos_cerrados': [],
            'herramienta_utilizada': 'nativo',
            'tiempo_ejecucion': 0
        }
        
        tiempo_inicio = time.time()
        
        for puerto in lista_puertos[:20]:  # Limitar para evitar timeouts
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((objetivo, puerto))
                sock.close()
                
                if result == 0:
                    resultado['puertos_abiertos'].append({
                        'puerto': puerto,
                        'protocolo': 'tcp',
                        'estado': 'open'
                    })
                else:
                    resultado['puertos_cerrados'].append(puerto)
                    
            except Exception:
                resultado['puertos_cerrados'].append(puerto)
        
        resultado['tiempo_ejecucion'] = round(time.time() - tiempo_inicio, 2)
        resultado['total_puertos_escaneados'] = len(lista_puertos)
        
        return resultado
    
    def obtener_informacion_red(self) -> Dict[str, Any]:
        """
        Obtener información básica de red del sistema.
        
        Returns:
            Diccionario con información de red
        """
        info = {
            'interfaces': [],
            'conexiones_activas': [],
            'rutas': [],
            'dns': []
        }
        
        # Obtener interfaces de red
        if 'ip' in self.herramientas_disponibles or os.path.exists('/sbin/ip'):
            cmd_resultado = self._ejecutar_comando_seguro(['ip', 'addr', 'show'])
            if cmd_resultado['exito']:
                info['interfaces'] = self._parsear_interfaces(cmd_resultado['stdout'])
        
        # Obtener conexiones activas
        if 'ss' in self.herramientas_disponibles:
            cmd_resultado = self._ejecutar_comando_seguro(['ss', '-tuln'])
            if cmd_resultado['exito']:
                info['conexiones_activas'] = self._parsear_conexiones(cmd_resultado['stdout'])
        elif 'netstat' in self.herramientas_disponibles:
            cmd_resultado = self._ejecutar_comando_seguro(['netstat', '-tuln'])
            if cmd_resultado['exito']:
                info['conexiones_activas'] = self._parsear_conexiones(cmd_resultado['stdout'])
        
        return info
    
    def _parsear_interfaces(self, salida: str) -> List[Dict[str, Any]]:
        """Parsear salida de ip addr show."""
        interfaces = []
        lineas = salida.split('\n')
        
        interface_actual = None
        for linea in lineas:
            if ': ' in linea and 'inet' not in linea:
                # Nueva interface
                partes = linea.split(': ')
                if len(partes) >= 2:
                    nombre = partes[1].split('@')[0]
                    interface_actual = {
                        'nombre': nombre,
                        'ips': [],
                        'estado': 'UP' if 'UP' in linea else 'DOWN'
                    }
                    interfaces.append(interface_actual)
            elif 'inet ' in linea and interface_actual:
                # IP de la interface
                partes = linea.strip().split()
                for i, parte in enumerate(partes):
                    if parte == 'inet' and i + 1 < len(partes):
                        ip = partes[i + 1].split('/')[0]
                        interface_actual['ips'].append(ip)
                        break
        
        return interfaces
    
    def _parsear_conexiones(self, salida: str) -> List[Dict[str, Any]]:
        """Parsear salida de ss o netstat."""
        conexiones = []
        lineas = salida.split('\n')
        
        for linea in lineas[1:]:  # Saltar header
            if linea.strip():
                partes = linea.split()
                if len(partes) >= 4:
                    conexiones.append({
                        'protocolo': partes[0],
                        'local': partes[3] if len(partes) > 3 else '',
                        'estado': partes[1] if 'LISTEN' in partes else 'ESTABLISHED'
                    })
        
        return conexiones[:20]  # Limitar resultados
    
    def validar_objetivo(self, objetivo: str) -> Dict[str, Any]:
        """
        Validar que un objetivo es válido y accesible.
        
        Args:
            objetivo: IP o hostname a validar
            
        Returns:
            Diccionario con resultado de validación
        """
        resultado = {
            'valido': False,
            'ip_resuelva': None,
            'accesible': False,
            'tiempo_respuesta': None,
            'error': None
        }
        
        try:
            import socket
            
            # Resolver hostname a IP
            ip = socket.gethostbyname(objetivo)
            resultado['ip_resuelva'] = ip
            resultado['valido'] = True
            
            # Verificar accesibilidad con ping
            if 'ping' in self.herramientas_disponibles:
                ping_resultado = self._ejecutar_comando_seguro(['ping', '-c', '1', '-W', '3', objetivo])
                if ping_resultado['exito']:
                    resultado['accesible'] = True
                    # Extraer tiempo de respuesta
                    if 'time=' in ping_resultado['stdout']:
                        try:
                            tiempo_str = ping_resultado['stdout'].split('time=')[1].split()[0]
                            resultado['tiempo_respuesta'] = float(tiempo_str.replace('ms', ''))
                        except (IndexError, ValueError):
                            pass
                            
        except socket.gaierror as e:
            resultado['error'] = f"Error resolviendo hostname: {e}"
        except Exception as e:
            resultado['error'] = f"Error validando objetivo: {e}"
        
        return resultado
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtener estadísticas del escaneador.
        
        Returns:
            Diccionario con estadísticas
        """
        return {
            'herramientas_disponibles': len(self.herramientas_disponibles),
            'herramientas_lista': list(self.herramientas_disponibles.keys()),
            'configuracion_activa': self.configuracion.copy(),
            'estado': 'operativo'
        }
