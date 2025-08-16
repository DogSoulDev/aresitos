#!/usr/bin/env python3
"""
Modelo para gestión de herramientas de ciberseguridad
Autor: Aresitos
"""

import logging
import json
import subprocess
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading

class ModeloHerramientas:
    def __init__(self):
        """Inicializa el modelo de herramientas"""
        self.logger = logging.getLogger(__name__)
        self.herramientas_disponibles = {}
        self.procesos_activos = {}
        self._lock = threading.Lock()
        self._cargar_herramientas_disponibles()
        
    def _cargar_herramientas_disponibles(self):
        """Carga la configuración de herramientas disponibles"""
        herramientas_config = {
            'nmap': {
                'nombre': 'Nmap',
                'descripcion': 'Escáner de red y puertos',
                'comando': 'nmap',
                'categorias': ['escaneo', 'red'],
                'parametros_comunes': ['-sS', '-sV', '-O', '-A', '-p-']
            },
            'metasploit': {
                'nombre': 'Metasploit Framework',
                'descripcion': 'Framework de explotación',
                'comando': 'msfconsole',
                'categorias': ['explotacion', 'pentesting'],
                'parametros_comunes': ['-q', '-x']
            },
            'burpsuite': {
                'nombre': 'Burp Suite',
                'descripcion': 'Proxy de interceptación web',
                'comando': 'burpsuite',
                'categorias': ['web', 'proxy'],
                'parametros_comunes': ['--user-config-file']
            },
            'john': {
                'nombre': 'John the Ripper',
                'descripcion': 'Crackeador de contraseñas',
                'comando': 'john',
                'categorias': ['password', 'cracking'],
                'parametros_comunes': ['--wordlist', '--rules', '--format']
            },
            'hashcat': {
                'nombre': 'Hashcat',
                'descripcion': 'Crackeador de hashes avanzado',
                'comando': 'hashcat',
                'categorias': ['password', 'cracking', 'gpu'],
                'parametros_comunes': ['-m', '-a', '-w']
            },
            'sqlmap': {
                'nombre': 'SQLMap',
                'descripcion': 'Herramienta de inyección SQL',
                'comando': 'sqlmap',
                'categorias': ['web', 'sql', 'injection'],
                'parametros_comunes': ['-u', '--dbs', '--tables']
            },
            'aircrack': {
                'nombre': 'Aircrack-ng',
                'descripcion': 'Suite de auditoría WiFi',
                'comando': 'aircrack-ng',
                'categorias': ['wifi', 'wireless'],
                'parametros_comunes': ['-w', '-b']
            },
            'nikto': {
                'nombre': 'Nikto',
                'descripcion': 'Escáner de vulnerabilidades web',
                'comando': 'nikto',
                'categorias': ['web', 'vulnerabilidades'],
                'parametros_comunes': ['-h', '-p', '-ssl']
            }
        }
        
        with self._lock:
            self.herramientas_disponibles = herramientas_config
    
    def verificar_herramienta_disponible(self, herramienta: str) -> bool:
        """
        Verifica si una herramienta está disponible en el sistema
        
        Args:
            herramienta: Nombre de la herramienta
            
        Returns:
            True si está disponible
        """
        try:
            if herramienta not in self.herramientas_disponibles:
                return False
                
            comando = self.herramientas_disponibles[herramienta]['comando']
            
            # Verificar si el comando existe
            result = subprocess.run(['which', comando], 
                                  capture_output=True, 
                                  text=True)
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error verificando herramienta {herramienta}: {e}")
            return False
    
    def obtener_herramientas_disponibles(self) -> Dict[str, Dict[str, Any]]:
        """
        Obtiene lista de herramientas disponibles
        
        Returns:
            Diccionario con herramientas disponibles
        """
        with self._lock:
            return self.herramientas_disponibles.copy()
    
    def obtener_herramientas_por_categoria(self, categoria: str) -> Dict[str, Dict[str, Any]]:
        """
        Obtiene herramientas filtradas por categoría
        
        Args:
            categoria: Categoría a filtrar
            
        Returns:
            Diccionario con herramientas de la categoría
        """
        herramientas_filtradas = {}
        
        with self._lock:
            for nombre, config in self.herramientas_disponibles.items():
                if categoria in config.get('categorias', []):
                    herramientas_filtradas[nombre] = config
                    
        return herramientas_filtradas
    
    def ejecutar_herramienta(self, herramienta: str, parametros: List[str], 
                           directorio_trabajo: Optional[str] = None) -> str:
        """
        Ejecuta una herramienta con parámetros específicos
        
        Args:
            herramienta: Nombre de la herramienta
            parametros: Lista de parámetros
            directorio_trabajo: Directorio de trabajo opcional
            
        Returns:
            ID del proceso iniciado
        """
        try:
            if herramienta not in self.herramientas_disponibles:
                raise ValueError(f"Herramienta no disponible: {herramienta}")
            
            comando = self.herramientas_disponibles[herramienta]['comando']
            comando_completo = [comando] + parametros
            
            proceso_id = f"{herramienta}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Ejecutar comando
            proceso = subprocess.Popen(
                comando_completo,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=directorio_trabajo
            )
            
            with self._lock:
                self.procesos_activos[proceso_id] = {
                    'herramienta': herramienta,
                    'comando': comando_completo,
                    'proceso': proceso,
                    'timestamp': datetime.now().isoformat(),
                    'directorio': directorio_trabajo
                }
            
            self.logger.info(f"Herramienta ejecutada: {herramienta} (ID: {proceso_id})")
            return proceso_id
            
        except Exception as e:
            self.logger.error(f"Error ejecutando herramienta {herramienta}: {e}")
            raise
    
    def obtener_resultado_herramienta(self, proceso_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene el resultado de una herramienta ejecutada
        
        Args:
            proceso_id: ID del proceso
            
        Returns:
            Resultado de la ejecución o None
        """
        try:
            with self._lock:
                if proceso_id not in self.procesos_activos:
                    return None
                
                info_proceso = self.procesos_activos[proceso_id]
                proceso = info_proceso['proceso']
            
            # Verificar si el proceso ha terminado
            if proceso.poll() is not None:
                stdout, stderr = proceso.communicate()
                
                resultado = {
                    'proceso_id': proceso_id,
                    'herramienta': info_proceso['herramienta'],
                    'comando': info_proceso['comando'],
                    'codigo_salida': proceso.returncode,
                    'stdout': stdout,
                    'stderr': stderr,
                    'completado': True
                }
                
                # Limpiar proceso completado
                with self._lock:
                    del self.procesos_activos[proceso_id]
                
                return resultado
            else:
                return {
                    'proceso_id': proceso_id,
                    'herramienta': info_proceso['herramienta'],
                    'completado': False,
                    'estado': 'ejecutando'
                }
                
        except Exception as e:
            self.logger.error(f"Error obteniendo resultado: {e}")
            return None
    
    def detener_herramienta(self, proceso_id: str) -> bool:
        """
        Detiene la ejecución de una herramienta
        
        Args:
            proceso_id: ID del proceso
            
        Returns:
            True si se detuvo correctamente
        """
        try:
            with self._lock:
                if proceso_id in self.procesos_activos:
                    proceso = self.procesos_activos[proceso_id]['proceso']
                    proceso.terminate()
                    
                    # Esperar a que termine
                    try:
                        proceso.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proceso.kill()
                    
                    del self.procesos_activos[proceso_id]
                    
            self.logger.info(f"Proceso detenido: {proceso_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deteniendo proceso {proceso_id}: {e}")
            return False
    
    def obtener_procesos_activos(self) -> Dict[str, Dict[str, Any]]:
        """
        Obtiene lista de procesos activos
        
        Returns:
            Diccionario con procesos activos
        """
        procesos_info = {}
        
        with self._lock:
            for proceso_id, info in self.procesos_activos.items():
                procesos_info[proceso_id] = {
                    'herramienta': info['herramienta'],
                    'comando': ' '.join(info['comando']),
                    'timestamp': info['timestamp'],
                    'estado': 'ejecutando'
                }
                
        return procesos_info
    
    def generar_comando_personalizado(self, herramienta: str, 
                                    objetivo: str, 
                                    opciones: Dict[str, Any]) -> List[str]:
        """
        Genera comando personalizado para una herramienta
        
        Args:
            herramienta: Nombre de la herramienta
            objetivo: Objetivo del escaneo/ataque
            opciones: Opciones específicas
            
        Returns:
            Lista con comando generado
        """
        if herramienta not in self.herramientas_disponibles:
            raise ValueError(f"Herramienta no disponible: {herramienta}")
        
        comando = []
        
        if herramienta == 'nmap':
            if opciones.get('escaneo_tcp'):
                comando.extend(['-sS'])
            if opciones.get('detectar_version'):
                comando.extend(['-sV'])
            if opciones.get('detectar_os'):
                comando.extend(['-O'])
            if opciones.get('puertos'):
                comando.extend(['-p', opciones['puertos']])
            comando.append(objetivo)
            
        elif herramienta == 'nikto':
            comando.extend(['-h', objetivo])
            if opciones.get('ssl'):
                comando.extend(['-ssl'])
            if opciones.get('puerto'):
                comando.extend(['-p', str(opciones['puerto'])])
                
        elif herramienta == 'sqlmap':
            comando.extend(['-u', objetivo])
            if opciones.get('obtener_dbs'):
                comando.extend(['--dbs'])
            if opciones.get('obtener_tablas'):
                comando.extend(['--tables'])
                
        return comando
    
    def obtener_plantillas_comando(self, herramienta: str) -> Dict[str, List[str]]:
        """
        Obtiene plantillas de comandos predefinidas
        
        Args:
            herramienta: Nombre de la herramienta
            
        Returns:
            Diccionario con plantillas
        """
        plantillas = {}
        
        if herramienta == 'nmap':
            plantillas = {
                'escaneo_basico': ['-sS', '-sV'],
                'escaneo_completo': ['-sS', '-sV', '-O', '-A'],
                'escaneo_rapido': ['-T4', '-F'],
                'escaneo_sigiloso': ['-sS', '-T1'],
                'todos_puertos': ['-p-', '-sV']
            }
            
        elif herramienta == 'nikto':
            plantillas = {
                'escaneo_basico': ['-h'],
                'escaneo_ssl': ['-h', '-ssl'],
                'escaneo_completo': ['-h', '-Tuning', 'x']
            }
            
        return plantillas
    
    def validar_parametros(self, herramienta: str, parametros: List[str]) -> bool:
        """
        Valida parámetros antes de ejecutar herramienta
        
        Args:
            herramienta: Nombre de la herramienta
            parametros: Lista de parámetros
            
        Returns:
            True si los parámetros son válidos
        """
        try:
            if herramienta not in self.herramientas_disponibles:
                return False
            
            # Validaciones básicas por herramienta
            if herramienta == 'nmap':
                # Verificar que hay un objetivo
                return len(parametros) > 0 and not all(p.startswith('-') for p in parametros)
                
            elif herramienta == 'nikto':
                # Verificar que hay un host especificado
                return '-h' in parametros
                
            elif herramienta == 'sqlmap':
                # Verificar que hay una URL especificada
                return '-u' in parametros
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error validando parámetros: {e}")
            return False
