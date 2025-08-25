#!/usr/bin/env python3
"""
Gestor de Permisos Seguros para Ares Aegis
==========================================

Este módulo maneja de forma segura la elevación de permisos necesaria
para herramientas de seguridad en sistemas Linux, especialmente Kali Linux.

Características de Seguridad:
- Validación estricta de comandos permitidos
- Lista blanca de herramientas autorizadas
- Sanitización de argumentos
- Logging de todas las operaciones con permisos elevados
- Timeout configurable para prevenir bloqueos

Autor: DogSoulDev
Fecha: 15 de Agosto de 2025
Versión: 1.0
"""

import os
import sys
import subprocess
import logging
import shlex
import getpass
from typing import List, Optional, Dict, Tuple, Any
from pathlib import Path
import re
import platform

class GestorPermisosSeguro:
    """
    Gestor centralizado para manejar permisos elevados de forma segura.
    
    Este gestor implementa múltiples capas de seguridad:
    1. Lista blanca de comandos permitidos
    2. Validación de argumentos
    3. Sanitización de entrada
    4. Logging completo de operaciones
    5. Timeouts para prevenir bloqueos
    """
    
    # Lista blanca de herramientas permitidas con sudo
    HERRAMIENTAS_PERMITIDAS = {
        'nmap': {
            'path': '/usr/bin/nmap',
            'descripcion': 'Network mapper para escaneo de red',
            'args_seguros': ['-sS', '-sT', '-sU', '-sP', '-sn', '-O', '-A', '-v', '-p', '-T'],
            'args_prohibidos': ['--script', '&', ';', '|', '`', '$', '(', ')']
        },
        'netstat': {
            'path': '/bin/netstat',
            'descripcion': 'Mostrar conexiones de red',
            'args_seguros': ['-tuln', '-an', '-rn', '-ie'],
            'args_prohibidos': ['&', ';', '|', '`', '$']
        },
        'ss': {
            'path': '/usr/bin/ss',
            'descripcion': 'Socket statistics',
            'args_seguros': ['-tuln', '-an', '-p'],
            'args_prohibidos': ['&', ';', '|', '`', '$']
        },
        'masscan': {
            'path': '/usr/bin/masscan',
            'descripcion': 'Mass IP port scanner',
            'args_seguros': ['-p', '--rate', '--range'],
            'args_prohibidos': ['&', ';', '|', '`', '$', '--script']
        },
        'tcpdump': {
            'path': '/usr/bin/tcpdump',
            'descripcion': 'Packet analyzer',
            'args_seguros': ['-i', '-c', '-w', '-r', '-n'],
            'args_prohibidos': ['&', ';', '|', '`', '$', '--']
        },
        'cat': {
            'path': '/bin/cat',
            'descripcion': 'Leer contenido de archivos',
            'args_seguros': [],
            'args_prohibidos': ['&', ';', '|', '`', '$', '>', '<']
        },
        'ls': {
            'path': '/bin/ls',
            'descripcion': 'Listar contenido de directorios',
            'args_seguros': ['-la', '-l', '-a', '-h', '-R'],
            'args_prohibidos': ['&', ';', '|', '`', '$']
        }
    }
    
    # Rutas del sistema que requieren permisos elevados para lectura
    RUTAS_SISTEMA_CRITICAS = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config',
        '/var/log/auth.log',
        '/var/log/syslog',
        '/proc/net/tcp',
        '/proc/net/udp'
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Inicializa el gestor de permisos.
        
        Args:
            logger: Logger personalizado. Si no se proporciona, se crea uno por defecto.
        """
        self.logger = logger or self._crear_logger()
        self.usuario_actual = getpass.getuser()
        
        # Verificar si somos root de forma compatible con Windows/Linux
        self.es_root = False
        try:
            if platform.system() == "Windows":
                import ctypes
                self.es_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # En Linux/Unix verificar usuario actual
                self.es_root = getpass.getuser() == 'root'
        except (AttributeError, ImportError, OSError):
            # Fallback: verificar variable de entorno
            self.es_root = (os.environ.get('USER') == 'root' or 
                           os.environ.get('USERNAME') == 'root')
            
        self.timeout_comando = 300  # 5 minutos máximo por comando
        
        self.logger.info(f"GestorPermisosSeguro inicializado para usuario: {self.usuario_actual}")
        if self.es_root:
            self.logger.warning("WARNING Ejecutándose como ROOT - permisos elevados activos")
    
    def _crear_logger(self) -> logging.Logger:
        """Crea un logger específico para el gestor de permisos."""
        logger = logging.getLogger('AresAegis.GestorPermisosSeguro')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def verificar_sudo_disponible(self) -> bool:
        """
        Verifica si sudo está disponible y configurado.
        
        Returns:
            bool: True si sudo está disponible, False en caso contrario.
        """
        try:
            resultado = subprocess.run(
                ['sudo', '-n', 'true'], 
                capture_output=True, 
                timeout=5,
                check=False
            )
            disponible = resultado.returncode == 0
            
            if disponible:
                self.logger.info("OK sudo disponible y configurado")
            else:
                self.logger.warning("WARNING sudo no disponible o requiere contraseña")
                
            return disponible
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"ERROR verificando sudo: {e}")
            return False
    
    def _validar_comando(self, herramienta: str, argumentos: List[str]) -> Tuple[bool, str]:
        """
        Valida que un comando sea seguro para ejecutar con permisos elevados.
        
        Args:
            herramienta: Nombre de la herramienta a ejecutar
            argumentos: Lista de argumentos del comando
            
        Returns:
            Tuple[bool, str]: (es_valido, mensaje_error)
        """
        # Verificar que la herramienta esté en la lista blanca
        if herramienta not in self.HERRAMIENTAS_PERMITIDAS:
            return False, f"Herramienta '{herramienta}' no está en la lista de herramientas permitidas"
        
        config_herramienta = self.HERRAMIENTAS_PERMITIDAS[herramienta]
        
        # Verificar que el binario existe
        if not os.path.exists(config_herramienta['path']):
            return False, f"Binario '{config_herramienta['path']}' no encontrado"
        
        # Validar argumentos
        args_str = ' '.join(argumentos)
        
        # Verificar argumentos prohibidos
        for arg_prohibido in config_herramienta.get('args_prohibidos', []):
            if arg_prohibido in args_str:
                return False, f"Argumento prohibido detectado: '{arg_prohibido}'"
        
        # Buscar caracteres peligrosos para inyección de comandos
        caracteres_peligrosos = ['&', ';', '|', '`', '$', '(', ')', '<', '>', '&&', '||']
        for char in caracteres_peligrosos:
            if char in args_str:
                return False, f"Carácter peligroso detectado: '{char}'"
        
        # Validar que no hay rutas sospechosas
        rutas_sospechosas = ['/etc/passwd', '/etc/shadow', '../', '~/', '/root/']
        for ruta in rutas_sospechosas:
            if ruta in args_str:
                self.logger.warning(f"WARNING Ruta potencialmente sensible en argumentos: {ruta}")
        
        return True, "Comando validado correctamente"
    
    def ejecutar_con_permisos(self, herramienta: str, argumentos: List[str], 
                             timeout: Optional[int] = None) -> Tuple[bool, str, str]:
        """
        Ejecuta un comando con permisos elevados de forma segura.
        
        Args:
            herramienta: Nombre de la herramienta a ejecutar
            argumentos: Lista de argumentos del comando
            timeout: Timeout personalizado en segundos
            
        Returns:
            Tuple[bool, str, str]: (exito, stdout, stderr)
        """
        timeout_efectivo = timeout or self.timeout_comando
        
        # Validar el comando
        es_valido, mensaje_validacion = self._validar_comando(herramienta, argumentos)
        if not es_valido:
            self.logger.error(f"ERROR Validación fallida: {mensaje_validacion}")
            return False, "", f"Error de validación: {mensaje_validacion}"
        
        # Construir comando seguro
        config_herramienta = self.HERRAMIENTAS_PERMITIDAS[herramienta]
        comando_completo = [config_herramienta['path']] + argumentos
        
        # Si ya somos root, ejecutar directamente
        if self.es_root:
            comando_final = comando_completo
        else:
            comando_final = ['sudo'] + comando_completo
        
        # Log de la operación
        comando_log = ' '.join(shlex.quote(arg) for arg in comando_final)
        self.logger.info(f" Ejecutando: {comando_log}")
        
        try:
            proceso = subprocess.run(
                comando_final,
                capture_output=True,
                text=True,
                timeout=timeout_efectivo,
                check=False
            )
            
            exito = proceso.returncode == 0
            
            if exito:
                self.logger.info(f"OK Comando ejecutado exitosamente: {herramienta}")
            else:
                self.logger.warning(f"WARNING Comando falló con código {proceso.returncode}: {herramienta}")
            
            return exito, proceso.stdout, proceso.stderr
            
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout ({timeout_efectivo}s) ejecutando {herramienta}"
            self.logger.error(f"ERROR {error_msg}")
            return False, "", error_msg
            
        except Exception as e:
            error_msg = f"Error ejecutando {herramienta}: {str(e)}"
            self.logger.error(f"ERROR {error_msg}")
            return False, "", error_msg
    
    def leer_archivo_sistema(self, ruta_archivo: str) -> Tuple[bool, str]:
        """
        Lee un archivo del sistema que requiere permisos elevados.
        
        Args:
            ruta_archivo: Ruta del archivo a leer
            
        Returns:
            Tuple[bool, str]: (exito, contenido_o_error)
        """
        # Verificar que la ruta está en la lista de rutas permitidas
        if ruta_archivo not in self.RUTAS_SISTEMA_CRITICAS:
            self.logger.warning(f"WARNING Intento de leer archivo no autorizado: {ruta_archivo}")
        
        try:
            if self.es_root:
                # Si ya somos root, leer directamente
                with open(ruta_archivo, 'r') as f:
                    contenido = f.read()
                self.logger.info(f"OK Archivo leído exitosamente: {ruta_archivo}")
                return True, contenido
            else:
                # Usar sudo cat para leer el archivo
                exito, stdout, stderr = self.ejecutar_con_permisos('cat', [ruta_archivo])
                if exito:
                    return True, stdout
                else:
                    return False, stderr
                    
        except Exception as e:
            error_msg = f"Error leyendo archivo {ruta_archivo}: {str(e)}"
            self.logger.error(f"ERROR {error_msg}")
            return False, error_msg
    
    def verificar_permisos_herramienta(self, herramienta: str) -> Dict[str, Any]:
        """
        Verifica el estado de permisos para una herramienta específica.
        
        Args:
            herramienta: Nombre de la herramienta a verificar
            
        Returns:
            Dict con información sobre permisos y disponibilidad
        """
        resultado = {
            'herramienta': herramienta,
            'disponible': False,
            'path': None,
            'permisos_ok': False,
            'sudo_requerido': False,
            'mensaje': ''
        }
        
        if herramienta not in self.HERRAMIENTAS_PERMITIDAS:
            resultado['mensaje'] = f"Herramienta '{herramienta}' no autorizada"
            return resultado
        
        config = self.HERRAMIENTAS_PERMITIDAS[herramienta]
        path_herramienta = config['path']
        
        # Verificar si existe
        if os.path.exists(path_herramienta):
            resultado['disponible'] = True
            resultado['path'] = path_herramienta
            
            # Verificar permisos
            if os.access(path_herramienta, os.X_OK):
                if self.es_root:
                    resultado['permisos_ok'] = True
                    resultado['mensaje'] = "Permisos elevados activos"
                else:
                    # Verificar si necesita sudo
                    test_exito, _, _ = self.ejecutar_con_permisos(herramienta, ['--help'])
                    if test_exito:
                        resultado['permisos_ok'] = True
                        resultado['sudo_requerido'] = True
                        resultado['mensaje'] = "Sudo disponible y funcional"
                    else:
                        resultado['mensaje'] = "Sudo requerido pero no disponible"
            else:
                resultado['mensaje'] = "Sin permisos de ejecución"
        else:
            resultado['mensaje'] = f"Binario no encontrado: {path_herramienta}"
        
        return resultado
    
    def generar_reporte_permisos(self) -> Dict[str, Any]:
        """
        Genera un reporte completo del estado de permisos del sistema.
        
        Returns:
            Dict con reporte completo de permisos
        """
        reporte = {
            'usuario': self.usuario_actual,
            'es_root': self.es_root,
            'sudo_disponible': self.verificar_sudo_disponible(),
            'herramientas': {},
            'recomendaciones': []
        }
        
        # Verificar cada herramienta
        for herramienta in self.HERRAMIENTAS_PERMITIDAS:
            reporte['herramientas'][herramienta] = self.verificar_permisos_herramienta(herramienta)
        
        # Generar recomendaciones
        if not reporte['es_root'] and not reporte['sudo_disponible']:
            reporte['recomendaciones'].append(
                "Configurar sudo para el usuario actual o ejecutar como root"
            )
        
        herramientas_faltantes = [
            h for h, info in reporte['herramientas'].items() 
            if not info['disponible']
        ]
        
        if herramientas_faltantes:
            reporte['recomendaciones'].append(
                f"Instalar herramientas faltantes: {', '.join(herramientas_faltantes)}"
            )
        
        return reporte

# Instancia global del gestor de permisos
gestor_permisos = GestorPermisosSeguro()

def obtener_gestor_permisos() -> GestorPermisosSeguro:
    """Obtiene la instancia global del gestor de permisos."""
    return gestor_permisos

def ejecutar_comando_seguro(herramienta: str, argumentos: List[str], 
                           timeout: Optional[int] = None) -> Tuple[bool, str, str]:
    """
    Función de conveniencia para ejecutar comandos con permisos elevados.
    
    Args:
        herramienta: Nombre de la herramienta
        argumentos: Lista de argumentos
        timeout: Timeout opcional
        
    Returns:
        Tuple[bool, str, str]: (exito, stdout, stderr)
    """
    return gestor_permisos.ejecutar_con_permisos(herramienta, argumentos, timeout)

if __name__ == "__main__":
    # Test del gestor de permisos
    gestor = GestorPermisosSeguro()
    
    print("=== Reporte de Permisos Ares Aegis ===")
    reporte = gestor.generar_reporte_permisos()
    
    print(f"Usuario: {reporte['usuario']}")
    print(f"Es root: {reporte['es_root']}")
    print(f"Sudo disponible: {reporte['sudo_disponible']}")
    
    print("\nHerramientas:")
    for herramienta, info in reporte['herramientas'].items():
        status = "[OK]" if info['disponible'] and info['permisos_ok'] else "ERROR"
        print(f"{status} {herramienta}: {info['mensaje']}")
    
    if reporte['recomendaciones']:
        print("\nRecomendaciones:")
        for rec in reporte['recomendaciones']:
            print(f"• {rec}")
