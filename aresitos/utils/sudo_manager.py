# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor Global de Sudo
===============================

Gestor singleton para mantener el estado de sudo entre todas las
ventanas de ARESITOS.
Permite que las herramientas mantengan permisos root sin solicitar
contraseña repetidamente.

Autor: DogSoulDev
Fecha: 22 de Agosto de 2025
"""

import os
import time
import subprocess
import threading
import gc  # Issue 21/24 - Optimización de memoria
import shlex
from typing import Optional


class SudoManager:
    """Manager global para mantener estado de sudo entre ventanas"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(SudoManager, cls).__new__(cls)
                    cls._instance._initialized = False  # type: ignore
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.sudo_authenticated = False
            self.sudo_password = None
            self.sudo_timestamp = None
            self.session_active = False
            self._initialized = True
    
    def set_sudo_authenticated(self, password: Optional[str] = None):
        """Marcar sudo como autenticado"""
        self.sudo_authenticated = True
        self.sudo_password = password
        # Mantener la sesión activa hasta que se llame a clear_sudo()
        self.session_active = True
        
        # Configurar variable de entorno para indicar que ARESITOS tiene sudo
        if password:
            os.environ['ARESITOS_SUDO_ACTIVE'] = '1'
    def _renovar_sudo_timestamp(self):
        """Renovar el timestamp de sudo para mantener la sesión activa
        - Issue 21/24 optimizado"""
        try:
            if self.sudo_password:
                # Ejecutar comando sudo simple para renovar timestamp
                # con timeout optimizado
                result = subprocess.run(
                    ['sudo', '-S', '-v'],
                    input=self.sudo_password + '\n',
                    text=True,
                    capture_output=True,
                    timeout=5,  # Reducido de 10 a 5 segundos
                    check=False
                )
                # Limpiar memoria inmediatamente después
                del result
                gc.collect()
        except Exception:
            pass
    
    def is_sudo_active(self) -> bool:
        """Verificar si sudo está activo"""
        # Consideramos sudo activo mientras la sesión no haya sido cerrada explícitamente
        try:
            return bool(self.sudo_authenticated and self.session_active)
        except Exception:
            return False
    
    def get_sudo_command(self, command: str) -> str:
        """Obtener comando con sudo apropiado"""
        if self.is_sudo_active() and self.sudo_password:
            return f"echo '{self.sudo_password}' | sudo -S {command}"
        return f"sudo {command}"
    
    def execute_sudo_command(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """Ejecutar comando con sudo usando las credenciales guardadas - sin límite de timeout"""
        # Ejecutamos comandos a través de sudo si la sesión está activa.
        # Usamos la forma segura cuando disponemos de la contraseña en memoria
        if self.is_sudo_active() and self.sudo_password:
            # Construir comando como lista cuando sea posible
            # Si el comando es una cadena compuesta, caemos a shell para compatibilidad
            try:
                # Intentar ejecutar como lista si el comando no contiene tuberías o redirecciones
                if isinstance(command, str) and any(c in command for c in ['|', '>', '<', ';', '&']):
                    full_command = f"echo '{self.sudo_password}' | sudo -S {command}"
                    result = subprocess.run(full_command, shell=True, text=True, capture_output=True, check=False)
                else:
                    # Ejecutar como lista para mayor seguridad
                    cmd_list = ['sudo', '-S'] + (shlex.split(command) if isinstance(command, str) else command)
                    # subprocess.run no admite pasar la password por stdin si usamos list sin shell;
                    # por simplicidad aquí enviamos la contraseña vía input cuando es necesario
                    result = subprocess.run(cmd_list, input=self.sudo_password + '\n', text=True, capture_output=True, check=False, timeout=timeout)
            except Exception:
                # Fallback a ejecución por shell en caso de error construyendo la cadena
                full_command = f"echo '{self.sudo_password}' | sudo -S {command}"
                result = subprocess.run(full_command, shell=True, text=True, capture_output=True, check=False)
            # Optimización de memoria - limpiar variables grandes
            if hasattr(result, 'stdout') and len(result.stdout) > 10000:  # >10KB
                gc.collect()
            return result
        else:
            # Fallback sin contraseña guardada
            return subprocess.run(
                f"sudo {command}",
                shell=True,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout
            )
    
    def clear_sudo(self):
        """Limpiar estado de sudo - Issue 21/24 optimizado"""
        self.sudo_authenticated = False
        # Limpiar memoria sensible de forma segura
        if hasattr(self, 'sudo_password') and self.sudo_password:
            self.sudo_password = None
        self.sudo_timestamp = None
        self.session_active = False
        
        # Forzar limpieza de memoria
        gc.collect()
        
        # Limpiar variable de entorno
        if 'ARESITOS_SUDO_ACTIVE' in os.environ:
            del os.environ['ARESITOS_SUDO_ACTIVE']
    
    def optimize_memory(self):
        """Método para optimización de memoria - Issue 21/24"""
        """Liberar memoria no utilizada y optimizar rendimiento"""
        try:
            # Forzar garbage collection
            collected = gc.collect()
            return f"Memoria optimizada: {collected} objetos liberados"
        except Exception as e:
            return f"Error optimizando memoria: {str(e)}"
    
    def get_status(self) -> dict:
        """Obtener estado actual del sudo"""
        return {
            'authenticated': self.sudo_authenticated,
            'active': self.is_sudo_active(),
            'timestamp': self.sudo_timestamp,
            'session_active': self.session_active,
            'env_var_set': 'ARESITOS_SUDO_ACTIVE' in os.environ
        }


# Función de conveniencia para obtener el SudoManager global
def get_sudo_manager() -> SudoManager:
    """Obtener la instancia global del SudoManager"""
    return SudoManager()


# Función de conveniencia para ejecutar comandos con sudo
def execute_sudo(command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Ejecutar comando con sudo usando el manager global"""
    sudo_manager = get_sudo_manager()
    return sudo_manager.execute_sudo_command(command, timeout)


# Función para verificar si sudo está disponible
def is_sudo_available() -> bool:
    """Verificar si sudo está disponible en el sistema"""
    sudo_manager = get_sudo_manager()
    return sudo_manager.is_sudo_active()
