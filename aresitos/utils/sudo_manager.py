# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor Global de Sudo
===============================

Gestor singleton para mantener el estado de sudo entre todas las ventanas de ARESITOS.
Permite que las herramientas mantengan permisos root sin solicitar contraseña repetidamente.

Autor: DogSoulDev
Fecha: 22 de Agosto de 2025
"""

import os
import time
import subprocess
import threading
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
                    cls._instance._initialized = False
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
        self.sudo_timestamp = time.time()
        self.session_active = True
        
        # Configurar variables de entorno para mantener sudo
        if password:
            os.environ['ARESITOS_SUDO_ACTIVE'] = '1'
            # Renovar sudo timestamp
            self._renovar_sudo_timestamp()
    
    def _renovar_sudo_timestamp(self):
        """Renovar el timestamp de sudo para mantener la sesión activa"""
        try:
            if self.sudo_password:
                # Ejecutar comando sudo simple para renovar timestamp
                subprocess.run(
                    ['sudo', '-S', '-v'],
                    input=self.sudo_password + '\n',
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False
                )
        except Exception:
            pass
    
    def is_sudo_active(self) -> bool:
        """Verificar si sudo está activo"""
        if not self.sudo_authenticated:
            return False
        
        # Verificar si han pasado más de 15 minutos (timeout typical de sudo)
        if self.sudo_timestamp and (time.time() - self.sudo_timestamp) > 900:  # 15 minutos
            return False
        
        return self.session_active
    
    def get_sudo_command(self, command: str) -> str:
        """Obtener comando con sudo apropiado"""
        if self.is_sudo_active() and self.sudo_password:
            return f"echo '{self.sudo_password}' | sudo -S {command}"
        return f"sudo {command}"
    
    def execute_sudo_command(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """Ejecutar comando con sudo usando las credenciales guardadas"""
        if self.is_sudo_active() and self.sudo_password:
            # Renovar timestamp antes de ejecutar
            self._renovar_sudo_timestamp()
            
            full_command = f"echo '{self.sudo_password}' | sudo -S {command}"
            return subprocess.run(
                full_command,
                shell=True,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False
            )
        else:
            # Fallback sin contraseña guardada
            return subprocess.run(
                f"sudo {command}",
                shell=True,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False
            )
    
    def clear_sudo(self):
        """Limpiar estado de sudo"""
        self.sudo_authenticated = False
        self.sudo_password = None
        self.sudo_timestamp = None
        self.session_active = False
        if 'ARESITOS_SUDO_ACTIVE' in os.environ:
            del os.environ['ARESITOS_SUDO_ACTIVE']
    
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
