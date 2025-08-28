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

ARESITOS - Módulo de Seguridad para Comandos de Terminal
========================================================
Módulo de seguridad que valida y sanitiza comandos ejecutados desde 
los terminales integrados de ARESITOS para prevenir ejecución de
comandos maliciosos o no autorizados.

Autor: DogSoulDev
Fecha: 22 de Agosto de 2025
"""

import os
import re
import platform
import getpass
import subprocess
from typing import Tuple, List, Dict, Optional, Any

# Importaciones específicas para Linux
try:
    import pwd
    import grp
    LINUX_MODULES_AVAILABLE = True
except ImportError:
    LINUX_MODULES_AVAILABLE = False


class ValidadorComandos:
    """Validador de seguridad para comandos de terminal en ARESITOS"""
    
    def __init__(self):
        self.usuario_actual = getpass.getuser()
        self.sistema = platform.system()
        
        # Comandos permitidos por categoría
        self.comandos_permitidos = {
            # Comandos de sistema básicos
            'sistema': [
                'ls', 'dir', 'pwd', 'whoami', 'id', 'groups', 'uptime',
                'df', 'du', 'free', 'top', 'htop', 'ps', 'pstree',
                'uname', 'hostname', 'date', 'cal', 'which', 'whereis'
            ],
            
            # Comandos de red y ciberseguridad
            'ciberseguridad': [
                'nmap', 'netstat', 'ss', 'lsof', 'iptables', 'ping',
                'traceroute', 'dig', 'nslookup', 'curl', 'wget',
                'tcpdump', 'wireshark', 'tshark', 'masscan', 'rustscan',
                'nikto', 'gobuster', 'feroxbuster', 'dirb', 'wfuzz',
                'sqlmap', 'hydra', 'john', 'hashcat', 'aircrack-ng'
            ],
            
            # Comandos de análisis y forense
            'forense': [
                'strings', 'hexdump', 'xxd', 'file', 'exiftool',
                'binwalk', 'foremost', 'volatility', 'chkrootkit',
                'rkhunter', 'lynis', 'aide', 'tripwire', 'samhain'
            ],
            
            # Comandos de archivos (solo lectura segura)
            'archivos': [
                'cat', 'head', 'tail', 'less', 'more', 'grep', 'find',
                'locate', 'wc', 'sort', 'uniq', 'cut', 'awk', 'sed'
            ],
            
            # Comandos de logs y monitoreo
            'logs': [
                'journalctl', 'dmesg', 'last', 'lastlog', 'who', 'w',
                'history', 'tail', 'watch', 'iostat', 'vmstat', 'sar'
            ]
        }
        
        # Comandos explícitamente prohibidos (peligrosos)
        self.comandos_prohibidos = [
            # Comandos destructivos
            'rm', 'rmdir', 'mv', 'cp', 'dd', 'shred', 'wipefs',
            
            # Comandos de modificación de sistema
            'chmod', 'chown', 'chgrp', 'mount', 'umount', 'fdisk',
            'mkfs', 'fsck', 'crontab', 'systemctl', 'service',
            
            # Comandos de red peligrosos
            'iptables', 'ufw', 'firewall-cmd', 'shutdown', 'reboot',
            'halt', 'poweroff', 'init', 'telinit',
            
            # Comandos de instalación/modificación
            'apt', 'apt-get', 'yum', 'dnf', 'pacman', 'pip', 'pip3',
            'npm', 'cargo', 'gem', 'go', 'make', 'cmake',
            
            # Comandos de shell y ejecución
            'bash', 'sh', 'zsh', 'fish', 'exec', 'eval', 'source',
            'su', 'sudo', 'passwd', 'usermod', 'useradd', 'userdel'
        ]
        
        # Patrones peligrosos en comandos
        self.patrones_peligrosos = [
            r'[;&|`$()]',           # Operadores de shell
            r'>\s*/',               # Redirección a sistema
            r'\$\(',                # Sustitución de comandos
            r'`.*`',                # Backticks
            r'\|\s*sudo',           # Pipe a sudo
            r'\|\s*su',             # Pipe a su
            r'/etc/',               # Acceso a configs
            r'/root/',              # Acceso a root
            r'/home/(?!kali)',      # Acceso a otros usuarios
            r'--password',          # Parámetros de password
            r'-p\s*\w+',           # Flags de password
        ]
    
    def validar_usuario_kali(self) -> bool:
        """Validar que el usuario actual sea 'kali' en Kali Linux"""
        try:
            if self.sistema != "Linux":
                return False
            
            # Verificar usuario kali
            if self.usuario_actual != "kali":
                return False
            
            # Verificar distribución Kali Linux
            try:
                with open('/etc/os-release', 'r') as f:
                    contenido = f.read()
                    if 'kali' not in contenido.lower():
                        return False
            except:
                return False
            
            # Verificar grupos de seguridad (solo en Linux)
            if LINUX_MODULES_AVAILABLE:
                try:
                    # Obtener grupos del usuario usando subprocess como alternativa
                    resultado = subprocess.run(['groups', self.usuario_actual], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        grupos_str = resultado.stdout.strip()
                        grupos_requeridos = ['sudo', 'kali']
                        return any(grupo in grupos_str for grupo in grupos_requeridos)
                except:
                    pass
            
            return True  # Si llegamos aquí, usuario kali en Kali Linux
            
        except Exception:
            return False
    
    def sanitizar_comando(self, comando: str) -> str:
        """Sanitizar comando eliminando caracteres peligrosos"""
        # Eliminar espacios extra
        comando = comando.strip()
        
        # Eliminar comentarios
        comando = re.sub(r'#.*$', '', comando)
        
        # Eliminar caracteres de control
        comando = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', comando)
        
        return comando
    
    def validar_comando_permitido(self, comando: str) -> Tuple[bool, str]:
        """Validar si un comando está en la lista de permitidos"""
        comando_base = comando.split()[0] if comando.split() else ""
        
        # Verificar si está explícitamente prohibido
        if comando_base in self.comandos_prohibidos:
            return False, f"Comando prohibido: {comando_base}"
        
        # Verificar patrones peligrosos
        for patron in self.patrones_peligrosos:
            if re.search(patron, comando):
                return False, f"Patrón peligroso detectado: {patron}"
        
        # Verificar si está en comandos permitidos
        todos_permitidos = []
        for categoria in self.comandos_permitidos.values():
            todos_permitidos.extend(categoria)
        
        if comando_base not in todos_permitidos:
            return False, f"Comando no autorizado: {comando_base}"
        
        return True, "Comando autorizado"
    
    def validar_longitud_comando(self, comando: str) -> Tuple[bool, str]:
        """Validar longitud del comando para prevenir ataques de buffer"""
        max_longitud = 1000
        
        if len(comando) > max_longitud:
            return False, f"Comando demasiado largo (max {max_longitud} caracteres)"
        
        return True, "Longitud válida"
    
    def validar_comando_completo(self, comando: str) -> Tuple[bool, str, str]:
        """
        Validación completa de comando
        
        Returns:
            Tuple[bool, str, str]: (es_válido, comando_sanitizado, mensaje)
        """
        # 1. Validar usuario Kali
        if not self.validar_usuario_kali():
            return False, "", "[FAIL] ACCESO DENEGADO: Solo usuario 'kali' en Kali Linux"
        
        # 2. Sanitizar comando
        comando_sanitizado = self.sanitizar_comando(comando)
        
        if not comando_sanitizado:
            return False, "", "[FAIL] Comando vacío después de sanitización"
        
        # 3. Validar longitud
        valido_longitud, msg_longitud = self.validar_longitud_comando(comando_sanitizado)
        if not valido_longitud:
            return False, "", f"[FAIL] {msg_longitud}"
        
        # 4. Validar comando permitido
        valido_permitido, msg_permitido = self.validar_comando_permitido(comando_sanitizado)
        if not valido_permitido:
            return False, "", f"[FAIL] {msg_permitido}"
        
        return True, comando_sanitizado, f"[OK] Comando autorizado: {comando_sanitizado}"
    
    def obtener_comandos_disponibles(self) -> Dict[str, List[str]]:
        """Obtener lista de comandos disponibles por categoría"""
        return self.comandos_permitidos.copy()
    
    def obtener_info_seguridad(self) -> Dict[str, Any]:
        """Obtener información del estado de seguridad actual"""
        return {
            'usuario_actual': self.usuario_actual,
            'sistema': self.sistema,
            'es_usuario_kali': self.validar_usuario_kali(),
            'total_comandos_permitidos': sum(len(cmds) for cmds in self.comandos_permitidos.values()),
            'total_comandos_prohibidos': len(self.comandos_prohibidos),
            'patrones_seguridad': len(self.patrones_peligrosos)
        }


# Instancia global del validador
validador_comandos = ValidadorComandos()


def validar_comando_seguro(comando: str) -> Tuple[bool, str, str]:
    """
    Función de conveniencia para validar comandos de forma segura
    
    Args:
        comando: Comando a validar
        
    Returns:
        Tuple[bool, str, str]: (es_válido, comando_sanitizado, mensaje)
    """
    return validador_comandos.validar_comando_completo(comando)


def obtener_comandos_disponibles() -> Dict[str, List[str]]:
    """Obtener comandos disponibles"""
    return validador_comandos.obtener_comandos_disponibles()


def info_seguridad_comandos() -> None:
    """Imprimir información de seguridad de comandos"""
    info = validador_comandos.obtener_info_seguridad()
    print("\n=== INFORMACIÓN SEGURIDAD COMANDOS ===")
    for clave, valor in info.items():
        print(f"{clave}: {valor}")
    print("=====================================\n")
