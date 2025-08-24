
# -*- coding: utf-8 -*-
"""
ARESITOS - Sistema de Seguridad para Kali Linux
===============================================

Sistema autónomo de monitoreo, análisis y auditoría de seguridad
diseñado específicamente para Kali Linux.

Principios ARESITOS:
- Autonomía: Sin dependencias externas 
- Robustez: Manejo de errores específico
- Escalabilidad: Arquitectura MVC
- Seguridad: Validación y logging
- Internacionalización: UTF-8
- Trazabilidad: Logging completo
- Optimización: Kali Linux nativo
- Sostenibilidad: Documentación completa

Autor: DogSoulDev
Versión: 3.0.0
Fecha: 24 de Agosto de 2025
"""

__version__ = "3.0.0"
__author__ = "DogSoulDev"
__email__ = "dogsouldev@proton.me"
__license__ = "MIT"
__description__ = "Sistema de Seguridad para Kali Linux"

# Metadatos del proyecto
ARESITOS_INFO = {
    "nombre": "ARESITOS",
    "version": __version__,
    "descripcion": "Sistema autónomo de seguridad para Kali Linux",
    "autor": __author__,
    "plataforma": "Kali Linux",
    "arquitectura": "MVC",
    "dependencias": "Solo Python stdlib",
    "principios": [
        "Autonomía",
        "Robustez", 
        "Escalabilidad",
        "Seguridad",
        "Internacionalización",
        "Trazabilidad",
        "Optimización",
        "Sostenibilidad"
    ]
}

def get_version():
    """Obtener la versión de ARESITOS."""
    return __version__

def get_info():
    """Obtener información completa de ARESITOS."""
    return ARESITOS_INFO.copy()

def verificar_compatibilidad():
    """Verificar compatibilidad con Kali Linux."""
    import platform
    import os
    
    sistema = platform.system()
    if sistema != "Linux":
        return False, f"Sistema no compatible: {sistema}"
    
    # Verificar si es Kali Linux
    try:
        with open('/etc/os-release', 'r', encoding='utf-8') as f:
            contenido = f.read()
            if 'kali' in contenido.lower():
                return True, "Compatible con Kali Linux"
    except (FileNotFoundError, PermissionError):
        pass
    
    return False, "No es Kali Linux o no se puede verificar"

# Exportar elementos principales
__all__ = [
    '__version__',
    '__author__',
    '__description__',
    'ARESITOS_INFO',
    'get_version',
    'get_info',
    'verificar_compatibilidad'
]