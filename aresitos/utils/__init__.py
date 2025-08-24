# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Módulo de Utilidades Optimizado
==============================================

Módulo que contiene las utilidades core del sistema ARESITOS v3.0.
Arquitectura limpia con solo componentes activamente utilizados.

Utilidades Principales:
- Gestión segura de permisos sudo
- Sanitización y validación de archivos
- Seguridad de comandos del sistema
- Detección de red y conectividad
- Helper de seguridad integrado

Principios ARESITOS v3.0:
- Solo importaciones de archivos existentes y utilizados
- Manejo de errores específico y robusto
- Logging integrado para trazabilidad completa
- Zero dependencias externas

Autor: DogSoulDev
Fecha: 24 de Agosto de 2025
"""

import logging

# Configurar logger para el módulo de utilidades
logger = logging.getLogger(__name__)

# Lista de utilidades disponibles para tracking
utilidades_disponibles = []

# === UTILIDADES CRÍTICAS ===

try:
    from .sudo_manager import SudoManager, get_sudo_manager, execute_sudo, is_sudo_available
    utilidades_disponibles.extend(['SudoManager', 'get_sudo_manager', 'execute_sudo', 'is_sudo_available'])
    logger.debug("Gestor de Sudo importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar componentes de sudo_manager: {e}")
    SudoManager = None
    get_sudo_manager = None
    execute_sudo = None
    is_sudo_available = None

try:
    from .seguridad_comandos import ValidadorComandos
    utilidades_disponibles.append('ValidadorComandos')
    logger.debug("Validador de Comandos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ValidadorComandos: {e}")
    ValidadorComandos = None

try:
    from .sanitizador_archivos import SanitizadorArchivos
    utilidades_disponibles.append('SanitizadorArchivos')
    logger.debug("Sanitizador de Archivos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar SanitizadorArchivos: {e}")
    SanitizadorArchivos = None

# === UTILIDADES ESPECIALIZADAS ===

try:
    from .helper_seguridad import HelperSeguridad
    utilidades_disponibles.append('HelperSeguridad')
    logger.debug("Helper de Seguridad importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar HelperSeguridad: {e}")
    HelperSeguridad = None

try:
    from .detector_red import DetectorRed
    utilidades_disponibles.append('DetectorRed')
    logger.debug("Detector de Red importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar DetectorRed: {e}")
    DetectorRed = None

try:
    from .detener_procesos import detener_procesos
    utilidades_disponibles.append('detener_procesos')
    logger.debug("Gestor de Procesos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar detener_procesos: {e}")
    detener_procesos = None

try:
    from .gestor_permisos import GestorPermisosSeguro
    utilidades_disponibles.append('GestorPermisosSeguro')
    logger.debug("Gestor de Permisos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar GestorPermisosSeguro: {e}")
    GestorPermisosSeguro = None

# Registro de utilidades disponibles
logger.info(f"Utilidades disponibles: {len(utilidades_disponibles)} utilidades cargadas")
logger.debug(f"Utilidades cargadas: {', '.join(utilidades_disponibles)}")

def get_utilidades_disponibles():
    """Obtener lista de utilidades disponibles."""
    return utilidades_disponibles.copy()

def verificar_utilidad(nombre_utilidad):
    """Verificar si una utilidad específica está disponible."""
    return nombre_utilidad in utilidades_disponibles

def verificar_dependencias_criticas():
    """Verificar que las dependencias críticas estén disponibles."""
    criticas = ['SudoManager', 'ValidadorComandos', 'SanitizadorArchivos']
    disponibles = [u for u in criticas if verificar_utilidad(u)]
    
    if len(disponibles) == len(criticas):
        logger.info("Todas las dependencias críticas están disponibles")
        return True, "Todas las utilidades críticas disponibles"
    else:
        faltantes = [u for u in criticas if u not in disponibles]
        logger.error(f"Dependencias críticas faltantes: {faltantes}")
        return False, f"Dependencias faltantes: {', '.join(faltantes)}"

# Ejecutar verificación inicial
verificar_dependencias_criticas()

# === EXPORTACIONES VALIDADAS ===
__all__ = [
    # Gestión de permisos (CRÍTICO)
    'SudoManager', 
    'get_sudo_manager', 
    'execute_sudo', 
    'is_sudo_available',
    
    # Seguridad de comandos (CRÍTICO)
    'ValidadorComandos',
    
    # Sanitización de archivos (CRÍTICO)
    'SanitizadorArchivos',
    
    # Utilidades especializadas
    'HelperSeguridad',
    'DetectorRed',
    'detener_procesos',
    'GestorPermisosSeguro',
    
    # Funciones utilitarias
    'get_utilidades_disponibles',
    'verificar_utilidad',
    'verificar_dependencias_criticas'
]
