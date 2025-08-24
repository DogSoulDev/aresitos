# -*- coding: utf-8 -*-
"""
ARESITOS - Módulo de Utilidades
==============================

Módulo que contiene utilidades del sistema ARESITOS.
Incluye sanitización de archivos, verificaciones de seguridad y gestión de permisos.

Principios ARESITOS aplicados:
- Importaciones con manejo de errores específico
- Logging integrado para trazabilidad
- Gestión segura de permisos
- Solo dependencias estándar de Python

Autor: DogSoulDev
Fecha: 24 de Agosto de 2025
"""

import logging

# Configurar logger para el módulo de utilidades
logger = logging.getLogger(__name__)

# Lista de utilidades disponibles para tracking
utilidades_disponibles = []

# Importar utilidades principales con manejo de errores robusto
try:
    from .sanitizador_archivos import SanitizadorArchivos
    utilidades_disponibles.append('SanitizadorArchivos')
    logger.debug("Sanitizador de Archivos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar SanitizadorArchivos: {e}")
    SanitizadorArchivos = None

try:
    from .helper_seguridad import HelperSeguridad
    utilidades_disponibles.append('HelperSeguridad')
    logger.debug("Helper de Seguridad importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar HelperSeguridad: {e}")
    HelperSeguridad = None

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

# Utilidades adicionales opcionales
try:
    from .detector_red import DetectorRed
    utilidades_disponibles.append('DetectorRed')
    logger.debug("Detector de Red importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar DetectorRed: {e}")
    DetectorRed = None

try:
    from .configurar import ConfiguradorAresAegis
    utilidades_disponibles.append('ConfiguradorAresAegis')
    logger.debug("Configurador importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ConfiguradorAresAegis: {e}")
    ConfiguradorAresAegis = None

try:
    from .gestor_permisos import GestorPermisosSeguro
    utilidades_disponibles.append('GestorPermisosSeguro')
    logger.debug("Gestor de Permisos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar GestorPermisosSeguro: {e}")
    GestorPermisosSeguro = None

try:
    from .seguridad_comandos import ValidadorComandos
    utilidades_disponibles.append('ValidadorComandos')
    logger.debug("Validador de Comandos importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ValidadorComandos: {e}")
    ValidadorComandos = None

# Importar funciones de verificar_kali (no tiene clases)
try:
    from .verificar_kali import verificar_compatibilidad_kali
    utilidades_disponibles.append('verificar_compatibilidad_kali')
    logger.debug("Verificador de Kali importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar verificar_compatibilidad_kali: {e}")
    verificar_compatibilidad_kali = None

# Registro de utilidades disponibles
logger.info(f"Utilidades disponibles: {len(utilidades_disponibles)} utilidades cargadas")
logger.debug(f"Utilidades cargadas: {', '.join(utilidades_disponibles)}")

def get_utilidades_disponibles():
    """Obtener lista de utilidades disponibles."""
    return utilidades_disponibles.copy()

def verificar_utilidad(nombre_utilidad):
    """Verificar si una utilidad específica está disponible."""
    return nombre_utilidad in utilidades_disponibles

def get_estadisticas_utilidades():
    """Obtener estadísticas de utilidades cargadas."""
    return {
        'total_disponibles': len(utilidades_disponibles),
        'seguridad': len([u for u in utilidades_disponibles if 'Seguridad' in u or 'Sudo' in u]),
        'sistema': len([u for u in utilidades_disponibles if 'Sistema' in u or 'Red' in u or 'Kali' in u]),
        'archivos': len([u for u in utilidades_disponibles if 'Archivo' in u or 'Sanitizador' in u])
    }

def verificar_dependencias_criticas():
    """Verificar que las dependencias críticas estén disponibles."""
    criticas = ['SanitizadorArchivos', 'HelperSeguridad', 'SudoManager']
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

__all__ = [
    # Utilidades principales
    'SanitizadorArchivos', 
    'HelperSeguridad', 
    'SudoManager', 
    'get_sudo_manager', 
    'execute_sudo', 
    'is_sudo_available',
    
    # Utilidades adicionales
    'DetectorRed',
    'ConfiguradorAresAegis',
    'GestorPermisosSeguro',
    'ValidadorComandos',
    'verificar_compatibilidad_kali',
    
    # Funciones utilitarias
    'get_utilidades_disponibles',
    'verificar_utilidad',
    'get_estadisticas_utilidades',
    'verificar_dependencias_criticas'
]
