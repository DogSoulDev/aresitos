# -*- coding: utf-8 -*-
"""
ARESITOS - Módulo de Modelos
============================

Módulo que contiene todos los modelos del sistema ARESITOS.
Sistema de monitoreo y análisis de seguridad con herramientas nativas Kali Linux.

Principios ARESITOS aplicados:
- Importaciones con manejo de errores específico
- Logging integrado para trazabilidad
- Solo dependencias estándar de Python
- Arquitectura MVC estricta

Autor: DogSoulDev
Versión: 3.0.0
Fecha: 24 de Agosto de 2025
"""

import logging

# Configurar logger para el módulo de modelos
logger = logging.getLogger(__name__)

# Lista de modelos disponibles para tracking
modelos_disponibles = []

# Importar modelos principales con manejo de errores robusto
try:
    from .modelo_escaneador import EscaneadorKali2025
    modelos_disponibles.append('EscaneadorKali2025')
    logger.debug("Modelo Escaneador importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar EscaneadorKali2025: {e}")
    EscaneadorKali2025 = None

try:
    from .modelo_siem import SIEMKali2025
    modelos_disponibles.append('SIEMKali2025')
    logger.debug("Modelo SIEM importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar SIEMKali2025: {e}")
    SIEMKali2025 = None

try:
    from .modelo_fim import FIMKali2025
    modelos_disponibles.append('FIMKali2025')
    logger.debug("Modelo FIM importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar FIMKali2025: {e}")
    FIMKali2025 = None

try:
    from .modelo_cuarentena import CuarentenaKali2025
    modelos_disponibles.append('CuarentenaKali2025')
    logger.debug("Modelo Cuarentena importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar CuarentenaKali2025: {e}")
    CuarentenaKali2025 = None

try:
    from .modelo_dashboard import ModeloDashboard
    modelos_disponibles.append('ModeloDashboard')
    logger.debug("Modelo Dashboard importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ModeloDashboard: {e}")
    ModeloDashboard = None

try:
    from .modelo_diccionarios import ModeloGestorDiccionarios
    modelos_disponibles.append('ModeloGestorDiccionarios')
    logger.debug("Modelo Gestor Diccionarios importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ModeloGestorDiccionarios: {e}")
    ModeloGestorDiccionarios = None

try:
    from .modelo_monitor import MonitorAvanzadoNativo
    modelos_disponibles.append('MonitorAvanzadoNativo')
    logger.debug("Modelo Monitor Avanzado importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar MonitorAvanzadoNativo: {e}")
    MonitorAvanzadoNativo = None

try:
    from .modelo_principal import ModeloPrincipal
    modelos_disponibles.append('ModeloPrincipal')
    logger.debug("Modelo Principal importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ModeloPrincipal: {e}")
    ModeloPrincipal = None

try:
    from .modelo_reportes import ModeloReportes
    modelos_disponibles.append('ModeloReportes')
    logger.debug("Modelo Reportes importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ModeloReportes: {e}")
    ModeloReportes = None

try:
    from .modelo_sistema import ModeloUtilidadesSistema
    modelos_disponibles.append('ModeloUtilidadesSistema')
    logger.debug("Modelo Utilidades Sistema importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ModeloUtilidadesSistema: {e}")
    ModeloUtilidadesSistema = None

try:
    from .modelo_wordlists import ConstructorWordlists
    modelos_disponibles.append('ConstructorWordlists')
    logger.debug("Modelo Constructor Wordlists importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ConstructorWordlists: {e}")
    ConstructorWordlists = None

try:
    from .modelo_wordlists_gestor import ModeloGestorWordlists
    modelos_disponibles.append('ModeloGestorWordlists')
    logger.debug("Modelo Gestor Wordlists importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar ModeloGestorWordlists: {e}")
    ModeloGestorWordlists = None

# Importar clases base con manejo de errores
try:
    from .modelo_escaneador_base import EscaneadorBase
    modelos_disponibles.append('EscaneadorBase')
    logger.debug("Modelo Escaneador Base importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar EscaneadorBase: {e}")
    EscaneadorBase = None

try:
    from .modelo_fim_base import FIMBase
    modelos_disponibles.append('FIMBase')
    logger.debug("Modelo FIM Base importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar FIMBase: {e}")
    FIMBase = None

try:
    from .modelo_siem_base import SIEMBase
    modelos_disponibles.append('SIEMBase')
    logger.debug("Modelo SIEM Base importado correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar SIEMBase: {e}")
    SIEMBase = None

# Registro de modelos disponibles
logger.info(f"Modelos disponibles: {len(modelos_disponibles)} de 15 total")
logger.debug(f"Modelos cargados: {', '.join(modelos_disponibles)}")

def get_modelos_disponibles():
    """Obtener lista de modelos disponibles."""
    return modelos_disponibles.copy()

def verificar_modelo(nombre_modelo):
    """Verificar si un modelo específico está disponible."""
    return nombre_modelo in modelos_disponibles

def get_estadisticas_modelos():
    """Obtener estadísticas de modelos cargados."""
    return {
        'total_disponibles': len(modelos_disponibles),
        'principales': len([m for m in modelos_disponibles if not m.endswith('Base')]),
        'base': len([m for m in modelos_disponibles if m.endswith('Base')]),
        'especializados': len([m for m in modelos_disponibles if 'Kali' in m])
    }

__all__ = [
    # Modelos principales
    'EscaneadorKali2025',
    'SIEMKali2025',
    'FIMKali2025',
    'CuarentenaKali2025',
    'ModeloDashboard',
    'ModeloGestorDiccionarios',
    'MonitorAvanzadoNativo',
    'ModeloPrincipal',
    'ModeloReportes',
    'ModeloUtilidadesSistema',
    'ConstructorWordlists',
    'ModeloGestorWordlists',
    
    # Clases base
    'EscaneadorBase',
    'FIMBase',
    'SIEMBase',
    
    # Funciones utilitarias
    'get_modelos_disponibles',
    'verificar_modelo',
    'get_estadisticas_modelos'
]

__version__ = "3.0.0"
