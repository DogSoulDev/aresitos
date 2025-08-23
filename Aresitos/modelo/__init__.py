# -*- coding: utf-8 -*-
"""
ARESITOS V3 - Módulo de Modelos de Datos
Sistema de escaneo modularizado y arquitectura MVC profesional
Autor: DogSoulDev
"""

# Importaciones principales del sistema de escaneo
try:
    from .modelo_escaneador import EscaneadorCompleto
    ESCANEADOR_DISPONIBLE = True
except ImportError:
    EscaneadorCompleto = None
    ESCANEADOR_DISPONIBLE = False

# Importar modelo SIEM
try:
    from .modelo_siem import SIEMKali2025
    SIEM_DISPONIBLE = True
except ImportError:
    SIEMKali2025 = None
    SIEM_DISPONIBLE = False

# Importar modelo FIM
try:
    from .modelo_fim_kali2025 import FIMKali2025
    FIM_DISPONIBLE = True
except ImportError:
    FIMKali2025 = None
    FIM_DISPONIBLE = False

# Importar modelo Dashboard
try:
    from .modelo_dashboard import ModeloDashboard
    DASHBOARD_DISPONIBLE = True
except ImportError:
    ModeloDashboard = None
    DASHBOARD_DISPONIBLE = False

# Importar modelo de reportes
try:
    from .modelo_reportes import ModeloReportes
    REPORTES_DISPONIBLE = True
except ImportError:
    ModeloReportes = None
    REPORTES_DISPONIBLE = False

# Importar modelo principal
try:
    from .modelo_principal import ModeloPrincipal
    PRINCIPAL_DISPONIBLE = True
except ImportError:
    ModeloPrincipal = None
    PRINCIPAL_DISPONIBLE = False

# Lista base de exportaciones
__all__ = []

# Añadir clases disponibles dinámicamente
if ESCANEADOR_DISPONIBLE:
    __all__.append('EscaneadorCompleto')

if SIEM_DISPONIBLE:
    __all__.append('SIEMKali2025')

if FIM_DISPONIBLE:
    __all__.append('FIMKali2025')

if DASHBOARD_DISPONIBLE:
    __all__.append('ModeloDashboard')

if REPORTES_DISPONIBLE:
    __all__.append('ModeloReportes')

if PRINCIPAL_DISPONIBLE:
    __all__.append('ModeloPrincipal')

# Información del módulo
__version__ = "3.0.0"
__author__ = "DogSoulDev"
__description__ = "ARESITOS V3 - Modelos de datos para ciberseguridad profesional"
