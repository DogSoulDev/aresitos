# -*- coding: utf-8 -*-
"""
Módulo de modelos de Ares Aegis
Incluye el sistema de escaneo modularizado
"""

# Importar clases principales del escáner
from .modelo_escaneador import (
    Escaneador, 
    EscaneadorBase, 
    EscaneadorAvanzado,
    SecurityError,
    TipoEscaneo,
    NivelCriticidad,
    crear_escaneador
)

# Importar EscaneadorKali2025 si está disponible
try:
    from .modelo_escaneador_kali2025 import EscaneadorKali2025
    KALI2025_ESCANEADOR_DISPONIBLE = True
except ImportError:
    EscaneadorKali2025 = None
    KALI2025_ESCANEADOR_DISPONIBLE = False

# Importar otros modelos principales (usando las clases que realmente existen)
try:
    from .modelo_siem import SIEMKali2025
    SIEM_DISPONIBLE = True
except ImportError:
    SIEMKali2025 = None
    SIEM_DISPONIBLE = False

try:
    from .modelo_fim import FIMKali2025
    FIM_DISPONIBLE = True
except ImportError:
    FIMKali2025 = None
    FIM_DISPONIBLE = False

__all__ = [
    'Escaneador',
    'EscaneadorBase', 
    'EscaneadorAvanzado',
    'SecurityError',
    'TipoEscaneo',
    'NivelCriticidad',
    'crear_escaneador'
]

# Añadir clases disponibles dinámicamente
if KALI2025_ESCANEADOR_DISPONIBLE:
    __all__.append('EscaneadorKali2025')

if SIEM_DISPONIBLE:
    __all__.append('SIEMKali2025')

if FIM_DISPONIBLE:
    __all__.append('FIMKali2025')

__version__ = "3.0.0"
