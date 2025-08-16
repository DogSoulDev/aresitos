# -*- coding: utf-8 -*-
"""
Módulo de modelos de Ares Aegis
Incluye el sistema de escaneo modularizado
"""

# Importar clases principales del escaneador
from .modelo_escaneador import (
    Escaneador, 
    EscaneadorBase, 
    EscaneadorAvanzado,
    SecurityError,
    TipoEscaneo,
    NivelCriticidad,
    crear_escaneador
)

# Importar otros modelos principales
from .modelo_siem import SIEM, SIEMAvanzado, TipoEvento, SeveridadEvento
from .modelo_fim import FIMAvanzado, TipoArchivoFIM, TipoCambioFIM

__all__ = [
    'Escaneador',
    'EscaneadorBase', 
    'EscaneadorAvanzado',
    'SecurityError',
    'TipoEscaneo',
    'NivelCriticidad',
    'crear_escaneador',
    'SIEM',
    'SIEMAvanzado', 
    'TipoEvento',
    'SeveridadEvento',
    'FIMAvanzado',
    'TipoArchivoFIM',
    'TipoCambioFIM'
]

__version__ = "3.0.0"
