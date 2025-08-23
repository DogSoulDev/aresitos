# -*- coding: utf-8 -*-
"""
Ares Aegis - Escaneador Modular
Punto de entrada principal para el sistema de escaneo modularizado
Mantiene compatibilidad con la interfaz existente
"""

# Importar las nuevas clases modularizadas
from .modelo_escaneador_base import EscaneadorBase, SecurityError, TipoEscaneo, NivelCriticidad
from .modelo_escaneador_avanzado_real import EscaneadorAvanzadoReal as EscaneadorAvanzado

# Importar clases especializadas si están disponibles
try:
    from .modelo_escaneador_avanzado_real import EscaneadorAvanzadoReal
    ESCANEADOR_REAL_DISPONIBLE = True
except ImportError:
    EscaneadorAvanzadoReal = None
    ESCANEADOR_REAL_DISPONIBLE = False

# Importar EscaneadorKali2025 si está disponible
try:
    from .modelo_escaneador_kali2025 import EscaneadorKali2025
    ESCANEADOR_KALI2025_DISPONIBLE = True
except ImportError:
    EscaneadorKali2025 = None
    ESCANEADOR_KALI2025_DISPONIBLE = False

# Mantener compatibilidad con importaciones existentes
__all__ = [
    'EscaneadorBase',
    'EscaneadorAvanzado', 
    'SecurityError',
    'TipoEscaneo',
    'NivelCriticidad',
    'crear_escaneador',
    'obtener_tipos_escaneo',
    'obtener_niveles_criticidad'
]

# Añadir clases disponibles dinámicamente
if ESCANEADOR_REAL_DISPONIBLE:
    __all__.append('EscaneadorAvanzadoReal')

if ESCANEADOR_KALI2025_DISPONIBLE:
    __all__.append('EscaneadorKali2025')

# Alias para compatibilidad hacia atrás
Escaneador = EscaneadorAvanzado  # Alias principal
EscaneadorCompleto = EscaneadorAvanzado  # Alias alternativo

# Información del módulo
__version__ = "3.0.0"
__author__ = "Ares Aegis Security Team"

def crear_escaneador(tipo: str = "avanzado", **kwargs):
    """
    Función de fábrica para crear escaneadores.
    
    Args:
        tipo: Tipo de escaneador ('base', 'avanzado', 'real')
        **kwargs: Argumentos adicionales para el constructor
        
    Returns:
        Instancia del escaneador correspondiente
    """
    if tipo == "base":
        return EscaneadorBase(**kwargs)
    elif tipo == "avanzado":
        return EscaneadorAvanzado(**kwargs)
    elif tipo == "real":
        if ESCANEADOR_REAL_DISPONIBLE and EscaneadorAvanzadoReal is not None:
            return EscaneadorAvanzadoReal(**kwargs)
        else:
            raise ImportError("EscaneadorAvanzadoReal no está disponible")
    # Usar EscaneadorKali2025 si está disponible
    elif tipo == "kali2025":
        if ESCANEADOR_KALI2025_DISPONIBLE and EscaneadorKali2025 is not None:
            return EscaneadorKali2025(**kwargs)
        elif ESCANEADOR_REAL_DISPONIBLE and EscaneadorAvanzadoReal is not None:
            return EscaneadorAvanzadoReal(**kwargs)
        else:
            raise ImportError("EscaneadorKali2025 no está disponible")
    else:
        raise ValueError(f"Tipo de escaneador no válido: {tipo}. Tipos disponibles: base, avanzado, real, kali2025")

def obtener_tipos_escaneo():
    """Retorna los tipos de escaneo disponibles."""
    return list(TipoEscaneo)

def obtener_niveles_criticidad():
    """Retorna los niveles de criticidad disponibles."""
    return list(NivelCriticidad)
