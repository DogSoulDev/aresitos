# -*- coding: utf-8 -*-
"""
Ares Aegis - Escaneador Modular
Punto de entrada principal para el sistema de escaneo modularizado
Mantiene compatibilidad con la interfaz existente
"""

# Importar las nuevas clases modularizadas
from .modelo_escaneador_base import EscaneadorBase, SecurityError, TipoEscaneo, NivelCriticidad
from .modelo_escaneador_avanzado import EscaneadorAvanzado

# Mantener compatibilidad con importaciones existentes
__all__ = [
    'EscaneadorBase',
    'EscaneadorAvanzado', 
    'SecurityError',
    'TipoEscaneo',
    'NivelCriticidad'
]

# Alias para compatibilidad hacia atrás
Escaneador = EscaneadorAvanzado  # Alias principal
EscaneadorCompleto = EscaneadorAvanzado  # Alias alternativo

# Información del módulo
__version__ = "3.0.0"
__author__ = "Ares Aegis Security Team"
__description__ = "Sistema modular de escaneo de seguridad"

def crear_escaneador(tipo: str = "avanzado", **kwargs):
    """
    Factory function para crear instancias del escaneador.
    
    Args:
        tipo: Tipo de escaneador ('base' o 'avanzado')
        **kwargs: Argumentos adicionales para el constructor
        
    Returns:
        Instancia del escaneador solicitado
    """
    if tipo.lower() == "base":
        return EscaneadorBase(**kwargs)
    elif tipo.lower() == "avanzado":
        return EscaneadorAvanzado(**kwargs)
    else:
        raise ValueError(f"Tipo de escaneador no válido: {tipo}. Use 'base' o 'avanzado'")

def obtener_version():
    """Obtener información de versión del módulo."""
    return {
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'modulos': ['EscaneadorBase', 'EscaneadorAvanzado'],
        'capacidades': [
            'Escaneo de puertos',
            'Detección de servicios', 
            'Análisis de vulnerabilidades',
            'Sistema de cache',
            'Detección de anomalías',
            'Sandbox de comandos',
            'Reportes de seguridad'
        ]
    }
