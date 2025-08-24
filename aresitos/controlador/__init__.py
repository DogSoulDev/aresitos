
# -*- coding: utf-8 -*-
"""
ARESITOS - Módulo de Controladores
=================================

Módulo que contiene todos los controladores del sistema ARESITOS.

Autor: DogSoulDev
"""

# Importaciones básicas que siempre funcionan
try:
    from .controlador_base import ControladorBase
except ImportError:
    ControladorBase = None

# Importaciones principales con manejo de errores
controladores_disponibles = []

try:
    from .controlador_principal import ControladorPrincipal
    controladores_disponibles.append('ControladorPrincipal')
except ImportError:
    ControladorPrincipal = None

try:
    from .controlador_dashboard import ControladorDashboard
    controladores_disponibles.append('ControladorDashboard')
except ImportError:
    ControladorDashboard = None

try:
    from .controlador_escaneo import ControladorEscaneo
    controladores_disponibles.append('ControladorEscaneo')
except ImportError:
    ControladorEscaneo = None

try:
    from .controlador_siem import ControladorSIEM
    controladores_disponibles.append('ControladorSIEM')
except ImportError:
    ControladorSIEM = None

try:
    from .controlador_fim import ControladorFIM
    controladores_disponibles.append('ControladorFIM')
except ImportError:
    ControladorFIM = None

try:
    from .controlador_auditoria import ControladorAuditoria
    controladores_disponibles.append('ControladorAuditoria')
except ImportError:
    ControladorAuditoria = None

try:
    from .controlador_cuarentena import ControladorCuarentena
    controladores_disponibles.append('ControladorCuarentena')
except ImportError:
    ControladorCuarentena = None

try:
    from .controlador_monitoreo import ControladorMonitoreo
    controladores_disponibles.append('ControladorMonitoreo')
except ImportError:
    ControladorMonitoreo = None

try:
    from .controlador_reportes import ControladorReportes
    controladores_disponibles.append('ControladorReportes')
except ImportError:
    ControladorReportes = None

try:
    from .controlador_herramientas import ControladorHerramientas
    controladores_disponibles.append('ControladorHerramientas')
except ImportError:
    ControladorHerramientas = None

# Gestores especializados
try:
    from .controlador_componentes import GestorComponentes
    controladores_disponibles.append('GestorComponentes')
except ImportError:
    GestorComponentes = None

try:
    from .controlador_configuracion import GestorConfiguracion
    controladores_disponibles.append('GestorConfiguracion')
except ImportError:
    GestorConfiguracion = None

# Solo exportar las clases que se importaron exitosamente
__all__ = [
    'ControladorBase',
    'ControladorPrincipal', 
    'ControladorDashboard',
    'ControladorEscaneo',
    'ControladorSIEM',
    'ControladorFIM',
    'ControladorAuditoria',
    'ControladorCuarentena',
    'ControladorMonitoreo',
    'ControladorReportes',
    'ControladorHerramientas'
]

# Agregar controladores opcionales si están disponibles
if 'GestorComponentes' in globals() and GestorComponentes is not None:
    __all__.append('GestorComponentes')
    
if 'GestorConfiguracion' in globals() and GestorConfiguracion is not None:
    __all__.append('GestorConfiguracion')
