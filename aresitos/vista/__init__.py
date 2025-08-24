# -*- coding: utf-8 -*-
"""
ARESITOS - Módulo de Vistas
===========================

Módulo que contiene todas las vistas de la interfaz gráfica de ARESITOS.
Implementa el patrón MVC con vistas robustas y manejo de errores específico.

Principios ARESITOS aplicados:
- Importaciones con manejo de errores específico
- Logging integrado para trazabilidad
- Documentación completa
- Arquitectura MVC estricta

Autor: DogSoulDev
Fecha: 24 de Agosto de 2025
"""

import logging

# Configurar logger para el módulo de vistas
logger = logging.getLogger(__name__)

# Importar vistas principales con manejo de errores robusto
vistas_disponibles = []

try:
    from .vista_principal import VistaPrincipal
    vistas_disponibles.append('VistaPrincipal')
    logger.debug("Vista Principal importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaPrincipal: {e}")
    VistaPrincipal = None

try:
    from .vista_login import LoginAresitos
    vistas_disponibles.append('LoginAresitos')
    logger.debug("Vista Login importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar LoginAresitos: {e}")
    LoginAresitos = None

try:
    from .vista_dashboard import VistaDashboard
    vistas_disponibles.append('VistaDashboard')
    logger.debug("Vista Dashboard importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaDashboard: {e}")
    VistaDashboard = None

try:
    from .vista_escaneo import VistaEscaneo
    vistas_disponibles.append('VistaEscaneo')
    logger.debug("Vista Escaneo importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaEscaneo: {e}")
    VistaEscaneo = None

try:
    from .vista_auditoria import VistaAuditoria
    vistas_disponibles.append('VistaAuditoria')
    logger.debug("Vista Auditoria importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaAuditoria: {e}")
    VistaAuditoria = None

try:
    from .vista_siem import VistaSIEM
    vistas_disponibles.append('VistaSIEM')
    logger.debug("Vista SIEM importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaSIEM: {e}")
    VistaSIEM = None

try:
    from .vista_fim import VistaFIM
    vistas_disponibles.append('VistaFIM')
    logger.debug("Vista FIM importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaFIM: {e}")
    VistaFIM = None

try:
    from .vista_reportes import VistaReportes
    vistas_disponibles.append('VistaReportes')
    logger.debug("Vista Reportes importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaReportes: {e}")
    VistaReportes = None

try:
    from .vista_monitoreo import VistaMonitoreo
    vistas_disponibles.append('VistaMonitoreo')
    logger.debug("Vista Monitoreo importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaMonitoreo: {e}")
    VistaMonitoreo = None

try:
    from .vista_herramientas_kali import VistaHerramientasKali
    vistas_disponibles.append('VistaHerramientasKali')
    logger.debug("Vista Herramientas Kali importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaHerramientasKali: {e}")
    VistaHerramientasKali = None

try:
    from .vista_datos import VistaGestionDatos
    vistas_disponibles.append('VistaGestionDatos')
    logger.debug("Vista Gestión Datos importada correctamente")
except ImportError as e:
    logger.warning(f"No se pudo importar VistaGestionDatos: {e}")
    VistaGestionDatos = None

# Registro de vistas disponibles
logger.info(f"Vistas disponibles: {len(vistas_disponibles)} de 11 total")
logger.debug(f"Vistas cargadas: {', '.join(vistas_disponibles)}")

def get_vistas_disponibles():
    """Obtener lista de vistas disponibles."""
    return vistas_disponibles.copy()

def verificar_vista(nombre_vista):
    """Verificar si una vista específica está disponible."""
    return nombre_vista in vistas_disponibles

# Solo exportar las clases que se importaron exitosamente
__all__ = [
    'VistaPrincipal',
    'LoginAresitos',
    'VistaDashboard', 
    'VistaEscaneo',
    'VistaAuditoria',
    'VistaSIEM',
    'VistaFIM',
    'VistaReportes',
    'VistaMonitoreo',
    'VistaHerramientasKali',
    'VistaGestionDatos',
    'get_vistas_disponibles',
    'verificar_vista'
]
