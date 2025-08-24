# -*- coding: utf-8 -*-
"""
ARESITOS - Módulo de Vistas
===========================

Módulo que contiene todas las vistas de la interfaz gráfica de ARESITOS.

Autor: DogSoulDev
"""

# Importar vistas principales
from .vista_principal import VistaPrincipal
from .vista_login import LoginAresitos
from .vista_dashboard import VistaDashboard
from .vista_escaneo import VistaEscaneo
from .vista_auditoria import VistaAuditoria
from .vista_siem import VistaSIEM
from .vista_fim import VistaFIM
from .vista_reportes import VistaReportes
from .vista_monitoreo import VistaMonitoreo
from .vista_herramientas import VistaHerramientasKali
from .vista_datos import VistaGestionDatos

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
    'VistaGestionDatos'
]
