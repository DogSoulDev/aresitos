
# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
"""

# Importar clases principales reales (sin mocks)
from .modelo_escaneador import EscaneadorKali2025
from .modelo_siem import SIEMKali2025
from .modelo_fim import FIMKali2025
from .modelo_cuarentena import CuarentenaKali2025
from .modelo_dashboard import ModeloDashboard
from .modelo_diccionarios import ModeloGestorDiccionarios
from .modelo_monitor import MonitorAvanzadoNativo
from .modelo_principal import ModeloPrincipal
from .modelo_reportes import ModeloReportes
from .modelo_sistema import ModeloUtilidadesSistema
from .modelo_wordlists import ConstructorWordlists
from .modelo_wordlists_gestor import ModeloGestorWordlists

# Importar clases base
from .modelo_escaneador_base import EscaneadorBase
from .modelo_fim_base import FIMBase
from .modelo_siem_base import SIEMBase

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
    'SIEMBase'
]

__version__ = "3.0.0"
