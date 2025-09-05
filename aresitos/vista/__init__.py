
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
from .vista_herramientas_kali import VistaHerramientasKali
from .vista_datos import VistaGestionDatos
from .vista_mantenimiento import VistaMantenimiento

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
    'VistaMantenimiento'
]
