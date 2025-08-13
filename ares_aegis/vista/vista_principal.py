# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk

# Importar todas las vistas disponibles
from ares_aegis.vista.vista_dashboard import VistaDashboard
from ares_aegis.vista.vista_escaneo import VistaEscaneo
from ares_aegis.vista.vista_monitoreo import VistaMonitoreo
from ares_aegis.vista.vista_utilidades import VistaUtilidades
from ares_aegis.vista.vista_auditoria import VistaAuditoria
from ares_aegis.vista.vista_gestion_datos import VistaGestionDatos
from ares_aegis.vista.vista_herramientas import VistaHerramientas
from ares_aegis.vista.vista_reportes import VistaReportes

try:
    from ares_aegis.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaPrincipal(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        # Solo aplicar tema si está disponible
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.setup_burp_theme(parent)
        else:
            self.theme = None
            
        self.crear_widgets()

    def setup_burp_theme(self, parent):
        """Configura el tema visual de Burp Suite"""
        if not self.theme:
            return
            
        # Configurar el fondo de la ventana principal
        parent.configure(bg=self.theme.get_color('bg_primary'))
        self.configure(bg=self.theme.get_color('bg_primary'))
        
        # Configurar estilos TTK
        self.style = ttk.Style()
        self.theme.configure_ttk_style(self.style)

    def set_controlador(self, controlador):
        self.controlador = controlador
        
        # Configurar controladores para todas las vistas
        if hasattr(self, 'vista_dashboard'):
            self.vista_dashboard.set_controlador(controlador)
        if hasattr(self.controlador, 'controlador_escaneo'):
            self.vista_escaneo.set_controlador(self.controlador.controlador_escaneo)
        if hasattr(self.controlador, 'controlador_monitoreo'):
            self.vista_monitoreo.set_controlador(self.controlador.controlador_monitoreo)
        if hasattr(self.controlador, 'controlador_utilidades'):
            self.vista_utilidades.set_controlador(self.controlador.controlador_utilidades)
        if hasattr(self.controlador, 'controlador_auditoria'):
            self.vista_auditoria.set_controlador(self.controlador.controlador_auditoria)
        if hasattr(self, 'vista_gestion_datos'):
            # Vista unificada para wordlists y diccionarios
            self.vista_gestion_datos.set_controlador(self.controlador)
        if hasattr(self.controlador, 'controlador_herramientas'):
            self.vista_herramientas.set_controlador(self.controlador.controlador_herramientas)
        if hasattr(self.controlador, 'controlador_reportes'):
            self.vista_reportes.set_controlador(self.controlador.controlador_reportes)

    def crear_widgets(self):
        # Barra de título estilo Burp Suite
        self.crear_barra_titulo()
        
        # Notebook principal con tema
        self.crear_notebook_principal()
        
        # Barra de estado
        self.crear_barra_estado()
    
    def crear_barra_titulo(self):
        """Crea la barra de título estilo Burp Suite"""
        if self.theme:
            titulo_frame = tk.Frame(self, bg=self.theme.get_color('bg_secondary'), height=50)
        else:
            titulo_frame = tk.Frame(self, bg='#f0f0f0', height=50)
        titulo_frame.pack(fill="x", padx=2, pady=(2, 0))
        titulo_frame.pack_propagate(False)
        
        # Logo y título
        if self.theme:
            titulo_label = tk.Label(
                titulo_frame,
                text="🛡️ ARESITOS",
                font=("Arial", 16, "bold"),
                fg=self.theme.get_color('fg_accent'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            titulo_label = tk.Label(
                titulo_frame,
                text="🛡️ ARESITOS",
                font=("Arial", 16, "bold"),
                fg='#ff6633',
                bg='#f0f0f0'
            )
        titulo_label.pack(side="left", padx=15, pady=10)
        
        # Subtítulo
        if self.theme:
            subtitulo_label = tk.Label(
                titulo_frame,
                text="Cybersecurity Professional Suite",
                font=("Arial", 9),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            subtitulo_label = tk.Label(
                titulo_frame,
                text="Cybersecurity Professional Suite",
                font=("Arial", 9),
                fg='#666666',
                bg='#f0f0f0'
            )
        subtitulo_label.pack(side="left", padx=(5, 0), pady=10)
        
        # Información del sistema
        if self.theme:
            info_label = tk.Label(
                titulo_frame,
                text="🐧 Kali Linux Ready",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            info_label = tk.Label(
                titulo_frame,
                text="🐧 Kali Linux Ready",
                font=("Arial", 8),
                fg='#666666',
                bg='#f0f0f0'
            )
        info_label.pack(side="right", padx=15, pady=10)
    
    def crear_notebook_principal(self):
        """Crea el notebook principal con estilo Burp Suite"""
        if self.theme:
            self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        else:
            self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=2, pady=2)
        
        # 1. DASHBOARD - Primera pestaña con métricas en tiempo real
        try:
            self.vista_dashboard = VistaDashboard(self.notebook)
            self.notebook.add(self.vista_dashboard, text="🚀 Dashboard")
        except Exception as e:
            print(f"Error creando vista dashboard: {e}")
        
        # 2. ESCANEO Y SIEM - Funcionalidad principal de escaneo
        self.vista_escaneo = VistaEscaneo(self.notebook)
        self.notebook.add(self.vista_escaneo, text="🎯 Escaneo y SIEM")
        
        # 3. MONITOREO Y CUARENTENA - Monitoreo del sistema
        self.vista_monitoreo = VistaMonitoreo(self.notebook)
        self.notebook.add(self.vista_monitoreo, text="📊 Monitoreo y Cuarentena")
        
        # 4. AUDITORÍA - Auditoría de seguridad avanzada
        try:
            self.vista_auditoria = VistaAuditoria(self.notebook)
            self.notebook.add(self.vista_auditoria, text="🔍 Auditoría")
        except Exception as e:
            print(f"Error creando vista auditoría: {e}")
        
        # 5. GESTIÓN DE DATOS - Wordlists y Diccionarios unificados
        try:
            self.vista_gestion_datos = VistaGestionDatos(self.notebook)
            self.notebook.add(self.vista_gestion_datos, text="�️ Gestión de Datos")
        except Exception as e:
            print(f"Error creando vista gestión de datos: {e}")
        
        # 6. HERRAMIENTAS - Herramientas adicionales de seguridad
        try:
            self.vista_herramientas = VistaHerramientas(self.notebook)
            self.notebook.add(self.vista_herramientas, text="🛠️ Herramientas")
        except Exception as e:
            print(f"Error creando vista herramientas: {e}")
        
        # 7. REPORTES - Generación y visualización de reportes
        try:
            self.vista_reportes = VistaReportes(self.notebook)
            self.notebook.add(self.vista_reportes, text="📋 Reportes")
        except Exception as e:
            print(f"Error creando vista reportes: {e}")
        
        # 8. UTILIDADES - Utilidades varias del sistema
        self.vista_utilidades = VistaUtilidades(self.notebook)
        self.notebook.add(self.vista_utilidades, text="⚙️ Utilidades")
    
    def crear_barra_estado(self):
        """Crea la barra de estado inferior estilo Burp"""
        if self.theme:
            status_frame = tk.Frame(self, bg=self.theme.get_color('bg_secondary'), height=25)
        else:
            status_frame = tk.Frame(self, bg='#f0f0f0', height=25)
        status_frame.pack(fill="x", padx=2, pady=(0, 2))
        status_frame.pack_propagate(False)
        
        # Estado de la aplicación
        if self.theme:
            self.status_label = tk.Label(
                status_frame,
                text="🟢 Aresitos Ready - All systems operational",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_primary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            self.status_label = tk.Label(
                status_frame,
                text="🟢 Aresitos Ready - All systems operational",
                font=("Arial", 8),
                fg='#000000',
                bg='#f0f0f0'
            )
        self.status_label.pack(side="left", padx=10, pady=3)
        
        # Información técnica
        if self.theme:
            tech_label = tk.Label(
                status_frame,
                text="Python Native | No External Dependencies",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            tech_label = tk.Label(
                status_frame,
                text="Python Native | No External Dependencies",
                font=("Arial", 8),
                fg='#666666',
                bg='#f0f0f0'
            )
        tech_label.pack(side="right", padx=10, pady=3)
    
    def actualizar_estado(self, mensaje):
        """Actualiza el mensaje de la barra de estado"""
        if hasattr(self, 'status_label'):
            self.status_label.configure(text=mensaje)


# RESUMEN: Vista principal de la aplicación con interfaz de pestañas para módulos.