# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk
import logging
import os
from tkinter import PhotoImage

# Importar todas las vistas disponibles
from aresitos.vista.vista_dashboard import VistaDashboard
from aresitos.vista.vista_escaneo import VistaEscaneo
from aresitos.vista.vista_monitoreo import VistaMonitoreo
from aresitos.vista.vista_auditoria import VistaAuditoria
from aresitos.vista.vista_gestion_datos import VistaGestionDatos
from aresitos.vista.vista_reportes import VistaReportes
from aresitos.vista.vista_fim import VistaFIM
from aresitos.vista.vista_siem import VistaSIEM

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaPrincipal(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
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
        
        # Aplicar estilos específicos para el notebook
        self.style.configure('Custom.TNotebook', 
                           background=self.theme.get_color('bg_primary'),
                           borderwidth=0)
        self.style.configure('Custom.TNotebook.Tab',
                           background=self.theme.get_color('bg_secondary'),
                           foreground=self.theme.get_color('fg_primary'),
                           padding=[20, 8],
                           borderwidth=1)
        self.style.map('Custom.TNotebook.Tab',
                     background=[('selected', self.theme.get_color('fg_accent')),
                               ('active', self.theme.get_color('bg_tertiary'))],
                     foreground=[('selected', self.theme.get_color('bg_primary')),
                               ('active', self.theme.get_color('fg_primary'))])

    def set_controlador(self, controlador):
        self.controlador = controlador
        self.logger.info("Controlador principal establecido en VistaPrincipal")
        
        # Configurar controladores para todas las vistas
        if hasattr(self, 'vista_dashboard'):
            self.vista_dashboard.set_controlador(controlador)
            self.logger.info("✓ Vista Dashboard conectada")
        else:
            self.logger.warning("⚠️ Vista Dashboard no disponible")
            
        if hasattr(self.controlador, 'controlador_escaneador'):
            self.vista_escaneo.set_controlador(self.controlador.controlador_escaneador)
            self.logger.info("✓ Vista Escaneo conectada")
        else:
            self.logger.warning("⚠️ Controlador Escaneador no disponible")
            
        if hasattr(self.controlador, 'controlador_monitoreo'):
            self.vista_monitoreo.set_controlador(self.controlador.controlador_monitoreo)
            self.logger.info("✓ Vista Monitoreo conectada")
        else:
            self.logger.warning("⚠️ Controlador Monitoreo no disponible")
            
        if hasattr(self.controlador, 'controlador_auditoria'):
            self.vista_auditoria.set_controlador(self.controlador.controlador_auditoria)
            self.logger.info("✓ Vista Auditoría conectada")
        else:
            self.logger.warning("⚠️ Controlador Auditoría no disponible")
            
        if hasattr(self, 'vista_gestion_datos'):
            # Vista unificada para wordlists y diccionarios
            self.vista_gestion_datos.set_controlador(self.controlador)
            self.logger.info("✓ Vista Gestión Datos conectada")
        else:
            self.logger.warning("⚠️ Vista Gestión Datos no disponible")
            
        if hasattr(self.controlador, 'controlador_reportes'):
            self.vista_reportes.set_controlador(self.controlador.controlador_reportes)
            self.logger.info("✓ Vista Reportes conectada")
        else:
            self.logger.warning("⚠️ Controlador Reportes no disponible")
        # Conectar FIM y SIEM correctamente
        if hasattr(self.controlador, 'controlador_fim'):
            self.vista_fim.set_controlador(self.controlador.controlador_fim)
            self.logger.info("✓ Vista FIM conectada")
        else:
            self.logger.warning("⚠️ Controlador FIM no disponible")
            
        if hasattr(self.controlador, 'controlador_siem'):
            self.vista_siem.set_controlador(self.controlador.controlador_siem)
            self.logger.info("✓ Vista SIEM conectada")
        else:
            self.logger.warning("⚠️ Controlador SIEM no disponible")
        
        # Inicializar vista con datos del controlador
        self.actualizar_vista_principal()
    
    def obtener_terminal_integrado(self):
        """Obtener referencia al terminal integrado global del dashboard."""
        from aresitos.vista.vista_dashboard import VistaDashboard
        return VistaDashboard.obtener_terminal_global()
    
    def log_actividad(self, mensaje, modulo="GENERAL", nivel="INFO"):
        """Registrar actividad en el terminal integrado global."""
        from aresitos.vista.vista_dashboard import VistaDashboard
        VistaDashboard.log_actividad_global(mensaje, modulo, nivel)

    def crear_widgets(self):
        # Configurar el fondo de este Frame también
        if self.theme:
            self.configure(bg=self.theme.get_color('bg_primary'))
        else:
            self.configure(bg='#2b2b2b')  # Fallback al tema Burp Suite
            
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
            titulo_frame = tk.Frame(self, bg='#3c3c3c', height=50)  # Gris oscuro Burp Suite
        titulo_frame.pack(fill="x", padx=2, pady=(2, 0))
        titulo_frame.pack_propagate(False)
        
        # Logo y título principal con icono
        titulo_main_frame = tk.Frame(titulo_frame, bg=self.theme.get_color('bg_secondary') if self.theme else '#3c3c3c')
        titulo_main_frame.pack(side="left", padx=15, pady=5)
        
        # Título principal
        if self.theme:
            titulo_label = tk.Label(
                titulo_main_frame,
                text="Aresitos",
                font=("Arial", 16, "bold"),
                fg=self.theme.get_color('fg_accent'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            titulo_label = tk.Label(
                titulo_main_frame,
                text="Aresitos",
                font=("Arial", 16, "bold"),
                fg='#ff6633',
                bg='#3c3c3c'
            )
        titulo_label.pack(side="left")
        
        # Subtítulo
        if self.theme:
            subtitulo_label = tk.Label(
                titulo_frame,
                text="Herramienta de Ciberseguridad",
                font=("Arial", 9),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            subtitulo_label = tk.Label(
                titulo_frame,
                text="Herramienta de Ciberseguridad",
                font=("Arial", 9),
                fg='#cccccc',
                bg='#3c3c3c'
            )
        subtitulo_label.pack(side="left", padx=(5, 0), pady=10)
        
        # Información del sistema
        if self.theme:
            info_label = tk.Label(
                titulo_frame,
                text="DogSoulDev crafted in Galicia",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            info_label = tk.Label(
                titulo_frame,
                text="DogSoulDev crafted in Galicia",
                font=("Arial", 8),
                fg='#cccccc',
                bg='#3c3c3c'
            )
        info_label.pack(side="right", padx=15, pady=10)
    
    def crear_notebook_principal(self):
        """Crea el notebook principal con estilo Burp Suite"""
        if self.theme:
            self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        else:
            self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=2, pady=2)
        
        # ORDEN DE PESTAÑAS REQUERIDO:
        # 1. Dashboard, 2. Escaneo, 3. SIEM, 4. FIM, 5. Monitoreo y Cuarentena, 6. Auditoría, 7. Wordlists y Diccionarios, 8. Reportes
        
        # 1. DASHBOARD - Primera pestaña con métricas en tiempo real
        try:
            self.vista_dashboard = VistaDashboard(self.notebook)
            self.notebook.add(self.vista_dashboard, text="Dashboard")
        except Exception as e:
            print(f"Error creando vista dashboard: {e}")
        
        # 2. ESCANEO - Funcionalidad principal de escaneo
        self.vista_escaneo = VistaEscaneo(self.notebook)
        self.notebook.add(self.vista_escaneo, text="Escaneo")
        
        # 3. SIEM - Security Information & Event Management
        try:
            self.vista_siem = VistaSIEM(self.notebook)
            self.notebook.add(self.vista_siem, text="SIEM")
        except Exception as e:
            print(f"Error creando vista SIEM: {e}")
        
        # 4. FIM - File Integrity Monitoring
        try:
            self.vista_fim = VistaFIM(self.notebook)
            self.notebook.add(self.vista_fim, text="FIM")
        except Exception as e:
            print(f"Error creando vista FIM: {e}")
        
        # 5. MONITOREO Y CUARENTENA - Monitoreo del sistema
        self.vista_monitoreo = VistaMonitoreo(self.notebook)
        self.notebook.add(self.vista_monitoreo, text="Monitoreo y Cuarentena")
        
        # 6. AUDITORÍA - Auditoría de seguridad avanzada
        try:
            self.vista_auditoria = VistaAuditoria(self.notebook)
            self.notebook.add(self.vista_auditoria, text="Auditoría")
        except Exception as e:
            print(f"Error creando vista auditoría: {e}")
        
        # 7. WORDLISTS & DICCIONARIOS - Gestión de datos unificados
        try:
            self.vista_gestion_datos = VistaGestionDatos(self.notebook)
            self.notebook.add(self.vista_gestion_datos, text="Wordlists y Diccionarios")
        except Exception as e:
            print(f"Error creando vista gestión de datos: {e}")
        
        # 8. REPORTES - Generación y visualización de reportes
        try:
            self.vista_reportes = VistaReportes(self.notebook)
            self.notebook.add(self.vista_reportes, text="Reportes")
        except Exception as e:
            print(f"Error creando vista reportes: {e}")
    
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
                text="ARESITOS Ready - Todos los sistemas operativos",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_primary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            self.status_label = tk.Label(
                status_frame,
                text="ARESITOS Ready - Todos los sistemas operativos",
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
    
    def actualizar_vista_principal(self):
        """Actualiza la vista principal con datos del controlador"""
        try:
            if self.controlador:
                self.logger.info("Actualizando vista principal con datos del controlador")
                # Actualizar estado general
                self.actualizar_estado("Sistema inicializado - Aresitos")
                
                # Verificar y actualizar sub-vistas que tienen el método actualizar_desde_controlador
                if hasattr(self, 'vista_gestion_datos') and hasattr(self.vista_gestion_datos, 'actualizar_desde_controlador'):
                    self.vista_gestion_datos.actualizar_desde_controlador()
                    
                # Actualizar vista principal después de un breve delay para permitir que los controladores se inicialicen
                self.after(100, self._actualizar_estado_componentes)
            else:
                self.logger.warning("No hay controlador disponible para actualizar vista principal")
                
        except Exception as e:
            self.logger.error(f"Error actualizando vista principal: {e}")
            self.actualizar_estado("Error en inicialización del sistema")
    
    def _actualizar_estado_componentes(self):
        """Método auxiliar para actualizar el estado de los componentes"""
        try:
            # Verificar estado de conexiones y componentes
            if self.controlador and hasattr(self.controlador, 'modelo'):
                estado_sistema = "Sistema operativo - Todos los módulos cargados"
                self.actualizar_estado(estado_sistema)
                self.logger.info("Estado de componentes actualizado correctamente")
        except Exception as e:
            self.logger.error(f"Error actualizando estado de componentes: {e}")
    
    def actualizar_estado(self, mensaje):
        """Actualiza el mensaje de la barra de estado"""
        if hasattr(self, 'status_label'):
            self.status_label.configure(text=mensaje)


# RESUMEN: Vista principal de la aplicación con interfaz de pestañas para módulos.
