# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk
import logging

from aresitos.vista.vista_herramientas import VistaHerramientas
from aresitos.vista.vista_auditoria import VistaAuditoria
from aresitos.vista.vista_reportes import VistaReportes
from aresitos.vista.vista_gestion_datos import VistaGestionDatos

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaUtilidades(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
            # Configurar estilos TTK
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
        else:
            self.theme = None
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
        self.logger.info("Controlador establecido en VistaUtilidades")
        
        if hasattr(self, 'vista_herramientas'):
            self.vista_herramientas.set_controlador(controlador)
        if hasattr(self, 'vista_auditoria'):
            self.vista_auditoria.set_controlador(controlador)
        if hasattr(self, 'vista_reportes'):
            self.vista_reportes.set_controlador(controlador)
        if hasattr(self, 'vista_gestion_datos'):
            self.vista_gestion_datos.set_controlador(controlador)
    
    def crear_interfaz(self):
        if self.theme:
            titulo_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            titulo_frame = tk.Frame(self)
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo = tk.Label(titulo_frame, text="Utilidades del Sistema",
                         font=('Arial', 18, 'bold'),
                         bg='#2b2b2b' if self.theme else 'white',
                         fg='#ff6633' if self.theme else 'black')
        titulo.pack()
        
        if self.theme:
            self.notebook = ttk.Notebook(self)
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('TNotebook', background='#2b2b2b', borderwidth=0)
            style.configure('TNotebook.Tab', 
                          background='#404040', 
                          foreground='white',
                          padding=[12, 8],
                          focuscolor='none')
            style.map('TNotebook.Tab',
                     background=[('selected', '#ff6633'), ('active', '#555555')],
                     foreground=[('selected', 'white'), ('active', 'white')])
        else:
            self.notebook = ttk.Notebook(self)
        
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.crear_pestanas()
    
    def crear_pestanas(self):
        self.vista_herramientas = VistaHerramientas(self.notebook)
        self.notebook.add(self.vista_herramientas, text=" Herramientas")
        
        self.vista_auditoria = VistaAuditoria(self.notebook)
        self.notebook.add(self.vista_auditoria, text=" Auditoria")
        
        self.vista_reportes = VistaReportes(self.notebook)
        self.notebook.add(self.vista_reportes, text=" Reportes")
        
        self.vista_gestion_datos = VistaGestionDatos(self.notebook)
        self.notebook.add(self.vista_gestion_datos, text=" Gestión de Datos")
    
    def actualizar_vista(self):
        """Actualizar todas las vistas con datos del controlador"""
        if not self.controlador:
            self.logger.warning("No hay controlador configurado para actualizar vista")
            return
        
        try:
            # Actualizar estado de herramientas si el controlador lo soporta
            if hasattr(self.controlador, 'obtener_estado_herramientas'):
                estado = self.controlador.obtener_estado_herramientas()
                self.logger.info(f"Estado de herramientas actualizado: {estado}")
            
            # Notificar a las vistas hijas
            if hasattr(self, 'vista_herramientas') and hasattr(self.vista_herramientas, 'actualizar_vista'):
                self.vista_herramientas.actualizar_vista()
            
            # Verificar disponibilidad de vista de auditoría (funcionalidad futura)
            if hasattr(self, 'vista_auditoria'):
                self.logger.debug("Vista de auditoría disponible para futuras actualizaciones")
                
        except Exception as e:
            self.logger.error(f"Error actualizando vista de utilidades: {e}")
    
    def verificar_estado_sistema(self):
        """Verificar estado general del sistema a través del controlador"""
        if not self.controlador:
            self.logger.warning("No hay controlador para verificar estado del sistema")
            return
        
        try:
            if hasattr(self.controlador, 'verificar_estado_sistema'):
                estado = self.controlador.verificar_estado_sistema()
                self.logger.info(f"Estado del sistema verificado: {estado}")
                return estado
            else:
                self.logger.warning("Controlador no soporta verificación de estado")
                
        except Exception as e:
            self.logger.error(f"Error verificando estado del sistema: {e}")
            return None
        self.notebook.add(self.vista_gestion_datos, text=" Gestión de Datos")
        
        if self.controlador:
            self.set_controlador(self.controlador)
