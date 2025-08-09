# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk
from ares_aegis.vista.vista_escaneo import VistaEscaneo
from ares_aegis.vista.vista_monitoreo import VistaMonitoreo
from ares_aegis.vista.vista_utilidades import VistaUtilidades

class VistaPrincipal(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.crear_widgets()

    def set_controlador(self, controlador):
        self.controlador = controlador
        if hasattr(self.controlador, 'controlador_escaneo'):
            self.vista_escaneo.set_controlador(self.controlador.controlador_escaneo)
        if hasattr(self.controlador, 'controlador_monitoreo'):
            self.vista_monitoreo.set_controlador(self.controlador.controlador_monitoreo)
        if hasattr(self.controlador, 'controlador_utilidades'):
            self.vista_utilidades.set_controlador(self.controlador.controlador_utilidades)

    def crear_widgets(self):
        label_titulo = ttk.Label(self, text="Aresitos", font=("Arial", 16, "bold"))
        label_titulo.pack(pady=10)
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.vista_escaneo = VistaEscaneo(self.notebook)
        self.notebook.add(self.vista_escaneo, text="Escaneo y SIEM")
        
        self.vista_monitoreo = VistaMonitoreo(self.notebook)
        self.notebook.add(self.vista_monitoreo, text="Monitoreo y Cuarentena")
        
        self.vista_utilidades = VistaUtilidades(self.notebook)
        self.notebook.add(self.vista_utilidades, text="Utilidades y Reportes")


# RESUMEN: Vista principal de la aplicación con interfaz de pestañas para módulos.