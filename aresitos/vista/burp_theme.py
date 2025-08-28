
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

import tkinter as tk
from tkinter import ttk

class BurpTheme:
    """Clase para manejar el tema visual inspirado en Burp Suite"""
    
    # Colores del tema oscuro (Burp Suite style)
    COLORS = {
        'bg_primary': '#2b2b2b',      # Fondo principal
        'bg_secondary': '#3c3c3c',    # Fondo secundario
        'bg_tertiary': '#4a4a4a',     # Fondo terciario
        'fg_primary': '#ffffff',      # Texto principal
        'fg_secondary': '#cccccc',    # Texto secundario
        'fg_accent': '#ff6633',       # Texto de acento (naranja Burp)
        'border': '#555555',          # Bordes
        'highlight': '#ff6633',       # Resaltado
        'button_bg': '#3c3c3c',       # Fondo de botones
        'button_fg': '#ffffff',       # Texto de botones
        'button_active': '#ff6633',   # Botón activo
        'entry_bg': '#4a4a4a',        # Fondo de campos de texto
        'entry_fg': '#ffffff',        # Texto de campos
        'tab_selected': '#ff6633',    # Pestaña seleccionada
        'tab_normal': '#3c3c3c',      # Pestaña normal
        'scrollbar': '#555555',       # Barra de desplazamiento
        'success': '#5cb85c',         # Verde para éxito
        'warning': '#f0ad4e',         # Amarillo para advertencia
        'danger': '#d9534f',          # Rojo para peligro
        'info': '#5bc0de'             # Azul para información
    }
    
    def __init__(self):
        self.colors = self.COLORS
    
    def get_color(self, key):
        """Obtiene un color del tema"""
        return self.colors.get(key, '#000000')
    
    def configure_ttk_style(self, style):
        """Configura los estilos TTK para que coincidan con el tema Burp Suite"""
        
        # Configurar el estilo del Notebook (pestañas)
        style.theme_use('clam')
        
        # Estilo para el Notebook
        style.configure('Custom.TNotebook', 
                       background=self.get_color('bg_primary'),
                       borderwidth=0)
        
        style.configure('Custom.TNotebook.Tab',
                       background=self.get_color('tab_normal'),
                       foreground=self.get_color('fg_primary'),
                       padding=[20, 10],
                       borderwidth=1,
                       relief='solid')
        
        style.map('Custom.TNotebook.Tab',
                  background=[('selected', self.get_color('tab_selected')),
                             ('active', self.get_color('bg_tertiary'))],
                  foreground=[('selected', '#ffffff')])
        
        # Estilo para botones
        style.configure('Burp.TButton',
                       background=self.get_color('button_bg'),
                       foreground=self.get_color('button_fg'),
                       borderwidth=1,
                       relief='solid',
                       padding=[10, 5])
        
        style.map('Burp.TButton',
                  background=[('active', self.get_color('button_active')),
                             ('pressed', self.get_color('highlight'))])
        
        # Estilo para labels
        style.configure('Burp.TLabel',
                       background=self.get_color('bg_primary'),
                       foreground=self.get_color('fg_primary'))
        
        style.configure('BurpTitle.TLabel',
                       background=self.get_color('bg_primary'),
                       foreground=self.get_color('fg_accent'),
                       font=('Arial', 14, 'bold'))
        
        # Estilo para frames
        style.configure('Burp.TFrame',
                       background=self.get_color('bg_primary'),
                       borderwidth=1,
                       relief='solid')
        
        # Estilo para entry widgets
        style.configure('Burp.TEntry',
                       fieldbackground=self.get_color('entry_bg'),
                       foreground=self.get_color('entry_fg'),
                       borderwidth=1,
                       relief='solid')
        
        # Estilo para labels frames
        style.configure('Burp.TLabelframe',
                       background=self.get_color('bg_primary'),
                       foreground=self.get_color('fg_accent'),
                       borderwidth=1,
                       relief='solid')
        
        style.configure('Burp.TLabelframe.Label',
                       background=self.get_color('bg_primary'),
                       foreground=self.get_color('fg_accent'),
                       font=('Arial', 10, 'bold'))
    
    def configure_text_widget(self, text_widget):
        """Configura un widget Text con el tema Burp Suite"""
        text_widget.configure(
            bg=self.get_color('entry_bg'),
            fg=self.get_color('entry_fg'),
            insertbackground=self.get_color('fg_accent'),
            selectbackground=self.get_color('highlight'),
            selectforeground='#ffffff',
            borderwidth=1,
            relief='solid'
        )

# Instancia global del tema
burp_theme = BurpTheme()
