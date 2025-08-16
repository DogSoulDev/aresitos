# -*- coding: utf-8 -*-
"""
Ares Aegis - Temas Visuales para Kali Linux
===========================================

Configuración de temas consistentes con el entorno de Kali Linux.
Tema principal: Burp Suite Dark Theme para mantener consistencia
con herramientas de pentesting profesionales.

Autor: DogSoulDev  
Fecha: 15 de Agosto de 2025
Versión: 1.0
"""

import tkinter as tk
from typing import Dict, Any

class TemaKaliDark:
    """
    Tema Burp Suite Dark optimizado para Kali Linux.
    Mantiene consistencia visual con herramientas de pentesting.
    """
    
    # Paleta de colores base Burp Suite Dark
    COLORES = {
        # Colores de fondo principales
        'bg_principal': '#2B2B2B',           # Fondo principal dark
        'bg_secundario': '#3C3C3C',         # Fondo paneles secundarios
        'bg_panel': '#4D4D4D',              # Fondo de paneles/tarjetas
        'bg_input': '#404040',              # Fondo campos de entrada
        'bg_seleccion': '#FF6600',          # Naranja Burp Suite para selecciones
        
        # Colores de texto
        'texto_principal': '#F5F5F5',       # Texto principal blanco/gris claro
        'texto_secundario': '#CCCCCC',      # Texto secundario gris medio
        'texto_deshabilitado': '#808080',   # Texto deshabilitado gris oscuro
        'texto_error': '#FF4444',           # Texto de error rojo
        'texto_exito': '#44FF44',           # Texto de éxito verde
        'texto_advertencia': '#FFBB33',     # Texto de advertencia amarillo
        
        # Colores de bordes y separadores
        'borde_principal': '#666666',       # Bordes principales
        'borde_focus': '#FF6600',           # Borde cuando tiene foco (naranja Burp)
        'separador': '#555555',             # Líneas separadoras
        
        # Colores de botones
        'btn_normal': '#FF6600',            # Botón normal naranja Burp
        'btn_hover': '#FF8533',             # Botón hover naranja más claro
        'btn_pressed': '#CC5200',           # Botón presionado naranja más oscuro
        'btn_disabled': '#666666',          # Botón deshabilitado
        
        # Botones secundarios
        'btn_secundario': '#4D4D4D',        # Botón secundario gris
        'btn_secundario_hover': '#666666',  # Hover gris más claro
        
        # Colores específicos de seguridad
        'critico': '#FF0000',               # Rojo para alertas críticas
        'alto': '#FF6600',                  # Naranja para alertas altas
        'medio': '#FFBB33',                 # Amarillo para alertas medias
        'bajo': '#44FF44',                  # Verde para alertas bajas
        'info': '#3399FF',                  # Azul para información
        
        # Colores de estado
        'activo': '#44FF44',                # Verde para estado activo
        'inactivo': '#808080',              # Gris para estado inactivo
        'error': '#FF4444',                 # Rojo para errores
        'procesando': '#FFBB33'             # Amarillo para procesando
    }
    
    # Configuración de fuentes
    FUENTES = {
        'principal': ('Consolas', 10, 'normal'),        # Fuente monoespaciada para código
        'titulo': ('Segoe UI', 12, 'bold'),             # Títulos
        'subtitulo': ('Segoe UI', 10, 'bold'),          # Subtítulos
        'texto': ('Segoe UI', 9, 'normal'),             # Texto normal
        'codigo': ('Consolas', 9, 'normal'),            # Código y logs
        'pequeno': ('Segoe UI', 8, 'normal')            # Texto pequeño
    }
    
    # Configuración de widgets específicos
    WIDGETS = {
        'frame': {
            'bg': COLORES['bg_principal'],
            'relief': 'flat'
        },
        'panel': {
            'bg': COLORES['bg_panel'],
            'relief': 'raised',
            'bd': 1,
            'highlightthickness': 1,
            'highlightcolor': COLORES['borde_principal']
        },
        'label': {
            'bg': COLORES['bg_principal'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['texto']
        },
        'entry': {
            'bg': COLORES['bg_input'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['codigo'],
            'relief': 'flat',
            'bd': 2,
            'highlightthickness': 2,
            'highlightcolor': COLORES['borde_focus'],
            'selectbackground': COLORES['bg_seleccion'],
            'selectforeground': COLORES['texto_principal']
        },
        'text': {
            'bg': COLORES['bg_input'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['codigo'],
            'relief': 'flat',
            'bd': 2,
            'highlightthickness': 2,
            'highlightcolor': COLORES['borde_focus'],
            'selectbackground': COLORES['bg_seleccion'],
            'selectforeground': COLORES['texto_principal'],
            'insertbackground': COLORES['texto_principal']
        },
        'button': {
            'bg': COLORES['btn_normal'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['texto'],
            'relief': 'flat',
            'bd': 0,
            'highlightthickness': 0,
            'activebackground': COLORES['btn_hover'],
            'activeforeground': COLORES['texto_principal']
        },
        'button_secundario': {
            'bg': COLORES['btn_secundario'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['texto'],
            'relief': 'flat',
            'bd': 0,
            'highlightthickness': 0,
            'activebackground': COLORES['btn_secundario_hover'],
            'activeforeground': COLORES['texto_principal']
        },
        'listbox': {
            'bg': COLORES['bg_input'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['codigo'],
            'relief': 'flat',
            'bd': 2,
            'highlightthickness': 2,
            'highlightcolor': COLORES['borde_focus'],
            'selectbackground': COLORES['bg_seleccion'],
            'selectforeground': COLORES['texto_principal']
        },
        'scrollbar': {
            'bg': COLORES['bg_secundario'],
            'troughcolor': COLORES['bg_principal'],
            'activebackground': COLORES['btn_hover'],
            'highlightthickness': 0
        },
        'menubar': {
            'bg': COLORES['bg_principal'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['texto'],
            'relief': 'flat',
            'bd': 0,
            'activebackground': COLORES['btn_hover'],
            'activeforeground': COLORES['texto_principal']
        },
        'menu': {
            'bg': COLORES['bg_panel'],
            'fg': COLORES['texto_principal'],
            'font': FUENTES['texto'],
            'relief': 'flat',
            'bd': 1,
            'activebackground': COLORES['btn_hover'],
            'activeforeground': COLORES['texto_principal']
        }
    }

def aplicar_tema_burp_suite(widget, tipo_widget='frame'):
    """
    Aplica el tema Burp Suite Dark a un widget específico.
    
    Args:
        widget: Widget de tkinter a tematizar
        tipo_widget: Tipo de widget ('frame', 'button', 'entry', etc.)
    """
    try:
        if tipo_widget in TemaKaliDark.WIDGETS:
            config = TemaKaliDark.WIDGETS[tipo_widget]
            widget.configure(**config)
            
            # Configurar cursor para botones
            if tipo_widget.startswith('button'):
                widget.configure(cursor='hand2')
                
                # Eventos hover para botones
                def on_enter(event):
                    event.widget.configure(bg=TemaKaliDark.COLORES['btn_hover'])
                
                def on_leave(event):
                    bg_color = TemaKaliDark.COLORES['btn_normal'] if tipo_widget == 'button' else TemaKaliDark.COLORES['btn_secundario']
                    event.widget.configure(bg=bg_color)
                
                widget.bind("<Enter>", on_enter)
                widget.bind("<Leave>", on_leave)
        
    except Exception as e:
        print(f"Error aplicando tema a {tipo_widget}: {e}")

def configurar_ventana_principal(ventana):
    """
    Configura una ventana principal con el tema Burp Suite Dark.
    
    Args:
        ventana: Ventana principal de tkinter
    """
    try:
        # Configurar ventana
        ventana.configure(bg=TemaKaliDark.COLORES['bg_principal'])
        
        # Configurar título y icono
        ventana.title("Ares Aegis - Kali Linux Security Scanner")
        
        # Intentar configurar icono si existe
        try:
            ventana.iconbitmap("aresitos/recursos/Aresitos.ico")
        except:
            pass  # Ignorar si no existe el icono
        
        return True
        
    except Exception as e:
        print(f"Error configurando ventana principal: {e}")
        return False

def crear_panel_con_tema(parent, titulo="", tipo='panel'):
    """
    Crea un panel con tema Burp Suite aplicado.
    
    Args:
        parent: Widget padre
        titulo: Título del panel (opcional)
        tipo: Tipo de panel ('panel', 'group', 'card')
    
    Returns:
        Frame configurado con tema
    """
    try:
        # Crear frame principal
        frame = tk.Frame(parent)
        aplicar_tema_burp_suite(frame, 'panel')
        
        # Añadir título si se especifica
        if titulo:
            titulo_label = tk.Label(frame, text=titulo)
            aplicar_tema_burp_suite(titulo_label, 'label')
            titulo_label.configure(font=TemaKaliDark.FUENTES['subtitulo'])
            titulo_label.pack(anchor='nw', padx=10, pady=(10, 5))
        
        return frame
        
    except Exception as e:
        print(f"Error creando panel con tema: {e}")
        return tk.Frame(parent)  # Fallback

def crear_boton_tema(parent, texto, comando=None, tipo='normal'):
    """
    Crea un botón con tema Burp Suite aplicado.
    
    Args:
        parent: Widget padre
        texto: Texto del botón
        comando: Función a ejecutar al hacer clic
        tipo: Tipo de botón ('normal', 'secundario', 'critico', 'exito')
    
    Returns:
        Button configurado con tema
    """
    try:
        # Crear botón con comando solo si se proporciona
        if comando is not None:
            button = tk.Button(parent, text=texto, command=comando)
        else:
            button = tk.Button(parent, text=texto)
        
        # Aplicar tema según tipo
        if tipo == 'secundario':
            aplicar_tema_burp_suite(button, 'button_secundario')
        elif tipo == 'critico':
            aplicar_tema_burp_suite(button, 'button')
            button.configure(bg=TemaKaliDark.COLORES['critico'])
        elif tipo == 'exito':
            aplicar_tema_burp_suite(button, 'button')
            button.configure(bg=TemaKaliDark.COLORES['activo'])
        else:
            aplicar_tema_burp_suite(button, 'button')
        
        # Padding interno
        button.configure(padx=15, pady=8)
        
        return button
        
    except Exception as e:
        print(f"Error creando botón con tema: {e}")
        # Fallback seguro
        if comando is not None:
            return tk.Button(parent, text=texto, command=comando)
        else:
            return tk.Button(parent, text=texto)

def crear_entrada_tema(parent, placeholder="", tipo='normal'):
    """
    Crea un campo de entrada con tema Burp Suite aplicado.
    
    Args:
        parent: Widget padre
        placeholder: Texto placeholder
        tipo: Tipo de entrada ('normal', 'password', 'search')
    
    Returns:
        Entry configurado con tema
    """
    try:
        entry = tk.Entry(parent)
        aplicar_tema_burp_suite(entry, 'entry')
        
        # Configurar placeholder si se especifica
        if placeholder:
            entry.insert(0, placeholder)
            entry.configure(fg=TemaKaliDark.COLORES['texto_secundario'])
            
            def on_focus_in(event):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.configure(fg=TemaKaliDark.COLORES['texto_principal'])
            
            def on_focus_out(event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.configure(fg=TemaKaliDark.COLORES['texto_secundario'])
            
            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
        
        # Configurar como password si es necesario
        if tipo == 'password':
            entry.configure(show='*')
        
        return entry
        
    except Exception as e:
        print(f"Error creando entrada con tema: {e}")
        return tk.Entry(parent)

def crear_texto_con_tema(parent, altura=10, ancho=50, solo_lectura=False):
    """
    Crea un widget Text con tema Burp Suite aplicado.
    
    Args:
        parent: Widget padre
        altura: Altura en líneas
        ancho: Ancho en caracteres
        solo_lectura: Si es de solo lectura
    
    Returns:
        Text configurado con tema
    """
    try:
        # Crear frame contenedor con scrollbar
        frame = tk.Frame(parent)
        aplicar_tema_burp_suite(frame, 'frame')
        
        # Crear widget Text
        texto = tk.Text(frame, height=altura, width=ancho)
        aplicar_tema_burp_suite(texto, 'text')
        
        # Crear scrollbar
        scrollbar = tk.Scrollbar(frame, command=texto.yview)
        aplicar_tema_burp_suite(scrollbar, 'scrollbar')
        
        # Conectar scrollbar con texto
        texto.configure(yscrollcommand=scrollbar.set)
        
        # Layout
        texto.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configurar como solo lectura si es necesario
        if solo_lectura:
            texto.configure(state='disabled')
        
        return frame, texto
        
    except Exception as e:
        print(f"Error creando texto con tema: {e}")
        return tk.Frame(parent), tk.Text(parent)

def obtener_color_por_severidad(severidad):
    """
    Obtiene el color correspondiente a un nivel de severidad.
    
    Args:
        severidad: Nivel de severidad ('critico', 'alto', 'medio', 'bajo', 'info')
    
    Returns:
        Color hexadecimal
    """
    severidad = severidad.lower()
    
    colores_severidad = {
        'critico': TemaKaliDark.COLORES['critico'],
        'alto': TemaKaliDark.COLORES['alto'],
        'medio': TemaKaliDark.COLORES['medio'],
        'bajo': TemaKaliDark.COLORES['bajo'],
        'info': TemaKaliDark.COLORES['info']
    }
    
    return colores_severidad.get(severidad, TemaKaliDark.COLORES['texto_principal'])

def configurar_tema_global():
    """
    Configura opciones globales del tema para toda la aplicación.
    """
    try:
        # La configuración global se aplicará cuando se cree la ventana principal
        # Esta función existe para compatibilidad futura
        return True
        
    except Exception as e:
        print(f"Error configurando tema global: {e}")
        return False

# Configuración automática (comentada para evitar errores)
# configurar_tema_global()

# RESUMEN TÉCNICO: Sistema de temas Burp Suite Dark para Ares Aegis.
# Implementa paleta de colores consistente con herramientas de pentesting profesionales,
# funciones helper para crear widgets tematizados, y configuración global automática.
# Mantiene estándares visuales de Kali Linux mientras proporciona interfaz moderna y profesional.
