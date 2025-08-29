
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
# -*- coding: utf-8 -*-
import logging
import tkinter as tk
from tkinter import scrolledtext
import datetime
import gc  # Issue 21/24 - Optimización de memoria

class TerminalMixin:
    """Mixin para agregar funcionalidad de terminal a las vistas."""
    
    def get_colors(self):
        """Obtener colores de la vista actual o usar valores por defecto."""
        # Intentar obtener colores de la vista que usa el mixin
        try:
            if hasattr(self, 'colors') and isinstance(getattr(self, 'colors'), dict):
                return getattr(self, 'colors')
        except (ValueError, TypeError, OSError) as e:
            logging.debug(f'Error en excepción: {e}')
            pass
        
        # Colores por defecto del tema Burp Suite
        return {
            'bg_primary': '#2b2b2b',
            'bg_secondary': '#1e1e1e', 
            'fg_primary': '#ffffff',
            'fg_accent': '#ff6633',
            'success': '#00ff88',
            'warning': '#ffcc00',
            'danger': '#ff4444',
            'info': '#44aaff'
        }
    
    def crear_terminal_integrado(self, parent_frame, titulo_vista="ARESITOS"):
        """Crear terminal integrado en cualquier vista."""
        colors = self.get_colors()
        
        # Título del terminal
        titulo_terminal = tk.Label(parent_frame, 
                                 text=f"Terminal ARESITOS - {titulo_vista}", 
                                 bg=colors['bg_secondary'], 
                                 fg=colors['fg_accent'],
                                 font=('Arial', 11, 'bold'))
        titulo_terminal.pack(anchor="w", padx=5, pady=(5, 0))
        
        # Frame para el terminal
        terminal_content = tk.Frame(parent_frame, bg=colors['bg_secondary'])
        terminal_content.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Crear siempre un terminal local funcional
        self.mini_terminal = scrolledtext.ScrolledText(terminal_content,
                                                     height=8,
                                                     bg='#000000',
                                                     fg='#00ff00',
                                                     font=("Consolas", 9),
                                                     insertbackground='#00ff00',
                                                     state='normal')
        self.mini_terminal.pack(fill="both", expand=True)
        
        # Mensaje inicial
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.mini_terminal.insert(tk.END, f"=== Terminal {titulo_vista} ===\n")
        self.mini_terminal.insert(tk.END, f"Iniciado: {timestamp}\n")
        self.mini_terminal.insert(tk.END, f"Vista: {titulo_vista}\n")
        self.mini_terminal.insert(tk.END, f"Sistema: ARESITOS v2.0 - Kali Linux\n\n")
        self.mini_terminal.see(tk.END)
    
    def crear_terminal_local(self, parent_frame, titulo_vista="ARESITOS"):
        """Crear terminal local si no hay terminal global disponible."""
        self.mini_terminal = scrolledtext.ScrolledText(parent_frame,
                                                     height=8,
                                                     bg='#000000',
                                                     fg='#00ff00',
                                                     font=("Consolas", 9),
                                                     insertbackground='#00ff00',
                                                     state='normal')
        self.mini_terminal.pack(fill="both", expand=True)
        
        # Mensaje inicial
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.mini_terminal.insert(tk.END, f"=== Terminal {titulo_vista} Local ===\n")
        self.mini_terminal.insert(tk.END, f"Iniciado: {timestamp}\n")
        self.mini_terminal.insert(tk.END, f"Vista: {titulo_vista}\n\n")
        self.mini_terminal.see(tk.END)
    
    def log_to_terminal(self, mensaje):
        """Enviar mensaje al terminal integrado."""
        try:
            if hasattr(self, 'mini_terminal') and self.mini_terminal:
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                mensaje_completo = f"[{timestamp}] {mensaje}\n"
                
                # Insertar en el terminal local
                self.mini_terminal.insert(tk.END, mensaje_completo)
                self.mini_terminal.see(tk.END)
                
                # También intentar enviar al terminal global si existe
                try:
                    vista_principal = getattr(self, 'vista_principal', None)
                    if vista_principal and hasattr(vista_principal, 'terminal_widget'):
                        terminal_global = vista_principal.terminal_widget
                        if terminal_global:
                            terminal_global.config(state='normal')
                            vista_name = self.__class__.__name__.replace('Vista', '').upper()
                            terminal_global.insert(tk.END, f"[{vista_name}] {mensaje_completo}")
                            terminal_global.see(tk.END)
                            terminal_global.config(state='disabled')
                except (ValueError, TypeError, OSError) as e:
                    logging.debug(f'Error en excepción: {e}')
                    pass  # Si falla el terminal global, continuar con el local
        except (ValueError, TypeError, OSError) as e:
            logging.debug(f'Error en excepción: {e}')
            pass  # Si no hay terminal, ignorar silenciosamente
    
    def agregar_paned_window_con_terminal(self, parent_frame, titulo_vista="ARESITOS"):
        """
        Agregar PanedWindow con terminal a cualquier vista.
        Retorna el frame de contenido donde se debe agregar el contenido principal.
        """
        colors = self.get_colors()
        
        # Crear PanedWindow para dividir contenido principal y terminal
        paned_window = tk.PanedWindow(parent_frame, orient=tk.VERTICAL, 
                                     bg=colors['bg_primary'], 
                                     sashrelief=tk.RAISED,
                                     sashwidth=3)
        paned_window.pack(fill="both", expand=True)
        
        # Frame superior para el contenido principal
        contenido_frame = tk.Frame(paned_window, bg=colors['bg_primary'])
        paned_window.add(contenido_frame, minsize=300)
        
        # Frame inferior para el terminal integrado
        terminal_frame = tk.Frame(paned_window, bg=colors['bg_secondary'])
        paned_window.add(terminal_frame, minsize=150)
        
        # Crear terminal integrado
        self.crear_terminal_integrado(terminal_frame, titulo_vista)
        
        # Configurar posición inicial del sash
        paned_window.update_idletasks()
        try:
            paned_window.sash_place(0, 400, 0)  # Posición inicial del divisor
        except (ValueError, TypeError, OSError) as e:
            logging.debug(f'Error en excepción: {e}')
            pass  # Si falla, usar posición por defecto
        
        return contenido_frame
    
    def optimizar_terminal_memoria(self):
        """Optimizar memoria del terminal - Issue 21/24"""
        """Limpiar buffer del terminal cuando excede límites y optimizar memoria"""
        try:
            # Buscar el terminal en diferentes atributos posibles
            terminal = None
            for attr_name in ['text_terminal', 'terminal_text', 'text_siem', 'text_monitor', 'text_fim']:
                if hasattr(self, attr_name):
                    terminal = getattr(self, attr_name)
                    break
            
            if terminal and hasattr(terminal, 'get'):
                # Obtener contenido actual
                contenido = terminal.get(1.0, tk.END)
                lineas = contenido.split('\n')
                
                # Si hay más de 1000 líneas, mantener solo las últimas 500
                if len(lineas) > 1000:
                    lineas_recientes = lineas[-500:]
                    nuevo_contenido = '\n'.join(lineas_recientes)
                    
                    # Limpiar y actualizar terminal
                    terminal.delete(1.0, tk.END)
                    terminal.insert(1.0, nuevo_contenido)
                    terminal.see(tk.END)
                    
                    # Forzar garbage collection
                    del contenido, lineas, lineas_recientes
                    gc.collect()
                    
                    # Log de optimización
                    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                    terminal.insert(tk.END, f"\n[{timestamp}] MEMORIA: Buffer optimizado - líneas reducidas\n")
                    terminal.see(tk.END)
                    
        except Exception as e:
            # Silencioso para no interrumpir operación
            pass
