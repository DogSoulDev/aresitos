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
    
    def crear_terminal_inferior(self, parent_frame, titulo_vista="ARESITOS", comando_callback=None, altura_terminal=12):
        """
        Crear terminal y campo de comando en la parte inferior de la vista, con label 'COMANDO:' y altura configurable.
        - parent_frame: Frame principal de la vista.
        - titulo_vista: Nombre de la vista para mostrar en el terminal.
        - comando_callback: función a ejecutar cuando se envía un comando.
        - altura_terminal: altura del área de terminal (default 12).
        """
        colors = self.get_colors()
        # Frame inferior para terminal y comando
        frame_inferior = tk.Frame(parent_frame, bg=colors['bg_secondary'])
        frame_inferior.pack(side="bottom", fill="x", padx=0, pady=0)
        # Título del terminal
        titulo_terminal = tk.Label(frame_inferior,
                                   text=f"Terminal ARESITOS - {titulo_vista}",
                                   bg=colors['bg_secondary'],
                                   fg=colors['fg_accent'],
                                   font=('Arial', 11, 'bold'))
        titulo_terminal.pack(anchor="w", padx=8, pady=(6, 0))
        # Terminal scrolledtext
        self.mini_terminal = scrolledtext.ScrolledText(frame_inferior,
                                                       height=altura_terminal,
                                                       bg='#000000',
                                                       fg='#00ff00',
                                                       font=("Consolas", 10),
                                                       insertbackground='#00ff00',
                                                       state='normal')
        self.mini_terminal.pack(fill="x", expand=False, padx=8, pady=(0, 4))
        # Mensaje inicial
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.mini_terminal.insert(tk.END, f"=== Terminal {titulo_vista} ===\n")
        self.mini_terminal.insert(tk.END, f"Iniciado: {timestamp}\n")
        self.mini_terminal.insert(tk.END, f"Vista: {titulo_vista}\n")
        self.mini_terminal.insert(tk.END, f"Sistema: ARESITOS v2.0 - Kali Linux\n\n")
        self.mini_terminal.see(tk.END)
        # Campo de entrada de comando con label
        comando_frame = tk.Frame(frame_inferior, bg=colors['bg_secondary'])
        comando_frame.pack(fill="x", padx=8, pady=(0, 8))
        label_comando = tk.Label(comando_frame,
                                 text="COMANDO:",
                                 bg=colors['bg_secondary'],
                                 fg='#00ff00',
                                 font=("Arial", 9, "bold"))
        label_comando.pack(side="left", padx=(0, 5))
        self.comando_entry = tk.Entry(comando_frame,
                                      font=("Consolas", 10),
                                      bg='#222222',
                                      fg='#00ff00',
                                      insertbackground='#00ff00',
                                      relief=tk.FLAT)
        self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.comando_entry.bind("<Return>", lambda event: self._ejecutar_comando_terminal(comando_callback))
        # Botón ejecutar unificado
        btn_ejecutar = tk.Button(comando_frame,
                                 text="EJECUTAR",
                                 font=("Arial", 10, "bold"),
                                 bg=colors['button_bg'] if 'button_bg' in colors else '#ffb86c',
                                 fg=colors['button_fg'] if 'button_fg' in colors else '#232629',
                                 command=lambda: self._ejecutar_comando_terminal(comando_callback))
        btn_ejecutar.pack(side="right", padx=(8, 0))
    def _ejecutar_comando_terminal(self, comando_callback):
        """Ejecuta el comando ingresado y lo muestra en el terminal."""
        comando = self.comando_entry.get()
        if comando:
            self.mini_terminal.insert(tk.END, f"$ {comando}\n")
            self.mini_terminal.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            if comando_callback:
                comando_callback(comando)
    
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
    
    # Método deprecated: usar crear_terminal_inferior directamente en el frame deseado
    
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
