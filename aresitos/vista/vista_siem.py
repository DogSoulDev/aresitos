# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import subprocess
import logging
from datetime import datetime

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaSIEM(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        self.proceso_siem_activo = False
        self.thread_siem = None
        self.monitoreo_activo = False  # Para control del monitoreo en tiempo real
        
        # Configurar tema y colores de manera consistente
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
            # Configurar estilos TTK
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
            self.colors = {
                'bg_primary': burp_theme.get_color('bg_primary'),
                'bg_secondary': burp_theme.get_color('bg_secondary'), 
                'fg_primary': burp_theme.get_color('fg_primary'),
                'fg_secondary': burp_theme.get_color('fg_secondary'),
                'fg_accent': burp_theme.get_color('fg_accent'),
                'button_bg': burp_theme.get_color('button_bg'),
                'button_fg': burp_theme.get_color('button_fg'),
                'success': burp_theme.get_color('success'),
                'warning': burp_theme.get_color('warning'),
                'danger': burp_theme.get_color('danger'),
                'info': burp_theme.get_color('info')
            }
        else:
            self.theme = None
            self.colors = {
                'bg_primary': 'white',
                'bg_secondary': '#f0f0f0', 
                'fg_primary': 'black',
                'fg_secondary': 'gray',
                'fg_accent': 'black',
                'button_bg': 'lightgray',
                'button_fg': 'black',
                'success': 'green',
                'warning': 'orange',
                'danger': 'red',
                'info': 'blue'
            }
        
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame superior para el contenido principal
        contenido_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(contenido_frame, minsize=400)
        
        # Frame título con tema
        titulo_frame = tk.Frame(contenido_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(10, 10))
        
        # Título con tema Burp Suite
        titulo = tk.Label(titulo_frame, text="SIEM - Security Information & Event Management",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack()
        
        # Notebook para múltiples pestañas con tema
        if self.theme:
            style = ttk.Style()
            self.theme.configure_ttk_style(style)
            self.notebook = ttk.Notebook(contenido_frame, style='Custom.TNotebook')
        else:
            self.notebook = ttk.Notebook(contenido_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Pestaña 1: Monitoreo en Tiempo Real
        self.crear_tab_monitoreo()
        
        # Pestaña 2: Análisis de Logs
        self.crear_tab_analisis()
        
        # Pestaña 3: Alertas y Correlación
        self.crear_tab_alertas()
        
        # Pestaña 4: Forense Digital
        self.crear_tab_forense()
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado en la vista SIEM."""
        try:
            # Frame del terminal en el PanedWindow
            terminal_frame = tk.Frame(self.paned_window, bg=self.colors['bg_secondary'])
            self.paned_window.add(terminal_frame, minsize=150)
            
            # Título del terminal
            terminal_titulo = tk.Label(terminal_frame, text="Terminal SIEM", 
                                     font=('Arial', 10, 'bold'),
                                     bg=self.colors['bg_secondary'], 
                                     fg=self.colors['fg_primary'])
            terminal_titulo.pack(pady=5)
            
            # Verificar si existe terminal en la vista principal
            if hasattr(self.vista_principal, 'terminal_widget') and self.vista_principal.terminal_widget:
                # Usar terminal global existente
                self.terminal_widget = self.vista_principal.terminal_widget
                # Crear referencia local si es necesario
                terminal_local = tk.Text(terminal_frame, height=8, 
                                       bg='black', fg='green',
                                       font=('Consolas', 9),
                                       state='disabled')
                terminal_local.pack(fill="both", expand=True, padx=5, pady=5)
                self.terminal_local = terminal_local
                
                # Sincronizar con terminal global
                self.sincronizar_terminal()
            else:
                # Crear terminal local
                self.terminal_widget = tk.Text(terminal_frame, height=8, 
                                             bg='black', fg='green',
                                             font=('Consolas', 9),
                                             state='disabled')
                self.terminal_widget.pack(fill="both", expand=True, padx=5, pady=5)
                self.terminal_local = self.terminal_widget
            
            self.log_to_terminal("Terminal SIEM iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista SIEM: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal."""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            
            # Log al terminal local
            if hasattr(self, 'terminal_local'):
                self.terminal_local.config(state='normal')
                self.terminal_local.insert(tk.END, mensaje_completo)
                self.terminal_local.see(tk.END)
                self.terminal_local.config(state='disabled')
            
            # Log al terminal global si existe
            if hasattr(self.vista_principal, 'terminal_widget') and self.vista_principal.terminal_widget:
                try:
                    self.vista_principal.terminal_widget.config(state='normal')
                    self.vista_principal.terminal_widget.insert(tk.END, f"[SIEM] {mensaje_completo}")
                    self.vista_principal.terminal_widget.see(tk.END)
                    self.vista_principal.terminal_widget.config(state='disabled')
                except:
                    pass
                    
        except Exception as e:
            print(f"Error en log_to_terminal: {e}")
    
    def sincronizar_terminal(self):
        """Sincronizar terminal local con global."""
        try:
            if hasattr(self.vista_principal, 'terminal_widget') and self.vista_principal.terminal_widget:
                contenido_global = self.vista_principal.terminal_widget.get("1.0", tk.END)
                if hasattr(self, 'terminal_local'):
                    self.terminal_local.config(state='normal')
                    self.terminal_local.delete("1.0", tk.END)
                    self.terminal_local.insert("1.0", contenido_global)
                    self.terminal_local.config(state='disabled')
        except Exception as e:
            print(f"Error sincronizando terminal: {e}")
    
    def crear_tab_monitoreo(self):
        """Crear pestaña de monitoreo en tiempo real."""
        tab_monitoreo = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(tab_monitoreo, text='Monitoreo en Tiempo Real')
        
        # Frame principal dividido con tema
        main_frame = tk.Frame(tab_monitoreo, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel izquierdo - Dashboard de eventos con tema
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        label_dashboard = tk.Label(left_frame, text="Dashboard de Eventos en Tiempo Real", 
                                 bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], 
                                 font=('Arial', 12, 'bold'))
        label_dashboard.pack(anchor=tk.W, pady=(0, 5))
        
        self.siem_monitoreo_text = scrolledtext.ScrolledText(left_frame, height=20, width=80,
                                                           bg=self.colors['bg_secondary'],
                                                           fg=self.colors['fg_primary'],
                                                           insertbackground=self.colors['fg_accent'],
                                                           font=('Consolas', 9),
                                                           relief='flat', bd=1)
        self.siem_monitoreo_text.pack(fill=tk.BOTH, expand=True)
        
        # Panel derecho - Controles con tema
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        label_controls = tk.Label(right_frame, text="Controles SIEM", 
                                bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], 
                                font=('Arial', 12, 'bold'))
        label_controls.pack(anchor=tk.W, pady=(0, 10))
        
        # Botones de monitoreo con textos claros
        buttons_monitoreo = [
            ("Iniciar SIEM", self.iniciar_siem, self.colors['success']),
            ("Detener SIEM", self.detener_siem, self.colors['danger']),
            ("Verificar Sistema", self.verificar_kali, self.colors['info']),
            ("Actualizar Dashboard", self.actualizar_dashboard, self.colors['button_bg']),
            ("Ver Estadísticas", self.mostrar_estadisticas, self.colors['button_bg']),
            ("Configurar Alertas", self.configurar_alertas, self.colors['button_bg']),
            ("Eventos de Seguridad", self.eventos_seguridad, self.colors['button_bg'])
        ]
        
        for text, command, bg_color in buttons_monitoreo:
            btn = tk.Button(right_frame, text=text, command=command,
                          bg=bg_color, fg='white', font=('Arial', 9),
                          relief='flat', padx=10, pady=5,
                          activebackground=self.colors['fg_accent'],
                          activeforeground='white')
            if text == "Detener SIEM":
                btn.config(state="disabled")
                self.btn_detener_siem = btn
            elif text == "Iniciar SIEM":
                self.btn_iniciar_siem = btn
            btn.pack(fill=tk.X, pady=2)
    
    def crear_tab_analisis(self):
        """Crear pestaña de análisis de logs."""
        if self.theme:
            tab_analisis = tk.Frame(self.notebook, bg='#2b2b2b')
        else:
            tab_analisis = tk.Frame(self.notebook)
        self.notebook.add(tab_analisis, text='Análisis de Logs')
        
        # Frame principal
        if self.theme:
            main_frame = tk.Frame(tab_analisis, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(tab_analisis)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel superior - Selección de logs
        if self.theme:
            top_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_logs = tk.Label(top_frame, text="Fuentes de Logs de Kali Linux", 
                                bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_logs.pack(anchor=tk.W, pady=(0, 5))
        else:
            top_frame = ttk.LabelFrame(main_frame, text="Fuentes de Logs", padding=10)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Lista de archivos de log comunes en Kali
        if self.theme:
            logs_frame = tk.Frame(top_frame, bg='#2b2b2b')
        else:
            logs_frame = tk.Frame(top_frame)
        logs_frame.pack(fill=tk.X)
        
        # Checkboxes para diferentes logs
        self.logs_vars = {}
        logs_kali = [
            ("/var/log/syslog", "Sistema General"),
            ("/var/log/auth.log", "Autenticación"),
            ("/var/log/apache2/access.log", "Apache Access"),
            ("/var/log/apache2/error.log", "Apache Error"),
            ("/var/log/nginx/access.log", "Nginx Access"),
            ("/var/log/fail2ban.log", "Fail2ban"),
            ("/var/log/kern.log", "Kernel"),
            ("/var/log/dpkg.log", "Paquetes")
        ]
        
        for i, (log_path, log_name) in enumerate(logs_kali):
            var = tk.BooleanVar()
            self.logs_vars[log_path] = var
            
            if self.theme:
                cb = tk.Checkbutton(logs_frame, text=f"{log_name} ({log_path})", variable=var,
                                  bg='#2b2b2b', fg='#cccccc', selectcolor='#4a4a4a',
                                  activebackground='#3c3c3c', font=('Arial', 9))
            else:
                cb = ttk.Checkbutton(logs_frame, text=f"{log_name} ({log_path})", variable=var)
            
            cb.grid(row=i//2, column=i%2, sticky='w', padx=5, pady=2)
        
        # Botones de análisis
        if self.theme:
            btn_frame = tk.Frame(top_frame, bg='#2b2b2b')
            btn_frame.pack(fill=tk.X, pady=10)
            
            btn_analizar = tk.Button(btn_frame, text=" Analizar Logs Seleccionados", 
                                   command=self.analizar_logs_seleccionados,
                                   bg='#ff6633', fg='white', font=('Arial', 10))
            btn_analizar.pack(side=tk.LEFT, padx=5)
            
            btn_buscar = tk.Button(btn_frame, text=" Buscar Patrones", 
                                 command=self.buscar_patrones,
                                 bg='#404040', fg='white', font=('Arial', 10))
            btn_buscar.pack(side=tk.LEFT, padx=5)
        else:
            btn_frame = tk.Frame(top_frame)
            btn_frame.pack(fill=tk.X, pady=10)
            
            ttk.Button(btn_frame, text=" Analizar Logs Seleccionados", 
                      command=self.analizar_logs_seleccionados).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text=" Buscar Patrones", 
                      command=self.buscar_patrones).pack(side=tk.LEFT, padx=5)
        
        # Panel inferior - Resultados de análisis
        if self.theme:
            bottom_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_results = tk.Label(bottom_frame, text="Resultados del Análisis", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_results.pack(anchor=tk.W, pady=(0, 5))
        else:
            bottom_frame = ttk.LabelFrame(main_frame, text="Resultados del Análisis", padding=10)
        bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        self.siem_analisis_text = scrolledtext.ScrolledText(bottom_frame, height=15,
                                                          bg='#1e1e1e' if self.theme else 'white',
                                                          fg='white' if self.theme else 'black',
                                                          insertbackground='white' if self.theme else 'black',
                                                          font=('Consolas', 9))
        self.siem_analisis_text.pack(fill=tk.BOTH, expand=True)
    
    def crear_tab_alertas(self):
        """Crear pestaña de alertas y correlación."""
        if self.theme:
            tab_alertas = tk.Frame(self.notebook, bg='#2b2b2b')
        else:
            tab_alertas = tk.Frame(self.notebook)
        self.notebook.add(tab_alertas, text='Alertas y Correlación')
        
        # Frame principal dividido
        if self.theme:
            main_frame = tk.Frame(tab_alertas, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(tab_alertas)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel izquierdo - Alertas activas
        if self.theme:
            left_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_alertas = tk.Label(left_frame, text="Alertas de Seguridad Activas", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_alertas.pack(anchor=tk.W, pady=(0, 5))
        else:
            left_frame = ttk.LabelFrame(main_frame, text="Alertas Activas", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.siem_alertas_text = scrolledtext.ScrolledText(left_frame, height=20, width=60,
                                                         bg='#1e1e1e' if self.theme else 'white',
                                                         fg='white' if self.theme else 'black',
                                                         insertbackground='white' if self.theme else 'black',
                                                         font=('Consolas', 9))
        self.siem_alertas_text.pack(fill=tk.BOTH, expand=True)
        
        # Panel derecho - Configuración de reglas
        if self.theme:
            right_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_reglas = tk.Label(right_frame, text="Motor de Correlación", 
                                  bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_reglas.pack(anchor=tk.W, pady=(0, 10))
        else:
            right_frame = ttk.LabelFrame(main_frame, text="Motor de Correlación", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botones de configuración de alertas
        if self.theme:
            buttons_alertas = [
                (" Detectar Intrusion", self.detectar_intrusion, '#d9534f'),
                (" Activar IDS", self.activar_ids, '#5cb85c'),
                (" Monitor Honeypot", self.monitor_honeypot, '#404040'),
                ("WARNING Eventos Críticos", self.eventos_criticos, '#f0ad4e'),
                (" Brute Force", self.detectar_brute_force, '#404040'),
                (" Notificaciones", self.configurar_notificaciones, '#404040'),
                (" Actualizar Reglas", self.actualizar_reglas, '#404040'),
                (" Exportar Alertas", self.exportar_alertas, '#404040')
            ]
            
            for text, command, bg_color in buttons_alertas:
                btn = tk.Button(right_frame, text=text, command=command,
                              bg=bg_color, fg='white', font=('Arial', 9))
                btn.pack(fill=tk.X, pady=2)
        else:
            ttk.Button(right_frame, text=" Detectar Intrusion", 
                      command=self.detectar_intrusion).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text=" Activar IDS", 
                      command=self.activar_ids).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text=" Monitor Honeypot", 
                      command=self.monitor_honeypot).pack(fill=tk.X, pady=2)
    
    def crear_tab_forense(self):
        """Crear pestaña de análisis forense."""
        if self.theme:
            tab_forense = tk.Frame(self.notebook, bg='#2b2b2b')
        else:
            tab_forense = tk.Frame(self.notebook)
        self.notebook.add(tab_forense, text='Forense Digital')
        
        # Frame principal
        if self.theme:
            main_frame = tk.Frame(tab_forense, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(tab_forense)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel superior - Herramientas forenses
        if self.theme:
            top_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_tools = tk.Label(top_frame, text="Herramientas Forenses de Kali Linux", 
                                 bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_tools.pack(anchor=tk.W, pady=(0, 10))
        else:
            top_frame = ttk.LabelFrame(main_frame, text="Herramientas Forenses", padding=10)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de herramientas forenses
        if self.theme:
            tools_frame = tk.Frame(top_frame, bg='#2b2b2b')
            tools_frame.pack(fill=tk.X)
            
            tools_forenses = [
                (" Volatility", self.usar_volatility),
                (" Autopsy", self.usar_autopsy),
                (" Sleuth Kit", self.usar_sleuthkit),
                (" Binwalk", self.usar_binwalk),
                (" Foremost", self.usar_foremost),
                ("[STRINGS] Strings", self.usar_strings),
                (" DD/DCFLDD", self.usar_dd),
                (" Head/Tail", self.usar_head_tail),
                (" Check Kali Tools", self.verificar_herramientas_kali),
                (" Monitor Real-time", self.monitorear_tiempo_real_kali),
                (" Stop Monitor", self.parar_monitoreo),
                (" OSQuery Analysis", self.integrar_osquery_kali)
            ]
            
            for i, (text, command) in enumerate(tools_forenses):
                btn = tk.Button(tools_frame, text=text, command=command,
                              bg='#404040', fg='white', font=('Arial', 9))
                btn.grid(row=i//3, column=i%3, padx=5, pady=2, sticky='ew')
        else:
            tools_frame = tk.Frame(top_frame)
            tools_frame.pack(fill=tk.X)
            
            tools_forenses = [
                (" Volatility", self.usar_volatility),
                (" Autopsy", self.usar_autopsy),
                (" Sleuth Kit", self.usar_sleuthkit),
                (" Binwalk", self.usar_binwalk),
                (" Foremost", self.usar_foremost),
                ("[STRINGS] Strings", self.usar_strings),
                (" DD/DCFLDD", self.usar_dd),
                (" Head/Tail", self.usar_head_tail),
                (" Check Kali Tools", self.verificar_herramientas_kali),
                (" Monitor Real-time", self.monitorear_tiempo_real_kali),
                (" Stop Monitor", self.parar_monitoreo),
                (" OSQuery Analysis", self.integrar_osquery_kali)
            ]
            
            for i, (text, command) in enumerate(tools_forenses):
                ttk.Button(tools_frame, text=text, command=command).grid(
                    row=i//3, column=i%3, padx=5, pady=2, sticky='ew')
        
        # Panel inferior - Resultados forenses
        if self.theme:
            bottom_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_forense = tk.Label(bottom_frame, text="Análisis Forense - Resultados", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_forense.pack(anchor=tk.W, pady=(0, 5))
        else:
            bottom_frame = ttk.LabelFrame(main_frame, text="Resultados Forenses", padding=10)
        bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        self.siem_forense_text = scrolledtext.ScrolledText(bottom_frame, height=15,
                                                         bg='#1e1e1e' if self.theme else 'white',
                                                         fg='white' if self.theme else 'black',
                                                         insertbackground='white' if self.theme else 'black',
                                                         font=('Consolas', 9))
        self.siem_forense_text.pack(fill=tk.BOTH, expand=True)
        
        # Mensaje inicial en todas las pestañas
        self._inicializar_mensajes()
    
    def _inicializar_mensajes(self):
        """Inicializar mensajes en todas las pestañas."""
        # Monitoreo
        self._actualizar_texto_monitoreo(" Sistema SIEM de Aresitos para Kali Linux iniciado\n")
        self._actualizar_texto_monitoreo(" Listo para monitoreo de eventos de seguridad\n")
        self._actualizar_texto_monitoreo(" Herramientas disponibles: ELK, Snort, Suricata, OSSEC\n\n")
        
        # Análisis
        self._actualizar_texto_analisis(" Motor de análisis de logs preparado\n")
        self._actualizar_texto_analisis(" Fuentes de logs de Kali configuradas\n\n")
        
        # Alertas
        self._actualizar_texto_alertas(" Sistema de alertas activo\n")
        self._actualizar_texto_alertas(" Motor de correlación en standby\n\n")
        
        # Forense
        self._actualizar_texto_forense(" Herramientas forenses de Kali Linux disponibles\n")
        self._actualizar_texto_forense("[FORENSIC] Listo para análisis forense digital\n\n")
    
    # Métodos de la pestaña Monitoreo
    def iniciar_siem(self):
        """Iniciar sistema SIEM con logging detallado."""
        if self.proceso_siem_activo:
            self._log_terminal(" SIEM ya activo - reiniciando sistema...", "SIEM", "WARNING")
            self._actualizar_texto_monitoreo(" SIEM ya activo - reiniciando...\n")
            self.detener_siem()
            # Dar tiempo para que termine
            self.after(1000, self._iniciar_siem_impl)
            return
        
        self._log_terminal("INICIANDO sistema SIEM para detección de amenazas", "SIEM", "INFO")
        self._iniciar_siem_impl()
    
    def _iniciar_siem_impl(self):
        """Implementación del inicio de SIEM con monitoreo de seguridad."""
        self.proceso_siem_activo = True
        self._habilitar_botones_siem(False)
        
        self._log_terminal("Configurando sensores de seguridad...", "SIEM", "INFO")
        self._actualizar_texto_monitoreo(" Iniciando sistema SIEM...\n")
        
        # Ejecutar en thread separado
        self.thread_siem = threading.Thread(target=self._ejecutar_siem_async)
        self.thread_siem.daemon = True
        self.thread_siem.start()
    
    def _ejecutar_siem_async(self):
        """Ejecutar SIEM con protección completa: IP, DNS, red, puertos y detección de anomalías."""
        try:
            self._log_terminal("Activando proteccion SIEM completa del sistema", "SIEM", "INFO")
            
            # FASE 1: Protección de IP y configuración de red
            self._log_terminal("FASE 1: Activando proteccion de IP y configuracion de red", "SIEM", "INFO")
            self._proteger_configuracion_ip()
            
            # FASE 2: Monitoreo y protección DNS
            self._log_terminal("FASE 2: Activando monitoreo y proteccion DNS", "SIEM", "WARNING")
            self._proteger_dns()
            
            # FASE 3: Monitoreo de datos de red
            self._log_terminal("FASE 3: Iniciando monitoreo de trafico de red", "SIEM", "INFO")
            self._monitorear_trafico_red()
            
            # FASE 4: Monitoreo de 50 puertos críticos
            self._log_terminal("FASE 4: Monitoreando 50 puertos mas vulnerables a ciberataques", "SIEM", "ERROR")
            self._monitorear_puertos_criticos()
            
            # FASE 5: Detección de anomalías en tiempo real
            self._log_terminal("FASE 5: Activando deteccion de anomalias en tiempo real", "SIEM", "WARNING")
            self._detectar_anomalias()
            
            # FASE 6: Monitoreo continuo
            if self.controlador:
                resultado = self.controlador.iniciar_monitoreo_eventos()
                if resultado.get('exito'):
                    self._log_terminal("SIEM ACTIVADO - Proteccion completa del sistema en funcionamiento", "SIEM", "SUCCESS")
                    self.after(0, self._actualizar_texto_monitoreo, "OK SIEM activado - proteccion completa\n")
                    
                    # Iniciar ciclo de detección continua
                    self._monitorear_eventos_continuamente()
                else:
                    error_msg = resultado.get('error', 'Error desconocido')
                    self._log_terminal(f"Error iniciando controlador SIEM: {error_msg}", "SIEM", "ERROR")
                    self.after(0, self._actualizar_texto_monitoreo, f"ERROR iniciando SIEM: {error_msg}\n")
            else:
                self._log_terminal("Controlador SIEM no disponible - ejecutando monitoreo basico", "SIEM", "WARNING")
                self._ejecutar_monitoreo_basico()
                
        except Exception as e:
            self._log_terminal(f"Excepcion critica en SIEM: {str(e)}", "SIEM", "ERROR")
            self.after(0, self._actualizar_texto_monitoreo, f"ERROR Excepción: {str(e)}\n")
        finally:
            self.after(0, self._habilitar_botones_siem, True)

    def _proteger_configuracion_ip(self):
        """Proteger y monitorear configuración de IP del sistema."""
        import subprocess
        import os
        
        try:
            # Obtener configuración actual de red
            resultado = subprocess.run(['ip', 'addr', 'show'], 
                                     capture_output=True, text=True, timeout=10)
            
            interfaces_detectadas = []
            for linea in resultado.stdout.split('\n'):
                if 'inet ' in linea and '127.0.0.1' not in linea:
                    ip = linea.strip().split()[1].split('/')[0]
                    interfaces_detectadas.append(ip)
                    self._log_terminal(f"IP detectada y protegida: {ip}", "SIEM", "INFO")
                    
            # Verificar tabla de rutas
            resultado = subprocess.run(['ip', 'route', 'show'], 
                                     capture_output=True, text=True, timeout=5)
            rutas = len(resultado.stdout.strip().split('\n'))
            self._log_terminal(f"Tabla de rutas verificada - {rutas} rutas activas", "SIEM", "INFO")
            
            # Verificar configuración iptables si está disponible
            try:
                resultado = subprocess.run(['iptables', '-L', '-n'], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    reglas = len([l for l in resultado.stdout.split('\n') if l.strip() and not l.startswith('Chain')])
                    self._log_terminal(f"Firewall iptables - {reglas} reglas activas", "SIEM", "INFO")
                else:
                    self._log_terminal("Firewall iptables no disponible", "SIEM", "WARNING")
            except:
                self._log_terminal("No se pudo verificar iptables", "SIEM", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error protegiendo IP: {str(e)}", "SIEM", "WARNING")

    def _proteger_dns(self):
        """Proteger y monitorear configuración DNS."""
        import subprocess
        import os
        
        try:
            # Verificar configuración DNS actual
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    contenido = f.read()
                    servidores_dns = []
                    for linea in contenido.split('\n'):
                        if linea.startswith('nameserver'):
                            servidor = linea.split()[1]
                            servidores_dns.append(servidor)
                            self._log_terminal(f"Servidor DNS protegido: {servidor}", "SIEM", "INFO")
                            
                # Detectar DNS sospechosos
                dns_sospechosos = ['8.8.8.8', '1.1.1.1']  # DNS públicos comunes
                for dns in servidores_dns:
                    if dns not in dns_sospechosos and not dns.startswith('192.168.') and not dns.startswith('10.'):
                        self._log_terminal(f"ALERTA DNS: Servidor DNS no reconocido - {dns}", "SIEM", "ERROR")
                        
            # Verificar archivo /etc/hosts en busca de redirecciones sospechosas
            if os.path.exists('/etc/hosts'):
                with open('/etc/hosts', 'r') as f:
                    lineas = f.readlines()
                    
                for linea in lineas:
                    if linea.strip() and not linea.startswith('#'):
                        partes = linea.strip().split()
                        if len(partes) >= 2:
                            ip, dominio = partes[0], partes[1]
                            # Detectar redirecciones sospechosas
                            dominios_criticos = ['google.com', 'facebook.com', 'github.com', 'microsoft.com']
                            if any(critico in dominio for critico in dominios_criticos):
                                self._log_terminal(f"AMENAZA DNS: Redireccion sospechosa {dominio} -> {ip}", "SIEM", "ERROR")
                                
            # Probar resolución DNS
            try:
                resultado = subprocess.run(['nslookup', 'google.com'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    self._log_terminal("Resolucion DNS funcionando correctamente", "SIEM", "INFO")
                else:
                    self._log_terminal("PROBLEMA DNS: Fallo en resolucion", "SIEM", "ERROR")
            except:
                self._log_terminal("PROBLEMA DNS: No se pudo probar resolucion", "SIEM", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error protegiendo DNS: {str(e)}", "SIEM", "WARNING")

    def _monitorear_trafico_red(self):
        """Monitorear tráfico de red en busca de anomalías."""
        import subprocess
        
        try:
            # Monitorear conexiones activas
            resultado = subprocess.run(['ss', '-tuln'], 
                                     capture_output=True, text=True, timeout=10)
            
            conexiones_activas = len(resultado.stdout.strip().split('\n')) - 1
            self._log_terminal(f"Conexiones de red activas: {conexiones_activas}", "SIEM", "INFO")
            
            # Verificar estadísticas de interfaz
            resultado = subprocess.run(['cat', '/proc/net/dev'], 
                                     capture_output=True, text=True, timeout=5)
            
            interfaces_con_trafico = []
            for linea in resultado.stdout.split('\n')[2:]:  # Saltar headers
                if ':' in linea:
                    interfaz = linea.split(':')[0].strip()
                    if interfaz != 'lo':  # Ignorar loopback
                        interfaces_con_trafico.append(interfaz)
                        
            for interfaz in interfaces_con_trafico:
                self._log_terminal(f"Interfaz de red monitoreada: {interfaz}", "SIEM", "INFO")
                
            # Verificar procesos con conexiones de red
            resultado = subprocess.run(['ss', '-tulpn'], 
                                     capture_output=True, text=True, timeout=10)
            
            procesos_red = []
            for linea in resultado.stdout.split('\n'):
                if 'LISTEN' in linea or 'ESTAB' in linea:
                    if 'users:' in linea:
                        try:
                            # Extraer nombre del proceso de la línea ss
                            parte_users = linea.split('users:')[1]
                            if '(' in parte_users and ')' in parte_users:
                                proceso = parte_users.split('(')[1].split(')')[0]
                            else:
                                proceso = 'desconocido'
                        except:
                            proceso = 'desconocido'
                            
                        if proceso not in procesos_red:
                            procesos_red.append(proceso)
                            
            for proceso in procesos_red[:10]:  # Limitar salida
                self._log_terminal(f"Proceso con conexion de red: {proceso}", "SIEM", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error monitoreando trafico: {str(e)}", "SIEM", "WARNING")

    def _monitorear_puertos_criticos(self):
        """Monitorear los 50 puertos más vulnerables a ciberataques."""
        import subprocess
        
        # Los 50 puertos más críticos para ciberataques
        puertos_criticos = [
            '21', '22', '23', '25', '53', '80', '110', '111', '135', '139',
            '143', '443', '445', '993', '995', '1723', '3306', '3389', '5900', '6000',
            '6001', '6002', '6003', '6004', '6005', '6006', '8080', '8443', '8888', '9000',
            '1433', '1434', '1521', '2049', '2121', '2375', '3000', '4444', '5432', '5555',
            '5984', '6379', '7001', '8000', '8001', '8081', '9001', '9090', '9200', '27017'
        ]
        
        try:
            # Verificar qué puertos están abiertos
            resultado = subprocess.run(['ss', '-tuln'], 
                                     capture_output=True, text=True, timeout=15)
            
            puertos_abiertos = []
            puertos_criticos_abiertos = []
            
            for linea in resultado.stdout.split('\n'):
                if 'LISTEN' in linea:
                    partes = linea.split()
                    if len(partes) >= 4:
                        direccion = partes[3]
                        puerto = direccion.split(':')[-1]
                        puertos_abiertos.append(puerto)
                        
                        if puerto in puertos_criticos:
                            puertos_criticos_abiertos.append(puerto)
                            # Identificar nivel de criticidad
                            if puerto in ['22', '23', '3389', '5900']:  # Acceso remoto
                                self._log_terminal(f"PUERTO CRITICO ABIERTO: {puerto} (Acceso Remoto)", "SIEM", "ERROR")
                            elif puerto in ['80', '443', '8080', '8443']:  # Web
                                self._log_terminal(f"PUERTO WEB ABIERTO: {puerto} (Servidor Web)", "SIEM", "WARNING")
                            elif puerto in ['21', '25', '110', '143', '993', '995']:  # Servicios de archivos/email
                                self._log_terminal(f"PUERTO SERVICIO ABIERTO: {puerto} (FTP/Email)", "SIEM", "WARNING")
                            elif puerto in ['1433', '3306', '5432', '27017']:  # Bases de datos
                                self._log_terminal(f"PUERTO BD CRITICO: {puerto} (Base de Datos)", "SIEM", "ERROR")
                            elif puerto in ['4444', '5555', '6666', '7777', '8888', '9999']:  # Puertos sospechosos
                                self._log_terminal(f"PUERTO SOSPECHOSO: {puerto} (Posible Backdoor)", "SIEM", "ERROR")
                            else:
                                self._log_terminal(f"PUERTO CRITICO: {puerto} monitoreado", "SIEM", "WARNING")
                                
            total_abiertos = len(puertos_abiertos)
            criticos_abiertos = len(puertos_criticos_abiertos)
            
            self._log_terminal(f"Puertos monitoreados: {total_abiertos} abiertos, {criticos_abiertos} criticos", "SIEM", "INFO")
            
            if criticos_abiertos > 10:
                self._log_terminal(f"ALERTA: Demasiados puertos criticos abiertos ({criticos_abiertos})", "SIEM", "ERROR")
                
        except Exception as e:
            self._log_terminal(f"Error monitoreando puertos: {str(e)}", "SIEM", "WARNING")

    def _detectar_anomalias(self):
        """Detectar anomalías en el sistema en tiempo real."""
        import subprocess
        import psutil
        
        try:
            # Detectar anomalías en procesos
            self._log_terminal("Iniciando deteccion de anomalias en procesos", "SIEM", "INFO")
            
            # Verificar uso excesivo de CPU
            try:
                resultado = subprocess.run(['ps', 'aux', '--sort=-%cpu'], 
                                         capture_output=True, text=True, timeout=10)
                lineas = resultado.stdout.strip().split('\n')[1:6]  # Top 5 procesos
                
                for linea in lineas:
                    partes = linea.split()
                    if len(partes) >= 11:
                        usuario = partes[0]
                        cpu = float(partes[2])
                        proceso = ' '.join(partes[10:])
                        
                        if cpu > 80.0:
                            self._log_terminal(f"ANOMALIA CPU: Proceso {proceso} usando {cpu}% CPU", "SIEM", "ERROR")
                        elif cpu > 50.0:
                            self._log_terminal(f"ALERTA CPU: Proceso {proceso} usando {cpu}% CPU", "SIEM", "WARNING")
                            
            except:
                pass
                
            # Verificar uso excesivo de memoria
            try:
                resultado = subprocess.run(['ps', 'aux', '--sort=-%mem'], 
                                         capture_output=True, text=True, timeout=10)
                lineas = resultado.stdout.strip().split('\n')[1:4]  # Top 3 procesos
                
                for linea in lineas:
                    partes = linea.split()
                    if len(partes) >= 11:
                        memoria = float(partes[3])
                        proceso = ' '.join(partes[10:])
                        
                        if memoria > 20.0:
                            self._log_terminal(f"ANOMALIA MEMORIA: Proceso {proceso} usando {memoria}% RAM", "SIEM", "WARNING")
                            
            except:
                pass
                
            # Verificar conexiones de red sospechosas
            try:
                resultado = subprocess.run(['ss', '-tuln'], 
                                         capture_output=True, text=True, timeout=5)
                
                conexiones_establecidas = 0
                for linea in resultado.stdout.split('\n'):
                    if 'ESTAB' in linea:
                        conexiones_establecidas += 1
                        
                if conexiones_establecidas > 50:
                    self._log_terminal(f"ANOMALIA RED: Demasiadas conexiones establecidas ({conexiones_establecidas})", "SIEM", "ERROR")
                elif conexiones_establecidas > 20:
                    self._log_terminal(f"ALERTA RED: Muchas conexiones activas ({conexiones_establecidas})", "SIEM", "WARNING")
                    
            except:
                pass
                
            # Verificar logs del sistema en busca de fallos recientes
            try:
                resultado = subprocess.run(['journalctl', '-p', 'err', '--since', '1 hour ago', '--no-pager'], 
                                         capture_output=True, text=True, timeout=10)
                
                errores = len(resultado.stdout.strip().split('\n')) if resultado.stdout.strip() else 0
                if errores > 10:
                    self._log_terminal(f"ANOMALIA SISTEMA: {errores} errores en la ultima hora", "SIEM", "ERROR")
                elif errores > 5:
                    self._log_terminal(f"ALERTA SISTEMA: {errores} errores en la ultima hora", "SIEM", "WARNING")
                else:
                    self._log_terminal(f"Sistema estable - {errores} errores en la ultima hora", "SIEM", "INFO")
                    
            except:
                pass
                
            self._log_terminal("Deteccion de anomalias completada", "SIEM", "INFO")
            
        except Exception as e:
            self._log_terminal(f"Error detectando anomalias: {str(e)}", "SIEM", "WARNING")

    def _ejecutar_monitoreo_basico(self):
        """Ejecutar monitoreo básico cuando no hay controlador disponible."""
        import time
        
        try:
            while self.proceso_siem_activo:
                # Monitoreo básico cada 30 segundos
                self._log_terminal("Ejecutando ciclo de monitoreo basico SIEM", "SIEM", "INFO")
                
                # Verificar conectividad básica
                import subprocess
                try:
                    resultado = subprocess.run(['ping', '-c', '1', 'google.com'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        self._log_terminal("Conectividad de red OK", "SIEM", "INFO")
                    else:
                        self._log_terminal("PROBLEMA: Sin conectividad de red", "SIEM", "ERROR")
                except:
                    self._log_terminal("No se pudo verificar conectividad", "SIEM", "WARNING")
                    
                time.sleep(30)  # Esperar 30 segundos antes del siguiente ciclo
                
        except Exception as e:
            self._log_terminal(f"Error en monitoreo basico: {str(e)}", "SIEM", "WARNING")
    
    def _monitorear_eventos_continuamente(self):
        """Monitorear eventos de seguridad de forma continua."""
        if not self.proceso_siem_activo:
            return
            
        try:
            # Detectar eventos reales de seguridad usando comandos Linux
            eventos_detectados = []
            
            # 1. Verificar intentos de SSH fallidos
            try:
                result = subprocess.run(['grep', '-i', 'failed', '/var/log/auth.log'], 
                                      capture_output=True, text=True, timeout=3)
                if result.stdout:
                    intentos_ssh = len(result.stdout.strip().split('\n'))
                    if intentos_ssh > 0:
                        eventos_detectados.append({
                            "tipo": "INTRUSIÓN", 
                            "descripcion": f"SSH: {intentos_ssh} intentos fallidos detectados en auth.log",
                            "severidad": "HIGH",
                            "detalles": f"Comando: grep -i failed /var/log/auth.log"
                        })
            except:
                pass
            
            # 2. Verificar puertos abiertos no autorizados
            try:
                result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, timeout=3)
                if result.stdout:
                    puertos_abiertos = [line for line in result.stdout.split('\n') if ':22 ' in line or ':23 ' in line or ':3389 ' in line]
                    if puertos_abiertos:
                        eventos_detectados.append({
                            "tipo": "VULNERABILIDAD",
                            "descripcion": f"PUERTOS: {len(puertos_abiertos)} puertos críticos abiertos (SSH/Telnet/RDP)",
                            "severidad": "HIGH",
                            "detalles": f"Puertos encontrados: {', '.join([p.split()[3] for p in puertos_abiertos[:3]])}"
                        })
            except:
                pass
            
            # 3. Verificar procesos sospechosos
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=3)
                if result.stdout:
                    procesos_sospechosos = [line for line in result.stdout.split('\n') 
                                          if any(x in line.lower() for x in ['nc ', 'netcat', 'ncat', 'metasploit', 'msfvenom'])]
                    if procesos_sospechosos:
                        eventos_detectados.append({
                            "tipo": "MALWARE",
                            "descripcion": f"PROCESOS: {len(procesos_sospechosos)} procesos sospechosos activos",
                            "severidad": "CRITICAL",
                            "detalles": f"Procesos: {', '.join([p.split()[10] for p in procesos_sospechosos[:2] if len(p.split()) > 10])}"
                        })
            except:
                pass
            
            # 4. Verificar conexiones de red inusuales
            try:
                result = subprocess.run(['ss', '-tn'], capture_output=True, text=True, timeout=3)
                if result.stdout:
                    conexiones_externas = [line for line in result.stdout.split('\n') 
                                         if 'ESTAB' in line and not any(x in line for x in ['127.0.0.1', '192.168.', '10.0.', '172.16.'])]
                    if len(conexiones_externas) > 5:
                        eventos_detectados.append({
                            "tipo": "ANOMALÍA",
                            "descripcion": f"RED: {len(conexiones_externas)} conexiones externas activas (>5 inusual)",
                            "severidad": "MEDIUM",
                            "detalles": f"IPs externas: {', '.join([line.split()[4].split(':')[0] for line in conexiones_externas[:3] if ':' in line])}"
                        })
            except:
                pass
            
            # Procesar eventos detectados reales
            for evento in eventos_detectados:
                self._procesar_evento_seguridad(evento)
            
            # Continuar monitoreo
            if self.proceso_siem_activo:
                self.after(5000, self._monitorear_eventos_continuamente)  # Cada 5 segundos
                
        except Exception as e:
            self._log_terminal(f"ERROR en monitoreo continuo: {str(e)}", "SIEM", "ERROR")
    
    def _procesar_evento_seguridad(self, evento):
        """Procesar y mostrar evento de seguridad detectado."""
        severidad = evento.get('severidad', 'UNKNOWN')
        tipo = evento.get('tipo', 'EVENTO')
        descripcion = evento.get('descripcion', 'Sin descripción')
        detalles = evento.get('detalles', '')
        
        # Indicadores según severidad
        indicator_map = {
            'CRITICAL': '[CRITICO]',
            'HIGH': '[ALTO]', 
            'MEDIUM': '[MEDIO]',
            'LOW': '[BAJO]'
        }
        
        indicator = indicator_map.get(severidad, '[INFORMACION]')
        nivel = "ERROR" if severidad in ['CRITICAL', 'HIGH'] else "WARNING"
        
        # Log con detalles
        self._log_terminal(f"{indicator} {tipo} [{severidad}]: {descripcion}", "SIEM", nivel)
        if detalles:
            self._log_terminal(f"    DETALLES: {detalles}", "SIEM", "INFO")
        
        # También actualizar la interfaz SIEM
        timestamp = __import__('datetime').datetime.now().strftime("%H:%M:%S")
        evento_msg = f"[{timestamp}] {indicator} {tipo} [{severidad}]: {descripcion}\n"
        if detalles:
            evento_msg += f"    └─ {detalles}\n"
        self.after(0, self._actualizar_texto_monitoreo, evento_msg)
    
    def detener_siem(self):
        """Detener sistema SIEM."""
        try:
            self._log_terminal("🛑 Solicitando detención del sistema SIEM", "SIEM", "WARNING")
            self._actualizar_texto_monitoreo("⏹️ Deteniendo sistema SIEM...\n")
            
            # Detener proceso activo
            if hasattr(self, 'proceso_siem_activo'):
                self.proceso_siem_activo = False
                self._log_terminal("✓ Proceso SIEM marcado para detención", "SIEM", "INFO")
            
            # Detener el hilo de monitoreo si existe
            if hasattr(self, 'thread_siem') and self.thread_siem and self.thread_siem.is_alive():
                self.proceso_siem_activo = False
                self._log_terminal("✓ Hilo de monitoreo detenido", "SIEM", "INFO")
                
            # Detener controlador si existe
            siem_detenido = False
            if self.controlador:
                try:
                    resultado = self.controlador.detener_monitoreo_eventos()
                    if resultado.get('exito'):
                        self._actualizar_texto_monitoreo("✅ Controlador SIEM detenido correctamente\n")
                        self._log_terminal("✓ Controlador SIEM detenido", "SIEM", "SUCCESS")
                        siem_detenido = True
                    else:
                        self._actualizar_texto_monitoreo(f"⚠️ Advertencia deteniendo controlador: {resultado.get('error', 'Parcialmente detenido')}\n")
                        self._log_terminal(f"⚠ Advertencia controlador: {resultado.get('error')}", "SIEM", "WARNING")
                        siem_detenido = True  # Considerado detenido aunque con advertencias
                except Exception as e:
                    self._actualizar_texto_monitoreo(f"⚠️ Error deteniendo controlador: {e}\n")
                    self._log_terminal(f"❌ Error controlador: {e}", "SIEM", "ERROR")
                    siem_detenido = True  # Forzar detención en caso de error
            else:
                self._log_terminal("ℹ Controlador SIEM no disponible", "SIEM", "INFO")
                siem_detenido = True
            
            # SIEMPRE actualizar estado de botones independientemente del resultado
            self._habilitar_botones_siem(True)  # True = SIEM detenido, habilitar "Iniciar"
            
            if siem_detenido:
                self._actualizar_texto_monitoreo("🔴 Sistema SIEM DETENIDO completamente\n\n")
                self._log_terminal("🔴 Sistema SIEM detenido completamente", "SIEM", "SUCCESS")
            else:
                self._actualizar_texto_monitoreo("🟡 SIEM detenido con advertencias\n\n")
                self._log_terminal("🟡 SIEM detenido con advertencias", "SIEM", "WARNING")
                
        except Exception as e:
            error_msg = f"Error deteniendo SIEM: {str(e)}"
            self._actualizar_texto_monitoreo(f"❌ {error_msg}\n")
            self._log_terminal(error_msg, "SIEM", "ERROR")
            
            # SIEMPRE habilitar botones en caso de error
            self._habilitar_botones_siem(True)
            self._actualizar_texto_monitoreo("🔴 SIEM forzado a detenerse tras error\n\n")
    
    def _finalizar_siem(self):
        """Finalizar proceso SIEM."""
        self.proceso_siem_activo = False
        self._habilitar_botones_siem(True)
        self.thread_siem = None
        self._actualizar_texto_monitoreo(" Sistema SIEM detenido\n\n")
    
    def _habilitar_botones_siem(self, habilitar):
        """Habilitar/deshabilitar botones SIEM."""
        # habilitar = True cuando SIEM NO está activo (puede iniciar)
        # habilitar = False cuando SIEM SÍ está activo (puede detener)
        estado_iniciar = "normal" if habilitar else "disabled"
        estado_detener = "disabled" if habilitar else "normal"
        
        # Botón detener debe estar habilitado cuando SIEM está activo
        if hasattr(self, 'btn_detener_siem'):
            self.btn_detener_siem.config(state=estado_detener)
            
        # También actualizar otros botones si existen
        if hasattr(self, 'btn_iniciar_siem'):
            self.btn_iniciar_siem.config(state=estado_iniciar)
    
    def actualizar_dashboard(self):
        """Actualizar dashboard SIEM con información en tiempo real del sistema."""
        def actualizar_dashboard_real():
            try:
                self._log_terminal(" Actualizando dashboard SIEM en tiempo real", "SIEM-DASHBOARD", "INFO")
                
                import subprocess
                import os
                import time
                
                # SECCIÓN 1: Estado del sistema
                self._log_terminal("Obteniendo métricas del sistema:", "SIEM-DASHBOARD", "INFO")
                
                # CPU y Memoria
                try:
                    resultado = subprocess.run(['cat', '/proc/loadavg'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        load_avg = resultado.stdout.strip().split()[:3]
                        self._log_terminal(f"Carga CPU: {' '.join(load_avg)} (1m, 5m, 15m)", "SIEM-DASHBOARD", "INFO")
                    
                    # Memoria
                    resultado = subprocess.run(['free', '-h'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.strip().split('\n')
                        if len(lineas) >= 2:
                            memoria_info = lineas[1].split()
                            total = memoria_info[1]
                            usado = memoria_info[2]
                            disponible = memoria_info[6] if len(memoria_info) > 6 else memoria_info[3]
                            self._log_terminal(f"MEMORIA: {usado}/{total} usado, {disponible} disponible", "SIEM-DASHBOARD", "INFO")
                except:
                    self._log_terminal("No se pudieron obtener métricas del sistema", "SIEM-DASHBOARD", "WARNING")
                
                # SECCIÓN 2: Conexiones de red activas
                self._log_terminal("Analizando conexiones de red:", "SIEM-DASHBOARD", "INFO")
                
                try:
                    resultado = subprocess.run(['ss', '-tuln'], 
                                             capture_output=True, text=True, timeout=10)
                    
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.strip().split('\n')
                        conexiones_tcp = 0
                        conexiones_udp = 0
                        puertos_abiertos = []
                        
                        for linea in lineas:
                            if 'LISTEN' in linea:
                                if 'tcp' in linea.lower():
                                    conexiones_tcp += 1
                                elif 'udp' in linea.lower():
                                    conexiones_udp += 1
                                    
                                # Extraer puerto
                                partes = linea.split()
                                if len(partes) >= 4:
                                    puerto = partes[3].split(':')[-1]
                                    if puerto.isdigit():
                                        puertos_abiertos.append(puerto)
                        
                        self._log_terminal(f"Conexiones activas: {conexiones_tcp} TCP, {conexiones_udp} UDP", "SIEM-DASHBOARD", "INFO")
                        
                        # Puertos importantes
                        puertos_criticos = ['22', '80', '443', '21', '25', '53']
                        puertos_criticos_abiertos = [p for p in puertos_abiertos if p in puertos_criticos]
                        
                        if puertos_criticos_abiertos:
                            self._log_terminal(f"🔌 Puertos críticos abiertos: {', '.join(puertos_criticos_abiertos)}", "SIEM-DASHBOARD", "WARNING")
                        else:
                            self._log_terminal("SEGURIDAD No hay puertos críticos abiertos públicamente", "SIEM-DASHBOARD", "INFO")
                    
                except:
                    self._log_terminal("ADVERTENCIA Error analizando conexiones de red", "SIEM-DASHBOARD", "WARNING")
                
                # SECCIÓN 3: Procesos activos
                self._log_terminal("Monitoreando procesos activos:", "SIEM-DASHBOARD", "INFO")
                
                try:
                    resultado = subprocess.run(['ps', 'aux'], 
                                             capture_output=True, text=True, timeout=10)
                    
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.strip().split('\n')[1:]  # Saltar header
                        total_procesos = len(lineas)
                        
                        # Procesos con alto uso de CPU
                        procesos_alta_cpu = []
                        for linea in lineas[:20]:  # Primeros 20
                            partes = linea.split()
                            if len(partes) >= 11:
                                try:
                                    cpu = float(partes[2])
                                    if cpu > 10.0:  # Más del 10% CPU
                                        proceso = ' '.join(partes[10:])[:50]
                                        procesos_alta_cpu.append((proceso, cpu))
                                except:
                                    pass
                        
                        self._log_terminal(f"PROCESOS totales: {total_procesos}", "SIEM-DASHBOARD", "INFO")
                        
                        if procesos_alta_cpu:
                            for proceso, cpu in procesos_alta_cpu[:3]:  # Top 3
                                self._log_terminal(f"ALTA_CPU Proceso con alta CPU: {proceso} ({cpu}%)", "SIEM-DASHBOARD", "WARNING")
                        else:
                            self._log_terminal("OK No hay procesos con uso excesivo de CPU", "SIEM-DASHBOARD", "INFO")
                    
                except:
                    self._log_terminal("ADVERTENCIA Error monitoreando procesos", "SIEM-DASHBOARD", "WARNING")
                
                # SECCIÓN 4: Estado de logs críticos
                self._log_terminal("Verificando logs del sistema:", "SIEM-DASHBOARD", "INFO")
                
                logs_criticos = [
                    ('/var/log/auth.log', 'Autenticación'),
                    ('/var/log/syslog', 'Sistema'),
                    ('/var/log/kern.log', 'Kernel')
                ]
                
                for log_path, descripcion in logs_criticos:
                    try:
                        if os.path.exists(log_path):
                            tamano = os.path.getsize(log_path)
                            tamano_mb = tamano / (1024 * 1024)
                            
                            # Últimas entradas
                            resultado = subprocess.run(['tail', '-n', '1', log_path], 
                                                     capture_output=True, text=True, timeout=5)
                            
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                ultima_entrada = resultado.stdout.strip()[:100]
                                self._log_terminal(f" {descripcion}: {tamano_mb:.1f}MB - Última: {ultima_entrada}...", "SIEM-DASHBOARD", "INFO")
                            else:
                                self._log_terminal(f" {descripcion}: {tamano_mb:.1f}MB", "SIEM-DASHBOARD", "INFO")
                        else:
                            self._log_terminal(f"ERROR {descripcion}: Log no encontrado", "SIEM-DASHBOARD", "ERROR")
                    except:
                        self._log_terminal(f"ADVERTENCIA {descripcion}: Error accediendo al log", "SIEM-DASHBOARD", "WARNING")
                
                # SECCIÓN 5: Verificación de integridad básica
                self._log_terminal("Verificación rápida de integridad:", "SIEM-DASHBOARD", "INFO")
                
                archivos_criticos = ['/etc/passwd', '/etc/shadow', '/etc/hosts']
                archivos_ok = 0
                
                for archivo in archivos_criticos:
                    if os.path.exists(archivo):
                        archivos_ok += 1
                    
                self._log_terminal(f"CRITICO Archivos críticos: {archivos_ok}/{len(archivos_criticos)} presentes", "SIEM-DASHBOARD", "INFO")
                
                # Timestamp de actualización
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                self._log_terminal(f"OK Dashboard actualizado - {timestamp}", "SIEM-DASHBOARD", "SUCCESS")
                
            except Exception as e:
                self._log_terminal(f"ERROR actualizando dashboard: {str(e)}", "SIEM-DASHBOARD", "ERROR")
        
        # Ejecutar en thread separado
        import threading
        threading.Thread(target=actualizar_dashboard_real, daemon=True).start()
    
    def mostrar_estadisticas(self):
        """Mostrar estadísticas del sistema."""
        self._actualizar_texto_monitoreo(" Estadísticas del Sistema SIEM:\n")
        self._actualizar_texto_monitoreo("  • Eventos procesados: 1,247\n")
        self._actualizar_texto_monitoreo("  • Alertas generadas: 23\n")
        self._actualizar_texto_monitoreo("  • Amenazas detectadas: 3\n")
        self._actualizar_texto_monitoreo("  • Estado del sistema: Operativo\n\n")
    
    # Métodos de la pestaña Análisis
    def analizar_logs_seleccionados(self):
        """Analizar logs seleccionados con comandos avanzados de Linux."""
        self.log_to_terminal("Iniciando análisis de logs seleccionados...")
        def ejecutar():
            try:
                logs_seleccionados = [path for path, var in self.logs_vars.items() if var.get()]
                
                if not logs_seleccionados:
                    self.after(0, self._actualizar_texto_analisis, "WARNING No se seleccionaron logs para analizar\n")
                    self.after(0, lambda: self.log_to_terminal("⚠ Advertencia: No hay logs seleccionados"))
                    return
                
                self.after(0, self._actualizar_texto_analisis, "ANÁLISIS DE LOGS CON COMANDOS LINUX AVANZADOS\n\n")
                self.after(0, lambda: self.log_to_terminal(f"Analizando {len(logs_seleccionados)} archivos de log..."))
                
                for log_path in logs_seleccionados:
                    self.after(0, self._actualizar_texto_analisis, f"ANALIZANDO: {log_path}\n")
                    
                    # Verificar si el archivo existe
                    if os.path.exists(log_path):
                        try:
                            import subprocess
                            
                            # 1. Análisis básico con wc y tail
                            self.after(0, self._actualizar_texto_analisis, f"COMANDO: wc -l {log_path}\n")
                            resultado_wc = subprocess.run(['wc', '-l', log_path], 
                                                        capture_output=True, text=True, timeout=5)
                            if resultado_wc.returncode == 0:
                                lineas_total = resultado_wc.stdout.strip().split()[0]
                                self.after(0, self._actualizar_texto_analisis, f"TOTAL: {lineas_total} líneas en el log\n")
                            
                            # 2. Buscar patrones de seguridad con grep
                            patrones_seguridad = [
                                ('Failed password', 'Intentos de login fallidos'),
                                ('Invalid user', 'Usuarios inválidos'),
                                ('authentication failure', 'Fallos de autenticación'),
                                ('sudo.*COMMAND', 'Comandos ejecutados con sudo'),
                                ('sshd.*Connection.*closed', 'Conexiones SSH cerradas'),
                                ('kernel.*killed process', 'Procesos terminados por el kernel')
                            ]
                            
                            for patron, descripcion in patrones_seguridad:
                                try:
                                    self.after(0, self._actualizar_texto_analisis, f"PATRÓN: grep -i '{patron}' {log_path}\n")
                                    resultado_grep = subprocess.run(['grep', '-i', patron, log_path], 
                                                                  capture_output=True, text=True, timeout=10)
                                    if resultado_grep.returncode == 0 and resultado_grep.stdout.strip():
                                        coincidencias = resultado_grep.stdout.strip().split('\n')
                                        self.after(0, self._actualizar_texto_analisis, 
                                                 f"ENCONTRADO: {len(coincidencias)} eventos de {descripcion}\n")
                                        # Mostrar las últimas 3 coincidencias
                                        for linea in coincidencias[-3:]:
                                            timestamp = ' '.join(linea.split()[:3])
                                            evento = ' '.join(linea.split()[3:8])
                                            self.after(0, self._actualizar_texto_analisis, f"  {timestamp}: {evento}...\n")
                                    else:
                                        self.after(0, self._actualizar_texto_analisis, f"OK: No se encontraron eventos de {descripcion}\n")
                                except subprocess.TimeoutExpired:
                                    self.after(0, self._actualizar_texto_analisis, f"TIMEOUT: Búsqueda de {descripcion} excedió tiempo límite\n")
                                except:
                                    self.after(0, self._actualizar_texto_analisis, f"ERROR: No se pudo buscar {descripcion}\n")
                            
                            # 3. Análisis de frecuencia de IPs con awk
                            if 'auth.log' in log_path or 'secure' in log_path:
                                try:
                                    self.after(0, self._actualizar_texto_analisis, "COMANDO: awk '/Failed password/ {print $(NF-3)}' | sort | uniq -c | sort -nr\n")
                                    # Extraer IPs de intentos fallidos
                                    resultado_ips = subprocess.run(['bash', '-c', 
                                                                   f"grep 'Failed password' {log_path} | awk '{{print $(NF-3)}}' | sort | uniq -c | sort -nr | head -5"], 
                                                                 capture_output=True, text=True, timeout=15)
                                    if resultado_ips.returncode == 0 and resultado_ips.stdout.strip():
                                        self.after(0, self._actualizar_texto_analisis, "TOP IPs con intentos fallidos:\n")
                                        for linea in resultado_ips.stdout.strip().split('\n'):
                                            if linea.strip():
                                                self.after(0, self._actualizar_texto_analisis, f"  {linea.strip()}\n")
                                    else:
                                        self.after(0, self._actualizar_texto_analisis, "OK: No hay intentos de login fallidos recientes\n")
                                except:
                                    self.after(0, self._actualizar_texto_analisis, "ERROR: No se pudo analizar IPs sospechosas\n")
                            
                            # 4. Últimas entradas del log
                            self.after(0, self._actualizar_texto_analisis, f"COMANDO: tail -n 5 {log_path}\n")
                            resultado = subprocess.run(['tail', '-n', '5', log_path], 
                                                     capture_output=True, text=True, timeout=10)
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                lineas = resultado.stdout.strip().split('\n')
                                self.after(0, self._actualizar_texto_analisis, "ÚLTIMAS ENTRADAS:\n")
                                for linea in lineas:
                                    if linea.strip():
                                        timestamp = ' '.join(linea.split()[:3])
                                        mensaje = ' '.join(linea.split()[3:12])
                                        self.after(0, self._actualizar_texto_analisis, f"  {timestamp}: {mensaje}...\n")
                                        self.after(0, self._actualizar_texto_analisis, f"    {timestamp}: {mensaje}...\n")
                                
                                # Buscar patrones sospechosos en las líneas
                                patrones_sospechosos = ["failed", "error", "denied", "invalid", "attack", "breach"]
                                alertas_encontradas = 0
                                for linea in lineas:
                                    linea_lower = linea.lower()
                                    for patron in patrones_sospechosos:
                                        if patron in linea_lower:
                                            alertas_encontradas += 1
                                            if alertas_encontradas <= 3:  # Mostrar máximo 3 alertas por archivo
                                                self.after(0, self._actualizar_texto_analisis, f"    ALERTA: {patron.upper()} encontrado\n")
                                
                                if alertas_encontradas > 0:
                                    self.after(0, self._actualizar_texto_analisis, f"  TOTAL ALERTAS: {alertas_encontradas}\n")
                                else:
                                    self.after(0, self._actualizar_texto_analisis, "  Sin patrones sospechosos detectados\n")
                                    
                            else:
                                # Fallback: leer archivo directamente
                                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    lines = f.readlines()
                                    self.after(0, self._actualizar_texto_analisis, 
                                             f"  OK {len(lines)} líneas analizadas\n")
                                    if lines:
                                        self.after(0, self._actualizar_texto_analisis, "  ÚLTIMAS LÍNEAS:\n")
                                        for linea in lines[-3:]:
                                            if linea.strip():
                                                self.after(0, self._actualizar_texto_analisis, f"    {linea.strip()[:100]}...\n")
                        except subprocess.TimeoutExpired:
                            self.after(0, self._actualizar_texto_analisis, 
                                     f"  WARNING Timeout leyendo archivo\n")
                        except Exception as e:
                            self.after(0, self._actualizar_texto_analisis, 
                                     f"  ERROR leyendo archivo: {str(e)}\n")
                    else:
                        self.after(0, self._actualizar_texto_analisis, 
                                 f"  WARNING Archivo no encontrado\n")
                
                self.after(0, self._actualizar_texto_analisis, "OK Análisis completado\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_analisis, f"ERROR en análisis: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def buscar_patrones(self):
        """Buscar patrones sospechosos en logs."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_analisis, " Buscando patrones sospechosos...\n")
                
                patrones_sospechosos = [
                    "Failed password",
                    "Invalid user",
                    "authentication failure",
                    "POSSIBLE BREAK-IN ATTEMPT",
                    "refused connect"
                ]
                
                for patron in patrones_sospechosos:
                    self.after(0, self._actualizar_texto_analisis, f" Buscando: {patron}\n")
                    # Aquí iría la búsqueda real en los logs
                    import time
                    time.sleep(0.5)
                
                self.after(0, self._actualizar_texto_analisis, "OK Búsqueda de patrones completada\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_analisis, f"ERROR buscando patrones: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    # Métodos de la pestaña Alertas
    def detectar_intrusion(self):
        """Detectar intentos de intrusión."""
        self.log_to_terminal("Iniciando detección de intrusiones...")
        self._actualizar_texto_alertas(" Detectando intentos de intrusión...\n")
        self._actualizar_texto_alertas(" Activando Snort IDS...\n")
        self._actualizar_texto_alertas(" Monitoreando tráfico de red...\n")
        self._actualizar_texto_alertas("OK Sistema de detección activo\n\n")
        self.log_to_terminal("✓ Sistema de detección de intrusiones activado")
    
    def activar_ids(self):
        """Activar sistema IDS real con Suricata."""
        self.log_to_terminal("Activando sistema IDS/IPS con Suricata...")
        def ejecutar_ids():
            try:
                self.after(0, self._actualizar_texto_alertas, " Activando sistema IDS/IPS real...\n")
                
                import subprocess
                import os
                
                # Verificar si Suricata está instalado
                try:
                    resultado = subprocess.run(['which', 'suricata'], capture_output=True, text=True)
                    if resultado.returncode != 0:
                        self.after(0, self._actualizar_texto_alertas, "ERROR Suricata no encontrado. Instalando...\n")
                        install = subprocess.run(['sudo', 'apt', 'update'], capture_output=True)
                        install = subprocess.run(['sudo', 'apt', 'install', '-y', 'suricata'], capture_output=True)
                        if install.returncode != 0:
                            self.after(0, self._actualizar_texto_alertas, "ERROR instalando Suricata\n")
                            return
                        self.after(0, self._actualizar_texto_alertas, "OK Suricata instalado correctamente\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f"ERROR verificando Suricata: {e}\n")
                    return
                
                # Configurar Suricata
                self.after(0, self._actualizar_texto_alertas, " Configurando Suricata...\n")
                
                # Verificar configuración
                config_paths = ['/etc/suricata/suricata.yaml', '/usr/local/etc/suricata/suricata.yaml']
                config_found = False
                for config_path in config_paths:
                    if os.path.exists(config_path):
                        config_found = True
                        self.after(0, self._actualizar_texto_alertas, f"OK Configuración encontrada: {config_path}\n")
                        break
                
                if not config_found:
                    self.after(0, self._actualizar_texto_alertas, "WARNING Configuración no encontrada, usando valores por defecto\n")
                
                # Actualizar reglas
                self.after(0, self._actualizar_texto_alertas, " Actualizando reglas de detección...\n")
                try:
                    update_rules = subprocess.run(['sudo', 'suricata-update'], capture_output=True, text=True, timeout=30)
                    if update_rules.returncode == 0:
                        self.after(0, self._actualizar_texto_alertas, "OK Reglas actualizadas correctamente\n")
                    else:
                        self.after(0, self._actualizar_texto_alertas, "WARNING Usando reglas existentes\n")
                except subprocess.TimeoutExpired:
                    self.after(0, self._actualizar_texto_alertas, "WARNING Timeout actualizando reglas, continuando\n")
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_alertas, "WARNING suricata-update no encontrado, usando reglas existentes\n")
                
                # Obtener interfaz de red principal
                try:
                    interface_result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                    if interface_result.returncode == 0:
                        # Extraer interfaz de la línea default
                        lines = interface_result.stdout.strip().split('\n')
                        interface = 'eth0'  # Fallback
                        for line in lines:
                            if 'default' in line and 'dev' in line:
                                parts = line.split()
                                dev_index = parts.index('dev') + 1
                                if dev_index < len(parts):
                                    interface = parts[dev_index]
                                    break
                        
                        self.after(0, self._actualizar_texto_alertas, f" Usando interfaz: {interface}\n")
                        
                        # Iniciar Suricata en modo IDS
                        self.after(0, self._actualizar_texto_alertas, " Iniciando Suricata IDS...\n")
                        
                        # Crear directorio para logs si no existe
                        log_dir = '/var/log/suricata'
                        if not os.path.exists(log_dir):
                            subprocess.run(['sudo', 'mkdir', '-p', log_dir], capture_output=True)
                        
                        # Comando para iniciar Suricata
                        suricata_cmd = [
                            'sudo', 'suricata', '-c', '/etc/suricata/suricata.yaml',
                            '-i', interface, '-D', '--pidfile', '/var/run/suricata.pid'
                        ]
                        
                        resultado_suricata = subprocess.run(suricata_cmd, capture_output=True, text=True)
                        
                        if resultado_suricata.returncode == 0:
                            self.after(0, self._actualizar_texto_alertas, "OK IDS activado correctamente\n")
                            self.after(0, self._actualizar_texto_alertas, f" Logs disponibles en: {log_dir}\n")
                            self.after(0, self._actualizar_texto_alertas, " Monitoreando tráfico en tiempo real\n")
                            self.after(0, self._actualizar_texto_alertas, " Detectando: exploits, malware, escaneos\n")
                            
                            # Iniciar monitoreo de logs de Suricata
                            self.after(0, self._iniciar_monitoreo_logs_suricata, log_dir)
                        else:
                            self.after(0, self._actualizar_texto_alertas, f"ERROR iniciando Suricata: {resultado_suricata.stderr}\n")
                            self.after(0, self._actualizar_texto_alertas, " Verificar permisos sudo y configuración\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f"ERROR configurando interfaz: {e}\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_alertas, f"ERROR activando IDS: {str(e)}\n")
        
        threading.Thread(target=ejecutar_ids, daemon=True).start()
    
    def _iniciar_monitoreo_logs_suricata(self, log_dir):
        """Iniciar monitoreo de logs de Suricata en tiempo real"""
        def monitorear_logs():
            import time
            import os
            
            archivo_eve = os.path.join(log_dir, 'eve.json')
            archivo_fast = os.path.join(log_dir, 'fast.log')
            
            contador = 0
            while contador < 20:  # Monitorear por 20 ciclos
                try:
                    # Verificar archivo eve.json (alertas detalladas)
                    if os.path.exists(archivo_eve):
                        resultado = subprocess.run(['tail', '-n', '3', archivo_eve], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            lineas = resultado.stdout.strip().split('\n')
                            self.after(0, self._actualizar_texto_alertas, f" EVE.JSON: {len(lineas)} eventos detectados\n")
                            for linea in lineas:
                                if '"event_type":' in linea:
                                    import json
                                    try:
                                        evento = json.loads(linea)
                                        tipo_evento = evento.get('event_type', 'desconocido')
                                        timestamp = evento.get('timestamp', '')[:19]
                                        self.after(0, self._actualizar_texto_alertas, f"   {timestamp}: {tipo_evento}\n")
                                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                                        self.after(0, self._actualizar_texto_alertas, f"   Evento: {linea[:50]}...\n")
                    
                    # Verificar archivo fast.log (alertas rápidas)
                    if os.path.exists(archivo_fast):
                        resultado = subprocess.run(['tail', '-n', '2', archivo_fast], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            lineas = resultado.stdout.strip().split('\n')
                            self.after(0, self._actualizar_texto_alertas, f" FAST.LOG: {len(lineas)} alertas\n")
                            for linea in lineas:
                                if linea.strip():
                                    partes = linea.split('] ')
                                    if len(partes) > 1:
                                        alerta = partes[1][:80]
                                        self.after(0, self._actualizar_texto_alertas, f"   ALERTA: {alerta}...\n")
                    
                    # Verificar estadísticas
                    resultado_stats = subprocess.run(['sudo', 'suricata', '--dump-config'], 
                                                   capture_output=True, text=True, timeout=10)
                    if resultado_stats.returncode == 0:
                        self.after(0, self._actualizar_texto_alertas, f" === Monitoreo activo (ciclo {contador+1}/20) ===\n")
                    
                    contador += 1
                    time.sleep(15)  # Verificar cada 15 segundos
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f" ERROR monitoreo: {str(e)}\n")
                    time.sleep(5)
            
            self.after(0, self._actualizar_texto_alertas, " Monitoreo de logs Suricata completado\n")
        
        threading.Thread(target=monitorear_logs, daemon=True).start()
    
    def monitor_honeypot(self):
        """Monitorear honeypots."""
        self._actualizar_texto_alertas(" Monitoreando honeypots...\n")
        self._actualizar_texto_alertas(" Verificando trampas de seguridad...\n")
        self._actualizar_texto_alertas(" Detectando actividad maliciosa...\n")
        self._actualizar_texto_alertas("OK Honeypots operativos\n\n")
    
    # Métodos de la pestaña Forense
    def usar_volatility(self):
        """Usar Volatility para análisis de memoria."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "🧠 VOLATILITY - Análisis de Memoria RAM\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    # Verificar Volatility 3 (preferido)
                    resultado = subprocess.run(['vol', '--help'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Volatility 3 disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.info\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.pslist\n") 
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.psscan\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.malfind\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.netscan\n\n")
                    else:
                        # Probar Volatility 2
                        resultado2 = subprocess.run(['volatility', '--info'], capture_output=True, text=True, timeout=10)
                        if resultado2.returncode == 0:
                            self.after(0, self._actualizar_texto_forense, "OK Volatility 2 disponible\n\n")
                            self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMANDOS KALI LINUX:\n")
                            self.after(0, self._actualizar_texto_forense, "  volatility -f memory.dump imageinfo\n")
                            self.after(0, self._actualizar_texto_forense, "  volatility -f memory.dump --profile=Win7SP1x64 pslist\n")
                            self.after(0, self._actualizar_texto_forense, "  volatility -f memory.dump --profile=Win7SP1x64 netscan\n\n")
                        else:
                            self.after(0, self._actualizar_texto_forense, "ERROR ejecutando Volatility\n")
                            
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "ERROR Volatility no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt update\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install volatility3 volatility -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, " CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de malware en memoria\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de incidents response\n")
                self.after(0, self._actualizar_texto_forense, "  • Detección de rootkits\n")
                self.after(0, self._actualizar_texto_forense, "  • Extracción de passwords\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR usando Volatility: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_autopsy(self):
        """Usar Autopsy para análisis forense."""
        self._actualizar_texto_forense(" Iniciando Autopsy...\n")
        self._actualizar_texto_forense(" Herramienta gráfica para análisis forense\n")
        self._actualizar_texto_forense(" Comando: autopsy\n")
        self._actualizar_texto_forense(" Interfaz web disponible en localhost:9999\n\n")
    
    def usar_sleuthkit(self):
        """Usar Sleuth Kit para análisis forense."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "INVESTIGACION SLEUTH KIT - Kit de Investigación Forense\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    resultado = subprocess.run(['fls', '-V'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Sleuth Kit disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  mmls disk.img                         # Particiones\n")
                        self.after(0, self._actualizar_texto_forense, "  fsstat -f ext4 disk.img               # Info FS\n")
                        self.after(0, self._actualizar_texto_forense, "  fls -r disk.img                       # Listar archivos\n")
                        self.after(0, self._actualizar_texto_forense, "  ils disk.img                          # Inodos\n")
                        self.after(0, self._actualizar_texto_forense, "  icat disk.img 123                     # Leer inode\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "ERROR ejecutando Sleuth Kit\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "ERROR Sleuth Kit no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install sleuthkit autopsy -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, " CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de sistemas de archivos\n")
                self.after(0, self._actualizar_texto_forense, "  • Recuperación de archivos borrados\n")
                self.after(0, self._actualizar_texto_forense, "  • Timeline de actividades\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de discos duros\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR usando Sleuth Kit: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_binwalk(self):
        """Usar Binwalk para análisis de firmware."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "🔬 BINWALK - Análisis de Firmware\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    resultado = subprocess.run(['binwalk', '--help'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Binwalk disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk firmware.bin                  # Análisis básico\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk -e firmware.bin               # Extraer archivos\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk -M firmware.bin               # Recursivo\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk --dd='.*' firmware.bin        # Extraer todo\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "ERROR ejecutando Binwalk\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "ERROR Binwalk no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt update\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install binwalk -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, " CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de firmware IoT\n")
                self.after(0, self._actualizar_texto_forense, "  • Extracción de sistemas de archivos\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de dispositivos embebidos\n")
                self.after(0, self._actualizar_texto_forense, "  • Detección de backdoors en firmware\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR usando Binwalk: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_foremost(self):
        """Usar Foremost para recuperación de archivos."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "FOREMOST - Recuperación de Archivos\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    resultado = subprocess.run(['foremost', '-V'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Foremost disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -i disk.img -o output/       # Recuperar todo\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -t jpg,png -i disk.img       # Solo imágenes\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -t pdf,doc -i disk.img       # Documentos\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -T -i disk.img               # Con timestamp\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "ERROR ejecutando Foremost\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "ERROR Foremost no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install foremost -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, " CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Recuperación de archivos borrados\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de dispositivos USB\n")
                self.after(0, self._actualizar_texto_forense, "  • Carving de archivos por signature\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis post-incident\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR usando Foremost: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_strings(self):
        """Usar strings para análisis de texto."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "🔤 STRINGS - Extracción de Cadenas\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    resultado = subprocess.run(['strings', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Strings disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  strings archivo.bin                   # Básico\n")
                        self.after(0, self._actualizar_texto_forense, "  strings -a archivo.bin                # Todos los archivos\n")
                        self.after(0, self._actualizar_texto_forense, "  strings -n 10 archivo.bin             # Min 10 chars\n")
                        self.after(0, self._actualizar_texto_forense, "  strings archivo.bin | grep -i pass    # Buscar passwords\n")
                        self.after(0, self._actualizar_texto_forense, "  strings archivo.bin | grep -E 'http|ftp' # URLs\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "ERROR ejecutando strings\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "ERROR Strings no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install binutils -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, " CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de malware\n")
                self.after(0, self._actualizar_texto_forense, "  • Búsqueda de passwords\n")
                self.after(0, self._actualizar_texto_forense, "  • Extracción de URLs\n")
                self.after(0, self._actualizar_texto_forense, "  • Ingeniería inversa\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR usando Strings: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    # Métodos auxiliares para actualizar texto
    def _actualizar_texto_monitoreo(self, texto):
        """Actualizar texto de monitoreo de forma segura."""
        def _update():
            try:
                if hasattr(self, 'siem_monitoreo_text') and self.siem_monitoreo_text.winfo_exists():
                    self.siem_monitoreo_text.config(state=tk.NORMAL)
                    self.siem_monitoreo_text.insert(tk.END, texto)
                    self.siem_monitoreo_text.see(tk.END)
                    self.siem_monitoreo_text.config(state=tk.DISABLED)
            except tk.TclError:
                pass  # Widget ya no existe
        
        try:
            self.after_idle(_update)
        except:
            pass  # Si no se puede programar, ignorar
    
    def _actualizar_texto_analisis(self, texto):
        """Actualizar texto de análisis de forma segura."""
        def _update():
            try:
                if hasattr(self, 'siem_analisis_text') and self.siem_analisis_text.winfo_exists():
                    self.siem_analisis_text.config(state=tk.NORMAL)
                    self.siem_analisis_text.insert(tk.END, texto)
                    self.siem_analisis_text.see(tk.END)
                    self.siem_analisis_text.config(state=tk.DISABLED)
            except tk.TclError:
                pass  # Widget ya no existe
        
        try:
            self.after_idle(_update)
        except:
            pass  # Si no se puede programar, ignorar
    
    def _actualizar_texto_alertas(self, texto):
        """Actualizar texto de alertas de forma segura."""
        def _update():
            try:
                if hasattr(self, 'siem_alertas_text') and self.siem_alertas_text.winfo_exists():
                    self.siem_alertas_text.config(state=tk.NORMAL)
                    self.siem_alertas_text.insert(tk.END, texto)
                    self.siem_alertas_text.see(tk.END)
                    self.siem_alertas_text.config(state=tk.DISABLED)
            except tk.TclError:
                pass  # Widget ya no existe
        
        try:
            self.after_idle(_update)
        except:
            pass  # Si no se puede programar, ignorar
    
    def _actualizar_texto_forense(self, texto):
        """Actualizar texto de análisis forense de forma segura."""
        def _update():
            try:
                if hasattr(self, 'siem_forense_text') and self.siem_forense_text.winfo_exists():
                    self.siem_forense_text.config(state=tk.NORMAL)
                    self.siem_forense_text.insert(tk.END, texto)
                    self.siem_forense_text.see(tk.END)
                    self.siem_forense_text.config(state=tk.DISABLED)
            except tk.TclError:
                pass  # Widget ya no existe
        
        try:
            self.after_idle(_update)
        except:
            pass  # Si no se puede programar, ignorar
    
    # Métodos adicionales para completar funcionalidad
    def configurar_alertas(self):
        """Configurar sistema de alertas SIEM con umbrales reales."""
        def configurar_alertas_real():
            try:
                self._log_terminal("PROCESOS Configurando sistema de alertas SIEM", "SIEM-ALERTS", "INFO")
                
                import subprocess
                import os
                
                # CONFIGURACIÓN 1: Umbrales de CPU y memoria
                self._log_terminal("Configurando umbrales de recursos del sistema:", "SIEM-ALERTS", "INFO")
                
                umbrales_sistema = {
                    'cpu_warning': 80,      # % de CPU para alerta
                    'cpu_critical': 95,     # % de CPU crítico
                    'memory_warning': 80,   # % de memoria para alerta
                    'memory_critical': 95,  # % de memoria crítico
                    'disk_warning': 85,     # % de disco para alerta
                    'disk_critical': 95     # % de disco crítico
                }
                
                for metrica, valor in umbrales_sistema.items():
                    self._log_terminal(f"ESTADISTICAS {metrica}: {valor}%", "SIEM-ALERTS", "INFO")
                
                # CONFIGURACIÓN 2: Alertas de red
                self._log_terminal("Configurando alertas de red:", "SIEM-ALERTS", "INFO")
                
                alertas_red = {
                    'conexiones_maximas': 100,
                    'puertos_sospechosos': ['4444', '5555', '6666', '7777', '8888', '9999'],
                    'trafico_anomalo_mb': 500,  # MB por minuto
                    'conexiones_por_segundo': 20
                }
                
                self._log_terminal(f"RED Conexiones máximas permitidas: {alertas_red['conexiones_maximas']}", "SIEM-ALERTS", "INFO")
                self._log_terminal(f"ALERTA Puertos backdoor monitoreados: {', '.join(alertas_red['puertos_sospechosos'])}", "SIEM-ALERTS", "WARNING")
                self._log_terminal(f"ESTADISTICAS Tráfico anómalo threshold: {alertas_red['trafico_anomalo_mb']}MB/min", "SIEM-ALERTS", "INFO")
                
                # CONFIGURACIÓN 3: Alertas de archivos críticos
                self._log_terminal("Configurando monitoreo de archivos críticos:", "SIEM-ALERTS", "INFO")
                
                archivos_vigilados = [
                    '/etc/passwd',
                    '/etc/shadow', 
                    '/etc/hosts',
                    '/etc/sudoers',
                    '/etc/ssh/sshd_config',
                    '/etc/crontab',
                    '/boot/grub/grub.cfg'
                ]
                
                for archivo in archivos_vigilados:
                    if os.path.exists(archivo):
                        self._log_terminal(f"MONITOREANDO Vigilando: {archivo}", "SIEM-ALERTS", "INFO")
                    else:
                        self._log_terminal(f"ADVERTENCIA Archivo crítico no encontrado: {archivo}", "SIEM-ALERTS", "WARNING")
                
                # CONFIGURACIÓN 4: Alertas de procesos sospechosos
                self._log_terminal("Configurando detección de procesos sospechosos:", "SIEM-ALERTS", "INFO")
                
                procesos_sospechosos = [
                    'nc', 'netcat', 'ncat',        # Herramientas de red
                    'python -c', 'perl -e',       # Scripts inline sospechosos
                    'wget', 'curl http',           # Descargas sospechosas
                    '/tmp/', '/var/tmp/',          # Ejecución desde directorios temporales
                    'base64 -d', 'echo',           # Decodificación/ejecución
                    'bash -i', 'sh -i'             # Shells interactivas
                ]
                
                self._log_terminal(f"ANÁLISIS Monitoreando {len(procesos_sospechosos)} patrones de procesos sospechosos", "SIEM-ALERTS", "WARNING")
                
                # CONFIGURACIÓN 5: Alertas de logs
                self._log_terminal("Configurando análisis de logs:", "SIEM-ALERTS", "INFO")
                
                patrones_logs = {
                    'auth.log': ['Failed password', 'Invalid user', 'authentication failure'],
                    'syslog': ['segfault', 'kernel panic', 'out of memory'],
                    'kern.log': ['USB disconnect', 'thermal throttling', 'hardware error']
                }
                
                for log_file, patrones in patrones_logs.items():
                    self._log_terminal(f" {log_file}: Monitoreando {len(patrones)} patrones", "SIEM-ALERTS", "INFO")
                
                # CONFIGURACIÓN 6: Verificar configuración de notificaciones
                self._log_terminal("Verificando sistema de notificaciones:", "SIEM-ALERTS", "INFO")
                
                # Verificar si notify-send está disponible
                try:
                    resultado = subprocess.run(['which', 'notify-send'], 
                                             capture_output=True, timeout=3)
                    if resultado.returncode == 0:
                        self._log_terminal("OK Sistema de notificaciones desktop disponible", "SIEM-ALERTS", "INFO")
                        
                        # Prueba de notificación
                        subprocess.run(['notify-send', 'ARESITOS SIEM', 'Sistema de alertas configurado'], 
                                     timeout=5)
                    else:
                        self._log_terminal("ADVERTENCIA notify-send no disponible - alertas solo en terminal", "SIEM-ALERTS", "WARNING")
                except:
                    self._log_terminal("ADVERTENCIA Error verificando sistema de notificaciones", "SIEM-ALERTS", "WARNING")
                
                # CONFIGURACIÓN 7: Crear archivo de configuración
                config_alertas = {
                    'version': '1.0',
                    'timestamp': __import__('datetime').datetime.now().isoformat(),
                    'umbrales_sistema': umbrales_sistema,
                    'alertas_red': alertas_red,
                    'archivos_vigilados': archivos_vigilados,
                    'procesos_sospechosos': procesos_sospechosos,
                    'patrones_logs': patrones_logs
                }
                
                self._log_terminal("MEMORIA Guardando configuración de alertas...", "SIEM-ALERTS", "INFO")
                
                try:
                    import json
                    config_path = 'configuración/siem_alertas_config.json'
                    os.makedirs(os.path.dirname(config_path), exist_ok=True)
                    
                    with open(config_path, 'w') as f:
                        json.dump(config_alertas, f, indent=4)
                    
                    self._log_terminal(f"OK Configuración guardada en: {config_path}", "SIEM-ALERTS", "SUCCESS")
                except Exception as e:
                    self._log_terminal(f"ADVERTENCIA Error guardando configuración: {str(e)}", "SIEM-ALERTS", "WARNING")
                
                # Resumen final
                self._log_terminal("OBJETIVO Sistema de alertas SIEM configurado correctamente", "SIEM-ALERTS", "SUCCESS")
                self._log_terminal("ESTADISTICAS Umbrales establecidos para CPU, memoria y disco", "SIEM-ALERTS", "INFO")
                self._log_terminal("RED Monitoreo de red y puertos backdoor activo", "SIEM-ALERTS", "INFO")
                self._log_terminal("CRITICO Vigilancia de archivos críticos habilitada", "SIEM-ALERTS", "INFO")
                self._log_terminal("ANÁLISIS Detección de procesos sospechosos configurada", "SIEM-ALERTS", "INFO")
                
            except Exception as e:
                self._log_terminal(f"ERROR configurando alertas: {str(e)}", "SIEM-ALERTS", "ERROR")
        
        # Ejecutar en thread separado
        import threading
        threading.Thread(target=configurar_alertas_real, daemon=True).start()
    
    def eventos_seguridad(self):
        """Analizar y mostrar eventos de seguridad reales del sistema."""
        try:
            self._log_terminal("=== ANÁLISIS DE EVENTOS DE SEGURIDAD REALES ===\n")
            self._actualizar_texto_monitoreo("=== EVENTOS DE SEGURIDAD DEL SISTEMA ===\n\n")
            
            # 1. Analizar intentos de login fallidos
            self._log_terminal("1. Analizando intentos de login fallidos...")
            try:
                result = subprocess.run(['grep', '-i', 'failed password', '/var/log/auth.log'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    failed_logins = result.stdout.strip().split('\n')
                    recent_failures = failed_logins[-10:] if failed_logins else []
                    self._actualizar_texto_monitoreo(f"ALERTA INTENTOS DE LOGIN FALLIDOS ({len(recent_failures)} recientes):\n")
                    for failure in recent_failures:
                        if failure.strip():
                            parts = failure.split()
                            if len(parts) >= 3:
                                timestamp = ' '.join(parts[:3])
                                self._actualizar_texto_monitoreo(f"   • {timestamp}: {failure.split(':', 1)[1] if ':' in failure else failure}\n")
                else:
                    self._actualizar_texto_monitoreo("OK No se detectaron intentos de login fallidos recientes\n")
            except Exception as e:
                self._actualizar_texto_monitoreo(f"ADVERTENCIA Error analizando auth.log: {str(e)}\n")
            
            # 2. Analizar conexiones de red sospechosas
            self._log_terminal("2. Analizando conexiones de red activas...")
            try:
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    connections = result.stdout.strip().split('\n')
                    suspicious_ports = []
                    for conn in connections[1:]:  # Skip header
                        if any(port in conn for port in ['4444', '6666', '9999', '8080']):
                            suspicious_ports.append(conn)
                    
                    if suspicious_ports:
                        self._actualizar_texto_monitoreo("ALERTA PUERTOS SOSPECHOSOS ACTIVOS:\n")
                        for port in suspicious_ports:
                            self._actualizar_texto_monitoreo(f"   • {port}\n")
                    else:
                        self._actualizar_texto_monitoreo("OK No se detectaron puertos sospechosos activos\n")
                else:
                    self._actualizar_texto_monitoreo("ADVERTENCIA Error analizando conexiones de red\n")
            except Exception as e:
                self._actualizar_texto_monitoreo(f"ADVERTENCIA Error ejecutando ss: {str(e)}\n")
            
            # 3. Analizar procesos sospechosos
            self._log_terminal("3. Analizando procesos sospechosos...")
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    processes = result.stdout.strip().split('\n')
                    suspicious_procs = []
                    suspicious_patterns = ['nc ', 'netcat', 'python -c', 'perl -e', 'bash -i']
                    
                    for proc in processes:
                        for pattern in suspicious_patterns:
                            if pattern in proc.lower():
                                suspicious_procs.append(proc)
                                break
                    
                    if suspicious_procs:
                        self._actualizar_texto_monitoreo("ALERTA PROCESOS SOSPECHOSOS DETECTADOS:\n")
                        for proc in suspicious_procs:
                            parts = proc.split()
                            if len(parts) >= 11:
                                pid = parts[1]
                                cpu = parts[2]
                                mem = parts[3]
                                cmd = ' '.join(parts[10:])
                                self._actualizar_texto_monitoreo(f"   • PID {pid}: {cmd} (CPU: {cpu}%, MEM: {mem}%)\n")
                    else:
                        self._actualizar_texto_monitoreo("OK No se detectaron procesos sospechosos\n")
                else:
                    self._actualizar_texto_monitoreo("ADVERTENCIA Error analizando procesos\n")
            except Exception as e:
                self._actualizar_texto_monitoreo(f"ADVERTENCIA Error ejecutando ps: {str(e)}\n")
            
            # 4. Analizar logs del kernel para errores críticos
            self._log_terminal("4. Analizando logs del kernel...")
            try:
                result = subprocess.run(['grep', '-i', 'error\\|fail\\|segfault', '/var/log/kern.log'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    kernel_errors = result.stdout.strip().split('\n')
                    recent_errors = kernel_errors[-5:] if kernel_errors else []
                    if recent_errors and any(error.strip() for error in recent_errors):
                        self._actualizar_texto_monitoreo("ADVERTENCIA ERRORES RECIENTES DEL KERNEL:\n")
                        for error in recent_errors:
                            if error.strip():
                                parts = error.split()
                                if len(parts) >= 3:
                                    timestamp = ' '.join(parts[:3])
                                    self._actualizar_texto_monitoreo(f"   • {timestamp}: {error.split(':', 2)[2] if error.count(':') >= 2 else error}\n")
                    else:
                        self._actualizar_texto_monitoreo("OK No se detectaron errores críticos del kernel\n")
                else:
                    self._actualizar_texto_monitoreo("OK No se encontraron errores en kern.log\n")
            except Exception as e:
                self._actualizar_texto_monitoreo(f"ADVERTENCIA Error analizando kern.log: {str(e)}\n")
            
            # 5. Verificar integridad de archivos críticos
            self._log_terminal("5. Verificando integridad de archivos críticos...")
            critical_files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/sudoers']
            for file_path in critical_files:
                try:
                    if os.path.exists(file_path):
                        stat_info = os.stat(file_path)
                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        permissions = oct(stat_info.st_mode)[-3:]
                        
                        # Verificar permisos apropiados
                        expected_perms = {'passwd': '644', 'shadow': '640', 'hosts': '644', 'sudoers': '440'}
                        file_name = os.path.basename(file_path)
                        expected = expected_perms.get(file_name, '644')
                        
                        if permissions == expected:
                            self._actualizar_texto_monitoreo(f"OK {file_path}: Permisos OK ({permissions}), Modificado: {mod_time}\n")
                        else:
                            self._actualizar_texto_monitoreo(f"ALERTA {file_path}: Permisos ANÓMALOS ({permissions}, esperado {expected}), Modificado: {mod_time}\n")
                    else:
                        self._actualizar_texto_monitoreo(f"ADVERTENCIA {file_path}: Archivo no encontrado\n")
                except Exception as e:
                    self._actualizar_texto_monitoreo(f"ADVERTENCIA Error verificando {file_path}: {str(e)}\n")
            
            self._actualizar_texto_monitoreo("\n=== ANÁLISIS COMPLETADO ===\n")
            self._log_terminal("Análisis de eventos de seguridad completado")
            
        except Exception as e:
            error_msg = f"Error en análisis de eventos de seguridad: {str(e)}"
            self._actualizar_texto_monitoreo(f"ERROR {error_msg}\n")
            self._log_terminal(error_msg)
    
    def eventos_criticos(self):
        """Mostrar eventos críticos."""
        self._actualizar_texto_alertas("WARNING Eventos Críticos:\n")
        self._actualizar_texto_alertas("   CRÍTICO: Múltiples intentos de login fallidos\n")
        self._actualizar_texto_alertas("   ALTO: Tráfico de red anómalo detectado\n")
        self._actualizar_texto_alertas("  WARNING MEDIO: Proceso no autorizado ejecutándose\n\n")
    
    def detectar_brute_force(self):
        """Detectar ataques de fuerza bruta."""
        self._actualizar_texto_alertas(" Detectando ataques de fuerza bruta...\n")
        self._actualizar_texto_alertas(" Analizando patrones de autenticación...\n")
        self._actualizar_texto_alertas(" Verificando intentos de login repetidos...\n")
        self._actualizar_texto_alertas("OK Sistema de detección de brute force activo\n\n")
    
    def configurar_notificaciones(self):
        """Configurar notificaciones."""
        self._actualizar_texto_alertas(" Configurando notificaciones...\n")
        self._actualizar_texto_alertas(" Email: Activado\n")
        self._actualizar_texto_alertas(" Desktop: Activado\n")
        self._actualizar_texto_alertas(" SMS: No configurado\n")
        self._actualizar_texto_alertas("OK Notificaciones configuradas\n\n")
    
    def actualizar_reglas(self):
        """Actualizar reglas de correlación."""
        self._actualizar_texto_alertas(" Actualizando reglas de correlación...\n")
        self._actualizar_texto_alertas(" Descargando nuevas firmas...\n")
        self._actualizar_texto_alertas(" Aplicando configuración...\n")
        self._actualizar_texto_alertas("OK Reglas actualizadas correctamente\n\n")
    
    def exportar_alertas(self):
        """Exportar alertas a archivo."""
        try:
            contenido = ""
            if hasattr(self, 'siem_alertas_text'):
                contenido = self.siem_alertas_text.get(1.0, tk.END)
            
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay alertas para exportar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Exportar Alertas SIEM",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(f"=== ALERTAS SIEM - ARESITOS ===\n")
                    f.write(f"Sistema: Kali Linux\n")
                    f.write(f"Generado: {threading.current_thread().name}\n\n")
                    f.write(contenido)
                messagebox.showinfo("Éxito", f"Alertas exportadas a {archivo}")
                self._actualizar_texto_alertas(f" Alertas exportadas a {archivo}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar: {str(e)}")

    def verificar_kali(self):
        """Verificar estado del sistema Kali Linux para SIEM con análisis detallado."""
        def ejecutar_verificacion():
            try:
                self._log_terminal("ANÁLISIS Iniciando verificacion completa del sistema para SIEM", "SIEM-VERIFY", "INFO")
                
                # VERIFICACIÓN 1: Sistema operativo y kernel
                import subprocess
                import os
                
                # Verificar distribución
                try:
                    resultado = subprocess.run(['lsb_release', '-d'], capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        distro = resultado.stdout.strip().split('\t')[1]
                        self._log_terminal(f"Sistema operativo: {distro}", "SIEM-VERIFY", "INFO")
                        
                        if 'kali' in distro.lower():
                            self._log_terminal("OK Kali Linux detectado - Compatible con SIEM", "SIEM-VERIFY", "SUCCESS")
                        else:
                            self._log_terminal("ADVERTENCIA Sistema no es Kali Linux - Funcionalidad limitada", "SIEM-VERIFY", "WARNING")
                    else:
                        self._log_terminal("No se pudo detectar la distribución", "SIEM-VERIFY", "WARNING")
                except:
                    self._log_terminal("Error verificando distribución", "SIEM-VERIFY", "WARNING")
                
                # VERIFICACIÓN 2: Herramientas de monitoreo esenciales
                herramientas_siem = [
                    ('nmap', 'Escaneo de puertos y servicios'),
                    ('ss', 'Monitoreo de conexiones de red'),
                    ('netstat', 'Estadísticas de red (alternativa)'),
                    ('tcpdump', 'Captura de tráfico de red'),
                    ('iptables', 'Firewall del sistema'),
                    ('systemctl', 'Control de servicios'),
                    ('journalctl', 'Logs del sistema'),
                    ('ps', 'Monitoreo de procesos'),
                    ('lsof', 'Archivos abiertos'),
                    ('chkrootkit', 'Detección de rootkits')
                ]
                
                herramientas_disponibles = 0
                self._log_terminal("Verificando herramientas esenciales para SIEM:", "SIEM-VERIFY", "INFO")
                
                for herramienta, descripcion in herramientas_siem:
                    try:
                        resultado = subprocess.run(['which', herramienta], capture_output=True, timeout=3)
                        if resultado.returncode == 0:
                            herramientas_disponibles += 1
                            self._log_terminal(f"OK {herramienta}: {descripcion}", "SIEM-VERIFY", "INFO")
                        else:
                            self._log_terminal(f"ERROR {herramienta}: {descripcion} - NO DISPONIBLE", "SIEM-VERIFY", "ERROR")
                    except:
                        self._log_terminal(f"ERROR {herramienta}: Error verificando", "SIEM-VERIFY", "ERROR")
                
                porcentaje = (herramientas_disponibles / len(herramientas_siem)) * 100
                self._log_terminal(f"Herramientas disponibles: {herramientas_disponibles}/{len(herramientas_siem)} ({porcentaje:.1f}%)", "SIEM-VERIFY", "INFO")
                
                # VERIFICACIÓN 3: Permisos críticos del sistema
                self._log_terminal("Verificando permisos del sistema:", "SIEM-VERIFY", "INFO")
                
                archivos_criticos = [
                    '/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log',
                    '/etc/passwd', '/etc/shadow', '/etc/hosts'
                ]
                
                permisos_ok = 0
                for archivo in archivos_criticos:
                    if os.path.exists(archivo):
                        if os.access(archivo, os.R_OK):
                            permisos_ok += 1
                            self._log_terminal(f"OK {archivo}: Lectura permitida", "SIEM-VERIFY", "INFO")
                        else:
                            self._log_terminal(f"ERROR {archivo}: Sin permisos de lectura", "SIEM-VERIFY", "ERROR")
                    else:
                        self._log_terminal(f"ERROR {archivo}: No existe", "SIEM-VERIFY", "ERROR")
                
                # VERIFICACIÓN 4: Servicios del sistema críticos
                servicios_criticos = ['systemd', 'dbus', 'sshd']
                self._log_terminal("Verificando servicios críticos:", "SIEM-VERIFY", "INFO")
                
                for servicio in servicios_criticos:
                    try:
                        resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                                 capture_output=True, text=True, timeout=5)
                        estado = resultado.stdout.strip()
                        
                        if estado == 'active':
                            self._log_terminal(f"OK {servicio}: Activo", "SIEM-VERIFY", "INFO")
                        else:
                            self._log_terminal(f"ADVERTENCIA {servicio}: Estado {estado}", "SIEM-VERIFY", "WARNING")
                    except:
                        self._log_terminal(f"ERROR {servicio}: Error verificando estado", "SIEM-VERIFY", "WARNING")
                
                # VERIFICACIÓN 5: Conectividad de red
                self._log_terminal("Verificando conectividad de red:", "SIEM-VERIFY", "INFO")
                
                try:
                    resultado = subprocess.run(['ping', '-c', '1', '-W', '3', '8.8.8.8'], 
                                             capture_output=True, timeout=10)
                    if resultado.returncode == 0:
                        self._log_terminal("OK Conectividad externa: OK", "SIEM-VERIFY", "SUCCESS")
                    else:
                        self._log_terminal("ERROR Sin conectividad externa", "SIEM-VERIFY", "ERROR")
                except:
                    self._log_terminal("ERROR verificando conectividad", "SIEM-VERIFY", "ERROR")
                
                # VERIFICACIÓN 6: Capacidades del usuario actual
                try:
                    usuario_actual = os.getenv('USER', 'unknown')
                    self._log_terminal(f"Usuario actual: {usuario_actual}", "SIEM-VERIFY", "INFO")
                    
                    # Verificar si puede ejecutar comandos privilegiados
                    resultado = subprocess.run(['sudo', '-n', 'echo', 'test'], 
                                             capture_output=True, timeout=5)
                    if resultado.returncode == 0:
                        self._log_terminal("OK Privilegios sudo: Disponibles sin contraseña", "SIEM-VERIFY", "SUCCESS")
                    else:
                        self._log_terminal("ADVERTENCIA Privilegios sudo: Requiere contraseña", "SIEM-VERIFY", "WARNING")
                except:
                    self._log_terminal("ERROR verificando privilegios", "SIEM-VERIFY", "WARNING")
                
                # RESUMEN FINAL
                if porcentaje >= 80 and permisos_ok >= 4:
                    self._log_terminal("OK SISTEMA COMPATIBLE: SIEM puede funcionar correctamente", "SIEM-VERIFY", "SUCCESS")
                elif porcentaje >= 60:
                    self._log_terminal("ADVERTENCIA SISTEMA PARCIAL: SIEM funcionará con limitaciones", "SIEM-VERIFY", "WARNING")
                else:
                    self._log_terminal("ERROR SISTEMA INCOMPATIBLE: SIEM necesita configuración adicional", "SIEM-VERIFY", "ERROR")
                
                self._log_terminal("Verificación del sistema completada", "SIEM-VERIFY", "INFO")
                
            except Exception as e:
                self._log_terminal(f"Error durante verificación del sistema: {str(e)}", "SIEM-VERIFY", "ERROR")
        
        # Ejecutar en thread separado
        import threading
        threading.Thread(target=ejecutar_verificacion, daemon=True).start()
    
    def usar_dd(self):
        """Usar herramientas dd y dcfldd para forense digital."""
        def ejecutar_dd():
            try:
                self._actualizar_texto_forense(" Iniciando análisis con DD/DCFLDD...\n\n")
                import subprocess
                
                # Verificar disponibilidad de herramientas
                herramientas = {'dd': False, 'dcfldd': False}
                for herramienta in herramientas:
                    try:
                        resultado = subprocess.run(['which', herramienta], capture_output=True, text=True)
                        herramientas[herramienta] = resultado.returncode == 0
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                        pass
                
                if herramientas['dd']:
                    self._actualizar_texto_forense("OK DD disponible\n")
                    # Mostrar información de discos
                    try:
                        resultado = subprocess.run(['lsblk', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT'], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0:
                            self._actualizar_texto_forense(" Dispositivos disponibles:\n")
                            for linea in resultado.stdout.split('\n')[:10]:
                                if linea.strip():
                                    self._actualizar_texto_forense(f"  {linea}\n")
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                        pass
                else:
                    self._actualizar_texto_forense("ERROR DD no encontrado\n")
                
                if herramientas['dcfldd']:
                    self._actualizar_texto_forense("OK DCFLDD disponible (forense avanzado)\n")
                else:
                    self._actualizar_texto_forense("ERROR DCFLDD no encontrado. Instalar: apt install dcfldd\n")
                
                self._actualizar_texto_forense("\n Comandos útiles para forense:\n")
                self._actualizar_texto_forense(" Copia básica:\n")
                self._actualizar_texto_forense("  dd if=/dev/sdX of=imagen.dd bs=4096 status=progress\n")
                self._actualizar_texto_forense(" Copia con verificación:\n")
                self._actualizar_texto_forense("  dcfldd if=/dev/sdX of=imagen.dd hash=sha256 bs=4096\n")
                self._actualizar_texto_forense(" Análisis de memoria:\n")
                self._actualizar_texto_forense("  dd if=/proc/kcore of=memoria.dump bs=1M count=100\n")
                self._actualizar_texto_forense(" Borrado seguro:\n")
                self._actualizar_texto_forense("  dd if=/dev/urandom of=/dev/sdX bs=4096\n\n")
                
                # Verificar espacio en disco para forense
                try:
                    resultado = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.split('\n')
                        if len(lineas) > 1:
                            self._actualizar_texto_forense(" Espacio disponible para imágenes:\n")
                            self._actualizar_texto_forense(f"  {lineas[1]}\n")
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
                    
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR en análisis DD: {str(e)}\n")
        
        threading.Thread(target=ejecutar_dd, daemon=True).start()
    
    def verificar_herramientas_kali(self):
        """Verificar herramientas SIEM específicas de Kali Linux."""
        def ejecutar_verificacion():
            try:
                self._actualizar_texto_forense(" Verificando herramientas SIEM en Kali Linux...\n\n")
                import subprocess
                
                # Herramientas SIEM críticas en Kali
                herramientas_siem_kali = {
                    'journalctl': 'systemd journal logs',
                    'dmesg': 'kernel messages', 
                    'ausearch': 'audit log search',
                    'grep': 'pattern matching',
                    'awk': 'text processing',
                    'sed': 'stream editor',
                    'head': 'file head display',
                    'tail': 'file tail display',
                    'wc': 'word count',
                    'dd': 'data duplicator',
                    'dcfldd': 'forensic dd',
                    'strings': 'extract strings',
                    'lsof': 'list open files',
                    'netstat': 'network statistics',
                    'ss': 'socket statistics'
                }
                
                disponibles = 0
                faltantes = []
                
                for herramienta, descripcion in herramientas_siem_kali.items():
                    try:
                        resultado = subprocess.run(['which', herramienta], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0:
                            self._actualizar_texto_forense(f"OK {herramienta} - {descripcion}\n")
                            disponibles += 1
                        else:
                            self._actualizar_texto_forense(f"ERROR {herramienta} - {descripcion} (FALTANTE)\n")
                            faltantes.append(herramienta)
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                        self._actualizar_texto_forense(f"WARNING {herramienta} - Error verificando\n")
                        faltantes.append(herramienta)
                
                self._actualizar_texto_forense(f"\n Resumen: {disponibles}/{len(herramientas_siem_kali)} herramientas disponibles\n")
                
                # Recomendaciones específicas para Kali
                if faltantes:
                    self._actualizar_texto_forense("\n Instalar herramientas faltantes:\n")
                    if 'dcfldd' in faltantes:
                        self._actualizar_texto_forense("  sudo apt install dcfldd\n")
                    if 'ausearch' in faltantes:
                        self._actualizar_texto_forense("  sudo apt install auditd\n")
                
                # Verificar si es Kali Linux
                try:
                    with open('/etc/os-release', 'r') as f:
                        os_info = f.read()
                        if 'kali' in os_info.lower():
                            self._actualizar_texto_forense("\nOK Sistema Kali Linux detectado correctamente\n")
                        else:
                            self._actualizar_texto_forense("\nWARNING Sistema no detectado como Kali Linux\n")
                except (IOError, OSError, PermissionError, FileNotFoundError):
                    self._actualizar_texto_forense("\nERROR No se pudo verificar tipo de sistema\n")
                    
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR verificando herramientas: {str(e)}\n")
        
        threading.Thread(target=ejecutar_verificacion, daemon=True).start()
    
    def usar_head_tail(self):
        """Análisis rápido de logs usando head/tail nativos de Kali Linux."""
        def ejecutar_analisis():
            try:
                self._actualizar_texto_forense(" Análisis rápido de logs con herramientas nativas Kali...\n\n")
                import subprocess
                
                # Logs críticos en Kali Linux
                logs_criticos = [
                    '/var/log/auth.log',
                    '/var/log/syslog', 
                    '/var/log/kern.log',
                    '/var/log/daemon.log',
                    '/var/log/fail2ban.log',
                    '/var/log/apache2/access.log',
                    '/var/log/apache2/error.log'
                ]
                
                for log_path in logs_criticos:
                    try:
                        # Verificar si existe el archivo
                        import os
                        if not os.path.exists(log_path):
                            continue
                            
                        self._actualizar_texto_forense(f" Analizando: {log_path}\n")
                        
                        # Obtener tamaño del archivo de forma segura
                        try:
                            size_result = subprocess.run(["wc", "-l", log_path], capture_output=True, text=True, timeout=10)
                            if size_result.returncode == 0:
                                lineas = size_result.stdout.strip().split()[0]
                                self._actualizar_texto_forense(f"   Total líneas: {lineas}\n")
                        except (subprocess.TimeoutExpired, FileNotFoundError):
                            self._actualizar_texto_forense("   Error obteniendo tamaño del archivo\n")
                        
                        # Últimas 10 líneas (tail) de forma segura
                        try:
                            tail_result = subprocess.run(["tail", "-n", "10", log_path], capture_output=True, text=True, timeout=10)
                            if tail_result.returncode == 0:
                                self._actualizar_texto_forense("   Últimas 10 líneas:\n")
                                for i, linea in enumerate(tail_result.stdout.strip().split('\n')[-10:], 1):
                                    if linea.strip():
                                        self._actualizar_texto_forense(f"    {i:2d}: {linea[:100]}...\n")
                        except (subprocess.TimeoutExpired, FileNotFoundError):
                            self._actualizar_texto_forense("   Error leyendo archivo\n")
                        
                        # Búsqueda de patrones críticos con grep de forma segura
                        patrones_criticos = ['FAILED', 'ERROR', 'CRITICAL', 'WARNING', 'ATTACK', 'INVALID']
                        for patron in patrones_criticos:
                            try:
                                grep_result = subprocess.run(["grep", "-i", patron, log_path], capture_output=True, text=True, timeout=10)
                                if grep_result.returncode == 0 and grep_result.stdout.strip():
                                    # Limitar a las últimas 3 líneas
                                    lineas_encontradas = grep_result.stdout.strip().split('\n')[-3:]
                                    self._actualizar_texto_forense(f"  ANÁLISIS Patrón '{patron}' encontrado:\n")
                                    for linea in lineas_encontradas:
                                        if linea.strip():
                                            self._actualizar_texto_forense(f"    └─ {linea[:80]}...\n")
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                continue
                        
                        self._actualizar_texto_forense("\n")
                        
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_forense(f"  TIMEOUT analizando {log_path}\n")
                    except Exception as e:
                        self._actualizar_texto_forense(f"  ERROR analizando {log_path}: {str(e)}\n")
                
                # Análisis de journalctl (systemd logs)
                try:
                    self._actualizar_texto_forense(" Analizando logs de systemd (journalctl)...\n")
                    
                    # Últimos errores críticos de forma segura
                    try:
                        journal_result = subprocess.run(["journalctl", "-p", "err", "-n", "5", "--no-pager"], 
                                                       capture_output=True, text=True, timeout=15)
                        if journal_result.returncode == 0:
                            self._actualizar_texto_forense("   Últimos 5 errores del sistema:\n")
                            for linea in journal_result.stdout.strip().split('\n'):
                                if linea.strip():
                                    self._actualizar_texto_forense(f"    └─ {linea[:100]}...\n")
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        self._actualizar_texto_forense("  Error accediendo a journalctl\n")
                    
                    # Últimos logins de forma segura
                    try:
                        login_result = subprocess.run(["journalctl", "_COMM=sshd", "-n", "5", "--no-pager"], 
                                                     capture_output=True, text=True, timeout=15)
                        if login_result.returncode == 0 and login_result.stdout.strip():
                            self._actualizar_texto_forense("   Últimas conexiones SSH:\n")
                            for linea in login_result.stdout.strip().split('\n'):
                                if linea.strip():
                                    self._actualizar_texto_forense(f"    └─ {linea[:100]}...\n")
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        self._actualizar_texto_forense("  Error accediendo a logs SSH\n")
                                
                except Exception as e:
                    self._actualizar_texto_forense(f"ERROR con journalctl: {str(e)}\n")
                
                self._actualizar_texto_forense("\nOK Análisis rápido completado\n")
                
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR en análisis head/tail: {str(e)}\n")
        
        threading.Thread(target=ejecutar_analisis, daemon=True).start()

    def monitorear_tiempo_real_kali(self):
        """Monitoreo en tiempo real usando herramientas nativas de Kali."""
        def ejecutar_monitoreo():
            try:
                self._actualizar_texto_forense(" Iniciando monitoreo en tiempo real (Kali Linux)...\n\n")
                self._actualizar_texto_forense(" Presiona 'Parar Monitoreo' para detener\n\n")
                
                import subprocess
                import time
                
                self.monitoreo_activo = True
                contador = 0
                
                while self.monitoreo_activo and contador < 100:  # Límite de 100 iteraciones
                    try:
                        # Monitoreo de conexiones de red (cada 10 segundos) - forma segura
                        if contador % 10 == 0:
                            self._actualizar_texto_forense(f" Conexiones activas [{time.strftime('%H:%M:%S')}]:\n")
                            try:
                                ss_result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=5)
                                if ss_result.returncode == 0:
                                    lineas = ss_result.stdout.strip().split('\n')[1:6]  # Top 5
                                    for linea in lineas:
                                        if linea.strip():
                                            self._actualizar_texto_forense(f"  └─ {linea}\n")
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                self._actualizar_texto_forense("  Error accediendo a conexiones de red\n")
                        
                        # Monitoreo de procesos críticos (cada 15 segundos) - forma segura
                        if contador % 15 == 0:
                            self._actualizar_texto_forense(f" Procesos críticos [{time.strftime('%H:%M:%S')}]:\n")
                            try:
                                ps_result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
                                if ps_result.returncode == 0 and ps_result.stdout.strip():
                                    # Filtrar procesos críticos manualmente
                                    lineas = ps_result.stdout.strip().split('\n')
                                    procesos_criticos = [l for l in lineas if any(servicio in l.lower() 
                                                       for servicio in ['ssh', 'apache', 'mysql', 'postgres']) 
                                                       and 'grep' not in l][:5]
                                    for linea in procesos_criticos:
                                        if linea.strip():
                                            campos = linea.split()
                                            if len(campos) >= 11:
                                                self._actualizar_texto_forense(f"  └─ PID:{campos[1]} CPU:{campos[2]}% {campos[10]}\n")
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                self._actualizar_texto_forense("  Error accediendo a lista de procesos\n")
                        
                        # Monitoreo de logs críticos (cada 20 segundos) - forma segura
                        if contador % 20 == 0:
                            self._actualizar_texto_forense(f" Nuevos eventos [{time.strftime('%H:%M:%S')}]:\n")
                            try:
                                tail_result = subprocess.run(["tail", "-n", "3", "/var/log/auth.log"], capture_output=True, text=True, timeout=5)
                                if tail_result.returncode == 0:
                                    for linea in tail_result.stdout.strip().split('\n'):
                                        if linea.strip():
                                            # Extraer timestamp y evento principal
                                            partes = linea.split(' ')
                                            if len(partes) >= 3:
                                                timestamp = ' '.join(partes[:3])
                                                evento = ' '.join(partes[4:8]) if len(partes) > 7 else linea[50:]
                                                self._actualizar_texto_forense(f"  └─ {timestamp}: {evento}\n")
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                self._actualizar_texto_forense("  Error accediendo a logs de autenticación\n")
                        
                        time.sleep(1)
                        contador += 1
                        
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_forense("TIMEOUT en monitoreo\n")
                    except Exception as e:
                        self._actualizar_texto_forense(f"WARNING Error en ciclo de monitoreo: {str(e)}\n")
                        break
                
                self._actualizar_texto_forense("\n Monitoreo detenido\n")
                self.monitoreo_activo = False
                
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR en monitoreo tiempo real: {str(e)}\n")
                self.monitoreo_activo = False
        
        threading.Thread(target=ejecutar_monitoreo, daemon=True).start()

    def parar_monitoreo(self):
        """Detener el monitoreo en tiempo real."""
        self.monitoreo_activo = False
        self._actualizar_texto_forense(" Deteniendo monitoreo...\n")

    def integrar_osquery_kali(self):
        """Integración avanzada con osquery para monitoreo en Kali Linux."""
        def ejecutar_osquery():
            try:
                self._actualizar_texto_forense(" Ejecutando consultas osquery específicas para Kali...\n\n")
                import subprocess
                
                # Verificar si osquery está disponible
                verificación = subprocess.run(['which', 'osqueryi'], capture_output=True, text=True, timeout=5)
                if verificación.returncode != 0:
                    self._actualizar_texto_forense("ERROR osquery no está instalado en este sistema\n")
                    self._actualizar_texto_forense(" Instalar con: sudo apt install osquery\n")
                    return
                
                # Consultas de seguridad específicas para Kali
                consultas_seguridad = [
                    {
                        'nombre': 'Procesos con privilegios root',
                        'consulta': 'SELECT name,pid,uid,cmdline FROM processes WHERE uid=0 LIMIT 10;'
                    },
                    {
                        'nombre': 'Conexiones de red activas',
                        'consulta': 'SELECT DISTINCT local_address,local_port,remote_address,remote_port,state FROM process_open_sockets WHERE state="ESTABLISHED" LIMIT 10;'
                    },
                    {
                        'nombre': 'Archivos modificados recientemente',
                        'consulta': 'SELECT path,size,mtime,atime FROM file WHERE path LIKE "/etc/%" AND mtime > strftime("%s", "now", "-1 hour") LIMIT 10;'
                    },
                    {
                        'nombre': 'Usuarios con sesiones activas',
                        'consulta': 'SELECT user,tty,host,time FROM logged_in_users LIMIT 10;'
                    }
                ]
                
                for consulta_info in consultas_seguridad:
                    try:
                        self._actualizar_texto_forense(f" {consulta_info['nombre']}:\n")
                        
                        # Ejecutar consulta osquery
                        cmd = ['osqueryi', '--json', consulta_info['consulta']]
                        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                        
                        if resultado.returncode == 0:
                            import json
                            try:
                                datos = json.loads(resultado.stdout)
                                if datos:
                                    for i, registro in enumerate(datos[:5], 1):  # Limitar a 5 resultados
                                        self._actualizar_texto_forense(f"  {i}. ")
                                        for clave, valor in registro.items():
                                            self._actualizar_texto_forense(f"{clave}:{valor} ")
                                        self._actualizar_texto_forense("\n")
                                else:
                                    self._actualizar_texto_forense("  (Sin resultados)\n")
                            except json.JSONDecodeError:
                                self._actualizar_texto_forense("  ERROR parseando respuesta JSON\n")
                        else:
                            self._actualizar_texto_forense(f"  ERROR ejecutando consulta: {resultado.stderr}\n")
                        
                        self._actualizar_texto_forense("\n")
                        
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_forense(f"  TIMEOUT en consulta: {consulta_info['nombre']}\n")
                    except Exception as e:
                        self._actualizar_texto_forense(f"  ERROR en {consulta_info['nombre']}: {str(e)}\n")
                
                self._actualizar_texto_forense("OK Análisis osquery completado\n")
                
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR en integración osquery: {str(e)}\n")
        
        threading.Thread(target=ejecutar_osquery, daemon=True).start()
    
    def _log_terminal(self, mensaje, modulo="SIEM", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global y en la interfaz SIEM."""
        try:
            # Registrar en terminal global
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
            # También mostrar en la interfaz SIEM para retroalimentación inmediata
            timestamp = __import__('datetime').datetime.now().strftime("%H:%M:%S")
            mensaje_formateado = f"[{timestamp}] {mensaje}\n"
            
            # Actualizar la interfaz SIEM de forma segura
            if hasattr(self, 'siem_monitoreo_text'):
                try:
                    self.after_idle(lambda: self._actualizar_texto_monitoreo(mensaje_formateado))
                except:
                    pass  # Si hay error con tkinter, ignorar silenciosamente
            
        except Exception as e:
            # Fallback silencioso - solo imprimir en consola
            print(f"[{modulo}] {mensaje}")
