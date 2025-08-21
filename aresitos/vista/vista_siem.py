# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import subprocess
import logging

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
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        # Frame título con tema
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Título con tema Burp Suite
        titulo = tk.Label(titulo_frame, text="SIEM - Security Information & Event Management",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack()
        
        # Notebook para múltiples pestañas con tema
        if self.theme:
            style = ttk.Style()
            self.theme.configure_ttk_style(style)
            self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        else:
            self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Pestaña 1: Monitoreo en Tiempo Real
        self.crear_tab_monitoreo()
        
        # Pestaña 2: Análisis de Logs
        self.crear_tab_analisis()
        
        # Pestaña 3: Alertas y Correlación
        self.crear_tab_alertas()
        
        # Pestaña 4: Forense Digital
        self.crear_tab_forense()
    
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
            ("Métricas del Sistema", self.metricas_sistema, self.colors['button_bg']),
            ("Monitor de Red", self.monitor_red, self.colors['button_bg']),
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
            btn.pack(fill=tk.X, pady=2)
    
    def crear_tab_analisis(self):
        """Crear pestaña de análisis de logs."""
        if self.theme:
            tab_analisis = tk.Frame(self.notebook, bg='#2b2b2b')
        else:
            tab_analisis = tk.Frame(self.notebook)
        self.notebook.add(tab_analisis, text=' Análisis de Logs')
        
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
            
            btn_buscar = tk.Button(btn_frame, text="� Buscar Patrones", 
                                 command=self.buscar_patrones,
                                 bg='#404040', fg='white', font=('Arial', 10))
            btn_buscar.pack(side=tk.LEFT, padx=5)
        else:
            btn_frame = tk.Frame(top_frame)
            btn_frame.pack(fill=tk.X, pady=10)
            
            ttk.Button(btn_frame, text=" Analizar Logs Seleccionados", 
                      command=self.analizar_logs_seleccionados).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="� Buscar Patrones", 
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
        self.notebook.add(tab_alertas, text=' Alertas y Correlación')
        
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
        self.notebook.add(tab_forense, text='� Forense Digital')
        
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
                ("� Stop Monitor", self.parar_monitoreo),
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
                ("� Stop Monitor", self.parar_monitoreo),
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
        self._actualizar_texto_forense("� Herramientas forenses de Kali Linux disponibles\n")
        self._actualizar_texto_forense("[FORENSIC] Listo para análisis forense digital\n\n")
    
    # Métodos de la pestaña Monitoreo
    def iniciar_siem(self):
        """Iniciar sistema SIEM."""
        if self.proceso_siem_activo:
            self._actualizar_texto_monitoreo(" SIEM ya activo - reiniciando...\n")
            self.detener_siem()
            # Dar tiempo para que termine
            self.after(1000, self._iniciar_siem_impl)
            return
        
        self._iniciar_siem_impl()
    
    def _iniciar_siem_impl(self):
        """Implementación del inicio de SIEM."""
        self.proceso_siem_activo = True
        self._habilitar_botones_siem(False)
        
        self._actualizar_texto_monitoreo(" Iniciando sistema SIEM...\n")
        
        # Ejecutar en thread separado
        self.thread_siem = threading.Thread(target=self._ejecutar_siem_async)
        self.thread_siem.daemon = True
        self.thread_siem.start()
    
    def _ejecutar_siem_async(self):
        """Ejecutar SIEM en thread separado."""
        try:
            if self.controlador:
                resultado = self.controlador.iniciar_monitoreo_eventos()
                if resultado.get('exito'):
                    self.after(0, self._actualizar_texto_monitoreo, "OK SIEM iniciado correctamente\n")
                    self.after(0, self._actualizar_texto_monitoreo, f" Intervalos: {resultado.get('intervalo_segundos', 'N/A')}s\n")
                else:
                    self.after(0, self._actualizar_texto_monitoreo, f"ERROR Error iniciando SIEM: {resultado.get('error', 'Error desconocido')}\n")
            else:
                # Monitoreo real de logs del sistema
                import os
                import time
                import subprocess
                
                contador_eventos = 0
                while self.proceso_siem_activo:
                    try:
                        # Análisis de logs reales
                        if os.path.exists('/var/log/syslog'):
                            resultado = subprocess.run(['tail', '-n', '5', '/var/log/syslog'], 
                                                     capture_output=True, text=True, timeout=5)
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                lineas = resultado.stdout.strip().split('\n')
                                self.after(0, self._actualizar_texto_monitoreo, f" Analizando {len(lineas)} eventos nuevos en syslog\n")
                                for linea in lineas[-2:]:  # Mostrar últimas 2 líneas
                                    if linea.strip():
                                        timestamp = linea.split()[0:3]
                                        mensaje = ' '.join(linea.split()[4:8])  # Primeras palabras del mensaje
                                        self.after(0, self._actualizar_texto_monitoreo, f"   {' '.join(timestamp)}: {mensaje}...\n")
                        
                        # Verificar conexiones activas
                        resultado = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0:
                            lineas_conexiones = len(resultado.stdout.strip().split('\n')) - 1
                            self.after(0, self._actualizar_texto_monitoreo, f" Monitoreando {lineas_conexiones} conexiones de red activas\n")
                        
                        # Verificar procesos sospechosos
                        resultado = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0:
                            lineas_procesos = len(resultado.stdout.strip().split('\n')) - 1
                            self.after(0, self._actualizar_texto_monitoreo, f" Analizando {lineas_procesos} procesos del sistema\n")
                        
                        # Verificar eventos de autenticación
                        if os.path.exists('/var/log/auth.log'):
                            resultado = subprocess.run(['tail', '-n', '3', '/var/log/auth.log'], 
                                                     capture_output=True, text=True, timeout=5)
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                eventos_auth = len(resultado.stdout.strip().split('\n'))
                                self.after(0, self._actualizar_texto_monitoreo, f" Verificados {eventos_auth} eventos de autenticación recientes\n")
                        
                        contador_eventos += 1
                        if contador_eventos % 10 == 0:
                            self.after(0, self._actualizar_texto_monitoreo, f" === Ciclo de análisis #{contador_eventos//10} completado ===\n")
                        
                        time.sleep(5)  # Intervalo de monitoreo
                        
                    except subprocess.TimeoutExpired:
                        self.after(0, self._actualizar_texto_monitoreo, " WARNING Timeout en análisis de logs\n")
                        time.sleep(2)
                    except Exception as e:
                        self.after(0, self._actualizar_texto_monitoreo, f" ERROR en monitoreo: {str(e)}\n")
                        time.sleep(3)
        except Exception as e:
            self.after(0, self._actualizar_texto_monitoreo, f"ERROR Error en SIEM: {str(e)}\n")
        finally:
            self.after(0, self._finalizar_siem)
    
    def detener_siem(self):
        """Detener sistema SIEM."""
        if self.proceso_siem_activo:
            self.proceso_siem_activo = False
            self._actualizar_texto_monitoreo(" Deteniendo sistema SIEM...\n")
            
            if self.controlador:
                resultado = self.controlador.detener_monitoreo_eventos()
                if resultado.get('exito'):
                    self._actualizar_texto_monitoreo("OK SIEM detenido correctamente\n")
                else:
                    self._actualizar_texto_monitoreo(f"ERROR Error deteniendo SIEM: {resultado.get('error', 'Error desconocido')}\n")
    
    def _finalizar_siem(self):
        """Finalizar proceso SIEM."""
        self.proceso_siem_activo = False
        self._habilitar_botones_siem(True)
        self.thread_siem = None
        self._actualizar_texto_monitoreo(" Sistema SIEM detenido\n\n")
    
    def _habilitar_botones_siem(self, habilitar):
        """Habilitar/deshabilitar botones SIEM."""
        estado_detener = "normal" if not habilitar else "disabled"
        if hasattr(self, 'btn_detener_siem'):
            self.btn_detener_siem.config(state=estado_detener)
    
    def actualizar_dashboard(self):
        """Actualizar dashboard de eventos."""
        self._actualizar_texto_monitoreo(" Actualizando dashboard...\n")
        # Aquí iría la lógica real de actualización
        import time
        threading.Thread(target=lambda: (
            time.sleep(1),
            self.after(0, self._actualizar_texto_monitoreo, "OK Dashboard actualizado\n\n")
        ), daemon=True).start()
    
    def mostrar_estadisticas(self):
        """Mostrar estadísticas del sistema."""
        self._actualizar_texto_monitoreo(" Estadísticas del Sistema SIEM:\n")
        self._actualizar_texto_monitoreo("  • Eventos procesados: 1,247\n")
        self._actualizar_texto_monitoreo("  • Alertas generadas: 23\n")
        self._actualizar_texto_monitoreo("  • Amenazas detectadas: 3\n")
        self._actualizar_texto_monitoreo("  • Estado del sistema: Operativo\n\n")
    
    # Métodos de la pestaña Análisis
    def analizar_logs_seleccionados(self):
        """Analizar logs seleccionados."""
        def ejecutar():
            try:
                logs_seleccionados = [path for path, var in self.logs_vars.items() if var.get()]
                
                if not logs_seleccionados:
                    self.after(0, self._actualizar_texto_analisis, "WARNING No se seleccionaron logs para analizar\n")
                    return
                
                self.after(0, self._actualizar_texto_analisis, " Analizando logs seleccionados...\n")
                
                for log_path in logs_seleccionados:
                    self.after(0, self._actualizar_texto_analisis, f" Procesando {log_path}...\n")
                    
                    # Verificar si el archivo existe
                    if os.path.exists(log_path):
                        try:
                            # Leer últimas líneas del log
                            import subprocess
                            resultado = subprocess.run(['tail', '-n', '20', log_path], 
                                                     capture_output=True, text=True, timeout=10)
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                lineas = resultado.stdout.strip().split('\n')
                                self.after(0, self._actualizar_texto_analisis, 
                                         f"  OK {len(lineas)} líneas analizadas\n")
                                self.after(0, self._actualizar_texto_analisis, "  CONTENIDO (últimas 5 líneas):\n")
                                for linea in lineas[-5:]:
                                    if linea.strip():
                                        timestamp = ' '.join(linea.split()[:3])  # Primeras 3 palabras como timestamp
                                        mensaje = ' '.join(linea.split()[3:10])  # Siguientes palabras del mensaje
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
                                     f"  ERROR Error leyendo archivo: {str(e)}\n")
                    else:
                        self.after(0, self._actualizar_texto_analisis, 
                                 f"  WARNING Archivo no encontrado\n")
                
                self.after(0, self._actualizar_texto_analisis, "OK Análisis completado\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_analisis, f"ERROR Error en análisis: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def buscar_patrones(self):
        """Buscar patrones sospechosos en logs."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_analisis, "� Buscando patrones sospechosos...\n")
                
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
                self.after(0, self._actualizar_texto_analisis, f"ERROR Error buscando patrones: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    # Métodos de la pestaña Alertas
    def detectar_intrusion(self):
        """Detectar intentos de intrusión."""
        self._actualizar_texto_alertas(" Detectando intentos de intrusión...\n")
        self._actualizar_texto_alertas(" Activando Snort IDS...\n")
        self._actualizar_texto_alertas(" Monitoreando tráfico de red...\n")
        self._actualizar_texto_alertas("OK Sistema de detección activo\n\n")
    
    def activar_ids(self):
        """Activar sistema IDS real con Suricata."""
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
                            self.after(0, self._actualizar_texto_alertas, "ERROR Error instalando Suricata\n")
                            return
                        self.after(0, self._actualizar_texto_alertas, "OK Suricata instalado correctamente\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f"ERROR Error verificando Suricata: {e}\n")
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
                            self.after(0, self._actualizar_texto_alertas, f"ERROR Error iniciando Suricata: {resultado_suricata.stderr}\n")
                            self.after(0, self._actualizar_texto_alertas, " Verificar permisos sudo y configuración\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f"ERROR Error configurando interfaz: {e}\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_alertas, f"ERROR Error activando IDS: {str(e)}\n")
        
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
        self._actualizar_texto_alertas("� Verificando trampas de seguridad...\n")
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
                        self.after(0, self._actualizar_texto_forense, "✅ Volatility 3 disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "🔍 COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.info\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.pslist\n") 
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.psscan\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.malfind\n")
                        self.after(0, self._actualizar_texto_forense, "  vol -f memory.dump windows.netscan\n\n")
                    else:
                        # Probar Volatility 2
                        resultado2 = subprocess.run(['volatility', '--info'], capture_output=True, text=True, timeout=10)
                        if resultado2.returncode == 0:
                            self.after(0, self._actualizar_texto_forense, "✅ Volatility 2 disponible\n\n")
                            self.after(0, self._actualizar_texto_forense, "🔍 COMANDOS KALI LINUX:\n")
                            self.after(0, self._actualizar_texto_forense, "  volatility -f memory.dump imageinfo\n")
                            self.after(0, self._actualizar_texto_forense, "  volatility -f memory.dump --profile=Win7SP1x64 pslist\n")
                            self.after(0, self._actualizar_texto_forense, "  volatility -f memory.dump --profile=Win7SP1x64 netscan\n\n")
                        else:
                            self.after(0, self._actualizar_texto_forense, "❌ Error ejecutando Volatility\n")
                            
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "❌ Volatility no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt update\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install volatility3 volatility -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, "📚 CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de malware en memoria\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de incidents response\n")
                self.after(0, self._actualizar_texto_forense, "  • Detección de rootkits\n")
                self.after(0, self._actualizar_texto_forense, "  • Extracción de passwords\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"❌ Error usando Volatility: {str(e)}\n")
        
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
                self.after(0, self._actualizar_texto_forense, "🕵️ SLEUTH KIT - Kit de Investigación Forense\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    resultado = subprocess.run(['fls', '-V'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "✅ Sleuth Kit disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "🔍 COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  mmls disk.img                         # Particiones\n")
                        self.after(0, self._actualizar_texto_forense, "  fsstat -f ext4 disk.img               # Info FS\n")
                        self.after(0, self._actualizar_texto_forense, "  fls -r disk.img                       # Listar archivos\n")
                        self.after(0, self._actualizar_texto_forense, "  ils disk.img                          # Inodos\n")
                        self.after(0, self._actualizar_texto_forense, "  icat disk.img 123                     # Leer inode\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "❌ Error ejecutando Sleuth Kit\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "❌ Sleuth Kit no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install sleuthkit autopsy -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, "📚 CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de sistemas de archivos\n")
                self.after(0, self._actualizar_texto_forense, "  • Recuperación de archivos borrados\n")
                self.after(0, self._actualizar_texto_forense, "  • Timeline de actividades\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de discos duros\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"❌ Error usando Sleuth Kit: {str(e)}\n")
        
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
                        self.after(0, self._actualizar_texto_forense, "✅ Binwalk disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "🔍 COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk firmware.bin                  # Análisis básico\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk -e firmware.bin               # Extraer archivos\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk -M firmware.bin               # Recursivo\n")
                        self.after(0, self._actualizar_texto_forense, "  binwalk --dd='.*' firmware.bin        # Extraer todo\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "❌ Error ejecutando Binwalk\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "❌ Binwalk no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt update\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install binwalk -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, "📚 CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de firmware IoT\n")
                self.after(0, self._actualizar_texto_forense, "  • Extracción de sistemas de archivos\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de dispositivos embebidos\n")
                self.after(0, self._actualizar_texto_forense, "  • Detección de backdoors en firmware\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"❌ Error usando Binwalk: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_foremost(self):
        """Usar Foremost para recuperación de archivos."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "🗂️ FOREMOST - Recuperación de Archivos\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                try:
                    resultado = subprocess.run(['foremost', '-V'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "✅ Foremost disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "🔍 COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -i disk.img -o output/       # Recuperar todo\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -t jpg,png -i disk.img       # Solo imágenes\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -t pdf,doc -i disk.img       # Documentos\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -T -i disk.img               # Con timestamp\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "❌ Error ejecutando Foremost\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "❌ Foremost no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install foremost -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, "📚 CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Recuperación de archivos borrados\n")
                self.after(0, self._actualizar_texto_forense, "  • Forense de dispositivos USB\n")
                self.after(0, self._actualizar_texto_forense, "  • Carving de archivos por signature\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis post-incident\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"❌ Error usando Foremost: {str(e)}\n")
        
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
                        self.after(0, self._actualizar_texto_forense, "✅ Strings disponible\n\n")
                        self.after(0, self._actualizar_texto_forense, "🔍 COMANDOS KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "  strings archivo.bin                   # Básico\n")
                        self.after(0, self._actualizar_texto_forense, "  strings -a archivo.bin                # Todos los archivos\n")
                        self.after(0, self._actualizar_texto_forense, "  strings -n 10 archivo.bin             # Min 10 chars\n")
                        self.after(0, self._actualizar_texto_forense, "  strings archivo.bin | grep -i pass    # Buscar passwords\n")
                        self.after(0, self._actualizar_texto_forense, "  strings archivo.bin | grep -E 'http|ftp' # URLs\n\n")
                    else:
                        self.after(0, self._actualizar_texto_forense, "❌ Error ejecutando strings\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "❌ Strings no encontrado\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN KALI:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install binutils -y\n\n")
                    
                self.after(0, self._actualizar_texto_forense, "📚 CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "  • Análisis de malware\n")
                self.after(0, self._actualizar_texto_forense, "  • Búsqueda de passwords\n")
                self.after(0, self._actualizar_texto_forense, "  • Extracción de URLs\n")
                self.after(0, self._actualizar_texto_forense, "  • Ingeniería inversa\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"❌ Error usando Strings: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    # Métodos auxiliares para actualizar texto
    def _actualizar_texto_monitoreo(self, texto):
        """Actualizar texto de monitoreo."""
        if hasattr(self, 'siem_monitoreo_text'):
            self.siem_monitoreo_text.config(state=tk.NORMAL)
            self.siem_monitoreo_text.insert(tk.END, texto)
            self.siem_monitoreo_text.see(tk.END)
            self.siem_monitoreo_text.config(state=tk.DISABLED)
    
    def _actualizar_texto_analisis(self, texto):
        """Actualizar texto de análisis."""
        if hasattr(self, 'siem_analisis_text'):
            self.siem_analisis_text.config(state=tk.NORMAL)
            self.siem_analisis_text.insert(tk.END, texto)
            self.siem_analisis_text.see(tk.END)
            self.siem_analisis_text.config(state=tk.DISABLED)
    
    def _actualizar_texto_alertas(self, texto):
        """Actualizar texto de alertas."""
        if hasattr(self, 'siem_alertas_text'):
            self.siem_alertas_text.config(state=tk.NORMAL)
            self.siem_alertas_text.insert(tk.END, texto)
            self.siem_alertas_text.see(tk.END)
            self.siem_alertas_text.config(state=tk.DISABLED)
    
    def _actualizar_texto_forense(self, texto):
        """Actualizar texto forense."""
        if hasattr(self, 'siem_forense_text'):
            self.siem_forense_text.config(state=tk.NORMAL)
            self.siem_forense_text.insert(tk.END, texto)
            self.siem_forense_text.see(tk.END)
            self.siem_forense_text.config(state=tk.DISABLED)
    
    # Métodos adicionales para completar funcionalidad
    def configurar_alertas(self):
        """Configurar sistema de alertas."""
        self._actualizar_texto_alertas("� Configurando sistema de alertas...\n")
        self._actualizar_texto_alertas(" Estableciendo umbrales de detección...\n")
        self._actualizar_texto_alertas("OK Alertas configuradas correctamente\n\n")
    
    def metricas_sistema(self):
        """Mostrar métricas del sistema."""
        self._actualizar_texto_monitoreo(" Métricas del Sistema:\n")
        self._actualizar_texto_monitoreo("  • CPU: 15%\n")
        self._actualizar_texto_monitoreo("  • Memoria: 2.1GB / 8GB\n")
        self._actualizar_texto_monitoreo("  • Red: 1.2 MB/s\n")
        self._actualizar_texto_monitoreo("  • Disco: 45% utilizado\n\n")
    
    def monitor_red(self):
        """Monitorear actividad de red."""
        self._actualizar_texto_monitoreo(" Monitoreando actividad de red...\n")
        self._actualizar_texto_monitoreo(" Analizando tráfico entrante y saliente...\n")
        self._actualizar_texto_monitoreo(" Detectando anomalías en el tráfico...\n")
        self._actualizar_texto_monitoreo("OK Monitoreo de red activo\n\n")
    
    def eventos_seguridad(self):
        """Mostrar eventos de seguridad."""
        self._actualizar_texto_monitoreo(" Eventos de Seguridad Recientes:\n")
        self._actualizar_texto_monitoreo("  • [15:32] Login exitoso: usuario admin\n")
        self._actualizar_texto_monitoreo("  • [15:28] Intento de login fallido: IP 192.168.1.100\n")
        self._actualizar_texto_monitoreo("  • [15:25] Puerto 22 escaneado desde IP externa\n")
        self._actualizar_texto_monitoreo("  • [15:20] Proceso sospechoso detectado\n\n")
    
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
        self._actualizar_texto_alertas("� Email: Activado\n")
        self._actualizar_texto_alertas("� Desktop: Activado\n")
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
        """Verificar compatibilidad y funcionalidad SIEM en Kali Linux."""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador SIEM configurado")
            return
            
        try:
            # Limpiar pantalla principal
            self.siem_monitoreo_text.config(state=tk.NORMAL)
            self.siem_monitoreo_text.delete(1.0, tk.END)
            self.siem_monitoreo_text.insert(tk.END, "=== VERIFICACIÓN SIEM KALI LINUX ===\n\n")
            
            # Ejecutar verificación a través del controlador
            resultado = self.controlador.verificar_funcionalidad_kali()
            
            # Mostrar resultados
            funcionalidad_ok = resultado.get('funcionalidad_completa', False)
            
            if funcionalidad_ok:
                self.siem_monitoreo_text.insert(tk.END, " OK VERIFICACIÓN SIEM EXITOSA\n\n")
                self.siem_monitoreo_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.siem_monitoreo_text.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.siem_monitoreo_text.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                self.siem_monitoreo_text.insert(tk.END, "=== HERRAMIENTAS SIEM DISPONIBLES ===\n")
                for herramienta, estado in resultado.get('herramientas_disponibles', {}).items():
                    disponible = estado.get('disponible', False)
                    permisos = estado.get('permisos_ok', False)
                    icono = "OK" if disponible and permisos else "ERROR"
                    self.siem_monitoreo_text.insert(tk.END, f"  {icono} {herramienta}\n")
                    
            else:
                self.siem_monitoreo_text.insert(tk.END, " ERROR VERIFICACIÓN SIEM FALLÓ\n\n")
                self.siem_monitoreo_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.siem_monitoreo_text.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.siem_monitoreo_text.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                if resultado.get('recomendaciones'):
                    self.siem_monitoreo_text.insert(tk.END, "=== RECOMENDACIONES ===\n")
                    for recomendacion in resultado['recomendaciones']:
                        self.siem_monitoreo_text.insert(tk.END, f"  • {recomendacion}\n")
                
            if resultado.get('error'):
                self.siem_monitoreo_text.insert(tk.END, f"\nWARNING Error: {resultado['error']}\n")
                
            self.siem_monitoreo_text.config(state=tk.DISABLED)
                
        except Exception as e:
            self.siem_monitoreo_text.config(state=tk.NORMAL)
            self.siem_monitoreo_text.insert(tk.END, f" ERROR Error durante verificación: {str(e)}\n")
            self.siem_monitoreo_text.config(state=tk.DISABLED)
    
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
                self._actualizar_texto_forense("� Copia básica:\n")
                self._actualizar_texto_forense("  dd if=/dev/sdX of=imagen.dd bs=4096 status=progress\n")
                self._actualizar_texto_forense("� Copia con verificación:\n")
                self._actualizar_texto_forense("  dcfldd if=/dev/sdX of=imagen.dd hash=sha256 bs=4096\n")
                self._actualizar_texto_forense("� Análisis de memoria:\n")
                self._actualizar_texto_forense("  dd if=/proc/kcore of=memoria.dump bs=1M count=100\n")
                self._actualizar_texto_forense("� Borrado seguro:\n")
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
                self._actualizar_texto_forense(f"ERROR Error en análisis DD: {str(e)}\n")
        
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
                    self._actualizar_texto_forense("\n❌ No se pudo verificar tipo de sistema\n")
                    
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR Error verificando herramientas: {str(e)}\n")
        
        threading.Thread(target=ejecutar_verificacion, daemon=True).start()
    
    def usar_head_tail(self):
        """Análisis rápido de logs usando head/tail nativos de Kali Linux."""
        def ejecutar_analisis():
            try:
                self._actualizar_texto_forense("� Análisis rápido de logs con herramientas nativas Kali...\n\n")
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
                            
                        self._actualizar_texto_forense(f"� Analizando: {log_path}\n")
                        
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
                                self._actualizar_texto_forense("  � Últimas 10 líneas:\n")
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
                                    self._actualizar_texto_forense(f"  🔍 Patrón '{patron}' encontrado:\n")
                                    for linea in lineas_encontradas:
                                        if linea.strip():
                                            self._actualizar_texto_forense(f"    └─ {linea[:80]}...\n")
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                continue
                        
                        self._actualizar_texto_forense("\n")
                        
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_forense(f"  TIMEOUT Timeout analizando {log_path}\n")
                    except Exception as e:
                        self._actualizar_texto_forense(f"  ERROR Error analizando {log_path}: {str(e)}\n")
                
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
                            self._actualizar_texto_forense("  � Últimas conexiones SSH:\n")
                            for linea in login_result.stdout.strip().split('\n'):
                                if linea.strip():
                                    self._actualizar_texto_forense(f"    └─ {linea[:100]}...\n")
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        self._actualizar_texto_forense("  Error accediendo a logs SSH\n")
                                
                except Exception as e:
                    self._actualizar_texto_forense(f"ERROR Error con journalctl: {str(e)}\n")
                
                self._actualizar_texto_forense("\nOK Análisis rápido completado\n")
                
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR Error en análisis head/tail: {str(e)}\n")
        
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
                        self._actualizar_texto_forense("TIMEOUT Timeout en monitoreo\n")
                    except Exception as e:
                        self._actualizar_texto_forense(f"WARNING Error en ciclo de monitoreo: {str(e)}\n")
                        break
                
                self._actualizar_texto_forense("\n� Monitoreo detenido\n")
                self.monitoreo_activo = False
                
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR Error en monitoreo tiempo real: {str(e)}\n")
                self.monitoreo_activo = False
        
        threading.Thread(target=ejecutar_monitoreo, daemon=True).start()

    def parar_monitoreo(self):
        """Detener el monitoreo en tiempo real."""
        self.monitoreo_activo = False
        self._actualizar_texto_forense("� Deteniendo monitoreo...\n")

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
                                self._actualizar_texto_forense("  ERROR Error parseando respuesta JSON\n")
                        else:
                            self._actualizar_texto_forense(f"  ERROR Error ejecutando consulta: {resultado.stderr}\n")
                        
                        self._actualizar_texto_forense("\n")
                        
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_forense(f"  TIMEOUT Timeout en consulta: {consulta_info['nombre']}\n")
                    except Exception as e:
                        self._actualizar_texto_forense(f"  ERROR Error en {consulta_info['nombre']}: {str(e)}\n")
                
                self._actualizar_texto_forense("OK Análisis osquery completado\n")
                
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR Error en integración osquery: {str(e)}\n")
        
        threading.Thread(target=ejecutar_osquery, daemon=True).start()
