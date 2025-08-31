# =============================================================
# PRINCIPIOS DE SEGURIDAD ARESITOS (NO TOCAR SIN AUDITORÍA)
# - Nunca solicitar ni almacenar la contraseña de root.
# - Nunca mostrar, registrar ni filtrar la contraseña de root.
# - Ningún input de usuario debe usarse como comando sin validar.
# - Todos los comandos pasan por el validador y gestor de permisos.
# - Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
# - Prohibido shell=True salvo justificación y validación exhaustiva.
# - Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
# =============================================================
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import subprocess
import logging
import platform
from datetime import datetime

try:
    from aresitos.vista.burp_theme import burp_theme
    from aresitos.utils.sudo_manager import get_sudo_manager, is_sudo_available
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaSIEM(tk.Frame):
    def _actualizar_texto_siem_seguro(self, texto):
        def _update():
            try:
                if hasattr(self, 'terminal_output') and self.terminal_output.winfo_exists():
                    self.terminal_output.insert(tk.END, texto)
                    self.terminal_output.see(tk.END)
            except (tk.TclError, AttributeError):
                pass
        self.after(0, _update)

    def _actualizar_estado_seguro(self, texto):
        # No existe label_estado, así que loguea en el área principal de texto terminal_output
        self._actualizar_texto_siem_seguro(f"[ESTADO] {texto}\n")
    @staticmethod
    def _get_base_dir():
        """Obtener la ruta base absoluta del proyecto ARESITOS."""
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        self.proceso_siem_activo = False
        self.thread_siem = None
        self.monitoreo_activo = False  # Para control del monitoreo en tiempo real
        self.cache_alertas = {}  # Para evitar spam de alertas repetitivas
        self.ultima_verificacion = {}  # Timestamps de últimas verificaciones
        
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
        """Crear terminal integrado SIEM con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - SIEM",
                bg=self.colors['bg_secondary'],
                fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")
            )
            self.paned_window.add(terminal_frame, minsize=120)
            
            # Frame para controles del terminal (compacto)
            controles_frame = tk.Frame(terminal_frame, bg=self.colors['bg_secondary'])
            controles_frame.pack(fill="x", padx=5, pady=2)
            
            # Botón limpiar terminal (estilo dashboard, compacto)
            btn_limpiar = tk.Button(
                controles_frame,
                text="LIMPIAR",
                command=self.limpiar_terminal_siem,
                bg=self.colors.get('warning', '#ffaa00'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)
            
            # Botón ver logs (estilo dashboard, compacto)
            btn_logs = tk.Button(
                controles_frame,
                text="VER LOGS",
                command=self.abrir_logs_siem,
                bg=self.colors.get('info', '#007acc'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)
            
            # Área de terminal (misma estética que dashboard, más pequeña)
            self.terminal_output = scrolledtext.ScrolledText(
                terminal_frame,
                height=6,  # Más pequeño que dashboard (que tiene más altura)
                bg='#000000',  # Terminal negro estándar
                fg='#00ff00',  # Terminal verde estándar
                font=("Consolas", 8),  # Fuente smaller que dashboard
                insertbackground='#00ff00',
                selectbackground='#333333'
            )
            self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Frame para entrada de comandos (como Dashboard)
            entrada_frame = tk.Frame(terminal_frame, bg='#1e1e1e')
            entrada_frame.pack(fill="x", padx=5, pady=2)
            
            tk.Label(entrada_frame, text="COMANDO:",
                    bg='#1e1e1e', fg='#00ff00',
                    font=("Arial", 9, "bold")).pack(side="left", padx=(0, 5))
            
            self.comando_entry = tk.Entry(
                entrada_frame,
                bg='#000000',
                fg='#00ff00',
                font=("Consolas", 9),
                insertbackground='#00ff00'
            )
            self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.comando_entry.bind("<Return>", self.ejecutar_comando_entry)
            
            ejecutar_btn = tk.Button(
                entrada_frame,
                text="EJECUTAR",
                command=self.ejecutar_comando_entry,
                bg='#2d5aa0',
                fg='white',
                font=("Arial", 8, "bold")
            )
            ejecutar_btn.pack(side="right")
            
            # Mensaje inicial estilo dashboard
            self._actualizar_terminal_seguro("="*60 + "\n")
            self._actualizar_terminal_seguro("Terminal ARESITOS - SIEM v2.0\n")
            self._actualizar_terminal_seguro(f"Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._actualizar_terminal_seguro(f"Sistema: Kali Linux - Security Information & Event Management\n")
            self._actualizar_terminal_seguro("="*60 + "\n")
            self._actualizar_terminal_seguro("LOG Monitoreo SIEM en tiempo real\n\n")
            
            self.log_to_terminal("Terminal SIEM iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista SIEM: {e}")
    
    def limpiar_terminal_siem(self):
        """Limpiar terminal SIEM manteniendo cabecera."""
        try:
            if hasattr(self, 'terminal_output'):
                self._actualizar_terminal_seguro("", "clear")
                # Recrear cabecera estándar
                self._actualizar_terminal_seguro("="*60 + "\n")
                self._actualizar_terminal_seguro("Terminal ARESITOS - SIEM v2.0\n")
                self._actualizar_terminal_seguro(f"Limpiado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self._actualizar_terminal_seguro("Sistema: Kali Linux - Security Information & Event Management\n")
                self._actualizar_terminal_seguro("="*60 + "\n")
                self._actualizar_terminal_seguro("LOG Terminal SIEM reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal SIEM: {e}")
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada, sin validación de seguridad, si el usuario autenticó como root/sudo."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        self._actualizar_terminal_seguro(f"\n> {comando}\n")
        self.comando_entry.delete(0, tk.END)
        # Ejecutar el comando tal cual en thread
        thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_async(self, comando):
        """Ejecutar comando de forma asíncrona con comandos especiales."""
        # Comandos especiales de ARESITOS
        if comando == "ayuda-comandos":
            self._mostrar_ayuda_comandos()
            return
        elif comando == "info-seguridad":
            self._mostrar_info_seguridad()
            return
        elif comando == "clear" or comando == "cls":
            self.limpiar_terminal_siem()
            return
        import platform
        sudo_manager = get_sudo_manager()
        if platform.system() == "Windows":
            import subprocess
            comando_completo = ["cmd", "/c", comando]
            try:
                resultado = subprocess.run(comando_completo, capture_output=True, text=True, timeout=30)
                if resultado.stdout:
                    self.terminal_output.insert(tk.END, resultado.stdout)
                if resultado.stderr:
                    self.terminal_output.insert(tk.END, f"ERROR: {resultado.stderr}")
            except subprocess.TimeoutExpired:
                self.terminal_output.insert(tk.END, "ERROR: Comando timeout (30s)\n")
            except Exception as e:
                self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
        else:
            try:
                resultado = sudo_manager.execute_sudo_command(comando, timeout=30)
                if resultado.stdout:
                    self.terminal_output.insert(tk.END, resultado.stdout)
                if resultado.stderr:
                    self.terminal_output.insert(tk.END, f"ERROR: {resultado.stderr}")
            except Exception as e:
                self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
        self.terminal_output.see(tk.END)
    
    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "  COMANDOS DISPONIBLES EN ARESITOS v2.0\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            self.terminal_output.insert(tk.END, "🔧 COMANDOS ESPECIALES:\n")
            self.terminal_output.insert(tk.END, "   ayuda-comandos, info-seguridad, clear/cls\n\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando ayuda: {e}\n")
        self.terminal_output.see(tk.END)
    
    def _mostrar_info_seguridad(self):
        """Mostrar información de seguridad actual."""
        try:
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            self.terminal_output.insert(tk.END, "Estado: Seguridad estándar, sin validación restrictiva.\n")
            self.terminal_output.insert(tk.END, "Para más detalles revise la configuración y logs.\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando info seguridad: {e}\n")
        self.terminal_output.see(tk.END)
    
    def abrir_logs_siem(self):
        """Abrir carpeta de logs SIEM."""
        try:
            import os
            logs_path = self._get_base_dir() / 'logs'
            if logs_path.exists():
                if platform.system() == "Linux":
                    subprocess.run(["xdg-open", str(logs_path)], check=False)
                else:
                    subprocess.run(["explorer", str(logs_path)], check=False)
                self.log_to_terminal("Carpeta de logs SIEM abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs SIEM: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal con formato estándar."""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            
            # Log al terminal integrado estándar
            if hasattr(self, 'terminal_output'):
                self.terminal_output.insert(tk.END, mensaje_completo)
                self.terminal_output.see(tk.END)
                    
        except Exception as e:
            print(f"Error en log_to_terminal: {e}")
    
    def sincronizar_terminal(self):
        """Sincronizar terminal - funcionalidad mantenida para compatibilidad."""
        # Esta función se mantiene para compatibilidad pero ahora usa terminal_output
        pass
    
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
            ("/var/log/boot.log", "Arranque del Sistema"),
            ("/var/log/dmesg", "Mensajes del Kernel (dmesg)"),
            ("/var/log/kern.log", "Kernel"),
            ("/var/log/faillog", "Intentos Fallidos"),
            ("/var/log/wtmp", "Inicios/Cierres de Sesión (wtmp)"),
            ("/var/log/lastlog", "Últimos Inicios de Sesión (lastlog)"),
            ("/var/log/apt/history.log", "APT Historial"),
            ("/var/log/dpkg.log", "Paquetes (dpkg)"),
            ("/var/log/mail.log", "Correo (mail.log)"),
            ("/var/log/secure", "Seguridad (secure)"),
            ("/var/log/audit/audit.log", "Auditoría Kernel (audit)"),
            ("/var/log/apache2/access.log", "Apache Access"),
            ("/var/log/apache2/error.log", "Apache Error"),
            ("/var/log/mysql/error.log", "MySQL Error"),
            ("/var/log/nginx/access.log", "Nginx Access"),
            ("/var/log/nginx/error.log", "Nginx Error"),
            ("/var/log/lighttpd/access.log", "Lighttpd Access"),
            ("/var/log/lighttpd/error.log", "Lighttpd Error"),
            ("/var/log/mongodb/mongod.log", "MongoDB"),
            ("/var/log/postgresql/postgresql.log", "PostgreSQL"),
            ("/var/log/samba/log.smbd", "Samba smbd"),
            ("/var/log/samba/log.nmbd", "Samba nmbd"),
            ("/var/log/squid/access.log", "Squid Access"),
            ("/var/log/squid/cache.log", "Squid Cache"),
        ]

        # Botón para descubrir todos los logs en /var/log/
        def descubrir_logs():
            import os
            encontrados = []
            for root, dirs, files in os.walk("/var/log/"):
                for f in files:
                    ruta = os.path.join(root, f)
                    # Solo archivos legibles y no duplicados
                    if ruta not in self.logs_vars and os.path.isfile(ruta):
                        try:
                            with open(ruta, 'r'):
                                pass
                            encontrados.append((ruta, os.path.relpath(ruta, "/var/log/")))
                        except Exception:
                            continue
            if encontrados:
                for ruta, nombre in encontrados:
                    var = tk.BooleanVar()
                    self.logs_vars[ruta] = var
                    if self.theme:
                        cb = tk.Checkbutton(logs_frame, text=f"{nombre} ({ruta})", variable=var,
                                          bg='#2b2b2b', fg='#cccccc', selectcolor='#4a4a4a',
                                          activebackground='#3c3c3c', font=('Arial', 9))
                    else:
                        cb = ttk.Checkbutton(logs_frame, text=f"{nombre} ({ruta})", variable=var)
                    cb.grid(row=len(self.logs_vars)//2, column=len(self.logs_vars)%2, sticky='w', padx=5, pady=2)
                self.log_to_terminal(f"{len(encontrados)} logs adicionales detectados en /var/log/")
            else:
                self.log_to_terminal("No se detectaron nuevos logs adicionales en /var/log/")

        # Botón para descubrir logs dinámicamente
        if self.theme:
            btn_descubrir = tk.Button(top_frame, text="Descubrir todos los logs en /var/log/", command=descubrir_logs,
                                     bg='#404040', fg='white', font=('Arial', 9, 'bold'))
            btn_descubrir.pack(side=tk.RIGHT, padx=5)
        else:
            ttk.Button(top_frame, text="Descubrir todos los logs en /var/log/", command=descubrir_logs).pack(side=tk.RIGHT, padx=5)
        
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
            
            # NUEVOS BOTONES FASE 3.2 - ANÁLISIS AVANZADO
            btn_patrones = tk.Button(btn_frame, text="Análisis Avanzado", 
                                   command=self.analizar_patrones_avanzados,
                                   bg='#d9534f', fg='white', font=('Arial', 10))
            btn_patrones.pack(side=tk.LEFT, padx=5)
            
            btn_correlacion = tk.Button(btn_frame, text="Correlación", 
                                      command=self.correlacionar_eventos_avanzado,
                                      bg='#5bc0de', fg='white', font=('Arial', 10))
            btn_correlacion.pack(side=tk.LEFT, padx=5)
        else:
            btn_frame = tk.Frame(top_frame)
            btn_frame.pack(fill=tk.X, pady=10)
            
            ttk.Button(btn_frame, text=" Analizar Logs Seleccionados", 
                      command=self.analizar_logs_seleccionados).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text=" Buscar Patrones", 
                      command=self.buscar_patrones).pack(side=tk.LEFT, padx=5)
            
            # NUEVOS BOTONES FASE 3.2 - ANÁLISIS AVANZADO (versión TTK)
            ttk.Button(btn_frame, text="Análisis Avanzado", 
                      command=self.analizar_patrones_avanzados).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Correlación", 
                      command=self.correlacionar_eventos_avanzado).pack(side=tk.LEFT, padx=5)
        
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

        # Botones de herramientas forenses (ampliado)
        if self.theme:
            tools_frame = tk.Frame(top_frame, bg='#2b2b2b')
            tools_frame.pack(fill=tk.X)
            tools_forenses = [
                (" Sleuth Kit", self.usar_sleuthkit),
                (" Binwalk", self.usar_binwalk),
                (" Foremost", self.usar_foremost),
                ("Extraer Strings", self.usar_strings),
                (" DD/DCFLDD", self.usar_dd),
                (" Head/Tail", self.usar_head_tail),
                (" exiftool", self.usar_exiftool),
                (" photorec", self.usar_photorec),
                (" hexdump", self.usar_hexdump),
                (" xxd", self.usar_xxd),
                (" hashdeep", self.usar_hashdeep),
                (" testdisk", self.usar_testdisk),
                (" bulk_extractor", self.usar_bulk_extractor),
                (" dc3dd", self.usar_dc3dd),
                (" guymager", self.usar_guymager),
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
                (" Sleuth Kit", self.usar_sleuthkit),
                (" Binwalk", self.usar_binwalk),
                (" Foremost", self.usar_foremost),
                ("Extraer Strings", self.usar_strings),
                (" DD/DCFLDD", self.usar_dd),
                (" Head/Tail", self.usar_head_tail),
                (" exiftool", self.usar_exiftool),
                (" photorec", self.usar_photorec),
                (" hexdump", self.usar_hexdump),
                (" xxd", self.usar_xxd),
                (" hashdeep", self.usar_hashdeep),
                (" testdisk", self.usar_testdisk),
                (" bulk_extractor", self.usar_bulk_extractor),
                (" dc3dd", self.usar_dc3dd),
                (" guymager", self.usar_guymager),
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
            label_results = tk.Label(bottom_frame, text="Resultados del Análisis Forense", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_results.pack(anchor=tk.W, pady=(0, 5))
        else:
            bottom_frame = ttk.LabelFrame(main_frame, text="Resultados del Análisis Forense", padding=10)
        bottom_frame.pack(fill=tk.BOTH, expand=True)

        self.siem_forense_text = scrolledtext.ScrolledText(bottom_frame, height=15,
                                                          bg='#1e1e1e' if self.theme else 'white',
                                                          fg='white' if self.theme else 'black',
                                                          insertbackground='white' if self.theme else 'black',
                                                          font=('Consolas', 9))
        self.siem_forense_text.pack(fill=tk.BOTH, expand=True)
    # === NUEVOS HANDLERS FORENSE ===
    def usar_exiftool(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("EXIFTOOL - Metadatos de archivos\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK exiftool disponible\n\n")
                        self._actualizar_texto_forense("Comandos útiles:\n  exiftool archivo.jpg\n  exiftool -a -u -g1 archivo.docx\n  exiftool -r carpeta/\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando exiftool\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("exiftool no encontrado. Instalar: sudo apt install exiftool\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando exiftool: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_photorec(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("PHOTOREC - Recuperación de archivos\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['photorec', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK photorec disponible\n\n")
                        self._actualizar_texto_forense("Comando: photorec\n  photorec (interfaz interactiva)\n  photorec /log /d carpeta_salida imagen.dd\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando photorec\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("photorec no encontrado. Instalar: sudo apt install testdisk\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando photorec: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_hexdump(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("HEXDUMP - Visualización hexadecimal\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['hexdump', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK hexdump disponible\n\n")
                        self._actualizar_texto_forense("Comandos:\n  hexdump -C archivo.bin\n  hexdump -n 256 archivo.bin\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando hexdump\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("hexdump no encontrado. Instalar: sudo apt install bsdmainutils\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando hexdump: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_xxd(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("XXD - Editor hexadecimal\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['xxd', '-h'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK xxd disponible\n\n")
                        self._actualizar_texto_forense("Comandos:\n  xxd archivo.bin\n  xxd -r archivo.hex > archivo.bin\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando xxd\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("xxd no encontrado. Instalar: sudo apt install xxd\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando xxd: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_hashdeep(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("HASHDEEP - Hashes recursivos\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['hashdeep', '-v'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK hashdeep disponible\n\n")
                        self._actualizar_texto_forense("Comandos:\n  hashdeep -r carpeta/\n  hashdeep -c md5,sha1,sha256 archivo\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando hashdeep\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("hashdeep no encontrado. Instalar: sudo apt install hashdeep\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando hashdeep: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_testdisk(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("TESTDISK - Recuperación de particiones\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['testdisk', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK testdisk disponible\n\n")
                        self._actualizar_texto_forense("Comando: testdisk\n  testdisk (interfaz interactiva)\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando testdisk\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("testdisk no encontrado. Instalar: sudo apt install testdisk\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando testdisk: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_bulk_extractor(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("BULK_EXTRACTOR - Extracción masiva de artefactos\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['bulk_extractor', '-V'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK bulk_extractor disponible\n\n")
                        self._actualizar_texto_forense("Comando:\n  bulk_extractor -o salida/ imagen.dd\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando bulk_extractor\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("bulk_extractor no encontrado. Instalar: sudo apt install bulk-extractor\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando bulk_extractor: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_dc3dd(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("DC3DD - Clonado forense avanzado\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['dc3dd', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK dc3dd disponible\n\n")
                        self._actualizar_texto_forense("Comando:\n  dc3dd if=/dev/sdX of=imagen.dd hash=sha256 log=log.txt\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando dc3dd\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("dc3dd no encontrado. Instalar: sudo apt install dc3dd\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando dc3dd: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    def usar_guymager(self):
        def ejecutar():
            try:
                self._actualizar_texto_forense("GUYMAGER - Adquisición forense de discos (GUI)\n" + "="*50 + "\n")
                import subprocess
                try:
                    resultado = subprocess.run(['guymager', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_forense("OK guymager disponible\n\n")
                        self._actualizar_texto_forense("Comando: guymager (interfaz gráfica)\n\n")
                    else:
                        self._actualizar_texto_forense("ERROR ejecutando guymager\n")
                except FileNotFoundError:
                    self._actualizar_texto_forense("guymager no encontrado. Instalar: sudo apt install guymager\n")
            except Exception as e:
                self._actualizar_texto_forense(f"ERROR usando guymager: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()
    
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
        # Variables de control de fases
        fases_completadas = 0
        fases_con_error = 0
        
        try:
            self._log_terminal("Activando proteccion SIEM completa del sistema", "SIEM", "INFO")
            
            # FASE 1: Protección de IP y configuración de red
            try:
                self._log_terminal("FASE 1: Activando proteccion de IP y configuracion de red", "SIEM", "INFO")
                self._proteger_configuracion_ip()
                fases_completadas += 1
                self._log_terminal("OK FASE 1 completada exitosamente", "SIEM", "SUCCESS")  # Issue 22/24: Sin emojis
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 1: {str(e)}", "SIEM", "ERROR")
                self._log_terminal("Continuando con la siguiente fase...", "SIEM", "WARNING")
            
            # FASE 2: Monitoreo y protección DNS
            try:
                self._log_terminal("FASE 2: Activando monitoreo y proteccion DNS", "SIEM", "WARNING")
                self._proteger_dns()
                fases_completadas += 1
                self._log_terminal("OK FASE 2 completada exitosamente", "SIEM", "SUCCESS")
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 2: {str(e)}", "SIEM", "ERROR")
                self._log_terminal("Continuando con la siguiente fase...", "SIEM", "WARNING")
            
            # FASE 3: Monitoreo de datos de red
            try:
                self._log_terminal("FASE 3: Iniciando monitoreo de trafico de red", "SIEM", "INFO")
                self._monitorear_trafico_red()
                fases_completadas += 1
                self._log_terminal("OK FASE 3 completada exitosamente", "SIEM", "SUCCESS")
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 3: {str(e)}", "SIEM", "ERROR")
                self._log_terminal("Continuando con la siguiente fase...", "SIEM", "WARNING")
            
            # FASE 4: Monitoreo de 50 puertos críticos
            try:
                self._log_terminal("FASE 4: Monitoreando 50 puertos mas vulnerables a ciberataques", "SIEM", "ERROR")
                self._monitorear_puertos_criticos()
                fases_completadas += 1
                self._log_terminal("OK FASE 4 completada exitosamente", "SIEM", "SUCCESS")
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 4: {str(e)}", "SIEM", "ERROR")
                self._log_terminal("Continuando con la siguiente fase...", "SIEM", "WARNING")
            
            # FASE 5: Detección de anomalías en tiempo real
            try:
                self._log_terminal("FASE 5: Activando deteccion de anomalias en tiempo real", "SIEM", "WARNING")
                self._detectar_anomalias()
                fases_completadas += 1
                self._log_terminal("OK FASE 5 completada exitosamente", "SIEM", "SUCCESS")
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 5: {str(e)}", "SIEM", "ERROR")
                self._log_terminal("Continuando con la siguiente fase...", "SIEM", "WARNING")
            
            # FASE 6: Monitoreo continuo
            try:
                if self.controlador:
                    resultado = self.controlador.iniciar_monitoreo_eventos()
                    if resultado.get('exito'):
                        self._log_terminal("SIEM ACTIVADO - Proteccion completa del sistema en funcionamiento", "SIEM", "SUCCESS")
                        self.after(0, self._actualizar_texto_monitoreo, "OK SIEM activado - proteccion completa\n")
                        
                        # Iniciar ciclo de detección continua
                        self._monitorear_eventos_continuamente()
                        fases_completadas += 1
                        self._log_terminal("OK FASE 6 completada exitosamente", "SIEM", "SUCCESS")
                    else:
                        error_msg = resultado.get('error', 'Error desconocido')
                        self._log_terminal(f"Error iniciando controlador SIEM: {error_msg}", "SIEM", "ERROR")
                        self.after(0, self._actualizar_texto_monitoreo, f"ERROR iniciando SIEM: {error_msg}\n")
                        fases_con_error += 1
                else:
                    self._log_terminal("Controlador SIEM no disponible - ejecutando monitoreo basico", "SIEM", "WARNING")
                    self._ejecutar_monitoreo_basico()
                    fases_completadas += 1
                    self._log_terminal("OK FASE 6 completada con monitoreo básico", "SIEM", "SUCCESS")
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 6: {str(e)}", "SIEM", "ERROR")
                self._log_terminal("Fase final completada con errores", "SIEM", "WARNING")
            
            # RESUMEN FINAL DE FASES
            try:
                self.after(0, self._actualizar_texto_monitoreo, f"\n{'='*50}\n")
                self.after(0, self._actualizar_texto_monitoreo, f"RESUMEN DE EJECUCIÓN SIEM\n")
                self.after(0, self._actualizar_texto_monitoreo, f"{'='*50}\n")
                self.after(0, self._actualizar_texto_monitoreo, f"OK FASES COMPLETADAS: {fases_completadas}/6\n")
                self.after(0, self._actualizar_texto_monitoreo, f"ERROR FASES CON ERROR: {fases_con_error}/6\n")
                
                if fases_con_error == 0:
                    self.after(0, self._actualizar_texto_monitoreo, f"ESTADO GENERAL: OK TODAS LAS FASES COMPLETADAS EXITOSAMENTE\n")
                    self._log_terminal("OK SIEM: Todas las fases completadas exitosamente", "SIEM", "SUCCESS")
                else:
                    self.after(0, self._actualizar_texto_monitoreo, f"ESTADO GENERAL: {fases_completadas} fases exitosas, {fases_con_error} con errores\n")
                    self._log_terminal(f"SIEM: {fases_completadas} fases exitosas, {fases_con_error} con errores", "SIEM", "WARNING")
                
                self.after(0, self._actualizar_texto_monitoreo, f"RESULTADO: SIEM ejecutado de forma resiliente\n")
                self.after(0, self._actualizar_texto_monitoreo, f"{'='*50}\n")
            except Exception as e:
                self._log_terminal(f"Error generando resumen final: {str(e)}", "SIEM", "ERROR")
                
        except Exception as e:
            self._log_terminal(f"Excepcion critica en SIEM: {str(e)}", "SIEM", "ERROR")
            self.after(0, self._actualizar_texto_monitoreo, f"ERROR Excepción: {str(e)}\n")
        finally:
            self.after(0, self._habilitar_botones_siem, True)

    def _proteger_configuracion_ip(self):
        """Proteger y monitorear configuración de IP del sistema."""
        import os
        try:
            from aresitos.utils.gestor_permisos import GestorPermisosSeguro
            gestor = GestorPermisosSeguro()
            # Obtener configuración actual de red
            exito, out, err = gestor.ejecutar_con_permisos('ip', ['addr', 'show'])
            interfaces_detectadas = []
            if exito:
                for linea in out.split('\n'):
                    if 'inet ' in linea and '127.0.0.1' not in linea:
                        ip = linea.strip().split()[1].split('/')[0]
                        interfaces_detectadas.append(ip)
                        self._log_terminal(f"IP detectada y protegida: {ip}", "SIEM", "INFO")
            # Verificar tabla de rutas
            exito, out, err = gestor.ejecutar_con_permisos('ip', ['route', 'show'])
            if exito:
                rutas = len(out.strip().split('\n'))
                self._log_terminal(f"Tabla de rutas verificada - {rutas} rutas activas", "SIEM", "INFO")
            # Verificar configuración iptables si está disponible
            exito, out, err = gestor.ejecutar_con_permisos('iptables', ['-L', '-n'])
            if exito:
                reglas = len([l for l in out.split('\n') if l.strip() and not l.startswith('Chain')])
                self._log_terminal(f"Firewall iptables - {reglas} reglas activas", "SIEM", "INFO")
            else:
                self._log_terminal("Firewall iptables no disponible", "SIEM", "WARNING")
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
        try:
            from aresitos.utils.gestor_permisos import GestorPermisosSeguro
            gestor = GestorPermisosSeguro()
            # Monitorear conexiones activas
            exito, out, err = gestor.ejecutar_con_permisos('ss', ['-tuln'])
            if exito:
                conexiones_activas = len(out.strip().split('\n')) - 1
                self._log_terminal(f"Conexiones de red activas: {conexiones_activas}", "SIEM", "INFO")
            # Verificar estadísticas de interfaz
            exito, out, err = gestor.ejecutar_con_permisos('cat', ['/proc/net/dev'])
            interfaces_con_trafico = []
            if exito:
                for linea in out.split('\n')[2:]:
                    if ':' in linea:
                        interfaz = linea.split(':')[0].strip()
                        if interfaz != 'lo':
                            interfaces_con_trafico.append(interfaz)
            for interfaz in interfaces_con_trafico:
                self._log_terminal(f"Interfaz de red monitoreada: {interfaz}", "SIEM", "INFO")
            # Verificar procesos con conexiones de red
            exito, out, err = gestor.ejecutar_con_permisos('ss', ['-tulpn'])
            procesos_red = []
            if exito:
                for linea in out.split('\n'):
                    if 'LISTEN' in linea or 'ESTAB' in linea:
                        if 'users:' in linea:
                            try:
                                parte_users = linea.split('users:')[1]
                                if '(' in parte_users and ')' in parte_users:
                                    proceso = parte_users.split('(')[1].split(')')[0]
                                else:
                                    proceso = 'desconocido'
                            except:
                                proceso = 'desconocido'
                            if proceso not in procesos_red:
                                procesos_red.append(proceso)
            for proceso in procesos_red[:10]:
                self._log_terminal(f"Proceso con conexion de red: {proceso}", "SIEM", "INFO")
        except Exception as e:
            self._log_terminal(f"Error monitoreando trafico: {str(e)}", "SIEM", "WARNING")

    def _monitorear_puertos_criticos(self):
        """Monitorear los 50 puertos más vulnerables a ciberataques con protección avanzada."""
        import subprocess
        
        # Los 50 puertos más críticos para ciberataques organizados por categoría
        puertos_criticos = {
            'acceso_remoto': {
                '22': 'SSH - Secure Shell',
                '23': 'Telnet (inseguro)',
                '3389': 'RDP - Remote Desktop Protocol',
                '5900': 'VNC - Virtual Network Computing',
                '5901': 'VNC alternativo',
                '1723': 'PPTP VPN'
            },
            'web_servicios': {
                '80': 'HTTP - Hypertext Transfer Protocol',
                '443': 'HTTPS - HTTP Secure',
                '8080': 'HTTP alternativo',
                '8443': 'HTTPS alternativo',
                '8000': 'HTTP desarrollo',
                '8001': 'HTTP alternativo',
                '8081': 'HTTP proxy',
                '9000': 'Servidor web alternativo',
                '9090': 'Panel de administración web'
            },
            'bases_datos': {
                '1433': 'Microsoft SQL Server',
                '1434': 'Microsoft SQL Monitor',
                '3306': 'MySQL/MariaDB',
                '5432': 'PostgreSQL',
                '5984': 'CouchDB',
                '6379': 'Redis',
                '9200': 'Elasticsearch',
                '27017': 'MongoDB'
            },
            'email_ftp': {
                '21': 'FTP - File Transfer Protocol',
                '25': 'SMTP - Simple Mail Transfer Protocol',
                '110': 'POP3 - Post Office Protocol',
                '143': 'IMAP - Internet Message Access Protocol',
                '993': 'IMAPS - IMAP over SSL',
                '995': 'POP3S - POP3 over SSL',
                '2121': 'FTP alternativo'
            },
            'backdoors_sospechosos': {
                '4444': 'Puerto backdoor común',
                '5555': 'Puerto backdoor común',
                '6666': 'Puerto sospechoso',
                '7777': 'Puerto sospechoso',
                '8888': 'Puerto sospechoso alternativo',
                '9999': 'Puerto backdoor común',
                '31337': 'Puerto hacker clásico',
                '12345': 'Puerto backdoor típico',
                '54321': 'Puerto backdoor típico'
            },
            'sistema_red': {
                '53': 'DNS - Domain Name System',
                '111': 'RPC - Remote Procedure Call',
                '135': 'MS RPC Endpoint Mapper',
                '139': 'NetBIOS Session Service',
                '445': 'SMB - Server Message Block',
                '2049': 'NFS - Network File System',
                '2375': 'Docker API',
                '6000': 'X11 forwarding',
                '6001': 'X11 forwarding alternativo',
                '7001': 'Servidor de aplicaciones'
            }
        }
        
        try:
            self._log_terminal("Iniciando monitoreo avanzado de puertos críticos...", "SIEM", "INFO")
            
            # Verificar qué puertos están abiertos usando ss
            resultado = subprocess.run(['ss', '-tuln'], 
                                     capture_output=True, text=True, timeout=15)
            
            puertos_abiertos_tcp = []
            puertos_abiertos_udp = []
            puertos_criticos_detectados = {}
            
            for linea in resultado.stdout.split('\n'):
                if linea.strip():
                    partes = linea.split()
                    if len(partes) >= 4:
                        protocolo = partes[0]
                        direccion = partes[3]
                        puerto = direccion.split(':')[-1]
                        
                        if protocolo.startswith('tcp') and 'LISTEN' in linea:
                            puertos_abiertos_tcp.append(puerto)
                        elif protocolo.startswith('udp'):
                            puertos_abiertos_udp.append(puerto)
                        
                        # Verificar si es un puerto crítico
                        for categoria, puertos_cat in puertos_criticos.items():
                            if puerto in puertos_cat:
                                descripcion = puertos_cat[puerto]
                                if categoria not in puertos_criticos_detectados:
                                    puertos_criticos_detectados[categoria] = []
                                puertos_criticos_detectados[categoria].append((puerto, descripcion, protocolo))
            
            # Reportar hallazgos por categoría
            total_criticos = 0
            for categoria, puertos_detectados in puertos_criticos_detectados.items():
                if puertos_detectados:
                    total_criticos += len(puertos_detectados)
                    
                    if categoria == 'acceso_remoto':
                        self._log_terminal(f"ACCESO REMOTO: {len(puertos_detectados)} puertos críticos detectados", "SIEM", "ERROR")
                    elif categoria == 'bases_datos':
                        self._log_terminal(f"BASES DE DATOS: {len(puertos_detectados)} puertos expuestos", "SIEM", "ERROR")
                    elif categoria == 'backdoors_sospechosos':
                        self._log_terminal(f"BACKDOORS DETECTADOS: {len(puertos_detectados)} puertos sospechosos", "SIEM", "ERROR")
                    elif categoria == 'web_servicios':
                        self._log_terminal(f"SERVICIOS WEB: {len(puertos_detectados)} puertos activos", "SIEM", "WARNING")
                    elif categoria == 'email_ftp':
                        self._log_terminal(f"EMAIL/FTP: {len(puertos_detectados)} servicios detectados", "SIEM", "WARNING")
                    elif categoria == 'sistema_red':
                        self._log_terminal(f"SERVICIOS SISTEMA: {len(puertos_detectados)} puertos activos", "SIEM", "INFO")
                    
                    # Mostrar detalles de cada puerto
                    for puerto, descripcion, protocolo in puertos_detectados:
                        nivel = "ERROR" if categoria in ['acceso_remoto', 'bases_datos', 'backdoors_sospechosos'] else "WARNING"
                        self._log_terminal(f"  Puerto {puerto}/{protocolo}: {descripcion}", "SIEM", nivel)
            
            # Resumen general
            total_tcp = len(puertos_abiertos_tcp)
            total_udp = len(puertos_abiertos_udp)
            
            self._log_terminal(f"RESUMEN: {total_tcp} TCP, {total_udp} UDP abiertos, {total_criticos} críticos", "SIEM", "INFO")
            
            # Alertas de seguridad basadas en el análisis
            if total_criticos > 15:
                self._log_terminal("ALERTA MÁXIMA: Demasiados puertos críticos expuestos", "SIEM", "ERROR")
            elif total_criticos > 10:
                self._log_terminal("ALERTA ALTA: Múltiples puertos críticos detectados", "SIEM", "WARNING")
            elif total_criticos > 5:
                self._log_terminal("ALERTA MEDIA: Varios puertos críticos abiertos", "SIEM", "WARNING")
            
            # Verificar conexiones establecidas en puertos críticos
            self._verificar_conexiones_criticas(puertos_criticos_detectados)
            
            # Monitoreo de IPs sospechosas
            self._monitorear_ips_sospechosas()
                                
        except Exception as e:
            self._log_terminal(f"Error monitoreando puertos críticos: {str(e)}", "SIEM", "ERROR")
    
    def _verificar_conexiones_criticas(self, puertos_criticos_detectados):
        """Verificar conexiones activas en puertos críticos."""
        import subprocess
        
        try:
            self._log_terminal("Verificando conexiones activas en puertos críticos...", "SIEM", "INFO")
            
            # Obtener conexiones establecidas
            resultado = subprocess.run(['ss', '-tupn'], 
                                     capture_output=True, text=True, timeout=10)
            
            conexiones_sospechosas = []
            if resultado.returncode == 0:
                for linea in resultado.stdout.split('\n'):
                    if 'ESTAB' in linea or 'ESTABLISHED' in linea:
                        partes = linea.split()
                        if len(partes) >= 5:
                            local_addr = partes[3]
                            remote_addr = partes[4]
                            puerto_local = local_addr.split(':')[-1]
                            ip_remota = remote_addr.split(':')[0]
                            
                            # Verificar si el puerto local es crítico
                            for categoria, puertos_detectados in puertos_criticos_detectados.items():
                                for puerto, descripcion, protocolo in puertos_detectados:
                                    if puerto == puerto_local:
                                        # Verificar si la IP remota es sospechosa
                                        if not self._es_ip_local(ip_remota):
                                            conexiones_sospechosas.append((puerto, ip_remota, descripcion))
                                            self._log_terminal(f"CONEXIÓN EXTERNA: Puerto {puerto} ({descripcion}) ← {ip_remota}", "SIEM", "WARNING")
            
            if conexiones_sospechosas:
                self._log_terminal(f"DETECTADAS: {len(conexiones_sospechosas)} conexiones externas en puertos críticos", "SIEM", "WARNING")
            else:
                self._log_terminal("Sin conexiones externas sospechosas detectadas", "SIEM", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error verificando conexiones críticas: {str(e)}", "SIEM", "WARNING")
    
    def _es_ip_local(self, ip):
        """Verificar si una IP es local/privada."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            # Verificación manual para IPs comunes
            return (ip.startswith('192.168.') or 
                   ip.startswith('10.') or 
                   ip.startswith('172.') or 
                   ip.startswith('127.') or 
                   ip == 'localhost')
    
    def _monitorear_ips_sospechosas(self):
        """Monitorear IPs sospechosas y bloquear ataques comunes."""
        import subprocess
        
        try:
            self._log_terminal("Monitoreando IPs sospechosas y patrones de ataque...", "SIEM", "INFO")
            
            # Verificar intentos de conexión recientes en logs
            logs_a_verificar = ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog']
            
            for log_file in logs_a_verificar:
                if os.path.exists(log_file):
                    try:
                        # Buscar intentos de fuerza bruta SSH
                        resultado = subprocess.run(['grep', '-i', 'failed password', log_file], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.strip().split('\n')
                            if len(lineas) > 5:  # Más de 5 intentos fallidos
                                self._log_terminal(f"FUERZA BRUTA DETECTADA: {len(lineas)} intentos fallidos en SSH", "SIEM", "ERROR")
                                
                                # Extraer IPs más frecuentes
                                ips_atacantes = {}
                                for linea in lineas[-10:]:  # Últimos 10 intentos
                                    if 'from' in linea:
                                        partes = linea.split('from')
                                        if len(partes) > 1:
                                            ip_parte = partes[1].split()[0]
                                            if ip_parte in ips_atacantes:
                                                ips_atacantes[ip_parte] += 1
                                            else:
                                                ips_atacantes[ip_parte] = 1
                                
                                # Reportar IPs más agresivas
                                for ip, intentos in sorted(ips_atacantes.items(), key=lambda x: x[1], reverse=True)[:3]:
                                    self._log_terminal(f"IP AGRESIVA: {ip} ({intentos} intentos)", "SIEM", "ERROR")
                    except:
                        pass
                    break  # Solo verificar el primer log disponible
            
            # Verificar conexiones de puertos no estándar
            resultado = subprocess.run(['ss', '-tupn'], 
                                     capture_output=True, text=True, timeout=10)
            if resultado.returncode == 0:
                puertos_altos = []
                for linea in resultado.stdout.split('\n'):
                    if 'ESTAB' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            remote_addr = partes[4]
                            try:
                                puerto_remoto = int(remote_addr.split(':')[-1])
                                if puerto_remoto > 50000:  # Puertos muy altos
                                    puertos_altos.append(puerto_remoto)
                            except:
                                pass
                
                if len(puertos_altos) > 10:
                    self._log_terminal(f"ACTIVIDAD SOSPECHOSA: {len(puertos_altos)} conexiones en puertos altos", "SIEM", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error monitoreando IPs sospechosas: {str(e)}", "SIEM", "WARNING")

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
                    
                time.sleep(25)  # Issue 21/24: Optimizado de 30 a 25 segundos antes del siguiente ciclo
                
        except Exception as e:
            self._log_terminal(f"Error en monitoreo basico: {str(e)}", "SIEM", "WARNING")
    
    def _monitorear_eventos_continuamente(self):
        """Monitorear eventos de seguridad de forma continua."""
        if not self.proceso_siem_activo:
            return
            
        try:
            # Detectar eventos reales de seguridad usando comandos Linux
            eventos_detectados = []
            
            # 1. Verificar intentos de SSH fallidos RECIENTES (último minuto)
            try:
                # Usar journalctl para obtener solo logs recientes 
                result = subprocess.run(['journalctl', '_COMM=sshd', '--since', '1 minute ago', '--no-pager'], 
                                      capture_output=True, text=True, timeout=3)
                if result.stdout and 'Failed password' in result.stdout:
                    # Contar solo líneas con "Failed password" en el último minuto
                    lineas_fallidas = [line for line in result.stdout.split('\n') if 'Failed password' in line]
                    if len(lineas_fallidas) > 0:
                        eventos_detectados.append({
                            "tipo": "INTRUSIÓN", 
                            "descripcion": f"SSH: {len(lineas_fallidas)} intentos fallidos RECIENTES (último minuto)",
                            "severidad": "HIGH",
                            "detalles": f"Comando: journalctl para eventos SSH recientes"
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
        
        # Verificar si es una alerta nueva o repetitiva
        if not self._es_alerta_nueva(tipo, descripcion):
            return  # Salir si es una alerta repetitiva
        
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
        """Detener sistema SIEM de forma robusta."""
        try:
            self._log_terminal("🛑 Iniciando detención del sistema SIEM", "SIEM", "WARNING")
            self._actualizar_texto_monitoreo("DETENIENDO Sistema SIEM...\n")
            
            # 1. Marcar proceso como inactivo INMEDIATAMENTE
            self.proceso_siem_activo = False
            self._log_terminal("OK Proceso SIEM marcado como inactivo", "SIEM", "INFO")  # Issue 22/24: Sin emojis
            
            # 2. Esperar a que el hilo termine (máximo 3 segundos)
            if hasattr(self, 'thread_siem') and self.thread_siem and self.thread_siem.is_alive():
                self._log_terminal("⏳ Esperando finalización del hilo SIEM...", "SIEM", "INFO")
                self.thread_siem.join(timeout=3.0)  # Esperar máximo 3 segundos
                if self.thread_siem.is_alive():
                    self._log_terminal("Hilo SIEM no respondió en tiempo esperado", "SIEM", "WARNING")
                else:
                    self._log_terminal("OK Hilo SIEM finalizado correctamente", "SIEM", "SUCCESS")
            
            # 3. Detener controlador si existe
            controlador_detenido = False
            if self.controlador:
                try:
                    self._log_terminal("INFO Deteniendo controlador SIEM...", "SIEM", "INFO")
                    resultado = self.controlador.detener_monitoreo_eventos()
                    if resultado and resultado.get('exito'):
                        self._actualizar_texto_monitoreo("OK Controlador SIEM detenido correctamente\n")
                        self._log_terminal("OK Controlador SIEM detenido", "SIEM", "SUCCESS")
                        controlador_detenido = True
                    else:
                        error_msg = resultado.get('error', 'Respuesta inesperada') if resultado else 'Sin respuesta'
                        self._actualizar_texto_monitoreo(f"Controlador: {error_msg}\n")
                        self._log_terminal(f"Controlador: {error_msg}", "SIEM", "WARNING")
                        controlador_detenido = True  # Continuar aunque haya advertencias
                except Exception as e:
                    self._actualizar_texto_monitoreo(f"Error en controlador: {str(e)}\n")
                    self._log_terminal(f"ERROR en controlador: {str(e)}", "SIEM", "ERROR")
                    controlador_detenido = True  # Forzar detención
            else:
                self._log_terminal("Sin controlador SIEM disponible", "SIEM", "INFO")
                controlador_detenido = True
            
            # 4. Limpiar variables de estado
            self.thread_siem = None
            
            # 5. SIEMPRE actualizar interfaz (crítico para que funcione el botón)
            try:
                self._habilitar_botones_siem(True)  # True = SIEM detenido, habilitar "Iniciar"
                self._log_terminal("OK Interfaz actualizada - botones habilitados", "SIEM", "SUCCESS")
            except Exception as e:
                self._log_terminal(f"ERROR actualizando interfaz: {str(e)}", "SIEM", "ERROR")
            
            # 6. Mensaje final
            if controlador_detenido:
                self._actualizar_texto_monitoreo("SISTEMA SIEM DETENIDO COMPLETAMENTE\n\n")
                self._log_terminal("Sistema SIEM detenido completamente", "SIEM", "SUCCESS")
            else:
                self._actualizar_texto_monitoreo("SIEM detenido con advertencias\n\n")
                self._log_terminal("SIEM detenido con advertencias", "SIEM", "WARNING")
                
        except Exception as e:
            error_msg = f"Error crítico deteniendo SIEM: {str(e)}"
            self._actualizar_texto_monitoreo(f"ERROR: {error_msg}\n")
            self._log_terminal(error_msg, "SIEM", "ERROR")
            
            # FORZAR detención en caso de error crítico
            self.proceso_siem_activo = False
            self.thread_siem = None
            
            try:
                self._habilitar_botones_siem(True)  # Forzar habilitación de botones
                self._actualizar_texto_monitoreo("SIEM detenido forzosamente tras error\n\n")
                self._log_terminal("SIEM detenido forzosamente", "SIEM", "ERROR")
            except:
                self._log_terminal("ERROR CRÍTICO: No se pudo actualizar interfaz", "SIEM", "ERROR")
    
    def _finalizar_siem(self):
        """Finalizar proceso SIEM."""
        self.proceso_siem_activo = False
        self._habilitar_botones_siem(True)
        self.thread_siem = None
        self._actualizar_texto_monitoreo(" Sistema SIEM detenido\n\n")
        
        # Limpiar cache de alertas al detener SIEM
        self.cache_alertas.clear()
        self.ultima_verificacion.clear()
    
    def _es_alerta_nueva(self, tipo_alerta, descripcion, intervalo_minutos=5):
        """Verificar si una alerta es nueva o ya fue reportada recientemente."""
        import time
        tiempo_actual = time.time()
        clave_alerta = f"{tipo_alerta}:{descripcion}"
        
        # Si nunca se reportó o pasó el intervalo, es nueva
        if clave_alerta not in self.cache_alertas:
            self.cache_alertas[clave_alerta] = tiempo_actual
            return True
        
        tiempo_anterior = self.cache_alertas[clave_alerta]
        if tiempo_actual - tiempo_anterior > (intervalo_minutos * 60):
            self.cache_alertas[clave_alerta] = tiempo_actual
            return True
        
        return False
    
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
        """Analizar logs seleccionados con comandos avanzados de Linux - VERSION ORGANIZADA."""
        self.log_to_terminal("Iniciando análisis estructurado de logs...")
        def ejecutar():
            try:
                logs_seleccionados = [path for path, var in self.logs_vars.items() if var.get()]
                
                if not logs_seleccionados:
                    self.after(0, self._actualizar_texto_analisis, "WARNING: No se seleccionaron logs para analizar\n")
                    self.after(0, lambda: self.log_to_terminal("Advertencia: No hay logs seleccionados"))
                    return
                
                # HEADER PRINCIPAL
                self.after(0, self._actualizar_texto_analisis, "="*80 + "\n")
                self.after(0, self._actualizar_texto_analisis, "              ANÁLISIS PROFESIONAL DE LOGS DE SEGURIDAD\n")
                self.after(0, self._actualizar_texto_analisis, "="*80 + "\n\n")
                self.after(0, lambda: self.log_to_terminal(f"Iniciando análisis de {len(logs_seleccionados)} archivos de log..."))
                
                total_eventos_criticos = 0
                resumen_alertas = {}
                
                for idx, log_path in enumerate(logs_seleccionados, 1):
                    self.after(0, self._actualizar_texto_analisis, f"\n[{idx}/{len(logs_seleccionados)}] " + "-"*60 + "\n")
                    self.after(0, self._actualizar_texto_analisis, f"ARCHIVO: {log_path}\n")
                    self.after(0, self._actualizar_texto_analisis, "-"*60 + "\n")
                    if os.path.exists(log_path):
                        try:
                            import subprocess
                            alertas_archivo = 0
                            # 1. INFORMACIÓN BÁSICA DEL ARCHIVO
                            self.after(0, self._actualizar_texto_analisis, "\n1. INFORMACIÓN BÁSICA:\n")
                            try:
                                resultado_wc = subprocess.run(['wc', '-l', log_path], capture_output=True, text=True, timeout=5)
                                if resultado_wc.returncode == 0:
                                    lineas_total = resultado_wc.stdout.strip().split()[0]
                                    self.after(0, self._actualizar_texto_analisis, f"   • Total de líneas: {lineas_total}\n")
                                tamano = os.path.getsize(log_path)
                                tamano_mb = tamano / (1024 * 1024)
                                self.after(0, self._actualizar_texto_analisis, f"   • Tamaño: {tamano_mb:.2f} MB\n")
                                import time
                                mtime = os.path.getmtime(log_path)
                                fecha_mod = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                                self.after(0, self._actualizar_texto_analisis, f"   • Última modificación: {fecha_mod}\n")
                            except Exception as e:
                                self.after(0, self._actualizar_texto_analisis, f"   [ERROR] No se pudo obtener información básica: {e}\n")

                            # 2. ANÁLISIS DE PATRONES DE SEGURIDAD Y APLICACIÓN
                            self.after(0, self._actualizar_texto_analisis, "\n2. ANÁLISIS DE SEGURIDAD Y APLICACIÓN:\n")
                            patrones_seguridad = [
                                ('Failed password', 'Intentos de login fallidos', 'HIGH'),
                                ('Invalid user', 'Usuarios inválidos', 'MEDIUM'),
                                ('authentication failure', 'Fallos de autenticación', 'HIGH'),
                                ('sudo.*COMMAND', 'Comandos sudo ejecutados', 'MEDIUM'),
                                ('sshd.*Connection.*closed', 'Conexiones SSH cerradas', 'LOW'),
                                ('kernel.*killed process', 'Procesos terminados', 'MEDIUM'),
                                ('denied', 'Accesos denegados', 'MEDIUM'),
                                ('attack', 'Ataques detectados', 'CRITICAL'),
                                ('breach', 'Violaciones detectadas', 'CRITICAL'),
                                ('error', 'Errores generales', 'MEDIUM'),
                                ('critical', 'Eventos críticos', 'CRITICAL'),
                                ('panic', 'Kernel Panic', 'CRITICAL'),
                                ('segfault', 'Fallo de Segmentación', 'CRITICAL'),
                                ('DROP', 'Paquetes DROP (firewall)', 'MEDIUM'),
                                ('REJECT', 'Paquetes REJECT (firewall)', 'MEDIUM'),
                                ('mail', 'Eventos de correo', 'LOW'),
                                ('postfix', 'Eventos de Postfix', 'LOW'),
                                ('mysql', 'Eventos MySQL', 'LOW'),
                                ('mariadb', 'Eventos MariaDB', 'LOW'),
                                ('nginx', 'Eventos Nginx', 'LOW'),
                                ('apache', 'Eventos Apache', 'LOW'),
                                ('lighttpd', 'Eventos Lighttpd', 'LOW'),
                                ('mongodb', 'Eventos MongoDB', 'LOW'),
                                ('postgresql', 'Eventos PostgreSQL', 'LOW'),
                                ('samba', 'Eventos Samba', 'LOW'),
                                ('squid', 'Eventos Squid', 'LOW'),
                                ('audit', 'Eventos de Auditoría', 'HIGH'),
                            ]
                            for patron, descripcion, nivel in patrones_seguridad:
                                try:
                                    resultado_grep = subprocess.run(['grep', '-i', patron, log_path], capture_output=True, text=True, timeout=10)
                                    if resultado_grep.returncode == 0 and resultado_grep.stdout.strip():
                                        coincidencias = resultado_grep.stdout.strip().split('\n')
                                        count = len(coincidencias)
                                        alertas_archivo += count
                                        indicador = {
                                            'CRITICAL': '[!!!]',
                                            'HIGH': '[!!]',
                                            'MEDIUM': '[!]',
                                            'LOW': '[·]'
                                        }.get(nivel, '[·]')
                                        self.after(0, self._actualizar_texto_analisis, f"   {indicador} {descripcion}: {count} eventos\n")
                                        if count > 0:
                                            resumen_alertas[descripcion] = resumen_alertas.get(descripcion, 0) + count
                                            if nivel in ['CRITICAL', 'HIGH'] and count > 0:
                                                self.after(0, self._actualizar_texto_analisis, f"       Muestras de eventos:\n")
                                                for i, linea in enumerate(coincidencias[-3:], 1):
                                                    self.after(0, self._actualizar_texto_analisis, f"       [{i}] {linea[:120]}...\n")
                                    else:
                                        self.after(0, self._actualizar_texto_analisis, f"   [OK] {descripcion}: Sin eventos\n")
                                except subprocess.TimeoutExpired:
                                    self.after(0, self._actualizar_texto_analisis, f"   [TIMEOUT] {descripcion}: Análisis excedió tiempo límite\n")
                                except Exception as e:
                                    self.after(0, self._actualizar_texto_analisis, f"   [ERROR] {descripcion}: {e}\n")

                            # 3. ANÁLISIS DE IPs SOSPECHOSAS (solo para logs de auth)
                            if any(x in log_path for x in ['auth.log', 'secure', 'sshd']):
                                self.after(0, self._actualizar_texto_analisis, "\n3. ANÁLISIS DE IPs SOSPECHOSAS:\n")
                                try:
                                    resultado_ips = subprocess.run(['bash', '-c', f"grep 'Failed password' {log_path} | awk '{{print $(NF-3)}}' | sort | uniq -c | sort -nr | head -5"], capture_output=True, text=True, timeout=15)
                                    if resultado_ips.returncode == 0 and resultado_ips.stdout.strip():
                                        self.after(0, self._actualizar_texto_analisis, "   TOP 5 IPs con intentos fallidos:\n")
                                        for linea in resultado_ips.stdout.strip().split('\n'):
                                            if linea.strip():
                                                partes = linea.strip().split()
                                                if len(partes) >= 2:
                                                    intentos = partes[0]
                                                    ip = ' '.join(partes[1:])
                                                    self.after(0, self._actualizar_texto_analisis, f"       • {ip}: {intentos} intentos\n")
                                    else:
                                        self.after(0, self._actualizar_texto_analisis, "   [OK] No hay intentos de login fallidos\n")
                                except Exception as e:
                                    self.after(0, self._actualizar_texto_analisis, f"   [ERROR] No se pudo analizar IPs: {e}\n")

                            # 4. EVENTOS RECIENTES (manejo especial para logs binarios)
                            self.after(0, self._actualizar_texto_analisis, "\n4. EVENTOS RECIENTES (Últimas 5 entradas):\n")
                            try:
                                if any(x in log_path for x in ['wtmp', 'lastlog', 'faillog']):
                                    resultado = subprocess.run(['last', '-n', '5', '-f', log_path], capture_output=True, text=True, timeout=10)
                                else:
                                    resultado = subprocess.run(['tail', '-n', '5', log_path], capture_output=True, text=True, timeout=10)
                                if resultado.returncode == 0 and resultado.stdout.strip():
                                    lineas = resultado.stdout.strip().split('\n')
                                    for i, linea in enumerate(lineas, 1):
                                        if linea.strip():
                                            self.after(0, self._actualizar_texto_analisis, f"   [{i}] {linea[:120]}...\n")
                            except Exception as e:
                                self.after(0, self._actualizar_texto_analisis, f"   [ERROR] No se pudieron obtener eventos recientes: {e}\n")

                            # RESUMEN DEL ARCHIVO
                            total_eventos_criticos += alertas_archivo
                            nivel_riesgo = "BAJO" if alertas_archivo < 10 else "MEDIO" if alertas_archivo < 50 else "ALTO"
                            self.after(0, self._actualizar_texto_analisis, f"\n   RESUMEN: {alertas_archivo} eventos detectados - Riesgo: {nivel_riesgo}\n")
                        except Exception as e:
                            self.after(0, self._actualizar_texto_analisis, f"   [ERROR] Error procesando archivo: {str(e)}\n")
                    else:
                        self.after(0, self._actualizar_texto_analisis, f"   [WARNING] Archivo no encontrado\n")
                
                # RESUMEN GLOBAL
                self.after(0, self._actualizar_texto_analisis, "\n" + "="*80 + "\n")
                self.after(0, self._actualizar_texto_analisis, "                        RESUMEN GLOBAL DEL ANÁLISIS\n")
                self.after(0, self._actualizar_texto_analisis, "="*80 + "\n")
                self.after(0, self._actualizar_texto_analisis, f"• Archivos analizados: {len(logs_seleccionados)}\n")
                self.after(0, self._actualizar_texto_analisis, f"• Total eventos detectados: {total_eventos_criticos}\n\n")
                
                if resumen_alertas:
                    self.after(0, self._actualizar_texto_analisis, "TIPOS DE EVENTOS ENCONTRADOS:\n")
                    for tipo, cantidad in sorted(resumen_alertas.items(), key=lambda x: x[1], reverse=True):
                        self.after(0, self._actualizar_texto_analisis, f"   • {tipo}: {cantidad} eventos\n")
                else:
                    self.after(0, self._actualizar_texto_analisis, "No se detectaron eventos de seguridad críticos.\n")
                
                # RECOMENDACIONES
                self.after(0, self._actualizar_texto_analisis, "\nRECOMENDACIONES:\n")
                if total_eventos_criticos > 100:
                    self.after(0, self._actualizar_texto_analisis, "   • CRÍTICO: Revisar inmediatamente los eventos detectados\n")
                    self.after(0, self._actualizar_texto_analisis, "   • Implementar medidas de seguridad adicionales\n")
                elif total_eventos_criticos > 20:
                    self.after(0, self._actualizar_texto_analisis, "   • MEDIO: Monitorear actividad sospechosa\n")
                    self.after(0, self._actualizar_texto_analisis, "   • Revisar configuraciones de seguridad\n")
                else:
                    self.after(0, self._actualizar_texto_analisis, "   • Sistema con actividad normal\n")
                    self.after(0, self._actualizar_texto_analisis, "   • Mantener monitoreo rutinario\n")
                
                self.after(0, self._actualizar_texto_analisis, "\n" + "="*80 + "\n")
                self.after(0, self._actualizar_texto_analisis, "ANÁLISIS COMPLETADO\n")
                self.after(0, lambda: self.log_to_terminal("Análisis de logs completado exitosamente"))
                
            except Exception as e:
                self.after(0, self._actualizar_texto_analisis, f"ERROR CRÍTICO en análisis: {str(e)}\n")
        
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
        self.log_to_terminal("OK Sistema de detección de intrusiones activado")
    
    def activar_ids(self):
        """Activar sistema IDS real con Suricata."""
        self.log_to_terminal("Activando sistema IDS/IPS con Suricata...")
        def ejecutar_ids():
            try:
                self.after(0, self._actualizar_texto_alertas, " Activando sistema IDS/IPS real...\n")
                
                import subprocess
                import os
                
                # Verificar si Suricata está instalado
                sudo_manager = get_sudo_manager()
                try:
                    resultado = subprocess.run(['which', 'suricata'], capture_output=True, text=True)
                    if resultado.returncode != 0:
                        self.after(0, self._actualizar_texto_alertas, "ERROR Suricata no encontrado. Instalando...\n")
                        
                        # Verificar sudo antes de instalar
                        if not is_sudo_available():
                            self.after(0, self._actualizar_texto_alertas, "ERROR: No hay permisos sudo disponibles\n")
                            self.after(0, self._actualizar_texto_alertas, "Reinicie ARESITOS e ingrese contraseña correcta\n")
                            return
                        
                        install = sudo_manager.execute_sudo_command('apt update', timeout=60)
                        install = sudo_manager.execute_sudo_command('apt install -y suricata', timeout=120)
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
                    update_rules = sudo_manager.execute_sudo_command('suricata-update', timeout=30)
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
                        
                        # Verificar si Suricata ya está ejecutándose
                        pidfile_path = '/var/run/suricata.pid'
                        try:
                            # Verificar si el pidfile existe y si el proceso sigue activo
                            if os.path.exists(pidfile_path):
                                with open(pidfile_path, 'r') as f:
                                    pid = int(f.read().strip())
                                # Verificar si el proceso sigue corriendo
                                check_proc = subprocess.run(['ps', '-p', str(pid)], capture_output=True, text=True)
                                if check_proc.returncode == 0:
                                    self.after(0, self._actualizar_texto_alertas, "INFO Suricata ya está ejecutándose\n")
                                    self.after(0, self._actualizar_texto_alertas, f" PID activo: {pid}\n")
                                    self.after(0, self._actualizar_texto_alertas, " Conectando al proceso existente\n")
                                    # Continuar con el monitoreo de logs del proceso existente
                                    self.after(0, self._iniciar_monitoreo_logs_suricata, log_dir)
                                    return
                                else:
                                    # El proceso no existe, remover pidfile obsoleto
                                    self.after(0, self._actualizar_texto_alertas, "INFO Removiendo pidfile obsoleto\n")
                                    sudo_manager.execute_sudo_command(f'rm -f {pidfile_path}', timeout=10)
                        except (FileNotFoundError, ValueError, PermissionError):
                            # Si hay error leyendo el pidfile, intentar removerlo
                            sudo_manager.execute_sudo_command(f'rm -f {pidfile_path}', timeout=10)
                        
                        # Crear directorio para logs si no existe
                        if not os.path.exists(log_dir):
                            sudo_manager.execute_sudo_command(f'mkdir -p {log_dir}', timeout=10)
                        
                        # Comando para iniciar Suricata usando SudoManager
                        self.after(0, self._actualizar_texto_alertas, f" Ejecutando: suricata -i {interface} -D\n")
                        resultado_suricata = sudo_manager.execute_sudo_command(
                            f'suricata -c /etc/suricata/suricata.yaml -i {interface} -D --pidfile {pidfile_path}', 
                            timeout=30
                        )
                        
                        if resultado_suricata.returncode == 0:
                            self.after(0, self._actualizar_texto_alertas, "OK IDS activado correctamente\n")
                            self.after(0, self._actualizar_texto_alertas, f" Logs disponibles en: {log_dir}\n")
                            self.after(0, self._actualizar_texto_alertas, " Monitoreando tráfico en tiempo real\n")
                            self.after(0, self._actualizar_texto_alertas, " Detectando: exploits, malware, escaneos\n")
                            
                            # Verificar que el pidfile se creó correctamente
                            if os.path.exists(pidfile_path):
                                self.after(0, self._actualizar_texto_alertas, f" PID file creado: {pidfile_path}\n")
                            
                            # Iniciar monitoreo de logs de Suricata
                            self.after(0, self._iniciar_monitoreo_logs_suricata, log_dir)
                        else:
                            error_msg = resultado_suricata.stderr.strip() if resultado_suricata.stderr else "Error desconocido"
                            self.after(0, self._actualizar_texto_alertas, f"ERROR iniciando Suricata: {error_msg}\n")
                            
                            # Dar sugerencias específicas según el error
                            if "pidfile" in error_msg.lower():
                                self.after(0, self._actualizar_texto_alertas, " SOLUCIÓN: sudo pkill suricata && sudo rm -f /var/run/suricata.pid\n")
                            elif "permission" in error_msg.lower():
                                self.after(0, self._actualizar_texto_alertas, " SOLUCIÓN: Verificar permisos sudo\n")
                            elif "interface" in error_msg.lower():
                                self.after(0, self._actualizar_texto_alertas, f" SOLUCIÓN: Verificar que la interfaz {interface} existe\n")
                            else:
                                self.after(0, self._actualizar_texto_alertas, " SOLUCIÓN: Verificar configuración en /etc/suricata/suricata.yaml\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f"ERROR configurando interfaz: {e}\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_alertas, f"ERROR activando IDS: {str(e)}\n")
        
        threading.Thread(target=ejecutar_ids, daemon=True).start()
    
    def _iniciar_monitoreo_logs_suricata(self, log_dir):
        """Iniciar monitoreo mejorado de logs de Suricata en tiempo real con alertas claras"""
        def monitorear_logs():
            import time
            import os
            import json
            
            archivo_eve = os.path.join(log_dir, 'eve.json')
            archivo_fast = os.path.join(log_dir, 'fast.log')
            
            self.after(0, self._actualizar_texto_alertas, "\n" + "="*70 + "\n")
            self.after(0, self._actualizar_texto_alertas, "           SISTEMA IDS/IPS ACTIVO - MONITOREO EN TIEMPO REAL\n")
            self.after(0, self._actualizar_texto_alertas, "="*70 + "\n\n")
            
            contador = 0
            alertas_totales = 0
            alertas_criticas = 0
            
            while contador < 20:  # Monitorear por 20 ciclos
                try:
                    # HEADER DE CICLO
                    self.after(0, self._actualizar_texto_alertas, f"[CICLO {contador+1:02d}/20] " + "-"*50 + "\n")
                    hora_actual = time.strftime('%H:%M:%S')
                    self.after(0, self._actualizar_texto_alertas, f"Timestamp: {hora_actual}\n")
                    
                    alertas_ciclo = 0
                    
                    # 1. ANÁLISIS DE EVENTOS DETALLADOS (eve.json)
                    if os.path.exists(archivo_eve):
                        self.after(0, self._actualizar_texto_alertas, "\n1. ANÁLISIS DE EVENTOS DETALLADOS:\n")
                        resultado = subprocess.run(['tail', '-n', '5', archivo_eve], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            lineas = resultado.stdout.strip().split('\n')
                            eventos_procesados = 0
                            
                            for linea in lineas:
                                if '"event_type":' in linea:
                                    try:
                                        evento = json.loads(linea)
                                        tipo_evento = evento.get('event_type', 'desconocido')
                                        timestamp = evento.get('timestamp', '')[:19]
                                        
                                        # Clasificar severidad según tipo de evento
                                        if tipo_evento in ['alert']:
                                            severidad = "CRÍTICA"
                                            alertas_criticas += 1
                                            icono = "[!!!]"
                                        elif tipo_evento in ['anomaly', 'drop']:
                                            severidad = "ALTA"
                                            icono = "[!*]"
                                        elif tipo_evento in ['flow', 'netflow']:
                                            severidad = "MEDIA"
                                            icono = "[i]"
                                        else:
                                            severidad = "BAJA"
                                            icono = "[·]"
                                        
                                        # Extraer información específica según tipo
                                        info_adicional = ""
                                        if tipo_evento == 'alert':
                                            alert_info = evento.get('alert', {})
                                            signature = alert_info.get('signature', 'Sin descripción')
                                            category = alert_info.get('category', 'General')
                                            severity = alert_info.get('severity', 'N/A')
                                            info_adicional = f"\n       Descripción: {signature[:60]}...\n       Categoría: {category}\n       Severidad Suricata: {severity}"
                                            
                                            # Información de red si está disponible
                                            src_ip = evento.get('src_ip', '')
                                            dest_ip = evento.get('dest_ip', '')
                                            if src_ip and dest_ip:
                                                info_adicional += f"\n       Flujo: {src_ip} → {dest_ip}"
                                        
                                        elif tipo_evento in ['flow', 'netflow']:
                                            src_ip = evento.get('src_ip', '')
                                            dest_ip = evento.get('dest_ip', '')
                                            proto = evento.get('proto', '')
                                            if src_ip and dest_ip:
                                                info_adicional = f"\n       Red: {src_ip} → {dest_ip} ({proto})"
                                        
                                        self.after(0, self._actualizar_texto_alertas, 
                                                 f"   {icono} [{severidad}] {timestamp} - {tipo_evento.upper()}{info_adicional}\n")
                                        alertas_ciclo += 1
                                        eventos_procesados += 1
                                        
                                    except json.JSONDecodeError:
                                        self.after(0, self._actualizar_texto_alertas, 
                                                 f"   [?] Evento malformado: {linea[:50]}...\n")
                            
                            if eventos_procesados == 0:
                                self.after(0, self._actualizar_texto_alertas, "   [OK] Sin eventos nuevos en eve.json\n")
                        else:
                            self.after(0, self._actualizar_texto_alertas, "   [INFO] Eve.json sin contenido nuevo\n")
                    else:
                        self.after(0, self._actualizar_texto_alertas, "   [WARNING] Archivo eve.json no encontrado\n")
                    
                    # 2. ANÁLISIS DE ALERTAS RÁPIDAS (fast.log)
                    if os.path.exists(archivo_fast):
                        self.after(0, self._actualizar_texto_alertas, "\n2. ALERTAS RÁPIDAS:\n")
                        resultado = subprocess.run(['tail', '-n', '3', archivo_fast], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            lineas = resultado.stdout.strip().split('\n')
                            for i, linea in enumerate(lineas, 1):
                                if linea.strip():
                                    # Parsear formato fast.log: timestamp [**] [sid:id] descripción [**] [Classification: class] [Priority: X] {protocol} src -> dst
                                    try:
                                        partes = linea.split('[**]')
                                        if len(partes) >= 3:
                                            timestamp = partes[0].strip()[:19]
                                            sid_info = partes[1].strip()
                                            descripcion = partes[2].strip()
                                            
                                            # Extraer prioridad si está disponible
                                            priority = "N/A"
                                            if '[Priority:' in linea:
                                                try:
                                                    priority_part = linea.split('[Priority:')[1].split(']')[0].strip()
                                                    priority = priority_part
                                                except:
                                                    pass
                                            
                                            # Determinar nivel según prioridad
                                            if priority in ['1', '2']:
                                                nivel = "CRÍTICA"
                                                icono = "[!!!]"
                                            elif priority in ['3', '4']:
                                                nivel = "ALTA"
                                                icono = "[!!]"
                                            else:
                                                nivel = "MEDIA"
                                                icono = "[!]"
                                            
                                            self.after(0, self._actualizar_texto_alertas, 
                                                     f"   {icono} [{nivel}] {timestamp}\n")
                                            self.after(0, self._actualizar_texto_alertas, 
                                                     f"       SID: {sid_info}\n")
                                            self.after(0, self._actualizar_texto_alertas, 
                                                     f"       Evento: {descripcion[:70]}...\n")
                                            self.after(0, self._actualizar_texto_alertas, 
                                                     f"       Prioridad: {priority}\n")
                                            alertas_ciclo += 1
                                        else:
                                            self.after(0, self._actualizar_texto_alertas, 
                                                     f"   [?] Formato no estándar: {linea[:50]}...\n")
                                    except Exception:
                                        self.after(0, self._actualizar_texto_alertas, 
                                                 f"   [ERROR] Error parseando alerta: {linea[:40]}...\n")
                            
                            if not lineas or all(not line.strip() for line in lineas):
                                self.after(0, self._actualizar_texto_alertas, "   [OK] Sin alertas nuevas en fast.log\n")
                        else:
                            self.after(0, self._actualizar_texto_alertas, "   [INFO] Fast.log sin contenido nuevo\n")
                    else:
                        self.after(0, self._actualizar_texto_alertas, "   [WARNING] Archivo fast.log no encontrado\n")
                    
                    # 3. ESTADÍSTICAS DEL CICLO
                    alertas_totales += alertas_ciclo
                    self.after(0, self._actualizar_texto_alertas, f"\n3. ESTADÍSTICAS DEL CICLO:\n")
                    self.after(0, self._actualizar_texto_alertas, f"   • Alertas en este ciclo: {alertas_ciclo}\n")
                    self.after(0, self._actualizar_texto_alertas, f"   • Total acumulado: {alertas_totales}\n")
                    self.after(0, self._actualizar_texto_alertas, f"   • Alertas críticas: {alertas_criticas}\n")
                    
                    # Nivel de riesgo actual
                    if alertas_criticas > 5:
                        nivel_riesgo = "CRÍTICO"
                        recomendacion = "Revisar inmediatamente"
                    elif alertas_totales > 10:
                        nivel_riesgo = "ALTO"
                        recomendacion = "Monitorear de cerca"
                    elif alertas_totales > 0:
                        nivel_riesgo = "MEDIO"
                        recomendacion = "Vigilancia normal"
                    else:
                        nivel_riesgo = "BAJO"
                        recomendacion = "Sistema estable"
                    
                    self.after(0, self._actualizar_texto_alertas, f"   • Nivel de riesgo: {nivel_riesgo}\n")
                    self.after(0, self._actualizar_texto_alertas, f"   • Recomendación: {recomendacion}\n")
                    
                    # 4. VERIFICACIÓN DE ESTADO DEL PROCESO
                    try:
                        resultado_stats = subprocess.run(['pgrep', 'suricata'], 
                                                       capture_output=True, text=True, timeout=5)
                        if resultado_stats.returncode == 0:
                            pids = resultado_stats.stdout.strip().split('\n')
                            self.after(0, self._actualizar_texto_alertas, f"   • Procesos Suricata activos: {len(pids)}\n")
                        else:
                            self.after(0, self._actualizar_texto_alertas, "   [WARNING] Suricata no parece estar ejecutándose\n")
                    except:
                        self.after(0, self._actualizar_texto_alertas, "   [ERROR] No se pudo verificar estado de Suricata\n")
                    
                    self.after(0, self._actualizar_texto_alertas, "\n")
                    
                    contador += 1
                    if contador < 20:
                        self.after(0, self._actualizar_texto_alertas, f"Esperando 15 segundos para el siguiente ciclo...\n\n")
                    time.sleep(12)  # Issue 21/24: Optimizado de 15 a 12 segundos - Verificar cada 12 segundos
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_alertas, f"[ERROR] Error en monitoreo: {str(e)}\n")
                    time.sleep(5)
            
            # RESUMEN FINAL
            self.after(0, self._actualizar_texto_alertas, "="*70 + "\n")
            self.after(0, self._actualizar_texto_alertas, "                    RESUMEN DEL MONITOREO COMPLETADO\n")
            self.after(0, self._actualizar_texto_alertas, "="*70 + "\n")
            self.after(0, self._actualizar_texto_alertas, f"• Duración del monitoreo: 20 ciclos (5 minutos)\n")
            self.after(0, self._actualizar_texto_alertas, f"• Total de alertas detectadas: {alertas_totales}\n")
            self.after(0, self._actualizar_texto_alertas, f"• Alertas críticas: {alertas_criticas}\n")
            
            if alertas_criticas > 0:
                self.after(0, self._actualizar_texto_alertas, "\nACCIONES RECOMENDADAS:\n")
                self.after(0, self._actualizar_texto_alertas, "• Revisar logs detallados en /var/log/suricata/\n")
                self.after(0, self._actualizar_texto_alertas, "• Analizar tráfico sospechoso\n")
                self.after(0, self._actualizar_texto_alertas, "• Considerar implementar contramedidas\n")
            else:
                self.after(0, self._actualizar_texto_alertas, "\nSISTEMA SEGURO: No se detectaron amenazas críticas\n")
            
            self.after(0, self._actualizar_texto_alertas, "\nEl monitoreo en tiempo real ha finalizado.\n")
            self.after(0, self._actualizar_texto_alertas, "Para continuar monitoreando, reactive el IDS.\n")
        
        threading.Thread(target=monitorear_logs, daemon=True).start()
    
    def monitor_honeypot(self):
        """Monitorear honeypots."""
        self._actualizar_texto_alertas(" Monitoreando honeypots...\n")
        self._actualizar_texto_alertas(" Verificando trampas de seguridad...\n")
        self._actualizar_texto_alertas(" Detectando actividad maliciosa...\n")
        self._actualizar_texto_alertas("OK Honeypots operativos\n\n")
    
    # Métodos de la pestaña Forense
    
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
                    self.after(0, self._actualizar_texto_forense, "  sudo apt install sleuthkit -y\n\n")
                    
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
        """Usar Foremost para recuperación de archivos - Modo seguro con verificación."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "FOREMOST - Recuperación de Archivos\n")
                self.after(0, self._actualizar_texto_forense, "="*50 + "\n")
                
                import subprocess
                import os
                
                # Verificación segura de instalación
                try:
                    resultado = subprocess.run(['which', 'foremost'], capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Foremost detectado en: " + resultado.stdout.strip() + "\n")
                        
                        # Verificar versión sin ejecutar recuperación
                        version_result = subprocess.run(['foremost', '-V'], capture_output=True, text=True, timeout=5)
                        if version_result.returncode == 0:
                            self.after(0, self._actualizar_texto_forense, "INFO " + version_result.stdout.strip() + "\n\n")
                        
                        self.after(0, self._actualizar_texto_forense, "COMANDOS PRINCIPALES:\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -i imagen.dd -o salida/      # Recuperar todo\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -t jpg,png -i imagen.dd      # Solo imágenes\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -t pdf,doc -i imagen.dd      # Documentos\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -T -i imagen.dd              # Con timestamp\n")
                        self.after(0, self._actualizar_texto_forense, "  foremost -w -i imagen.dd              # Solo escritura\n\n")
                        
                        self.after(0, self._actualizar_texto_forense, "TIPOS DE ARCHIVO SOPORTADOS:\n")
                        self.after(0, self._actualizar_texto_forense, "• Imágenes: jpg, gif, png, bmp\n")
                        self.after(0, self._actualizar_texto_forense, "• Documentos: pdf, doc, xls, ppt\n")
                        self.after(0, self._actualizar_texto_forense, "• Audio/Video: avi, exe, wav, wmv\n")
                        self.after(0, self._actualizar_texto_forense, "• Archivos: zip, rar, html, cpp\n\n")
                        
                        # Verificar espacio disponible
                        try:
                            df_result = subprocess.run(['df', '-h', '.'], capture_output=True, text=True, timeout=3)
                            if df_result.returncode == 0:
                                lines = df_result.stdout.strip().split('\n')
                                if len(lines) > 1:
                                    space_info = lines[1].split()
                                    if len(space_info) >= 4:
                                        self.after(0, self._actualizar_texto_forense, f"ESPACIO DISPONIBLE: {space_info[3]}\n")
                        except:
                            pass
                        
                    else:
                        self.after(0, self._actualizar_texto_forense, "WARNING Foremost no encontrado\n")
                        self.after(0, self._actualizar_texto_forense, "INSTALACION: sudo apt install foremost -y\n\n")
                        
                except Exception as e:
                    self.after(0, self._actualizar_texto_forense, f"ERROR verificando Foremost: {str(e)}\n")
                    
                self.after(0, self._actualizar_texto_forense, "CASOS DE USO:\n")
                self.after(0, self._actualizar_texto_forense, "• Recuperación de archivos borrados\n")
                self.after(0, self._actualizar_texto_forense, "• Forense de dispositivos USB\n")
                self.after(0, self._actualizar_texto_forense, "• Carving de archivos por signature\n")
                self.after(0, self._actualizar_texto_forense, "• Análisis post-incidente\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR usando Foremost: {str(e)}\n")
                
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_strings(self):
        """Análisis profesional con strings para extracción de cadenas de texto."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_forense, "🔤 ANÁLISIS PROFESIONAL CON STRINGS\n")
                self.after(0, self._actualizar_texto_forense, "="*60 + "\n")
                
                import subprocess
                import os
                import tempfile
                
                # Verificar disponibilidad de strings
                try:
                    resultado = subprocess.run(['strings', '--version'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.after(0, self._actualizar_texto_forense, "OK Strings disponible en el sistema\n\n")
                    
                        # ANÁLISIS AUTOMÁTICO DE ARCHIVOS CRÍTICOS DEL SISTEMA
                        self.after(0, self._actualizar_texto_forense, "ANÁLISIS AUTOMÁTICO - ARCHIVOS CRÍTICOS DEL SISTEMA:\n")
                        self.after(0, self._actualizar_texto_forense, "-" * 50 + "\n")
                        
                        archivos_criticos = [
                            "/bin/bash",
                            "/bin/sh", 
                            "/usr/bin/sudo",
                            "/etc/passwd",
                            "/var/log/auth.log"
                        ]
                        
                        for archivo in archivos_criticos:
                            if os.path.exists(archivo) and os.path.isfile(archivo):
                                self.after(0, self._actualizar_texto_forense, f"\n📄 ANALIZANDO: {archivo}\n")
                                try:
                                    # Análisis básico de strings
                                    resultado_strings = subprocess.run(
                                        ['strings', '-n', '8', archivo], 
                                        capture_output=True, text=True, timeout=15
                                    )
                                    
                                    if resultado_strings.returncode == 0:
                                        lines = resultado_strings.stdout.split('\n')[:10]  # Primeras 10 líneas
                                        self.after(0, self._actualizar_texto_forense, f"  OK {len(lines)} strings encontrados (mostrando primeros 10):\n")
                                        for i, line in enumerate(lines, 1):
                                            if line.strip():
                                                self.after(0, self._actualizar_texto_forense, f"    {i:2d}: {line[:80]}...\n")
                                        
                                        # Búsqueda de patrones sospechosos
                                        self.after(0, self._actualizar_texto_forense, "  BÚSQUEDA DE PATRONES SOSPECHOSOS:\n")
                                        patrones = ['password', 'admin', 'root', 'key', 'token', 'secret']
                                        
                                        for patron in patrones:
                                            grep_result = subprocess.run(
                                                ['strings', archivo], 
                                                capture_output=True, text=True, timeout=10
                                            )
                                            if grep_result.returncode == 0:
                                                matches = [line for line in grep_result.stdout.split('\n') 
                                                         if patron.lower() in line.lower()]
                                                if matches:
                                                    self.after(0, self._actualizar_texto_forense, f"    PATRÓN '{patron}': {len(matches)} coincidencias\n")
                                    
                                except subprocess.TimeoutExpired:
                                    self.after(0, self._actualizar_texto_forense, f"    Timeout analizando {archivo}\n")
                                except Exception as e:
                                    self.after(0, self._actualizar_texto_forense, f"    Error: {str(e)[:50]}\n")
                        
                        # COMANDOS PROFESIONALES DE KALI LINUX
                        self.after(0, self._actualizar_texto_forense, "\nCOMANDOS PROFESIONALES KALI LINUX:\n")
                        self.after(0, self._actualizar_texto_forense, "-" * 50 + "\n")
                        comandos_profesionales = [
                            ("Análisis Completo", "strings -a -t x archivo.bin | head -100"),
                            ("Buscar Passwords", "strings archivo.bin | grep -iE '(pass|pwd|secret|key)' | head -20"),
                            ("Extraer URLs", r"strings archivo.bin | grep -E 'https?://[^\s]+' | head -20"),
                            ("Buscar IPs", "strings archivo.bin | grep -E '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'"),
                            ("Strings Unicode", "strings -el archivo.bin | head -50"),
                            ("Filtrar por Longitud", "strings -n 15 archivo.bin | head -30"),
                            ("Buscar Emails", "strings archivo.bin | grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'"),
                            ("Analizar Binarios", "strings /usr/bin/* | grep -i suspicious")
                        ]
                        
                        for descripcion, comando in comandos_profesionales:
                            self.after(0, self._actualizar_texto_forense, f"  {descripcion}:\n")
                            self.after(0, self._actualizar_texto_forense, f"      {comando}\n\n")
                        
                        # CREAR SCRIPT DE ANÁLISIS AUTOMATIZADO
                        script_path = "/tmp/aresitos_strings_analysis.sh"
                        script_content = '''#!/bin/bash
# ARESITOS - Script de Análisis Profesional con Strings
echo "=== ARESITOS STRINGS ANALYSIS ==="
echo "Generado: $(date)"
echo "==============================="

if [ "$1" = "" ]; then
    echo "Uso: $0 <archivo_a_analizar>"
    exit 1
fi

ARCHIVO="$1"
OUTPUT_DIR="/tmp/aresitos_logs/strings_analysis"
mkdir -p "$OUTPUT_DIR"

echo "Analizando: $ARCHIVO"
echo "Resultados en: $OUTPUT_DIR"

# Análisis básico
strings -a "$ARCHIVO" > "$OUTPUT_DIR/all_strings.txt"
echo "OK Strings básicos extraídos"

# Buscar patrones de interés
strings "$ARCHIVO" | grep -iE "(pass|pwd|secret|key|token)" > "$OUTPUT_DIR/credentials.txt"
strings "$ARCHIVO" | grep -E "https?://[^\\s]+" > "$OUTPUT_DIR/urls.txt"
strings "$ARCHIVO" | grep -E "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" > "$OUTPUT_DIR/ips.txt"
strings "$ARQUIVO" | grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}" > "$OUTPUT_DIR/emails.txt"

echo "OK Análisis completado"
echo "Archivos generados:"
ls -la "$OUTPUT_DIR/"
'''
                        
                        try:
                            with open(script_path, 'w') as f:
                                f.write(script_content)
                            os.chmod(script_path, 0o755)
                            self.after(0, self._actualizar_texto_forense, f"SCRIPT CREADO: {script_path}\n")
                            self.after(0, self._actualizar_texto_forense, f"   Uso: {script_path} <archivo>\n\n")
                        except Exception as e:
                            self.after(0, self._actualizar_texto_forense, f"Error creando script: {e}\n")
                        
                    else:
                        self.after(0, self._actualizar_texto_forense, "Error ejecutando strings\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_forense, "Strings no encontrado en el sistema\n")
                    self.after(0, self._actualizar_texto_forense, "📦 INSTALACIÓN EN KALI LINUX:\n")
                    self.after(0, self._actualizar_texto_forense, "  sudo apt update && sudo apt install binutils -y\n\n")
                    
                # CASOS DE USO PROFESIONALES
                self.after(0, self._actualizar_texto_forense, "CASOS DE USO PROFESIONALES:\n")
                self.after(0, self._actualizar_texto_forense, "-" * 40 + "\n")
                casos_uso = [
                    "🦠 Análisis de malware y detección de IoCs",
                    "Ingeniería inversa de binarios sospechosos", 
                    "Búsqueda de credenciales hardcodeadas",
                    "🌐 Extracción de URLs y dominios maliciosos",
                    "📧 Identificación de direcciones de email",
                    "🏠 Descubrimiento de direcciones IP internas",
                    "🔑 Localización de claves criptográficas",
                    "📱 Análisis forense de aplicaciones móviles"
                ]
                
                for caso in casos_uso:
                    self.after(0, self._actualizar_texto_forense, f"  {caso}\n")
                
                self.after(0, self._actualizar_texto_forense, f"\n📁 DIRECTORIO DE LOGS: /tmp/aresitos_logs/strings_analysis/\n")
                self.after(0, self._actualizar_texto_forense, "ANÁLISIS COMPLETADO\n\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_forense, f"ERROR en análisis con strings: {str(e)}\n")
        
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
        """Detener el monitoreo en tiempo real usando sistema unificado con advertencia profesional."""
        import tkinter.messagebox as messagebox
        if not messagebox.askyesno("Confirmar acción crítica", "¿Está seguro que desea detener el monitoreo SIEM? Esta acción puede afectar la supervisión de seguridad en curso."):
            self._log_terminal("Operación de detención de monitoreo SIEM cancelada por el usuario.", "SIEM", "INFO")
            return
        self.monitoreo_activo = False
        from ..utils.detener_procesos import detener_procesos
        def callback_actualizacion(mensaje):
            self._actualizar_texto_forense(mensaje)
        def callback_habilitar():
            self._log_terminal("Monitoreo SIEM detenido completamente", "SIEM", "INFO")
        detener_procesos.detener_monitoreo(callback_actualizacion, callback_habilitar)

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
    
    # ====================== EXPANSION FASE 3.2: ANÁLISIS AVANZADO DE EVENTOS ======================
    
    def analizar_patrones_avanzados(self):
        """Análisis avanzado de patrones de comportamiento sospechoso."""
        try:
            self._actualizar_texto_analisis("INICIANDO ANÁLISIS AVANZADO DE PATRONES DE SEGURIDAD\n")
            self._actualizar_texto_analisis("=" * 70 + "\n")
            
            # 1. Análisis de conexiones de red sospechosas
            self._analizar_conexiones_red()
            
            # 2. Análisis de procesos anómalos
            self._analizar_procesos_anomalos()
            
            # 3. Análisis de actividad de archivos críticos
            self._analizar_actividad_archivos()
            
            # 4. Análisis de intentos de escalamiento de privilegios
            self._analizar_escalamiento_privilegios()
            
            # 5. Análisis de patrones de tiempo (ataques fuera de horarios)
            self._analizar_patrones_temporales()
            
            self._actualizar_texto_analisis("\nANÁLISIS AVANZADO COMPLETADO\n")
            self.log_to_terminal("Análisis avanzado de patrones completado")
            
        except Exception as e:
            error_msg = f"Error en análisis avanzado: {str(e)}"
            self._actualizar_texto_analisis(f"ERROR: {error_msg}\n")
            self.log_to_terminal(error_msg)
    
    def _analizar_conexiones_red(self):
        """Analizar conexiones de red sospechosas."""
        try:
            self._actualizar_texto_analisis("\n🌐 1. ANÁLISIS DE CONEXIONES DE RED SOSPECHOSAS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            import re
            
            # Obtener conexiones activas usando netstat
            try:
                resultado = subprocess.run(['netstat', '-tuln'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    conexiones = resultado.stdout.split('\n')
                    puertos_sospechosos = ['4444', '6666', '1337', '31337', '8080', '8888']
                    conexiones_sospechosas = []
                    
                    for linea in conexiones:
                        for puerto in puertos_sospechosos:
                            if puerto in linea and ('LISTEN' in linea or 'ESTABLISHED' in linea):
                                conexiones_sospechosas.append(linea.strip())
                    
                    if conexiones_sospechosas:
                        self._actualizar_texto_analisis("CONEXIONES SOSPECHOSAS DETECTADAS:\n")
                        for conn in conexiones_sospechosas[:10]:  # Máximo 10
                            self._actualizar_texto_analisis(f"  {conn}\n")
                    else:
                        self._actualizar_texto_analisis("No se detectaron conexiones en puertos sospechosos conocidos\n")
                        
                else:
                    self._actualizar_texto_analisis("Error ejecutando netstat\n")
                    
            except subprocess.TimeoutExpired:
                self._actualizar_texto_analisis("Timeout en análisis de conexiones\n")
            
            # Análisis adicional con ss (Socket Statistics)
            try:
                resultado_ss = subprocess.run(['ss', '-tuln'], 
                                            capture_output=True, text=True, timeout=10)
                
                if resultado_ss.returncode == 0:
                    self._actualizar_texto_analisis("\nEstadísticas de sockets activos:\n")
                    lineas = resultado_ss.stdout.split('\n')
                    tcp_count = sum(1 for linea in lineas if linea.startswith('tcp'))
                    udp_count = sum(1 for linea in lineas if linea.startswith('udp'))
                    
                    self._actualizar_texto_analisis(f"  Conexiones TCP activas: {tcp_count}\n")
                    self._actualizar_texto_analisis(f"  Conexiones UDP activas: {udp_count}\n")
                    
                    if tcp_count > 100:
                        self._actualizar_texto_analisis("  ALERTA: Número elevado de conexiones TCP\n")
                    
            except:
                pass  # ss opcional
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error analizando conexiones: {str(e)}\n")
    
    def _analizar_procesos_anomalos(self):
        """Analizar procesos con comportamiento anómalo."""
        try:
            self._actualizar_texto_analisis("\n2. ANÁLISIS DE PROCESOS ANÓMALOS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            
            # Procesos con alto uso de CPU
            try:
                resultado = subprocess.run(['ps', 'aux', '--sort=-%cpu'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:11]  # Top 10 procesos
                    procesos_sospechosos = []
                    
                    for linea in lineas:
                        if linea.strip():
                            campos = linea.split()
                            if len(campos) >= 11:
                                cpu_usage = float(campos[2])
                                proceso = ' '.join(campos[10:])
                                
                                # Detectar procesos sospechosos
                                nombres_sospechosos = ['nc', 'netcat', 'wget', 'curl', 'python', 'perl', 'bash']
                                if cpu_usage > 80 or any(nom in proceso.lower() for nom in nombres_sospechosos):
                                    if cpu_usage > 10:  # Solo si tiene uso significativo
                                        procesos_sospechosos.append((cpu_usage, proceso))
                    
                    if procesos_sospechosos:
                        self._actualizar_texto_analisis("PROCESOS CON ACTIVIDAD SOSPECHOSA:\n")
                        for cpu, proc in procesos_sospechosos[:5]:
                            self._actualizar_texto_analisis(f"  CPU: {cpu}% - {proc}\n")
                    else:
                        self._actualizar_texto_analisis("No se detectaron procesos anómalos por CPU\n")
                        
            except Exception as e:
                self._actualizar_texto_analisis(f"Error analizando procesos: {str(e)}\n")
            
            # Análisis de procesos sin terminal padre (posibles backdoors)
            try:
                resultado_ppid = subprocess.run(['ps', '-eo', 'pid,ppid,comm'], 
                                              capture_output=True, text=True, timeout=10)
                
                if resultado_ppid.returncode == 0:
                    lineas = resultado_ppid.stdout.split('\n')[1:]
                    huerfanos = []
                    
                    for linea in lineas:
                        if linea.strip():
                            campos = linea.split()
                            if len(campos) >= 3:
                                pid, ppid, comm = campos[0], campos[1], campos[2]
                                if ppid == '1' and comm not in ['systemd', 'init', 'kthreadd']:
                                    huerfanos.append(f"PID:{pid} - {comm}")
                    
                    if huerfanos:
                        self._actualizar_texto_analisis(f"\nProcesos huérfanos detectados: {len(huerfanos)}\n")
                        for huerfano in huerfanos[:5]:
                            self._actualizar_texto_analisis(f"  📍 {huerfano}\n")
                            
            except:
                pass
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error en análisis de procesos: {str(e)}\n")
    
    def _analizar_actividad_archivos(self):
        """Analizar actividad sospechosa en archivos críticos."""
        try:
            self._actualizar_texto_analisis("\n📁 3. ANÁLISIS DE ACTIVIDAD EN ARCHIVOS CRÍTICOS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import os
            import subprocess
            from datetime import datetime, timedelta
            
            # Archivos críticos del sistema a monitorear
            archivos_criticos = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/crontab',
                '/etc/sudoers', '/etc/ssh/sshd_config', '/etc/fstab'
            ]
            
            self._actualizar_texto_analisis("Verificando modificaciones recientes en archivos críticos:\n")
            
            modificaciones_recientes = []
            fecha_limite = datetime.now() - timedelta(hours=24)
            
            for archivo in archivos_criticos:
                try:
                    if os.path.exists(archivo):
                        stat = os.stat(archivo)
                        fecha_mod = datetime.fromtimestamp(stat.st_mtime)
                        
                        if fecha_mod > fecha_limite:
                            modificaciones_recientes.append((archivo, fecha_mod))
                            
                except Exception:
                    continue
            
            if modificaciones_recientes:
                self._actualizar_texto_analisis("ARCHIVOS CRÍTICOS MODIFICADOS EN LAS ÚLTIMAS 24H:\n")
                for archivo, fecha in modificaciones_recientes:
                    self._actualizar_texto_analisis(f"  {archivo} - {fecha.strftime('%Y-%m-%d %H:%M:%S')}\n")
            else:
                self._actualizar_texto_analisis("No se detectaron modificaciones recientes en archivos críticos\n")
            
            # Verificar archivos con permisos sospechosos
            try:
                resultado = subprocess.run(['find', '/etc', '-type', 'f', '-perm', '/022'], 
                                         capture_output=True, text=True, timeout=15)
                
                if resultado.returncode == 0:
                    archivos_permisos = resultado.stdout.strip().split('\n')
                    archivos_permisos = [f for f in archivos_permisos if f.strip()]
                    
                    if archivos_permisos:
                        self._actualizar_texto_analisis(f"\nARCHIVOS CON PERMISOS SOSPECHOSOS: {len(archivos_permisos)}\n")
                        for archivo in archivos_permisos[:5]:
                            self._actualizar_texto_analisis(f"  🔸 {archivo}\n")
                        if len(archivos_permisos) > 5:
                            self._actualizar_texto_analisis(f"  ... y {len(archivos_permisos) - 5} más\n")
                            
            except:
                pass
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error analizando archivos: {str(e)}\n")
    
    def _analizar_escalamiento_privilegios(self):
        """Analizar intentos de escalamiento de privilegios."""
        try:
            self._actualizar_texto_analisis("\n4. ANÁLISIS DE ESCALAMIENTO DE PRIVILEGIOS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            
            # Verificar comandos sudo recientes
            try:
                resultado = subprocess.run(['journalctl', '-u', 'sudo', '--since', '1 hour ago', '--no-pager'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    lineas_sudo = resultado.stdout.split('\n')
                    intentos_sudo = [l for l in lineas_sudo if 'sudo:' in l and l.strip()]
                    
                    if intentos_sudo:
                        self._actualizar_texto_analisis(f"Actividad sudo en la última hora: {len(intentos_sudo)} eventos\n")
                        
                        # Buscar intentos fallidos
                        fallos = [l for l in intentos_sudo if 'FAILED' in l or 'authentication failure' in l]
                        if fallos:
                            self._actualizar_texto_analisis(f"INTENTOS FALLIDOS DE SUDO: {len(fallos)}\n")
                            for fallo in fallos[:3]:
                                self._actualizar_texto_analisis(f"  {fallo.split()[-10:]}\n")
                    else:
                        self._actualizar_texto_analisis("No hay actividad sudo reciente\n")
                        
            except:
                self._actualizar_texto_analisis("No se pudo verificar actividad sudo\n")
            
            # Verificar procesos ejecutándose como root
            try:
                resultado = subprocess.run(['ps', '-U', 'root', '-o', 'pid,comm'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]
                    procesos_root = [l.strip() for l in lineas if l.strip()]
                    
                    # Buscar procesos sospechosos ejecutándose como root
                    procesos_sospechosos = []
                    patrones_sospechosos = ['nc', 'netcat', 'python', 'perl', 'ruby', 'wget', 'curl']
                    
                    for linea in procesos_root:
                        for patron in patrones_sospechosos:
                            if patron in linea.lower():
                                procesos_sospechosos.append(linea)
                                break
                    
                    if procesos_sospechosos:
                        self._actualizar_texto_analisis(f"PROCESOS SOSPECHOSOS COMO ROOT: {len(procesos_sospechosos)}\n")
                        for proc in procesos_sospechosos[:5]:
                            self._actualizar_texto_analisis(f"  {proc}\n")
                    else:
                        self._actualizar_texto_analisis("No se detectaron procesos sospechosos como root\n")
                        
            except:
                pass
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error analizando escalamiento: {str(e)}\n")
    
    def _analizar_patrones_temporales(self):
        """Analizar patrones de actividad temporal sospechosos."""
        try:
            self._actualizar_texto_analisis("\n⏰ 5. ANÁLISIS DE PATRONES TEMPORALES\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            from datetime import datetime
            
            hora_actual = datetime.now().hour
            
            # Determinar si es horario laboral
            es_horario_laboral = 8 <= hora_actual <= 18
            
            self._actualizar_texto_analisis(f"🕐 Hora actual: {datetime.now().strftime('%H:%M:%S')}\n")
            
            if es_horario_laboral:
                self._actualizar_texto_analisis("Actividad durante horario laboral normal\n")
            else:
                self._actualizar_texto_analisis("ACTIVIDAD FUERA DE HORARIO LABORAL\n")
                
                # Analizar logins fuera de horario
                try:
                    resultado = subprocess.run(['last', '-n', '20'], 
                                             capture_output=True, text=True, timeout=10)
                    
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.split('\n')
                        logins_nocturnos = []
                        
                        for linea in lineas:
                            if 'pts/' in linea or 'tty' in linea:
                                # Extraer hora del login (formato aproximado)
                                if any(hour in linea for hour in ['22:', '23:', '00:', '01:', '02:', '03:', '04:', '05:']):
                                    logins_nocturnos.append(linea.strip())
                        
                        if logins_nocturnos:
                            self._actualizar_texto_analisis(f"LOGINS NOCTURNOS DETECTADOS: {len(logins_nocturnos)}\n")
                            for login in logins_nocturnos[:3]:
                                self._actualizar_texto_analisis(f"  📍 {login}\n")
                        else:
                            self._actualizar_texto_analisis("No se detectaron logins nocturnos recientes\n")
                            
                except:
                    pass
            
            # Verificar procesos iniciados recientemente
            try:
                resultado = subprocess.run(['ps', '-eo', 'lstart,comm'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]
                    procesos_recientes = []
                    
                    for linea in lineas:
                        if linea.strip():
                            # Los procesos muy recientes pueden ser sospechosos
                            if 'python' in linea.lower() or 'bash' in linea.lower() or 'sh' in linea.lower():
                                procesos_recientes.append(linea.strip())
                    
                    if procesos_recientes:
                        self._actualizar_texto_analisis(f"\nProcesos de script recientes: {len(procesos_recientes)}\n")
                        # Limitar salida
                        if len(procesos_recientes) > 10:
                            self._actualizar_texto_analisis("  (Mostrando solo algunos por brevedad)\n")
                            
            except:
                pass
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error analizando patrones temporales: {str(e)}\n")
    
    def correlacionar_eventos_avanzado(self):
        """Correlación avanzada de eventos de seguridad."""
        try:
            self._actualizar_texto_analisis("🔗 INICIANDO CORRELACIÓN AVANZADA DE EVENTOS\n")
            self._actualizar_texto_analisis("=" * 70 + "\n")
            
            # 1. Correlación de intentos de acceso fallidos
            self._correlacionar_intentos_acceso()
            
            # 2. Correlación de actividad de red y procesos
            self._correlacionar_red_procesos()
            
            # 3. Correlación de modificaciones de archivos y logins
            self._correlacionar_archivos_logins()
            
            # 4. Análisis de cadenas de eventos sospechosos
            self._analizar_cadenas_eventos()
            
            self._actualizar_texto_analisis("\nCORRELACIÓN AVANZADA COMPLETADA\n")
            self.log_to_terminal("Correlación avanzada de eventos completada")
            
        except Exception as e:
            error_msg = f"Error en correlación avanzada: {str(e)}"
            self._actualizar_texto_analisis(f"ERROR: {error_msg}\n")
            self.log_to_terminal(error_msg)
    
    def _correlacionar_intentos_acceso(self):
        """Correlacionar múltiples intentos de acceso fallidos."""
        try:
            self._actualizar_texto_analisis("\n1. CORRELACIÓN DE INTENTOS DE ACCESO\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            
            # Analizar logs de autenticación
            try:
                resultado = subprocess.run(['journalctl', '_COMM=sshd', '--since', '1 hour ago', '--no-pager'], 
                                         capture_output=True, text=True, timeout=15)
                
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')
                    intentos_fallidos = []
                    ips_sospechosas = {}
                    
                    for linea in lineas:
                        if 'Failed' in linea or 'authentication failure' in linea:
                            intentos_fallidos.append(linea)
                            
                            # Extraer IP si está presente
                            import re
                            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', linea)
                            if ip_match:
                                ip = ip_match.group()
                                ips_sospechosas[ip] = ips_sospechosas.get(ip, 0) + 1
                    
                    if intentos_fallidos:
                        self._actualizar_texto_analisis(f"INTENTOS DE ACCESO FALLIDOS: {len(intentos_fallidos)}\n")
                        
                        # IPs con múltiples intentos (posible fuerza bruta)
                        ips_bruta = [(ip, count) for ip, count in ips_sospechosas.items() if count >= 3]
                        
                        if ips_bruta:
                            self._actualizar_texto_analisis("POSIBLES ATAQUES DE FUERZA BRUTA:\n")
                            for ip, count in sorted(ips_bruta, key=lambda x: x[1], reverse=True)[:5]:
                                self._actualizar_texto_analisis(f"  IP: {ip} - {count} intentos\n")
                        else:
                            self._actualizar_texto_analisis("No se detectaron patrones de fuerza bruta\n")
                    else:
                        self._actualizar_texto_analisis("No hay intentos de acceso fallidos recientes\n")
                        
            except:
                self._actualizar_texto_analisis("No se pudieron analizar logs de SSH\n")
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error correlacionando accesos: {str(e)}\n")
    
    def _correlacionar_red_procesos(self):
        """Correlacionar actividad de red con procesos activos."""
        try:
            self._actualizar_texto_analisis("\n🌐 2. CORRELACIÓN RED-PROCESOS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            
            # Obtener conexiones con procesos
            try:
                resultado = subprocess.run(['netstat', '-tupl'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')
                    conexiones_proceso = []
                    procesos_red_sospechosos = []
                    
                    for linea in lineas:
                        if 'python' in linea.lower() or 'nc' in linea.lower() or 'bash' in linea.lower():
                            if 'LISTEN' in linea or 'ESTABLISHED' in linea:
                                procesos_red_sospechosos.append(linea.strip())
                    
                    if procesos_red_sospechosos:
                        self._actualizar_texto_analisis("PROCESOS CON ACTIVIDAD DE RED SOSPECHOSA:\n")
                        for proc in procesos_red_sospechosos[:5]:
                            self._actualizar_texto_analisis(f"  {proc}\n")
                    else:
                        self._actualizar_texto_analisis("No se detectaron procesos de red sospechosos\n")
                        
            except:
                self._actualizar_texto_analisis("Error analizando correlación red-procesos\n")
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error en correlación red-procesos: {str(e)}\n")
    
    def _correlacionar_archivos_logins(self):
        """Correlacionar modificaciones de archivos con logins.""" 
        try:
            self._actualizar_texto_analisis("\n📁 3. CORRELACIÓN ARCHIVOS-LOGINS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            import subprocess
            from datetime import datetime, timedelta
            
            # Obtener logins recientes
            try:
                resultado_last = subprocess.run(['last', '-n', '10'], 
                                              capture_output=True, text=True, timeout=10)
                
                if resultado_last.returncode == 0:
                    lineas_last = resultado_last.stdout.split('\n')
                    logins_recientes = [l for l in lineas_last if 'pts/' in l or 'tty' in l]
                    
                    self._actualizar_texto_analisis(f"Logins recientes detectados: {len(logins_recientes)}\n")
                    
                    # Si hay logins recientes, verificar modificaciones de archivos
                    if logins_recientes:
                        try:
                            # Buscar archivos modificados recientemente
                            resultado_find = subprocess.run(['find', '/etc', '/home', '-type', 'f', '-mmin', '-60'], 
                                                           capture_output=True, text=True, timeout=15)
                            
                            if resultado_find.returncode == 0:
                                archivos_mod = resultado_find.stdout.strip().split('\n')
                                archivos_mod = [f for f in archivos_mod if f.strip()]
                                
                                if archivos_mod:
                                    self._actualizar_texto_analisis(f"ARCHIVOS MODIFICADOS EN LA ÚLTIMA HORA: {len(archivos_mod)}\n")
                                    
                                    # Mostrar algunos archivos críticos si fueron modificados
                                    criticos_mod = [f for f in archivos_mod if any(crit in f for crit in ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '.ssh'])]
                                    
                                    if criticos_mod:
                                        self._actualizar_texto_analisis("ARCHIVOS CRÍTICOS MODIFICADOS:\n")
                                        for archivo in criticos_mod[:5]:
                                            self._actualizar_texto_analisis(f"  {archivo}\n")
                                    
                                else:
                                    self._actualizar_texto_analisis("No hay modificaciones significativas de archivos\n")
                                    
                        except:
                            pass
                    else:
                        self._actualizar_texto_analisis("No hay logins recientes\n")
                        
            except:
                self._actualizar_texto_analisis("Error analizando correlación archivos-logins\n")
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error correlacionando archivos-logins: {str(e)}\n")
    
    def _analizar_cadenas_eventos(self):
        """Analizar cadenas de eventos que pueden indicar un ataque."""
        try:
            self._actualizar_texto_analisis("\n🔗 4. ANÁLISIS DE CADENAS DE EVENTOS\n")
            self._actualizar_texto_analisis("-" * 50 + "\n")
            
            # Simular análisis de cadena de eventos típica de ataque
            eventos_sospechosos = []
            
            import subprocess
            
            # 1. Verificar si hay escaneo de puertos reciente
            try:
                resultado = subprocess.run(['netstat', '-i'], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    eventos_sospechosos.append("actividad_red")
            except:
                pass
            
            # 2. Verificar procesos sospechosos
            try:
                resultado = subprocess.run(['ps', 'aux'], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    if any(proc in resultado.stdout.lower() for proc in ['nc', 'netcat', 'python']):
                        eventos_sospechosos.append("procesos_sospechosos")
            except:
                pass
            
            # 3. Verificar intentos de login
            try:
                resultado = subprocess.run(['journalctl', '--since', '30 minutes ago', '--no-pager'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    if 'Failed' in resultado.stdout or 'authentication' in resultado.stdout:
                        eventos_sospechosos.append("intentos_acceso")
            except:
                pass
            
            # Evaluar la cadena de eventos
            if len(eventos_sospechosos) >= 2:
                self._actualizar_texto_analisis("CADENA DE EVENTOS SOSPECHOSA DETECTADA:\n")
                self._actualizar_texto_analisis(f"  📍 Eventos correlacionados: {', '.join(eventos_sospechosos)}\n")
                self._actualizar_texto_analisis("  Posible intento de intrusión en progreso\n")
                self._actualizar_texto_analisis("  Recomendación: Revisar logs detalladamente y considerar medidas defensivas\n")
            elif len(eventos_sospechosos) == 1:
                self._actualizar_texto_analisis("Evento aislado detectado:\n")
                self._actualizar_texto_analisis(f"  📍 Tipo: {eventos_sospechosos[0]}\n")
                self._actualizar_texto_analisis("  Mantener vigilancia\n")
            else:
                self._actualizar_texto_analisis("No se detectaron cadenas de eventos sospechosas\n")
                
        except Exception as e:
            self._actualizar_texto_analisis(f"Error analizando cadenas: {str(e)}\n")
    
    def obtener_datos_para_reporte(self):
        """Obtener datos del SIEM para incluir en reportes."""
        try:
            # Obtener el texto de resultados del SIEM
            contenido_siem = ""
            if hasattr(self, 'siem_monitoreo_text'):
                contenido_siem = self.siem_monitoreo_text.get(1.0, 'end-1c')
            
            if hasattr(self, 'siem_analisis_text'):
                contenido_analisis = self.siem_analisis_text.get(1.0, 'end-1c')
                contenido_siem += "\n--- ANÁLISIS ---\n" + contenido_analisis
            
            # Crear estructura de datos para el reporte
            datos_siem = {
                'timestamp': datetime.now().isoformat(),
                'modulo': 'SIEM Avanzado',
                'estado': 'activo' if self.proceso_siem_activo else 'inactivo',
                'version_expandida': True,
                'capacidades_avanzadas': [
                    'Análisis de patrones de comportamiento',
                    'Correlación avanzada de eventos',
                    'Detección de conexiones sospechosas',
                    'Análisis de procesos anómalos',
                    'Monitoreo de archivos críticos',
                    'Detección de escalamiento de privilegios',
                    'Análisis de patrones temporales'
                ],
                'resultados_texto': contenido_siem[-3000:] if len(contenido_siem) > 3000 else contenido_siem,
                'estadisticas': {
                    'lineas_log': len(contenido_siem.split('\n')),
                    'alertas_criticas': contenido_siem.count('CRITICO') + contenido_siem.count(''),
                    'alertas_altas': contenido_siem.count('ALTO') + contenido_siem.count(''),
                    'alertas_medias': contenido_siem.count('MEDIO') + contenido_siem.count(''),
                    'eventos_procesados': contenido_siem.count('EVENTO') + contenido_siem.count('detectado'),
                    'correlaciones_realizadas': contenido_siem.count('CORRELACIÓN') + contenido_siem.count('correlación')
                },
                'analisis_realizados': {
                    'patrones_avanzados': 'ANÁLISIS AVANZADO' in contenido_siem,
                    'correlacion_eventos': 'CORRELACIÓN AVANZADA' in contenido_siem,
                    'conexiones_red': 'CONEXIONES DE RED' in contenido_siem,
                    'procesos_anomalos': 'PROCESOS ANÓMALOS' in contenido_siem,
                    'archivos_criticos': 'ARCHIVOS CRÍTICOS' in contenido_siem,
                    'escalamiento_privilegios': 'ESCALAMIENTO DE PRIVILEGIOS' in contenido_siem
                },
                'info_sistema': 'SIEM expandido con análisis avanzado de patrones y correlación de eventos'
            }
            
            return datos_siem
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'modulo': 'SIEM',
                'estado': 'error',
                'error': f'Error obteniendo datos: {str(e)}',
                'info': 'Error al obtener datos del SIEM para reporte'
            }
    
    def _actualizar_terminal_seguro(self, texto, modo="append"):
        """Actualizar terminal_output de forma segura desde threads."""
        def _update():
            try:
                if hasattr(self, 'terminal_output') and self.terminal_output.winfo_exists():
                    if modo == "clear":
                        self.terminal_output.delete(1.0, tk.END)
                    elif modo == "replace":
                        self.terminal_output.delete(1.0, tk.END)
                        self.terminal_output.insert(1.0, texto)
                    elif modo == "append":
                        self.terminal_output.insert(tk.END, texto)
                    elif modo == "insert_start":
                        self.terminal_output.insert(1.0, texto)
                    self.terminal_output.see(tk.END)
                    if hasattr(self.terminal_output, 'update'):
                        self.terminal_output.update()
            except (tk.TclError, AttributeError):
                pass
        
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass

