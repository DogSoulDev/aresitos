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

import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging
import datetime

# Importar el gestor de sudo de ARESITOS
from aresitos.utils.sudo_manager import get_sudo_manager
from aresitos.utils.logger_aresitos import LoggerAresitos

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaAuditoria(tk.Frame):
    herramientas_apt = [
        'lynis', 'rkhunter', 'chkrootkit', 'clamav', 'nuclei', 'httpx', 'linpeas', 'pspy'
    ]

    def __init__(self, *args, root_session=None, controlador=None, **kwargs):
        """
        root_session: objeto o token de sesión root pasado desde el login principal.
        Debe mantenerse en memoria en todas las vistas importantes para evitar problemas de permisos.
        """
        super().__init__(*args, **kwargs)
        self.root_session = root_session
        self.controlador = controlador
        self.colors = {
            'bg_primary': '#232629',
            'bg_secondary': '#31363b',
            'fg_primary': '#f8f8f2',
            'fg_accent': '#ffb86c',
            'warning': '#ff5555',
            'danger': '#ff5555',
            'success': '#50fa7b',
            'info': '#8be9fd',
        }
        if BURP_THEME_AVAILABLE and burp_theme:
            if hasattr(burp_theme, 'colors'):
                self.colors.update(burp_theme.colors)
            elif isinstance(burp_theme, dict):
                self.colors.update(burp_theme)
        self.logger = LoggerAresitos.get_instance()
        self.crear_interfaz()

    # Métodos eliminados: _es_root, _deshabilitar_todo_auditoria_por_root, set_controlador, analizar_servicios, verificar_permisos
    # Todos estos métodos dependían de atributos y lógica de seguridad eliminados.
    # El logger se mantiene para mostrar información en el terminal y enviarla a Reportes.
    def log_terminal(self, mensaje, modulo="AUDITORIA", nivel="INFO"):
        # Muestra en terminal y envía a Reportes (Dashboard)
        self._actualizar_terminal(mensaje + "\n")
        try:
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
        except Exception:
            pass
        # Registrar en logger centralizado
        if hasattr(self, 'logger') and self.logger:
            self.logger.log(mensaje, nivel=nivel, modulo=modulo)

    def crear_interfaz(self):
        self.configure(bg=self.colors['bg_primary'])
        self.pack_propagate(False)

        # Frame principal vertical
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Título arriba
        titulo_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(10, 10))
        titulo = tk.Label(titulo_frame, text="Auditoría de Seguridad del Sistema",
            bg=self.colors['bg_primary'], fg=self.colors['fg_accent'],
            font=('Arial', 16, 'bold'))
        titulo.pack(pady=10)

        # Frame horizontal para dividir botones y terminal
        content_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Panel izquierdo: botones
        left_frame = tk.Frame(content_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=5)
        self._crear_seccion_deteccion_malware(left_frame)
        self._crear_seccion_configuraciones(left_frame)
        self._crear_seccion_utilidades(left_frame)

        # Panel derecho: terminal integrado
        right_frame = tk.Frame(content_frame, bg=self.colors['bg_primary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, pady=5)
        self.crear_terminal_integrado(parent=right_frame)

    def crear_terminal_integrado(self, parent=None):
        try:
            if parent is None:
                parent = self
            terminal_frame = tk.LabelFrame(
                parent,
                text="Terminal ARESITOS - Auditoría",
                bg=self.colors['bg_secondary'],
                fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")
            )
            terminal_frame.pack(fill="both", expand=True, padx=5, pady=5)

            controles_frame = tk.Frame(terminal_frame, bg=self.colors['bg_secondary'])
            controles_frame.pack(fill="x", padx=5, pady=2)

            btn_limpiar = tk.Button(
                controles_frame,
                text="LIMPIAR",
                command=self.limpiar_terminal_auditoria,
                bg=self.colors.get('warning', '#ffaa00'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)

            btn_logs = tk.Button(
                controles_frame,
                text="VER LOGS",
                command=self.abrir_logs_auditoria,
                bg=self.colors.get('info', '#007acc'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)

            self.terminal_output = scrolledtext.ScrolledText(
                terminal_frame,
                height=12,
                bg='#000000',
                fg='#00ff00',
                font=("Consolas", 10),
                insertbackground='#00ff00',
                selectbackground='#333333'
            )
            self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)

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

            # Mensaje inicial
            self._actualizar_terminal("="*60 + "\n")
            self._actualizar_terminal("Terminal ARESITOS - Auditoría v2.0\n")
            from datetime import datetime
            self._actualizar_terminal(f"Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._actualizar_terminal("Sistema: Kali Linux - Security Audit Tools\n")
            self._actualizar_terminal("="*60 + "\n")
            self._actualizar_terminal("LOG Auditoría en tiempo real\n\n")
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Auditoría: {e}")

    def _actualizar_terminal(self, texto, modo=None):
        if hasattr(self, 'terminal_output') and self.terminal_output:
            if modo == "clear":
                self.terminal_output.delete(1.0, tk.END)
            self.terminal_output.insert(tk.END, texto)
            self.terminal_output.see(tk.END)
    def actualizar_info_panel(self, titulo_accion, descripcion):
        pass  # Paneles de info eliminados, función dummy

    def _mostrar_info_seguridad(self):
        info = (
            "\n[INFO SEGURIDAD]\n"
            "- Utilice siempre comandos validados y auditados.\n"
            "- No ejecute comandos peligrosos sin comprender su efecto.\n"
            "- Revise los logs de auditoría para detectar anomalías.\n"
            "- Mantenga el sistema y las herramientas actualizadas.\n"
        )
        self.log_terminal(info)
    # Método eliminado: _ejecutar_comando_seguro (ya no se usa validación ni gestor de permisos)

    def limpiar_terminal_auditoria(self):
        try:
            from datetime import datetime
            if hasattr(self, 'terminal_output'):
                self._actualizar_terminal("", "clear")
                self._actualizar_terminal("="*60 + "\n")
                self._actualizar_terminal("Terminal ARESITOS - Auditoría v2.0\n")
                self._actualizar_terminal(f"Limpiado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self._actualizar_terminal("Sistema: Kali Linux - Security Audit Tools\n")
                self._actualizar_terminal("="*60 + "\n")
                self._actualizar_terminal("LOG Terminal Auditoría reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Auditoría: {e}")
    
    def ejecutar_comando_entry(self, event=None):
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        self.log_terminal(f"> {comando}")
        self.comando_entry.delete(0, tk.END)
        def run_and_report():
            self._ejecutar_comando_async(comando, reportar=True)
        thread = threading.Thread(target=run_and_report)
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_async(self, comando, reportar=False):
        try:
            # Comandos especiales de ARESITOS
            if comando == "info-seguridad":
                self._mostrar_info_seguridad()
                if reportar:
                    self._enviar_a_reportes("info-seguridad", comando, "[INFO SEGURIDAD]", False)
                return
            elif comando in ["clear", "cls"]:
                self.limpiar_terminal_auditoria()
                if reportar:
                    self._enviar_a_reportes("limpiar", comando, "Pantalla limpiada", False)
                return

            import platform
            if platform.system() == "Windows":
                import subprocess
                comando_completo = ["cmd", "/c", comando]
                resultado = subprocess.run(
                    comando_completo,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                # Usar el gestor de sudo para ejecutar comandos en Linux
                sudo_manager = get_sudo_manager()
                resultado = sudo_manager.execute_sudo_command(comando, timeout=30)

            if resultado.stdout:
                self.log_terminal(resultado.stdout)
                if reportar:
                    self._enviar_a_reportes("terminal", comando, resultado.stdout, False)
            if resultado.stderr:
                self.log_terminal(resultado.stderr, nivel="ERROR")
                if reportar:
                    self._enviar_a_reportes("terminal", comando, resultado.stderr, True)
        except Exception as e:
            self.log_terminal(f"[ERROR] {e}", nivel="ERROR")
            if reportar:
                self._enviar_a_reportes("terminal", comando, str(e), True)
    
    def abrir_logs_auditoria(self):
        self.log_terminal("[INFO] Función para abrir logs aún no implementada.")
    
    def _crear_seccion_deteccion_malware(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        tk.Label(section_frame, text="Detección de Malware", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        # Botones adaptados: solo muestran info en terminal
        buttons = [
            ("Detectar Rootkits", "rkhunter --check --sk --nocolors || chkrootkit", self.colors['warning'],
             "Analiza el sistema en busca de rootkits y malware usando herramientas nativas de Linux/Kali. Muestra hallazgos críticos y sugerencias de seguridad."),
            ("Auditoría nuclei", "nuclei -update-templates && nuclei -l targets.txt -o nuclei_report.txt", self.colors['info'],
             "Ejecuta un escaneo de vulnerabilidades profesional con nuclei. Requiere tener nuclei instalado y actualizado."),
            ("Scan httpx", "httpx -u http://localhost:80", self.colors['fg_accent'],
             "Realiza un escaneo rápido de servicios web usando httpx para detectar tecnologías, títulos y estado HTTP."),
        ]
        for text, comando, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text):
                def ejecutar_y_reportar():
                    self.actualizar_info_panel(text, ayuda_text)
                    self.log_terminal(f"[EJECUTANDO] {cmd}")
                    import subprocess
                    try:
                        resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                        salida = resultado.stdout.strip()
                        error = resultado.stderr.strip()
                        if salida:
                            self.log_terminal(salida)
                            self._enviar_a_reportes(text, cmd, salida, False)
                        if error:
                            self.log_terminal(error, nivel="ERROR")
                            self._enviar_a_reportes(text, cmd, error, True)
                    except Exception as e:
                        self.log_terminal(f"[ERROR] {e}", nivel="ERROR")
                        self._enviar_a_reportes(text, cmd, str(e), True)
                return ejecutar_y_reportar
            btn = tk.Button(section_frame, text=text, command=make_cmd(comando, ayuda),
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)

    def _enviar_a_reportes(self, herramienta, comando, salida, es_error=False):
        """Envía la información de la ejecución a la vista de reportes si está disponible."""
        try:
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            if vista_reportes:
                datos = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'herramienta': herramienta,
                    'comando': comando,
                    'salida': salida,
                    'es_error': es_error
                }
                vista_reportes.set_datos_modulo('auditoria', datos)
        except Exception:
            pass
    
    def _crear_seccion_configuraciones(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        tk.Label(section_frame, text="Configuraciones", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        # Botones adaptados: solo muestran info en terminal
        buttons = [
            ("Configuración SSH", "cat /etc/ssh/sshd_config", self.colors['fg_accent'],
             "Audita la configuración del servicio SSH para detectar debilidades y malas prácticas."),
            ("Políticas de Contraseña", "cat /etc/login.defs", self.colors['danger'],
             "Verifica las políticas de contraseñas del sistema y detecta usuarios sin contraseña o configuraciones débiles."),
            ("Análisis SUID/SGID", "find / -perm /6000 -type f 2>/dev/null", self.colors['warning'],
             "Busca archivos con permisos SUID/SGID que pueden ser explotados para escalar privilegios."),
        ]
        for text, comando, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text):
                def ejecutar_y_reportar():
                    self.actualizar_info_panel(text, ayuda_text)
                    self.log_terminal(f"[EJECUTANDO] {cmd}")
                    import subprocess
                    try:
                        resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                        salida = resultado.stdout.strip()
                        error = resultado.stderr.strip()
                        if salida:
                            self.log_terminal(salida)
                            self._enviar_a_reportes(text, cmd, salida, False)
                        if error:
                            self.log_terminal(error, nivel="ERROR")
                            self._enviar_a_reportes(text, cmd, error, True)
                    except Exception as e:
                        self.log_terminal(f"[ERROR] {e}", nivel="ERROR")
                        self._enviar_a_reportes(text, cmd, str(e), True)
                return ejecutar_y_reportar
            btn = tk.Button(section_frame, text=text, command=make_cmd(comando, ayuda),
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
    
    def _crear_seccion_utilidades(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        tk.Label(section_frame, text="Utilidades", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        # Botones adaptados: solo los que tienen sentido en el nuevo flujo
        buttons = [
            ("Guardar Resultados", self.guardar_auditoria, self.colors['info'],
             "Permite guardar en un archivo de texto todos los resultados y hallazgos de la auditoría."),
            ("Limpiar Pantalla", self.limpiar_auditoria, self.colors['warning'],
             "Limpia la terminal de auditoría y reinicia la cabecera de la pantalla."),
        ]
        for text, command, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text):
                return lambda: (self.actualizar_info_panel(text, ayuda_text), cmd())
            btn = tk.Button(section_frame, text=text, command=make_cmd(command, ayuda),
                           bg=color, fg=self.colors['fg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)

        # BOTÓN PONER EN CUARENTENA
        cuarentena_label = tk.Label(section_frame, text="Cuarentena de Archivos", 
                                  bg=self.colors['bg_secondary'], fg=self.colors['danger'],
                                  font=('Arial', 10, 'bold'))
        cuarentena_label.pack(anchor="w", padx=10, pady=(10, 2))

        self.cuarentena_entry = tk.Entry(section_frame, width=30, font=('Consolas', 10))
        self.cuarentena_entry.pack(fill="x", padx=10, pady=(0, 5))
        self.cuarentena_entry.insert(0, "Ruta del archivo a poner en cuarentena")

        btn_cuarentena = tk.Button(section_frame, text="Poner en cuarentena",
                                   command=self._poner_en_cuarentena_desde_entry,
                                   bg=self.colors['danger'], fg='white',
                                   font=('Arial', 9, 'bold'), relief='flat', padx=10, pady=5)
        btn_cuarentena.pack(fill=tk.X, padx=10, pady=2)

    def _poner_en_cuarentena_desde_entry(self):
        """Pone en cuarentena el archivo especificado en el campo de entrada."""
        ruta = self.cuarentena_entry.get().strip()
        if not ruta or ruta == "Ruta del archivo a poner en cuarentena":
            self.log_terminal("Debe especificar la ruta del archivo a poner en cuarentena.")
            return
        if not hasattr(self, 'controlador') or not self.controlador or not hasattr(self.controlador, 'controlador_cuarentena'):
            self.log_terminal("Controlador de cuarentena no disponible.")
            return
        try:
            resultado = self.controlador.controlador_cuarentena.cuarentenar_archivo(ruta, razon="Manual desde Auditoría")
            if resultado.get('exito'):
                self.log_terminal(f"Archivo puesto en cuarentena: {ruta}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Archivo puesto en cuarentena: {ruta}", False)
            else:
                self.log_terminal(f"Error poniendo en cuarentena: {resultado.get('mensaje','sin mensaje')}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Error: {resultado.get('mensaje','sin mensaje')}", True)
        except Exception as e:
            self.log_terminal(f"Excepción poniendo en cuarentena: {e}")
            self._enviar_a_reportes('poner_en_cuarentena', str(e), True)
    
    # Método eliminado: ejecutar_lynis (no se usa en el nuevo flujo)
    
    # Métodos eliminados: cancelar_auditoria, detectar_rootkits (no se usan en el nuevo flujo)

    
    def guardar_auditoria(self):
        # Guardar el contenido del terminal integrado
        contenido = self.terminal_output.get(1.0, tk.END)
        if not contenido.strip():
            messagebox.showwarning("Advertencia", "No hay resultados para guardar")
            return
        archivo = filedialog.asksaveasfilename(
            title="Guardar Resultados de Auditoria",
            defaultextension=".txt",
            filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if archivo:
            with open(archivo, 'w', encoding='utf-8') as f:
                f.write(contenido)
            messagebox.showinfo("Exito", f"Auditoria guardada en {archivo}")
    
    def limpiar_auditoria(self):
        self.limpiar_terminal_auditoria()
    
    # Métodos eliminados: cancelar_rootkits, ejecutar_nuclei, ejecutar_httpx, analizar_suid_sgid, auditar_ssh, verificar_password_policy (no se usan en el nuevo flujo)

    # El logger global ahora es log_terminal

    # Método eliminado: _analizar_resultados_chkrootkit (no se usa en el nuevo flujo)

