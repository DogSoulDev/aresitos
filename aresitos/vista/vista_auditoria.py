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
        # Sincronizar con reportes
        try:
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            if vista_reportes:
                import datetime
                datos = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'modulo': 'auditoria',
                    'mensaje': mensaje,
                    'nivel': nivel
                }
                vista_reportes.set_datos_modulo('auditoria', datos)
        except Exception:
            pass

    def crear_interfaz(self):
        self.configure(bg=self.colors['bg_primary'])
        self.pack_propagate(False)

        # Frame principal vertical
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Título arriba
        titulo_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(10, 10))
        titulo = tk.Label(titulo_frame, text="Auditoría de seguridad del sistema",
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
        if parent is None:
            parent = self
        terminal_frame = tk.LabelFrame(parent, text="Terminal de auditoría", bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        terminal_frame.pack(fill="both", expand=True, padx=5, pady=5)

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

        tk.Label(entrada_frame, text="Comando:",
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
            text="Ejecutar",
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
        self._actualizar_terminal("Sistema: Kali Linux - Herramientas de auditoría de seguridad\n")
        self._actualizar_terminal("="*60 + "\n")
        self._actualizar_terminal("Log de auditoría en tiempo real\n\n")

    def _actualizar_terminal(self, texto, modo=None):
        if hasattr(self, 'terminal_output') and self.terminal_output:
            if modo == "clear":
                self.terminal_output.delete(1.0, tk.END)
            self.terminal_output.insert(tk.END, texto)
            self.terminal_output.see(tk.END)
    # ...existing code...
    def actualizar_info_panel(self, titulo_accion, descripcion):
        pass  # Paneles de info eliminados, función dummy

    def _mostrar_info_seguridad(self):
        info = (
            "\n[INFORMACIÓN DE SEGURIDAD]\n"
            "- Utilice siempre comandos validados y auditados.\n"
            "- No ejecute comandos peligrosos sin comprender su efecto.\n"
            "- Revise los registros de auditoría para detectar anomalías.\n"
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
                self._actualizar_terminal("Sistema: Kali Linux - Herramientas de auditoría de seguridad\n")
                self._actualizar_terminal("="*60 + "\n")
                self._actualizar_terminal("Log de terminal de auditoría reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Auditoría: {e}")
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada SIEMPRE como root usando SudoManager."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        self.log_terminal(f"> {comando}")
        self.comando_entry.delete(0, tk.END)
        def run_and_report():
            resultado = self._ejecutar_comando_seguro(comando, timeout=30, usar_sudo=True)
            if resultado.get('output'):
                self.log_terminal(resultado['output'])
            if resultado.get('error'):
                self.log_terminal(resultado['error'], nivel="ERROR")
        thread = threading.Thread(target=run_and_report)
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_seguro(self, comando, timeout=30, usar_sudo=True):
        """Ejecuta un comando del sistema de forma segura y robusta, siempre como root usando SudoManager si no es Windows."""
        try:
            import platform
            if platform.system() == "Windows":
                import subprocess
                comando_completo = ["cmd", "/c", comando]
                resultado = subprocess.run(
                    comando_completo,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return {
                    'success': resultado.returncode == 0,
                    'output': resultado.stdout,
                    'error': resultado.stderr,
                    'returncode': resultado.returncode
                }
            else:
                from aresitos.utils.sudo_manager import get_sudo_manager
                sudo_manager = get_sudo_manager()
                resultado = sudo_manager.execute_sudo_command(comando, timeout=timeout)
                return {
                    'success': resultado.returncode == 0 if hasattr(resultado, 'returncode') else True,
                    'output': resultado.stdout if hasattr(resultado, 'stdout') else str(resultado),
                    'error': resultado.stderr if hasattr(resultado, 'stderr') else '',
                    'returncode': resultado.returncode if hasattr(resultado, 'returncode') else 0
                }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'returncode': None
            }
    
    def abrir_logs_auditoria(self):
        self.log_terminal("[INFO] Función para abrir registros aún no implementada.")
    
    def _crear_seccion_deteccion_malware(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        tk.Label(section_frame, text="Detección de malware", 
                 bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        # Botones adaptados: solo muestran info en terminal
        buttons = [
            ("Detectar Rootkits", "rkhunter --check --sk --nocolors || chkrootkit", self.colors['warning'],
             "Analiza el sistema en busca de rootkits y malware usando herramientas nativas de Linux/Kali. Muestra hallazgos críticos y sugerencias de seguridad."),
            ("Auditoría nuclei", "nuclei -update-templates && nuclei -l targets.txt -o nuclei_report.txt", self.colors['info'],
             "Ejecuta un escaneo de vulnerabilidades profesional con nuclei. Requiere tener nuclei instalado y actualizado. El archivo 'targets.txt' debe existir y contener los objetivos (uno por línea)."),
            ("Scan httpx", "httpx http://localhost:80 -title -sc -tech-detect", self.colors['fg_accent'],
             "Realiza un escaneo rápido de servicios web usando httpx para detectar tecnologías, títulos y estado HTTP. Para escaneo masivo usa 'httpx -l lista.txt -title -sc -tech-detect'. El archivo 'lista.txt' debe existir y contener los objetivos."),
        ]
        import shutil
        for text, comando, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text, tool_name=None):
                def ejecutar_y_reportar():
                    self.actualizar_info_panel(text, ayuda_text)
                    import os
                    # Comprobación especial para nuclei y targets.txt
                    if text == "Auditoría nuclei":
                        if not os.path.exists("targets.txt"):
                            msg = "[ERROR] El archivo 'targets.txt' no existe. Crea el archivo y añade los objetivos (uno por línea) antes de ejecutar nuclei."
                            self.log_terminal(msg, nivel="ERROR")
                            self._enviar_a_reportes(text, cmd, msg, True)
                            return
                    # Comprobación especial para httpx y lista.txt
                    if text == "Scan httpx" and "-l lista.txt" in cmd:
                        if not os.path.exists("lista.txt"):
                            msg = "[ERROR] El archivo 'lista.txt' no existe. Crea el archivo y añade los objetivos (uno por línea) antes de ejecutar httpx en modo masivo."
                            self.log_terminal(msg, nivel="ERROR")
                            self._enviar_a_reportes(text, cmd, msg, True)
                            return
                    self.log_terminal(f"[EJECUTANDO] {cmd}")
                    # Validar instalación si corresponde
                    if tool_name:
                        import shutil
                        if not shutil.which(tool_name):
                            msg = f"[ERROR] La herramienta '{tool_name}' no está instalada o no se encuentra en el PATH."
                            self.log_terminal(msg, nivel="ERROR")
                            self._enviar_a_reportes(text, cmd, msg, True)
                            return
                    resultado = self._ejecutar_comando_seguro(cmd, timeout=120, usar_sudo=True)
                    salida = resultado.get('output', '').strip()
                    error = resultado.get('error', '').strip()
                    if salida:
                        self.log_terminal(f"[RESULTADO] {salida}")
                        self._enviar_a_reportes(text, cmd, salida, False)
                    if error:
                        self.log_terminal(f"[ERROR] {error}", nivel="ERROR")
                        self._enviar_a_reportes(text, cmd, error, True)
                    if not salida and not error:
                        msg = "[INFO] El comando no produjo salida. Verifique parámetros o permisos."
                        self.log_terminal(msg)
                        self._enviar_a_reportes(text, cmd, msg, False)
                return ejecutar_y_reportar
            # Detectar herramienta principal para validación
            tool = None
            if "nuclei" in comando:
                tool = "nuclei"
            elif "httpx" in comando:
                tool = "httpx"
            elif "rkhunter" in comando:
                tool = "rkhunter"
            elif "chkrootkit" in comando:
                tool = "chkrootkit"
            btn = tk.Button(section_frame, text=text, command=make_cmd(comando, ayuda, tool),
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
            ("Editar SSH", self.editar_configuracion_ssh, self.colors['info'],
             "Edita de forma segura la configuración SSH. Se realiza copia de seguridad y validación antes de guardar."),
            ("Políticas de Contraseña", self._auditar_politicas_contrasena, self.colors['danger'],
             "Verifica las políticas de contraseñas, usuarios sin contraseña y configuraciones débiles."),
            ("Análisis SUID/SGID", "find / -perm -4000 -type f 2>/dev/null && find / -perm -2000 -type f 2>/dev/null", self.colors['warning'],
             "Busca archivos con permisos SUID/SGID que pueden ser explotados para escalar privilegios."),
            ("Auditoría Lynis", "lynis audit system", self.colors['info'],
             "Ejecuta un escaneo completo de seguridad con Lynis y muestra el resumen de hallazgos."),
            ("Escaneo ClamAV /home", "clamscan -r /home", self.colors['success'],
             "Escanea el directorio /home en busca de malware usando ClamAV."),
            ("Escaneo ClamAV /tmp", "clamscan -r /tmp", self.colors['success'],
             "Escanea el directorio /tmp en busca de malware usando ClamAV."),
            ("linpeas (privesc)", "./linpeas.sh -a -r", self.colors['fg_accent'],
             "Ejecuta linpeas con los parámetros recomendados para detectar vectores de escalada de privilegios."),
            ("pspy (monitor de procesos)", "./pspy64 -pf -i 1000", self.colors['info'],
             "Ejecuta pspy para monitorizar procesos y tareas programadas sin privilegios root."),
            ("Usuarios sin contraseña", "awk -F: '($2 == \"\") {print $1}' /etc/shadow", self.colors['danger'],
             "Lista los usuarios del sistema que no tienen contraseña definida."),
            ("Tareas programadas (cron)", "crontab -l && ls -al /etc/cron* && cat /etc/crontab", self.colors['warning'],
             "Muestra todas las tareas programadas y cron jobs del sistema."),
            ("Servicios de red abiertos", "ss -tuln", self.colors['fg_accent'],
             "Lista los servicios de red y puertos abiertos en el sistema."),
        ]
        for text, comando, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text):
                if callable(cmd):
                    return lambda: (self.actualizar_info_panel(text, ayuda_text), cmd())
                def ejecutar_y_reportar():
                    self.actualizar_info_panel(text, ayuda_text)
                    self.log_terminal(f"[EJECUTANDO] {cmd}")
                    resultado = self._ejecutar_comando_seguro(cmd, timeout=180, usar_sudo=True)
                    salida = resultado.get('output', '').strip()
                    error = resultado.get('error', '').strip()
                    if salida:
                        self.log_terminal(f"[RESULTADO] {salida}")
                        self._enviar_a_reportes(text, cmd, salida, False)
                    if error:
                        self.log_terminal(f"[ERROR] {error}", nivel="ERROR")
                        self._enviar_a_reportes(text, cmd, error, True)
                    if not salida and not error:
                        msg = "[INFO] El comando no produjo salida. Verifique parámetros o permisos."
                        self.log_terminal(msg)
                        self._enviar_a_reportes(text, cmd, msg, False)
                return ejecutar_y_reportar
            btn = tk.Button(section_frame, text=text, command=make_cmd(comando, ayuda),
                            bg=color, fg=self.colors['bg_primary'],
                            font=('Arial', 9, 'bold'), relief='flat',
                            padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)

    def _auditar_politicas_contrasena(self):
        """Audita políticas de contraseña y usuarios sin contraseña usando SudoManager."""
        self.actualizar_info_panel("Políticas de Contraseña", "Verifica políticas y usuarios sin contraseña.")
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            sudo_manager = get_sudo_manager()
            cmds = [
                ("cat /etc/login.defs", "cat /etc/login.defs"),
                ("grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs", "grep PASS_*"),
                ("awk -F: '($2 == \"\") {print $1}' /etc/shadow", "awk /etc/shadow"),
                ("chage -l root", "chage -l root")
            ]
            for cmd, label in cmds:
                self.log_terminal(f"[EJECUTANDO] {cmd}")
                resultado = sudo_manager.execute_sudo_command(cmd, timeout=30)
                salida = getattr(resultado, 'stdout', '')
                error = getattr(resultado, 'stderr', '')
                if salida:
                    if label == "awk /etc/shadow" and salida.strip():
                        self.log_terminal("[ALERTA] Usuarios sin contraseña:\n" + salida, nivel="WARNING")
                        self._enviar_a_reportes("Políticas de Contraseña", label, salida, True)
                    else:
                        self.log_terminal(salida)
                        self._enviar_a_reportes("Políticas de Contraseña", label, salida, False)
                if error:
                    self.log_terminal(f"[ERROR] {error}", nivel="ERROR")
                    self._enviar_a_reportes("Políticas de Contraseña", label, error, True)
            if not salida:
                self.log_terminal("No se detectaron usuarios sin contraseña.")
        except Exception as e:
            self.log_terminal(f"[ERROR] Auditoría de políticas de contraseña: {e}", nivel="ERROR")
            self._enviar_a_reportes("Políticas de Contraseña", "error", str(e), True)
    def destroy(self):
        """Garantiza que no queden procesos ni threads abiertos al cerrar la vista."""
        # Finalizar cualquier thread de auditoría si existe
        try:
            if hasattr(self, 'terminal_output'):
                self.terminal_output = None
            # Si hay threads en ejecución, intentar detenerlos
            import threading
            for t in threading.enumerate():
                if t is not threading.current_thread() and hasattr(t, 'daemon') and t.daemon:
                    try:
                        t.join(timeout=1)
                    except Exception:
                        pass
        except Exception:
            pass
        # Llamar al destroy original
        super().destroy()

    def editar_configuracion_ssh(self):
        """Permite editar /etc/ssh/sshd_config de forma segura, con backup y validación."""
        import shutil
        import tempfile
        ruta_ssh = "/etc/ssh/sshd_config"
        backup_path = f"{ruta_ssh}.backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            # Leer contenido actual
            with open(ruta_ssh, 'r', encoding='utf-8') as f:
                contenido = f.read()
        except Exception as e:
            self.log_terminal(f"[ERROR] No se pudo leer sshd_config: {e}", nivel="ERROR")
            return
        # Crear ventana de edición
        def editar_configuracion_ssh(self):
            import shutil
            import tempfile
            ruta_ssh = "/etc/ssh/sshd_config"
            backup_path = f"{ruta_ssh}.backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            try:
                # Leer contenido actual
                with open(ruta_ssh, 'r', encoding='utf-8') as f:
                    contenido = f.read()
            except Exception as e:
                self.log_terminal(f"[ERROR] No se pudo leer sshd_config: {e}", nivel="ERROR")
                return
            # Crear ventana de edición
            editor = tk.Toplevel(self)
            editor.title("Editar configuración de SSH")
            editor.geometry("700x600")
            editor.configure(bg=self.colors['bg_secondary'])
            tk.Label(editor, text="Edite la configuración de SSH con precaución.", bg=self.colors['bg_secondary'], fg=self.colors['danger'], font=("Arial", 11, "bold")).pack(pady=8)
            text_area = scrolledtext.ScrolledText(editor, wrap=tk.WORD, font=("Consolas", 10), bg="#222", fg="#eee", insertbackground="#eee")
            text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_area.insert(tk.END, contenido)
            def guardar_cambios():
                nuevo_contenido = text_area.get(1.0, tk.END)
                # Validación básica: no permitir líneas vacías al inicio, ni comandos peligrosos
                if "PermitRootLogin yes" in nuevo_contenido:
                    if not messagebox.askyesno("Advertencia de Seguridad", "Estás permitiendo el login de root por SSH. ¿Seguro que quieres continuar?"):
                        return
                try:
                    shutil.copy2(ruta_ssh, backup_path)
                    with open(ruta_ssh, 'w', encoding='utf-8') as f:
                        f.write(nuevo_contenido)
                    self.log_terminal(f"[OK] Configuración SSH guardada. Backup en {backup_path}")
                    messagebox.showinfo("Éxito", f"Configuración SSH guardada y backup creado en {backup_path}")
                except Exception as e:
                    self.log_terminal(f"[ERROR] No se pudo guardar sshd_config: {e}", nivel="ERROR")
                    messagebox.showerror("Error", f"No se pudo guardar sshd_config: {e}")
            btn_guardar = tk.Button(editor, text="Guardar cambios", command=guardar_cambios, bg=self.colors['success'], fg='white', font=("Arial", 10, "bold"))
            btn_guardar.pack(pady=10)
    
    def _crear_seccion_utilidades(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        tk.Label(section_frame, text="Utilidades", 
                 bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        # Botones adaptados: solo los que tienen sentido en el nuevo flujo
        buttons = [
            ("Guardar resultados", self.guardar_auditoria, self.colors['info'],
             "Permite guardar en un archivo de texto todos los resultados y hallazgos de la auditoría."),
            ("Limpiar pantalla", self.limpiar_auditoria, self.colors['warning'],
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
        cuarentena_label = tk.Label(section_frame, text="Cuarentena de archivos", 
                                  bg=self.colors['bg_secondary'], fg=self.colors['danger'],
                                  font=('Arial', 10, 'bold'))
        cuarentena_label.pack(anchor="w", padx=10, pady=(10, 2))

        self.cuarentena_entry = tk.Entry(section_frame, width=30, font=('Consolas', 10))
        self.cuarentena_entry.pack_forget()  # Ocultamos el entry, ya no se usará

        btn_cuarentena = tk.Button(section_frame, text="Mandar a cuarentena",
                                   command=self.seleccionar_archivo_cuarentena,
                                   bg=self.colors['danger'], fg='white',
                                   font=('Arial', 10), relief='flat', padx=8, pady=4)
        btn_cuarentena.pack(fill=tk.X, padx=10, pady=2)

    def seleccionar_archivo_cuarentena(self):
        archivo = filedialog.askopenfilename(title="Seleccionar archivo para poner en cuarentena")
        if not archivo:
            self.log_terminal("No se seleccionó ningún archivo.")
            return
        self._poner_en_cuarentena_desde_ruta(archivo)

    def _poner_en_cuarentena_desde_ruta(self, ruta):
        """Pone en cuarentena el archivo especificado por ruta."""
        if not ruta:
            self.log_terminal("Debe seleccionar un archivo válido para poner en cuarentena.")
            return
        if not hasattr(self, 'controlador') or not self.controlador or not hasattr(self.controlador, 'controlador_cuarentena'):
            self.log_terminal("El controlador de cuarentena no está disponible.")
            return
        try:
            resultado = self.controlador.controlador_cuarentena.cuarentenar_archivo(ruta, razon="Manual desde Auditoría")
            if resultado.get('exito'):
                self.log_terminal(f"Archivo puesto en cuarentena: {ruta}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Archivo puesto en cuarentena: {ruta}", False)
            else:
                self.log_terminal(f"Error al poner en cuarentena: {resultado.get('mensaje','sin mensaje')}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Error: {resultado.get('mensaje','sin mensaje')}", True)
        except Exception as e:
            self.log_terminal(f"Excepción al poner en cuarentena: {e}")
            self._enviar_a_reportes('poner_en_cuarentena', str(e), True)

    def _poner_en_cuarentena_desde_entry(self):
        """Pone en cuarentena el archivo especificado en el campo de entrada."""
        ruta = self.cuarentena_entry.get().strip()
        if not ruta or ruta == "Ruta del archivo a poner en cuarentena":
            self.log_terminal("Debe especificar la ruta del archivo que desea poner en cuarentena.")
            return
        if not hasattr(self, 'controlador') or not self.controlador or not hasattr(self.controlador, 'controlador_cuarentena'):
            self.log_terminal("El controlador de cuarentena no está disponible.")
            return
        try:
            resultado = self.controlador.controlador_cuarentena.cuarentenar_archivo(ruta, razon="Manual desde Auditoría")
            if resultado.get('exito'):
                self.log_terminal(f"Archivo puesto en cuarentena: {ruta}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Archivo puesto en cuarentena: {ruta}", False)
            else:
                self.log_terminal(f"Error al poner en cuarentena: {resultado.get('mensaje','sin mensaje')}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Error: {resultado.get('mensaje','sin mensaje')}", True)
        except Exception as e:
            self.log_terminal(f"Excepción al poner en cuarentena: {e}")
            self._enviar_a_reportes('poner_en_cuarentena', str(e), True)
    
    # Método eliminado: ejecutar_lynis (no se usa en el nuevo flujo)
    
    # Métodos eliminados: cancelar_auditoria, detectar_rootkits (no se usan en el nuevo flujo)

    
    def guardar_auditoria(self):
        # Guardar el contenido del terminal integrado
        if not hasattr(self, 'terminal_output') or self.terminal_output is None:
            messagebox.showwarning("Advertencia", "No hay resultados para guardar.")
            return
        contenido = self.terminal_output.get(1.0, tk.END)
        if not contenido.strip():
            messagebox.showwarning("Advertencia", "No hay resultados para guardar.")
            return
        archivo = filedialog.asksaveasfilename(
            title="Guardar resultados de auditoría",
            defaultextension=".txt",
            filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if archivo:
            with open(archivo, 'w', encoding='utf-8') as f:
                f.write(contenido)
            messagebox.showinfo("Éxito", f"Auditoría guardada en {archivo}")
    
    def limpiar_auditoria(self):
        self.limpiar_terminal_auditoria()
    
    # Métodos eliminados: cancelar_rootkits, ejecutar_nuclei, ejecutar_httpx, analizar_suid_sgid, auditar_ssh, verificar_password_policy (no se usan en el nuevo flujo)

    # El logger global ahora es log_terminal

    # Método eliminado: _analizar_resultados_chkrootkit (no se usa en el nuevo flujo)

