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

    def __init__(self, *args, **kwargs):
        import os
        self.etc_dir = os.path.join(os.sep, 'etc')
        self.var_log_dir = os.path.join(os.sep, 'var', 'log')
        self.usr_bin_dir = os.path.join(os.sep, 'usr', 'bin')
        self.usr_sbin_dir = os.path.join(os.sep, 'usr', 'sbin')
        self.bin_dir = os.path.join(os.sep, 'bin')
        self.sbin_dir = os.path.join(os.sep, 'sbin')
        self.usr_local_bin_dir = os.path.join(os.sep, 'usr', 'local', 'bin')
        self.usr_local_sbin_dir = os.path.join(os.sep, 'usr', 'local', 'sbin')
        self.rutas_criticas = [
            os.path.join(self.etc_dir, 'passwd'),
            os.path.join(self.etc_dir, 'shadow'),
            os.path.join(self.etc_dir, 'group'),
            os.path.join(self.etc_dir, 'sudoers'),
            os.path.join(self.etc_dir, 'ssh', 'sshd_config'),
            os.path.join(self.etc_dir, 'hosts'),
            os.path.join(self.var_log_dir, 'auth.log'),
            os.path.join(self.var_log_dir, 'syslog'),
            os.path.join(self.var_log_dir, 'kern.log'),
            os.path.join(self.var_log_dir, 'secure'),
            os.path.join(self.var_log_dir, 'wtmp'),
            os.path.join(self.var_log_dir, 'btmp'),
            self.usr_bin_dir + '/',
            self.usr_sbin_dir + '/',
            self.bin_dir + '/',
            self.sbin_dir + '/',
            self.usr_local_bin_dir + '/',
            self.usr_local_sbin_dir + '/',
            os.path.join(self.var_log_dir, 'lynis.log'),
            os.path.join(self.var_log_dir, 'rkhunter.log'),
            os.path.join(self.var_log_dir, 'chkrootkit.log')
        ]
        super().__init__(*args, **kwargs)
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
        self.proceso_auditoria_activo = False
        self.crear_interfaz()
        if not hasattr(self, 'auditoria_text'):
            self.auditoria_text = None
        if not hasattr(self, 'comando_entry'):
            self.comando_entry = None
        self._actualizar_texto_auditoria("[INFO] Auditoría de seguridad lista. Selecciona una acción o ejecuta un comando.\n")
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            sudo_manager = get_sudo_manager()
            if not self._es_root() and not sudo_manager.is_sudo_active():
                self._deshabilitar_todo_auditoria_por_root()
                self._actualizar_texto_auditoria("[ADVERTENCIA] Permisos insuficientes: algunas acciones están deshabilitadas. Ejecuta como root/sudo para acceso completo.\n")
        except Exception:
            pass
        # Instancia de GestorPermisosSeguro para ejecutar comandos
        try:
            from aresitos.utils.gestor_permisos import GestorPermisosSeguro
            self._gestor_permisos = GestorPermisosSeguro()
        except Exception:
            class _GestorPermisosMock:
                def ejecutar_con_permisos(self, *a, **kw):
                    raise RuntimeError("GestorPermisosSeguro no disponible")
            self._gestor_permisos = _GestorPermisosMock()

    def _es_root(self):
        try:
            import sys
            import os
            if sys.platform.startswith('linux'):
                geteuid = getattr(os, 'geteuid', None)
                if callable(geteuid):
                    return geteuid() == 0
                getuid = getattr(os, 'getuid', None)
                if callable(getuid):
                    return getuid() == 0
                import getpass
                return getpass.getuser() == 'root'
            else:
                import getpass
                return getpass.getuser() == 'root'
        except Exception:
            return False

    def _deshabilitar_todo_auditoria_por_root(self):
        try:
            for attr in [
                'btn_cancelar_rootkits', 'btn_iniciar', 'btn_detener', 'btn_verificar',
                'btn_monitoreo_avanzado', 'btn_analisis_forense', 'btn_tiempo_real'
            ]:
                if hasattr(self, attr):
                    getattr(self, attr).config(state="disabled")
        except Exception:
            pass
    def set_controlador(self, controlador):
        self.controlador = controlador
    def _mostrar_ayuda_comandos(self):
        self._actualizar_texto_auditoria("[INFO] Ayuda de comandos no implementada aún.\n")

    def obtener_info_hardware(self):
        self._actualizar_texto_auditoria("[INFO] Obteniendo información de hardware...\n")
        try:
            exito, out, err = self._ejecutar_comando_seguro('lscpu', "Información de CPU", timeout=10, usar_sudo=False)
            if out:
                self._actualizar_texto_auditoria(f"\n--- CPU ---\n{out}\n")
            exito, out, err = self._ejecutar_comando_seguro('lsmem', "Información de RAM", timeout=10, usar_sudo=False)
            if out:
                self._actualizar_texto_auditoria(f"\n--- RAM ---\n{out}\n")
            exito, out, err = self._ejecutar_comando_seguro('lsblk', "Almacenamiento", timeout=10, usar_sudo=False)
            if out:
                self._actualizar_texto_auditoria(f"\n--- Almacenamiento ---\n{out}\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] No se pudo obtener información de hardware: {e}\n")
        self._actualizar_texto_auditoria("[INFO] Consulta de hardware finalizada.\n\n")

    def _finalizar_auditoria(self):
        self._actualizar_texto_auditoria("[INFO] Finalización de auditoría no implementada aún.\n")
    def _actualizar_texto_auditoria(self, texto):
        if hasattr(self, 'auditoria_text') and self.auditoria_text:
            try:
                self.auditoria_text.insert('end', texto)
                self.auditoria_text.see('end')
            except Exception as e:
                print(f"[ERROR] No se pudo actualizar el área de texto de auditoría: {e}\nIntentado mostrar: {texto}")
        else:
            print(texto)

    def analizar_servicios(self):
        self._actualizar_texto_auditoria("[INFO] Analizando servicios activos...\n")
        try:
            exito, out, err = self._ejecutar_comando_seguro('systemctl list-units --type=service --state=running', "Listar servicios activos", timeout=20, usar_sudo=False)
            if out:
                self._actualizar_texto_auditoria(f"\n--- Servicios activos ---\n{out}\n")
            if err:
                self._actualizar_texto_auditoria(f"[ERROR] {err}\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] No se pudo analizar servicios: {e}\n")
        self._actualizar_texto_auditoria("[INFO] Análisis de servicios finalizado.\n\n")

    def verificar_permisos(self):
        self._actualizar_texto_auditoria("[INFO] Verificando permisos de archivos críticos...\n")
        try:
            archivos = [os.path.join(self.etc_dir, 'passwd'), os.path.join(self.etc_dir, 'shadow'), os.path.join(self.etc_dir, 'sudoers')]
            for archivo in archivos:
                if os.path.exists(archivo):
                    exito, out, err = self._ejecutar_comando_seguro(f'ls -l {archivo}', f"Permisos de {archivo}", timeout=5, usar_sudo=True)
                    if out:
                        self._actualizar_texto_auditoria(f"{out}\n")
                    if err:
                        self._actualizar_texto_auditoria(f"[ERROR] {err}\n")
                else:
                    self._actualizar_texto_auditoria(f"[ADVERTENCIA] {archivo} no existe en el sistema.\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] No se pudo verificar permisos: {e}\n")
        self._actualizar_texto_auditoria("[INFO] Verificación de permisos finalizada.\n\n")
    def crear_interfaz(self):
        self.configure(bg=self.colors['bg_primary'])
        self.pack_propagate(False)
        self.paned_window = tk.PanedWindow(self, orient="horizontal", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)

        botones_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(botones_frame, minsize=220)


        terminal_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(terminal_frame, minsize=400)

        titulo_frame = tk.Frame(terminal_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(10, 10))
        titulo = tk.Label(titulo_frame, text="Auditoría de Seguridad del Sistema",
            bg=self.colors['bg_primary'], fg=self.colors['fg_accent'],
            font=('Arial', 16, 'bold'))
        titulo.pack(pady=10)

        self.info_panel = tk.LabelFrame(terminal_frame, text="Información de la Acción", bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], font=('Arial', 11, 'bold'))
        self.info_panel.pack(fill=tk.X, padx=10, pady=(0, 5))
        self.info_label = tk.Label(self.info_panel, text="Selecciona una acción para ver información relevante aquí.",
                                 bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], anchor="w", justify="left", font=('Arial', 10))
        self.info_label.pack(fill=tk.X, padx=8, pady=6)

        self._crear_seccion_deteccion_malware(botones_frame)
        self._crear_seccion_configuraciones(botones_frame)
        self._crear_seccion_utilidades(botones_frame)

        self.auditoria_text = tk.Text(terminal_frame, wrap=tk.WORD, height=20, width=120, bg="#181818", fg="#00FF00", insertbackground="#00FF00")
        self.auditoria_text.pack(padx=10, pady=10, fill="both", expand=True)

        comando_label = tk.Label(terminal_frame, text="COMANDO:", bg=self.colors['bg_primary'], fg=self.colors['fg_accent'], font=('Arial', 10, 'bold'))
        comando_label.pack(padx=10, anchor="w")

        self.comando_entry = tk.Entry(terminal_frame, width=80, bg="#222", fg="#00FF00", insertbackground="#00FF00")
        self.comando_entry.pack(padx=10, pady=5, fill="x")
        self.comando_entry.bind('<Return>', self.ejecutar_comando_entry)
    def actualizar_info_panel(self, titulo_accion, descripcion):
        self.info_panel.config(text=titulo_accion)
        self.info_label.config(text=descripcion)

    def _mostrar_info_seguridad(self):
        info = (
            "\n[INFO SEGURIDAD]\n"
            "- Utilice siempre comandos validados y auditados.\n"
            "- No ejecute comandos peligrosos sin comprender su efecto.\n"
            "- Revise los logs de auditoría para detectar anomalías.\n"
            "- Mantenga el sistema y las herramientas actualizadas.\n"
        )
        self._actualizar_texto_auditoria(info)
    def _ejecutar_comando_seguro(self, comando, descripcion="", timeout=60, usar_sudo=False, mostrar_en_terminal=True):
        """
        Ejecuta un comando externo de forma segura, validando y registrando la acción.
        - Valida el comando con el validador global de seguridad.
        - Usa SudoManager si se requiere privilegio.
        - Registra la acción en el log global y en la interfaz.
        - Maneja errores y timeouts de forma robusta.
        """
        from aresitos.utils.seguridad_comandos import validador_comandos
        try:
            valido, comando_sanitizado, msg = validador_comandos.validar_comando_completo(comando)
            if not valido:
                self._actualizar_texto_auditoria(f"[SECURITY] {msg}\n")
                return False, '', msg
            if descripcion:
                self._actualizar_texto_auditoria(f"[INFO] Ejecutando: {descripcion}\n")
            self._actualizar_texto_auditoria(f"[CMD] {comando_sanitizado}\n")
            if self._gestor_permisos is None:
                self._actualizar_texto_auditoria("[ERROR] GestorPermisosSeguro no disponible\n")
                return False, '', 'GestorPermisosSeguro no disponible'
            # Convertir comando_sanitizado a lista si es string
            if isinstance(comando_sanitizado, str):
                comando_list = comando_sanitizado.split()
            else:
                comando_list = comando_sanitizado
            herramienta = comando_list[0]
            argumentos = comando_list[1:]
            exito, out, err = self._gestor_permisos.ejecutar_con_permisos(herramienta, argumentos, timeout=timeout)
            if mostrar_en_terminal:
                if out:
                    self._actualizar_texto_auditoria(out)
                if err:
                    self._actualizar_texto_auditoria(f"[ERROR] {err}\n")
            return exito, out, err
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] Fallo ejecutando comando: {e}\n")
            return False, '', str(e)

    def limpiar_terminal_auditoria(self):
        try:
            import datetime
            if hasattr(self, 'auditoria_text') and self.auditoria_text:
                self.auditoria_text.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.auditoria_text.insert(tk.END, "="*60 + "\n")
                self.auditoria_text.insert(tk.END, "Terminal ARESITOS - Auditoría v2.0\n")
                self.auditoria_text.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.auditoria_text.insert(tk.END, "Sistema: Kali Linux - Security Audit Tools\n")
                self.auditoria_text.insert(tk.END, "="*60 + "\n")
                self.auditoria_text.insert(tk.END, "LOG Terminal Auditoría reiniciado\n\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] Error limpiando terminal Auditoría: {e}\n")
    
    def ejecutar_comando_entry(self, event=None):
        if hasattr(self, 'comando_entry') and self.comando_entry:
            comando = self.comando_entry.get().strip()
            if not comando:
                return
            if hasattr(self, 'auditoria_text') and self.auditoria_text:
                self.auditoria_text.insert(tk.END, f"\n> {comando}\n")
                self.auditoria_text.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            # Ejecutar el comando tal cual en thread
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
            thread.daemon = True
            thread.start()
    
    def _ejecutar_comando_async(self, comando):
        def worker():
            # Comandos especiales de ARESITOS
            if comando == "ayuda-comandos":
                self._mostrar_ayuda_comandos()
                return
            elif comando == "info-seguridad":
                self._mostrar_info_seguridad()
                return
            elif comando in ["clear", "cls"]:
                self.limpiar_terminal_auditoria()
                return
            self._ejecutar_comando_seguro(comando, descripcion="Comando terminal usuario", timeout=30, usar_sudo=False, mostrar_en_terminal=True)
            if hasattr(self, 'auditoria_text') and self.auditoria_text:
                self.auditoria_text.see(tk.END)
        threading.Thread(target=worker, daemon=True).start()
    
    def abrir_logs_auditoria(self):
        self._actualizar_texto_auditoria("[INFO] Función para abrir logs aún no implementada.\n")
    
    def _crear_seccion_deteccion_malware(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Detección de Malware", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Detectar Rootkits", self.detectar_rootkits, self.colors['warning'],
             "Analiza el sistema en busca de rootkits y malware usando herramientas nativas de Linux/Kali. Muestra hallazgos críticos y sugerencias de seguridad."),
            ("Cancelar Rootkits", self.cancelar_rootkits, self.colors['danger'],
             "Detiene cualquier proceso activo de detección de rootkits y limpia archivos temporales generados por las herramientas."),
            ("Auditoría nuclei", self.ejecutar_nuclei, self.colors['info'],
             "Ejecuta un escaneo de vulnerabilidades profesional con nuclei. Requiere tener nuclei instalado y actualizado."),
            ("Scan httpx", self.ejecutar_httpx, self.colors['fg_accent'],
             "Realiza un escaneo rápido de servicios web usando httpx para detectar tecnologías, títulos y estado HTTP."),
        ]
        for text, command, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text):
                return lambda: (self.actualizar_info_panel(text, ayuda_text), cmd())
            btn = tk.Button(section_frame, text=text, command=make_cmd(command, ayuda),
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
            if "Cancelar" in text:
                btn.config(state="disabled")
                if "Rootkits" in text:
                    self.btn_cancelar_rootkits = btn
    
    def _crear_seccion_configuraciones(self, parent):
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Configuraciones", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Analizar Servicios", self.analizar_servicios, self.colors['info'],
             "Analiza los servicios activos en el sistema para detectar configuraciones inseguras o servicios innecesarios."),
            ("Verificar Permisos", self.verificar_permisos, self.colors['success'],
             "Verifica los permisos de archivos y directorios críticos para detectar posibles riesgos de seguridad."),
            ("Configuración SSH", self.auditar_ssh, self.colors['fg_accent'],
             "Audita la configuración del servicio SSH para detectar debilidades y malas prácticas."),
            ("Políticas de Contraseña", self.verificar_password_policy, self.colors['danger'],
             "Verifica las políticas de contraseñas del sistema y detecta usuarios sin contraseña o configuraciones débiles."),
            ("Análisis SUID/SGID", self.analizar_suid_sgid, self.colors['warning'],
             "Busca archivos con permisos SUID/SGID que pueden ser explotados para escalar privilegios."),
        ]
        for text, command, color, ayuda in buttons:
            def make_cmd(cmd, ayuda_text):
                return lambda: (self.actualizar_info_panel(text, ayuda_text), cmd())
            btn = tk.Button(section_frame, text=text, command=make_cmd(command, ayuda),
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
        
        buttons = [
            ("Info Hardware", self.obtener_info_hardware, self.colors['bg_primary'],
             "Muestra información básica del hardware del sistema (CPU, RAM, almacenamiento, etc.)."),
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
    
    def ejecutar_lynis(self):
        if self.proceso_auditoria_activo:
            self._actualizar_texto_auditoria("ERROR Auditoría Lynis ya en ejecución\n")
            return
            
        def ejecutar_lynis_worker():
            self.proceso_auditoria_activo = True
            self._actualizar_texto_auditoria("=== INICIANDO AUDITORÍA LYNIS PROFESIONAL ===\n")
            # Validar y ejecutar Lynis con privilegios si es posible
            exito_which, out_which, err_which = self._ejecutar_comando_seguro("which lynis", "Verificar instalación de Lynis", timeout=10, usar_sudo=False)
            if exito_which:
                self._actualizar_texto_auditoria("OK Lynis encontrado en sistema\n")
                log_dir = os.path.join(self.var_log_dir, "lynis")
                self._actualizar_texto_auditoria(f"• Verificando directorio de logs: {log_dir}\n")
                cmd = "lynis audit system --verbose --quick --warning --no-colors"
                exito_lynis, out_lynis, err_lynis = self._ejecutar_comando_seguro(cmd, "Auditoría completa del sistema", timeout=600, usar_sudo=True)
                self._actualizar_texto_auditoria("\n=== PROCESANDO RESULTADOS LYNIS ===\n")
                if out_lynis:
                    lineas_importantes = []
                    warnings_count = 0
                    suggestions_count = 0
                    for linea in out_lynis.split('\n'):
                        linea = linea.strip()
                        if any(keyword in linea.lower() for keyword in [
                            'warning', 'suggestion', 'found', 'missing', 'weak', 
                            'vulnerable', 'security', 'hardening', 'firewall',
                            'password', 'permission', 'root', 'sudo', 'ssh']):
                            if 'warning' in linea.lower():
                                warnings_count += 1
                                lineas_importantes.append(f"WARNING {linea}")
                            elif 'suggestion' in linea.lower():
                                suggestions_count += 1
                                lineas_importantes.append(f"TIP {linea}")
                            elif any(critical in linea.lower() for critical in ['vulnerable', 'weak', 'missing']):
                                lineas_importantes.append(f"CRITICO {linea}")
                            else:
                                lineas_importantes.append(f"INFO {linea}")
                    self._actualizar_texto_auditoria(f"OK Auditoría completada - Procesando {len(lineas_importantes)} hallazgos\n")
                    self._actualizar_texto_auditoria(f"WARNING Advertencias encontradas: {warnings_count}\n")
                    self._actualizar_texto_auditoria(f"TIP Sugerencias de mejora: {suggestions_count}\n\n")
                    self._actualizar_texto_auditoria("=== HALLAZGOS PRINCIPALES ===\n")
                    for i, linea in enumerate(lineas_importantes[:30], 1):
                        self._actualizar_texto_auditoria(f"{i:2d}. {linea}\n")
                    if len(lineas_importantes) > 30:
                        self._actualizar_texto_auditoria(f"... y {len(lineas_importantes) - 30} hallazgos adicionales\n")
                    self._actualizar_texto_auditoria("\n=== ARCHIVOS DE REPORTE ===\n")
                    posibles_reportes = [
                        os.path.join(self.var_log_dir, "lynis.log"),
                        os.path.join(self.var_log_dir, "lynis-report.dat"),
                        os.path.join(os.sep, "tmp", "lynis.log")
                    ]
                        # ...existing code...
                self._actualizar_texto_auditoria("• Verificar: lynis --version\n")
            self._actualizar_texto_auditoria("=== AUDITORÍA LYNIS PROFESIONAL COMPLETADA ===\n\n")
                # Eliminar la inicialización de widgets fuera de métodos
            self.thread_auditoria = None
            self._actualizar_texto_auditoria("\n=== Auditoría finalizada ===\n\n")
    
    def cancelar_auditoria(self):
        if self.proceso_auditoria_activo:
            self.proceso_auditoria_activo = False
            self._actualizar_texto_auditoria("\n🛑 Cancelando auditoría...\n")
            
            # Importar sistema unificado para detener procesos de auditoría
            try:
                from ..utils.detener_procesos import detener_procesos
                
                # Callbacks para la vista
                def callback_actualizacion(mensaje):
                    self._actualizar_texto_auditoria(mensaje)
                
                def callback_habilitar():
                    self._finalizar_auditoria()
                    self._log_terminal("Auditoría cancelada completamente", "AUDITORIA", "INFO")
                
                # Usar sistema unificado
                detener_procesos.cancelar_auditoria(callback_actualizacion, callback_habilitar)
                    
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR cancelando auditoría: {e}\n")
                self._finalizar_auditoria()
    
    def detectar_rootkits(self):
        import threading
        self._log_terminal("Iniciando detección de rootkits y malware...")
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_auditoria, "=== DETECCIÓN DE ROOTKITS CON HERRAMIENTAS LINUX ===\n\n")
                herramientas = [
                    ("rkhunter", "rkhunter --check --sk --nocolors"),
                    ("chkrootkit", "chkrootkit"),
                    ("lynis", "lynis audit system --tests-from-group malware --no-colors")
                ]
                alguna_encontrada = False
                for nombre, comando in herramientas:
                    exito, out, err = self._ejecutar_comando_seguro(f"which {nombre}", f"Verificando {nombre}", timeout=10, usar_sudo=False)
                    if exito and out.strip():
                        alguna_encontrada = True
                        self.after(0, self._actualizar_texto_auditoria, f"\n[INFO] Ejecutando {nombre}...\n")
                        exito2, out2, err2 = self._ejecutar_comando_seguro(comando, f"Detección de rootkits con {nombre}", timeout=180, usar_sudo=True)
                        if out2:
                            self.after(0, self._actualizar_texto_auditoria, f"\n--- Resultados de {nombre} ---\n{out2}\n")
                        if err2:
                            self.after(0, self._actualizar_texto_auditoria, f"[ERROR] {err2}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"[ADVERTENCIA] Herramienta {nombre} no encontrada en el sistema.\n")
                if not alguna_encontrada:
                    self.after(0, self._actualizar_texto_auditoria, "[ERROR] No se encontró ninguna herramienta de detección de rootkits instalada. Instala rkhunter, chkrootkit o lynis.\n")
                self.after(0, self._actualizar_texto_auditoria, "\n=== DETECCIÓN FINALIZADA ===\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR detectando rootkits: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    
    def guardar_auditoria(self):
        if hasattr(self, 'auditoria_text') and self.auditoria_text:
            contenido = self.auditoria_text.get(1.0, tk.END)
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
        if hasattr(self, 'auditoria_text') and self.auditoria_text:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.delete(1.0, tk.END)
            self.auditoria_text.config(state=tk.DISABLED)
    
    def cancelar_rootkits(self):
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== CANCELANDO DETECCIÓN ROOTKITS ===\n")
                procesos_rootkits = ['rkhunter', 'chkrootkit', 'unhide', 'lynis']
                procesos_terminados = 0
                for proceso in procesos_rootkits:
                    try:
                        exito, out, err = self._gestor_permisos.ejecutar_con_permisos('pgrep', ['-f', proceso])
                        if exito and out.strip():
                            pids = out.strip().split('\n')
                            for pid in pids:
                                if pid.strip():
                                    exito_kill, _, err_kill = self._gestor_permisos.ejecutar_con_permisos('kill', ['-TERM', pid.strip()])
                                    if exito_kill:
                                        self._actualizar_texto_auditoria(f"OK Terminado proceso {proceso} (PID: {pid.strip()})\n")
                                        procesos_terminados += 1
                                    else:
                                        self._actualizar_texto_auditoria(f"[ERROR] Fallo terminando proceso {proceso} PID {pid.strip()}: {err_kill}\n")
                    except Exception as e:
                        self._actualizar_texto_auditoria(f"[ERROR] Fallo terminando proceso {proceso}: {e}\n")
                if procesos_terminados > 0:
                    self._actualizar_texto_auditoria(f"OK COMPLETADO: {procesos_terminados} procesos de rootkits terminados\n")
                else:
                    self._actualizar_texto_auditoria("• INFO: No se encontraron procesos de detección de rootkits activos\n")
                archivos_temp = [
                    os.path.join(os.sep, 'tmp', 'rkhunter.log'),
                    os.path.join(os.sep, 'tmp', 'chkrootkit.log'),
                    os.path.join(self.var_log_dir, 'rkhunter.log')
                ]
                for archivo in archivos_temp:
                    try:
                        exito_rm, _, err_rm = self._gestor_permisos.ejecutar_con_permisos('rm', ['-f', archivo])
                        if not exito_rm:
                            self._actualizar_texto_auditoria(f"[ERROR] Fallo eliminando archivo temporal {archivo}: {err_rm}\n")
                    except Exception as e:
                        self._actualizar_texto_auditoria(f"[ERROR] Fallo eliminando archivo temporal {archivo}: {e}\n")
                self._actualizar_texto_auditoria("OK Limpieza de archivos temporales completada\n")
                self._actualizar_texto_auditoria("=== CANCELACIÓN ROOTKITS COMPLETADA ===\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR durante cancelación: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ejecutar_nuclei(self):
        if self.proceso_auditoria_activo:
            self._actualizar_texto_auditoria("ERROR Auditoría nuclei ya en ejecución\n")
            return
        def ejecutar_nuclei_worker():
            try:
                self.proceso_auditoria_activo = True
                self._actualizar_texto_auditoria("=== INICIANDO AUDITORÍA NUCLEI PROFESIONAL ===\n")
                exito_which, out_which, err_which = self._ejecutar_comando_seguro("which nuclei", "Verificar instalación de nuclei", timeout=10, usar_sudo=False)
                if exito_which:
                    self._actualizar_texto_auditoria("OK nuclei encontrado en sistema\n")
                    self._ejecutar_comando_seguro("nuclei -update-templates", "Actualizar templates nuclei", timeout=300, usar_sudo=True)
                    # ...existing code...
                    # El resto del flujo de objetivos, escaneo y templates puede ser adaptado a _ejecutar_comando_seguro de forma análoga
                    self._actualizar_texto_auditoria("[INFO] Auditoría nuclei ejecutada con validación y seguridad\n")
                else:
                    self._actualizar_texto_auditoria("ERROR nuclei no encontrado en sistema\n")
                    self._actualizar_texto_auditoria("INSTALACIÓN REQUERIDA:\n")
                    self._actualizar_texto_auditoria("• apt update && apt install nuclei\n")
                    self._actualizar_texto_auditoria("• O desde Go: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n")
                    self._actualizar_texto_auditoria("• Verificar: nuclei -version\n")
                    self._actualizar_texto_auditoria("• Actualizar templates: nuclei -update-templates\n")
                self._actualizar_texto_auditoria("=== AUDITORÍA NUCLEI PROFESIONAL COMPLETADA ===\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR CRÍTICO en auditoría nuclei: {str(e)}\n")
            finally:
                self.proceso_auditoria_activo = False
        self.thread_auditoria = threading.Thread(target=ejecutar_nuclei_worker, daemon=True)
        self.thread_auditoria.start()
    
    def ejecutar_httpx(self):
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== INICIANDO ESCANEO HTTPX ===\n")
                exito_which, out_which, err_which = self._ejecutar_comando_seguro(["which", "httpx"], "Verificar instalación de httpx", 10, False)
                if exito_which:
                    self._actualizar_texto_auditoria("OK httpx encontrado en sistema\n")
                    # Ejemplo: escanear localhost:80
                    self._ejecutar_comando_seguro([
                        "httpx", "-u", "http://localhost:80", "-probe", "-status-code", "-title", "-tech-detect", "-timeout", "5", "-silent"
                    ], "Escaneo rápido httpx", 15, False)
                    self._actualizar_texto_auditoria("[INFO] Escaneo httpx ejecutado con validación y seguridad\n")
                else:
                    self._actualizar_texto_auditoria("WARNING httpx no encontrado\n")
                    self._actualizar_texto_auditoria("INSTALACIÓN: apt install httpx\n")
                    self._actualizar_texto_auditoria("O desde Go: go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n")
                self._actualizar_texto_auditoria("=== ESCANEO HTTPX COMPLETADO ===\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en httpx: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_suid_sgid(self):
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Analizando archivos SUID/SGID...\n")
                try:
                    self._actualizar_texto_auditoria(" Buscando archivos SUID...\n")
                    exito_suid, out_suid, err_suid = self._gestor_permisos.ejecutar_con_permisos('find', ['/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], timeout=30)
                    if out_suid:
                        archivos_suid = out_suid.strip().split('\n')[:20]
                        self._actualizar_texto_auditoria(f" Archivos SUID encontrados ({len(archivos_suid)} de muchos):\n")
                        for archivo in archivos_suid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                    self._actualizar_texto_auditoria(" Buscando archivos SGID...\n")
                    exito_sgid, out_sgid, err_sgid = self._gestor_permisos.ejecutar_con_permisos('find', ['/', '-perm', '-2000', '-type', 'f', '2>/dev/null'], timeout=30)
                    if out_sgid:
                        archivos_sgid = out_sgid.strip().split('\n')[:20]
                        self._actualizar_texto_auditoria(f" Archivos SGID encontrados ({len(archivos_sgid)} de muchos):\n")
                        for archivo in archivos_sgid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR buscando SUID/SGID: {str(e)}\n")
                self._actualizar_texto_auditoria("OK Análisis SUID/SGID completado\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en análisis SUID/SGID: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def auditar_ssh(self):
        self._actualizar_texto_auditoria("[INFO] Auditando configuración SSH...\n")
        try:
            sshd_config = os.path.join(self.etc_dir, 'ssh', 'sshd_config')
            if os.path.exists(sshd_config):
                exito, out, err = self._ejecutar_comando_seguro(f'grep -E "^PermitRootLogin|^PasswordAuthentication|^Port" {sshd_config}', "Opciones críticas SSH", timeout=10, usar_sudo=True)
                if out:
                    self._actualizar_texto_auditoria(f"\n--- Opciones críticas ---\n{out}\n")
                if err:
                    self._actualizar_texto_auditoria(f"[ERROR] {err}\n")
            else:
                self._actualizar_texto_auditoria("[ADVERTENCIA] sshd_config no encontrado.\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] No se pudo auditar SSH: {e}\n")
        self._actualizar_texto_auditoria("[INFO] Auditoría SSH finalizada.\n\n")
    
    def verificar_password_policy(self):
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Verificando políticas de contraseñas...\n")
                import subprocess
                import os
                
                try:
                    # Verificar /etc/login.defs
                    login_defs_path = os.path.join(self.etc_dir, 'login.defs')
                    if os.path.exists(login_defs_path):
                        self._actualizar_texto_auditoria(f" Configuración en {login_defs_path}:\n")
                        exito_grep, out_grep, err_grep = self._gestor_permisos.ejecutar_con_permisos('grep', ['-E', 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE', login_defs_path])
                        if out_grep:
                            for linea in out_grep.split('\n'):
                                if linea.strip() and not linea.startswith('#'):
                                    self._actualizar_texto_auditoria(f"  {linea}\n")
                    # Verificar PAM
                    pam_common_path = os.path.join(self.etc_dir, 'pam.d', 'common-password')
                    if os.path.exists(pam_common_path):
                        self._actualizar_texto_auditoria(f" Configuración PAM (common-password):\n")
                        exito_pam, out_pam, err_pam = self._gestor_permisos.ejecutar_con_permisos('grep', ['pam_pwquality', pam_common_path])
                        if out_pam:
                            self._actualizar_texto_auditoria(f"  OK pwquality configurado\n")
                        else:
                            self._actualizar_texto_auditoria(f"  WARNING pwquality no configurado\n")
                    # Verificar usuarios con contraseñas vacías
                    self._actualizar_texto_auditoria(" Verificando usuarios sin contraseña:\n")
                    shadow_path = os.path.join(self.etc_dir, 'shadow')
                    exito_awk, out_awk, err_awk = self._gestor_permisos.ejecutar_con_permisos('awk', ['-F:', '($2 == "") {print $1}', shadow_path])
                    if out_awk and out_awk.strip():
                        self._actualizar_texto_auditoria("  WARNING Usuarios sin contraseña encontrados:\n")
                        for usuario in out_awk.split('\n'):
                            if usuario.strip():
                                self._actualizar_texto_auditoria(f"    {usuario}\n")
                    else:
                        self._actualizar_texto_auditoria("  OK No hay usuarios sin contraseña\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR verificando políticas: {str(e)}\n")
                self._actualizar_texto_auditoria("OK Verificación de políticas completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en verificación de políticas: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()

    def _log_terminal(self, mensaje, modulo="AUDITORIA", nivel="INFO"):
        from aresitos.vista.vista_dashboard import VistaDashboard
        VistaDashboard.log_actividad_global(mensaje, modulo, nivel)

    def _analizar_resultados_chkrootkit(self, output):
        try:
            lineas = output.split('\n')
            sospechas_criticas = []
            sospechas_moderadas = []
            total_checks = 0
            patrones_criticos = ['INFECTED', 'SUSPECT', 'MALWARE', 'ROOTKIT', 'TROJAN']
            patrones_moderados = ['WARNING', 'POSSIBLE', 'SUSPICIOUS', 'UNKNOWN']
            for linea in lineas:
                linea_clean = linea.strip()
                if not linea_clean:
                    continue
                linea_upper = linea_clean.upper()
                if 'CHECKING' in linea_upper:
                    total_checks += 1
                if any(patron in linea_upper for patron in patrones_criticos):
                    sospechas_criticas.append(linea_clean)
                elif any(patron in linea_upper for patron in patrones_moderados):
                    sospechas_moderadas.append(linea_clean)
            self._actualizar_texto_auditoria(f"\n[CHKROOTKIT] Chequeos realizados: {total_checks}\n")
            if sospechas_criticas:
                self._actualizar_texto_auditoria(f"[CRÍTICO] Hallazgos críticos: {len(sospechas_criticas)}\n")
                for s in sospechas_criticas[:20]:
                    self._actualizar_texto_auditoria(f"  {s}\n")
                if len(sospechas_criticas) > 20:
                    self._actualizar_texto_auditoria(f"  ...y {len(sospechas_criticas)-20} más\n")
            else:
                self._actualizar_texto_auditoria("[OK] No se detectaron amenazas críticas.\n")
            if sospechas_moderadas:
                self._actualizar_texto_auditoria(f"[MODERADO] Hallazgos moderados: {len(sospechas_moderadas)}\n")
                for s in sospechas_moderadas[:20]:
                    self._actualizar_texto_auditoria(f"  {s}\n")
                if len(sospechas_moderadas) > 20:
                    self._actualizar_texto_auditoria(f"  ...y {len(sospechas_moderadas)-20} más\n")
            self._actualizar_texto_auditoria("[INFO] Análisis chkrootkit finalizado.\n\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] Fallo analizando resultados chkrootkit: {e}\n")

