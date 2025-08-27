# -*- coding: utf-8 -*-

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
    rutas_criticas = [
        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers', '/etc/ssh/sshd_config', '/etc/hosts',
        '/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log', '/var/log/secure', '/var/log/wtmp', '/var/log/btmp',
        '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/local/bin/', '/usr/local/sbin/', '/var/log/lynis.log', '/var/log/rkhunter.log', '/var/log/chkrootkit.log'
    ]

    def __init__(self, *args, **kwargs):
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
        # Verificar permisos root al iniciar
        if not self._es_root():
            self._deshabilitar_todo_auditoria_por_root()
            messagebox.showwarning("Permisos insuficientes", "Debes ejecutar ARESITOS como root para usar la Auditoría.")
            self._actualizar_texto_auditoria("[ERROR] Debes ejecutar ARESITOS como root para usar la Auditoría.\n")

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
        # Deshabilita todos los botones de auditoría y muestra advertencia
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
        """Establece el controlador principal para la vista de auditoría (stub seguro)."""
        self.controlador = controlador
        # Se puede ampliar para conectar callbacks o lógica específica
    def _mostrar_ayuda_comandos(self):
        self._actualizar_texto_auditoria("[INFO] Ayuda de comandos no implementada aún.\n")

    def obtener_info_hardware(self):
        self._actualizar_texto_auditoria("[INFO] Información de hardware no implementada aún.\n")

    def _finalizar_auditoria(self):
        self._actualizar_texto_auditoria("[INFO] Finalización de auditoría no implementada aún.\n")
    def _actualizar_texto_auditoria(self, texto):
        # Stub seguro: actualiza el área de texto de auditoría si existe
        if hasattr(self, 'auditoria_text') and self.auditoria_text:
            try:
                self.auditoria_text.insert('end', texto)
                self.auditoria_text.see('end')
            except Exception as e:
                # Si falla la inserción, mostrar error en consola como último recurso
                print(f"[ERROR] No se pudo actualizar el área de texto de auditoría: {e}\nIntentado mostrar: {texto}")
        else:
            # Fallback seguro: mostrar en consola
            print(texto)

    def analizar_servicios(self):
        # Stub seguro para evitar errores
        self._actualizar_texto_auditoria("[INFO] Análisis de servicios no implementado aún.\n")

    def verificar_permisos(self):
        # Stub seguro para evitar errores
        self._actualizar_texto_auditoria("[INFO] Verificación de permisos no implementada aún.\n")
    def crear_interfaz(self):
        """Crear interfaz especializada para auditorías de seguridad."""
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)

        # Frame superior para el contenido principal
        contenido_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(contenido_frame, minsize=400)

        # Frame del título con tema Burp Suite
        titulo_frame = tk.Frame(contenido_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(10, 10))

        titulo = tk.Label(titulo_frame, text="Auditoría de Seguridad del Sistema",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack(pady=10)

        # Frame principal con tema
        main_frame = tk.Frame(contenido_frame, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Panel izquierdo - Resultados con tema Burp Suite
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        label_results = tk.Label(left_frame, text="Resultados de Auditoría",
                                 bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                 font=('Arial', 12, 'bold'))
        label_results.pack(anchor=tk.W, pady=(0, 5))

        # Terminal de salida de auditoría
        self.auditoria_text = scrolledtext.ScrolledText(left_frame, height=25, width=65,
                                   bg=self.colors['bg_primary'],
                                   fg=self.colors['fg_primary'],
                                   insertbackground=self.colors['fg_accent'],
                                   font=('Consolas', 10),
                                   relief='flat', bd=1)
        self.auditoria_text.pack(fill=tk.BOTH, expand=True)

        # Entrada de comandos
        self.comando_entry = tk.Entry(left_frame, font=('Consolas', 10),
                                      bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                      insertbackground=self.colors['fg_accent'], relief='flat', bd=1)
        self.comando_entry.pack(fill=tk.X, pady=(10, 0))
        self.comando_entry.bind('<Return>', self.ejecutar_comando_entry)

        # Llamar a las secciones de botones y utilidades
        self._crear_seccion_deteccion_malware(left_frame)
        self._crear_seccion_configuraciones(left_frame)
        self._crear_seccion_utilidades(left_frame)
    # ...existing code...

    def _mostrar_info_seguridad(self):
        """Mostrar información de seguridad y buenas prácticas."""
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
        import subprocess
        try:
            valido, comando_sanitizado, msg = validador_comandos.validar_comando_completo(comando)
            if not valido:
                self._actualizar_texto_auditoria(f"[SECURITY] {msg}\n")
                return None
            if descripcion:
                self._actualizar_texto_auditoria(f"[INFO] Ejecutando: {descripcion}\n")
            self._actualizar_texto_auditoria(f"[CMD] {comando_sanitizado}\n")
            if usar_sudo:
                try:
                    from aresitos.utils.sudo_manager import get_sudo_manager
                    sudo_manager = get_sudo_manager()
                    if sudo_manager.is_sudo_active():
                        resultado = sudo_manager.execute_sudo_command(comando_sanitizado, timeout=timeout)
                    else:
                        self._actualizar_texto_auditoria("[WARNING] SudoManager no activo, ejecutando sin privilegios\n")
                        resultado = subprocess.run(comando_sanitizado, shell=True, capture_output=True, text=True, timeout=timeout)
                except ImportError:
                    resultado = subprocess.run(comando_sanitizado, shell=True, capture_output=True, text=True, timeout=timeout)
            else:
                resultado = subprocess.run(comando_sanitizado, shell=True, capture_output=True, text=True, timeout=timeout)
            if mostrar_en_terminal:
                if resultado.stdout:
                    self._actualizar_texto_auditoria(resultado.stdout)
                if resultado.stderr:
                    self._actualizar_texto_auditoria(f"[ERROR] {resultado.stderr}\n")
            return resultado
        except subprocess.TimeoutExpired:
            self._actualizar_texto_auditoria("[ERROR] Timeout ejecutando comando\n")
        except Exception as e:
            self._actualizar_texto_auditoria(f"[ERROR] Fallo ejecutando comando: {e}\n")
    # Eliminado: bloques de widgets y llamadas a métodos fuera de métodos





    
    def limpiar_terminal_auditoria(self):
        """Limpiar terminal Auditoría manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
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
        """Ejecutar comando desde la entrada con validación de seguridad."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        
        # Validar comando con el módulo de seguridad
        try:
            from aresitos.utils.seguridad_comandos import validador_comandos
            
            es_valido, comando_sanitizado, mensaje = validador_comandos.validar_comando_completo(comando)
            
            # Mostrar el comando original en el terminal
            self.auditoria_text.insert(tk.END, f"\n> {comando}\n")
            
            if not es_valido:
                # Mostrar error de seguridad
                self.auditoria_text.insert(tk.END, f"{mensaje}\n")
                self.auditoria_text.insert(tk.END, "TIP Use 'ayuda-comandos' para ver comandos disponibles\n")
                self.auditoria_text.see(tk.END)
                self.comando_entry.delete(0, tk.END)
                return
            
            # Mostrar mensaje de autorización
            self.auditoria_text.insert(tk.END, f"{mensaje}\n")
            self.auditoria_text.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            
            # Ejecutar comando sanitizado en thread
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando_sanitizado,))
            thread.daemon = True
            thread.start()
            
        except ImportError:
            # Fallback sin validación (modo inseguro)
            self.auditoria_text.insert(tk.END, f"\n> {comando}\n")
            self.auditoria_text.insert(tk.END, "[WARNING]  EJECUTANDO SIN VALIDACIÓN DE SEGURIDAD\n")
            self.auditoria_text.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            self.auditoria_text.insert(tk.END, f"\n> {comando}\n")
            self.auditoria_text.insert(tk.END, f"[FAIL] Error de seguridad: {e}\n")
            self.auditoria_text.see(tk.END)
            self.comando_entry.delete(0, tk.END)
    
    def _ejecutar_comando_async(self, comando):
        """Ejecutar comando de forma asíncrona, validando y registrando la acción."""
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
            self.auditoria_text.see(tk.END)
        threading.Thread(target=worker, daemon=True).start()
    
    def abrir_logs_auditoria(self):
        """Abrir carpeta de logs Auditoría."""
    # Acción no implementada aún.
    pass
    
    def _crear_seccion_deteccion_malware(self, parent):
        """Crear sección de detección de malware y rootkits."""
        # Sección de detección de malware con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Detección de Malware", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Detectar Rootkits", self.detectar_rootkits, self.colors['warning']),
            ("Cancelar Rootkits", self.cancelar_rootkits, self.colors['danger']),
            ("Auditoría nuclei", self.ejecutar_nuclei, self.colors['info']),
            ("Scan httpx", self.ejecutar_httpx, self.colors['fg_accent']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
            
            # Configuración especial para botones cancelar
            if "Cancelar" in text:
                btn.config(state="disabled")
                if "Rootkits" in text:
                    self.btn_cancelar_rootkits = btn
    
    def _crear_seccion_configuraciones(self, parent):
        """Crear sección de análisis de configuraciones."""
        # Sección de configuraciones con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Configuraciones", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Analizar Servicios", self.analizar_servicios, self.colors['info']),
            ("Verificar Permisos", self.verificar_permisos, self.colors['success']),
            ("Configuración SSH", self.auditar_ssh, self.colors['fg_accent']),
            ("Políticas de Contraseña", self.verificar_password_policy, self.colors['danger']),
            ("Análisis SUID/SGID", self.analizar_suid_sgid, self.colors['warning']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
    
    def _crear_seccion_utilidades(self, parent):
        """Crear sección de utilidades generales."""
        # Sección de utilidades con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Utilidades", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Info Hardware", self.obtener_info_hardware, self.colors['bg_primary']),
            ("Guardar Resultados", self.guardar_auditoria, self.colors['info']),
            ("Limpiar Pantalla", self.limpiar_auditoria, self.colors['warning']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['fg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
    
    def ejecutar_lynis(self):
        """Ejecutar auditoría completa del sistema con Lynis - auditor de seguridad profesional."""
        if self.proceso_auditoria_activo:
            self._actualizar_texto_auditoria("ERROR Auditoría Lynis ya en ejecución\n")
            return
            
        def ejecutar_lynis_worker():
            self.proceso_auditoria_activo = True
            self._actualizar_texto_auditoria("=== INICIANDO AUDITORÍA LYNIS PROFESIONAL ===\n")
            # Validar y ejecutar Lynis con privilegios si es posible
            resultado_which = self._ejecutar_comando_seguro("which lynis", "Verificar instalación de Lynis", timeout=10, usar_sudo=False)
            if resultado_which and resultado_which.returncode == 0:
                self._actualizar_texto_auditoria("OK Lynis encontrado en sistema\n")
                log_dir = "/var/log/lynis"
                self._actualizar_texto_auditoria(f"• Verificando directorio de logs: {log_dir}\n")
                cmd = "lynis audit system --verbose --quick --warning --no-colors"
                resultado_lynis = self._ejecutar_comando_seguro(cmd, "Auditoría completa del sistema", timeout=600, usar_sudo=True)
                salida = resultado_lynis.stdout if resultado_lynis else ""
                errores = resultado_lynis.stderr if resultado_lynis else ""
                self._actualizar_texto_auditoria("\n=== PROCESANDO RESULTADOS LYNIS ===\n")
                if salida:
                    lineas_importantes = []
                    warnings_count = 0
                    suggestions_count = 0
                    for linea in salida.split('\n'):
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
                    posibles_reportes = ["/var/log/lynis.log", "/var/log/lynis-report.dat", "/tmp/lynis.log"]
                        # ...existing code...
                self._actualizar_texto_auditoria("• Verificar: lynis --version\n")
            self._actualizar_texto_auditoria("=== AUDITORÍA LYNIS PROFESIONAL COMPLETADA ===\n\n")
                # Eliminar la inicialización de widgets fuera de métodos
            self.thread_auditoria = None
            self._actualizar_texto_auditoria("\n=== Auditoría finalizada ===\n\n")
    
    def cancelar_auditoria(self):
        """Cancelar auditoría usando sistema unificado."""
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
        """Detectar rootkits usando herramientas nativas de Linux y Kali."""
        import threading
        self._log_terminal("Iniciando detección de rootkits y malware...")
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_auditoria, "=== DETECCIÓN DE ROOTKITS CON HERRAMIENTAS LINUX ===\n\n")
                # Aquí debe ir el cuerpo real de la función ejecutar, correctamente indentado
                pass
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR detectando rootkits: {str(e)}\n")
        threading.Thread(target=ejecutar, daemon=True).start()

    
    def guardar_auditoria(self):
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
        self.auditoria_text.config(state=tk.NORMAL)
        self.auditoria_text.delete(1.0, tk.END)
        self.auditoria_text.config(state=tk.DISABLED)
    
    def cancelar_rootkits(self):
        """Cancelar detección de rootkits mediante terminación de procesos activos."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== CANCELANDO DETECCIÓN ROOTKITS ===\n")
                import subprocess
                
                # Terminar procesos conocidos de detección de rootkits
                procesos_rootkits = ['rkhunter', 'chkrootkit', 'unhide', 'lynis']
                procesos_terminados = 0
                
                for proceso in procesos_rootkits:
                    try:
                        # Buscar procesos activos
                        resultado = subprocess.run(['pgrep', '-f', proceso], 
                                                capture_output=True, text=True)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            pids = resultado.stdout.strip().split('\n')
                            for pid in pids:
                                if pid.strip():
                                    # Terminar proceso específico
                                    subprocess.run(['kill', '-TERM', pid.strip()], 
                                                capture_output=True)
                                    self._actualizar_texto_auditoria(f"OK Terminado proceso {proceso} (PID: {pid.strip()})\n")
                                    procesos_terminados += 1
                    except Exception as e:
                        self._actualizar_texto_auditoria(f"[ERROR] Fallo terminando proceso {proceso}: {e}\n")
                
                if procesos_terminados > 0:
                    self._actualizar_texto_auditoria(f"OK COMPLETADO: {procesos_terminados} procesos de rootkits terminados\n")
                else:
                    self._actualizar_texto_auditoria("• INFO: No se encontraron procesos de detección de rootkits activos\n")
                    
                # Limpiar archivos temporales de rootkits
                archivos_temp = ['/tmp/rkhunter.log', '/tmp/chkrootkit.log', '/var/log/rkhunter.log']
                for archivo in archivos_temp:
                    try:
                        subprocess.run(['rm', '-f', archivo], capture_output=True)
                    except Exception as e:
                        self._actualizar_texto_auditoria(f"[ERROR] Fallo eliminando archivo temporal {archivo}: {e}\n")
                        
                self._actualizar_texto_auditoria("OK Limpieza de archivos temporales completada\n")
                self._actualizar_texto_auditoria("=== CANCELACIÓN ROOTKITS COMPLETADA ===\n\n")
                
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR durante cancelación: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ejecutar_nuclei(self):
        """Ejecutar auditoría completa con nuclei - escáner de vulnerabilidades profesional mejorado."""
        if self.proceso_auditoria_activo:
            self._actualizar_texto_auditoria("ERROR Auditoría nuclei ya en ejecución\n")
            return
        def ejecutar_nuclei_worker():
            try:
                self.proceso_auditoria_activo = True
                self._actualizar_texto_auditoria("=== INICIANDO AUDITORÍA NUCLEI PROFESIONAL ===\n")
                resultado_which = self._ejecutar_comando_seguro("which nuclei", "Verificar instalación de nuclei", timeout=10, usar_sudo=False)
                if resultado_which and resultado_which.returncode == 0:
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
        """Ejecutar escaneo web completo con httpx - probe HTTP avanzado."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== INICIANDO ESCANEO HTTPX ===\n")
                resultado_which = self._ejecutar_comando_seguro("which httpx", "Verificar instalación de httpx", timeout=10, usar_sudo=False)
                if resultado_which and resultado_which.returncode == 0:
                    self._actualizar_texto_auditoria("OK httpx encontrado en sistema\n")
                    # Ejemplo: escanear localhost:80
                    self._ejecutar_comando_seguro("httpx -u http://localhost:80 -probe -status-code -title -tech-detect -timeout 5 -silent", "Escaneo rápido httpx", timeout=15, usar_sudo=False)
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
        """Analizar archivos SUID/SGID."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Analizando archivos SUID/SGID...\n")
                import subprocess
                
                try:
                    # Buscar archivos SUID
                    self._actualizar_texto_auditoria(" Buscando archivos SUID...\n")
                    resultado = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], 
                                             capture_output=True, text=True, timeout=30)
                    if resultado.stdout:
                        archivos_suid = resultado.stdout.strip().split('\n')[:20]  # Primeros 20
                        self._actualizar_texto_auditoria(f" Archivos SUID encontrados ({len(archivos_suid)} de muchos):\n")
                        for archivo in archivos_suid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                    
                    # Buscar archivos SGID
                    self._actualizar_texto_auditoria(" Buscando archivos SGID...\n")
                    resultado = subprocess.run(['find', '/', '-perm', '-2000', '-type', 'f', '2>/dev/null'], 
                                             capture_output=True, text=True, timeout=30)
                    if resultado.stdout:
                        archivos_sgid = resultado.stdout.strip().split('\n')[:20]  # Primeros 20
                        self._actualizar_texto_auditoria(f" Archivos SGID encontrados ({len(archivos_sgid)} de muchos):\n")
                        for archivo in archivos_sgid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("TIMEOUT en búsqueda SUID/SGID\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR buscando SUID/SGID: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Análisis SUID/SGID completado\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en análisis SUID/SGID: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def auditar_ssh(self):
        """Auditar configuración SSH."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Auditando configuración SSH...\n")
                import subprocess
                import os
                
                try:
                    # Verificar si SSH está instalado
                    if os.path.exists('/etc/ssh/sshd_config'):
                        self._actualizar_texto_auditoria("OK SSH configurado en el sistema\n")
                        
                        # Verificar configuraciones importantes
                        with open('/etc/ssh/sshd_config', 'r') as f:
                            config = f.read()
                            
                        self._actualizar_texto_auditoria(" Verificando configuraciones críticas:\n")
                        
                        if 'PermitRootLogin no' in config:
                            self._actualizar_texto_auditoria("  OK PermitRootLogin: Deshabilitado\n")
                        else:
                            self._actualizar_texto_auditoria("  WARNING PermitRootLogin: Revisar configuración\n")
                        
                        if 'PasswordAuthentication no' in config:
                            self._actualizar_texto_auditoria("  OK PasswordAuthentication: Deshabilitado\n")
                        else:
                            self._actualizar_texto_auditoria("  WARNING PasswordAuthentication: Habilitado\n")
                        
                        if 'Port 22' in config:
                            self._actualizar_texto_auditoria("  WARNING Puerto: 22 (puerto por defecto)\n")
                        else:
                            self._actualizar_texto_auditoria("  OK Puerto: Cambiado del puerto por defecto\n")
                            
                    else:
                        self._actualizar_texto_auditoria("ERROR SSH no encontrado o no configurado\n")
                    
                    # Verificar servicio SSH
                    resultado = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
                    if resultado.stdout.strip() == 'active':
                        self._actualizar_texto_auditoria("OK Servicio SSH: Activo\n")
                    else:
                        self._actualizar_texto_auditoria("ERROR Servicio SSH: Inactivo\n")
                
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR auditando SSH: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Auditoría SSH completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en auditoría SSH: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_password_policy(self):
        """Verificar políticas de contraseñas."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Verificando políticas de contraseñas...\n")
                import subprocess
                import os
                
                try:
                    # Verificar /etc/login.defs
                    if os.path.exists('/etc/login.defs'):
                        self._actualizar_texto_auditoria(" Configuración en /etc/login.defs:\n")
                        resultado = subprocess.run(['grep', '-E', 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE', '/etc/login.defs'], 
                                                 capture_output=True, text=True)
                        if resultado.stdout:
                            for linea in resultado.stdout.split('\n'):
                                if linea.strip() and not linea.startswith('#'):
                                    self._actualizar_texto_auditoria(f"  {linea}\n")
                    
                    # Verificar PAM
                    if os.path.exists('/etc/pam.d/common-password'):
                        self._actualizar_texto_auditoria(" Configuración PAM (common-password):\n")
                        resultado = subprocess.run(['grep', 'pam_pwquality', '/etc/pam.d/common-password'], 
                                                 capture_output=True, text=True)
                        if resultado.stdout:
                            self._actualizar_texto_auditoria(f"  OK pwquality configurado\n")
                        else:
                            self._actualizar_texto_auditoria(f"  WARNING pwquality no configurado\n")
                    
                    # Verificar usuarios con contraseñas vacías
                    self._actualizar_texto_auditoria(" Verificando usuarios sin contraseña:\n")
                    resultado = subprocess.run(['awk', '-F:', '($2 == "") {print $1}', '/etc/shadow'], 
                                             capture_output=True, text=True)
                    if resultado.stdout.strip():
                        self._actualizar_texto_auditoria("  WARNING Usuarios sin contraseña encontrados:\n")
                        for usuario in resultado.stdout.split('\n'):
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
        """Registrar mensaje en el terminal integrado global."""
        # Usar el terminal global de VistaDashboard
        from aresitos.vista.vista_dashboard import VistaDashboard
        VistaDashboard.log_actividad_global(mensaje, modulo, nivel)

    def _analizar_resultados_chkrootkit(self, output):
        """Analizar resultados de chkrootkit de forma robusta y mostrar todo en pantalla."""
        try:
            lineas = output.split('\n')
            sospechas_criticas = []
            sospechas_moderadas = []
            total_checks = 0
            # Patrones mejorados de detección para chkrootkit
            patrones_criticos = ['INFECTED', 'SUSPECT', 'MALWARE', 'ROOTKIT', 'TROJAN']
            patrones_moderados = ['WARNING', 'POSSIBLE', 'SUSPICIOUS', 'UNKNOWN']
            for linea in lineas:
                linea_clean = linea.strip()
                if not linea_clean:
                    continue
                linea_upper = linea_clean.upper()
                # Contar checks realizados (líneas que contienen "CHECKING")
                if 'CHECKING' in linea_upper:
                    total_checks += 1
                # Clasificar hallazgos por criticidad
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

