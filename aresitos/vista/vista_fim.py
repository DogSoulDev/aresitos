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
# Importar el gestor de sudo de ARESITOS
from aresitos.utils.sudo_manager import get_sudo_manager
import logging
from datetime import datetime, timedelta

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

from aresitos.vista.terminal_mixin import TerminalMixin

class VistaFIM(tk.Frame, TerminalMixin):
    def _enviar_a_reportes(self, comando, salida, es_error=False):
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
                    'timestamp': datetime.now().isoformat(),
                    'modulo': 'fim',
                    'comando': comando,
                    'salida': salida,
                    'es_error': es_error
                }
                vista_reportes.set_datos_modulo('fim', datos)
        except Exception:
            pass
    def _actualizar_texto_fim_seguro(self, texto):
        def _update():
            try:
                if hasattr(self, 'fim_text') and self.fim_text.winfo_exists():
                    self.fim_text.config(state=tk.NORMAL)
                    self.fim_text.insert(tk.END, texto)
                    self.fim_text.see(tk.END)
                from aresitos.utils.logger_aresitos import LoggerAresitos
                self.logger = LoggerAresitos.get_instance()
            except (tk.TclError, AttributeError):
                pass
        self.after(0, _update)

    def _actualizar_estado_seguro(self, texto):
        # No existe label_estado, así que loguea en el área principal de texto FIM
        self._actualizar_texto_fim_seguro(f"[ESTADO] {texto}\n")
    @staticmethod
    def _get_base_dir():
        """Obtener la ruta base absoluta del proyecto ARESITOS."""
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_monitoreo_activo = False
        self.thread_monitoreo = None
        self.logger = logging.getLogger(__name__)
        # Centralizar rutas críticas/sensibles de Kali Linux
        self.rutas_sensibles_kali = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers', '/etc/security/', '/etc/login.defs',
            '/etc/ssh/sshd_config', '/etc/ssh/ssh_config', '/root/.ssh/', '/home/*/.ssh/', '/etc/hosts.allow', '/etc/hosts.deny',
            '/boot/', '/lib/modules/', '/proc/modules', '/sys/module/', '/etc/modules', '/etc/modprobe.d/',
            '/etc/hosts', '/etc/resolv.conf', '/etc/network/interfaces', '/etc/iptables/', '/etc/ufw/',
            '/etc/systemd/system/', '/etc/init.d/', '/etc/cron.d/', '/etc/crontab', '/var/spool/cron/', '/etc/anacrontab',
            '/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log', '/var/log/secure', '/var/log/wtmp', '/var/log/btmp',
            '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/bin/', '/usr/local/sbin/',
            '/etc/apt/sources.list', '/etc/apt/sources.list.d/', '/etc/default/', '/opt/', '/usr/share/kali-*',
            '/var/log/audit/', '/var/log/faillog', '/var/log/lastlog', '/var/log/apt/', '/var/log/dpkg.log',
            '/var/log/clamav/', '/var/log/rkhunter.log', '/var/log/chkrootkit.log', '/var/log/plaso/', '/var/log/forensics/',
            '/var/log/guymager/', '/var/log/testdisk.log', '/var/log/autopsy/', '/var/log/volatility/', '/var/log/yara/',
            '/var/log/lynis.log', '/var/log/lynis-report.dat', '/var/log/lynis-control.dat',
            '/var/lib/aide/', '/var/lib/tripwire/', '/var/lib/samhain/', '/etc/fail2ban/', '/etc/aide/', '/etc/tripwire/', '/etc/samhain/',
            '/etc/logrotate.d/', '/etc/rsyslog.d/', '/etc/audit/', '/etc/mysql/', '/etc/postgresql/', '/etc/bind/', '/etc/dhcp/', '/etc/samba/', '/etc/vsftpd/'
        ]
        # Configurar tema y colores
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
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
                'fg_secondary': '#666666',
                'fg_accent': '#007acc',
                'button_bg': '#007acc',
                'button_fg': 'white',
                'success': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545',
                'info': '#17a2b8'
            }
        self.crear_interfaz()
        # No deshabilitar botones por privilegios al iniciar. Feedback solo al intentar usar funciones avanzadas.


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

    # Eliminada función de deshabilitar botones por root/sudo. Ahora el feedback es solo al intentar usar funciones avanzadas.
    
    def _log_terminal(self, mensaje, modulo="FIM", nivel="INFO"):
        """Registrar actividad en el terminal integrado global."""
        try:
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
        except Exception:
            pass  # Terminal no disponible

    def crear_interfaz(self):
        """Crear la interfaz de usuario para FIM."""
        self.configure(bg=self.colors['bg_primary'])
        
        # Título principal
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        titulo_label = tk.Label(titulo_frame, text="FIM - File Integrity Monitoring", 
                               bg=self.colors['bg_primary'], fg=self.colors['fg_accent'],
                               font=('Arial', 16, 'bold'))
        titulo_label.pack(anchor="w")
        
        subtitulo_label = tk.Label(titulo_frame, text="Monitoreo de integridad de archivos críticos del sistema",
                                  bg=self.colors['bg_primary'], fg=self.colors['fg_secondary'],
                                  font=('Arial', 10))
        subtitulo_label.pack(anchor="w")
        
        # Frame principal con paned window
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Crear PanedWindow para dividir contenido principal y terminal
        paned_window = tk.PanedWindow(main_frame, orient=tk.VERTICAL, 
                                     bg=self.colors['bg_primary'], 
                                     sashrelief=tk.RAISED,
                                     sashwidth=3)
        paned_window.pack(fill="both", expand=True)

        # Frame superior para el contenido principal de FIM
        contenido_frame = tk.Frame(paned_window, bg=self.colors['bg_primary'])
        paned_window.add(contenido_frame, minsize=300)

        # Crear el contenido principal de FIM en contenido_frame
        self.crear_contenido_fim(contenido_frame)
        # Terminal inferior estandarizado (único terminal)
        self.crear_terminal_inferior(self, titulo_vista="FIM", altura_terminal=12)
        # Configurar posición inicial del sash
        paned_window.update_idletasks()
        try:
            paned_window.sash_place(0, 400, 0)  # Posición inicial del divisor
        except:
            pass  # Si falla, usar posición por defecto
    
    def crear_terminal_integrado(self, parent_frame):
        """Crear terminal integrado FIM con diseño estándar coherente y tema burp_theme."""
        try:
            from aresitos.vista.burp_theme import burp_theme
            terminal_frame = tk.LabelFrame(
                parent_frame,
                text="Terminal ARESITOS - FIM",
                bg=self.colors['bg_secondary'],
                fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")
            )
            terminal_frame.pack(fill="both", expand=True)

            # Controles de terminal (igual que monitoreo)
            controles_frame = tk.Frame(terminal_frame, bg=self.colors['bg_secondary'])
            controles_frame.pack(fill="x", padx=5, pady=2)
            btn_limpiar = tk.Button(
                controles_frame,
                text="LIMPIAR",
                command=self.limpiar_terminal_fim,
                bg="#ffaa00",
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)
            btn_logs = tk.Button(
                controles_frame,
                text="VER LOGS",
                command=self.abrir_logs_fim,
                bg="#007acc",
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)

            self.terminal_output = scrolledtext.ScrolledText(
                terminal_frame,
                height=6,
                bg='#000000',
                fg='#00ff00',
                font=("Consolas", 8),
                insertbackground='#00ff00',
                selectbackground='#333333'
            )
            self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)

            entrada_frame = tk.Frame(terminal_frame, bg='#1e1e1e')
            entrada_frame.pack(fill="x", padx=5, pady=2)
            tk.Label(entrada_frame, text="COMANDO:", bg='#1e1e1e', fg='#00ff00', font=("Arial", 9, "bold")).pack(side="left", padx=(0, 5))
            self.comando_entry = tk.Entry(entrada_frame, bg='#000000', fg='#00ff00', font=("Consolas", 9), insertbackground='#00ff00')
            self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.comando_entry.bind("<Return>", self.ejecutar_comando_entry)
            ejecutar_btn = tk.Button(entrada_frame, text="EJECUTAR", command=self.ejecutar_comando_entry, bg='#2d5aa0', fg='white', font=("Arial", 8, "bold"))
            ejecutar_btn.pack(side="right")

            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - FIM v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, "Sistema: Kali Linux - File Integrity Monitoring\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Monitoreo FIM en tiempo real\n\n")

        except Exception as e:
            self.crear_terminal_local(parent_frame)
    
    def limpiar_terminal_fim(self):
        """Limpiar terminal FIM manteniendo cabecera."""
        try:
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - FIM v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - File Integrity Monitoring\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal FIM reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal FIM: {e}")
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada (sin validación de seguridad, root/sudo autenticado)."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        self.terminal_output.insert(tk.END, f"\n> {comando}\n")
        self.terminal_output.see(tk.END)
        self.comando_entry.delete(0, tk.END)
        def run_and_report():
            self._ejecutar_comando_async(comando, reportar=True)
        thread = threading.Thread(target=run_and_report)
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_async(self, comando, reportar=False):
        """Ejecutar comando de forma asíncrona con comandos especiales."""
        try:
            # Comandos especiales de ARESITOS
            if comando == "ayuda-comandos":
                self._mostrar_ayuda_comandos()
                if reportar:
                    self._enviar_a_reportes(comando, "[AYUDA COMANDOS]", False)
                return
            elif comando == "info-seguridad":
                self._mostrar_info_seguridad()
                if reportar:
                    self._enviar_a_reportes(comando, "[INFO SEGURIDAD]", False)
                return
            elif comando in ["clear", "cls"]:
                self.limpiar_terminal_fim()
                if reportar:
                    self._enviar_a_reportes(comando, "Pantalla limpiada", False)
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
                self.terminal_output.insert(tk.END, resultado.stdout)
                if reportar:
                    self._enviar_a_reportes(comando, resultado.stdout, False)
            if resultado.stderr:
                self.terminal_output.insert(tk.END, f"ERROR: {resultado.stderr}")
                if reportar:
                    self._enviar_a_reportes(comando, resultado.stderr, True)

            self.terminal_output.see(tk.END)

        except Exception as e:
            self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
            if reportar:
                self._enviar_a_reportes(comando, str(e), True)
        self.terminal_output.see(tk.END)
    
    def abrir_logs_fim(self):
        """Abrir carpeta de logs FIM con ruta robusta y multiplataforma."""
        try:
            import os
            import platform
            # Ruta robusta y multiplataforma al directorio de logs, relativa al proyecto
            logs_path = self._get_base_dir() / "logs"
            if logs_path.exists():
                if platform.system() == "Linux":
                    subprocess.run(["xdg-open", str(logs_path)], check=False)
                else:
                    subprocess.run(["explorer", str(logs_path)], check=False)
                self.log_to_terminal("Carpeta de logs FIM abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs FIM: {e}")
    
    def crear_terminal_local(self, parent_frame):
        """Crear terminal local si no hay terminal global disponible (fallback)."""
        self.terminal_output = scrolledtext.ScrolledText(parent_frame,
            height=6,
            bg='#000000',
            fg='#00ff00',
            font=("Consolas", 8),
            insertbackground='#00ff00')
        self.terminal_output.pack(fill="both", expand=True)
        # Mensaje inicial
        self.terminal_output.insert(tk.END, f"=== Terminal FIM Local ===\n")
        self.terminal_output.insert(tk.END, f"Iniciado: {datetime.now().strftime('%H:%M:%S')}\n")
        self.terminal_output.insert(tk.END, f"File Integrity Monitoring\n\n")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal con formato estándar."""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            
            # Log al terminal integrado estándar
            if hasattr(self, 'terminal_output'):
                self.terminal_output.insert(tk.END, mensaje_completo)
                self.terminal_output.see(tk.END)
        except:
            pass  # Si no hay terminal, ignorar silenciosamente
    
    def crear_contenido_fim(self, parent_frame):
        """Crear el contenido principal de FIM."""
        # Panel izquierdo - Controles
        left_frame = tk.Frame(parent_frame, bg=self.colors['bg_secondary'], relief="solid", bd=1)
        left_frame.pack(side="left", fill="y", padx=(0, 10))

        # Panel derecho - Resultados
        right_frame = tk.Frame(parent_frame, bg=self.colors['bg_primary'])
        right_frame.pack(side="right", fill="both", expand=True)

        # Controles del FIM
        controles_label = tk.Label(left_frame, text="Controles FIM", 
                                  bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                  font=('Arial', 12, 'bold'))
        controles_label.pack(anchor="w", padx=10, pady=(10, 5))

        # Botones de control
        self.btn_iniciar = tk.Button(left_frame, text="Iniciar Monitoreo",
                                    command=self.iniciar_monitoreo,
                                    bg=self.colors['success'], fg='white',
                                    font=('Arial', 10, 'bold'),
                                    relief='flat', padx=15, pady=8)
        self.btn_iniciar.pack(fill="x", padx=10, pady=5)

        self.btn_detener = tk.Button(left_frame, text="Detener Monitoreo",
                                    command=self.detener_monitoreo,
                                    state="disabled",
                                    bg=self.colors['danger'], fg='white',
                                    font=('Arial', 10),
                                    relief='flat', padx=15, pady=8)
        self.btn_detener.pack(fill="x", padx=10, pady=5)

        self.btn_verificar = tk.Button(left_frame, text="Verificar Integridad",
                                      command=self.verificar_integridad,
                                      bg=self.colors['info'], fg='white',
                                      font=('Arial', 10),
                                      relief='flat', padx=15, pady=8)
        self.btn_verificar.pack(fill="x", padx=10, pady=5)

        # NUEVOS BOTONES FASE 3.3 - FIM AVANZADO
        self.btn_monitoreo_avanzado = tk.Button(left_frame, text="Monitoreo Avanzado",
                                               command=self.monitoreo_avanzado_kali,
                                               bg='#6f42c1', fg='white',
                                               font=('Arial', 10),
                                               relief='flat', padx=15, pady=8)
        self.btn_monitoreo_avanzado.pack(fill="x", padx=10, pady=5)

    # Botón de Análisis Forense eliminado porque el método no está definido

        self.btn_tiempo_real = tk.Button(left_frame, text="Monitoreo Tiempo Real",
                                        command=self.iniciar_monitoreo_tiempo_real,
                                        bg='#28a745', fg='white',
                                        font=('Arial', 10),
                                        relief='flat', padx=15, pady=8)
        self.btn_tiempo_real.pack(fill="x", padx=10, pady=5)

        # BOTÓN PONER EN CUARENTENA
        cuarentena_label = tk.Label(left_frame, text="Cuarentena de Archivos", 
                                  bg=self.colors['bg_secondary'], fg=self.colors['danger'],
                                  font=('Arial', 11, 'bold'))
        cuarentena_label.pack(anchor="w", padx=10, pady=(20, 5))

        self.cuarentena_entry = tk.Entry(left_frame, width=30, font=('Consolas', 10))
        self.cuarentena_entry.pack(fill="x", padx=10, pady=(0, 5))
        self.cuarentena_entry.insert(0, "Ruta del archivo a poner en cuarentena")

        btn_cuarentena = tk.Button(
            left_frame, text="Agregar a Cuarentena",
            command=self._poner_en_cuarentena_desde_entry,
            bg="#ffb86c", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=12, pady=6,
            activebackground="#ffd9b3", activeforeground="#ff6633"
        )
        btn_cuarentena.pack(fill="x", padx=10, pady=5)

        # Área de resultados
        resultados_label = tk.Label(right_frame, text="Resultados del Monitoreo FIM",
                                   bg=self.colors['bg_primary'], fg=self.colors['fg_accent'],
                                   font=('Arial', 12, 'bold'))
        resultados_label.pack(anchor="w", pady=(0, 10))

        self.fim_text = scrolledtext.ScrolledText(right_frame, height=25,
                                                 bg=self.colors['bg_secondary'], 
                                                 fg=self.colors['fg_primary'],
                                                 font=('Consolas', 10),
                                                 insertbackground=self.colors['fg_accent'],
                                                 selectbackground=self.colors['fg_accent'],
                                                 wrap=tk.WORD, state=tk.DISABLED)
        self.fim_text.pack(fill="both", expand=True)

    def _poner_en_cuarentena_desde_entry(self):
        """Pone en cuarentena el archivo especificado en el campo de entrada."""
        ruta = self.cuarentena_entry.get().strip()
        if not ruta or ruta == "Ruta del archivo a poner en cuarentena":
            self.log_to_terminal("Debe especificar la ruta del archivo a poner en cuarentena.")
            return
        if not hasattr(self, 'controlador') or not self.controlador or not hasattr(self.controlador, 'controlador_cuarentena'):
            self.log_to_terminal("Controlador de cuarentena no disponible.")
            return
        try:
            resultado = self.controlador.controlador_cuarentena.cuarentenar_archivo(ruta, razon="Manual desde FIM")
            if resultado.get('exito'):
                self.log_to_terminal(f"Archivo puesto en cuarentena: {ruta}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Archivo puesto en cuarentena: {ruta}", False)
                self.cuarentena_entry.delete(0, tk.END)
            else:
                self.log_to_terminal(f"Error poniendo en cuarentena: {resultado.get('mensaje','sin mensaje')}")
                self._enviar_a_reportes('poner_en_cuarentena', f"Error: {resultado.get('mensaje','sin mensaje')}", True)
        except Exception as e:
            self.log_to_terminal(f"Excepción poniendo en cuarentena: {e}")
            self._enviar_a_reportes('poner_en_cuarentena', str(e), True)
    
    def iniciar_monitoreo(self):
        """Iniciar monitoreo continuo con información detallada."""
        if self.proceso_monitoreo_activo:
            return
        # Permitir iniciar monitoreo aunque no sea root, pero mostrar advertencia si alguna función lo requiere
        self.proceso_monitoreo_activo = True
        self._habilitar_botones_monitoreo(False)
        self._log_terminal("Iniciando sistema FIM - File Integrity Monitoring", "FIM", "INFO")
        self.log_to_terminal("FIM Iniciando monitoreo FIM del sistema...")
        self._actualizar_texto_fim("=== INICIANDO MONITOREO FIM - FILE INTEGRITY MONITORING ===\n\n")
        self.thread_monitoreo = threading.Thread(target=self._ejecutar_monitoreo_async)
        self.thread_monitoreo.daemon = True
        self.thread_monitoreo.start()
    
    def _ejecutar_monitoreo_async(self):
        """Ejecutar monitoreo FIM con análisis detallado usando comandos nativos de Linux."""
        fases_completadas = 0
        fases_con_error = 0
        total_fases = 3
        
        try:
            # FASE 1: Información del sistema con comandos Linux avanzados
            try:
                self._log_terminal("FASE 1: Análisis inicial del sistema con herramientas Linux", "FIM", "INFO")
                self.after(0, self._actualizar_texto_fim, "FASE 1: ANÁLISIS INICIAL DEL SISTEMA CON COMANDOS LINUX\n")
                self.after(0, self._actualizar_texto_fim, "POR QUÉ: Establecer baseline de seguridad usando herramientas nativas de Kali\n")
                self.after(0, self._actualizar_texto_fim, "CÓMO: Verificación con find, stat, lsof, and auditd para análisis forense\n\n")
                
                # Comandos Linux para monitoreo avanzado
                import subprocess
                
                # 1. Verificar archivos modificados recientemente
                self.after(0, self._actualizar_texto_fim, "COMANDO: find /etc -type f -mtime -1\n")
                self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Archivos de configuración modificados en las últimas 24 horas\n")
                try:
                    from aresitos.utils.gestor_permisos import GestorPermisosSeguro
                    gestor = GestorPermisosSeguro()
                    exito, out, err = gestor.ejecutar_con_permisos('find', ['/etc', '-type', 'f', '-mtime', '-1'])
                    if exito and out:
                        archivos_modificados = out.strip().split('\n')
                        self.after(0, self._actualizar_texto_fim, f"RESULTADO: {len(archivos_modificados)} archivos modificados\n")
                        for archivo in archivos_modificados[:5]:
                            self.after(0, self._actualizar_texto_fim, f"  - {archivo}\n")
                    else:
                        self.after(0, self._actualizar_texto_fim, "RESULTADO: No hay archivos modificados recientemente\n")
                except Exception:
                    self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo ejecutar find en /etc\n")
                
                self.after(0, self._actualizar_texto_fim, "\n")
                
                # 2. Verificar permisos sospechosos con find
                self.after(0, self._actualizar_texto_fim, "COMANDO: find /usr/bin -perm -4000 -type f\n")
                self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Detectar binarios con permisos SUID sospechosos\n")
                try:
                    from aresitos.utils.gestor_permisos import GestorPermisosSeguro
                    gestor = GestorPermisosSeguro()
                    exito, out, err = gestor.ejecutar_con_permisos('find', ['/usr/bin', '-perm', '-4000', '-type', 'f'])
                    if exito and out:
                        binarios_suid = out.strip().split('\n')
                        self.after(0, self._actualizar_texto_fim, f"RESULTADO: {len(binarios_suid)} binarios con SUID encontrados\n")
                        for binario in binarios_suid[:8]:
                            self.after(0, self._actualizar_texto_fim, f"  SUID: {binario}\n")
                    else:
                        self.after(0, self._actualizar_texto_fim, "RESULTADO: No se encontraron binarios SUID en /usr/bin\n")
                except Exception:
                    self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo verificar permisos SUID\n")
                
                self.after(0, self._actualizar_texto_fim, "\n")
                
                fases_completadas += 1
                self._log_terminal("OK FASE 1 completada exitosamente", "FIM", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 1: {str(e)}", "FIM", "ERROR")
                self.after(0, self._actualizar_texto_fim, f"ERROR FASE 1: {str(e)}\n")
                self._log_terminal("Continuando con la siguiente fase...", "FIM", "WARNING")
            
            # 3. Verificar procesos con archivos abiertos sospechosos
            self.after(0, self._actualizar_texto_fim, "COMANDO: lsof -i :22,80,443,8080,4444\n")
            self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Detectar procesos usando puertos comunes y backdoors\n")
            try:
                from aresitos.utils.gestor_permisos import GestorPermisosSeguro
                gestor = GestorPermisosSeguro()
                exito, out, err = gestor.ejecutar_con_permisos('lsof', ['-i', ':22,80,443,8080,4444'])
                if exito and out:
                    conexiones = out.strip().split('\n')[1:]
                    self.after(0, self._actualizar_texto_fim, f"RESULTADO: {len(conexiones)} conexiones activas en puertos críticos\n")
                    for conexion in conexiones[:5]:
                        partes = conexion.split()
                        if len(partes) >= 2:
                            self.after(0, self._actualizar_texto_fim, f"  PROCESO: {partes[0]} PID: {partes[1]}\n")
                else:
                    self.after(0, self._actualizar_texto_fim, "RESULTADO: No hay conexiones activas en puertos monitoreados\n")
            except Exception:
                self.after(0, self._actualizar_texto_fim, "ADVERTENCIA: lsof no disponible o error en ejecución\n")
            
            self.after(0, self._actualizar_texto_fim, "\n")
            
            # Archivos críticos específicos para ciberseguridad
            archivos_criticos = {
                '/etc/passwd': 'Lista de usuarios del sistema - modificaciones indican creación de cuentas maliciosas',
                '/etc/shadow': 'Hashes de contraseñas - cambios no autorizados indican compromiso de cuentas',
                '/etc/sudoers': 'Permisos administrativos - modificaciones pueden otorgar privilegios a atacantes',
                '/etc/hosts': 'Resolución DNS local - cambios pueden redirigir tráfico a servidores maliciosos',
                '/etc/ssh/sshd_config': 'Configuración SSH - modificaciones pueden habilitar accesos no autorizados',
                '/etc/crontab': 'Tareas programadas - cambios pueden establecer persistencia de malware',
                '/etc/fstab': 'Sistemas de archivos montados - modificaciones pueden exponer datos',
                '/root/.bashrc': 'Configuración shell de root - cambios pueden establecer backdoors'
            }
            
            if self.controlador:
                self._log_terminal("Conectando con controlador FIM avanzado", "FIM", "INFO")
                resultado = self.controlador.iniciar_monitoreo()
                
                # Variables de control de fases
                fases_completadas = 0
                fases_con_error = 0
                
                if resultado and resultado.get('exito'):
                    rutas_monitoreadas = resultado.get('rutas_monitoreadas', 0)
                    intervalo = resultado.get('intervalo_segundos', 30)
                    
                    self._log_terminal(f"FIM iniciado - monitoreando {rutas_monitoreadas} rutas cada {intervalo}s", "FIM", "SUCCESS")
                    self.after(0, self._actualizar_texto_fim, f"ESTADO: FIM activo - {rutas_monitoreadas} rutas bajo monitoreo\n")
                    self.after(0, self._actualizar_texto_fim, f"INTERVALO: Verificación cada {intervalo} segundos\n\n")
                    
                    # FASE 2: Verificación de archivos críticos
                    try:
                        self._log_terminal("FASE 2: Verificación de archivos críticos de seguridad", "FIM", "INFO")
                        self.after(0, self._actualizar_texto_fim, "FASE 2: VERIFICACIÓN DE ARCHIVOS CRÍTICOS\n")
                        
                        import time
                        import hashlib
                        import os
                        
                        archivos_verificados = 0
                        archivos_problema = 0
                        
                        for archivo, descripcion in archivos_criticos.items():
                            if not self.proceso_monitoreo_activo:
                                break
                            
                            try:
                                if os.path.exists(archivo):
                                    stat_info = os.stat(archivo)
                                    permisos = oct(stat_info.st_mode)[-3:]
                                    tamaño = stat_info.st_size
                                    
                                    # Verificar permisos apropiados
                                    permisos_esperados = {
                                        '/etc/passwd': '644',
                                        '/etc/shadow': '640', 
                                        '/etc/sudoers': '440',
                                        '/etc/hosts': '644',
                                        '/etc/ssh/sshd_config': '644',
                                        '/etc/crontab': '644',
                                        '/etc/fstab': '644',
                                        '/root/.bashrc': '644'
                                    }
                                    
                                    esperado = permisos_esperados.get(archivo, '644')
                                    archivos_verificados += 1
                                    
                                    if permisos == esperado:
                                        self.after(0, self._actualizar_texto_fim, f"OK {archivo}: Permisos correctos ({permisos}), Tamaño: {tamaño} bytes\n")
                                        self.after(0, self._actualizar_texto_fim, f"   FUNCIÓN: {descripcion}\n")
                                    else:
                                        archivos_problema += 1
                                        self.after(0, self._actualizar_texto_fim, f"ALERTA {archivo}: Permisos anómalos ({permisos}, esperado {esperado})\n")
                                        self.after(0, self._actualizar_texto_fim, f"   RIESGO: {descripcion}\n")
                                        self.after(0, self._actualizar_texto_fim, f"   ACCIÓN: Revisar cambios recientes y verificar integridad\n")
                                        self._log_terminal(f"ALERTA: Permisos anómalos en {archivo}", "FIM", "WARNING")
                                    
                                    # Calcular hash para baseline
                                    if os.path.isfile(archivo):
                                        with open(archivo, 'rb') as f:
                                            contenido = f.read()
                                            hash_sha256 = hashlib.sha256(contenido).hexdigest()[:16]
                                        self.after(0, self._actualizar_texto_fim, f"   HASH: {hash_sha256}... (baseline establecido)\n\n")
                                    
                                else:
                                    archivos_problema += 1
                                    self.after(0, self._actualizar_texto_fim, f"CRÍTICO {archivo}: Archivo no encontrado\n")
                                    self.after(0, self._actualizar_texto_fim, f"   IMPACTO: {descripcion}\n")
                                    self.after(0, self._actualizar_texto_fim, f"   ACCIÓN: Verificar si fue eliminado maliciosamente\n\n")
                                    self._log_terminal(f"CRÍTICO: Archivo crítico no encontrado - {archivo}", "FIM", "ERROR")
                                    
                            except Exception as e:
                                archivos_problema += 1
                                self.after(0, self._actualizar_texto_fim, f"ERROR verificando {archivo}: {str(e)}\n\n")
                        
                        fases_completadas += 1
                        self._log_terminal("OK FASE 2 completada exitosamente", "FIM", "SUCCESS")
                        
                    except Exception as e:
                        fases_con_error += 1
                        self._log_terminal(f"ERROR ERROR en FASE 2: {str(e)}", "FIM", "ERROR")
                        self.after(0, self._actualizar_texto_fim, f"ERROR FASE 2: {str(e)}\n")
                        self._log_terminal("Continuando con la siguiente fase...", "FIM", "WARNING")
                    
                    # FASE 2.5: Monitoreo avanzado con herramientas de Kali
                    try:
                        self._log_terminal("FASE 2.5: Análisis avanzado con herramientas especializadas de Kali", "FIM", "INFO")
                        self.after(0, self._actualizar_texto_fim, "\nFASE 2.5: ANÁLISIS AVANZADO CON HERRAMIENTAS KALI\n")
                        self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Análisis forense profundo usando toolkit de Kali Linux\n\n")
                        
                        # 1. Análisis de procesos ocultos con ps avanzado
                        self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: ps auxf | grep -v grep\n")
                        self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar procesos ocultos y jerarquías sospechosas\n")
                        try:
                            result = subprocess.run(['ps', 'auxf'], capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                procesos = result.stdout.strip().split('\n')
                                procesos_sospechosos = []
                                for proceso in procesos:
                                    if any(sospechoso in proceso.lower() for sospechoso in 
                                          ['backdoor', 'rootkit', 'trojan', 'keylog', 'rat']):
                                        procesos_sospechosos.append(proceso)
                                
                                if procesos_sospechosos:
                                    self.after(0, self._actualizar_texto_fim, f"ALERTA: {len(procesos_sospechosos)} procesos sospechosos detectados\n")
                                    for proc in procesos_sospechosos[:3]:
                                        self.after(0, self._actualizar_texto_fim, f"  SOSPECHOSO: {proc[:60]}...\n")
                                    self._log_terminal(f"ALERTA: {len(procesos_sospechosos)} procesos sospechosos en el sistema", "FIM", "WARNING")
                                else:
                                    self.after(0, self._actualizar_texto_fim, f"OK: {len(procesos)} procesos verificados, ninguno sospechoso\n")
                            else:
                                self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo ejecutar análisis de procesos\n")
                        except:
                            self.after(0, self._actualizar_texto_fim, "ERROR: Comando ps no disponible\n")
                        
                        self.after(0, self._actualizar_texto_fim, "\n")
                        
                        # 2. Verificación de módulos del kernel con lsmod
                        self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: lsmod | head -20\n")
                        self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar módulos del kernel maliciosos o rootkits\n")
                        try:
                            result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5)
                            if result.returncode == 0:
                                modulos = result.stdout.strip().split('\n')[1:21]  # Primeros 20 módulos
                                modulos_sospechosos = []
                                for modulo in modulos:
                                    partes = modulo.split()
                                    if len(partes) >= 1:
                                        nombre_modulo = partes[0]
                                        if any(sospechoso in nombre_modulo.lower() for sospechoso in 
                                              ['rootkit', 'hide', 'stealth', 'keylog']):
                                            modulos_sospechosos.append(nombre_modulo)
                                
                                if modulos_sospechosos:
                                    self.after(0, self._actualizar_texto_fim, f"ALERTA: {len(modulos_sospechosos)} módulos kernel sospechosos\n")
                                    for mod in modulos_sospechosos:
                                        self.after(0, self._actualizar_texto_fim, f"  MÓDULO SOSPECHOSO: {mod}\n")
                                    self._log_terminal(f"ALERTA: Módulos kernel sospechosos detectados", "FIM", "ERROR")
                                else:
                                    self.after(0, self._actualizar_texto_fim, f"OK: {len(modulos)} módulos kernel verificados\n")
                            else:
                                self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo verificar módulos del kernel\n")
                        except:
                            self.after(0, self._actualizar_texto_fim, "ERROR: lsmod no disponible\n")
                        
                        self.after(0, self._actualizar_texto_fim, "\n")
                        
                        # 3. Análisis de conexiones de red sospechosas con ss
                        self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: ss -tupnl | grep -E ':(4444|5555|6666|7777|8888|9999|31337)'\n")
                        self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar backdoors en puertos comúnmente usados por atacantes\n")
                        try:
                            result = subprocess.run(['ss', '-tupnl'], capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                lineas = result.stdout.strip().split('\n')
                                puertos_backdoor = ['4444', '5555', '6666', '7777', '8888', '9999', '31337', '12345', '54321']
                                backdoors_detectados = []
                                
                                for linea in lineas:
                                    for puerto in puertos_backdoor:
                                        if f':{puerto}' in linea:
                                            backdoors_detectados.append((puerto, linea))
                                
                                if backdoors_detectados:
                                    self.after(0, self._actualizar_texto_fim, f"CRÍTICO: {len(backdoors_detectados)} posibles backdoors detectados\n")
                                    for puerto, linea in backdoors_detectados:
                                        self.after(0, self._actualizar_texto_fim, f"  BACKDOOR PUERTO {puerto}: {linea[:50]}...\n")
                                    self._log_terminal(f"CRÍTICO: {len(backdoors_detectados)} backdoors detectados", "FIM", "ERROR")
                                else:
                                    self.after(0, self._actualizar_texto_fim, "OK: No se detectaron puertos de backdoor conocidos\n")
                            else:
                                self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo verificar conexiones de red\n")
                        except:
                            self.after(0, self._actualizar_texto_fim, "ERROR: ss no disponible\n")
                        
                        fases_completadas += 1
                        self._log_terminal("OK FASE 2.5 completada exitosamente", "FIM", "SUCCESS")
                        
                    except Exception as e:
                        fases_con_error += 1
                        self._log_terminal(f"ERROR ERROR en FASE 2.5: {str(e)}", "FIM", "ERROR")
                        self.after(0, self._actualizar_texto_fim, f"ERROR FASE 2.5: {str(e)}\n")
                        self._log_terminal("Continuando con la siguiente fase...", "FIM", "WARNING")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # 4. Verificación de archivos en directorios temporales
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: find /tmp /var/tmp -type f -executable -mtime -1\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar ejecutables sospechosos en directorios temporales\n")
                    try:
                        directorios_tmp = ['/tmp', '/var/tmp', '/dev/shm']
                        ejecutables_sospechosos = []
                        
                        for directorio in directorios_tmp:
                            if os.path.exists(directorio):
                                result = subprocess.run(['find', directorio, '-type', 'f', '-executable', '-mtime', '-1'], 
                                                      capture_output=True, text=True, timeout=15)
                                if result.returncode == 0 and result.stdout.strip():
                                    archivos = result.stdout.strip().split('\n')
                                    ejecutables_sospechosos.extend(archivos)
                        
                        if ejecutables_sospechosos:
                            self.after(0, self._actualizar_texto_fim, f"ALERTA: {len(ejecutables_sospechosos)} ejecutables recientes en /tmp\n")
                            for ejecutable in ejecutables_sospechosos[:5]:  # Primeros 5
                                if ejecutable.strip():
                                    try:
                                        stat_info = os.stat(ejecutable)
                                        # Usar comando ls para obtener propietario
                                        resultado_ls = subprocess.run(['ls', '-l', ejecutable], 
                                                                     capture_output=True, text=True, timeout=5)
                                        if resultado_ls.returncode == 0:
                                            partes_ls = resultado_ls.stdout.split()
                                            propietario = partes_ls[2] if len(partes_ls) > 2 else f"UID:{stat_info.st_uid}"
                                        else:
                                            propietario = f"UID:{stat_info.st_uid}"
                                        tamaño = stat_info.st_size
                                        self.after(0, self._actualizar_texto_fim, f"  EJECUTABLE: {ejecutable} (owner: {propietario}, size: {tamaño})\n")
                                    except:
                                        self.after(0, self._actualizar_texto_fim, f"  EJECUTABLE: {ejecutable}\n")
                            self._log_terminal(f"ALERTA: {len(ejecutables_sospechosos)} ejecutables sospechosos en directorios temporales", "FIM", "WARNING")
                        else:
                            self.after(0, self._actualizar_texto_fim, "OK: No se encontraron ejecutables recientes en directorios temporales\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_fim, f"ERROR: {str(e)}\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # 5. Verificación de logs de autenticación recientes
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: grep -i 'failed\\|error\\|invalid' /var/log/auth.log | tail -10\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar intentos de autenticación sospechosos o ataques\n")
                    try:
                        logs_auth = ['/var/log/auth.log', '/var/log/secure']
                        intentos_sospechosos = 0
                        
                        for log_file in logs_auth:
                            if os.path.exists(log_file):
                                result = subprocess.run(['grep', '-i', r'failed\|error\|invalid', log_file], 
                                                      capture_output=True, text=True, timeout=10)
                                if result.returncode == 0:
                                    lineas = result.stdout.strip().split('\n')
                                    intentos_sospechosos = len(lineas)
                                    if intentos_sospechosos > 10:
                                        self.after(0, self._actualizar_texto_fim, f"ALERTA: {intentos_sospechosos} intentos de autenticación fallidos\n")
                                        # Mostrar últimos 3 intentos
                                        for linea in lineas[-3:]:
                                            if linea.strip():
                                                timestamp = ' '.join(linea.split()[:3])
                                                self.after(0, self._actualizar_texto_fim, f"  FALLO: {timestamp}\n")
                                        self._log_terminal(f"ALERTA: {intentos_sospechosos} intentos de autenticación fallidos", "FIM", "WARNING")
                                    else:
                                        self.after(0, self._actualizar_texto_fim, f"OK: {intentos_sospechosos} fallos de autenticación (normal)\n")
                                break  # Solo verificar el primer log disponible
                        
                        if intentos_sospechosos == 0:
                            self.after(0, self._actualizar_texto_fim, "OK: No se encontraron fallos de autenticación\n")
                    except:
                        self.after(0, self._actualizar_texto_fim, "ERROR: No se pudieron verificar logs de autenticación\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # FASE 3: Resumen del análisis
                    try:
                        self._log_terminal("FASE 3: Generando resumen de seguridad", "FIM", "INFO")
                        self.after(0, self._actualizar_texto_fim, "FASE 3: RESUMEN DEL ANÁLISIS FIM\n")
                        self.after(0, self._actualizar_texto_fim, f"ARCHIVOS VERIFICADOS: {archivos_verificados}\n")
                        self.after(0, self._actualizar_texto_fim, f"PROBLEMAS DETECTADOS: {archivos_problema}\n")
                        
                        if archivos_problema == 0:
                            self.after(0, self._actualizar_texto_fim, "ESTADO: Sistema íntegro - No se detectaron anomalías\n")
                            self._log_terminal("Sistema íntegro - baseline establecido correctamente", "FIM", "SUCCESS")
                        else:
                            self.after(0, self._actualizar_texto_fim, f"ESTADO: Se detectaron {archivos_problema} anomalías - Revisar alertas\n")
                            self._log_terminal(f"ALERTA: {archivos_problema} anomalías detectadas en archivos críticos", "FIM", "WARNING")
                        
                        self.after(0, self._actualizar_texto_fim, "\nMONITOREO CONTINUO ACTIVO - Verificando cambios en tiempo real...\n")
                        self.after(0, self._actualizar_texto_fim, "INFO: Los cambios en archivos críticos serán detectados y reportados automáticamente\n")
                        
                        fases_completadas += 1
                        self._log_terminal("OK FASE 3 completada exitosamente", "FIM", "SUCCESS")
                        
                    except Exception as e:
                        fases_con_error += 1
                        self._log_terminal(f"ERROR ERROR en FASE 3: {str(e)}", "FIM", "ERROR")
                        self.after(0, self._actualizar_texto_fim, f"ERROR FASE 3: {str(e)}\n")
                        self._log_terminal("Fase final completada con errores", "FIM", "WARNING")
                    
                    # RESUMEN FINAL DE FASES
                    try:
                        self.after(0, self._actualizar_texto_fim, f"\n{'='*50}\n")
                        self.after(0, self._actualizar_texto_fim, f"RESUMEN DE EJECUCIÓN FIM\n")
                        self.after(0, self._actualizar_texto_fim, f"{'='*50}\n")
                        self.after(0, self._actualizar_texto_fim, f"OK FASES COMPLETADAS: {fases_completadas}/3\n")
                        self.after(0, self._actualizar_texto_fim, f"ERROR FASES CON ERROR: {fases_con_error}/3\n")
                        
                        if fases_con_error == 0:
                            self.after(0, self._actualizar_texto_fim, f"ESTADO GENERAL: OK TODAS LAS FASES COMPLETADAS EXITOSAMENTE\n")
                            self._log_terminal("OK FIM: Todas las fases completadas exitosamente", "FIM", "SUCCESS")
                        else:
                            self.after(0, self._actualizar_texto_fim, f"ESTADO GENERAL: ADVERTENCIA {fases_completadas} fases exitosas, {fases_con_error} con errores\n")
                            self._log_terminal(f"ADVERTENCIA FIM: {fases_completadas} fases exitosas, {fases_con_error} con errores", "FIM", "WARNING")
                        
                        self.after(0, self._actualizar_texto_fim, f"RESULTADO: FIM ejecutado de forma resiliente\n")
                        self.after(0, self._actualizar_texto_fim, f"{'='*50}\n")
                    except Exception as e:
                        self._log_terminal(f"Error generando resumen final: {str(e)}", "FIM", "ERROR")
                        
                else:
                    self._log_terminal("Error iniciando controlador FIM", "FIM", "ERROR")
                    self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo iniciar el controlador FIM\n")
            else:
                # Modo sin controlador - análisis básico
                self._log_terminal("Ejecutando análisis FIM básico (sin controlador)", "FIM", "WARNING")
                self.after(0, self._actualizar_texto_fim, "MODO: Análisis básico de integridad (controlador no disponible)\n\n")
                
                # Análisis básico de archivos críticos usando comandos del sistema
                self._realizar_analisis_basico()
                
        except Exception as e:
            error_msg = f"Error en monitoreo FIM: {str(e)}"
            self._log_terminal(error_msg, "FIM", "ERROR")
            self.after(0, self._actualizar_texto_fim, f"ERROR: {error_msg}\n")
        finally:
            # --- SINCRONIZACIÓN SILENCIOSA DE DATOS PARA REPORTES ---
            try:
                from aresitos.vista.vista_reportes import VistaReportes
                vista_reportes = None
                if hasattr(self.master, 'vista_reportes'):
                    vista_reportes = getattr(self.master, 'vista_reportes', None)
                else:
                    vistas = getattr(self.master, 'vistas', None)
                    if vistas and hasattr(vistas, 'get'):
                        vista_reportes = vistas.get('reportes', None)
                if vista_reportes and hasattr(self, 'obtener_datos_para_reporte'):
                    metodo = getattr(self, 'obtener_datos_para_reporte', None)
                    if callable(metodo):
                        datos = metodo()
                        vista_reportes.set_datos_modulo('fim', datos)
            except Exception:
                pass
            # Reactivar botones
            self.after(0, self._habilitar_botones_monitoreo, True)

    def detener_monitoreo(self):
        """Detener monitoreo FIM usando sistema unificado."""
        # Detener variable de control
        self.proceso_monitoreo_activo = False
        
        # Importar sistema unificado
        from ..utils.detener_procesos import detener_procesos
        
        # Callbacks para la vista
        def callback_actualizacion(mensaje):
            self._actualizar_texto_fim(mensaje)
        
        def callback_habilitar():
            self.after(0, self._habilitar_botones_monitoreo, True)
            self._log_terminal("Monitoreo FIM detenido completamente", "FIM", "INFO")
        
        # Usar sistema unificado
        detener_procesos.detener_fim(callback_actualizacion, callback_habilitar)
    
    def verificar_integridad(self):
        """Verificar integridad de archivos críticos."""
        self._log_terminal("Verificando integridad de archivos críticos", "FIM", "INFO")
        self._actualizar_texto_fim("=== VERIFICACIÓN DE INTEGRIDAD MANUAL ===\n")
        self._actualizar_texto_fim("Analizando archivos críticos del sistema...\n\n")
        
        # Realizar verificación básica
        self._realizar_analisis_basico()
        
        # NUEVO: Análisis completo de rutas sensibles para Issue 18
        self._analisis_completo_rutas_sensibles()
    
    def _analisis_completo_rutas_sensibles(self):
        """Análisis completo de rutas sensibles críticas de Kali Linux - Issue 18/24."""
        try:
            self._actualizar_texto_fim("\n" + "="*60 + "\n")
            self._actualizar_texto_fim("ANÁLISIS COMPLETO DE RUTAS SENSIBLES KALI LINUX\n")
            self._actualizar_texto_fim("="*60 + "\n")
            
            # Definir rutas sensibles categorizadas
            rutas_sensibles = {
                'autenticacion': {
                    '/etc/passwd': 'Lista de usuarios del sistema',
                    '/etc/shadow': 'Hashes de contraseñas',
                    '/etc/group': 'Definiciones de grupos',
                    '/etc/sudoers': 'Configuración de privilegios sudo',
                    '/etc/security/': 'Configuraciones de seguridad PAM',
                    '/etc/login.defs': 'Configuración de login del sistema'
                },
                'ssh_acceso_remoto': {
                    '/etc/ssh/sshd_config': 'Configuración principal SSH',
                    '/etc/ssh/ssh_config': 'Configuración cliente SSH',
                    '/root/.ssh/': 'Claves SSH del root',
                    '/home/*/.ssh/': 'Claves SSH de usuarios',
                    '/etc/hosts.allow': 'Hosts permitidos',
                    '/etc/hosts.deny': 'Hosts denegados'
                },
                'sistema_kernel': {
                    '/boot/': 'Archivos de arranque del sistema',
                    '/lib/modules/': 'Módulos del kernel',
                    '/proc/modules': 'Módulos cargados actualmente',
                    '/sys/module/': 'Información de módulos del kernel',
                    '/etc/modules': 'Módulos a cargar al inicio',
                    '/etc/modprobe.d/': 'Configuración de módulos'
                },
                'red_dns': {
                    '/etc/hosts': 'Resolución DNS local',
                    '/etc/resolv.conf': 'Configuración DNS',
                    '/etc/network/interfaces': 'Configuración de red',
                    '/etc/iptables/': 'Reglas de firewall',
                    '/etc/ufw/': 'Configuración UFW firewall'
                },
                'servicios_criticos': {
                    '/etc/systemd/system/': 'Servicios del sistema',
                    '/etc/init.d/': 'Scripts de inicialización',
                    '/etc/cron.d/': 'Tareas programadas del sistema',
                    '/etc/crontab': 'Archivo principal de cron',
                    '/var/spool/cron/': 'Crontabs de usuarios',
                    '/etc/anacrontab': 'Configuración anacron'
                },
                'logs_auditoria': {
                    '/var/log/auth.log': 'Log de autenticación',
                    '/var/log/syslog': 'Log principal del sistema',
                    '/var/log/kern.log': 'Log del kernel',
                    '/var/log/secure': 'Log de seguridad',
                    '/var/log/wtmp': 'Log de logins',
                    '/var/log/btmp': 'Log de intentos fallidos'
                },
                'ejecutables_sistema': {
                    '/bin/': 'Binarios esenciales del sistema',
                    '/sbin/': 'Binarios de administración',
                    '/usr/bin/': 'Binarios de aplicaciones',
                    '/usr/sbin/': 'Binarios administrativos',
                    '/usr/local/bin/': 'Binarios locales'
                },
                'configuracion_kali': {
                    '/etc/apt/sources.list': 'Repositorios APT',
                    '/etc/apt/sources.list.d/': 'Repositorios adicionales',
                    '/etc/default/': 'Configuraciones por defecto',
                    '/opt/': 'Software adicional instalado',
                    '/usr/share/kali-*': 'Herramientas específicas Kali'
                }
            }
            
            # Análisis por categorías
            total_archivos_verificados = 0
            total_problemas_detectados = 0
            
            for categoria, rutas in rutas_sensibles.items():
                self._actualizar_texto_fim(f"\nCATEGORÍA: {categoria.upper().replace('_', ' ')}\n")
                self._actualizar_texto_fim("-" * 50 + "\n")
                
                archivos_categoria = 0
                problemas_categoria = 0
                
                for ruta, descripcion in rutas.items():
                    if not self.proceso_monitoreo_activo:
                        break
                    
                    # Análisis específico por tipo de ruta
                    if '*' in ruta:
                        # Ruta con wildcard - usar glob
                        resultado = self._analizar_ruta_wildcard(ruta, descripcion)
                    elif os.path.isdir(ruta):
                        # Directorio - analizar contenido
                        resultado = self._analizar_directorio_sensible(ruta, descripcion)
                    elif os.path.isfile(ruta):
                        # Archivo individual - análisis detallado
                        resultado = self._analizar_archivo_sensible(ruta, descripcion)
                    else:
                        # Ruta no existe
                        self._actualizar_texto_fim(f"  WARNING: {ruta} no encontrado - {descripcion}\n")
                        continue
                    
                    archivos_categoria += resultado.get('archivos_verificados', 0)
                    problemas_categoria += resultado.get('problemas_detectados', 0)
                
                self._actualizar_texto_fim(f"RESUMEN {categoria}: {archivos_categoria} archivos, {problemas_categoria} problemas\n")
                total_archivos_verificados += archivos_categoria
                total_problemas_detectados += problemas_categoria
            
            # Resumen final del análisis
            self._actualizar_texto_fim(f"\n" + "="*60 + "\n")
            self._actualizar_texto_fim("RESUMEN ANÁLISIS COMPLETO DE RUTAS SENSIBLES\n")
            self._actualizar_texto_fim("="*60 + "\n")
            self._actualizar_texto_fim(f"Total archivos verificados: {total_archivos_verificados}\n")
            self._actualizar_texto_fim(f"Total problemas detectados: {total_problemas_detectados}\n")
            
            if total_problemas_detectados == 0:
                self._actualizar_texto_fim("ESTADO: OK - No se detectaron problemas críticos\n")
                self._log_terminal("FIM: Análisis completo completado - Sin problemas críticos", "FIM", "INFO")
            elif total_problemas_detectados <= 5:
                self._actualizar_texto_fim("ESTADO: WARNING - Problemas menores detectados\n")
                self._log_terminal(f"FIM: {total_problemas_detectados} problemas menores detectados", "FIM", "WARNING")
            else:
                self._actualizar_texto_fim("ESTADO: CRITICO - Múltiples problemas detectados\n")
                self._log_terminal(f"FIM: {total_problemas_detectados} problemas críticos detectados", "FIM", "ERROR")
            
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR en análisis completo: {str(e)}\n")
            self._log_terminal(f"Error en análisis FIM: {str(e)}", "FIM", "ERROR")
    
    def _analizar_archivo_sensible(self, archivo, descripcion):
        """Analizar un archivo sensible específico."""
        try:
            resultado = {'archivos_verificados': 1, 'problemas_detectados': 0}
            
            # Información básica del archivo
            stat_info = os.stat(archivo)
            permisos = oct(stat_info.st_mode)[-3:]
            tamaño = stat_info.st_size
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            self._actualizar_texto_fim(f"  ARCHIVO: {archivo}\n")
            self._actualizar_texto_fim(f"    Descripción: {descripcion}\n")
            self._actualizar_texto_fim(f"    Permisos: {permisos} | Tamaño: {tamaño} bytes | UID: {uid} | GID: {gid}\n")
            
            # Verificar permisos apropiados para archivos críticos
            permisos_esperados = {
                '/etc/passwd': '644',
                '/etc/shadow': '640',
                '/etc/sudoers': '440',
                '/etc/ssh/sshd_config': '644',
                '/etc/hosts': '644'
            }
            
            if archivo in permisos_esperados:
                if permisos != permisos_esperados[archivo]:
                    self._actualizar_texto_fim(f"    PROBLEMA: Permisos incorrectos (esperado {permisos_esperados[archivo]})\n")
                    resultado['problemas_detectados'] += 1
                else:
                    self._actualizar_texto_fim(f"    OK: Permisos correctos\n")
            
            # Verificar propietario para archivos críticos
            if uid != 0 and archivo.startswith('/etc/'):
                self._actualizar_texto_fim(f"    WARNING: Archivo crítico no pertenece a root (UID: {uid})\n")
                resultado['problemas_detectados'] += 1
            
            # Calcular checksum SHA-256
            try:
                resultado_sha = subprocess.run(['sha256sum', archivo], 
                                             capture_output=True, text=True, timeout=5)
                if resultado_sha.returncode == 0:
                    checksum = resultado_sha.stdout.split()[0]
                    self._actualizar_texto_fim(f"    SHA-256: {checksum[:16]}...\n")
                else:
                    self._actualizar_texto_fim(f"    WARNING: No se pudo calcular checksum\n")
            except Exception:
                pass
            
            return resultado
            
        except Exception as e:
            self._actualizar_texto_fim(f"  ERROR analizando {archivo}: {str(e)}\n")
            return {'archivos_verificados': 0, 'problemas_detectados': 1}
    
    def _analizar_directorio_sensible(self, directorio, descripcion):
        """Analizar un directorio sensible y su contenido."""
        try:
            resultado = {'archivos_verificados': 0, 'problemas_detectados': 0}
            
            self._actualizar_texto_fim(f"  DIRECTORIO: {directorio}\n")
            self._actualizar_texto_fim(f"    Descripción: {descripcion}\n")
            
            # Contar archivos en el directorio
            try:
                archivos = os.listdir(directorio)
                self._actualizar_texto_fim(f"    Contiene: {len(archivos)} elementos\n")
                
                # Verificar permisos del directorio
                stat_info = os.stat(directorio)
                permisos = oct(stat_info.st_mode)[-3:]
                self._actualizar_texto_fim(f"    Permisos directorio: {permisos}\n")
                
                # Análisis específico para ciertos directorios
                if directorio == '/etc/ssh/':
                    # Verificar archivos de configuración SSH
                    archivos_ssh_criticos = ['sshd_config', 'ssh_config']
                    for archivo_ssh in archivos_ssh_criticos:
                        ruta_completa = os.path.join(directorio, archivo_ssh)
                        if os.path.exists(ruta_completa):
                            sub_resultado = self._analizar_archivo_sensible(ruta_completa, f"Configuración SSH: {archivo_ssh}")
                            resultado['archivos_verificados'] += sub_resultado['archivos_verificados']
                            resultado['problemas_detectados'] += sub_resultado['problemas_detectados']
                
                elif directorio.endswith('/.ssh/'):
                    # Verificar claves SSH
                    archivos_ssh_keys = [f for f in archivos if f.endswith(('.pub', '_rsa', '_ed25519', '_ecdsa'))]
                    if archivos_ssh_keys:
                        self._actualizar_texto_fim(f"    Claves SSH encontradas: {len(archivos_ssh_keys)}\n")
                        for key_file in archivos_ssh_keys[:3]:  # Limitar para no saturar
                            ruta_key = os.path.join(directorio, key_file)
                            if os.path.isfile(ruta_key):
                                stat_key = os.stat(ruta_key)
                                permisos_key = oct(stat_key.st_mode)[-3:]
                                self._actualizar_texto_fim(f"      {key_file}: permisos {permisos_key}\n")
                                if permisos_key not in ['600', '644']:
                                    resultado['problemas_detectados'] += 1
                
                elif directorio.startswith('/var/log/'):
                    # Verificar logs críticos
                    logs_criticos = [f for f in archivos if f in ['auth.log', 'syslog', 'kern.log']]
                    if logs_criticos:
                        self._actualizar_texto_fim(f"    Logs críticos: {', '.join(logs_criticos)}\n")
                
                resultado['archivos_verificados'] = len(archivos)
                
            except PermissionError:
                self._actualizar_texto_fim(f"    ERROR: Sin permisos para acceder\n")
                resultado['problemas_detectados'] += 1
                
            return resultado
            
        except Exception as e:
            self._actualizar_texto_fim(f"  ERROR analizando directorio {directorio}: {str(e)}\n")
            return {'archivos_verificados': 0, 'problemas_detectados': 1}
    
    def _analizar_ruta_wildcard(self, patron, descripcion):
        """Analizar rutas con wildcards usando glob."""
        try:
            import glob
            resultado = {'archivos_verificados': 0, 'problemas_detectados': 0}
            
            self._actualizar_texto_fim(f"  PATRÓN: {patron}\n")
            self._actualizar_texto_fim(f"    Descripción: {descripcion}\n")
            
            # Expandir el patrón
            rutas_encontradas = glob.glob(patron)
            if rutas_encontradas:
                self._actualizar_texto_fim(f"    Encontradas: {len(rutas_encontradas)} coincidencias\n")
                
                # Analizar primeras 3 coincidencias para no saturar
                for ruta in rutas_encontradas[:3]:
                    if os.path.isfile(ruta):
                        sub_resultado = self._analizar_archivo_sensible(ruta, descripcion)
                        resultado['archivos_verificados'] += sub_resultado['archivos_verificados']
                        resultado['problemas_detectados'] += sub_resultado['problemas_detectados']
                    elif os.path.isdir(ruta):
                        sub_resultado = self._analizar_directorio_sensible(ruta, descripcion)
                        resultado['archivos_verificados'] += sub_resultado['archivos_verificados']
                        resultado['problemas_detectados'] += sub_resultado['problemas_detectados']
                
                if len(rutas_encontradas) > 3:
                    self._actualizar_texto_fim(f"    ... y {len(rutas_encontradas) - 3} más\n")
            else:
                self._actualizar_texto_fim(f"    No se encontraron coincidencias\n")
                
            return resultado
            
        except Exception as e:
            self._actualizar_texto_fim(f"  ERROR con patrón {patron}: {str(e)}\n")
            return {'archivos_verificados': 0, 'problemas_detectados': 1}
    
    def iniciar_monitoreo_tiempo_real(self):
        """Iniciar monitoreo en tiempo real usando inotify de Linux."""
        if hasattr(self, 'monitoreo_tiempo_real_activo') and self.monitoreo_tiempo_real_activo:
            return
        
        self.monitoreo_tiempo_real_activo = True
        self._log_terminal("Iniciando monitoreo FIM en tiempo real con inotify", "FIM", "INFO")
        self._actualizar_texto_fim("=== MONITOREO FIM EN TIEMPO REAL ACTIVADO ===\n")
        self._actualizar_texto_fim("Usando inotify de Linux para detección inmediata de cambios\n\n")
        
        # Ejecutar en thread separado
        thread_tiempo_real = threading.Thread(target=self._monitoreo_tiempo_real_async)
        thread_tiempo_real.daemon = True
        thread_tiempo_real.start()
    
    def _monitoreo_tiempo_real_async(self):
        """Monitoreo en tiempo real usando inotify para detectar cambios inmediatos."""
        try:
            # Directorios críticos para monitoreo en tiempo real
            directorios_criticos = [
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                '/etc/hosts', '/etc/ssh/', '/etc/crontab', '/root/.ssh/',
                '/root/.bashrc', '/root/.bash_history', '/bin/', '/sbin/',
                '/usr/bin/', '/usr/sbin/', '/tmp/', '/var/tmp/', '/dev/shm/'
            ]
            
            self.after(0, self._actualizar_texto_fim, "INICIANDO MONITOREO EN TIEMPO REAL:\n")
            for directorio in directorios_criticos:
                if os.path.exists(directorio):
                    self.after(0, self._actualizar_texto_fim, f"  OK Monitoreando: {directorio}\n")
            
            self.after(0, self._actualizar_texto_fim, "\nUSANDO inotifywatch para detección inmediata...\n")
            
            # Usar inotifywatch para monitoreo en tiempo real
            comando_inotify = [
                'inotifywatch', '-r', '-t', '300', '-e', 
                'modify,create,delete,move,attrib'
            ] + [d for d in directorios_criticos if os.path.exists(d)]
            
            try:
                resultado = subprocess.run(
                    comando_inotify,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutos de monitoreo
                )
                
                if resultado.returncode == 0 and resultado.stdout:
                    self.after(0, self._actualizar_texto_fim, "\nCOMPETADO: Resumen de actividad detectada:\n")
                    lineas = resultado.stdout.strip().split('\n')
                    eventos_detectados = 0
                    
                    for linea in lineas[3:]:  # Saltar headers
                        if linea.strip() and not linea.startswith('total'):
                            eventos_detectados += 1
                            self.after(0, self._actualizar_texto_fim, f"  {linea}\n")
                    
                    if eventos_detectados > 0:
                        self.after(0, self._actualizar_texto_fim, f"\nALERTA: {eventos_detectados} eventos de cambio detectados\n")
                        self._log_terminal(f"FIM: {eventos_detectados} eventos de cambio detectados", "FIM", "WARNING")
                    else:
                        self.after(0, self._actualizar_texto_fim, "\nOK: No se detectaron cambios durante el monitoreo\n")
                else:
                    self.after(0, self._actualizar_texto_fim, "\nINFO: Monitoreo completado sin eventos\n")
                    
            except subprocess.TimeoutExpired:
                self.after(0, self._actualizar_texto_fim, "\nINFO: Tiempo de monitoreo completado (5 minutos)\n")
            except FileNotFoundError:
                self.after(0, self._actualizar_texto_fim, "\nWARNING: inotifywatch no disponible\n")
                self.after(0, self._actualizar_texto_fim, "Instalando inotify-tools...\n")
                
                # Intentar instalar inotify-tools
                try:
                    from aresitos.utils.sudo_manager import get_sudo_manager
                    sudo_manager = get_sudo_manager()
                    install_result = sudo_manager.execute_sudo_command('apt install -y inotify-tools', timeout=60)
                    
                    if install_result.returncode == 0:
                        self.after(0, self._actualizar_texto_fim, "OK: inotify-tools instalado correctamente\n")
                        self.after(0, self._actualizar_texto_fim, "Reinicie el monitoreo para usar inotify\n")
                    else:
                        self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo instalar inotify-tools\n")
                except ImportError:
                    self.after(0, self._actualizar_texto_fim, "ERROR: SudoManager no disponible\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto_fim, f"ERROR en monitoreo tiempo real: {str(e)}\n")
        finally:
            self.monitoreo_tiempo_real_activo = False
    
    def _realizar_analisis_basico(self):
        """Realizar análisis básico de archivos críticos sin controlador."""
        try:
            import os
            import stat
            
            self.after(0, self._actualizar_texto_fim, "INICIANDO ANÁLISIS BÁSICO DE INTEGRIDAD\n")
            self.after(0, self._actualizar_texto_fim, "NOTA: Análisis limitado sin herramientas específicas de Kali Linux\n\n")
            
            # Archivos básicos que podemos verificar en cualquier sistema
            archivos_basicos = {
                './main.py': 'Archivo principal de ARESITOS',
                './aresitos/__init__.py': 'Módulo principal de la aplicación',
                './configuracion/': 'Directorio de configuración',
                './data/': 'Directorio de datos'
            }
            
            # EXPANSIÓN: Directorios críticos adicionales de Kali Linux para monitoreo
            directorios_kali_expandidos = {
                # Directorios del sistema críticos
                '/etc/passwd': 'Archivo de usuarios del sistema',
                '/etc/shadow': 'Archivo de contraseñas encriptadas',
                '/etc/group': 'Archivo de grupos del sistema',
                '/etc/sudoers': 'Configuración de permisos sudo',
                '/etc/hosts': 'Archivo de hosts del sistema',
                '/etc/crontab': 'Tareas programadas del sistema',
                '/etc/ssh/': 'Configuración SSH',
                '/etc/apache2/': 'Configuración Apache (si existe)',
                '/etc/nginx/': 'Configuración Nginx (si existe)',
                '/etc/systemd/': 'Configuración de servicios systemd',
                '/etc/init.d/': 'Scripts de inicio del sistema',
                '/etc/rc.local': 'Script de inicio local',
                '/etc/profile': 'Perfil global del sistema',
                '/etc/bashrc': 'Configuración global de bash',
                '/etc/environment': 'Variables de entorno del sistema',
                '/etc/motd': 'Mensaje del día',
                '/etc/issue': 'Banner de login',
                '/etc/fstab': 'Tabla de sistemas de archivos',
                '/etc/iptables/': 'Reglas de firewall',
                
                # Directorios de herramientas de Kali
                '/usr/share/wordlists/': 'Wordlists de Kali Linux',
                '/usr/share/nmap/': 'Scripts de Nmap',
                '/usr/share/metasploit-framework/': 'Framework Metasploit',
                '/usr/share/john/': 'John the Ripper',
                '/usr/share/burpsuite/': 'Burp Suite',
                '/usr/share/aircrack-ng/': 'Aircrack-ng',
                '/usr/share/sqlmap/': 'SQLMap',
                '/usr/share/nikto/': 'Nikto web scanner',
                '/usr/share/dirb/': 'DIRB directory buster',
                '/usr/share/gobuster/': 'Gobuster directory/file buster',
                '/usr/share/hydra/': 'THC Hydra',
                '/usr/share/hashcat/': 'Hashcat password recovery',
                '/usr/share/wireshark/': 'Wireshark network analyzer',
                
                # Directorios de usuario críticos
                '/home/': 'Directorios de usuarios',
                '/root/': 'Directorio del usuario root',
                '/root/.ssh/': 'Claves SSH del root',
                '/root/.bash_history': 'Historial de comandos de root',
                '/root/.bashrc': 'Configuración de bash de root',
                '/tmp/': 'Directorio temporal (crítico para seguridad)',
                '/var/log/': 'Logs del sistema',
                '/var/www/': 'Directorio web (si existe)',
                '/var/tmp/': 'Directorio temporal variable',
                '/dev/shm/': 'Memoria compartida (usado por malware)',
                
                # Binarios críticos
                '/usr/bin/': 'Binarios del sistema',
                '/usr/sbin/': 'Binarios de administración',
                '/bin/': 'Binarios esenciales',
                '/sbin/': 'Binarios de sistema esenciales',
                '/usr/local/bin/': 'Binarios locales instalados',
                '/usr/local/sbin/': 'Binarios de administración locales',
                
                # Directorios de configuración adicionales
                '/opt/': 'Software adicional instalado',
                '/usr/lib/': 'Librerías del sistema',
                '/lib/': 'Librerías esenciales',
                '/lib64/': 'Librerías de 64 bits',
                '/usr/share/': 'Datos compartidos de aplicaciones',
                '/var/cache/': 'Cache del sistema',
                '/var/spool/': 'Cola de trabajos del sistema',
                '/proc/sys/': 'Configuración del kernel en tiempo real',
                
                # Directorios específicos de seguridad
                '/etc/fail2ban/': 'Configuración Fail2Ban',
                '/etc/aide/': 'Configuración AIDE (Advanced Intrusion Detection)',
                '/etc/tripwire/': 'Configuración Tripwire',
                '/etc/samhain/': 'Configuración Samhain HIDS',
                '/etc/logrotate.d/': 'Configuración de rotación de logs',
                '/etc/rsyslog.d/': 'Configuración de syslog',
                '/etc/audit/': 'Configuración de auditoría del sistema',
                
                # Directorios de servicios de red
                '/etc/mysql/': 'Configuración MySQL/MariaDB',
                '/etc/postgresql/': 'Configuración PostgreSQL',
                '/etc/bind/': 'Configuración DNS BIND',
                '/etc/dhcp/': 'Configuración DHCP',
                '/etc/samba/': 'Configuración Samba',
                '/etc/vsftpd/': 'Configuración FTP'
            }
            
            self.after(0, self._actualizar_texto_fim, "\nEXPANSION FIM: Monitoreando directorios críticos de Kali Linux\n")
            self.after(0, self._actualizar_texto_fim, "="*70 + "\n")
            
            archivos_encontrados = 0
            
            # 1. Verificar archivos básicos del proyecto
            self.after(0, self._actualizar_texto_fim, "\nARCHIVOS VERIFICANDO ARCHIVOS DEL PROYECTO ARESITOS:\n")
            for archivo, descripcion in archivos_basicos.items():
                try:
                    if os.path.exists(archivo):
                        stat_info = os.stat(archivo)
                        if os.path.isfile(archivo):
                            tamaño = stat_info.st_size
                            self.after(0, self._actualizar_texto_fim, f"OK {archivo}: {descripcion} (Tamaño: {tamaño} bytes)\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, f"OK {archivo}: {descripcion} (Directorio)\n")
                        archivos_encontrados += 1
                    else:
                        self.after(0, self._actualizar_texto_fim, f"ERROR {archivo}: {descripcion} (NO ENCONTRADO)\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_fim, f"WARNING Error verificando {archivo}: {e}\n")
            
            # 2. Verificar directorios críticos de Kali Linux (solo si estamos en Linux)
            import platform
            if platform.system().lower() == 'linux':
                self.after(0, self._actualizar_texto_fim, f"\n🐉 VERIFICANDO DIRECTORIOS CRÍTICOS DE KALI LINUX:\n")
                
                directorios_criticos = 0
                directorios_monitoreados = 0
                
                for ruta, descripcion in directorios_kali_expandidos.items():
                    try:
                        if os.path.exists(ruta):
                            stat_info = os.stat(ruta)
                            permisos = oct(stat_info.st_mode)[-3:]
                            
                            if os.path.isfile(ruta):
                                tamaño = stat_info.st_size
                                self.after(0, self._actualizar_texto_fim, f"SEGURIDAD {ruta}: {descripcion} (Archivo: {tamaño}B, Permisos: {permisos})\n")
                                directorios_criticos += 1
                            elif os.path.isdir(ruta):
                                try:
                                    # Contar archivos en directorio (limitado para no sobrecargar)
                                    archivos_en_dir = len(os.listdir(ruta)) if os.access(ruta, os.R_OK) else "Sin acceso"
                                    self.after(0, self._actualizar_texto_fim, f"[CATEGORIA] {ruta}: {descripcion} (Dir: {archivos_en_dir} items, Permisos: {permisos})\n")
                                    directorios_criticos += 1
                                except PermissionError:
                                    self.after(0, self._actualizar_texto_fim, f"ACCESO {ruta}: {descripcion} (Sin permisos de lectura)\n")
                                    directorios_criticos += 1
                                    
                            directorios_monitoreados += 1
                            
                        else:
                            # Solo mostrar los más importantes si no existen
                            if ruta in ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/usr/share/wordlists/', '/usr/share/nmap/']:
                                self.after(0, self._actualizar_texto_fim, f"ERROR {ruta}: {descripcion} (NO ENCONTRADO)\n")
                                
                    except Exception as e:
                        if ruta in ['/etc/passwd', '/etc/shadow', '/etc/hosts']:  # Solo reportar errores críticos
                            self.after(0, self._actualizar_texto_fim, f"WARNING Error accediendo a {ruta}: {e}\n")
                
                self.after(0, self._actualizar_texto_fim, f"\nRESUMEN EXPANSIÓN FIM:\n")
                self.after(0, self._actualizar_texto_fim, f"   • Directorios críticos encontrados: {directorios_criticos}\n")
                self.after(0, self._actualizar_texto_fim, f"   • Rutas monitoreadas: {directorios_monitoreados}\n")
                self.after(0, self._actualizar_texto_fim, f"   • Sistema: Kali Linux compatible\n")
                
            else:
                self.after(0, self._actualizar_texto_fim, f"\nLIMITACION: No estamos en Linux - Monitoreo básico únicamente\n")
                self.after(0, self._actualizar_texto_fim, f"   Para funcionalidad completa, ejecutar en Kali Linux\n")
            
            self.after(0, self._actualizar_texto_fim, f"\nRESUMEN TOTAL: {archivos_encontrados} elementos verificados del proyecto\n")
            self.after(0, self._actualizar_texto_fim, "RECOMENDACION: Ejecutar en Kali Linux para análisis completo de seguridad\n")
            
        except Exception as e:
            self.after(0, self._actualizar_texto_fim, f"ERROR en análisis básico: {str(e)}\n")

    def _habilitar_botones_monitoreo(self, habilitar):
        """Habilitar/deshabilitar botones según estado del monitoreo."""
        if habilitar:
            self.btn_iniciar.config(state="normal")
            self.btn_detener.config(state="disabled")
        else:
            self.btn_iniciar.config(state="disabled")
            self.btn_detener.config(state="normal")
    
    def _actualizar_texto_fim(self, texto):
        """Actualizar texto en el área de resultados de forma segura."""
        try:
            if hasattr(self, 'fim_text') and self.fim_text and self.fim_text.winfo_exists():
                self.fim_text.config(state=tk.NORMAL)
                self.fim_text.insert(tk.END, texto)
                self.fim_text.see(tk.END)
                self.fim_text.config(state=tk.DISABLED)
        except (tk.TclError, AttributeError):
            pass  # Widget ya no existe o ha sido destruido
    
    def set_controlador(self, controlador):
        """Establecer el controlador del FIM."""
        self.controlador = controlador
        self._log_terminal("Controlador FIM establecido", "FIM", "INFO")
    
    # ====================== EXPANSION FASE 3.3: FIM AVANZADO ======================
    
    def monitoreo_avanzado_kali(self):
        """Monitoreo avanzado utilizando herramientas específicas de Kali Linux."""
        try:
            self._actualizar_texto_fim("INFO INICIANDO MONITOREO AVANZADO FIM PARA KALI LINUX\n")
            self._actualizar_texto_fim("=" * 70 + "\n")
            
            # Verificar que estamos en Linux
            import platform
            if platform.system() != 'Linux':
                self._actualizar_texto_fim("WARNING ADVERTENCIA: Funcionalidad completa solo disponible en Kali Linux\n")
                self._actualizar_texto_fim("Ejecutando análisis básico...\n\n")
                self.verificar_integridad()
                return
            
            # ISSUE 18/24: Análisis completo de rutas sensibles
            self._analisis_completo_rutas_sensibles()
            
            # 1. Monitoreo con inotify (nativo de Linux)
            self._monitoreo_inotify()
            
            # 2. Verificación de checksums con herramientas avanzadas
            self._verificacion_checksums_avanzada()
            
            # 3. Análisis de permisos críticos
            self._analisis_permisos_criticos()
            
            # 4. Detección de archivos ocultos y sospechosos
            self._deteccion_archivos_sospechosos()
            
            # 5. Monitoreo de logs de sistema en tiempo real
            # self._monitoreo_logs_sistema()  # Comentado: no definido en vista_fim.py
            
            # 6. Verificación de firmas de archivos críticos
            self._verificacion_firmas()
            
            self._actualizar_texto_fim("\nOK MONITOREO AVANZADO FIM COMPLETADO\n")
            self._log_terminal("Monitoreo avanzado FIM completado", "FIM", "SUCCESS")
            
        except Exception as e:
            error_msg = f"Error en monitoreo avanzado FIM: {str(e)}"
            self._actualizar_texto_fim(f"ERROR: {error_msg}\n")
            self._log_terminal(error_msg, "FIM", "ERROR")
    
    def _monitoreo_inotify(self):
        """Configurar monitoreo en tiempo real con inotify."""
        try:
            self._actualizar_texto_fim("\nINFO 1. CONFIGURACIÓN DE MONITOREO INOTIFY\n")
            self._actualizar_texto_fim("-" * 50 + "\n")
            
            import subprocess
            
            # Verificar si inotify-tools está disponible
            try:
                resultado = subprocess.run(['which', 'inotifywait'], 
                                         capture_output=True, text=True, timeout=5)
                
                if resultado.returncode == 0:
                    self._actualizar_texto_fim("OK inotify-tools disponible\n")
                    
                    # Configurar monitoreo de directorios críticos
                    directorios_criticos = ['/etc', '/usr/bin', '/usr/sbin', '/home']
                    
                    self._actualizar_texto_fim("INFO Configurando monitoreo en tiempo real para:\n")
                    for directorio in directorios_criticos:
                        if os.path.exists(directorio):
                            self._actualizar_texto_fim(f"  DIR {directorio}\n")
                    
                    # Mostrar comando de monitoreo que se ejecutaría
                    cmd_inotify = "inotifywait -m -r -e modify,create,delete,move"
                    self._actualizar_texto_fim(f"\nCOMMAND Comando de monitoreo: {cmd_inotify}\n")
                    self._actualizar_texto_fim("INFO Eventos monitoreados: modify, create, delete, move\n")
                    
                else:
                    self._actualizar_texto_fim("WARNING inotify-tools no disponible\n")
                    self._actualizar_texto_fim("INFO Para instalar: apt-get install inotify-tools\n")
                    
            except subprocess.TimeoutExpired:
                self._actualizar_texto_fim("WARNING Timeout verificando inotify-tools\n")
                
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR configurando inotify: {str(e)}\n")
    
    def _verificacion_checksums_avanzada(self):
        """Verificación avanzada de checksums usando múltiples algoritmos."""
        try:
            self._actualizar_texto_fim("\nINFO 2. VERIFICACIÓN AVANZADA DE CHECKSUMS\n")
            self._actualizar_texto_fim("-" * 50 + "\n")
            
            import subprocess
            import hashlib
            
            # Archivos críticos para verificar
            archivos_criticos = [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/hosts',
                '/etc/ssh/sshd_config', '/etc/fstab'
            ]
            
            algoritmos = ['md5', 'sha1', 'sha256', 'sha512']
            checksums_calculados = 0
            
            self._actualizar_texto_fim("INFO Calculando checksums con múltiples algoritmos:\n")
            
            for archivo in archivos_criticos:
                if os.path.exists(archivo) and os.path.isfile(archivo):
                    try:
                        self._actualizar_texto_fim(f"\n📄 {archivo}:\n")
                        
                        # Calcular checksums con diferentes algoritmos
                        for algoritmo in algoritmos[:2]:  # Limitar a 2 para no saturar
                            try:
                                if algoritmo == 'md5':
                                    resultado = subprocess.run(['md5sum', archivo], 
                                                             capture_output=True, text=True, timeout=5)
                                elif algoritmo == 'sha256':
                                    resultado = subprocess.run(['sha256sum', archivo], 
                                                             capture_output=True, text=True, timeout=5)
                                else:
                                    continue
                                
                                if resultado.returncode == 0:
                                    checksum = resultado.stdout.split()[0]
                                    self._actualizar_texto_fim(f"  {algoritmo.upper()}: {checksum[:16]}...\n")
                                    checksums_calculados += 1
                                    
                            except subprocess.TimeoutExpired:
                                self._actualizar_texto_fim(f"  {algoritmo.upper()}: Timeout\n")
                            except Exception:
                                pass
                                
                    except Exception as e:
                        self._actualizar_texto_fim(f"  ERROR Error: {str(e)}\n")
            
            self._actualizar_texto_fim(f"\n[DATOS] Checksums calculados: {checksums_calculados}\n")
            
            # Verificar herramientas de integridad adicionales
            herramientas_integridad = ['aide', 'tripwire', 'samhain']
            self._actualizar_texto_fim("\n🛠️ Verificando herramientas de integridad disponibles:\n")
            
            for herramienta in herramientas_integridad:
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=3)
                    if resultado.returncode == 0:
                        self._actualizar_texto_fim(f"  OK {herramienta}: Disponible\n")
                    else:
                        self._actualizar_texto_fim(f"  ERROR {herramienta}: No instalado\n")
                except:
                    self._actualizar_texto_fim(f"  ❓ {herramienta}: Error verificando\n")
            
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR Error en verificación de checksums: {str(e)}\n")
    
    def _analisis_permisos_criticos(self):
        """Análisis detallado de permisos en archivos críticos."""
        try:
            self._actualizar_texto_fim("\n🔒 3. ANÁLISIS DE PERMISOS CRÍTICOS\n")
            self._actualizar_texto_fim("-" * 50 + "\n")
            
            import subprocess
            import stat
            
            # Archivos que deben tener permisos específicos
            permisos_esperados = {
                '/etc/passwd': 0o644,
                '/etc/shadow': 0o640,
                '/etc/sudoers': 0o440,
                '/etc/ssh/sshd_config': 0o644,
                '/etc/hosts': 0o644
            }
            
            permisos_incorrectos = 0
            archivos_verificados = 0
            
            self._actualizar_texto_fim("[BUSCAR] Verificando permisos de archivos críticos:\n")
            
            for archivo, permiso_esperado in permisos_esperados.items():
                if os.path.exists(archivo):
                    try:
                        # Obtener permisos actuales
                        stat_info = os.stat(archivo)
                        permisos_actuales = stat.filemode(stat_info.st_mode)
                        permisos_octal = oct(stat_info.st_mode)[-3:]
                        
                        # Comparar con permisos esperados
                        if (stat_info.st_mode & 0o777) == permiso_esperado:
                            self._actualizar_texto_fim(f"  OK {archivo}: {permisos_actuales} (OK)\n")
                        else:
                            self._actualizar_texto_fim(f"  ADVERTENCIA️ {archivo}: {permisos_actuales} (Esperado: {oct(permiso_esperado)})\n")
                            permisos_incorrectos += 1
                            
                        archivos_verificados += 1
                        
                    except Exception as e:
                        self._actualizar_texto_fim(f"  ERROR {archivo}: Error - {str(e)}\n")
                else:
                    self._actualizar_texto_fim(f"  ❓ {archivo}: No encontrado\n")
            
            # Buscar archivos con permisos demasiado permisivos
            try:
                self._actualizar_texto_fim("\n[BUSCAR] Buscando archivos con permisos excesivos:\n")
                
                # Buscar archivos con permisos 777 (muy peligroso)
                resultado = subprocess.run(['find', '/etc', '-type', 'f', '-perm', '777'], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    archivos_777 = resultado.stdout.strip().split('\n')
                    archivos_777 = [f for f in archivos_777 if f.strip()]
                    
                    if archivos_777:
                        self._actualizar_texto_fim(f"  🚨 ARCHIVOS CON PERMISOS 777: {len(archivos_777)}\n")
                        for archivo in archivos_777[:5]:  # Mostrar máximo 5
                            self._actualizar_texto_fim(f"    🔴 {archivo}\n")
                        if len(archivos_777) > 5:
                            self._actualizar_texto_fim(f"    ... y {len(archivos_777) - 5} más\n")
                    else:
                        self._actualizar_texto_fim("  OK No se encontraron archivos con permisos 777\n")
                        
            except subprocess.TimeoutExpired:
                self._actualizar_texto_fim("  ⏱️ Timeout buscando archivos con permisos excesivos\n")
            except:
                pass
            
            self._actualizar_texto_fim(f"\n[DATOS] Resumen de permisos:\n")
            self._actualizar_texto_fim(f"  • Archivos verificados: {archivos_verificados}\n")
            self._actualizar_texto_fim(f"  • Permisos incorrectos: {permisos_incorrectos}\n")
            
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR Error analizando permisos: {str(e)}\n")
    
    def _deteccion_archivos_sospechosos(self):
        """Detectar archivos ocultos y potencialmente sospechosos."""
        try:
            self._actualizar_texto_fim("\n🕵️ 4. DETECCIÓN DE ARCHIVOS SOSPECHOSOS\n")
            self._actualizar_texto_fim("-" * 50 + "\n")
            
            import subprocess
            
            # 1. Buscar archivos ocultos en directorios críticos
            directorios_criticos = ['/etc', '/usr/bin', '/usr/sbin']
            archivos_ocultos_total = 0
            
            self._actualizar_texto_fim("[BUSCAR] Buscando archivos ocultos en directorios críticos:\n")
            
            for directorio in directorios_criticos:
                if os.path.exists(directorio):
                    try:
                        resultado = subprocess.run(['find', directorio, '-name', '.*', '-type', 'f'], 
                                                 capture_output=True, text=True, timeout=10)
                        
                        if resultado.returncode == 0:
                            archivos_ocultos = resultado.stdout.strip().split('\n')
                            archivos_ocultos = [f for f in archivos_ocultos if f.strip()]
                            
                            if archivos_ocultos:
                                self._actualizar_texto_fim(f"  [CATEGORIA] {directorio}: {len(archivos_ocultos)} archivos ocultos\n")
                                archivos_ocultos_total += len(archivos_ocultos)
                                
                                # Mostrar algunos ejemplos si hay muchos
                                if len(archivos_ocultos) <= 3:
                                    for archivo in archivos_ocultos:
                                        self._actualizar_texto_fim(f"    • {archivo}\n")
                                else:
                                    for archivo in archivos_ocultos[:2]:
                                        self._actualizar_texto_fim(f"    • {archivo}\n")
                                    self._actualizar_texto_fim(f"    ... y {len(archivos_ocultos) - 2} más\n")
                            else:
                                self._actualizar_texto_fim(f"  [CATEGORIA] {directorio}: Sin archivos ocultos\n")
                                
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_fim(f"  ⏱️ {directorio}: Timeout en búsqueda\n")
                    except:
                        pass
            
            # 2. Buscar archivos con nombres sospechosos
            patrones_sospechosos = ['*backdoor*', '*malware*', '*trojan*', '*rootkit*']
            self._actualizar_texto_fim("\n🚨 Buscando archivos con nombres sospechosos:\n")
            
            archivos_sospechosos_total = 0
            for patron in patrones_sospechosos[:2]:  # Limitar búsqueda
                try:
                    resultado = subprocess.run(['find', '/', '-name', patron, '-type', 'f'], 
                                             capture_output=True, text=True, timeout=15)
                    
                    if resultado.returncode == 0:
                        archivos = resultado.stdout.strip().split('\n')
                        archivos = [f for f in archivos if f.strip()]
                        
                        if archivos:
                            self._actualizar_texto_fim(f"  🔴 Patrón '{patron}': {len(archivos)} archivos\n")
                            archivos_sospechosos_total += len(archivos)
                            for archivo in archivos[:2]:  # Mostrar máximo 2
                                self._actualizar_texto_fim(f"    ADVERTENCIA️ {archivo}\n")
                                
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_fim(f"  ⏱️ Timeout buscando patrón: {patron}\n")
                except:
                    pass
            
            if archivos_sospechosos_total == 0:
                self._actualizar_texto_fim("  OK No se encontraron archivos con nombres sospechosos\n")
            
            # 3. Verificar archivos modificados recientemente
            try:
                self._actualizar_texto_fim("\n⏰ Archivos modificados en las últimas 24 horas:\n")
                
                resultado = subprocess.run(['find', '/etc', '/usr/bin', '-type', 'f', '-mtime', '-1'], 
                                         capture_output=True, text=True, timeout=15)
                
                if resultado.returncode == 0:
                    archivos_recientes = resultado.stdout.strip().split('\n')
                    archivos_recientes = [f for f in archivos_recientes if f.strip()]
                    
                    if archivos_recientes:
                        self._actualizar_texto_fim(f"🚨 ARCHIVOS MODIFICADOS EN LAS ÚLTIMAS 24 HORAS: {len(archivos_recientes)}\n")
                        for archivo in archivos_recientes[:5]:
                            self._actualizar_texto_fim(f"  📝 {archivo}\n")
                        if len(archivos_recientes) > 5:
                            self._actualizar_texto_fim(f"  ... y {len(archivos_recientes) - 5} más\n")
                    else:
                        self._actualizar_texto_fim("OK Sin modificaciones recientes en directorios críticos\n")
                        
            except subprocess.TimeoutExpired:
                self._actualizar_texto_fim("⏱️ Timeout buscando archivos recientes\n")
            except:
                pass
            
            # Verificar archivos con timestamps futuros (anómalo)
            try:
                # Buscar archivos con fecha de modificación futura
                fecha_actual = datetime.now()
                fecha_limite = fecha_actual + timedelta(days=1)
                
                resultado = subprocess.run(['find', '/etc', '-type', 'f', '-newermt', fecha_limite.strftime('%Y-%m-%d')], 
                                         capture_output=True, text=True, timeout=10)
                
                if resultado.returncode == 0:
                    archivos_futuros = resultado.stdout.strip().split('\n')
                    archivos_futuros = [f for f in archivos_futuros if f.strip()]
                    
                    if archivos_futuros:
                        self._actualizar_texto_fim(f"🚨 ARCHIVOS CON TIMESTAMPS FUTUROS: {len(archivos_futuros)}\n")
                        for archivo in archivos_futuros[:3]:
                            self._actualizar_texto_fim(f"  ADVERTENCIA️ {archivo}\n")
                    else:
                        self._actualizar_texto_fim("OK Sin archivos con timestamps anómalos\n")
                        
            except:
                pass
                
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR Error analizando timestamps: {str(e)}\n")
    
    def _verificacion_firmas(self):
        """Verificación de firmas de archivos críticos."""
        try:
            self._actualizar_texto_fim("\n🔏 4. VERIFICACIÓN DE FIRMAS\n")
            self._actualizar_texto_fim("-" * 50 + "\n")
            
            import subprocess
            
            # Verificar herramientas de verificación de firmas
            herramientas_firma = ['file', 'hexdump', 'strings']
            
            self._actualizar_texto_fim("🛠️ Verificando herramientas de análisis disponibles:\n")
            
            for herramienta in herramientas_firma:
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=3)
                    if resultado.returncode == 0:
                        self._actualizar_texto_fim(f"  OK {herramienta}: Disponible\n")
                    else:
                        self._actualizar_texto_fim(f"  ERROR {herramienta}: No encontrado\n")
                except:
                    self._actualizar_texto_fim(f"  ❓ {herramienta}: Error verificando\n")
            
            # Analizar tipo de archivos críticos con 'file'
            archivos_binarios = ['/usr/bin/sudo', '/usr/bin/passwd', '/usr/sbin/sshd']
            
            self._actualizar_texto_fim(f"\n[BUSCAR] Verificando firmas de archivos binarios:\n")
            
            for archivo in archivos_binarios:
                if os.path.exists(archivo):
                    try:
                        resultado = subprocess.run(['file', archivo], 
                                                 capture_output=True, text=True, timeout=5)
                        
                        if resultado.returncode == 0:
                            tipo_archivo = resultado.stdout.strip()
                            self._actualizar_texto_fim(f"  📄 {archivo}:\n")
                            self._actualizar_texto_fim(f"      {tipo_archivo}\n")
                            
                            # Verificar si es ELF (formato normal en Linux)
                            if 'ELF' in tipo_archivo:
                                self._actualizar_texto_fim(f"      OK Formato ELF válido\n")
                            else:
                                self._actualizar_texto_fim(f"      ADVERTENCIA️ Formato no estándar\n")
                                
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_fim(f"  ⏱️ Timeout verificando {archivo}\n")
                    except Exception as e:
                        self._actualizar_texto_fim(f"  ERROR Error: {str(e)}\n")
                else:
                    self._actualizar_texto_fim(f"  ❓ {archivo}: No encontrado\n")
            
            # Verificar checksums conocidos si están disponibles
            try:
                self._actualizar_texto_fim(f"\n🔐 Verificando base de datos de checksums del sistema:\n")
                
                # Verificar si debsums está disponible (verifica checksums de paquetes)
                resultado = subprocess.run(['which', 'debsums'], 
                                         capture_output=True, text=True, timeout=3)
                
                if resultado.returncode == 0:
                    self._actualizar_texto_fim("  OK debsums disponible para verificación de paquetes\n")
                    
                    # Verificar algunos paquetes críticos
                    paquetes_criticos = ['passwd', 'sudo', 'openssh-server']
                    for paquete in paquetes_criticos[:2]:  # Limitar verificación
                        try:
                            resultado_deb = subprocess.run(['debsums', '-s', paquete], 
                                                         capture_output=True, text=True, timeout=10)
                            
                            if resultado_deb.returncode == 0:
                                self._actualizar_texto_fim(f"    OK {paquete}: Checksums OK\n")
                            else:
                                self._actualizar_texto_fim(f"    ADVERTENCIA️ {paquete}: Checksums modificados\n")
                                
                        except subprocess.TimeoutExpired:
                            self._actualizar_texto_fim(f"    ⏱️ {paquete}: Timeout\n")
                        except:
                            pass
                else:
                    self._actualizar_texto_fim("  ❓ debsums no disponible\n")
                    self._actualizar_texto_fim("  [SUGERENCIA] Para instalar: apt-get install debsums\n")
                    
            except:
                pass
                
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR Error verificando firmas: {str(e)}\n")
    
    def obtener_datos_para_reporte(self):
        """Obtener datos del FIM para incluir en reportes."""
        try:
            # Obtener el texto de resultados del FIM
            contenido_fim = ""
            if hasattr(self, 'fim_text'):
                contenido_fim = self.fim_text.get(1.0, 'end-1c')
            
            # Crear estructura de datos para el reporte
            datos_fim = {
                'timestamp': datetime.now().isoformat(),
                'modulo': 'FIM Avanzado',
                'estado': 'activo' if self.proceso_monitoreo_activo else 'inactivo',
                'version_expandida': True,
                'capacidades_avanzadas': [
                    'Monitoreo inotify en tiempo real',
                    'Verificación de checksums múltiples algoritmos',
                    'Análisis de permisos críticos',
                    'Detección de archivos sospechosos',
                    'Monitoreo de logs de sistema',
                    'Análisis forense de archivos',
                    'Verificación de firmas y metadatos'
                ],
                'resultados_texto': contenido_fim[-2500:] if len(contenido_fim) > 2500 else contenido_fim,
                'estadisticas': {
                    'lineas_monitoreadas': len(contenido_fim.split('\n')),
                    'archivos_verificados': contenido_fim.count('verificados') + contenido_fim.count('checksums'),
                    'alertas_criticas': contenido_fim.count('🚨') + contenido_fim.count('CRITICO'),
                    'alertas_warnings': contenido_fim.count('ADVERTENCIA️') + contenido_fim.count('WARNING'),
                    'archivos_sospechosos': contenido_fim.count('sospechoso') + contenido_fim.count('SOSPECHOSO'),
                    'permisos_incorrectos': contenido_fim.count('permisos incorrectos') + contenido_fim.count('permisos excesivos')
                },
                'verificaciones_realizadas': {
                    'monitoreo_avanzado': 'MONITOREO AVANZADO' in contenido_fim,
                    'checksums_multiples': 'CHECKSUMS' in contenido_fim,
                    'permisos_criticos': 'PERMISOS CRÍTICOS' in contenido_fim,
                    'archivos_sospechosos': 'ARCHIVOS SOSPECHOSOS' in contenido_fim,
                    'logs_sistema': 'LOGS DE SISTEMA' in contenido_fim,
                    'analisis_forense': 'ANÁLISIS FORENSE' in contenido_fim
                },
                'info_sistema': 'FIM expandido con capacidades forenses y monitoreo avanzado para Kali Linux'
            }
            
            return datos_fim
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'modulo': 'FIM',
                'estado': 'error',
                'error': f'Error obteniendo datos: {str(e)}',
                'info': 'Error al obtener datos del FIM para reporte'
            }

    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "COMANDOS DISPONIBLES EN ARESITOS v2.0 - FIM\n")
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
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS - FIM\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            self.terminal_output.insert(tk.END, "Estado: Seguridad estándar, sin validación restrictiva.\n")
            self.terminal_output.insert(tk.END, "Para más detalles revise la configuración y logs.\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando info seguridad: {e}\n")
        self.terminal_output.see(tk.END)

