# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from aresitos.utils.thread_safe_gui import ThreadSafeFlag
import logging
import datetime

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaAuditoria(tk.Frame):
    """
    Vista especializada para auditorías de seguridad del sistema.
    
    Enfoque específico:
    - Auditorías generales del sistema (Lynis, nuclei, httpx)
    - Análisis de configuraciones de seguridad
    - Verificación de permisos y políticas
    - Detección de rootkits y malware
    
    Nota: Las funciones de SIEM, FIM y Escaneo están en sus respectivas pestañas especializadas.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        self.vista_principal = parent  # Referencia al padre para acceder al terminal

        # Estados únicos de auditoría (thread-safe)
        self.flag_auditoria = ThreadSafeFlag()
        self.flag_rootkits = ThreadSafeFlag()
        self.thread_auditoria = None

        # Configuración del tema Burp Suite
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            # Diccionario de colores consistente con otras vistas
            self.colors = {
                'bg_primary': burp_theme.get_color('bg_primary'),      # #2b2b2b
                'bg_secondary': burp_theme.get_color('bg_secondary'),  # #1e1e1e  
                'fg_primary': burp_theme.get_color('fg_primary'),      # #ffffff
                'fg_accent': burp_theme.get_color('fg_accent'),        # #ff6633
                'success': burp_theme.get_color('success'),            # #00ff88
                'warning': burp_theme.get_color('warning'),            # #ffcc00
                'danger': burp_theme.get_color('danger'),              # #ff4444
                'info': burp_theme.get_color('info')                   # #44aaff
            }
            self.configure(bg=self.colors['bg_primary'])
            # Configurar estilos TTK
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
        else:
            self.theme = None
            # Colores por defecto para compatibilidad
            self.colors = {
                'bg_primary': '#f0f0f0',
                'bg_secondary': '#ffffff',
                'fg_primary': '#000000',
                'fg_accent': '#0066cc',
                'success': '#008800',
                'warning': '#ff8800',
                'danger': '#cc0000',
                'info': '#0066cc'
            }

        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
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
        
        self.auditoria_text = scrolledtext.ScrolledText(left_frame, height=25, width=65,
                                                       bg=self.colors['bg_primary'],
                                                       fg=self.colors['fg_primary'],
                                                       insertbackground=self.colors['fg_accent'],
                                                       font=('Consolas', 10),
                                                       relief='flat', bd=1)
        self.auditoria_text.pack(fill=tk.BOTH, expand=True)
        
        # Panel derecho - Herramientas de Auditoría con tema Burp Suite
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        label_tools = tk.Label(right_frame, text="Herramientas de Auditoría", 
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                             font=('Arial', 12, 'bold'))
        label_tools.pack(anchor=tk.W, pady=(0, 10))
        
        # Crear secciones organizadas
        self._crear_seccion_auditoria_sistema(right_frame)
        self._crear_seccion_deteccion_malware(right_frame)
        self._crear_seccion_configuraciones(right_frame)
        self._crear_seccion_utilidades(right_frame)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado Auditoría con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - Auditoría",
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
                command=self.limpiar_terminal_auditoria,
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
                command=self.abrir_logs_auditoria,
                bg=self.colors.get('info', '#007acc'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)
            
            # Área de terminal (misma estética que dashboard, más pequeña)
            self.terminal_output = scrolledtext.ScrolledText(
                terminal_frame,
                height=6,  # Más pequeño que dashboard
                bg='#000000',  # Terminal negro estándar
                fg='#00ff00',  # Terminal verde estándar
                font=("Consolas", 8),  # Fuente menor que dashboard
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
            import datetime
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - Auditoría v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, f"Sistema: Kali Linux - Security Audit Tools\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Auditoría de seguridad\n\n")
            
            self.log_to_terminal("Terminal Auditoría iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Auditoría: {e}")
    
    def limpiar_terminal_auditoria(self):
        """Limpiar terminal Auditoría manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - Auditoría v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - Security Audit Tools\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal Auditoría reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Auditoría: {e}")
    
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
            self.terminal_output.insert(tk.END, f"\n> {comando}\n")
            
            if not es_valido:
                # Mostrar error de seguridad
                self.terminal_output.insert(tk.END, f"{mensaje}\n")
                self.terminal_output.insert(tk.END, "TIP Use 'ayuda-comandos' para ver comandos disponibles\n")
                self.terminal_output.see(tk.END)
                self.comando_entry.delete(0, tk.END)
                return
            
            # Mostrar mensaje de autorización
            self.terminal_output.insert(tk.END, f"{mensaje}\n")
            self.terminal_output.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            
            # Ejecutar comando sanitizado en thread
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando_sanitizado,))
            thread.daemon = True
            thread.start()
            
        except ImportError:
            # Fallback sin validación (modo inseguro)
            self.terminal_output.insert(tk.END, f"\n> {comando}\n")
            self.terminal_output.insert(tk.END, "[WARNING]  EJECUTANDO SIN VALIDACIÓN DE SEGURIDAD\n")
            self.terminal_output.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            self.terminal_output.insert(tk.END, f"\n> {comando}\n")
            self.terminal_output.insert(tk.END, f"[FAIL] Error de seguridad: {e}\n")
            self.terminal_output.see(tk.END)
            self.comando_entry.delete(0, tk.END)
    
    def _ejecutar_comando_async(self, comando):
        """Ejecutar comando de forma asíncrona con comandos especiales."""
        try:
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
            
            import platform
            import subprocess
            
            if platform.system() == "Windows":
                comando_completo = ["cmd", "/c", comando]
            else:
                comando_completo = ["/bin/bash", "-c", comando]
            
            resultado = subprocess.run(
                comando_completo,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if resultado.stdout:
                self.terminal_output.insert(tk.END, resultado.stdout)
            if resultado.stderr:
                self.terminal_output.insert(tk.END, f"ERROR: {resultado.stderr}")
            
            self.terminal_output.see(tk.END)
            
        except subprocess.TimeoutExpired:
            self.terminal_output.insert(tk.END, "ERROR: Comando timeout (30s)\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
        
        self.terminal_output.see(tk.END)
    
    def abrir_logs_auditoria(self):
        """Abrir carpeta de logs Auditoría."""
        try:
            import os
            import platform
            import subprocess
            logs_path = "logs/"
            if os.path.exists(logs_path):
                if platform.system() == "Linux":
                    subprocess.run(["xdg-open", logs_path], check=False)
                else:
                    subprocess.run(["explorer", logs_path], check=False)
                self.log_to_terminal("Carpeta de logs Auditoría abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs Auditoría: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal usando función estándar."""
        self._log_terminal(mensaje, "AUDITORIA", "INFO")
    
    def sincronizar_terminal(self):
        """Función de compatibilidad - ya no necesaria con terminal estándar."""
        pass
    
    def _crear_seccion_auditoria_sistema(self, parent):
        """Crear sección de auditorías generales del sistema."""
        # Sección de auditorías del sistema con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Auditorías del Sistema", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Ejecutar Lynis", self.ejecutar_lynis, self.colors['fg_accent']),
            ("Cancelar Lynis", self.cancelar_auditoria, self.colors['danger']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
            
            # Configuración especial para botón cancelar
            if "Cancelar" in text:
                btn.config(state="disabled")
                self.btn_cancelar_auditoria = btn
    
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
        if self.flag_auditoria.is_set():
            self._actualizar_texto_auditoria("ERROR Auditoría Lynis ya en ejecución\n")
            return
            
        def ejecutar_lynis_worker():
            try:
                self.flag_auditoria.set()
                self._actualizar_texto_auditoria("=== INICIANDO AUDITORÍA LYNIS PROFESIONAL ===\n")
                import subprocess
                import os
                import time
                
                # Importar SudoManager para operaciones privilegiadas
                try:
                    from aresitos.utils.sudo_manager import SudoManager
                    sudo_manager = SudoManager()
                    if sudo_manager.is_sudo_active():
                        self._actualizar_texto_auditoria("OK SudoManager activo para auditoría completa\n")
                    else:
                        self._actualizar_texto_auditoria("WARNING SudoManager no activo - algunas verificaciones pueden fallar\n")
                except ImportError:
                    sudo_manager = None
                    self._actualizar_texto_auditoria("WARNING SudoManager no disponible\n")
                
                try:
                    # Verificar si Lynis está instalado
                    resultado = subprocess.run(['which', 'lynis'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("OK Lynis encontrado en sistema\n")
                        
                        # Verificar y crear directorios de logs
                        log_dir = "/var/log/lynis"
                        self._actualizar_texto_auditoria(f"• Verificando directorio de logs: {log_dir}\n")
                        
                        # Ejecutar Lynis con configuración profesional
                        self._actualizar_texto_auditoria("• Ejecutando auditoría completa del sistema (puede tardar 5-10 minutos)...\n")
                        
                        # Comando Lynis mejorado con más verificaciones
                        cmd = [
                            'lynis', 
                            'audit', 
                            'system',
                            '--verbose',  # Salida detallada
                            '--quick',    # Omitir algunos tests lentos
                            '--warning',  # Mostrar advertencias
                            '--no-colors' # Sin colores para mejor parsing
                        ]
                        
                        # Usar SudoManager si está disponible para acceso completo
                        if sudo_manager and sudo_manager.is_sudo_active():
                            self._actualizar_texto_auditoria("• Ejecutando con privilegios elevados para verificaciones completas\n")
                            comando_str = ' '.join(cmd)
                            proceso_result = sudo_manager.execute_sudo_command(comando_str, timeout=600)  # 10 minutos
                            
                            if proceso_result.returncode == 0:
                                salida = proceso_result.stdout
                                errores = proceso_result.stderr
                            else:
                                salida = proceso_result.stdout
                                errores = proceso_result.stderr
                                self._actualizar_texto_auditoria(f"WARNING Lynis terminó con código: {proceso_result.returncode}\n")
                        else:
                            # Ejecutar sin sudo
                            self._actualizar_texto_auditoria("• Ejecutando sin privilegios elevados - algunas verificaciones limitadas\n")
                            proceso = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                            salida = proceso.stdout
                            errores = proceso.stderr
                        
                        # Procesar y mostrar resultados
                        self._actualizar_texto_auditoria("\n=== PROCESANDO RESULTADOS LYNIS ===\n")
                        
                        if salida:
                            # Filtrar líneas importantes
                            lineas_importantes = []
                            warnings_count = 0
                            suggestions_count = 0
                            
                            for linea in salida.split('\n'):
                                linea = linea.strip()
                                
                                # Filtrar información importante
                                if any(keyword in linea.lower() for keyword in [
                                    'warning', 'suggestion', 'found', 'missing', 'weak', 
                                    'vulnerable', 'security', 'hardening', 'firewall',
                                    'password', 'permission', 'root', 'sudo', 'ssh'
                                ]):
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
                            
                            # Mostrar resumen de hallazgos
                            self._actualizar_texto_auditoria(f"OK Auditoría completada - Procesando {len(lineas_importantes)} hallazgos\n")
                            self._actualizar_texto_auditoria(f"WARNING Advertencias encontradas: {warnings_count}\n")
                            self._actualizar_texto_auditoria(f"TIP Sugerencias de mejora: {suggestions_count}\n\n")
                            
                            # Mostrar hallazgos más importantes (primeros 30)
                            self._actualizar_texto_auditoria("=== HALLAZGOS PRINCIPALES ===\n")
                            for i, linea in enumerate(lineas_importantes[:30], 1):
                                self._actualizar_texto_auditoria(f"{i:2d}. {linea}\n")
                            
                            if len(lineas_importantes) > 30:
                                self._actualizar_texto_auditoria(f"... y {len(lineas_importantes) - 30} hallazgos adicionales\n")
                            
                            # Buscar archivo de reporte de Lynis
                            self._actualizar_texto_auditoria("\n=== ARCHIVOS DE REPORTE ===\n")
                            posibles_reportes = [
                                "/var/log/lynis.log",
                                "/var/log/lynis-report.dat",
                                "/tmp/lynis.log"
                            ]
                            
                            for reporte in posibles_reportes:
                                if os.path.exists(reporte):
                                    try:
                                        stat_info = os.stat(reporte)
                                        size_kb = stat_info.st_size / 1024
                                        self._actualizar_texto_auditoria(f"OK Reporte disponible: {reporte} ({size_kb:.1f} KB)\n")
                                    except:
                                        self._actualizar_texto_auditoria(f"OK Reporte disponible: {reporte}\n")
                        
                        # Recomendaciones específicas para Kali Linux
                        self._actualizar_texto_auditoria("\n=== RECOMENDACIONES KALI LINUX ===\n")
                        self._actualizar_texto_auditoria("• Revisar configuración SSH: /etc/ssh/sshd_config\n")
                        self._actualizar_texto_auditoria("• Verificar permisos de archivos críticos: /etc/passwd, /etc/shadow\n")
                        self._actualizar_texto_auditoria("• Actualizar sistema: apt update && apt upgrade\n")
                        self._actualizar_texto_auditoria("• Configurar firewall: ufw enable\n")
                        self._actualizar_texto_auditoria("• Revisar servicios activos: systemctl list-units --type=service\n")
                        
                        # Comandos útiles de seguimiento
                        self._actualizar_texto_auditoria("\n=== COMANDOS LYNIS ÚTILES ===\n")
                        self._actualizar_texto_auditoria("• lynis audit system --verbose\n")
                        self._actualizar_texto_auditoria("• lynis show profiles\n")
                        self._actualizar_texto_auditoria("• lynis show groups\n")
                        self._actualizar_texto_auditoria("• lynis audit system --tests-from-group authentication\n")
                        self._actualizar_texto_auditoria("• lynis audit system --tests-from-group networking\n")
                        
                        if errores and errores.strip():
                            self._actualizar_texto_auditoria(f"\nWARNING Errores reportados:\n{errores[:500]}\n")
                        
                    else:
                        self._actualizar_texto_auditoria("ERROR Lynis no encontrado en sistema\n")
                        self._actualizar_texto_auditoria("INSTALACIÓN REQUERIDA:\n")
                        self._actualizar_texto_auditoria("• apt update && apt install lynis\n")
                        self._actualizar_texto_auditoria("• O desde fuente: wget https://cisofy.com/files/lynis-x.x.x.tar.gz\n")
                        self._actualizar_texto_auditoria("• Verificar: lynis --version\n")
                        
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("ERROR Timeout en auditoría Lynis - proceso muy lento (>10 minutos)\n")
                except FileNotFoundError as e:
                    self._actualizar_texto_auditoria(f"ERROR Comando no encontrado: {str(e)}\n")
                except PermissionError as e:
                    self._actualizar_texto_auditoria(f"ERROR Sin permisos: {str(e)}\n")
                    if sudo_manager:
                        self._actualizar_texto_auditoria("• Intentar con SudoManager activo en otras ventanas\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR en auditoría Lynis: {str(e)}\n")
                
                self._actualizar_texto_auditoria("=== AUDITORÍA LYNIS PROFESIONAL COMPLETADA ===\n\n")
                
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR CRÍTICO en auditoría Lynis: {str(e)}\n")
            finally:
                self.flag_auditoria.clear()
        
        # Ejecutar en thread separado
        self.thread_auditoria = threading.Thread(target=ejecutar_lynis_worker, daemon=True)
        self.thread_auditoria.start()
    
    def _actualizar_texto_auditoria(self, texto):
        """Actualizar texto de auditoría en el hilo principal de forma segura."""
        try:
            if hasattr(self, 'auditoria_text') and self.auditoria_text and self.auditoria_text.winfo_exists():
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, texto)
                self.auditoria_text.see(tk.END)
                self.auditoria_text.config(state=tk.DISABLED)
        except (tk.TclError, AttributeError):
            pass  # Widget ya no existe o ha sido destruido
    
    def _habilitar_cancelar(self, habilitar):
        """Habilitar o deshabilitar botón de cancelar de forma segura."""
        try:
            estado = "normal" if habilitar else "disabled"
            if hasattr(self, 'btn_cancelar_auditoria') and self.btn_cancelar_auditoria.winfo_exists():
                self.btn_cancelar_auditoria.config(state=estado)
        except (tk.TclError, AttributeError):
            pass  # Widget ya no existe o ha sido destruido
    
    def _finalizar_auditoria(self):
        """Finalizar proceso de auditoría."""
        self.proceso_auditoria_activo = False
        self._habilitar_cancelar(False)
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
        self.log_to_terminal("Iniciando detección de rootkits y malware...")
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_auditoria, "=== DETECCIÓN DE ROOTKITS CON HERRAMIENTAS LINUX ===\n\n")
                
                # 1. Verificar procesos ocultos con ps y comparación
                self.after(0, self._actualizar_texto_auditoria, "FASE 1: Verificación de procesos ocultos\n")
                self.after(0, self._actualizar_texto_auditoria, "COMANDO: ps aux | wc -l vs ls /proc | grep '^[0-9]' | wc -l\n")
                
                import subprocess
                try:
                    # Contar procesos con ps
                    resultado_ps = subprocess.run(['bash', '-c', 'ps aux | wc -l'], 
                                                capture_output=True, text=True, timeout=10)
                    # Contar directorios de procesos en /proc
                    resultado_proc = subprocess.run(['bash', '-c', "ls /proc | grep '^[0-9]' | wc -l"], 
                                                  capture_output=True, text=True, timeout=10)
                    
                    if resultado_ps.returncode == 0 and resultado_proc.returncode == 0:
                        procesos_ps = int(resultado_ps.stdout.strip()) - 1  # -1 para header
                        procesos_proc = int(resultado_proc.stdout.strip())
                        diferencia = abs(procesos_ps - procesos_proc)
                        
                        self.after(0, self._actualizar_texto_auditoria, f"PROCESOS PS: {procesos_ps}\n")
                        self.after(0, self._actualizar_texto_auditoria, f"PROCESOS /proc: {procesos_proc}\n")
                        self.after(0, self._actualizar_texto_auditoria, f"DIFERENCIA: {diferencia}\n")
                        
                        if diferencia > 5:  # Umbral de sospecha
                            self.after(0, self._actualizar_texto_auditoria, "ALERTA: Diferencia significativa detectada - posible rootkit\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "OK: Recuento de procesos normal\n")
                except:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR: No se pudo verificar procesos\n")
                
                self.after(0, self._actualizar_texto_auditoria, "\n")
                
                # 2. Verificar modificaciones en comandos del sistema
                self.after(0, self._actualizar_texto_auditoria, "FASE 2: Verificación de integridad de comandos\n")
                comandos_criticos = ['/bin/ps', '/bin/ls', '/bin/netstat', '/usr/bin/who', '/usr/bin/w']
                
                for comando in comandos_criticos:
                    try:
                        # Verificar si el comando existe y obtener información
                        resultado = subprocess.run(['stat', '-c', '%s %Y', comando], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0:
                            info = resultado.stdout.strip().split()
                            tamaño = info[0]
                            timestamp = info[1]
                            self.after(0, self._actualizar_texto_auditoria, f"OK: {comando} - Tamaño: {tamaño} bytes\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, f"ALERTA: {comando} no encontrado o inaccesible\n")
                    except:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: No se pudo verificar {comando}\n")
                
                self.after(0, self._actualizar_texto_auditoria, "\n")
                
                # 3. Verificar conexiones de red ocultas
                self.after(0, self._actualizar_texto_auditoria, "FASE 3: Verificación de conexiones de red ocultas\n")
                self.after(0, self._actualizar_texto_auditoria, "COMANDO: ss -tuln vs netstat -tuln\n")
                
                try:
                    # Comparar salidas de ss y netstat
                    resultado_ss = subprocess.run(['ss', '-tuln'], 
                                                capture_output=True, text=True, timeout=10)
                    resultado_netstat = subprocess.run(['netstat', '-tuln'], 
                                                     capture_output=True, text=True, timeout=10)
                    
                    if resultado_ss.returncode == 0 and resultado_netstat.returncode == 0:
                        lineas_ss = len(resultado_ss.stdout.strip().split('\n'))
                        lineas_netstat = len(resultado_netstat.stdout.strip().split('\n'))
                        diferencia_red = abs(lineas_ss - lineas_netstat)
                        
                        self.after(0, self._actualizar_texto_auditoria, f"CONEXIONES SS: {lineas_ss}\n")
                        self.after(0, self._actualizar_texto_auditoria, f"CONEXIONES NETSTAT: {lineas_netstat}\n")
                        
                        if diferencia_red > 3:
                            self.after(0, self._actualizar_texto_auditoria, "ALERTA: Diferencias en listado de conexiones\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "OK: Listados de red coinciden\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, "ERROR: No se pudieron ejecutar comandos de red\n")
                except:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR: Error comparando herramientas de red\n")
                
                self.after(0, self._actualizar_texto_auditoria, "\n")
                
                # 4. Verificar módulos del kernel sospechosos
                self.after(0, self._actualizar_texto_auditoria, "FASE 4: Verificación de módulos del kernel\n")
                self.after(0, self._actualizar_texto_auditoria, "COMANDO: lsmod | grep -v '^Module'\n")
                
                try:
                    resultado = subprocess.run(['bash', '-c', "lsmod | grep -v '^Module' | wc -l"], 
                                             capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        modulos_count = resultado.stdout.strip()
                        self.after(0, self._actualizar_texto_auditoria, f"MÓDULOS CARGADOS: {modulos_count}\n")
                        
                        # Buscar módulos con nombres sospechosos
                        resultado_modulos = subprocess.run(['lsmod'], 
                                                         capture_output=True, text=True, timeout=10)
                        if resultado_modulos.returncode == 0:
                            modulos_sospechosos = ['rootkit', 'hidden', 'stealth', 'backdoor']
                            lineas = resultado_modulos.stdout.lower().split('\n')
                            
                            encontrados = []
                            for linea in lineas:
                                for sospechoso in modulos_sospechosos:
                                    if sospechoso in linea:
                                        encontrados.append(linea.strip())
                            
                            if encontrados:
                                self.after(0, self._actualizar_texto_auditoria, "ALERTA: Módulos sospechosos encontrados:\n")
                                for modulo in encontrados:
                                    self.after(0, self._actualizar_texto_auditoria, f"  SOSPECHOSO: {modulo}\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "OK: No se encontraron módulos con nombres sospechosos\n")
                except:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR: No se pudo verificar módulos del kernel\n")
                
                # Usar controlador si está disponible
                if self.controlador:
                    self.after(0, self._actualizar_texto_auditoria, "\nFASE 5: Ejecutando detector del controlador\n")
                    resultado = self.controlador.ejecutar_deteccion_rootkits()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "OK Detección de rootkits completada\n")
                        if 'rootkits_detectados' in resultado:
                            count = resultado['rootkits_detectados']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"ADVERTENCIA {count} posibles rootkits detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "OK No se detectaron rootkits\n")
                        if 'salida' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, f"\nDETALLES:\n{resultado['salida']}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual con configuración optimizada
                    self.after(0, self._actualizar_texto_auditoria, " Detectando rootkits con rkhunter y chkrootkit (optimizado)...\n")
                    
                    import subprocess
                    
                    # Configuración optimizada para herramientas anti-rootkit
                    herramientas = [
                        (['rkhunter', '--check', '--skip-keypress', '--quiet'], 'rkhunter'),
                        (['chkrootkit', '-q'], 'chkrootkit')  # Modo quiet para mejor parsing
                    ]
                    
                    # Intentar usar SudoManager para permisos elevados
                    try:
                        from aresitos.utils.sudo_manager import get_sudo_manager
                        sudo_manager = get_sudo_manager()
                        sudo_disponible = sudo_manager.is_sudo_active()
                        
                        if sudo_disponible:
                            self.after(0, self._actualizar_texto_auditoria, " Ejecutando con permisos elevados para análisis completo...\n")
                    except ImportError:
                        sudo_disponible = False
                        sudo_manager = None
                    
                    for comando, nombre in herramientas:
                        try:
                            self.after(0, self._actualizar_texto_auditoria, f" Ejecutando {nombre} con configuración optimizada...\n")
                            
                            # Usar sudo si está disponible para chkrootkit (necesita acceso root)
                            if nombre == 'chkrootkit' and sudo_disponible and sudo_manager:
                                resultado = sudo_manager.execute_sudo_command('chkrootkit -q', timeout=420)
                            else:
                                resultado = subprocess.run(comando, capture_output=True, text=True, timeout=420)
                            
                            if resultado.returncode == 0:
                                self.after(0, self._actualizar_texto_auditoria, f"OK {nombre} completado exitosamente\n")
                                
                                # Análisis inteligente de resultados específico por herramienta
                                if nombre == 'chkrootkit':
                                    self._analizar_resultados_chkrootkit(resultado.stdout)
                                elif nombre == 'rkhunter':
                                    self._analizar_resultados_rkhunter(resultado.stdout)
                                    
                            else:
                                error_msg = resultado.stderr.strip() if resultado.stderr else "Error desconocido"
                                self.after(0, self._actualizar_texto_auditoria, f"WARNING Error en {nombre}: {error_msg}\n")
                                
                        except FileNotFoundError:
                            self.after(0, self._actualizar_texto_auditoria, f"ERROR {nombre} no encontrado. Instalar: sudo apt install {nombre}\n")
                        except subprocess.TimeoutExpired:
                            self.after(0, self._actualizar_texto_auditoria, f"TIMEOUT en {nombre} (análisis muy extenso)\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR detectando rootkits: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_servicios(self):
        """Analizar servicios del sistema usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.analizar_servicios_sistema()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "OK Análisis de servicios completado\n")
                        if 'servicios_activos' in resultado:
                            count = resultado['servicios_activos']
                            self.after(0, self._actualizar_texto_auditoria, f" Servicios activos encontrados: {count}\n")
                        if 'detalles' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, resultado['detalles'])
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, " Analizando servicios activos en Kali Linux...\n")
                    
                    import subprocess
                    try:
                        resultado = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                                 capture_output=True, text=True)
                        if resultado.returncode == 0:
                            self.after(0, self._actualizar_texto_auditoria, " Servicios activos:\n\n")
                            lineas = resultado.stdout.split('\n')
                            for linea in lineas[1:21]:
                                if linea.strip() and 'service' in linea:
                                    self.after(0, self._actualizar_texto_auditoria, f"  {linea}\n")
                            self.after(0, self._actualizar_texto_auditoria, "\n... (mostrando primeros 20)\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "ERROR obteniendo servicios\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {str(e)}\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR analizando servicios: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_permisos(self):
        """Verificar permisos críticos del sistema usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.verificar_permisos_criticos()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "OK Verificación de permisos completada\n")
                        if 'permisos_incorrectos' in resultado:
                            count = resultado['permisos_incorrectos']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"ADVERTENCIA {count} permisos incorrectos detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "OK Todos los permisos están correctos\n")
                        if 'detalles' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, f"\nDETALLES:\n{resultado['detalles']}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, "Verificando permisos críticos del sistema...\n")
                    
                    import subprocess
                    import os
                    
                    rutas_criticas = [
                        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                        '/boot', '/usr/bin/passwd', '/usr/bin/sudo', '/etc/ssh'
                    ]
                    
                    for ruta in rutas_criticas:
                        try:
                            if os.path.exists(ruta):
                                stat_result = os.stat(ruta)
                                permisos = oct(stat_result.st_mode)[-3:]
                                uid = stat_result.st_uid
                                gid = stat_result.st_gid
                                
                                self.after(0, self._actualizar_texto_auditoria, 
                                    f"DIRECTORIO {ruta}: {permisos} (uid:{uid}, gid:{gid})\n")
                                
                                if ruta in ['/etc/shadow', '/etc/sudoers'] and permisos != '640':
                                    self.after(0, self._actualizar_texto_auditoria, "ADVERTENCIA Permisos inusuales detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, f"DIRECTORIO {ruta}: No existe\n")
                        except Exception as e:
                            self.after(0, self._actualizar_texto_auditoria, f"ERROR {ruta}: Error - {str(e)}\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\nOK Verificación de permisos completada\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR verificando permisos: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def obtener_info_hardware(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Obteniendo información de hardware del sistema...\n")
                self.auditoria_text.update()
                
                import subprocess
                
                comandos_info = [
                    (['lscpu'], 'CPU'),
                    (['lsmem', '--summary'], 'Memoria'),
                    (['lsblk'], 'Discos'),
                    (['lspci', '-v'], 'PCI'),
                    (['lsusb'], 'USB'),
                    (['dmidecode', '-t', 'system'], 'Sistema')
                ]
                
                for comando, tipo in comandos_info:
                    try:
                        self.auditoria_text.insert(tk.END, f"\n=== {tipo} ===\n")
                        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.split('\n')[:15]
                            for linea in lineas:
                                if linea.strip():
                                    self.auditoria_text.insert(tk.END, f"{linea}\n")
                        else:
                            self.auditoria_text.insert(tk.END, f" Error obteniendo {tipo}\n")
                    except FileNotFoundError:
                        self.auditoria_text.insert(tk.END, f" Comando {comando[0]} no encontrado\n")
                    except subprocess.TimeoutExpired:
                        self.auditoria_text.insert(tk.END, f"TIME Timeout en {tipo}\n")
                    except Exception as e:
                        self.auditoria_text.insert(tk.END, f" Error: {str(e)}\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error obteniendo info hardware: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def guardar_auditoria(self):
        try:
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
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
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
                        continue
                
                if procesos_terminados > 0:
                    self._actualizar_texto_auditoria(f"OK COMPLETADO: {procesos_terminados} procesos de rootkits terminados\n")
                else:
                    self._actualizar_texto_auditoria("• INFO: No se encontraron procesos de detección de rootkits activos\n")
                    
                # Limpiar archivos temporales de rootkits
                archivos_temp = ['/tmp/rkhunter.log', '/tmp/chkrootkit.log', '/var/log/rkhunter.log']
                for archivo in archivos_temp:
                    try:
                        subprocess.run(['rm', '-f', archivo], capture_output=True)
                    except:
                        pass
                        
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
                import subprocess
                import os
                import time
                
                # Importar SudoManager para operaciones privilegiadas
                try:
                    from aresitos.utils.sudo_manager import SudoManager
                    sudo_manager = SudoManager()
                    if sudo_manager.is_sudo_active():
                        self._actualizar_texto_auditoria("OK SudoManager activo para escaneo completo\n")
                    else:
                        self._actualizar_texto_auditoria("WARNING SudoManager no activo - algunas detecciones pueden fallar\n")
                except ImportError:
                    sudo_manager = None
                    self._actualizar_texto_auditoria("WARNING SudoManager no disponible\n")
                
                try:
                    # Verificar si nuclei está instalado
                    resultado = subprocess.run(['which', 'nuclei'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("OK nuclei encontrado en sistema\n")
                        
                        # Verificar y actualizar templates con timeout extendido
                        self._actualizar_texto_auditoria("• Actualizando templates nuclei (puede tardar varios minutos)...\n")
                        update_result = subprocess.run(['nuclei', '-update-templates'], 
                                                     capture_output=True, text=True, timeout=300)
                        if update_result.returncode == 0:
                            self._actualizar_texto_auditoria("OK Templates nuclei actualizados exitosamente\n")
                        else:
                            self._actualizar_texto_auditoria("WARNING Error actualizando templates, usando existentes\n")
                        
                        # Detectar objetivos expandidos
                        self._actualizar_texto_auditoria("• Detectando objetivos para escaneo nuclei avanzado...\n")
                        
                        targets = []
                        
                        # 1. Localhost y servicios locales
                        local_targets = ['127.0.0.1', 'localhost']
                        for target in local_targets:
                            targets.append(target)
                            self._actualizar_texto_auditoria(f"  OK Objetivo local: {target}\n")
                        
                        # 2. Detectar IPs locales con múltiples métodos
                        try:
                            # Método hostname -I más robusto
                            ip_result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=10)
                            if ip_result.returncode == 0 and ip_result.stdout.strip():
                                ips_locales = ip_result.stdout.strip().split()
                                for ip in ips_locales:
                                    # Rango de IPs privadas completo
                                    if (ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                                      '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')) 
                                        and ip not in targets):
                                        targets.append(ip)
                                        self._actualizar_texto_auditoria(f"  OK IP local detectada: {ip}\n")
                                        
                            # Método gateway
                            route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                                        capture_output=True, text=True, timeout=10)
                            if route_result.returncode == 0 and 'via' in route_result.stdout:
                                gateway = route_result.stdout.split('via')[1].split()[0]
                                if gateway not in targets:
                                    targets.append(gateway)
                                    self._actualizar_texto_auditoria(f"  OK Gateway detectado: {gateway}\n")
                            
                            # 3. Detectar servicios web activos localmente
                            common_ports = ['80', '443', '8080', '8443', '3000', '5000', '8000', '9000']
                            for port in common_ports:
                                for local_ip in ['127.0.0.1', 'localhost']:
                                    try:
                                        import socket
                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        sock.settimeout(1)
                                        result = sock.connect_ex((local_ip if local_ip != 'localhost' else '127.0.0.1', int(port)))
                                        sock.close()
                                        if result == 0:
                                            web_target = f"http://{local_ip}:{port}"
                                            if web_target not in targets:
                                                targets.append(web_target)
                                                self._actualizar_texto_auditoria(f"  OK Servicio web detectado: {web_target}\n")
                                    except:
                                        pass
                                        
                        except Exception as e:
                            self._actualizar_texto_auditoria(f"  WARNING Error detectando objetivos: {str(e)}\n")
                        
                        # Valor por defecto si no hay objetivos
                        if not targets:
                            targets = ['127.0.0.1']
                            self._actualizar_texto_auditoria("  WARNING Usando objetivo por defecto: 127.0.0.1\n")
                        
                        self._actualizar_texto_auditoria(f"• Total objetivos para auditoría: {len(targets)}\n")
                        
                        # Escaneos profesionales por severidad expandidos
                        severidades = [
                            ('critical', 'CRÍTICAS'),
                            ('high', 'ALTAS'), 
                            ('medium', 'MEDIAS'),
                            ('low', 'BAJAS'),
                            ('info', 'INFORMATIVAS')
                        ]
                        
                        vulnerabilidades_totales = 0
                        
                        for severidad, descripcion in severidades:
                            self._actualizar_texto_auditoria(f"\n=== ESCANEO VULNERABILIDADES {descripcion} ===\n")
                            
                            for target in targets:
                                self._actualizar_texto_auditoria(f"  → Escaneando {target} [{descripcion}]...\n")
                                
                                # Comando nuclei mejorado con más opciones
                                cmd = [
                                    'nuclei', 
                                    '-u', target, 
                                    '-severity', severidad,
                                    '-timeout', '45',  # Timeout aumentado significativamente
                                    '-rate-limit', '150',  # Velocidad aumentada
                                    '-retries', '2',  # Reintentos
                                    '-no-color', 
                                    '-silent',
                                    '-stats',  # Estadísticas
                                    '-include-tags', 'exposure,misconfiguration,rce,sqli,xss,lfi,rfi,ssrf,cve,oob,dns,ssl,tls'
                                ]
                                
                                try:
                                    proceso = subprocess.run(cmd, capture_output=True, 
                                                           text=True, timeout=420)  # 7 minutos
                                    
                                    if proceso.stdout and proceso.stdout.strip():
                                        vulnerabilidades_encontradas = proceso.stdout.strip().split('\n')
                                        vuln_count = len([v for v in vulnerabilidades_encontradas if v.strip() and '[' in v])
                                        vulnerabilidades_totales += vuln_count
                                        
                                        if vuln_count > 0:
                                            self._actualizar_texto_auditoria(f"VULNERABILIDADES {descripcion} ENCONTRADAS en {target} ({vuln_count}):\n")
                                            for linea in vulnerabilidades_encontradas:
                                                if linea.strip() and '[' in linea:  # Filtrar líneas válidas
                                                    self._actualizar_texto_auditoria(f"  • {linea}\n")
                                        else:
                                            self._actualizar_texto_auditoria(f"OK Sin vulnerabilidades {descripcion.lower()} en {target}\n")
                                    else:
                                        self._actualizar_texto_auditoria(f"OK Sin vulnerabilidades {descripcion.lower()} en {target}\n")
                                        
                                    time.sleep(2)  # Pausa entre escaneos
                                    
                                except subprocess.TimeoutExpired:
                                    self._actualizar_texto_auditoria(f"WARNING Timeout escaneando {target} [{descripcion}] - escáner tomó más de 7 minutos\n")
                                except Exception as e:
                                    self._actualizar_texto_auditoria(f"WARNING Error escaneando {target}: {str(e)}\n")
                        
                        # Escaneo con templates especializados mejorado
                        self._actualizar_texto_auditoria(f"\n=== ESCANEO CON TEMPLATES ESPECIALIZADOS ===\n")
                        
                        templates_especializados = [
                            ('vulnerabilities/', 'Vulnerabilidades conocidas'),
                            ('exposures/', 'Exposiciones de información'),
                            ('misconfiguration/', 'Configuraciones incorrectas'),
                            ('technologies/', 'Detección de tecnologías'),
                            ('cves/', 'CVEs específicos'),
                            ('takeovers/', 'Subdomain takeovers'),
                            ('network/', 'Vulnerabilidades de red'),
                            ('default-logins/', 'Credenciales por defecto')
                        ]
                        
                        for template_path, descripcion in templates_especializados:
                            self._actualizar_texto_auditoria(f"  → Templates {descripcion}...\n")
                            
                            # Usar todos los objetivos para templates críticos
                            targets_template = targets if template_path in ['vulnerabilities/', 'cves/', 'exposures/'] else targets[:2]
                            
                            for target in targets_template:
                                cmd_template = [
                                    'nuclei',
                                    '-u', target,
                                    '-t', template_path,
                                    '-timeout', '60',  # Timeout aumentado para templates
                                    '-rate-limit', '100',
                                    '-retries', '1',
                                    '-no-color',
                                    '-silent'
                                ]
                                
                                try:
                                    proceso = subprocess.run(cmd_template, capture_output=True, 
                                                           text=True, timeout=300)  # 5 minutos
                                    
                                    if proceso.stdout and proceso.stdout.strip():
                                        resultados = [r for r in proceso.stdout.strip().split('\n') if r.strip() and '[' in r]
                                        result_count = len(resultados)
                                        vulnerabilidades_totales += result_count
                                        
                                        if result_count > 0:
                                            self._actualizar_texto_auditoria(f"  • {descripcion} en {target}: {result_count} encontradas\n")
                                            for resultado in resultados[:5]:  # Mostrar primeros 5
                                                self._actualizar_texto_auditoria(f"    - {resultado}\n")
                                            if len(resultados) > 5:
                                                self._actualizar_texto_auditoria(f"    ... y {len(resultados) - 5} más\n")
                                        else:
                                            self._actualizar_texto_auditoria(f"  OK Sin {descripcion.lower()} en {target}\n")
                                    
                                except subprocess.TimeoutExpired:
                                    self._actualizar_texto_auditoria(f"    WARNING Timeout template {descripcion} en {target}\n")
                                except Exception as e:
                                    self._actualizar_texto_auditoria(f"    WARNING Error template {descripcion}: {str(e)}\n")
                        
                        # Resumen final mejorado
                        self._actualizar_texto_auditoria(f"\n=== RESUMEN AUDITORÍA NUCLEI PROFESIONAL ===\n")
                        self._actualizar_texto_auditoria(f"OK Objetivos escaneados: {len(targets)}\n")
                        self._actualizar_texto_auditoria(f"OK Templates ejecutados: {len(templates_especializados)}\n")
                        self._actualizar_texto_auditoria(f"OK Total vulnerabilidades encontradas: {vulnerabilidades_totales}\n")
                        
                        if vulnerabilidades_totales > 20:
                            self._actualizar_texto_auditoria(f"CRITICO ALERTA: Sistema altamente vulnerable ({vulnerabilidades_totales} issues)\n")
                        elif vulnerabilidades_totales > 5:
                            self._actualizar_texto_auditoria(f"WARNING REVISAR: Vulnerabilidades encontradas requieren atención\n")
                        elif vulnerabilidades_totales > 0:
                            self._actualizar_texto_auditoria(f"WARNING MENOR: Pocas vulnerabilidades detectadas\n")
                        else:
                            self._actualizar_texto_auditoria(f"OK SEGURO: Sistema sin vulnerabilidades detectables con nuclei\n")
                        
                        # Comandos útiles mejorados
                        self._actualizar_texto_auditoria("\n=== COMANDOS NUCLEI AVANZADOS RECOMENDADOS ===\n")
                        self._actualizar_texto_auditoria("• nuclei -u <target> -severity critical,high -o resultados.txt\n")
                        self._actualizar_texto_auditoria("• nuclei -l targets.txt -t vulnerabilities/ -json -o vuln.json\n")
                        self._actualizar_texto_auditoria("• nuclei -u <target> -include-tags sqli,xss,rce,ssrf -rate-limit 200\n")
                        self._actualizar_texto_auditoria("• nuclei -u <target> -t cves/ -severity critical,high\n")
                        self._actualizar_texto_auditoria("• nuclei -u <target> -exclude-tags intrusive -timeout 60\n")
                        
                    else:
                        self._actualizar_texto_auditoria("ERROR nuclei no encontrado en sistema\n")
                        self._actualizar_texto_auditoria("INSTALACIÓN REQUERIDA:\n")
                        self._actualizar_texto_auditoria("• apt update && apt install nuclei\n")
                        self._actualizar_texto_auditoria("• O desde Go: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n")
                        self._actualizar_texto_auditoria("• Verificar: nuclei -version\n")
                        self._actualizar_texto_auditoria("• Actualizar templates: nuclei -update-templates\n")
                        
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("ERROR Timeout verificando nuclei - comando muy lento\n")
                except FileNotFoundError as e:
                    self._actualizar_texto_auditoria(f"ERROR Comando no encontrado: {str(e)}\n")
                except PermissionError as e:
                    self._actualizar_texto_auditoria(f"ERROR Sin permisos: {str(e)}\n")
                    if sudo_manager:
                        self._actualizar_texto_auditoria("• Intentar con SudoManager activo en otras ventanas\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR en auditoría nuclei: {str(e)}\n")
                
                self._actualizar_texto_auditoria("=== AUDITORÍA NUCLEI PROFESIONAL COMPLETADA ===\n\n")
                
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR CRÍTICO en auditoría nuclei: {str(e)}\n")
            finally:
                self.proceso_auditoria_activo = False
        
        # Ejecutar en thread separado
        self.thread_auditoria = threading.Thread(target=ejecutar_nuclei_worker, daemon=True)
        self.thread_auditoria.start()
    
    def ejecutar_httpx(self):
        """Ejecutar escaneo web completo con httpx - probe HTTP avanzado."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== INICIANDO ESCANEO HTTPX ===\n")
                import subprocess
                import os
                
                try:
                    # Verificar si httpx está instalado
                    resultado = subprocess.run(['which', 'httpx'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("OK httpx encontrado en sistema\n")
                        
                        # Targets comunes para escanear
                        targets = ['127.0.0.1', 'localhost', '192.168.1.1', '192.168.1.254']
                        puertos = ['80', '443', '8080', '8443', '3000', '5000']
                        
                        servicios_encontrados = []
                        
                        for target in targets:
                            self._actualizar_texto_auditoria(f"• Escaneando servicios web en {target}...\n")
                            
                            # Crear lista de URLs para httpx
                            urls_target = []
                            for puerto in puertos:
                                urls_target.extend([f"http://{target}:{puerto}", f"https://{target}:{puerto}"])
                            
                            # Ejecutar httpx con probe
                            for url in urls_target:
                                try:
                                    cmd = ['httpx', '-u', url, '-probe', '-status-code', 
                                          '-title', '-tech-detect', '-timeout', '5', '-silent']
                                    
                                    proceso = subprocess.run(cmd, capture_output=True, 
                                                           text=True, timeout=10)
                                    
                                    if proceso.stdout and proceso.stdout.strip():
                                        lineas = proceso.stdout.strip().split('\n')
                                        for linea in lineas:
                                            if linea.strip() and '[' in linea:
                                                servicios_encontrados.append(linea.strip())
                                                self._actualizar_texto_auditoria(f"  OK SERVICIO: {linea.strip()}\n")
                                                
                                except subprocess.TimeoutExpired:
                                    continue
                                except Exception:
                                    continue
                        
                        if servicios_encontrados:
                            self._actualizar_texto_auditoria(f"\n=== RESUMEN: {len(servicios_encontrados)} servicios web encontrados ===\n")
                            for servicio in servicios_encontrados:
                                self._actualizar_texto_auditoria(f"  • {servicio}\n")
                        else:
                            self._actualizar_texto_auditoria("• INFO: No se encontraron servicios web activos\n")
                        
                        # Ejecutar detección de tecnologías en localhost
                        self._actualizar_texto_auditoria("\n• Detectando tecnologías en localhost...\n")
                        try:
                            cmd_tech = ['httpx', '-u', 'http://localhost', '-tech-detect', 
                                       '-follow-redirects', '-timeout', '10', '-silent']
                            tech_result = subprocess.run(cmd_tech, capture_output=True, 
                                                       text=True, timeout=15)
                            if tech_result.stdout and tech_result.stdout.strip():
                                self._actualizar_texto_auditoria(f"TECNOLOGÍAS: {tech_result.stdout.strip()}\n")
                            else:
                                self._actualizar_texto_auditoria("• No se detectaron tecnologías específicas\n")
                        except:
                            pass
                        
                        # Mostrar comandos útiles
                        self._actualizar_texto_auditoria("\n=== COMANDOS HTTPX ÚTILES ===\n")
                        self._actualizar_texto_auditoria("• httpx -l targets.txt -probe: Verificar múltiples URLs\n")
                        self._actualizar_texto_auditoria("• httpx -u target.com -ports 80,443,8080: Puertos específicos\n")
                        self._actualizar_texto_auditoria("• httpx -u target.com -screenshot: Capturar pantalla\n")
                        self._actualizar_texto_auditoria("• httpx -u target.com -favicon: Hash de favicon\n")
                        
                    else:
                        self._actualizar_texto_auditoria("WARNING httpx no encontrado\n")
                        self._actualizar_texto_auditoria("INSTALACIÓN: apt install httpx\n")
                        self._actualizar_texto_auditoria("O desde Go: go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n")
                        
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR verificando httpx: {str(e)}\n")
                
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
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")

    def _analizar_resultados_chkrootkit(self, output):
        """Analizar resultados de chkrootkit de forma inteligente."""
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
            
            # Reportar resultados
            total_criticas = len(sospechas_criticas)
            total_moderadas = len(sospechas_moderadas)
            
            if total_criticas > 0:
                self.after(0, self._actualizar_texto_auditoria, f"CRITICO CHKROOTKIT: {total_criticas} amenazas CRITICAS detectadas:\n")
                for sospecha in sospechas_criticas[:5]:  # Mostrar hasta 5 críticas
                    self.after(0, self._actualizar_texto_auditoria, f"   CRITICO {sospecha}\n")
                if total_criticas > 5:
                    self.after(0, self._actualizar_texto_auditoria, f"   ... y {total_criticas - 5} amenazas adicionales\n")
            
            if total_moderadas > 0:
                self.after(0, self._actualizar_texto_auditoria, f"WARNING CHKROOTKIT: {total_moderadas} elementos sospechosos:\n")
                for sospecha in sospechas_moderadas[:3]:  # Mostrar hasta 3 moderadas
                    self.after(0, self._actualizar_texto_auditoria, f"   SOSPECHOSO {sospecha}\n")
                if total_moderadas > 3:
                    self.after(0, self._actualizar_texto_auditoria, f"   ... y {total_moderadas - 3} elementos adicionales\n")
            
            if total_criticas == 0 and total_moderadas == 0:
                self.after(0, self._actualizar_texto_auditoria, "OK CHKROOTKIT: Sistema limpio - No rootkits detectados\n")
            
            # Estadísticas del análisis
            if total_checks > 0:
                self.after(0, self._actualizar_texto_auditoria, f"INFO CHKROOTKIT: {total_checks} verificaciones completadas\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto_auditoria, f"ERROR analizando resultados chkrootkit: {str(e)}\n")

    def _analizar_resultados_rkhunter(self, output):
        """Analizar resultados de rkhunter de forma inteligente."""
        try:
            lineas = output.split('\n')
            warnings = []
            infected = []
            suspicious = []
            total_files_checked = 0
            
            for linea in lineas:
                linea_clean = linea.strip()
                if not linea_clean:
                    continue
                    
                linea_upper = linea_clean.upper()
                
                # Contar archivos verificados
                if 'CHECKING' in linea_upper:
                    total_files_checked += 1
                
                # Detectar problemas específicos de rkhunter
                if 'WARNING' in linea_upper and 'INFECTED' not in linea_upper:
                    warnings.append(linea_clean)
                elif 'INFECTED' in linea_upper or 'SUSPECT' in linea_upper:
                    infected.append(linea_clean)
                elif 'SUSPICIOUS' in linea_upper or 'POSSIBLE' in linea_upper:
                    suspicious.append(linea_clean)
            
            # Reportar resultados
            total_infected = len(infected)
            total_suspicious = len(suspicious)
            total_warnings = len(warnings)
            
            if total_infected > 0:
                self.after(0, self._actualizar_texto_auditoria, f"CRITICO RKHUNTER: {total_infected} archivos INFECTADOS detectados:\n")
                for item in infected[:5]:
                    self.after(0, self._actualizar_texto_auditoria, f"   INFECTADO {item}\n")
                if total_infected > 5:
                    self.after(0, self._actualizar_texto_auditoria, f"   ... y {total_infected - 5} archivos adicionales\n")
            
            if total_suspicious > 0:
                self.after(0, self._actualizar_texto_auditoria, f"WARNING RKHUNTER: {total_suspicious} elementos sospechosos:\n")
                for item in suspicious[:3]:
                    self.after(0, self._actualizar_texto_auditoria, f"   SOSPECHOSO {item}\n")
                if total_suspicious > 3:
                    self.after(0, self._actualizar_texto_auditoria, f"   ... y {total_suspicious - 3} elementos adicionales\n")
            
            if total_warnings > 0:
                self.after(0, self._actualizar_texto_auditoria, f"INFO RKHUNTER: {total_warnings} advertencias menores\n")
            
            if total_infected == 0 and total_suspicious == 0:
                self.after(0, self._actualizar_texto_auditoria, "OK RKHUNTER: Sistema limpio - No amenazas detectadas\n")
            
            # Estadísticas del análisis
            if total_files_checked > 0:
                self.after(0, self._actualizar_texto_auditoria, f"INFO RKHUNTER: {total_files_checked} elementos verificados\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto_auditoria, f"ERROR analizando resultados rkhunter: {str(e)}\n")

    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            from aresitos.utils.seguridad_comandos import validador_comandos
            
            comandos = validador_comandos.obtener_comandos_disponibles()
            
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "[SECURITY]  COMANDOS DISPONIBLES EN ARESITOS v2.0 - AUDITORÍA\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            
            for categoria, lista_comandos in comandos.items():
                self.terminal_output.insert(tk.END, f"FOLDER {categoria.upper()}:\n")
                comandos_linea = ", ".join(lista_comandos)
                self.terminal_output.insert(tk.END, f"   {comandos_linea}\n\n")
            
            self.terminal_output.insert(tk.END, "[TOOLS] COMANDOS ESPECIALES:\n")
            self.terminal_output.insert(tk.END, "   ayuda-comandos, info-seguridad, clear/cls\n\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando ayuda: {e}\n")
        
        self.terminal_output.see(tk.END)
    
    def _mostrar_info_seguridad(self):
        """Mostrar información de seguridad actual."""
        try:
            from aresitos.utils.seguridad_comandos import validador_comandos
            
            info = validador_comandos.obtener_info_seguridad()
            
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS - AUDITORÍA\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            
            estado_seguridad = "[OK] SEGURO" if info['es_usuario_kali'] else "[FAIL] INSEGURO"
            
            self.terminal_output.insert(tk.END, f"Estado: {estado_seguridad}\n")
            self.terminal_output.insert(tk.END, f"Usuario: {info['usuario_actual']}\n")
            self.terminal_output.insert(tk.END, f"Sistema: {info['sistema']}\n")
            self.terminal_output.insert(tk.END, f"Usuario Kali válido: {info['es_usuario_kali']}\n")
            self.terminal_output.insert(tk.END, f"Comandos permitidos: {info['total_comandos_permitidos']}\n")
            self.terminal_output.insert(tk.END, f"Comandos prohibidos: {info['total_comandos_prohibidos']}\n")
            self.terminal_output.insert(tk.END, f"Patrones de seguridad: {info['patrones_seguridad']}\n\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando info seguridad: {e}\n")
        
        self.terminal_output.see(tk.END)

