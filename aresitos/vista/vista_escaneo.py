# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import logging
import threading
from aresitos.utils.thread_safe_gui import ThreadSafeFlag
import datetime

try:
    from aresitos.vista.burp_theme import burp_theme
    from aresitos.utils.detector_red import DetectorRed
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None
    DetectorRed = None

class VistaEscaneo(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.flag_proceso = ThreadSafeFlag()
        self.thread_escaneo = None
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
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
            
        self.crear_widgets()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame superior para el contenido principal
        main_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(main_frame, minsize=400)
        
        # Título con tema Burp Suite
        titulo_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill="x", pady=(10, 15))
        
        titulo_label = tk.Label(titulo_frame, text="ESCANEADOR DE VULNERABILIDADES", 
                              font=('Arial', 14, 'bold'),
                              bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo_label.pack()
        
        # Frame de botones con tema
        btn_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        btn_frame.pack(fill="x", pady=(0, 10))
        
        # Botones con tema Burp Suite
        self.btn_escanear = tk.Button(btn_frame, text="Escanear Sistema", 
                                    command=self.ejecutar_escaneo,
                                    bg=self.colors['fg_accent'], fg='white', 
                                    font=('Arial', 10, 'bold'),
                                    relief='flat', padx=15, pady=8,
                                    activebackground=self.colors['danger'],
                                    activeforeground='white')
        self.btn_escanear.pack(side="left", padx=(0, 10))
        
        self.btn_cancelar_escaneo = tk.Button(btn_frame, text="Cancelar", 
                                            command=self.cancelar_escaneo,
                                            state="disabled",
                                            bg=self.colors['button_bg'], fg='white',
                                            font=('Arial', 10),
                                            relief='flat', padx=15, pady=8,
                                            activebackground=self.colors['danger'],
                                            activeforeground='white')
        self.btn_cancelar_escaneo.pack(side="left", padx=(0, 15))
        
        self.btn_logs = tk.Button(btn_frame, text="Ver Logs", 
                                command=self.ver_logs,
                                bg=self.colors['button_bg'], fg='white',
                                font=('Arial', 10),
                                relief='flat', padx=15, pady=8,
                                activebackground=self.colors['fg_accent'],
                                activeforeground='white')
        self.btn_logs.pack(side="left", padx=(0, 10))
        
        # Barra de progreso
        self.progress_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        self.progress_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        self.progress_label = tk.Label(self.progress_frame, text="Estado: Listo", 
                                     bg=self.colors['bg_primary'], fg=self.colors['fg_primary'],
                                     font=('Arial', 9))
        self.progress_label.pack(side="left")
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='determinate', length=300)
        self.progress_bar.pack(side="right", padx=(10, 0))
        
        # Área de resultados con tema Burp Suite
        self.text_resultados = scrolledtext.ScrolledText(main_frame, height=20,
                                                       bg=self.colors['bg_secondary'], 
                                                       fg=self.colors['fg_primary'],
                                                       font=('Consolas', 10),
                                                       insertbackground=self.colors['fg_accent'],
                                                       selectbackground=self.colors['fg_accent'],
                                                       relief='flat', bd=1)
        
        self.text_resultados.pack(fill="both", expand=True, padx=10)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado Escaneo con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - Escaneador",
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
                command=self.limpiar_terminal_escaneo,
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
                command=self.abrir_logs_escaneo,
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
                bg='#000000',  # Fondo negro como dashboard
                fg='#00ff00',  # Texto verde como dashboard
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
            self._actualizar_terminal_seguro("="*60 + "\n")
            self._actualizar_terminal_seguro("Terminal ARESITOS - Escaneador v2.0\n")
            self._actualizar_terminal_seguro(f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._actualizar_terminal_seguro(f"Sistema: Kali Linux - Network & Vulnerability Scanner\n")
            self._actualizar_terminal_seguro("="*60 + "\n")
            self._actualizar_terminal_seguro("LOG Escaneador en tiempo real\n\n")
            
            self.log_to_terminal("Terminal Escaneo iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Escaneo: {e}")
    
    def limpiar_terminal_escaneo(self):
        """Limpiar terminal Escaneo manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
                self._actualizar_terminal_seguro("", "clear")
                # Recrear cabecera estándar
                self._actualizar_terminal_seguro("="*60 + "\n")
                self._actualizar_terminal_seguro("Terminal ARESITOS - Escaneador v2.0\n")
                self._actualizar_terminal_seguro(f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self._actualizar_terminal_seguro("Sistema: Kali Linux - Network & Vulnerability Scanner\n")
                self._actualizar_terminal_seguro("="*60 + "\n")
                self._actualizar_terminal_seguro("LOG Terminal Escaneador reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Escaneador: {e}")
    
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
            self._actualizar_terminal_seguro(f"\n> {comando}\n")
            
            if not es_valido:
                # Mostrar error de seguridad
                self._actualizar_terminal_seguro(f"{mensaje}\n")
                self._actualizar_terminal_seguro("[SUGERENCIA] Use 'ayuda-comandos' para ver comandos disponibles\n")
                self.comando_entry.delete(0, tk.END)
                return
            
            # Mostrar mensaje de autorización
            self._actualizar_terminal_seguro(f"{mensaje}\n")
            self.comando_entry.delete(0, tk.END)
            
            # Ejecutar comando sanitizado en thread
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando_sanitizado,))
            thread.daemon = True
            thread.start()
            
        except ImportError:
            # Fallback sin validación (modo inseguro)
            self.terminal_output.insert(tk.END, f"\n> {comando}\n")
            self.terminal_output.insert(tk.END, "ADVERTENCIA️  EJECUTANDO SIN VALIDACIÓN DE SEGURIDAD\n")
            self.terminal_output.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            self.terminal_output.insert(tk.END, f"\n> {comando}\n")
            self.terminal_output.insert(tk.END, f"ERROR Error de seguridad: {e}\n")
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
                self.limpiar_terminal_escaneo()
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
    
    def abrir_logs_escaneo(self):
        """Abrir carpeta de logs Escaneador."""
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
                self.log_to_terminal("Carpeta de logs Escaneador abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs Escaneador: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal con formato estándar."""
        try:
            import datetime
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
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
    
    def ejecutar_escaneo(self):
        """Ejecutar escaneo del sistema."""
        if self.flag_proceso.is_set():
            return
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de escaneo configurado")
            return
        # Limpiar resultados anteriores
        self._actualizar_resultados_seguro("", "clear")
        self._actualizar_resultados_seguro("Iniciando escaneo...\n\n")
        # Inicializar barra de progreso
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Estado: Iniciando escaneo...")
        # Log al terminal integrado
        self._log_terminal("INICIANDO escaneo del sistema", "ESCANEADOR", "INFO")
        self.log_to_terminal("Iniciando escaneo del sistema...")
        # Configurar UI para escaneo
        self.flag_proceso.set()
        self.btn_escanear.config(state="disabled")
        self.btn_cancelar_escaneo.config(state="normal")
        # Ejecutar escaneo en thread separado
        self.thread_escaneo = threading.Thread(target=self._ejecutar_escaneo_async)
        self.thread_escaneo.daemon = True
        self.thread_escaneo.start()
    
    def _log_terminal(self, mensaje, modulo="ESCANEADOR", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")
    
    def _actualizar_texto_seguro(self, texto):
        """Actualizar texto de resultados de forma segura desde cualquier hilo."""
        def _update():
            try:
                if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                    self.text_resultados.insert(tk.END, texto)
                    self.text_resultados.see(tk.END)
                    if hasattr(self.text_resultados, 'update'):
                        self.text_resultados.update()
            except (tk.TclError, AttributeError):
                pass  # Widget ya no existe o ha sido destruido
        
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass
    
    def _actualizar_progreso_seguro(self, valor, texto=""):
        """Actualizar barra de progreso de forma segura desde cualquier hilo."""
        def _update():
            try:
                if hasattr(self, 'progress_bar') and self.progress_bar.winfo_exists():
                    self.progress_bar['value'] = valor
                if hasattr(self, 'progress_label') and self.progress_label.winfo_exists() and texto:
                    self.progress_label.config(text=texto)
            except (tk.TclError, AttributeError):
                pass
        
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass  # Ventana ya destruida
    
    def _ejecutar_escaneo_async(self):
        """Ejecutar escaneo completo del sistema usando el escaneador avanzado Kali 2025."""
        try:
            if not self.flag_proceso.is_set():
                return
            
            # Progreso inicial
            self._actualizar_progreso_seguro(10, "Estado: Preparando escaneo...")
            
            self._log_terminal("Iniciando ESCANEO COMPLETO KALI 2025 - Aresitos Aegis", "ESCANEADOR", "INFO")
            self._actualizar_texto_seguro("=== ARESITOS AEGIS - ESCANEO AVANZADO KALI 2025 ===\n\n")
            
            # Verificar controlador con logs detallados
            self._log_terminal(f"Verificando controlador: {self.controlador is not None}", "ESCANEADOR", "DEBUG")
            if self.controlador:
                self._log_terminal(f"Métodos disponibles: {[m for m in dir(self.controlador) if 'escaneo' in m.lower()]}", "ESCANEADOR", "DEBUG")
            
            # Forzar uso del controlador de escaneo avanzado
            if self.controlador:
                self._actualizar_progreso_seguro(20, "Estado: Configurando escaneador...")
                
                self._log_terminal("CONTROLADOR Controlador disponible - Iniciando escaneo Kali 2025", "ESCANEADOR", "SUCCESS")  # Issue 22/24: Sin emojis
                self._actualizar_texto_seguro("MODO: Escaneador Avanzado Kali 2025\n")
                self._actualizar_texto_seguro("HERRAMIENTAS: masscan, nmap, nuclei, gobuster, ffuf, rustscan\n\n")
                
                # Determinar objetivo usando DetectorRed
                if DetectorRed:
                    try:
                        self.detector_red = DetectorRed()
                        objetivos = self.detector_red.obtener_objetivos_escaneo()
                        if not objetivos:
                            objetivos = ["127.0.0.1"]  # Fallback si no se detecta red
                        self._log_terminal(f"CONTROLADOR Red detectada automáticamente: {objetivos}", "ESCANEADOR", "INFO")
                    except Exception as e:
                        self._log_terminal(f"CONTROLADOR Error detección automática: {e}", "ESCANEADOR", "WARNING")
                        objetivos = ["127.0.0.1"]
                else:
                    objetivos = ["127.0.0.1"]  # Siempre incluir localhost
                
                self._actualizar_progreso_seguro(30, "Estado: Detectando objetivos de escaneo...")
                
                self._actualizar_texto_seguro(f"OBJETIVOS: {', '.join(objetivos)}\n\n")
                
                # Ejecutar escaneo para cada objetivo
                resultados_totales = {"exito": True, "resultados": []}
                progreso_por_objetivo = 60 // len(objetivos)  # Distribuir 60% entre objetivos
                
                for i, objetivo in enumerate(objetivos):
                    progreso_actual = 40 + (i * progreso_por_objetivo)
                    self._actualizar_progreso_seguro(progreso_actual, f"Estado: Escaneando {objetivo}...")
                    
                    self._log_terminal(f"Escaneando objetivo: {objetivo}", "ESCANEADOR", "INFO")
                    self._actualizar_texto_seguro(f"ESCANEANDO: {objetivo}\n")
                    
                    try:
                        # Intentar método Kali 2025 primero
                        if hasattr(self.controlador, 'escaneo_completo_kali2025'):
                            resultado = self.controlador.escaneo_completo_kali2025(objetivo)
                        # Fallback a método genérico
                        elif hasattr(self.controlador, 'escaneo_completo'):
                            resultado = self.controlador.escaneo_completo(objetivo)
                        # Fallback a escaneo básico del controlador
                        elif hasattr(self.controlador, 'escanear_sistema'):
                            resultado = self.controlador.escanear_sistema(objetivo)
                        else:
                            self._log_terminal("Métodos de escaneo no encontrados en controlador", "ESCANEADOR", "ERROR")
                            raise Exception("Controlador sin métodos de escaneo")
                        
                        if resultado and resultado.get("exito"):
                            resultados_totales["resultados"].append(resultado)
                            self._log_terminal(f"CONTROLADOR Escaneo de {objetivo} completado", "ESCANEADOR", "SUCCESS")
                        else:
                            self._log_terminal(f"ERROR Error en escaneo de {objetivo}: {resultado.get('error', 'Error desconocido')}", "ESCANEADOR", "ERROR")
                            
                    except Exception as e:
                        self._log_terminal(f"ERROR Excepción escaneando {objetivo}: {str(e)}", "ESCANEADOR", "ERROR")
                        continue
                
                # Mostrar resultados consolidados
                if resultados_totales["resultados"]:
                    self._actualizar_progreso_seguro(90, "Estado: Procesando resultados...")
                    self._mostrar_resultados_consolidados(resultados_totales)
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo completar ningún escaneo\n")
                    self._ejecutar_escaneo_emergencia()
                    
            else:
                self._log_terminal("Controlador no disponible - Ejecutando escaneo profesional nativo", "ESCANEADOR", "INFO")
                self._actualizar_progreso_seguro(40, "Estado: Validando herramientas...")
                
                # Verificar herramientas disponibles
                herramientas_status = self._validar_herramientas_escaneo()
                
                # Usar escaneo avanzado o integral según disponibilidad
                if DetectorRed:
                    try:
                        self.detector_red = DetectorRed()
                        objetivos_escaneo = self.detector_red.obtener_objetivos_escaneo()
                        if not objetivos_escaneo:
                            objetivos_escaneo = ["127.0.0.1"]
                    except Exception as e:
                        self._log_terminal(f"Error detección automática: {e}", "ESCANEADOR", "WARNING")
                        objetivos_escaneo = ["127.0.0.1"]
                else:
                    objetivos_escaneo = ["127.0.0.1"]
                    
                resultados_totales = {"exito": True, "resultados": []}
                for objetivo in objetivos_escaneo:
                    try:
                        if herramientas_status["total"] >= 3:
                            self._log_terminal(f"Usando escaneo avanzado multiherramienta para {objetivo}", "ESCANEADOR", "INFO")
                            self._actualizar_progreso_seguro(60, f"Estado: Escaneo avanzado {objetivo}...")
                            resultado = self._escaneo_avanzado_multiherramienta(objetivo)
                        else:
                            self._log_terminal(f"Usando escaneo integral básico para {objetivo}", "ESCANEADOR", "INFO")
                            self._actualizar_progreso_seguro(60, f"Estado: Escaneo integral {objetivo}...")
                            resultado = self._escaneo_integral_kali(objetivo)
                        
                        if resultado and resultado.get("exito"):
                            resultados_totales["resultados"].append(resultado)
                            self._log_terminal(f"Escaneo de {objetivo} completado exitosamente", "ESCANEADOR", "SUCCESS")
                    except Exception as e:
                        self._log_terminal(f"Error en escaneo de {objetivo}: {str(e)}", "ESCANEADOR", "ERROR")
                
                # Si hay resultados, mostrarlos, sino ejecutar emergencia
                if resultados_totales["resultados"]:
                    self._actualizar_progreso_seguro(90, "Estado: Procesando resultados...")
                    self._mostrar_resultados_consolidados(resultados_totales)
                else:
                    self._ejecutar_escaneo_emergencia()
                
        except Exception as e:
            self._log_terminal(f"ERROR CRÍTICO en escaneo: {str(e)}", "ESCANEADOR", "ERROR")
            self._actualizar_texto_seguro(f"\nERROR CRÍTICO: {str(e)}\n")
            self._ejecutar_escaneo_emergencia()
        finally:
            # Finalizar proceso
            self._actualizar_progreso_seguro(100, "Estado: Escaneo completado")
            self.flag_proceso.clear()
            self.after_idle(self._finalizar_escaneo)
    
    def _mostrar_resultados_consolidados(self, resultados_totales):
        """Mostrar resultados consolidados de todos los escaneos."""
        try:
            self._actualizar_texto_seguro("\n" + "=" * 70 + "\n")
            self._actualizar_texto_seguro("    RESULTADOS CONSOLIDADOS - ESCANEO KALI 2025\n")
            self._actualizar_texto_seguro("=" * 70 + "\n\n")
            
            total_vulnerabilidades = 0
            total_puertos = 0
            total_servicios = 0
            
            for i, resultado in enumerate(resultados_totales["resultados"], 1):
                datos = resultado.get("resultado", {})
                objetivo = datos.get("objetivo", f"Objetivo {i}")
                
                self._actualizar_texto_seguro(f"--- OBJETIVO {i}: {objetivo} ---\n")
                
                # Resumen ejecutivo por objetivo
                resumen = datos.get("resumen", {})
                if resumen:
                    puertos = resumen.get('puertos_abiertos', 0)
                    servicios = resumen.get('servicios_detectados', 0)
                    vulnerabilidades = resumen.get('vulnerabilidades_encontradas', 0)
                    
                    self._actualizar_texto_seguro(f"  Puertos abiertos: {puertos}\n")
                    self._actualizar_texto_seguro(f"  Servicios: {servicios}\n")
                    self._actualizar_texto_seguro(f"  Vulnerabilidades: {vulnerabilidades}\n")
                    
                    total_puertos += puertos
                    total_servicios += servicios
                    total_vulnerabilidades += vulnerabilidades
                
                # Mostrar algunos detalles importantes
                fases = datos.get("fases", {})
                if "nmap" in fases and fases["nmap"].get("exito"):
                    servicios_importantes = fases["nmap"].get("servicios", [])[:3]
                    for servicio in servicios_importantes:
                        puerto = servicio.get("puerto", "N/A")
                        nombre = servicio.get("servicio", "desconocido")
                        self._actualizar_texto_seguro(f"    ├─ Puerto {puerto}: {nombre}\n")
                
                if "nuclei" in fases and fases["nuclei"].get("exito"):
                    vulnerabilidades = fases["nuclei"].get("vulnerabilidades", [])[:2]
                    for vuln in vulnerabilidades:
                        template = vuln.get("template", "N/A")
                        self._actualizar_texto_seguro(f"    [!] VULNERABILIDAD: {template}\n")
                
                self._actualizar_texto_seguro("\n")
            
            # Resumen global
            self._actualizar_texto_seguro("--- RESUMEN GLOBAL ---\n")
            self._actualizar_texto_seguro(f"Total objetivos escaneados: {len(resultados_totales['resultados'])}\n")
            self._actualizar_texto_seguro(f"Total puertos abiertos: {total_puertos}\n")
            self._actualizar_texto_seguro(f"Total servicios detectados: {total_servicios}\n")
            self._actualizar_texto_seguro(f"Total vulnerabilidades: {total_vulnerabilidades}\n\n")
            
            # Recomendaciones
            self._actualizar_texto_seguro("--- RECOMENDACIONES ---\n")
            if total_vulnerabilidades > 0:
                self._actualizar_texto_seguro("CRITICO: Se encontraron vulnerabilidades - Revisar inmediatamente\n")
            if total_puertos > 20:
                self._actualizar_texto_seguro("ATENCION: Muchos puertos abiertos - Revisar superficie de ataque\n")
            self._actualizar_texto_seguro("🔵 Revisar logs detallados en el módulo SIEM\n")
            self._actualizar_texto_seguro("🔵 Considerar monitoreo FIM de archivos críticos\n\n")
            
            self._actualizar_texto_seguro("=" * 70 + "\n")
            self._actualizar_texto_seguro("        ESCANEO KALI 2025 COMPLETADO EXITOSAMENTE\n")
            self._actualizar_texto_seguro("=" * 70 + "\n")
            
            self._log_terminal("CONTROLADOR Escaneo Kali 2025 completado con éxito", "ESCANEADOR", "SUCCESS")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error mostrando resultados consolidados: {str(e)}\n")
            self._log_terminal(f"Error mostrando resultados: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _ejecutar_escaneo_emergencia(self):
        """Escaneo de emergencia cuando el controlador no está disponible."""
        try:
            self._actualizar_texto_seguro("\n=== MODO EMERGENCIA - ESCANEO DIRECTO ===\n\n")
            self._log_terminal("Ejecutando escaneo de emergencia", "ESCANEADOR", "WARNING")
            
            import subprocess
            import os
            
            # 1. Información del sistema
            self._actualizar_texto_seguro("--- INFORMACIÓN DEL SISTEMA ---\n")
            try:
                resultado = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    self._actualizar_texto_seguro(f"Sistema: {resultado.stdout.strip()}\n")
            except:
                pass
            
            try:
                resultado = subprocess.run(['whoami'], capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    self._actualizar_texto_seguro(f"Usuario: {resultado.stdout.strip()}\n")
            except:
                pass
            
            # 2. Red y conectividad
            self._actualizar_texto_seguro("\n--- ANÁLISIS DE RED ---\n")
            try:
                resultado = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')
                    interfaces = [l.strip() for l in lineas if 'inet ' in l and '127.0.0.1' not in l][:3]
                    for interfaz in interfaces:
                        self._actualizar_texto_seguro(f"Interfaz: {interfaz}\n")
            except:
                pass
            
            # 3. Puertos locales
            try:
                resultado = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = [l for l in resultado.stdout.split('\n') if 'LISTEN' in l][:5]
                    if lineas:
                        self._actualizar_texto_seguro(f"\nPuertos en escucha: {len(lineas)}\n")
                        for linea in lineas:
                            self._actualizar_texto_seguro(f"  {linea.strip()}\n")
            except:
                pass
            
            # 4. Procesos críticos
            self._actualizar_texto_seguro("\n--- PROCESOS DEL SISTEMA ---\n")
            try:
                resultado = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:6]  # Primeros 5 procesos
                    for linea in lineas:
                        if linea.strip():
                            campos = linea.split()
                            if len(campos) >= 11:
                                usuario = campos[0]
                                cpu = campos[2]
                                comando = ' '.join(campos[10:])[:50]
                                self._actualizar_texto_seguro(f"  {usuario} ({cpu}% CPU): {comando}\n")
            except:
                pass
            
            self._actualizar_texto_seguro("\n--- ESCANEO DE EMERGENCIA COMPLETADO ---\n")
            self._actualizar_texto_seguro("NOTA: Para un análisis completo, verifique la conexión del controlador\n")
            
            self._log_terminal("Escaneo de emergencia completado", "ESCANEADOR", "INFO")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo de emergencia: {str(e)}\n")
            self._log_terminal(f"Error en escaneo de emergencia: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _mostrar_resultados_escaneo_kali(self, resultado):
        """Mostrar resultados del escaneo Kali 2025 de forma organizada."""
        try:
            datos = resultado.get("resultado", {})
            objetivo = datos.get("objetivo", "N/A")
            
            self._actualizar_texto_seguro("=" * 60 + "\n")
            self._actualizar_texto_seguro("           RESULTADOS DEL ESCANEO KALI 2025\n")
            self._actualizar_texto_seguro("=" * 60 + "\n\n")
            
            # Información general
            self._actualizar_texto_seguro(f"OBJETIVO ESCANEADO: {objetivo}\n")
            self._actualizar_texto_seguro(f"TIMESTAMP: {datos.get('timestamp', 'N/A')}\n")
            
            herramientas = datos.get("herramientas_utilizadas", [])
            self._actualizar_texto_seguro(f"HERRAMIENTAS UTILIZADAS: {', '.join(herramientas)}\n\n")
            
            # Resumen de resultados
            resumen = datos.get("resumen", {})
            if resumen:
                self._actualizar_texto_seguro("--- RESUMEN EJECUTIVO ---\n")
                self._actualizar_texto_seguro(f"Puertos Abiertos: {resumen.get('puertos_abiertos', 0)}\n")
                self._actualizar_texto_seguro(f"Servicios Detectados: {resumen.get('servicios_detectados', 0)}\n")
                self._actualizar_texto_seguro(f"Vulnerabilidades: {resumen.get('vulnerabilidades_encontradas', 0)}\n")
                self._actualizar_texto_seguro(f"Herramientas Utilizadas: {resumen.get('herramientas_utilizadas', 0)}\n\n")
            
            # Resultados por fase
            fases = datos.get("fases", {})
            
            # FASE 1: Masscan
            if "masscan" in fases:
                masscan_data = fases["masscan"]
                self._actualizar_texto_seguro("--- FASE 1: MASSCAN (Reconocimiento Rápido) ---\n")
                if masscan_data.get("exito"):
                    puertos = masscan_data.get("puertos_abiertos", [])
                    self._actualizar_texto_seguro(f"PUERTOS ENCONTRADOS: {len(puertos)}\n")
                    for puerto in puertos[:10]:  # Mostrar primeros 10
                        self._actualizar_texto_seguro(f"  - {puerto['ip']}:{puerto['puerto']}/{puerto['protocolo']}\n")
                    if len(puertos) > 10:
                        self._actualizar_texto_seguro(f"  ... y {len(puertos) - 10} puertos más\n")
                else:
                    self._actualizar_texto_seguro("ERROR en masscan o no ejecutado\n")
                self._actualizar_texto_seguro("\n")
            
            # FASE 2: Nmap
            if "nmap" in fases:
                nmap_data = fases["nmap"]
                self._actualizar_texto_seguro("--- FASE 2: NMAP (Análisis Detallado) ---\n")
                if nmap_data.get("exito"):
                    servicios = nmap_data.get("servicios", [])
                    self._actualizar_texto_seguro(f"SERVICIOS IDENTIFICADOS: {len(servicios)}\n")
                    for servicio in servicios[:8]:  # Mostrar primeros 8
                        puerto = servicio.get("puerto", "N/A")
                        protocolo = servicio.get("protocolo", "N/A")
                        servicio_name = servicio.get("servicio", "desconocido")
                        version = servicio.get("version", "")
                        self._actualizar_texto_seguro(f"  - Puerto {puerto}/{protocolo}: {servicio_name} {version}\n")
                    if len(servicios) > 8:
                        self._actualizar_texto_seguro(f"  ... y {len(servicios) - 8} servicios más\n")
                    
                    # Información del sistema
                    if "sistema_operativo" in nmap_data:
                        self._actualizar_texto_seguro(f"SISTEMA OPERATIVO: {nmap_data['sistema_operativo']}\n")
                else:
                    self._actualizar_texto_seguro("ERROR en nmap o no ejecutado\n")
                self._actualizar_texto_seguro("\n")
            
            # FASE 3: Nuclei
            if "nuclei" in fases:
                nuclei_data = fases["nuclei"]
                self._actualizar_texto_seguro("--- FASE 3: NUCLEI (Detección de Vulnerabilidades) ---\n")
                if nuclei_data.get("exito"):
                    vulnerabilidades = nuclei_data.get("vulnerabilidades", [])
                    if vulnerabilidades:
                        self._actualizar_texto_seguro(f"VULNERABILIDADES ENCONTRADAS: {len(vulnerabilidades)}\n")
                        for vuln in vulnerabilidades[:5]:  # Mostrar primeras 5
                            self._actualizar_texto_seguro(f"  - {vuln.get('template', 'N/A')}: {vuln.get('descripcion', 'Sin descripción')}\n")
                        if len(vulnerabilidades) > 5:
                            self._actualizar_texto_seguro(f"  ... y {len(vulnerabilidades) - 5} vulnerabilidades más\n")
                    else:
                        self._actualizar_texto_seguro("No se encontraron vulnerabilidades conocidas\n")
                else:
                    self._actualizar_texto_seguro("ERROR en nuclei o no ejecutado\n")
                self._actualizar_texto_seguro("\n")
            
            # Fases web (Gobuster, FFUF)
            fases_web = [k for k in fases.keys() if k.startswith(("gobuster_", "ffuf_"))]
            if fases_web:
                self._actualizar_texto_seguro("--- FASES WEB: GOBUSTER & FFUF ---\n")
                for fase_web in fases_web[:3]:  # Mostrar primeras 3
                    data = fases[fase_web]
                    self._actualizar_texto_seguro(f"{fase_web.upper()}: ")
                    if data.get("exito"):
                        directorios = data.get("directorios_encontrados", [])
                        self._actualizar_texto_seguro(f"{len(directorios)} elementos encontrados\n")
                    else:
                        self._actualizar_texto_seguro("No ejecutado o error\n")
                self._actualizar_texto_seguro("\n")
            
            # Recomendaciones finales
            self._actualizar_texto_seguro("--- RECOMENDACIONES ---\n")
            if resumen.get("vulnerabilidades_encontradas", 0) > 0:
                self._actualizar_texto_seguro("• PRIORIDAD ALTA: Revisar vulnerabilidades encontradas\n")
            if resumen.get("puertos_abiertos", 0) > 10:
                self._actualizar_texto_seguro("• REVISAR: Gran cantidad de puertos abiertos detectados\n")
            self._actualizar_texto_seguro("• Revisar logs completos en el módulo SIEM\n")
            self._actualizar_texto_seguro("• Considerar análisis de archivos críticos en FIM\n\n")
            
            self._actualizar_texto_seguro("=" * 60 + "\n")
            self._actualizar_texto_seguro("           ESCANEO KALI 2025 COMPLETADO\n")
            self._actualizar_texto_seguro("=" * 60 + "\n")
            
            self._log_terminal("CONTROLADOR Escaneo Kali 2025 completado exitosamente", "ESCANEADOR", "SUCCESS")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error mostrando resultados: {str(e)}\n")
            self._log_terminal(f"Error mostrando resultados: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _ejecutar_escaneo_basico_fallback(self):
        """Escaneo básico como fallback cuando el controlador avanzado no está disponible."""
        try:
            self._actualizar_texto_seguro("\n=== MODO FALLBACK: ESCANEO DIRECTO ===\n\n")
            self._log_terminal("Ejecutando escaneo básico directo", "ESCANEADOR", "WARNING")
            
            import subprocess
            import os
            
            # Variables para contar fases
            fases_completadas = 0
            fases_con_error = 0
            total_fases = 7
            
            # FASE 1: Información del sistema
            try:
                self._log_terminal("FASE 1: Recopilando información del sistema", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("--- FASE 1: INFORMACIÓN DEL SISTEMA ---\n")
                
                resultado = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    self._actualizar_texto_seguro(f"Sistema: {resultado.stdout.strip()}\n")
                
                resultado = subprocess.run(['whoami'], capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    self._actualizar_texto_seguro(f"Usuario actual: {resultado.stdout.strip()}\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 1 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 1: {str(e)}", "ESCANEADOR", "ERROR")
            
            # FASE 2: Análisis de red básico
            try:
                self._log_terminal("FASE 2: Análisis básico de red", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("\n--- FASE 2: ANÁLISIS DE RED ---\n")
                
                # Interfaces de red
                resultado = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')
                    interfaces_activas = [l.strip() for l in lineas if 'inet ' in l and '127.0.0.1' not in l]
                    self._actualizar_texto_seguro(f"Interfaces activas: {len(interfaces_activas)}\n")
                    for interfaz in interfaces_activas[:3]:
                        self._actualizar_texto_seguro(f"  {interfaz}\n")
                
                # Gateway
                resultado = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    self._actualizar_texto_seguro(f"Gateway: {resultado.stdout.strip()}\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 2 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 2: {str(e)}", "ESCANEADOR", "ERROR")
            
            # FASE 3: Puertos en escucha
            try:
                self._log_terminal("FASE 3: Verificando puertos en escucha", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("\n--- FASE 3: PUERTOS EN ESCUCHA ---\n")
                
                resultado = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = [l for l in resultado.stdout.split('\n') if 'LISTEN' in l]
                    self._actualizar_texto_seguro(f"Puertos TCP en escucha: {len(lineas)}\n")
                    for linea in lineas[:5]:  # Mostrar primeros 5
                        self._actualizar_texto_seguro(f"  {linea.strip()}\n")
                    if len(lineas) > 5:
                        self._actualizar_texto_seguro(f"  ... y {len(lineas) - 5} puertos más\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 3 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 3: {str(e)}", "ESCANEADOR", "ERROR")
            
            # FASE 4: Procesos activos
            try:
                self._log_terminal("FASE 4: Analizando procesos activos", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("\n--- FASE 4: PROCESOS CRÍTICOS ---\n")
                
                resultado = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:8]  # Primeros 7 procesos
                    self._actualizar_texto_seguro("Top procesos por CPU:\n")
                    for linea in lineas:
                        if linea.strip():
                            campos = linea.split()
                            if len(campos) >= 11:
                                usuario = campos[0]
                                cpu = campos[2]
                                comando = ' '.join(campos[10:])[:40]
                                self._actualizar_texto_seguro(f"  {usuario} ({cpu}%): {comando}\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 4 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 4: {str(e)}", "ESCANEADOR", "ERROR")
            
            # FASE 5: Servicios del sistema
            try:
                self._log_terminal("FASE 5: Verificando servicios del sistema", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("\n--- FASE 5: SERVICIOS ACTIVOS ---\n")
                
                resultado = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager'], 
                                         capture_output=True, text=True, timeout=15)
                if resultado.returncode == 0:
                    lineas = [l for l in resultado.stdout.split('\n') if '.service' in l and 'running' in l]
                    self._actualizar_texto_seguro(f"Servicios activos: {len(lineas)}\n")
                    for linea in lineas[:6]:  # Mostrar primeros 6
                        servicio = linea.split()[0] if linea.split() else linea.strip()
                        self._actualizar_texto_seguro(f"  {servicio}\n")
                    if len(lineas) > 6:
                        self._actualizar_texto_seguro(f"  ... y {len(lineas) - 6} servicios más\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 5 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 5: {str(e)}", "ESCANEADOR", "ERROR")
            
            # FASE 6: Verificación de herramientas de seguridad
            try:
                self._log_terminal("FASE 6: Verificando herramientas de seguridad disponibles", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("\n--- FASE 6: HERRAMIENTAS DE SEGURIDAD ---\n")
                
                herramientas = ['nmap', 'masscan', 'gobuster', 'nuclei', 'nikto', 'rustscan']
                disponibles = []
                
                for herramienta in herramientas:
                    try:
                        resultado = subprocess.run(['which', herramienta], capture_output=True, text=True, timeout=3)
                        if resultado.returncode == 0:
                            disponibles.append(herramienta)
                            self._actualizar_texto_seguro(f"  CONTROLADOR {herramienta}: {resultado.stdout.strip()}\n")
                        else:
                            self._actualizar_texto_seguro(f"  ERROR {herramienta}: No disponible\n")
                    except:
                        self._actualizar_texto_seguro(f"  ? {herramienta}: Error verificando\n")
                
                self._actualizar_texto_seguro(f"\nHerramientas disponibles: {len(disponibles)}/{len(herramientas)}\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 6 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 6: {str(e)}", "ESCANEADOR", "ERROR")
            
            # FASE 7: Resumen de seguridad
            try:
                self._log_terminal("FASE 7: Generando resumen de seguridad", "ESCANEADOR", "INFO")
                self._actualizar_texto_seguro("\n--- FASE 7: RESUMEN DE SEGURIDAD ---\n")
                
                # Verificar si es Kali Linux
                try:
                    resultado = subprocess.run(['cat', '/etc/os-release'], capture_output=True, text=True, timeout=5)
                    if 'kali' in resultado.stdout.lower():
                        self._actualizar_texto_seguro("CONTROLADOR Sistema: Kali Linux detectado\n")
                    else:
                        self._actualizar_texto_seguro("WARNING Sistema: No es Kali Linux\n")
                except:
                    pass
                
                # Estado general
                self._actualizar_texto_seguro(f"CONTROLADOR Fases completadas: {fases_completadas}/{total_fases}\n")
                if fases_con_error > 0:
                    self._actualizar_texto_seguro(f"WARNING Fases con errores: {fases_con_error}\n")
                
                fases_completadas += 1
                self._log_terminal("CONTROLADOR FASE 7 completada", "ESCANEADOR", "SUCCESS")
                
            except Exception as e:
                fases_con_error += 1
                self._log_terminal(f"ERROR ERROR en FASE 7: {str(e)}", "ESCANEADOR", "ERROR")
            
            # Resumen final
            self._actualizar_texto_seguro("\n" + "=" * 60 + "\n")
            self._actualizar_texto_seguro("RESUMEN DEL ESCANEO BÁSICO\n")
            self._actualizar_texto_seguro("=" * 60 + "\n")
            self._actualizar_texto_seguro(f"Total de fases: {total_fases}\n")
            self._actualizar_texto_seguro(f"Fases completadas: {fases_completadas}\n")
            self._actualizar_texto_seguro(f"Fases con errores: {fases_con_error}\n\n")
            
            if fases_con_error == 0:
                self._actualizar_texto_seguro("OK ESCANEO COMPLETADO SIN ERRORES\n")
                self._log_terminal("[EXITO] Escaneo básico completado exitosamente", "ESCANEADOR", "SUCCESS")
            elif fases_completadas > fases_con_error:
                self._actualizar_texto_seguro("WARNING ESCANEO COMPLETADO CON ADVERTENCIAS\n")
                self._log_terminal("WARNING Escaneo básico completado con advertencias", "ESCANEADOR", "WARNING")
            else:
                self._actualizar_texto_seguro("ERROR ESCANEO COMPLETADO CON ERRORES\n")
                self._log_terminal("ERROR Escaneo básico completado con errores", "ESCANEADOR", "ERROR")
            
            self._actualizar_texto_seguro("\nNOTA: Para análisis completo, use el escaneador avanzado Kali 2025\n")
            self._actualizar_texto_seguro("=" * 60 + "\n")
            
        except Exception as e:
            self._log_terminal(f"Error crítico en escaneo básico: {str(e)}", "ESCANEADOR", "ERROR")
            self._actualizar_texto_seguro(f"ERROR CRÍTICO: {str(e)}\n")
    
    def _analizar_amenazas_detectadas(self, resultados):
        """Analizar resultados en busca de amenazas y vulnerabilidades."""
        try:
            # Analizar puertos sospechosos
            puertos_peligrosos = {
                '22': 'SSH - Posible acceso remoto',
                '23': 'Telnet - Protocolo inseguro',
                '25': 'SMTP - Servidor de correo',
                '53': 'DNS - Servidor de nombres',
                '80': 'HTTP - Servidor web',
                '135': 'RPC - Servicio Windows crítico',
                '139': 'NetBIOS - Compartición Windows',
                '443': 'HTTPS - Servidor web seguro',
                '445': 'SMB - Compartición archivos Windows',
                '993': 'IMAPS - Correo seguro',
                '995': 'POP3S - Correo seguro',
                '3389': 'RDP - Escritorio remoto Windows'
            }
            
            puertos_encontrados = resultados.get('puertos', [])
            if puertos_encontrados:
                self._log_terminal(f"🔌 Detectados {len(puertos_encontrados)} puertos activos", "ESCANEADOR", "WARNING")
                
                for puerto_info in puertos_encontrados:
                    # Extraer número de puerto de la información
                    for puerto_num, descripcion in puertos_peligrosos.items():
                        if puerto_num in str(puerto_info):
                            self._log_terminal(f"ALERTA PUERTO CRÍTICO: {puerto_num} - {descripcion}", "ESCANEADOR", "WARNING")
                            break
            
            # Analizar procesos sospechosos
            procesos = resultados.get('procesos', [])
            procesos_sospechosos = [
                'nc', 'netcat', 'ncat',  # Herramientas de red
                'python', 'perl', 'ruby',  # Interpretes (pueden ejecutar malware)
                'wget', 'curl',  # Descargas
                'ssh', 'telnet',  # Acceso remoto
                'tor', 'i2p',  # Anonimización
            ]
            
            for proceso in procesos[:20]:  # Analizar primeros 20 procesos
                proceso_lower = proceso.lower()
                for sospechoso in procesos_sospechosos:
                    if sospechoso in proceso_lower:
                        self._log_terminal(f"ALERTA PROCESO SOSPECHOSO: {proceso.strip()}", "ESCANEADOR", "WARNING")
                        break
            
            # Análisis de configuración de seguridad
            analisis = resultados.get('análisis', [])
            if analisis:
                for item in analisis:
                    if any(palabra in item.lower() for palabra in ['error', 'fail', 'vulnerable', 'insecure', 'weak']):
                        self._log_terminal(f"🔓 VULNERABILIDAD: {item}", "ESCANEADOR", "ERROR")
                    elif any(palabra in item.lower() for palabra in ['warning', 'caution', 'deprecated']):
                        self._log_terminal(f"ADVERTENCIA: {item}", "ESCANEADOR", "WARNING")
                        
        except Exception as e:
            self._log_terminal(f"ERROR analizando amenazas: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _mostrar_resultados_escaneo(self, resultados):
        """Mostrar resultados en la UI y en el terminal integrado."""
        if not self.proceso_activo:
            return
        
        # Log detallado en el terminal integrado
        self._log_terminal("MOSTRANDO resultados del escaneo", "ESCANEADOR", "INFO")
        
        # Mostrar en la UI tradicional
        self.text_resultados.insert(tk.END, "=== PUERTOS ===\n")
        puertos_encontrados = resultados.get('puertos', [])
        for linea in puertos_encontrados:
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        # Log de puertos al terminal integrado
        if puertos_encontrados:
            self._log_terminal(f"🔌 Encontrados {len(puertos_encontrados)} puertos", "ESCANEADOR", "SUCCESS")
            for puerto in puertos_encontrados[:3]:  # Mostrar solo los primeros 3
                self._log_terminal(f"  └─ {puerto}", "ESCANEADOR", "INFO")
        else:
            self._log_terminal("🔌 No se encontraron puertos activos", "ESCANEADOR", "INFO")
        
        self.text_resultados.insert(tk.END, "\n=== PROCESOS ===\n")
        procesos_encontrados = resultados.get('procesos', [])[:10]  # Mostrar solo 10
        for linea in procesos_encontrados:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de procesos al terminal integrado
        if procesos_encontrados:
            self._log_terminal(f"ENCONTRADOS {len(procesos_encontrados)} procesos", "ESCANEADOR", "SUCCESS")
        
        self.text_resultados.insert(tk.END, "\n=== ANÁLISIS ===\n")
        analisis = resultados.get('análisis', [])
        for linea in analisis:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de análisis al terminal integrado
        if analisis:
            self._log_terminal(f"ANÁLISIS completado: {len(analisis)} elementos", "ESCANEADOR", "SUCCESS")
            
        # Resumen final en terminal integrado
        total_elementos = len(puertos_encontrados) + len(procesos_encontrados) + len(analisis)
        self._log_terminal(f"COMPLETADO Escaneo finalizado: {total_elementos} elementos analizados", "ESCANEADOR", "SUCCESS")
    
    def _mostrar_error_escaneo(self, error):
        """Mostrar error en la UI."""
        self.text_resultados.insert(tk.END, f"\n Error durante el escaneo: {error}\n")
    
    def _finalizar_escaneo(self):
        """Finalizar el proceso de escaneo."""
        self.flag_proceso.clear()
        self.btn_escanear.config(state="normal")
        self.btn_cancelar_escaneo.config(state="disabled")
        # Resetear barra de progreso
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Estado: Listo")
        self.thread_escaneo = None

    def _escaneo_integral_kali(self, objetivo):
        """Escaneo integral usando herramientas nativas de Kali Linux.""" 
        import subprocess
        import time
        
        resultados = {
            "objetivo": objetivo,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "fases": {},
            "resumen": {"puertos_abiertos": 0, "servicios_detectados": 0, "vulnerabilidades_encontradas": 0}
        }
        
        self._actualizar_texto_seguro(f"\n=== ESCANEO INTEGRAL KALI - {objetivo} ===\n\n")
        
        # FASE 1: Ping y conectividad básica
        self._actualizar_texto_seguro("FASE 1: Verificando conectividad...\n")
        try:
            ping_result = subprocess.run(['ping', '-c', '3', objetivo], 
                                       capture_output=True, text=True, timeout=15)
            if ping_result.returncode == 0:
                self._actualizar_texto_seguro(f"OK {objetivo} responde a ping\n")
                resultados["fases"]["ping"] = {"exito": True, "responde": True}
            else:
                self._actualizar_texto_seguro(f"WARNING {objetivo} no responde a ping (pero puede estar activo)\n")
                resultados["fases"]["ping"] = {"exito": True, "responde": False}
        except Exception as e:
            self._actualizar_texto_seguro(f"ERROR en ping: {str(e)}\n")
            resultados["fases"]["ping"] = {"exito": False, "error": str(e)}
        
        # FASE 2: Escaneo rápido de puertos con nmap
        self._actualizar_texto_seguro("\nFASE 2: Escaneo rápido de puertos (nmap)...\n")
        puertos_abiertos = []
        try:
            nmap_result = subprocess.run(['nmap', '-T4', '-F', objetivo], 
                                       capture_output=True, text=True, timeout=60)
            if nmap_result.returncode == 0:
                lineas = nmap_result.stdout.split('\n')
                puertos_lineas = [l for l in lineas if '/tcp' in l and 'open' in l]
                for linea in puertos_lineas:
                    puerto = linea.split('/')[0].strip()
                    servicio = linea.split()[-1] if len(linea.split()) > 2 else "unknown"
                    puertos_abiertos.append({"puerto": puerto, "servicio": servicio})
                    self._actualizar_texto_seguro(f"  Puerto {puerto}/tcp: {servicio}\n")
                
                resultados["fases"]["nmap"] = {
                    "exito": True, 
                    "puertos": puertos_abiertos,
                    "total_puertos": len(puertos_abiertos)
                }
                resultados["resumen"]["puertos_abiertos"] = len(puertos_abiertos)
                self._actualizar_texto_seguro(f"RESULTADO: {len(puertos_abiertos)} puertos abiertos encontrados\n")
            else:
                self._actualizar_texto_seguro("ERROR: nmap falló\n")
                resultados["fases"]["nmap"] = {"exito": False}
        except Exception as e:
            self._actualizar_texto_seguro(f"ERROR en nmap: {str(e)}\n")
            resultados["fases"]["nmap"] = {"exito": False, "error": str(e)}
        
        # FASE 3: Detección de servicios si hay puertos abiertos
        if puertos_abiertos:
            self._actualizar_texto_seguro("\nFASE 3: Detección de servicios y versiones...\n")
            try:
                puertos_str = ','.join([p["puerto"] for p in puertos_abiertos[:10]])  # Limitar a 10
                nmap_sv_result = subprocess.run(['nmap', '-sV', '-p', puertos_str, objetivo], 
                                              capture_output=True, text=True, timeout=120)
                if nmap_sv_result.returncode == 0:
                    self._actualizar_texto_seguro("Detección de servicios completada:\n")
                    servicios_detectados = 0
                    lineas = nmap_sv_result.stdout.split('\n')
                    for linea in lineas:
                        if '/tcp' in linea and 'open' in linea:
                            servicios_detectados += 1
                            self._actualizar_texto_seguro(f"  {linea.strip()}\n")
                    
                    resultados["fases"]["deteccion_servicios"] = {"exito": True, "servicios": servicios_detectados}
                    resultados["resumen"]["servicios_detectados"] = servicios_detectados
                else:
                    self._actualizar_texto_seguro("ERROR en detección de servicios\n")
                    resultados["fases"]["deteccion_servicios"] = {"exito": False}
            except Exception as e:
                self._actualizar_texto_seguro(f"ERROR en detección de servicios: {str(e)}\n")
                resultados["fases"]["deteccion_servicios"] = {"exito": False, "error": str(e)}
        
        # FASE 4: Escaneo de scripts básicos si es localhost
        if objetivo == "127.0.0.1" or objetivo == "localhost":
            self._actualizar_texto_seguro("\nFASE 4: Análisis local del sistema...\n")
            try:
                # Verificar procesos críticos
                ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=30)
                if ps_result.returncode == 0:
                    procesos = len(ps_result.stdout.split('\n')) - 1
                    self._actualizar_texto_seguro(f"Procesos activos: {procesos}\n")
                
                # Verificar espacio en disco
                df_result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=10)
                if df_result.returncode == 0:
                    self._actualizar_texto_seguro("Espacio en disco:\n")
                    lineas = df_result.stdout.split('\n')[1:4]  # Primeras 3 líneas
                    for linea in lineas:
                        if linea.strip():
                            self._actualizar_texto_seguro(f"  {linea}\n")
                            
                resultados["fases"]["analisis_local"] = {"exito": True}
            except Exception as e:
                self._actualizar_texto_seguro(f"ERROR en análisis local: {str(e)}\n")
                resultados["fases"]["analisis_local"] = {"exito": False, "error": str(e)}
        
        self._actualizar_texto_seguro(f"\n=== ESCANEO COMPLETADO: {objetivo} ===\n")
        return {"exito": True, "resultado": resultados}

    def _validar_herramientas_escaneo(self):
        """Validar que las herramientas de escaneo estén disponibles."""
        import subprocess
        
        herramientas = {
            'nmap': 'Escaneador de red principal',
            'masscan': 'Escaneador rápido de puertos',
            'rustscan': 'Escaneador ultrarrápido',
            'nuclei': 'Motor de detección de vulnerabilidades',
            'gobuster': 'Enumeración de directorios',
            'ffuf': 'Fuzzer web avanzado'
        }
        
        herramientas_disponibles = []
        herramientas_faltantes = []
        
        self._actualizar_texto_seguro("\n=== VALIDACIÓN DE HERRAMIENTAS DE ESCANEO ===\n")
        
        for herramienta, descripcion in herramientas.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    herramientas_disponibles.append(herramienta)
                    self._actualizar_texto_seguro(f"OK {herramienta}: {descripcion}\n")
                else:
                    herramientas_faltantes.append(herramienta)
                    self._actualizar_texto_seguro(f"FALTA {herramienta}: {descripcion}\n")
            except:
                herramientas_faltantes.append(herramienta)
                self._actualizar_texto_seguro(f"ERROR {herramienta}: No se pudo verificar\n")
        
        self._actualizar_texto_seguro(f"\nHERRAMIENTAS DISPONIBLES: {len(herramientas_disponibles)}/{len(herramientas)}\n")
        
        if herramientas_faltantes:
            self._actualizar_texto_seguro("\nPARA INSTALAR HERRAMIENTAS FALTANTES:\n")
            self._actualizar_texto_seguro("sudo apt update && sudo apt install -y " + " ".join(herramientas_faltantes) + "\n")
        
        self._actualizar_texto_seguro("=" * 50 + "\n\n")
        
        return {
            "disponibles": herramientas_disponibles,
            "faltantes": herramientas_faltantes,
            "total": len(herramientas_disponibles)
        }

    def _escaneo_avanzado_multiherramienta(self, objetivo):
        """Escaneo avanzado usando múltiples herramientas profesionales."""
        import subprocess
        import json
        from datetime import datetime
        
        self._actualizar_texto_seguro(f"\n=== ESCANEO AVANZADO MULTIHERRAMIENTA: {objetivo} ===\n")
        
        # Validar herramientas primero
        herramientas_status = self._validar_herramientas_escaneo()
        herramientas_disponibles = herramientas_status["disponibles"]
        
        if not herramientas_disponibles:
            self._actualizar_texto_seguro("ERROR: No hay herramientas de escaneo disponibles.\n")
            return {"exito": False, "error": "Sin herramientas"}
        
        resultados = {
            "objetivo": objetivo,
            "timestamp": datetime.now().isoformat(),
            "herramientas_usadas": [],
            "puertos_encontrados": [],
            "servicios_detectados": [],
            "vulnerabilidades": [],
            "directorios_web": []
        }
        
        # FASE 1: Detección rápida con rustscan
        if 'rustscan' in herramientas_disponibles:
            self._actualizar_texto_seguro("\nFASE 1: Detección rápida de puertos (rustscan)\n")
            try:
                cmd = ['rustscan', '-a', objetivo, '--range', '1-65535', '--ulimit', '5000']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.stdout:
                    resultados["herramientas_usadas"].append("rustscan")
                    # Parsear puertos encontrados
                    for line in result.stdout.split('\n'):
                        if 'Open' in line and objetivo in line:
                            puerto = line.split()[-1] if line.split() else ""
                            if puerto.isdigit():
                                resultados["puertos_encontrados"].append(int(puerto))
                    self._actualizar_texto_seguro(f"Puertos encontrados: {len(resultados['puertos_encontrados'])}\n")
            except Exception as e:
                self._actualizar_texto_seguro(f"Error en rustscan: {str(e)}\n")
        
        # FASE 2: Escaneo masivo con masscan (si no hay rustscan)
        elif 'masscan' in herramientas_disponibles:
            self._actualizar_texto_seguro("\nFASE 1: Escaneo masivo de puertos (masscan)\n")
            try:
                cmd = ['masscan', objetivo, '-p1-65535', '--rate=1000']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.stdout:
                    resultados["herramientas_usadas"].append("masscan")
                    # Parsear resultados de masscan
                    for line in result.stdout.split('\n'):
                        if 'open' in line.lower():
                            parts = line.split()
                            for part in parts:
                                if part.isdigit():
                                    resultados["puertos_encontrados"].append(int(part))
                    self._actualizar_texto_seguro(f"Puertos encontrados: {len(resultados['puertos_encontrados'])}\n")
            except Exception as e:
                self._actualizar_texto_seguro(f"Error en masscan: {str(e)}\n")
        
        # FASE 3: Detección de servicios con nmap
        if 'nmap' in herramientas_disponibles and resultados["puertos_encontrados"]:
            self._actualizar_texto_seguro("\nFASE 2: Detección de servicios (nmap)\n")
            try:
                puertos_str = ','.join(map(str, resultados["puertos_encontrados"][:50]))  # Limitar a 50 puertos
                cmd = ['nmap', '-sV', '-sC', objetivo, '-p', puertos_str]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    resultados["herramientas_usadas"].append("nmap")
                    # Parsear servicios
                    for line in result.stdout.split('\n'):
                        if '/tcp' in line or '/udp' in line:
                            servicio_info = line.strip()
                            if servicio_info:
                                resultados["servicios_detectados"].append(servicio_info)
                    self._actualizar_texto_seguro(f"Servicios detectados: {len(resultados['servicios_detectados'])}\n")
            except Exception as e:
                self._actualizar_texto_seguro(f"Error en nmap: {str(e)}\n")
        
        # FASE 4: Detección de vulnerabilidades con nuclei
        if 'nuclei' in herramientas_disponibles:
            self._actualizar_texto_seguro("\nFASE 3: Detección de vulnerabilidades (nuclei)\n")
            try:
                cmd = ['nuclei', '-u', f'http://{objetivo}', '-severity', 'high,critical', '-silent']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                if result.stdout:
                    resultados["herramientas_usadas"].append("nuclei")
                    vulnerabilidades = result.stdout.strip().split('\n')
                    resultados["vulnerabilidades"] = [v for v in vulnerabilidades if v.strip()]
                    self._actualizar_texto_seguro(f"Vulnerabilidades encontradas: {len(resultados['vulnerabilidades'])}\n")
            except Exception as e:
                self._actualizar_texto_seguro(f"Error en nuclei: {str(e)}\n")
        
        # FASE 5: Enumeración de directorios web con gobuster
        if 'gobuster' in herramientas_disponibles and any('80' in str(p) or '443' in str(p) or '8080' in str(p) for p in resultados["puertos_encontrados"]):
            self._actualizar_texto_seguro("\nFASE 4: Enumeración de directorios web (gobuster)\n")
            try:
                # Usar wordlist común de Kali
                wordlist = '/usr/share/wordlists/dirb/common.txt'
                cmd = ['gobuster', 'dir', '-u', f'http://{objetivo}', '-w', wordlist, '-q']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.stdout:
                    resultados["herramientas_usadas"].append("gobuster")
                    directorios = result.stdout.strip().split('\n')
                    resultados["directorios_web"] = [d for d in directorios if d.strip()]
                    self._actualizar_texto_seguro(f"Directorios encontrados: {len(resultados['directorios_web'])}\n")
            except Exception as e:
                self._actualizar_texto_seguro(f"Error en gobuster: {str(e)}\n")
        
        # Mostrar resumen final
        self._actualizar_texto_seguro("\n=== RESUMEN DEL ESCANEO AVANZADO ===\n")
        self._actualizar_texto_seguro(f"Herramientas utilizadas: {', '.join(resultados['herramientas_usadas'])}\n")
        self._actualizar_texto_seguro(f"Total de puertos encontrados: {len(resultados['puertos_encontrados'])}\n")
        self._actualizar_texto_seguro(f"Servicios detectados: {len(resultados['servicios_detectados'])}\n")
        self._actualizar_texto_seguro(f"Vulnerabilidades: {len(resultados['vulnerabilidades'])}\n")
        self._actualizar_texto_seguro(f"Directorios web: {len(resultados['directorios_web'])}\n")
        self._actualizar_texto_seguro("=" * 50 + "\n\n")
        
        return {"exito": True, "resultado": resultados}

    def _exportar_resultados_escaneo(self, resultados, formato="json"):
        """Exportar resultados de escaneo a archivo."""
        import json
        import os
        from datetime import datetime
        
        try:
            # Crear directorio de reportes si no existe
            directorio_reportes = "/tmp/aresitos_reportes"
            if not os.path.exists(directorio_reportes):
                os.makedirs(directorio_reportes)
            
            # Generar nombre de archivo único
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_archivo = f"escaneo_aresitos_{timestamp}.{formato}"
            ruta_completa = os.path.join(directorio_reportes, nombre_archivo)
            
            if formato == "json":
                with open(ruta_completa, 'w', encoding='utf-8') as f:
                    json.dump(resultados, f, indent=2, ensure_ascii=False, default=str)
            
            elif formato == "txt":
                with open(ruta_completa, 'w', encoding='utf-8') as f:
                    f.write("=== REPORTE DE ESCANEO ARESITOS ===\n")
                    f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    if isinstance(resultados, dict) and "resultado" in resultados:
                        datos = resultados["resultado"]
                        f.write(f"Objetivo: {datos.get('objetivo', 'N/A')}\n")
                        f.write(f"Herramientas utilizadas: {', '.join(datos.get('herramientas_usadas', []))}\n")
                        f.write(f"Puertos encontrados: {len(datos.get('puertos_encontrados', []))}\n")
                        f.write(f"Servicios detectados: {len(datos.get('servicios_detectados', []))}\n")
                        f.write(f"Vulnerabilidades: {len(datos.get('vulnerabilidades', []))}\n\n")
                        
                        if datos.get('puertos_encontrados'):
                            f.write("PUERTOS ABIERTOS:\n")
                            for puerto in datos['puertos_encontrados']:
                                f.write(f"  - {puerto}\n")
                            f.write("\n")
                        
                        if datos.get('servicios_detectados'):
                            f.write("SERVICIOS DETECTADOS:\n")
                            for servicio in datos['servicios_detectados']:
                                f.write(f"  - {servicio}\n")
                            f.write("\n")
                        
                        if datos.get('vulnerabilidades'):
                            f.write("VULNERABILIDADES ENCONTRADAS:\n")
                            for vuln in datos['vulnerabilidades']:
                                f.write(f"  - {vuln}\n")
                            f.write("\n")
            
            self._actualizar_texto_seguro(f"Reporte exportado: {ruta_completa}\n")
            return {"exito": True, "archivo": ruta_completa}
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error al exportar reporte: {str(e)}\n")
            return {"exito": False, "error": str(e)}

    def _escaneo_red_completa(self, rango_red=None):
        """Escaneo completo de una red local."""
        import subprocess
        import ipaddress
        from datetime import datetime
        
        # Detectar red automáticamente si no se especifica
        if not rango_red:
            if DetectorRed:
                try:
                    detector = DetectorRed()
                    redes = detector.obtener_objetivos_escaneo()
                    if redes and len(redes) > 1:  # Si hay más de localhost
                        rango_red = redes[1]  # Usar la primera red que no sea localhost
                    else:
                        rango_red = "192.168.1.0/24"  # Fallback
                except Exception:
                    rango_red = "192.168.1.0/24"  # Fallback
            else:
                rango_red = "192.168.1.0/24"  # Fallback
        
        self._actualizar_texto_seguro(f"\n=== ESCANEO DE RED COMPLETA: {rango_red} ===\n")
        
        try:
            # Validar formato de red
            red = ipaddress.ip_network(rango_red, strict=False)
            self._actualizar_texto_seguro(f"Red válida: {red} ({red.num_addresses} direcciones)\n")
            
            resultados_red = {
                "red": str(red),
                "timestamp": datetime.now().isoformat(),
                "hosts_activos": [],
                "hosts_escaneados": [],
                "total_puertos": 0,
                "servicios_unicos": set()
            }
            
            # FASE 1: Descubrimiento de hosts activos con ping
            self._actualizar_texto_seguro("\nFASE 1: Descubrimiento de hosts activos...\n")
            hosts_activos = []
            
            # Usar nmap para descubrimiento rápido si está disponible
            try:
                cmd = ['nmap', '-sn', str(red)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'Nmap scan report for' in line:
                            ip = line.split()[-1].strip('()')
                            if self._validar_ip(ip):
                                hosts_activos.append(ip)
                                self._actualizar_texto_seguro(f"Host activo: {ip}\n")
            except:
                # Fallback: ping individual
                self._actualizar_texto_seguro("Fallback: usando ping individual...\n")
                for host in list(red.hosts())[:20]:  # Limitar a 20 hosts
                    try:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(host)], 
                                              capture_output=True, timeout=3)
                        if result.returncode == 0:
                            hosts_activos.append(str(host))
                            self._actualizar_texto_seguro(f"Host activo: {host}\n")
                    except:
                        continue
            
            resultados_red["hosts_activos"] = hosts_activos
            self._actualizar_texto_seguro(f"\nHosts activos encontrados: {len(hosts_activos)}\n")
            
            # FASE 2: Escaneo de puertos en hosts activos
            self._actualizar_texto_seguro("\nFASE 2: Escaneo de puertos en hosts activos...\n")
            
            for i, host in enumerate(hosts_activos[:10]):  # Limitar a 10 hosts
                self._actualizar_texto_seguro(f"\nEscaneando host {i+1}/{min(10, len(hosts_activos))}: {host}\n")
                
                # Escaneo rápido de puertos comunes
                try:
                    puertos_comunes = "22,23,53,80,135,139,443,445,993,995,1723,3389,5900,8080"
                    cmd = ['nmap', '-sS', '-T4', host, '-p', puertos_comunes]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    
                    host_info = {
                        "ip": host,
                        "puertos_abiertos": [],
                        "servicios": [],
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    if result.stdout:
                        for line in result.stdout.split('\n'):
                            if '/tcp' in line and 'open' in line:
                                puerto_info = line.strip()
                                puerto_num = puerto_info.split('/')[0]
                                if puerto_num.isdigit():
                                    host_info["puertos_abiertos"].append(int(puerto_num))
                                    host_info["servicios"].append(puerto_info)
                                    resultados_red["servicios_unicos"].add(puerto_info.split()[2] if len(puerto_info.split()) > 2 else "unknown")
                    
                    if host_info["puertos_abiertos"]:
                        resultados_red["hosts_escaneados"].append(host_info)
                        resultados_red["total_puertos"] += len(host_info["puertos_abiertos"])
                        self._actualizar_texto_seguro(f"  Puertos abiertos: {host_info['puertos_abiertos']}\n")
                
                except Exception as e:
                    self._actualizar_texto_seguro(f"  Error escaneando {host}: {str(e)}\n")
            
            # Convertir set a lista para JSON
            resultados_red["servicios_unicos"] = list(resultados_red["servicios_unicos"])
            
            # Mostrar resumen
            self._actualizar_texto_seguro(f"\n=== RESUMEN DEL ESCANEO DE RED ===\n")
            self._actualizar_texto_seguro(f"Red escaneada: {rango_red}\n")
            self._actualizar_texto_seguro(f"Hosts activos: {len(hosts_activos)}\n")
            self._actualizar_texto_seguro(f"Hosts con puertos abiertos: {len(resultados_red['hosts_escaneados'])}\n")
            self._actualizar_texto_seguro(f"Total de puertos abiertos: {resultados_red['total_puertos']}\n")
            self._actualizar_texto_seguro(f"Servicios únicos: {len(resultados_red['servicios_unicos'])}\n")
            self._actualizar_texto_seguro("=" * 50 + "\n\n")
            
            return {"exito": True, "resultado": resultados_red}
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo de red: {str(e)}\n")
            return {"exito": False, "error": str(e)}

    def _validar_ip(self, ip_str):
        """Validar formato de dirección IP."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_str)
            return True
        except:
            return False

    def configurar_tipo_escaneo(self, tipo_escaneo="integral"):
        """Configurar el tipo de escaneo a realizar."""
        tipos_validos = {
            "integral": "Escaneo integral básico con herramientas nativas",
            "avanzado": "Escaneo avanzado con múltiples herramientas",
            "red": "Escaneo completo de red local",
            "rapido": "Escaneo rápido de puertos comunes",
            "profundo": "Escaneo profundo con detección de vulnerabilidades"
        }
        
        if tipo_escaneo not in tipos_validos:
            self._actualizar_texto_seguro(f"Tipo de escaneo inválido: {tipo_escaneo}\n")
            self._actualizar_texto_seguro("Tipos válidos:\n")
            for tipo, desc in tipos_validos.items():
                self._actualizar_texto_seguro(f"  - {tipo}: {desc}\n")
            return False
        
        self.tipo_escaneo_actual = tipo_escaneo
        self._actualizar_texto_seguro(f"Tipo de escaneo configurado: {tipos_validos[tipo_escaneo]}\n")
        return True

    def ejecutar_escaneo_configurado(self, objetivo):
        """Ejecutar escaneo según el tipo configurado."""
        tipo = getattr(self, 'tipo_escaneo_actual', 'integral')
        
        self._actualizar_texto_seguro(f"Ejecutando escaneo tipo '{tipo}' para objetivo: {objetivo}\n")
        
        try:
            if tipo == "integral":
                return self._escaneo_integral_kali(objetivo)
            elif tipo == "avanzado":
                return self._escaneo_avanzado_multiherramienta(objetivo)
            elif tipo == "red":
                # Si el objetivo parece ser una IP, convertir a rango de red
                if "/" not in objetivo and self._validar_ip(objetivo):
                    # Convertir IP individual a rango /24
                    partes = objetivo.split('.')
                    if len(partes) == 4:
                        rango_red = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
                    else:
                        rango_red = objetivo
                else:
                    rango_red = objetivo
                return self._escaneo_red_completa(rango_red)
            elif tipo == "rapido":
                return self._escaneo_rapido_puertos(objetivo)
            elif tipo == "profundo":
                return self._escaneo_profundo_vulnerabilidades(objetivo)
            else:
                return self._escaneo_integral_kali(objetivo)
                
        except Exception as e:
            error_msg = f"Error en escaneo configurado: {str(e)}"
            self._actualizar_texto_seguro(error_msg + "\n")
            return {"exito": False, "error": error_msg}

    def _escaneo_rapido_puertos(self, objetivo):
        """Escaneo rápido de puertos más comunes."""
        import subprocess
        from datetime import datetime
        
        self._actualizar_texto_seguro(f"\n=== ESCANEO RÁPIDO DE PUERTOS: {objetivo} ===\n")
        
        puertos_comunes = "21,22,23,25,53,80,110,135,139,143,443,445,587,993,995,1723,3389,5900,8080,8443"
        
        resultado = {
            "objetivo": objetivo,
            "tipo": "rapido",
            "timestamp": datetime.now().isoformat(),
            "puertos_encontrados": [],
            "tiempo_escaneo": 0
        }
        
        try:
            inicio = datetime.now()
            cmd = ['nmap', '-sS', '-T5', objetivo, '-p', puertos_comunes]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            fin = datetime.now()
            
            resultado["tiempo_escaneo"] = (fin - inicio).total_seconds()
            
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        puerto = line.split('/')[0]
                        if puerto.isdigit():
                            resultado["puertos_encontrados"].append(int(puerto))
                            self._actualizar_texto_seguro(f"Puerto abierto: {line.strip()}\n")
            
            self._actualizar_texto_seguro(f"\nEscaneo completado en {resultado['tiempo_escaneo']:.2f} segundos\n")
            self._actualizar_texto_seguro(f"Puertos abiertos encontrados: {len(resultado['puertos_encontrados'])}\n")
            
            return {"exito": True, "resultado": resultado}
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo rápido: {str(e)}\n")
            return {"exito": False, "error": str(e)}

    def _escaneo_profundo_vulnerabilidades(self, objetivo):
        """Escaneo profundo enfocado en vulnerabilidades."""
        import subprocess
        from datetime import datetime
        
        self._actualizar_texto_seguro(f"\n=== ESCANEO PROFUNDO DE VULNERABILIDADES: {objetivo} ===\n")
        
        resultado = {
            "objetivo": objetivo,
            "tipo": "profundo",
            "timestamp": datetime.now().isoformat(),
            "vulnerabilidades_criticas": [],
            "vulnerabilidades_altas": [],
            "servicios_vulnerables": [],
            "scripts_ejecutados": []
        }
        
        try:
            # Fase 1: Escaneo con scripts de vulnerabilidades de nmap
            self._actualizar_texto_seguro("Fase 1: Ejecutando scripts de vulnerabilidades nmap...\n")
            cmd = ['nmap', '-sV', '--script', 'vuln', objetivo, '-T4']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                resultado["scripts_ejecutados"].append("nmap-vuln")
                lineas = result.stdout.split('\n')
                for i, linea in enumerate(lineas):
                    if 'CVE-' in linea or 'VULNERABLE' in linea:
                        if 'CRITICAL' in linea.upper() or 'HIGH' in linea.upper():
                            resultado["vulnerabilidades_criticas"].append(linea.strip())
                        else:
                            resultado["vulnerabilidades_altas"].append(linea.strip())
                        self._actualizar_texto_seguro(f"Vulnerabilidad: {linea.strip()}\n")
            
            # Fase 2: Nuclei si está disponible
            try:
                self._actualizar_texto_seguro("Fase 2: Ejecutando nuclei para detección avanzada...\n")
                cmd = ['nuclei', '-u', f'http://{objetivo}', '-severity', 'critical,high,medium', '-silent']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                
                if result.stdout:
                    resultado["scripts_ejecutados"].append("nuclei")
                    for linea in result.stdout.strip().split('\n'):
                        if linea.strip():
                            if 'critical' in linea.lower():
                                resultado["vulnerabilidades_criticas"].append(linea.strip())
                            else:
                                resultado["vulnerabilidades_altas"].append(linea.strip())
                            self._actualizar_texto_seguro(f"Nuclei: {linea.strip()}\n")
            except:
                self._actualizar_texto_seguro("Nuclei no disponible, continuando...\n")
            
            # Resumen
            total_vulns = len(resultado["vulnerabilidades_criticas"]) + len(resultado["vulnerabilidades_altas"])
            self._actualizar_texto_seguro(f"\n=== RESUMEN DE VULNERABILIDADES ===\n")
            self._actualizar_texto_seguro(f"Vulnerabilidades críticas: {len(resultado['vulnerabilidades_criticas'])}\n")
            self._actualizar_texto_seguro(f"Vulnerabilidades altas: {len(resultado['vulnerabilidades_altas'])}\n")
            self._actualizar_texto_seguro(f"Total encontradas: {total_vulns}\n")
            self._actualizar_texto_seguro("=" * 50 + "\n\n")
            
            return {"exito": True, "resultado": resultado}
            
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo profundo: {str(e)}\n")
            return {"exito": False, "error": str(e)}

    def obtener_estadisticas_modulo(self):
        """Obtener estadísticas y capacidades del módulo de escaneo."""
        import subprocess
        
        self._actualizar_texto_seguro("\n=== ESTADÍSTICAS DEL MÓDULO DE ESCANEO ARESITOS ===\n")
        
        estadisticas = {
            "version_modulo": "ARESITOS v3.0 - Vista Escaneo Profesional",
            "fecha_revision": "2025-01-02",
            "herramientas_soportadas": {
                "nmap": "Escaneador de red principal",
                "masscan": "Escaneador rápido de puertos",
                "rustscan": "Escaneador ultrarrápido",
                "nuclei": "Motor de detección de vulnerabilidades", 
                "gobuster": "Enumeración de directorios",
                "ffuf": "Fuzzer web avanzado"
            },
            "tipos_escaneo": {
                "integral": "Escaneo completo con herramientas nativas",
                "avanzado": "Escaneo multiherramienta profesional",
                "red": "Escaneo completo de red local",
                "rapido": "Escaneo rápido de puertos comunes",
                "profundo": "Detección profunda de vulnerabilidades"
            },
            "capacidades": [
                "Escaneo autónomo sin dependencias externas",
                "Integración con herramientas nativas de Kali Linux",
                "Exportación de resultados en JSON/TXT",
                "Progress tracking en tiempo real",
                "Logging integrado con terminal",
                "Fallback inteligente si faltan herramientas",
                "Validación automática de herramientas",
                "Escaneo de redes completas",
                "Detección avanzada de vulnerabilidades"
            ]
        }
        
        # Verificar herramientas disponibles
        herramientas_disponibles = self._validar_herramientas_escaneo()
        estadisticas["herramientas_disponibles"] = herramientas_disponibles["disponibles"]
        estadisticas["herramientas_faltantes"] = herramientas_disponibles["faltantes"]
        
        # Mostrar estadísticas
        self._actualizar_texto_seguro(f"Versión: {estadisticas['version_modulo']}\n")
        self._actualizar_texto_seguro(f"Última revisión: {estadisticas['fecha_revision']}\n")
        self._actualizar_texto_seguro(f"Herramientas disponibles: {len(estadisticas['herramientas_disponibles'])}/{len(estadisticas['herramientas_soportadas'])}\n")
        self._actualizar_texto_seguro(f"Tipos de escaneo: {len(estadisticas['tipos_escaneo'])}\n")
        self._actualizar_texto_seguro(f"Capacidades implementadas: {len(estadisticas['capacidades'])}\n")
        
        self._actualizar_texto_seguro("\nCAPACIDADES PRINCIPALES:\n")
        for capacidad in estadisticas["capacidades"]:
            self._actualizar_texto_seguro(f"  OK {capacidad}\n")
        
        self._actualizar_texto_seguro("\nTIPOS DE ESCANEO DISPONIBLES:\n")
        for tipo, descripcion in estadisticas["tipos_escaneo"].items():
            self._actualizar_texto_seguro(f"  • {tipo}: {descripcion}\n")
        
        self._actualizar_texto_seguro("=" * 60 + "\n\n")
        
        return estadisticas

    def cancelar_escaneo(self):
        """Cancelar escaneo usando sistema unificado."""
        # Detener variable de control
        self.proceso_activo = False
        
        # Importar sistema unificado
        from ..utils.detener_procesos import detener_procesos
        
        # Callbacks para la vista
        def callback_actualizacion(mensaje):
            self.text_resultados.insert(tk.END, mensaje)
        
        def callback_habilitar():
            self._log_terminal("Escaneo cancelado completamente", "ESCANEADOR", "INFO")
        
        # Usar sistema unificado
        detener_procesos.cancelar_escaneo(callback_actualizacion, callback_habilitar)

    def _verificar_herramientas_kali(self):
        """Verificar herramientas esenciales de Kali Linux."""
        import subprocess
        
        herramientas_kali = [
            'nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'sqlmap',
            'metasploit', 'msfconsole', 'john', 'hashcat', 'hydra',
            'aircrack-ng', 'wireshark', 'tcpdump', 'netcat', 'socat',
            'binwalk', 'foremost', 'volatility', 'yara', 'chkrootkit',
            'rkhunter', 'clamscan', 'lynis'
        ]
        
        herramientas_encontradas = 0
        total_herramientas = len(herramientas_kali)
        
        for herramienta in herramientas_kali:
            try:
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, text=True, timeout=3)
                if resultado.returncode == 0:
                    ruta = resultado.stdout.strip()
                    self._log_terminal(f"OK: {herramienta} disponible en {ruta}", "VERIFICADOR", "INFO")
                    herramientas_encontradas += 1
                else:
                    self._log_terminal(f"WARNING: {herramienta} no encontrada", "VERIFICADOR", "WARNING")
            except:
                self._log_terminal(f"ERROR: No se pudo verificar {herramienta}", "VERIFICADOR", "WARNING")
                
        porcentaje = (herramientas_encontradas / total_herramientas) * 100
        self._log_terminal(f"Herramientas Kali disponibles: {herramientas_encontradas}/{total_herramientas} ({porcentaje:.1f}%)", "VERIFICADOR", "INFO")

    def _verificar_servicios_sistema(self):
        """Verificar servicios críticos del sistema."""
        import subprocess
        
        servicios_criticos = [
            'systemd', 'dbus', 'networkd', 'resolved', 'ssh'
        ]
        
        for servicio in servicios_criticos:
            try:
                resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                         capture_output=True, text=True, timeout=5)
                estado = resultado.stdout.strip()
                
                if estado == 'active':
                    self._log_terminal(f"OK: Servicio {servicio} activo", "VERIFICADOR", "INFO")
                elif estado == 'inactive':
                    self._log_terminal(f"INFO: Servicio {servicio} inactivo", "VERIFICADOR", "INFO")
                else:
                    self._log_terminal(f"WARNING: Servicio {servicio} en estado {estado}", "VERIFICADOR", "WARNING")
                    
            except Exception as e:
                self._log_terminal(f"ERROR: No se pudo verificar servicio {servicio}", "VERIFICADOR", "WARNING")

    def _verificar_paquetes_sistema(self):
        """Verificar integridad de paquetes del sistema."""
        import subprocess
        
        try:
            # Verificar base de datos de paquetes
            self._log_terminal("Verificando base de datos de paquetes APT...", "VERIFICADOR", "INFO")
            resultado = subprocess.run(['dpkg', '--audit'], 
                                     capture_output=True, text=True, timeout=15)
            
            if resultado.returncode == 0 and not resultado.stdout.strip():
                self._log_terminal("OK: Base de datos de paquetes integra", "VERIFICADOR", "INFO")
            else:
                self._log_terminal("WARNING: Se encontraron problemas en la base de datos de paquetes", "VERIFICADOR", "WARNING")
                
            # Verificar paquetes esenciales de Kali
            paquetes_esenciales = [
                'kali-linux-core', 'apt', 'dpkg', 'systemd', 'openssh-server'
            ]
            
            for paquete in paquetes_esenciales:
                try:
                    resultado = subprocess.run(['dpkg', '-l', paquete], 
                                             capture_output=True, text=True, timeout=5)
                    if 'ii' in resultado.stdout:
                        self._log_terminal(f"OK: Paquete {paquete} instalado correctamente", "VERIFICADOR", "INFO")
                    else:
                        self._log_terminal(f"WARNING: Paquete {paquete} no encontrado o problemas", "VERIFICADOR", "WARNING")
                except:
                    self._log_terminal(f"ERROR: No se pudo verificar paquete {paquete}", "VERIFICADOR", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error verificando paquetes: {str(e)}", "VERIFICADOR", "WARNING")

    def _verificar_configuracion_red(self):
        """Verificar configuración de red del sistema."""
        import subprocess
        
        try:
            # Verificar interfaces de red
            resultado = subprocess.run(['ip', 'link', 'show'], 
                                     capture_output=True, text=True, timeout=5)
            interfaces = []
            for linea in resultado.stdout.split('\n'):
                if ': ' in linea and 'state' in linea.lower():
                    nombre = linea.split(': ')[1].split('@')[0]
                    estado = 'UP' if 'state UP' in linea else 'DOWN'
                    interfaces.append((nombre, estado))
                    
            for nombre, estado in interfaces:
                if nombre != 'lo':  # Ignorar loopback
                    self._log_terminal(f"Interfaz {nombre}: {estado}", "VERIFICADOR", "INFO")
                    
            # Verificar resolución DNS
            try:
                resultado = subprocess.run(['nslookup', 'google.com'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    self._log_terminal("OK: Resolucion DNS funcionando", "VERIFICADOR", "INFO")
                else:
                    self._log_terminal("WARNING: Problemas con resolucion DNS", "VERIFICADOR", "WARNING")
            except:
                self._log_terminal("WARNING: No se pudo verificar DNS", "VERIFICADOR", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error verificando red: {str(e)}", "VERIFICADOR", "WARNING")
    
    def ver_logs(self):
        """Ver logs almacenados de escaneos y verificaciones - se auto-eliminan al cerrar programa."""
        if not self.controlador:
            self._log_terminal("Error: No hay controlador configurado", "LOGS", "ERROR")
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "=== LOGS DE ESCANEO Y VERIFICACION ===\n\n")
        
        self._log_terminal("Consultando logs almacenados", "LOGS", "INFO")
        
        # Obtener logs desde el controlador
        try:
            logs = self.controlador.obtener_logs_escaneo()
            
            # Crear archivo temporal de logs si no existe
            import tempfile
            import os
            
            logs_temporales = getattr(self, '_logs_temporales', [])
            
            # Agregar logs del terminal integrado si están disponibles
            try:
                # Los logs del terminal se manejan directamente por VistaDashboard
                # Por ahora usamos solo los logs del controlador
                pass
            except:
                pass
                
            # Mostrar logs en pantalla
            if logs:
                self.text_resultados.insert(tk.END, "=== LOGS DEL CONTROLADOR ===\n")
                for linea in logs:
                    self.text_resultados.insert(tk.END, f"{linea}\n")
                self.text_resultados.insert(tk.END, "\n")
                
            if logs_temporales:
                self.text_resultados.insert(tk.END, "=== LOGS DEL TERMINAL INTEGRADO ===\n")
                for log_entry in logs_temporales[-50:]:  # Últimos 50 logs
                    self.text_resultados.insert(tk.END, f"{log_entry}\n")
            else:
                self.text_resultados.insert(tk.END, "No se encontraron logs almacenados.\n")
                
            # Almacenar logs para persistencia temporal
            self._logs_temporales = logs_temporales
            
            # Programar auto-eliminación al cerrar (registrar callback)
            if not hasattr(self, '_auto_limpieza_registrada'):
                self._auto_limpieza_registrada = True
                import atexit
                atexit.register(self._limpiar_logs_temporales)
                
            self._log_terminal(f"Logs consultados: {len(logs)} del controlador, {len(logs_temporales)} del terminal", "LOGS", "INFO")
            
        except AttributeError:
            self.text_resultados.insert(tk.END, "Error: Controlador no implementa obtener_logs_escaneo\n")
            self._log_terminal("Error: Metodo obtener_logs_escaneo no disponible", "LOGS", "ERROR")
        except Exception as e:
            self.text_resultados.insert(tk.END, f"Error obteniendo logs: {str(e)}\n")
            self._log_terminal(f"Error obteniendo logs: {str(e)}", "LOGS", "ERROR")

    def _limpiar_logs_temporales(self):
        """Limpiar logs temporales al cerrar el programa."""
        try:
            if hasattr(self, '_logs_temporales'):
                self._logs_temporales.clear()
                print("[ARESITOS] Logs temporales eliminados al cerrar programa")
        except:
            pass
    
    def ver_eventos(self):
        """Función eliminada - SIEM movido a módulo separado."""
        # Redirect al módulo SIEM para análisis de eventos
        self._actualizar_texto_seguro("INFORMACIÓN: Los eventos SIEM se han movido al módulo SIEM dedicado.\n")
        self._actualizar_texto_seguro("Para análisis de eventos de seguridad, usar el módulo SIEM.\n\n")
        self._log_terminal("Funcionalidad SIEM movida a módulo dedicado", "ESCANEADOR", "INFO")
    def _escanear_archivos_criticos(self):
        """Escanear archivos críticos del sistema en busca de modificaciones sospechosas."""
        import subprocess
        import os
        
        archivos_criticos = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
            '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
            '/etc/ssh/sshd_config', '/etc/crontab', '/boot/grub/grub.cfg',
            '/etc/fstab', '/etc/network/interfaces'
        ]
        
        for archivo in archivos_criticos:
            try:
                if os.path.exists(archivo):
                    # Verificar permisos del archivo
                    stat_info = os.stat(archivo)
                    permisos = oct(stat_info.st_mode)[-3:]
                    
                    # Verificar permisos sospechosos
                    if archivo in ['/etc/passwd', '/etc/group'] and permisos != '644':
                        self._log_terminal(f"VULNERABILIDAD CRITICA: {archivo} tiene permisos incorrectos ({permisos})", "ESCANEADOR", "ERROR")
                    elif archivo == '/etc/shadow' and permisos not in ['640', '600']:
                        self._log_terminal(f"VULNERABILIDAD CRITICA: {archivo} tiene permisos incorrectos ({permisos})", "ESCANEADOR", "ERROR")
                    elif archivo == '/etc/sudoers' and permisos != '440':
                        self._log_terminal(f"VULNERABILIDAD CRITICA: {archivo} tiene permisos incorrectos ({permisos})", "ESCANEADOR", "ERROR")
                    else:
                        self._log_terminal(f"OK: {archivo} - permisos correctos ({permisos})", "ESCANEADOR", "INFO")
                        
                    # Verificar modificaciones recientes
                    resultado = subprocess.run(['find', archivo, '-mtime', '-1'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.stdout.strip():
                        self._log_terminal(f"ALERTA: {archivo} modificado en las ultimas 24 horas", "ESCANEADOR", "WARNING")
                        
                else:
                    self._log_terminal(f"VULNERABILIDAD CRITICA: Archivo critico {archivo} no encontrado", "ESCANEADOR", "ERROR")
                    
            except Exception as e:
                self._log_terminal(f"Error verificando {archivo}: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_permisos_sospechosos(self):
        """Buscar archivos con permisos sospechosos que podrían ser una amenaza."""
        import subprocess
        
        try:
            # Buscar archivos SUID sospechosos
            self._log_terminal("Escaneando archivos SUID sospechosos...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['find', '/', '-type', 'f', '-perm', '-4000', '2>/dev/null'], 
                                     capture_output=True, text=True, timeout=30, shell=True)
            
            archivos_suid = resultado.stdout.strip().split('\n') if resultado.stdout.strip() else []
            
            # Lista de archivos SUID legítimos comunes
            suid_legitimos = [
                '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su', '/bin/mount', '/bin/umount',
                '/usr/bin/gpasswd', '/usr/bin/newgrp', '/usr/bin/chsh', '/usr/bin/chfn'
            ]
            
            for archivo in archivos_suid:
                if archivo.strip() and archivo not in suid_legitimos:
                    self._log_terminal(f"AMENAZA POTENCIAL: Archivo SUID sospechoso - {archivo}", "ESCANEADOR", "ERROR")
                    
            # Buscar archivos world-writable
            self._log_terminal("Escaneando archivos world-writable...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['find', '/', '-type', 'f', '-perm', '-002', '2>/dev/null'], 
                                     capture_output=True, text=True, timeout=30, shell=True)
            
            archivos_writable = resultado.stdout.strip().split('\n') if resultado.stdout.strip() else []
            for archivo in archivos_writable[:10]:  # Limitar salida
                if archivo.strip():
                    self._log_terminal(f"RIESGO DE SEGURIDAD: Archivo world-writable - {archivo}", "ESCANEADOR", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error escaneando permisos: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_malware_rootkits(self):
        """Escanear en busca de malware y rootkits usando herramientas nativas."""
        import subprocess
        import os
        
        try:
            # Verificar procesos ocultos
            self._log_terminal("Buscando procesos ocultos...", "ESCANEADOR", "WARNING")
            try:
                resultado = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                procesos = len(resultado.stdout.strip().split('\n')) - 1
                self._log_terminal(f"Procesos activos encontrados: {procesos}", "ESCANEADOR", "INFO")
            except:
                pass
                
            # Verificar archivos en /tmp sospechosos
            self._log_terminal("Verificando archivos temporales sospechosos...", "ESCANEADOR", "WARNING")
            directorios_tmp = ['/tmp', '/var/tmp', '/dev/shm']
            
            for directorio in directorios_tmp:
                if os.path.exists(directorio):
                    try:
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-executable'], 
                                                 capture_output=True, text=True, timeout=10)
                        ejecutables = resultado.stdout.strip().split('\n') if resultado.stdout.strip() else []
                        
                        for ejecutable in ejecutables:
                            if ejecutable.strip():
                                self._log_terminal(f"ARCHIVO SOSPECHOSO: Ejecutable en {ejecutable}", "ESCANEADOR", "ERROR")
                    except:
                        pass
                        
            # Verificar conexiones de red sospechosas
            self._log_terminal("Verificando conexiones de red activas...", "ESCANEADOR", "INFO")
            try:
                resultado = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
                lineas = resultado.stdout.strip().split('\n')
                puertos_abiertos = []
                
                for linea in lineas:
                    if ':' in linea and 'LISTEN' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            puerto = partes[3].split(':')[-1]
                            puertos_abiertos.append(puerto)
                            
                # Puertos comúnmente usados por malware
                puertos_sospechosos = ['4444', '5555', '6666', '7777', '8888', '9999', '31337']
                for puerto in puertos_abiertos:
                    if puerto in puertos_sospechosos:
                        self._log_terminal(f"PUERTO SOSPECHOSO ABIERTO: {puerto} - posible backdoor", "ESCANEADOR", "ERROR")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando conexiones: {str(e)}", "ESCANEADOR", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error escaneando malware: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_procesos_sospechosos(self):
        """Analizar procesos en ejecución en busca de actividad sospechosa."""
        import subprocess
        
        try:
            # Obtener lista de procesos
            resultado = subprocess.run(['ps', 'auxww'], capture_output=True, text=True, timeout=15)
            lineas = resultado.stdout.strip().split('\n')[1:]  # Saltar header
            
            procesos_sospechosos = []
            palabras_sospechosas = [
                'nc', 'netcat', 'telnet', 'wget', 'curl', 'python -c', 'perl -e', 
                'bash -i', 'sh -i', '/dev/tcp', 'reverse', 'shell', 'backdoor'
            ]
            
            for linea in lineas:
                comando = linea.split(None, 10)[-1] if linea else ""
                
                # Verificar procesos con nombres sospechosos
                for palabra in palabras_sospechosas:
                    if palabra.lower() in comando.lower():
                        procesos_sospechosos.append(comando)
                        break
                        
                # Verificar procesos corriendo desde ubicaciones sospechosas
                if any(ubicacion in comando for ubicacion in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                    procesos_sospechosos.append(comando)
                    
            for proceso in procesos_sospechosos:
                self._log_terminal(f"PROCESO SOSPECHOSO: {proceso}", "ESCANEADOR", "ERROR")
                
            if not procesos_sospechosos:
                self._log_terminal("No se encontraron procesos sospechosos activos", "ESCANEADOR", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error analizando procesos: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_conexiones_red(self):
        """Verificar conexiones de red en busca de actividad sospechosa."""
        import subprocess
        
        try:
            # Verificar conexiones TCP activas
            self._log_terminal("Analizando conexiones TCP activas...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
            
            conexiones_sospechosas = []
            puertos_comunes_ataques = [
                '22', '23', '25', '53', '80', '110', '135', '139', '443', '445', 
                '993', '995', '1433', '1521', '3306', '3389', '5432', '5900'
            ]
            
            for linea in resultado.stdout.split('\n'):
                if 'LISTEN' in linea or 'ESTABLISHED' in linea:
                    partes = linea.split()
                    if len(partes) >= 4:
                        direccion_local = partes[3]
                        puerto = direccion_local.split(':')[-1]
                        
                        if puerto in puertos_comunes_ataques:
                            self._log_terminal(f"PUERTO CRITICO ABIERTO: {puerto} ({direccion_local})", "ESCANEADOR", "WARNING")
                            
            # Verificar interfaces de red
            resultado = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
            interfaces = []
            for linea in resultado.stdout.split('\n'):
                if 'inet ' in linea and '127.0.0.1' not in linea:
                    ip = linea.split()[1].split('/')[0]
                    interfaces.append(ip)
                    
            for ip in interfaces:
                self._log_terminal(f"Interfaz de red activa: {ip}", "ESCANEADOR", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error analizando conexiones de red: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_usuarios_grupos(self):
        """Verificar usuarios y grupos del sistema en busca de anomalías."""
        import subprocess
        
        try:
            # Verificar usuarios con UID 0 (root)
            self._log_terminal("Verificando usuarios con privilegios root...", "ESCANEADOR", "WARNING")
            with open('/etc/passwd', 'r') as f:
                lineas = f.readlines()
                
            usuarios_root = []
            usuarios_sin_shell = []
            
            for linea in lineas:
                partes = linea.strip().split(':')
                if len(partes) >= 7:
                    usuario = partes[0]
                    uid = partes[2]
                    shell = partes[6]
                    
                    if uid == '0' and usuario != 'root':
                        usuarios_root.append(usuario)
                        
                    if shell in ['/bin/bash', '/bin/sh', '/bin/zsh'] and uid != '0':
                        if int(uid) < 1000 and usuario not in ['daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody']:
                            usuarios_sin_shell.append(f"{usuario} (UID: {uid})")
                            
            for usuario in usuarios_root:
                self._log_terminal(f"VULNERABILIDAD CRITICA: Usuario con UID 0 adicional - {usuario}", "ESCANEADOR", "ERROR")
                
            # Verificar últimos logins
            try:
                resultado = subprocess.run(['last', '-n', '10'], capture_output=True, text=True, timeout=5)
                self._log_terminal("Ultimos 5 logins registrados:", "ESCANEADOR", "INFO")
                lineas = resultado.stdout.strip().split('\n')[:5]
                for linea in lineas:
                    if linea.strip() and 'reboot' not in linea.lower():
                        self._log_terminal(f"  {linea}", "ESCANEADOR", "INFO")
            except:
                pass
                
        except Exception as e:
            self._log_terminal(f"Error verificando usuarios: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_vulnerabilidades(self):
        """Escanear vulnerabilidades conocidas del sistema con información detallada."""
        import subprocess
        import os
        from datetime import datetime
        
        try:
            # Verificar versión del kernel
            self._log_terminal("Verificando version del kernel...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
            kernel_version = resultado.stdout.strip()
            self._log_terminal(f"Kernel version: {kernel_version}", "ESCANEADOR", "INFO")
            
            # Verificar paquetes desactualizados con información detallada
            self._log_terminal("Verificando actualizaciones disponibles...", "ESCANEADOR", "INFO")
            try:
                resultado = subprocess.run(['apt', 'list', '--upgradable'], 
                                         capture_output=True, text=True, timeout=20)
                lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                actualizaciones = len(lineas)
                
                if actualizaciones > 0:
                    self._log_terminal(f"ATENCION: {actualizaciones} paquetes pueden actualizarse", "ESCANEADOR", "WARNING")
                    
                    # Mostrar paquetes críticos de seguridad
                    paquetes_criticos = []
                    for linea in lineas[:10]:  # Primeros 10 paquetes
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 2:
                                paquete = partes[0].split('/')[0]
                                version_nueva = partes[1]
                                # Identificar paquetes críticos de seguridad
                                if any(critico in paquete.lower() for critico in ['kernel', 'openssl', 'openssh', 'sudo', 'libc']):
                                    paquetes_criticos.append((paquete, version_nueva))
                                    self._log_terminal(f"PAQUETE CRÍTICO: {paquete} -> {version_nueva}", "SEGURIDAD", "ERROR")
                                else:
                                    self._log_terminal(f"Actualización disponible: {paquete} -> {version_nueva}", "ESCANEADOR", "INFO")
                else:
                    self._log_terminal("Sistema actualizado", "ESCANEADOR", "INFO")
            except:
                self._log_terminal("No se pudo verificar actualizaciones", "ESCANEADOR", "WARNING")
            
            # Verificar archivos sospechosos con información detallada
            self._log_terminal("Verificando archivos sospechosos en el sistema...", "ARCHIVOS", "INFO")
            try:
                directorios_criticos = ['/tmp', '/var/tmp', '/dev/shm', '/home']
                extensiones_sospechosas = ['.sh', '.py', '.pl', '.bin', '.exe']
                
                for directorio in directorios_criticos:
                    if os.path.exists(directorio):
                        # Buscar archivos ejecutables recientes
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-executable', '-mtime', '-7'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos = resultado.stdout.strip().split('\n')
                            for archivo in archivos[:5]:  # Primeros 5 archivos
                                if archivo.strip():
                                    try:
                                        stat_info = os.stat(archivo)
                                        tamaño = stat_info.st_size
                                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                        
                                        # Obtener propietario del archivo
                                        try:
                                            # Usar comando ls para obtener el propietario
                                            resultado_ls = subprocess.run(['ls', '-l', archivo], 
                                                                        capture_output=True, text=True, timeout=5)
                                            if resultado_ls.returncode == 0:
                                                partes_ls = resultado_ls.stdout.split()
                                                propietario = partes_ls[2] if len(partes_ls) > 2 else f"UID:{stat_info.st_uid}"
                                            else:
                                                propietario = f"UID:{stat_info.st_uid}"
                                        except:
                                            propietario = f"UID:{stat_info.st_uid}"
                                        
                                        # Obtener permisos
                                        permisos = oct(stat_info.st_mode)[-3:]
                                        
                                        self._log_terminal(f"ARCHIVO EJECUTABLE: {archivo}", "ARCHIVOS", "WARNING")
                                        self._log_terminal(f"  Propietario: {propietario}, Tamaño: {tamaño} bytes, Permisos: {permisos}", "ARCHIVOS", "INFO")
                                        self._log_terminal(f"  Fecha modificación: {mod_time}", "ARCHIVOS", "INFO")
                                        
                                        # Verificar hash del archivo si es pequeño
                                        if tamaño < 1024 * 1024:  # Menos de 1MB
                                            resultado_hash = subprocess.run(['sha256sum', archivo], 
                                                                           capture_output=True, text=True, timeout=10)
                                            if resultado_hash.returncode == 0:
                                                hash_value = resultado_hash.stdout.split()[0][:16]  # Primeros 16 caracteres
                                                self._log_terminal(f"  SHA256 (parcial): {hash_value}...", "ARCHIVOS", "INFO")
                                                
                                    except Exception as e:
                                        self._log_terminal(f"ARCHIVO EJECUTABLE: {archivo} (error leyendo info)", "ARCHIVOS", "WARNING")
                        
                        # Buscar archivos con extensiones sospechosas
                        for extension in extensiones_sospechosas:
                            resultado = subprocess.run(['find', directorio, '-name', f'*{extension}', '-mtime', '-7'], 
                                                     capture_output=True, text=True, timeout=20)
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                archivos = resultado.stdout.strip().split('\n')
                                for archivo in archivos[:3]:  # Primeros 3 por extensión
                                    if archivo.strip():
                                        try:
                                            stat_info = os.stat(archivo)
                                            mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                            self._log_terminal(f"SCRIPT RECIENTE: {archivo} (mod: {mod_time})", "ARCHIVOS", "WARNING")
                                        except:
                                            self._log_terminal(f"SCRIPT RECIENTE: {archivo}", "ARCHIVOS", "WARNING")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando archivos sospechosos: {str(e)}", "ARCHIVOS", "WARNING")
                
            # Verificar servicios críticos con información adicional
            self._log_terminal("Verificando servicios críticos de seguridad...", "SERVICIOS", "INFO")
            servicios_criticos = {
                'ssh': 'Servicio SSH para conexiones remotas',
                'ufw': 'Firewall no complicado',
                'fail2ban': 'Protección contra ataques de fuerza bruta',
                'cron': 'Programador de tareas',
                'rsyslog': 'Sistema de logs'
            }
            
            for servicio, descripcion in servicios_criticos.items():
                try:
                    resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                             capture_output=True, text=True, timeout=5)
                    estado = resultado.stdout.strip()
                    
                    if estado == 'active':
                        self._log_terminal(f"SERVICIO ACTIVO: {servicio} - {descripcion}", "SERVICIOS", "INFO")
                        
                        # Obtener información adicional del servicio
                        resultado_status = subprocess.run(['systemctl', 'status', servicio, '--no-pager', '-l'], 
                                                        capture_output=True, text=True, timeout=5)
                        if resultado_status.returncode == 0:
                            lineas = resultado_status.stdout.split('\n')
                            for linea in lineas[:5]:  # Primeras 5 líneas del status
                                if 'Active:' in linea or 'Main PID:' in linea:
                                    info = linea.strip()
                                    self._log_terminal(f"  {info}", "SERVICIOS", "INFO")
                                    break
                    else:
                        self._log_terminal(f"RIESGO: Servicio {servicio} no activo - {descripcion}", "SERVICIOS", "WARNING")
                        
                except Exception as e:
                    self._log_terminal(f"No se pudo verificar servicio {servicio}: {str(e)}", "SERVICIOS", "WARNING")
            
            # Verificar logs de seguridad recientes
            self._log_terminal("Verificando logs de seguridad recientes...", "LOGS", "INFO")
            try:
                logs_seguridad = ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog']
                for log_file in logs_seguridad:
                    if os.path.exists(log_file):
                        # Buscar intentos de login fallidos
                        resultado = subprocess.run(['grep', '-i', r'failed\|failure\|invalid', log_file], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.strip().split('\n')
                            fallos_recientes = len(lineas)
                            if fallos_recientes > 0:
                                self._log_terminal(f"INTENTOS FALLIDOS: {fallos_recientes} intentos de login fallidos en {log_file}", "LOGS", "WARNING")
                                
                                # Mostrar las últimas 3 líneas más recientes
                                for linea in lineas[-3:]:
                                    if linea.strip():
                                        # Extraer timestamp y información relevante
                                        partes = linea.split()
                                        if len(partes) >= 3:
                                            timestamp = ' '.join(partes[:3])
                                            mensaje = ' '.join(partes[3:])[:50]  # Limitar longitud
                                            self._log_terminal(f"  {timestamp}: {mensaje}...", "LOGS", "WARNING")
                        break  # Solo verificar el primer log que exista
                        
            except Exception as e:
                self._log_terminal(f"Error verificando logs de seguridad: {str(e)}", "LOGS", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error escaneando vulnerabilidades: {str(e)}", "ESCANEADOR", "WARNING")

    def _escaneo_red_kali(self):
        """Escaneo de red usando herramientas nativas de Kali Linux."""
        try:
            import subprocess
            
            self._actualizar_texto_seguro("=== ESCANEO DE RED CON HERRAMIENTAS KALI ===\n\n")
            
            # 1. Obtener interfaz de red activa
            self._actualizar_texto_seguro("COMANDO: ip route | grep default\n")
            try:
                resultado = subprocess.run(['bash', '-c', 'ip route | grep default'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    ruta_default = resultado.stdout.strip()
                    interfaz = ruta_default.split()[-1] if len(ruta_default.split()) > 4 else 'unknown'
                    gateway = ruta_default.split()[2] if len(ruta_default.split()) > 2 else 'unknown'
                    self._actualizar_texto_seguro(f"INTERFAZ ACTIVA: {interfaz}\n")
                    self._actualizar_texto_seguro(f"GATEWAY: {gateway}\n\n")
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo determinar la ruta por defecto\n\n")
            except:
                self._actualizar_texto_seguro("ERROR: Comando ip route falló\n\n")
            
            # 2. Escaneo de red local con nmap si está disponible
            self._actualizar_texto_seguro("COMANDO: which nmap\n")
            try:
                resultado_nmap = subprocess.run(['which', 'nmap'], 
                                              capture_output=True, text=True, timeout=5)
                if resultado_nmap.returncode == 0:
                    self._actualizar_texto_seguro("NMAP DISPONIBLE: Ejecutando escaneo básico de red\n")
                    
                    # Detectar la red local usando DetectorRed
                    if DetectorRed:
                        try:
                            detector = DetectorRed()
                            redes = detector.obtener_objetivos_escaneo()
                            # Buscar la primera red que no sea localhost
                            red_local = None
                            for red in redes:
                                if red not in ["127.0.0.1", "localhost"]:
                                    red_local = red
                                    break
                            
                            if not red_local:
                                red_local = "192.168.1.0/24"
                                self._actualizar_texto_seguro("ADVERTENCIA: No se detectó red, usando por defecto 192.168.1.0/24\n")
                            else:
                                self._actualizar_texto_seguro(f"RED DETECTADA AUTOMÁTICAMENTE: {red_local}\n")
                        except Exception as e:
                            red_local = "192.168.1.0/24"
                            self._actualizar_texto_seguro(f"ERROR en detección automática: {e}, usando red por defecto\n")
                    else:
                        red_local = "192.168.1.0/24"
                        self._actualizar_texto_seguro("ADVERTENCIA: DetectorRed no disponible, usando red por defecto\n")
                    
                    # Escaneo de la red detectada
                    try:
                        self._actualizar_texto_seguro(f"ESCANEANDO: {red_local}\n")
                        resultado_red = subprocess.run(['nmap', '-sn', red_local], 
                                                     capture_output=True, text=True, timeout=30)
                        if resultado_red.returncode == 0:
                            # Filtrar solo hosts que están UP
                            lineas = resultado_red.stdout.split('\n')
                            hosts_activos = []
                            for i, linea in enumerate(lineas):
                                if 'Nmap scan report for' in linea and i + 1 < len(lineas):
                                    if 'Host is up' in lineas[i + 1]:
                                        ip = linea.split()[-1]
                                        # Limpiar IP de paréntesis si los tiene
                                        ip = ip.strip('()')
                                        hosts_activos.append(ip)
                            
                            hosts_up = len(hosts_activos)
                            self._actualizar_texto_seguro(f"HOSTS ACTIVOS: {hosts_up} dispositivos detectados en red local\n")
                            # Mostrar solo IPs activas
                            for ip in hosts_activos:
                                self._actualizar_texto_seguro(f"  HOST: {ip}\n")
                        else:
                            self._actualizar_texto_seguro("ERROR: Escaneo nmap falló\n")
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_seguro("TIMEOUT: Escaneo nmap excedió tiempo límite\n")
                else:
                    self._actualizar_texto_seguro("NMAP NO DISPONIBLE: Usando métodos alternativos\n")
                    # Usar ping para escaneo básico
                    self._actualizar_texto_seguro("ALTERNATIVO: Usando ping para verificar gateway\n")
                    try:
                        ping_result = subprocess.run(['ping', '-c', '3', gateway], 
                                                   capture_output=True, text=True, timeout=15)
                        if ping_result.returncode == 0:
                            self._actualizar_texto_seguro(f"CONECTIVIDAD: Gateway {gateway} responde\n")
                        else:
                            self._actualizar_texto_seguro(f"PROBLEMA: Gateway {gateway} no responde\n")
                    except:
                        self._actualizar_texto_seguro("ERROR: No se pudo hacer ping al gateway\n")
            except:
                self._actualizar_texto_seguro("ERROR: No se pudo verificar disponibilidad de nmap\n")
            
            self._actualizar_texto_seguro("\n")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"ERROR EN ESCANEO DE RED: {str(e)}\n\n")

    def _escanear_servicios_kali(self):
        """Escaneo de servicios usando herramientas nativas de Linux."""
        try:
            import subprocess
            
            self._actualizar_texto_seguro("=== ANÁLISIS DE SERVICIOS CON HERRAMIENTAS LINUX ===\n\n")
            
            # 1. Servicios en escucha con ss
            self._actualizar_texto_seguro("COMANDO: ss -tuln\n")
            try:
                resultado = subprocess.run(['ss', '-tuln'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                    puertos_tcp = []
                    puertos_udp = []
                    
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 4:
                                protocolo = partes[0]
                                direccion_local = partes[3]
                                puerto = direccion_local.split(':')[-1]
                                
                                if protocolo.startswith('tcp'):
                                    puertos_tcp.append(puerto)
                                elif protocolo.startswith('udp'):
                                    puertos_udp.append(puerto)
                    
                    self._actualizar_texto_seguro(f"PUERTOS TCP EN ESCUCHA: {len(set(puertos_tcp))}\n")
                    for puerto in sorted(set(puertos_tcp))[:10]:  # Mostrar primeros 10
                        self._actualizar_texto_seguro(f"  TCP: {puerto}\n")
                    
                    self._actualizar_texto_seguro(f"PUERTOS UDP EN ESCUCHA: {len(set(puertos_udp))}\n")
                    for puerto in sorted(set(puertos_udp))[:5]:  # Mostrar primeros 5
                        self._actualizar_texto_seguro(f"  UDP: {puerto}\n")
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo ejecutar comando ss\n")
            except:
                self._actualizar_texto_seguro("ERROR: Comando ss no disponible\n")
            
            self._actualizar_texto_seguro("\n")
            
            # 2. Procesos con conexiones de red usando lsof
            self._actualizar_texto_seguro("COMANDO: lsof -i -n | head -15\n")
            try:
                resultado = subprocess.run(['bash', '-c', 'lsof -i -n | head -15'], 
                                         capture_output=True, text=True, timeout=15)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                    self._actualizar_texto_seguro("PROCESOS CON CONEXIONES DE RED:\n")
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 8:
                                proceso = partes[0]
                                pid = partes[1]
                                conexion = partes[7] if len(partes) > 7 else 'N/A'
                                self._actualizar_texto_seguro(f"  {proceso} (PID: {pid}): {conexion}\n")
                else:
                    self._actualizar_texto_seguro("INFO: lsof no mostró conexiones o no está disponible\n")
            except:
                self._actualizar_texto_seguro("ADVERTENCIA: lsof no disponible\n")
            
            self._actualizar_texto_seguro("\n")
            
            # 3. Servicios systemd activos
            self._actualizar_texto_seguro("COMANDO: systemctl list-units --type=service --state=running\n")
            try:
                resultado = subprocess.run(['bash', '-c', 'systemctl list-units --type=service --state=running | head -10'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                    servicios_activos = 0
                    for linea in lineas:
                        if '.service' in linea and 'running' in linea:
                            servicios_activos += 1
                            nombre_servicio = linea.split()[0].replace('.service', '')
                            self._actualizar_texto_seguro(f"  ACTIVO: {nombre_servicio}\n")
                    
                    self._actualizar_texto_seguro(f"TOTAL SERVICIOS ACTIVOS: {servicios_activos}\n")
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo listar servicios systemd\n")
            except:
                self._actualizar_texto_seguro("ERROR: systemctl no disponible\n")
                
            self._actualizar_texto_seguro("\n")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"ERROR EN ANÁLISIS DE SERVICIOS: {str(e)}\n\n")
    
    def _escaneo_avanzado_kali(self):
        """Análisis avanzado con herramientas especializadas de Kali Linux expandidas."""
        import subprocess
        import os
        
        try:
            self._log_terminal("Iniciando análisis avanzado EXPANDIDO con herramientas Kali", "ESCANEADOR", "INFO")
            
            # 1. HERRAMIENTAS KALI EXPANDIDAS
            herramientas_kali = {
                # Escaneo de red
                'nmap': 'Escaneador de puertos y servicios avanzado',
                'masscan': 'Escaneador masivo de puertos ultra-rápido',
                'zmap': 'Escaneador de Internet de alta velocidad',
                'rustscan': 'Escaneador de puertos moderno en Rust',
                
                # Análisis de red
                'ss': 'Análisis de sockets y conexiones',
                'netstat': 'Estadísticas de red',
                'lsof': 'Archivos y conexiones abiertas',
                'iftop': 'Monitor de ancho de banda por conexión',
                'nethogs': 'Monitor de ancho de banda por proceso',
                
                # Escaneo web
                'nikto': 'Escaneador de vulnerabilidades web',
                'dirb': 'Escaneador de directorios web',
                'gobuster': 'Escaneador de directorios/DNS rápido',
                'ffuf': 'Fuzzer web rápido',
                'whatweb': 'Identificador de tecnologías web',
                'httpx': 'Kit de herramientas HTTP',
                
                # Seguridad y análisis
                'chkrootkit': 'Detector de rootkits',
                'lynis': 'Auditor de seguridad del sistema',
                'rkhunter': 'Cazador de rootkits',
                'clamav': 'Antivirus',
                'yara': 'Motor de detección de malware',
                
                # Análisis forense
                'volatility': 'Análisis de memoria forense',
                'binwalk': 'Análisis de firmware y archivos binarios',
                'foremost': 'Recuperación de archivos',
                'strings': 'Extractor de cadenas de texto',
                
                # Análisis de procesos
                'pspy': 'Monitor de procesos sin root',
                'htop': 'Monitor avanzado de procesos',
                'iotop': 'Monitor de E/S de procesos'
            }
            
            herramientas_disponibles = []
            categorias_disponibles = {'red': [], 'web': [], 'seguridad': [], 'forense': [], 'procesos': []}
            
            for herramienta, descripcion in herramientas_kali.items():
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        herramientas_disponibles.append(herramienta)
                        
                        # Categorizar herramientas
                        if herramienta in ['nmap', 'masscan', 'zmap', 'rustscan', 'ss', 'netstat', 'lsof', 'iftop', 'nethogs']:
                            categorias_disponibles['red'].append(herramienta)
                        elif herramienta in ['nikto', 'dirb', 'gobuster', 'ffuf', 'whatweb', 'httpx']:
                            categorias_disponibles['web'].append(herramienta)
                        elif herramienta in ['chkrootkit', 'lynis', 'rkhunter', 'clamav', 'yara']:
                            categorias_disponibles['seguridad'].append(herramienta)
                        elif herramienta in ['volatility', 'binwalk', 'foremost', 'strings']:
                            categorias_disponibles['forense'].append(herramienta)
                        elif herramienta in ['pspy', 'htop', 'iotop']:
                            categorias_disponibles['procesos'].append(herramienta)
                            
                        self._log_terminal(f"CONTROLADOR DISPONIBLE: {herramienta} - {descripcion}", "KALI", "SUCCESS")
                except:
                    pass
            
            total_herramientas = len(herramientas_disponibles)
            self._log_terminal(f"RESUMEN: {total_herramientas} herramientas Kali disponibles", "KALI", "INFO")
            
            # 2. ESCANEO DE RED AVANZADO
            if categorias_disponibles['red']:
                self._log_terminal("=== ESCANEO DE RED AVANZADO ===", "RED", "INFO")
                
                # Nmap avanzado si está disponible
                if 'nmap' in herramientas_disponibles:
                    self._ejecutar_nmap_avanzado()
                
                # Masscan si está disponible
                if 'masscan' in herramientas_disponibles:
                    self._ejecutar_masscan()
                
                # Rustscan si está disponible
                if 'rustscan' in herramientas_disponibles:
                    self._ejecutar_rustscan()
            
            # 3. ESCANEO WEB AVANZADO
            if categorias_disponibles['web']:
                self._log_terminal("=== ESCANEO WEB AVANZADO ===", "WEB", "INFO")
                
                # Detectar servicios web locales primero
                servicios_web = self._detectar_servicios_web()
                
                if servicios_web:
                    for servicio in servicios_web:
                        self._log_terminal(f"SERVICIO WEB DETECTADO: {servicio}", "WEB", "WARNING")
                        
                        # Nikto si está disponible
                        if 'nikto' in herramientas_disponibles:
                            self._ejecutar_nikto(servicio)
                        
                        # Whatweb si está disponible
                        if 'whatweb' in herramientas_disponibles:
                            self._ejecutar_whatweb(servicio)
                
            # 4. ANÁLISIS DE SEGURIDAD PROFUNDO
            if categorias_disponibles['seguridad']:
                self._log_terminal("=== ANÁLISIS DE SEGURIDAD PROFUNDO ===", "SEGURIDAD", "WARNING")
                
                # Chkrootkit
                if 'chkrootkit' in herramientas_disponibles:
                    self._ejecutar_chkrootkit()
                
                # Rkhunter
                if 'rkhunter' in herramientas_disponibles:
                    self._ejecutar_rkhunter()
                
                # ClamAV
                if 'clamav' in herramientas_disponibles:
                    self._ejecutar_clamav()
            
            # 5. ANÁLISIS FORENSE BÁSICO
            if categorias_disponibles['forense']:
                self._log_terminal("=== ANÁLISIS FORENSE BÁSICO ===", "FORENSE", "INFO")
                
                # Strings en archivos sospechosos
                if 'strings' in herramientas_disponibles:
                    self._analizar_strings_sospechosos()
                
                # Binwalk en archivos críticos
                if 'binwalk' in herramientas_disponibles:
                    self._analizar_binwalk()
            
            # 6. MONITOREO DE PROCESOS AVANZADO
            if categorias_disponibles['procesos']:
                self._log_terminal("=== MONITOREO DE PROCESOS AVANZADO ===", "PROCESOS", "INFO")
                
                # Pspy si está disponible
                if 'pspy' in herramientas_disponibles:
                    self._ejecutar_pspy()
                
                # Análisis con lsof
                if 'lsof' in herramientas_disponibles:
                    self._analizar_lsof_avanzado()
            
            self._log_terminal("ANÁLISIS AVANZADO KALI COMPLETADO", "ESCANEADOR", "SUCCESS")
            
        except Exception as e:
            self._log_terminal(f"ERROR en análisis avanzado: {str(e)}", "ESCANEADOR", "ERROR")
    
    # MÉTODOS DE HERRAMIENTAS ESPECÍFICAS DE KALI LINUX
    
    def _ejecutar_nmap_avanzado(self):
        """Ejecutar escaneo Nmap avanzado."""
        import subprocess
        try:
            self._log_terminal("Ejecutando Nmap avanzado...", "NMAP", "INFO")
            
            # Escaneo completo con detección de servicios y OS
            comandos_nmap = [
                ['nmap', '-sV', '-O', '--script=default', 'localhost'],
                ['nmap', '-sS', '--top-ports', '1000', 'localhost'],
                ['nmap', '-sU', '--top-ports', '100', 'localhost']  # UDP scan
            ]
            
            for i, cmd in enumerate(comandos_nmap, 1):
                try:
                    resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.split('\n')
                        puertos_importantes = []
                        
                        for linea in lineas:
                            if 'open' in linea and ('tcp' in linea or 'udp' in linea):
                                puertos_importantes.append(linea.strip())
                        
                        if puertos_importantes:
                            self._log_terminal(f"NMAP SCAN {i}: {len(puertos_importantes)} puertos detectados", "NMAP", "WARNING")
                            for puerto in puertos_importantes[:5]:  # Mostrar primeros 5
                                self._log_terminal(f"  {puerto}", "NMAP", "INFO")
                        else:
                            self._log_terminal(f"NMAP SCAN {i}: Sin puertos abiertos detectados", "NMAP", "INFO")
                    else:
                        self._log_terminal(f"NMAP SCAN {i}: Error en ejecución", "NMAP", "WARNING")
                
                except subprocess.TimeoutExpired:
                    self._log_terminal(f"NMAP SCAN {i}: Timeout - escaneo muy lento", "NMAP", "WARNING")
                except Exception as e:
                    self._log_terminal(f"NMAP SCAN {i}: Error {str(e)}", "NMAP", "ERROR")
                    
        except Exception as e:
            self._log_terminal(f"Error en Nmap avanzado: {str(e)}", "NMAP", "ERROR")
    
    def _ejecutar_masscan(self):
        """Ejecutar Masscan para escaneo rápido."""
        import subprocess
        try:
            self._log_terminal("Ejecutando Masscan (escaneador ultra-rápido)...", "MASSCAN", "INFO")
            
            # Masscan en red local
            resultado = subprocess.run(['masscan', '127.0.0.1', '-p1-1000', '--rate=1000'], 
                                     capture_output=True, text=True, timeout=60)
            
            if resultado.returncode == 0 and resultado.stdout.strip():
                lineas = resultado.stdout.strip().split('\n')
                puertos_masivos = []
                
                for linea in lineas:
                    if 'open' in linea.lower():
                        puertos_masivos.append(linea.strip())
                
                if puertos_masivos:
                    self._log_terminal(f"MASSCAN: {len(puertos_masivos)} puertos encontrados", "MASSCAN", "WARNING")
                    for puerto in puertos_masivos[:10]:
                        self._log_terminal(f"  {puerto}", "MASSCAN", "INFO")
                else:
                    self._log_terminal("MASSCAN: No se encontraron puertos abiertos", "MASSCAN", "INFO")
            else:
                self._log_terminal("MASSCAN: Sin resultados o error en ejecución", "MASSCAN", "WARNING")
                
        except subprocess.TimeoutExpired:
            self._log_terminal("MASSCAN: Timeout - escaneo interrumpido", "MASSCAN", "WARNING")
        except Exception as e:
            self._log_terminal(f"Error en Masscan: {str(e)}", "MASSCAN", "ERROR")
    
    def _ejecutar_rustscan(self):
        """Ejecutar RustScan para escaneo moderno."""
        import subprocess
        try:
            self._log_terminal("Ejecutando RustScan (escaneador moderno)...", "RUSTSCAN", "INFO")
            
            resultado = subprocess.run(['rustscan', '-a', '127.0.0.1', '--', '-sV'], 
                                     capture_output=True, text=True, timeout=90)
            
            if resultado.returncode == 0 and resultado.stdout.strip():
                lineas = resultado.stdout.strip().split('\n')
                puertos_rust = []
                
                for linea in lineas:
                    if 'open' in linea.lower() or 'tcp' in linea.lower():
                        puertos_rust.append(linea.strip())
                
                if puertos_rust:
                    self._log_terminal(f"RUSTSCAN: {len(puertos_rust)} servicios detectados", "RUSTSCAN", "WARNING")
                    for puerto in puertos_rust[:8]:
                        self._log_terminal(f"  {puerto}", "RUSTSCAN", "INFO")
                else:
                    self._log_terminal("RUSTSCAN: No se detectaron servicios", "RUSTSCAN", "INFO")
            else:
                self._log_terminal("RUSTSCAN: Sin resultados disponibles", "RUSTSCAN", "WARNING")
                
        except subprocess.TimeoutExpired:
            self._log_terminal("RUSTSCAN: Timeout - escaneo interrumpido", "RUSTSCAN", "WARNING")
        except Exception as e:
            self._log_terminal(f"Error en RustScan: {str(e)}", "RUSTSCAN", "ERROR")
    
    def _detectar_servicios_web(self):
        """Detectar servicios web en el sistema."""
        import subprocess
        servicios_web = []
        
        try:
            # Buscar puertos web comunes
            puertos_web = ['80', '443', '8080', '8443', '3000', '5000', '8000', '9000']
            
            for puerto in puertos_web:
                try:
                    # Verificar si el puerto está abierto
                    resultado = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0 and f':{puerto} ' in resultado.stdout:
                        servicios_web.append(f'http://localhost:{puerto}')
                        
                except Exception:
                    continue
            
            # También buscar servicios web conocidos
            try:
                resultado_ps = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                if resultado_ps.returncode == 0:
                    if any(serv in resultado_ps.stdout.lower() for serv in ['apache', 'nginx', 'httpd']):
                        if 'http://localhost:80' not in servicios_web:
                            servicios_web.append('http://localhost:80')
                            
            except Exception:
                pass
                
        except Exception as e:
            self._log_terminal(f"Error detectando servicios web: {str(e)}", "WEB", "ERROR")
        
        return servicios_web
    
    def _ejecutar_nikto(self, url):
        """Ejecutar Nikto contra un servicio web."""
        import subprocess
        try:
            self._log_terminal(f"Ejecutando Nikto contra {url}...", "NIKTO", "INFO")
            
            resultado = subprocess.run(['nikto', '-h', url, '-maxtime', '60'], 
                                     capture_output=True, text=True, timeout=90)
            
            if resultado.returncode == 0 and resultado.stdout.strip():
                lineas = resultado.stdout.split('\n')
                vulnerabilidades = []
                
                for linea in lineas:
                    if any(palabra in linea.lower() for palabra in ['vulnerability', 'vuln', 'risk', 'warning']):
                        vulnerabilidades.append(linea.strip())
                
                if vulnerabilidades:
                    self._log_terminal(f"NIKTO: {len(vulnerabilidades)} posibles problemas en {url}", "NIKTO", "WARNING")
                    for vuln in vulnerabilidades[:5]:
                        if vuln:
                            self._log_terminal(f"  {vuln[:100]}...", "NIKTO", "WARNING")
                else:
                    self._log_terminal(f"NIKTO: No se encontraron problemas evidentes en {url}", "NIKTO", "INFO")
            else:
                self._log_terminal(f"NIKTO: Sin resultados para {url}", "NIKTO", "WARNING")
                
        except subprocess.TimeoutExpired:
            self._log_terminal(f"NIKTO: Timeout escaneando {url}", "NIKTO", "WARNING")
        except Exception as e:
            self._log_terminal(f"Error en Nikto: {str(e)}", "NIKTO", "ERROR")
    
    def _ejecutar_whatweb(self, url):
        """Ejecutar Whatweb para identificar tecnologías."""
        import subprocess
        try:
            self._log_terminal(f"Identificando tecnologías en {url} con Whatweb...", "WHATWEB", "INFO")
            
            resultado = subprocess.run(['whatweb', url, '--log-brief=-'], 
                                     capture_output=True, text=True, timeout=30)
            
            if resultado.returncode == 0 and resultado.stdout.strip():
                tecnologias = resultado.stdout.strip()
                if tecnologias:
                    self._log_terminal(f"WHATWEB: Tecnologías detectadas en {url}", "WHATWEB", "INFO")
                    # Parsear tecnologías
                    if '[' in tecnologias and ']' in tecnologias:
                        tech_list = tecnologias.split('[')[1].split(']')[0].split(',')
                        for tech in tech_list[:8]:  # Mostrar primeras 8
                            if tech.strip():
                                self._log_terminal(f"  {tech.strip()}", "WHATWEB", "INFO")
                    else:
                        self._log_terminal(f"  {tecnologias[:200]}...", "WHATWEB", "INFO")
                else:
                    self._log_terminal(f"WHATWEB: No se identificaron tecnologías en {url}", "WHATWEB", "WARNING")
            else:
                self._log_terminal(f"WHATWEB: Error analizando {url}", "WHATWEB", "WARNING")
                
        except subprocess.TimeoutExpired:
            self._log_terminal(f"WHATWEB: Timeout analizando {url}", "WHATWEB", "WARNING")
        except Exception as e:
            self._log_terminal(f"Error en Whatweb: {str(e)}", "WHATWEB", "ERROR")
    
    def _ejecutar_chkrootkit(self):
        """Ejecutar Chkrootkit para detectar rootkits con configuración optimizada."""
        import subprocess
        try:
            self._log_terminal("Iniciando análisis profundo con Chkrootkit...", "CHKROOTKIT", "INFO")
            
            # Configuración optimizada para Kali Linux
            comando = ['chkrootkit', '-q']  # Modo quiet para output más limpio
            
            # Usar SudoManager para permisos elevados necesarios
            try:
                from aresitos.utils.sudo_manager import get_sudo_manager
                sudo_manager = get_sudo_manager()
                
                if sudo_manager.is_sudo_active():
                    # Ejecutar con sudo para acceso completo al sistema
                    self._log_terminal("Ejecutando con permisos elevados para análisis completo...", "CHKROOTKIT", "INFO")
                    resultado = sudo_manager.execute_sudo_command('chkrootkit -q', timeout=420)
                else:
                    # Fallback sin sudo
                    self._log_terminal("Ejecutando sin sudo - análisis limitado...", "CHKROOTKIT", "WARNING")
                    resultado = subprocess.run(comando, capture_output=True, text=True, timeout=420)
            except ImportError:
                # Fallback si SudoManager no está disponible
                resultado = subprocess.run(comando, capture_output=True, text=True, timeout=420)
            
            if resultado.returncode == 0:
                # Análisis inteligente de resultados
                lineas = resultado.stdout.split('\n')
                sospechas_criticas = []
                sospechas_moderadas = []
                informacion_general = []
                
                # Patrones mejorados de detección
                patrones_criticos = ['INFECTED', 'SUSPECT', 'MALWARE', 'ROOTKIT', 'TROJAN']
                patrones_moderados = ['WARNING', 'POSSIBLE', 'SUSPICIOUS', 'UNKNOWN']
                patrones_informativos = ['CHECKING', 'FOUND', 'OK']
                
                for linea in lineas:
                    linea_upper = linea.upper().strip()
                    if not linea_upper:
                        continue
                        
                    # Clasificar hallazgos por criticidad
                    if any(patron in linea_upper for patron in patrones_criticos):
                        sospechas_criticas.append(linea.strip())
                    elif any(patron in linea_upper for patron in patrones_moderados):
                        sospechas_moderadas.append(linea.strip())
                    elif any(patron in linea_upper for patron in patrones_informativos):
                        if 'INFECTED' not in linea_upper and 'SUSPECT' not in linea_upper:
                            informacion_general.append(linea.strip())
                
                # Reportar resultados de forma inteligente
                total_criticas = len(sospechas_criticas)
                total_moderadas = len(sospechas_moderadas)
                
                if total_criticas > 0:
                    self._log_terminal(f"CHKROOTKIT: WARNING {total_criticas} amenazas CRITICAS detectadas", "CHKROOTKIT", "ERROR")
                    for sospecha in sospechas_criticas[:8]:  # Mostrar hasta 8 críticas
                        if sospecha:
                            self._log_terminal(f"  CRITICO {sospecha}", "CHKROOTKIT", "ERROR")
                    if total_criticas > 8:
                        self._log_terminal(f"  ... y {total_criticas - 8} amenazas críticas adicionales", "CHKROOTKIT", "ERROR")
                
                if total_moderadas > 0:
                    self._log_terminal(f"CHKROOTKIT: WARNING {total_moderadas} elementos sospechosos detectados", "CHKROOTKIT", "WARNING")
                    for sospecha in sospechas_moderadas[:5]:  # Mostrar hasta 5 moderadas
                        if sospecha:
                            self._log_terminal(f"  SOSPECHOSO {sospecha}", "CHKROOTKIT", "WARNING")
                    if total_moderadas > 5:
                        self._log_terminal(f"  ... y {total_moderadas - 5} elementos sospechosos adicionales", "CHKROOTKIT", "WARNING")
                
                if total_criticas == 0 and total_moderadas == 0:
                    self._log_terminal("CHKROOTKIT: OK Sistema limpio - No se detectaron rootkits conocidos", "CHKROOTKIT", "SUCCESS")
                    
                # Información adicional sobre el análisis
                total_checks = len(informacion_general)
                if total_checks > 0:
                    self._log_terminal(f"CHKROOTKIT: Análisis completado - {total_checks} verificaciones realizadas", "CHKROOTKIT", "INFO")
                    
            else:
                error_output = resultado.stderr.strip() if resultado.stderr else "Sin información de error"
                self._log_terminal(f"CHKROOTKIT: Error en ejecución (código {resultado.returncode})", "CHKROOTKIT", "WARNING")
                if error_output:
                    self._log_terminal(f"CHKROOTKIT: {error_output}", "CHKROOTKIT", "WARNING")
                
        except subprocess.TimeoutExpired:
            self._log_terminal("CHKROOTKIT: Timeout después de 7 minutos - Sistema puede estar sobrecargado", "CHKROOTKIT", "WARNING")
            self._log_terminal("CHKROOTKIT: Recomendación: Ejecutar manualmente con más tiempo", "CHKROOTKIT", "INFO")
        except Exception as e:
            self._log_terminal(f"CHKROOTKIT: Error inesperado - {str(e)}", "CHKROOTKIT", "ERROR")
            # Información de troubleshooting
            self._log_terminal("CHKROOTKIT: Verifique que chkrootkit esté instalado: sudo apt install chkrootkit", "CHKROOTKIT", "INFO")
    
    def _ejecutar_rkhunter(self):
        """Ejecutar RKHunter para caza de rootkits."""
        import subprocess
        try:
            self._log_terminal("Ejecutando RKHunter (cazador de rootkits)...", "RKHUNTER", "WARNING")
            
            # RKHunter con chequeos básicos y rápidos
            resultado = subprocess.run(['rkhunter', '--check', '--skip-keypress', '--report-warnings-only'], 
                                     capture_output=True, text=True, timeout=120)
            
            if resultado.stdout.strip():
                lineas = resultado.stdout.split('\n')
                advertencias = []
                
                for linea in lineas:
                    if any(palabra in linea.upper() for palabra in ['WARNING', 'SUSPECT', 'INFECTION']):
                        advertencias.append(linea.strip())
                
                if advertencias:
                    self._log_terminal(f"RKHUNTER: {len(advertencias)} advertencias encontradas", "RKHUNTER", "WARNING")
                    for adv in advertencias[:8]:
                        if adv:
                            self._log_terminal(f"  {adv}", "RKHUNTER", "WARNING")
                else:
                    self._log_terminal("RKHUNTER: Análisis completado sin advertencias críticas", "RKHUNTER", "SUCCESS")
            else:
                self._log_terminal("RKHUNTER: Análisis silencioso - sin problemas detectados", "RKHUNTER", "INFO")
                
        except subprocess.TimeoutExpired:
            self._log_terminal("RKHUNTER: Timeout - análisis interrumpido", "RKHUNTER", "WARNING")
        except Exception as e:
            self._log_terminal(f"Error en RKHunter: {str(e)}", "RKHUNTER", "ERROR")
    
    def _ejecutar_clamav(self):
        """Ejecutar ClamAV para escaneo de malware."""
        import subprocess
        import os
        try:
            self._log_terminal("Ejecutando ClamAV (escaneo de malware)...", "CLAMAV", "WARNING")
            
            # Escanear directorios críticos con ClamAV
            directorios_criticos = ['/tmp', '/var/tmp', '/home']
            
            for directorio in directorios_criticos:
                if os.path.exists(directorio):
                    try:
                        self._log_terminal(f"Escaneando {directorio} con ClamAV...", "CLAMAV", "INFO")
                        resultado = subprocess.run(['clamscan', '-r', '--bell', directorio], 
                                                 capture_output=True, text=True, timeout=120)
                        
                        if 'FOUND' in resultado.stdout.upper():
                            lineas = resultado.stdout.split('\n')
                            malware_encontrado = []
                            
                            for linea in lineas:
                                if 'FOUND' in linea.upper():
                                    malware_encontrado.append(linea.strip())
                            
                            if malware_encontrado:
                                self._log_terminal(f"CLAMAV: {len(malware_encontrado)} archivos sospechosos en {directorio}", "CLAMAV", "ERROR")
                                for malware in malware_encontrado[:5]:
                                    self._log_terminal(f"  {malware}", "CLAMAV", "ERROR")
                        else:
                            self._log_terminal(f"CLAMAV: {directorio} limpio", "CLAMAV", "SUCCESS")
                            
                    except subprocess.TimeoutExpired:
                        self._log_terminal(f"CLAMAV: Timeout escaneando {directorio}", "CLAMAV", "WARNING")
                    except Exception as e:
                        self._log_terminal(f"CLAMAV: Error en {directorio}: {str(e)}", "CLAMAV", "WARNING")
                        
        except Exception as e:
            self._log_terminal(f"Error en ClamAV: {str(e)}", "CLAMAV", "ERROR")
    
    def _analizar_strings_sospechosos(self):
        """Analizar strings en archivos sospechosos."""
        import subprocess
        import os
        try:
            self._log_terminal("Analizando strings en archivos sospechosos...", "STRINGS", "INFO")
            
            # Buscar archivos binarios recientes en ubicaciones sospechosas
            directorios_sospechosos = ['/tmp', '/var/tmp', '/dev/shm']
            
            for directorio in directorios_sospechosos:
                if os.path.exists(directorio):
                    try:
                        # Buscar archivos ejecutables recientes
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-executable', '-mtime', '-1'], 
                                                 capture_output=True, text=True, timeout=30)
                        
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos = resultado.stdout.strip().split('\n')[:3]  # Primeros 3
                            
                            for archivo in archivos:
                                if archivo.strip():
                                    try:
                                        # Analizar strings del archivo
                                        strings_result = subprocess.run(['strings', archivo], 
                                                                      capture_output=True, text=True, timeout=15)
                                        
                                        if strings_result.returncode == 0:
                                            strings_sospechosos = []
                                            for string in strings_result.stdout.split('\n'):
                                                # Buscar strings sospechosos
                                                if any(sospechoso in string.lower() for sospechoso in 
                                                      ['password', 'backdoor', 'shell', 'exploit', 'payload']):
                                                    strings_sospechosos.append(string.strip())
                                            
                                            if strings_sospechosos:
                                                self._log_terminal(f"STRINGS SOSPECHOSOS en {archivo}:", "STRINGS", "WARNING")
                                                for s in strings_sospechosos[:3]:
                                                    if s:
                                                        self._log_terminal(f"  {s[:50]}...", "STRINGS", "WARNING")
                                                        
                                    except Exception:
                                        continue
                                        
                    except Exception:
                        continue
                        
        except Exception as e:
            self._log_terminal(f"Error analizando strings: {str(e)}", "STRINGS", "ERROR")
    
    def _analizar_binwalk(self):
        """Analizar archivos con Binwalk."""
        import subprocess
        import os
        try:
            self._log_terminal("Ejecutando análisis Binwalk en archivos críticos...", "BINWALK", "INFO")
            
            # Analizar algunos archivos del sistema con binwalk
            archivos_criticos = ['/usr/bin/python3', '/bin/bash', '/bin/sh']
            
            for archivo in archivos_criticos:
                if os.path.exists(archivo):
                    try:
                        resultado = subprocess.run(['binwalk', archivo], 
                                                 capture_output=True, text=True, timeout=30)
                        
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            lineas = resultado.stdout.split('\n')
                            hallazgos = []
                            
                            for linea in lineas:
                                if any(palabra in linea.lower() for palabra in ['compressed', 'encrypted', 'archive']):
                                    hallazgos.append(linea.strip())
                            
                            if hallazgos:
                                self._log_terminal(f"BINWALK: Hallazgos en {archivo}", "BINWALK", "INFO")
                                for hallazgo in hallazgos[:3]:
                                    if hallazgo:
                                        self._log_terminal(f"  {hallazgo}", "BINWALK", "INFO")
                                        
                    except subprocess.TimeoutExpired:
                        self._log_terminal(f"BINWALK: Timeout analizando {archivo}", "BINWALK", "WARNING")
                    except Exception:
                        continue
                        
        except Exception as e:
            self._log_terminal(f"Error en Binwalk: {str(e)}", "BINWALK", "ERROR")
    
    def _ejecutar_pspy(self):
        """Ejecutar Pspy para monitoreo de procesos sin root."""
        import subprocess
        try:
            self._log_terminal("Ejecutando Pspy (monitor de procesos sin root)...", "PSPY", "INFO")
            
            # Ejecutar pspy por tiempo limitado
            resultado = subprocess.run(['timeout', '30', 'pspy64'], 
                                     capture_output=True, text=True, timeout=35)
            
            if resultado.stdout.strip():
                lineas = resultado.stdout.split('\n')
                procesos_interesantes = []
                
                for linea in lineas:
                    if any(palabra in linea.lower() for palabra in ['exec', 'cron', 'shell', 'script']):
                        procesos_interesantes.append(linea.strip())
                
                if procesos_interesantes:
                    self._log_terminal(f"PSPY: {len(procesos_interesantes)} procesos interesantes detectados", "PSPY", "WARNING")
                    for proceso in procesos_interesantes[:8]:
                        if proceso:
                            self._log_terminal(f"  {proceso[:100]}...", "PSPY", "INFO")
                else:
                    self._log_terminal("PSPY: Actividad de procesos normal", "PSPY", "INFO")
            else:
                self._log_terminal("PSPY: Sin salida o herramienta no disponible", "PSPY", "WARNING")
                
        except subprocess.TimeoutExpired:
            self._log_terminal("PSPY: Monitoreo completado (timeout esperado)", "PSPY", "INFO")
        except Exception as e:
            self._log_terminal(f"Error en Pspy: {str(e)}", "PSPY", "ERROR")
    
    def _analizar_lsof_avanzado(self):
        """Análisis avanzado con lsof."""
        import subprocess
        try:
            self._log_terminal("Ejecutando análisis avanzado con lsof...", "LSOF", "INFO")
            
            # Análisis de archivos abiertos por procesos sospechosos
            comandos_lsof = [
                ['lsof', '+L1'],  # Archivos borrados pero aún en uso
                ['lsof', '-i'],   # Conexiones de red
                ['lsof', '-U']    # Sockets Unix
            ]
            
            nombres_analisis = ['Archivos borrados en uso', 'Conexiones de red', 'Sockets Unix']
            
            for i, (cmd, nombre) in enumerate(zip(comandos_lsof, nombres_analisis)):
                try:
                    resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    
                    if resultado.returncode == 0 and resultado.stdout.strip():
                        lineas = resultado.stdout.split('\n')[1:]  # Skip header
                        elementos_relevantes = []
                        
                        for linea in lineas[:20]:  # Primeros 20
                            if linea.strip():
                                elementos_relevantes.append(linea.strip())
                        
                        if elementos_relevantes:
                            self._log_terminal(f"LSOF {nombre}: {len(elementos_relevantes)} elementos detectados", "LSOF", "INFO")
                            for elemento in elementos_relevantes[:5]:
                                self._log_terminal(f"  {elemento[:80]}...", "LSOF", "INFO")
                        else:
                            self._log_terminal(f"LSOF {nombre}: Sin elementos relevantes", "LSOF", "INFO")
                    else:
                        self._log_terminal(f"LSOF {nombre}: Sin resultados", "LSOF", "WARNING")
                        
                except subprocess.TimeoutExpired:
                    self._log_terminal(f"LSOF {nombre}: Timeout", "LSOF", "WARNING")
                except Exception as e:
                    self._log_terminal(f"LSOF {nombre}: Error {str(e)}", "LSOF", "ERROR")
                    
        except Exception as e:
            self._log_terminal(f"Error en análisis lsof avanzado: {str(e)}", "LSOF", "ERROR")
    
    def _verificar_configuraciones_seguridad(self):
        """Verificar configuraciones críticas de seguridad del sistema."""
        import subprocess
        import os
        
        try:
            self._log_terminal("Verificando configuraciones críticas de seguridad", "SEGURIDAD", "INFO")
            
            # 1. Verificar configuración SSH
            ssh_config = '/etc/ssh/sshd_config'
            if os.path.exists(ssh_config):
                self._log_terminal("Analizando configuración SSH...", "SSH", "INFO")
                try:
                    with open(ssh_config, 'r') as f:
                        contenido = f.read()
                        
                    # Verificar configuraciones críticas
                    if 'PermitRootLogin no' in contenido or 'PermitRootLogin yes' not in contenido:
                        self._log_terminal("SSH: PermitRootLogin configurado correctamente", "SSH", "INFO")
                    else:
                        self._log_terminal("SSH: ADVERTENCIA - PermitRootLogin puede estar habilitado", "SSH", "WARNING")
                        
                    if 'PasswordAuthentication no' in contenido:
                        self._log_terminal("SSH: Autenticación por contraseña deshabilitada (seguro)", "SSH", "INFO")
                    else:
                        self._log_terminal("SSH: Autenticación por contraseña habilitada", "SSH", "WARNING")
                        
                except Exception as e:
                    self._log_terminal(f"Error leyendo configuración SSH: {str(e)}", "SSH", "WARNING")
            
            # 2. Verificar firewall
            self._log_terminal("Verificando estado del firewall...", "FIREWALL", "INFO")
            try:
                # Verificar iptables
                resultado = subprocess.run(['iptables', '-L'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')
                    reglas = len([l for l in lineas if l.strip() and not l.startswith('Chain') and not l.startswith('target')])
                    self._log_terminal(f"FIREWALL: {reglas} reglas iptables activas", "FIREWALL", "INFO")
                    
                    # Verificar si hay reglas DROP
                    if 'DROP' in resultado.stdout:
                        self._log_terminal("FIREWALL: Políticas de bloqueo detectadas", "FIREWALL", "INFO")
                    else:
                        self._log_terminal("FIREWALL: ADVERTENCIA - No se detectan políticas de bloqueo", "FIREWALL", "WARNING")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando firewall: {str(e)}", "FIREWALL", "WARNING")
            
            # 3. Verificar permisos de archivos críticos
            self._log_terminal("Verificando permisos de archivos críticos...", "PERMISOS", "INFO")
            archivos_criticos = {
                '/etc/passwd': '644',
                '/etc/shadow': '640',
                '/etc/sudoers': '440',
                '/boot': '755'
            }
            
            for archivo, permisos_esperados in archivos_criticos.items():
                if os.path.exists(archivo):
                    try:
                        stat_info = os.stat(archivo)
                        permisos_actuales = oct(stat_info.st_mode)[-3:]
                        
                        if permisos_actuales == permisos_esperados:
                            self._log_terminal(f"PERMISOS: {archivo} correcto ({permisos_actuales})", "PERMISOS", "INFO")
                        else:
                            self._log_terminal(f"PERMISOS: {archivo} INCORRECTO ({permisos_actuales}, esperado {permisos_esperados})", "PERMISOS", "WARNING")
                            
                    except Exception as e:
                        self._log_terminal(f"Error verificando permisos de {archivo}: {str(e)}", "PERMISOS", "WARNING")
            
            # 4. Verificar usuarios con privilegios
            self._log_terminal("Verificando usuarios con privilegios especiales...", "USUARIOS", "INFO")
            try:
                # Usuarios con UID 0 (root)
                resultado = subprocess.run(['awk', '-F:', '$3==0{print $1}', '/etc/passwd'], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    usuarios_root = resultado.stdout.strip().split('\n')
                    for usuario in usuarios_root:
                        if usuario.strip():
                            if usuario == 'root':
                                self._log_terminal(f"USUARIO ROOT: {usuario} (normal)", "USUARIOS", "INFO")
                            else:
                                self._log_terminal(f"USUARIO ROOT: {usuario} (SOSPECHOSO)", "USUARIOS", "ERROR")
                
                # Usuarios en grupo sudo
                if os.path.exists('/etc/group'):
                    resultado = subprocess.run(['grep', '^sudo:', '/etc/group'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        linea_sudo = resultado.stdout.strip()
                        if ':' in linea_sudo:
                            usuarios_sudo = linea_sudo.split(':')[-1].split(',') if linea_sudo.split(':')[-1] else []
                            for usuario in usuarios_sudo:
                                if usuario.strip():
                                    self._log_terminal(f"USUARIO SUDO: {usuario.strip()}", "USUARIOS", "INFO")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando usuarios: {str(e)}", "USUARIOS", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error verificando configuraciones de seguridad: {str(e)}", "SEGURIDAD", "ERROR")
    
    def _detectar_rootkits_avanzado(self):
        """Detección avanzada de rootkits y backdoors usando múltiples métodos."""
        import subprocess
        import os
        
        try:
            self._log_terminal("Iniciando detección avanzada de rootkits y backdoors", "ROOTKIT", "WARNING")
            
            # 1. Verificar herramientas de detección disponibles
            herramientas_deteccion = ['chkrootkit', 'rkhunter', 'clamav']
            herramientas_disponibles = []
            
            for herramienta in herramientas_deteccion:
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        herramientas_disponibles.append(herramienta)
                        self._log_terminal(f"DETECTOR DISPONIBLE: {herramienta}", "ROOTKIT", "INFO")
                except:
                    pass
            
            # 2. Verificar archivos de sistema modificados recientemente
            self._log_terminal("Verificando archivos de sistema modificados recientemente...", "ROOTKIT", "INFO")
            try:
                directorios_sistema = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
                for directorio in directorios_sistema:
                    if os.path.exists(directorio):
                        # Buscar archivos modificados en las últimas 24 horas
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-mtime', '-1'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos_modificados = resultado.stdout.strip().split('\n')
                            for archivo in archivos_modificados[:5]:  # Mostrar primeros 5
                                if archivo.strip():
                                    try:
                                        stat_info = os.stat(archivo)
                                        from datetime import datetime
                                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                        self._log_terminal(f"SISTEMA MODIFICADO: {archivo} (mod: {mod_time})", "ROOTKIT", "WARNING")
                                    except:
                                        pass
                        
            except Exception as e:
                self._log_terminal(f"Error verificando archivos de sistema: {str(e)}", "ROOTKIT", "WARNING")
            
            # 3. Buscar procesos ocultos o sospechosos
            self._log_terminal("Buscando procesos ocultos o con nombres sospechosos...", "ROOTKIT", "INFO")
            try:
                resultado = subprocess.run(['ps', 'aux'], 
                                         capture_output=True, text=True, timeout=15)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]  # Skip header
                    procesos_sospechosos = []
                    
                    patrones_sospechosos = [
                        'kthreadd', 'ksoftirqd', '[', ']', 'migration', 'watchdog',
                        'rcu_', 'systemd', 'kworker', 'ksoftirqd'
                    ]
                    
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 11:
                                proceso = ' '.join(partes[10:])
                                
                                # Buscar patrones anómalos
                                if any(patron in proceso.lower() for patron in ['backdoor', 'rootkit', 'trojan']):
                                    procesos_sospechosos.append(proceso)
                                    self._log_terminal(f"PROCESO SOSPECHOSO: {proceso}", "ROOTKIT", "ERROR")
                                
                                # Procesos con nombres muy cortos o extraños
                                nombre_proceso = partes[10] if len(partes) > 10 else ''
                                if len(nombre_proceso) == 1 and nombre_proceso.isalpha():
                                    self._log_terminal(f"PROCESO NOMBRE EXTRAÑO: {proceso}", "ROOTKIT", "WARNING")
                
            except Exception as e:
                self._log_terminal(f"Error analizando procesos: {str(e)}", "ROOTKIT", "WARNING")
            
            # 4. Verificar conexiones de red sospechosas
            self._log_terminal("Verificando conexiones de red sospechosas...", "ROOTKIT", "INFO")
            try:
                resultado = subprocess.run(['ss', '-tupln'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]  # Skip header
                    puertos_sospechosos = ['1337', '31337', '12345', '54321', '9999']
                    
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 4:
                                direccion_local = partes[3]
                                puerto = direccion_local.split(':')[-1]
                                
                                if puerto in puertos_sospechosos:
                                    self._log_terminal(f"PUERTO SOSPECHOSO ABIERTO: {puerto} ({direccion_local})", "ROOTKIT", "ERROR")
                                
                                # Verificar puertos altos poco comunes
                                try:
                                    puerto_num = int(puerto)
                                    if puerto_num > 49152 and 'LISTEN' in linea:
                                        self._log_terminal(f"PUERTO ALTO EN ESCUCHA: {puerto}", "ROOTKIT", "WARNING")
                                except:
                                    pass
                
            except Exception as e:
                self._log_terminal(f"Error verificando conexiones: {str(e)}", "ROOTKIT", "WARNING")
            
            # 5. Verificar cargas del kernel sospechosas
            self._log_terminal("Verificando módulos del kernel cargados...", "ROOTKIT", "INFO")
            try:
                resultado = subprocess.run(['lsmod'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]  # Skip header
                    modulos_sospechosos = []
                    
                    for linea in lineas[:20]:  # Primeros 20 módulos
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 1:
                                modulo = partes[0]
                                # Buscar módulos con nombres extraños
                                if any(char in modulo.lower() for char in ['rootkit', 'backdoor', 'hide']):
                                    modulos_sospechosos.append(modulo)
                                    self._log_terminal(f"MÓDULO SOSPECHOSO: {modulo}", "ROOTKIT", "ERROR")
                    
                    total_modulos = len(lineas)
                    self._log_terminal(f"MÓDULOS KERNEL: {total_modulos} módulos cargados", "ROOTKIT", "INFO")
                
            except Exception as e:
                self._log_terminal(f"Error verificando módulos kernel: {str(e)}", "ROOTKIT", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error en detección de rootkits: {str(e)}", "ROOTKIT", "ERROR")
    
    def obtener_datos_para_reporte(self):
        """Obtener datos del escaneador para incluir en reportes."""
        try:
            # Obtener el texto de resultados del escaneador
            if hasattr(self, 'text_resultados'):
                contenido_escaneo = self.text_resultados.get(1.0, 'end-1c')
            else:
                contenido_escaneo = "No hay resultados de escaneo disponibles"
            
            # Crear estructura de datos para el reporte
            datos_escaneo = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Escaneador Avanzado',
                'estado': 'activo' if self.flag_proceso.is_set() else 'inactivo',
                'version_expandida': True,
                'herramientas_disponibles': self._verificar_herramientas_disponibles(),
                'resultados_texto': contenido_escaneo[-2000:] if len(contenido_escaneo) > 2000 else contenido_escaneo,  # Últimos 2000 caracteres
                'estadisticas': {
                    'lineas_resultados': len(contenido_escaneo.split('\n')),
                    'palabras_clave_seguridad': self._contar_palabras_clave_seguridad(contenido_escaneo),
                    'alertas_detectadas': contenido_escaneo.count('WARNING') + contenido_escaneo.count('ERROR'),
                    'escaneos_exitosos': contenido_escaneo.count('SUCCESS') + contenido_escaneo.count('completada exitosamente')
                },
                'resumen_herramientas': {
                    'nmap': 'NMAP' in contenido_escaneo,
                    'masscan': 'MASSCAN' in contenido_escaneo,
                    'nikto': 'NIKTO' in contenido_escaneo,
                    'chkrootkit': 'CHKROOTKIT' in contenido_escaneo,
                    'clamav': 'CLAMAV' in contenido_escaneo,
                    'lsof': 'LSOF' in contenido_escaneo
                },
                'info_sistema': 'Escaneador expandido con 25+ herramientas de Kali Linux integradas'
            }
            
            return datos_escaneo
            
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Escaneador',
                'estado': 'error',
                'error': f'Error obteniendo datos: {str(e)}',
                'info': 'Error al obtener datos del escaneador para reporte'
            }
    
    def _verificar_herramientas_disponibles(self):
        """Verificar qué herramientas de Kali están disponibles."""
        import subprocess
        herramientas_kali = [
            'nmap', 'masscan', 'rustscan', 'nikto', 'dirb', 'gobuster', 
            'whatweb', 'httpx', 'chkrootkit', 'rkhunter', 'clamav',
            'binwalk', 'strings', 'lsof', 'pspy'
        ]
        
        disponibles = []
        for herramienta in herramientas_kali:
            try:
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, text=True, timeout=3)
                if resultado.returncode == 0:
                    disponibles.append(herramienta)
            except:
                pass
        
        return {
            'total_disponibles': len(disponibles),
            'total_posibles': len(herramientas_kali),
            'porcentaje_disponibilidad': round((len(disponibles) / len(herramientas_kali)) * 100, 1),
            'herramientas': disponibles
        }
    
    def _contar_palabras_clave_seguridad(self, texto):
        """Contar palabras clave relacionadas con seguridad en el texto."""
        palabras_clave = [
            'vulnerability', 'exploit', 'malware', 'rootkit', 'backdoor',
            'suspicious', 'warning', 'error', 'infected', 'threat',
            'puerto', 'servicio', 'proceso', 'conexion', 'archivo'
        ]
        
        texto_lower = texto.lower()
        conteo = {}
        
        for palabra in palabras_clave:
            conteo[palabra] = texto_lower.count(palabra)
        
        return conteo

    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            from aresitos.utils.seguridad_comandos import validador_comandos
            
            comandos = validador_comandos.obtener_comandos_disponibles()
            
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "  COMANDOS DISPONIBLES EN ARESITOS v2.0 - ESCANEADOR\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            
            for categoria, lista_comandos in comandos.items():
                self.terminal_output.insert(tk.END, f"[CATEGORIA] {categoria.upper()}:\n")
                comandos_linea = ", ".join(lista_comandos)
                self.terminal_output.insert(tk.END, f"   {comandos_linea}\n\n")
            
            self.terminal_output.insert(tk.END, "🔧 COMANDOS ESPECIALES:\n")
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
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS - ESCANEADOR\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            
            estado_seguridad = "OK SEGURO" if info['es_usuario_kali'] else "ERROR INSEGURO"
            
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
                pass  # Widget ya no existe o ha sido destruido
        
        # Programar la actualización para el hilo principal
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass  # Ventana ya destruida

    def _actualizar_resultados_seguro(self, texto, modo="append"):
        """Actualizar text_resultados de forma segura desde threads."""
        def _update():
            try:
                if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                    if modo == "clear":
                        self.text_resultados.delete(1.0, tk.END)
                    elif modo == "replace":
                        self.text_resultados.delete(1.0, tk.END)
                        self.text_resultados.insert(1.0, texto)
                    elif modo == "append":
                        self.text_resultados.insert(tk.END, texto)
                    elif modo == "insert_start":
                        self.text_resultados.insert(1.0, texto)
                    self.text_resultados.see(tk.END)
                    if hasattr(self.text_resultados, 'update'):
                        self.text_resultados.update()
            except (tk.TclError, AttributeError):
                pass  # Widget ya no existe o ha sido destruido
        
        # Programar la actualización para el hilo principal
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass  # Ventana ya destruida


# RESUMEN: Interfaz de escaneo de vulnerabilidades con opciones básicas y avanzadas.

