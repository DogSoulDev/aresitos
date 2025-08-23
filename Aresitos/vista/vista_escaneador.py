# -*- coding: utf-8 -*-
"""
ARESITOS - Vista Escaneador Unificada v3.0
==========================================

Interfaz gráfica unificada para operaciones de escaneo de seguridad.
Consolida todas las funcionalidades de escaneo en una vista optimizada.

Principios ARESITOS aplicados:
- Interfaz limpia sin emoticonos
- Funcionalidad completa unificada
- Código optimizado y mantenible

Autor: DogSoulDev
Versión: 3.0
Fecha: Agosto 2025
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import logging
import threading
import datetime
import json

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None


class VistaEscaneador(tk.Frame):
    """
    Vista unificada para operaciones de escaneo.
    
    Integra todas las funcionalidades de escaneo en una interfaz limpia y funcional.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_activo = False
        self.thread_escaneo = None
        self.vista_principal = parent
        
        # Configurar logging de forma robusta siguiendo principios ARESITOS
        self._inicializar_logger()
        
        # Configurar tema
        self._configurar_tema()
        
        # Variables de la interfaz
        self._inicializar_variables()
        
        # Crear interfaz
        self._crear_interfaz()
        
        if self.logger:
            self.logger.info("VistaEscaneador v3.0 inicializada correctamente")

    def _inicializar_logger(self):
        """
        Inicializar logger de forma robusta siguiendo principios ARESITOS.
        
        Principios aplicados:
        - Robustez: Manejo de errores en inicialización
        - Automatización: Configuración automática
        - Transparencia: Logs claros sobre el estado
        """
        try:
            self.logger = logging.getLogger(__name__)
            if not self.logger.handlers:
                # Configurar handler básico si no existe
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
                self.logger.setLevel(logging.INFO)
            
            self.logger.info("Logger Vista Escaneador inicializado correctamente")
            
        except Exception as e:
            # Fallback a print si hay problemas con logging
            print(f"ERROR inicializando logger Vista Escaneador: {e}")
            self.logger = None

    def _configurar_tema(self):
        """Configurar tema visual Burp Suite."""
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            # Configurar estilo TTK
            self.style = ttk.Style()
            self.theme.configure_ttk_style(self.style)
            
            # Usar colores del tema Burp
            self.colores = {
                'bg_principal': burp_theme.get_color('bg_primary'),
                'bg_secundario': burp_theme.get_color('bg_secondary'),
                'texto_principal': burp_theme.get_color('fg_primary'),
                'texto_secundario': burp_theme.get_color('fg_secondary'),
                'acento': burp_theme.get_color('fg_accent'),
                'exito': burp_theme.get_color('success'),
                'error': burp_theme.get_color('danger'),
                'warning': burp_theme.get_color('warning')
            }
        else:
            # Fallback a tema por defecto
            self.colores = {
                'bg_principal': '#2b2b2b',
                'bg_secundario': '#3c3c3c',
                'texto_principal': '#ffffff',
                'texto_secundario': '#cccccc',
                'acento': '#ff6b35',
                'exito': '#4caf50',
                'error': '#f44336',
                'warning': '#ff9800'
            }
        
        self.configure(bg=self.colores['bg_principal'])

    def _inicializar_variables(self):
        """Inicializar variables de la vista."""
        self.var_objetivo = tk.StringVar()
        self.var_tipo_escaneo = tk.StringVar(value="completo")
        self.var_progreso = tk.IntVar()
        self.var_estado = tk.StringVar(value="Listo")
        
        # Opciones de escaneo
        self.tipos_escaneo = [
            ("Completo", "completo"),
            ("Red", "red"),
            ("Sistema", "sistema"),
            ("Vulnerabilidades", "vulnerabilidades"),
            ("Web", "web")
        ]

    def _crear_interfaz(self):
        """Crear la interfaz gráfica."""
        # Frame principal
        main_frame = ttk.Frame(self, style="Burp.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Crear secciones
        self._crear_seccion_configuracion(main_frame)
        self._crear_seccion_control(main_frame)
        self._crear_seccion_progreso(main_frame)
        self._crear_seccion_resultados(main_frame)
        self._crear_seccion_estado(main_frame)

    def _crear_seccion_configuracion(self, parent):
        """Crear sección de configuración de escaneo."""
        config_frame = ttk.LabelFrame(parent, text="Configuración de Escaneo", style="Burp.TLabelframe")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Objetivo
        ttk.Label(config_frame, text="Objetivo:", style="Burp.TLabel").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_objetivo = ttk.Entry(config_frame, textvariable=self.var_objetivo, width=40, style="Burp.TEntry")
        self.entry_objetivo.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        
        # Tipo de escaneo
        ttk.Label(config_frame, text="Tipo:", style="Burp.TLabel").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        tipo_combo = ttk.Combobox(config_frame, textvariable=self.var_tipo_escaneo, 
                                 values=[tipo[1] for tipo in self.tipos_escaneo], 
                                 state="readonly", width=15, style="Burp.TCombobox")
        tipo_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Botón de validación
        validar_btn = ttk.Button(config_frame, text="Validar Objetivo", 
                               command=self._validar_objetivo, style="Burp.TButton")
        validar_btn.grid(row=1, column=2, sticky=tk.E, padx=5, pady=5)
        
        config_frame.grid_columnconfigure(1, weight=1)

    def _crear_seccion_control(self, parent):
        """Crear sección de control de escaneo."""
        control_frame = ttk.LabelFrame(parent, text="Control de Escaneo", style="Burp.TLabelframe")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de control
        self.btn_iniciar = ttk.Button(control_frame, text="Iniciar Escaneo", 
                                     command=self._iniciar_escaneo, state=tk.NORMAL, style="Burp.TButton")
        self.btn_iniciar.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.btn_detener = ttk.Button(control_frame, text="Detener Escaneo", 
                                     command=self._detener_escaneo, state=tk.DISABLED, style="Burp.TButton")
        self.btn_detener.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.btn_limpiar = ttk.Button(control_frame, text="Limpiar Resultados", 
                                     command=self._limpiar_resultados, style="Burp.TButton")
        self.btn_limpiar.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Información de estado
        self.lbl_estado = ttk.Label(control_frame, textvariable=self.var_estado, style="Burp.TLabel")
        self.lbl_estado.pack(side=tk.RIGHT, padx=5, pady=5)

    def _crear_seccion_progreso(self, parent):
        """Crear sección de progreso."""
        progreso_frame = ttk.LabelFrame(parent, text="Progreso")
        progreso_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Barra de progreso
        self.progress_bar = ttk.Progressbar(progreso_frame, variable=self.var_progreso, 
                                          maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # Etiqueta de progreso
        self.lbl_progreso = ttk.Label(progreso_frame, text="0%")
        self.lbl_progreso.pack(pady=2)

    def _crear_seccion_resultados(self, parent):
        """Crear sección de resultados."""
        resultados_frame = ttk.LabelFrame(parent, text="Resultados")
        resultados_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Notebook para diferentes vistas
        self.notebook = ttk.Notebook(resultados_frame, style="Custom.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Pestaña de resumen
        self._crear_pestana_resumen()
        
        # Pestaña de detalles
        self._crear_pestana_detalles()
        
        # Pestaña de vulnerabilidades
        self._crear_pestana_vulnerabilidades()
        
        # Pestaña de logs
        self._crear_pestana_logs()

    def _crear_pestana_resumen(self):
        """Crear pestaña de resumen."""
        resumen_frame = ttk.Frame(self.notebook, style="Burp.TFrame")
        self.notebook.add(resumen_frame, text="Resumen")
        
        # Crear Treeview para resumen
        columns = ('Elemento', 'Cantidad', 'Estado')
        self.tree_resumen = ttk.Treeview(resumen_frame, columns=columns, show='headings', height=8, style="Burp.Treeview")
        
        for col in columns:
            self.tree_resumen.heading(col, text=col)
            self.tree_resumen.column(col, width=150)
        
        # Scrollbar para resumen
        scrollbar_resumen = ttk.Scrollbar(resumen_frame, orient=tk.VERTICAL, command=self.tree_resumen.yview, style="Burp.Vertical.TScrollbar")
        self.tree_resumen.configure(yscrollcommand=scrollbar_resumen.set)
        
        self.tree_resumen.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_resumen.pack(side=tk.RIGHT, fill=tk.Y)

    def _crear_pestana_detalles(self):
        """Crear pestaña de detalles."""
        detalles_frame = ttk.Frame(self.notebook, style="Burp.TFrame")
        self.notebook.add(detalles_frame, text="Detalles")
        
        # Texto con scroll para detalles
        self.text_detalles = scrolledtext.ScrolledText(detalles_frame, wrap=tk.WORD, height=15)
        self.text_detalles.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configurar tema Burp para widget Text siguiendo principios ARESITOS
        if hasattr(self, 'theme') and self.theme:
            self.theme.configure_text_widget(self.text_detalles)

    def _crear_pestana_vulnerabilidades(self):
        """Crear pestaña de vulnerabilidades."""
        vulns_frame = ttk.Frame(self.notebook, style="Burp.TFrame")
        self.notebook.add(vulns_frame, text="Vulnerabilidades")
        
        # Treeview para vulnerabilidades
        columns = ('Tipo', 'Severidad', 'Descripción')
        self.tree_vulns = ttk.Treeview(vulns_frame, columns=columns, show='headings', height=15, style="Burp.Treeview")
        
        for col in columns:
            self.tree_vulns.heading(col, text=col)
            if col == 'Descripción':
                self.tree_vulns.column(col, width=400)
            else:
                self.tree_vulns.column(col, width=120)
        
        # Scrollbar para vulnerabilidades
        scrollbar_vulns = ttk.Scrollbar(vulns_frame, orient=tk.VERTICAL, command=self.tree_vulns.yview, style="Burp.Vertical.TScrollbar")
        self.tree_vulns.configure(yscrollcommand=scrollbar_vulns.set)
        
        self.tree_vulns.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_vulns.pack(side=tk.RIGHT, fill=tk.Y)

    def _crear_pestana_logs(self):
        """Crear pestaña de logs."""
        logs_frame = ttk.Frame(self.notebook, style="Burp.TFrame")
        self.notebook.add(logs_frame, text="Logs")
        
        # Texto con scroll para logs
        self.text_logs = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD, height=15)
        self.text_logs.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configurar tema Burp para widget Text siguiendo principios ARESITOS
        if hasattr(self, 'theme') and self.theme:
            self.theme.configure_text_widget(self.text_logs)

    def _crear_seccion_estado(self, parent):
        """Crear sección de estado del sistema."""
        estado_frame = ttk.LabelFrame(parent, text="Estado del Sistema")
        estado_frame.pack(fill=tk.X)
        
        # Información del escaneador
        self.lbl_info = ttk.Label(estado_frame, text="Escaneador: No conectado")
        self.lbl_info.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Botón de actualización
        refresh_btn = ttk.Button(estado_frame, text="Actualizar Estado", 
                               command=self._actualizar_estado, style="Burp.TButton")
        refresh_btn.pack(side=tk.RIGHT, padx=5, pady=5)

    def _log_seguro(self, mensaje, nivel="info"):
        """
        Método de logging seguro siguiendo principios ARESITOS.
        
        Principios aplicados:
        - Robustez: Funciona aunque logger sea None
        - Simplicidad: Interfaz unificada para logs
        - Transparencia: Siempre registra información
        """
        try:
            if self.logger:
                if nivel == "info":
                    self.logger.info(mensaje)
                elif nivel == "error":
                    self.logger.error(mensaje)
                elif nivel == "warning":
                    self.logger.warning(mensaje)
                elif nivel == "debug":
                    self.logger.debug(mensaje)
            else:
                # Fallback a print con prefijo de nivel
                print(f"[ESCANEADOR-{nivel.upper()}] {mensaje}")
        except Exception:
            # Último recurso: print simple
            print(f"[ESCANEADOR] {mensaje}")

    def establecer_controlador(self, controlador):
        """Establecer controlador de escaneo con verificación robusta."""
        self.controlador = controlador
        if controlador:
            try:
                # Verificar que el controlador tenga los métodos necesarios
                metodos_requeridos = [
                    'escanear_objetivo', 'detener_escaneo', 'obtener_progreso',
                    'estado', 'registrar_callback', 'obtener_capacidades'
                ]
                
                for metodo in metodos_requeridos:
                    if not hasattr(controlador, metodo):
                        raise AttributeError(f"Controlador no tiene método: {metodo}")
                
                # Registrar callbacks con manejo de errores
                try:
                    controlador.registrar_callback('progreso', self._callback_progreso)
                    controlador.registrar_callback('completado', self._callback_completado)
                    controlador.registrar_callback('error', self._callback_error)
                    self._log_seguro("Callbacks registrados exitosamente")
                except Exception as e:
                    self._log_seguro(f"Error registrando callbacks: {e}", "error")
                
                # Actualizar estado inicial
                self._actualizar_estado()
                self._log_seguro("Controlador establecido correctamente")
                
            except Exception as e:
                self._log_seguro(f"Error estableciendo controlador: {e}", "error")
                self.controlador = None
                self.lbl_info.config(text=f"Error: Controlador inválido")
        else:
            self._log_seguro("Controlador es None", "warning")
            self.lbl_info.config(text="Controlador: No disponible")

    def _validar_objetivo(self):
        """Validar objetivo de escaneo."""
        objetivo = self.var_objetivo.get().strip()
        if not objetivo:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un objetivo")
            return
        
        # Aquí se podría agregar validación más específica
        self._log_mensaje(f"Objetivo validado: {objetivo}")
        messagebox.showinfo("Información", f"Objetivo válido: {objetivo}")

    def _iniciar_escaneo(self):
        """Iniciar proceso de escaneo con validación robusta."""
        # PRIMERO: Validar objetivo (datos del usuario)
        objetivo = self.var_objetivo.get().strip()
        if not objetivo:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un objetivo")
            # Enfocar el campo de objetivo si existe
            if hasattr(self, 'entry_objetivo'):
                self.entry_objetivo.focus()
            return
        
        # SEGUNDO: Verificar controlador (dependencias del sistema)
        if not self.controlador:
            messagebox.showerror("Error", "Controlador no disponible")
            self._log_seguro("Intento de escaneo sin controlador", "error")
            return
        
        # Obtener tipo de escaneo
        tipo_escaneo = self.var_tipo_escaneo.get()
        if not tipo_escaneo:
            tipo_escaneo = "completo"
        
        # Verificar si ya hay un escaneo en progreso
        if self.proceso_activo:
            messagebox.showwarning("Advertencia", "Ya hay un escaneo en progreso")
            return
        
        try:
            self._log_seguro(f"Iniciando escaneo: {objetivo} (tipo: {tipo_escaneo})")
            
            # Limpiar resultados anteriores
            self._limpiar_resultados()
            
            # Cambiar estado de la interfaz
            self._cambiar_estado_escaneo(True)
            self.var_estado.set("Iniciando...")
            self.var_progreso.set(0)
            
            # Iniciar escaneo asíncrono
            resultado = self.controlador.escanear_objetivo(objetivo, tipo_escaneo, asincrono=True)
            
            if resultado.get('exito'):
                self.var_estado.set("Escaneando...")
                self._log_mensaje(f"Escaneo iniciado: {objetivo} (tipo: {tipo_escaneo})")
                
                # Iniciar hilo para monitorear progreso
                self._iniciar_monitoreo_progreso()
                
            else:
                error = resultado.get('error', 'Error desconocido')
                self._cambiar_estado_escaneo(False)
                self.var_estado.set("Error")
                self._log_mensaje(f"ERROR al iniciar: {error}")
                messagebox.showerror("Error", f"No se pudo iniciar el escaneo: {error}")
                
        except Exception as e:
            self._log_seguro(f"Excepción en _iniciar_escaneo: {e}", "error")
            self._cambiar_estado_escaneo(False)
            self.var_estado.set("Error")
            messagebox.showerror("Error", f"Error al iniciar escaneo: {str(e)}")

    def _detener_escaneo(self):
        """Detener proceso de escaneo."""
        if not self.controlador:
            return
        
        try:
            resultado = self.controlador.detener_escaneo()
            if resultado.get('exito'):
                self._cambiar_estado_escaneo(False)
                self.var_estado.set("Detenido")
                self._log_mensaje("Escaneo detenido por el usuario")
            else:
                messagebox.showerror("Error", "No se pudo detener el escaneo")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al detener escaneo: {str(e)}")

    def _limpiar_resultados(self):
        """Limpiar resultados mostrados."""
        # Limpiar resumen
        for item in self.tree_resumen.get_children():
            self.tree_resumen.delete(item)
        
        # Limpiar detalles
        self.text_detalles.delete(1.0, tk.END)
        
        # Limpiar vulnerabilidades
        for item in self.tree_vulns.get_children():
            self.tree_vulns.delete(item)
        
        # Limpiar logs
        self.text_logs.delete(1.0, tk.END)
        
        # Resetear progreso
        self.var_progreso.set(0)
        self.lbl_progreso.config(text="0%")
        
        self._log_mensaje("Resultados limpiados")

    def _cambiar_estado_escaneo(self, escaneando):
        """Cambiar estado de los controles según si está escaneando."""
        self.proceso_activo = escaneando
        
        if escaneando:
            self.btn_iniciar.config(state=tk.DISABLED)
            self.btn_detener.config(state=tk.NORMAL)
        else:
            self.btn_iniciar.config(state=tk.NORMAL)
            self.btn_detener.config(state=tk.DISABLED)

    def _actualizar_estado(self):
        """Actualizar estado del sistema."""
        if not self.controlador:
            self.lbl_info.config(text="Escaneador: No conectado")
            return
        
        try:
            estado = self.controlador.estado()
            if estado.get('escaneador_disponible'):
                info = f"Escaneador: Conectado (v{estado.get('version', 'N/A')})"
                capacidades = len(estado.get('capacidades', []))
                info += f" - {capacidades} capacidades"
            else:
                info = "Escaneador: No disponible"
            
            self.lbl_info.config(text=info)
            
        except Exception as e:
            self.lbl_info.config(text=f"Error: {str(e)}")

    def _callback_progreso(self, datos):
        """Callback para actualización de progreso."""
        progreso = datos.get('progreso', 0)
        self.var_progreso.set(progreso)
        self.lbl_progreso.config(text=f"{progreso}%")

    def _callback_completado(self, datos):
        """Callback para escaneo completado."""
        self._cambiar_estado_escaneo(False)
        self.var_estado.set("Completado")
        
        # Mostrar resultados
        resultado = datos.get('resultado', {})
        self._mostrar_resultados(resultado)
        
        messagebox.showinfo("Información", "Escaneo completado exitosamente")

    def _callback_error(self, datos):
        """Callback para errores de escaneo."""
        self._cambiar_estado_escaneo(False)
        self.var_estado.set("Error")
        
        error = datos.get('error', 'Error desconocido')
        self._log_mensaje(f"ERROR: {error}")
        messagebox.showerror("Error", f"Error en escaneo: {error}")

    def _mostrar_resultados(self, resultado):
        """Mostrar resultados del escaneo."""
        if not resultado:
            return
        
        # Mostrar resumen
        self._mostrar_resumen(resultado)
        
        # Mostrar detalles
        self._mostrar_detalles(resultado)
        
        # Mostrar vulnerabilidades
        self._mostrar_vulnerabilidades(resultado)

    def _mostrar_resumen(self, resultado):
        """Mostrar resumen en el árbol."""
        # Limpiar resumen anterior
        for item in self.tree_resumen.get_children():
            self.tree_resumen.delete(item)
        
        # Agregar elementos del resumen
        hosts = len(resultado.get('hosts_detectados', []))
        puertos = len(resultado.get('puertos_abiertos', []))
        vulns = len(resultado.get('vulnerabilidades', []))
        servicios = len(resultado.get('servicios_detectados', []))
        
        self.tree_resumen.insert('', 'end', values=('Hosts detectados', hosts, 'Completado'))
        self.tree_resumen.insert('', 'end', values=('Puertos abiertos', puertos, 'Completado'))
        self.tree_resumen.insert('', 'end', values=('Vulnerabilidades', vulns, 'Completado'))
        self.tree_resumen.insert('', 'end', values=('Servicios', servicios, 'Completado'))

    def _mostrar_detalles(self, resultado):
        """Mostrar detalles en el área de texto."""
        self.text_detalles.delete(1.0, tk.END)
        
        # Formatear y mostrar detalles
        detalles = json.dumps(resultado, indent=2, ensure_ascii=False, default=str)
        self.text_detalles.insert(tk.END, detalles)

    def _mostrar_vulnerabilidades(self, resultado):
        """Mostrar vulnerabilidades en el árbol."""
        # Limpiar vulnerabilidades anteriores
        for item in self.tree_vulns.get_children():
            self.tree_vulns.delete(item)
        
        # Agregar vulnerabilidades
        vulnerabilidades = resultado.get('vulnerabilidades', [])
        for vuln in vulnerabilidades:
            tipo = vuln.get('tipo', 'Desconocido')
            severidad = vuln.get('severidad', 'baja')
            descripcion = vuln.get('descripcion', 'Sin descripción')
            
            self.tree_vulns.insert('', 'end', values=(tipo, severidad, descripcion))

    def _log_mensaje(self, mensaje):
        """Agregar mensaje al log."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        mensaje_completo = f"[{timestamp}] {mensaje}\n"
        
        self.text_logs.insert(tk.END, mensaje_completo)
        self.text_logs.see(tk.END)

    def obtener_configuracion(self):
        """Obtener configuración actual."""
        return {
            'objetivo': self.var_objetivo.get(),
            'tipo_escaneo': self.var_tipo_escaneo.get(),
            'tema': 'burp' if BURP_THEME_AVAILABLE else 'default'
        }

    def establecer_configuracion(self, config):
        """Establecer configuración."""
        if 'objetivo' in config:
            self.var_objetivo.set(config['objetivo'])
        if 'tipo_escaneo' in config:
            self.var_tipo_escaneo.set(config['tipo_escaneo'])

    def _iniciar_monitoreo_progreso(self):
        """Iniciar monitoreo de progreso en hilo separado."""
        def monitorear():
            try:
                while self.proceso_activo and self.controlador:
                    try:
                        progreso_info = self.controlador.obtener_progreso()
                        
                        if progreso_info.get('disponible'):
                            progreso = progreso_info.get('progreso', 0)
                            escaneando = progreso_info.get('escaneando', False)
                            
                            # Actualizar interfaz en el hilo principal
                            self.after(0, self._actualizar_progreso_ui, progreso, escaneando)
                            
                            if not escaneando:
                                break
                                
                    except Exception as e:
                        self._log_seguro(f"Error monitoreando progreso: {e}", "error")
                        
                    # Esperar un poco antes de la siguiente verificación
                    threading.Event().wait(1.0)
                    
            except Exception as e:
                self._log_seguro(f"Error en hilo de monitoreo: {e}", "error")
        
        if self.controlador:
            hilo_monitoreo = threading.Thread(target=monitorear, daemon=True)
            hilo_monitoreo.start()

    def _actualizar_progreso_ui(self, progreso, escaneando):
        """Actualizar interfaz de progreso en hilo principal."""
        try:
            self.var_progreso.set(progreso)
            
            if hasattr(self, 'lbl_progreso'):
                self.lbl_progreso.config(text=f"{progreso}%")
            
            if not escaneando and self.proceso_activo:
                # El escaneo terminó
                self._cambiar_estado_escaneo(False)
                self.var_estado.set("Completado")
                
        except Exception as e:
            self._log_seguro(f"Error actualizando UI de progreso: {e}", "error")
