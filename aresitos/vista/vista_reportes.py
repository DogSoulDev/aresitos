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

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import os
import logging
import datetime
import gc  # Issue 21/24 - Optimización de memoria

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaReportes(tk.Frame):
    def _abrir_ventana_edicion_reporte(self, callback_guardar):
        import tkinter as tk
        ventana = tk.Toplevel(self)
        ventana.title("Editar campos del reporte de incidente")
        ventana.transient(self.winfo_toplevel())
        ventana.grab_set()
        colors = getattr(self, 'colors', {
            'bg_primary': '#2b2b2b', 'fg_primary': '#ffffff', 'fg_accent': '#ff6633',
            'button_bg': '#ffb86c', 'button_fg': '#232629'
        })
        ventana.configure(bg=colors['bg_primary'])
        campos = {
            'organizacion': tk.StringVar(value=""),
            'contacto': tk.StringVar(value=""),
            'correo': tk.StringVar(value=""),
            'telefono': tk.StringVar(value=""),
            'titulo': tk.StringVar(value=""),
            'fecha_deteccion': tk.StringVar(value=""),
            'fecha_inicio': tk.StringVar(value=""),
            'descripcion': tk.StringVar(value=""),
            'tipo': tk.StringVar(value=""),
            'sistemas_afectados': tk.StringVar(value=""),
            'acciones': tk.StringVar(value=""),
            'impacto': tk.StringVar(value=""),
            'datos_comprometidos': tk.StringVar(value=""),
            'observaciones': tk.StringVar(value="")
        }
        if self.reporte_actual and isinstance(self.reporte_actual, dict):
            resumen = self.reporte_actual.get('resumen', {})
            campos['organizacion'].set(self.reporte_actual.get('organizacion', campos['organizacion'].get()))
            campos['contacto'].set(self.reporte_actual.get('contacto', campos['contacto'].get()))
            campos['correo'].set(self.reporte_actual.get('correo', campos['correo'].get()))
            campos['telefono'].set(self.reporte_actual.get('telefono', campos['telefono'].get()))
            campos['titulo'].set(self.reporte_actual.get('titulo', campos['titulo'].get()))
            campos['fecha_deteccion'].set(self.reporte_actual.get('fecha_deteccion', campos['fecha_deteccion'].get()))
            campos['fecha_inicio'].set(self.reporte_actual.get('fecha_inicio', campos['fecha_inicio'].get()))
            campos['descripcion'].set(self.reporte_actual.get('descripcion', campos['descripcion'].get()))
            campos['tipo'].set(self.reporte_actual.get('tipo', campos['tipo'].get()))
            campos['sistemas_afectados'].set(self.reporte_actual.get('sistemas_afectados', campos['sistemas_afectados'].get()))
            campos['acciones'].set(self.reporte_actual.get('acciones', campos['acciones'].get()))
            campos['impacto'].set(self.reporte_actual.get('impacto', campos['impacto'].get()))
            campos['datos_comprometidos'].set(self.reporte_actual.get('datos_comprometidos', campos['datos_comprometidos'].get()))
            campos['observaciones'].set(self.reporte_actual.get('observaciones', campos['observaciones'].get()))
        row = 0
        text_widgets = {}
        labels = [
            ("Nombre de la organización", 'organizacion'),
            ("Persona de contacto", 'contacto'),
            ("Correo electrónico", 'correo'),
            ("Teléfono", 'telefono'),
            ("Título del incidente", 'titulo'),
            ("Fecha y hora de detección", 'fecha_deteccion'),
            ("Fecha y hora de inicio", 'fecha_inicio'),
            ("Descripción breve del incidente", 'descripcion'),
            ("Tipo de incidente", 'tipo'),
            ("Sistemas o servicios afectados", 'sistemas_afectados'),
            ("Acciones tomadas", 'acciones'),
            ("Impacto estimado", 'impacto'),
            ("Datos comprometidos", 'datos_comprometidos'),
            ("Observaciones relevantes", 'observaciones')
        ]
        for label, var in labels:
            tk.Label(ventana, text=label+':', bg=colors['bg_primary'], fg=colors['fg_accent'], font=("Arial", 11, "bold")).grid(row=row, column=0, sticky='e', padx=8, pady=4)
            if var in ['descripcion', 'acciones', 'impacto', 'datos_comprometidos', 'observaciones', 'sistemas_afectados']:
                entry = tk.Text(ventana, height=3, width=48, bg=colors['bg_primary'], fg=colors['fg_primary'], insertbackground=colors['fg_accent'], font=("Consolas", 10))
                entry.insert('1.0', campos[var].get())
                entry.grid(row=row, column=1, padx=8, pady=4)
                text_widgets[var] = entry
            else:
                entry = tk.Entry(ventana, textvariable=campos[var], width=50, bg=colors['bg_primary'], fg=colors['fg_primary'], insertbackground=colors['fg_accent'], font=("Consolas", 10))
                entry.grid(row=row, column=1, padx=8, pady=4)
            row += 1
        def on_guardar():
            datos = {}
            for k in campos:
                if k in text_widgets:
                    datos[k] = text_widgets[k].get('1.0', 'end').strip()
                else:
                    datos[k] = campos[k].get().strip()
            ventana.destroy()
            callback_guardar(datos)
        btn_guardar = tk.Button(ventana, text="Generar y Guardar Reporte", command=on_guardar,
                                bg=colors['button_bg'], fg=colors['button_fg'], font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8)
        btn_guardar.grid(row=row, column=0, columnspan=2, pady=12)

    # ...existing code...
    def guardar_texto(self):
        """Guardar reporte con edición previa de campos clave."""
        import getpass, datetime
        def guardar_con_campos(campos):
            contenido = self._generar_reporte_profesional_txt(campos)
            from tkinter import filedialog, messagebox
            archivo = filedialog.asksaveasfilename(
                title="Guardar Reporte TXT",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            if archivo:
                try:
                    with open(archivo, 'w', encoding='utf-8') as f:
                        f.write(contenido)
                    usuario = getpass.getuser()
                    fecha = datetime.datetime.now().isoformat()
                    resumen = f"Título: {campos.get('titulo','')}, Autor: {campos.get('autor','')}, Fecha: {campos.get('fecha','')}, Archivo: {archivo}"
                    self.logger.log(f"[EXPORTACIÓN TXT] Usuario: {usuario}, Fecha: {fecha}, {resumen}", nivel="INFO", modulo="REPORTES")
                    self._log_terminal(f"[EXPORTACIÓN TXT] Usuario: {usuario}, Fecha: {fecha}, {resumen}", modulo="REPORTES", nivel="INFO")
                    messagebox.showinfo("Éxito", f"Reporte guardado correctamente en {archivo}")
                except Exception as e:
                    self.logger.log(f"[EXPORTACIÓN TXT][ERROR] {str(e)}", nivel="ERROR", modulo="REPORTES")
                    self._log_terminal(f"[EXPORTACIÓN TXT][ERROR] {str(e)}", modulo="REPORTES", nivel="ERROR")
                    messagebox.showerror("Error", f"Error al guardar texto: {str(e)}")
        self._abrir_ventana_edicion_reporte(guardar_con_campos)

    def _generar_reporte_profesional_txt(self, campos):
        """Genera el texto plano profesional del reporte de incidente siguiendo el estándar CISA, en castellano y corregido ortográficamente."""
        line = lambda c: c*80
        secciones = [
            line('='),
            "INFORME DE INCIDENTE DE CIBERSEGURIDAD - ARESITOS", line('='),
            f"Nombre de la organización: {campos.get('organizacion','')}",
            f"Persona de contacto: {campos.get('contacto','')}",
            f"Correo electrónico: {campos.get('correo','')}",
            f"Teléfono: {campos.get('telefono','')}",
            "",
            f"Título del incidente: {campos.get('titulo','')}",
            f"Fecha y hora de detección: {campos.get('fecha_deteccion','')}",
            f"Fecha y hora de inicio: {campos.get('fecha_inicio','')}",
            f"Descripción breve del incidente: {campos.get('descripcion','')}",
            f"Tipo de incidente: {campos.get('tipo','')}",
            f"Sistemas o servicios afectados: {campos.get('sistemas_afectados','')}",
            "",
            "--- ACCIONES TOMADAS ---",
            f"Acciones de contención, erradicación y recuperación: {campos.get('acciones','')}",
            "",
            "--- IMPACTO ESTIMADO ---",
            f"Impacto en operaciones: {campos.get('impacto','')}",
            f"Datos comprometidos: {campos.get('datos_comprometidos','')}",
            "",
            "--- INFORMACIÓN ADICIONAL ---",
            f"Observaciones relevantes: {campos.get('observaciones','')}",
            "",
            line('='),
            "Reporte generado por ARESITOS - https://github.com/DogSoulDev/aresitos"
        ]
        return '\n'.join(secciones)
    def _actualizar_texto_reporte_seguro(self, texto):
        def _update():
            try:
                if hasattr(self, 'reporte_text') and self.reporte_text.winfo_exists():
                    self.reporte_text.insert(tk.END, texto)
                    self.reporte_text.see(tk.END)
            except (tk.TclError, AttributeError):
                pass
        self.after(0, _update)

    def _actualizar_estado_seguro(self, texto):
        # No existe label_estado, así que loguea en el área principal de texto de reporte
        self._actualizar_texto_reporte_seguro(f"[ESTADO] {texto}\n")
    @staticmethod
    def _get_base_dir():
        """Obtener la ruta base absoluta del proyecto ARESITOS."""
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    
    # --- NUEVO: Almacenamiento persistente de datos de módulos para reportes ---
    def inicializar_datos_modulos(self):
        """Inicializa los atributos de datos de cada módulo para sincronización."""
        self._datos_dashboard = None
        self._datos_escaneo = None
        self._datos_monitoreo = None
        self._datos_fim = None
        self._datos_siem = None
        self._datos_cuarentena = None
        self._datos_terminal_principal = None

    def set_datos_modulo(self, modulo, datos):
        """Permite a los controladores o vistas de cada módulo actualizar sus datos para reportes."""
        if modulo == 'dashboard':
            self._datos_dashboard = datos
        elif modulo == 'escaneo':
            self._datos_escaneo = datos
        elif modulo == 'monitoreo':
            self._datos_monitoreo = datos
        elif modulo == 'fim':
            self._datos_fim = datos
        elif modulo == 'siem':
            self._datos_siem = datos
        elif modulo == 'cuarentena':
            self._datos_cuarentena = datos
        elif modulo == 'terminal_principal':
            self._datos_terminal_principal = datos

    def get_datos_modulo(self, modulo):
        """Devuelve los datos almacenados del módulo solicitado."""
        if modulo == 'dashboard':
            return self._datos_dashboard
        elif modulo == 'escaneo':
            return self._datos_escaneo
        elif modulo == 'monitoreo':
            return self._datos_monitoreo
        elif modulo == 'fim':
            return self._datos_fim
        elif modulo == 'siem':
            return self._datos_siem
        elif modulo == 'cuarentena':
            return self._datos_cuarentena
        elif modulo == 'terminal_principal':
            return self._datos_terminal_principal
        return None

    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        # Usar logger global de ARESITOS
        from aresitos.utils.logger_aresitos import LoggerAresitos
        self.logger = LoggerAresitos.get_instance()
        self.reporte_actual = None
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        self.inicializar_datos_modulos()  # Inicializa almacenamiento de datos de módulos
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
        titulo = tk.Label(titulo_frame, text="Generación y Gestión de Reportes",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack()
        
        # Frame principal con tema
        main_frame = tk.Frame(contenido_frame, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel izquierdo con tema
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        left_label = tk.Label(left_frame, text="Contenido del Reporte",
                             font=('Arial', 12, 'bold'),
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        left_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Área de texto con tema Burp Suite
        self.reporte_text = scrolledtext.ScrolledText(left_frame, height=25, width=70,
                                                     bg=self.colors['bg_secondary'],
                                                     fg=self.colors['fg_primary'],
                                                     insertbackground=self.colors['fg_accent'],
                                                     font=('Consolas', 10),
                                                     relief='flat', bd=1)
        self.reporte_text.pack(fill=tk.BOTH, expand=True)
        # Explicación general del reporte
        explicacion = (
            "INFORME DE SEGURIDAD ARESITOS\n"
            "============================\n"
            "Este informe proporciona un análisis completo y estructurado del estado de seguridad de su sistema Kali Linux.\n\n"
            "¿Qué encontrará en este informe?\n"
            "- Un resumen claro y detallado de cada área clave de seguridad, organizado por módulos:\n"
            "   • Dashboard: Estado general y resumen del sistema.\n"
            "   • Escaneo: Resultados de análisis de red y vulnerabilidades detectadas.\n"
            "   • Monitoreo: Actividad de procesos y eventos relevantes en tiempo real.\n"
            "   • FIM: Integridad y cambios en archivos críticos del sistema.\n"
            "   • SIEM: Eventos de seguridad y correlación de incidentes.\n"
            "   • Cuarentena: Elementos y amenazas aisladas para su revisión.\n\n"
            "¿Cómo usar este informe?\n"
            "- Revise cada sección para identificar riesgos, anomalías o áreas de mejora.\n"
            "- Utilice la información como base para auditorías, análisis forense o acciones preventivas.\n"
            "- Puede personalizar el contenido seleccionando los módulos a incluir desde el panel derecho.\n\n"
            "Este informe está diseñado para ser claro, profesional y útil tanto para usuarios técnicos como para responsables de seguridad.\n\n"
        )
        self.reporte_text.insert('end', explicacion)
        
        # Panel derecho con tema
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        right_label = tk.Label(right_frame, text="Panel de Control",
                              font=('Arial', 12, 'bold'),
                              bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        right_label.pack(anchor=tk.W, pady=(0, 10))

        # Frame de configuración con tema
        config_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        config_frame.pack(fill=tk.X, pady=(0, 10))

        # Mejor visibilidad: checkboxes grandes y bien separados para cada módulo
        config_label = tk.Label(config_frame, text="Módulos a incluir en el Reporte:",
            font=('Arial', 12, 'bold'),
            bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        config_label.pack(anchor=tk.W, pady=(0, 8))

        self.incluir_dashboard = tk.BooleanVar(value=True)
        self.incluir_escaneo = tk.BooleanVar(value=True)
        self.incluir_monitoreo = tk.BooleanVar(value=True)
        self.incluir_fim = tk.BooleanVar(value=True)
        self.incluir_siem = tk.BooleanVar(value=True)
        self.incluir_cuarentena = tk.BooleanVar(value=True)

        check_style = {'font': ('Arial', 11, 'bold'), 'bg': self.colors['bg_secondary'], 'activebackground': self.colors['bg_secondary'], 'fg': self.colors['fg_primary'], 'anchor': 'w', 'padx': 12, 'pady': 4}
        tk.Checkbutton(config_frame, text="Dashboard (Resumen del sistema)", variable=self.incluir_dashboard, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Escaneo (Vulnerabilidades)", variable=self.incluir_escaneo, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Monitoreo (Procesos y eventos)", variable=self.incluir_monitoreo, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="FIM (Integridad de archivos)", variable=self.incluir_fim, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="SIEM (Eventos de seguridad)", variable=self.incluir_siem, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Cuarentena (Amenazas aisladas)", variable=self.incluir_cuarentena, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)

        # --- BOTONES DE ACCIÓN PRINCIPALES ---
        # Frame para agrupar botones
        botones_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        botones_frame.pack(fill=tk.X, pady=(0, 10))

        button_style = {
            'font': ("Arial", 12, "bold"),
            'relief': 'raised',
            'padx': 18,
            'pady': 8,
            'bd': 2
        }

        # Colores diferenciados para cada acción principal


        btn_generar = tk.Button(
            botones_frame, text="Generar Reporte", command=self.generar_reporte_completo,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#ffb86c', fg='#232629', activebackground='#fffae3', activeforeground='#ff5555'
        )
        btn_generar.pack(fill=tk.X, pady=4, padx=10)

        btn_actualizar = tk.Button(
            botones_frame, text="Actualizar", command=self.actualizar_reporte,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#8be9fd', fg='#232629', activebackground='#e3f6ff', activeforeground='#ff5555'
        )
        btn_actualizar.pack(fill=tk.X, pady=4, padx=10)

        btn_guardar_json = tk.Button(
            botones_frame, text="Guardar JSON", command=self.guardar_json,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#50fa7b', fg='#232629', activebackground='#e3ffe3', activeforeground='#ff5555'
        )
        btn_guardar_json.pack(fill=tk.X, pady=4, padx=10)

        btn_guardar_txt = tk.Button(
            botones_frame, text="Guardar TXT", command=self.guardar_texto,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#ffb86c', fg='#232629', activebackground='#fffae3', activeforeground='#ff5555'
        )
        btn_guardar_txt.pack(fill=tk.X, pady=4, padx=10)

        btn_exportar_pdf = tk.Button(
            botones_frame, text="Exportar PDF", command=self.exportar_pdf,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#ff5555', fg='#f8f8f2', activebackground='#ffeaea', activeforeground='#232629'
        )
        btn_exportar_pdf.pack(fill=tk.X, pady=4, padx=10)

        btn_cargar = tk.Button(
            botones_frame, text="Cargar Reporte", command=self.cargar_reporte,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#8be9fd', fg='#232629', activebackground='#e3f6ff', activeforeground='#ff5555'
        )
        btn_cargar.pack(fill=tk.X, pady=4, padx=10)

        btn_listar = tk.Button(
            botones_frame, text="Listar Reportes", command=self.listar_reportes,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#50fa7b', fg='#232629', activebackground='#e3ffe3', activeforeground='#ff5555'
        )
        btn_listar.pack(fill=tk.X, pady=4, padx=10)

        btn_comparar = tk.Button(
            botones_frame, text="Comparar Reportes", command=self.comparar_reportes_kali,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#ffb86c', fg='#232629', activebackground='#fffae3', activeforeground='#ff5555'
        )
        btn_comparar.pack(fill=tk.X, pady=4, padx=10)

        btn_limpiar = tk.Button(
            botones_frame, text="Limpiar Vista", command=self.limpiar_reporte,
            font=("Arial", 12, "bold"), relief='raised', padx=18, pady=8, bd=2,
            bg='#ff5555', fg='#f8f8f2', activebackground='#ffeaea', activeforeground='#232629'
        )
        btn_limpiar.pack(fill=tk.X, pady=4, padx=10)

        # --- BOTONES DE ANÁLISIS AVANZADO KALI ---
        analisis_frame = tk.LabelFrame(right_frame, text="Análisis Avanzado Kali", bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], font=("Arial", 9, "bold"))
        analisis_frame.pack(fill=tk.X, pady=(0, 10))

        btn_logs_kali = tk.Button(
            analisis_frame, text="Análisis Logs Kali", command=self.analizar_logs_kali,
            **button_style
        )
        btn_logs_kali.pack(fill=tk.X, pady=2, padx=6)

        btn_stats_kali = tk.Button(
            analisis_frame, text="Estadísticas Kali", command=self.generar_estadisticas_kali,
            **button_style
        )
        btn_stats_kali.pack(fill=tk.X, pady=2, padx=6)

        btn_informe_kali = tk.Button(
            analisis_frame, text="Informe Seguridad Kali", command=self.generar_informe_seguridad,
            **button_style
        )
        btn_informe_kali.pack(fill=tk.X, pady=2, padx=6)

    def exportar_pdf(self):
        """Exportar el reporte mostrado a PDF usando enscript y ps2pdf (nativo Kali)."""
        import tempfile, os, subprocess
        from tkinter import messagebox, filedialog
        import getpass, datetime
        try:
            contenido = self.reporte_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay contenido para exportar")
                return
            with tempfile.NamedTemporaryFile(delete=False, suffix='.txt', mode='w', encoding='utf-8') as tmp_txt:
                tmp_txt.write(contenido)
                tmp_txt_path = tmp_txt.name
            tmp_ps_path = tmp_txt_path.replace('.txt', '.ps')
            pdf_destino = filedialog.asksaveasfilename(
                title="Exportar Reporte PDF",
                defaultextension=".pdf",
                filetypes=[("Archivo PDF", "*.pdf"), ("Todos los archivos", "*.*")]
            )
            if not pdf_destino:
                os.unlink(tmp_txt_path)
                return
            from aresitos.utils.sudo_manager import get_sudo_manager
            sudo_manager = get_sudo_manager()
            res1 = sudo_manager.execute_sudo_command(f"enscript -B -o '{tmp_ps_path}' '{tmp_txt_path}'")
            if hasattr(res1, 'returncode') and res1.returncode != 0:
                os.unlink(tmp_txt_path)
                error_msg = res1.stderr if hasattr(res1, 'stderr') else str(res1)
                messagebox.showerror("Error", f"Error ejecutando enscript: {error_msg}")
                return
            res2 = sudo_manager.execute_sudo_command(f"ps2pdf '{tmp_ps_path}' '{pdf_destino}'")
            if hasattr(res2, 'returncode') and res2.returncode != 0:
                os.unlink(tmp_txt_path)
                os.unlink(tmp_ps_path)
                error_msg = res2.stderr if hasattr(res2, 'stderr') else str(res2)
                messagebox.showerror("Error", f"Error ejecutando ps2pdf: {error_msg}")
                return
            os.unlink(tmp_txt_path)
            os.unlink(tmp_ps_path)
            usuario = getpass.getuser()
            fecha = datetime.datetime.now().isoformat()
            self.logger.log(f"[EXPORTACIÓN PDF] Usuario: {usuario}, Fecha: {fecha}, Archivo: {pdf_destino}", nivel="INFO", modulo="REPORTES")
            self._log_terminal(f"[EXPORTACIÓN PDF] Usuario: {usuario}, Fecha: {fecha}, Archivo: {pdf_destino}", modulo="REPORTES", nivel="INFO")
            messagebox.showinfo("Éxito", f"Reporte exportado correctamente a {pdf_destino}")
        except Exception as e:
            self.logger.log(f"[EXPORTACIÓN PDF][ERROR] {str(e)}", nivel="ERROR", modulo="REPORTES")
            self._log_terminal(f"[EXPORTACIÓN PDF][ERROR] {str(e)}", modulo="REPORTES", nivel="ERROR")
            messagebox.showerror("Error", f"Error exportando PDF: {str(e)}")
        
    # ... (widgets de análisis Kali solo deben estar en crear_interfaz)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def generar_reporte_completo(self):
        self.log_to_terminal("Generando reporte completo del sistema...")
        def generar():
            try:
                if not self.controlador:
                    messagebox.showerror("Error", "Controlador no configurado")
                    return
                self._actualizar_reporte_seguro("", "clear")
                self._actualizar_reporte_seguro(" Generando reporte completo...\n\n")
                self.log_to_terminal("DATOS Recopilando datos del sistema...")
                # Obtener datos de todos los módulos y terminales posibles
                datos_dashboard = self._obtener_datos_dashboard() if hasattr(self, 'incluir_dashboard') and self.incluir_dashboard.get() else self._obtener_datos_dashboard() if hasattr(self, '_obtener_datos_dashboard') else None
                datos_escaneo = self._obtener_datos_escaneo() if hasattr(self, 'incluir_escaneo') and self.incluir_escaneo.get() else self._obtener_datos_escaneo() if hasattr(self, '_obtener_datos_escaneo') else None
                datos_monitoreo = self._obtener_datos_monitoreo() if hasattr(self, 'incluir_monitoreo') and self.incluir_monitoreo.get() else self._obtener_datos_monitoreo() if hasattr(self, '_obtener_datos_monitoreo') else None
                datos_fim = self._obtener_datos_fim() if hasattr(self, 'incluir_fim') and self.incluir_fim.get() else self._obtener_datos_fim() if hasattr(self, '_obtener_datos_fim') else None
                datos_siem = self._obtener_datos_siem() if hasattr(self, 'incluir_siem') and self.incluir_siem.get() else self._obtener_datos_siem() if hasattr(self, '_obtener_datos_siem') else None
                datos_cuarentena = self._obtener_datos_cuarentena() if hasattr(self, 'incluir_cuarentena') and self.incluir_cuarentena.get() else self._obtener_datos_cuarentena() if hasattr(self, '_obtener_datos_cuarentena') else None
                # Capturar terminal principal y terminales de módulos si existen
                datos_terminal_principal = self._obtener_terminal_principal() if hasattr(self, '_obtener_terminal_principal') else None
                datos_terminales_modulos = {}
                for nombre_modulo in ['dashboard', 'escaneo', 'monitoreo', 'fim', 'siem', 'cuarentena']:
                    metodo = getattr(self, f'_obtener_terminal_{nombre_modulo}', None)
                    if callable(metodo):
                        datos_terminales_modulos[nombre_modulo] = metodo()
                self.log_to_terminal("REPORTE Generando reporte con módulos y terminales asociados...")
                self.reporte_actual = self.controlador.generar_reporte_completo(
                    datos_escaneo=datos_escaneo,
                    datos_monitoreo=datos_monitoreo,
                    datos_utilidades=datos_dashboard,
                    datos_fim=datos_fim,
                    datos_siem=datos_siem,
                    datos_cuarentena=datos_cuarentena,
                    datos_terminal_principal=datos_terminal_principal,
                    datos_terminales_modulos=datos_terminales_modulos
                )
                if self.reporte_actual:
                    self.log_to_terminal("OK Reporte generado correctamente")
                    self.mostrar_reporte(self.reporte_actual)
                    self.log_to_terminal("REPORTE Reporte mostrado en pantalla")
                else:
                    self._actualizar_reporte_seguro(" Error al generar el reporte")
                    self.log_to_terminal("ERROR Error al generar el reporte")
            except Exception as e:
                self._actualizar_reporte_seguro(f" Error durante la generación: {str(e)}")
        thread = threading.Thread(target=generar, name="ReporteCompleto")
        thread.daemon = True
        thread.start()
        gc.collect()
    
    def mostrar_reporte(self, reporte):
        self._actualizar_reporte_seguro("", "clear")
        try:
            if isinstance(reporte, dict):
                secciones = []
                # Portada
                secciones.append("="*80)
                secciones.append("INFORME DE INCIDENTE Y SEGURIDAD - ARESITOS")
                secciones.append("="*80)
                secciones.append(f"Fecha de generación: {reporte.get('fecha_generacion', 'No disponible')}")
                secciones.append(f"Versión: {reporte.get('version', 'ARESITOS')}")
                secciones.append("")
                # Resumen Ejecutivo
                secciones.append("--- RESUMEN EJECUTIVO ---")
                resumen = reporte.get('resumen', {})
                for k, v in resumen.items():
                    secciones.append(f"{k.replace('_',' ').capitalize()}: {v}")
                secciones.append("")
                # Detalles Técnicos por módulo
                modulos = [
                    ("DASHBOARD", reporte.get('dashboard', {})),
                    ("ESCANEO", reporte.get('escaneo', {})),
                    ("MONITOREO", reporte.get('monitoreo', {})),
                    ("FIM", reporte.get('fim', {})),
                    ("SIEM", reporte.get('siem', {})),
                    ("CUARENTENA", reporte.get('cuarentena', {})),
                    ("TERMINAL PRINCIPAL", reporte.get('terminal_principal', {})),
                ]
                secciones.append("--- DETALLES TÉCNICOS POR MÓDULO ---")
                for nombre, datos in modulos:
                    secciones.append("-"*60)
                    secciones.append(f"[ {nombre} ]")
                    if datos:
                        if isinstance(datos, dict):
                            for k, v in datos.items():
                                secciones.append(f"  {k.replace('_',' ').capitalize()}: {v}")
                        elif isinstance(datos, list):
                            for item in datos:
                                secciones.append(f"  - {item}")
                        else:
                            secciones.append(f"  {str(datos)}")
                    else:
                        secciones.append("  Sin datos disponibles.")
                secciones.append("")
                # Cronología (si existe)
                if 'cronologia' in reporte:
                    secciones.append("--- CRONOLOGÍA DEL INCIDENTE ---")
                    for evento in reporte['cronologia']:
                        secciones.append(f"- {evento}")
                    secciones.append("")
                # Acciones tomadas (si existe)
                if 'acciones' in reporte:
                    secciones.append("--- ACCIONES TOMADAS ---")
                    for accion in reporte['acciones']:
                        secciones.append(f"- {accion}")
                    secciones.append("")
                # Impacto (si existe)
                if 'impacto' in reporte:
                    secciones.append("--- IMPACTO ---")
                    secciones.append(str(reporte['impacto']))
                    secciones.append("")
                # Lecciones aprendidas (si existe)
                if 'lecciones_aprendidas' in reporte:
                    secciones.append("--- LECCIONES APRENDIDAS ---")
                    for leccion in reporte['lecciones_aprendidas']:
                        secciones.append(f"- {leccion}")
                    secciones.append("")
                # Anexos (si existe)
                if 'anexos' in reporte:
                    secciones.append("--- ANEXOS ---")
                    for anexo in reporte['anexos']:
                        secciones.append(f"- {anexo}")
                    secciones.append("")
                secciones.append("="*80)
                texto_reporte = "\n".join(secciones)
            else:
                texto_reporte = str(reporte)
            self._actualizar_reporte_seguro(texto_reporte, "replace")
        except Exception as e:
            self._actualizar_reporte_seguro(f"Error al mostrar reporte: {str(e)}")
    
    def actualizar_reporte(self):
        if self.reporte_actual:
            self.mostrar_reporte(self.reporte_actual)
        else:
            messagebox.showwarning("Advertencia", "No hay reporte generado para actualizar")
    
    def guardar_json(self):
        import getpass, datetime
        try:
            if not self.reporte_actual:
                messagebox.showwarning("Advertencia", "No hay reporte para guardar")
                return
            archivo = filedialog.asksaveasfilename(
                title="Guardar Reporte JSON",
                defaultextension=".json",
                filetypes=[("Archivo JSON", "*.json"), ("Todos los archivos", "*.*")]
            )
            if archivo:
                # Estructura profesional alineada con CISA, en castellano
                datos = self.reporte_actual.copy() if isinstance(self.reporte_actual, dict) else {}
                reporte_json = {
                    "organizacion": datos.get('organizacion', ''),
                    "contacto": datos.get('contacto', ''),
                    "correo": datos.get('correo', ''),
                    "telefono": datos.get('telefono', ''),
                    "titulo": datos.get('titulo', ''),
                    "fecha_deteccion": datos.get('fecha_deteccion', ''),
                    "fecha_inicio": datos.get('fecha_inicio', ''),
                    "descripcion": datos.get('descripcion', ''),
                    "tipo": datos.get('tipo', ''),
                    "sistemas_afectados": datos.get('sistemas_afectados', ''),
                    "acciones": datos.get('acciones', ''),
                    "impacto": datos.get('impacto', ''),
                    "datos_comprometidos": datos.get('datos_comprometidos', ''),
                    "observaciones": datos.get('observaciones', ''),
                    "generado_por": "ARESITOS",
                    "fecha_exportacion": datetime.datetime.now().isoformat()
                }
                import json
                with open(archivo, 'w', encoding='utf-8') as f:
                    json.dump(reporte_json, f, indent=2, ensure_ascii=False)
                usuario = getpass.getuser()
                fecha = reporte_json["fecha_exportacion"]
                resumen = f"Organización: {reporte_json.get('organizacion','')}, Título: {reporte_json.get('titulo','')}, Archivo: {archivo}"
                self.logger.log(f"[EXPORTACIÓN JSON] Usuario: {usuario}, Fecha: {fecha}, {resumen}", nivel="INFO", modulo="REPORTES")
                self._log_terminal(f"[EXPORTACIÓN JSON] Usuario: {usuario}, Fecha: {fecha}, {resumen}", modulo="REPORTES", nivel="INFO")
                messagebox.showinfo("Éxito", f"Reporte guardado correctamente en {archivo}")
        except Exception as e:
            self.logger.log(f"[EXPORTACIÓN JSON][ERROR] {str(e)}", nivel="ERROR", modulo="REPORTES")
            self._log_terminal(f"[EXPORTACIÓN JSON][ERROR] {str(e)}", modulo="REPORTES", nivel="ERROR")
            messagebox.showerror("Error", f"Error al guardar JSON: {str(e)}")
    
    
    def cargar_reporte(self):
        """Cargar reporte desde archivo, sin validaciones ni sanitización."""
        try:
            archivo = filedialog.askopenfilename(
                title="Cargar Reporte",
                filetypes=[("Archivos de reporte", "*.json *.txt"), ("Todos los archivos", "*.*")]
            )
            if archivo:
                if archivo.endswith('.json'):
                    with open(archivo, 'r', encoding='utf-8') as f:
                        self.reporte_actual = json.load(f)
                    self.mostrar_reporte(self.reporte_actual)
                else:
                    with open(archivo, 'r', encoding='utf-8') as f:
                        contenido = f.read()
                    self._actualizar_reporte_seguro("", "clear")
                    self._actualizar_reporte_seguro(contenido, "replace")
                messagebox.showinfo("Éxito", f"Reporte cargado desde {os.path.basename(archivo)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar reporte: {str(e)}")
    
    def listar_reportes(self):
        try:
            if not self.controlador:
                messagebox.showerror("Error", "Controlador no configurado")
                return
            
            reportes = self.controlador.listar_reportes_guardados()
            
            self._actualizar_reporte_seguro("", "clear")
            self._actualizar_reporte_seguro(" REPORTES GUARDADOS\n")
            self._actualizar_reporte_seguro("=" * 50 + "\n\n")
            
            if reportes:
                for i, reporte in enumerate(reportes, 1):
                    self._actualizar_reporte_seguro(f"{i}. {reporte}\n")
            else:
                self._actualizar_reporte_seguro("No se encontraron reportes guardados.\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al listar reportes: {str(e)}")
    
    def limpiar_reporte(self):
        respuesta = messagebox.askyesno("Confirmar", "¿Está seguro de que desea limpiar la vista?")
        if respuesta:
            self.reporte_text.delete(1.0, tk.END)
            self.reporte_actual = None
    
    def _log_terminal(self, mensaje, modulo="REPORTES", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")
    
    def analizar_logs_kali(self):
        """Análisis avanzado de logs usando herramientas nativas de Kali con permisos seguros."""
        import datetime
        import json
        from aresitos.utils.sudo_manager import get_sudo_manager
        def realizar_analisis():
            sudo_manager = get_sudo_manager()
            try:
                self.reporte_text.delete(1.0, tk.END)
                self.reporte_text.insert(tk.END, "=== ANÁLISIS DE LOGS CON HERRAMIENTAS KALI ===\n\n")
                self.reporte_text.update()
                analisis = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "logs_sistema": {},
                    "estadisticas": {},
                    "alertas": []
                }
                # Últimos errores críticos
                resultado = sudo_manager.execute_sudo_command('cat /var/log/syslog')
                if resultado.stdout:
                    lines = [l for l in resultado.stdout.split('\n') if 'error' in l.lower()]
                    analisis["logs_sistema"]["errores_syslog"] = lines[-10:]
                else:
                    analisis["logs_sistema"]["errores_syslog"] = ["Error accediendo a syslog"]
                # Análisis de autenticación
                resultado = sudo_manager.execute_sudo_command('cat /var/log/auth.log')
                if resultado.stdout:
                    lines = [l for l in resultado.stdout.split('\n') if 'Failed' in l]
                    analisis["logs_sistema"]["fallos_auth"] = len(lines)
                else:
                    analisis["logs_sistema"]["fallos_auth"] = 0
                # Estadísticas de memoria y CPU
                resultado = sudo_manager.execute_sudo_command('top -bn1')
                if resultado.stdout:
                    analisis["estadisticas"]["top_info"] = resultado.stdout.split('\n')[:5]
                else:
                    analisis["estadisticas"]["top_info"] = ["Error ejecutando top"]
                texto_analisis = json.dumps(analisis, indent=2, ensure_ascii=False)
                self.reporte_text.insert(tk.END, texto_analisis)
                self._log_terminal("Análisis de logs completado", "REPORTES", "INFO")
            except Exception as e:
                self.reporte_text.insert(tk.END, f"Error en análisis: {str(e)}")
        thread = threading.Thread(target=realizar_analisis)
        thread.daemon = True
        thread.start()
    
    def generar_estadisticas_kali(self):
        """Generar estadísticas del sistema usando comandos nativos de Kali con permisos seguros."""
        import datetime
        import json
        from aresitos.utils.sudo_manager import get_sudo_manager
        def generar():
            sudo_manager = get_sudo_manager()
            try:
                self.reporte_text.delete(1.0, tk.END)
                self.reporte_text.insert(tk.END, "=== ESTADÍSTICAS DEL SISTEMA KALI ===\n\n")
                self.reporte_text.update()
                estadisticas = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "sistema": {},
                    "red": {},
                    "procesos": {},
                    "disco": {}
                }
                # Información del sistema
                resultado = sudo_manager.execute_sudo_command('uname -a')
                if resultado.stdout:
                    estadisticas["sistema"]["kernel"] = resultado.stdout.strip()
                else:
                    estadisticas["sistema"]["kernel"] = "Error obteniendo info del kernel"
                # Uso de memoria
                resultado = sudo_manager.execute_sudo_command('free -h')
                if resultado.stdout:
                    estadisticas["sistema"]["memoria"] = resultado.stdout.split('\n')[:3]
                else:
                    estadisticas["sistema"]["memoria"] = ["Error obteniendo memoria"]
                # Procesos activos
                resultado = sudo_manager.execute_sudo_command('ps aux --sort=-%cpu')
                if resultado.stdout:
                    estadisticas["procesos"]["top_cpu"] = resultado.stdout.split('\n')[:10]
                else:
                    estadisticas["procesos"]["top_cpu"] = ["Error obteniendo procesos"]
                # Conexiones de red
                resultado = sudo_manager.execute_sudo_command('ss -tuln')
                if resultado.stdout:
                    estadisticas["red"]["conexiones"] = len(resultado.stdout.split('\n'))
                else:
                    estadisticas["red"]["conexiones"] = 0
                # Uso del disco
                resultado = sudo_manager.execute_sudo_command('df -h')
                if resultado.stdout:
                    estadisticas["disco"]["particiones"] = resultado.stdout.split('\n')[1:6]
                else:
                    estadisticas["disco"]["particiones"] = ["Error obteniendo info del disco"]
                texto_stats = json.dumps(estadisticas, indent=2, ensure_ascii=False)
                self.reporte_text.insert(tk.END, texto_stats)
                self._log_terminal("Estadísticas generadas", "REPORTES", "INFO")
            except Exception as e:
                self.reporte_text.insert(tk.END, f"Error generando estadísticas: {str(e)}")
        thread = threading.Thread(target=generar)
        thread.daemon = True
        thread.start()
    
    def generar_informe_seguridad(self):
        """Generar informe de seguridad usando herramientas de Kali con permisos seguros."""
        import datetime
        import json
        from aresitos.utils.sudo_manager import get_sudo_manager
        def generar_informe():
            sudo_manager = get_sudo_manager()
            try:
                self.reporte_text.delete(1.0, tk.END)
                self.reporte_text.insert(tk.END, "=== INFORME DE SEGURIDAD KALI ===\n\n")
                self.reporte_text.update()
                informe = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "servicios": {},
                    "usuarios": {},
                    "archivos": {},
                    "red": {}
                }
                # Servicios activos
                resultado = sudo_manager.execute_sudo_command('systemctl list-units --type=service --state=running')
                if resultado.stdout:
                    servicios_activos = len([line for line in resultado.stdout.split('\n') if '.service' in line])
                    informe["servicios"]["activos"] = servicios_activos
                else:
                    informe["servicios"]["activos"] = 0
                # Usuarios conectados
                resultado = sudo_manager.execute_sudo_command('who')
                if resultado.stdout:
                    informe["usuarios"]["conectados"] = len(resultado.stdout.split('\n')) - 1
                else:
                    informe["usuarios"]["conectados"] = 0
                # Archivos SUID
                resultado = sudo_manager.execute_sudo_command('find /usr -perm -4000 -type f')
                if resultado.stdout:
                    informe["archivos"]["suid_binaries"] = len(resultado.stdout.split('\n')) - 1
                else:
                    informe["archivos"]["suid_binaries"] = 0
                # Conexiones sospechosas
                resultado = sudo_manager.execute_sudo_command('ss -tuln')
                if resultado.stdout:
                    informe["red"]["puertos_escucha"] = len([line for line in resultado.stdout.split('\n') if 'LISTEN' in line])
                else:
                    informe["red"]["puertos_escucha"] = 0
                # Verificar logs de seguridad
                resultado = sudo_manager.execute_sudo_command('cat /var/log/auth.log')
                if resultado.stdout:
                    informe["usuarios"]["fallos_auth"] = len([l for l in resultado.stdout.split('\n') if 'authentication failure' in l])
                else:
                    informe["usuarios"]["fallos_auth"] = 0
                texto_informe = json.dumps(informe, indent=2, ensure_ascii=False)
                self.reporte_text.insert(tk.END, texto_informe)
                self._log_terminal("Informe de seguridad generado", "REPORTES", "INFO")
            except Exception as e:
                self.reporte_text.insert(tk.END, f"Error generando informe: {str(e)}")
        thread = threading.Thread(target=generar_informe)
        thread.daemon = True
        thread.start()
    
    def comparar_reportes_kali(self):
        """Comparar reportes usando herramientas de línea de comandos de Kali Linux, sin validación restrictiva."""
        try:
            archivo1 = filedialog.askopenfilename(
                title="Seleccionar primer reporte",
                filetypes=[("Archivos de reporte", "*.json *.txt"), ("Todos los archivos", "*.*")]
            )
            if not archivo1:
                return
            archivo2 = filedialog.askopenfilename(
                title="Seleccionar segundo reporte",
                filetypes=[("Archivos de reporte", "*.json *.txt"), ("Todos los archivos", "*.*")]
            )
            
            if not archivo2:
                return
            
            # VALIDAR SEGUNDO ARCHIVO
            # Sin validación ni sanitización, solo comparar archivos directamente
            
            def realizar_comparacion():
                try:
                    from aresitos.utils.sudo_manager import get_sudo_manager
                    sudo_manager = get_sudo_manager()
                    self.reporte_text.delete(1.0, tk.END)
                    self.reporte_text.insert(tk.END, "=== COMPARACIÓN DE REPORTES ===\n\n")
                    self.reporte_text.update()
                    # Usar diff para comparar archivos
                    try:
                        result = sudo_manager.execute_sudo_command(f'diff -u "{archivo1}" "{archivo2}"', timeout=10)
                        if hasattr(result, 'stdout') and result.stdout:
                            self.reporte_text.insert(tk.END, "DIFERENCIAS ENCONTRADAS:\n")
                            self.reporte_text.insert(tk.END, "=" * 30 + "\n\n")
                            self.reporte_text.insert(tk.END, result.stdout)
                        else:
                            self.reporte_text.insert(tk.END, "Los archivos son idénticos.\n")
                    except Exception as e:
                        logging.debug(f'Error en excepción: {e}')
                        # Fallback a comparación simple
                        with open(archivo1, 'r', encoding='utf-8') as f1, open(archivo2, 'r', encoding='utf-8') as f2:
                            content1 = f1.read()
                            content2 = f2.read()
                        if content1 == content2:
                            self.reporte_text.insert(tk.END, "Los archivos son idénticos.\n")
                        else:
                            self.reporte_text.insert(tk.END, "Los archivos son diferentes.\n")
                            self.reporte_text.insert(tk.END, f"Tamaño archivo 1: {len(content1)} caracteres\n")
                            self.reporte_text.insert(tk.END, f"Tamaño archivo 2: {len(content2)} caracteres\n")
                    self._log_terminal("Comparación de reportes completada", "REPORTES", "INFO")
                except Exception as e:
                    self.reporte_text.insert(tk.END, f"Error en comparación: {str(e)}")
            thread = threading.Thread(target=realizar_comparacion)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al comparar reportes: {str(e)}")

# RESUMEN: Vista para generación y gestión de reportes del sistema. Permite generar 
# reportes completos con datos de escaneo, monitoreo y utilidades, guardar en 
# formato JSON y TXT, cargar reportes existentes y gestionar archivos de reportes.
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado Reportes con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - Reportes",
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
                command=self.limpiar_terminal_reportes,
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
                command=self.abrir_logs_reportes,
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
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - Reportes v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, f"Sistema: Kali Linux - Reports Management\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Generación de reportes\n\n")
            
            self.log_to_terminal("Terminal Reportes iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Reportes: {e}")
    
    def limpiar_terminal_reportes(self):
        """Limpiar terminal Reportes manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - Reportes v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - Reports Management\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal Reportes reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Reportes: {e}")
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada, sin validación de seguridad, si el usuario autenticó como root/sudo."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        self.terminal_output.insert(tk.END, f"\n> {comando}\n")
        self.terminal_output.see(tk.END)
        self.comando_entry.delete(0, tk.END)
        # Ejecutar el comando tal cual en thread
        thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_async(self, comando):
        """Ejecutar comando de forma asíncrona SOLO en Kali Linux, usando SudoManager y comandos nativos."""
        try:
            if comando == "ayuda-comandos":
                self._mostrar_ayuda_comandos()
                return
            elif comando == "info-seguridad":
                self._mostrar_info_seguridad()
                return
            elif comando in ["clear", "cls"]:
                self.limpiar_terminal_reportes()
                return
            from aresitos.utils.sudo_manager import get_sudo_manager
            sudo_manager = get_sudo_manager()
            resultado = sudo_manager.execute_sudo_command(comando, timeout=30)
            if resultado.stdout:
                self.terminal_output.insert(tk.END, resultado.stdout)
            if resultado.stderr:
                self.terminal_output.insert(tk.END, f"ERROR: {resultado.stderr}")
            self.terminal_output.see(tk.END)
        except Exception as e:
            self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
        self.terminal_output.see(tk.END)
    
    def _obtener_datos_dashboard(self):
        """Obtener datos del módulo Dashboard."""
        try:
            # Prioridad: devolver datos sincronizados si existen
            if self._datos_dashboard:
                return self._datos_dashboard
            # Si no hay datos sincronizados, intentar obtenerlos en vivo
            if hasattr(self.vista_principal, 'notebook') and hasattr(self.vista_principal.notebook, 'tab'):
                for i, (nombre, vista) in enumerate(self.vista_principal.vistas.items()):
                    if 'dashboard' in nombre.lower():
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos = vista.obtener_datos_para_reporte()
                            self._datos_dashboard = datos
                            return datos
            # Fallback: datos básicos
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Dashboard',
                'estado': 'datos_limitados',
                'info': 'Datos básicos del sistema'
            }
        except Exception as e:
            return {'error': f'Error obteniendo datos dashboard: {str(e)}'}

    def _obtener_datos_escaneo(self):
        """Obtener datos completos del módulo Escaneador - Issue 20/24."""
        try:
            if self._datos_escaneo:
                return self._datos_escaneo
            # Si no hay datos sincronizados, obtener en vivo
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Escaneador',
                'estado': 'captura_completa',
                'terminal_content': '',
                'estadisticas': {},
                'configuracion': {}
            }
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'escaneo' in nombre.lower():
                        if hasattr(vista, 'text_terminal'):
                            try:
                                contenido_terminal = vista.text_terminal.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal de escaneador'
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        if hasattr(vista, 'estadisticas_escaneador'):
                            datos['estadisticas'] = vista.estadisticas_escaneador
                        break
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal de escaneador no accesible'
            self._datos_escaneo = datos
            return datos
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Escaneador',
                'error': f'Error obteniendo datos escaneo: {str(e)}',
                'estado': 'error'
            }

    def _obtener_datos_monitoreo(self):
        """Obtener datos completos del módulo Monitoreo - Issue 20/24."""
        try:
            if self._datos_monitoreo:
                return self._datos_monitoreo
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Monitoreo',
                'estado': 'captura_completa',
                'terminal_content': '',
                'monitor_estado': {},
                'alertas': []
            }
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'monitoreo' in nombre.lower():
                        if hasattr(vista, 'text_monitor'):
                            try:
                                contenido_terminal = vista.text_monitor.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if any(palabra in linea.upper() for palabra in ['ERROR', 'WARNING', 'CRITICO', 'ALERTA']):
                                        datos['alertas'].append(linea.strip())
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal de monitoreo'
                        if hasattr(vista, 'monitor_activo'):
                            datos['monitor_estado']['activo'] = vista.monitor_activo
                        if hasattr(vista, 'monitor_red_activo'):
                            datos['monitor_estado']['red_activo'] = vista.monitor_red_activo
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        break
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal de monitoreo no accesible'
            self._datos_monitoreo = datos
            return datos
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Monitoreo',
                'error': f'Error obteniendo datos monitoreo: {str(e)}',
                'estado': 'error'
            }

    def _obtener_datos_fim(self):
        """Obtener datos completos del módulo FIM - Issue 20/24."""
        try:
            if self._datos_fim:
                return self._datos_fim
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'FIM',
                'estado': 'captura_completa',
                'terminal_content': '',
                'monitor_fim_activo': False,
                'archivos_monitoreados': [],
                'alertas_integridad': []
            }
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'fim' in nombre.lower():
                        if hasattr(vista, 'text_fim'):
                            try:
                                contenido_terminal = vista.text_fim.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if 'PROBLEMA:' in linea or 'WARNING:' in linea or 'ERROR' in linea:
                                        datos['alertas_integridad'].append(linea.strip())
                                    elif 'Verificando:' in linea or 'ARCHIVO:' in linea:
                                        datos['archivos_monitoreados'].append(linea.strip())
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal FIM'
                        if hasattr(vista, 'proceso_monitoreo_activo'):
                            datos['monitor_fim_activo'] = vista.proceso_monitoreo_activo
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        break
            datos['estadisticas'] = {
                'archivos_monitoreados': len(datos['archivos_monitoreados']),
                'alertas_detectadas': len(datos['alertas_integridad']),
                'monitor_activo': datos['monitor_fim_activo']
            }
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal FIM no accesible'
            self._datos_fim = datos
            return datos
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'FIM',
                'error': f'Error obteniendo datos FIM: {str(e)}',
                'estado': 'error'
            }

    def _obtener_datos_siem(self):
        """Obtener datos completos del módulo SIEM - Issue 20/24."""
        try:
            if self._datos_siem:
                return self._datos_siem
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'SIEM',
                'estado': 'captura_completa',
                'terminal_content': '',
                'siem_activo': False,
                'eventos_seguridad': [],
                'alertas_criticas': []
            }
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'siem' in nombre.lower():
                        if hasattr(vista, 'text_siem'):
                            try:
                                contenido_terminal = vista.text_siem.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if any(palabra in linea.upper() for palabra in ['CRITICO', 'ALERTA', 'VULNERABILIDAD', 'BACKDOOR', 'MALWARE']):
                                        datos['alertas_criticas'].append(linea.strip())
                                    elif any(palabra in linea.upper() for palabra in ['DETECTADO', 'MONITOREO', 'PUERTOS', 'CONEXIONES']):
                                        datos['eventos_seguridad'].append(linea.strip())
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal SIEM'
                        if hasattr(vista, 'siem_activo'):
                            datos['siem_activo'] = vista.siem_activo
                        elif hasattr(vista, 'proceso_siem_activo'):
                            datos['siem_activo'] = vista.proceso_siem_activo
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        break
            datos['estadisticas'] = {
                'eventos_detectados': len(datos['eventos_seguridad']),
                'alertas_criticas': len(datos['alertas_criticas']),
                'siem_activo': datos['siem_activo']
            }
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal SIEM no accesible'
            self._datos_siem = datos
            return datos
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'SIEM',
                'error': f'Error obteniendo datos SIEM: {str(e)}',
                'estado': 'error'
            }

    def _obtener_datos_cuarentena(self):
        """Obtener datos completos del módulo de cuarentena - Issue 20/24."""
        try:
            if self._datos_cuarentena:
                return self._datos_cuarentena
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Cuarentena',
                'estado': 'captura_completa',
                'terminal_content': '',
                'archivos_cuarentena': [],
                'alertas_cuarentena': [],
                'procesos_monitoreados': []
            }
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'cuarentena' in nombre.lower():
                        if hasattr(vista, 'text_terminal'):
                            try:
                                contenido_terminal = vista.text_terminal.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if any(palabra in linea.upper() for palabra in ['CUARENTENA', 'AISLADO', 'BLOQUEADO']):
                                        datos['archivos_cuarentena'].append(linea.strip())
                                    elif any(palabra in linea.upper() for palabra in ['ALERTA', 'SOSPECHOSO', 'MALWARE']):
                                        datos['alertas_cuarentena'].append(linea.strip())
                                    elif any(palabra in linea.upper() for palabra in ['PROCESO', 'PID', 'MONITOREO']):
                                        datos['procesos_monitoreados'].append(linea.strip())
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal cuarentena'
                        if hasattr(vista, 'cuarentena_activa'):
                            datos['cuarentena_activa'] = vista.cuarentena_activa
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        break
            datos['estadisticas'] = {
                'archivos_en_cuarentena': len(datos['archivos_cuarentena']),
                'alertas_activas': len(datos['alertas_cuarentena']),
                'procesos_monitoreados': len(datos['procesos_monitoreados'])
            }
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal de cuarentena no accesible'
            self._datos_cuarentena = datos
            return datos
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Cuarentena',
                'error': f'Error obteniendo datos cuarentena: {str(e)}',
                'estado': 'error'
            }
    
    def _obtener_terminal_principal(self):
        """Obtener contenido del terminal principal de Aresitos - Issue 20/24."""
        try:
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Terminal_Principal',
                'estado': 'captura_completa',
                'terminal_content': '',
                'comandos_ejecutados': [],
                'eventos_sistema': []
            }
            
            # Buscar el terminal principal
            if hasattr(self.vista_principal, 'text_terminal'):
                try:
                    contenido_terminal = self.vista_principal.text_terminal.get(1.0, tk.END)
                    datos['terminal_content'] = contenido_terminal.strip()
                    datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                    
                    # Analizar contenido del terminal principal
                    lineas = contenido_terminal.split('\n')
                    for linea in lineas:
                        if any(palabra in linea.upper() for palabra in ['COMANDO', 'EJECUTANDO', 'INICIANDO']):
                            datos['comandos_ejecutados'].append(linea.strip())
                        elif any(palabra in linea.upper() for palabra in ['ARESITOS', 'SISTEMA', 'CARGANDO']):
                            datos['eventos_sistema'].append(linea.strip())
                            
                except Exception:
                    datos['terminal_content'] = 'No se pudo capturar terminal principal'
            
            # Si tiene terminal alterno
            elif hasattr(self.vista_principal, 'terminal_frame') and hasattr(self.vista_principal.terminal_frame, 'text_terminal'):
                try:
                    contenido_terminal = self.vista_principal.terminal_frame.text_terminal.get(1.0, tk.END)
                    datos['terminal_content'] = contenido_terminal.strip()
                    datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                except Exception:
                    datos['terminal_content'] = 'Terminal principal no accesible'
            
            # Estadísticas del terminal principal
            datos['estadisticas'] = {
                'comandos_ejecutados': len(datos['comandos_ejecutados']),
                'eventos_sistema': len(datos['eventos_sistema']),
                'lineas_terminal': datos.get('terminal_lines', 0)
            }
            
            # Si no se encontró terminal, marcar como limitado
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal principal no accesible'
            
            return datos
            
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Terminal_Principal',
                'error': f'Error obteniendo terminal principal: {str(e)}',
                'estado': 'error'
            }
    
    def abrir_logs_reportes(self):
        """Abrir carpeta de logs Reportes con ruta robusta y multiplataforma."""
        try:
            import os
            import subprocess
            logs_path = self._get_base_dir() / 'logs'
            if logs_path.exists():
                subprocess.run(["xdg-open", str(logs_path)], check=False)
                self.log_to_terminal(f"Carpeta de logs Reportes abierta: {logs_path}")
            else:
                self.log_to_terminal(f"WARNING: Carpeta de logs no encontrada en {logs_path}")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs Reportes: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal usando función estándar."""
        self._log_terminal(mensaje, "REPORTES", "INFO")
    
    def sincronizar_terminal(self):
        """Función de compatibilidad - ya no necesaria con terminal estándar."""
        pass

    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles (versión simplificada)."""
        self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
        self.terminal_output.insert(tk.END, "[INFO]  Terminal Reportes - Comandos disponibles\n")
        self.terminal_output.insert(tk.END, "="*60 + "\n\n")
        self.terminal_output.insert(tk.END, "Puedes ejecutar cualquier comando del sistema.\n")
        self.terminal_output.insert(tk.END, "Comandos especiales: clear/cls\n")
        self.terminal_output.insert(tk.END, "="*60 + "\n")
        self.terminal_output.see(tk.END)

    def _mostrar_info_seguridad(self):
        """Mostrar información de seguridad (deshabilitado)."""
        self._actualizar_terminal_seguro("\n[INFO] Seguridad: validación deshabilitada.\n")
    
    def _actualizar_reporte_seguro(self, texto, modo="append"):
        """Actualizar reporte_text de forma segura desde threads."""
        def _update():
            try:
                if hasattr(self, 'reporte_text') and self.reporte_text.winfo_exists():
                    if modo == "clear":
                        self.reporte_text.delete(1.0, tk.END)
                    elif modo == "replace":
                        self.reporte_text.delete(1.0, tk.END)
                        self.reporte_text.insert(1.0, texto)
                    elif modo == "append":
                        self.reporte_text.insert(tk.END, texto)
                    elif modo == "insert_start":
                        self.reporte_text.insert(1.0, texto)
                    self.reporte_text.see(tk.END)
                    if hasattr(self.reporte_text, 'update'):
                        self.reporte_text.update()
            except (tk.TclError, AttributeError):
                pass
        
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass
    
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
    
    def mostrar_log_centralizado(self):
        """Muestra el log centralizado de LoggerAresitos en una ventana nueva."""
        from aresitos.utils.logger_aresitos import LoggerAresitos
        log = LoggerAresitos.get_instance().get_log()
        ventana = tk.Toplevel(self)
        ventana.title("Log Centralizado de ARESITOS")
        ventana.geometry("900x500")
        ventana.configure(bg=self.colors.get('bg_secondary', '#f0f0f0'))
        text_log = scrolledtext.ScrolledText(ventana, bg='#1e1e1e', fg='#00ff00', font=("Consolas", 10))
        text_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for linea in log:
            text_log.insert(tk.END, linea + "\n")
        text_log.see(tk.END)
        text_log.config(state=tk.DISABLED)

    def crear_boton_log_centralizado(self, parent=None):
        """Crea un botón para mostrar el log centralizado en la interfaz de reportes."""
        if parent is None:
            parent = self
        btn = tk.Button(parent, text="Ver Log Centralizado", command=self.mostrar_log_centralizado,
                        bg=self.colors.get('info', '#007acc'), fg='white', font=("Arial", 9, "bold"))
        btn.pack(side=tk.TOP, anchor=tk.NE, padx=10, pady=5)

