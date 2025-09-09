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

from aresitos.vista.terminal_mixin import TerminalMixin

class VistaReportes(tk.Frame, TerminalMixin):
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
        """Genera el texto plano profesional del reporte de incidente siguiendo la estructura ISO/IEC 27001, en castellano formal y corregido ortográficamente."""
        line = lambda c: c*80
        secciones = [
            line('='),
            "INFORME DE INCIDENTE DE SEGURIDAD DE LA INFORMACIÓN - ISO/IEC 27001", line('='),
            f"Organización: {campos.get('organizacion','')}",
            f"Persona de contacto: {campos.get('contacto','')}",
            f"Correo electrónico: {campos.get('correo','')}",
            f"Teléfono: {campos.get('telefono','')}",
            f"Fecha de generación del informe: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            line('-'),
            "RESUMEN EJECUTIVO",
            line('-'),
            f"Título del incidente: {campos.get('titulo','')}",
            f"Fecha y hora de detección: {campos.get('fecha_deteccion','')}",
            f"Fecha y hora de inicio: {campos.get('fecha_inicio','')}",
            f"Tipo de incidente: {campos.get('tipo','')}",
            f"Sistemas o servicios afectados: {campos.get('sistemas_afectados','')}",
            "",
            line('-'),
            "DESCRIPCIÓN DEL INCIDENTE",
            line('-'),
            f"Descripción detallada: {campos.get('descripcion','')}",
            "",
            line('-'),
            "CRONOLOGÍA DEL INCIDENTE",
            line('-'),
            f"(Incluya aquí la secuencia de eventos relevantes, si aplica)",
            "",
            line('-'),
            "ACCIONES TOMADAS",
            line('-'),
            f"Acciones de contención, erradicación y recuperación: {campos.get('acciones','')}",
            "",
            line('-'),
            "IMPACTO Y ANÁLISIS",
            line('-'),
            f"Impacto en operaciones: {campos.get('impacto','')}",
            f"Datos comprometidos: {campos.get('datos_comprometidos','')}",
            "",
            line('-'),
            "LECCIONES APRENDIDAS",
            line('-'),
            f"(Incluya aquí las lecciones aprendidas y mejoras identificadas, si aplica)",
            "",
            line('-'),
            "RECOMENDACIONES",
            line('-'),
            f"(Incluya aquí recomendaciones para evitar incidentes similares)",
            "",
            line('-'),
            "ANEXOS",
            line('-'),
            f"Observaciones y documentación adicional: {campos.get('observaciones','')}",
            "",
            line('='),
            "Reporte generado por ARESITOS conforme a ISO/IEC 27001 - https://github.com/DogSoulDev/aresitos"
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
        self._datos_dashboard = {}
        self._datos_escaneo = {}
        self._datos_monitoreo = {}
        self._datos_fim = {}
        self._datos_siem = {}
        self._datos_cuarentena = {}
        self._datos_terminal_principal = {}

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

    # --- Métodos de obtención de datos de cada módulo ---
    def _obtener_datos_dashboard(self):
        return self.get_datos_modulo('dashboard') or {}
    def _obtener_datos_escaneo(self):
        return self.get_datos_modulo('escaneo') or {}
    def _obtener_datos_monitoreo(self):
        return self.get_datos_modulo('monitoreo') or {}
    def _obtener_datos_fim(self):
        return self.get_datos_modulo('fim') or {}
    def _obtener_datos_siem(self):
        return self.get_datos_modulo('siem') or {}
    def _obtener_datos_cuarentena(self):
        return self.get_datos_modulo('cuarentena') or {}
    def _obtener_terminal_principal(self):
        return self.get_datos_modulo('terminal_principal') or {}
    def _obtener_terminales_externas(self):
        """Detecta y recopila información básica de terminales externas abiertas en Kali Linux."""
        import subprocess, platform
        if platform.system().lower() != 'linux':
            return {'estado': 'no_soportado', 'info': 'Solo disponible en Kali/Linux'}
        try:
            # Detectar terminales abiertas (gnome-terminal, konsole, xterm, etc.)
            resultado = subprocess.run(
                ["ps", "-eo", "pid,comm,args"], capture_output=True, text=True, check=True
            )
            terminales = []
            for linea in resultado.stdout.splitlines():
                if any(term in linea for term in ["gnome-terminal", "konsole", "xterm", "xfce4-terminal", "tilix", "mate-terminal"]):
                    partes = linea.split(None, 2)
                    if len(partes) >= 3:
                        terminales.append({
                            'pid': partes[0],
                            'comando': partes[1],
                            'args': partes[2]
                        })
            return {
                'estado': 'detectado',
                'terminales_encontradas': len(terminales),
                'detalles': terminales
            }
        except Exception as e:
            return {'estado': 'error', 'info': str(e)}

    # --- Métodos de logging seguro y actualización de reporte ---
    def log_to_terminal(self, texto, modulo="REPORTES", nivel="INFO"):
        if hasattr(self, 'mini_terminal'):
            self.mini_terminal.insert('end', f"[{modulo}][{nivel}] {texto}\n")
            self.mini_terminal.see('end')
    def _actualizar_reporte_seguro(self, texto, modo="replace"):
        if hasattr(self, 'reporte_text'):
            try:
                if modo == "replace":
                    self.reporte_text.delete(1.0, 'end')
                    self.reporte_text.insert('end', texto)
                elif modo == "clear":
                    self.reporte_text.delete(1.0, 'end')
                else:
                    self.reporte_text.insert('end', texto)
                self.reporte_text.see('end')
            except Exception:
                pass

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
        self.incluir_terminales_externas = tk.BooleanVar(value=False)

        check_style = {'font': ('Arial', 11, 'bold'), 'bg': self.colors['bg_secondary'], 'activebackground': self.colors['bg_secondary'], 'fg': self.colors['fg_primary'], 'anchor': 'w', 'padx': 12, 'pady': 4}
        tk.Checkbutton(config_frame, text="Dashboard (Resumen del sistema)", variable=self.incluir_dashboard, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Escaneo (Vulnerabilidades)", variable=self.incluir_escaneo, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Monitoreo (Procesos y eventos)", variable=self.incluir_monitoreo, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="FIM (Integridad de archivos)", variable=self.incluir_fim, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="SIEM (Eventos de seguridad)", variable=self.incluir_siem, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Cuarentena (Amenazas aisladas)", variable=self.incluir_cuarentena, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        tk.Checkbutton(config_frame, text="Terminales externas abiertas en Kali (incluir información de terminales externas en el reporte)", variable=self.incluir_terminales_externas, command=self.actualizar_reporte, **check_style).pack(fill=tk.X, pady=2)
        explicacion_terminales = tk.Label(config_frame, text="Si marcas esta opción, ARESITOS intentará detectar y agregar información de las terminales externas abiertas en Kali Linux al reporte final. Útil para auditoría avanzada y trazabilidad completa.", wraplength=320, justify='left', bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], font=("Arial", 9, "italic"))
        explicacion_terminales.pack(anchor=tk.W, pady=(2, 8))

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

        # Crear terminal inferior estandarizado
        self.crear_terminal_inferior(self, titulo_vista="Reportes")

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
        
        # Crear terminal inferior estandarizado
        self.crear_terminal_inferior(self, titulo_vista="Reportes")

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
                datos_dashboard = self._obtener_datos_dashboard() if hasattr(self, 'incluir_dashboard') and self.incluir_dashboard.get() else self._obtener_datos_dashboard() if hasattr(self, '_obtener_datos_dashboard') else None
                datos_escaneo = self._obtener_datos_escaneo() if hasattr(self, 'incluir_escaneo') and self.incluir_escaneo.get() else self._obtener_datos_escaneo() if hasattr(self, '_obtener_datos_escaneo') else None
                datos_monitoreo = self._obtener_datos_monitoreo() if hasattr(self, 'incluir_monitoreo') and self.incluir_monitoreo.get() else self._obtener_datos_monitoreo() if hasattr(self, '_obtener_datos_monitoreo') else None
                datos_fim = self._obtener_datos_fim() if hasattr(self, 'incluir_fim') and self.incluir_fim.get() else self._obtener_datos_fim() if hasattr(self, '_obtener_datos_fim') else None
                datos_siem = self._obtener_datos_siem() if hasattr(self, 'incluir_siem') and self.incluir_siem.get() else self._obtener_datos_siem() if hasattr(self, '_obtener_datos_siem') else None
                datos_cuarentena = self._obtener_datos_cuarentena() if hasattr(self, 'incluir_cuarentena') and self.incluir_cuarentena.get() else self._obtener_datos_cuarentena() if hasattr(self, '_obtener_datos_cuarentena') else None
                datos_terminal_principal = self._obtener_terminal_principal() if hasattr(self, '_obtener_terminal_principal') else None
                datos_terminales_modulos = {}
                for nombre_modulo in ['dashboard', 'escaneo', 'monitoreo', 'fim', 'siem', 'cuarentena']:
                    metodo = getattr(self, f'_obtener_terminal_{nombre_modulo}', None)
                    if callable(metodo):
                        datos_terminales_modulos[nombre_modulo] = metodo()
                datos_terminales_externas = None
                if hasattr(self, 'incluir_terminales_externas') and self.incluir_terminales_externas.get():
                    self.log_to_terminal("Detectando terminales externas abiertas en Kali...")
                    datos_terminales_externas = self._obtener_terminales_externas()
                self.log_to_terminal("REPORTE Generando reporte con módulos y terminales asociados...")
                self.reporte_actual = self.controlador.generar_reporte_completo(
                    datos_escaneo=datos_escaneo,
                    datos_monitoreo=datos_monitoreo,
                    datos_utilidades=datos_dashboard,
                    datos_fim=datos_fim,
                    datos_siem=datos_siem,
                    datos_cuarentena=datos_cuarentena,
                    datos_terminal_principal=datos_terminal_principal,
                    datos_terminales_modulos=datos_terminales_modulos,
                    datos_terminales_externas=datos_terminales_externas
                )
                if self.reporte_actual:
                    self.log_to_terminal("OK Reporte generado correctamente")
                    self.mostrar_reporte(self.reporte_actual)
                    self.log_to_terminal("REPORTE Reporte mostrado en pantalla")
                else:
                    self._actualizar_reporte_seguro(" Error al generar el reporte")
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
                    ("TERMINALES EXTERNAS", reporte.get('datos_terminales_externas', {})),
                ]
                secciones.append("--- DETALLES TÉCNICOS POR MÓDULO ---")
                for nombre, datos in modulos:
                    secciones.append("-"*60)
                    secciones.append(f"[ {nombre} ]")
                    if datos:
                        if nombre == "TERMINALES EXTERNAS" and isinstance(datos, dict):
                            secciones.append(f"  Estado: {datos.get('estado', 'N/A')}")
                            secciones.append(f"  Terminales encontradas: {datos.get('terminales_encontradas', 0)}")
                            detalles = datos.get('detalles', [])
                            if detalles:
                                secciones.append("  Detalles de terminales externas:")
                                for term in detalles:
                                    secciones.append(f"    PID: {term.get('pid','')} | Comando: {term.get('comando','')} | Args: {term.get('args','')}")
                            else:
                                secciones.append("  No se detectaron terminales externas abiertas.")
                        elif isinstance(datos, dict):
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

