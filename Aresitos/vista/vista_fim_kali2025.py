# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Vista FIM Integrada Kali 2025 OPTIMIZADA
Vista optimizada que integra Controlador + Vista FIM siguiendo principios ARESITOS V3
OPTIMIZADO: Python nativo + Kali tools + Thread Safety + Acceso Dinámico
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor

try:
    from Aresitos.modelo.modelo_fim_kali2025 import FIMKali2025
    FIM_DISPONIBLE = True
except ImportError:
    FIM_DISPONIBLE = False
    FIMKali2025 = None

class VistaFIMKali2025:
    """
    Vista integrada FIM (File Integrity Monitoring) para Kali Linux 2025
    OPTIMIZADO con PRINCIPIOS ARESITOS V3: Thread Safety + Acceso Dinámico + Kali Tools
    Combina funcionalidades de controlador y vista siguiendo principios ARESITOS
    """
    
    def __init__(self, parent=None, modelo_principal=None):
        # Thread Safety (PRINCIPIO ARESITOS V3)
        self._lock = threading.RLock()
        self._cache = {}
        self._thread_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="VistaFIM")
        
        # Inicialización thread-safe
        with self._lock:
            self.parent = parent
            self.modelo_principal = modelo_principal
            
            # Tema Burp Suite (oscuro profesional)
            self.colores = {
                'bg_principal': '#1e1e1e',
                'bg_secundario': '#2d2d2d',
                'bg_entrada': '#3e3e3e',
                'fg_texto': '#ffffff',
                'fg_secundario': '#cccccc',
                'accent': '#ff6600',
                'success': '#00ff00',
                'warning': '#ffff00',
                'error': '#ff0000',
                'border': '#555555'
            }
            
            # Inicializar modelo FIM con acceso dinámico
            self._inicializar_fim_dinamico()
            
            # Estado de la vista thread-safe
            self._monitoreo_activo = False
            self._actualizacion_ui_activa = False
            
            # Callbacks para integración con validación de tipos
            self.callbacks: Dict[str, Optional[Callable]] = {
                'actualizacion_estado': None,
                'notificacion_evento': None,
                'error_callback': None
            }
            
            # Variables UI inicializadas como None
            self.frame_principal = None
            self.notebook = None
            self.texto_log = None
            self.tabla_eventos = None
            self.tabla_detecciones = None
            
            self.log("[FIM VISTA] Sistema de vista FIM inicializado con ARESITOS V3")
    
    def _inicializar_fim_dinamico(self):
        """Inicializar FIM con acceso dinámico y fallback robusto (PRINCIPIO ARESITOS V3)."""
        try:
            if FIM_DISPONIBLE and FIMKali2025:
                self.fim = FIMKali2025()
                self.log("OK FIM Kali2025 inicializado correctamente")
            else:
                self.fim = self._crear_fim_mock()
                self.log("WARNING FIM no disponible, usando mock")
                
        except Exception as e:
            self.log(f"ERROR Error inicializando FIM: {e}")
            self.fim = self._crear_fim_mock()
    
    def _crear_fim_mock(self):
        """Crear FIM mock con métodos dinámicos (PRINCIPIO ARESITOS V3)."""
        class FIMMock:
            def __init__(self):
                self.logger = None
                
            def iniciar_monitoreo_tiempo_real(self, rutas):
                return {'exito': False, 'error': 'FIM mock - funcionalidad no disponible'}
                
            def detener_monitoreo(self):
                return True
                
            def escaneo_rootkits_completo(self):
                return {'exito': False, 'detecciones': {}, 'detecciones_totales': 0}
                
            def auditoria_seguridad_linpeas(self):
                return {'exito': False, 'problemas_seguridad': [], 'total_problemas': 0}
                
            def escaneo_malware_yara_clamav(self, directorio):
                return {'exito': False, 'detecciones': {}, 'detecciones_totales': 0}
                
            def analisis_completo_fim_kali2025(self):
                return {
                    'exito': False,
                    'herramientas_utilizadas': [],
                    'resumen': {'cambios_detectados': 0, 'rootkits_detectados': 0, 'malware_detectado': 0, 'problemas_seguridad': 0},
                    'analisis': {}
                }
                
            def obtener_estado_fim(self):
                return {
                    'estado': {'cambios_detectados': 0},
                    'herramientas_disponibles': ['mock'],
                    'fim_mock': True
                }
                
            def __getattr__(self, name):
                """Método dinámico para cualquier atributo no definido"""
                def mock_method(*args, **kwargs):
                    return {'exito': False, 'error': f'Método {name} no implementado en FIM mock'}
                return mock_method
        
        return FIMMock()
    
    def log(self, mensaje: str):
        """Sistema de logging optimizado"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {mensaje}")
        
        # Actualizar UI si existe
        if self.texto_log:
            try:
                self.texto_log.insert(tk.END, f"[{timestamp}] {mensaje}\n")
                self.texto_log.see(tk.END)
            except:
                pass
    
    def crear_interfaz(self, parent_frame):
        """
        Crear interfaz principal FIM con tema Burp Suite y acceso dinámico (PRINCIPIO ARESITOS V3).
        """
        try:
            self.frame_principal = ttk.Frame(parent_frame)
            self.frame_principal.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Configurar estilo Burp Suite
            self._configurar_estilo_burp()
            
            # Crear notebook principal con verificación
            self.notebook = ttk.Notebook(self.frame_principal, style='Burp.TNotebook')
            if self.notebook:
                self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                # Crear tabs del FIM con acceso dinámico
                self._crear_tab_monitoreo()
                self._crear_tab_escaneo()
                self._crear_tab_detecciones()
                self._crear_tab_configuracion()
                self._crear_tab_logs()
                
                # Iniciar actualización UI de forma asíncrona
                self._thread_pool.submit(self._iniciar_actualizacion_ui)
                
                self.log("OK Interfaz FIM creada correctamente")
            else:
                self.log("ERROR Error creando notebook principal")
                
        except Exception as e:
            self.log(f"ERROR Error creando interfaz: {e}")
            # Crear interfaz mínima de fallback
            self._crear_interfaz_fallback(parent_frame)
    
    def _crear_interfaz_fallback(self, parent_frame):
        """Crear interfaz mínima de fallback (PRINCIPIO ARESITOS V3)."""
        try:
            fallback_frame = tk.Frame(parent_frame, bg=self.colores['bg_principal'])
            fallback_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            tk.Label(fallback_frame, 
                    text="WARNING FIM - Modo Limitado", 
                    bg=self.colores['bg_principal'], 
                    fg=self.colores['warning'],
                    font=('Arial', 14, 'bold')).pack(pady=20)
            
            self.texto_log = tk.Text(fallback_frame,
                                   bg=self.colores['bg_entrada'],
                                   fg=self.colores['fg_texto'],
                                   font=('Consolas', 10))
            self.texto_log.pack(fill=tk.BOTH, expand=True, pady=10)
            
            self.log("WARNING Interfaz FIM en modo fallback")
            
        except Exception as e:
            self.log(f"ERROR Error en interfaz fallback: {e}")
    
    def _configurar_estilo_burp(self):
        """Configurar tema visual Burp Suite"""
        style = ttk.Style()
        
        # Configurar colores base
        style.configure('Burp.TNotebook', 
                       background=self.colores['bg_principal'],
                       borderwidth=1,
                       relief='solid')
        
        style.configure('Burp.TNotebook.Tab',
                       background=self.colores['bg_secundario'],
                       foreground=self.colores['fg_texto'],
                       padding=[10, 5],
                       borderwidth=1)
        
        style.map('Burp.TNotebook.Tab',
                 background=[('selected', self.colores['accent'])],
                 foreground=[('selected', '#ffffff')])
        
        style.configure('Burp.TFrame',
                       background=self.colores['bg_principal'])
        
        style.configure('Burp.TLabel',
                       background=self.colores['bg_principal'],
                       foreground=self.colores['fg_texto'])
        
        style.configure('Burp.TButton',
                       background=self.colores['bg_secundario'],
                       foreground=self.colores['fg_texto'],
                       borderwidth=1,
                       relief='solid')
        
        style.map('Burp.TButton',
                 background=[('active', self.colores['accent'])])
    
    def _crear_tab_monitoreo(self):
        """Tab de monitoreo en tiempo real con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            frame_monitoreo = ttk.Frame(self.notebook, style='Burp.TFrame')
            
            # Verificar que notebook existe antes de agregar
            if hasattr(self, 'notebook') and self.notebook:
                metodo_add = getattr(self.notebook, 'add', None)
                if metodo_add:
                    metodo_add(frame_monitoreo, text="[SCAN] Monitoreo Tiempo Real")
                else:
                    self.log("WARNING Método add no disponible en notebook")
                    return
            else:
                self.log("WARNING Notebook no disponible para tab monitoreo")
                return
            
            # Panel superior - controles
            frame_controles = ttk.Frame(frame_monitoreo, style='Burp.TFrame')
            frame_controles.pack(fill=tk.X, padx=10, pady=5)
            
            # Botones principales
            self.btn_iniciar_monitoreo = ttk.Button(
                frame_controles,
                text="START INICIAR MONITOREO",
                command=self._iniciar_monitoreo_ui,
                style='Burp.TButton'
            )
            self.btn_iniciar_monitoreo.pack(side=tk.LEFT, padx=5)
            
            self.btn_detener_monitoreo = ttk.Button(
                frame_controles,
                text="⏹ DETENER MONITOREO",
                command=self._detener_monitoreo_ui,
                style='Burp.TButton',
                state='disabled'
            )
            self.btn_detener_monitoreo.pack(side=tk.LEFT, padx=5)
            
            self.btn_agregar_ruta = ttk.Button(
                frame_controles,
                text="DIR AGREGAR RUTA",
                command=self._agregar_ruta_ui,
                style='Burp.TButton'
            )
            self.btn_agregar_ruta.pack(side=tk.LEFT, padx=5)
            
            # Estado del monitoreo
            self.label_estado = ttk.Label(
                frame_controles,
                text="Estado: DETENIDO",
                style='Burp.TLabel'
            )
            self.label_estado.pack(side=tk.RIGHT, padx=10)
            
            # Panel medio - rutas monitoreadas
            frame_rutas = ttk.LabelFrame(frame_monitoreo, text="Rutas Monitoreadas", style='Burp.TFrame')
            frame_rutas.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Lista de rutas
            self.lista_rutas = tk.Listbox(
                frame_rutas,
                bg=self.colores['bg_entrada'],
                fg=self.colores['fg_texto'],
                selectbackground=self.colores['accent'],
                borderwidth=1,
                relief='solid'
            )
            self.lista_rutas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            scrollbar_rutas = ttk.Scrollbar(frame_rutas, orient=tk.VERTICAL, command=self.lista_rutas.yview)
            scrollbar_rutas.pack(side=tk.RIGHT, fill=tk.Y)
            self.lista_rutas.config(yscrollcommand=scrollbar_rutas.set)
            
            # Panel inferior - eventos en tiempo real
            frame_eventos = ttk.LabelFrame(frame_monitoreo, text="Eventos en Tiempo Real", style='Burp.TFrame')
            frame_eventos.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Tabla de eventos
            columnas_eventos = ('Tiempo', 'Archivo', 'Evento', 'Severidad')
            self.tabla_eventos = ttk.Treeview(
                frame_eventos,
                columns=columnas_eventos,
                show='headings',
                height=8
            )
            
            for col in columnas_eventos:
                self.tabla_eventos.heading(col, text=col)
                self.tabla_eventos.column(col, width=150)
            
            self.tabla_eventos.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            scrollbar_eventos = ttk.Scrollbar(frame_eventos, orient=tk.VERTICAL, command=self.tabla_eventos.yview)
            scrollbar_eventos.pack(side=tk.RIGHT, fill=tk.Y)
            self.tabla_eventos.config(yscrollcommand=scrollbar_eventos.set)
            
            # Cargar rutas predeterminadas
            self._cargar_rutas_predeterminadas()
            
        except Exception as e:
            self.log(f"ERROR Error creando tab monitoreo: {e}")
    
    def _crear_tab_escaneo(self):
        """Tab de escaneos de seguridad con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            frame_escaneo = ttk.Frame(self.notebook, style='Burp.TFrame')
            
            # Verificar que notebook existe antes de agregar
            if hasattr(self, 'notebook') and self.notebook:
                metodo_add = getattr(self.notebook, 'add', None)
                if metodo_add:
                    metodo_add(frame_escaneo, text="SHIELD Escaneos Seguridad")
                else:
                    self.log("WARNING Método add no disponible en notebook")
                    return
            else:
                self.log("WARNING Notebook no disponible para tab escaneos")
                return
            
            # Panel controles escaneo
            frame_controles_escaneo = ttk.Frame(frame_escaneo, style='Burp.TFrame')
            frame_controles_escaneo.pack(fill=tk.X, padx=10, pady=5)
            
            # Botones de escaneo
            self.btn_escaneo_rootkits = ttk.Button(
                frame_controles_escaneo,
                text="[SCAN] ESCANEO ROOTKITS",
                command=self._ejecutar_escaneo_rootkits,
                style='Burp.TButton'
            )
            self.btn_escaneo_rootkits.pack(side=tk.LEFT, padx=5)
            
            self.btn_auditoria_linpeas = ttk.Button(
                frame_controles_escaneo,
                text="LIST AUDITORÍA LINPEAS",
                command=self._ejecutar_auditoria_linpeas,
                style='Burp.TButton'
            )
            self.btn_auditoria_linpeas.pack(side=tk.LEFT, padx=5)
            
            self.btn_escaneo_malware = ttk.Button(
                frame_controles_escaneo,
                text="🦠 ESCANEO MALWARE",
                command=self._ejecutar_escaneo_malware,
                style='Burp.TButton'
            )
            self.btn_escaneo_malware.pack(side=tk.LEFT, padx=5)
            
            self.btn_analisis_completo = ttk.Button(
                frame_controles_escaneo,
                text="[TARGET] ANÁLISIS COMPLETO",
                command=self._ejecutar_analisis_completo,
                style='Burp.TButton'
            )
            self.btn_analisis_completo.pack(side=tk.LEFT, padx=5)
            
            # Progress bar
            self.progress_escaneo = ttk.Progressbar(
                frame_controles_escaneo,
                mode='indeterminate',
                style='Burp.Horizontal.TProgressbar'
            )
            self.progress_escaneo.pack(side=tk.RIGHT, padx=10, fill=tk.X, expand=True)
            
            # Panel resultados escaneo
            frame_resultados = ttk.LabelFrame(frame_escaneo, text="Resultados Escaneos", style='Burp.TFrame')
            frame_resultados.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Notebook para diferentes tipos de resultados
            self.notebook_resultados = ttk.Notebook(frame_resultados, style='Burp.TNotebook')
            self.notebook_resultados.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Tab rootkits
            self._crear_tab_resultados_rootkits()
            
            # Tab malware
            self._crear_tab_resultados_malware()
            
            # Tab vulnerabilidades
            self._crear_tab_resultados_vulnerabilidades()
            
        except Exception as e:
            self.log(f"ERROR Error creando tab escaneo: {e}")
    
    def _crear_tab_detecciones(self):
        """Tab de detecciones y alertas con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            frame_detecciones = ttk.Frame(self.notebook, style='Burp.TFrame')
            
            # Verificar que notebook existe antes de agregar
            if hasattr(self, 'notebook') and self.notebook:
                metodo_add = getattr(self.notebook, 'add', None)
                if metodo_add:
                    metodo_add(frame_detecciones, text="WARN Detecciones")
                else:
                    self.log("WARNING Método add no disponible en notebook")
                    return
            else:
                self.log("WARNING Notebook no disponible para tab detecciones")
                return
            
            # Panel filtros
            frame_filtros = ttk.Frame(frame_detecciones, style='Burp.TFrame')
            frame_filtros.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Label(frame_filtros, text="Filtros:", style='Burp.TLabel').pack(side=tk.LEFT, padx=5)
            
            self.combo_severidad = ttk.Combobox(
                frame_filtros,
                values=['TODAS', 'ALTA', 'MEDIA', 'BAJA'],
                state='readonly',
                width=10
            )
            self.combo_severidad.set('TODAS')
            self.combo_severidad.pack(side=tk.LEFT, padx=5)
            
            self.combo_tipo = ttk.Combobox(
                frame_filtros,
                values=['TODOS', 'rootkit', 'malware', 'virus', 'vulnerabilidad'],
                state='readonly',
                width=15
            )
            self.combo_tipo.set('TODOS')
            self.combo_tipo.pack(side=tk.LEFT, padx=5)
            
            ttk.Button(
                frame_filtros,
                text="🔄 ACTUALIZAR",
                command=self._actualizar_detecciones,
                style='Burp.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            # Tabla detecciones
            frame_tabla_det = ttk.Frame(frame_detecciones, style='Burp.TFrame')
            frame_tabla_det.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            columnas_det = ('ID', 'Timestamp', 'Herramienta', 'Tipo', 'Archivo', 'Descripción', 'Severidad')
            self.tabla_detecciones = ttk.Treeview(
                frame_tabla_det,
                columns=columnas_det,
                show='headings'
            )
            
            for col in columnas_det:
                self.tabla_detecciones.heading(col, text=col)
                self.tabla_detecciones.column(col, width=120)
            
            self.tabla_detecciones.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            scrollbar_det = ttk.Scrollbar(frame_tabla_det, orient=tk.VERTICAL, command=self.tabla_detecciones.yview)
            scrollbar_det.pack(side=tk.RIGHT, fill=tk.Y)
            self.tabla_detecciones.config(yscrollcommand=scrollbar_det.set)
            
        except Exception as e:
            self.log(f"ERROR Error creando tab detecciones: {e}")
    
    def _crear_tab_configuracion(self):
        """Tab de configuración FIM con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            frame_config = ttk.Frame(self.notebook, style='Burp.TFrame')
            
            # Verificar que notebook existe antes de agregar
            if hasattr(self, 'notebook') and self.notebook:
                metodo_add = getattr(self.notebook, 'add', None)
                if metodo_add:
                    metodo_add(frame_config, text="SETUP Configuración")
                else:
                    self.log("WARNING Método add no disponible en notebook")
                    return
            else:
                self.log("WARNING Notebook no disponible para tab configuración")
                return
            
            # Panel herramientas
            frame_herramientas = ttk.LabelFrame(frame_config, text="Herramientas Disponibles", style='Burp.TFrame')
            frame_herramientas.pack(fill=tk.X, padx=10, pady=5)
            
            self.texto_herramientas = tk.Text(
                frame_herramientas,
                height=6,
                bg=self.colores['bg_entrada'],
                fg=self.colores['fg_texto'],
                state='disabled'
            )
            self.texto_herramientas.pack(fill=tk.X, padx=5, pady=5)
            
            # Panel estado FIM
            frame_estado = ttk.LabelFrame(frame_config, text="Estado del Sistema", style='Burp.TFrame')
            frame_estado.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            self.texto_estado = scrolledtext.ScrolledText(
                frame_estado,
                bg=self.colores['bg_entrada'],
                fg=self.colores['fg_texto'],
                state='disabled'
            )
            self.texto_estado.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Botones configuración
            frame_botones_config = ttk.Frame(frame_config, style='Burp.TFrame')
            frame_botones_config.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Button(
                frame_botones_config,
                text="🔄 ACTUALIZAR ESTADO",
                command=self._actualizar_estado_fim,
                style='Burp.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(
                frame_botones_config,
                text="SAVE EXPORTAR CONFIG",
                command=self._exportar_configuracion,
                style='Burp.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            # Actualizar estado inicial
            self._actualizar_estado_fim()
            
        except Exception as e:
            self.log(f"ERROR Error creando tab configuración: {e}")
    
    def _crear_tab_logs(self):
        """Tab de logs del sistema con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            frame_logs = ttk.Frame(self.notebook, style='Burp.TFrame')
            
            # Verificar que notebook existe antes de agregar
            if hasattr(self, 'notebook') and self.notebook:
                metodo_add = getattr(self.notebook, 'add', None)
                if metodo_add:
                    metodo_add(frame_logs, text="📄 Logs")
                else:
                    self.log("WARNING Método add no disponible en notebook")
                    return
            else:
                self.log("WARNING Notebook no disponible para tab logs")
                return
            
            # Controles logs
            frame_controles_logs = ttk.Frame(frame_logs, style='Burp.TFrame')
            frame_controles_logs.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Button(
                frame_controles_logs,
                text="CLEAR LIMPIAR LOGS",
                command=self._limpiar_logs,
                style='Burp.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(
                frame_controles_logs,
                text="SAVE GUARDAR LOGS",
                command=self._guardar_logs,
                style='Burp.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            # Área de logs
            self.texto_log = scrolledtext.ScrolledText(
                frame_logs,
                bg=self.colores['bg_entrada'],
                fg=self.colores['fg_texto'],
                font=('Consolas', 10)
            )
            self.texto_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
        except Exception as e:
            self.log(f"ERROR Error creando tab logs: {e}")
    
    def _crear_tab_resultados_rootkits(self):
        """Tab para resultados de rootkits"""
        frame_rootkits = ttk.Frame(self.notebook_resultados, style='Burp.TFrame')
        self.notebook_resultados.add(frame_rootkits, text="Rootkits")
        
        self.tabla_rootkits = ttk.Treeview(
            frame_rootkits,
            columns=('Herramienta', 'Archivo', 'Tipo', 'Descripción', 'Severidad'),
            show='headings'
        )
        
        for col in self.tabla_rootkits['columns']:
            self.tabla_rootkits.heading(col, text=col)
            self.tabla_rootkits.column(col, width=120)
        
        self.tabla_rootkits.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _crear_tab_resultados_malware(self):
        """Tab para resultados de malware"""
        frame_malware = ttk.Frame(self.notebook_resultados, style='Burp.TFrame')
        self.notebook_resultados.add(frame_malware, text="Malware")
        
        self.tabla_malware = ttk.Treeview(
            frame_malware,
            columns=('Herramienta', 'Archivo', 'Amenaza', 'Tipo', 'Severidad'),
            show='headings'
        )
        
        for col in self.tabla_malware['columns']:
            self.tabla_malware.heading(col, text=col)
            self.tabla_malware.column(col, width=120)
        
        self.tabla_malware.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _crear_tab_resultados_vulnerabilidades(self):
        """Tab para resultados de vulnerabilidades"""
        frame_vulns = ttk.Frame(self.notebook_resultados, style='Burp.TFrame')
        self.notebook_resultados.add(frame_vulns, text="Vulnerabilidades")
        
        self.tabla_vulnerabilidades = ttk.Treeview(
            frame_vulns,
            columns=('Descripción', 'Tipo', 'Severidad', 'Fuente'),
            show='headings'
        )
        
        for col in self.tabla_vulnerabilidades['columns']:
            self.tabla_vulnerabilidades.heading(col, text=col)
            self.tabla_vulnerabilidades.column(col, width=150)
        
        self.tabla_vulnerabilidades.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Métodos de funcionalidad principal
    def _cargar_rutas_predeterminadas(self):
        """Cargar rutas críticas predeterminadas"""
        rutas_criticas = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/etc/crontab',
            '/etc/hosts',
            '/var/log',
            '/usr/bin',
            '/usr/sbin',
            '/home'
        ]
        
        for ruta in rutas_criticas:
            self.lista_rutas.insert(tk.END, ruta)
    
    def _iniciar_monitoreo_ui(self):
        """Iniciar monitoreo desde UI"""
        if not self.fim:
            messagebox.showerror("Error", "FIM no disponible")
            return
        
        rutas = []
        for i in range(self.lista_rutas.size()):
            ruta = self.lista_rutas.get(i)
            if os.path.exists(ruta):
                rutas.append(ruta)
        
        if not rutas:
            messagebox.showwarning("Advertencia", "No hay rutas válidas para monitorear")
            return
        
        def iniciar_thread():
            try:
                resultado = self.fim.iniciar_monitoreo_tiempo_real(rutas)
                if resultado.get('exito'):
                    self._monitoreo_activo = True
                    self.btn_iniciar_monitoreo.config(state='disabled')
                    self.btn_detener_monitoreo.config(state='normal')
                    self.label_estado.config(text="Estado: ACTIVO", foreground=self.colores['success'])
                    self.log("✓ Monitoreo FIM iniciado correctamente")
                else:
                    messagebox.showerror("Error", f"Error iniciando monitoreo: {resultado.get('error')}")
            except Exception as e:
                messagebox.showerror("Error", f"Error: {e}")
        
        threading.Thread(target=iniciar_thread, daemon=True).start()
    
    def _detener_monitoreo_ui(self):
        """Detener monitoreo desde UI"""
        if self.fim:
            self.fim.detener_monitoreo()
            
        self._monitoreo_activo = False
        self.btn_iniciar_monitoreo.config(state='normal')
        self.btn_detener_monitoreo.config(state='disabled')
        self.label_estado.config(text="Estado: DETENIDO", foreground=self.colores['error'])
        self.log("✓ Monitoreo FIM detenido")
    
    def _agregar_ruta_ui(self):
        """Agregar nueva ruta para monitorear"""
        ruta = filedialog.askdirectory(title="Seleccionar directorio para monitorear")
        if ruta:
            self.lista_rutas.insert(tk.END, ruta)
            self.log(f"✓ Ruta agregada: {ruta}")
    
    def _ejecutar_escaneo_rootkits(self):
        """Ejecutar escaneo de rootkits"""
        if not self.fim:
            messagebox.showerror("Error", "FIM no disponible")
            return
        
        def escaneo_thread():
            try:
                self.progress_escaneo.start()
                self.btn_escaneo_rootkits.config(state='disabled')
                
                self.log("[SECURITY] Iniciando escaneo de rootkits...")
                resultado = self.fim.escaneo_rootkits_completo()
                
                # Mostrar resultados en tabla
                self._mostrar_resultados_rootkits(resultado)
                
                self.log(f"✓ Escaneo rootkits completado: {resultado.get('detecciones_totales', 0)} detecciones")
                
            except Exception as e:
                self.log(f"ERROR escaneo rootkits: {e}")
                messagebox.showerror("Error", f"Error en escaneo: {e}")
            finally:
                self.progress_escaneo.stop()
                self.btn_escaneo_rootkits.config(state='normal')
        
        threading.Thread(target=escaneo_thread, daemon=True).start()
    
    def _ejecutar_auditoria_linpeas(self):
        """Ejecutar auditoría LinPEAS"""
        if not self.fim:
            messagebox.showerror("Error", "FIM no disponible")
            return
        
        def auditoria_thread():
            try:
                self.progress_escaneo.start()
                self.btn_auditoria_linpeas.config(state='disabled')
                
                self.log("[LINPEAS] Iniciando auditoría de seguridad...")
                resultado = self.fim.auditoria_seguridad_linpeas()
                
                # Mostrar resultados
                self._mostrar_resultados_vulnerabilidades(resultado)
                
                self.log(f"✓ Auditoría LinPEAS completada: {resultado.get('total_problemas', 0)} problemas")
                
            except Exception as e:
                self.log(f"ERROR auditoría LinPEAS: {e}")
                messagebox.showerror("Error", f"Error en auditoría: {e}")
            finally:
                self.progress_escaneo.stop()
                self.btn_auditoria_linpeas.config(state='normal')
        
        threading.Thread(target=auditoria_thread, daemon=True).start()
    
    def _ejecutar_escaneo_malware(self):
        """Ejecutar escaneo de malware"""
        directorio = filedialog.askdirectory(title="Seleccionar directorio para escanear malware")
        if not directorio or not self.fim:
            return
        
        def malware_thread():
            try:
                self.progress_escaneo.start()
                self.btn_escaneo_malware.config(state='disabled')
                
                self.log(f"[MALWARE] Escaneando malware en: {directorio}")
                resultado = self.fim.escaneo_malware_yara_clamav(directorio)
                
                # Mostrar resultados
                self._mostrar_resultados_malware(resultado)
                
                self.log(f"✓ Escaneo malware completado: {resultado.get('detecciones_totales', 0)} detecciones")
                
            except Exception as e:
                self.log(f"ERROR escaneo malware: {e}")
                messagebox.showerror("Error", f"Error en escaneo: {e}")
            finally:
                self.progress_escaneo.stop()
                self.btn_escaneo_malware.config(state='normal')
        
        threading.Thread(target=malware_thread, daemon=True).start()
    
    def _ejecutar_analisis_completo(self):
        """Ejecutar análisis completo FIM"""
        if not self.fim:
            messagebox.showerror("Error", "FIM no disponible")
            return
        
        def analisis_thread():
            try:
                self.progress_escaneo.start()
                self.btn_analisis_completo.config(state='disabled')
                
                self.log("[START] Iniciando análisis completo FIM...")
                resultado = self.fim.analisis_completo_fim_kali2025()
                
                # Mostrar todos los resultados
                self._mostrar_resultados_completos(resultado)
                
                self.log(f"✓ Análisis completo terminado - {len(resultado.get('herramientas_utilizadas', []))} herramientas")
                
            except Exception as e:
                self.log(f"ERROR análisis completo: {e}")
                messagebox.showerror("Error", f"Error en análisis: {e}")
            finally:
                self.progress_escaneo.stop()
                self.btn_analisis_completo.config(state='normal')
        
        threading.Thread(target=analisis_thread, daemon=True).start()
    
    # Métodos de visualización de resultados
    def _mostrar_resultados_rootkits(self, resultado: Dict[str, Any]):
        """Mostrar resultados de rootkits en tabla"""
        # Limpiar tabla
        for item in self.tabla_rootkits.get_children():
            self.tabla_rootkits.delete(item)
        
        detecciones = resultado.get('detecciones', {})
        for herramienta, lista_det in detecciones.items():
            for det in lista_det:
                self.tabla_rootkits.insert('', 'end', values=(
                    herramienta,
                    det.get('archivo', ''),
                    det.get('tipo', ''),
                    det.get('descripcion', ''),
                    det.get('severidad', '')
                ))
    
    def _mostrar_resultados_malware(self, resultado: Dict[str, Any]):
        """Mostrar resultados de malware en tabla"""
        # Limpiar tabla
        for item in self.tabla_malware.get_children():
            self.tabla_malware.delete(item)
        
        detecciones = resultado.get('detecciones', {})
        for herramienta, lista_det in detecciones.items():
            for det in lista_det:
                self.tabla_malware.insert('', 'end', values=(
                    herramienta,
                    det.get('archivo', ''),
                    det.get('virus', det.get('regla', '')),
                    det.get('tipo', ''),
                    det.get('severidad', '')
                ))
    
    def _mostrar_resultados_vulnerabilidades(self, resultado: Dict[str, Any]):
        """Mostrar resultados de vulnerabilidades"""
        # Limpiar tabla
        for item in self.tabla_vulnerabilidades.get_children():
            self.tabla_vulnerabilidades.delete(item)
        
        problemas = resultado.get('problemas_seguridad', [])
        for problema in problemas:
            self.tabla_vulnerabilidades.insert('', 'end', values=(
                problema.get('descripcion', ''),
                problema.get('tipo', ''),
                problema.get('severidad', ''),
                'LinPEAS'
            ))
    
    def _mostrar_resultados_completos(self, resultado: Dict[str, Any]):
        """Mostrar resultados del análisis completo"""
        # Mostrar resumen en logs
        resumen = resultado.get('resumen', {})
        self.log(f"RESUMEN ANÁLISIS:")
        self.log(f"- Cambios detectados: {resumen.get('cambios_detectados', 0)}")
        self.log(f"- Rootkits detectados: {resumen.get('rootkits_detectados', 0)}")
        self.log(f"- Malware detectado: {resumen.get('malware_detectado', 0)}")
        self.log(f"- Problemas seguridad: {resumen.get('problemas_seguridad', 0)}")
        
        # Mostrar en tablas correspondientes
        analisis = resultado.get('analisis', {})
        
        if 'rootkits' in analisis:
            self._mostrar_resultados_rootkits(analisis['rootkits'])
        
        if 'seguridad' in analisis:
            self._mostrar_resultados_vulnerabilidades(analisis['seguridad'])
    
    def _actualizar_detecciones(self):
        """Actualizar tabla de detecciones desde BD"""
        # TODO: Implementar consulta a base de datos SQLite
        self.log("✓ Detecciones actualizadas")
    
    def _actualizar_estado_fim(self):
        """Actualizar estado del sistema FIM"""
        if not self.fim:
            estado_texto = "FIM no disponible"
        else:
            estado = self.fim.obtener_estado_fim()
            estado_texto = json.dumps(estado, indent=2, ensure_ascii=False)
            
            # Mostrar herramientas disponibles
            herramientas = '\n'.join(estado.get('herramientas_disponibles', []))
            self.texto_herramientas.config(state='normal')
            self.texto_herramientas.delete(1.0, tk.END)
            self.texto_herramientas.insert(1.0, herramientas)
            self.texto_herramientas.config(state='disabled')
        
        self.texto_estado.config(state='normal')
        self.texto_estado.delete(1.0, tk.END)
        self.texto_estado.insert(1.0, estado_texto)
        self.texto_estado.config(state='disabled')
    
    def _exportar_configuracion(self):
        """Exportar configuración FIM"""
        if not self.fim:
            return
        
        archivo = filedialog.asksaveasfilename(
            title="Guardar configuración FIM",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if archivo:
            try:
                estado = self.fim.obtener_estado_fim()
                with open(archivo, 'w', encoding='utf-8') as f:
                    json.dump(estado, f, indent=2, ensure_ascii=False)
                self.log(f"✓ Configuración exportada: {archivo}")
            except Exception as e:
                self.log(f"ERROR exportando configuración: {e}")
    
    def _limpiar_logs(self):
        """Limpiar área de logs con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            # Acceso dinámico al texto_log
            texto_log = getattr(self, 'texto_log', None)
            if texto_log:
                metodo_delete = getattr(texto_log, 'delete', None)
                if metodo_delete:
                    metodo_delete(1.0, tk.END)
                    self.log("✓ Logs limpiados")
                else:
                    self.log("WARNING Método delete no disponible en texto_log")
            else:
                self.log("WARNING texto_log no disponible para limpiar")
        except Exception as e:
            self.log(f"ERROR Error limpiando logs: {e}")
    
    def _guardar_logs(self):
        """Guardar logs a archivo con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            archivo = filedialog.asksaveasfilename(
                title="Guardar logs FIM",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            
            if archivo:
                # Acceso dinámico al texto_log
                texto_log = getattr(self, 'texto_log', None)
                if texto_log:
                    metodo_get = getattr(texto_log, 'get', None)
                    if metodo_get:
                        contenido = metodo_get(1.0, tk.END)
                        with open(archivo, 'w', encoding='utf-8') as f:
                            f.write(contenido)
                        self.log(f"✓ Logs guardados: {archivo}")
                    else:
                        self.log("WARNING Método get no disponible en texto_log")
                else:
                    self.log("WARNING texto_log no disponible para guardar")
        except Exception as e:
            self.log(f"ERROR Error guardando logs: {e}")
    
    def _iniciar_actualizacion_ui(self):
        """Iniciar hilo de actualización de UI"""
        if self._actualizacion_ui_activa:
            return
            
        self._actualizacion_ui_activa = True
        
        def actualizar_ui():
            while self._actualizacion_ui_activa:
                try:
                    # Actualizar estado de monitoreo
                    if self._monitoreo_activo and self.fim:
                        estado = self.fim.obtener_estado_fim()
                        if estado.get('estado', {}).get('cambios_detectados', 0) > 0:
                            # Actualizar contadores, etc.
                            pass
                    
                    time.sleep(2)  # Actualizar cada 2 segundos
                except Exception as e:
                    self.log(f"ERROR actualización UI: {e}")
                    break
        
        threading.Thread(target=actualizar_ui, daemon=True).start()
    
    def cerrar(self):
        """Cerrar vista y liberar recursos"""
        self._actualizacion_ui_activa = False
        if self.fim:
            self.fim.detener_monitoreo()
        self.log("✓ Vista FIM cerrada")
    
    # Métodos para integración con controlador principal
    def registrar_callback(self, tipo: str, callback: Callable):
        """Registrar callback para eventos"""
        self.callbacks[tipo] = callback
    
    def obtener_estado(self) -> Dict[str, Any]:
        """Obtener estado actual de la vista"""
        return {
            'monitoreo_activo': self._monitoreo_activo,
            'fim_disponible': self.fim is not None,
            'rutas_monitoreadas': self.lista_rutas.size() if self.lista_rutas else 0
        }
