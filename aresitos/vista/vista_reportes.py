# -*- coding: utf-8 -*-

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
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        self.reporte_actual = None
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
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
            
        self.crear_interfaz()
    
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
        
        config_label = tk.Label(config_frame, text="Incluir en el Reporte:",
                               font=('Arial', 10, 'bold'),
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'])
        config_label.pack(anchor=tk.W)
        
        self.incluir_dashboard = tk.BooleanVar(value=True)
        self.incluir_escaneo = tk.BooleanVar(value=True)
        self.incluir_monitoreo = tk.BooleanVar(value=True)
        self.incluir_fim = tk.BooleanVar(value=True)
        self.incluir_siem = tk.BooleanVar(value=True)
        self.incluir_cuarentena = tk.BooleanVar(value=True)
        
        opciones = [
            ("Datos de Dashboard", self.incluir_dashboard),
            ("Resultados de Escaneo", self.incluir_escaneo),
            ("Datos de Monitoreo y Cuarentena", self.incluir_monitoreo),
            ("Datos de FIM (File Integrity)", self.incluir_fim),
            ("Datos de SIEM (Herramientas Forenses)", self.incluir_siem),
            ("Estado de Cuarentena", self.incluir_cuarentena)
        ]
        
        for texto, variable in opciones:
            cb = tk.Checkbutton(config_frame, text=texto, variable=variable,
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                               selectcolor=self.colors['bg_primary'],
                               activebackground=self.colors['bg_secondary'],
                               activeforeground=self.colors['fg_accent'],
                               font=('Arial', 9))
            cb.pack(anchor=tk.W, pady=2)
        
        # Botones de acción con tema Burp Suite
        botones_generar = [
            ("Generar Reporte Completo", self.generar_reporte_completo),
            ("Actualizar Vista", self.actualizar_reporte)
        ]
        
        for texto, comando in botones_generar:
            btn = tk.Button(right_frame, text=texto, command=comando,
                           bg=self.colors['fg_accent'], fg=self.colors['bg_primary'],
                           font=('Arial', 10, 'bold'),
                           relief='flat', padx=10, pady=5,
                           activebackground=self.colors['warning'])
            btn.pack(fill=tk.X, pady=5)
        
        # Separador con tema
        separador = tk.Frame(right_frame, height=2, bg=self.colors['bg_primary'])
        separador.pack(fill=tk.X, pady=10)
        
        # Botones de gestión con tema Burp Suite
        botones_gestion = [
            ("Guardar JSON", self.guardar_json),
            ("Guardar TXT", self.guardar_texto),
            ("Cargar Reporte", self.cargar_reporte),
            ("Listar Reportes", self.listar_reportes),
            ("Limpiar Vista", self.limpiar_reporte)
        ]
        
        for texto, comando in botones_gestion:
            btn = tk.Button(right_frame, text=texto, command=comando,
                           bg=self.colors['bg_primary'], fg=self.colors['fg_primary'],
                           font=('Arial', 10),
                           relief='flat', padx=10, pady=5,
                           activebackground=self.colors['bg_secondary'])
            btn.pack(fill=tk.X, pady=5)
        
        # Frame de información con tema
        info_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        info_frame.pack(fill=tk.X, pady=(20, 0))
        
        info_title = tk.Label(info_frame, text="Información",
                             font=('Arial', 10, 'bold'),
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        info_title.pack(anchor=tk.W)
        
        info_text = "Genera reportes completos del sistema con datos de Dashboard, Escaneo, Monitoreo, FIM, SIEM con herramientas forenses y estado de Cuarentena - optimizado para Kali Linux."
        info_label = tk.Label(info_frame, text=info_text, 
                             wraplength=180, justify=tk.LEFT,
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                             font=('Arial', 9))
        info_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Frame de herramientas de análisis Kali
        kali_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        kali_frame.pack(fill=tk.X, pady=(10, 0))
        
        kali_title = tk.Label(kali_frame, text="Análisis Avanzado Kali",
                             font=('Arial', 10, 'bold'),
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        kali_title.pack(anchor=tk.W)
        
        # Botones de análisis con herramientas de Kali
        botones_kali = [
            ("Análisis de Logs", self.analizar_logs_kali),
            ("Estadísticas Sistema", self.generar_estadisticas_kali),
            ("Informe Seguridad", self.generar_informe_seguridad),
            ("Comparar Reportes", self.comparar_reportes_kali)
        ]
        
        for texto, comando in botones_kali:
            btn = tk.Button(kali_frame, text=texto, command=comando,
                           bg=self.colors['info'], fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'),
                           relief='flat', padx=8, pady=3,
                           activebackground=self.colors['warning'])
            btn.pack(fill=tk.X, pady=2)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def generar_reporte_completo(self):
        self.log_to_terminal("Generando reporte completo del sistema...")
        def generar():
            try:
                if not self.controlador:
                    messagebox.showerror("Error", "Controlador no configurado")
                    return
                
                self.reporte_text.delete(1.0, tk.END)
                self.reporte_text.insert(tk.END, " Generando reporte completo...\n\n")
                self.reporte_text.update()
                
                self.log_to_terminal("DATOS Recopilando datos del sistema...")
                
                # Obtener datos reales de cada módulo
                datos_dashboard = self._obtener_datos_dashboard() if self.incluir_dashboard.get() else None
                datos_escaneo = self._obtener_datos_escaneo() if self.incluir_escaneo.get() else None  
                datos_monitoreo = self._obtener_datos_monitoreo() if self.incluir_monitoreo.get() else None
                datos_fim = self._obtener_datos_fim() if self.incluir_fim.get() else None
                datos_siem = self._obtener_datos_siem() if self.incluir_siem.get() else None
                datos_cuarentena = self._obtener_datos_cuarentena() if self.incluir_cuarentena.get() else None
                
                # Capturar terminal principal de Aresitos - Issue 20/24
                datos_terminal_principal = self._obtener_terminal_principal()
                
                self.log_to_terminal("REPORTE Generando reporte con módulos seleccionados...")
                
                # Llamar con parámetros correctos incluyendo terminal principal - Issue 20/24
                self.reporte_actual = self.controlador.generar_reporte_completo(
                    datos_escaneo=datos_escaneo,
                    datos_monitoreo=datos_monitoreo, 
                    datos_utilidades=datos_dashboard,  # Dashboard como utilidades
                    datos_fim=datos_fim,
                    datos_siem=datos_siem,
                    datos_cuarentena=datos_cuarentena,
                    datos_terminal_principal=datos_terminal_principal
                )
                
                if self.reporte_actual:
                    self.log_to_terminal("OK Reporte generado correctamente")
                    self.mostrar_reporte(self.reporte_actual)
                    self.log_to_terminal("REPORTE Reporte mostrado en pantalla")
                else:
                    self.reporte_text.insert(tk.END, " Error al generar el reporte")
                    self.log_to_terminal("ERROR Error al generar el reporte")
                    
            except Exception as e:
                self.reporte_text.insert(tk.END, f" Error durante la generación: {str(e)}")
        
        # Issue 21/24: Threading optimizado con gestión de memoria
        thread = threading.Thread(target=generar, name="ReporteCompleto")
        thread.daemon = True
        thread.start()
        
        # Optimización de memoria después del threading
        gc.collect()
    
    def mostrar_reporte(self, reporte):
        self.reporte_text.delete(1.0, tk.END)
        
        try:
            if isinstance(reporte, dict):
                import json
                texto_reporte = json.dumps(reporte, indent=2, ensure_ascii=False)
            else:
                texto_reporte = str(reporte)
            self.reporte_text.insert(tk.END, texto_reporte)
        except Exception as e:
            self.reporte_text.insert(tk.END, f"Error al mostrar reporte: {str(e)}")
    
    def actualizar_reporte(self):
        if self.reporte_actual:
            self.mostrar_reporte(self.reporte_actual)
        else:
            messagebox.showwarning("Advertencia", "No hay reporte generado para actualizar")
    
    def guardar_json(self):
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
                import json
                with open(archivo, 'w', encoding='utf-8') as f:
                    json.dump(self.reporte_actual, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Éxito", f"Reporte guardado correctamente en {archivo}")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar JSON: {str(e)}")
    
    def guardar_texto(self):
        try:
            contenido = self.reporte_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay contenido para guardar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Guardar Reporte TXT",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(contenido)
                messagebox.showinfo("Éxito", f"Reporte guardado correctamente en {archivo}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar texto: {str(e)}")
    
    def cargar_reporte(self):
        """Cargar reporte con validación de seguridad."""
        from aresitos.utils.sanitizador_archivos import SanitizadorArchivos
        
        try:
            # Obtener filtros seguros para el diálogo
            sanitizador = SanitizadorArchivos()
            filetypes = sanitizador.generar_filtros_dialogo('reportes')
            
            archivo = filedialog.askopenfilename(
                title="Cargar Reporte",
                filetypes=filetypes
            )
            
            if archivo:
                # VALIDACIÓN DE SEGURIDAD
                resultado_validacion = sanitizador.validar_archivo(archivo, 'reportes')
                
                if not resultado_validacion['valido']:
                    error_msg = f"Archivo rechazado por seguridad:\n{resultado_validacion['mensaje']}"
                    messagebox.showerror("Archivo No Válido", error_msg)
                    return
                
                # Mostrar advertencias si las hay
                if resultado_validacion['advertencias']:
                    advertencias = resultado_validacion['advertencias']
                    if isinstance(advertencias, list):
                        advertencia_msg = f"Advertencias:\n{'; '.join(advertencias)}"
                    else:
                        advertencia_msg = f"Advertencias:\n{advertencias}"
                    
                    # Preguntar si continuar con advertencias
                    continuar = messagebox.askyesno(
                        "Advertencias de Seguridad", 
                        f"{advertencia_msg}\n\n¿Desea continuar cargando el archivo?"
                    )
                    if not continuar:
                        return
                
                # Cargar archivo validado
                if archivo.endswith('.json'):
                    with open(archivo, 'r', encoding='utf-8') as f:
                        self.reporte_actual = json.load(f)
                    self.mostrar_reporte(self.reporte_actual)
                else:
                    with open(archivo, 'r', encoding='utf-8') as f:
                        contenido = f.read()
                    self.reporte_text.delete(1.0, tk.END)
                    self.reporte_text.insert(tk.END, contenido)
                
                messagebox.showinfo("Éxito", f"Reporte cargado y validado desde {os.path.basename(archivo)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar reporte: {str(e)}")
    
    def listar_reportes(self):
        try:
            if not self.controlador:
                messagebox.showerror("Error", "Controlador no configurado")
                return
            
            reportes = self.controlador.listar_reportes_guardados()
            
            self.reporte_text.delete(1.0, tk.END)
            self.reporte_text.insert(tk.END, " REPORTES GUARDADOS\n")
            self.reporte_text.insert(tk.END, "=" * 50 + "\n\n")
            
            if reportes:
                for i, reporte in enumerate(reportes, 1):
                    self.reporte_text.insert(tk.END, f"{i}. {reporte}\n")
            else:
                self.reporte_text.insert(tk.END, "No se encontraron reportes guardados.\n")
                
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
        """Análisis avanzado de logs usando herramientas nativas de Kali."""
        def realizar_analisis():
            try:
                import subprocess
                import datetime
                
                self.reporte_text.delete(1.0, tk.END)
                self.reporte_text.insert(tk.END, "=== ANÁLISIS DE LOGS CON HERRAMIENTAS KALI ===\n\n")
                self.reporte_text.update()
                
                # Análisis de logs del sistema
                analisis = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "logs_sistema": {},
                    "estadisticas": {},
                    "alertas": []
                }
                
                # Últimos errores críticos
                try:
                    result = subprocess.run(['grep', '-i', 'error', '/var/log/syslog'], 
                                          capture_output=True, text=True, timeout=10)
                    analisis["logs_sistema"]["errores_syslog"] = result.stdout.split('\n')[-10:]
                except:
                    analisis["logs_sistema"]["errores_syslog"] = ["Error accediendo a syslog"]
                
                # Análisis de autenticación
                try:
                    result = subprocess.run(['grep', 'Failed', '/var/log/auth.log'], 
                                          capture_output=True, text=True, timeout=10)
                    analisis["logs_sistema"]["fallos_auth"] = len(result.stdout.split('\n'))
                except:
                    analisis["logs_sistema"]["fallos_auth"] = 0
                
                # Estadísticas de memoria y CPU
                try:
                    result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=5)
                    lines = result.stdout.split('\n')[:5]
                    analisis["estadisticas"]["top_info"] = lines
                except:
                    analisis["estadisticas"]["top_info"] = ["Error ejecutando top"]
                
                # Mostrar resultados
                import json
                texto_analisis = json.dumps(analisis, indent=2, ensure_ascii=False)
                self.reporte_text.insert(tk.END, texto_analisis)
                
                self._log_terminal("Análisis de logs completado", "REPORTES", "INFO")
                
            except Exception as e:
                self.reporte_text.insert(tk.END, f"Error en análisis: {str(e)}")
        
        thread = threading.Thread(target=realizar_analisis)
        thread.daemon = True
        thread.start()
    
    def generar_estadisticas_kali(self):
        """Generar estadísticas del sistema usando comandos nativos de Kali."""
        def generar():
            try:
                import subprocess
                import datetime
                
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
                try:
                    result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=5)
                    estadisticas["sistema"]["kernel"] = result.stdout.strip()
                except:
                    estadisticas["sistema"]["kernel"] = "Error obteniendo info del kernel"
                
                # Uso de memoria
                try:
                    result = subprocess.run(['free', '-h'], capture_output=True, text=True, timeout=5)
                    estadisticas["sistema"]["memoria"] = result.stdout.split('\n')[:3]
                except:
                    estadisticas["sistema"]["memoria"] = ["Error obteniendo memoria"]
                
                # Procesos activos
                try:
                    result = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True, timeout=8)  # Issue 21/24: Optimizado de 5 a 8 segundos
                    estadisticas["procesos"]["top_cpu"] = result.stdout.split('\n')[:10]
                except:
                    estadisticas["procesos"]["top_cpu"] = ["Error obteniendo procesos"]
                
                # Conexiones de red
                try:
                    result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=5)
                    estadisticas["red"]["conexiones"] = len(result.stdout.split('\n'))
                except:
                    estadisticas["red"]["conexiones"] = 0
                
                # Uso del disco
                try:
                    result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=5)
                    estadisticas["disco"]["particiones"] = result.stdout.split('\n')[1:6]
                except:
                    estadisticas["disco"]["particiones"] = ["Error obteniendo info del disco"]
                
                # Mostrar estadísticas
                import json
                texto_stats = json.dumps(estadisticas, indent=2, ensure_ascii=False)
                self.reporte_text.insert(tk.END, texto_stats)
                
                self._log_terminal("Estadísticas generadas", "REPORTES", "INFO")
                
            except Exception as e:
                self.reporte_text.insert(tk.END, f"Error generando estadísticas: {str(e)}")
        
        thread = threading.Thread(target=generar)
        thread.daemon = True
        thread.start()
    
    def generar_informe_seguridad(self):
        """Generar informe de seguridad usando herramientas de Kali."""
        def generar_informe():
            try:
                import subprocess
                import datetime
                
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
                try:
                    result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                          capture_output=True, text=True, timeout=10)
                    servicios_activos = len([line for line in result.stdout.split('\n') if '.service' in line])
                    informe["servicios"]["activos"] = servicios_activos
                except:
                    informe["servicios"]["activos"] = 0
                
                # Usuarios conectados
                try:
                    result = subprocess.run(['who'], capture_output=True, text=True, timeout=5)
                    informe["usuarios"]["conectados"] = len(result.stdout.split('\n')) - 1
                except:
                    informe["usuarios"]["conectados"] = 0
                
                # Archivos SUID
                try:
                    result = subprocess.run(['find', '/usr', '-perm', '-4000', '-type', 'f', '2>/dev/null'], 
                                          capture_output=True, text=True, timeout=15)
                    informe["archivos"]["suid_binaries"] = len(result.stdout.split('\n')) - 1
                except:
                    informe["archivos"]["suid_binaries"] = 0
                
                # Conexiones sospechosas
                try:
                    result = subprocess.run(['ss', '-tuln', '|', 'grep', 'LISTEN'], 
                                          capture_output=True, text=True, timeout=5, shell=True)
                    informe["red"]["puertos_escucha"] = len(result.stdout.split('\n')) - 1
                except:
                    informe["red"]["puertos_escucha"] = 0
                
                # Verificar logs de seguridad
                try:
                    result = subprocess.run(['grep', '-c', 'authentication failure', '/var/log/auth.log'], 
                                          capture_output=True, text=True, timeout=5)
                    informe["usuarios"]["fallos_auth"] = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
                except:
                    informe["usuarios"]["fallos_auth"] = 0
                
                # Mostrar informe
                import json
                texto_informe = json.dumps(informe, indent=2, ensure_ascii=False)
                self.reporte_text.insert(tk.END, texto_informe)
                
                self._log_terminal("Informe de seguridad generado", "REPORTES", "INFO")
                
            except Exception as e:
                self.reporte_text.insert(tk.END, f"Error generando informe: {str(e)}")
        
        thread = threading.Thread(target=generar_informe)
        thread.daemon = True
        thread.start()
    
    def comparar_reportes_kali(self):
        """Comparar reportes usando herramientas de línea de comandos con validación de seguridad."""
        from aresitos.utils.sanitizador_archivos import SanitizadorArchivos
        
        try:
            # Obtener filtros seguros
            sanitizador = SanitizadorArchivos()
            filetypes = sanitizador.generar_filtros_dialogo('reportes')
            
            archivo1 = filedialog.askopenfilename(
                title="Seleccionar primer reporte",
                filetypes=filetypes
            )
            
            if not archivo1:
                return
            
            # VALIDAR PRIMER ARCHIVO
            resultado1 = sanitizador.validar_archivo(archivo1, 'reportes')
            if not resultado1['valido']:
                error_msg = f"Primer archivo rechazado:\n{resultado1['mensaje']}"
                messagebox.showerror("Archivo No Válido", error_msg)
                return
            
            archivo2 = filedialog.askopenfilename(
                title="Seleccionar segundo reporte",
                filetypes=filetypes
            )
            
            if not archivo2:
                return
            
            # VALIDAR SEGUNDO ARCHIVO
            resultado2 = sanitizador.validar_archivo(archivo2, 'reportes')
            if not resultado2['valido']:
                error_msg = f"Segundo archivo rechazado:\n{resultado2['mensaje']}"
                messagebox.showerror("Archivo No Válido", error_msg)
                return
            
            def realizar_comparacion():
                try:
                    import subprocess
                    
                    self.reporte_text.delete(1.0, tk.END)
                    self.reporte_text.insert(tk.END, "=== COMPARACIÓN DE REPORTES ===\n\n")
                    self.reporte_text.update()
                    
                    # Usar diff para comparar archivos
                    try:
                        result = subprocess.run(['diff', '-u', archivo1, archivo2], 
                                              capture_output=True, text=True, timeout=10)
                        if result.stdout:
                            self.reporte_text.insert(tk.END, "DIFERENCIAS ENCONTRADAS:\n")
                            self.reporte_text.insert(tk.END, "=" * 30 + "\n\n")
                            self.reporte_text.insert(tk.END, result.stdout)
                        else:
                            self.reporte_text.insert(tk.END, "Los archivos son idénticos.\n")
                    except:
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
                self.terminal_output.insert(tk.END, "💡 Use 'ayuda-comandos' para ver comandos disponibles\n")
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
            self.terminal_output.insert(tk.END, "⚠️  EJECUTANDO SIN VALIDACIÓN DE SEGURIDAD\n")
            self.terminal_output.see(tk.END)
            self.comando_entry.delete(0, tk.END)
            
            thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            self.terminal_output.insert(tk.END, f"\n> {comando}\n")
            self.terminal_output.insert(tk.END, f"❌ Error de seguridad: {e}\n")
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
                self.limpiar_terminal_reportes()
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
    
    def _obtener_datos_dashboard(self):
        """Obtener datos del módulo Dashboard."""
        try:
            # Acceder a la vista principal para obtener datos del dashboard
            if hasattr(self.vista_principal, 'notebook') and hasattr(self.vista_principal.notebook, 'tab'):
                # Buscar la pestaña del dashboard
                for i, (nombre, vista) in enumerate(self.vista_principal.vistas.items()):
                    if 'dashboard' in nombre.lower():
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            return vista.obtener_datos_para_reporte()
            
            # Datos básicos por defecto
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
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Escaneador',
                'estado': 'captura_completa',
                'terminal_content': '',
                'estadisticas': {},
                'configuracion': {}
            }
            
            # Buscar la vista de escaneo y capturar su terminal
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'escaneo' in nombre.lower():
                        # Capturar contenido del terminal de escaneador
                        if hasattr(vista, 'text_terminal'):
                            try:
                                contenido_terminal = vista.text_terminal.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal de escaneador'
                        
                        # Capturar datos específicos si tiene método
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        
                        # Capturar estadísticas de escaneador
                        if hasattr(vista, 'estadisticas_escaneador'):
                            datos['estadisticas'] = vista.estadisticas_escaneador
                        
                        break
            
            # Si no se encontró terminal, marcar como limitado
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal de escaneador no accesible'
            
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
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Monitoreo',
                'estado': 'captura_completa',
                'terminal_content': '',
                'monitor_estado': {},
                'alertas': []
            }
            
            # Buscar la vista de monitoreo y capturar su terminal
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'monitoreo' in nombre.lower():
                        # Capturar contenido del terminal de monitoreo
                        if hasattr(vista, 'text_monitor'):
                            try:
                                contenido_terminal = vista.text_monitor.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                
                                # Analizar contenido para extraer alertas
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if any(palabra in linea.upper() for palabra in ['ERROR', 'WARNING', 'CRITICO', 'ALERTA']):
                                        datos['alertas'].append(linea.strip())
                                        
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal de monitoreo'
                        
                        # Capturar estado del monitor
                        if hasattr(vista, 'monitor_activo'):
                            datos['monitor_estado']['activo'] = vista.monitor_activo
                        if hasattr(vista, 'monitor_red_activo'):
                            datos['monitor_estado']['red_activo'] = vista.monitor_red_activo
                        
                        # Capturar datos específicos si tiene método
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        
                        break
            
            # Si no se encontró terminal, marcar como limitado
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal de monitoreo no accesible'
            
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
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'FIM',
                'estado': 'captura_completa',
                'terminal_content': '',
                'monitor_fim_activo': False,
                'archivos_monitoreados': [],
                'alertas_integridad': []
            }
            
            # Buscar la vista FIM y capturar su terminal
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'fim' in nombre.lower():
                        # Capturar contenido del terminal FIM
                        if hasattr(vista, 'text_fim'):
                            try:
                                contenido_terminal = vista.text_fim.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                
                                # Analizar contenido para extraer información de integridad
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if 'PROBLEMA:' in linea or 'WARNING:' in linea or 'ERROR' in linea:
                                        datos['alertas_integridad'].append(linea.strip())
                                    elif 'Verificando:' in linea or 'ARCHIVO:' in linea:
                                        datos['archivos_monitoreados'].append(linea.strip())
                                        
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal FIM'
                        
                        # Capturar estado del monitoreo FIM
                        if hasattr(vista, 'proceso_monitoreo_activo'):
                            datos['monitor_fim_activo'] = vista.proceso_monitoreo_activo
                        
                        # Capturar datos específicos si tiene método
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        
                        break
            
            # Estadísticas del análisis
            datos['estadisticas'] = {
                'archivos_monitoreados': len(datos['archivos_monitoreados']),
                'alertas_detectadas': len(datos['alertas_integridad']),
                'monitor_activo': datos['monitor_fim_activo']
            }
            
            # Si no se encontró terminal, marcar como limitado
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal FIM no accesible'
            
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
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'SIEM',
                'estado': 'captura_completa',
                'terminal_content': '',
                'siem_activo': False,
                'eventos_seguridad': [],
                'alertas_criticas': []
            }
            
            # Buscar la vista SIEM y capturar su terminal
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'siem' in nombre.lower():
                        # Capturar contenido del terminal SIEM
                        if hasattr(vista, 'text_siem'):
                            try:
                                contenido_terminal = vista.text_siem.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                
                                # Analizar contenido para extraer eventos de seguridad
                                lineas = contenido_terminal.split('\n')
                                for linea in lineas:
                                    if any(palabra in linea.upper() for palabra in ['CRITICO', 'ALERTA', 'VULNERABILIDAD', 'BACKDOOR', 'MALWARE']):
                                        datos['alertas_criticas'].append(linea.strip())
                                    elif any(palabra in linea.upper() for palabra in ['DETECTADO', 'MONITOREO', 'PUERTOS', 'CONEXIONES']):
                                        datos['eventos_seguridad'].append(linea.strip())
                                        
                            except Exception:
                                datos['terminal_content'] = 'No se pudo capturar terminal SIEM'
                        
                        # Capturar estado del SIEM
                        if hasattr(vista, 'siem_activo'):
                            datos['siem_activo'] = vista.siem_activo
                        elif hasattr(vista, 'proceso_siem_activo'):
                            datos['siem_activo'] = vista.proceso_siem_activo
                        
                        # Capturar datos específicos si tiene método
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        
                        break
            
            # Estadísticas del análisis SIEM
            datos['estadisticas'] = {
                'eventos_detectados': len(datos['eventos_seguridad']),
                'alertas_criticas': len(datos['alertas_criticas']),
                'siem_activo': datos['siem_activo']
            }
            
            # Si no se encontró terminal, marcar como limitado
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal SIEM no accesible'
            
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
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Cuarentena',
                'estado': 'captura_completa',
                'terminal_content': '',
                'archivos_cuarentena': [],
                'alertas_cuarentena': [],
                'procesos_monitoreados': []
            }
            
            # Buscar la vista de cuarentena y capturar su terminal
            if hasattr(self.vista_principal, 'vistas'):
                for nombre, vista in self.vista_principal.vistas.items():
                    if 'cuarentena' in nombre.lower():
                        # Capturar contenido del terminal de cuarentena
                        if hasattr(vista, 'text_terminal'):
                            try:
                                contenido_terminal = vista.text_terminal.get(1.0, tk.END)
                                datos['terminal_content'] = contenido_terminal.strip()
                                datos['terminal_lines'] = len(contenido_terminal.split('\n'))
                                
                                # Analizar contenido para extraer datos de cuarentena
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
                        
                        # Capturar estado específico de cuarentena
                        if hasattr(vista, 'cuarentena_activa'):
                            datos['cuarentena_activa'] = vista.cuarentena_activa
                        
                        # Capturar datos específicos si tiene método
                        if hasattr(vista, 'obtener_datos_para_reporte'):
                            datos_especificos = vista.obtener_datos_para_reporte()
                            if isinstance(datos_especificos, dict):
                                datos.update(datos_especificos)
                        
                        break
            
            # Estadísticas del análisis de cuarentena
            datos['estadisticas'] = {
                'archivos_en_cuarentena': len(datos['archivos_cuarentena']),
                'alertas_activas': len(datos['alertas_cuarentena']),
                'procesos_monitoreados': len(datos['procesos_monitoreados'])
            }
            
            # Si no se encontró terminal, marcar como limitado
            if not datos['terminal_content']:
                datos['estado'] = 'datos_limitados'
                datos['info'] = 'Terminal de cuarentena no accesible'
            
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
        """Abrir carpeta de logs Reportes."""
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
                self.log_to_terminal("Carpeta de logs Reportes abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs Reportes: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal usando función estándar."""
        self._log_terminal(mensaje, "REPORTES", "INFO")
    
    def sincronizar_terminal(self):
        """Función de compatibilidad - ya no necesaria con terminal estándar."""
        pass

    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            from aresitos.utils.seguridad_comandos import validador_comandos
            
            comandos = validador_comandos.obtener_comandos_disponibles()
            
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "🛡️  COMANDOS DISPONIBLES EN ARESITOS v2.0 - REPORTES\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            
            for categoria, lista_comandos in comandos.items():
                self.terminal_output.insert(tk.END, f"📂 {categoria.upper()}:\n")
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
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS - REPORTES\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            
            estado_seguridad = "✅ SEGURO" if info['es_usuario_kali'] else "❌ INSEGURO"
            
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
