# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import logging
import datetime

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
                
                incluir_dashboard = {} if self.incluir_dashboard.get() else None
                incluir_escaneo = {} if self.incluir_escaneo.get() else None
                incluir_monitoreo = {} if self.incluir_monitoreo.get() else None
                incluir_fim = {} if self.incluir_fim.get() else None
                incluir_siem = {} if self.incluir_siem.get() else None
                incluir_cuarentena = {} if self.incluir_cuarentena.get() else None
                
                self.log_to_terminal("REPORTE Generando reporte con módulos seleccionados...")
                
                self.reporte_actual = self.controlador.generar_reporte_completo(
                    incluir_dashboard, incluir_escaneo, incluir_monitoreo, incluir_fim, incluir_siem, incluir_cuarentena
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
        
        thread = threading.Thread(target=generar)
        thread.daemon = True
        thread.start()
    
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
        try:
            archivo = filedialog.askopenfilename(
                title="Cargar Reporte",
                filetypes=[("Archivo JSON", "*.json"), ("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                if archivo.endswith('.json'):
                    with open(archivo, 'r', encoding='utf-8') as f:
                        self.reporte_actual = json.load(f)
                    self.mostrar_reporte(self.reporte_actual)
                else:
                    with open(archivo, 'r', encoding='utf-8') as f:
                        contenido = f.read()
                    self.reporte_text.delete(1.0, tk.END)
                    self.reporte_text.insert(tk.END, contenido)
                
                messagebox.showinfo("Éxito", f"Reporte cargado desde {archivo}")
                
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
                    result = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True, timeout=5)
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
        """Comparar reportes usando herramientas de línea de comandos."""
        try:
            archivo1 = filedialog.askopenfilename(
                title="Seleccionar primer reporte",
                filetypes=[("Archivo JSON", "*.json"), ("Archivo de texto", "*.txt")]
            )
            
            if not archivo1:
                return
            
            archivo2 = filedialog.askopenfilename(
                title="Seleccionar segundo reporte",
                filetypes=[("Archivo JSON", "*.json"), ("Archivo de texto", "*.txt")]
            )
            
            if not archivo2:
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
        """Función de compatibilidad - ya no necesaria con terminal estándar."""
        pass
