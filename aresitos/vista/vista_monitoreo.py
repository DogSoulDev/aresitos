# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import time

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaMonitoreo(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.monitor_activo = False
        self.monitor_red_activo = False
        self.thread_red = None
        
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
        self.actualizar_estado()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        # Frame principal con tema Burp Suite
        self.notebook = tk.Frame(self, bg=self.colors['bg_primary'])
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Crear pestañas como frames separados con navegación por botones
        self.crear_navegacion_pestanas()
        self.crear_pestana_monitoreo()
        self.crear_pestana_cuarentena()
        
        # Mostrar pestaña por defecto
        self.mostrar_pestana('monitoreo')
    
    def crear_navegacion_pestanas(self):
        """Crear navegación por pestañas con tema Burp Suite."""
        nav_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        nav_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_monitoreo = tk.Button(nav_frame, text=" Monitoreo Sistema",
                                     command=lambda: self.mostrar_pestana('monitoreo'),
                                     bg='#ff6633', fg='white',
                                     font=('Arial', 10, 'bold'),
                                     relief='flat', bd=0, padx=15, pady=8,
                                     activebackground='#e55a2b', activeforeground='white')
        self.btn_monitoreo.pack(side="left", padx=(0, 5))
        
        self.btn_cuarentena = tk.Button(nav_frame, text=" Cuarentena",
                                      command=lambda: self.mostrar_pestana('cuarentena'),
                                      bg='#404040', fg='white',
                                      font=('Arial', 10),
                                      relief='flat', bd=0, padx=15, pady=8,
                                      activebackground='#505050', activeforeground='white')
        self.btn_cuarentena.pack(side="left")
    
    def mostrar_pestana(self, pestana):
        """Mostrar la pestaña seleccionada."""
        # Actualizar colores de botones
        if pestana == 'monitoreo':
            self.btn_monitoreo.configure(bg='#ff6633')
            self.btn_cuarentena.configure(bg='#404040')
            
            if hasattr(self, 'frame_cuarentena'):
                self.frame_cuarentena.pack_forget()
            if hasattr(self, 'frame_monitor'):
                self.frame_monitor.pack(fill="both", expand=True)
        else:
            self.btn_monitoreo.configure(bg='#404040')
            self.btn_cuarentena.configure(bg='#ff6633')
            
            if hasattr(self, 'frame_monitor'):
                self.frame_monitor.pack_forget()
            if hasattr(self, 'frame_cuarentena'):
                self.frame_cuarentena.pack(fill="both", expand=True)
    
    def crear_pestana_monitoreo(self):
        self.frame_monitor = tk.Frame(self.notebook, bg='#2b2b2b')
        
        # Título
        titulo_frame = tk.Frame(self.frame_monitor, bg='#2b2b2b')
        titulo_frame.pack(fill="x", pady=(0, 15))
        
        titulo_label = tk.Label(titulo_frame, text=" MONITOR DEL SISTEMA", 
                              font=('Arial', 14, 'bold'),
                              bg='#2b2b2b', fg='#ff6633')
        titulo_label.pack()
        
        # Frame de controles con tema
        control_frame = tk.Frame(self.frame_monitor, bg='#2b2b2b')
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_iniciar_monitor = tk.Button(control_frame, text=" Iniciar Monitoreo", 
                                           command=self.iniciar_monitoreo,
                                           bg='#ff6633', fg='white',
                                           font=('Arial', 10, 'bold'),
                                           relief='flat', bd=0, padx=15, pady=8,
                                           activebackground='#e55a2b', activeforeground='white')
        self.btn_iniciar_monitor.pack(side="left", padx=(0, 10))
        
        self.btn_detener_monitor = tk.Button(control_frame, text=" Detener Monitoreo", 
                                            command=self.detener_monitoreo, state="disabled",
                                            bg='#404040', fg='white',
                                            font=('Arial', 10),
                                            relief='flat', bd=0, padx=15, pady=8,
                                            activebackground='#505050', activeforeground='white')
        self.btn_detener_monitor.pack(side="left", padx=(0, 10))
        
        self.btn_red = tk.Button(control_frame, text=" Monitorear Red", 
                               command=self.monitorear_red,
                               bg='#404040', fg='white',
                               font=('Arial', 10),
                               relief='flat', bd=0, padx=15, pady=8,
                               activebackground='#505050', activeforeground='white')
        self.btn_red.pack(side="left", padx=(0, 10))
        
        self.btn_cancelar_red = tk.Button(control_frame, text=" Cancelar Red", 
                                        command=self.cancelar_monitoreo_red,
                                        state="disabled",
                                        bg='#404040', fg='white',
                                        font=('Arial', 10),
                                        relief='flat', bd=0, padx=15, pady=8,
                                        activebackground='#505050', activeforeground='white')
        self.btn_cancelar_red.pack(side="left", padx=(0, 10))
        
        self.label_estado = tk.Label(control_frame, text="Estado: Detenido",
                                   bg='#2b2b2b', fg='#ffffff',
                                   font=('Arial', 10))
        self.label_estado.pack(side="right", padx=(10, 0))
        
        # Área de texto con tema
        self.text_monitor = scrolledtext.ScrolledText(self.frame_monitor, height=25,
                                                    bg='#1e1e1e', fg='#ffffff',
                                                    font=('Consolas', 10),
                                                    insertbackground='#ff6633',
                                                    selectbackground='#404040')
        self.text_monitor.pack(fill="both", expand=True)
    
    def crear_pestana_cuarentena(self):
        self.frame_cuarentena = tk.Frame(self.notebook, bg='#2b2b2b')
        
        # Título
        titulo_frame = tk.Frame(self.frame_cuarentena, bg='#2b2b2b')
        titulo_frame.pack(fill="x", pady=(0, 15))
        
        titulo_label = tk.Label(titulo_frame, text=" GESTIÓN DE CUARENTENA", 
                              font=('Arial', 14, 'bold'),
                              bg='#2b2b2b', fg='#ff6633')
        titulo_label.pack()
        
        # Frame de controles con tema
        control_frame = tk.Frame(self.frame_cuarentena, bg='#2b2b2b')
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_agregar_cuarentena = tk.Button(control_frame, text=" Agregar Archivo", 
                                              command=self.agregar_a_cuarentena,
                                              bg='#ff6633', fg='white',
                                              font=('Arial', 10, 'bold'),
                                              relief='flat', bd=0, padx=15, pady=8,
                                              activebackground='#e55a2b', activeforeground='white')
        self.btn_agregar_cuarentena.pack(side="left", padx=(0, 10))
        
        self.btn_listar_cuarentena = tk.Button(control_frame, text=" Listar Archivos", 
                                             command=self.listar_cuarentena,
                                             bg='#404040', fg='white',
                                             font=('Arial', 10),
                                             relief='flat', bd=0, padx=15, pady=8,
                                             activebackground='#505050', activeforeground='white')
        self.btn_listar_cuarentena.pack(side="left", padx=(0, 10))
        
        self.btn_limpiar_cuarentena = tk.Button(control_frame, text=" Limpiar Todo", 
                                              command=self.limpiar_cuarentena,
                                              bg='#404040', fg='white',
                                              font=('Arial', 10),
                                              relief='flat', bd=0, padx=15, pady=8,
                                              activebackground='#505050', activeforeground='white')
        self.btn_limpiar_cuarentena.pack(side="left")
        
        # Área de texto con tema
        self.text_cuarentena = scrolledtext.ScrolledText(self.frame_cuarentena, height=25,
                                                       bg='#1e1e1e', fg='#ffffff',
                                                       font=('Consolas', 10),
                                                       insertbackground='#ff6633',
                                                       selectbackground='#404040')
        self.text_cuarentena.pack(fill="both", expand=True)
    
    def iniciar_monitoreo(self):
        if not self.controlador:
            return
            
        if self.controlador.iniciar_monitoreo():
            self.monitor_activo = True
            self.btn_iniciar_monitor.config(state="disabled")
            self.btn_detener_monitor.config(state="normal")
            self.label_estado.config(text="Estado: Activo")
            self.text_monitor.insert(tk.END, "Monitoreo iniciado...\n")
            self.after(2000, self.actualizar_monitoreo)  # Actualizar cada 2 segundos
        else:
            messagebox.showerror("Error", "Monitor init failed")
    
    def detener_monitoreo(self):
        if not self.controlador:
            return
            
        self.controlador.detener_monitoreo()
        self.monitor_activo = False
        self.btn_iniciar_monitor.config(state="normal")
        self.btn_detener_monitor.config(state="disabled")
        self.label_estado.config(text="Estado: Detenido")
        self.text_monitor.insert(tk.END, "Monitoreo detenido.\n")
    
    def actualizar_monitoreo(self):
        if not self.monitor_activo or not self.controlador:
            return
            
        estado = self.controlador.obtener_estado_monitoreo()
        
        if estado["datos_recientes"]:
            ultimo_dato = estado["datos_recientes"][-1]
            timestamp_raw = ultimo_dato.get("timestamp", time.time())
            
            if isinstance(timestamp_raw, str):
                timestamp = timestamp_raw
            elif isinstance(timestamp_raw, (int, float)):
                timestamp = time.strftime("%H:%M:%S", time.localtime(timestamp_raw))
            else:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
            
            info = f"[{timestamp}] "
            if "memoria_porcentaje" in ultimo_dato:
                info += f"Memoria: {ultimo_dato['memoria_porcentaje']:.1f}% | "
            if "procesos_activos" in ultimo_dato:
                info += f"Procesos: {ultimo_dato['procesos_activos']} | "
            if "error" in ultimo_dato:
                info += f"Error: {ultimo_dato['error']}"
            
            self.text_monitor.insert(tk.END, info + "\n")
            self.text_monitor.see(tk.END)
        
        if self.monitor_activo:
            self.after(2000, self.actualizar_monitoreo)
    
    def monitorear_red(self):
        if not self.controlador:
            messagebox.showwarning("Advertencia", 
                                 "El controlador de monitoreo no está configurado.\n"
                                 "Por favor, reinicie la aplicación.")
            return
        
        if self.monitor_red_activo:
            messagebox.showwarning("Advertencia", "Ya hay un monitoreo de red en curso.")
            return
            
        self.monitor_red_activo = True
        self.btn_red.config(state="disabled")
        self.btn_cancelar_red.config(state="normal")
        
        self.text_monitor.insert(tk.END, "\n === MONITOREO DE RED INICIADO ===\n")
        
        # Ejecutar monitoreo en thread separado
        import threading
        self.thread_red = threading.Thread(target=self._monitorear_red_async)
        self.thread_red.daemon = True
        self.thread_red.start()
    
    def _monitorear_red_async(self):
        """Monitorear red en thread separado."""
        try:
            # Verificar que el controlador esté configurado
            if not self.controlador:
                self.after(0, self._mostrar_error_red, "Controlador de monitoreo no configurado")
                return
            
            resultados = self.controlador.monitorear_red()
            
            if not self.monitor_red_activo:  # Verificar si fue cancelado
                return
            
            # Actualizar UI en el hilo principal
            self.after(0, self._mostrar_resultados_red, resultados)
            
        except Exception as e:
            if self.monitor_red_activo:
                self.after(0, self._mostrar_error_red, str(e))
        finally:
            self.after(0, self._finalizar_monitoreo_red)
    
    def _mostrar_resultados_red(self, resultados):
        """Mostrar resultados del monitoreo de red."""
        if not self.monitor_red_activo:
            return
            
        for resultado in resultados:
            self.text_monitor.insert(tk.END, f"{resultado}\n")
        
        self.text_monitor.see(tk.END)
    
    def _mostrar_error_red(self, error):
        """Mostrar error del monitoreo de red."""
        self.text_monitor.insert(tk.END, f"\n Error en monitoreo de red: {error}\n")
    
    def _finalizar_monitoreo_red(self):
        """Finalizar monitoreo de red."""
        self.monitor_red_activo = False
        self.btn_red.config(state="normal")
        self.btn_cancelar_red.config(state="disabled")
        self.thread_red = None
        self.text_monitor.insert(tk.END, "\n=== MONITOREO DE RED FINALIZADO ===\n")
    
    def cancelar_monitoreo_red(self):
        """Cancelar el monitoreo de red."""
        if self.monitor_red_activo:
            self.monitor_red_activo = False
            self.text_monitor.insert(tk.END, "\n Monitoreo de red cancelado por el usuario.\n")
            self._finalizar_monitoreo_red()
    
    def agregar_a_cuarentena(self):
        archivo = filedialog.askopenfilename(title="Seleccionar archivo para cuarentena")
        if not archivo:
            return
            
        # Crear controlador de cuarentena directamente si no está disponible
        try:
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            controlador_cuarentena = ControladorCuarentena()
            resultado = controlador_cuarentena.poner_archivo_en_cuarentena(archivo)
            
            if resultado["exito"]:
                self.text_cuarentena.insert(tk.END, f"✓ Archivo agregado a cuarentena: {archivo}\n")
                messagebox.showinfo("Éxito", "Archivo enviado a cuarentena correctamente")
            else:
                self.text_cuarentena.insert(tk.END, f"✗ Error: {resultado['error']}\n")
                messagebox.showerror("Error", resultado["error"])
                
        except Exception as e:
            self.text_cuarentena.insert(tk.END, f"✗ Error del sistema: {str(e)}\n")
            messagebox.showerror("Error", f"Error del sistema: {str(e)}")
    
    def listar_cuarentena(self):
        try:
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            controlador_cuarentena = ControladorCuarentena()
            
            self.text_cuarentena.delete(1.0, tk.END)
            self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
            
            archivos = controlador_cuarentena.listar_archivos_cuarentena()
            
            if not archivos:
                self.text_cuarentena.insert(tk.END, "No hay archivos en cuarentena.\n")
            else:
                for i, archivo in enumerate(archivos, 1):
                    self.text_cuarentena.insert(tk.END, f"{i}. {archivo.get('ruta_original', 'Desconocido')}\n")
                    self.text_cuarentena.insert(tk.END, f"   Fecha: {archivo.get('fecha', 'N/A')}\n")
                    self.text_cuarentena.insert(tk.END, f"   Razón: {archivo.get('razon', 'N/A')}\n\n")
                    
            # Obtener resumen adicional
            resumen = controlador_cuarentena.obtener_resumen_cuarentena()
            if resumen:
                self.text_cuarentena.insert(tk.END, f"\n=== RESUMEN ===\n")
                self.text_cuarentena.insert(tk.END, f"Total archivos: {resumen.get('total_archivos', 0)}\n")
                self.text_cuarentena.insert(tk.END, f"Tamaño total: {resumen.get('tamano_total', 0)} bytes\n")
                
        except Exception as e:
            self.text_cuarentena.insert(tk.END, f"Error listando cuarentena: {str(e)}\n")
        
        if not archivos:
            self.text_cuarentena.insert(tk.END, "No hay archivos en cuarentena.\n")
            return
        
        self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
        for archivo in archivos:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(archivo["timestamp"])))
            self.text_cuarentena.insert(tk.END, 
                f"Hash: {archivo['hash']}\n"
                f"Archivo: {archivo['archivo_original']}\n"
                f"Motivo: {archivo['motivo']}\n"
                f"Fecha: {timestamp}\n"
                f"{'='*50}\n\n"
            )
    
    def limpiar_cuarentena(self):
        if not self.controlador:
            return
            
        respuesta = messagebox.askyesno("Confirm", 
                                      "¿Eliminar permanentemente todos los archivos de cuarentena?")
        if respuesta:
            resultado = self.controlador.limpiar_cuarentena_completa()
            self.text_cuarentena.insert(tk.END, 
                f"Cuarentena limpiada. Archivos eliminados: {resultado['eliminados']}\n")
            if resultado["errores"]:
                for error in resultado["errores"]:
                    self.text_cuarentena.insert(tk.END, f"Error: {error}\n")
    
    def actualizar_estado(self):
        pass


# RESUMEN: Sistema de monitoreo de red y procesos usando herramientas nativas.
