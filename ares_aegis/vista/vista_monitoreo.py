# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import time

class VistaMonitoreo(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.monitor_activo = False
        self.crear_widgets()
        self.actualizar_estado()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.crear_pestana_monitoreo()
        
        self.crear_pestana_cuarentena()
    
    def crear_pestana_monitoreo(self):
        frame_monitor = ttk.Frame(self.notebook)
        self.notebook.add(frame_monitor, text="Monitoreo Sistema")
        
        control_frame = ttk.Frame(frame_monitor)
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_iniciar_monitor = ttk.Button(control_frame, text="Iniciar Monitoreo", 
                                            command=self.iniciar_monitoreo)
        self.btn_iniciar_monitor.pack(side="left", padx=(0, 5))
        
        self.btn_detener_monitor = ttk.Button(control_frame, text="Detener Monitoreo", 
                                            command=self.detener_monitoreo, state="disabled")
        self.btn_detener_monitor.pack(side="left", padx=(0, 5))
        
        self.btn_red = ttk.Button(control_frame, text="Monitorear Red", 
                                command=self.monitorear_red)
        self.btn_red.pack(side="left", padx=(0, 5))
        
        self.label_estado = ttk.Label(control_frame, text="Estado: Detenido")
        self.label_estado.pack(side="right")
        
        self.text_monitor = scrolledtext.ScrolledText(frame_monitor, height=28)
        self.text_monitor.pack(fill="both", expand=True)
    
    def crear_pestana_cuarentena(self):
        frame_cuarentena = ttk.Frame(self.notebook)
        self.notebook.add(frame_cuarentena, text="Cuarentena")
        
        control_frame = ttk.Frame(frame_cuarentena)
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_agregar_cuarentena = ttk.Button(control_frame, text="Agregar Archivo", 
                                               command=self.agregar_a_cuarentena)
        self.btn_agregar_cuarentena.pack(side="left", padx=(0, 5))
        
        self.btn_listar_cuarentena = ttk.Button(control_frame, text="Listar Archivos", 
                                              command=self.listar_cuarentena)
        self.btn_listar_cuarentena.pack(side="left", padx=(0, 5))
        
        self.btn_limpiar_cuarentena = ttk.Button(control_frame, text="Limpiar Todo", 
                                               command=self.limpiar_cuarentena)
        self.btn_limpiar_cuarentena.pack(side="left")
        
        self.text_cuarentena = scrolledtext.ScrolledText(frame_cuarentena, height=28)
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
            return
            
        self.text_monitor.insert(tk.END, "\n=== MONITOREO DE RED ===\n")
        resultados = self.controlador.monitorear_red()
        
        for resultado in resultados:
            self.text_monitor.insert(tk.END, f"{resultado}\n")
        
        self.text_monitor.see(tk.END)
    
    def agregar_a_cuarentena(self):
        archivo = filedialog.askopenfilename(title="Seleccionar archivo para cuarentena")
        if not archivo:
            return
            
        if not self.controlador:
            return
            
        resultado = self.controlador.poner_archivo_en_cuarentena(archivo)
        
        if resultado["exito"]:
            self.text_cuarentena.insert(tk.END, f"Archivo agregado a cuarentena: {archivo}\n")
            messagebox.showinfo("Success", "File quarantined")
        else:
            self.text_cuarentena.insert(tk.END, f"Error: {resultado['error']}\n")
            messagebox.showerror("Error", resultado["error"])
    
    def listar_cuarentena(self):
        if not self.controlador:
            return
            
        self.text_cuarentena.delete(1.0, tk.END)
        archivos = self.controlador.listar_archivos_cuarentena()
        
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
