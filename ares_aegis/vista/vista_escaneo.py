# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext

class VistaEscaneo(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.crear_widgets()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_escanear = ttk.Button(btn_frame, text="Escanear Sistema", 
                                      command=self.ejecutar_escaneo)
        self.btn_escanear.pack(side="left", padx=(0, 5))
        
        self.btn_logs = ttk.Button(btn_frame, text="Ver Logs", 
                                  command=self.ver_logs)
        self.btn_logs.pack(side="left", padx=(0, 5))
        
        self.btn_eventos = ttk.Button(btn_frame, text="Eventos SIEM", 
                                     command=self.ver_eventos)
        self.btn_eventos.pack(side="left")
        
        self.text_resultados = scrolledtext.ScrolledText(main_frame, height=28)
        self.text_resultados.pack(fill="both", expand=True)
    
    def ejecutar_escaneo(self):
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Iniciando escaneo...\n\n")
        
        resultados = self.controlador.ejecutar_escaneo_basico()
        
        self.text_resultados.insert(tk.END, "=== PUERTOS ===\n")
        for linea in resultados.get('puertos', []):
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        self.text_resultados.insert(tk.END, "\n=== PROCESOS ===\n")
        for linea in resultados.get('procesos', [])[:10]:  # Mostrar solo 10
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        self.text_resultados.insert(tk.END, "\n=== ANÁLISIS ===\n")
        for linea in resultados.get('analisis', []):
            self.text_resultados.insert(tk.END, f"{linea}\n")
    
    def ver_logs(self):
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Obteniendo logs...\n\n")
        
        logs = self.controlador.obtener_logs()
        for linea in logs:
            self.text_resultados.insert(tk.END, f"{linea}\n")
    
    def ver_eventos(self):
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Eventos SIEM:\n\n")
        
        eventos = self.controlador.obtener_eventos_siem()
        for evento in eventos:
            timestamp = evento.get('timestamp', '')
            if isinstance(timestamp, str):
                timestamp_str = timestamp
            else:
                timestamp_str = str(timestamp)
            self.text_resultados.insert(tk.END, 
                f"[{timestamp_str}] {evento.get('tipo', 'Desconocido')}: {evento.get('descripcion', 'Sin descripción')}\n")


# RESUMEN: Interfaz de escaneo de vulnerabilidades con opciones básicas y avanzadas.