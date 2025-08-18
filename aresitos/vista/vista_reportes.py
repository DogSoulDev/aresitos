# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json

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
        self.reporte_actual = None
        
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
        # Frame título con tema
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Título con tema Burp Suite
        titulo = tk.Label(titulo_frame, text="📄 Generación y Gestión de Reportes",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack()
        
        # Frame principal con tema
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Panel izquierdo con tema
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        left_label = tk.Label(left_frame, text="📝 Contenido del Reporte",
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
        
        right_label = tk.Label(right_frame, text="⚙️ Opciones de Reporte",
                              font=('Arial', 12, 'bold'),
                              bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        right_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Frame de configuración con tema
        config_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        config_label = tk.Label(config_frame, text="🔧 Incluir en el Reporte:",
                               font=('Arial', 10, 'bold'),
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'])
        config_label.pack(anchor=tk.W)
        
        self.incluir_escaneo = tk.BooleanVar(value=True)
        self.incluir_monitoreo = tk.BooleanVar(value=True)
        self.incluir_utilidades = tk.BooleanVar(value=True)
        self.incluir_fim = tk.BooleanVar(value=True)
        self.incluir_siem = tk.BooleanVar(value=True)
        self.incluir_cuarentena = tk.BooleanVar(value=True)
        
        opciones = [
            ("🔍 Resultados de Escaneo", self.incluir_escaneo),
            ("📊 Datos de Monitoreo", self.incluir_monitoreo),
            ("🔒 Datos de FIM (File Integrity)", self.incluir_fim),
            ("🛡️ Datos de SIEM", self.incluir_siem),
            ("🔐 Datos de Cuarentena", self.incluir_cuarentena),
            ("🛠️ Información de Utilidades", self.incluir_utilidades)
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
            ("📋 Generar Reporte Completo", self.generar_reporte_completo),
            ("🔄 Actualizar Vista", self.actualizar_reporte)
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
            ("💾 Guardar JSON", self.guardar_json),
            ("📄 Guardar TXT", self.guardar_texto),
            ("📂 Cargar Reporte", self.cargar_reporte),
            ("📝 Listar Reportes", self.listar_reportes),
            ("🗑️ Limpiar Vista", self.limpiar_reporte)
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
        
        info_title = tk.Label(info_frame, text="ℹ️ Información",
                             font=('Arial', 10, 'bold'),
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'])
        info_title.pack(anchor=tk.W)
        
        info_text = "Genera reportes completos del sistema con datos de escaneo, monitoreo, FIM, SIEM, cuarentena y utilidades optimizadas para Kali Linux."
        info_label = tk.Label(info_frame, text=info_text, 
                             wraplength=180, justify=tk.LEFT,
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                             font=('Arial', 9))
        info_label.pack(anchor=tk.W, pady=(5, 0))
    
    def generar_reporte_completo(self):
        def generar():
            try:
                if not self.controlador:
                    messagebox.showerror("Error", "Controlador no configurado")
                    return
                
                self.reporte_text.delete(1.0, tk.END)
                self.reporte_text.insert(tk.END, " Generando reporte completo...\n\n")
                self.reporte_text.update()
                
                incluir_escaneo = {} if self.incluir_escaneo.get() else None
                incluir_monitoreo = {} if self.incluir_monitoreo.get() else None
                incluir_fim = {} if self.incluir_fim.get() else None
                incluir_siem = {} if self.incluir_siem.get() else None
                incluir_cuarentena = {} if self.incluir_cuarentena.get() else None
                
                self.reporte_actual = self.controlador.generar_reporte_completo(
                    incluir_escaneo, incluir_monitoreo, incluir_fim, incluir_siem, incluir_cuarentena
                )
                
                if self.reporte_actual:
                    self.mostrar_reporte(self.reporte_actual)
                else:
                    self.reporte_text.insert(tk.END, " Error al generar el reporte")
                    
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

# RESUMEN: Vista para generación y gestión de reportes del sistema. Permite generar 
# reportes completos con datos de escaneo, monitoreo y utilidades, guardar en 
# formato JSON y TXT, cargar reportes existentes y gestionar archivos de reportes.
