# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
from typing import Optional, Any

class VistaUtilidades(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador: Any = None  # Será establecido por set_controlador
        self.reporte_actual = None
        self.crear_widgets()
    
    def set_controlador(self, controlador):
        """Establece el controlador para esta vista."""
        self.controlador = controlador
    
    def crear_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.crear_pestana_herramientas()
        
        self.crear_pestana_auditoria()
        
        self.crear_pestana_reportes()
        
        self.crear_pestana_wordlists()
        
        self.crear_pestana_diccionarios()
    
    def crear_pestana_herramientas(self):
        frame_herramientas = ttk.Frame(self.notebook)
        self.notebook.add(frame_herramientas, text="Herramientas")
        
        control_frame = ttk.Frame(frame_herramientas)
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_verificar_herramientas = ttk.Button(control_frame, 
                                                   text="Verificar Tools", 
                                                   command=self.verificar_herramientas)
        self.btn_verificar_herramientas.pack(side="left", padx=(0, 5))
        
        self.btn_info_hardware = ttk.Button(control_frame, 
                                           text="Info HW", 
                                           command=self.obtener_info_hardware)
        self.btn_info_hardware.pack(side="left", padx=(0, 5))
        
        self.btn_servicios = ttk.Button(control_frame, 
                                       text="Procesos", 
                                       command=self.analizar_servicios)
        self.btn_servicios.pack(side="left", padx=(0, 5))
        
        self.btn_permisos = ttk.Button(control_frame, 
                                      text="Permisos", 
                                      command=self.verificar_permisos)
        self.btn_permisos.pack(side="left", padx=(0, 5))
        
        self.btn_limpiar = ttk.Button(control_frame, 
                                     text="Cleanup", 
                                     command=self.limpiar_sistema)
        self.btn_limpiar.pack(side="left")
        
        self.text_herramientas = scrolledtext.ScrolledText(frame_herramientas, height=25)
        self.text_herramientas.pack(fill="both", expand=True)
    
    def crear_pestana_auditoria(self):
        frame_auditoria = ttk.Frame(self.notebook)
        self.notebook.add(frame_auditoria, text="Auditoría")
        
        control_frame = ttk.Frame(frame_auditoria)
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_lynis = ttk.Button(control_frame, 
                                   text="Lynis", 
                                   command=self.ejecutar_lynis)
        self.btn_lynis.pack(side="left", padx=(0, 5))
        
        self.btn_chkrootkit = ttk.Button(control_frame, 
                                        text="Rootkits", 
                                        command=self.ejecutar_chkrootkit)
        self.btn_chkrootkit.pack(side="left")
        
        self.label_estado_auditoria = ttk.Label(control_frame, text="")
        self.label_estado_auditoria.pack(side="right")
        
        self.text_auditoria = scrolledtext.ScrolledText(frame_auditoria, height=25)
        self.text_auditoria.pack(fill="both", expand=True)
    
    def crear_pestana_reportes(self):
        frame_reportes = ttk.Frame(self.notebook)
        self.notebook.add(frame_reportes, text="Reportes")
        
        control_frame = ttk.Frame(frame_reportes)
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_generar_reporte = ttk.Button(control_frame, 
                                            text="Generar", 
                                            command=self.generar_reporte)
        self.btn_generar_reporte.pack(side="left", padx=(0, 5))
        
        self.btn_guardar_json = ttk.Button(control_frame, 
                                          text="JSON", 
                                          command=self.guardar_reporte_json)
        self.btn_guardar_json.pack(side="left", padx=(0, 5))
        
        self.btn_guardar_txt = ttk.Button(control_frame, 
                                         text="TXT", 
                                         command=self.guardar_reporte_txt)
        self.btn_guardar_txt.pack(side="left", padx=(0, 5))
        
        self.btn_listar_reportes = ttk.Button(control_frame, 
                                            text="Listar", 
                                            command=self.listar_reportes)
        self.btn_listar_reportes.pack(side="left")
        
        self.text_reportes = scrolledtext.ScrolledText(frame_reportes, height=25)
        self.text_reportes.pack(fill="both", expand=True)
    
    def verificar_herramientas(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_herramientas.delete(1.0, tk.END)
        self.text_herramientas.insert(tk.END, "Verificando herramientas de Kali Linux...\n\n")
        
        def ejecutar():
            try:
                if not self.controlador:
                    self.after(0, lambda: self.text_herramientas.insert(tk.END, "Error: Controlador no inicializado\n"))
                    return
                resultado = self.controlador.verificar_herramientas_disponibles()
                self.after(0, lambda: self._mostrar_herramientas(resultado))
            except Exception as e:
                self.after(0, lambda: self.text_herramientas.insert(tk.END, f"Error: {e}\n"))
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def _mostrar_herramientas(self, resultado):
        self.text_herramientas.insert(tk.END, 
            f"Total herramientas verificadas: {resultado['total']}\n\n")
        
        self.text_herramientas.insert(tk.END, "=== DISPONIBLES ===\n")
        for herramienta in resultado['disponibles']:
            self.text_herramientas.insert(tk.END, f"✓ {herramienta}\n")
        
        self.text_herramientas.insert(tk.END, "\n=== NO DISPONIBLES ===\n")
        for herramienta in resultado['no_disponibles']:
            self.text_herramientas.insert(tk.END, f"✗ {herramienta}\n")
    
    def obtener_info_hardware(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_herramientas.delete(1.0, tk.END)
        self.text_herramientas.insert(tk.END, "Obteniendo información del hardware...\n\n")
        
        try:
            info = self.controlador.obtener_informacion_hardware()
            
            self.text_herramientas.insert(tk.END, "=== INFORMACIÓN DEL HARDWARE ===\n")
            for clave, valor in info.items():
                self.text_herramientas.insert(tk.END, f"{clave.replace('_', ' ').title()}: {valor}\n")
        except Exception as e:
            self.text_herramientas.insert(tk.END, f"Error: {e}\n")
    
    def analizar_servicios(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_herramientas.delete(1.0, tk.END)
        self.text_herramientas.insert(tk.END, "Analizando servicios activos...\n\n")
        
        try:
            resultado = self.controlador.analizar_servicios_activos()
            
            if resultado['exito']:
                self.text_herramientas.insert(tk.END, "=== SERVICIOS ACTIVOS ===\n")
                for servicio in resultado['servicios'][:20]:  # Mostrar solo 20
                    self.text_herramientas.insert(tk.END, 
                        f"{servicio['nombre']} - {servicio['active']}/{servicio['sub']}\n")
            else:
                self.text_herramientas.insert(tk.END, f"Error: {resultado['error']}\n")
        except Exception as e:
            self.text_herramientas.insert(tk.END, f"Error: {e}\n")
    
    def verificar_permisos(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_herramientas.delete(1.0, tk.END)
        self.text_herramientas.insert(tk.END, "Verificando permisos de archivos críticos...\n\n")
        
        try:
            resultados = self.controlador.verificar_permisos_criticos()
            
            self.text_herramientas.insert(tk.END, "=== PERMISOS DE ARCHIVOS CRÍTICOS ===\n")
            for resultado in resultados:
                if resultado.get('existe', False):
                    self.text_herramientas.insert(tk.END, 
                        f"{resultado['archivo']}: {resultado['permisos']} "
                        f"(UID: {resultado['uid']}, GID: {resultado['gid']})\n")
                else:
                    self.text_herramientas.insert(tk.END, 
                        f"{resultado['archivo']}: {resultado.get('error', 'No encontrado')}\n")
        except Exception as e:
            self.text_herramientas.insert(tk.END, f"Error: {e}\n")
    
    def limpiar_sistema(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        respuesta = messagebox.askyesno("Confirm", 
                                      "¿Ejecutar limpieza del sistema? (Requiere sudo)")
        if not respuesta:
            return
            
        self.text_herramientas.delete(1.0, tk.END)
        self.text_herramientas.insert(tk.END, "Ejecutando limpieza del sistema...\n\n")
        
        def ejecutar():
            try:
                if not self.controlador:
                    self.after(0, lambda: self.text_herramientas.insert(tk.END, "Error: Controlador no inicializado\n"))
                    return
                resultados = self.controlador.ejecutar_limpieza_sistema()
                self.after(0, lambda: self._mostrar_limpieza(resultados))
            except Exception as e:
                self.after(0, lambda: self.text_herramientas.insert(tk.END, f"Error: {e}\n"))
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def _mostrar_limpieza(self, resultados):
        self.text_herramientas.insert(tk.END, "=== RESULTADOS DE LIMPIEZA ===\n")
        for resultado in resultados:
            estado = "✓" if resultado['exito'] else "✗"
            self.text_herramientas.insert(tk.END, 
                f"{estado} {resultado['comando']}\n")
            if 'salida' in resultado and resultado['salida']:
                self.text_herramientas.insert(tk.END, f"   {resultado['salida'][:100]}...\n")
            if 'error' in resultado:
                self.text_herramientas.insert(tk.END, f"   Error: {resultado['error']}\n")
    
    def ejecutar_lynis(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_auditoria.delete(1.0, tk.END)
        self.text_auditoria.insert(tk.END, "Ejecutando auditoría con Lynis...\n")
        self.label_estado_auditoria.config(text="Ejecutando audit...")
        
        def ejecutar():
            try:
                if not self.controlador:
                    self.after(0, lambda: self._mostrar_lynis({'exito': False, 'error': 'Controlador no inicializado'}))
                    return
                resultado = self.controlador.ejecutar_auditoria_lynis()
                self.after(0, lambda: self._mostrar_lynis(resultado))
            except Exception as e:
                self.after(0, lambda: self._mostrar_lynis({'exito': False, 'error': str(e)}))
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def _mostrar_lynis(self, resultado):
        self.label_estado_auditoria.config(text="")
        
        if resultado['exito']:
            lineas = resultado['salida'].split('\n')
            lineas_importantes = [l for l in lineas if any(palabra in l.lower() 
                                for palabra in ['warning', 'suggestion', 'hardening', 'found'])]
            
            self.text_auditoria.insert(tk.END, "\n=== RESULTADOS LYNIS (RESUMEN) ===\n")
            for linea in lineas_importantes[:50]:  # Limitar a 50 líneas
                self.text_auditoria.insert(tk.END, f"{linea}\n")
        else:
            self.text_auditoria.insert(tk.END, f"\nError ejecutando Lynis: {resultado['error']}\n")
    
    def ejecutar_chkrootkit(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_auditoria.delete(1.0, tk.END)
        self.text_auditoria.insert(tk.END, "Ejecutando detección de rootkits...\n")
        self.label_estado_auditoria.config(text="Escaneando rootkits...")
        
        def ejecutar():
            try:
                if not self.controlador:
                    self.after(0, lambda: self._mostrar_chkrootkit({'exito': False, 'error': 'Controlador no inicializado'}))
                    return
                resultado = self.controlador.ejecutar_deteccion_rootkit()
                self.after(0, lambda: self._mostrar_chkrootkit(resultado))
            except Exception as e:
                self.after(0, lambda: self._mostrar_chkrootkit({'exito': False, 'error': str(e)}))
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def _mostrar_chkrootkit(self, resultado):
        self.label_estado_auditoria.config(text="")
        
        if resultado['exito']:
            lineas = resultado['salida'].split('\n')
            lineas_importantes = [l for l in lineas if any(palabra in l.lower() 
                                for palabra in ['infected', 'suspicious', 'checking', 'found'])]
            
            self.text_auditoria.insert(tk.END, "\n=== RESULTADOS CHKROOTKIT ===\n")
            for linea in lineas_importantes[:30]:  # Limitar líneas
                self.text_auditoria.insert(tk.END, f"{linea}\n")
        else:
            self.text_auditoria.insert(tk.END, f"\nError: {resultado['error']}\n")
    
    def generar_reporte(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        self.text_reportes.delete(1.0, tk.END)
        self.text_reportes.insert(tk.END, "Generando reporte completo...\n")
        
        def ejecutar():
            try:
                if not self.controlador:
                    self.after(0, lambda: self.text_reportes.insert(tk.END, "Error: Controlador no inicializado\n"))
                    return
                reporte = self.controlador.generar_reporte_completo()
                self.reporte_actual = reporte
                texto_reporte = self.controlador.obtener_reporte_texto(reporte)
                self.after(0, lambda: self._mostrar_reporte(texto_reporte))
            except Exception as e:
                self.after(0, lambda: self.text_reportes.insert(tk.END, f"Error: {e}\n"))
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def _mostrar_reporte(self, texto_reporte):
        self.text_reportes.delete(1.0, tk.END)
        self.text_reportes.insert(tk.END, texto_reporte)
    
    def guardar_reporte_json(self):
        if not self.reporte_actual:
            messagebox.showwarning("Warning", "Generate report first")
            return
            
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        try:
            resultado = self.controlador.guardar_reporte_json(self.reporte_actual)
            
            if resultado['exito']:
                messagebox.showinfo("Success", f"Reporte guardado en: {resultado['archivo']}")
            else:
                messagebox.showerror("Error", resultado['error'])
        except Exception as e:
            messagebox.showerror("Error", f"Error guardando reporte: {e}")
    
    def guardar_reporte_txt(self):
        if not self.reporte_actual:
            messagebox.showwarning("Warning", "Generate report first")
            return
            
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        try:
            resultado = self.controlador.guardar_reporte_texto(self.reporte_actual)
            
            if resultado['exito']:
                messagebox.showinfo("Success", f"Reporte guardado en: {resultado['archivo']}")
            else:
                messagebox.showerror("Error", resultado['error'])
        except Exception as e:
            messagebox.showerror("Error", f"Error guardando reporte: {e}")
    
    def listar_reportes(self):
        if not self.controlador:
            messagebox.showwarning("Error", "Controller not configured")
            return
            
        try:
            reportes = self.controlador.listar_reportes_guardados()
            
            self.text_reportes.delete(1.0, tk.END)
            self.text_reportes.insert(tk.END, "=== REPORTES GUARDADOS ===\n\n")
            
            if not reportes:
                self.text_reportes.insert(tk.END, "No hay reportes guardados.\n")
                return
            
            for reporte in reportes:
                self.text_reportes.insert(tk.END, 
                    f"Archivo: {reporte['nombre']}\n"
                    f"Tamaño: {reporte['tamaño']} bytes\n"
                    f"Modificado: {reporte['modificado']}\n"
                    f"Ruta: {reporte['ruta']}\n"
                    f"{'-'*50}\n\n"
                )
        except Exception as e:
            self.text_reportes.insert(tk.END, f"Error: {e}\n")
    
    def crear_pestana_wordlists(self):
        frame_wordlists = ttk.Frame(self.notebook)
        self.notebook.add(frame_wordlists, text="Wordlists")
        
        titulo = ttk.Label(frame_wordlists, text="Gestión de Wordlists de Ciberseguridad", 
                          font=("Arial", 14, "bold"))
        titulo.pack(pady=10)
        
        main_frame = ttk.Frame(frame_wordlists)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        left_frame = ttk.LabelFrame(main_frame, text="Wordlists Disponibles", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.wordlists_listbox = tk.Listbox(left_frame, height=20)
        self.wordlists_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        scrollbar_wl = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.wordlists_listbox.yview)
        scrollbar_wl.pack(side=tk.RIGHT, fill=tk.Y)
        self.wordlists_listbox.config(yscrollcommand=scrollbar_wl.set)
        
        buttons_frame = ttk.Frame(left_frame)
        buttons_frame.pack(fill=tk.X)
        
        ttk.Button(buttons_frame, text="Refresh", 
                  command=self.actualizar_wordlists).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="View", 
                  command=self.ver_wordlist).pack(side=tk.LEFT, padx=5)
        
        right_frame = ttk.LabelFrame(main_frame, text="Acciones", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        ttk.Button(right_frame, text="📁 Cargar Wordlist", 
                  command=self.cargar_wordlist).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Edit", 
                  command=self.editar_wordlist).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Delete", 
                  command=self.eliminar_wordlist).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Export", 
                  command=self.exportar_wordlist).pack(fill=tk.X, pady=5)
        
        ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        create_frame = ttk.LabelFrame(right_frame, text="Create", padding=5)
        create_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(create_frame, text="Nombre:").pack(anchor=tk.W)
        self.nuevo_wordlist_entry = ttk.Entry(create_frame)
        self.nuevo_wordlist_entry.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(create_frame, text="➕ Crear Wordlist", 
                  command=self.crear_nueva_wordlist).pack(fill=tk.X)
        
        self.actualizar_wordlists()
    
    def crear_pestana_diccionarios(self):
        frame_diccionarios = ttk.Frame(self.notebook)
        self.notebook.add(frame_diccionarios, text="📚 Diccionarios")
        
        titulo = ttk.Label(frame_diccionarios, text="📖 Gestión de Diccionarios de Ciberseguridad", 
                          font=("Arial", 14, "bold"))
        titulo.pack(pady=10)
        
        main_frame = ttk.Frame(frame_diccionarios)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        left_frame = ttk.LabelFrame(main_frame, text="Diccionarios Disponibles", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.diccionarios_listbox = tk.Listbox(left_frame, height=15)
        self.diccionarios_listbox.pack(fill=tk.X, pady=(0, 10))
        
        search_frame = ttk.LabelFrame(left_frame, text="Buscar en Diccionario", padding=5)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Término a buscar:").pack(anchor=tk.W)
        self.buscar_entry = ttk.Entry(search_frame)
        self.buscar_entry.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(search_frame, text="Buscar", 
                  command=self.buscar_en_diccionario).pack(fill=tk.X)
        
        self.resultado_busqueda = tk.Text(left_frame, height=8, wrap=tk.WORD)
        self.resultado_busqueda.pack(fill=tk.BOTH, expand=True)
        
        right_frame = ttk.LabelFrame(main_frame, text="Acciones", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        ttk.Button(right_frame, text="📁 Cargar Diccionario", 
                  command=self.cargar_diccionario).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Editar Diccionario", 
                  command=self.editar_diccionario).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Eliminar Diccionario", 
                  command=self.eliminar_diccionario).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="Export", 
                  command=self.exportar_diccionario).pack(fill=tk.X, pady=5)
        
        ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        add_frame = ttk.LabelFrame(right_frame, text="Agregar Entrada", padding=5)
        add_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(add_frame, text="Término:").pack(anchor=tk.W)
        self.nuevo_termino_entry = ttk.Entry(add_frame)
        self.nuevo_termino_entry.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(add_frame, text="Definición:").pack(anchor=tk.W)
        self.nueva_definicion_entry = tk.Text(add_frame, height=3, wrap=tk.WORD)
        self.nueva_definicion_entry.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(add_frame, text="➕ Agregar Entrada", 
                  command=self.agregar_entrada_diccionario).pack(fill=tk.X)
        
        self.actualizar_diccionarios()
    
    def actualizar_wordlists(self):
        try:
            if not self.controlador:
                return
            self.wordlists_listbox.delete(0, tk.END)
            wordlists = self.controlador.listar_wordlists()
            for wordlist in wordlists:
                self.wordlists_listbox.insert(tk.END, wordlist)
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar wordlists: {str(e)}")
    
    def ver_wordlist(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.wordlists_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione una wordlist")
                return
            
            nombre = self.wordlists_listbox.get(seleccion[0])
            contenido = self.controlador.cargar_wordlist(nombre)
            
            ventana = tk.Toplevel(self.master)
            ventana.title(f"Contenido de: {nombre}")
            ventana.geometry("600x400")
            
            text_widget = tk.Text(ventana, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text_widget.insert(tk.END, "\n".join(contenido))
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al ver wordlist: {str(e)}")
    
    def cargar_wordlist(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            archivo = filedialog.askopenfilename(
                title="Seleccionar archivo de wordlist",
                filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            if archivo:
                nombre = simpledialog.askstring("Nombre", "Nombre para la wordlist:")
                if nombre:
                    resultado = self.controlador.cargar_wordlist_desde_archivo(archivo, nombre)
                    if resultado:
                        messagebox.showinfo("Success", "Wordlist cargada correctamente")
                        self.actualizar_wordlists()
                    else:
                        messagebox.showerror("Error", "Error al cargar la wordlist")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar wordlist: {str(e)}")
    
    def editar_wordlist(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.wordlists_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione una wordlist")
                return
            
            nombre = self.wordlists_listbox.get(seleccion[0])
            contenido = self.controlador.cargar_wordlist(nombre)
            
            ventana = tk.Toplevel(self.master)
            ventana.title(f"Editar: {nombre}")
            ventana.geometry("600x400")
            
            text_widget = tk.Text(ventana, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text_widget.insert(tk.END, "\n".join(contenido))
            
            def guardar_cambios():
                if not self.controlador:
                    messagebox.showerror("Error", "Controlador no inicializado")
                    return
                nuevo_contenido = text_widget.get(1.0, tk.END).strip().split('\n')
                if self.controlador.guardar_wordlist(nombre, nuevo_contenido):
                    messagebox.showinfo("Success", "Wordlist guardada correctamente")
                    ventana.destroy()
                    self.actualizar_wordlists()
                else:
                    messagebox.showerror("Error", "Error al guardar la wordlist")
            
            ttk.Button(ventana, text="Guardar", command=guardar_cambios).pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al editar wordlist: {str(e)}")
    
    def eliminar_wordlist(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.wordlists_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione una wordlist")
                return
            
            nombre = self.wordlists_listbox.get(seleccion[0])
            if messagebox.askyesno("Confirm", f"¿Eliminar la wordlist '{nombre}'?"):
                if self.controlador.eliminar_wordlist(nombre):
                    messagebox.showinfo("Success", "Wordlist eliminada correctamente")
                    self.actualizar_wordlists()
                else:
                    messagebox.showerror("Error", "Error al eliminar la wordlist")
        except Exception as e:
            messagebox.showerror("Error", f"Error al eliminar wordlist: {str(e)}")
    
    def exportar_wordlist(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.wordlists_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione una wordlist")
                return
            
            nombre = self.wordlists_listbox.get(seleccion[0])
            archivo = filedialog.asksaveasfilename(
                title="Guardar wordlist como",
                defaultextension=".txt",
                filetypes=[("Archivos de texto", "*.txt")]
            )
            if archivo:
                if self.controlador.exportar_wordlist(nombre, archivo):
                    messagebox.showinfo("Success", "Wordlist exportada correctamente")
                else:
                    messagebox.showerror("Error", "Error al exportar la wordlist")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar wordlist: {str(e)}")
    
    def crear_nueva_wordlist(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            nombre = self.nuevo_wordlist_entry.get().strip()
            if not nombre:
                messagebox.showwarning("Warning", "Ingrese un nombre para la wordlist")
                return
            
            if self.controlador.crear_wordlist_vacia(nombre):
                messagebox.showinfo("Success", "Wordlist creada correctamente")
                self.nuevo_wordlist_entry.delete(0, tk.END)
                self.actualizar_wordlists()
            else:
                messagebox.showerror("Error", "Error al crear la wordlist")
        except Exception as e:
            messagebox.showerror("Error", f"Error al crear wordlist: {str(e)}")
    
    def actualizar_diccionarios(self):
        try:
            if not self.controlador:
                return
            self.diccionarios_listbox.delete(0, tk.END)
            diccionarios = self.controlador.listar_diccionarios()
            for diccionario in diccionarios:
                self.diccionarios_listbox.insert(tk.END, diccionario)
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar diccionarios: {str(e)}")
    
    def buscar_en_diccionario(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.diccionarios_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione un diccionario")
                return
            
            nombre_dict = self.diccionarios_listbox.get(seleccion[0])
            termino = self.buscar_entry.get().strip()
            
            if not termino:
                messagebox.showwarning("Warning", "Ingrese un término a buscar")
                return
            
            resultados = self.controlador.buscar_en_diccionario(nombre_dict, termino)
            
            self.resultado_busqueda.delete(1.0, tk.END)
            if resultados:
                for resultado in resultados:
                    self.resultado_busqueda.insert(tk.END, f"📍 {resultado['termino']}\n")
                    self.resultado_busqueda.insert(tk.END, f"   {resultado['definicion']}\n\n")
            else:
                self.resultado_busqueda.insert(tk.END, "No se encontraron resultados.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al buscar: {str(e)}")
    
    def cargar_diccionario(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            archivo = filedialog.askopenfilename(
                title="Seleccionar archivo de diccionario",
                filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
            )
            if archivo:
                nombre = simpledialog.askstring("Nombre", "Nombre para el diccionario:")
                if nombre:
                    resultado = self.controlador.cargar_diccionario_desde_archivo(archivo, nombre)
                    if resultado:
                        messagebox.showinfo("Success", "Diccionario cargado correctamente")
                        self.actualizar_diccionarios()
                    else:
                        messagebox.showerror("Error", "Error al cargar el diccionario")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar diccionario: {str(e)}")
    
    def editar_diccionario(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.diccionarios_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione un diccionario")
                return
            
            nombre = self.diccionarios_listbox.get(seleccion[0])
            contenido = self.controlador.obtener_diccionario_completo(nombre)
            
            ventana = tk.Toplevel(self.master)
            ventana.title(f"Editar: {nombre}")
            ventana.geometry("700x500")
            
            main_frame = ttk.Frame(ventana)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            terms_frame = ttk.LabelFrame(main_frame, text="Términos", padding=5)
            terms_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            
            terms_listbox = tk.Listbox(terms_frame)
            terms_listbox.pack(fill=tk.BOTH, expand=True)
            
            for termino in contenido.keys():
                terms_listbox.insert(tk.END, termino)
            
            edit_frame = ttk.LabelFrame(main_frame, text="Editar Término", padding=5)
            edit_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
            
            ttk.Label(edit_frame, text="Término:").pack(anchor=tk.W)
            term_entry = ttk.Entry(edit_frame)
            term_entry.pack(fill=tk.X, pady=(0, 5))
            
            ttk.Label(edit_frame, text="Definición:").pack(anchor=tk.W)
            def_text = tk.Text(edit_frame, height=10, wrap=tk.WORD)
            def_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
            
            def cargar_termino():
                sel = terms_listbox.curselection()
                if sel:
                    termino = terms_listbox.get(sel[0])
                    term_entry.delete(0, tk.END)
                    term_entry.insert(0, termino)
                    def_text.delete(1.0, tk.END)
                    def_text.insert(1.0, contenido[termino])
            
            def guardar_termino():
                termino = term_entry.get().strip()
                definicion = def_text.get(1.0, tk.END).strip()
                if termino and definicion:
                    contenido[termino] = definicion
                    terms_listbox.delete(0, tk.END)
                    for t in contenido.keys():
                        terms_listbox.insert(tk.END, t)
            
            def eliminar_termino():
                sel = terms_listbox.curselection()
                if sel:
                    termino = terms_listbox.get(sel[0])
                    if messagebox.askyesno("Confirm", f"¿Eliminar '{termino}'?"):
                        del contenido[termino]
                        terms_listbox.delete(sel[0])
                        term_entry.delete(0, tk.END)
                        def_text.delete(1.0, tk.END)
            
            def guardar_diccionario():
                if not self.controlador:
                    messagebox.showerror("Error", "Controlador no inicializado")
                    return
                if self.controlador.guardar_diccionario_completo(nombre, contenido):
                    messagebox.showinfo("Success", "Diccionario guardado correctamente")
                    ventana.destroy()
                    self.actualizar_diccionarios()
                else:
                    messagebox.showerror("Error", "Error al guardar el diccionario")
            
            terms_listbox.bind('<<ListboxSelect>>', lambda e: cargar_termino())
            
            buttons_frame = ttk.Frame(edit_frame)
            buttons_frame.pack(fill=tk.X, pady=5)
            
            ttk.Button(buttons_frame, text="Guardar Término", 
                      command=guardar_termino).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(buttons_frame, text="Eliminar", 
                      command=eliminar_termino).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(edit_frame, text="Guardar Diccionario", 
                      command=guardar_diccionario).pack(fill=tk.X, pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al editar diccionario: {str(e)}")
    
    def eliminar_diccionario(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.diccionarios_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione un diccionario")
                return
            
            nombre = self.diccionarios_listbox.get(seleccion[0])
            if messagebox.askyesno("Confirm", f"¿Eliminar el diccionario '{nombre}'?"):
                if self.controlador.eliminar_diccionario(nombre):
                    messagebox.showinfo("Success", "Diccionario eliminado correctamente")
                    self.actualizar_diccionarios()
                else:
                    messagebox.showerror("Error", "Error al eliminar el diccionario")
        except Exception as e:
            messagebox.showerror("Error", f"Error al eliminar diccionario: {str(e)}")
    
    def exportar_diccionario(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.diccionarios_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione un diccionario")
                return
            
            nombre = self.diccionarios_listbox.get(seleccion[0])
            archivo = filedialog.asksaveasfilename(
                title="Guardar diccionario como",
                defaultextension=".txt",
                filetypes=[("Archivos de texto", "*.txt")]
            )
            if archivo:
                if self.controlador.exportar_diccionario_txt(nombre, archivo):
                    messagebox.showinfo("Success", "Diccionario exportado correctamente")
                else:
                    messagebox.showerror("Error", "Error al exportar el diccionario")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar diccionario: {str(e)}")
    
    def agregar_entrada_diccionario(self):
        try:
            if not self.controlador:
                messagebox.showwarning("Error", "Controller not configured")
                return
                
            seleccion = self.diccionarios_listbox.curselection()
            if not seleccion:
                messagebox.showwarning("Warning", "Seleccione un diccionario")
                return
            
            nombre_dict = self.diccionarios_listbox.get(seleccion[0])
            termino = self.nuevo_termino_entry.get().strip()
            definicion = self.nueva_definicion_entry.get(1.0, tk.END).strip()
            
            if not termino or not definicion:
                messagebox.showwarning("Warning", "Ingrese tanto el término como la definición")
                return
            
            if self.controlador.agregar_entrada_diccionario(nombre_dict, termino, definicion):
                messagebox.showinfo("Success", "Entrada agregada correctamente")
                self.nuevo_termino_entry.delete(0, tk.END)
                self.nueva_definicion_entry.delete(1.0, tk.END)
            else:
                messagebox.showerror("Error", "Error al agregar la entrada")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al agregar entrada: {str(e)}")


# RESUMEN: Interfaz para utilidades con pestañas de wordlists y diccionarios.

