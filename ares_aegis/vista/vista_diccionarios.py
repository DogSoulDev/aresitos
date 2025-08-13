# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import json
import os

try:
    from ares_aegis.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaDiccionarios(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.configure(bg='#2b2b2b')
        else:
            self.theme = None
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        if self.theme:
            titulo_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            titulo_frame = tk.Frame(self)
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo = tk.Label(titulo_frame, text="Gestion de Diccionarios",
                         font=('Arial', 16, 'bold'),
                         bg='#2b2b2b' if self.theme else 'white',
                         fg='#ff6633' if self.theme else 'black')
        titulo.pack()
        
        if self.theme:
            main_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        if self.theme:
            left_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_dict = tk.Label(left_frame, text="Editor de Diccionarios", 
                                bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_dict.pack(anchor=tk.W, pady=(0, 5))
        else:
            left_frame = ttk.LabelFrame(main_frame, text="Editor de Diccionarios", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        config_subframe = tk.Frame(left_frame, bg='#2b2b2b' if self.theme else 'white')
        config_subframe.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(config_subframe, text="Nombre del Diccionario:", 
                bg='#2b2b2b' if self.theme else 'white',
                fg='white' if self.theme else 'black').pack(anchor=tk.W)
        
        self.nombre_diccionario = tk.Entry(config_subframe,
                                         bg='#1e1e1e' if self.theme else 'white',
                                         fg='white' if self.theme else 'black',
                                         insertbackground='white' if self.theme else 'black')
        self.nombre_diccionario.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(config_subframe, text="Categoria:", 
                bg='#2b2b2b' if self.theme else 'white',
                fg='white' if self.theme else 'black').pack(anchor=tk.W)
        
        self.categoria_dict = ttk.Combobox(config_subframe, 
                                         values=["Vulnerabilidades", "Puertos", "Servicios", "Exploits", "CVE"], 
                                         state="readonly")
        self.categoria_dict.pack(fill=tk.X, pady=(0, 10))
        self.categoria_dict.set("Vulnerabilidades")
        
        tk.Label(config_subframe, text="Formato:", 
                bg='#2b2b2b' if self.theme else 'white',
                fg='white' if self.theme else 'black').pack(anchor=tk.W)
        
        self.formato_dict = ttk.Combobox(config_subframe, 
                                       values=["JSON", "CSV", "TXT"], 
                                       state="readonly")
        self.formato_dict.pack(fill=tk.X, pady=(0, 10))
        self.formato_dict.set("JSON")
        
        self.diccionario_text = scrolledtext.ScrolledText(left_frame, height=18, width=60,
                                                        bg='#1e1e1e' if self.theme else 'white',
                                                        fg='white' if self.theme else 'black',
                                                        insertbackground='white' if self.theme else 'black',
                                                        font=('Consolas', 10))
        self.diccionario_text.pack(fill=tk.BOTH, expand=True)
        
        if self.theme:
            right_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_tools = tk.Label(right_frame, text="Herramientas de Diccionario", 
                                 bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_tools.pack(anchor=tk.W, pady=(0, 10))
        else:
            right_frame = ttk.LabelFrame(main_frame, text="Herramientas de Diccionario", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        if self.theme:
            buttons = [
                ("Crear Diccionario", self.crear_diccionario, '#ff6633'),
                ("Cargar Diccionario", self.cargar_diccionario, '#404040'),
                ("Validar Formato", self.validar_diccionario, '#404040'),
                ("Buscar Entrada", self.buscar_entrada, '#404040'),
                ("Agregar Entrada", self.agregar_entrada, '#404040'),
                ("Guardar Diccionario", self.guardar_diccionario, '#404040'),
                ("Limpiar Editor", self.limpiar_diccionario, '#404040')
            ]
            
            for text, command, bg_color in buttons:
                btn = tk.Button(right_frame, text=text, command=command,
                              bg=bg_color, fg='white', font=('Arial', 10))
                btn.pack(fill=tk.X, pady=2)
        else:
            ttk.Button(right_frame, text="Crear Diccionario", 
                      command=self.crear_diccionario).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Cargar Diccionario", 
                      command=self.cargar_diccionario).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Validar Formato", 
                      command=self.validar_diccionario).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Buscar Entrada", 
                      command=self.buscar_entrada).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Agregar Entrada", 
                      command=self.agregar_entrada).pack(fill=tk.X, pady=5)
            ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            ttk.Button(right_frame, text="Guardar Diccionario", 
                      command=self.guardar_diccionario).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Limpiar Editor", 
                      command=self.limpiar_diccionario).pack(fill=tk.X, pady=5)
    
    def crear_diccionario(self):
        try:
            nombre = self.nombre_diccionario.get()
            categoria = self.categoria_dict.get()
            formato = self.formato_dict.get()
            
            if not nombre:
                messagebox.showwarning("Advertencia", "Ingrese un nombre para el diccionario")
                return
            
            if formato == "JSON":
                estructura = {
                    "nombre": nombre,
                    "categoria": categoria,
                    "version": "1.0",
                    "fecha_creacion": "",
                    "entradas": {}
                }
                contenido = json.dumps(estructura, indent=2, ensure_ascii=False)
            elif formato == "CSV":
                contenido = "clave,valor,descripcion\n"
            else:
                contenido = f"# Diccionario: {nombre}\n# Categoria: {categoria}\n\n"
            
            self.diccionario_text.config(state=tk.NORMAL)
            self.diccionario_text.delete(1.0, tk.END)
            self.diccionario_text.insert(1.0, contenido)
            self.diccionario_text.config(state=tk.DISABLED)
            
            messagebox.showinfo("Exito", f"Diccionario '{nombre}' creado")
        except Exception as e:
            messagebox.showerror("Error", f"Error creando diccionario: {str(e)}")
    
    def cargar_diccionario(self):
        try:
            archivo = filedialog.askopenfilename(
                title="Cargar Diccionario",
                filetypes=[
                    ("Archivos JSON", "*.json"),
                    ("Archivos CSV", "*.csv"),
                    ("Archivos de texto", "*.txt"),
                    ("Todos los archivos", "*.*")
                ]
            )
            
            if archivo:
                with open(archivo, 'r', encoding='utf-8') as f:
                    contenido = f.read()
                
                self.diccionario_text.config(state=tk.NORMAL)
                self.diccionario_text.delete(1.0, tk.END)
                self.diccionario_text.insert(1.0, contenido)
                self.diccionario_text.config(state=tk.DISABLED)
                
                nombre_archivo = os.path.splitext(os.path.basename(archivo))[0]
                self.nombre_diccionario.delete(0, tk.END)
                self.nombre_diccionario.insert(0, nombre_archivo)
                
                extension = os.path.splitext(archivo)[1].lower()
                if extension == '.json':
                    self.formato_dict.set("JSON")
                elif extension == '.csv':
                    self.formato_dict.set("CSV")
                else:
                    self.formato_dict.set("TXT")
                
                messagebox.showinfo("Exito", f"Diccionario cargado desde {os.path.basename(archivo)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar diccionario: {str(e)}")
    
    def validar_diccionario(self):
        try:
            contenido = self.diccionario_text.get(1.0, tk.END)
            formato = self.formato_dict.get()
            
            errores = []
            
            if formato == "JSON":
                try:
                    data = json.loads(contenido)
                    if not isinstance(data, dict):
                        errores.append("El JSON debe ser un objeto")
                except json.JSONDecodeError as e:
                    errores.append(f"Error JSON: {str(e)}")
            elif formato == "CSV":
                lineas = contenido.strip().split('\n')
                if not lineas or not lineas[0]:
                    errores.append("CSV vacio")
                else:
                    primera_linea = lineas[0].split(',')
                    for i, linea in enumerate(lineas[1:], 2):
                        campos = linea.split(',')
                        if len(campos) != len(primera_linea):
                            errores.append(f"Linea {i}: numero incorrecto de campos")
            
            if errores:
                mensaje = "Errores encontrados:\n" + "\n".join(errores)
                messagebox.showerror("Validacion Fallida", mensaje)
            else:
                messagebox.showinfo("Validacion Exitosa", "El diccionario es valido")
        except Exception as e:
            messagebox.showerror("Error", f"Error al validar: {str(e)}")
    
    def buscar_entrada(self):
        try:
            busqueda = simpledialog.askstring("Buscar", "Ingrese el termino a buscar:")
            if not busqueda:
                return
            
            contenido = self.diccionario_text.get(1.0, tk.END)
            lineas = contenido.split('\n')
            resultados = []
            
            for i, linea in enumerate(lineas, 1):
                if busqueda.lower() in linea.lower():
                    resultados.append(f"Linea {i}: {linea}")
            
            if resultados:
                mensaje = f"Encontradas {len(resultados)} coincidencias:\n\n" + "\n".join(resultados[:10])
                if len(resultados) > 10:
                    mensaje += f"\n... y {len(resultados) - 10} mas"
                messagebox.showinfo("Resultados de Busqueda", mensaje)
            else:
                messagebox.showinfo("Sin Resultados", "No se encontraron coincidencias")
        except Exception as e:
            messagebox.showerror("Error", f"Error en busqueda: {str(e)}")
    
    def agregar_entrada(self):
        try:
            formato = self.formato_dict.get()
            
            if formato == "JSON":
                clave = simpledialog.askstring("Nueva Entrada", "Clave:")
                if not clave:
                    return
                valor = simpledialog.askstring("Nueva Entrada", "Valor:")
                if not valor:
                    return
                
                contenido = self.diccionario_text.get(1.0, tk.END)
                try:
                    data = json.loads(contenido)
                    if "entradas" not in data:
                        data["entradas"] = {}
                    data["entradas"][clave] = valor
                    nuevo_contenido = json.dumps(data, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    messagebox.showerror("Error", "El contenido actual no es JSON valido")
                    return
            elif formato == "CSV":
                clave = simpledialog.askstring("Nueva Entrada", "Clave:")
                if not clave:
                    return
                valor = simpledialog.askstring("Nueva Entrada", "Valor:")
                if not valor:
                    return
                descripcion = simpledialog.askstring("Nueva Entrada", "Descripcion (opcional):") or ""
                
                contenido = self.diccionario_text.get(1.0, tk.END)
                nuevo_contenido = contenido + f"{clave},{valor},{descripcion}\n"
            else:
                entrada = simpledialog.askstring("Nueva Entrada", "Entrada:")
                if not entrada:
                    return
                
                contenido = self.diccionario_text.get(1.0, tk.END)
                nuevo_contenido = contenido + f"{entrada}\n"
            
            self.diccionario_text.config(state=tk.NORMAL)
            self.diccionario_text.delete(1.0, tk.END)
            self.diccionario_text.insert(1.0, nuevo_contenido)
            self.diccionario_text.config(state=tk.DISABLED)
            
            messagebox.showinfo("Exito", "Entrada agregada")
        except Exception as e:
            messagebox.showerror("Error", f"Error agregando entrada: {str(e)}")
    
    def guardar_diccionario(self):
        try:
            contenido = self.diccionario_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay diccionario para guardar")
                return
            
            formato = self.formato_dict.get().lower()
            nombre = self.nombre_diccionario.get() or "diccionario"
            
            archivo = filedialog.asksaveasfilename(
                title="Guardar Diccionario",
                defaultextension=f".{formato}",
                filetypes=[
                    ("Archivos JSON", "*.json"),
                    ("Archivos CSV", "*.csv"),
                    ("Archivos de texto", "*.txt"),
                    ("Todos los archivos", "*.*")
                ]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(contenido)
                messagebox.showinfo("Exito", f"Diccionario guardado en {archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def limpiar_diccionario(self):
        self.diccionario_text.config(state=tk.NORMAL)
        self.diccionario_text.delete(1.0, tk.END)
        self.diccionario_text.config(state=tk.DISABLED)
        self.nombre_diccionario.delete(0, tk.END)
