# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import os
from pathlib import Path

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False

class VistaGestionDatos(tk.Frame):
    """
    Vista unificada para gestión de Wordlists y Diccionarios.
    Simplicidad y funcionalidad siguiendo el patrón visual de Burp Suite.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        # Configurar tema
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.configure(bg='#2b2b2b')
        else:
            self.theme = None
        
        # Rutas de datos
        self.ruta_wordlists = Path("data/wordlists")
        self.ruta_diccionarios = Path("data/diccionarios")
        
        # Variables de estado
        self.tipo_actual = "wordlists"  # "wordlists" o "diccionarios"
        self.archivo_seleccionado = None
        self.datos_actuales = {}
        
        self.crear_interfaz()
        self.cargar_archivos()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        """Crear interfaz principal con estilo Burp Suite."""
        # Frame principal
        if self.theme:
            main_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        if self.theme:
            titulo = tk.Label(main_frame, text=" Gestión de Datos", 
                            font=('Arial', 16, 'bold'),
                            bg='#2b2b2b', fg='#ff6633')
        else:
            titulo = tk.Label(main_frame, text=" Gestión de Datos", 
                            font=('Arial', 16, 'bold'))
        titulo.pack(pady=(0, 20))
        
        # Frame de selección de tipo
        self.crear_selector_tipo(main_frame)
        
        # Frame principal dividido
        content_frame = tk.Frame(main_frame, bg='#2b2b2b' if self.theme else 'white')
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Panel izquierdo - Lista de archivos
        self.crear_panel_archivos(content_frame)
        
        # Panel derecho - Acciones y contenido
        self.crear_panel_acciones(content_frame)
    
    def crear_selector_tipo(self, parent):
        """Crear selector de tipo de datos."""
        if self.theme:
            selector_frame = tk.Frame(parent, bg='#2b2b2b')
        else:
            selector_frame = tk.Frame(parent)
        selector_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de selección
        if self.theme:
            self.btn_wordlists = tk.Button(selector_frame, text=" Wordlists", 
                                         command=lambda: self.cambiar_tipo("wordlists"),
                                         bg='#ff6633', fg='white', font=('Arial', 11, 'bold'),
                                         relief='flat', padx=20, pady=8)
            self.btn_wordlists.pack(side=tk.LEFT, padx=(0, 10))
            
            self.btn_diccionarios = tk.Button(selector_frame, text=" Diccionarios", 
                                            command=lambda: self.cambiar_tipo("diccionarios"),
                                            bg='#404040', fg='white', font=('Arial', 11),
                                            relief='flat', padx=20, pady=8)
            self.btn_diccionarios.pack(side=tk.LEFT)
        else:
            self.btn_wordlists = ttk.Button(selector_frame, text=" Wordlists", 
                                          command=lambda: self.cambiar_tipo("wordlists"))
            self.btn_wordlists.pack(side=tk.LEFT, padx=(0, 10))
            
            self.btn_diccionarios = ttk.Button(selector_frame, text=" Diccionarios", 
                                             command=lambda: self.cambiar_tipo("diccionarios"))
            self.btn_diccionarios.pack(side=tk.LEFT)
    
    def crear_panel_archivos(self, parent):
        """Crear panel de lista de archivos."""
        if self.theme:
            left_frame = tk.Frame(parent, bg='#2b2b2b')
        else:
            left_frame = ttk.LabelFrame(parent, text="Archivos Disponibles", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        if self.theme:
            label_archivos = tk.Label(left_frame, text="Archivos Disponibles", 
                                    bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_archivos.pack(anchor=tk.W, pady=(0, 10))
        
        # Lista de archivos
        if self.theme:
            # Frame para el Listbox con estilo personalizado
            list_frame = tk.Frame(left_frame, bg='#1e1e1e', relief='sunken', bd=1)
            list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            self.lista_archivos = tk.Listbox(list_frame, 
                                           bg='#1e1e1e', fg='white',
                                           selectbackground='#ff6633',
                                           selectforeground='white',
                                           font=('Consolas', 10),
                                           relief='flat', bd=0)
        else:
            self.lista_archivos = tk.Listbox(left_frame, font=('Consolas', 10))
        
        self.lista_archivos.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.lista_archivos.bind('<<ListboxSelect>>', self.on_archivo_seleccionado)
        
        # Scrollbar para la lista
        if self.theme:
            scrollbar = tk.Scrollbar(list_frame, bg='#404040')
        else:
            scrollbar = tk.Scrollbar(left_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.lista_archivos.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.lista_archivos.yview)
    
    def crear_panel_acciones(self, parent):
        """Crear panel de acciones y contenido."""
        if self.theme:
            right_frame = tk.Frame(parent, bg='#2b2b2b')
        else:
            right_frame = ttk.LabelFrame(parent, text="Acciones y Contenido", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        if self.theme:
            label_acciones = tk.Label(right_frame, text="Acciones y Contenido", 
                                    bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_acciones.pack(anchor=tk.W, pady=(0, 10))
        
        # Frame de botones de acción
        if self.theme:
            btn_frame = tk.Frame(right_frame, bg='#2b2b2b')
        else:
            btn_frame = tk.Frame(right_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de acción
        acciones = [
            (" Cargar", self.cargar_archivo, '#4CAF50'),
            (" Editar", self.editar_archivo, '#2196F3'),
            (" Guardar", self.guardar_archivo, '#FF9800'),
            (" Eliminar", self.eliminar_archivo, '#f44336'),
            (" Exportar", self.exportar_archivo, '#9C27B0')
        ]
        
        for i, (texto, comando, color) in enumerate(acciones):
            if self.theme:
                btn = tk.Button(btn_frame, text=texto, command=comando,
                              bg=color, fg='white', font=('Arial', 10),
                              relief='flat', padx=15, pady=5)
                btn.pack(side=tk.LEFT, padx=(0, 5))
            else:
                btn = ttk.Button(btn_frame, text=texto, command=comando)
                btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Área de contenido
        if self.theme:
            content_label = tk.Label(right_frame, text="Contenido del Archivo", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 11, 'bold'))
            content_label.pack(anchor=tk.W, pady=(10, 5))
        
        self.text_contenido = scrolledtext.ScrolledText(right_frame, height=20,
                                                       bg='#1e1e1e' if self.theme else 'white',
                                                       fg='white' if self.theme else 'black',
                                                       insertbackground='white' if self.theme else 'black',
                                                       font=('Consolas', 10))
        self.text_contenido.pack(fill=tk.BOTH, expand=True)
    
    def cambiar_tipo(self, nuevo_tipo):
        """Cambiar entre wordlists y diccionarios."""
        self.tipo_actual = nuevo_tipo
        
        # Actualizar botones
        if self.theme:
            if nuevo_tipo == "wordlists":
                self.btn_wordlists['bg'] = '#ff6633'
                self.btn_diccionarios['bg'] = '#404040'
            else:
                self.btn_wordlists['bg'] = '#404040'
                self.btn_diccionarios['bg'] = '#ff6633'
        
        # Limpiar selección y contenido
        self.archivo_seleccionado = None
        self.text_contenido.delete(1.0, tk.END)
        
        # Recargar archivos
        self.cargar_archivos()
    
    def cargar_archivos(self):
        """Cargar lista de archivos según el tipo seleccionado."""
        self.lista_archivos.delete(0, tk.END)
        
        if self.tipo_actual == "wordlists":
            ruta = self.ruta_wordlists
            extensiones = ['.txt', '.json']
        else:
            ruta = self.ruta_diccionarios
            extensiones = ['.json']
        
        if ruta.exists():
            archivos = []
            for ext in extensiones:
                archivos.extend(ruta.glob(f'*{ext}'))
            
            # Ordenar archivos
            archivos.sort(key=lambda x: x.name.lower())
            
            for archivo in archivos:
                # Mostrar nombre del archivo con icono según tipo
                if archivo.suffix == '.json':
                    icono = ""
                else:
                    icono = ""
                self.lista_archivos.insert(tk.END, f"{icono} {archivo.name}")
    
    def on_archivo_seleccionado(self, event):
        """Manejar selección de archivo."""
        selection = self.lista_archivos.curselection()
        if selection:
            nombre_archivo = self.lista_archivos.get(selection[0])
            # Quitar el icono del nombre
            nombre_archivo = nombre_archivo.split(' ', 1)[1]
            
            if self.tipo_actual == "wordlists":
                archivo_path = self.ruta_wordlists / nombre_archivo
            else:
                archivo_path = self.ruta_diccionarios / nombre_archivo
            
            self.archivo_seleccionado = archivo_path
            self.mostrar_contenido_archivo()
    
    def mostrar_contenido_archivo(self):
        """Mostrar contenido del archivo seleccionado."""
        if not self.archivo_seleccionado or not self.archivo_seleccionado.exists():
            return
        
        try:
            self.text_contenido.delete(1.0, tk.END)
            
            if self.archivo_seleccionado.suffix == '.json':
                with open(self.archivo_seleccionado, 'r', encoding='utf-8') as f:
                    datos = json.load(f)
                    self.datos_actuales = datos
                    contenido_formateado = json.dumps(datos, indent=2, ensure_ascii=False)
                    self.text_contenido.insert(1.0, contenido_formateado)
            else:
                with open(self.archivo_seleccionado, 'r', encoding='utf-8', errors='ignore') as f:
                    contenido = f.read()
                    self.text_contenido.insert(1.0, contenido)
            
            # Información del archivo
            stats = self.archivo_seleccionado.stat()
            info = f"\n\n# === INFORMACIÓN DEL ARCHIVO ===\n"
            info += f"# Nombre: {self.archivo_seleccionado.name}\n"
            info += f"# Tamaño: {stats.st_size} bytes\n"
            info += f"# Tipo: {self.tipo_actual.capitalize()}\n"
            
            if self.archivo_seleccionado.suffix == '.json' and self.datos_actuales:
                if isinstance(self.datos_actuales, dict):
                    info += f"# Elementos: {len(self.datos_actuales)} claves\n"
                elif isinstance(self.datos_actuales, list):
                    info += f"# Elementos: {len(self.datos_actuales)} items\n"
            
            self.text_contenido.insert(tk.END, info)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")
    
    def cargar_archivo(self):
        """Cargar archivo externo."""
        if self.tipo_actual == "wordlists":
            filetypes = [("Archivos de texto", "*.txt"), ("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        else:
            filetypes = [("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        
        archivo = filedialog.askopenfilename(
            title=f"Cargar {self.tipo_actual.capitalize()}",
            filetypes=filetypes
        )
        
        if archivo:
            try:
                # Copiar archivo a la carpeta correspondiente
                archivo_origen = Path(archivo)
                if self.tipo_actual == "wordlists":
                    destino = self.ruta_wordlists / archivo_origen.name
                else:
                    destino = self.ruta_diccionarios / archivo_origen.name
                
                # Crear directorio si no existe
                destino.parent.mkdir(parents=True, exist_ok=True)
                
                # Copiar archivo
                import shutil
                shutil.copy2(archivo_origen, destino)
                
                # Recargar lista
                self.cargar_archivos()
                
                messagebox.showinfo("Éxito", f"Archivo cargado exitosamente:\n{destino.name}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")
    
    def editar_archivo(self):
        """Habilitar edición del archivo actual."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para editar.")
            return
        
        # Habilitar edición
        self.text_contenido.config(state=tk.NORMAL)
        messagebox.showinfo("Modo Edición", 
                          "Archivo habilitado para edición.\n"
                          "Use 'Guardar' para confirmar los cambios.")
    
    def guardar_archivo(self):
        """Guardar cambios en el archivo."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "No hay archivo seleccionado para guardar.")
            return
        
        try:
            contenido = self.text_contenido.get(1.0, tk.END)
            
            # Limpiar información del archivo del contenido
            lineas = contenido.split('\n')
            contenido_limpio = []
            en_info = False
            
            for linea in lineas:
                if linea.startswith("# === INFORMACIÓN DEL ARCHIVO ==="):
                    en_info = True
                    break
                if not en_info:
                    contenido_limpio.append(linea)
            
            contenido_final = '\n'.join(contenido_limpio).rstrip()
            
            if self.archivo_seleccionado.suffix == '.json':
                # Validar JSON
                try:
                    datos = json.loads(contenido_final)
                    with open(self.archivo_seleccionado, 'w', encoding='utf-8') as f:
                        json.dump(datos, f, indent=2, ensure_ascii=False)
                except json.JSONDecodeError as e:
                    messagebox.showerror("Error JSON", f"Formato JSON inválido: {str(e)}")
                    return
            else:
                with open(self.archivo_seleccionado, 'w', encoding='utf-8') as f:
                    f.write(contenido_final)
            
            messagebox.showinfo("Éxito", "Archivo guardado exitosamente.")
            
            # Recargar contenido para mostrar información actualizada
            self.mostrar_contenido_archivo()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar archivo: {str(e)}")
    
    def eliminar_archivo(self):
        """Eliminar archivo seleccionado."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para eliminar.")
            return
        
        respuesta = messagebox.askyesno("Confirmar Eliminación", 
                                      f"¿Está seguro de eliminar el archivo?\n\n{self.archivo_seleccionado.name}\n\n"
                                      "Esta acción no se puede deshacer.")
        
        if respuesta:
            try:
                self.archivo_seleccionado.unlink()
                
                # Limpiar selección y contenido
                self.archivo_seleccionado = None
                self.text_contenido.delete(1.0, tk.END)
                
                # Recargar lista
                self.cargar_archivos()
                
                messagebox.showinfo("Éxito", "Archivo eliminado exitosamente.")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error al eliminar archivo: {str(e)}")
    
    def exportar_archivo(self):
        """Exportar archivo seleccionado."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para exportar.")
            return
        
        # Definir tipos de archivo para exportación
        if self.archivo_seleccionado.suffix == '.json':
            filetypes = [("Archivos JSON", "*.json"), ("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
            defaultext = ".json"
        else:
            filetypes = [("Archivos de texto", "*.txt"), ("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
            defaultext = ".txt"
        
        archivo_destino = filedialog.asksaveasfilename(
            title="Exportar Archivo",
            defaultextension=defaultext,
            filetypes=filetypes,
            initialfile=self.archivo_seleccionado.stem
        )
        
        if archivo_destino:
            try:
                contenido = self.text_contenido.get(1.0, tk.END)
                
                # Limpiar información del archivo del contenido
                lineas = contenido.split('\n')
                contenido_limpio = []
                en_info = False
                
                for linea in lineas:
                    if linea.startswith("# === INFORMACIÓN DEL ARCHIVO ==="):
                        en_info = True
                        break
                    if not en_info:
                        contenido_limpio.append(linea)
                
                contenido_final = '\n'.join(contenido_limpio).rstrip()
                
                # Exportar según extensión
                destino_path = Path(archivo_destino)
                if destino_path.suffix == '.json':
                    try:
                        datos = json.loads(contenido_final)
                        with open(destino_path, 'w', encoding='utf-8') as f:
                            json.dump(datos, f, indent=2, ensure_ascii=False)
                    except json.JSONDecodeError:
                        # Si no es JSON válido, guardar como texto
                        with open(destino_path, 'w', encoding='utf-8') as f:
                            f.write(contenido_final)
                else:
                    with open(destino_path, 'w', encoding='utf-8') as f:
                        f.write(contenido_final)
                
                messagebox.showinfo("Éxito", f"Archivo exportado exitosamente:\n{destino_path.name}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error al exportar archivo: {str(e)}")
