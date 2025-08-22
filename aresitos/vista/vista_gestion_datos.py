# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import os
import logging
import datetime
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
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Configuración del tema Burp Suite
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            # Diccionario de colores consistente con otras vistas
            self.colors = {
                'bg_primary': burp_theme.get_color('bg_primary'),      # #2b2b2b
                'bg_secondary': burp_theme.get_color('bg_secondary'),  # #1e1e1e  
                'fg_primary': burp_theme.get_color('fg_primary'),      # #ffffff
                'fg_accent': burp_theme.get_color('fg_accent'),        # #ff6633
                'success': burp_theme.get_color('success'),            # #00ff88
                'warning': burp_theme.get_color('warning'),            # #ffcc00
                'danger': burp_theme.get_color('danger'),              # #ff4444
                'info': burp_theme.get_color('info')                   # #44aaff
            }
            self.configure(bg=self.colors['bg_primary'])
            # Configurar estilos TTK
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
        else:
            self.theme = None
            # Colores por defecto para compatibilidad
            self.colors = {
                'bg_primary': '#f0f0f0',
                'bg_secondary': '#ffffff',
                'fg_primary': '#000000',
                'fg_accent': '#0066cc',
                'success': '#008800',
                'warning': '#ff8800',
                'danger': '#cc0000',
                'info': '#0066cc'
            }
        
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
        self.logger.info("Controlador establecido en VistaGestionDatos")
        
        # Cargar datos desde el controlador si está disponible
        self.actualizar_desde_controlador()
    
    def crear_interfaz(self):
        """Crear interfaz principal con estilo Burp Suite."""
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame superior para el contenido principal
        main_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(main_frame, minsize=400)
        
        # Título
        titulo = tk.Label(main_frame, text=" Gestión de Datos", 
                        font=('Arial', 16, 'bold'),
                        bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack(pady=(10, 20))
        
        # Frame de selección de tipo
        self.crear_selector_tipo(main_frame)
        
        # Frame principal dividido
        content_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Panel izquierdo - Lista de archivos
        self.crear_panel_archivos(content_frame)
        
        # Panel derecho - Acciones y contenido
        self.crear_panel_acciones(content_frame)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
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
            (" Exportar", self.exportar_archivo, '#9C27B0'),
            (" Análisis Kali", self.analizar_con_kali, '#FF5722')
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
        
        # Frame adicional para herramientas de Kali
        if self.theme:
            kali_frame = tk.Frame(right_frame, bg='#2b2b2b')
        else:
            kali_frame = tk.Frame(right_frame)
        kali_frame.pack(fill=tk.X, pady=(5, 10))
        
        # Botones de herramientas de Kali
        herramientas_kali = [
            (" grep", self.usar_grep_kali, '#607D8B'),
            (" sort", self.usar_sort_kali, '#795548'),
            (" wc", self.contar_lineas_kali, '#9E9E9E'),
            (" uniq", self.lineas_unicas_kali, '#673AB7')
        ]
        
        for texto, comando, color in herramientas_kali:
            if self.theme:
                btn = tk.Button(kali_frame, text=texto, command=comando,
                              bg=color, fg='white', font=('Arial', 9),
                              relief='flat', padx=12, pady=3)
                btn.pack(side=tk.LEFT, padx=(0, 3))
            else:
                btn = ttk.Button(kali_frame, text=texto, command=comando)
                btn.pack(side=tk.LEFT, padx=(0, 3))
        
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
        try:
            self.logger.info(f"Cambiando tipo de gestión de datos a: {nuevo_tipo}")
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
            
            # Llamar al controlador para obtener datos específicos del tipo
            if self.controlador:
                if nuevo_tipo == "wordlists":
                    wordlists_data = self.controlador.obtener_wordlists_disponibles()
                    self.logger.info(f"Wordlists disponibles: {len(wordlists_data) if wordlists_data else 0}")
                else:
                    diccionarios_data = self.controlador.obtener_diccionarios_disponibles()
                    self.logger.info(f"Diccionarios disponibles: {len(diccionarios_data) if diccionarios_data else 0}")
                    
                # Actualizar estadísticas en la vista
                self.actualizar_desde_controlador()
            
            # Recargar archivos
            self.cargar_archivos()
            
        except Exception as e:
            self.logger.error(f"Error cambiando tipo de gestión: {e}")
    
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
        self.log_to_terminal(f"Cargando archivo {self.tipo_actual}...")
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
                
                self.log_to_terminal(f"OK Archivo copiado a: {destino.name}")
                
                # Recargar lista
                self.cargar_archivos()
                
                self.log_to_terminal(f"LISTA Lista de {self.tipo_actual} actualizada")
                messagebox.showinfo("Éxito", f"Archivo cargado exitosamente:\n{destino.name}")
                
            except Exception as e:
                self.log_to_terminal(f"ERROR Error al cargar archivo: {str(e)}")
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
            
            self.log_to_terminal(f"ARCHIVO Archivo guardado: {self.archivo_seleccionado.name}")
            messagebox.showinfo("Éxito", "Archivo guardado exitosamente.")
            
            # Recargar contenido para mostrar información actualizada
            self.mostrar_contenido_archivo()
            
        except Exception as e:
            self.log_to_terminal(f"ERROR Error al guardar: {str(e)}")
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
                
                self.log_to_terminal(f"📤 Archivo exportado: {destino_path.name}")
                messagebox.showinfo("Éxito", f"Archivo exportado exitosamente:\n{destino_path.name}")
                
            except Exception as e:
                self.log_to_terminal(f"ERROR Error al exportar: {str(e)}")
                messagebox.showerror("Error", f"Error al exportar archivo: {str(e)}")
    
    def actualizar_desde_controlador(self):
        """Actualizar datos desde el controlador si está disponible"""
        if not self.controlador:
            return
        
        try:
            # Si el controlador tiene gestores de wordlists/diccionarios, usarlos
            if hasattr(self.controlador, 'modelo_principal'):
                modelo = self.controlador.modelo_principal
                
                if hasattr(modelo, 'gestor_wordlists') and modelo.gestor_wordlists:
                    self.logger.info("Datos de wordlists disponibles desde controlador")
                    
                if hasattr(modelo, 'gestor_diccionarios') and modelo.gestor_diccionarios:
                    self.logger.info("Datos de diccionarios disponibles desde controlador")
                    
        except Exception as e:
            self.logger.error(f"Error actualizando desde controlador: {e}")
    
    def obtener_estadisticas_datos(self):
        """Obtener estadísticas de datos a través del controlador"""
        if not self.controlador:
            return {}
        
        try:
            if hasattr(self.controlador, 'modelo_principal'):
                modelo = self.controlador.modelo_principal
                if hasattr(modelo, 'obtener_estadisticas_generales'):
                    estadisticas = modelo.obtener_estadisticas_generales()
                    self.logger.info(f"Estadísticas obtenidas: {estadisticas}")
                    return estadisticas
                    
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            
        return {}
    
    def _log_terminal(self, mensaje, modulo="GESTION", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")
    
    def analizar_con_kali(self):
        """Análisis avanzado de wordlists/diccionarios con herramientas de Kali."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para analizar.")
            return
        
        try:
            import subprocess
            import threading
            
            def realizar_analisis():
                try:
                    self.text_contenido.delete(1.0, tk.END)
                    self.text_contenido.insert(tk.END, f"=== ANÁLISIS KALI DE {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'} ===\n\n")
                    self.text_contenido.update()
                    
                    archivo_path = str(self.archivo_seleccionado)
                    
                    # Información básica con wc
                    try:
                        result = subprocess.run(['wc', '-l', '-w', '-c', archivo_path], 
                                              capture_output=True, text=True, timeout=10)
                        self.text_contenido.insert(tk.END, f"ESTADÍSTICAS BÁSICAS:\n{result.stdout}\n")
                    except:
                        self.text_contenido.insert(tk.END, "Error obteniendo estadísticas básicas\n")
                    
                    # Análisis de duplicados
                    try:
                        result = subprocess.run(['sort', archivo_path], 
                                              capture_output=True, text=True, timeout=15)
                        if result.stdout:
                            result2 = subprocess.run(['uniq', '-d'], 
                                                   input=result.stdout, capture_output=True, text=True, timeout=10)
                            duplicados = len(result2.stdout.split('\n')) if result2.stdout else 0
                            self.text_contenido.insert(tk.END, f"\nLÍNEAS DUPLICADAS: {duplicados}\n")
                    except:
                        self.text_contenido.insert(tk.END, "\nError analizando duplicados\n")
                    
                    # Longitudes de líneas
                    try:
                        result = subprocess.run(['awk', '{print length($0)}', archivo_path], 
                                              capture_output=True, text=True, timeout=10)
                        if result.stdout:
                            lengths = [int(x) for x in result.stdout.split('\n') if x.strip().isdigit()]
                            if lengths:
                                self.text_contenido.insert(tk.END, f"\nLONGITUD MÍNIMA: {min(lengths)}\n")
                                self.text_contenido.insert(tk.END, f"LONGITUD MÁXIMA: {max(lengths)}\n")
                                self.text_contenido.insert(tk.END, f"LONGITUD PROMEDIO: {sum(lengths)/len(lengths):.1f}\n")
                    except:
                        self.text_contenido.insert(tk.END, "\nError analizando longitudes\n")
                    
                    # Caracteres especiales
                    try:
                        result = subprocess.run(['grep', '-o', '[^a-zA-Z0-9 ]', archivo_path], 
                                              capture_output=True, text=True, timeout=10)
                        especiales = len(set(result.stdout))
                        self.text_contenido.insert(tk.END, f"\nCARACTERES ESPECIALES ÚNICOS: {especiales}\n")
                    except:
                        self.text_contenido.insert(tk.END, "\nError analizando caracteres especiales\n")
                    
                    self.text_contenido.insert(tk.END, "\n=== ANÁLISIS COMPLETADO ===\n")
                    self._log_terminal(f"Análisis Kali completado para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                    
                except Exception as e:
                    self.text_contenido.insert(tk.END, f"\nError en análisis: {str(e)}")
            
            thread = threading.Thread(target=realizar_analisis)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error iniciando análisis: {str(e)}")
    
    def usar_grep_kali(self):
        """Buscar patrones usando grep."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para buscar.")
            return
        
        from tkinter import simpledialog
        patron = simpledialog.askstring("Buscar con grep", "Ingrese el patrón a buscar:")
        
        if patron:
            try:
                import subprocess
                import threading
                
                def buscar():
                    try:
                        result = subprocess.run(['grep', '-n', '-i', patron, str(self.archivo_seleccionado)], 
                                              capture_output=True, text=True, timeout=10)
                        
                        self.text_contenido.delete(1.0, tk.END)
                        self.text_contenido.insert(tk.END, f"=== BÚSQUEDA GREP: '{patron}' ===\n\n")
                        
                        if result.stdout:
                            coincidencias = result.stdout.split('\n')
                            self.text_contenido.insert(tk.END, f"COINCIDENCIAS ENCONTRADAS: {len(coincidencias)-1}\n\n")
                            self.text_contenido.insert(tk.END, result.stdout)
                        else:
                            self.text_contenido.insert(tk.END, "No se encontraron coincidencias.\n")
                        
                        self._log_terminal(f"Búsqueda grep '{patron}' en {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                        
                    except Exception as e:
                        self.text_contenido.insert(tk.END, f"Error en búsqueda: {str(e)}")
                
                thread = threading.Thread(target=buscar)
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                messagebox.showerror("Error", f"Error en grep: {str(e)}")
    
    def usar_sort_kali(self):
        """Ordenar contenido usando sort."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para ordenar.")
            return
        
        try:
            import subprocess
            import threading
            
            def ordenar():
                try:
                    # Ordenar y mostrar
                    result = subprocess.run(['sort', '-u', str(self.archivo_seleccionado)], 
                                          capture_output=True, text=True, timeout=15)
                    
                    self.text_contenido.delete(1.0, tk.END)
                    self.text_contenido.insert(tk.END, "=== CONTENIDO ORDENADO (SIN DUPLICADOS) ===\n\n")
                    
                    if result.stdout:
                        lineas = result.stdout.split('\n')
                        self.text_contenido.insert(tk.END, f"LÍNEAS ÚNICAS: {len(lineas)-1}\n\n")
                        self.text_contenido.insert(tk.END, result.stdout)
                    else:
                        self.text_contenido.insert(tk.END, "Archivo vacío o error procesando.\n")
                    
                    self._log_terminal(f"Ordenamiento completado para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                    
                except Exception as e:
                    self.text_contenido.insert(tk.END, f"Error ordenando: {str(e)}")
            
            thread = threading.Thread(target=ordenar)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error en sort: {str(e)}")
    
    def contar_lineas_kali(self):
        """Contar líneas, palabras y caracteres usando wc."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para contar.")
            return
        
        try:
            import subprocess
            
            result = subprocess.run(['wc', '-l', '-w', '-c', str(self.archivo_seleccionado)], 
                                  capture_output=True, text=True, timeout=5)
            
            self.text_contenido.delete(1.0, tk.END)
            self.text_contenido.insert(tk.END, f"=== ESTADÍSTICAS DE {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'} ===\n\n")
            self.text_contenido.insert(tk.END, "FORMATO: líneas palabras caracteres archivo\n")
            self.text_contenido.insert(tk.END, f"{result.stdout}\n")
            
            # Análisis adicional
            if result.stdout:
                parts = result.stdout.strip().split()
                if len(parts) >= 3:
                    lineas = int(parts[0])
                    palabras = int(parts[1])
                    caracteres = int(parts[2])
                    
                    self.text_contenido.insert(tk.END, f"\nDETALLE:\n")
                    self.text_contenido.insert(tk.END, f"- Líneas: {lineas:,}\n")
                    self.text_contenido.insert(tk.END, f"- Palabras: {palabras:,}\n")
                    self.text_contenido.insert(tk.END, f"- Caracteres: {caracteres:,}\n")
                    
                    if lineas > 0:
                        self.text_contenido.insert(tk.END, f"- Promedio palabras/línea: {palabras/lineas:.2f}\n")
                        self.text_contenido.insert(tk.END, f"- Promedio caracteres/línea: {caracteres/lineas:.2f}\n")
            
            self._log_terminal(f"Conteo completado para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error contando: {str(e)}")
    
    def lineas_unicas_kali(self):
        """Mostrar líneas únicas usando uniq."""
        if not self.archivo_seleccionado:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para procesar.")
            return
        
        try:
            import subprocess
            import threading
            
            def procesar_unicas():
                try:
                    # Primero ordenar, luego obtener únicas
                    result1 = subprocess.run(['sort', str(self.archivo_seleccionado)], 
                                           capture_output=True, text=True, timeout=15)
                    
                    if result1.stdout:
                        result2 = subprocess.run(['uniq', '-c'], 
                                               input=result1.stdout, capture_output=True, text=True, timeout=10)
                        
                        self.text_contenido.delete(1.0, tk.END)
                        self.text_contenido.insert(tk.END, "=== LÍNEAS ÚNICAS CON FRECUENCIA ===\n\n")
                        self.text_contenido.insert(tk.END, "FORMATO: frecuencia línea\n\n")
                        
                        if result2.stdout:
                            # Ordenar por frecuencia (descendente)
                            result3 = subprocess.run(['sort', '-nr'], 
                                                   input=result2.stdout, capture_output=True, text=True, timeout=10)
                            self.text_contenido.insert(tk.END, result3.stdout if result3.stdout else result2.stdout)
                        else:
                            self.text_contenido.insert(tk.END, "Error procesando líneas únicas.\n")
                    else:
                        self.text_contenido.insert(tk.END, "Archivo vacío o error leyendo.\n")
                    
                    self._log_terminal(f"Análisis de líneas únicas para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                    
                except Exception as e:
                    self.text_contenido.insert(tk.END, f"Error procesando: {str(e)}")
            
            thread = threading.Thread(target=procesar_unicas)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error en uniq: {str(e)}")
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado Gestión Datos con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - Gestión Datos",
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
                command=self.limpiar_terminal_gestion,
                bg='#ffaa00',
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)
            
            # Botón ver logs (estilo dashboard, compacto)
            btn_logs = tk.Button(
                controles_frame,
                text="VER LOGS",
                command=self.abrir_logs_gestion,
                bg='#007acc',
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)
            
            # Área de terminal (misma estética que dashboard, más pequeña)
            self.terminal_output = scrolledtext.ScrolledText(
                terminal_frame,
                height=6,  # Más pequeño que dashboard
                bg='#000000',  # Fondo negro como dashboard
                fg='#00ff00',  # Texto verde como dashboard
                font=("Consolas", 8),  # Fuente menor que dashboard
                insertbackground='#00ff00',
                selectbackground='#333333'
            )
            self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Mensaje inicial estilo dashboard
            import datetime
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - Gestión Datos v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, f"Sistema: Kali Linux - Data Management\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Gestión de datos\n\n")
            
            self.log_to_terminal("Terminal Gestión Datos iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Gestión Datos: {e}")
    
    def limpiar_terminal_gestion(self):
        """Limpiar terminal Gestión Datos manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - Gestión Datos v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - Data Management\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal Gestión Datos reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Gestión Datos: {e}")
    
    def abrir_logs_gestion(self):
        """Abrir carpeta de logs Gestión Datos."""
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
                self.log_to_terminal("Carpeta de logs Gestión Datos abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs Gestión Datos: {e}")
    
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
