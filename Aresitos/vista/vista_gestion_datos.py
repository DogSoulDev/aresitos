# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import os
import logging
import datetime
import threading
from pathlib import Path

try:
    from Aresitos.vista.burp_theme import burp_theme
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
            (" Análisis Kali", self.analizar_con_kali, '#FF5722'),
            ("🛡️ Formatos", self.mostrar_ayuda_formatos, '#607D8B')
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
        
        # Frame adicional para gestión de archivos
        if self.theme:
            gestion_frame = tk.Frame(right_frame, bg='#2b2b2b')
        else:
            gestion_frame = tk.Frame(right_frame)
        gestion_frame.pack(fill=tk.X, pady=(5, 10))
        
        # Botones de gestión de archivos
        gestión_acciones = [
            ("🔄 Refrescar", self.cargar_archivos, '#17a2b8'),
            ("📁 Abrir Carpeta", self.abrir_carpeta_actual, '#007acc'),
            ("📊 Estadísticas", self.obtener_estadisticas_datos, '#6c757d')
        ]
        
        for texto, comando, color in gestión_acciones:
            if self.theme:
                btn = tk.Button(gestion_frame, text=texto, command=comando,
                              bg=color, fg='white', font=('Arial', 9),
                              relief='flat', padx=10, pady=3)
                btn.pack(side=tk.LEFT, padx=(0, 5))
            else:
                btn = ttk.Button(gestion_frame, text=texto, command=comando)
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
            self._actualizar_contenido_seguro("", "clear")
            
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
            tipo_str = "wordlists"
        else:
            ruta = self.ruta_diccionarios
            extensiones = ['.json']
            tipo_str = "diccionarios"
        
        if ruta.exists():
            archivos = []
            for ext in extensiones:
                archivos.extend(ruta.glob(f'*{ext}'))
            
            # Ordenar archivos
            archivos.sort(key=lambda x: x.name.lower())
            
            # Mostrar información de refresco
            self._log_terminal(f"🔄 Actualizando lista de {tipo_str}... Encontrados {len(archivos)} archivos", "GESTION")
            
            for archivo in archivos:
                # Mostrar nombre del archivo con icono según tipo
                if archivo.suffix == '.json':
                    icono = "📄"
                else:
                    icono = "📝"
                self.lista_archivos.insert(tk.END, f"{icono} {archivo.name}")
            
            # Mensaje de confirmación
            if archivos:
                self._log_terminal(f"✓ Lista de {tipo_str} actualizada correctamente", "GESTION")
            else:
                self._log_terminal(f"⚠️ No se encontraron {tipo_str} en la carpeta", "GESTION", "WARNING")
        else:
            self._log_terminal(f"❌ Carpeta de {tipo_str} no encontrada: {ruta}", "GESTION", "ERROR")
    
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
            self._actualizar_contenido_seguro("", "clear")
            
            if self.archivo_seleccionado.suffix == '.json':
                with open(self.archivo_seleccionado, 'r', encoding='utf-8') as f:
                    datos = json.load(f)
                    self.datos_actuales = datos
                    contenido_formateado = json.dumps(datos, indent=2, ensure_ascii=False)
                    self._actualizar_contenido_seguro(contenido_formateado, "replace")
            else:
                with open(self.archivo_seleccionado, 'r', encoding='utf-8', errors='ignore') as f:
                    contenido = f.read()
                    self._actualizar_contenido_seguro(contenido, "replace")
            
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
            
            self._actualizar_contenido_seguro(info)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")
    
    def cargar_archivo(self):
        """Cargar archivo externo con validación de seguridad."""
        from Aresitos.utils.sanitizador_archivos import SanitizadorArchivos
        from Aresitos.utils.helper_seguridad import HelperSeguridad
        
        # Mostrar información de seguridad al usuario
        if not HelperSeguridad.mostrar_info_carga_archivo(self.tipo_actual):
            self.log_to_terminal("CANCEL Usuario canceló la carga por información de seguridad")
            return
        
        self.log_to_terminal(f"Cargando archivo {self.tipo_actual}...")
        
        # Obtener filtros seguros para el diálogo
        sanitizador = SanitizadorArchivos()
        filetypes = sanitizador.generar_filtros_dialogo(self.tipo_actual)
        
        archivo = filedialog.askopenfilename(
            title=f"Cargar {self.tipo_actual.capitalize()}",
            filetypes=filetypes
        )
        
        if archivo:
            try:
                # VALIDACIÓN DE SEGURIDAD
                self.log_to_terminal(f"SECURE Validando archivo: {os.path.basename(archivo)}")
                
                resultado_validacion = sanitizador.validar_archivo(archivo, self.tipo_actual)
                
                # Usar helper para mostrar resultado de validación
                if not HelperSeguridad.mostrar_resultado_validacion(resultado_validacion):
                    self.log_to_terminal("CANCEL Carga cancelada por validación de seguridad")
                    return
                
                self.log_to_terminal(f"SECURE Archivo validado correctamente")
                
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
    
    def mostrar_ayuda_formatos(self):
        """Mostrar ayuda sobre formatos de archivo soportados."""
        from Aresitos.utils.helper_seguridad import HelperSeguridad
        
        self.log_to_terminal(f"INFO Mostrando ayuda de formatos para {self.tipo_actual}")
        HelperSeguridad.mostrar_ayuda_formatos(self.tipo_actual)
    
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
                self._actualizar_contenido_seguro("", "clear")
                
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
            from Aresitos.vista.vista_dashboard import VistaDashboard
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
                    # Limpiar contenido de forma segura
                    self._actualizar_contenido_seguro("", "clear")
                    self._actualizar_contenido_seguro(f"=== ANÁLISIS KALI DE {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'} ===\n\n")
                    
                    archivo_path = str(self.archivo_seleccionado)
                    
                    # Información básica con wc
                    try:
                        result = subprocess.run(['wc', '-l', '-w', '-c', archivo_path], 
                                              capture_output=True, text=True, timeout=10)
                        self._actualizar_contenido_seguro(f"ESTADÍSTICAS BÁSICAS:\n{result.stdout}\n")
                    except:
                        self._actualizar_contenido_seguro("Error obteniendo estadísticas básicas\n")
                    
                    # Análisis de duplicados
                    try:
                        result = subprocess.run(['sort', archivo_path], 
                                              capture_output=True, text=True, timeout=15)
                        if result.stdout:
                            result2 = subprocess.run(['uniq', '-d'], 
                                                   input=result.stdout, capture_output=True, text=True, timeout=10)
                            duplicados = len(result2.stdout.split('\n')) if result2.stdout else 0
                            self._actualizar_contenido_seguro(f"\nLÍNEAS DUPLICADAS: {duplicados}\n")
                    except:
                        self._actualizar_contenido_seguro("\nError analizando duplicados\n")
                    
                    # Longitudes de líneas
                    try:
                        result = subprocess.run(['awk', '{print length($0)}', archivo_path], 
                                              capture_output=True, text=True, timeout=10)
                        if result.stdout:
                            lengths = [int(x) for x in result.stdout.split('\n') if x.strip().isdigit()]
                            if lengths:
                                self._actualizar_contenido_seguro(f"\nLONGITUD MÍNIMA: {min(lengths)}\n")
                                self._actualizar_contenido_seguro(f"LONGITUD MÁXIMA: {max(lengths)}\n")
                                self._actualizar_contenido_seguro(f"LONGITUD PROMEDIO: {sum(lengths)/len(lengths):.1f}\n")
                    except:
                        self._actualizar_contenido_seguro("\nError analizando longitudes\n")
                    
                    # Caracteres especiales
                    try:
                        result = subprocess.run(['grep', '-o', '[^a-zA-Z0-9 ]', archivo_path], 
                                              capture_output=True, text=True, timeout=10)
                        especiales = len(set(result.stdout))
                        self._actualizar_contenido_seguro(f"\nCARACTERES ESPECIALES ÚNICOS: {especiales}\n")
                    except:
                        self._actualizar_contenido_seguro("\nError analizando caracteres especiales\n")
                    
                    self._actualizar_contenido_seguro("\n=== ANÁLISIS COMPLETADO ===\n")
                    self._log_terminal(f"Análisis Kali completado para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                    
                except Exception as e:
                    self._actualizar_contenido_seguro(f"\nError en análisis: {str(e)}")
            
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
                        
                        self._actualizar_contenido_seguro("", "clear")
                        self._actualizar_contenido_seguro(f"=== BÚSQUEDA GREP: '{patron}' ===\n\n")
                        
                        if result.stdout:
                            coincidencias = result.stdout.split('\n')
                            self._actualizar_contenido_seguro(f"COINCIDENCIAS ENCONTRADAS: {len(coincidencias)-1}\n\n")
                            self._actualizar_contenido_seguro(result.stdout)
                        else:
                            self._actualizar_contenido_seguro("No se encontraron coincidencias.\n")
                        
                        self._log_terminal(f"Búsqueda grep '{patron}' en {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                        
                    except Exception as e:
                        self._actualizar_contenido_seguro(f"Error en búsqueda: {str(e)}")
                
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
                    
                    self._actualizar_contenido_seguro("", "clear")
                    self._actualizar_contenido_seguro("=== CONTENIDO ORDENADO (SIN DUPLICADOS) ===\n\n")
                    
                    if result.stdout:
                        lineas = result.stdout.split('\n')
                        self._actualizar_contenido_seguro(f"LÍNEAS ÚNICAS: {len(lineas)-1}\n\n")
                        self._actualizar_contenido_seguro(result.stdout)
                    else:
                        self._actualizar_contenido_seguro("Archivo vacío o error procesando.\n")
                    
                    self._log_terminal(f"Ordenamiento completado para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                    
                except Exception as e:
                    self._actualizar_contenido_seguro(f"Error ordenando: {str(e)}")
            
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
            
            self._actualizar_contenido_seguro("", "clear")
            self._actualizar_contenido_seguro(f"=== ESTADÍSTICAS DE {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'} ===\n\n")
            self._actualizar_contenido_seguro("FORMATO: líneas palabras caracteres archivo\n")
            self._actualizar_contenido_seguro(f"{result.stdout}\n")
            
            # Análisis adicional
            if result.stdout:
                parts = result.stdout.strip().split()
                if len(parts) >= 3:
                    lineas = int(parts[0])
                    palabras = int(parts[1])
                    caracteres = int(parts[2])
                    
                    self._actualizar_contenido_seguro(f"\nDETALLE:\n")
                    self._actualizar_contenido_seguro(f"- Líneas: {lineas:,}\n")
                    self._actualizar_contenido_seguro(f"- Palabras: {palabras:,}\n")
                    self._actualizar_contenido_seguro(f"- Caracteres: {caracteres:,}\n")
                    
                    if lineas > 0:
                        self._actualizar_contenido_seguro(f"- Promedio palabras/línea: {palabras/lineas:.2f}\n")
                        self._actualizar_contenido_seguro(f"- Promedio caracteres/línea: {caracteres/lineas:.2f}\n")
            
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
                        
                        self._actualizar_contenido_seguro("", "clear")
                        self._actualizar_contenido_seguro("=== LÍNEAS ÚNICAS CON FRECUENCIA ===\n\n")
                        self._actualizar_contenido_seguro("FORMATO: frecuencia línea\n\n")
                        
                        if result2.stdout:
                            # Ordenar por frecuencia (descendente)
                            result3 = subprocess.run(['sort', '-nr'], 
                                                   input=result2.stdout, capture_output=True, text=True, timeout=10)
                            self._actualizar_contenido_seguro(result3.stdout if result3.stdout else result2.stdout)
                        else:
                            self._actualizar_contenido_seguro("Error procesando líneas únicas.\n")
                    else:
                        self._actualizar_contenido_seguro("Archivo vacío o error leyendo.\n")
                    
                    self._log_terminal(f"Análisis de líneas únicas para {self.archivo_seleccionado.name if self.archivo_seleccionado else 'archivo'}", "GESTION", "INFO")
                    
                except Exception as e:
                    self._actualizar_contenido_seguro(f"Error procesando: {str(e)}")
            
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
                command=self.abrir_logs_gestion,
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
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada con validación de seguridad."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        
        # Validar comando con el módulo de seguridad
        try:
            from Aresitos.utils.seguridad_comandos import validador_comandos
            
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
                self.limpiar_terminal_gestion()
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
    
    def abrir_carpeta_actual(self):
        """Abrir carpeta actual (wordlists o diccionarios) según el tipo seleccionado."""
        try:
            import os
            import platform
            import subprocess
            
            # Determinar carpeta según tipo actual
            if self.tipo_actual == "wordlists":
                carpeta_path = str(self.ruta_wordlists.resolve())
                tipo_carpeta = "wordlists"
            else:
                carpeta_path = str(self.ruta_diccionarios.resolve())
                tipo_carpeta = "diccionarios"
            
            if os.path.exists(carpeta_path):
                # Comandos específicos para Kali Linux
                if platform.system() == "Linux":
                    comandos_kali = [
                        ["thunar", carpeta_path],       # XFCE (predeterminado Kali)
                        ["nautilus", carpeta_path],     # GNOME
                        ["dolphin", carpeta_path],      # KDE
                        ["pcmanfm", carpeta_path],      # LXDE
                        ["xdg-open", carpeta_path]      # Genérico Linux
                    ]
                    
                    for comando in comandos_kali:
                        try:
                            subprocess.run(["which", comando[0]], check=True, 
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            subprocess.Popen(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            self._log_terminal(f"OK Carpeta {tipo_carpeta} abierta con {comando[0]}: {carpeta_path}", "GESTION")
                            break
                        except subprocess.CalledProcessError:
                            continue
                    else:
                        self._log_terminal(f"ERROR No se encontró gestor de archivos en Kali", "GESTION", "ERROR")
                else:
                    # Windows
                    subprocess.run(["explorer", carpeta_path], check=False)
                    self._log_terminal(f"OK Carpeta {tipo_carpeta} abierta: {carpeta_path}", "GESTION")
                
                # Mostrar contenido de la carpeta y refrescar lista
                self._mostrar_contenido_carpeta(carpeta_path, tipo_carpeta)
                self.cargar_archivos()  # Refrescar lista automáticamente
                
            else:
                self._log_terminal(f"ERROR Carpeta {tipo_carpeta} no encontrada: {carpeta_path}", "GESTION", "ERROR")
                
        except Exception as e:
            self._log_terminal(f"ERROR abriendo carpeta {tipo_carpeta}: {e}", "GESTION", "ERROR")
    
    def _mostrar_contenido_carpeta(self, carpeta_path, tipo_carpeta):
        """Mostrar estadísticas del contenido de la carpeta."""
        try:
            import os
            archivos = os.listdir(carpeta_path)
            
            if tipo_carpeta == "wordlists":
                archivos_validos = [f for f in archivos if f.endswith(('.txt', '.json'))]
                extensiones_msg = "(.txt/.json)"
            else:
                archivos_validos = [f for f in archivos if f.endswith('.json')]
                extensiones_msg = "(.json)"
            
            if archivos_validos:
                self._log_terminal(f"INFO {len(archivos_validos)} {tipo_carpeta} disponibles {extensiones_msg}:", "GESTION")
                for archivo in sorted(archivos_validos)[:8]:  # Mostrar primeros 8
                    extension_icon = "📄" if archivo.endswith('.json') else "📝"
                    self._log_terminal(f"   {extension_icon} {archivo}", "GESTION")
                
                if len(archivos_validos) > 8:
                    self._log_terminal(f"   ... y {len(archivos_validos)-8} archivos más", "GESTION")
                
                # Estadísticas por tipo
                if tipo_carpeta == "wordlists":
                    txt_count = len([f for f in archivos_validos if f.endswith('.txt')])
                    json_count = len([f for f in archivos_validos if f.endswith('.json')])
                    self._log_terminal(f"   Tipos: {txt_count} archivos .txt, {json_count} archivos .json", "GESTION")
                else:
                    self._log_terminal(f"   Total diccionarios JSON: {len(archivos_validos)}", "GESTION")
            else:
                self._log_terminal(f"INFO Carpeta encontrada pero sin {tipo_carpeta} válidos {extensiones_msg}", "GESTION")
                otros_archivos = [f for f in archivos if not f.startswith('.')][:5]
                if otros_archivos:
                    self._log_terminal(f"   Otros archivos: {', '.join(otros_archivos)}", "GESTION")
                    
        except Exception as e:
            self._log_terminal(f"ERROR leyendo contenido de carpeta: {e}", "GESTION", "ERROR")
    
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

    def _actualizar_contenido_seguro(self, texto, modo="append"):
        """Actualizar text_contenido de forma segura desde threads."""
        def _update():
            try:
                if hasattr(self, 'text_contenido') and self.text_contenido.winfo_exists():
                    if modo == "clear":
                        self.text_contenido.delete(1.0, tk.END)
                    elif modo == "replace":
                        self.text_contenido.delete(1.0, tk.END)
                        self.text_contenido.insert(1.0, texto)
                    elif modo == "append":
                        self.text_contenido.insert(tk.END, texto)
                    elif modo == "insert_start":
                        self.text_contenido.insert(1.0, texto)
                    self.text_contenido.see(tk.END)
                    if hasattr(self.text_contenido, 'update'):
                        self.text_contenido.update()
            except (tk.TclError, AttributeError):
                pass  # Widget ya no existe o ha sido destruido
        
        try:
            self.after_idle(_update)
        except:
            pass  # Si no se puede programar, ignorar

    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            from Aresitos.utils.seguridad_comandos import validador_comandos
            
            comandos = validador_comandos.obtener_comandos_disponibles()
            
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "🛡️  COMANDOS DISPONIBLES EN ARESITOS v2.0 - GESTIÓN DATOS\n")
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
            from Aresitos.utils.seguridad_comandos import validador_comandos
            
            info = validador_comandos.obtener_info_seguridad()
            
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS - GESTIÓN DATOS\n")
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
