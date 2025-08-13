# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os

try:
    from ares_aegis.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaWordlists(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_wordlist_activo = False
        self.thread_wordlist = None
        
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.configure(bg='#2b2b2b')
        else:
            self.theme = None
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
        # Actualizar datos cuando se establece el controlador
        self.actualizar_datos_wordlists()
    
    def actualizar_datos_wordlists(self):
        """Actualizar la vista con las wordlists cargadas."""
        if not self.controlador:
            return
            
        try:
            # Limpiar el texto actual
            self.wordlist_text.delete(1.0, tk.END)
            
            # Obtener información de wordlists
            info_wordlists = self.controlador.obtener_informacion_completa()
            
            if info_wordlists:
                self.wordlist_text.insert(tk.END, "📝 WORDLISTS CARGADAS EN ARESITOS\n")
                self.wordlist_text.insert(tk.END, "=" * 50 + "\n\n")
                
                total_wordlists = info_wordlists.get('total_wordlists', 0)
                total_categorias = info_wordlists.get('total_categorias', 0)
                
                self.wordlist_text.insert(tk.END, f"📊 Total de wordlists: {total_wordlists}\n")
                self.wordlist_text.insert(tk.END, f"📂 Categorías disponibles: {total_categorias}\n\n")
                
                # Mostrar categorías con conteos
                categorias = info_wordlists.get('categorias', {})
                self.wordlist_text.insert(tk.END, "📋 CATEGORÍAS Y CONTEOS:\n")
                self.wordlist_text.insert(tk.END, "-" * 30 + "\n")
                
                for categoria, datos in categorias.items():
                    if isinstance(datos, dict) and 'count' in datos:
                        count = datos['count']
                        self.wordlist_text.insert(tk.END, f"  • {categoria}: {count:,} elementos\n")
                    else:
                        self.wordlist_text.insert(tk.END, f"  • {categoria}: datos disponibles\n")
                
                # Mostrar archivos cargados
                archivos = info_wordlists.get('archivos_cargados', [])
                if archivos:
                    self.wordlist_text.insert(tk.END, f"\n📁 ARCHIVOS CARGADOS ({len(archivos)}):\n")
                    self.wordlist_text.insert(tk.END, "-" * 30 + "\n")
                    for archivo in archivos:
                        self.wordlist_text.insert(tk.END, f"  ✅ {archivo}\n")
                
                self.wordlist_text.insert(tk.END, "\n💡 Usa los botones para gestionar wordlists")
                
            else:
                self.wordlist_text.insert(tk.END, "❌ No hay wordlists cargadas\n")
                self.wordlist_text.insert(tk.END, "Usa 'Cargar Base' para importar wordlists")
                
        except Exception as e:
            self.wordlist_text.insert(tk.END, f"❌ Error cargando datos: {str(e)}\n")
    
    def crear_interfaz(self):
        if self.theme:
            titulo_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            titulo_frame = tk.Frame(self)
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo = tk.Label(titulo_frame, text="Constructor de Wordlists para Kali Linux",
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
            label_config = tk.Label(left_frame, text="Configuracion de Wordlist", 
                                  bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_config.pack(anchor=tk.W, pady=(0, 5))
        else:
            left_frame = ttk.LabelFrame(main_frame, text="Configuracion de Wordlist", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        config_subframe = tk.Frame(left_frame, bg='#2b2b2b' if self.theme else 'white')
        config_subframe.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(config_subframe, text="Tipo de Wordlist:", 
                bg='#2b2b2b' if self.theme else 'white',
                fg='white' if self.theme else 'black').pack(anchor=tk.W)
        
        self.tipo_wordlist = ttk.Combobox(config_subframe, 
                                        values=["Passwords", "Directorios", "Subdominios", "API Endpoints", "Usernames"], 
                                        state="readonly")
        self.tipo_wordlist.pack(fill=tk.X, pady=(0, 10))
        self.tipo_wordlist.set("Passwords")
        
        tk.Label(config_subframe, text="Patron Base:", 
                bg='#2b2b2b' if self.theme else 'white',
                fg='white' if self.theme else 'black').pack(anchor=tk.W)
        
        self.patron_base = tk.Entry(config_subframe,
                                   bg='#1e1e1e' if self.theme else 'white',
                                   fg='white' if self.theme else 'black',
                                   insertbackground='white' if self.theme else 'black')
        self.patron_base.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(config_subframe, text="Numero de Variaciones:", 
                bg='#2b2b2b' if self.theme else 'white',
                fg='white' if self.theme else 'black').pack(anchor=tk.W)
        
        self.num_variaciones = tk.Entry(config_subframe,
                                       bg='#1e1e1e' if self.theme else 'white',
                                       fg='white' if self.theme else 'black',
                                       insertbackground='white' if self.theme else 'black')
        self.num_variaciones.pack(fill=tk.X, pady=(0, 10))
        self.num_variaciones.insert(0, "100")
        
        self.incluir_numeros = tk.BooleanVar(value=True)
        tk.Checkbutton(config_subframe, text="Incluir Numeros",
                      variable=self.incluir_numeros,
                      bg='#2b2b2b' if self.theme else 'white',
                      fg='white' if self.theme else 'black',
                      selectcolor='#404040' if self.theme else 'white').pack(anchor=tk.W)
        
        self.incluir_simbolos = tk.BooleanVar()
        tk.Checkbutton(config_subframe, text="Incluir Simbolos",
                      variable=self.incluir_simbolos,
                      bg='#2b2b2b' if self.theme else 'white',
                      fg='white' if self.theme else 'black',
                      selectcolor='#404040' if self.theme else 'white').pack(anchor=tk.W)
        
        self.usar_leet = tk.BooleanVar()
        tk.Checkbutton(config_subframe, text="Usar Leet Speak",
                      variable=self.usar_leet,
                      bg='#2b2b2b' if self.theme else 'white',
                      fg='white' if self.theme else 'black',
                      selectcolor='#404040' if self.theme else 'white').pack(anchor=tk.W)
        
        self.wordlist_text = scrolledtext.ScrolledText(left_frame, height=12, width=50,
                                                      bg='#1e1e1e' if self.theme else 'white',
                                                      fg='white' if self.theme else 'black',
                                                      insertbackground='white' if self.theme else 'black',
                                                      font=('Consolas', 10))
        self.wordlist_text.pack(fill=tk.BOTH, expand=True)
        
        if self.theme:
            right_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_tools = tk.Label(right_frame, text="Herramientas de Wordlist", 
                                 bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_tools.pack(anchor=tk.W, pady=(0, 10))
        else:
            right_frame = ttk.LabelFrame(main_frame, text="Herramientas de Wordlist", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        if self.theme:
            buttons = [
                ("Generar Wordlist", self.generar_wordlist, '#ff6633'),
                ("❌ Cancelar", self.cancelar_wordlist, '#cc0000'),
                ("Cargar Base", self.cargar_base, '#404040'),
                ("Combinar Listas", self.combinar_listas, '#404040'),
                ("Filtrar Duplicados", self.filtrar_duplicados, '#404040'),
                ("Validar Formato", self.validar_formato, '#404040'),
                ("Guardar Wordlist", self.guardar_wordlist, '#404040'),
                ("Limpiar Pantalla", self.limpiar_wordlist, '#404040')
            ]
            
            for text, command, bg_color in buttons:
                btn = tk.Button(right_frame, text=text, command=command,
                              bg=bg_color, fg='white', font=('Arial', 10))
                if text == "❌ Cancelar":
                    btn.config(state="disabled")
                    self.btn_cancelar_wordlist = btn
                btn.pack(fill=tk.X, pady=2)
        else:
            # Crear botones individuales para mejor control
            self.btn_generar = ttk.Button(right_frame, text="Generar Wordlist", 
                                         command=self.generar_wordlist)
            self.btn_generar.pack(fill=tk.X, pady=5)
            
            self.btn_cancelar_wordlist = ttk.Button(right_frame, text="❌ Cancelar", 
                                                   command=self.cancelar_wordlist,
                                                   state="disabled")
            self.btn_cancelar_wordlist.pack(fill=tk.X, pady=5)
            
            ttk.Button(right_frame, text="Cargar Base", 
                      command=self.cargar_base).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Combinar Listas", 
                      command=self.combinar_listas).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Filtrar Duplicados", 
                      command=self.filtrar_duplicados).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Validar Formato", 
                      command=self.validar_formato).pack(fill=tk.X, pady=5)
            ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            ttk.Button(right_frame, text="Guardar Wordlist", 
                      command=self.guardar_wordlist).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Limpiar Pantalla", 
                      command=self.limpiar_wordlist).pack(fill=tk.X, pady=5)
    
    def generar_wordlist(self):
        """Generar wordlist con configuración seleccionada."""
        if self.proceso_wordlist_activo:
            messagebox.showwarning("Atención", "Ya hay una generación de wordlist en curso.")
            return
        
        # Validaciones básicas
        tipo = self.tipo_wordlist.get()
        if not tipo:
            messagebox.showerror("Error", "Debe seleccionar un tipo de wordlist.")
            return
        
        try:
            num_var = int(self.num_variaciones.get()) if self.num_variaciones.get().isdigit() else 100
            if num_var < 1:
                raise ValueError("Número de variaciones inválido")
        except ValueError:
            messagebox.showerror("Error", "El número de variaciones debe ser válido.")
            return
        
        # Iniciar proceso
        self.proceso_wordlist_activo = True
        self._habilitar_cancelar_wordlist(True)
        
        # Ejecutar en hilo separado
        self.thread_wordlist = threading.Thread(
            target=self._generar_wordlist_async,
            args=(tipo, num_var),
            daemon=True
        )
        self.thread_wordlist.start()
    
    def _generar_wordlist_async(self, tipo, num_var):
        """Generar wordlist de forma asíncrona."""
        try:
            self.wordlist_text.config(state=tk.NORMAL)
            self.wordlist_text.delete(1.0, tk.END)
            self.wordlist_text.insert(tk.END, f"🔄 Generando wordlist '{tipo}'...\n")
            self.wordlist_text.config(state=tk.DISABLED)
            
            if not self.proceso_wordlist_activo:
                return
            
            patron = self.patron_base.get()
            opciones = {
                'incluir_numeros': self.incluir_numeros.get(),
                'incluir_simbolos': self.incluir_simbolos.get(),
                'usar_leet': self.usar_leet.get()
            }
            
            wordlist_generada = []
            
            if not self.proceso_wordlist_activo:
                return
            
            # Generar según tipo
            if tipo == "Passwords":
                wordlist_generada = self.generar_passwords(patron, num_var, opciones)
            elif tipo == "Directorios":
                wordlist_generada = self.generar_directorios(num_var)
            elif tipo == "Subdominios":
                wordlist_generada = self.generar_subdominios(num_var)
            elif tipo == "API Endpoints":
                wordlist_generada = self.generar_api_endpoints(num_var)
            elif tipo == "Usernames":
                wordlist_generada = self.generar_usernames(num_var)
            
            if not self.proceso_wordlist_activo:
                return
            
            # Mostrar resultados
            self.wordlist_text.config(state=tk.NORMAL)
            self.wordlist_text.delete(1.0, tk.END)
            
            count = 0
            for palabra in wordlist_generada[:num_var]:
                if not self.proceso_wordlist_activo:
                    return
                
                self.wordlist_text.insert(tk.END, f"{palabra}\n")
                count += 1
                
                # Verificar cancelación cada 50 elementos
                if count % 50 == 0:
                    self.wordlist_text.update()
            
            if self.proceso_wordlist_activo:
                self.wordlist_text.insert(tk.END, f"\n✅ Wordlist generada: {count} elementos\n")
                self.wordlist_text.config(state=tk.DISABLED)
                
        except Exception as e:
            if self.proceso_wordlist_activo:
                self.wordlist_text.config(state=tk.NORMAL)
                self.wordlist_text.insert(tk.END, f"❌ Error en generación: {str(e)}\n")
                self.wordlist_text.config(state=tk.DISABLED)
        finally:
            if self.proceso_wordlist_activo:
                self._finalizar_proceso_wordlist()
    
    def generar_passwords(self, patron, num_var, opciones):
        import random
        import string
        
        passwords = []
        base_words = [patron] if patron else ['admin', 'password', 'login', 'test', 'user', 'kali', 'root']
        
        for base in base_words:
            for i in range(min(50, num_var // len(base_words))):
                palabra = base
                
                if opciones.get('usar_leet'):
                    palabra = palabra.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
                
                if opciones.get('incluir_numeros'):
                    palabra += str(random.randint(0, 999))
                
                if opciones.get('incluir_simbolos'):
                    palabra += random.choice('!@#$%^&*')
                
                passwords.extend([palabra, palabra.upper(), palabra.capitalize()])
        
        return list(set(passwords))
    
    def generar_directorios(self, num_var):
        dirs_comunes = [
            'admin', 'administrator', 'backup', 'config', 'data', 'images', 'includes',
            'js', 'css', 'uploads', 'downloads', 'files', 'docs', 'api', 'test',
            'tmp', 'temp', 'cache', 'logs', 'database', 'db', 'public', 'private',
            'assets', 'media', 'content', 'wp-admin', 'wp-content', 'phpmyadmin'
        ]
        return dirs_comunes[:num_var]
    
    def generar_subdominios(self, num_var):
        subs_comunes = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'portal',
            'dashboard', 'panel', 'cpanel', 'webmail', 'secure', 'vpn',
            'beta', 'demo', 'mobile', 'app', 'cdn', 'static'
        ]
        return subs_comunes[:num_var]
    
    def generar_api_endpoints(self, num_var):
        endpoints = [
            'api/v1/users', 'api/v1/login', 'api/v1/auth', 'api/v1/admin',
            'api/v2/data', 'api/config', 'api/status', 'api/health',
            'rest/api/users', 'rest/login', 'graphql', 'webhook',
            'api/v1/posts', 'api/v1/comments', 'api/upload', 'api/download'
        ]
        return endpoints[:num_var]
    
    def generar_usernames(self, num_var):
        users = [
            'admin', 'administrator', 'root', 'user', 'guest', 'test',
            'demo', 'support', 'service', 'operator', 'manager', 'owner',
            'kali', 'debian', 'ubuntu', 'oracle', 'postgres', 'mysql'
        ]
        return users[:num_var]
    
    def cargar_base(self):
        try:
            archivo = filedialog.askopenfilename(
                title="Cargar Wordlist Base",
                filetypes=[
                    ("Archivos de texto", "*.txt"),
                    ("Todos los archivos", "*.*")
                ]
            )
            
            if archivo:
                with open(archivo, 'r', encoding='utf-8', errors='ignore') as f:
                    contenido = f.read()
                
                self.wordlist_text.config(state=tk.NORMAL)
                self.wordlist_text.delete(1.0, tk.END)
                self.wordlist_text.insert(1.0, contenido)
                self.wordlist_text.config(state=tk.DISABLED)
                
                messagebox.showinfo("Exito", f"Wordlist cargada desde {os.path.basename(archivo)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar wordlist: {str(e)}")
    
    def combinar_listas(self):
        try:
            archivos = filedialog.askopenfilenames(
                title="Seleccionar Wordlists a Combinar",
                filetypes=[
                    ("Archivos de texto", "*.txt"),
                    ("Todos los archivos", "*.*")
                ]
            )
            
            if archivos:
                self.wordlist_text.config(state=tk.NORMAL)
                self.wordlist_text.insert(tk.END, "Combinando wordlists...\n")
                self.wordlist_text.update()
                
                contenido_combinado = []
                
                for archivo in archivos:
                    with open(archivo, 'r', encoding='utf-8', errors='ignore') as f:
                        lineas = f.read().strip().split('\n')
                        contenido_combinado.extend(lineas)
                
                contenido_unico = list(set([linea.strip() for linea in contenido_combinado if linea.strip()]))
                contenido_unico.sort()
                
                self.wordlist_text.delete(1.0, tk.END)
                for linea in contenido_unico:
                    self.wordlist_text.insert(tk.END, f"{linea}\n")
                
                self.wordlist_text.config(state=tk.DISABLED)
                messagebox.showinfo("Exito", f"Combinadas {len(archivos)} wordlists - {len(contenido_unico)} entradas unicas")
        except Exception as e:
            messagebox.showerror("Error", f"Error al combinar: {str(e)}")
    
    def filtrar_duplicados(self):
        try:
            contenido = self.wordlist_text.get(1.0, tk.END)
            lineas = contenido.strip().split('\n')
            
            lineas_unicas = list(set([linea.strip() for linea in lineas if linea.strip()]))
            lineas_unicas.sort()
            
            self.wordlist_text.config(state=tk.NORMAL)
            self.wordlist_text.delete(1.0, tk.END)
            
            for linea in lineas_unicas:
                self.wordlist_text.insert(tk.END, f"{linea}\n")
            
            self.wordlist_text.config(state=tk.DISABLED)
            messagebox.showinfo("Exito", f"Duplicados eliminados. {len(lineas_unicas)} entradas unicas")
        except Exception as e:
            messagebox.showerror("Error", f"Error al filtrar: {str(e)}")
    
    def validar_formato(self):
        try:
            contenido = self.wordlist_text.get(1.0, tk.END)
            lineas = contenido.strip().split('\n')
            
            validas = 0
            invalidas = 0
            
            for linea in lineas:
                if linea.strip() and len(linea.strip()) > 0:
                    validas += 1
                else:
                    invalidas += 1
            
            mensaje = f"Entradas validas: {validas}\nEntradas invalidas: {invalidas}"
            messagebox.showinfo("Validacion de Formato", mensaje)
        except Exception as e:
            messagebox.showerror("Error", f"Error al validar: {str(e)}")
    
    def guardar_wordlist(self):
        try:
            contenido = self.wordlist_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay wordlist para guardar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Guardar Wordlist",
                defaultextension=".txt",
                filetypes=[
                    ("Archivos de texto", "*.txt"),
                    ("Todos los archivos", "*.*")
                ]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(contenido)
                messagebox.showinfo("Exito", f"Wordlist guardada en {archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def limpiar_wordlist(self):
        self.wordlist_text.config(state=tk.NORMAL)
        self.wordlist_text.delete(1.0, tk.END)
        self.wordlist_text.config(state=tk.DISABLED)
    
    def cancelar_wordlist(self):
        """Cancelar la generación de wordlist en curso."""
        if self.proceso_wordlist_activo:
            self.proceso_wordlist_activo = False
            self.wordlist_text.config(state=tk.NORMAL)
            self.wordlist_text.insert(tk.END, "\n⚠️ Generación de wordlist cancelada por el usuario.\n")
            self.wordlist_text.config(state=tk.DISABLED)
            self._finalizar_proceso_wordlist()
    
    def _habilitar_cancelar_wordlist(self, habilitar):
        """Habilitar o deshabilitar botón de cancelar wordlist."""
        estado = "normal" if habilitar else "disabled"
        if hasattr(self, 'btn_cancelar_wordlist'):
            self.btn_cancelar_wordlist.config(state=estado)
    
    def _finalizar_proceso_wordlist(self):
        """Finalizar proceso de wordlist."""
        self.proceso_wordlist_activo = False
        self._habilitar_cancelar_wordlist(False)
        self.thread_wordlist = None
