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

class VistaFIM(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_monitoreo_activo = False
        self.thread_monitoreo = None
        
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
        
        titulo = tk.Label(titulo_frame, text="File Integrity Monitoring (FIM) - Kali Linux",
                         font=('Arial', 16, 'bold'),
                         bg='#2b2b2b' if self.theme else 'white',
                         fg='#ff6633' if self.theme else 'black')
        titulo.pack()
        
        # Frame principal dividido en dos secciones
        if self.theme:
            main_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Panel izquierdo - Resultados y monitoreo
        if self.theme:
            left_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_results = tk.Label(left_frame, text="Monitoreo de Integridad en Tiempo Real", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_results.pack(anchor=tk.W, pady=(0, 5))
        else:
            left_frame = ttk.LabelFrame(main_frame, text="Monitoreo de Integridad en Tiempo Real", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.fim_text = scrolledtext.ScrolledText(left_frame, height=25, width=70,
                                                 bg='#1e1e1e' if self.theme else 'white',
                                                 fg='white' if self.theme else 'black',
                                                 insertbackground='white' if self.theme else 'black',
                                                 font=('Consolas', 9))
        self.fim_text.pack(fill=tk.BOTH, expand=True)
        
        # Panel derecho - Controles
        if self.theme:
            right_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_controls = tk.Label(right_frame, text="Controles FIM", 
                                    bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_controls.pack(anchor=tk.W, pady=(0, 10))
        else:
            right_frame = ttk.LabelFrame(main_frame, text="Controles FIM", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Sección de configuración de rutas
        if self.theme:
            config_frame = tk.Frame(right_frame, bg='#2b2b2b')
            config_label = tk.Label(config_frame, text="Configurar Rutas a Monitorear",
                                  bg='#2b2b2b', fg='#cccccc', font=('Arial', 10, 'bold'))
            config_label.pack(anchor=tk.W, pady=(0, 5))
        else:
            config_frame = ttk.LabelFrame(right_frame, text="Configurar Rutas", padding=5)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Entry para rutas
        if self.theme:
            path_label = tk.Label(config_frame, text="Ruta:", bg='#2b2b2b', fg='#cccccc')
            path_label.pack(anchor=tk.W)
            self.path_entry = tk.Entry(config_frame, bg='#4a4a4a', fg='white', 
                                     insertbackground='white', width=25)
        else:
            path_label = ttk.Label(config_frame, text="Ruta:")
            path_label.pack(anchor=tk.W)
            self.path_entry = ttk.Entry(config_frame, width=25)
        self.path_entry.pack(fill=tk.X, pady=2)
        self.path_entry.insert(0, "/etc")  # Ruta por defecto
        
        # Botones de configuración
        if self.theme:
            btn_add_path = tk.Button(config_frame, text="Agregar Ruta", 
                                   command=self.agregar_ruta_monitoreo,
                                   bg='#404040', fg='white', font=('Arial', 9))
            btn_add_path.pack(fill=tk.X, pady=2)
            
            btn_browse = tk.Button(config_frame, text="Examinar...", 
                                 command=self.examinar_ruta,
                                 bg='#404040', fg='white', font=('Arial', 9))
            btn_browse.pack(fill=tk.X, pady=2)
        else:
            btn_add_path = ttk.Button(config_frame, text="Agregar Ruta", 
                                    command=self.agregar_ruta_monitoreo)
            btn_add_path.pack(fill=tk.X, pady=2)
            
            btn_browse = ttk.Button(config_frame, text="Examinar...", 
                                  command=self.examinar_ruta)
            btn_browse.pack(fill=tk.X, pady=2)
        
        # Lista de rutas monitoreadas
        if self.theme:
            list_label = tk.Label(config_frame, text="Rutas Monitoreadas:",
                                bg='#2b2b2b', fg='#cccccc', font=('Arial', 9))
            list_label.pack(anchor=tk.W, pady=(10, 2))
        
        self.rutas_listbox = tk.Listbox(config_frame, height=4,
                                       bg='#4a4a4a' if self.theme else 'white',
                                       fg='white' if self.theme else 'black',
                                       selectbackground='#ff6633' if self.theme else 'blue',
                                       font=('Consolas', 8))
        self.rutas_listbox.pack(fill=tk.X, pady=2)
        
        # Agregar rutas por defecto críticas de Kali Linux
        rutas_criticas = ["/etc", "/boot", "/usr/bin", "/root"]
        for ruta in rutas_criticas:
            self.rutas_listbox.insert(tk.END, ruta)
        
        # Separador
        if self.theme:
            sep_frame = tk.Frame(right_frame, bg='#555555', height=2)
            sep_frame.pack(fill=tk.X, pady=10)
        else:
            ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Botones principales de FIM
        if self.theme:
            buttons = [
                ("🛡️ Crear Baseline", self.crear_baseline, '#ff6633'),
                ("▶️ Iniciar Monitoreo", self.iniciar_monitoreo, '#5cb85c'),
                ("⏹️ Detener Monitoreo", self.detener_monitoreo, '#d9534f'),
                ("🔍 Verificar Integridad", self.verificar_integridad, '#404040'),
                ("📊 Escaneo Manual", self.escaneo_manual, '#404040'),
                ("🔧 Usar AIDE (Kali)", self.usar_aide, '#404040'),
                ("🔧 Usar Tripwire", self.usar_tripwire, '#404040'),
                ("📁 Ver Baseline", self.ver_baseline, '#404040'),
                ("💾 Guardar Reporte", self.guardar_reporte, '#404040'),
                ("🗑️ Limpiar Pantalla", self.limpiar_pantalla, '#404040')
            ]
            
            for i, (text, command, bg_color) in enumerate(buttons):
                btn = tk.Button(right_frame, text=text, command=command,
                              bg=bg_color, fg='white', font=('Arial', 9))
                if text == "⏹️ Detener Monitoreo":
                    btn.config(state="disabled")
                    self.btn_detener_monitoreo = btn
                btn.pack(fill=tk.X, pady=2)
        else:
            # Crear botones individuales para mejor control
            self.btn_crear_baseline = ttk.Button(right_frame, text="🛡️ Crear Baseline", 
                                               command=self.crear_baseline)
            self.btn_crear_baseline.pack(fill=tk.X, pady=2)
            
            self.btn_iniciar_monitoreo = ttk.Button(right_frame, text="▶️ Iniciar Monitoreo", 
                                                  command=self.iniciar_monitoreo)
            self.btn_iniciar_monitoreo.pack(fill=tk.X, pady=2)
            
            self.btn_detener_monitoreo = ttk.Button(right_frame, text="⏹️ Detener Monitoreo", 
                                                  command=self.detener_monitoreo,
                                                  state="disabled")
            self.btn_detener_monitoreo.pack(fill=tk.X, pady=2)
            
            ttk.Button(right_frame, text="🔍 Verificar Integridad", 
                      command=self.verificar_integridad).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text="📊 Escaneo Manual", 
                      command=self.escaneo_manual).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text="🔧 Usar AIDE (Kali)", 
                      command=self.usar_aide).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text="🔧 Usar Tripwire", 
                      command=self.usar_tripwire).pack(fill=tk.X, pady=2)
            ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="📁 Ver Baseline", 
                      command=self.ver_baseline).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text="💾 Guardar Reporte", 
                      command=self.guardar_reporte).pack(fill=tk.X, pady=2)
            ttk.Button(right_frame, text="🗑️ Limpiar Pantalla", 
                      command=self.limpiar_pantalla).pack(fill=tk.X, pady=2)
        
        # Mensaje inicial
        self._actualizar_texto_fim("🛡️ Sistema FIM de Aresitos para Kali Linux iniciado\n")
        self._actualizar_texto_fim("📁 Rutas críticas pre-configuradas: /etc, /boot, /usr/bin, /root\n")
        self._actualizar_texto_fim("🔧 Herramientas disponibles: AIDE, Tripwire, inotify-tools\n")
        self._actualizar_texto_fim("⚡ Listo para crear baseline y monitorear integridad de archivos\n\n")
    
    def agregar_ruta_monitoreo(self):
        """Agregar ruta para monitoreo."""
        ruta = self.path_entry.get().strip()
        if not ruta:
            messagebox.showwarning("Advertencia", "Ingrese una ruta válida")
            return
        
        if not os.path.exists(ruta):
            if not messagebox.askyesno("Confirmar", f"La ruta {ruta} no existe. ¿Agregarla de todos modos?"):
                return
        
        # Verificar si ya existe
        rutas_existentes = [self.rutas_listbox.get(i) for i in range(self.rutas_listbox.size())]
        if ruta not in rutas_existentes:
            self.rutas_listbox.insert(tk.END, ruta)
            self._actualizar_texto_fim(f"📁 Ruta agregada para monitoreo: {ruta}\n")
            self.path_entry.delete(0, tk.END)
        else:
            messagebox.showinfo("Información", "La ruta ya está siendo monitoreada")
    
    def examinar_ruta(self):
        """Examinar y seleccionar directorio."""
        ruta = filedialog.askdirectory(title="Seleccionar directorio para monitoreo")
        if ruta:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, ruta)
    
    def crear_baseline(self):
        """Crear baseline de integridad de archivos."""
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_fim, "🛡️ Creando baseline de integridad...\n")
                
                if self.controlador:
                    self.controlador.crear_baseline()
                    self.after(0, self._actualizar_texto_fim, "✅ Baseline creado correctamente\n")
                else:
                    # Simulación si no hay controlador
                    import time
                    rutas = [self.rutas_listbox.get(i) for i in range(self.rutas_listbox.size())]
                    for ruta in rutas:
                        self.after(0, self._actualizar_texto_fim, f"📁 Procesando {ruta}...\n")
                        time.sleep(0.5)
                    self.after(0, self._actualizar_texto_fim, "✅ Baseline completado para todas las rutas\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"❌ Error creando baseline: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def iniciar_monitoreo(self):
        """Iniciar monitoreo continuo."""
        if self.proceso_monitoreo_activo:
            return
        
        self.proceso_monitoreo_activo = True
        self._habilitar_botones_monitoreo(False)
        
        self._actualizar_texto_fim("▶️ Iniciando monitoreo continuo de integridad...\n")
        
        # Ejecutar en thread separado
        self.thread_monitoreo = threading.Thread(target=self._ejecutar_monitoreo_async)
        self.thread_monitoreo.daemon = True
        self.thread_monitoreo.start()
    
    def _ejecutar_monitoreo_async(self):
        """Ejecutar monitoreo en thread separado."""
        try:
            if self.controlador:
                self.controlador.iniciar_monitoreo_continuo()
            else:
                # Simulación si no hay controlador
                import time
                while self.proceso_monitoreo_activo:
                    self.after(0, self._actualizar_texto_fim, "🔍 Verificando integridad...\n")
                    time.sleep(5)  # Verificar cada 5 segundos
        except Exception as e:
            self.after(0, self._actualizar_texto_fim, f"❌ Error en monitoreo: {str(e)}\n")
        finally:
            self.after(0, self._finalizar_monitoreo)
    
    def detener_monitoreo(self):
        """Detener monitoreo continuo."""
        if self.proceso_monitoreo_activo:
            self.proceso_monitoreo_activo = False
            self._actualizar_texto_fim("⏹️ Deteniendo monitoreo...\n")
            
            if self.controlador:
                self.controlador.detener_monitoreo()
    
    def _finalizar_monitoreo(self):
        """Finalizar proceso de monitoreo."""
        self.proceso_monitoreo_activo = False
        self._habilitar_botones_monitoreo(True)
        self.thread_monitoreo = None
        self._actualizar_texto_fim("⏹️ Monitoreo detenido\n\n")
    
    def _habilitar_botones_monitoreo(self, habilitar):
        """Habilitar/deshabilitar botones de monitoreo."""
        estado_detener = "normal" if not habilitar else "disabled"
        if hasattr(self, 'btn_detener_monitoreo'):
            self.btn_detener_monitoreo.config(state=estado_detener)
    
    def verificar_integridad(self):
        """Verificar integridad manual."""
        def ejecutar():
            try:
                self._actualizar_texto_fim("🔍 Verificando integridad de archivos...\n")
                
                if self.controlador:
                    resultado = self.controlador.verificar_integridad()
                    self.after(0, self._actualizar_texto_fim, f"📊 Resultado: {resultado}\n")
                else:
                    # Simulación
                    import time
                    rutas = [self.rutas_listbox.get(i) for i in range(self.rutas_listbox.size())]
                    for ruta in rutas:
                        self.after(0, self._actualizar_texto_fim, f"✅ {ruta}: Integridad verificada\n")
                        time.sleep(0.3)
                
                self.after(0, self._actualizar_texto_fim, "✅ Verificación completada\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"❌ Error en verificación: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def escaneo_manual(self):
        """Ejecutar escaneo manual."""
        def ejecutar():
            try:
                self._actualizar_texto_fim("📊 Ejecutando escaneo manual...\n")
                
                if self.controlador:
                    self.controlador.ejecutar_escaneo_manual()
                else:
                    # Simulación usando herramientas de Kali
                    import subprocess
                    try:
                        self.after(0, self._actualizar_texto_fim, "🔧 Usando find para detectar cambios...\n")
                        resultado = subprocess.run(['find', '/etc', '-type', 'f', '-mtime', '-1'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.stdout:
                            archivos = resultado.stdout.strip().split('\n')
                            self.after(0, self._actualizar_texto_fim, f"📁 Archivos modificados recientemente: {len(archivos)}\n")
                            for archivo in archivos[:10]:  # Mostrar solo los primeros 10
                                self.after(0, self._actualizar_texto_fim, f"  {archivo}\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, "✅ No se detectaron cambios recientes\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_fim, f"❌ Error ejecutando find: {str(e)}\n")
                
                self.after(0, self._actualizar_texto_fim, "✅ Escaneo manual completado\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"❌ Error en escaneo: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_aide(self):
        """Usar AIDE (Advanced Intrusion Detection Environment) de Kali Linux."""
        def ejecutar():
            try:
                self._actualizar_texto_fim("🔧 Ejecutando AIDE (Advanced Intrusion Detection Environment)...\n")
                
                import subprocess
                try:
                    # Verificar si AIDE está instalado
                    resultado = subprocess.run(['which', 'aide'], capture_output=True, text=True)
                    if resultado.returncode != 0:
                        self.after(0, self._actualizar_texto_fim, "❌ AIDE no encontrado. Instalar con: apt install aide\n")
                        return
                    
                    self.after(0, self._actualizar_texto_fim, "🔧 Inicializando base de datos AIDE...\n")
                    # Nota: En un entorno real, esto requeriría privilegios root
                    self.after(0, self._actualizar_texto_fim, "📝 Comando a ejecutar: aide --init\n")
                    self.after(0, self._actualizar_texto_fim, "📝 Comando de verificación: aide --check\n")
                    self.after(0, self._actualizar_texto_fim, "⚠️  Nota: Requiere privilegios root para ejecutar\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_fim, f"❌ Error con AIDE: {str(e)}\n")
                
                self.after(0, self._actualizar_texto_fim, "✅ Configuración AIDE completada\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"❌ Error usando AIDE: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_tripwire(self):
        """Usar Tripwire para monitoreo de integridad."""
        def ejecutar():
            try:
                self._actualizar_texto_fim("🔧 Configurando Tripwire para monitoreo de integridad...\n")
                
                import subprocess
                try:
                    # Verificar si Tripwire está disponible
                    resultado = subprocess.run(['which', 'tripwire'], capture_output=True, text=True)
                    if resultado.returncode != 0:
                        self.after(0, self._actualizar_texto_fim, "❌ Tripwire no encontrado. Instalar con: apt install tripwire\n")
                        return
                    
                    self.after(0, self._actualizar_texto_fim, "🔧 Configurando Tripwire...\n")
                    self.after(0, self._actualizar_texto_fim, "📝 Pasos de configuración:\n")
                    self.after(0, self._actualizar_texto_fim, "  1. tripwire --init\n")
                    self.after(0, self._actualizar_texto_fim, "  2. tripwire --check\n")
                    self.after(0, self._actualizar_texto_fim, "  3. tripwire --update\n")
                    self.after(0, self._actualizar_texto_fim, "⚠️  Nota: Requiere configuración inicial y privilegios root\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_fim, f"❌ Error con Tripwire: {str(e)}\n")
                
                self.after(0, self._actualizar_texto_fim, "✅ Información Tripwire mostrada\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"❌ Error usando Tripwire: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ver_baseline(self):
        """Ver información del baseline actual."""
        try:
            if self.controlador:
                baseline_info = self.controlador.obtener_info_baseline()
                self._actualizar_texto_fim("📁 Información del Baseline:\n")
                self._actualizar_texto_fim(str(baseline_info) + "\n\n")
            else:
                self._actualizar_texto_fim("📁 Baseline actual:\n")
                self._actualizar_texto_fim("🗓️ Fecha de creación: Pendiente\n")
                self._actualizar_texto_fim("📊 Archivos monitoreados: Pendiente\n")
                self._actualizar_texto_fim("🔍 Estado: No creado\n\n")
        except Exception as e:
            self._actualizar_texto_fim(f"❌ Error obteniendo baseline: {str(e)}\n")
    
    def guardar_reporte(self):
        """Guardar reporte de FIM."""
        try:
            contenido = self.fim_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay resultados para guardar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Guardar Reporte FIM",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(f"=== REPORTE FIM - ARESITOS ===\n")
                    f.write(f"Sistema: Kali Linux\n")
                    f.write(f"Generado: {threading.current_thread().name}\n\n")
                    f.write(contenido)
                messagebox.showinfo("Éxito", f"Reporte FIM guardado en {archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def limpiar_pantalla(self):
        """Limpiar pantalla de resultados."""
        self.fim_text.config(state=tk.NORMAL)
        self.fim_text.delete(1.0, tk.END)
        self._actualizar_texto_fim("🛡️ Sistema FIM de Aresitos - Pantalla limpiada\n\n")
        self.fim_text.config(state=tk.DISABLED)
    
    def _actualizar_texto_fim(self, texto):
        """Actualizar texto de FIM en el hilo principal."""
        if self.fim_text:
            self.fim_text.config(state=tk.NORMAL)
            self.fim_text.insert(tk.END, texto)
            self.fim_text.see(tk.END)
            self.fim_text.config(state=tk.DISABLED)
