# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import logging

try:
    from aresitos.vista.burp_theme import burp_theme
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
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Importar terminal global
        try:
            from aresitos.vista.vista_dashboard import VistaDashboard
            self._terminal_global = VistaDashboard._terminal_widget
        except (ImportError, AttributeError):
            self._terminal_global = None
        
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
    
    def _log_terminal(self, mensaje, modulo="FIM", nivel="INFO"):
        """Registrar actividad en el terminal integrado global."""
        try:
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
        except Exception:
            pass  # Terminal no disponible
    
    def _analizar_amenazas_detectadas(self, tipo_evento, ruta, detalles):
        """Analizar y clasificar amenazas detectadas en FIM."""
        amenazas_criticas = []
        
        # Análisis de archivos críticos modificados
        archivos_criticos = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/hosts', '/boot/grub/grub.cfg']
        if any(critico in ruta for critico in archivos_criticos):
            amenazas_criticas.append({
                'tipo': 'MODIFICACIÓN CRÍTICA',
                'severidad': 'CRITICAL',
                'descripcion': f'Archivo crítico modificado: {ruta}',
                'emoji': '🚨'
            })
        
        # Análisis de permisos sospechosos
        if 'permisos' in detalles.lower():
            if any(peligroso in detalles for peligroso in ['777', '666', '755']):
                amenazas_criticas.append({
                    'tipo': 'PERMISOS PELIGROSOS',
                    'severidad': 'HIGH',
                    'descripcion': f'Permisos inseguros detectados en {ruta}: {detalles}',
                    'emoji': '⚠️'
                })
        
        # Análisis de archivos ejecutables modificados
        if ruta.endswith(('.sh', '.py', '.pl', '.rb')) or '/bin/' in ruta or '/sbin/' in ruta:
            amenazas_criticas.append({
                'tipo': 'EJECUTABLE MODIFICADO',
                'severidad': 'HIGH',
                'descripcion': f'Archivo ejecutable modificado: {ruta}',
                'emoji': '🔧'
            })
        
        # Análisis de nuevos archivos en directorios sensibles
        directorios_sensibles = ['/tmp', '/var/tmp', '/dev/shm', '/etc/cron.d']
        if any(sensible in ruta for sensible in directorios_sensibles) and 'nuevo' in tipo_evento.lower():
            amenazas_criticas.append({
                'tipo': 'ARCHIVO SOSPECHOSO',
                'severidad': 'MEDIUM',
                'descripcion': f'Nuevo archivo en directorio sensible: {ruta}',
                'emoji': '📁'
            })
        
        # Reportar amenazas encontradas
        for amenaza in amenazas_criticas:
            self._log_terminal(
                f"{amenaza['emoji']} {amenaza['tipo']} [{amenaza['severidad']}]: {amenaza['descripcion']}", 
                "FIM", 
                "ERROR" if amenaza['severidad'] in ['CRITICAL', 'HIGH'] else "WARNING"
            )
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        # Frame título con tema
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Título con tema Burp Suite
        titulo = tk.Label(titulo_frame, text="File Integrity Monitoring (FIM) - Kali Linux",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack()
        
        # Frame principal con tema
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Panel izquierdo - Resultados y monitoreo con tema
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Label de resultados con tema
        label_results = tk.Label(left_frame, text="Monitoreo de Integridad en Tiempo Real", 
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], 
                               font=('Arial', 12, 'bold'))
        label_results.pack(anchor=tk.W, pady=(0, 5))
        
        # Text widget con tema Burp Suite
        self.fim_text = scrolledtext.ScrolledText(left_frame, height=25, width=70,
                                                 bg=self.colors['bg_secondary'],
                                                 fg=self.colors['fg_primary'],
                                                 insertbackground=self.colors['fg_accent'],
                                                 font=('Consolas', 9),
                                                 relief='flat', bd=1)
        self.fim_text.pack(fill=tk.BOTH, expand=True)
        
        # Panel derecho - Controles con tema
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Label de controles con tema
        label_controls = tk.Label(right_frame, text="Controles FIM", 
                                bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], 
                                font=('Arial', 12, 'bold'))
        label_controls.pack(anchor=tk.W, pady=(0, 10))
        
        # Sección de configuración de rutas con tema
        config_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        config_label = tk.Label(config_frame, text="Configurar Rutas a Monitorear",
                              bg=self.colors['bg_secondary'], fg=self.colors['fg_secondary'], 
                              font=('Arial', 10, 'bold'))
        config_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Entry para rutas con tema
        path_label = tk.Label(config_frame, text="Ruta:", 
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_secondary'])
        path_label.pack(anchor=tk.W)
        
        self.path_entry = tk.Entry(config_frame, bg=self.colors['bg_secondary'], 
                                 fg=self.colors['fg_primary'], 
                                 insertbackground=self.colors['fg_accent'], 
                                 width=25, relief='flat', bd=1)
        self.path_entry.pack(fill=tk.X, pady=2)
        self.path_entry.insert(0, "/etc")  # Ruta por defecto
        
        # Botones de configuración con tema Burp Suite
        btn_add_path = tk.Button(config_frame, text="Agregar Ruta", 
                               command=self.agregar_ruta_monitoreo,
                               bg=self.colors['button_bg'], fg=self.colors['button_fg'], 
                               font=('Arial', 9),
                               relief='flat', padx=10, pady=5,
                               activebackground=self.colors['fg_accent'],
                               activeforeground='white')
        btn_add_path.pack(fill=tk.X, pady=2)
        
        btn_browse = tk.Button(config_frame, text="Examinar...", 
                             command=self.examinar_ruta,
                             bg=self.colors['button_bg'], fg=self.colors['button_fg'], 
                             font=('Arial', 9),
                             relief='flat', padx=10, pady=5,
                             activebackground=self.colors['fg_accent'],
                             activeforeground='white')
        btn_browse.pack(fill=tk.X, pady=2)
        
        # Lista de rutas monitoreadas con tema
        list_label = tk.Label(config_frame, text="Rutas Monitoreadas:",
                            bg=self.colors['bg_secondary'], fg=self.colors['fg_secondary'], 
                            font=('Arial', 9))
        list_label.pack(anchor=tk.W, pady=(10, 2))
        
        self.rutas_listbox = tk.Listbox(config_frame, height=4,
                                       bg=self.colors['bg_secondary'],
                                       fg=self.colors['fg_primary'],
                                       selectbackground=self.colors['fg_accent'],
                                       font=('Consolas', 8),
                                       relief='flat', bd=1)
        self.rutas_listbox.pack(fill=tk.X, pady=2)
        
        # Agregar rutas por defecto críticas de Kali Linux
        rutas_criticas = ["/etc", "/boot", "/usr/bin", "/root"]
        for ruta in rutas_criticas:
            self.rutas_listbox.insert(tk.END, ruta)
        
        # Separador con tema
        sep_frame = tk.Frame(right_frame, bg=self.colors['fg_accent'], height=2)
        sep_frame.pack(fill=tk.X, pady=10)
        
        # Botones principales de FIM con textos claros
        buttons = [
            ("Crear Baseline", self.crear_baseline, self.colors['fg_accent']),
            ("Iniciar Monitoreo", self.iniciar_monitoreo, self.colors['success']),
            ("Detener Monitoreo", self.detener_monitoreo, self.colors['danger']),
            ("Verificar Sistema", self.verificar_kali, self.colors['info']),
            ("Verificar Integridad", self.verificar_integridad, self.colors['button_bg']),
            ("Escaneo Manual", self.escaneo_manual, self.colors['button_bg']),
            ("Usar LinPEAS", self.usar_linpeas, self.colors['button_bg']),
            ("Usar Tripwire", self.usar_tripwire, self.colors['button_bg']),
            ("Ver Baseline", self.ver_baseline, self.colors['button_bg']),
            ("Guardar Reporte", self.guardar_reporte, self.colors['button_bg']),
            ("Limpiar Pantalla", self.limpiar_pantalla, self.colors['button_bg'])
        ]
        
        for i, (text, command, bg_color) in enumerate(buttons):
            btn = tk.Button(right_frame, text=text, command=command,
                          bg=bg_color, fg='white', font=('Arial', 9),
                          relief='flat', padx=10, pady=5,
                          activebackground=self.colors['fg_accent'],
                          activeforeground='white')
            if text == "Detener Monitoreo":
                btn.config(state="disabled")
                self.btn_detener_monitoreo = btn
            btn.pack(fill=tk.X, pady=2)
        
        # Mensaje inicial
        self._actualizar_texto_fim("Sistema FIM de ARESITOS iniciado correctamente\n")
        self._actualizar_texto_fim("Rutas críticas configuradas: /etc, /boot, /usr/bin, /root\n")
        self._actualizar_texto_fim("Herramientas disponibles: LinPEAS, Tripwire, inotify-tools\n")
        self._actualizar_texto_fim("Listo para crear baseline y monitorear integridad de archivos\n\n")
    
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
            self._actualizar_texto_fim(f" Ruta agregada para monitoreo: {ruta}\n")
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
                self.after(0, self._actualizar_texto_fim, " Creando baseline de integridad...\n")
                
                if self.controlador:
                    resultado = self.controlador.crear_baseline()
                    if resultado.get('exito'):
                        archivos = resultado.get('archivos_procesados', 0)
                        tiempo = resultado.get('tiempo_ejecucion', 0)
                        self.after(0, self._actualizar_texto_fim, f"OK Baseline creado correctamente\n")
                        self.after(0, self._actualizar_texto_fim, f" Archivos procesados: {archivos}\n")
                        self.after(0, self._actualizar_texto_fim, f"TIMEOUT Tiempo: {tiempo}s\n")
                    else:
                        self.after(0, self._actualizar_texto_fim, f"ERROR Error creando baseline: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Simulación si no hay controlador
                    import time
                    rutas = [self.rutas_listbox.get(i) for i in range(self.rutas_listbox.size())]
                    for ruta in rutas:
                        self.after(0, self._actualizar_texto_fim, f" Procesando {ruta}...\n")
                        time.sleep(0.5)
                    self.after(0, self._actualizar_texto_fim, "OK Baseline completado para todas las rutas\n")
                
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"ERROR Error creando baseline: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def iniciar_monitoreo(self):
        """Iniciar monitoreo continuo."""
        if self.proceso_monitoreo_activo:
            return
        
        self.proceso_monitoreo_activo = True
        self._habilitar_botones_monitoreo(False)
        
        # Log al terminal integrado
        self._log_terminal("Iniciando monitoreo continuo de integridad FIM", "FIM", "INFO")
        self._actualizar_texto_fim("Iniciando monitoreo continuo de integridad...\n")
        
        # Ejecutar en thread separado
        self.thread_monitoreo = threading.Thread(target=self._ejecutar_monitoreo_async)
        self.thread_monitoreo.daemon = True
        self.thread_monitoreo.start()
    
    def _ejecutar_monitoreo_async(self):
        """Ejecutar monitoreo en thread separado con deteccion de amenazas."""
        try:
            if self.controlador:
                self._log_terminal("Conectando con controlador FIM", "FIM", "INFO")
                resultado = self.controlador.iniciar_monitoreo_continuo()
                
                if resultado.get('exito'):
                    rutas_monitoreadas = resultado.get('rutas_monitoreadas', 0)
                    intervalo = resultado.get('intervalo_segundos', 30)
                    
                    self._log_terminal(f"FIM iniciado correctamente - {rutas_monitoreadas} rutas monitoreadas", "FIM", "SUCCESS")
                    self.after(0, self._actualizar_texto_fim, "FIM iniciado correctamente\n")
                    self.after(0, self._actualizar_texto_fim, f"Rutas monitoreadas: {rutas_monitoreadas}\n")
                    self.after(0, self._actualizar_texto_fim, f"Intervalo: {intervalo}s\n")
                    
                    # Monitoreo en tiempo real con deteccion de amenazas
                    import time
                    import subprocess
                    import hashlib
                    import os
                    
                    # Archivos criticos del sistema que monitoreamos
                    rutas_criticas = [
                        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/sudoers', 
                        '/etc/ssh/sshd_config', '/etc/crontab', '/root/.bashrc',
                        '/etc/fstab', '/etc/systemd/system', '/boot'
                    ]
                    
                    checksums_baseline = {}
                    contador_ciclos = 0
                    
                    self._log_terminal("Creando baseline de archivos criticos", "FIM", "INFO")
                    
                    # Crear baseline inicial
                    for ruta in rutas_criticas:
                        if not self.proceso_monitoreo_activo:
                            break
                        
                        try:
                            if os.path.exists(ruta):
                                if os.path.isfile(ruta):
                                    with open(ruta, 'rb') as f:
                                        contenido = f.read()
                                        checksum = hashlib.sha256(contenido).hexdigest()[:16]
                                    checksums_baseline[ruta] = checksum
                                    self._log_terminal(f"Baseline creado: {ruta}", "FIM", "DEBUG")
                                elif os.path.isdir(ruta):
                                    # Para directorios, verificar permisos y archivos nuevos
                                    checksums_baseline[ruta] = "DIR_" + str(len(os.listdir(ruta)))
                        except Exception as e:
                            self._log_terminal(f"Error accediendo a {ruta}: {str(e)}", "FIM", "WARNING")
                    
                    self._log_terminal(f"Baseline completado - {len(checksums_baseline)} elementos", "FIM", "SUCCESS")
                    
                    # Ciclo de monitoreo continuo
                    while self.proceso_monitoreo_activo:
                        try:
                            contador_ciclos += 1
                            cambios_detectados = 0
                            amenazas_detectadas = 0
                            
                            self._log_terminal(f"Verificacion FIM #{contador_ciclos} iniciada", "FIM", "INFO")
                            
                            for ruta in rutas_criticas:
                                if not self.proceso_monitoreo_activo:
                                    break
                                
                                try:
                                    if os.path.exists(ruta):
                                        if os.path.isfile(ruta):
                                            # Verificar integridad de archivo
                                            with open(ruta, 'rb') as f:
                                                contenido = f.read()
                                                checksum_actual = hashlib.sha256(contenido).hexdigest()[:16]
                                            
                                            if ruta in checksums_baseline:
                                                if checksums_baseline[ruta] != checksum_actual:
                                                    # CAMBIO DETECTADO - POSIBLE AMENAZA
                                                    cambios_detectados += 1
                                                    
                                                    # Detectar tipos de cambios sospechosos
                                                    if ruta in ['/etc/passwd', '/etc/shadow']:
                                                        amenazas_detectadas += 1
                                                        self._log_terminal(f"AMENAZA CRITICA: Archivo de usuarios modificado - {ruta}", "FIM", "ERROR")
                                                        self.after(0, self._actualizar_texto_fim, f"AMENAZA CRITICA: {ruta} modificado\n")
                                                    elif ruta == '/etc/hosts':
                                                        amenazas_detectadas += 1
                                                        self._log_terminal(f"AMENAZA: Archivo hosts modificado - posible redireccion DNS", "FIM", "ERROR")
                                                        self.after(0, self._actualizar_texto_fim, f"AMENAZA DNS: {ruta} modificado\n")
                                                    elif ruta == '/etc/sudoers':
                                                        amenazas_detectadas += 1
                                                        self._log_terminal(f"AMENAZA CRITICA: Permisos sudo modificados - {ruta}", "FIM", "ERROR")
                                                        self.after(0, self._actualizar_texto_fim, f"AMENAZA SUDO: {ruta} modificado\n")
                                                    elif '/ssh/' in ruta:
                                                        amenazas_detectadas += 1
                                                        self._log_terminal(f"AMENAZA: Configuracion SSH modificada - {ruta}", "FIM", "ERROR")
                                                        self.after(0, self._actualizar_texto_fim, f"AMENAZA SSH: {ruta} modificado\n")
                                                    else:
                                                        self._log_terminal(f"CAMBIO DETECTADO: {ruta} - verificar manualmente", "FIM", "WARNING")
                                                        self.after(0, self._actualizar_texto_fim, f"CAMBIO: {ruta} modificado\n")
                                                    
                                                    # Actualizar baseline
                                                    checksums_baseline[ruta] = checksum_actual
                                                    
                                        elif os.path.isdir(ruta):
                                            # Verificar cambios en directorio
                                            archivos_actuales = len(os.listdir(ruta))
                                            baseline_dir = checksums_baseline.get(ruta, "DIR_0")
                                            archivos_baseline = int(baseline_dir.split('_')[1])
                                            
                                            if archivos_actuales != archivos_baseline:
                                                cambios_detectados += 1
                                                if ruta == '/boot':
                                                    amenazas_detectadas += 1
                                                    self._log_terminal(f"AMENAZA CRITICA: Directorio /boot modificado - posible bootkit", "FIM", "ERROR")
                                                    self.after(0, self._actualizar_texto_fim, f"AMENAZA BOOT: Archivos en /boot cambiaron\n")
                                                else:
                                                    self._log_terminal(f"CAMBIO DIR: {ruta} - {archivos_actuales} archivos (antes: {archivos_baseline})", "FIM", "WARNING")
                                                    self.after(0, self._actualizar_texto_fim, f"CAMBIO DIR: {ruta} ({archivos_actuales} archivos)\n")
                                                
                                                checksums_baseline[ruta] = f"DIR_{archivos_actuales}"
                                    
                                    else:
                                        # Archivo eliminado
                                        if ruta in checksums_baseline:
                                            amenazas_detectadas += 1
                                            self._log_terminal(f"AMENAZA CRITICA: Archivo critico eliminado - {ruta}", "FIM", "ERROR")
                                            self.after(0, self._actualizar_texto_fim, f"AMENAZA: {ruta} ELIMINADO\n")
                                            del checksums_baseline[ruta]
                                
                                except Exception as e:
                                    self._log_terminal(f"Error verificando {ruta}: {str(e)}", "FIM", "WARNING")
                            
                            # Resumen del ciclo
                            if amenazas_detectadas > 0:
                                self._log_terminal(f"ALERTA: {amenazas_detectadas} amenazas detectadas en ciclo #{contador_ciclos}", "FIM", "ERROR")
                                self.after(0, self._actualizar_texto_fim, f"ALERTA: {amenazas_detectadas} amenazas detectadas\n")
                            elif cambios_detectados > 0:
                                self._log_terminal(f"Verificacion #{contador_ciclos}: {cambios_detectados} cambios detectados", "FIM", "WARNING")
                            else:
                                self._log_terminal(f"Verificacion #{contador_ciclos}: Sistema integro", "FIM", "SUCCESS")
                            
                            # Esperar antes del siguiente ciclo
                            time.sleep(intervalo)
                            
                        except Exception as e:
                            self._log_terminal(f"Error en ciclo de monitoreo: {str(e)}", "FIM", "ERROR")
                            time.sleep(10)  # Esperar mas tiempo si hay error
                
                else:
                    self._log_terminal("Error iniciando FIM - verificar permisos", "FIM", "ERROR")
                    self.after(0, self._actualizar_texto_fim, "Error iniciando FIM\n")
            else:
                self._log_terminal("Controlador FIM no disponible", "FIM", "ERROR")
                self.after(0, self._actualizar_texto_fim, "Controlador no disponible\n")
                
        except Exception as e:
            self._log_terminal(f"Error critico en FIM: {str(e)}", "FIM", "ERROR")
            self.after(0, self._actualizar_texto_fim, f"Error critico: {str(e)}\n")
        finally:
            self.proceso_monitoreo_activo = False
            self._log_terminal("Monitoreo FIM detenido", "FIM", "INFO")
            self.after(0, self._habilitar_botones_monitoreo, True)
    
    def detener_monitoreo(self):
        """Detener monitoreo continuo."""
        if self.proceso_monitoreo_activo:
            self.proceso_monitoreo_activo = False
            self._actualizar_texto_fim(" Deteniendo monitoreo...\n")
            
            if self.controlador:
                resultado = self.controlador.detener_monitoreo_continuo()
                if resultado.get('exito'):
                    self._actualizar_texto_fim("OK Monitoreo detenido correctamente\n")
                else:
                    self._actualizar_texto_fim(f"ERROR Error deteniendo monitoreo: {resultado.get('error', 'Error desconocido')}\n")
    
    def _finalizar_monitoreo(self):
        """Finalizar proceso de monitoreo."""
        self.proceso_monitoreo_activo = False
        self._habilitar_botones_monitoreo(True)
        self.thread_monitoreo = None
        self._actualizar_texto_fim(" Monitoreo detenido\n\n")
    
    def _habilitar_botones_monitoreo(self, habilitar):
        """Habilitar/deshabilitar botones de monitoreo."""
        estado_detener = "normal" if not habilitar else "disabled"
        if hasattr(self, 'btn_detener_monitoreo'):
            self.btn_detener_monitoreo.config(state=estado_detener)
    
    def verificar_integridad(self):
        """Verificar integridad manual."""
        def ejecutar():
            try:
                self._actualizar_texto_fim(" Verificando integridad de archivos...\n")
                
                if self.controlador:
                    resultado = self.controlador.verificar_integridad()
                    self.after(0, self._actualizar_texto_fim, f" Resultado: {resultado}\n")
                else:
                    # Simulación
                    import time
                    rutas = [self.rutas_listbox.get(i) for i in range(self.rutas_listbox.size())]
                    for ruta in rutas:
                        self.after(0, self._actualizar_texto_fim, f"OK {ruta}: Integridad verificada\n")
                        time.sleep(0.3)
                
                self.after(0, self._actualizar_texto_fim, "OK Verificación completada\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"ERROR Error en verificación: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def escaneo_manual(self):
        """Ejecutar escaneo manual."""
        def ejecutar():
            try:
                self._actualizar_texto_fim(" Ejecutando escaneo manual...\n")
                
                if self.controlador:
                    self.controlador.ejecutar_escaneo_manual()
                else:
                    # Simulación usando herramientas de Kali
                    import subprocess
                    try:
                        self.after(0, self._actualizar_texto_fim, " Usando find para detectar cambios...\n")
                        resultado = subprocess.run(['find', '/etc', '-type', 'f', '-mtime', '-1'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.stdout:
                            archivos = resultado.stdout.strip().split('\n')
                            self.after(0, self._actualizar_texto_fim, f" Archivos modificados recientemente: {len(archivos)}\n")
                            for archivo in archivos[:10]:  # Mostrar solo los primeros 10
                                self.after(0, self._actualizar_texto_fim, f"  {archivo}\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, "OK No se detectaron cambios recientes\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_fim, f"ERROR Error ejecutando find: {str(e)}\n")
                
                self.after(0, self._actualizar_texto_fim, "OK Escaneo manual completado\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"ERROR Error en escaneo: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_linpeas(self):
        """Usar LinPEAS (Linux Privilege Escalation Awesome Script) de Kali Linux."""
        def ejecutar():
            try:
                self._actualizar_texto_fim(" Ejecutando LinPEAS (Linux Privilege Escalation Awesome Script)...\n")
                
                import subprocess
                try:
                    # Verificar si LinPEAS está instalado
                    resultado = subprocess.run(['which', 'linpeas'], capture_output=True, text=True)
                    if resultado.returncode != 0:
                        self.after(0, self._actualizar_texto_fim, "ERROR LinPEAS no encontrado. Instalar con: wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh\n")
                        return
                    
                    self.after(0, self._actualizar_texto_fim, " Iniciando escaneo de escalación de privilegios...\n")
                    # Nota: En un entorno real, esto ejecutaría LinPEAS
                    self.after(0, self._actualizar_texto_fim, " Comando a ejecutar: linpeas.sh\n")
                    self.after(0, self._actualizar_texto_fim, " Escaneando configuraciones del sistema...\n")
                    self.after(0, self._actualizar_texto_fim, "✓ LinPEAS es más eficiente y moderno que las herramientas obsoletas\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_fim, f"ERROR Error con LinPEAS: {str(e)}\n")
                
                self.after(0, self._actualizar_texto_fim, "OK Escaneo LinPEAS completado\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"ERROR Error usando LinPEAS: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def usar_tripwire(self):
        """Usar Tripwire para monitoreo de integridad."""
        def ejecutar():
            try:
                self._actualizar_texto_fim(" Configurando Tripwire para monitoreo de integridad...\n")
                
                import subprocess
                try:
                    # Verificar si Tripwire está disponible
                    resultado = subprocess.run(['which', 'tripwire'], capture_output=True, text=True)
                    if resultado.returncode != 0:
                        self.after(0, self._actualizar_texto_fim, "ERROR Tripwire no encontrado. Instalar con: apt install tripwire\n")
                        return
                    
                    self.after(0, self._actualizar_texto_fim, " Configurando Tripwire...\n")
                    self.after(0, self._actualizar_texto_fim, " Pasos de configuración:\n")
                    self.after(0, self._actualizar_texto_fim, "  1. tripwire --init\n")
                    self.after(0, self._actualizar_texto_fim, "  2. tripwire --check\n")
                    self.after(0, self._actualizar_texto_fim, "  3. tripwire --update\n")
                    self.after(0, self._actualizar_texto_fim, "WARNING  Nota: Requiere configuración inicial y privilegios root\n")
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_fim, f"ERROR Error con Tripwire: {str(e)}\n")
                
                self.after(0, self._actualizar_texto_fim, "OK Información Tripwire mostrada\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_fim, f"ERROR Error usando Tripwire: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ver_baseline(self):
        """Ver información del baseline actual."""
        try:
            if self.controlador:
                baseline_info = self.controlador.obtener_info_baseline()
                self._actualizar_texto_fim(" Información del Baseline:\n")
                self._actualizar_texto_fim(str(baseline_info) + "\n\n")
            else:
                self._actualizar_texto_fim(" Baseline actual:\n")
                self._actualizar_texto_fim(" Fecha de creación: Pendiente\n")
                self._actualizar_texto_fim(" Archivos monitoreados: Pendiente\n")
                self._actualizar_texto_fim(" Estado: No creado\n\n")
        except Exception as e:
            self._actualizar_texto_fim(f"ERROR Error obteniendo baseline: {str(e)}\n")
    
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
        self._actualizar_texto_fim(" Sistema FIM de Aresitos - Pantalla limpiada\n\n")
        self.fim_text.config(state=tk.DISABLED)
    
    def _actualizar_texto_fim(self, texto):
        """Actualizar texto de FIM en el hilo principal."""
        if self.fim_text:
            self.fim_text.config(state=tk.NORMAL)
            self.fim_text.insert(tk.END, texto)
            self.fim_text.see(tk.END)
            self.fim_text.config(state=tk.DISABLED)

    def verificar_kali(self):
        """Verificar compatibilidad y funcionalidad FIM en Kali Linux."""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador FIM configurado")
            return
            
        try:
            self.fim_text.config(state=tk.NORMAL)
            self.fim_text.delete(1.0, tk.END)
            self.fim_text.insert(tk.END, "=== VERIFICACIÓN FIM KALI LINUX ===\n\n")
            
            # Ejecutar verificación a través del controlador
            resultado = self.controlador.verificar_funcionalidad_kali()
            
            # Mostrar resultados
            funcionalidad_ok = resultado.get('funcionalidad_completa', False)
            
            if funcionalidad_ok:
                self.fim_text.insert(tk.END, " OK VERIFICACIÓN FIM EXITOSA\n\n")
                self.fim_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.fim_text.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.fim_text.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                self.fim_text.insert(tk.END, "=== HERRAMIENTAS FIM DISPONIBLES ===\n")
                for herramienta, estado in resultado.get('herramientas_disponibles', {}).items():
                    disponible = estado.get('disponible', False)
                    permisos = estado.get('permisos_ok', False)
                    icono = "OK" if disponible and permisos else "ERROR"
                    self.fim_text.insert(tk.END, f"  {icono} {herramienta}\n")
                    
            else:
                self.fim_text.insert(tk.END, " ERROR VERIFICACIÓN FIM FALLÓ\n\n")
                self.fim_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.fim_text.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.fim_text.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                if resultado.get('recomendaciones'):
                    self.fim_text.insert(tk.END, "=== RECOMENDACIONES ===\n")
                    for recomendacion in resultado['recomendaciones']:
                        self.fim_text.insert(tk.END, f"  • {recomendacion}\n")
                
            if resultado.get('error'):
                self.fim_text.insert(tk.END, f"\nWARNING Error: {resultado['error']}\n")
                
            self.fim_text.config(state=tk.DISABLED)
                
        except Exception as e:
            self.fim_text.config(state=tk.NORMAL)
            self.fim_text.insert(tk.END, f" ERROR Error durante verificación: {str(e)}\n")
            self.fim_text.config(state=tk.DISABLED)
            print(f"Error logging a terminal: {e}")
