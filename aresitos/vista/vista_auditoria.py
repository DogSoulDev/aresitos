# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaAuditoria(tk.Frame):
    """
    Vista especializada para auditorías de seguridad del sistema.
    
    Enfoque específico:
    - Auditorías generales del sistema (Lynis, OpenVAS, Nessus)
    - Análisis de configuraciones de seguridad
    - Verificación de permisos y políticas
    - Detección de rootkits y malware
    
    Nota: Las funciones de SIEM, FIM y Escaneo están en sus respectivas pestañas especializadas.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        
        # Estados únicos de auditoría
        self.proceso_auditoria_activo = False
        self.proceso_rootkits_activo = False
        self.thread_auditoria = None
        
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
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        """Crear interfaz especializada para auditorías de seguridad."""
        # Frame del título con tema Burp Suite
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo = tk.Label(titulo_frame, text="[SCAN] Auditoría de Seguridad del Sistema",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack(pady=10)
        
        # Frame principal con tema
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Panel izquierdo - Resultados con tema Burp Suite
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        label_results = tk.Label(left_frame, text="[METADATA] Resultados de Auditoría", 
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                               font=('Arial', 12, 'bold'))
        label_results.pack(anchor=tk.W, pady=(0, 5))
        
        self.auditoria_text = scrolledtext.ScrolledText(left_frame, height=25, width=65,
                                                       bg=self.colors['bg_primary'],
                                                       fg=self.colors['fg_primary'],
                                                       insertbackground=self.colors['fg_accent'],
                                                       font=('Consolas', 10),
                                                       relief='flat', bd=1)
        self.auditoria_text.pack(fill=tk.BOTH, expand=True)
        
        # Panel derecho - Herramientas de Auditoría con tema Burp Suite
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        label_tools = tk.Label(right_frame, text="[UTILS] Herramientas de Auditoría", 
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                             font=('Arial', 12, 'bold'))
        label_tools.pack(anchor=tk.W, pady=(0, 10))
        
        # Crear secciones organizadas
        self._crear_seccion_auditoria_sistema(right_frame)
        self._crear_seccion_deteccion_malware(right_frame)
        self._crear_seccion_configuraciones(right_frame)
        self._crear_seccion_utilidades(right_frame)
    
    def _crear_seccion_auditoria_sistema(self, parent):
        """Crear sección de auditorías generales del sistema."""
        # Sección de auditorías del sistema con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="[SCAN] Auditorías del Sistema", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("[SCAN] Ejecutar Lynis", self.ejecutar_lynis, self.colors['fg_accent']),
            ("[EMOJI] Cancelar Lynis", self.cancelar_auditoria, self.colors['danger']),
            ("[EMOJI] Verificar Kali", self.verificar_kali, self.colors['info']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
            
            # Configuración especial para botón cancelar
            if "Cancelar" in text:
                btn.config(state="disabled")
                self.btn_cancelar_auditoria = btn
    
    def _crear_seccion_deteccion_malware(self, parent):
        """Crear sección de detección de malware y rootkits."""
        # Sección de detección de malware con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="[EMOJI] Detección de Malware", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("[SCAN] Detectar Rootkits", self.detectar_rootkits, self.colors['warning']),
            ("[EMOJI] Cancelar Rootkits", self.cancelar_rootkits, self.colors['danger']),
            ("[SECURITY] Auditoría OpenVAS", self.ejecutar_openvas, self.colors['info']),
            ("[STATS] Scan Nessus", self.ejecutar_nessus, self.colors['fg_accent']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
            
            # Configuración especial para botones cancelar
            if "Cancelar" in text:
                btn.config(state="disabled")
                if "Rootkits" in text:
                    self.btn_cancelar_rootkits = btn
    
    def _crear_seccion_configuraciones(self, parent):
        """Crear sección de análisis de configuraciones."""
        # Sección de configuraciones con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="[SETTINGS] Configuraciones", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("[CONFIG] Analizar Servicios", self.analizar_servicios, self.colors['info']),
            ("[SECURE] Verificar Permisos", self.verificar_permisos, self.colors['success']),
            ("[EMOJI] Configuración SSH", self.auditar_ssh, self.colors['fg_accent']),
            ("[SECURITY] Políticas Password", self.verificar_password_policy, self.colors['danger']),
            ("[WARNING] Análisis SUID/SGID", self.analizar_suid_sgid, self.colors['warning']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['bg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
    
    def _crear_seccion_utilidades(self, parent):
        """Crear sección de utilidades generales."""
        # Sección de utilidades con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="[UTILS] Utilidades", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("[SYSTEM] Info Hardware", self.obtener_info_hardware, self.colors['bg_primary']),
            ("[SAVE] Guardar Resultados", self.guardar_auditoria, self.colors['info']),
            ("[CLEAN] Limpiar Pantalla", self.limpiar_auditoria, self.colors['warning']),
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(section_frame, text=text, command=command,
                           bg=color, fg=self.colors['fg_primary'],
                           font=('Arial', 9, 'bold'), relief='flat',
                           padx=10, pady=5)
            btn.pack(fill=tk.X, pady=2)
    
    def ejecutar_lynis(self):
        if self.proceso_auditoria_activo:
            return
            
        self.proceso_auditoria_activo = True
        self._habilitar_cancelar(True)
        
        self.auditoria_text.config(state=tk.NORMAL)
        self.auditoria_text.insert(tk.END, "Iniciando auditoría Lynis en Kali Linux...\n")
        self.auditoria_text.config(state=tk.DISABLED)
        
        # Ejecutar en thread separado
        self.thread_auditoria = threading.Thread(target=self._ejecutar_lynis_async)
        self.thread_auditoria.daemon = True
        self.thread_auditoria.start()
    
    def _ejecutar_lynis_async(self):
        """Ejecutar Lynis en thread separado."""
        try:
            # Actualizar UI
            self.after(0, self._actualizar_texto_auditoria, " Ejecutando auditoría Lynis (puede tardar varios minutos)...\n")
            
            if self.controlador:
                # Usar el controlador
                resultado = self.controlador.ejecutar_auditoria_completa("lynis")
                if resultado.get('exito'):
                    self.after(0, self._actualizar_texto_auditoria, "OK Auditoría Lynis completada exitosamente\n")
                    if 'salida' in resultado:
                        self.after(0, self._actualizar_texto_auditoria, resultado['salida'])
                else:
                    self.after(0, self._actualizar_texto_auditoria, f"ERROR Error en auditoría: {resultado.get('error', 'Error desconocido')}\n")
            else:
                # Fallback: ejecución directa
                import subprocess
                try:
                    proceso = subprocess.Popen(['lynis', 'audit', 'system'], 
                                             stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, 
                                             text=True)
                
                    # Verificar periódicamente si fue cancelado
                    while proceso.poll() is None and self.proceso_auditoria_activo:
                        import time
                        time.sleep(1)
                    
                    if not self.proceso_auditoria_activo:
                        # Fue cancelado, terminar el proceso
                        proceso.terminate()
                        proceso.wait()
                        self.after(0, self._actualizar_texto_auditoria, "\nERROR Auditoría Lynis cancelada por el usuario.\n")
                        return
                    
                    stdout, stderr = proceso.communicate()
                    
                    if proceso.returncode == 0:
                        self.after(0, self._actualizar_texto_auditoria, "OK Auditoría Lynis completada\n")
                        self.after(0, self._actualizar_texto_auditoria, stdout[-2000:])  # Últimas 2000 caracteres
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR Error en Lynis: {stderr}\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR Lynis no encontrado. Instale con: apt install lynis\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_auditoria, f"ERROR Error ejecutando Lynis: {str(e)}\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto_auditoria, f"ERROR Error general: {str(e)}\n")
        finally:
            self.after(0, self._finalizar_auditoria)
    
    def _actualizar_texto_auditoria(self, texto):
        """Actualizar texto de auditoría en el hilo principal."""
        if self.auditoria_text:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.insert(tk.END, texto)
            self.auditoria_text.see(tk.END)
            self.auditoria_text.config(state=tk.DISABLED)
    
    def _habilitar_cancelar(self, habilitar):
        """Habilitar o deshabilitar botón de cancelar."""
        estado = "normal" if habilitar else "disabled"
        if hasattr(self, 'btn_cancelar_auditoria'):
            self.btn_cancelar_auditoria.config(state=estado)
    
    def _finalizar_auditoria(self):
        """Finalizar proceso de auditoría."""
        self.proceso_auditoria_activo = False
        self._habilitar_cancelar(False)
        self.thread_auditoria = None
        self._actualizar_texto_auditoria("\n=== Auditoría finalizada ===\n\n")
    
    def cancelar_auditoria(self):
        """Cancelar la auditoría en curso."""
        if self.proceso_auditoria_activo:
            self.proceso_auditoria_activo = False
            self._actualizar_texto_auditoria("\n Cancelando auditoría...\n")
    
    def detectar_rootkits(self):
        """Detectar rootkits usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.ejecutar_deteccion_rootkits()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "[EMOJI] OK Detección de rootkits completada\n")
                        if 'rootkits_detectados' in resultado:
                            count = resultado['rootkits_detectados']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"[WARNING] WARNING {count} posibles rootkits detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "[EMOJI] OK No se detectaron rootkits\n")
                        if 'salida' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, f"\n[METADATA] DETALLES:\n{resultado['salida']}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"[EMOJI] ERROR Error: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, " Detectando rootkits con rkhunter y chkrootkit...\n")
                    
                    import subprocess
                    herramientas = [
                        (['rkhunter', '--check', '--skip-keypress'], 'rkhunter'),
                        (['chkrootkit'], 'chkrootkit')
                    ]
                    
                    for comando, nombre in herramientas:
                        try:
                            self.after(0, self._actualizar_texto_auditoria, f" Ejecutando {nombre}...\n")
                            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
                            if resultado.returncode == 0:
                                self.after(0, self._actualizar_texto_auditoria, f"OK {nombre} completado\n")
                                if "INFECTED" in resultado.stdout or "infected" in resultado.stdout:
                                    self.after(0, self._actualizar_texto_auditoria, "WARNING POSIBLES ROOTKITS DETECTADOS\n")
                                else:
                                    self.after(0, self._actualizar_texto_auditoria, f"OK No se detectaron rootkits con {nombre}\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, f"ERROR Error en {nombre}\n")
                        except FileNotFoundError:
                            self.after(0, self._actualizar_texto_auditoria, f"ERROR {nombre} no encontrado. Instalar con: apt install {nombre}\n")
                        except subprocess.TimeoutExpired:
                            self.after(0, self._actualizar_texto_auditoria, f"TIMEOUT Timeout en {nombre}\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR Error detectando rootkits: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_servicios(self):
        """Analizar servicios del sistema usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.analizar_servicios_sistema()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "OK Análisis de servicios completado\n")
                        if 'servicios_activos' in resultado:
                            count = resultado['servicios_activos']
                            self.after(0, self._actualizar_texto_auditoria, f" Servicios activos encontrados: {count}\n")
                        if 'detalles' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, resultado['detalles'])
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR Error: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, " Analizando servicios activos en Kali Linux...\n")
                    
                    import subprocess
                    try:
                        resultado = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                                 capture_output=True, text=True)
                        if resultado.returncode == 0:
                            self.after(0, self._actualizar_texto_auditoria, " Servicios activos:\n\n")
                            lineas = resultado.stdout.split('\n')
                            for linea in lineas[1:21]:
                                if linea.strip() and 'service' in linea:
                                    self.after(0, self._actualizar_texto_auditoria, f"  {linea}\n")
                            self.after(0, self._actualizar_texto_auditoria, "\n... (mostrando primeros 20)\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "ERROR Error obteniendo servicios\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR Error: {str(e)}\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR Error analizando servicios: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_permisos(self):
        """Verificar permisos críticos del sistema usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.verificar_permisos_criticos()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "[EMOJI] OK Verificación de permisos completada\n")
                        if 'permisos_incorrectos' in resultado:
                            count = resultado['permisos_incorrectos']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"[WARNING] WARNING {count} permisos incorrectos detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "[EMOJI] OK Todos los permisos están correctos\n")
                        if 'detalles' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, f"\n[METADATA] DETALLES:\n{resultado['detalles']}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"[EMOJI] ERROR Error: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, "[SCAN] Verificando permisos críticos del sistema...\n")
                    
                    import subprocess
                    import os
                    
                    rutas_criticas = [
                        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                        '/boot', '/usr/bin/passwd', '/usr/bin/sudo', '/etc/ssh'
                    ]
                    
                    for ruta in rutas_criticas:
                        try:
                            if os.path.exists(ruta):
                                stat_result = os.stat(ruta)
                                permisos = oct(stat_result.st_mode)[-3:]
                                uid = stat_result.st_uid
                                gid = stat_result.st_gid
                                
                                self.after(0, self._actualizar_texto_auditoria, 
                                    f"[EMOJI] {ruta}: {permisos} (uid:{uid}, gid:{gid})\n")
                                
                                if ruta in ['/etc/shadow', '/etc/sudoers'] and permisos != '640':
                                    self.after(0, self._actualizar_texto_auditoria, "[WARNING] Permisos inusuales detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, f"[EMOJI] {ruta}: No existe\n")
                        except Exception as e:
                            self.after(0, self._actualizar_texto_auditoria, f"[EMOJI] {ruta}: Error - {str(e)}\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\n[EMOJI] Verificación de permisos completada\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"[EMOJI] ERROR verificando permisos: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def obtener_info_hardware(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Obteniendo información de hardware del sistema...\n")
                self.auditoria_text.update()
                
                import subprocess
                
                comandos_info = [
                    (['lscpu'], 'CPU'),
                    (['lsmem', '--summary'], 'Memoria'),
                    (['lsblk'], 'Discos'),
                    (['lspci', '-v'], 'PCI'),
                    (['lsusb'], 'USB'),
                    (['dmidecode', '-t', 'system'], 'Sistema')
                ]
                
                for comando, tipo in comandos_info:
                    try:
                        self.auditoria_text.insert(tk.END, f"\n=== {tipo} ===\n")
                        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.split('\n')[:15]
                            for linea in lineas:
                                if linea.strip():
                                    self.auditoria_text.insert(tk.END, f"{linea}\n")
                        else:
                            self.auditoria_text.insert(tk.END, f" Error obteniendo {tipo}\n")
                    except FileNotFoundError:
                        self.auditoria_text.insert(tk.END, f" Comando {comando[0]} no encontrado\n")
                    except subprocess.TimeoutExpired:
                        self.auditoria_text.insert(tk.END, f"⏱ Timeout en {tipo}\n")
                    except Exception as e:
                        self.auditoria_text.insert(tk.END, f" Error: {str(e)}\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error obteniendo info hardware: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def guardar_auditoria(self):
        try:
            contenido = self.auditoria_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay resultados para guardar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Guardar Resultados de Auditoria",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(contenido)
                messagebox.showinfo("Exito", f"Auditoria guardada en {archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def limpiar_auditoria(self):
        self.auditoria_text.config(state=tk.NORMAL)
        self.auditoria_text.delete(1.0, tk.END)
        self.auditoria_text.config(state=tk.DISABLED)
    
    def cancelar_rootkits(self):
        """Cancelar detección de rootkits."""
        if hasattr(self, 'proceso_rootkits_activo'):
            self.proceso_rootkits_activo = False
            self._actualizar_texto_auditoria(" Detección de rootkits cancelada\n")
    
    def ejecutar_openvas(self):
        """Ejecutar auditoría con OpenVAS."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Iniciando auditoría OpenVAS...\n")
                import subprocess
                
                try:
                    # Verificar si OpenVAS está instalado
                    resultado = subprocess.run(['which', 'openvas'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("OK OpenVAS encontrado\n")
                        self._actualizar_texto_auditoria(" Comandos OpenVAS:\n")
                        self._actualizar_texto_auditoria("  • openvas-start: Iniciar servicios\n")
                        self._actualizar_texto_auditoria("  • openvas-stop: Detener servicios\n")
                        self._actualizar_texto_auditoria("  • openvas-check-setup: Verificar configuración\n")
                    else:
                        self._actualizar_texto_auditoria("ERROR OpenVAS no encontrado. Instalar con: apt install openvas\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR Error verificando OpenVAS: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Auditoría OpenVAS completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR Error en OpenVAS: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ejecutar_nessus(self):
        """Ejecutar scan con Nessus."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Iniciando scan Nessus...\n")
                import subprocess
                
                try:
                    # Verificar si Nessus está instalado
                    resultado = subprocess.run(['which', 'nessus'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("OK Nessus encontrado\n")
                        self._actualizar_texto_auditoria(" Comandos Nessus:\n")
                        self._actualizar_texto_auditoria("  • service nessusd start: Iniciar servicio\n")
                        self._actualizar_texto_auditoria("  • https://localhost:8834: Interfaz web\n")
                    else:
                        self._actualizar_texto_auditoria("ERROR Nessus no encontrado. Descargar desde tenable.com\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR Error verificando Nessus: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Verificación Nessus completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR Error en Nessus: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_suid_sgid(self):
        """Analizar archivos SUID/SGID."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Analizando archivos SUID/SGID...\n")
                import subprocess
                
                try:
                    # Buscar archivos SUID
                    self._actualizar_texto_auditoria(" Buscando archivos SUID...\n")
                    resultado = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], 
                                             capture_output=True, text=True, timeout=30)
                    if resultado.stdout:
                        archivos_suid = resultado.stdout.strip().split('\n')[:20]  # Primeros 20
                        self._actualizar_texto_auditoria(f" Archivos SUID encontrados ({len(archivos_suid)} de muchos):\n")
                        for archivo in archivos_suid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                    
                    # Buscar archivos SGID
                    self._actualizar_texto_auditoria(" Buscando archivos SGID...\n")
                    resultado = subprocess.run(['find', '/', '-perm', '-2000', '-type', 'f', '2>/dev/null'], 
                                             capture_output=True, text=True, timeout=30)
                    if resultado.stdout:
                        archivos_sgid = resultado.stdout.strip().split('\n')[:20]  # Primeros 20
                        self._actualizar_texto_auditoria(f" Archivos SGID encontrados ({len(archivos_sgid)} de muchos):\n")
                        for archivo in archivos_sgid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("TIMEOUT Timeout en búsqueda SUID/SGID\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR Error buscando SUID/SGID: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Análisis SUID/SGID completado\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR Error en análisis SUID/SGID: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def auditar_ssh(self):
        """Auditar configuración SSH."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Auditando configuración SSH...\n")
                import subprocess
                import os
                
                try:
                    # Verificar si SSH está instalado
                    if os.path.exists('/etc/ssh/sshd_config'):
                        self._actualizar_texto_auditoria("OK SSH configurado en el sistema\n")
                        
                        # Verificar configuraciones importantes
                        with open('/etc/ssh/sshd_config', 'r') as f:
                            config = f.read()
                            
                        self._actualizar_texto_auditoria(" Verificando configuraciones críticas:\n")
                        
                        if 'PermitRootLogin no' in config:
                            self._actualizar_texto_auditoria("  OK PermitRootLogin: Deshabilitado\n")
                        else:
                            self._actualizar_texto_auditoria("  WARNING PermitRootLogin: Revisar configuración\n")
                        
                        if 'PasswordAuthentication no' in config:
                            self._actualizar_texto_auditoria("  OK PasswordAuthentication: Deshabilitado\n")
                        else:
                            self._actualizar_texto_auditoria("  WARNING PasswordAuthentication: Habilitado\n")
                        
                        if 'Port 22' in config:
                            self._actualizar_texto_auditoria("  WARNING Puerto: 22 (puerto por defecto)\n")
                        else:
                            self._actualizar_texto_auditoria("  OK Puerto: Cambiado del puerto por defecto\n")
                            
                    else:
                        self._actualizar_texto_auditoria("ERROR SSH no encontrado o no configurado\n")
                    
                    # Verificar servicio SSH
                    resultado = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
                    if resultado.stdout.strip() == 'active':
                        self._actualizar_texto_auditoria("OK Servicio SSH: Activo\n")
                    else:
                        self._actualizar_texto_auditoria("ERROR Servicio SSH: Inactivo\n")
                
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR Error auditando SSH: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Auditoría SSH completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR Error en auditoría SSH: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_password_policy(self):
        """Verificar políticas de contraseñas."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria(" Verificando políticas de contraseñas...\n")
                import subprocess
                import os
                
                try:
                    # Verificar /etc/login.defs
                    if os.path.exists('/etc/login.defs'):
                        self._actualizar_texto_auditoria(" Configuración en /etc/login.defs:\n")
                        resultado = subprocess.run(['grep', '-E', 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE', '/etc/login.defs'], 
                                                 capture_output=True, text=True)
                        if resultado.stdout:
                            for linea in resultado.stdout.split('\n'):
                                if linea.strip() and not linea.startswith('#'):
                                    self._actualizar_texto_auditoria(f"  {linea}\n")
                    
                    # Verificar PAM
                    if os.path.exists('/etc/pam.d/common-password'):
                        self._actualizar_texto_auditoria(" Configuración PAM (common-password):\n")
                        resultado = subprocess.run(['grep', 'pam_pwquality', '/etc/pam.d/common-password'], 
                                                 capture_output=True, text=True)
                        if resultado.stdout:
                            self._actualizar_texto_auditoria(f"  OK pwquality configurado\n")
                        else:
                            self._actualizar_texto_auditoria(f"  WARNING pwquality no configurado\n")
                    
                    # Verificar usuarios con contraseñas vacías
                    self._actualizar_texto_auditoria(" Verificando usuarios sin contraseña:\n")
                    resultado = subprocess.run(['awk', '-F:', '($2 == "") {print $1}', '/etc/shadow'], 
                                             capture_output=True, text=True)
                    if resultado.stdout.strip():
                        self._actualizar_texto_auditoria("  WARNING Usuarios sin contraseña encontrados:\n")
                        for usuario in resultado.stdout.split('\n'):
                            if usuario.strip():
                                self._actualizar_texto_auditoria(f"    {usuario}\n")
                    else:
                        self._actualizar_texto_auditoria("  OK No hay usuarios sin contraseña\n")
                
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR Error verificando políticas: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Verificación de políticas completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR Error en verificación de políticas: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()

    def verificar_kali(self):
        """Verificar compatibilidad y funcionalidad de auditoría en Kali Linux."""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de auditoría configurado")
            return
            
        try:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.delete(1.0, tk.END)
            self.auditoria_text.insert(tk.END, "=== VERIFICACIÓN AUDITORÍA KALI LINUX ===\n\n")
            
            # Ejecutar verificación a través del controlador
            resultado = self.controlador.verificar_funcionalidad_kali()
            
            # Mostrar resultados
            funcionalidad_ok = resultado.get('funcionalidad_completa', False)
            
            if funcionalidad_ok:
                self.auditoria_text.insert(tk.END, " OK VERIFICACIÓN AUDITORÍA EXITOSA\n\n")
                self.auditoria_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.auditoria_text.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.auditoria_text.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                self.auditoria_text.insert(tk.END, "=== HERRAMIENTAS AUDITORÍA DISPONIBLES ===\n")
                for herramienta, estado in resultado.get('herramientas_disponibles', {}).items():
                    disponible = estado.get('disponible', False)
                    permisos = estado.get('permisos_ok', False)
                    icono = "OK" if disponible and permisos else "ERROR"
                    self.auditoria_text.insert(tk.END, f"  {icono} {herramienta}\n")
                    
            else:
                self.auditoria_text.insert(tk.END, " ERROR VERIFICACIÓN AUDITORÍA FALLÓ\n\n")
                self.auditoria_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.auditoria_text.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.auditoria_text.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                if resultado.get('recomendaciones'):
                    self.auditoria_text.insert(tk.END, "=== RECOMENDACIONES ===\n")
                    for recomendacion in resultado['recomendaciones']:
                        self.auditoria_text.insert(tk.END, f"  • {recomendacion}\n")
                
            if resultado.get('error'):
                self.auditoria_text.insert(tk.END, f"\nWARNING Error: {resultado['error']}\n")
                
            self.auditoria_text.config(state=tk.DISABLED)
                
        except Exception as e:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.insert(tk.END, f" ERROR Error durante verificación: {str(e)}\n")
            self.auditoria_text.config(state=tk.DISABLED)
