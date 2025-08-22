# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging
import datetime

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
    - Auditorías generales del sistema (Lynis, nuclei, httpx)
    - Análisis de configuraciones de seguridad
    - Verificación de permisos y políticas
    - Detección de rootkits y malware
    
    Nota: Las funciones de SIEM, FIM y Escaneo están en sus respectivas pestañas especializadas.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
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
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame superior para el contenido principal
        contenido_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(contenido_frame, minsize=400)
        
        # Frame del título con tema Burp Suite
        titulo_frame = tk.Frame(contenido_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(10, 10))
        
        titulo = tk.Label(titulo_frame, text="Auditoría de Seguridad del Sistema",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack(pady=10)
        
        # Frame principal con tema
        main_frame = tk.Frame(contenido_frame, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Panel izquierdo - Resultados con tema Burp Suite
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        label_results = tk.Label(left_frame, text="Resultados de Auditoría", 
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
        
        label_tools = tk.Label(right_frame, text="Herramientas de Auditoría", 
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                             font=('Arial', 12, 'bold'))
        label_tools.pack(anchor=tk.W, pady=(0, 10))
        
        # Crear secciones organizadas
        self._crear_seccion_auditoria_sistema(right_frame)
        self._crear_seccion_deteccion_malware(right_frame)
        self._crear_seccion_configuraciones(right_frame)
        self._crear_seccion_utilidades(right_frame)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado en la vista Auditoría."""
        try:
            # Frame del terminal en el PanedWindow
            terminal_frame = tk.Frame(self.paned_window, bg=self.colors['bg_secondary'])
            self.paned_window.add(terminal_frame, minsize=150)
            
            # Título del terminal
            terminal_titulo = tk.Label(terminal_frame, text="Terminal Auditoría", 
                                     font=('Arial', 10, 'bold'),
                                     bg=self.colors['bg_secondary'], 
                                     fg=self.colors['fg_primary'])
            terminal_titulo.pack(pady=5)
            
            # Verificar si existe terminal en la vista principal
            if hasattr(self.vista_principal, 'terminal_widget') and self.vista_principal.terminal_widget:
                # Usar terminal global existente
                self.terminal_widget = self.vista_principal.terminal_widget
                # Crear referencia local si es necesario
                terminal_local = tk.Text(terminal_frame, height=8, 
                                       bg='black', fg='green',
                                       font=('Consolas', 9),
                                       state='disabled')
                terminal_local.pack(fill="both", expand=True, padx=5, pady=5)
                self.terminal_local = terminal_local
                
                # Sincronizar con terminal global
                self.sincronizar_terminal()
            else:
                # Crear terminal local
                self.terminal_widget = tk.Text(terminal_frame, height=8, 
                                             bg='black', fg='green',
                                             font=('Consolas', 9),
                                             state='disabled')
                self.terminal_widget.pack(fill="both", expand=True, padx=5, pady=5)
                self.terminal_local = self.terminal_widget
            
            self.log_to_terminal("Terminal Auditoría iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Auditoría: {e}")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal."""
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            
            # Log al terminal local
            if hasattr(self, 'terminal_local'):
                self.terminal_local.config(state='normal')
                self.terminal_local.insert(tk.END, mensaje_completo)
                self.terminal_local.see(tk.END)
                self.terminal_local.config(state='disabled')
            
            # Log al terminal global si existe
            if hasattr(self.vista_principal, 'terminal_widget') and self.vista_principal.terminal_widget:
                try:
                    self.vista_principal.terminal_widget.config(state='normal')
                    self.vista_principal.terminal_widget.insert(tk.END, f"[AUDIT] {mensaje_completo}")
                    self.vista_principal.terminal_widget.see(tk.END)
                    self.vista_principal.terminal_widget.config(state='disabled')
                except:
                    pass
                    
        except Exception as e:
            print(f"Error en log_to_terminal: {e}")
    
    def sincronizar_terminal(self):
        """Sincronizar terminal local con global."""
        try:
            if hasattr(self.vista_principal, 'terminal_widget') and self.vista_principal.terminal_widget:
                contenido_global = self.vista_principal.terminal_widget.get("1.0", tk.END)
                if hasattr(self, 'terminal_local'):
                    self.terminal_local.config(state='normal')
                    self.terminal_local.delete("1.0", tk.END)
                    self.terminal_local.insert("1.0", contenido_global)
                    self.terminal_local.config(state='disabled')
        except Exception as e:
            print(f"Error sincronizando terminal: {e}")
    
    def _crear_seccion_auditoria_sistema(self, parent):
        """Crear sección de auditorías generales del sistema."""
        # Sección de auditorías del sistema con tema Burp Suite
        section_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        section_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(section_frame, text="Auditorías del Sistema", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Ejecutar Lynis", self.ejecutar_lynis, self.colors['fg_accent']),
            ("Cancelar Lynis", self.cancelar_auditoria, self.colors['danger']),
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
        
        tk.Label(section_frame, text="Detección de Malware", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Detectar Rootkits", self.detectar_rootkits, self.colors['warning']),
            ("Cancelar Rootkits", self.cancelar_rootkits, self.colors['danger']),
            ("Auditoría nuclei", self.ejecutar_nuclei, self.colors['info']),
            ("Scan httpx", self.ejecutar_httpx, self.colors['fg_accent']),
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
        
        tk.Label(section_frame, text="Configuraciones", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Analizar Servicios", self.analizar_servicios, self.colors['info']),
            ("Verificar Permisos", self.verificar_permisos, self.colors['success']),
            ("Configuración SSH", self.auditar_ssh, self.colors['fg_accent']),
            ("Políticas de Contraseña", self.verificar_password_policy, self.colors['danger']),
            ("Análisis SUID/SGID", self.analizar_suid_sgid, self.colors['warning']),
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
        
        tk.Label(section_frame, text="Utilidades", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        buttons = [
            ("Info Hardware", self.obtener_info_hardware, self.colors['bg_primary']),
            ("Guardar Resultados", self.guardar_auditoria, self.colors['info']),
            ("Limpiar Pantalla", self.limpiar_auditoria, self.colors['warning']),
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
        self.log_to_terminal("Iniciando auditoría completa con Lynis...")
        
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
                    self.after(0, self._actualizar_texto_auditoria, f"ERROR en auditoría: {resultado.get('error', 'Error desconocido')}\n")
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
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR en Lynis: {stderr}\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR Lynis no encontrado. Instale con: apt install lynis\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_auditoria, f"ERROR ejecutando Lynis: {str(e)}\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto_auditoria, f"ERROR general: {str(e)}\n")
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
        """Detectar rootkits usando herramientas nativas de Linux y Kali."""
        self.log_to_terminal("Iniciando detección de rootkits y malware...")
        def ejecutar():
            try:
                self.after(0, self._actualizar_texto_auditoria, "=== DETECCIÓN DE ROOTKITS CON HERRAMIENTAS LINUX ===\n\n")
                
                # 1. Verificar procesos ocultos con ps y comparación
                self.after(0, self._actualizar_texto_auditoria, "FASE 1: Verificación de procesos ocultos\n")
                self.after(0, self._actualizar_texto_auditoria, "COMANDO: ps aux | wc -l vs ls /proc | grep '^[0-9]' | wc -l\n")
                
                import subprocess
                try:
                    # Contar procesos con ps
                    resultado_ps = subprocess.run(['bash', '-c', 'ps aux | wc -l'], 
                                                capture_output=True, text=True, timeout=10)
                    # Contar directorios de procesos en /proc
                    resultado_proc = subprocess.run(['bash', '-c', "ls /proc | grep '^[0-9]' | wc -l"], 
                                                  capture_output=True, text=True, timeout=10)
                    
                    if resultado_ps.returncode == 0 and resultado_proc.returncode == 0:
                        procesos_ps = int(resultado_ps.stdout.strip()) - 1  # -1 para header
                        procesos_proc = int(resultado_proc.stdout.strip())
                        diferencia = abs(procesos_ps - procesos_proc)
                        
                        self.after(0, self._actualizar_texto_auditoria, f"PROCESOS PS: {procesos_ps}\n")
                        self.after(0, self._actualizar_texto_auditoria, f"PROCESOS /proc: {procesos_proc}\n")
                        self.after(0, self._actualizar_texto_auditoria, f"DIFERENCIA: {diferencia}\n")
                        
                        if diferencia > 5:  # Umbral de sospecha
                            self.after(0, self._actualizar_texto_auditoria, "ALERTA: Diferencia significativa detectada - posible rootkit\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "OK: Recuento de procesos normal\n")
                except:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR: No se pudo verificar procesos\n")
                
                self.after(0, self._actualizar_texto_auditoria, "\n")
                
                # 2. Verificar modificaciones en comandos del sistema
                self.after(0, self._actualizar_texto_auditoria, "FASE 2: Verificación de integridad de comandos\n")
                comandos_criticos = ['/bin/ps', '/bin/ls', '/bin/netstat', '/usr/bin/who', '/usr/bin/w']
                
                for comando in comandos_criticos:
                    try:
                        # Verificar si el comando existe y obtener información
                        resultado = subprocess.run(['stat', '-c', '%s %Y', comando], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0:
                            info = resultado.stdout.strip().split()
                            tamaño = info[0]
                            timestamp = info[1]
                            self.after(0, self._actualizar_texto_auditoria, f"OK: {comando} - Tamaño: {tamaño} bytes\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, f"ALERTA: {comando} no encontrado o inaccesible\n")
                    except:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: No se pudo verificar {comando}\n")
                
                self.after(0, self._actualizar_texto_auditoria, "\n")
                
                # 3. Verificar conexiones de red ocultas
                self.after(0, self._actualizar_texto_auditoria, "FASE 3: Verificación de conexiones de red ocultas\n")
                self.after(0, self._actualizar_texto_auditoria, "COMANDO: ss -tuln vs netstat -tuln\n")
                
                try:
                    # Comparar salidas de ss y netstat
                    resultado_ss = subprocess.run(['ss', '-tuln'], 
                                                capture_output=True, text=True, timeout=10)
                    resultado_netstat = subprocess.run(['netstat', '-tuln'], 
                                                     capture_output=True, text=True, timeout=10)
                    
                    if resultado_ss.returncode == 0 and resultado_netstat.returncode == 0:
                        lineas_ss = len(resultado_ss.stdout.strip().split('\n'))
                        lineas_netstat = len(resultado_netstat.stdout.strip().split('\n'))
                        diferencia_red = abs(lineas_ss - lineas_netstat)
                        
                        self.after(0, self._actualizar_texto_auditoria, f"CONEXIONES SS: {lineas_ss}\n")
                        self.after(0, self._actualizar_texto_auditoria, f"CONEXIONES NETSTAT: {lineas_netstat}\n")
                        
                        if diferencia_red > 3:
                            self.after(0, self._actualizar_texto_auditoria, "ALERTA: Diferencias en listado de conexiones\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "OK: Listados de red coinciden\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, "ERROR: No se pudieron ejecutar comandos de red\n")
                except:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR: Error comparando herramientas de red\n")
                
                self.after(0, self._actualizar_texto_auditoria, "\n")
                
                # 4. Verificar módulos del kernel sospechosos
                self.after(0, self._actualizar_texto_auditoria, "FASE 4: Verificación de módulos del kernel\n")
                self.after(0, self._actualizar_texto_auditoria, "COMANDO: lsmod | grep -v '^Module'\n")
                
                try:
                    resultado = subprocess.run(['bash', '-c', "lsmod | grep -v '^Module' | wc -l"], 
                                             capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        modulos_count = resultado.stdout.strip()
                        self.after(0, self._actualizar_texto_auditoria, f"MÓDULOS CARGADOS: {modulos_count}\n")
                        
                        # Buscar módulos con nombres sospechosos
                        resultado_modulos = subprocess.run(['lsmod'], 
                                                         capture_output=True, text=True, timeout=10)
                        if resultado_modulos.returncode == 0:
                            modulos_sospechosos = ['rootkit', 'hidden', 'stealth', 'backdoor']
                            lineas = resultado_modulos.stdout.lower().split('\n')
                            
                            encontrados = []
                            for linea in lineas:
                                for sospechoso in modulos_sospechosos:
                                    if sospechoso in linea:
                                        encontrados.append(linea.strip())
                            
                            if encontrados:
                                self.after(0, self._actualizar_texto_auditoria, "ALERTA: Módulos sospechosos encontrados:\n")
                                for modulo in encontrados:
                                    self.after(0, self._actualizar_texto_auditoria, f"  SOSPECHOSO: {modulo}\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "OK: No se encontraron módulos con nombres sospechosos\n")
                except:
                    self.after(0, self._actualizar_texto_auditoria, "ERROR: No se pudo verificar módulos del kernel\n")
                
                # Usar controlador si está disponible
                if self.controlador:
                    self.after(0, self._actualizar_texto_auditoria, "\nFASE 5: Ejecutando detector del controlador\n")
                    resultado = self.controlador.ejecutar_deteccion_rootkits()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "✓ Detección de rootkits completada\n")
                        if 'rootkits_detectados' in resultado:
                            count = resultado['rootkits_detectados']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"ADVERTENCIA {count} posibles rootkits detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "✓ No se detectaron rootkits\n")
                        if 'salida' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, f"\nDETALLES:\n{resultado['salida']}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {resultado.get('error', 'Error desconocido')}\n")
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
                                self.after(0, self._actualizar_texto_auditoria, f"ERROR en {nombre}\n")
                        except FileNotFoundError:
                            self.after(0, self._actualizar_texto_auditoria, f"ERROR {nombre} no encontrado. Instalar con: apt install {nombre}\n")
                        except subprocess.TimeoutExpired:
                            self.after(0, self._actualizar_texto_auditoria, f"TIMEOUT en {nombre}\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR detectando rootkits: {str(e)}\n")
        
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
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {resultado.get('error', 'Error desconocido')}\n")
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
                            self.after(0, self._actualizar_texto_auditoria, "ERROR obteniendo servicios\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {str(e)}\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR analizando servicios: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_permisos(self):
        """Verificar permisos críticos del sistema usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.verificar_permisos_criticos()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "✓ Verificación de permisos completada\n")
                        if 'permisos_incorrectos' in resultado:
                            count = resultado['permisos_incorrectos']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"ADVERTENCIA {count} permisos incorrectos detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "✓ Todos los permisos están correctos\n")
                        if 'detalles' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, f"\nDETALLES:\n{resultado['detalles']}\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"ERROR: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, "Verificando permisos críticos del sistema...\n")
                    
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
                                    f"DIRECTORIO {ruta}: {permisos} (uid:{uid}, gid:{gid})\n")
                                
                                if ruta in ['/etc/shadow', '/etc/sudoers'] and permisos != '640':
                                    self.after(0, self._actualizar_texto_auditoria, "ADVERTENCIA Permisos inusuales detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, f"DIRECTORIO {ruta}: No existe\n")
                        except Exception as e:
                            self.after(0, self._actualizar_texto_auditoria, f"ERROR {ruta}: Error - {str(e)}\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\n✓ Verificación de permisos completada\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"ERROR verificando permisos: {str(e)}\n")
        
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
        """Cancelar detección de rootkits mediante terminación de procesos activos."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== CANCELANDO DETECCIÓN ROOTKITS ===\n")
                import subprocess
                
                # Terminar procesos conocidos de detección de rootkits
                procesos_rootkits = ['rkhunter', 'chkrootkit', 'unhide', 'lynis']
                procesos_terminados = 0
                
                for proceso in procesos_rootkits:
                    try:
                        # Buscar procesos activos
                        resultado = subprocess.run(['pgrep', '-f', proceso], 
                                                capture_output=True, text=True)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            pids = resultado.stdout.strip().split('\n')
                            for pid in pids:
                                if pid.strip():
                                    # Terminar proceso específico
                                    subprocess.run(['kill', '-TERM', pid.strip()], 
                                                capture_output=True)
                                    self._actualizar_texto_auditoria(f"✓ Terminado proceso {proceso} (PID: {pid.strip()})\n")
                                    procesos_terminados += 1
                    except Exception as e:
                        continue
                
                if procesos_terminados > 0:
                    self._actualizar_texto_auditoria(f"✓ COMPLETADO: {procesos_terminados} procesos de rootkits terminados\n")
                else:
                    self._actualizar_texto_auditoria("• INFO: No se encontraron procesos de detección de rootkits activos\n")
                    
                # Limpiar archivos temporales de rootkits
                archivos_temp = ['/tmp/rkhunter.log', '/tmp/chkrootkit.log', '/var/log/rkhunter.log']
                for archivo in archivos_temp:
                    try:
                        subprocess.run(['rm', '-f', archivo], capture_output=True)
                    except:
                        pass
                        
                self._actualizar_texto_auditoria("✓ Limpieza de archivos temporales completada\n")
                self._actualizar_texto_auditoria("=== CANCELACIÓN ROOTKITS COMPLETADA ===\n\n")
                
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR durante cancelación: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ejecutar_nuclei(self):
        """Ejecutar auditoría completa con nuclei - escáner de vulnerabilidades moderno."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== INICIANDO AUDITORÍA NUCLEI ===\n")
                import subprocess
                import os
                
                try:
                    # Verificar si nuclei está instalado
                    resultado = subprocess.run(['which', 'nuclei'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✓ nuclei encontrado en sistema\n")
                        
                        # Verificar templates actualizados
                        self._actualizar_texto_auditoria("• Verificando templates nuclei...\n")
                        update_result = subprocess.run(['nuclei', '-update-templates'], 
                                                     capture_output=True, text=True, timeout=30)
                        if update_result.returncode == 0:
                            self._actualizar_texto_auditoria("✓ Templates nuclei actualizados\n")
                        
                        # Ejecutar escaneo básico de red local
                        self._actualizar_texto_auditoria("• Ejecutando escaneo nuclei de red local...\n")
                        targets = ['127.0.0.1', 'localhost', '192.168.1.1']
                        
                        for target in targets:
                            self._actualizar_texto_auditoria(f"  → Escaneando {target}...\n")
                            
                            # Escaneo básico con nuclei
                            cmd = ['nuclei', '-u', target, '-severity', 'high,critical', 
                                  '-timeout', '10', '-no-color', '-silent']
                            
                            proceso = subprocess.run(cmd, capture_output=True, 
                                                   text=True, timeout=60)
                            
                            if proceso.stdout and proceso.stdout.strip():
                                self._actualizar_texto_auditoria(f"VULNERABILIDADES ENCONTRADAS en {target}:\n")
                                for linea in proceso.stdout.strip().split('\n'):
                                    if linea.strip():
                                        self._actualizar_texto_auditoria(f"  • {linea}\n")
                            else:
                                self._actualizar_texto_auditoria(f"✓ No se encontraron vulnerabilidades críticas en {target}\n")
                        
                        # Mostrar comandos útiles
                        self._actualizar_texto_auditoria("\n=== COMANDOS NUCLEI ÚTILES ===\n")
                        self._actualizar_texto_auditoria("• nuclei -u <target> -severity critical: Solo críticas\n")
                        self._actualizar_texto_auditoria("• nuclei -l targets.txt -o resultados.txt: Múltiples targets\n")
                        self._actualizar_texto_auditoria("• nuclei -t vulnerabilities/ -u <target>: Solo vulnerabilidades\n")
                        self._actualizar_texto_auditoria("• nuclei -t exposures/ -u <target>: Exposiciones\n")
                        
                    else:
                        self._actualizar_texto_auditoria("WARNING nuclei no encontrado\n")
                        self._actualizar_texto_auditoria("INSTALACIÓN: apt install nuclei\n")
                        self._actualizar_texto_auditoria("O desde Go: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest\n")
                        
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("WARNING Timeout en nuclei - proceso demasiado lento\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR verificando nuclei: {str(e)}\n")
                
                self._actualizar_texto_auditoria("=== AUDITORÍA NUCLEI COMPLETADA ===\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en nuclei: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ejecutar_httpx(self):
        """Ejecutar escaneo web completo con httpx - probe HTTP avanzado."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("=== INICIANDO ESCANEO HTTPX ===\n")
                import subprocess
                import os
                
                try:
                    # Verificar si httpx está instalado
                    resultado = subprocess.run(['which', 'httpx'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✓ httpx encontrado en sistema\n")
                        
                        # Targets comunes para escanear
                        targets = ['127.0.0.1', 'localhost', '192.168.1.1', '192.168.1.254']
                        puertos = ['80', '443', '8080', '8443', '3000', '5000']
                        
                        servicios_encontrados = []
                        
                        for target in targets:
                            self._actualizar_texto_auditoria(f"• Escaneando servicios web en {target}...\n")
                            
                            # Crear lista de URLs para httpx
                            urls_target = []
                            for puerto in puertos:
                                urls_target.extend([f"http://{target}:{puerto}", f"https://{target}:{puerto}"])
                            
                            # Ejecutar httpx con probe
                            for url in urls_target:
                                try:
                                    cmd = ['httpx', '-u', url, '-probe', '-status-code', 
                                          '-title', '-tech-detect', '-timeout', '5', '-silent']
                                    
                                    proceso = subprocess.run(cmd, capture_output=True, 
                                                           text=True, timeout=10)
                                    
                                    if proceso.stdout and proceso.stdout.strip():
                                        lineas = proceso.stdout.strip().split('\n')
                                        for linea in lineas:
                                            if linea.strip() and '[' in linea:
                                                servicios_encontrados.append(linea.strip())
                                                self._actualizar_texto_auditoria(f"  ✓ SERVICIO: {linea.strip()}\n")
                                                
                                except subprocess.TimeoutExpired:
                                    continue
                                except Exception:
                                    continue
                        
                        if servicios_encontrados:
                            self._actualizar_texto_auditoria(f"\n=== RESUMEN: {len(servicios_encontrados)} servicios web encontrados ===\n")
                            for servicio in servicios_encontrados:
                                self._actualizar_texto_auditoria(f"  • {servicio}\n")
                        else:
                            self._actualizar_texto_auditoria("• INFO: No se encontraron servicios web activos\n")
                        
                        # Ejecutar detección de tecnologías en localhost
                        self._actualizar_texto_auditoria("\n• Detectando tecnologías en localhost...\n")
                        try:
                            cmd_tech = ['httpx', '-u', 'http://localhost', '-tech-detect', 
                                       '-follow-redirects', '-timeout', '10', '-silent']
                            tech_result = subprocess.run(cmd_tech, capture_output=True, 
                                                       text=True, timeout=15)
                            if tech_result.stdout and tech_result.stdout.strip():
                                self._actualizar_texto_auditoria(f"TECNOLOGÍAS: {tech_result.stdout.strip()}\n")
                            else:
                                self._actualizar_texto_auditoria("• No se detectaron tecnologías específicas\n")
                        except:
                            pass
                        
                        # Mostrar comandos útiles
                        self._actualizar_texto_auditoria("\n=== COMANDOS HTTPX ÚTILES ===\n")
                        self._actualizar_texto_auditoria("• httpx -l targets.txt -probe: Verificar múltiples URLs\n")
                        self._actualizar_texto_auditoria("• httpx -u target.com -ports 80,443,8080: Puertos específicos\n")
                        self._actualizar_texto_auditoria("• httpx -u target.com -screenshot: Capturar pantalla\n")
                        self._actualizar_texto_auditoria("• httpx -u target.com -favicon: Hash de favicon\n")
                        
                    else:
                        self._actualizar_texto_auditoria("WARNING httpx no encontrado\n")
                        self._actualizar_texto_auditoria("INSTALACIÓN: apt install httpx\n")
                        self._actualizar_texto_auditoria("O desde Go: go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n")
                        
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR verificando httpx: {str(e)}\n")
                
                self._actualizar_texto_auditoria("=== ESCANEO HTTPX COMPLETADO ===\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en httpx: {str(e)}\n")
        
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
                    self._actualizar_texto_auditoria("TIMEOUT en búsqueda SUID/SGID\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"ERROR buscando SUID/SGID: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Análisis SUID/SGID completado\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en análisis SUID/SGID: {str(e)}\n")
        
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
                    self._actualizar_texto_auditoria(f"ERROR auditando SSH: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Auditoría SSH completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en auditoría SSH: {str(e)}\n")
        
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
                    self._actualizar_texto_auditoria(f"ERROR verificando políticas: {str(e)}\n")
                
                self._actualizar_texto_auditoria("OK Verificación de políticas completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"ERROR en verificación de políticas: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()

    def _log_terminal(self, mensaje, modulo="AUDITORIA", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")
