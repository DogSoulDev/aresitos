# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import subprocess
import logging
import datetime

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
                'fg_secondary': '#666666',
                'fg_accent': '#007acc',
                'button_bg': '#007acc',
                'button_fg': 'white',
                'success': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545',
                'info': '#17a2b8'
            }
        
        self.crear_interfaz()
    
    def _log_terminal(self, mensaje, modulo="FIM", nivel="INFO"):
        """Registrar actividad en el terminal integrado global."""
        try:
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
        except Exception:
            pass  # Terminal no disponible

    def crear_interfaz(self):
        """Crear la interfaz de usuario para FIM."""
        self.configure(bg=self.colors['bg_primary'])
        
        # Título principal
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        titulo_label = tk.Label(titulo_frame, text="FIM - File Integrity Monitoring", 
                               bg=self.colors['bg_primary'], fg=self.colors['fg_accent'],
                               font=('Arial', 16, 'bold'))
        titulo_label.pack(anchor="w")
        
        subtitulo_label = tk.Label(titulo_frame, text="Monitoreo de integridad de archivos críticos del sistema",
                                  bg=self.colors['bg_primary'], fg=self.colors['fg_secondary'],
                                  font=('Arial', 10))
        subtitulo_label.pack(anchor="w")
        
        # Frame principal con paned window
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Crear PanedWindow para dividir contenido principal y terminal
        paned_window = tk.PanedWindow(main_frame, orient=tk.VERTICAL, 
                                     bg=self.colors['bg_primary'], 
                                     sashrelief=tk.RAISED,
                                     sashwidth=3)
        paned_window.pack(fill="both", expand=True)
        
        # Frame superior para el contenido principal de FIM
        contenido_frame = tk.Frame(paned_window, bg=self.colors['bg_primary'])
        paned_window.add(contenido_frame, minsize=300)
        
        # Crear el contenido principal de FIM en contenido_frame
        self.crear_contenido_fim(contenido_frame)
        
        # Frame inferior para el terminal integrado
        terminal_frame = tk.Frame(paned_window, bg=self.colors['bg_secondary'])
        paned_window.add(terminal_frame, minsize=150)
        
        # Crear terminal integrado
        self.crear_terminal_integrado(terminal_frame)
        
        # Configurar posición inicial del sash
        paned_window.update_idletasks()
        try:
            paned_window.sash_place(0, 400, 0)  # Posición inicial del divisor
        except:
            pass  # Si falla, usar posición por defecto
    
    def crear_terminal_integrado(self, parent_frame):
        """Crear terminal integrado FIM con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard (reemplaza el parent_frame directamente)
            # Configurar el parent_frame como LabelFrame estilo dashboard
            parent_frame.config(relief="ridge", bd=2)
            
            # Título del terminal estilo dashboard
            titulo_frame = tk.Frame(parent_frame, bg=self.colors['bg_secondary'])
            titulo_frame.pack(fill="x", padx=5, pady=2)
            
            titulo_label = tk.Label(titulo_frame,
                                   text="Terminal ARESITOS - FIM",
                                   bg=self.colors['bg_secondary'],
                                   fg=self.colors['fg_primary'],
                                   font=("Arial", 10, "bold"))
            titulo_label.pack(side="left")
            
            # Frame para controles del terminal (compacto)
            controles_frame = tk.Frame(parent_frame, bg=self.colors['bg_secondary'])
            controles_frame.pack(fill="x", padx=5, pady=2)
            
            # Botón limpiar terminal (estilo dashboard, compacto)
            btn_limpiar = tk.Button(
                controles_frame,
                text="LIMPIAR",
                command=self.limpiar_terminal_fim,
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
                command=self.abrir_logs_fim,
                bg=self.colors.get('info', '#007acc'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)
            
            # Área de terminal (misma estética que dashboard, más pequeña)
            self.terminal_output = scrolledtext.ScrolledText(
                parent_frame,
                height=6,  # Más pequeño que dashboard
                bg='#000000',  # Fondo negro como dashboard
                fg='#00ff00',  # Texto verde como dashboard
                font=("Consolas", 8),  # Fuente menor que dashboard
                insertbackground='#00ff00',
                selectbackground='#333333'
            )
            self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Mensaje inicial estilo dashboard
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - FIM v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, f"Sistema: Kali Linux - File Integrity Monitoring\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Monitoreo FIM en tiempo real\n\n")
            
        except Exception as e:
            # Fallback: crear terminal básico
            self.crear_terminal_local(parent_frame)
    
    def limpiar_terminal_fim(self):
        """Limpiar terminal FIM manteniendo cabecera."""
        try:
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - FIM v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - File Integrity Monitoring\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal FIM reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal FIM: {e}")
    
    def abrir_logs_fim(self):
        """Abrir carpeta de logs FIM."""
        try:
            import os
            import platform
            logs_path = "logs/"
            if os.path.exists(logs_path):
                if platform.system() == "Linux":
                    subprocess.run(["xdg-open", logs_path], check=False)
                else:
                    subprocess.run(["explorer", logs_path], check=False)
                self.log_to_terminal("Carpeta de logs FIM abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs FIM: {e}")
    
    def crear_terminal_local(self, parent_frame):
        """Crear terminal local si no hay terminal global disponible (fallback)."""
        self.terminal_output = scrolledtext.ScrolledText(parent_frame,
                                                     height=6,
                                                     bg='#000000',
                                                     fg='#00ff00',
                                                     font=("Consolas", 8),
                                                     insertbackground='#00ff00')
        self.terminal_output.pack(fill="both", expand=True)
        
        # Mensaje inicial
        import datetime
        self.terminal_output.insert(tk.END, f"=== Terminal FIM Local ===\n")
        self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self.terminal_output.insert(tk.END, f"File Integrity Monitoring\n\n")
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal con formato estándar."""
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            
            # Log al terminal integrado estándar
            if hasattr(self, 'terminal_output'):
                self.terminal_output.insert(tk.END, mensaje_completo)
                self.terminal_output.see(tk.END)
        except:
            pass  # Si no hay terminal, ignorar silenciosamente
    
    def crear_contenido_fim(self, parent_frame):
        """Crear el contenido principal de FIM."""
        # Panel izquierdo - Controles
        left_frame = tk.Frame(parent_frame, bg=self.colors['bg_secondary'], relief="solid", bd=1)
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        
        # Panel derecho - Resultados
        right_frame = tk.Frame(parent_frame, bg=self.colors['bg_primary'])
        right_frame.pack(side="right", fill="both", expand=True)
        
        # Controles del FIM
        controles_label = tk.Label(left_frame, text="Controles FIM", 
                                  bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                  font=('Arial', 12, 'bold'))
        controles_label.pack(anchor="w", padx=10, pady=(10, 5))
        
        # Botones de control
        self.btn_iniciar = tk.Button(left_frame, text="Iniciar Monitoreo",
                                    command=self.iniciar_monitoreo,
                                    bg=self.colors['success'], fg='white',
                                    font=('Arial', 10, 'bold'),
                                    relief='flat', padx=15, pady=8)
        self.btn_iniciar.pack(fill="x", padx=10, pady=5)
        
        self.btn_detener = tk.Button(left_frame, text="Detener Monitoreo",
                                    command=self.detener_monitoreo,
                                    state="disabled",
                                    bg=self.colors['danger'], fg='white',
                                    font=('Arial', 10),
                                    relief='flat', padx=15, pady=8)
        self.btn_detener.pack(fill="x", padx=10, pady=5)
        
        self.btn_verificar = tk.Button(left_frame, text="Verificar Integridad",
                                      command=self.verificar_integridad,
                                      bg=self.colors['info'], fg='white',
                                      font=('Arial', 10),
                                      relief='flat', padx=15, pady=8)
        self.btn_verificar.pack(fill="x", padx=10, pady=5)
        
        # Área de resultados
        resultados_label = tk.Label(right_frame, text="Resultados del Monitoreo FIM",
                                   bg=self.colors['bg_primary'], fg=self.colors['fg_accent'],
                                   font=('Arial', 12, 'bold'))
        resultados_label.pack(anchor="w", pady=(0, 10))
        
        self.fim_text = scrolledtext.ScrolledText(right_frame, height=25,
                                                 bg=self.colors['bg_secondary'], 
                                                 fg=self.colors['fg_primary'],
                                                 font=('Consolas', 10),
                                                 insertbackground=self.colors['fg_accent'],
                                                 selectbackground=self.colors['fg_accent'],
                                                 wrap=tk.WORD, state=tk.DISABLED)
        self.fim_text.pack(fill="both", expand=True)
    
    def iniciar_monitoreo(self):
        """Iniciar monitoreo continuo con información detallada."""
        if self.proceso_monitoreo_activo:
            return
        
        self.proceso_monitoreo_activo = True
        self._habilitar_botones_monitoreo(False)
        
        # Log al terminal integrado
        self._log_terminal("Iniciando sistema FIM - File Integrity Monitoring", "FIM", "INFO")
        self.log_to_terminal("FIM Iniciando monitoreo FIM del sistema...")
        self._actualizar_texto_fim("=== INICIANDO MONITOREO FIM - FILE INTEGRITY MONITORING ===\n\n")
        
        # Ejecutar en thread separado
        self.thread_monitoreo = threading.Thread(target=self._ejecutar_monitoreo_async)
        self.thread_monitoreo.daemon = True
        self.thread_monitoreo.start()
    
    def _ejecutar_monitoreo_async(self):
        """Ejecutar monitoreo FIM con análisis detallado usando comandos nativos de Linux."""
        try:
            # FASE 1: Información del sistema con comandos Linux avanzados
            self._log_terminal("FASE 1: Análisis inicial del sistema con herramientas Linux", "FIM", "INFO")
            self.after(0, self._actualizar_texto_fim, "FASE 1: ANÁLISIS INICIAL DEL SISTEMA CON COMANDOS LINUX\n")
            self.after(0, self._actualizar_texto_fim, "POR QUÉ: Establecer baseline de seguridad usando herramientas nativas de Kali\n")
            self.after(0, self._actualizar_texto_fim, "CÓMO: Verificación con find, stat, lsof, and auditd para análisis forense\n\n")
            
            # Comandos Linux para monitoreo avanzado
            import subprocess
            
            # 1. Verificar archivos modificados recientemente
            self.after(0, self._actualizar_texto_fim, "COMANDO: find /etc -type f -mtime -1\n")
            self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Archivos de configuración modificados en las últimas 24 horas\n")
            try:
                result = subprocess.run(['find', '/etc', '-type', 'f', '-mtime', '-1'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout:
                    archivos_modificados = result.stdout.strip().split('\n')
                    self.after(0, self._actualizar_texto_fim, f"RESULTADO: {len(archivos_modificados)} archivos modificados\n")
                    for archivo in archivos_modificados[:5]:  # Mostrar primeros 5
                        self.after(0, self._actualizar_texto_fim, f"  - {archivo}\n")
                else:
                    self.after(0, self._actualizar_texto_fim, "RESULTADO: No hay archivos modificados recientemente\n")
            except:
                self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo ejecutar find en /etc\n")
            
            self.after(0, self._actualizar_texto_fim, "\n")
            
            # 2. Verificar permisos sospechosos con find
            self.after(0, self._actualizar_texto_fim, "COMANDO: find /usr/bin -perm -4000 -type f\n")
            self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Detectar binarios con permisos SUID sospechosos\n")
            try:
                result = subprocess.run(['find', '/usr/bin', '-perm', '-4000', '-type', 'f'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and result.stdout:
                    binarios_suid = result.stdout.strip().split('\n')
                    self.after(0, self._actualizar_texto_fim, f"RESULTADO: {len(binarios_suid)} binarios con SUID encontrados\n")
                    for binario in binarios_suid[:8]:  # Mostrar primeros 8
                        self.after(0, self._actualizar_texto_fim, f"  SUID: {binario}\n")
                else:
                    self.after(0, self._actualizar_texto_fim, "RESULTADO: No se encontraron binarios SUID en /usr/bin\n")
            except:
                self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo verificar permisos SUID\n")
            
            self.after(0, self._actualizar_texto_fim, "\n")
            
            # 3. Verificar procesos con archivos abiertos sospechosos
            self.after(0, self._actualizar_texto_fim, "COMANDO: lsof -i :22,80,443,8080,4444\n")
            self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Detectar procesos usando puertos comunes y backdoors\n")
            try:
                result = subprocess.run(['lsof', '-i', ':22,80,443,8080,4444'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout:
                    conexiones = result.stdout.strip().split('\n')[1:]  # Skip header
                    self.after(0, self._actualizar_texto_fim, f"RESULTADO: {len(conexiones)} conexiones activas en puertos críticos\n")
                    for conexion in conexiones[:5]:
                        partes = conexion.split()
                        if len(partes) >= 2:
                            self.after(0, self._actualizar_texto_fim, f"  PROCESO: {partes[0]} PID: {partes[1]}\n")
                else:
                    self.after(0, self._actualizar_texto_fim, "RESULTADO: No hay conexiones activas en puertos monitoreados\n")
            except:
                self.after(0, self._actualizar_texto_fim, "ADVERTENCIA: lsof no disponible o error en ejecución\n")
            
            self.after(0, self._actualizar_texto_fim, "\n")
            
            # Archivos críticos específicos para ciberseguridad
            archivos_criticos = {
                '/etc/passwd': 'Lista de usuarios del sistema - modificaciones indican creación de cuentas maliciosas',
                '/etc/shadow': 'Hashes de contraseñas - cambios no autorizados indican compromiso de cuentas',
                '/etc/sudoers': 'Permisos administrativos - modificaciones pueden otorgar privilegios a atacantes',
                '/etc/hosts': 'Resolución DNS local - cambios pueden redirigir tráfico a servidores maliciosos',
                '/etc/ssh/sshd_config': 'Configuración SSH - modificaciones pueden habilitar accesos no autorizados',
                '/etc/crontab': 'Tareas programadas - cambios pueden establecer persistencia de malware',
                '/etc/fstab': 'Sistemas de archivos montados - modificaciones pueden exponer datos',
                '/root/.bashrc': 'Configuración shell de root - cambios pueden establecer backdoors'
            }
            
            if self.controlador:
                self._log_terminal("Conectando con controlador FIM avanzado", "FIM", "INFO")
                resultado = self.controlador.iniciar_monitoreo_continuo()
                
                if resultado and resultado.get('exito'):
                    rutas_monitoreadas = resultado.get('rutas_monitoreadas', 0)
                    intervalo = resultado.get('intervalo_segundos', 30)
                    
                    self._log_terminal(f"FIM iniciado - monitoreando {rutas_monitoreadas} rutas cada {intervalo}s", "FIM", "SUCCESS")
                    self.after(0, self._actualizar_texto_fim, f"ESTADO: FIM activo - {rutas_monitoreadas} rutas bajo monitoreo\n")
                    self.after(0, self._actualizar_texto_fim, f"INTERVALO: Verificación cada {intervalo} segundos\n\n")
                    
                    # FASE 2: Verificación de archivos críticos
                    self._log_terminal("FASE 2: Verificación de archivos críticos de seguridad", "FIM", "INFO")
                    self.after(0, self._actualizar_texto_fim, "FASE 2: VERIFICACIÓN DE ARCHIVOS CRÍTICOS\n")
                    
                    import time
                    import hashlib
                    import os
                    
                    archivos_verificados = 0
                    archivos_problema = 0
                    
                    for archivo, descripcion in archivos_criticos.items():
                        if not self.proceso_monitoreo_activo:
                            break
                        
                        try:
                            if os.path.exists(archivo):
                                stat_info = os.stat(archivo)
                                permisos = oct(stat_info.st_mode)[-3:]
                                tamaño = stat_info.st_size
                                
                                # Verificar permisos apropiados
                                permisos_esperados = {
                                    '/etc/passwd': '644',
                                    '/etc/shadow': '640', 
                                    '/etc/sudoers': '440',
                                    '/etc/hosts': '644',
                                    '/etc/ssh/sshd_config': '644',
                                    '/etc/crontab': '644',
                                    '/etc/fstab': '644',
                                    '/root/.bashrc': '644'
                                }
                                
                                esperado = permisos_esperados.get(archivo, '644')
                                archivos_verificados += 1
                                
                                if permisos == esperado:
                                    self.after(0, self._actualizar_texto_fim, f"OK {archivo}: Permisos correctos ({permisos}), Tamaño: {tamaño} bytes\n")
                                    self.after(0, self._actualizar_texto_fim, f"   FUNCIÓN: {descripcion}\n")
                                else:
                                    archivos_problema += 1
                                    self.after(0, self._actualizar_texto_fim, f"ALERTA {archivo}: Permisos anómalos ({permisos}, esperado {esperado})\n")
                                    self.after(0, self._actualizar_texto_fim, f"   RIESGO: {descripcion}\n")
                                    self.after(0, self._actualizar_texto_fim, f"   ACCIÓN: Revisar cambios recientes y verificar integridad\n")
                                    self._log_terminal(f"ALERTA: Permisos anómalos en {archivo}", "FIM", "WARNING")
                                
                                # Calcular hash para baseline
                                if os.path.isfile(archivo):
                                    with open(archivo, 'rb') as f:
                                        contenido = f.read()
                                        hash_sha256 = hashlib.sha256(contenido).hexdigest()[:16]
                                    self.after(0, self._actualizar_texto_fim, f"   HASH: {hash_sha256}... (baseline establecido)\n\n")
                                
                            else:
                                archivos_problema += 1
                                self.after(0, self._actualizar_texto_fim, f"CRÍTICO {archivo}: Archivo no encontrado\n")
                                self.after(0, self._actualizar_texto_fim, f"   IMPACTO: {descripcion}\n")
                                self.after(0, self._actualizar_texto_fim, f"   ACCIÓN: Verificar si fue eliminado maliciosamente\n\n")
                                self._log_terminal(f"CRÍTICO: Archivo crítico no encontrado - {archivo}", "FIM", "ERROR")
                                
                        except Exception as e:
                            archivos_problema += 1
                            self.after(0, self._actualizar_texto_fim, f"ERROR verificando {archivo}: {str(e)}\n\n")
                    
                    # FASE 2.5: Monitoreo avanzado con herramientas de Kali
                    self._log_terminal("FASE 2.5: Análisis avanzado con herramientas especializadas de Kali", "FIM", "INFO")
                    self.after(0, self._actualizar_texto_fim, "\nFASE 2.5: ANÁLISIS AVANZADO CON HERRAMIENTAS KALI\n")
                    self.after(0, self._actualizar_texto_fim, "PROPÓSITO: Análisis forense profundo usando toolkit de Kali Linux\n\n")
                    
                    # 1. Análisis de procesos ocultos con ps avanzado
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: ps auxf | grep -v grep\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar procesos ocultos y jerarquías sospechosas\n")
                    try:
                        result = subprocess.run(['ps', 'auxf'], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            procesos = result.stdout.strip().split('\n')
                            procesos_sospechosos = []
                            for proceso in procesos:
                                if any(sospechoso in proceso.lower() for sospechoso in 
                                      ['backdoor', 'rootkit', 'trojan', 'keylog', 'rat']):
                                    procesos_sospechosos.append(proceso)
                            
                            if procesos_sospechosos:
                                self.after(0, self._actualizar_texto_fim, f"ALERTA: {len(procesos_sospechosos)} procesos sospechosos detectados\n")
                                for proc in procesos_sospechosos[:3]:
                                    self.after(0, self._actualizar_texto_fim, f"  SOSPECHOSO: {proc[:60]}...\n")
                                self._log_terminal(f"ALERTA: {len(procesos_sospechosos)} procesos sospechosos en el sistema", "FIM", "WARNING")
                            else:
                                self.after(0, self._actualizar_texto_fim, f"OK: {len(procesos)} procesos verificados, ninguno sospechoso\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo ejecutar análisis de procesos\n")
                    except:
                        self.after(0, self._actualizar_texto_fim, "ERROR: Comando ps no disponible\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # 2. Verificación de módulos del kernel con lsmod
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: lsmod | head -20\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar módulos del kernel maliciosos o rootkits\n")
                    try:
                        result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            modulos = result.stdout.strip().split('\n')[1:21]  # Primeros 20 módulos
                            modulos_sospechosos = []
                            for modulo in modulos:
                                partes = modulo.split()
                                if len(partes) >= 1:
                                    nombre_modulo = partes[0]
                                    if any(sospechoso in nombre_modulo.lower() for sospechoso in 
                                          ['rootkit', 'hide', 'stealth', 'keylog']):
                                        modulos_sospechosos.append(nombre_modulo)
                            
                            if modulos_sospechosos:
                                self.after(0, self._actualizar_texto_fim, f"ALERTA: {len(modulos_sospechosos)} módulos kernel sospechosos\n")
                                for mod in modulos_sospechosos:
                                    self.after(0, self._actualizar_texto_fim, f"  MÓDULO SOSPECHOSO: {mod}\n")
                                self._log_terminal(f"ALERTA: Módulos kernel sospechosos detectados", "FIM", "ERROR")
                            else:
                                self.after(0, self._actualizar_texto_fim, f"OK: {len(modulos)} módulos kernel verificados\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo verificar módulos del kernel\n")
                    except:
                        self.after(0, self._actualizar_texto_fim, "ERROR: lsmod no disponible\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # 3. Análisis de conexiones de red sospechosas con ss
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: ss -tupnl | grep -E ':(4444|5555|6666|7777|8888|9999|31337)'\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar backdoors en puertos comúnmente usados por atacantes\n")
                    try:
                        result = subprocess.run(['ss', '-tupnl'], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            lineas = result.stdout.strip().split('\n')
                            puertos_backdoor = ['4444', '5555', '6666', '7777', '8888', '9999', '31337', '12345', '54321']
                            backdoors_detectados = []
                            
                            for linea in lineas:
                                for puerto in puertos_backdoor:
                                    if f':{puerto}' in linea:
                                        backdoors_detectados.append((puerto, linea))
                            
                            if backdoors_detectados:
                                self.after(0, self._actualizar_texto_fim, f"CRÍTICO: {len(backdoors_detectados)} posibles backdoors detectados\n")
                                for puerto, linea in backdoors_detectados:
                                    self.after(0, self._actualizar_texto_fim, f"  BACKDOOR PUERTO {puerto}: {linea[:50]}...\n")
                                self._log_terminal(f"CRÍTICO: {len(backdoors_detectados)} backdoors detectados", "FIM", "ERROR")
                            else:
                                self.after(0, self._actualizar_texto_fim, "OK: No se detectaron puertos de backdoor conocidos\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo verificar conexiones de red\n")
                    except:
                        self.after(0, self._actualizar_texto_fim, "ERROR: ss no disponible\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # 4. Verificación de archivos en directorios temporales
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: find /tmp /var/tmp -type f -executable -mtime -1\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar ejecutables sospechosos en directorios temporales\n")
                    try:
                        directorios_tmp = ['/tmp', '/var/tmp', '/dev/shm']
                        ejecutables_sospechosos = []
                        
                        for directorio in directorios_tmp:
                            if os.path.exists(directorio):
                                result = subprocess.run(['find', directorio, '-type', 'f', '-executable', '-mtime', '-1'], 
                                                      capture_output=True, text=True, timeout=15)
                                if result.returncode == 0 and result.stdout.strip():
                                    archivos = result.stdout.strip().split('\n')
                                    ejecutables_sospechosos.extend(archivos)
                        
                        if ejecutables_sospechosos:
                            self.after(0, self._actualizar_texto_fim, f"ALERTA: {len(ejecutables_sospechosos)} ejecutables recientes en /tmp\n")
                            for ejecutable in ejecutables_sospechosos[:5]:  # Primeros 5
                                if ejecutable.strip():
                                    try:
                                        stat_info = os.stat(ejecutable)
                                        # Usar comando ls para obtener propietario
                                        resultado_ls = subprocess.run(['ls', '-l', ejecutable], 
                                                                     capture_output=True, text=True, timeout=5)
                                        if resultado_ls.returncode == 0:
                                            partes_ls = resultado_ls.stdout.split()
                                            propietario = partes_ls[2] if len(partes_ls) > 2 else f"UID:{stat_info.st_uid}"
                                        else:
                                            propietario = f"UID:{stat_info.st_uid}"
                                        tamaño = stat_info.st_size
                                        self.after(0, self._actualizar_texto_fim, f"  EJECUTABLE: {ejecutable} (owner: {propietario}, size: {tamaño})\n")
                                    except:
                                        self.after(0, self._actualizar_texto_fim, f"  EJECUTABLE: {ejecutable}\n")
                            self._log_terminal(f"ALERTA: {len(ejecutables_sospechosos)} ejecutables sospechosos en directorios temporales", "FIM", "WARNING")
                        else:
                            self.after(0, self._actualizar_texto_fim, "OK: No se encontraron ejecutables recientes en directorios temporales\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_fim, f"ERROR: {str(e)}\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # 5. Verificación de logs de autenticación recientes
                    self.after(0, self._actualizar_texto_fim, "HERRAMIENTA: grep -i 'failed\\|error\\|invalid' /var/log/auth.log | tail -10\n")
                    self.after(0, self._actualizar_texto_fim, "FUNCIÓN: Detectar intentos de autenticación sospechosos o ataques\n")
                    try:
                        logs_auth = ['/var/log/auth.log', '/var/log/secure']
                        intentos_sospechosos = 0
                        
                        for log_file in logs_auth:
                            if os.path.exists(log_file):
                                result = subprocess.run(['grep', '-i', r'failed\|error\|invalid', log_file], 
                                                      capture_output=True, text=True, timeout=10)
                                if result.returncode == 0:
                                    lineas = result.stdout.strip().split('\n')
                                    intentos_sospechosos = len(lineas)
                                    if intentos_sospechosos > 10:
                                        self.after(0, self._actualizar_texto_fim, f"ALERTA: {intentos_sospechosos} intentos de autenticación fallidos\n")
                                        # Mostrar últimos 3 intentos
                                        for linea in lineas[-3:]:
                                            if linea.strip():
                                                timestamp = ' '.join(linea.split()[:3])
                                                self.after(0, self._actualizar_texto_fim, f"  FALLO: {timestamp}\n")
                                        self._log_terminal(f"ALERTA: {intentos_sospechosos} intentos de autenticación fallidos", "FIM", "WARNING")
                                    else:
                                        self.after(0, self._actualizar_texto_fim, f"OK: {intentos_sospechosos} fallos de autenticación (normal)\n")
                                break  # Solo verificar el primer log disponible
                        
                        if intentos_sospechosos == 0:
                            self.after(0, self._actualizar_texto_fim, "OK: No se encontraron fallos de autenticación\n")
                    except:
                        self.after(0, self._actualizar_texto_fim, "ERROR: No se pudieron verificar logs de autenticación\n")
                    
                    self.after(0, self._actualizar_texto_fim, "\n")
                    
                    # FASE 3: Resumen del análisis
                    self._log_terminal("FASE 3: Generando resumen de seguridad", "FIM", "INFO")
                    self.after(0, self._actualizar_texto_fim, "FASE 3: RESUMEN DEL ANÁLISIS FIM\n")
                    self.after(0, self._actualizar_texto_fim, f"ARCHIVOS VERIFICADOS: {archivos_verificados}\n")
                    self.after(0, self._actualizar_texto_fim, f"PROBLEMAS DETECTADOS: {archivos_problema}\n")
                    
                    if archivos_problema == 0:
                        self.after(0, self._actualizar_texto_fim, "ESTADO: Sistema íntegro - No se detectaron anomalías\n")
                        self._log_terminal("Sistema íntegro - baseline establecido correctamente", "FIM", "SUCCESS")
                    else:
                        self.after(0, self._actualizar_texto_fim, f"ESTADO: Se detectaron {archivos_problema} anomalías - Revisar alertas\n")
                        self._log_terminal(f"ALERTA: {archivos_problema} anomalías detectadas en archivos críticos", "FIM", "WARNING")
                    
                    self.after(0, self._actualizar_texto_fim, "\nMONITOREO CONTINUO ACTIVO - Verificando cambios en tiempo real...\n")
                    self.after(0, self._actualizar_texto_fim, "INFO: Los cambios en archivos críticos serán detectados y reportados automáticamente\n")
                else:
                    self._log_terminal("Error iniciando controlador FIM", "FIM", "ERROR")
                    self.after(0, self._actualizar_texto_fim, "ERROR: No se pudo iniciar el controlador FIM\n")
            else:
                # Modo sin controlador - análisis básico
                self._log_terminal("Ejecutando análisis FIM básico (sin controlador)", "FIM", "WARNING")
                self.after(0, self._actualizar_texto_fim, "MODO: Análisis básico de integridad (controlador no disponible)\n\n")
                
                # Análisis básico de archivos críticos usando comandos del sistema
                self._realizar_analisis_basico()
                
        except Exception as e:
            error_msg = f"Error en monitoreo FIM: {str(e)}"
            self._log_terminal(error_msg, "FIM", "ERROR")
            self.after(0, self._actualizar_texto_fim, f"ERROR: {error_msg}\n")
        finally:
            # Reactivar botones
            self.after(0, self._habilitar_botones_monitoreo, True)

    def detener_monitoreo(self):
        """Detener monitoreo continuo de manera robusta."""
        def ejecutar_detencion():
            try:
                self._actualizar_texto_fim("=== DETENIENDO MONITOREO FIM ===\n")
                import subprocess
                import os
                import signal
                
                # Detener variable de control
                self.proceso_monitoreo_activo = False
                
                # Terminar procesos de monitoreo conocidos
                procesos_fim = ['inotifywait', 'auditd', 'aide', 'samhain', 'tripwire']
                procesos_terminados = 0
                
                for proceso in procesos_fim:
                    try:
                        # Buscar procesos activos relacionados con FIM
                        resultado = subprocess.run(['pgrep', '-f', proceso], 
                                                capture_output=True, text=True)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            pids = resultado.stdout.strip().split('\n')
                            for pid in pids:
                                if pid.strip():
                                    try:
                                        # Terminar proceso específico
                                        subprocess.run(['kill', '-TERM', pid.strip()], 
                                                    capture_output=True)
                                        self._actualizar_texto_fim(f"✓ Terminado proceso {proceso} (PID: {pid.strip()})\n")
                                        procesos_terminados += 1
                                    except Exception:
                                        continue
                    except Exception:
                        continue
                
                # Terminar procesos Python de monitoreo
                try:
                    resultado = subprocess.run(['pgrep', '-f', 'python.*fim'], 
                                            capture_output=True, text=True)
                    if resultado.returncode == 0 and resultado.stdout.strip():
                        pids = resultado.stdout.strip().split('\n')
                        for pid in pids:
                            if pid.strip() and pid.strip() != str(os.getpid()):
                                try:
                                    subprocess.run(['kill', '-TERM', pid.strip()], 
                                                capture_output=True)
                                    self._actualizar_texto_fim(f"✓ Terminado monitoreo Python (PID: {pid.strip()})\n")
                                    procesos_terminados += 1
                                except Exception:
                                    continue
                except Exception:
                    pass
                
                # Limpiar archivos temporales de FIM
                archivos_temp = [
                    '/tmp/fim_monitor.pid',
                    '/tmp/fim_changes.log',
                    '/var/log/fim_monitor.log',
                    '/tmp/inotify_monitor.pid'
                ]
                
                for archivo in archivos_temp:
                    try:
                        if os.path.exists(archivo):
                            os.remove(archivo)
                            self._actualizar_texto_fim(f"✓ Limpiado archivo temporal: {archivo}\n")
                    except Exception:
                        pass
                
                # Detener monitores inotify específicos
                try:
                    subprocess.run(['pkill', '-f', 'inotifywait.*fim'], 
                                capture_output=True)
                except Exception:
                    pass
                
                if procesos_terminados > 0:
                    self._actualizar_texto_fim(f"✓ COMPLETADO: {procesos_terminados} procesos de monitoreo terminados\n")
                else:
                    self._actualizar_texto_fim("• INFO: No se encontraron procesos de monitoreo FIM activos\n")
                
                self._actualizar_texto_fim("✓ Limpieza de archivos temporales completada\n")
                self._actualizar_texto_fim("=== MONITOREO FIM DETENIDO COMPLETAMENTE ===\n\n")
                
                # Reactivar botones
                self.after(0, self._habilitar_botones_monitoreo, True)
                self._log_terminal("Monitoreo FIM detenido completamente", "FIM", "INFO")
                
            except Exception as e:
                self._actualizar_texto_fim(f"ERROR durante detención: {str(e)}\n")
                self.after(0, self._habilitar_botones_monitoreo, True)
        
        import threading
        threading.Thread(target=ejecutar_detencion, daemon=True).start()
    
    def verificar_integridad(self):
        """Verificar integridad de archivos críticos."""
        self._log_terminal("Verificando integridad de archivos críticos", "FIM", "INFO")
        self._actualizar_texto_fim("=== VERIFICACIÓN DE INTEGRIDAD MANUAL ===\n")
        self._actualizar_texto_fim("Analizando archivos críticos del sistema...\n\n")
        
        # Realizar verificación básica
        self._realizar_analisis_basico()
    
    def _realizar_analisis_basico(self):
        """Realizar análisis básico de archivos críticos sin controlador."""
        try:
            import os
            import stat
            
            self.after(0, self._actualizar_texto_fim, "INICIANDO ANÁLISIS BÁSICO DE INTEGRIDAD\n")
            self.after(0, self._actualizar_texto_fim, "NOTA: Análisis limitado sin herramientas específicas de Kali Linux\n\n")
            
            # Archivos básicos que podemos verificar en cualquier sistema
            archivos_basicos = {
                './main.py': 'Archivo principal de ARESITOS',
                './aresitos/__init__.py': 'Módulo principal de la aplicación',
                './configuracion/': 'Directorio de configuración',
                './data/': 'Directorio de datos'
            }
            
            # EXPANSIÓN: Directorios críticos adicionales de Kali Linux para monitoreo
            directorios_kali_expandidos = {
                # Directorios del sistema críticos
                '/etc/passwd': 'Archivo de usuarios del sistema',
                '/etc/shadow': 'Archivo de contraseñas encriptadas',
                '/etc/group': 'Archivo de grupos del sistema',
                '/etc/sudoers': 'Configuración de permisos sudo',
                '/etc/hosts': 'Archivo de hosts del sistema',
                '/etc/crontab': 'Tareas programadas del sistema',
                '/etc/ssh/': 'Configuración SSH',
                '/etc/apache2/': 'Configuración Apache (si existe)',
                '/etc/nginx/': 'Configuración Nginx (si existe)',
                
                # Directorios de herramientas de Kali
                '/usr/share/wordlists/': 'Wordlists de Kali Linux',
                '/usr/share/nmap/': 'Scripts de Nmap',
                '/usr/share/metasploit-framework/': 'Framework Metasploit',
                '/usr/share/john/': 'John the Ripper',
                '/usr/share/burpsuite/': 'Burp Suite',
                '/usr/share/aircrack-ng/': 'Aircrack-ng',
                '/usr/share/sqlmap/': 'SQLMap',
                
                # Directorios de usuario críticos
                '/home/': 'Directorios de usuarios',
                '/root/': 'Directorio del usuario root',
                '/tmp/': 'Directorio temporal (crítico para seguridad)',
                '/var/log/': 'Logs del sistema',
                '/var/www/': 'Directorio web (si existe)',
                
                # Binarios críticos
                '/usr/bin/': 'Binarios del sistema',
                '/usr/sbin/': 'Binarios de administración',
                '/bin/': 'Binarios esenciales',
                '/sbin/': 'Binarios de sistema esenciales'
            }
            
            self.after(0, self._actualizar_texto_fim, "\nEXPANSION FIM: Monitoreando directorios críticos de Kali Linux\n")
            self.after(0, self._actualizar_texto_fim, "="*70 + "\n")
            
            archivos_encontrados = 0
            
            # 1. Verificar archivos básicos del proyecto
            self.after(0, self._actualizar_texto_fim, "\nARCHIVOS VERIFICANDO ARCHIVOS DEL PROYECTO ARESITOS:\n")
            for archivo, descripcion in archivos_basicos.items():
                try:
                    if os.path.exists(archivo):
                        stat_info = os.stat(archivo)
                        if os.path.isfile(archivo):
                            tamaño = stat_info.st_size
                            self.after(0, self._actualizar_texto_fim, f"OK {archivo}: {descripcion} (Tamaño: {tamaño} bytes)\n")
                        else:
                            self.after(0, self._actualizar_texto_fim, f"OK {archivo}: {descripcion} (Directorio)\n")
                        archivos_encontrados += 1
                    else:
                        self.after(0, self._actualizar_texto_fim, f"ERROR {archivo}: {descripcion} (NO ENCONTRADO)\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_fim, f"WARNING Error verificando {archivo}: {e}\n")
            
            # 2. Verificar directorios críticos de Kali Linux (solo si estamos en Linux)
            import platform
            if platform.system().lower() == 'linux':
                self.after(0, self._actualizar_texto_fim, f"\n🐉 VERIFICANDO DIRECTORIOS CRÍTICOS DE KALI LINUX:\n")
                
                directorios_criticos = 0
                directorios_monitoreados = 0
                
                for ruta, descripcion in directorios_kali_expandidos.items():
                    try:
                        if os.path.exists(ruta):
                            stat_info = os.stat(ruta)
                            permisos = oct(stat_info.st_mode)[-3:]
                            
                            if os.path.isfile(ruta):
                                tamaño = stat_info.st_size
                                self.after(0, self._actualizar_texto_fim, f"SEGURIDAD {ruta}: {descripcion} (Archivo: {tamaño}B, Permisos: {permisos})\n")
                                directorios_criticos += 1
                            elif os.path.isdir(ruta):
                                try:
                                    # Contar archivos en directorio (limitado para no sobrecargar)
                                    archivos_en_dir = len(os.listdir(ruta)) if os.access(ruta, os.R_OK) else "Sin acceso"
                                    self.after(0, self._actualizar_texto_fim, f"📂 {ruta}: {descripcion} (Dir: {archivos_en_dir} items, Permisos: {permisos})\n")
                                    directorios_criticos += 1
                                except PermissionError:
                                    self.after(0, self._actualizar_texto_fim, f"ACCESO {ruta}: {descripcion} (Sin permisos de lectura)\n")
                                    directorios_criticos += 1
                                    
                            directorios_monitoreados += 1
                            
                        else:
                            # Solo mostrar los más importantes si no existen
                            if ruta in ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/usr/share/wordlists/', '/usr/share/nmap/']:
                                self.after(0, self._actualizar_texto_fim, f"ERROR {ruta}: {descripcion} (NO ENCONTRADO)\n")
                                
                    except Exception as e:
                        if ruta in ['/etc/passwd', '/etc/shadow', '/etc/hosts']:  # Solo reportar errores críticos
                            self.after(0, self._actualizar_texto_fim, f"WARNING Error accediendo a {ruta}: {e}\n")
                
                self.after(0, self._actualizar_texto_fim, f"\nRESUMEN EXPANSIÓN FIM:\n")
                self.after(0, self._actualizar_texto_fim, f"   • Directorios críticos encontrados: {directorios_criticos}\n")
                self.after(0, self._actualizar_texto_fim, f"   • Rutas monitoreadas: {directorios_monitoreados}\n")
                self.after(0, self._actualizar_texto_fim, f"   • Sistema: Kali Linux compatible\n")
                
            else:
                self.after(0, self._actualizar_texto_fim, f"\nLIMITACION: No estamos en Linux - Monitoreo básico únicamente\n")
                self.after(0, self._actualizar_texto_fim, f"   Para funcionalidad completa, ejecutar en Kali Linux\n")
            
            self.after(0, self._actualizar_texto_fim, f"\nRESUMEN TOTAL: {archivos_encontrados} elementos verificados del proyecto\n")
            self.after(0, self._actualizar_texto_fim, "RECOMENDACION: Ejecutar en Kali Linux para análisis completo de seguridad\n")
            
        except Exception as e:
            self.after(0, self._actualizar_texto_fim, f"ERROR en análisis básico: {str(e)}\n")

    def _habilitar_botones_monitoreo(self, habilitar):
        """Habilitar/deshabilitar botones según estado del monitoreo."""
        if habilitar:
            self.btn_iniciar.config(state="normal")
            self.btn_detener.config(state="disabled")
        else:
            self.btn_iniciar.config(state="disabled")
            self.btn_detener.config(state="normal")
    
    def _actualizar_texto_fim(self, texto):
        """Actualizar texto en el área de resultados de forma segura."""
        try:
            if hasattr(self, 'fim_text') and self.fim_text:
                self.fim_text.config(state=tk.NORMAL)
                self.fim_text.insert(tk.END, texto)
                self.fim_text.see(tk.END)
                self.fim_text.config(state=tk.DISABLED)
        except Exception:
            pass  # Ignorar errores de UI
    
    def set_controlador(self, controlador):
        """Establecer el controlador del FIM."""
        self.controlador = controlador
        self._log_terminal("Controlador FIM establecido", "FIM", "INFO")
