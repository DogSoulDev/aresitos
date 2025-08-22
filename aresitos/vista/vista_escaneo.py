# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import logging
import threading
import datetime

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaEscaneo(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_activo = False
        self.thread_escaneo = None
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
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
                'fg_secondary': 'gray',
                'fg_accent': 'black',
                'button_bg': 'lightgray',
                'button_fg': 'black',
                'success': 'green',
                'warning': 'orange',
                'danger': 'red',
                'info': 'blue'
            }
            
        self.crear_widgets()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame superior para el contenido principal
        main_frame = tk.Frame(self.paned_window, bg=self.colors['bg_primary'])
        self.paned_window.add(main_frame, minsize=400)
        
        # Título con tema Burp Suite
        titulo_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill="x", pady=(10, 15))
        
        titulo_label = tk.Label(titulo_frame, text="ESCANEADOR DE VULNERABILIDADES", 
                              font=('Arial', 14, 'bold'),
                              bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo_label.pack()
        
        # Frame de botones con tema
        btn_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        btn_frame.pack(fill="x", pady=(0, 10))
        
        # Botones con tema Burp Suite
        self.btn_escanear = tk.Button(btn_frame, text="Escanear Sistema", 
                                    command=self.ejecutar_escaneo,
                                    bg=self.colors['fg_accent'], fg='white', 
                                    font=('Arial', 10, 'bold'),
                                    relief='flat', padx=15, pady=8,
                                    activebackground=self.colors['danger'],
                                    activeforeground='white')
        self.btn_escanear.pack(side="left", padx=(0, 10))
        
        self.btn_cancelar_escaneo = tk.Button(btn_frame, text="Cancelar", 
                                            command=self.cancelar_escaneo,
                                            state="disabled",
                                            bg=self.colors['button_bg'], fg='white',
                                            font=('Arial', 10),
                                            relief='flat', padx=15, pady=8,
                                            activebackground=self.colors['danger'],
                                            activeforeground='white')
        self.btn_cancelar_escaneo.pack(side="left", padx=(0, 15))
        
        self.btn_logs = tk.Button(btn_frame, text="Ver Logs", 
                                command=self.ver_logs,
                                bg=self.colors['button_bg'], fg='white',
                                font=('Arial', 10),
                                relief='flat', padx=15, pady=8,
                                activebackground=self.colors['fg_accent'],
                                activeforeground='white')
        self.btn_logs.pack(side="left", padx=(0, 10))
        
        self.btn_eventos = tk.Button(btn_frame, text="Eventos SIEM", 
                                   command=self.ver_eventos,
                                   bg=self.colors['button_bg'], fg='white',
                                   font=('Arial', 10),
                                   relief='flat', padx=15, pady=8,
                                   activebackground=self.colors['fg_accent'],
                                   activeforeground='white')
        self.btn_eventos.pack(side="left")
        
        # Área de resultados con tema Burp Suite
        self.text_resultados = scrolledtext.ScrolledText(main_frame, height=20,
                                                       bg=self.colors['bg_secondary'], 
                                                       fg=self.colors['fg_primary'],
                                                       font=('Consolas', 10),
                                                       insertbackground=self.colors['fg_accent'],
                                                       selectbackground=self.colors['fg_accent'],
                                                       relief='flat', bd=1)
        
        self.text_resultados.pack(fill="both", expand=True, padx=10)
        
        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado Escaneo con diseño estándar coherente."""
        try:
            # Frame del terminal estilo dashboard
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - Escaneador",
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
                command=self.limpiar_terminal_escaneo,
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
                command=self.abrir_logs_escaneo,
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
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - Escaneador v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, f"Sistema: Kali Linux - Network & Vulnerability Scanner\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Escaneador en tiempo real\n\n")
            
            self.log_to_terminal("Terminal Escaneo iniciado correctamente")
            
        except Exception as e:
            print(f"Error creando terminal integrado en Vista Escaneo: {e}")
    
    def limpiar_terminal_escaneo(self):
        """Limpiar terminal Escaneo manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - Escaneador v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - Network & Vulnerability Scanner\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal Escaneador reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Escaneador: {e}")
    
    def abrir_logs_escaneo(self):
        """Abrir carpeta de logs Escaneador."""
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
                self.log_to_terminal("Carpeta de logs Escaneador abierta")
            else:
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
        except Exception as e:
            self.log_to_terminal(f"ERROR abriendo logs Escaneador: {e}")
    
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
        """Sincronizar terminal - funcionalidad mantenida para compatibilidad."""
        # Esta función se mantiene para compatibilidad pero ahora usa terminal_output
        pass
    
    def ejecutar_escaneo(self):
        """Ejecutar escaneo del sistema."""
        if self.proceso_activo:
            return
            
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de escaneo configurado")
            return
        
        # Limpiar resultados anteriores
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Iniciando escaneo...\n\n")
        
        # Log al terminal integrado
        self._log_terminal("INICIANDO escaneo del sistema", "ESCANEADOR", "INFO")
        self.log_to_terminal("Iniciando escaneo del sistema...")
        
        # Configurar UI para escaneo
        self.proceso_activo = True
        self.btn_escanear.config(state="disabled")
        self.btn_cancelar_escaneo.config(state="normal")
        
        # Ejecutar escaneo en thread separado
        self.thread_escaneo = threading.Thread(target=self._ejecutar_escaneo_async)
        self.thread_escaneo.daemon = True
        self.thread_escaneo.start()
    
    def _log_terminal(self, mensaje, modulo="ESCANEADOR", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")
    
    def _actualizar_texto_seguro(self, texto):
        """Actualizar texto de resultados de forma segura desde cualquier hilo."""
        def _update():
            try:
                if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                    self.text_resultados.insert(tk.END, texto)
                    self.text_resultados.see(tk.END)
            except tk.TclError:
                pass  # Widget ya no existe
        
        try:
            self.after_idle(_update)
        except:
            pass  # Si no se puede programar, ignorar
    
    def _ejecutar_escaneo_async(self):
        """Ejecutar escaneo completo del sistema usando herramientas nativas de Kali Linux."""
        try:
            if not self.proceso_activo:
                return
            
            self._log_terminal("Iniciando escaneo completo con herramientas nativas de Kali Linux", "ESCANEADOR", "INFO")
            
            # FASE 1: Escaneo de red local con herramientas de Kali
            self._log_terminal("FASE 1: Reconocimiento de red con herramientas de Kali", "ESCANEADOR", "INFO")
            self._escaneo_red_kali()
            
            # FASE 2: Verificación de servicios y puertos
            self._log_terminal("FASE 2: Análisis de servicios con ss y netstat", "ESCANEADOR", "INFO")
            self._escanear_servicios_kali()
            
            # FASE 3: Escaneo de archivos críticos del sistema
            self._log_terminal("FASE 3: Verificando archivos críticos del sistema", "ESCANEADOR", "INFO")
            self._escanear_archivos_criticos()
            
            # FASE 4: Verificación de permisos sospechosos
            self._log_terminal("FASE 2: Analizando permisos sospechosos", "ESCANEADOR", "WARNING")
            self._escanear_permisos_sospechosos()
            
            # FASE 3: Búsqueda de malware y rootkits
            self._log_terminal("FASE 3: Escaneando en busca de malware y rootkits", "ESCANEADOR", "WARNING")
            self._escanear_malware_rootkits()
            
            # FASE 4: Verificación de procesos sospechosos
            self._log_terminal("FASE 4: Analizando procesos en ejecución", "ESCANEADOR", "INFO")
            self._escanear_procesos_sospechosos()
            
            # FASE 5: Análisis de conexiones de red
            self._log_terminal("FASE 5: Verificando conexiones de red", "ESCANEADOR", "INFO")
            self._escanear_conexiones_red()
            
            # FASE 6: Verificación de usuarios y grupos
            self._log_terminal("FASE 6: Analizando usuarios y grupos del sistema", "ESCANEADOR", "INFO")
            self._escanear_usuarios_grupos()
            
            # FASE 7: Búsqueda de vulnerabilidades conocidas
            self._log_terminal("FASE 7: Escaneando vulnerabilidades conocidas", "ESCANEADOR", "ERROR")
            self._escanear_vulnerabilidades()
            
            # FASE 8: Análisis avanzado con herramientas Kali
            self._log_terminal("FASE 8: Análisis con herramientas especializadas de Kali", "ESCANEADOR", "WARNING")
            self._escaneo_avanzado_kali()
            
            # FASE 9: Verificación de configuraciones de seguridad
            self._log_terminal("FASE 9: Verificando configuraciones de seguridad del sistema", "ESCANEADOR", "INFO")
            self._verificar_configuraciones_seguridad()
            
            # FASE 10: Detección de rootkits con herramientas nativas
            self._log_terminal("FASE 10: Detección avanzada de rootkits y backdoors", "ESCANEADOR", "ERROR")
            self._detectar_rootkits_avanzado()
            
            self._log_terminal("Escaneo completo del sistema finalizado", "ESCANEADOR", "SUCCESS")
            
        except Exception as e:
            if self.proceso_activo:
                self._log_terminal(f"Error durante el escaneo completo: {str(e)}", "ESCANEADOR", "ERROR")
                self.after(0, self._mostrar_error_escaneo, str(e))
        finally:
            self.after(0, self._finalizar_escaneo)
    
    def _analizar_amenazas_detectadas(self, resultados):
        """Analizar resultados en busca de amenazas y vulnerabilidades."""
        try:
            # Analizar puertos sospechosos
            puertos_peligrosos = {
                '22': 'SSH - Posible acceso remoto',
                '23': 'Telnet - Protocolo inseguro',
                '25': 'SMTP - Servidor de correo',
                '53': 'DNS - Servidor de nombres',
                '80': 'HTTP - Servidor web',
                '135': 'RPC - Servicio Windows crítico',
                '139': 'NetBIOS - Compartición Windows',
                '443': 'HTTPS - Servidor web seguro',
                '445': 'SMB - Compartición archivos Windows',
                '993': 'IMAPS - Correo seguro',
                '995': 'POP3S - Correo seguro',
                '3389': 'RDP - Escritorio remoto Windows'
            }
            
            puertos_encontrados = resultados.get('puertos', [])
            if puertos_encontrados:
                self._log_terminal(f"🔌 Detectados {len(puertos_encontrados)} puertos activos", "ESCANEADOR", "WARNING")
                
                for puerto_info in puertos_encontrados:
                    # Extraer número de puerto de la información
                    for puerto_num, descripcion in puertos_peligrosos.items():
                        if puerto_num in str(puerto_info):
                            self._log_terminal(f"ALERTA PUERTO CRÍTICO: {puerto_num} - {descripcion}", "ESCANEADOR", "WARNING")
                            break
            
            # Analizar procesos sospechosos
            procesos = resultados.get('procesos', [])
            procesos_sospechosos = [
                'nc', 'netcat', 'ncat',  # Herramientas de red
                'python', 'perl', 'ruby',  # Interpretes (pueden ejecutar malware)
                'wget', 'curl',  # Descargas
                'ssh', 'telnet',  # Acceso remoto
                'tor', 'i2p',  # Anonimización
            ]
            
            for proceso in procesos[:20]:  # Analizar primeros 20 procesos
                proceso_lower = proceso.lower()
                for sospechoso in procesos_sospechosos:
                    if sospechoso in proceso_lower:
                        self._log_terminal(f"ALERTA PROCESO SOSPECHOSO: {proceso.strip()}", "ESCANEADOR", "WARNING")
                        break
            
            # Análisis de configuración de seguridad
            analisis = resultados.get('análisis', [])
            if analisis:
                for item in analisis:
                    if any(palabra in item.lower() for palabra in ['error', 'fail', 'vulnerable', 'insecure', 'weak']):
                        self._log_terminal(f"🔓 VULNERABILIDAD: {item}", "ESCANEADOR", "ERROR")
                    elif any(palabra in item.lower() for palabra in ['warning', 'caution', 'deprecated']):
                        self._log_terminal(f"ADVERTENCIA: {item}", "ESCANEADOR", "WARNING")
                        
        except Exception as e:
            self._log_terminal(f"ERROR analizando amenazas: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _mostrar_resultados_escaneo(self, resultados):
        """Mostrar resultados en la UI y en el terminal integrado."""
        if not self.proceso_activo:
            return
        
        # Log detallado en el terminal integrado
        self._log_terminal("MOSTRANDO resultados del escaneo", "ESCANEADOR", "INFO")
        
        # Mostrar en la UI tradicional
        self.text_resultados.insert(tk.END, "=== PUERTOS ===\n")
        puertos_encontrados = resultados.get('puertos', [])
        for linea in puertos_encontrados:
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        # Log de puertos al terminal integrado
        if puertos_encontrados:
            self._log_terminal(f"🔌 Encontrados {len(puertos_encontrados)} puertos", "ESCANEADOR", "SUCCESS")
            for puerto in puertos_encontrados[:3]:  # Mostrar solo los primeros 3
                self._log_terminal(f"  └─ {puerto}", "ESCANEADOR", "INFO")
        else:
            self._log_terminal("🔌 No se encontraron puertos activos", "ESCANEADOR", "INFO")
        
        self.text_resultados.insert(tk.END, "\n=== PROCESOS ===\n")
        procesos_encontrados = resultados.get('procesos', [])[:10]  # Mostrar solo 10
        for linea in procesos_encontrados:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de procesos al terminal integrado
        if procesos_encontrados:
            self._log_terminal(f"ENCONTRADOS {len(procesos_encontrados)} procesos", "ESCANEADOR", "SUCCESS")
        
        self.text_resultados.insert(tk.END, "\n=== ANÁLISIS ===\n")
        analisis = resultados.get('análisis', [])
        for linea in analisis:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de análisis al terminal integrado
        if analisis:
            self._log_terminal(f"ANÁLISIS completado: {len(analisis)} elementos", "ESCANEADOR", "SUCCESS")
            
        # Resumen final en terminal integrado
        total_elementos = len(puertos_encontrados) + len(procesos_encontrados) + len(analisis)
        self._log_terminal(f"COMPLETADO Escaneo finalizado: {total_elementos} elementos analizados", "ESCANEADOR", "SUCCESS")
    
    def _mostrar_error_escaneo(self, error):
        """Mostrar error en la UI."""
        self.text_resultados.insert(tk.END, f"\n Error durante el escaneo: {error}\n")
    
    def _finalizar_escaneo(self):
        """Finalizar el proceso de escaneo."""
        self.proceso_activo = False
        self.btn_escanear.config(state="normal")
        self.btn_cancelar_escaneo.config(state="disabled")
        self.thread_escaneo = None
    
    def cancelar_escaneo(self):
        """Cancelar el escaneo en curso de manera robusta."""
        def ejecutar_cancelacion():
            try:
                self.text_resultados.insert(tk.END, "\n=== CANCELANDO ESCANEO EN CURSO ===\n")
                import subprocess
                import os
                
                # Detener variable de control
                self.proceso_activo = False
                
                # Terminar procesos de escaneo conocidos
                procesos_escaneo = ['nmap', 'masscan', 'rustscan', 'nikto', 'gobuster', 
                                  'feroxbuster', 'dirb', 'wfuzz', 'sqlmap', 'nuclei', 'httpx']
                procesos_terminados = 0
                
                for proceso in procesos_escaneo:
                    try:
                        # Buscar procesos activos
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
                                        self.text_resultados.insert(tk.END, f"✓ Terminado proceso {proceso} (PID: {pid.strip()})\n")
                                        procesos_terminados += 1
                                    except Exception:
                                        continue
                    except Exception:
                        continue
                
                # Terminar procesos Python de escaneo
                try:
                    resultado = subprocess.run(['pgrep', '-f', 'python.*escan'], 
                                            capture_output=True, text=True)
                    if resultado.returncode == 0 and resultado.stdout.strip():
                        pids = resultado.stdout.strip().split('\n')
                        for pid in pids:
                            if pid.strip() and pid.strip() != str(os.getpid()):
                                try:
                                    subprocess.run(['kill', '-TERM', pid.strip()], 
                                                capture_output=True)
                                    self.text_resultados.insert(tk.END, f"✓ Terminado escaneo Python (PID: {pid.strip()})\n")
                                    procesos_terminados += 1
                                except Exception:
                                    continue
                except Exception:
                    pass
                
                # Limpiar archivos temporales de escaneo
                archivos_temp = [
                    '/tmp/nmap_scan.xml',
                    '/tmp/masscan_output.txt',
                    '/tmp/nikto_output.txt',
                    '/tmp/gobuster_output.txt',
                    '/tmp/escaneo_temp.log'
                ]
                
                for archivo in archivos_temp:
                    try:
                        if os.path.exists(archivo):
                            os.remove(archivo)
                            self.text_resultados.insert(tk.END, f"✓ Limpiado archivo temporal: {archivo}\n")
                    except Exception:
                        pass
                
                if procesos_terminados > 0:
                    self.text_resultados.insert(tk.END, f"✓ COMPLETADO: {procesos_terminados} procesos de escaneo terminados\n")
                else:
                    self.text_resultados.insert(tk.END, "• INFO: No se encontraron procesos de escaneo activos\n")
                
                self.text_resultados.insert(tk.END, "=== CANCELACIÓN DE ESCANEO COMPLETADA ===\n\n")
                
                # Log al terminal
                self._log_terminal("Escaneo cancelado completamente", "ESCANEADOR", "INFO")
                
            except Exception as e:
                self.text_resultados.insert(tk.END, f"ERROR durante cancelación: {str(e)}\n")
        
        import threading
        threading.Thread(target=ejecutar_cancelacion, daemon=True).start()

    def _verificar_herramientas_kali(self):
        """Verificar herramientas esenciales de Kali Linux."""
        import subprocess
        
        herramientas_kali = [
            'nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'sqlmap',
            'metasploit', 'msfconsole', 'john', 'hashcat', 'hydra',
            'aircrack-ng', 'wireshark', 'tcpdump', 'netcat', 'socat',
            'binwalk', 'foremost', 'volatility', 'yara', 'chkrootkit',
            'rkhunter', 'clamscan', 'lynis'
        ]
        
        herramientas_encontradas = 0
        total_herramientas = len(herramientas_kali)
        
        for herramienta in herramientas_kali:
            try:
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, text=True, timeout=3)
                if resultado.returncode == 0:
                    ruta = resultado.stdout.strip()
                    self._log_terminal(f"OK: {herramienta} disponible en {ruta}", "VERIFICADOR", "INFO")
                    herramientas_encontradas += 1
                else:
                    self._log_terminal(f"WARNING: {herramienta} no encontrada", "VERIFICADOR", "WARNING")
            except:
                self._log_terminal(f"ERROR: No se pudo verificar {herramienta}", "VERIFICADOR", "WARNING")
                
        porcentaje = (herramientas_encontradas / total_herramientas) * 100
        self._log_terminal(f"Herramientas Kali disponibles: {herramientas_encontradas}/{total_herramientas} ({porcentaje:.1f}%)", "VERIFICADOR", "INFO")

    def _verificar_servicios_sistema(self):
        """Verificar servicios críticos del sistema."""
        import subprocess
        
        servicios_criticos = [
            'systemd', 'dbus', 'networkd', 'resolved', 'ssh'
        ]
        
        for servicio in servicios_criticos:
            try:
                resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                         capture_output=True, text=True, timeout=5)
                estado = resultado.stdout.strip()
                
                if estado == 'active':
                    self._log_terminal(f"OK: Servicio {servicio} activo", "VERIFICADOR", "INFO")
                elif estado == 'inactive':
                    self._log_terminal(f"INFO: Servicio {servicio} inactivo", "VERIFICADOR", "INFO")
                else:
                    self._log_terminal(f"WARNING: Servicio {servicio} en estado {estado}", "VERIFICADOR", "WARNING")
                    
            except Exception as e:
                self._log_terminal(f"ERROR: No se pudo verificar servicio {servicio}", "VERIFICADOR", "WARNING")

    def _verificar_paquetes_sistema(self):
        """Verificar integridad de paquetes del sistema."""
        import subprocess
        
        try:
            # Verificar base de datos de paquetes
            self._log_terminal("Verificando base de datos de paquetes APT...", "VERIFICADOR", "INFO")
            resultado = subprocess.run(['dpkg', '--audit'], 
                                     capture_output=True, text=True, timeout=15)
            
            if resultado.returncode == 0 and not resultado.stdout.strip():
                self._log_terminal("OK: Base de datos de paquetes integra", "VERIFICADOR", "INFO")
            else:
                self._log_terminal("WARNING: Se encontraron problemas en la base de datos de paquetes", "VERIFICADOR", "WARNING")
                
            # Verificar paquetes esenciales de Kali
            paquetes_esenciales = [
                'kali-linux-core', 'apt', 'dpkg', 'systemd', 'openssh-server'
            ]
            
            for paquete in paquetes_esenciales:
                try:
                    resultado = subprocess.run(['dpkg', '-l', paquete], 
                                             capture_output=True, text=True, timeout=5)
                    if 'ii' in resultado.stdout:
                        self._log_terminal(f"OK: Paquete {paquete} instalado correctamente", "VERIFICADOR", "INFO")
                    else:
                        self._log_terminal(f"WARNING: Paquete {paquete} no encontrado o problemas", "VERIFICADOR", "WARNING")
                except:
                    self._log_terminal(f"ERROR: No se pudo verificar paquete {paquete}", "VERIFICADOR", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error verificando paquetes: {str(e)}", "VERIFICADOR", "WARNING")

    def _verificar_configuracion_red(self):
        """Verificar configuración de red del sistema."""
        import subprocess
        
        try:
            # Verificar interfaces de red
            resultado = subprocess.run(['ip', 'link', 'show'], 
                                     capture_output=True, text=True, timeout=5)
            interfaces = []
            for linea in resultado.stdout.split('\n'):
                if ': ' in linea and 'state' in linea.lower():
                    nombre = linea.split(': ')[1].split('@')[0]
                    estado = 'UP' if 'state UP' in linea else 'DOWN'
                    interfaces.append((nombre, estado))
                    
            for nombre, estado in interfaces:
                if nombre != 'lo':  # Ignorar loopback
                    self._log_terminal(f"Interfaz {nombre}: {estado}", "VERIFICADOR", "INFO")
                    
            # Verificar resolución DNS
            try:
                resultado = subprocess.run(['nslookup', 'google.com'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    self._log_terminal("OK: Resolucion DNS funcionando", "VERIFICADOR", "INFO")
                else:
                    self._log_terminal("WARNING: Problemas con resolucion DNS", "VERIFICADOR", "WARNING")
            except:
                self._log_terminal("WARNING: No se pudo verificar DNS", "VERIFICADOR", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error verificando red: {str(e)}", "VERIFICADOR", "WARNING")
    
    def ver_logs(self):
        """Ver logs almacenados de escaneos y verificaciones - se auto-eliminan al cerrar programa."""
        if not self.controlador:
            self._log_terminal("Error: No hay controlador configurado", "LOGS", "ERROR")
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "=== LOGS DE ESCANEO Y VERIFICACION ===\n\n")
        
        self._log_terminal("Consultando logs almacenados", "LOGS", "INFO")
        
        # Obtener logs desde el controlador
        try:
            logs = self.controlador.obtener_logs_escaneo()
            
            # Crear archivo temporal de logs si no existe
            import tempfile
            import os
            
            logs_temporales = getattr(self, '_logs_temporales', [])
            
            # Agregar logs del terminal integrado si están disponibles
            try:
                # Los logs del terminal se manejan directamente por VistaDashboard
                # Por ahora usamos solo los logs del controlador
                pass
            except:
                pass
                
            # Mostrar logs en pantalla
            if logs:
                self.text_resultados.insert(tk.END, "=== LOGS DEL CONTROLADOR ===\n")
                for linea in logs:
                    self.text_resultados.insert(tk.END, f"{linea}\n")
                self.text_resultados.insert(tk.END, "\n")
                
            if logs_temporales:
                self.text_resultados.insert(tk.END, "=== LOGS DEL TERMINAL INTEGRADO ===\n")
                for log_entry in logs_temporales[-50:]:  # Últimos 50 logs
                    self.text_resultados.insert(tk.END, f"{log_entry}\n")
            else:
                self.text_resultados.insert(tk.END, "No se encontraron logs almacenados.\n")
                
            # Almacenar logs para persistencia temporal
            self._logs_temporales = logs_temporales
            
            # Programar auto-eliminación al cerrar (registrar callback)
            if not hasattr(self, '_auto_limpieza_registrada'):
                self._auto_limpieza_registrada = True
                import atexit
                atexit.register(self._limpiar_logs_temporales)
                
            self._log_terminal(f"Logs consultados: {len(logs)} del controlador, {len(logs_temporales)} del terminal", "LOGS", "INFO")
            
        except AttributeError:
            self.text_resultados.insert(tk.END, "Error: Controlador no implementa obtener_logs_escaneo\n")
            self._log_terminal("Error: Metodo obtener_logs_escaneo no disponible", "LOGS", "ERROR")
        except Exception as e:
            self.text_resultados.insert(tk.END, f"Error obteniendo logs: {str(e)}\n")
            self._log_terminal(f"Error obteniendo logs: {str(e)}", "LOGS", "ERROR")

    def _limpiar_logs_temporales(self):
        """Limpiar logs temporales al cerrar el programa."""
        try:
            if hasattr(self, '_logs_temporales'):
                self._logs_temporales.clear()
                print("[ARESITOS] Logs temporales eliminados al cerrar programa")
        except:
            pass
    
    def ver_eventos(self):
        """Analizar y mostrar eventos SIEM reales del sistema."""
        import subprocess
        import os
        from datetime import datetime
        
        try:
            self.text_resultados.delete(1.0, tk.END)
            self._actualizar_texto_seguro("=== ANÁLISIS DE EVENTOS SIEM REALES ===\n\n")
            
            self._log_terminal("Iniciando análisis de eventos SIEM del sistema", "SIEM_ANALYZER", "INFO")
            
            # 1. Analizar logs de autenticación para eventos de seguridad
            self.text_resultados.insert(tk.END, "EVENTOS DE AUTENTICACIÓN:\n")
            try:
                result = subprocess.run(['grep', '-E', 'Failed password|Invalid user|authentication failure', '/var/log/auth.log'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    auth_events = result.stdout.strip().split('\n')
                    recent_events = auth_events[-10:] if auth_events else []
                    
                    if recent_events and any(event.strip() for event in recent_events):
                        for event in recent_events:
                            if event.strip():
                                parts = event.split()
                                if len(parts) >= 3:
                                    timestamp = ' '.join(parts[:3])
                                    self.text_resultados.insert(tk.END, f"   ALERTA {timestamp}: {event.split(':', 1)[1] if ':' in event else event}\n")
                    else:
                        self.text_resultados.insert(tk.END, "   OK No se detectaron eventos de autenticación sospechosos\n")
                else:
                    self.text_resultados.insert(tk.END, "   ADVERTENCIA No se pudo acceder a /var/log/auth.log\n")
            except Exception as e:
                self.text_resultados.insert(tk.END, f"   ERROR analizando auth.log: {str(e)}\n")
            
            # 2. Analizar conexiones de red activas
            self.text_resultados.insert(tk.END, "\nANÁLISIS DE RED:\n")
            try:
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    connections = result.stdout.strip().split('\n')[1:]  # Skip header
                    suspicious_ports = []
                    backdoor_ports = ['4444', '6666', '9999', '31337', '12345']
                    
                    for conn in connections:
                        for port in backdoor_ports:
                            if f':{port} ' in conn or f':{port}\t' in conn:
                                suspicious_ports.append(conn)
                                break
                    
                    if suspicious_ports:
                        self.text_resultados.insert(tk.END, "   ALERTA PUERTOS SOSPECHOSOS DETECTADOS:\n")
                        for port in suspicious_ports:
                            self.text_resultados.insert(tk.END, f"      • {port.strip()}\n")
                    else:
                        self.text_resultados.insert(tk.END, "   OK No se detectaron puertos backdoor activos\n")
                        
                    # Contar conexiones por estado
                    listening_count = len([c for c in connections if 'LISTEN' in c])
                    self.text_resultados.insert(tk.END, f"   SERVICIOS en escucha: {listening_count}\n")
                else:
                    self.text_resultados.insert(tk.END, "   ADVERTENCIA Error ejecutando comando ss\n")
            except Exception as e:
                self.text_resultados.insert(tk.END, f"   ERROR analizando red: {str(e)}\n")
            
            # 3. Analizar procesos sospechosos
            self.text_resultados.insert(tk.END, "\nANÁLISIS DE PROCESOS:\n")
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    processes = result.stdout.strip().split('\n')
                    suspicious_patterns = ['nc ', 'netcat', 'python -c', 'perl -e', 'bash -i', '/dev/tcp']
                    suspicious_procs = []
                    
                    for proc in processes:
                        proc_lower = proc.lower()
                        for pattern in suspicious_patterns:
                            if pattern in proc_lower:
                                suspicious_procs.append(proc)
                                break
                    
                    if suspicious_procs:
                        self.text_resultados.insert(tk.END, "   ALERTA PROCESOS SOSPECHOSOS DETECTADOS:\n")
                        for proc in suspicious_procs[:5]:  # Limitar a 5 procesos
                            parts = proc.split()
                            if len(parts) >= 11:
                                user = parts[0]
                                pid = parts[1]
                                cpu = parts[2]
                                cmd = ' '.join(parts[10:])[:50]  # Limitar longitud
                                self.text_resultados.insert(tk.END, f"      • PID {pid} ({user}): {cmd}... (CPU: {cpu}%)\n")
                    else:
                        self.text_resultados.insert(tk.END, "   OK No se detectaron procesos sospechosos\n")
                        
                    # Detectar procesos con alto uso de CPU
                    high_cpu_procs = []
                    for proc in processes[1:]:  # Skip header
                        parts = proc.split()
                        if len(parts) >= 3:
                            try:
                                cpu_usage = float(parts[2])
                                if cpu_usage > 80.0:
                                    high_cpu_procs.append((parts[1], parts[10] if len(parts) > 10 else "unknown", cpu_usage))
                            except ValueError:
                                continue
                    
                    if high_cpu_procs:
                        self.text_resultados.insert(tk.END, "   ADVERTENCIA PROCESOS CON ALTO USO DE CPU:\n")
                        for pid, cmd, cpu in high_cpu_procs[:3]:
                            self.text_resultados.insert(tk.END, f"      • PID {pid}: {cmd} ({cpu}% CPU)\n")
                        
                else:
                    self.text_resultados.insert(tk.END, "   ADVERTENCIA Error ejecutando comando ps\n")
            except Exception as e:
                self.text_resultados.insert(tk.END, f"   ERROR analizando procesos: {str(e)}\n")
            
            # 4. Verificar integridad de archivos críticos del sistema
            self.text_resultados.insert(tk.END, "\nINTEGRIDAD DE ARCHIVOS CRÍTICOS:\n")
            critical_files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/sudoers', '/etc/ssh/sshd_config']
            
            for file_path in critical_files:
                try:
                    if os.path.exists(file_path):
                        stat_info = os.stat(file_path)
                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        permissions = oct(stat_info.st_mode)[-3:]
                        
                        # Verificar permisos apropiados
                        expected_perms = {
                            'passwd': '644', 'shadow': '640', 'hosts': '644', 
                            'sudoers': '440', 'sshd_config': '644'
                        }
                        file_name = os.path.basename(file_path)
                        expected = expected_perms.get(file_name, '644')
                        
                        if permissions == expected:
                            self.text_resultados.insert(tk.END, f"   OK {file_path}: CORRECTO (permisos {permissions}, mod: {mod_time})\n")
                        else:
                            self.text_resultados.insert(tk.END, f"   ALERTA {file_path}: PERMISOS ANÓMALOS ({permissions}, esperado {expected})\n")
                    else:
                        self.text_resultados.insert(tk.END, f"   ERROR {file_path}: Archivo no encontrado\n")
                except Exception as e:
                    self.text_resultados.insert(tk.END, f"   ADVERTENCIA Error verificando {file_path}: {str(e)}\n")
            
            # 5. Analizar logs del sistema en busca de errores críticos
            self.text_resultados.insert(tk.END, "\nANÁLISIS DE LOGS DEL SISTEMA:\n")
            try:
                result = subprocess.run(['grep', '-i', 'error\\|fail\\|critical\\|alert', '/var/log/syslog'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    system_errors = result.stdout.strip().split('\n')
                    recent_errors = system_errors[-5:] if system_errors else []
                    
                    if recent_errors and any(error.strip() for error in recent_errors):
                        self.text_resultados.insert(tk.END, "   ADVERTENCIA ERRORES RECIENTES DEL SISTEMA:\n")
                        for error in recent_errors:
                            if error.strip():
                                parts = error.split()
                                if len(parts) >= 3:
                                    timestamp = ' '.join(parts[:3])
                                    message = ' '.join(parts[4:])[:80]  # Limitar longitud
                                    self.text_resultados.insert(tk.END, f"      • {timestamp}: {message}...\n")
                    else:
                        self.text_resultados.insert(tk.END, "   OK No se detectaron errores críticos recientes\n")
                else:
                    self.text_resultados.insert(tk.END, "   OK No se encontraron errores en syslog\n")
            except Exception as e:
                self.text_resultados.insert(tk.END, f"   ERROR analizando syslog: {str(e)}\n")
            
            self.text_resultados.insert(tk.END, "\n=== ANÁLISIS SIEM COMPLETADO ===\n")
            self._log_terminal("Análisis de eventos SIEM completado", "SIEM_ANALYZER", "INFO")
            
        except Exception as e:
            error_msg = f"Error en análisis SIEM: {str(e)}"
            self.text_resultados.insert(tk.END, f"ERROR {error_msg}\n")
            self._log_terminal(error_msg, "SIEM_ANALYZER", "ERROR")

    def _escanear_archivos_criticos(self):
        """Escanear archivos críticos del sistema en busca de modificaciones sospechosas."""
        import subprocess
        import os
        
        archivos_criticos = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
            '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
            '/etc/ssh/sshd_config', '/etc/crontab', '/boot/grub/grub.cfg',
            '/etc/fstab', '/etc/network/interfaces'
        ]
        
        for archivo in archivos_criticos:
            try:
                if os.path.exists(archivo):
                    # Verificar permisos del archivo
                    stat_info = os.stat(archivo)
                    permisos = oct(stat_info.st_mode)[-3:]
                    
                    # Verificar permisos sospechosos
                    if archivo in ['/etc/passwd', '/etc/group'] and permisos != '644':
                        self._log_terminal(f"VULNERABILIDAD CRITICA: {archivo} tiene permisos incorrectos ({permisos})", "ESCANEADOR", "ERROR")
                    elif archivo == '/etc/shadow' and permisos not in ['640', '600']:
                        self._log_terminal(f"VULNERABILIDAD CRITICA: {archivo} tiene permisos incorrectos ({permisos})", "ESCANEADOR", "ERROR")
                    elif archivo == '/etc/sudoers' and permisos != '440':
                        self._log_terminal(f"VULNERABILIDAD CRITICA: {archivo} tiene permisos incorrectos ({permisos})", "ESCANEADOR", "ERROR")
                    else:
                        self._log_terminal(f"OK: {archivo} - permisos correctos ({permisos})", "ESCANEADOR", "INFO")
                        
                    # Verificar modificaciones recientes
                    resultado = subprocess.run(['find', archivo, '-mtime', '-1'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.stdout.strip():
                        self._log_terminal(f"ALERTA: {archivo} modificado en las ultimas 24 horas", "ESCANEADOR", "WARNING")
                        
                else:
                    self._log_terminal(f"VULNERABILIDAD CRITICA: Archivo critico {archivo} no encontrado", "ESCANEADOR", "ERROR")
                    
            except Exception as e:
                self._log_terminal(f"Error verificando {archivo}: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_permisos_sospechosos(self):
        """Buscar archivos con permisos sospechosos que podrían ser una amenaza."""
        import subprocess
        
        try:
            # Buscar archivos SUID sospechosos
            self._log_terminal("Escaneando archivos SUID sospechosos...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['find', '/', '-type', 'f', '-perm', '-4000', '2>/dev/null'], 
                                     capture_output=True, text=True, timeout=30, shell=True)
            
            archivos_suid = resultado.stdout.strip().split('\n') if resultado.stdout.strip() else []
            
            # Lista de archivos SUID legítimos comunes
            suid_legitimos = [
                '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su', '/bin/mount', '/bin/umount',
                '/usr/bin/gpasswd', '/usr/bin/newgrp', '/usr/bin/chsh', '/usr/bin/chfn'
            ]
            
            for archivo in archivos_suid:
                if archivo.strip() and archivo not in suid_legitimos:
                    self._log_terminal(f"AMENAZA POTENCIAL: Archivo SUID sospechoso - {archivo}", "ESCANEADOR", "ERROR")
                    
            # Buscar archivos world-writable
            self._log_terminal("Escaneando archivos world-writable...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['find', '/', '-type', 'f', '-perm', '-002', '2>/dev/null'], 
                                     capture_output=True, text=True, timeout=30, shell=True)
            
            archivos_writable = resultado.stdout.strip().split('\n') if resultado.stdout.strip() else []
            for archivo in archivos_writable[:10]:  # Limitar salida
                if archivo.strip():
                    self._log_terminal(f"RIESGO DE SEGURIDAD: Archivo world-writable - {archivo}", "ESCANEADOR", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error escaneando permisos: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_malware_rootkits(self):
        """Escanear en busca de malware y rootkits usando herramientas nativas."""
        import subprocess
        import os
        
        try:
            # Verificar procesos ocultos
            self._log_terminal("Buscando procesos ocultos...", "ESCANEADOR", "WARNING")
            try:
                resultado = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                procesos = len(resultado.stdout.strip().split('\n')) - 1
                self._log_terminal(f"Procesos activos encontrados: {procesos}", "ESCANEADOR", "INFO")
            except:
                pass
                
            # Verificar archivos en /tmp sospechosos
            self._log_terminal("Verificando archivos temporales sospechosos...", "ESCANEADOR", "WARNING")
            directorios_tmp = ['/tmp', '/var/tmp', '/dev/shm']
            
            for directorio in directorios_tmp:
                if os.path.exists(directorio):
                    try:
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-executable'], 
                                                 capture_output=True, text=True, timeout=10)
                        ejecutables = resultado.stdout.strip().split('\n') if resultado.stdout.strip() else []
                        
                        for ejecutable in ejecutables:
                            if ejecutable.strip():
                                self._log_terminal(f"ARCHIVO SOSPECHOSO: Ejecutable en {ejecutable}", "ESCANEADOR", "ERROR")
                    except:
                        pass
                        
            # Verificar conexiones de red sospechosas
            self._log_terminal("Verificando conexiones de red activas...", "ESCANEADOR", "INFO")
            try:
                resultado = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
                lineas = resultado.stdout.strip().split('\n')
                puertos_abiertos = []
                
                for linea in lineas:
                    if ':' in linea and 'LISTEN' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            puerto = partes[3].split(':')[-1]
                            puertos_abiertos.append(puerto)
                            
                # Puertos comúnmente usados por malware
                puertos_sospechosos = ['4444', '5555', '6666', '7777', '8888', '9999', '31337']
                for puerto in puertos_abiertos:
                    if puerto in puertos_sospechosos:
                        self._log_terminal(f"PUERTO SOSPECHOSO ABIERTO: {puerto} - posible backdoor", "ESCANEADOR", "ERROR")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando conexiones: {str(e)}", "ESCANEADOR", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error escaneando malware: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_procesos_sospechosos(self):
        """Analizar procesos en ejecución en busca de actividad sospechosa."""
        import subprocess
        
        try:
            # Obtener lista de procesos
            resultado = subprocess.run(['ps', 'auxww'], capture_output=True, text=True, timeout=15)
            lineas = resultado.stdout.strip().split('\n')[1:]  # Saltar header
            
            procesos_sospechosos = []
            palabras_sospechosas = [
                'nc', 'netcat', 'telnet', 'wget', 'curl', 'python -c', 'perl -e', 
                'bash -i', 'sh -i', '/dev/tcp', 'reverse', 'shell', 'backdoor'
            ]
            
            for linea in lineas:
                comando = linea.split(None, 10)[-1] if linea else ""
                
                # Verificar procesos con nombres sospechosos
                for palabra in palabras_sospechosas:
                    if palabra.lower() in comando.lower():
                        procesos_sospechosos.append(comando)
                        break
                        
                # Verificar procesos corriendo desde ubicaciones sospechosas
                if any(ubicacion in comando for ubicacion in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                    procesos_sospechosos.append(comando)
                    
            for proceso in procesos_sospechosos:
                self._log_terminal(f"PROCESO SOSPECHOSO: {proceso}", "ESCANEADOR", "ERROR")
                
            if not procesos_sospechosos:
                self._log_terminal("No se encontraron procesos sospechosos activos", "ESCANEADOR", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error analizando procesos: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_conexiones_red(self):
        """Verificar conexiones de red en busca de actividad sospechosa."""
        import subprocess
        
        try:
            # Verificar conexiones TCP activas
            self._log_terminal("Analizando conexiones TCP activas...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
            
            conexiones_sospechosas = []
            puertos_comunes_ataques = [
                '22', '23', '25', '53', '80', '110', '135', '139', '443', '445', 
                '993', '995', '1433', '1521', '3306', '3389', '5432', '5900'
            ]
            
            for linea in resultado.stdout.split('\n'):
                if 'LISTEN' in linea or 'ESTABLISHED' in linea:
                    partes = linea.split()
                    if len(partes) >= 4:
                        direccion_local = partes[3]
                        puerto = direccion_local.split(':')[-1]
                        
                        if puerto in puertos_comunes_ataques:
                            self._log_terminal(f"PUERTO CRITICO ABIERTO: {puerto} ({direccion_local})", "ESCANEADOR", "WARNING")
                            
            # Verificar interfaces de red
            resultado = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
            interfaces = []
            for linea in resultado.stdout.split('\n'):
                if 'inet ' in linea and '127.0.0.1' not in linea:
                    ip = linea.split()[1].split('/')[0]
                    interfaces.append(ip)
                    
            for ip in interfaces:
                self._log_terminal(f"Interfaz de red activa: {ip}", "ESCANEADOR", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error analizando conexiones de red: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_usuarios_grupos(self):
        """Verificar usuarios y grupos del sistema en busca de anomalías."""
        import subprocess
        
        try:
            # Verificar usuarios con UID 0 (root)
            self._log_terminal("Verificando usuarios con privilegios root...", "ESCANEADOR", "WARNING")
            with open('/etc/passwd', 'r') as f:
                lineas = f.readlines()
                
            usuarios_root = []
            usuarios_sin_shell = []
            
            for linea in lineas:
                partes = linea.strip().split(':')
                if len(partes) >= 7:
                    usuario = partes[0]
                    uid = partes[2]
                    shell = partes[6]
                    
                    if uid == '0' and usuario != 'root':
                        usuarios_root.append(usuario)
                        
                    if shell in ['/bin/bash', '/bin/sh', '/bin/zsh'] and uid != '0':
                        if int(uid) < 1000 and usuario not in ['daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody']:
                            usuarios_sin_shell.append(f"{usuario} (UID: {uid})")
                            
            for usuario in usuarios_root:
                self._log_terminal(f"VULNERABILIDAD CRITICA: Usuario con UID 0 adicional - {usuario}", "ESCANEADOR", "ERROR")
                
            # Verificar últimos logins
            try:
                resultado = subprocess.run(['last', '-n', '10'], capture_output=True, text=True, timeout=5)
                self._log_terminal("Ultimos 5 logins registrados:", "ESCANEADOR", "INFO")
                lineas = resultado.stdout.strip().split('\n')[:5]
                for linea in lineas:
                    if linea.strip() and 'reboot' not in linea.lower():
                        self._log_terminal(f"  {linea}", "ESCANEADOR", "INFO")
            except:
                pass
                
        except Exception as e:
            self._log_terminal(f"Error verificando usuarios: {str(e)}", "ESCANEADOR", "WARNING")

    def _escanear_vulnerabilidades(self):
        """Escanear vulnerabilidades conocidas del sistema con información detallada."""
        import subprocess
        import os
        from datetime import datetime
        
        try:
            # Verificar versión del kernel
            self._log_terminal("Verificando version del kernel...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
            kernel_version = resultado.stdout.strip()
            self._log_terminal(f"Kernel version: {kernel_version}", "ESCANEADOR", "INFO")
            
            # Verificar paquetes desactualizados con información detallada
            self._log_terminal("Verificando actualizaciones disponibles...", "ESCANEADOR", "INFO")
            try:
                resultado = subprocess.run(['apt', 'list', '--upgradable'], 
                                         capture_output=True, text=True, timeout=20)
                lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                actualizaciones = len(lineas)
                
                if actualizaciones > 0:
                    self._log_terminal(f"ATENCION: {actualizaciones} paquetes pueden actualizarse", "ESCANEADOR", "WARNING")
                    
                    # Mostrar paquetes críticos de seguridad
                    paquetes_criticos = []
                    for linea in lineas[:10]:  # Primeros 10 paquetes
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 2:
                                paquete = partes[0].split('/')[0]
                                version_nueva = partes[1]
                                # Identificar paquetes críticos de seguridad
                                if any(critico in paquete.lower() for critico in ['kernel', 'openssl', 'openssh', 'sudo', 'libc']):
                                    paquetes_criticos.append((paquete, version_nueva))
                                    self._log_terminal(f"PAQUETE CRÍTICO: {paquete} -> {version_nueva}", "SEGURIDAD", "ERROR")
                                else:
                                    self._log_terminal(f"Actualización disponible: {paquete} -> {version_nueva}", "ESCANEADOR", "INFO")
                else:
                    self._log_terminal("Sistema actualizado", "ESCANEADOR", "INFO")
            except:
                self._log_terminal("No se pudo verificar actualizaciones", "ESCANEADOR", "WARNING")
            
            # Verificar archivos sospechosos con información detallada
            self._log_terminal("Verificando archivos sospechosos en el sistema...", "ARCHIVOS", "INFO")
            try:
                directorios_criticos = ['/tmp', '/var/tmp', '/dev/shm', '/home']
                extensiones_sospechosas = ['.sh', '.py', '.pl', '.bin', '.exe']
                
                for directorio in directorios_criticos:
                    if os.path.exists(directorio):
                        # Buscar archivos ejecutables recientes
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-executable', '-mtime', '-7'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos = resultado.stdout.strip().split('\n')
                            for archivo in archivos[:5]:  # Primeros 5 archivos
                                if archivo.strip():
                                    try:
                                        stat_info = os.stat(archivo)
                                        tamaño = stat_info.st_size
                                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                        
                                        # Obtener propietario del archivo
                                        try:
                                            # Usar comando ls para obtener el propietario
                                            resultado_ls = subprocess.run(['ls', '-l', archivo], 
                                                                        capture_output=True, text=True, timeout=5)
                                            if resultado_ls.returncode == 0:
                                                partes_ls = resultado_ls.stdout.split()
                                                propietario = partes_ls[2] if len(partes_ls) > 2 else f"UID:{stat_info.st_uid}"
                                            else:
                                                propietario = f"UID:{stat_info.st_uid}"
                                        except:
                                            propietario = f"UID:{stat_info.st_uid}"
                                        
                                        # Obtener permisos
                                        permisos = oct(stat_info.st_mode)[-3:]
                                        
                                        self._log_terminal(f"ARCHIVO EJECUTABLE: {archivo}", "ARCHIVOS", "WARNING")
                                        self._log_terminal(f"  Propietario: {propietario}, Tamaño: {tamaño} bytes, Permisos: {permisos}", "ARCHIVOS", "INFO")
                                        self._log_terminal(f"  Fecha modificación: {mod_time}", "ARCHIVOS", "INFO")
                                        
                                        # Verificar hash del archivo si es pequeño
                                        if tamaño < 1024 * 1024:  # Menos de 1MB
                                            resultado_hash = subprocess.run(['sha256sum', archivo], 
                                                                           capture_output=True, text=True, timeout=10)
                                            if resultado_hash.returncode == 0:
                                                hash_value = resultado_hash.stdout.split()[0][:16]  # Primeros 16 caracteres
                                                self._log_terminal(f"  SHA256 (parcial): {hash_value}...", "ARCHIVOS", "INFO")
                                                
                                    except Exception as e:
                                        self._log_terminal(f"ARCHIVO EJECUTABLE: {archivo} (error leyendo info)", "ARCHIVOS", "WARNING")
                        
                        # Buscar archivos con extensiones sospechosas
                        for extension in extensiones_sospechosas:
                            resultado = subprocess.run(['find', directorio, '-name', f'*{extension}', '-mtime', '-7'], 
                                                     capture_output=True, text=True, timeout=20)
                            if resultado.returncode == 0 and resultado.stdout.strip():
                                archivos = resultado.stdout.strip().split('\n')
                                for archivo in archivos[:3]:  # Primeros 3 por extensión
                                    if archivo.strip():
                                        try:
                                            stat_info = os.stat(archivo)
                                            mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                            self._log_terminal(f"SCRIPT RECIENTE: {archivo} (mod: {mod_time})", "ARCHIVOS", "WARNING")
                                        except:
                                            self._log_terminal(f"SCRIPT RECIENTE: {archivo}", "ARCHIVOS", "WARNING")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando archivos sospechosos: {str(e)}", "ARCHIVOS", "WARNING")
                
            # Verificar servicios críticos con información adicional
            self._log_terminal("Verificando servicios críticos de seguridad...", "SERVICIOS", "INFO")
            servicios_criticos = {
                'ssh': 'Servicio SSH para conexiones remotas',
                'ufw': 'Firewall no complicado',
                'fail2ban': 'Protección contra ataques de fuerza bruta',
                'cron': 'Programador de tareas',
                'rsyslog': 'Sistema de logs'
            }
            
            for servicio, descripcion in servicios_criticos.items():
                try:
                    resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                             capture_output=True, text=True, timeout=5)
                    estado = resultado.stdout.strip()
                    
                    if estado == 'active':
                        self._log_terminal(f"SERVICIO ACTIVO: {servicio} - {descripcion}", "SERVICIOS", "INFO")
                        
                        # Obtener información adicional del servicio
                        resultado_status = subprocess.run(['systemctl', 'status', servicio, '--no-pager', '-l'], 
                                                        capture_output=True, text=True, timeout=5)
                        if resultado_status.returncode == 0:
                            lineas = resultado_status.stdout.split('\n')
                            for linea in lineas[:5]:  # Primeras 5 líneas del status
                                if 'Active:' in linea or 'Main PID:' in linea:
                                    info = linea.strip()
                                    self._log_terminal(f"  {info}", "SERVICIOS", "INFO")
                                    break
                    else:
                        self._log_terminal(f"RIESGO: Servicio {servicio} no activo - {descripcion}", "SERVICIOS", "WARNING")
                        
                except Exception as e:
                    self._log_terminal(f"No se pudo verificar servicio {servicio}: {str(e)}", "SERVICIOS", "WARNING")
            
            # Verificar logs de seguridad recientes
            self._log_terminal("Verificando logs de seguridad recientes...", "LOGS", "INFO")
            try:
                logs_seguridad = ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog']
                for log_file in logs_seguridad:
                    if os.path.exists(log_file):
                        # Buscar intentos de login fallidos
                        resultado = subprocess.run(['grep', '-i', r'failed\|failure\|invalid', log_file], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.strip().split('\n')
                            fallos_recientes = len(lineas)
                            if fallos_recientes > 0:
                                self._log_terminal(f"INTENTOS FALLIDOS: {fallos_recientes} intentos de login fallidos en {log_file}", "LOGS", "WARNING")
                                
                                # Mostrar las últimas 3 líneas más recientes
                                for linea in lineas[-3:]:
                                    if linea.strip():
                                        # Extraer timestamp y información relevante
                                        partes = linea.split()
                                        if len(partes) >= 3:
                                            timestamp = ' '.join(partes[:3])
                                            mensaje = ' '.join(partes[3:])[:50]  # Limitar longitud
                                            self._log_terminal(f"  {timestamp}: {mensaje}...", "LOGS", "WARNING")
                        break  # Solo verificar el primer log que exista
                        
            except Exception as e:
                self._log_terminal(f"Error verificando logs de seguridad: {str(e)}", "LOGS", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error escaneando vulnerabilidades: {str(e)}", "ESCANEADOR", "WARNING")

    def _escaneo_red_kali(self):
        """Escaneo de red usando herramientas nativas de Kali Linux."""
        try:
            import subprocess
            
            self._actualizar_texto_seguro("=== ESCANEO DE RED CON HERRAMIENTAS KALI ===\n\n")
            
            # 1. Obtener interfaz de red activa
            self._actualizar_texto_seguro("COMANDO: ip route | grep default\n")
            try:
                resultado = subprocess.run(['bash', '-c', 'ip route | grep default'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    ruta_default = resultado.stdout.strip()
                    interfaz = ruta_default.split()[-1] if len(ruta_default.split()) > 4 else 'unknown'
                    gateway = ruta_default.split()[2] if len(ruta_default.split()) > 2 else 'unknown'
                    self._actualizar_texto_seguro(f"INTERFAZ ACTIVA: {interfaz}\n")
                    self._actualizar_texto_seguro(f"GATEWAY: {gateway}\n\n")
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo determinar la ruta por defecto\n\n")
            except:
                self._actualizar_texto_seguro("ERROR: Comando ip route falló\n\n")
            
            # 2. Escaneo de red local con nmap si está disponible
            self._actualizar_texto_seguro("COMANDO: which nmap\n")
            try:
                resultado_nmap = subprocess.run(['which', 'nmap'], 
                                              capture_output=True, text=True, timeout=5)
                if resultado_nmap.returncode == 0:
                    self._actualizar_texto_seguro("NMAP DISPONIBLE: Ejecutando escaneo básico de red\n")
                    # Escaneo básico de la red local
                    try:
                        resultado_red = subprocess.run(['nmap', '-sn', '192.168.1.0/24'], 
                                                     capture_output=True, text=True, timeout=30)
                        if resultado_red.returncode == 0:
                            # Filtrar solo hosts que están UP
                            lineas = resultado_red.stdout.split('\n')
                            hosts_activos = []
                            for i, linea in enumerate(lineas):
                                if 'Nmap scan report for' in linea and i + 1 < len(lineas):
                                    if 'Host is up' in lineas[i + 1]:
                                        ip = linea.split()[-1]
                                        hosts_activos.append(ip)
                            
                            hosts_up = len(hosts_activos)
                            self._actualizar_texto_seguro(f"HOSTS ACTIVOS: {hosts_up} dispositivos detectados en red local\n")
                            # Mostrar solo IPs activas
                            for ip in hosts_activos:
                                self._actualizar_texto_seguro(f"  HOST: {ip}\n")
                        else:
                            self._actualizar_texto_seguro("ERROR: Escaneo nmap falló\n")
                    except subprocess.TimeoutExpired:
                        self._actualizar_texto_seguro("TIMEOUT: Escaneo nmap excedió tiempo límite\n")
                else:
                    self._actualizar_texto_seguro("NMAP NO DISPONIBLE: Usando métodos alternativos\n")
                    # Usar ping para escaneo básico
                    self._actualizar_texto_seguro("ALTERNATIVO: Usando ping para verificar gateway\n")
                    try:
                        ping_result = subprocess.run(['ping', '-c', '3', gateway], 
                                                   capture_output=True, text=True, timeout=15)
                        if ping_result.returncode == 0:
                            self._actualizar_texto_seguro(f"CONECTIVIDAD: Gateway {gateway} responde\n")
                        else:
                            self._actualizar_texto_seguro(f"PROBLEMA: Gateway {gateway} no responde\n")
                    except:
                        self._actualizar_texto_seguro("ERROR: No se pudo hacer ping al gateway\n")
            except:
                self._actualizar_texto_seguro("ERROR: No se pudo verificar disponibilidad de nmap\n")
            
            self._actualizar_texto_seguro("\n")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"ERROR EN ESCANEO DE RED: {str(e)}\n\n")

    def _escanear_servicios_kali(self):
        """Escaneo de servicios usando herramientas nativas de Linux."""
        try:
            import subprocess
            
            self._actualizar_texto_seguro("=== ANÁLISIS DE SERVICIOS CON HERRAMIENTAS LINUX ===\n\n")
            
            # 1. Servicios en escucha con ss
            self._actualizar_texto_seguro("COMANDO: ss -tuln\n")
            try:
                resultado = subprocess.run(['ss', '-tuln'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                    puertos_tcp = []
                    puertos_udp = []
                    
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 4:
                                protocolo = partes[0]
                                direccion_local = partes[3]
                                puerto = direccion_local.split(':')[-1]
                                
                                if protocolo.startswith('tcp'):
                                    puertos_tcp.append(puerto)
                                elif protocolo.startswith('udp'):
                                    puertos_udp.append(puerto)
                    
                    self._actualizar_texto_seguro(f"PUERTOS TCP EN ESCUCHA: {len(set(puertos_tcp))}\n")
                    for puerto in sorted(set(puertos_tcp))[:10]:  # Mostrar primeros 10
                        self._actualizar_texto_seguro(f"  TCP: {puerto}\n")
                    
                    self._actualizar_texto_seguro(f"PUERTOS UDP EN ESCUCHA: {len(set(puertos_udp))}\n")
                    for puerto in sorted(set(puertos_udp))[:5]:  # Mostrar primeros 5
                        self._actualizar_texto_seguro(f"  UDP: {puerto}\n")
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo ejecutar comando ss\n")
            except:
                self._actualizar_texto_seguro("ERROR: Comando ss no disponible\n")
            
            self._actualizar_texto_seguro("\n")
            
            # 2. Procesos con conexiones de red usando lsof
            self._actualizar_texto_seguro("COMANDO: lsof -i -n | head -15\n")
            try:
                resultado = subprocess.run(['bash', '-c', 'lsof -i -n | head -15'], 
                                         capture_output=True, text=True, timeout=15)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                    self._actualizar_texto_seguro("PROCESOS CON CONEXIONES DE RED:\n")
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 8:
                                proceso = partes[0]
                                pid = partes[1]
                                conexion = partes[7] if len(partes) > 7 else 'N/A'
                                self._actualizar_texto_seguro(f"  {proceso} (PID: {pid}): {conexion}\n")
                else:
                    self._actualizar_texto_seguro("INFO: lsof no mostró conexiones o no está disponible\n")
            except:
                self._actualizar_texto_seguro("ADVERTENCIA: lsof no disponible\n")
            
            self._actualizar_texto_seguro("\n")
            
            # 3. Servicios systemd activos
            self._actualizar_texto_seguro("COMANDO: systemctl list-units --type=service --state=running\n")
            try:
                resultado = subprocess.run(['bash', '-c', 'systemctl list-units --type=service --state=running | head -10'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                    servicios_activos = 0
                    for linea in lineas:
                        if '.service' in linea and 'running' in linea:
                            servicios_activos += 1
                            nombre_servicio = linea.split()[0].replace('.service', '')
                            self._actualizar_texto_seguro(f"  ACTIVO: {nombre_servicio}\n")
                    
                    self._actualizar_texto_seguro(f"TOTAL SERVICIOS ACTIVOS: {servicios_activos}\n")
                else:
                    self._actualizar_texto_seguro("ERROR: No se pudo listar servicios systemd\n")
            except:
                self._actualizar_texto_seguro("ERROR: systemctl no disponible\n")
                
            self._actualizar_texto_seguro("\n")
            
        except Exception as e:
            self._actualizar_texto_seguro(f"ERROR EN ANÁLISIS DE SERVICIOS: {str(e)}\n\n")
    
    def _escaneo_avanzado_kali(self):
        """Análisis avanzado con herramientas especializadas de Kali Linux."""
        import subprocess
        import os
        
        try:
            self._log_terminal("Iniciando análisis avanzado con herramientas Kali", "ESCANEADOR", "INFO")
            
            # 1. Verificar disponibilidad de herramientas de Kali
            herramientas_kali = {
                'nmap': 'Escaneador de puertos y servicios',
                'ss': 'Análisis de sockets y conexiones',
                'netstat': 'Estadísticas de red',
                'lsof': 'Archivos y conexiones abiertas',
                'chkrootkit': 'Detector de rootkits',
                'lynis': 'Auditor de seguridad del sistema',
                'rkhunter': 'Cazador de rootkits',
                'clamav': 'Antivirus'
            }
            
            herramientas_disponibles = []
            for herramienta, descripcion in herramientas_kali.items():
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        herramientas_disponibles.append(herramienta)
                        self._log_terminal(f"HERRAMIENTA DISPONIBLE: {herramienta} - {descripcion}", "KALI", "INFO")
                except:
                    pass
            
            # 2. Escaneo de puertos con nmap si está disponible
            if 'nmap' in herramientas_disponibles:
                self._log_terminal("Ejecutando escaneo de puertos con nmap...", "NMAP", "INFO")
                try:
                    # Escaneo básico de puertos comunes
                    resultado = subprocess.run(['nmap', '-sS', '-F', 'localhost'], 
                                             capture_output=True, text=True, timeout=60)
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.split('\n')
                        puertos_abiertos = []
                        for linea in lineas:
                            if '/tcp' in linea and 'open' in linea:
                                puerto = linea.split('/')[0].strip()
                                servicio = linea.split()[-1] if len(linea.split()) > 2 else 'unknown'
                                puertos_abiertos.append((puerto, servicio))
                                
                        if puertos_abiertos:
                            self._log_terminal(f"PUERTOS ABIERTOS DETECTADOS: {len(puertos_abiertos)}", "NMAP", "WARNING")
                            for puerto, servicio in puertos_abiertos[:10]:  # Mostrar primeros 10
                                self._log_terminal(f"  Puerto {puerto}: {servicio}", "NMAP", "INFO")
                        else:
                            self._log_terminal("No se detectaron puertos abiertos", "NMAP", "INFO")
                except Exception as e:
                    self._log_terminal(f"Error en escaneo nmap: {str(e)}", "NMAP", "WARNING")
            
            # 3. Análisis de procesos con comportamiento sospechoso
            self._log_terminal("Analizando procesos con alta actividad de red...", "PROCESO", "INFO")
            try:
                # Buscar procesos con muchas conexiones abiertas
                if 'lsof' in herramientas_disponibles:
                    resultado = subprocess.run(['lsof', '-i', '-n'], 
                                             capture_output=True, text=True, timeout=15)
                    if resultado.returncode == 0:
                        lineas = resultado.stdout.split('\n')[1:]  # Skip header
                        procesos_red = {}
                        
                        for linea in lineas:
                            if linea.strip():
                                partes = linea.split()
                                if len(partes) >= 2:
                                    proceso = partes[0]
                                    if proceso in procesos_red:
                                        procesos_red[proceso] += 1
                                    else:
                                        procesos_red[proceso] = 1
                        
                        # Identificar procesos con muchas conexiones
                        for proceso, conexiones in procesos_red.items():
                            if conexiones > 5:
                                self._log_terminal(f"PROCESO CON ALTA ACTIVIDAD DE RED: {proceso} ({conexiones} conexiones)", "PROCESO", "WARNING")
                
            except Exception as e:
                self._log_terminal(f"Error analizando procesos de red: {str(e)}", "PROCESO", "WARNING")
            
            # 4. Verificación de archivos binarios sospechosos
            self._log_terminal("Buscando archivos binarios en ubicaciones sospechosas...", "ARCHIVOS", "INFO")
            try:
                directorios_sospechosos = ['/tmp', '/var/tmp', '/dev/shm', '/home']
                for directorio in directorios_sospechosos:
                    if os.path.exists(directorio):
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-executable', 
                                                  '-newer', '/etc/passwd'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos = resultado.stdout.strip().split('\n')
                            for archivo in archivos[:5]:  # Mostrar primeros 5
                                if archivo.strip():
                                    try:
                                        stat_info = os.stat(archivo)
                                        tamaño = stat_info.st_size
                                        from datetime import datetime
                                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                        self._log_terminal(f"BINARIO SOSPECHOSO: {archivo} (tamaño: {tamaño} bytes, mod: {mod_time})", "ARCHIVOS", "WARNING")
                                    except:
                                        self._log_terminal(f"BINARIO SOSPECHOSO: {archivo}", "ARCHIVOS", "WARNING")
                        
            except Exception as e:
                self._log_terminal(f"Error buscando archivos sospechosos: {str(e)}", "ARCHIVOS", "WARNING")
            
            # 5. Verificación de servicios críticos del sistema
            self._log_terminal("Verificando estado de servicios críticos...", "SERVICIOS", "INFO")
            try:
                servicios_criticos = ['ssh', 'cron', 'rsyslog', 'systemd']
                for servicio in servicios_criticos:
                    resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                             capture_output=True, text=True, timeout=5)
                    estado = resultado.stdout.strip()
                    if estado == 'active':
                        self._log_terminal(f"SERVICIO CRÍTICO: {servicio} está ACTIVO", "SERVICIOS", "INFO")
                    else:
                        self._log_terminal(f"SERVICIO CRÍTICO: {servicio} está {estado}", "SERVICIOS", "WARNING")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando servicios: {str(e)}", "SERVICIOS", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error en análisis avanzado Kali: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _verificar_configuraciones_seguridad(self):
        """Verificar configuraciones críticas de seguridad del sistema."""
        import subprocess
        import os
        
        try:
            self._log_terminal("Verificando configuraciones críticas de seguridad", "SEGURIDAD", "INFO")
            
            # 1. Verificar configuración SSH
            ssh_config = '/etc/ssh/sshd_config'
            if os.path.exists(ssh_config):
                self._log_terminal("Analizando configuración SSH...", "SSH", "INFO")
                try:
                    with open(ssh_config, 'r') as f:
                        contenido = f.read()
                        
                    # Verificar configuraciones críticas
                    if 'PermitRootLogin no' in contenido or 'PermitRootLogin yes' not in contenido:
                        self._log_terminal("SSH: PermitRootLogin configurado correctamente", "SSH", "INFO")
                    else:
                        self._log_terminal("SSH: ADVERTENCIA - PermitRootLogin puede estar habilitado", "SSH", "WARNING")
                        
                    if 'PasswordAuthentication no' in contenido:
                        self._log_terminal("SSH: Autenticación por contraseña deshabilitada (seguro)", "SSH", "INFO")
                    else:
                        self._log_terminal("SSH: Autenticación por contraseña habilitada", "SSH", "WARNING")
                        
                except Exception as e:
                    self._log_terminal(f"Error leyendo configuración SSH: {str(e)}", "SSH", "WARNING")
            
            # 2. Verificar firewall
            self._log_terminal("Verificando estado del firewall...", "FIREWALL", "INFO")
            try:
                # Verificar iptables
                resultado = subprocess.run(['iptables', '-L'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')
                    reglas = len([l for l in lineas if l.strip() and not l.startswith('Chain') and not l.startswith('target')])
                    self._log_terminal(f"FIREWALL: {reglas} reglas iptables activas", "FIREWALL", "INFO")
                    
                    # Verificar si hay reglas DROP
                    if 'DROP' in resultado.stdout:
                        self._log_terminal("FIREWALL: Políticas de bloqueo detectadas", "FIREWALL", "INFO")
                    else:
                        self._log_terminal("FIREWALL: ADVERTENCIA - No se detectan políticas de bloqueo", "FIREWALL", "WARNING")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando firewall: {str(e)}", "FIREWALL", "WARNING")
            
            # 3. Verificar permisos de archivos críticos
            self._log_terminal("Verificando permisos de archivos críticos...", "PERMISOS", "INFO")
            archivos_criticos = {
                '/etc/passwd': '644',
                '/etc/shadow': '640',
                '/etc/sudoers': '440',
                '/boot': '755'
            }
            
            for archivo, permisos_esperados in archivos_criticos.items():
                if os.path.exists(archivo):
                    try:
                        stat_info = os.stat(archivo)
                        permisos_actuales = oct(stat_info.st_mode)[-3:]
                        
                        if permisos_actuales == permisos_esperados:
                            self._log_terminal(f"PERMISOS: {archivo} correcto ({permisos_actuales})", "PERMISOS", "INFO")
                        else:
                            self._log_terminal(f"PERMISOS: {archivo} INCORRECTO ({permisos_actuales}, esperado {permisos_esperados})", "PERMISOS", "WARNING")
                            
                    except Exception as e:
                        self._log_terminal(f"Error verificando permisos de {archivo}: {str(e)}", "PERMISOS", "WARNING")
            
            # 4. Verificar usuarios con privilegios
            self._log_terminal("Verificando usuarios con privilegios especiales...", "USUARIOS", "INFO")
            try:
                # Usuarios con UID 0 (root)
                resultado = subprocess.run(['awk', '-F:', '$3==0{print $1}', '/etc/passwd'], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    usuarios_root = resultado.stdout.strip().split('\n')
                    for usuario in usuarios_root:
                        if usuario.strip():
                            if usuario == 'root':
                                self._log_terminal(f"USUARIO ROOT: {usuario} (normal)", "USUARIOS", "INFO")
                            else:
                                self._log_terminal(f"USUARIO ROOT: {usuario} (SOSPECHOSO)", "USUARIOS", "ERROR")
                
                # Usuarios en grupo sudo
                if os.path.exists('/etc/group'):
                    resultado = subprocess.run(['grep', '^sudo:', '/etc/group'], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        linea_sudo = resultado.stdout.strip()
                        if ':' in linea_sudo:
                            usuarios_sudo = linea_sudo.split(':')[-1].split(',') if linea_sudo.split(':')[-1] else []
                            for usuario in usuarios_sudo:
                                if usuario.strip():
                                    self._log_terminal(f"USUARIO SUDO: {usuario.strip()}", "USUARIOS", "INFO")
                        
            except Exception as e:
                self._log_terminal(f"Error verificando usuarios: {str(e)}", "USUARIOS", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error verificando configuraciones de seguridad: {str(e)}", "SEGURIDAD", "ERROR")
    
    def _detectar_rootkits_avanzado(self):
        """Detección avanzada de rootkits y backdoors usando múltiples métodos."""
        import subprocess
        import os
        
        try:
            self._log_terminal("Iniciando detección avanzada de rootkits y backdoors", "ROOTKIT", "WARNING")
            
            # 1. Verificar herramientas de detección disponibles
            herramientas_deteccion = ['chkrootkit', 'rkhunter', 'clamav']
            herramientas_disponibles = []
            
            for herramienta in herramientas_deteccion:
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=5)
                    if resultado.returncode == 0:
                        herramientas_disponibles.append(herramienta)
                        self._log_terminal(f"DETECTOR DISPONIBLE: {herramienta}", "ROOTKIT", "INFO")
                except:
                    pass
            
            # 2. Verificar archivos de sistema modificados recientemente
            self._log_terminal("Verificando archivos de sistema modificados recientemente...", "ROOTKIT", "INFO")
            try:
                directorios_sistema = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
                for directorio in directorios_sistema:
                    if os.path.exists(directorio):
                        # Buscar archivos modificados en las últimas 24 horas
                        resultado = subprocess.run(['find', directorio, '-type', 'f', '-mtime', '-1'], 
                                                 capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos_modificados = resultado.stdout.strip().split('\n')
                            for archivo in archivos_modificados[:5]:  # Mostrar primeros 5
                                if archivo.strip():
                                    try:
                                        stat_info = os.stat(archivo)
                                        from datetime import datetime
                                        mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                                        self._log_terminal(f"SISTEMA MODIFICADO: {archivo} (mod: {mod_time})", "ROOTKIT", "WARNING")
                                    except:
                                        pass
                        
            except Exception as e:
                self._log_terminal(f"Error verificando archivos de sistema: {str(e)}", "ROOTKIT", "WARNING")
            
            # 3. Buscar procesos ocultos o sospechosos
            self._log_terminal("Buscando procesos ocultos o con nombres sospechosos...", "ROOTKIT", "INFO")
            try:
                resultado = subprocess.run(['ps', 'aux'], 
                                         capture_output=True, text=True, timeout=15)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]  # Skip header
                    procesos_sospechosos = []
                    
                    patrones_sospechosos = [
                        'kthreadd', 'ksoftirqd', '[', ']', 'migration', 'watchdog',
                        'rcu_', 'systemd', 'kworker', 'ksoftirqd'
                    ]
                    
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 11:
                                proceso = ' '.join(partes[10:])
                                
                                # Buscar patrones anómalos
                                if any(patron in proceso.lower() for patron in ['backdoor', 'rootkit', 'trojan']):
                                    procesos_sospechosos.append(proceso)
                                    self._log_terminal(f"PROCESO SOSPECHOSO: {proceso}", "ROOTKIT", "ERROR")
                                
                                # Procesos con nombres muy cortos o extraños
                                nombre_proceso = partes[10] if len(partes) > 10 else ''
                                if len(nombre_proceso) == 1 and nombre_proceso.isalpha():
                                    self._log_terminal(f"PROCESO NOMBRE EXTRAÑO: {proceso}", "ROOTKIT", "WARNING")
                
            except Exception as e:
                self._log_terminal(f"Error analizando procesos: {str(e)}", "ROOTKIT", "WARNING")
            
            # 4. Verificar conexiones de red sospechosas
            self._log_terminal("Verificando conexiones de red sospechosas...", "ROOTKIT", "INFO")
            try:
                resultado = subprocess.run(['ss', '-tupln'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]  # Skip header
                    puertos_sospechosos = ['1337', '31337', '12345', '54321', '9999']
                    
                    for linea in lineas:
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 4:
                                direccion_local = partes[3]
                                puerto = direccion_local.split(':')[-1]
                                
                                if puerto in puertos_sospechosos:
                                    self._log_terminal(f"PUERTO SOSPECHOSO ABIERTO: {puerto} ({direccion_local})", "ROOTKIT", "ERROR")
                                
                                # Verificar puertos altos poco comunes
                                try:
                                    puerto_num = int(puerto)
                                    if puerto_num > 49152 and 'LISTEN' in linea:
                                        self._log_terminal(f"PUERTO ALTO EN ESCUCHA: {puerto}", "ROOTKIT", "WARNING")
                                except:
                                    pass
                
            except Exception as e:
                self._log_terminal(f"Error verificando conexiones: {str(e)}", "ROOTKIT", "WARNING")
            
            # 5. Verificar cargas del kernel sospechosas
            self._log_terminal("Verificando módulos del kernel cargados...", "ROOTKIT", "INFO")
            try:
                resultado = subprocess.run(['lsmod'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    lineas = resultado.stdout.split('\n')[1:]  # Skip header
                    modulos_sospechosos = []
                    
                    for linea in lineas[:20]:  # Primeros 20 módulos
                        if linea.strip():
                            partes = linea.split()
                            if len(partes) >= 1:
                                modulo = partes[0]
                                # Buscar módulos con nombres extraños
                                if any(char in modulo.lower() for char in ['rootkit', 'backdoor', 'hide']):
                                    modulos_sospechosos.append(modulo)
                                    self._log_terminal(f"MÓDULO SOSPECHOSO: {modulo}", "ROOTKIT", "ERROR")
                    
                    total_modulos = len(lineas)
                    self._log_terminal(f"MÓDULOS KERNEL: {total_modulos} módulos cargados", "ROOTKIT", "INFO")
                
            except Exception as e:
                self._log_terminal(f"Error verificando módulos kernel: {str(e)}", "ROOTKIT", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error en detección de rootkits: {str(e)}", "ROOTKIT", "ERROR")


# RESUMEN: Interfaz de escaneo de vulnerabilidades con opciones básicas y avanzadas.
