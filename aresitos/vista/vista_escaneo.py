# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import logging
import threading

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
        # Frame principal con tema
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        
        # Título con tema Burp Suite
        titulo_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill="x", pady=(0, 15))
        
        titulo_label = tk.Label(titulo_frame, text="ESCANEADOR DE VULNERABILIDADES", 
                              font=('Arial', 14, 'bold'),
                              bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo_label.pack()
        
        # Frame de botones con tema
        btn_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
            
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
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
        
        self.btn_verificar = tk.Button(btn_frame, text="Verificar Kali", 
                                     command=self.verificar_kali,
                                     bg=self.colors['info'], fg='white', 
                                     font=('Arial', 10, 'bold'),
                                     relief='flat', padx=15, pady=8,
                                     activebackground=self.colors['fg_accent'],
                                     activeforeground='white')
        self.btn_verificar.pack(side="left", padx=(0, 10))
            
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
        self.text_resultados = scrolledtext.ScrolledText(main_frame, height=25,
                                                       bg=self.colors['bg_secondary'], 
                                                       fg=self.colors['fg_primary'],
                                                       font=('Consolas', 10),
                                                       insertbackground=self.colors['fg_accent'],
                                                       selectbackground=self.colors['fg_accent'],
                                                       relief='flat', bd=1)
        
        self.text_resultados.pack(fill="both", expand=True)
    
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
        self._log_terminal("🚀 Iniciando escaneo del sistema", "ESCANEADOR", "INFO")
        
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
    
    def _ejecutar_escaneo_async(self):
        """Ejecutar escaneo completo del sistema en busca de vulnerabilidades, virus, malware y permisos sospechosos."""
        try:
            if not self.proceso_activo:
                return
            
            self._log_terminal("Iniciando escaneo completo del sistema operativo Kali Linux", "ESCANEADOR", "INFO")
            
            # FASE 1: Escaneo de archivos críticos del sistema
            self._log_terminal("FASE 1: Verificando archivos críticos del sistema", "ESCANEADOR", "INFO")
            self._escanear_archivos_criticos()
            
            # FASE 2: Verificación de permisos sospechosos
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
                            self._log_terminal(f"⚠️ PUERTO CRÍTICO: {puerto_num} - {descripcion}", "ESCANEADOR", "WARNING")
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
                        self._log_terminal(f"🚨 PROCESO SOSPECHOSO: {proceso.strip()}", "ESCANEADOR", "WARNING")
                        break
            
            # Análisis de configuración de seguridad
            analisis = resultados.get('análisis', [])
            if analisis:
                for item in analisis:
                    if any(palabra in item.lower() for palabra in ['error', 'fail', 'vulnerable', 'insecure', 'weak']):
                        self._log_terminal(f"🔓 VULNERABILIDAD: {item}", "ESCANEADOR", "ERROR")
                    elif any(palabra in item.lower() for palabra in ['warning', 'caution', 'deprecated']):
                        self._log_terminal(f"⚠️ ADVERTENCIA: {item}", "ESCANEADOR", "WARNING")
                        
        except Exception as e:
            self._log_terminal(f"❌ Error analizando amenazas: {str(e)}", "ESCANEADOR", "ERROR")
    
    def _mostrar_resultados_escaneo(self, resultados):
        """Mostrar resultados en la UI y en el terminal integrado."""
        if not self.proceso_activo:
            return
        
        # Log detallado en el terminal integrado
        self._log_terminal("📊 Mostrando resultados del escaneo", "ESCANEADOR", "INFO")
        
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
            self._log_terminal(f"⚙️ Encontrados {len(procesos_encontrados)} procesos", "ESCANEADOR", "SUCCESS")
        
        self.text_resultados.insert(tk.END, "\n=== ANÁLISIS ===\n")
        analisis = resultados.get('análisis', [])
        for linea in analisis:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de análisis al terminal integrado
        if analisis:
            self._log_terminal(f"🔍 Análisis completado: {len(analisis)} elementos", "ESCANEADOR", "SUCCESS")
            
        # Resumen final en terminal integrado
        total_elementos = len(puertos_encontrados) + len(procesos_encontrados) + len(analisis)
        self._log_terminal(f"✅ Escaneo finalizado: {total_elementos} elementos analizados", "ESCANEADOR", "SUCCESS")
    
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
        """Cancelar el escaneo en curso."""
        if self.proceso_activo:
            self.proceso_activo = False
            self.text_resultados.insert(tk.END, "\n Escaneo cancelado por el usuario.\n")
    
    def verificar_kali(self):
        """Verificar la integridad completa del sistema operativo Kali Linux."""
        try:
            self.text_resultados.delete(1.0, tk.END)
            self.text_resultados.insert(tk.END, "=== VERIFICACION INTEGRIDAD KALI LINUX ===\n\n")
            
            # Log al terminal integrado
            self._log_terminal("Iniciando verificacion completa de integridad del sistema Kali Linux", "VERIFICADOR", "INFO")
            
            # Deshabilitar botón durante verificación
            self.btn_verificar.config(state="disabled")
            
            # Ejecutar verificación completa en thread separado
            threading.Thread(target=self._verificar_integridad_kali_async, daemon=True).start()
            
        except Exception as e:
            self._log_terminal(f"Error iniciando verificacion: {str(e)}", "VERIFICADOR", "ERROR")
            messagebox.showerror("Error", f"Error durante verificación: {str(e)}")
        finally:
            # Reactivar botón después de 30 segundos
            self.after(30000, lambda: self.btn_verificar.config(state="normal"))

    def _verificar_integridad_kali_async(self):
        """Verificar integridad del sistema Kali Linux de forma asíncrona."""
        import subprocess
        import os
        
        try:
            # FASE 1: Verificar estructura de directorios críticos
            self._log_terminal("FASE 1: Verificando estructura de directorios criticos", "VERIFICADOR", "INFO")
            self._verificar_directorios_criticos()
            
            # FASE 2: Verificar archivos de configuración esenciales
            self._log_terminal("FASE 2: Verificando archivos de configuracion esenciales", "VERIFICADOR", "INFO")
            self._verificar_archivos_configuracion()
            
            # FASE 3: Verificar herramientas de Kali Linux
            self._log_terminal("FASE 3: Verificando herramientas de seguridad de Kali", "VERIFICADOR", "INFO")
            self._verificar_herramientas_kali()
            
            # FASE 4: Verificar servicios del sistema
            self._log_terminal("FASE 4: Verificando servicios criticos del sistema", "VERIFICADOR", "INFO")
            self._verificar_servicios_sistema()
            
            # FASE 5: Verificar integridad de paquetes
            self._log_terminal("FASE 5: Verificando integridad de paquetes instalados", "VERIFICADOR", "INFO")
            self._verificar_paquetes_sistema()
            
            # FASE 6: Verificar configuración de red
            self._log_terminal("FASE 6: Verificando configuracion de red", "VERIFICADOR", "INFO")
            self._verificar_configuracion_red()
            
            self._log_terminal("Verificacion de integridad completada", "VERIFICADOR", "SUCCESS")
            
        except Exception as e:
            self._log_terminal(f"Error durante verificacion de integridad: {str(e)}", "VERIFICADOR", "ERROR")

    def _verificar_directorios_criticos(self):
        """Verificar que existen los directorios críticos del sistema."""
        import os
        
        directorios_criticos = [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin',
            '/etc', '/var', '/tmp', '/home', '/root', '/boot',
            '/lib', '/usr/lib', '/proc', '/sys', '/dev'
        ]
        
        directorios_kali = [
            '/usr/share/wordlists', '/usr/share/nmap', '/usr/share/metasploit-framework',
            '/usr/share/sqlmap', '/usr/share/dirb', '/usr/share/nikto'
        ]
        
        todos_directorios = directorios_criticos + directorios_kali
        
        for directorio in todos_directorios:
            if os.path.exists(directorio) and os.path.isdir(directorio):
                self._log_terminal(f"OK: Directorio {directorio} presente", "VERIFICADOR", "INFO")
            else:
                self._log_terminal(f"ERROR: Directorio critico {directorio} no encontrado", "VERIFICADOR", "ERROR")

    def _verificar_archivos_configuracion(self):
        """Verificar archivos de configuración esenciales."""
        import os
        
        archivos_esenciales = [
            '/etc/passwd', '/etc/group', '/etc/shadow', '/etc/sudoers',
            '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
            '/etc/fstab', '/etc/shells', '/etc/profile',
            '/etc/ssh/sshd_config', '/etc/apt/sources.list'
        ]
        
        for archivo in archivos_esenciales:
            if os.path.exists(archivo) and os.path.isfile(archivo):
                # Verificar tamaño mínimo (no debe estar vacío)
                tamano = os.path.getsize(archivo)
                if tamano > 0:
                    self._log_terminal(f"OK: {archivo} presente y valido ({tamano} bytes)", "VERIFICADOR", "INFO")
                else:
                    self._log_terminal(f"ERROR: {archivo} esta vacio", "VERIFICADOR", "ERROR")
            else:
                self._log_terminal(f"ERROR: Archivo critico {archivo} no encontrado", "VERIFICADOR", "ERROR")

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
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Eventos SIEM:\n\n")
        
        eventos = self.controlador.obtener_eventos_siem()
        for evento in eventos:
            timestamp = evento.get('timestamp', '')
            if isinstance(timestamp, str):
                timestamp_str = timestamp
            else:
                timestamp_str = str(timestamp)
            self.text_resultados.insert(tk.END, 
                f"[{timestamp_str}] {evento.get('tipo', 'Desconocido')}: {evento.get('descripcion', 'Sin descripción')}\n")

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
        """Escanear vulnerabilidades conocidas del sistema."""
        import subprocess
        import os
        
        try:
            # Verificar versión del kernel
            self._log_terminal("Verificando version del kernel...", "ESCANEADOR", "INFO")
            resultado = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
            kernel_version = resultado.stdout.strip()
            self._log_terminal(f"Kernel version: {kernel_version}", "ESCANEADOR", "INFO")
            
            # Verificar paquetes desactualizados
            self._log_terminal("Verificando actualizaciones disponibles...", "ESCANEADOR", "INFO")
            try:
                resultado = subprocess.run(['apt', 'list', '--upgradable'], 
                                         capture_output=True, text=True, timeout=20)
                actualizaciones = len(resultado.stdout.strip().split('\n')) - 1
                if actualizaciones > 0:
                    self._log_terminal(f"ATENCION: {actualizaciones} paquetes pueden actualizarse", "ESCANEADOR", "WARNING")
                else:
                    self._log_terminal("Sistema actualizado", "ESCANEADOR", "INFO")
            except:
                self._log_terminal("No se pudo verificar actualizaciones", "ESCANEADOR", "WARNING")
                
            # Verificar servicios críticos
            servicios_criticos = ['ssh', 'ufw', 'fail2ban']
            for servicio in servicios_criticos:
                try:
                    resultado = subprocess.run(['systemctl', 'is-active', servicio], 
                                             capture_output=True, text=True, timeout=5)
                    estado = resultado.stdout.strip()
                    if estado == 'active':
                        self._log_terminal(f"Servicio de seguridad activo: {servicio}", "ESCANEADOR", "INFO")
                    else:
                        self._log_terminal(f"RIESGO: Servicio de seguridad {servicio} no activo", "ESCANEADOR", "WARNING")
                except:
                    self._log_terminal(f"No se pudo verificar servicio: {servicio}", "ESCANEADOR", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error escaneando vulnerabilidades: {str(e)}", "ESCANEADOR", "WARNING")


# RESUMEN: Interfaz de escaneo de vulnerabilidades con opciones básicas y avanzadas.
