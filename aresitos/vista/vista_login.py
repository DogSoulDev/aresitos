import re

class SeguridadUtils:
    """Utilidades de seguridad mejoradas"""
    @staticmethod
    def validar_entrada(entrada: str) -> bool:
        if not entrada:
            return False
        caracteres_peligrosos = ['&', ';', '|', '`', '$', '<', '>', '\n', '\r', '\\', '"']
        if any(char in entrada for char in caracteres_peligrosos):
            return False
        if len(entrada) > 128:
            return False
        return True
    @staticmethod
    def limpiar_memoria_string(variable: str) -> None:
        try:
            longitud = len(variable)
            variable = 'x' * longitud
            del variable
        except (ValueError, TypeError, AttributeError):
            pass
    @staticmethod
    def sanitizar_para_log(mensaje: str) -> str:
        mensaje = re.sub(r'password[=:\s]+\S+', 'password=***', mensaje, flags=re.IGNORECASE)
        mensaje = re.sub(r'contraseña[=:\s]+\S+', 'contraseña=***', mensaje, flags=re.IGNORECASE)
        mensaje = re.sub(r'pass[=:\s]+\S+', 'pass=***', mensaje, flags=re.IGNORECASE)
        if len(mensaje) > 500:
            mensaje = mensaje[:497] + "..."
        return mensaje
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import subprocess
import shlex
import os
import sys
import platform
import getpass
import shutil
from aresitos.utils.sudo_manager import SudoManager
from aresitos.vista.vista_herramientas_kali import VistaHerramientasKali
# Definir HERRAMIENTAS_REQUERIDAS localmente si no existe en el import
HERRAMIENTAS_REQUERIDAS = [
    'nmap', 'masscan', 'zmap', 'dnsenum', 'dnsrecon', 'fierce',
    'sublist3r', 'amass', 'gobuster', 'feroxbuster', 'httpx', 'wfuzz',
    'nikto', 'sqlmap', 'wpscan', 'joomscan', 'droopescan', 'nuclei',
    'wapiti', 'skipfish', 'whatweb', 'wafw00f', 'davtest',
    'metasploit', 'searchsploit', 'msfconsole', 'msfvenom', 'exploitdb',
    'beef-xss', 'set', 'social-engineer-toolkit',
    'tcpdump', 'netcat', 'nc', 'socat', 'netstat', 'ss', 'lsof', 'arp-scan', 'ping', 'traceroute', 'mtr',
    'hydra', 'medusa', 'ncrack', 'john', 'hashcat', 'aircrack-ng',
    'crunch', 'cewl', 'cupp', 'patator',
    'sleuthkit', 'binwalk', 'foremost', 'strings', 'hexdump', 'xxd', 'file', 'exiftool',
    'curl', 'wget', 'git', 'python3', 'pip3', 'perl', 'ruby',
    'java', 'gcc', 'make', 'cmake', 'openssl',
    'burpsuite', 'owasp-zap', 'nuclei', 'xsser', 'weevely',
    'backdoor-factory', 'shellter', 'veil', 'empire'
]
# Herramientas que pueden causar problemas o requieren instalación manual
HERRAMIENTAS_PROBLEMATICAS = [
    'metasploit', 'msfconsole', 'msfvenom', 'beef-xss', 'set', 'social-engineer-toolkit',
    'burpsuite', 'owasp-zap', 'nuclei', 'xsser', 'weevely',
    'backdoor-factory', 'shellter', 'veil', 'empire',
    'rkhunter', 'chkrootkit', 'lynis'
]
class RateLimiter:
    """Rate limiter para prevenir ataques de fuerza bruta"""
    def __init__(self, max_intentos: int = 3, ventana_tiempo: int = 300):
        self.max_intentos = max_intentos
        self.ventana_tiempo = ventana_tiempo  # 5 minutos
        self.intentos = {}
        self.lock = threading.Lock()

    def puede_intentar(self, identificador: str = "default") -> bool:
        with self.lock:
            ahora = time.time()
            if identificador not in self.intentos:
                self.intentos[identificador] = []
            self.intentos[identificador] = [
                timestamp for timestamp in self.intentos[identificador]
                if ahora - timestamp < self.ventana_tiempo
            ]
            return len(self.intentos[identificador]) < self.max_intentos

    def registrar_intento(self, identificador: str = "default"):
        with self.lock:
            if identificador not in self.intentos:
                self.intentos[identificador] = []
            self.intentos[identificador].append(time.time())

        return False

from aresitos.utils.permisos_sistema import es_root

def verificar_permisos_admin_seguro():
    """Verificar permisos de administrador de forma centralizada y robusta."""
    return es_root()

class LoginAresitos:
    def __init__(self, root=None, *args, **kwargs):
        # Inicialización de colores y fondos para la interfaz
        self.bg_primary = "#23272e"
        self.bg_secondary = "#2c313c"
        self.bg_tertiary = "#1a1d23"
        self.fg_primary = "#f5f5f5"
        self.fg_secondary = "#bdbdbd"
        self.accent_orange = "#ff6633"
        self.accent_green = "#4caf50"
        self.accent_red = "#f44336"
        self.accent_blue = "#2196f3"
        # Inicialización de utilidades y control de intentos
        self.rate_limiter = RateLimiter()
        self.utils_seguridad = SeguridadUtils()
        if root is None:
            self.root = tk.Tk()
        else:
            self.root = root
        super().__init__(*args, **kwargs)

    def revocar_sudo(self):
        """Revoca el estado sudo y actualiza el terminal principal."""
        try:
            from aresitos.utils.sudo_manager import SudoManager
            sudo_manager = SudoManager()
            sudo_manager.clear_sudo()
        except Exception:
            pass

    def verificar_password(self):
        """Verifica la contraseña de root y avanza si es correcta."""
        password = self.password_entry.get()
        if not self.rate_limiter.puede_intentar():
            tiempo_restante = 5
            messagebox.showerror(
                "Bloqueado",
                f"Demasiados intentos fallidos.\nIntente nuevamente en {tiempo_restante} minutos."
            )
            self.escribir_log("Intento bloqueado por rate limiting")
            return
        if not password:
            messagebox.showerror("Error", "Por favor ingrese la contraseña")
            return
        if not self.utils_seguridad.validar_entrada(password):
            messagebox.showerror("Error", "Contraseña contiene caracteres no válidos")
            self.rate_limiter.registrar_intento()
            self.escribir_log("Contraseña con caracteres inválidos detectada")
            return
        self.escribir_log("Verificando credenciales de root...")
        try:
            resultado = subprocess.run(
                ['sudo', '-S', '-k', 'echo', 'test'],
                input=password + '\n',
                text=True,
                capture_output=True,
                timeout=10,
                check=False
            )
            if resultado.returncode == 0:
                self.password_correcta = True
                self.escribir_log("Autenticacion exitosa - Permisos de root confirmados")
                sudo_manager = SudoManager()
                sudo_manager.set_sudo_authenticated(password)
                self.password_entry.delete(0, tk.END)
                self.login_btn.config(state=tk.DISABLED)
                self.password_entry.config(state=tk.DISABLED)
                self.skip_btn.config(state=tk.DISABLED)
                self.iniciar_aplicacion()
            else:
                self.rate_limiter.registrar_intento()
                self.escribir_log("Contraseña incorrecta")
                self.utils_seguridad.limpiar_memoria_string(password)
                self.password_entry.delete(0, tk.END)
                messagebox.showerror("Error", "Contraseña incorrecta")
        except subprocess.TimeoutExpired:
            self.rate_limiter.registrar_intento()
            self.escribir_log("Timeout verificando contraseña")
            self.utils_seguridad.limpiar_memoria_string(password)
            self.password_entry.delete(0, tk.END)
            messagebox.showerror("Error", "Timeout en verificación")
        except FileNotFoundError:
            self.escribir_log("sudo no disponible - Continuando sin verificación")
            self.root.destroy()
        except subprocess.SubprocessError as e:
            self.rate_limiter.registrar_intento()
            self.escribir_log(f"Error subprocess: {type(e).__name__}")
            self.utils_seguridad.limpiar_memoria_string(password)
            self.password_entry.delete(0, tk.END)
            messagebox.showerror("Error", "Error en verificación del sistema")
        except Exception as e:
            self.rate_limiter.registrar_intento()
            self.escribir_log(f"Error en verificación: {type(e).__name__}")
            self.utils_seguridad.limpiar_memoria_string(password)
            self.password_entry.delete(0, tk.END)
            messagebox.showerror("Error", "Error de verificación")

    def ocultar_ventana(self):
        """Oculta la ventana principal revocando sudo."""
        try:
            self.revocar_sudo()
        except Exception:
            pass
        self.root.withdraw()

    def salir_sistema(self, code=1):
        try:
            self.revocar_sudo()
        except Exception:
            pass
        sys.exit(code)
        
    def centrar_ventana(self):
        """Centrar la ventana en la pantalla"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")
    
    def crear_interfaz(self):
        """Crear la interfaz grafica completa con tema Burp Suite"""
        
        # Frame principal
        main_frame = tk.Frame(self.root, bg=self.bg_primary)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Titulo principal
        title_label = tk.Label(
            main_frame,
            text="ARESITOS",
            font=("Arial", 24, "bold"),
            fg=self.accent_orange,
            bg=self.bg_primary
        )
        title_label.pack(pady=(20, 10))
        
        subtitle_label = tk.Label(
            main_frame,
            text="Herramienta de Ciberseguridad",
            font=("Arial", 12),
            fg=self.fg_secondary,
            bg=self.bg_primary
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Frame de login
        login_frame = tk.LabelFrame(
            main_frame,
            text="Autenticacion de Root",
            font=("Arial", 12, "bold"),
            fg=self.accent_orange,
            bg=self.bg_secondary,
            relief=tk.RAISED,
            bd=2
        )
        login_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Campo de contraseña
        tk.Label(
            login_frame,
            text="Contraseña de Root:",
            font=("Arial", 10),
            fg=self.fg_primary,
            bg=self.bg_secondary
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.password_entry = tk.Entry(
            login_frame,
            show="*",
            font=("Arial", 12),
            bg=self.bg_tertiary,
            fg=self.fg_primary,
            insertbackground=self.accent_blue,
            relief=tk.FLAT,
            bd=5
        )
        self.password_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.password_entry.bind('<Return>', lambda e: self.verificar_password())
        
        # Botones de login
        btn_frame = tk.Frame(login_frame, bg=self.bg_secondary)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.login_btn = tk.Button(
            btn_frame,
            text="Verificar Root",
            font=("Arial", 11, "bold"),
            bg=self.accent_green,
            fg="#ffffff",
            relief=tk.FLAT,
            command=self.verificar_password,
            cursor='hand2'
        )
        self.login_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.skip_btn = tk.Button(
            btn_frame,
            text="Continuar sin Root",
            font=("Arial", 10),
            bg=self.accent_red,
            fg="#ffffff",
            relief=tk.FLAT,
            command=self.continuar_sin_root,
            cursor='hand2'
        )
        self.skip_btn.pack(side=tk.LEFT)
        
        # Frame de verificación del sistema
        self.verify_frame = tk.LabelFrame(
            main_frame,
            text="Verificacion del Sistema",
            font=("Arial", 12, "bold"),
            fg=self.accent_orange,
            bg=self.bg_secondary,
            relief=tk.RAISED,
            bd=2
        )
        self.verify_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Area de texto para logs
        self.log_text = scrolledtext.ScrolledText(
            self.verify_frame,
            height=12,
            font=("Consolas", 9),
            bg=self.bg_primary,
            fg=self.fg_primary,
            insertbackground=self.accent_blue,
            relief=tk.FLAT,
            bd=5,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Frame de botones principales
        main_button_frame = tk.Frame(main_frame, bg=self.bg_primary)
        main_button_frame.pack(fill=tk.X, pady=10)
        
        # Boton continuar
        self.continue_btn = tk.Button(
            main_button_frame,
            text="Iniciar Aresitos",
            font=("Arial", 12, "bold"),
            bg=self.accent_green,
            fg="#ffffff",
            relief=tk.FLAT,
            command=self.iniciar_aplicacion,
            cursor='hand2',
            state=tk.DISABLED,
            padx=30,
            pady=10
        )
        self.continue_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Boton salir
        exit_btn = tk.Button(
            main_button_frame,
            text="Salir",
            font=("Arial", 10),
            bg=self.accent_red,
            fg="#ffffff",
            relief=tk.FLAT,
            command=self._salir_con_revocacion_sudo,
            cursor='hand2',
            padx=20
        )
        exit_btn.pack(side=tk.LEFT)

    def _salir_con_revocacion_sudo(self):
        """Revoca sudo y cierra la aplicación de forma segura."""
        try:
            self.revocar_sudo()
        except Exception:
            pass
        self.root.destroy()

    def enfocar_password(self):
        """Coloca el foco en el campo de contraseña si existe."""
        try:
            self.password_entry.focus()
        except Exception:
            pass
    
    def escribir_log(self, mensaje):
        """Escribir mensaje en el area de logs de forma segura"""
        try:
            # Verificar que el widget y la ventana aún existen
            if not hasattr(self, 'log_text') or not self.log_text or not self.log_text.winfo_exists():
                print(f"[LOGIN] {mensaje}")
                return
                
            # Verificar que la ventana principal aún existe
            if not hasattr(self, 'root') or not self.root:
                print(f"[LOGIN] {mensaje}")
                return
            
            # Sanitizar mensaje antes de mostrar
            mensaje_seguro = self.utils_seguridad.sanitizar_para_log(mensaje)
            
            # Actualización directa sin callbacks problemáticos
            try:
                if self.log_text.winfo_exists():
                    self.log_text.config(state=tk.NORMAL)
                    
                    # Insertar timestamp y mensaje
                    timestamp = time.strftime('%H:%M:%S')
                    linea_completa = f"[{timestamp}] {mensaje_seguro}\n"
                    
                    self.log_text.insert(tk.END, linea_completa)
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)
                    
                    # Solo actualizar si la ventana aún existe
                    if self.root and self.root.winfo_exists():
                        self.root.update_idletasks()
            except (tk.TclError, AttributeError):
                # Si hay cualquier error con tkinter, usar print como fallback
                print(f"[LOGIN] {mensaje_seguro}")
                
        except Exception as e:
            # Log de fallback en caso de error
            print(f"[LOGIN] {mensaje}")  # No mostrar el error técnico
    
    def verificar_entorno_inicial(self):
        try:
            # Informacion basica del sistema
            sistema = platform.system()
            version = platform.release()
            usuario = getpass.getuser()
            
            # Verificar permisos
            es_root = verificar_permisos_admin_seguro()
            
            self.escribir_log("Bienvenido a ARESITOS - Sistema de Seguridad Cibernetica")
            self.escribir_log(f"Sistema detectado: {sistema} {version}")
            self.escribir_log(f"Usuario actual: {usuario}")
            self.escribir_log("Kali Linux detectado - Entorno optimo")
            
            if es_root:
                self.escribir_log("Permisos de root detectados")
                self.password_correcta = True
                self.login_btn.config(state=tk.DISABLED)
                self.password_entry.config(state=tk.DISABLED)
                self.skip_btn.config(state=tk.DISABLED)
            else:
                self.escribir_log("Se requiere autenticacion de root para funcionalidad completa")
            
            self.escribir_log("Iniciando verificación automatica de herramientas...")
            
            # Verificar herramientas en hilo separado
            threading.Thread(target=self.verificar_herramientas_inicial, daemon=True).start()
            
        except Exception as e:
            self.escribir_log(f"Error verificando entorno: {e}")
    
    def verificar_herramientas_inicial(self):
        try:
            self.herramientas_disponibles = []
            self.herramientas_faltantes = []
            total = len(HERRAMIENTAS_REQUERIDAS)
            for i, herramienta in enumerate(HERRAMIENTAS_REQUERIDAS):
                if shutil.which(herramienta):
                    self.herramientas_disponibles.append(herramienta)
                else:
                    self.herramientas_faltantes.append(herramienta)
                if i % 10 == 0:
                    progreso = (i + 1) / total * 100
                    self.escribir_log(f"Verificando herramientas... {i+1}/{total} ({progreso:.1f}%)")
            disponibles = len(self.herramientas_disponibles)
            self.escribir_log(f"Verificacion completada: {disponibles}/{total} herramientas disponibles")
            if self.herramientas_faltantes:
                faltan = len(self.herramientas_faltantes)
                self.escribir_log(f"ADVERTENCIA: {faltan} herramientas no están disponibles. Puede instalarlas en la siguiente pantalla.")
            self.verificacion_completada = True
            # Permitir avanzar siempre tras la verificación
            self.continue_btn.config(state=tk.NORMAL, bg=self.accent_green)
        except Exception as e:
            self.escribir_log(f"Error verificando herramientas: {e}")
    
    def configurar_permisos_aresitos(self, password):
        """Configurar permisos completos para ARESITOS usando la contraseña root"""
        try:
            # Detectar rutas posibles del proyecto
            rutas_posibles = self._detectar_rutas_proyecto()
            
            for ruta in rutas_posibles:
                if os.path.exists(ruta):
                    self.escribir_log(f"Configurando permisos para: {ruta}")
                    self._ejecutar_comandos_permisos(ruta, password)
                    break
            else:
                self.escribir_log("WARNING No se encontró directorio válido del proyecto")
                
        except Exception as e:
            self.escribir_log(f"Error configurando permisos: {type(e).__name__}")
    
    def _detectar_rutas_proyecto(self):
        """Detectar posibles rutas del proyecto ARESITOS"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        aresitos_root = os.path.dirname(os.path.dirname(script_dir))
        
        home = os.environ.get('HOME', os.path.expanduser('~'))
        rutas_posibles = [
            aresitos_root,  # Ruta calculada desde el script
            os.path.join(home, "aresitos"),
            os.path.join(home, "Desktop", "aresitos"),
            os.path.join(home, "Ares-Aegis"),
            os.path.join(home, "Desktop", "Ares-Aegis"),
            os.path.expanduser("~/aresitos"),
            os.path.expanduser("~/Desktop/aresitos"),
            os.path.expanduser("~/Ares-Aegis"),
            os.path.expanduser("~/Desktop/Ares-Aegis")
        ]
        
        return rutas_posibles
    
    def _ejecutar_comandos_permisos(self, ruta_proyecto, password):
        """Ejecutar comandos de permisos para una ruta específica"""
        # Lista de comandos para configurar permisos
        comandos_permisos = [
            # Permisos básicos para el proyecto (más seguros)
            f"chmod -R 755 {shlex.quote(ruta_proyecto)}",
            f"chown -R $USER:$USER {shlex.quote(ruta_proyecto)}",
            
            # Permisos seguros para configuración (solo escritura para propietario)
            f"chmod -R 755 {shlex.quote(os.path.join(ruta_proyecto, 'configuración'))}",
            f"chmod 644 {shlex.quote(os.path.join(ruta_proyecto, 'configuración', 'aresitos_config.json'))} 2>/dev/null || true",
            f"chmod 644 {shlex.quote(os.path.join(ruta_proyecto, 'configuración', 'aresitos_config_kali.json'))} 2>/dev/null || true",
            
            # Permisos seguros para data y logs (solo usuario puede escribir)
            f"chmod -R 755 {shlex.quote(os.path.join(ruta_proyecto, 'data'))} 2>/dev/null || true",
            f"chmod -R 755 {shlex.quote(os.path.join(ruta_proyecto, 'logs'))} 2>/dev/null || true",
            
            # Ejecutables Python
            f"find {shlex.quote(ruta_proyecto)} -name '*.py' -exec chmod +x {{}} \\;",
            f"chmod +x {shlex.quote(os.path.join(ruta_proyecto, 'main.py'))}",
            
            # Crear directorios necesarios con permisos seguros
            f"mkdir -p {shlex.quote(os.path.join(ruta_proyecto, 'logs'))} && chmod 755 {shlex.quote(os.path.join(ruta_proyecto, 'logs'))}",
            f"mkdir -p /tmp/aresitos_quarantine && chmod 755 /tmp/aresitos_quarantine",
            
            # Herramientas de Kali Linux
            "chmod +x /usr/bin/nmap 2>/dev/null || true",
            "chmod +x /usr/bin/masscan 2>/dev/null || true", 
            "chmod +x /usr/bin/nikto 2>/dev/null || true",
            "chmod +x /usr/bin/lynis 2>/dev/null || true",
            "chmod +x /usr/bin/rkhunter 2>/dev/null || true",
            "chmod +x /usr/bin/chkrootkit 2>/dev/null || true"
        ]
        
        # Ejecutar cada comando con sudo
        for i, comando in enumerate(comandos_permisos, 1):
            try:
                self.escribir_log(f"Ejecutando comando {i}/{len(comandos_permisos)}: permisos...")
                
                # Construir el comando completo con sudo
                comando_sudo = f"sudo -S sh -c '{comando}'"
                
                resultado = subprocess.run(
                    comando_sudo,
                    input=password + '\n',
                    text=True,
                    shell=True,
                    capture_output=True,
                    timeout=30,
                    check=False
                )
                
                if resultado.returncode == 0:
                    self.escribir_log(f"Comando {i} ejecutado exitosamente")
                else:
                    self.escribir_log(f"Comando {i} falló (código {resultado.returncode})")
                    if resultado.stderr:
                        self.escribir_log(f"Error: {resultado.stderr.strip()[:100]}")
                        
            except subprocess.TimeoutExpired:
                self.escribir_log(f"Timeout en comando {i}")
            except Exception as e:
                self.escribir_log(f"Error en comando {i}: {type(e).__name__}")
        
        # Verificación final de permisos
        try:
            main_py = os.path.join(ruta_proyecto, 'main.py')
            config_file = os.path.join(ruta_proyecto, 'configuración', 'aresitos_config.json')
            
            if os.access(main_py, os.X_OK):
                self.escribir_log("main.py ejecutable")
            if os.access(config_file, os.R_OK | os.W_OK):
                self.escribir_log("Archivo de configuración accesible")
            else:
                self.escribir_log("Archivo de configuración no accesible")
                
        except (IOError, OSError, PermissionError, FileNotFoundError):
            pass
            
        self.escribir_log("Configuración de permisos completada")
    
    
    def instalar_herramientas_kali_automatico(self, password):
        """Instalar automáticamente herramientas faltantes de Kali Linux"""
        try:
            self.escribir_log(" Iniciando instalación automática de herramientas...")
            
            # Lista de herramientas críticas para Kali
            herramientas_criticas = [
                'nmap', 'masscan', 'nikto', 'sqlmap', 'hydra', 
                'lynis', 'rkhunter', 'chkrootkit', 'tcpdump',
                'net-tools', 'netstat-nat'
            ]
            
            herramientas_a_instalar = []
            for herramienta in herramientas_criticas:
                if herramienta in self.herramientas_faltantes:
                    herramientas_a_instalar.append(herramienta)
            
            if not herramientas_a_instalar:
                self.escribir_log("OK Todas las herramientas críticas ya están instaladas")
                return
            
            self.escribir_log(f" Instalando {len(herramientas_a_instalar)} herramientas faltantes...")
            
            # Ejecutar instalación en background
            import threading
            thread = threading.Thread(
                target=self._ejecutar_instalacion_herramientas,
                args=(herramientas_a_instalar, password),
                daemon=True
            )
            thread.start()
            
        except Exception as e:
            self.escribir_log(f"ERROR en instalación automática: {e}")
    
    def _ejecutar_instalacion_herramientas(self, herramientas, password):
        """Ejecutar instalación de herramientas en thread separado"""
        try:
            # Actualizar repositorios primero
            self.escribir_log(" Actualizando repositorios...")
            cmd_update = f"echo '{password}' | sudo -S apt update"
            
            result = subprocess.run(
                cmd_update, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            if result.returncode == 0:
                self.escribir_log("OK Repositorios actualizados")
            else:
                self.escribir_log("WARNING al actualizar repositorios")
            
            # Filtrar herramientas problemáticas
            herramientas_seguras = [h for h in herramientas if h not in HERRAMIENTAS_PROBLEMATICAS]
            herramientas_problematicas = [h for h in herramientas if h in HERRAMIENTAS_PROBLEMATICAS]
            
            if herramientas_problematicas:
                self.escribir_log(f"ADVERTENCIA️  Omitiendo herramientas problemáticas: {', '.join(herramientas_problematicas)}")
                self.escribir_log("[SUGERENCIA] Instale manualmente con: sudo apt install <herramienta>")
            
            # Instalar herramientas seguras una por una
            for herramienta in herramientas_seguras[:8]:  # Aumentamos a 8 pero solo seguras
                self.escribir_log(f" Instalando {herramienta}...")
                
                cmd_install = f"echo '{password}' | sudo -S apt install -y {herramienta}"
                
                # Timeout diferencial basado en el tipo de herramienta
                timeout_herramienta = 60  # Por defecto 60 segundos
                if herramienta in ['nmap', 'burpsuite']:
                    timeout_herramienta = 180  # Herramientas grandes: 3 minutos
                elif herramienta in ['python3', 'curl', 'wget', 'git']:
                    timeout_herramienta = 30   # Herramientas básicas: 30 segundos
                
                try:
                    result = subprocess.run(
                        cmd_install,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=timeout_herramienta
                    )
                    
                    if result.returncode == 0:
                        self.escribir_log(f"OK {herramienta} instalado correctamente")
                        # Remover de la lista de faltantes
                        if herramienta in self.herramientas_faltantes:
                            self.herramientas_faltantes.remove(herramienta)
                    else:
                        self.escribir_log(f"ERROR Error instalando {herramienta}")
                        if "package not found" in result.stderr.lower():
                            self.escribir_log(f"[SUGERENCIA] {herramienta} no disponible en repositorios")
                        elif "timeout" in str(result.stderr).lower():
                            self.escribir_log(f"⏱️  {herramienta} timeout - requiere instalación manual")
                            
                except subprocess.TimeoutExpired:
                    self.escribir_log(f"⏱️  Timeout instalando {herramienta} - continuando...")
                except Exception as e:
                    self.escribir_log(f"ERROR Error inesperado con {herramienta}: {e}")
            self.escribir_log(" Instalación automática completada")
            
            # Limpiar password de memoria
            self.utils_seguridad.limpiar_memoria_string(password)
            
        except Exception as e:
            self.escribir_log(f"ERROR en instalación: {e}")

    def continuar_sin_root(self):
        """Continuar sin permisos de root"""
        self.escribir_log("Continuando sin permisos de root")
        self.escribir_log("ADVERTENCIA: Funcionalidad limitada sin permisos de administrador")
        
        # Deshabilitar campos de login
        self.login_btn.config(state=tk.DISABLED)
        self.password_entry.config(state=tk.DISABLED)
        self.skip_btn.config(state=tk.DISABLED)
        
        # Habilitar continuar si ya se verificaron herramientas
        if self.verificacion_completada:
            self.continue_btn.config(state=tk.NORMAL, bg=self.accent_orange)
    
    def iniciar_aplicacion(self):
        """Iniciar la aplicacion principal"""
        if not self.verificacion_completada:
            messagebox.showwarning("Advertencia", "Complete la verificación del sistema primero")
            return
        
        self.escribir_log(" Abriendo ventana de herramientas de Kali Linux...")
        # Refuerzo: renovar estado sudo al abrir herramientas
        from aresitos.utils.sudo_manager import SudoManager
        sudo_manager = SudoManager()
        if sudo_manager.is_sudo_active():
            sudo_manager._renovar_sudo_timestamp()
        else:
            self.escribir_log("[ERROR] Permisos sudo no activos. Reinicie sesión.")
            messagebox.showerror("Permisos requeridos", "No hay permisos sudo activos. Reinicie sesión e ingrese la contraseña correcta.")
            return
        
        try:
            # Crear ventana separada para herramientas de Kali
            def callback_herramientas_completadas():
                """Callback para cuando se complete la configuración de herramientas"""
                self._iniciar_aplicacion_principal()
            
            # Crear nueva ventana para herramientas
            ventana_herramientas = tk.Toplevel(self.root)
            ventana_herramientas.title("ARESITOS - Configuración de Herramientas Kali")
            ventana_herramientas.geometry("1000x700")
            ventana_herramientas.configure(bg='#2b2b2b')
            
            # Ventana de herramientas configurada
            
            # Centrar ventana de herramientas
            ventana_herramientas.update_idletasks()
            x = (ventana_herramientas.winfo_screenwidth() // 2) - (1000 // 2)
            y = (ventana_herramientas.winfo_screenheight() // 2) - (700 // 2)
            ventana_herramientas.geometry(f"1000x700+{x}+{y}")
            
            # Crear vista de herramientas en la nueva ventana
            vista_herramientas = VistaHerramientasKali(ventana_herramientas, callback_herramientas_completadas)
            vista_herramientas.pack(fill="both", expand=True)
            
            # Ocultar ventana de login
            self.ocultar_ventana()
            
            self.escribir_log("Ventana de herramientas Kali abierta")
            
        except Exception as e:
            self.escribir_log(f"ERROR mostrando vista de herramientas: {str(e)}")
            import traceback
            self.escribir_log(f"Detalles del error: {traceback.format_exc()}")
            self.escribir_log("Intentando continuar a la aplicación principal...")
            # Si falla, continuar directamente a la aplicación principal
            self._iniciar_aplicacion_principal()
    
    def _iniciar_aplicacion_principal(self):
        """Iniciar la aplicación principal después de configurar herramientas"""
        self.escribir_log(" Iniciando ARESITOS...")
        
        try:
            # Importar módulos principales
            from aresitos.vista.vista_principal import VistaPrincipal
            from aresitos.controlador.controlador_principal import ControladorPrincipal
            from aresitos.modelo.modelo_principal import ModeloPrincipal
            from aresitos.utils.sudo_manager import SudoManager

            self.escribir_log("Módulos principales importados correctamente")

            # Cerrar ventana de login
            self.root.destroy()

            self.escribir_log("Creando aplicación principal...")

            # Crear aplicación principal con tema Burp Suite
            root_app = tk.Tk()
            root_app.title("Aresitos")
            root_app.geometry("1400x900")
            # Favicon robusto multiplataforma
            try:
                import os
                from tkinter import PhotoImage
                icon_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "recursos", "aresitos_icono.png"))
                if os.path.exists(icon_path):
                    self._icon_img2 = PhotoImage(file=icon_path)
                    root_app.iconphoto(True, self._icon_img2)
            except Exception as e:
                print(f"[WARN] No se pudo cargar el icono de ventana principal: {e}")

            # Ventana configurada

            # CRÍTICO: Configurar el tema ANTES de crear las vistas
            root_app.configure(bg='#2b2b2b')  # Fondo Burp Suite principal

            self.escribir_log("Ventana principal configurada con tema Burp Suite")

            # Ventana configurada

            self.escribir_log("Inicializando modelo de datos...")
            # Inicializar MVC correctamente
            modelo = ModeloPrincipal()

            self.escribir_log("Creando vista principal...")
            vista = VistaPrincipal(root_app)
            vista.pack(fill="both", expand=True)  # CRÍTICO: Hacer que la vista ocupe toda la ventana

            self.escribir_log("Inicializando controlador principal...")
            controlador = ControladorPrincipal(modelo)

            self.escribir_log("Configurando conexión vista-controlador...")
            # CRÍTICO: Conectar el controlador a la vista
            vista.set_controlador(controlador)

            # Centrar ventana principal
            root_app.update_idletasks()
            x = (root_app.winfo_screenwidth() // 2) - (1200 // 2)
            y = (root_app.winfo_screenheight() // 2) - (800 // 2)
            root_app.geometry(f"1200x800+{x}+{y}")

            # Refuerzo: renovar estado sudo al abrir la principal
            sudo_manager = SudoManager()
            if sudo_manager.is_sudo_active():
                sudo_manager._renovar_sudo_timestamp()
            else:
                self.escribir_log("[ERROR] Permisos sudo no activos en principal. Reinicie sesión.")
                messagebox.showerror("Permisos requeridos", "No hay permisos sudo activos. Reinicie sesión e ingrese la contraseña correcta.")
                return

            # Ventana principal configurada
            self.escribir_log("OK Ventana de aplicación configurada correctamente")

            # Forzar actualización de la ventana
            root_app.update()

            self.escribir_log(" Aplicación principal configurada. Iniciando interfaz...")

            # Mostrar ventana y comenzar loop principal
            root_app.deiconify()  # Asegurar que la ventana esté visible
            root_app.lift()       # Traer al frente
            root_app.focus_force() # Forzar foco

            root_app.mainloop()
            
        except ImportError as e:
            # Si no puede importar, usar el main original
            self.escribir_log(f"Error de importación: {e}")
            self.escribir_log("Módulos principales no encontrados, usando modo básico")
            messagebox.showinfo("Info", 
                               "Aplicación principal no encontrada.\n"
                               "Ejecute: python main.py\n\n"
                               "O instale la aplicación completa.")
            
        except Exception as e:
            self.escribir_log(f"Error crítico iniciando aplicación: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Error iniciando aplicación:\n{e}")

def main():
    """Función principal de la aplicación de login"""
    # Verificar que estamos en Kali Linux antes de continuar
    # if not verificar_kali_linux_estricto():
    #     # Verificar si estamos en modo desarrollo
    #     if '--dev' in sys.argv or '--desarrollo' in sys.argv:
    #         print("MODO DESARROLLO: Vista de login en entorno no-Kali")
    #         print("   Ejecutando con funcionalidades limitadas...")
    #     else:
    #         print("ERROR: ARESITOS requiere Kali Linux")
    #         print("Sistema operativo no compatible")
    #         sys.exit(1)
    
    print("ARESITOS - Iniciando login...")
    
    # Verificar tkinter disponible
    try:
        import tkinter as tk
        print("Tkinter importado correctamente")
    except ImportError as e:
        print(f"ERROR: tkinter no disponible: {e}")
        print("Instale con: sudo apt install python3-tk")
        sys.exit(1)
    
    # Crear y ejecutar aplicación de login
    try:
        print("Creando aplicación de login...")
        app = LoginAresitos()
        print("Aplicación de login creada")
        
        print("Iniciando interfaz gráfica...")
        app.root.mainloop()
        
    except KeyboardInterrupt:
        print("Login cancelado por el usuario")
    except Exception as e:
        print(f"ERROR crítico en login: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

