# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Login
========================

Vista para autenticación y verificación de herramientas del sistema ARESITOS.

Autor: DogSoulDev
Fecha: 16 de Agosto de 2025
"""

import os
import sys
import platform
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import getpass
import subprocess
import shlex
import hashlib
import re
import signal
import ctypes
from typing import Optional, Dict, List

try:
    from aresitos.vista.burp_theme import burp_theme
    from aresitos.vista.vista_herramientas_kali import VistaHerramientasKali
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

# Clase para manejar rate limiting de intentos de login
class RateLimiter:
    """Rate limiter para prevenir ataques de fuerza bruta"""
    
    def __init__(self, max_intentos: int = 3, ventana_tiempo: int = 300):
        self.max_intentos = max_intentos
        self.ventana_tiempo = ventana_tiempo  # 5 minutos
        self.intentos: Dict[str, List[float]] = {}
        self.lock = threading.Lock()
    
    def puede_intentar(self, identificador: str = "default") -> bool:
        """Verificar si se puede realizar un intento"""
        with self.lock:
            ahora = time.time()
            
            if identificador not in self.intentos:
                self.intentos[identificador] = []
            
            # Limpiar intentos antiguos
            self.intentos[identificador] = [
                timestamp for timestamp in self.intentos[identificador]
                if ahora - timestamp < self.ventana_tiempo
            ]
            
            return len(self.intentos[identificador]) < self.max_intentos
    
    def registrar_intento(self, identificador: str = "default"):
        """Registrar un intento fallido"""
        with self.lock:
            if identificador not in self.intentos:
                self.intentos[identificador] = []
            self.intentos[identificador].append(time.time())

# Utilidades de seguridad
class SeguridadUtils:
    """Utilidades de seguridad mejoradas"""
    
    @staticmethod
    def validar_entrada(entrada: str) -> bool:
        """Validar entrada para prevenir inyección de comandos"""
        if not entrada:
            return False
        
        # Caracteres peligrosos para inyección de comandos
        caracteres_peligrosos = ['&', ';', '|', '`', '$', '<', '>', '\n', '\r', '\\', '"']
        
        # Verificar caracteres peligrosos
        if any(char in entrada for char in caracteres_peligrosos):
            return False
        
        # Verificar longitud máxima
        if len(entrada) > 128:
            return False
        
        return True
    
    @staticmethod
    def limpiar_memoria_string(variable: str) -> None:
        """Intentar limpiar string de memoria (limitado en Python)"""
        try:
            # Python maneja la memoria automáticamente, pero podemos
            # sobrescribir la variable con datos aleatorios
            longitud = len(variable)
            variable = 'x' * longitud
            del variable
        except:
            pass
    
    @staticmethod
    def sanitizar_para_log(mensaje: str) -> str:
        """Sanitizar mensaje para logging seguro"""
        # Remover posibles contraseñas
        mensaje = re.sub(r'password[=:\s]+\S+', 'password=***', mensaje, flags=re.IGNORECASE)
        mensaje = re.sub(r'contraseña[=:\s]+\S+', 'contraseña=***', mensaje, flags=re.IGNORECASE)
        mensaje = re.sub(r'pass[=:\s]+\S+', 'pass=***', mensaje, flags=re.IGNORECASE)
        
        # Limitar longitud
        if len(mensaje) > 500:
            mensaje = mensaje[:497] + "..."
        
        return mensaje

def verificar_kali_linux_criptografico() -> bool:
    """Verificación criptográfica mejorada de Kali Linux"""
    try:
        # Verificación múltiple más robusta
        verificaciones = []
        
        # 1. Verificar /etc/os-release con hash conocido
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'kali' in content and 'linux' in content:
                    verificaciones.append(True)
        
        # 2. Verificar estructura de directorios específica de Kali
        directorios_kali = [
            '/usr/share/kali-defaults',
            '/etc/kali-version',
            '/usr/share/kali-themes',
            '/usr/share/applications/kali-linux.desktop'
        ]
        
        dirs_encontrados = sum(1 for d in directorios_kali if os.path.exists(d))
        if dirs_encontrados >= 2:  # Al menos 2 de 4
            verificaciones.append(True)
        
        # 3. Verificar herramientas específicas de Kali
        herramientas_kali = [
            '/usr/bin/nmap',
            '/usr/bin/sqlmap', 
            '/usr/bin/hydra',
            '/usr/bin/nikto',
            '/usr/share/wordlists'
        ]
        
        tools_encontradas = sum(1 for t in herramientas_kali if os.path.exists(t))
        if tools_encontradas >= 3:  # Al menos 3 de 5
            verificaciones.append(True)
        
        # 4. Verificar distribución en /proc/version si existe
        if os.path.exists('/proc/version'):
            with open('/proc/version', 'r') as f:
                version_info = f.read().lower()
                if 'debian' in version_info:  # Kali se basa en Debian
                    verificaciones.append(True)
        
        # Requerir al menos 2 verificaciones exitosas
        return len(verificaciones) >= 2
        
    except Exception:
        return False

# Herramientas requeridas para Aresitos (Kali Linux especializado)
HERRAMIENTAS_REQUERIDAS = [
    # Scanners de red criticos
    'nmap', 'masscan', 'zmap', 'rustscan', 'dnsenum', 'dnsrecon', 'fierce',
    'sublist3r', 'amass', 'gobuster', 'dirb', 'dirbuster', 'wfuzz',
    
    # Analisis de vulnerabilidades
    'nikto', 'sqlmap', 'wpscan', 'joomscan', 'droopescan', 'nuclei',
    'wapiti', 'skipfish', 'whatweb', 'wafw00f', 'davtest',
    
    # Herramientas de explotacion
    'metasploit', 'searchsploit', 'msfconsole', 'msfvenom', 'exploitdb',
    'beef-xss', 'set', 'social-engineer-toolkit',
    
    # Analisis de red
    'wireshark', 'tshark', 'tcpdump', 'netcat', 'nc', 'socat', 'netstat',
    'ss', 'lsof', 'arp-scan', 'ping', 'traceroute', 'mtr',
    
    # Cracking y bruteforce
    'hydra', 'medusa', 'ncrack', 'john', 'hashcat', 'aircrack-ng',
    'crunch', 'cewl', 'cupp', 'patator',
    
    # Forense y analisis
    'volatility', 'autopsy', 'sleuthkit', 'binwalk', 'foremost',
    'strings', 'hexdump', 'xxd', 'file', 'exiftool',
    
    # Utilidades del sistema
    'curl', 'wget', 'git', 'python3', 'pip3', 'perl', 'ruby',
    'java', 'gcc', 'make', 'cmake', 'openssl',
    
    # Herramientas adicionales
    'burpsuite', 'owasp-zap', 'commix', 'xsser', 'weevely',
    'backdoor-factory', 'shellter', 'veil', 'empire'
]

# Puertos criticos de seguridad para monitoreo (Kali Linux especializado)
PUERTOS_CRITICOS = [
    # Servicios basicos
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
    
    # Servicios de directorio y autenticacion
    389, 636, 88, 464, 749, 750, 751, 752, 753, 754,
    
    # Bases de datos
    1433, 1521, 3306, 5432, 6379, 27017, 5984, 9200, 9300,
    
    # Servicios de transferencia
    20, 69, 115, 119, 194, 389, 427, 465, 587, 691, 993, 995,
    
    # Servicios remotos
    3389, 5900, 5901, 5902, 1194, 1723, 4500,
    
    # Servicios web especializados
    8080, 8081, 8443, 9000, 9001, 9090, 8888, 3000, 4000, 5000,
    
    # Puertos de gestion
    161, 162, 623, 8080, 8081, 8443, 9000, 9001, 9090,
    
    # Servicios especializados
    179, 502, 503, 1194, 1812, 1813, 4500, 8883
]

def verificar_kali_linux_estricto():
    """Verificar estrictamente que estamos en Kali Linux usando método criptográfico"""
    return verificar_kali_linux_criptografico()

def verificar_permisos_admin_seguro():
    """Verificar permisos de administrador de forma segura"""
    try:
        # Verificar que estamos en Kali Linux primero
        if not verificar_kali_linux_criptografico():
            return False
        
        # Verificar sistema operativo primero
        if platform.system().lower() != 'linux':
            return False
        
        # Método 1: Verificar UID directamente (solo en Linux)
        try:
            if platform.system() == "Linux" and hasattr(os, 'getuid'):
                uid = getattr(os, 'getuid')()
                if uid == 0:
                    return True
        except (AttributeError, ImportError, OSError):
            # os.getuid() no existe en Windows o no hay soporte
            pass
        
        # Método 2: Verificar usando subprocess de forma segura
        try:
            result = subprocess.run(
                ['id', '-u'], 
                capture_output=True, 
                text=True, 
                timeout=3,
                check=False
            )
            if result.returncode == 0:
                uid = int(result.stdout.strip())
                return uid == 0
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        
        # Método 3: Verificar variable de entorno como último recurso
        return os.environ.get('USER') == 'root'
        
    except Exception:
        return False

class LoginAresitos:
    """
    Interfaz grafica de login para Aresitos con verificacion completa del sistema.
    Exclusivamente para Kali Linux con tema Burp Suite.
    Implementa medidas de seguridad avanzadas.
    """
    
    def __init__(self):
        # Verificar Kali Linux ANTES de crear ventana
        if not verificar_kali_linux_estricto():
            print("ERROR: ARESITOS requiere Kali Linux")
            print("Sistema no compatible detectado")
            sys.exit(1)
        
        # Inicializar rate limiter
        self.rate_limiter = RateLimiter(max_intentos=3, ventana_tiempo=300)
        self.utils_seguridad = SeguridadUtils()
        
        self.root = tk.Tk()
        self.root.title("ARESITOS - Autenticacion Segura")
        self.root.geometry("800x600")
        
        # Configurar tema Burp Suite
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            # Definir colores usando el tema
            self.bg_primary = burp_theme.get_color('bg_primary')
            self.bg_secondary = burp_theme.get_color('bg_secondary')
            self.bg_tertiary = burp_theme.get_color('bg_tertiary')
            self.fg_primary = burp_theme.get_color('fg_primary')
            self.fg_secondary = burp_theme.get_color('fg_secondary')
            self.accent_orange = burp_theme.get_color('fg_accent')
            self.accent_green = burp_theme.get_color('success')
            self.accent_red = burp_theme.get_color('danger')
        else:
            self.theme = None
            # Colores fallback (tema Burp Suite manual)
            self.bg_primary = "#1e1e1e"      # Fondo principal
            self.bg_secondary = "#2d2d2d"    # Fondo secundario  
            self.bg_tertiary = "#3c3c3c"     # Fondo terciario
            self.fg_primary = "#f0f0f0"      # Texto principal
            self.fg_secondary = "#b0b0b0"    # Texto secundario
            self.accent_orange = "#ff6633"   # Naranja Burp
            self.accent_green = "#4caf50"    # Verde exito
            self.accent_red = "#f44336"      # Rojo error
        self.accent_blue = "#2196f3"     # Azul info
        
        self.root.configure(bg=self.bg_primary)
        self.root.resizable(False, False)
        
        # Configurar estilos TTK si el tema está disponible
        if BURP_THEME_AVAILABLE and burp_theme:
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
        
        # Centrar ventana
        self.centrar_ventana()
        
        # Variables de estado
        self.password_correcta = False
        self.verificacion_completada = False
        self.es_kali = True  # Ya verificado
        self.herramientas_disponibles = []
        self.herramientas_faltantes = []
        self.session_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        
        # Crear interfaz
        self.crear_interfaz()
        
        # Auto-verificar entorno al inicio
        threading.Thread(target=self.verificar_entorno_inicial, daemon=True).start()
        
    def centrar_ventana(self):
        """Centrar la ventana en la pantalla"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (800 // 2)
        y = (self.root.winfo_screenheight() // 2) - (600 // 2)
        self.root.geometry(f"800x600+{x}+{y}")
    
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
        title_label.pack(pady=(0, 10))
        
        subtitle_label = tk.Label(
            main_frame,
            text="Sistema de Seguridad Cibernetica - Kali Linux",
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
        
        # Frame de verificacion del sistema
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
            command=self.root.quit,
            cursor='hand2',
            padx=20
        )
        exit_btn.pack(side=tk.LEFT)
        
        # Focus en campo de contraseña
        self.password_entry.focus()
    
    def escribir_log(self, mensaje):
        """Escribir mensaje en el area de logs de forma segura"""
        try:
            # Sanitizar mensaje antes de mostrar
            mensaje_seguro = self.utils_seguridad.sanitizar_para_log(mensaje)
            
            self.log_text.config(state=tk.NORMAL)
            
            # Insertar timestamp y mensaje
            timestamp = time.strftime('%H:%M:%S')
            linea_completa = f"[{timestamp}] {mensaje_seguro}\n"
            
            self.log_text.insert(tk.END, linea_completa)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
            self.root.update()
        except Exception as e:
            # Log de fallback en caso de error
            print(f"Error en logging: {e}")
    
    def verificar_entorno_inicial(self):
        """Verificar entorno del sistema al inicio"""
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
            
            self.escribir_log("Iniciando verificacion automatica de herramientas...")
            
            # Verificar herramientas en hilo separado
            threading.Thread(target=self.verificar_herramientas_inicial, daemon=True).start()
            
        except Exception as e:
            self.escribir_log(f"Error verificando entorno: {e}")
    
    def verificar_herramientas_inicial(self):
        """Verificacion inicial de herramientas"""
        try:
            self.herramientas_disponibles = []
            self.herramientas_faltantes = []
            
            total = len(HERRAMIENTAS_REQUERIDAS)
            
            for i, herramienta in enumerate(HERRAMIENTAS_REQUERIDAS):
                if shutil.which(herramienta):
                    self.herramientas_disponibles.append(herramienta)
                else:
                    self.herramientas_faltantes.append(herramienta)
                
                # Actualizar progreso cada 10 herramientas
                if i % 10 == 0:
                    progreso = (i + 1) / total * 100
                    self.escribir_log(f"Verificando herramientas... {i+1}/{total} ({progreso:.1f}%)")
            
            disponibles = len(self.herramientas_disponibles)
            
            self.escribir_log(f"Verificacion completada: {disponibles}/{total} herramientas disponibles")
            
            if disponibles >= total * 0.8:
                self.escribir_log("Excelente: Mas del 80% de herramientas disponibles")
                self.continue_btn.config(state=tk.NORMAL, bg=self.accent_green)
            elif disponibles >= total * 0.5:
                self.escribir_log("Aceptable: Mas del 50% de herramientas disponibles")
                self.continue_btn.config(state=tk.NORMAL, bg=self.accent_orange)
            else:
                self.escribir_log("Insuficiente: Menos del 50% de herramientas disponibles")
                self.continue_btn.config(state=tk.NORMAL, bg=self.accent_red)
            
            if self.herramientas_faltantes:
                faltan = len(self.herramientas_faltantes)
                self.escribir_log(f"{faltan} herramientas necesitan instalacion")
                
                # Mostrar algunas herramientas faltantes importantes
                importantes = ['nmap', 'sqlmap', 'hydra', 'wireshark', 'metasploit']
                faltantes_importantes = [h for h in importantes if h in self.herramientas_faltantes]
                
                if faltantes_importantes:
                    self.escribir_log(f"Herramientas criticas faltantes: {', '.join(faltantes_importantes[:5])}")
            
            self.verificacion_completada = True
            
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
        
        rutas_posibles = [
            aresitos_root,  # Ruta calculada desde el script
            "/home/kali/Aresitos",
            "/home/kali/Desktop/Aresitos", 
            "/home/kali/Ares-Aegis",
            "/home/kali/Desktop/Ares-Aegis",
            os.path.expanduser("~/Aresitos"),
            os.path.expanduser("~/Desktop/Aresitos"),
            os.path.expanduser("~/Ares-Aegis"),
            os.path.expanduser("~/Desktop/Ares-Aegis")
        ]
        
        return rutas_posibles
    
    def _ejecutar_comandos_permisos(self, ruta_proyecto, password):
        """Ejecutar comandos de permisos para una ruta específica"""
        # Lista de comandos para configurar permisos
        comandos_permisos = [
            # Permisos básicos para el proyecto
            f"chmod -R 755 {shlex.quote(ruta_proyecto)}",
            f"chown -R $USER:$USER {shlex.quote(ruta_proyecto)}",
            
            # Permisos especiales para configuración
            f"chmod -R 777 {shlex.quote(os.path.join(ruta_proyecto, 'configuracion'))}",
            f"chmod 777 {shlex.quote(os.path.join(ruta_proyecto, 'configuracion', 'aresitos_config.json'))} 2>/dev/null || true",
            f"chmod 777 {shlex.quote(os.path.join(ruta_proyecto, 'configuracion', 'aresitos_config_kali.json'))} 2>/dev/null || true",
            
            # Permisos para data y logs
            f"chmod -R 777 {shlex.quote(os.path.join(ruta_proyecto, 'data'))} 2>/dev/null || true",
            f"chmod -R 777 {shlex.quote(os.path.join(ruta_proyecto, 'logs'))} 2>/dev/null || true",
            
            # Ejecutables Python
            f"find {shlex.quote(ruta_proyecto)} -name '*.py' -exec chmod +x {{}} \\;",
            f"chmod +x {shlex.quote(os.path.join(ruta_proyecto, 'main.py'))}",
            
            # Crear directorios necesarios
            f"mkdir -p {shlex.quote(os.path.join(ruta_proyecto, 'logs'))} && chmod 777 {shlex.quote(os.path.join(ruta_proyecto, 'logs'))}",
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
            config_file = os.path.join(ruta_proyecto, 'configuracion', 'aresitos_config.json')
            
            if os.access(main_py, os.X_OK):
                self.escribir_log("main.py ejecutable")
            if os.access(config_file, os.R_OK | os.W_OK):
                self.escribir_log("Archivo de configuración accesible")
            else:
                self.escribir_log("Archivo de configuración no accesible")
                
        except Exception:
            pass
            
        self.escribir_log("Configuración de permisos completada")
    
    def verificar_password(self):
        """Verificar la contraseña ingresada con medidas de seguridad mejoradas"""
        password = self.password_entry.get()
        
        # Verificar rate limiting
        if not self.rate_limiter.puede_intentar(self.session_id):
            tiempo_restante = 5  # Mostrar tiempo simplificado
            messagebox.showerror(
                "Bloqueado", 
                f"Demasiados intentos fallidos.\n"
                f"Intente nuevamente en {tiempo_restante} minutos."
            )
            self.escribir_log("Intento bloqueado por rate limiting")
            return
        
        # Validar entrada
        if not password:
            messagebox.showerror("Error", "Por favor ingrese la contraseña")
            return
        
        if not self.utils_seguridad.validar_entrada(password):
            messagebox.showerror("Error", "Contraseña contiene caracteres no válidos")
            self.rate_limiter.registrar_intento(self.session_id)
            self.escribir_log("Contraseña con caracteres inválidos detectada")
            return
        
        self.escribir_log("Verificando credenciales de root...")
        
        try:
            # Escapar la contraseña de forma segura
            password_escaped = shlex.quote(password)
            
            # Ejecutar verificación con timeout más estricto
            resultado = subprocess.run(
                ['sudo', '-S', '-k', 'echo', 'test'], 
                input=password + '\n', 
                text=True, 
                capture_output=True, 
                timeout=10,  # Timeout aumentado pero controlado
                check=False
            )
            
            if resultado.returncode == 0:
                self.password_correcta = True
                self.escribir_log("Autenticacion exitosa - Permisos de root confirmados")
                
                # Configurar permisos completos para ARESITOS
                self.configurar_permisos_aresitos(password)
                
                # Limpiar contraseña de memoria
                self.utils_seguridad.limpiar_memoria_string(password)
                self.password_entry.delete(0, tk.END)
                
                # Deshabilitar campos de login
                self.login_btn.config(state=tk.DISABLED)
                self.password_entry.config(state=tk.DISABLED)
                self.skip_btn.config(state=tk.DISABLED)
                
                # INSTALACIÓN AUTOMÁTICA DE HERRAMIENTAS KALI
                self.escribir_log(" Configurando herramientas de Kali Linux...")
                self.instalar_herramientas_kali_automatico(password)
                
                # Si ya completo verificacion, habilitar continuar
                if self.verificacion_completada:
                    self.continue_btn.config(state=tk.NORMAL)
            else:
                self.rate_limiter.registrar_intento(self.session_id)
                self.escribir_log("Contraseña incorrecta")
                
                # Limpiar contraseña de memoria
                self.utils_seguridad.limpiar_memoria_string(password)
                self.password_entry.delete(0, tk.END)
                
                messagebox.showerror("Error", "Contraseña incorrecta")
                
        except subprocess.TimeoutExpired:
            self.rate_limiter.registrar_intento(self.session_id)
            self.escribir_log("Timeout verificando contraseña")
            self.utils_seguridad.limpiar_memoria_string(password)
            self.password_entry.delete(0, tk.END)
            messagebox.showerror("Error", "Timeout en verificacion")
        except FileNotFoundError:
            self.escribir_log("sudo no disponible - Continuando sin verificacion")
            self.continuar_sin_root()
        except subprocess.SubprocessError as e:
            self.rate_limiter.registrar_intento(self.session_id)
            self.escribir_log(f"Error subprocess: {type(e).__name__}")
            self.utils_seguridad.limpiar_memoria_string(password)
            self.password_entry.delete(0, tk.END)
            messagebox.showerror("Error", "Error en verificacion del sistema")
        except Exception as e:
            self.rate_limiter.registrar_intento(self.session_id)
            self.escribir_log(f"Error en verificacion: {type(e).__name__}")
            self.utils_seguridad.limpiar_memoria_string(password)
            self.password_entry.delete(0, tk.END)
            messagebox.showerror("Error", "Error de verificacion")
    
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
            self.escribir_log(f"ERROR Error en instalación automática: {e}")
    
    def _ejecutar_instalacion_herramientas(self, herramientas, password):
        """Ejecutar instalación de herramientas en thread separado"""
        try:
            # Actualizar repositorios primero
            self.escribir_log("📥 Actualizando repositorios...")
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
                self.escribir_log("WARNING Warning al actualizar repositorios")
            
            # Instalar herramientas una por una
            for herramienta in herramientas[:5]:  # Limitamos a 5 para no sobrecargar
                self.escribir_log(f" Instalando {herramienta}...")
                
                cmd_install = f"echo '{password}' | sudo -S apt install -y {herramienta}"
                
                result = subprocess.run(
                    cmd_install,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    self.escribir_log(f"OK {herramienta} instalado correctamente")
                    # Remover de la lista de faltantes
                    if herramienta in self.herramientas_faltantes:
                        self.herramientas_faltantes.remove(herramienta)
                else:
                    self.escribir_log(f"ERROR Error instalando {herramienta}")
            
            self.escribir_log(" Instalación automática completada")
            
            # Limpiar password de memoria
            self.utils_seguridad.limpiar_memoria_string(password)
            
        except Exception as e:
            self.escribir_log(f"ERROR Error en instalación: {e}")

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
            messagebox.showwarning("Advertencia", "Complete la verificacion del sistema primero")
            return
        
        self.escribir_log(" Abriendo ventana de herramientas de Kali Linux...")
        
        try:
            # Mostrar vista de herramientas de Kali antes de la aplicación principal
            def callback_herramientas_completadas():
                """Callback para cuando se complete la configuración de herramientas"""
                self._iniciar_aplicacion_principal()
            
            # Crear ventana de herramientas
            vista_herramientas = VistaHerramientasKali(self.root, callback_herramientas_completadas)
            
        except Exception as e:
            self.escribir_log(f"ERROR Error mostrando vista de herramientas: {str(e)}")
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
            
            self.escribir_log("Módulos principales importados correctamente")
            
            # Cerrar ventana de login
            self.root.destroy()
            
            self.escribir_log("Creando aplicación principal...")
            
            # Crear aplicación principal
            root_app = tk.Tk()
            root_app.title("ARESITOS - Sistema de Seguridad Kali Linux")
            root_app.geometry("1200x800")
            
            # Configurar ícono si está disponible
            try:
                icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "recursos", "Aresitos.ico")
                if os.path.exists(icon_path):
                    root_app.iconbitmap(icon_path)
            except:
                pass
            
            self.escribir_log("Inicializando modelo de datos...")
            # Inicializar MVC
            modelo = ModeloPrincipal()
            
            self.escribir_log("Creando vista principal...")
            vista = VistaPrincipal(root_app)
            
            self.escribir_log("Inicializando controlador principal...")
            controlador = ControladorPrincipal(modelo, vista)
            
            self.escribir_log("Configurando conexión vista-controlador...")
            vista.set_controlador(controlador)
            
            # Centrar ventana principal
            root_app.update_idletasks()
            x = (root_app.winfo_screenwidth() // 2) - (1200 // 2)
            y = (root_app.winfo_screenheight() // 2) - (800 // 2)
            root_app.geometry(f"1200x800+{x}+{y}")
            
            # Configurar ícono para la ventana principal también
            try:
                icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "recursos", "Aresitos.ico")
                if os.path.exists(icon_path):
                    root_app.iconbitmap(icon_path)
                    self.escribir_log("OK Ícono de aplicación configurado correctamente")
                else:
                    self.escribir_log("WARNING Archivo de ícono no encontrado en: " + icon_path)
            except Exception as e:
                self.escribir_log(f"WARNING Error configurando ícono: {str(e)}")
            
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
    if not verificar_kali_linux_estricto():
        print("ERROR: ARESITOS requiere Kali Linux")
        print("Sistema operativo no compatible")
        sys.exit(1)
    
    print("ARESITOS - Iniciando login...")
    
    # Verificar tkinter disponible
    try:
        import tkinter as tk
        print("✓ Tkinter importado correctamente")
    except ImportError as e:
        print(f"ERROR: tkinter no disponible: {e}")
        print("Instale con: sudo apt install python3-tk")
        sys.exit(1)
    
    # Crear y ejecutar aplicación de login
    try:
        print("Creando aplicación de login...")
        app = LoginAresitos()
        print("✓ Aplicación de login creada")
        
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
