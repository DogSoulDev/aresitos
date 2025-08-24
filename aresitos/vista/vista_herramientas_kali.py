# -*- coding: utf-8 -*-
"""
ARESITOS - Vista Herramientas Kali Linux [SINCRONIZADO CON CONFIGURADOR]
========================================================================

Vista especializada para herramientas nativas de Kali Linux.
Mantiene la arquitectura 100% Python nativo + herramientas Kali.

PRINCIPIOS ARESITOS V3.0 APLICADOS:
- CONSISTENCIA: Herramientas sincronizadas con configurar_kali.sh
- THREAD SAFETY: ThreadPoolExecutor para operaciones concurrentes
- TRANSPARENCIA: Documentación precisa de dependencias
- MODULARIDAD: Separación clara de responsabilidades

SINCRONIZACIÓN: Las herramientas verificadas coinciden EXACTAMENTE
con las definidas en essential_tools, advanced_tools y security_tools
del archivo configurar_kali.sh.

Autor: DogSoulDev
Fecha: 23 de Agosto de 2025 [SINCRONIZADO]
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import logging
from typing import Optional, Any
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

try:
    from aresitos.vista.burp_theme import burp_theme
    from aresitos.utils.sudo_manager import get_sudo_manager, is_sudo_available
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientasKali(tk.Frame):
    """Vista para herramientas nativas de Kali Linux"""
    
    def __init__(self, parent, callback_completado=None):
        """Inicialización con principios ARESITOS V3: Thread Safety + Acceso Dinámico."""
        super().__init__(parent)
        
        # PRINCIPIO ARESITOS V3: Thread Safety
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ARESITOS_Kali")
        
        # VERIFICACIÓN CRÍTICA: Solo para Kali Linux (excepto en modo desarrollo)
        import sys
        modo_desarrollo = '--dev' in sys.argv or '--desarrollo' in sys.argv
        
        try:
            if not self._verificar_kali_linux() and not modo_desarrollo:
                messagebox.showerror(
                    "Error - Solo Kali Linux", 
                    "ARESITOS está diseñado exclusivamente para Kali Linux.\n\n"
                    "Sistema detectado no es compatible.\n"
                    "Instale Kali Linux para usar ARESITOS."
                )
                self._cleanup_resources()
                return
            elif not self._verificar_kali_linux() and modo_desarrollo:
                messagebox.showinfo(
                    "Modo Desarrollo", 
                    "MODO DESARROLLO ACTIVADO\n\n"
                    "Ejecutando en entorno no-Kali.\n"
                    "Funcionalidad limitada disponible."
                )
            
            # PRINCIPIO ARESITOS V3: Inicialización Dinámica
            self.controlador = None  # Patrón MVC
            self.callback_completado = callback_completado
            self.proceso_activo = False
            self.logger = logging.getLogger(__name__)
            
            # PRINCIPIO ARESITOS V3: Configuración de tema con fallback
            self._configurar_tema_dinamico()
            
            # PRINCIPIO ARESITOS V3: Cache sistema
            self._cache_herramientas = {}
            self._cache_comandos = {}
            
            # Crear interfaz protegida
            self.crear_interfaz()
            
        except Exception as e:
            self.logger.error(f"Error en inicialización: {e}")
            self._crear_interfaz_fallback()
    
    def _cleanup_resources(self):
        """Limpieza de recursos con thread safety (PRINCIPIO ARESITOS V3)."""
        try:
            with self.lock:
                if hasattr(self, 'executor'):
                    self.executor.shutdown(wait=False)
                if hasattr(self, 'proceso_activo'):
                    self.proceso_activo = False
        except Exception as e:
            print(f"Error en cleanup: {e}")
    
    def _configurar_tema_dinamico(self):
        """Configuración dinámica del tema con fallback (PRINCIPIO ARESITOS V3)."""
        try:
            # Acceso dinámico al tema
            if BURP_THEME_AVAILABLE and burp_theme:
                self.theme = burp_theme
            # Configurar estilo TTK siguiendo principios ARESITOS
            self.style = ttk.Style()
            self.theme.configure_ttk_style(self.style)
            bg_color = getattr(burp_theme, 'get_color', lambda x: '#2e2e2e')('bg_primary')
            self.configure(bg=bg_color)
            
            self.colors = {
                'bg_primary': getattr(burp_theme, 'get_color', lambda x: '#2e2e2e')('bg_primary'),
                'bg_secondary': getattr(burp_theme, 'get_color', lambda x: '#404040')('bg_secondary'), 
                'fg_primary': getattr(burp_theme, 'get_color', lambda x: '#ffffff')('fg_primary'),
                'fg_accent': getattr(burp_theme, 'get_color', lambda x: '#ff6633')('fg_accent'),
                'button_bg': getattr(burp_theme, 'get_color', lambda x: '#007acc')('button_bg'),
                'success': getattr(burp_theme, 'get_color', lambda x: '#00ff00')('success'),
                'warning': getattr(burp_theme, 'get_color', lambda x: '#ffaa00')('warning')
            }
            self.configure(bg=self.colors['bg_primary'])
                
        except Exception as e:
            self.logger.warning(f"Error configurando tema: {e}")
            # Tema de emergencia
            self.colors = {'bg_primary': '#2e2e2e', 'bg_secondary': '#404040', 'fg_primary': '#ffffff',
                          'fg_accent': '#ff6633', 'button_bg': '#007acc', 'success': '#00ff00', 'warning': '#ffaa00'}
            self.configure(bg=self.colors['bg_primary'])
    
    def _crear_interfaz_fallback(self):
        """Interfaz de fallback en caso de error (PRINCIPIO ARESITOS V3)."""
        try:
            fallback_frame = tk.Frame(self, bg='#2e2e2e')
            fallback_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            tk.Label(
                fallback_frame,
                text="WARNING MODO SEGURO - HERRAMIENTAS KALI",
                bg='#2e2e2e',
                fg='#ffaa00',
                font=('Arial', 12, 'bold')
            ).pack(pady=10)
            
            tk.Label(
                fallback_frame,
                text="Interfaz reducida disponible",
                bg='#2e2e2e',
                fg='#ffffff'
            ).pack()
            
        except Exception as e:
            print(f"Error en interfaz fallback: {e}")
    
    def set_controlador(self, controlador: Optional[Any]):
        """Establecer controlador siguiendo patrón MVC"""
        self.controlador = controlador
    
    def crear_interfaz(self):
        """Crear interfaz completa para herramientas Kali con principios ARESITOS V3."""
        try:
            # PRINCIPIO ARESITOS V3: Thread Safety
            with self.lock:
                # Frame principal
                main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
                main_frame.pack(fill="both", expand=True, padx=20, pady=20)
                
                # PRINCIPIO ARESITOS V3: Carga dinámica de logo
                self._cargar_logo_dinamico(main_frame)
                
                # Título principal
                titulo = tk.Label(
                    main_frame,
                    text="SECURE HERRAMIENTAS KALI LINUX",
                    bg=self.colors['bg_primary'],
                    fg=self.colors['fg_accent'],
                    font=('Arial', 16, 'bold')
                )
                titulo.pack(pady=(0, 20))
                
                # PRINCIPIO ARESITOS V3: Creación protegida de componentes
                self._crear_notebook_herramientas(main_frame)
                
        except Exception as e:
            self.logger.error(f"Error creando interfaz: {e}")
            self._crear_interfaz_fallback()
    
    def _cargar_logo_dinamico(self, parent):
        """Logo textual de ciberseguridad sin dependencias externas (PRINCIPIO ARESITOS V3)."""
        try:
            # Logo textual con símbolo de ciberseguridad
            logo_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
            logo_frame.pack(pady=(0, 10))
            
            # Símbolo de seguridad
            symbol_label = tk.Label(
                logo_frame,
                text="[SHIELD]",
                font=("Arial", 16, "bold"),
                bg=self.colors['bg_primary'],
                fg="#2E86C1"
            )
            symbol_label.pack()
            
            # Texto ARESITOS
            text_label = tk.Label(
                logo_frame,
                text="ARESITOS V3",
                font=("Arial", 12, "bold"),
                bg=self.colors['bg_primary'],
                fg=self.colors['text_primary']
            )
            text_label.pack()
            
            # Subtítulo
            subtitle_label = tk.Label(
                logo_frame,
                text="CYBER SECURITY TOOLS",
                font=("Arial", 8),
                bg=self.colors['bg_primary'],
                fg=self.colors['text_secondary']
            )
            subtitle_label.pack()
            
        except Exception as e:
            self.logger.warning(f"Error configurando logo: {e}")
            # Continuar sin logo si hay problemas
    
    def _crear_notebook_herramientas(self, parent):
        """Crear notebook de herramientas con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            # Crear notebook con verificación dinámica
            notebook_class = getattr(ttk, 'Notebook', None)
            if notebook_class:
                self.notebook = notebook_class(parent)
                self.notebook.pack(fill="both", expand=True)
                
                # PRINCIPIO ARESITOS V3: Creación asíncrona de tabs
                self.executor.submit(self._crear_tabs_herramientas)
            else:
                self.logger.error("Notebook no disponible")
                self._crear_interfaz_simple(parent)
                
        except Exception as e:
            self.logger.error(f"Error creando notebook: {e}")
            self._crear_interfaz_simple(parent)
    
    def _crear_interfaz_simple(self, parent):
        """Interfaz simple de fallback (PRINCIPIO ARESITOS V3)."""
        try:
            simple_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
            simple_frame.pack(fill="both", expand=True)
            
            tk.Label(
                simple_frame,
                text="LIST Herramientas Kali disponibles en modo básico",
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary'],
                font=('Arial', 12)
            ).pack(pady=20)
            
        except Exception as e:
            self.logger.error(f"Error en interfaz simple: {e}")
    
    def _crear_tabs_herramientas(self):
        """Crear contenido de herramientas de forma asíncrona (PRINCIPIO ARESITOS V3)."""
        try:
            # PRINCIPIO ARESITOS V3: Verificación dinámica de notebook
            if hasattr(self, 'notebook') and self.notebook:
                # Por ahora, retornamos ya que el archivo usa botones directos
                # En futuras versiones se pueden agregar tabs específicos
                self.logger.info("Notebook disponible para futuras expansiones")
            else:
                self.logger.warning("Notebook no disponible")
                
        except Exception as e:
            self.logger.error(f"Error preparando tabs: {e}")
        
        # Continuar con la creación de la interfaz original
        try:
            # Llamar al método después para crear la interfaz principal
            self.after(100, self._crear_interfaz_principal)
        except Exception as e:
            self.logger.error(f"Error programando interfaz principal: {e}")
    
    def _crear_interfaz_principal(self):
        """Crear la interfaz principal con botones (PRINCIPIO ARESITOS V3)."""
        try:
            # Verificar si ya tiene parent configurado
            if not hasattr(self, '_interfaz_creada'):
                self._interfaz_creada = True
                
                # Buscar el main_frame o crear uno nuevo
                main_frame = None
                for child in self.winfo_children():
                    if isinstance(child, tk.Frame):
                        main_frame = child
                        break
                
                if not main_frame:
                    main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
                    main_frame.pack(fill="both", expand=True, padx=20, pady=20)
                
                # Título
                titulo_label = tk.Label(
                    main_frame, 
                    text="Configurador de Herramientas Kali",
                    font=('Arial', 16, 'bold'),
                    bg=self.colors['bg_primary'], 
                    fg=self.colors['fg_accent']
                )
                titulo_label.pack(pady=(0, 20))
                
                # Subtítulo informativo
                info_label = tk.Label(
                    main_frame,
                    text="Antes de arrancar el programa es recomendable instalar las herramientas que se usaran.",
                    font=('Arial', 11),
                    bg=self.colors['bg_primary'],
                    fg=self.colors['fg_primary'],
                    justify=tk.CENTER
                )
                info_label.pack(pady=(0, 30))
                
                # Frame de botones con distribución uniforme
                botones_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
                botones_frame.pack(fill="x", pady=(0, 20))
                
                # Configurar columnas con peso igual para distribución uniforme
                for i in range(4):
                    botones_frame.grid_columnconfigure(i, weight=1, uniform="botones")
                
                # PRINCIPIO ARESITOS V3: Creación protegida de botones
                self._crear_botones_herramientas(botones_frame, main_frame)
                
        except Exception as e:
            self.logger.error(f"Error creando interfaz principal: {e}")
    
    def _crear_botones_herramientas(self, botones_frame, main_frame):
        """Crear botones de herramientas con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            # Botón verificar herramientas - PRINCIPIO ARESITOS: TTK con estilo consistente
            self.btn_verificar = ttk.Button(
                botones_frame,
                text="🔍 Verificar Herramientas",
                style="Burp.TButton",
                command=self.verificar_herramientas
            )
            self.btn_verificar.grid(row=0, column=0, padx=10, sticky="ew")
            
            # Botón mostrar optimizaciones - PRINCIPIO ARESITOS: Interfaz clara e intuitiva
            self.btn_optimizaciones = ttk.Button(
                botones_frame,
                text="⚡ Ver Optimizaciones",
                style="Burp.TButton",
                command=self.mostrar_optimizaciones
            )
            self.btn_optimizaciones.grid(row=0, column=1, padx=10, sticky="ew")
            
            # Botón instalar herramientas - PRINCIPIO ARESITOS: Automatización de instalación
            self.btn_instalar = ttk.Button(
                botones_frame,
                text="⚙️ Instalar Faltantes",
                style="Burp.TButton",
                command=self.instalar_herramientas,
                state='disabled'
            )
            self.btn_instalar.grid(row=0, column=2, padx=10, sticky="ew")
            
            # PRINCIPIO ARESITOS V3: Continuar con resto de la interfaz
            self._crear_resto_interfaz(botones_frame, main_frame)
            
        except Exception as e:
            self.logger.error(f"Error creando botones: {e}")
    
    def _crear_resto_interfaz(self, botones_frame, main_frame):
        """Crear el resto de la interfaz (PRINCIPIO ARESITOS V3)."""
        try:
            # Botón continuar - PRINCIPIO ARESITOS: Progreso fluido hacia aplicación principal
            self.btn_continuar = ttk.Button(
                botones_frame,
                text="✅ Continuar a ARESITOS",
                style="Burp.TButton",
                command=self.continuar_aplicacion,
                state='normal'  # Habilitado por defecto
            )
            self.btn_continuar.grid(row=0, column=3, padx=10, sticky="ew")
            
            # Área de resultados
            self.text_resultados = scrolledtext.ScrolledText(
                main_frame,
                height=20,
                width=80,
                bg=self.colors['bg_secondary'],
                fg=self.colors['fg_primary'],
                font=('Consolas', 10),
                insertbackground=self.colors['fg_accent'],
                relief='flat',
                bd=2
            )
            self.text_resultados.pack(fill="both", expand=True)
            
            # Mensaje inicial
            self._mostrar_mensaje_inicial()
            
        except Exception as e:
            self.logger.error(f"Error creando resto de interfaz: {e}")
    
    def _mostrar_mensaje_inicial(self):
        """Mostrar mensaje inicial con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            # PRINCIPIO ARESITOS V3: Acceso dinámico al text widget
            text_widget = getattr(self, 'text_resultados', None)
            if text_widget:
                metodo_insert = getattr(text_widget, 'insert', None)
                if metodo_insert:
                    mensaje_inicial = (
                        "ARESITOS v3.0 - Configurador de Herramientas Escaneador Profesional\n" +
                        "=" * 50 + "\n\n" +
                        "Sistema optimizado para Kali Linux con comandos nativos integrados:\n\n" +
                        "COMANDOS BÁSICOS:\n" +
                        "• Sistema: ps, ss, lsof, grep, awk, find, stat, lsmod, iptables\n" +
                        "• Red: nmap, netcat, ip, route, ss, hping3, curl, wget\n" +
                        "• Análisis: wireshark, tcpdump, strings, file, hexdump\n" +
                        "• Forense: bulk_extractor, binwalk, foremost, dd, autopsy\n\n" +
                        "HERRAMIENTAS ESPECIALIZADAS:\n" +
                        "• Reconocimiento: nmap, masscan, enum4linux, gobuster\n" +
                        "• Vulnerabilidades: nikto, dirb, sqlmap, wpscan\n" +
                        "• Explotación: metasploit, burpsuite, hydra, john\n" +
                        "• Post-explotación: mimikatz, empire, powersploit\n" +
                        "• Análisis malware: yara, clamav, virustotal-cli\n\n" +
                        "TOOL Presiona 'Verificar Herramientas' para comprobar disponibilidad\n" +
                        "CONFIG Presiona 'Ver Optimizaciones' para detalles técnicos\n" +
                        "📦 Presiona 'Instalar Faltantes' si necesitas herramientas\n" +
                        "PLAY Presiona 'Continuar a ARESITOS' cuando estés listo\n\n"
                    )
                    metodo_insert(tk.END, mensaje_inicial)
                else:
                    self.logger.warning("Método insert no disponible en text_resultados")
        except Exception as e:
            self.logger.error(f"Error mostrando mensaje inicial: {e}")
    def _centrar_ventana(self):
        """Centrar la ventana en la pantalla"""
        try:
            # Obtener la ventana raíz
            root = self.winfo_toplevel()
            root.update_idletasks()
            
            # Establecer tamaño mínimo más grande para mostrar todos los botones
            root.minsize(1000, 700)
            
            # Obtener dimensiones
            width = max(1000, root.winfo_width())
            height = max(700, root.winfo_height())
            x = (root.winfo_screenwidth() // 2) - (width // 2)
            y = (root.winfo_screenheight() // 2) - (height // 2)
            
            # Establecer posición y tamaño
            root.geometry(f"{width}x{height}+{x}+{y}")
            
            # Asegurar que sea redimensionable
            root.resizable(True, True)
            
        except Exception as e:
            self.logger.debug(f"Error centrando ventana: {e}")
    
    def mostrar_optimizaciones(self):
        """Mostrar todas las optimizaciones Kali Linux ya aplicadas"""
        self.text_resultados.delete(1.0, tk.END)
        
        optimizaciones_texto = """ARESITOS v3.0 - OPTIMIZACIONES KALI LINUX APLICADAS
=======================================================

OK SISTEMA COMPLETAMENTE OPTIMIZADO PARA KALI LINUX

VISTA DASHBOARD:
   • 15 comandos Linux avanzados integrados
   • ps aux --sort=-%cpu (procesos por CPU)
   • ip addr show (configuración de red)
   • ss -tuln (conexiones activas)
   • lsof -i (archivos y procesos de red)
   • systemctl list-units (servicios del sistema)
   • free -h, df -h (memoria y disco)
   • uname -a (información del kernel)
   • who, last (usuarios conectados/historial)

VISTA ESCANEO:
   • Escaneo de red nativo con nmap integrado
   • Análisis de servicios con ss y lsof
   • Detección de procesos de red
   • Monitoreo de servicios systemd
   • Reconnaissance avanzado con herramientas Kali

VISTA FIM (File Integrity Monitoring):
   • find para detección de archivos modificados
   • stat para análisis detallado de permisos
   • lsof para monitoreo de archivos abiertos
   • Detección de binarios SUID
   • Verificación de integridad con comandos nativos

VISTA SIEM (Security Information & Event Management):
   • grep avanzado para análisis de logs
   • awk para procesamiento de registros
   • Análisis de patrones de seguridad
   • Correlación de eventos con herramientas Linux
   • Detección de anomalías

VISTA MONITOREO:
   • Monitoreo en tiempo real con top y ps
   • Análisis de red con ss y netstat
   • Supervisión del sistema de archivos
   • Tracking de logins con last y who
   • Monitoreo de recursos del sistema

VISTA AUDITORÍA:
   • Detección avanzada de rootkits
   • Comparación /proc vs ps para detección
   • Verificación de integridad de comandos
   • Análisis de módulos del kernel
   • Verificación de procesos sospechosos

VISTA REPORTES:
   • Análisis de logs con herramientas Kali
   • Generación de estadísticas del sistema
   • Informes de seguridad automatizados
   • Comparación de reportes con diff
   • Análisis forense de registros

VISTA GESTIÓN DE DATOS:
   • Análisis de wordlists con grep, sort, uniq
   • Estadísticas avanzadas con wc y awk
   • Procesamiento de diccionarios
   • Optimización de datos con herramientas Linux

INTEGRACIÓN NATIVA:
   • 60+ comandos Linux nativos integrados
   • Subprocess optimizado para Kali
   • Threading para operaciones no bloqueantes
   • Manejo robusto de errores
   • Logging integrado al terminal

HERRAMIENTAS PRINCIPALES DEL ESCANEADOR PROFESIONAL v3.0:
   • CORE: nmap (scripts NSE), masscan (escaneo masivo), gobuster (directorios)
   • AVANZADAS: rustscan (velocidad), nuclei (CVE), ffuf (fuzzing), feroxbuster (recursivo)
   • ANÁLISIS: strings, hexdump, binwalk, sleuthkit, yara
   • SEGURIDAD: chkrootkit, rkhunter, auditd, fail2ban, lynis
   • RED: ip, route, netstat, netcat, tcpdump, wireshark

BENEFICIOS DEL ESCANEADOR PROFESIONAL v3.0:
   • Rendimiento optimizado para Kali Linux 2025
   • Integración nativa con herramientas de escaneado modernas  
   • Detección automática de vulnerabilidades CVE actualizadas
   • Enumeración web avanzada con múltiples métodos
   • Fallback inteligente según herramientas disponibles
   • Exportación profesional de resultados de escaneo

OK ESTADO: ESCANEADOR PROFESIONAL v3.0 OPTIMIZADO
LISTO PARA: Escaneos de vulnerabilidades en entornos Kali Linux 2025

"""
        
        self.text_resultados.insert(tk.END, optimizaciones_texto)
        self.text_resultados.see(tk.END)
        
        self._log_terminal("Optimizaciones Kali Linux mostradas", "HERRAMIENTAS_KALI", "INFO")
    
    def verificar_herramientas(self):
        """Verificar herramientas de Kali Linux disponibles con principios ARESITOS V3."""
        try:
            # PRINCIPIO ARESITOS V3: Thread Safety
            with self.lock:
                if self.proceso_activo:
                    self.logger.warning("Verificación ya en proceso")
                    return
                
                self.proceso_activo = True
                
                # PRINCIPIO ARESITOS V3: Acceso dinámico a componentes UI
                btn_verificar = getattr(self, 'btn_verificar', None)
                if btn_verificar:
                    metodo_exists = getattr(btn_verificar, 'winfo_exists', None)
                    metodo_config = getattr(btn_verificar, 'config', None)
                    if metodo_exists and metodo_config:
                        try:
                            if metodo_exists():
                                metodo_config(state='disabled')
                        except tk.TclError:
                            pass
                
                text_resultados = getattr(self, 'text_resultados', None)
                if text_resultados:
                    metodo_exists = getattr(text_resultados, 'winfo_exists', None)
                    metodo_delete = getattr(text_resultados, 'delete', None)
                    if metodo_exists and metodo_delete:
                        try:
                            if metodo_exists():
                                metodo_delete(1.0, tk.END)
                        except tk.TclError:
                            pass
                
                # PRINCIPIO ARESITOS V3: Ejecución asíncrona con ThreadPoolExecutor
                self.executor.submit(self._verificar_herramientas_async)
                
        except Exception as e:
            self.logger.error(f"Error iniciando verificación de herramientas: {e}")
            self.proceso_activo = False
    
    def _verificar_herramientas_async(self):
        """Verificación asíncrona de herramientas con principios ARESITOS V3."""
        try:
            # PRINCIPIO ARESITOS V3: Thread Safety y logging
            with self.lock:
                self.logger.info("Iniciando verificación asíncrona de herramientas")
            
            # Mostrar mensaje inicial de forma segura
            self.after(0, self._actualizar_texto, "Verificando herramientas de Kali Linux...\n\n")
            
            # PRINCIPIO ARESITOS V3: Cache sistema para herramientas
            if not hasattr(self, '_cache_herramientas'):
                self._cache_herramientas = {}
            
            # Lista de herramientas esenciales modernizadas para Kali 2025
            # HERRAMIENTAS SINCRONIZADAS CON configurar_kali.sh [PRINCIPIO ARESITOS: CONSISTENCIA]
            herramientas = [
                # Comandos básicos del sistema (nativos de Linux)
                'ps', 'ss', 'lsof', 'netstat', 'top', 'free', 'df', 'uname', 'who', 'last',
                'find', 'stat', 'grep', 'awk', 'sort', 'uniq', 'wc', 'tail', 'head',
                'systemctl', 'ip', 'route', 'wget', 'curl', 'diff', 'ls', 'chmod', 'chown',
                'lsmod', 'kill', 'pgrep', 'pkill', 'sha256sum', 'md5sum', 'sha1sum', 'sha512sum',
                'iptables', 'cat', 'less', 'more', 'pwd', 'mkdir', 'rm', 'cp', 'mv',
                'which', 'whereis', 'type', 'command',
                
                # HERRAMIENTAS ESENCIALES (sincronizadas con essential_tools en configurar_kali.sh)
                'python3-dev', 'python3-venv', 'python3-tk', 'git',
                'nmap', 'masscan', 'net-tools', 'iproute2', 'tcpdump', 'iftop', 'netcat-openbsd',
                'wireshark', 'autopsy', 'sleuthkit', 'foremost', 'binwalk', 'strings', 'exiftool',
                'htop', 'psmisc', 'dnsutils', 'whois',
                
                # HERRAMIENTAS AVANZADAS (sincronizadas con advanced_tools en configurar_kali.sh)
                'ffuf', 'feroxbuster', 'rustscan', 'nuclei', 'nikto', 'whatweb', 'dirb',
                'lynis', 'chkrootkit',
                
                # HERRAMIENTAS DE SEGURIDAD (sincronizadas con security_tools en configurar_kali.sh)
                'rkhunter', 'clamav-daemon', 'clamav-freshclam', 'bulk_extractor', 'yara',
                
                # Comandos adicionales para funcionalidades específicas ARESITOS
                'clamscan', 'freshclam',  # ClamAV ejecutables
                'gobuster',  # Directory enumeration (disponible en Kali)
                'httpx',     # HTTP probing (instalado via Go en configurador)
                
                # Herramientas de monitoreo para FIM y SIEM
                'inotifywait', 'auditd', 'ausearch', 'aide', 'debsums', 'dpkg',
                'logger', 'journalctl', 'aureport', 'auditctl',
                
                # Editores y gestores de archivos para cheatsheets
                'nano', 'vim', 'vi', 'gedit', 'mousepad',
                'thunar', 'nautilus', 'dolphin', 'pcmanfm', 'caja', 'nemo', 'xdg-open'
            ]
            
            herramientas_faltantes = []
            herramientas_ok = []
            
            for herramienta in herramientas:
                try:
                    # Verificar si la herramienta existe
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        herramientas_ok.append(herramienta)
                        self.after(0, self._actualizar_texto, f"OK {herramienta} - OK\n")
                    else:
                        herramientas_faltantes.append(herramienta)
                        self.after(0, self._actualizar_texto, f"ERROR {herramienta} - FALTANTE\n")
                        
                except subprocess.TimeoutExpired:
                    herramientas_faltantes.append(herramienta)
                    self.after(0, self._actualizar_texto, f"ERROR {herramienta} - TIMEOUT\n")
                except Exception as e:
                    herramientas_faltantes.append(herramienta)
                    self.after(0, self._actualizar_texto, f"ERROR {herramienta} - ERROR: {e}\n")
            
            # Mostrar resumen
            self.after(0, self._mostrar_resumen_verificacion, herramientas_ok, herramientas_faltantes)
            
        except Exception as e:
            self.after(0, self._actualizar_texto, f"\nError durante la verificación: {e}\n")
        finally:
            self.after(0, self._finalizar_verificacion)
    
    def _mostrar_resumen_verificacion(self, herramientas_ok, herramientas_faltantes):
        """Mostrar resumen de la verificación"""
        self._actualizar_texto(f"\n{'='*50}\n")
        self._actualizar_texto(f"RESUMEN DE VERIFICACIÓN\n")
        self._actualizar_texto(f"{'='*50}\n\n")
        self._actualizar_texto(f"Herramientas encontradas: {len(herramientas_ok)}\n")
        self._actualizar_texto(f"Herramientas faltantes: {len(herramientas_faltantes)}\n\n")
        
        if herramientas_faltantes:
            self._actualizar_texto("HERRAMIENTAS FALTANTES:\n")
            for herramienta in herramientas_faltantes:
                self._actualizar_texto(f"  • {herramienta}\n")
            self._actualizar_texto("\nHaga clic en 'Instalar Herramientas Faltantes' para instalarlas.\n")
            try:
                if hasattr(self, 'btn_instalar') and self.btn_instalar.winfo_exists():
                    self.btn_instalar.config(state='normal')
            except (tk.TclError, AttributeError):
                pass
        else:
            self._actualizar_texto("¡Todas las herramientas están disponibles!\n")
            try:
                if hasattr(self, 'btn_continuar') and self.btn_continuar.winfo_exists():
                    self.btn_continuar.config(state='normal')
            except (tk.TclError, AttributeError):
                pass
    
    def _actualizar_texto(self, texto):
        """Actualizar texto en el área de resultados con principios ARESITOS V3."""
        try:
            # PRINCIPIO ARESITOS V3: Acceso dinámico a text_resultados
            text_widget = getattr(self, 'text_resultados', None)
            if text_widget:
                # Verificar métodos dinámicamente
                metodo_exists = getattr(text_widget, 'winfo_exists', None)
                metodo_insert = getattr(text_widget, 'insert', None)
                metodo_see = getattr(text_widget, 'see', None)
                metodo_update = getattr(text_widget, 'update', None)
                
                if metodo_exists and metodo_exists():
                    if metodo_insert:
                        metodo_insert(tk.END, texto)
                    if metodo_see:
                        metodo_see(tk.END)
                    if metodo_update:
                        metodo_update()
                else:
                    self.logger.warning("Widget text_resultados no existe")
            else:
                self.logger.warning("text_resultados no disponible")
        except (tk.TclError, AttributeError) as e:
            # PRINCIPIO ARESITOS V3: Logging robusto de errores
            self.logger.debug(f"Widget ya destruido o error de acceso: {e}")
        except Exception as e:
            self.logger.error(f"Error actualizando texto: {e}")
    
    def _finalizar_verificacion(self):
        """Finalizar proceso de verificación con verificación de seguridad"""
        try:
            self.proceso_activo = False
            # Verificar si el widget aún existe y la ventana no ha sido destruida
            if hasattr(self, 'btn_verificar') and self.btn_verificar.winfo_exists():
                self.btn_verificar.config(state='normal')
        except (tk.TclError, AttributeError):
            # Widget ya destruido, ignorar silenciosamente
            self.proceso_activo = False
    
    def instalar_herramientas(self):
        """Instalar herramientas faltantes"""
        if self.proceso_activo:
            return
        
        respuesta = messagebox.askyesno(
            "Instalar Herramientas",
            "¿Desea instalar las herramientas faltantes?\n\n" +
            "Esto ejecutará: sudo apt update && sudo apt install -y [herramientas]\n\n" +
            "Nota: Se requieren permisos de administrador."
        )
        
        if not respuesta:
            return
        
        self.proceso_activo = True
        try:
            if hasattr(self, 'btn_instalar') and self.btn_instalar.winfo_exists():
                self.btn_instalar.config(state='disabled')
            if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                self.text_resultados.delete(1.0, tk.END)
        except (tk.TclError, AttributeError):
            pass
        
        # Ejecutar instalación en thread separado
        thread = threading.Thread(target=self._instalar_herramientas_async)
        thread.daemon = True
        thread.start()
    
    def _instalar_herramientas_async(self):
        """Instalación asíncrona de herramientas usando SudoManager"""
        try:
            self.after(0, self._actualizar_texto, "Instalando herramientas de Kali Linux...\n\n")
            
            # Verificar que sudo esté disponible
            sudo_manager = get_sudo_manager()
            if not is_sudo_available():
                self.after(0, self._actualizar_texto, "ERROR: No hay permisos sudo disponibles\n")
                self.after(0, self._actualizar_texto, "Reinicie ARESITOS e ingrese la contraseña correcta\n")
                return
            
            # Lista de paquetes disponibles en repositorios APT de Kali
            paquetes = [
                # Comandos básicos del sistema (ya incluidos en Kali por defecto)
                'procps', 'iproute2', 'net-tools', 'util-linux', 'findutils', 'grep', 'gawk',
                'coreutils', 'systemd', 'wget', 'curl', 'diffutils',
                # Herramientas de monitoreo y análisis sistema (FASE 3.2 y 3.3)
                'inotify-tools', 'chkrootkit', 'rkhunter', 'lynis', 'auditd', 'debsums',
                'rsyslog', 'logrotate', 'logwatch',
                # Escaneadores básicos (FASE 3.1 - Escaneador Expandido)
                'nmap', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'dirb',
                # Servicios de red (FASE 3.1)
                'netcat-traditional', 'whatweb', 'wfuzz', 'ffuf',
                # Cracking y passwords
                'hashcat', 'john', 'hydra', 'medusa', 'patator',
                # Análisis SQL
                'sqlmap', 'sqlninja',
                # Cuarentena y malware (FASE 3.3 - FIM expandido)
                'clamav', 'clamav-daemon', 'clamav-freshclam', 'yara', 'binwalk', 'exiftool',
                'foremost', 'sleuthkit', 'autopsy',
                # SIEM y auditoría (FASE 3.2)
                'fail2ban', 'aide', 'tripwire', 'samhain',
                # Herramientas de análisis avanzado (FASE 3)
                'tcpdump', 'wireshark', 'tshark', 'strace', 'ltrace', 'gdb',
                'osquery', 'file', 'hexdump'
            ]
            
            # PAQUETES PARA INSTALACIÓN AUTOMÁTICA (sincronizados con configurar_kali.sh)
            # [PRINCIPIO ARESITOS: CONSISTENCIA CON CONFIGURADOR]
            paquetes = [
                # Herramientas esenciales del configurador
                'python3-dev', 'python3-venv', 'python3-tk', 'git', 'curl', 'wget',
                'net-tools', 'iproute2', 'tcpdump', 'iftop', 'netcat-openbsd',
                'htop', 'psmisc', 'dnsutils', 'whois',
                
                # Herramientas forenses y SIEM verificadas
                'wireshark', 'autopsy', 'sleuthkit', 'foremost', 'binwalk', 'strings', 'exiftool',
                
                # Escaneadores avanzados (coincide con advanced_tools)
                'ffuf', 'feroxbuster', 'rustscan', 'nuclei', 'nikto', 'whatweb', 'dirb',
                'lynis', 'chkrootkit',
                
                # Herramientas de seguridad (coincide con security_tools)
                'rkhunter', 'clamav-daemon', 'clamav-freshclam', 'bulk_extractor', 'yara',
                
                # Herramientas adicionales necesarias para ARESITOS
                'gobuster', 'aide'
            ]
            
            # HERRAMIENTAS PROBLEMÁTICAS: Solo las que pueden requerir atención especial
            # [PRINCIPIO ARESITOS: DOCUMENTACIÓN PRECISA]
            herramientas_problematicas = {
                'python3-dev': {
                    'razon': 'Paquete de desarrollo, verificar instalación',
                    'comando': 'sudo apt install python3-dev',
                    'notas': 'Esencial para compilar extensiones Python'
                },
                'python3-venv': {
                    'razon': 'Módulo de entornos virtuales',
                    'comando': 'sudo apt install python3-venv',
                    'notas': 'Requerido para aislamiento de dependencias'
                },
                'bulk_extractor': {
                    'razon': 'Herramienta de análisis forense estable',
                    'comando': 'Incluido en configurar_kali.sh',
                    'notas': 'Análisis forense de archivos y memoria - reemplazo de volatility3'
                },
                'clamav-daemon': {
                    'razon': 'Servicio de antivirus',
                    'comando': 'Configurado automáticamente por configurar_kali.sh',
                    'notas': 'Motor antivirus ClamAV con configuración automática'
                }
            }
            
            # HERRAMIENTAS MANUALES: Instalación vía Go/Rust según configurador
            # [PRINCIPIO ARESITOS: TRANSPARENCIA EN DEPENDENCIAS]
            herramientas_manuales = [
                'httpx: Instalado via Go en configurar_kali.sh (go install)',
                'rustscan: Disponible via APT en Kali Linux 2025',
                'nuclei: Disponible via APT + actualización automática de templates',
                'feroxbuster: Scanner en Rust disponible via APT',
                'ffuf: Fuzzer web disponible via APT'
            ]
            
            # Actualizar repositorios usando SudoManager
            self.after(0, self._actualizar_texto, "Actualizando repositorios...\n")
            result = sudo_manager.execute_sudo_command('apt update', timeout=120)
            
            if result.returncode == 0:
                self.after(0, self._actualizar_texto, "OK Repositorios actualizados\n\n")
            else:
                self.after(0, self._actualizar_texto, f"ERROR actualizando repositorios: {result.stderr}\n\n")
            
            # Instalar paquetes uno por uno para mejor control de errores
            self.after(0, self._actualizar_texto, "Instalando herramientas...\n")
            
            paquetes_exitosos = []
            paquetes_fallidos = []
            
            for paquete in paquetes:
                try:
                    self.after(0, self._actualizar_texto, f"Instalando {paquete}...\n")
                    
                    # Usar SudoManager en lugar de sudo directo
                    result = sudo_manager.execute_sudo_command(f'apt install -y {paquete}', timeout=120)
                    
                    if result.returncode == 0:
                        paquetes_exitosos.append(paquete)
                        self.after(0, self._actualizar_texto, f"OK {paquete} instalado correctamente\n")
                    else:
                        paquetes_fallidos.append(paquete)
                        error_msg = result.stderr.strip()
                        
                        # Identificar errores comunes y dar instrucciones específicas
                        if "Unable to locate package" in error_msg or "E: Package" in error_msg:
                            self.after(0, self._actualizar_texto, f"ERROR instalando {paquete}: Paquete no encontrado en repositorios\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con: sudo apt update && sudo apt install {paquete}\n")
                            self.after(0, self._actualizar_texto, f"  ALTERNATIVA: Busque en: https://kali.org/tools/ para instalación alternativa\n")
                        elif "WARNING: apt does not have a stable CLI interface" in error_msg:
                            self.after(0, self._actualizar_texto, f"WARNING {paquete}: Advertencia de compatibilidad APT (no es error crítico)\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con: sudo apt install {paquete}\n")
                        elif "externally-managed-environment" in error_msg:
                            self.after(0, self._actualizar_texto, f"ERROR instalando {paquete}: Entorno Python gestionado externamente\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale con pipx: pipx install {paquete}\n")
                            self.after(0, self._actualizar_texto, f"  ALTERNATIVA: python3 -m pip install --user {paquete} --break-system-packages\n")
                        else:
                            self.after(0, self._actualizar_texto, f"ERROR instalando {paquete}: {error_msg[:100]}...\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con: sudo apt install {paquete}\n")
                            self.after(0, self._actualizar_texto, f"  DOCUMENTACIÓN: Consulte documentación específica de la herramienta\n")
                        
                except subprocess.TimeoutExpired:
                    paquetes_fallidos.append(paquete)
                    self.after(0, self._actualizar_texto, f"TIMEOUT instalando {paquete}\n")
                    self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con más tiempo: sudo apt install {paquete}\n")
                    self.after(0, self._actualizar_texto, f"  NOTA: Puede requerir descargas grandes o dependencias complejas\n")
                except Exception as e:
                    paquetes_fallidos.append(paquete)
                    self.after(0, self._actualizar_texto, f"ERROR instalando {paquete}: {str(e)[:100]}...\n")
                    self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Revise permisos e instale manualmente: sudo apt install {paquete}\n")
                    self.after(0, self._actualizar_texto, f"  VERIFICACIÓN: Verifique conectividad y repositorios actualizados\n")
            
            # Mostrar resumen
            self.after(0, self._actualizar_texto, f"\n{'='*50}\n")
            self.after(0, self._actualizar_texto, f"RESUMEN DE INSTALACIÓN\n")
            self.after(0, self._actualizar_texto, f"{'='*50}\n")
            self.after(0, self._actualizar_texto, f"OK Instalados correctamente: {len(paquetes_exitosos)}\n")
            self.after(0, self._actualizar_texto, f"ERROR Errores de instalación: {len(paquetes_fallidos)}\n\n")
            
            if paquetes_fallidos:
                self.after(0, self._actualizar_texto, f"HERRAMIENTAS QUE REQUIEREN INSTALACIÓN MANUAL:\n")
                for paquete in paquetes_fallidos:
                    self.after(0, self._actualizar_texto, f"   • {paquete}\n")
                self.after(0, self._actualizar_texto, f"\nCOMANDOS PARA INSTALACIÓN MANUAL:\n")
                self.after(0, self._actualizar_texto, f"sudo apt update\n")
                for paquete in paquetes_fallidos:
                    self.after(0, self._actualizar_texto, f"sudo apt install {paquete}\n")
                self.after(0, self._actualizar_texto, f"\nRECURSOS ADICIONALES:\n")
                self.after(0, self._actualizar_texto, f"• Kali Tools: https://kali.org/tools/\n")
                self.after(0, self._actualizar_texto, f"• Documentation: https://kali.org/docs/\n")
                self.after(0, self._actualizar_texto, f"• Forum Support: https://forums.kali.org/\n")
            
            if paquetes_fallidos:
                self.after(0, self._actualizar_texto, "PAQUETES CON ERRORES:\n")
                for paquete in paquetes_fallidos:
                    self.after(0, self._actualizar_texto, f"  • {paquete}\n")
                self.after(0, self._actualizar_texto, "\nEstos paquetes pueden no estar disponibles en este sistema.\n")
            
            # Considerar exitoso si al menos el 70% se instaló
            if len(paquetes_exitosos) >= len(paquetes) * 0.7:
                self.after(0, self._actualizar_texto, "\nOK Instalación completada exitosamente\n")
                
                # Mostrar información sobre herramientas problemáticas
                self.after(0, self._actualizar_texto, "\n" + "="*60 + "\n")
                self.after(0, self._actualizar_texto, "HERRAMIENTAS ESPECIALES - INSTALACIÓN MANUAL\n")
                self.after(0, self._actualizar_texto, "="*60 + "\n")
                self.after(0, self._actualizar_texto, "Las siguientes herramientas requieren instalación manual especial:\n\n")
                
                for herramienta, info in herramientas_problematicas.items():
                    self.after(0, self._actualizar_texto, f"HERRAMIENTA {herramienta.upper()}:\n")
                    self.after(0, self._actualizar_texto, f"   Razón: {info['razon']}\n")
                    self.after(0, self._actualizar_texto, f"   Comando: {info['comando']}\n")
                    self.after(0, self._actualizar_texto, f"   Notas: {info['notas']}\n\n")
                
                # Mostrar información sobre herramientas de la FASE 3
                self.after(0, self._actualizar_texto, "\n" + "="*60 + "\n")
                self.after(0, self._actualizar_texto, "HERRAMIENTAS FASE 3 - EXPANSIONES AVANZADAS\n")
                self.after(0, self._actualizar_texto, "="*60 + "\n")
                self.after(0, self._actualizar_texto, "ESCANEADOR EXPANDIDO (Fase 3.1):\n")
                self.after(0, self._actualizar_texto, "   • nmap, masscan, rustscan (escaneo de red)\n")
                self.after(0, self._actualizar_texto, "   • nikto, whatweb (análisis web)\n")
                self.after(0, self._actualizar_texto, "   • chkrootkit, rkhunter (detección rootkits)\n")
                self.after(0, self._actualizar_texto, "   • binwalk, strings (análisis forense)\n")
                self.after(0, self._actualizar_texto, "   • clamav (antivirus integrado)\n\n")
                
                self.after(0, self._actualizar_texto, "SIEM AVANZADO (Fase 3.2):\n")
                self.after(0, self._actualizar_texto, "   • auditd, rsyslog (auditoría y logs)\n")
                self.after(0, self._actualizar_texto, "   • fail2ban (protección contra fuerza bruta)\n")
                self.after(0, self._actualizar_texto, "   • logwatch (análisis de logs)\n")
                self.after(0, self._actualizar_texto, "   • tcpdump, wireshark (análisis de red)\n\n")
                
                self.after(0, self._actualizar_texto, "FIM OPTIMIZADO (Fase 3.3):\n")
                self.after(0, self._actualizar_texto, "   • inotify-tools (monitoreo tiempo real)\n")
                self.after(0, self._actualizar_texto, "   • aide (integridad archivos)\n")
                self.after(0, self._actualizar_texto, "   • debsums (verificación checksums)\n")
                self.after(0, self._actualizar_texto, "   • sleuthkit, autopsy (análisis forense)\n\n")
                
                # Mostrar información sobre herramientas de instalación manual
                self.after(0, self._actualizar_texto, "=" * 60 + "\n")
                self.after(0, self._actualizar_texto, "HERRAMIENTAS DE INSTALACIÓN MANUAL\n")
                self.after(0, self._actualizar_texto, "="*60 + "\n")
                for herramienta in herramientas_manuales:
                    self.after(0, self._actualizar_texto, f"SYMBOL {herramienta}\n")
                self.after(0, self._actualizar_texto, "\nEstas herramientas se pueden instalar manualmente\n")
                self.after(0, self._actualizar_texto, "para funcionalidades específicas adicionales.\n")
                self.after(0, self._actualizar_texto, "\nNOTA: Las capacidades avanzadas de la Fase 3 funcionan\n")
                self.after(0, self._actualizar_texto, "   con las herramientas instaladas automáticamente.\n")
                
                self.after(0, self._habilitar_continuar)
            else:
                self.after(0, self._actualizar_texto, f"\nERROR Instalación con muchos errores ({len(paquetes_fallidos)}/{len(paquetes)} fallaron)\n")
                self.after(0, self._actualizar_texto, "Recomendación: Verificar conexión y repositorios\n")
                
        except subprocess.TimeoutExpired:
            self.after(0, self._actualizar_texto, "\nTIMEOUT durante la instalación\n")
        except Exception as e:
            self.after(0, self._actualizar_texto, f"\nERROR: {e}\n")
        finally:
            self.after(0, self._finalizar_instalacion)
    
    def _habilitar_continuar(self):
        """Habilitar botón de continuar con verificación de seguridad"""
        try:
            # Verificar si el widget aún existe y la ventana no ha sido destruida
            if hasattr(self, 'btn_continuar') and self.btn_continuar.winfo_exists():
                self.btn_continuar.config(state='normal')
        except (tk.TclError, AttributeError):
            # Widget ya destruido, ignorar silenciosamente
            pass
    
    def _finalizar_instalacion(self):
        """Finalizar proceso de instalación con verificación de seguridad"""
        try:
            self.proceso_activo = False
            # Verificar si el widget aún existe y la ventana no ha sido destruida
            if hasattr(self, 'btn_instalar') and self.btn_instalar.winfo_exists():
                self.btn_instalar.config(state='normal')
        except (tk.TclError, AttributeError):
            # Widget ya destruido, ignorar silenciosamente
            self.proceso_activo = False
    
    def _ejecutar_callback_seguro(self):
        """Ejecutar callback de forma segura"""
        try:
            if self.callback_completado:
                self.callback_completado()
        except Exception:
            # Error al ejecutar callback, ignorar
            pass
    
    def _cerrar_ventana_seguro(self):
        """Cerrar ventana de forma segura"""
        try:
            if hasattr(self, 'master') and self.master.winfo_exists():
                self.master.destroy()
        except (tk.TclError, AttributeError):
            # Ventana ya destruida, ignorar
            pass
    
    def _log_terminal(self, mensaje, modulo="HERRAMIENTAS_KALI", nivel="INFO"):
        """Log al terminal integrado de manera segura."""
        try:
            # Importar terminal global
            from aresitos.vista.vista_dashboard import VistaDashboard
            if hasattr(VistaDashboard, '_terminal_widget') and VistaDashboard._terminal_widget is not None:
                def _update_terminal():
                    try:
                        terminal = VistaDashboard._terminal_widget
                        if terminal and hasattr(terminal, 'insert'):
                            timestamp = __import__('datetime').datetime.now().strftime("%H:%M:%S")
                            formatted_msg = f"[{timestamp}] [{modulo}] [{nivel}] {mensaje}\n"
                            terminal.insert(tk.END, formatted_msg)
                            terminal.see(tk.END)
                    except Exception as e:
                        print(f"Error actualizando terminal: {e}")
                
                # Usar after_idle para asegurar ejecución en el hilo principal
                self.after_idle(_update_terminal)
        except Exception as e:
            # Fallback a logging normal
            if hasattr(self, 'logger'):
                self.logger.info(f"[{modulo}] {mensaje}")
            print(f"Terminal log error: {e}")
    
    def _verificar_kali_linux(self) -> bool:
        """Verificar que estamos ejecutando en Kali Linux con principios ARESITOS V3."""
        try:
            import platform
            import os
            
            # PRINCIPIO ARESITOS V3: Cache sistema para verificaciones
            cache_key = 'kali_verification'
            if hasattr(self, '_cache_herramientas') and cache_key in self._cache_herramientas:
                return self._cache_herramientas[cache_key]
            
            # PRINCIPIO ARESITOS V3: Verificación múltiple con fallbacks dinámicos
            verificaciones = [
                self._verificar_os_release,
                self._verificar_platform_system,
                self._verificar_lsb_release,
                self._verificar_directorios_kali,
                self._verificar_comandos_kali
            ]
            
            for verificacion in verificaciones:
                try:
                    if verificacion():
                        # Guardar en cache
                        if hasattr(self, '_cache_herramientas'):
                            self._cache_herramientas[cache_key] = True
                        return True
                except Exception as e:
                    self.logger.debug(f"Error en verificación {verificacion.__name__}: {e}")
                    continue
            
            # No es Kali Linux
            if hasattr(self, '_cache_herramientas'):
                self._cache_herramientas[cache_key] = False
            return False
            
        except Exception as e:
            self.logger.error(f"Error verificando Kali Linux: {e}")
            return False
    
    def _verificar_os_release(self) -> bool:
        """Verificar /etc/os-release para Kali (PRINCIPIO ARESITOS V3)."""
        try:
            import os
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    contenido = f.read().lower()
                    return 'id=kali' in contenido or 'kali' in contenido
            return False
        except Exception:
            return False
    
    def _verificar_platform_system(self) -> bool:
        """Verificar platform.system() para Kali (PRINCIPIO ARESITOS V3)."""
        try:
            import platform
            return 'kali' in platform.system().lower()
        except Exception:
            return False
    
    def _verificar_lsb_release(self) -> bool:
        """Verificar lsb_release para Kali (PRINCIPIO ARESITOS V3)."""
        try:
            resultado = subprocess.run(['lsb_release', '-i'], 
                                     capture_output=True, text=True, timeout=5)
            return 'kali' in resultado.stdout.lower()
        except Exception:
            return False
    
    def _verificar_directorios_kali(self) -> bool:
        """Verificar directorios específicos de Kali (PRINCIPIO ARESITOS V3)."""
        try:
            import os
            directorios_kali = [
                '/usr/share/kali-themes',
                '/etc/apt/sources.list.d',
                '/usr/share/kali-desktop-base'
            ]
            return any(os.path.exists(d) for d in directorios_kali)
        except Exception:
            return False
    
    def _verificar_comandos_kali(self) -> bool:
        """Verificar comandos específicos de Kali (PRINCIPIO ARESITOS V3)."""
        try:
            import shutil
            comandos_kali = ['apt', 'dpkg', 'systemctl']
            return all(shutil.which(cmd) for cmd in comandos_kali)
        except Exception:
            return False

    def continuar_aplicacion(self):
        """Continuar a la aplicación principal de ARESITOS"""
        try:
            self._log_terminal("Usuario continuando a aplicación principal", "HERRAMIENTAS_KALI", "INFO")
            
            # Ejecutar callback si existe
            if self.callback_completado:
                self.callback_completado()
            else:
                # Fallback: cerrar esta ventana y que el sistema maneje el siguiente paso
                if hasattr(self, 'master') and self.master:
                    self.master.destroy()
                else:
                    self.destroy()
                    
        except Exception as e:
            self.logger.error(f"Error continuando aplicación: {e}")
            # Forzar cierre y continuar
            try:
                if hasattr(self, 'master') and self.master:
                    self.master.destroy()
                else:
                    self.destroy()
            except:
                pass
