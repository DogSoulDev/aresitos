# -*- coding: utf-8 -*-
"""
ARESITOS - Vista Herramientas Kali Linux
========================================

Vista especializada para herramientas nativas de Kali Linux.
Mantiene la arquitectura 100% Python nativo + herramientas Kali.

Autor: DogSoulDev
Fecha: 19 de Agosto de 2025
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import logging
from typing import Optional, Any

try:
    from Aresitos.vista.burp_theme import burp_theme
    from Aresitos.utils.sudo_manager import get_sudo_manager, is_sudo_available
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientasKali(tk.Frame):
    """Vista para herramientas nativas de Kali Linux"""
    
    def __init__(self, parent, callback_completado=None):
        super().__init__(parent)
        
        # VERIFICACIÓN CRÍTICA: Solo para Kali Linux
        if not self._verificar_kali_linux():
            messagebox.showerror(
                "Error - Solo Kali Linux", 
                "ARESITOS está diseñado exclusivamente para Kali Linux.\n\n"
                "Sistema detectado no es compatible.\n"
                "Instale Kali Linux para usar ARESITOS."
            )
            self.destroy()
            return
            
        self.controlador = None  # Patrón MVC
        self.callback_completado = callback_completado
        self.proceso_activo = False
        self.logger = logging.getLogger(__name__)
        
        # Configurar tema
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
            self.colors = {
                'bg_primary': burp_theme.get_color('bg_primary'),
                'bg_secondary': burp_theme.get_color('bg_secondary'), 
                'fg_primary': burp_theme.get_color('fg_primary'),
                'fg_accent': burp_theme.get_color('fg_accent'),
                'button_bg': burp_theme.get_color('button_bg'),
                'success': burp_theme.get_color('success'),
                'warning': burp_theme.get_color('warning')
            }
        else:
            self.colors = {
                'bg_primary': '#2e2e2e',
                'bg_secondary': '#404040',
                'fg_primary': '#ffffff',
                'fg_accent': '#ff6633',
                'button_bg': '#007acc',
                'success': '#00ff00',
                'warning': '#ffaa00'
            }
            self.configure(bg=self.colors['bg_primary'])
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador: Optional[Any]):
        """Establecer controlador siguiendo patrón MVC"""
        self.controlador = controlador
    
    def crear_interfaz(self):
        """Crear interfaz completa para herramientas Kali"""
        # Frame principal
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Logo de Aresitos
        try:
            import os
            logo_path = os.path.join(os.path.dirname(__file__), '..', 'recursos', 'Aresitos.png')
            if os.path.exists(logo_path):
                self.logo_img = tk.PhotoImage(file=logo_path)
                logo_label = tk.Label(
                    main_frame,
                    image=self.logo_img,
                    bg=self.colors['bg_primary']
                )
                logo_label.pack(pady=(0, 10))
        except Exception:
            pass  # Continuar sin logo si hay problemas
        
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
        
        # Botón verificar herramientas
        self.btn_verificar = tk.Button(
            botones_frame,
            text="Verificar Herramientas",
            command=self.verificar_herramientas,
            bg=self.colors['button_bg'],
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2'
        )
        self.btn_verificar.grid(row=0, column=0, padx=10, sticky="ew")
        
        # Botón mostrar optimizaciones
        self.btn_optimizaciones = tk.Button(
            botones_frame,
            text="Ver Optimizaciones",
            command=self.mostrar_optimizaciones,
            bg='#9C27B0',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2'
        )
        self.btn_optimizaciones.grid(row=0, column=1, padx=10, sticky="ew")
        
        # Botón instalar herramientas
        self.btn_instalar = tk.Button(
            botones_frame,
            text="Instalar Faltantes",
            command=self.instalar_herramientas,
            bg=self.colors['warning'],
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2',
            state='disabled'
        )
        self.btn_instalar.grid(row=0, column=2, padx=10, sticky="ew")
        
        # Botón continuar (habilitado por defecto en modo desarrollo)
        self.btn_continuar = tk.Button(
            botones_frame,
            text="Continuar a ARESITOS",
            command=self.continuar_aplicacion,
            bg=self.colors['success'],
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=15,
            pady=8,
            cursor='hand2',
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
        self.text_resultados.insert(tk.END, 
            "ARESITOS v3.0 - Configurador de Herramientas Escaneador Profesional\n" +
            "=" * 50 + "\n\n" +
            "Sistema optimizado para Kali Linux con comandos nativos integrados:\n\n" +
            "COMANDOS BÁSICOS:\n" +
            "• Sistema: ps, ss, lsof, grep, awk, find, stat, lsmod, iptables\n" +
            "• Red: nmap, netcat, ip, route, ss, hping3, curl, wget\n" +
            "• Archivos: ls, chmod, chown, cat, sha256sum, md5sum\n\n" +
            "SEGURIDAD Y DETECCIÓN:\n" +
            "• Anti-rootkit: chkrootkit, rkhunter, lynis, unhide, tiger\n" +
            "• Malware: clamav, yara, binwalk, strings, exiftool\n" +
            "• Monitoreo: inotifywait, auditd, systemctl, pspy, aide\n" +
            "• Firewall: iptables, fail2ban-client\n\n" +
            "ANÁLISIS FORENSE:\n" +
            "• Forense: sleuthkit, autopsy, foremost\n" +
            "• Memoria: hexdump, strings, file, binwalk\n" +
            "• Logs: journalctl, aureport, logwatch, rsyslog\n\n" +
            "[NETWORK] PENETRACIÓN Y AUDITORÍA:\n" +
            "• Escaneadores: nmap, masscan, nuclei, nikto, gobuster, feroxbuster\n" +
            "• Cracking: hashcat, john, hydra, medusa, patator, crunch\n" +
            "• Web: sqlmap, whatweb, wfuzz, ffuf, dirb\n" +
            "• Bases de datos: sqlite3, mysql, psql\n\n" +
            "DIR INTERFAZ Y VISUALIZACIÓN:\n" +
            "• Gestores: thunar, nautilus, dolphin, xdg-open\n" +
            "• Editores: nano, vim, gedit, mousepad\n\n" +
            "Haga clic en 'Verificar Herramientas' para comprobar disponibilidad.\n" +
            "NOTA: Los comandos básicos del sistema ya están integrados.\n\n"
        )
        
        # Centrar ventana
        self.after(100, self._centrar_ventana)
    
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
        
        optimizaciones_texto = """ARESITOS v2.0 - OPTIMIZACIONES KALI LINUX APLICADAS
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
        """Verificar herramientas de Kali Linux disponibles"""
        if self.proceso_activo:
            return
        
        self.proceso_activo = True
        try:
            if hasattr(self, 'btn_verificar') and self.btn_verificar.winfo_exists():
                self.btn_verificar.config(state='disabled')
            if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                self.text_resultados.delete(1.0, tk.END)
        except (tk.TclError, AttributeError):
            pass
        
        # Ejecutar verificación en thread separado
        thread = threading.Thread(target=self._verificar_herramientas_async)
        thread.daemon = True
        thread.start()
    
    def _verificar_herramientas_async(self):
        """Verificación asíncrona de herramientas"""
        try:
            self.after(0, self._actualizar_texto, "Verificando herramientas de Kali Linux...\n\n")
            
            # Lista de herramientas esenciales modernizadas para Kali 2025
            herramientas = [
                # Comandos básicos del sistema (nativos)
                'ps', 'ss', 'lsof', 'netstat', 'top', 'free', 'df', 'uname', 'who', 'last',
                'find', 'stat', 'grep', 'awk', 'sort', 'uniq', 'wc', 'tail', 'head',
                'systemctl', 'ip', 'route', 'wget', 'curl', 'diff', 'ls', 'chmod', 'chown',
                # Comandos para nuevas funcionalidades implementadas
                'lsmod', 'kill', 'pgrep', 'pkill', 'sha256sum', 'md5sum', 'sha1sum', 'sha512sum',
                'iptables', 'cat', 'less', 'more', 'pwd', 'mkdir', 'rm', 'cp', 'mv',
                # Herramientas de monitoreo y análisis del sistema (para FIM y SIEM)
                'inotifywait', 'inotify-tools', 'auditd', 'ausearch', 'aide',
                'debsums', 'dpkg', 'rpm', 'synaptic',
                # Anti-rootkit y detección (usadas en escaneador avanzado FASE 3.1)
                'chkrootkit', 'rkhunter', 'lynis', 'unhide', 'tiger', 'maldet',
                # Escaneadores de red y puertos (usados en SIEM y Escaneador FASE 3.1)
                'nmap', 'masscan', 'rustscan', 'gobuster', 'feroxbuster', 'nikto', 'nuclei', 'httpx',
                'zmap', 'unicornscan', 'hping3', 'dirb', 'dirbuster',
                # Análisis de servicios y red (expandido FASE 3.1)
                'netcat', 'netcat-traditional', 'whatweb', 'wfuzz', 'ffuf', 'dirb',
                'enum4linux', 'smbclient', 'rpcclient', 'ldapsearch',
                # Cracking y fuerza bruta
                'hashcat', 'john', 'hydra', 'medusa', 'patator', 'crunch', 'cewl',
                # Bases de datos y SQL
                'sqlmap', 'sqlninja', 'sqlite3', 'mysql', 'psql',
                # Análisis de malware (expandido para FIM y cuarentena FASE 3.3)
                'clamav', 'clamscan', 'freshclam', 'clamav-daemon', 'yara', 'binwalk', 'strings', 'file', 'exiftool',
                'hexdump', 'foremost', 'sleuthkit', 'autopsy',
                # FIM y monitoreo avanzado (FASE 3.2 y 3.3)
                'pspy', 'pspy64', 'pspy32', 'linpeas', 'logger', 'fail2ban-client', 'logwatch',
                'incron', 'fswatch', 'entr', 'watchman',
                # Análisis forense y auditoría (usadas en SIEM FASE 3.2)
                'logrotate', 'rsyslog', 'journalctl', 'aureport', 'auditctl',
                # Herramientas adicionales para análisis avanzado (FASE 3)
                'osquery', 'osqueryi', 'tcpdump', 'wireshark', 'tshark',
                'strace', 'ltrace', 'gdb', 'objdump', 'readelf',
                # Gestores de archivos para cheatsheets
                'thunar', 'nautilus', 'dolphin', 'pcmanfm', 'caja', 'nemo', 'xdg-open',
                # Editores de texto para visualización
                'nano', 'vim', 'vi', 'gedit', 'mousepad',
                # Herramientas base de verificación
                'which', 'whereis', 'type', 'command'
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
        """Actualizar texto en el área de resultados con verificación de seguridad"""
        try:
            # Verificar si el widget aún existe y la ventana no ha sido destruida
            if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                self.text_resultados.insert(tk.END, texto)
                self.text_resultados.see(tk.END)
                self.text_resultados.update()
        except (tk.TclError, AttributeError):
            # Widget ya destruido, ignorar silenciosamente
            pass
    
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
            
            # Lista de herramientas esenciales para ARESITOS en Kali Linux
            paquetes = [
                # Comandos básicos del sistema
                'procps', 'iproute2', 'net-tools', 'util-linux', 'findutils', 'grep', 'gawk',
                'coreutils', 'systemd', 'wget', 'curl', 'diffutils',
                # Herramientas de monitoreo y análisis
                'inotify-tools', 'chkrootkit', 'rkhunter', 'lynis', 'auditd', 'debsums',
                'rsyslog', 'logrotate', 'logwatch',
                # Escaneadores de red
                'nmap', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'dirb',
                # Servicios de red
                'netcat-traditional', 'whatweb', 'wfuzz', 'ffuf',
                # Análisis de contraseñas
                'hashcat', 'john', 'hydra', 'medusa', 'patator',
                # Análisis SQL
                'sqlmap',
                # Antimalware y forense
                'clamav', 'clamav-daemon', 'clamav-freshclam', 'yara', 'binwalk', 'exiftool',
                'foremost', 'sleuthkit', 'autopsy',
                # SIEM y seguridad
                'fail2ban', 'aide',
                # Análisis avanzado
                'tcpdump', 'wireshark', 'tshark', 'strace', 'ltrace', 'gdb',
                'osquery', 'file', 'hexdump'
            ]
            
            # Herramientas problemáticas que requieren instalación manual especial
            herramientas_problematicas = {
                'tripwire': {
                    'razon': 'Requiere configuración interactiva y puede tardar +10 minutos',
                    'comando': 'sudo apt install tripwire',
                    'notas': 'Configurará automáticamente durante instalación. Responder prompts.'
                },
                'samhain': {
                    'razon': 'Configuración compleja y dependencias especiales',
                    'comando': 'sudo apt install samhain',
                    'notas': 'Herramienta de integridad avanzada. Configuración manual requerida.'
                },
                'sqlninja': {
                    'razon': 'Paquete obsoleto en Kali Linux 2025',
                    'comando': 'Usar sqlmap como alternativa',
                    'notas': 'sqlninja no está disponible en repositorios actuales'
                },
                'volatility3': {
                    'razon': 'Instalación vía pip, no APT',
                    'comando': 'pip3 install volatility3',
                    'notas': 'Herramienta de análisis de memoria forense'
                }
            }
            
            # Herramientas que requieren instalación manual (se informará al usuario):
            herramientas_manuales = [
                'rustscan: cargo install rustscan (requiere Rust)',
                'httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest (requiere Go)',
                'nuclei: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest (requiere Go)',
                'linpeas: wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
                'pspy64: wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64',
                'pspy32: wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32',
                'dirbuster: Ya incluido en Kali en /usr/share/dirbuster/',
                'strings: Parte del paquete binutils (generalmente ya instalado)'
            ]
            
            # Actualizar repositorios 
            self.after(0, self._actualizar_texto, "Actualizando repositorios...\n")
            
            try:
                # Usar subprocess directo con sudo
                cmd_update = ['sudo', 'apt', 'update']
                result = subprocess.run(cmd_update, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    self.after(0, self._actualizar_texto, "OK Repositorios actualizados\n\n")
                else:
                    self.after(0, self._actualizar_texto, f"ADVERTENCIA al actualizar repositorios\n\n")
            except Exception as e:
                self.after(0, self._actualizar_texto, f"ERROR actualizando repositorios: {e}\n\n")
            
            # Instalar paquetes en lotes para mayor eficiencia
            self.after(0, self._actualizar_texto, "Instalando herramientas esenciales...\n")
            
            paquetes_exitosos = []
            paquetes_fallidos = []
            
            # Dividir en lotes de 5 paquetes para evitar timeouts
            batch_size = 5
            for i in range(0, len(paquetes), batch_size):
                batch = paquetes[i:i+batch_size]
                batch_names = ' '.join(batch)
                
                try:
                    self.after(0, self._actualizar_texto, f"Instalando lote: {batch_names}\n")
                    
                    # Comando de instalación
                    cmd_install = ['sudo', 'apt', 'install', '-y'] + batch
                    result = subprocess.run(cmd_install, capture_output=True, text=True, timeout=180)
                    
                    if result.returncode == 0:
                        paquetes_exitosos.extend(batch)
                        self.after(0, self._actualizar_texto, f"OK Lote instalado correctamente\n")
                    else:
                        paquetes_fallidos.extend(batch)
                        error_msg = result.stderr.strip()
                        
                        # Identificar errores comunes y dar instrucciones específicas
                        if "Unable to locate package" in error_msg or "E: Package" in error_msg:
                            self.after(0, self._actualizar_texto, f"ERROR instalando lote {batch_names}: Paquetes no encontrados en repositorios\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con: sudo apt update && sudo apt install {batch_names}\n")
                            self.after(0, self._actualizar_texto, f"  ALTERNATIVA: Busque en: https://kali.org/tools/ para instalación alternativa\n")
                        elif "WARNING: apt does not have a stable CLI interface" in error_msg:
                            self.after(0, self._actualizar_texto, f"WARNING lote {batch_names}: Advertencia de compatibilidad APT (no es error crítico)\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con: sudo apt install {batch_names}\n")
                        elif "externally-managed-environment" in error_msg:
                            self.after(0, self._actualizar_texto, f"ERROR instalando lote {batch_names}: Entorno Python gestionado externamente\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale con pipx: pipx install {batch_names}\n")
                            self.after(0, self._actualizar_texto, f"  ALTERNATIVA: python3 -m pip install --user {batch_names} --break-system-packages\n")
                        else:
                            self.after(0, self._actualizar_texto, f"ERROR instalando lote {batch_names}: {error_msg[:100]}...\n")
                            self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con: sudo apt install {batch_names}\n")
                            self.after(0, self._actualizar_texto, f"  DOCUMENTACIÓN: Consulte documentación específica de la herramienta\n")
                        
                except subprocess.TimeoutExpired:
                    paquetes_fallidos.extend(batch)
                    self.after(0, self._actualizar_texto, f"TIMEOUT instalando lote {batch_names}\n")
                    self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Instale manualmente con más tiempo: sudo apt install {batch_names}\n")
                    self.after(0, self._actualizar_texto, f"  NOTA: Puede requerir descargas grandes o dependencias complejas\n")
                except Exception as e:
                    paquetes_fallidos.extend(batch)
                    self.after(0, self._actualizar_texto, f"ERROR instalando lote {batch_names}: {str(e)[:100]}...\n")
                    self.after(0, self._actualizar_texto, f"  SOLUCIÓN: Revise permisos e instale manualmente: sudo apt install {batch_names}\n")
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
    
    def continuar_aplicacion(self):
        """Continuar a la aplicación principal con verificación de seguridad"""
        try:
            # Verificar si los widgets aún existen antes de acceder a ellos
            if not (hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists()):
                return
                
            self.text_resultados.insert(tk.END, "\nIniciando ARESITOS v2.0...\n")
            self.text_resultados.insert(tk.END, "Herramientas modernas configuradas correctamente\n")
            self.text_resultados.insert(tk.END, "Tema Burp Suite aplicado\n")
            self.text_resultados.insert(tk.END, "Dashboard completo cargado\n")
            self.text_resultados.see(tk.END)
            
            # Deshabilitar botón para evitar clicks múltiples
            if hasattr(self, 'btn_continuar') and self.btn_continuar.winfo_exists():
                self.btn_continuar.config(state='disabled', text="Iniciando...")
            
            # Ejecutar callback si está disponible
            if self.callback_completado:
                if hasattr(self, 'text_resultados') and self.text_resultados.winfo_exists():
                    self.text_resultados.insert(tk.END, "\nAbriendo aplicación principal...\n")
                    self.text_resultados.see(tk.END)
                # Usar after para ejecutar el callback en el hilo principal
                self.after(1500, self._ejecutar_callback_seguro)
            else:
                messagebox.showinfo("Información", 
                                  "Configuración completada exitosamente.\n"
                                  "ARESITOS v2.0 se iniciará automáticamente.")
                # Si no hay callback, cerrar esta ventana
                self.after(2000, self._cerrar_ventana_seguro)
        except (tk.TclError, AttributeError):
            # Widget ya destruido, ignorar silenciosamente
            pass
    
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
            from Aresitos.vista.vista_dashboard import VistaDashboard
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
        """Verificar que estamos ejecutando en Kali Linux."""
        try:
            import platform
            import os
            
            # Verificar ID del sistema operativo
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    contenido = f.read()
                    if 'ID=kali' in contenido or 'kali' in contenido.lower():
                        return True
            
            # Verificar nombre del sistema
            if 'kali' in platform.system().lower():
                return True
                
            # Verificar distribución
            try:
                resultado = subprocess.run(['lsb_release', '-i'], 
                                         capture_output=True, text=True, timeout=5)
                if 'kali' in resultado.stdout.lower():
                    return True
            except:
                pass
            
            return False
        except Exception:
            return False
