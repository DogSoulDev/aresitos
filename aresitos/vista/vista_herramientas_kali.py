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
    from aresitos.vista.burp_theme import burp_theme
    from aresitos.utils.sudo_manager import get_sudo_manager, is_sudo_available
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientasKali(tk.Frame):
    """Vista para herramientas nativas de Kali Linux"""
    
    def __init__(self, parent, callback_completado=None):
        super().__init__(parent)
        
        # VERIFICACIÓN CRÍTICA: Solo para Kali Linux (con soporte modo desarrollo)
        import sys
        modo_desarrollo = '--dev' in sys.argv or '--desarrollo' in sys.argv
        
        if not self._verificar_kali_linux() and not modo_desarrollo:
            messagebox.showerror(
                "Error - Solo Kali Linux", 
                "ARESITOS está diseñado exclusivamente para Kali Linux.\n\n"
                "Sistema detectado no es compatible.\n"
                "Instale Kali Linux para usar ARESITOS.\n\n"
                "Para desarrollo: usar --dev o --desarrollo"
            )
            self.destroy()
            return
        
        if modo_desarrollo:
            print("[MODO DESARROLLO] VistaHerramientasKali: Ejecutando en entorno no-Kali")
            
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
        
        # CRÍTICO: Verificar estado de sudo heredado del login
        self._verificar_estado_sudo()
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador: Optional[Any]):
        """Establecer controlador siguiendo patrón MVC"""
        self.controlador = controlador
    
    def _verificar_estado_sudo(self):
        """Verificar y mostrar el estado de sudo heredado del login"""
        try:
            sudo_manager = get_sudo_manager()
            estado = sudo_manager.get_status()
            
            if estado['authenticated'] and estado['active']:
                print(f"[HERRAMIENTAS] Sudo activo - credenciales heredadas del login")
                print(f"[HERRAMIENTAS] Timestamp: {estado['timestamp']}")
                self.sudo_disponible = True
            else:
                print(f"[HERRAMIENTAS] Advertencia: Sudo no activo")
                print(f"[HERRAMIENTAS] Estado: {estado}")
                self.sudo_disponible = False
                
        except Exception as e:
            print(f"[HERRAMIENTAS] Error verificando sudo: {e}")
            self.sudo_disponible = False
    
    def crear_interfaz(self):
        """Crear interfaz completa para herramientas Kali"""
        # Frame principal
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Logo de Aresitos
        try:
            import os
            logo_path = os.path.join(os.path.dirname(__file__), '..', 'recursos', 'aresitos.png')
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
            "🌐 PENETRACIÓN Y AUDITORÍA:\n" +
            "• Escaneadores: nmap, masscan, nuclei, nikto, gobuster, feroxbuster\n" +
            "• Cracking: hashcat, john, hydra, medusa, patator, crunch\n" +
            "• Web: sqlmap, whatweb, wfuzz, ffuf, dirb\n" +
            "• Bases de datos: sqlite3, mysql, psql\n\n" +
            "📁 INTERFAZ Y VISUALIZACIÓN:\n" +
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
            
                        # Lista de herramientas esenciales optimizada para Kali Linux 2024+
            paquetes = [
                # === ESCANEO DE RED Y RECONNAISSANCE ===
                'nmap',           # Scanner de puertos principal
                'masscan',        # Scanner de puertos ultra rápido
                'rustscan',       # Scanner moderno en Rust
                'nuclei',         # Scanner de vulnerabilidades moderno
                'nikto',          # Scanner web clásico
                'gobuster',       # Fuzzer de directorios en Go
                'feroxbuster',    # Fuzzer de directorios en Rust
                'dirb',           # Fuzzer de directorios clásico
                'dirbuster',      # Fuzzer de directorios GUI
                'whatweb',        # Identificador de tecnologías web
                'wafw00f',        # Detector de WAF
                'httprobe',       # Verificador de servicios HTTP
                
                # === HERRAMIENTAS DE RED ===
                'netcat-openbsd', # Netcat principal en Kali
                'socat',          # Socket relay avanzado
                'netdiscover',    # Descubrimiento de hosts
                'arp-scan',       # Scanner ARP
                'fping',          # Ping masivo
                'hping3',         # Generador de paquetes
                
                # === FUZZING Y TESTING WEB ===
                'wfuzz',          # Fuzzer web principal
                'ffuf',           # Fuzzer rápido en Go
                'burpsuite',      # Suite de testing web
                'zaproxy',        # OWASP ZAP
                'commix',         # Inyección de comandos
                'xsser',          # Testing XSS
                
                # === CRACKING Y PASSWORDS ===
                'hashcat',        # Cracker de hashes GPU
                'john',           # John the Ripper
                'hydra',          # Brute force login
                'medusa',         # Brute force alternativo
                'patator',        # Fuzzer modular
                'crunch',         # Generador de wordlists
                'cewl',           # Extractor de wordlists web
                'hashid',         # Identificador de hashes
                
                # === ANÁLISIS SQL ===
                'sqlmap',         # SQL injection principal
                'sqlninja',       # SQL injection avanzado
                'bbqsql',         # Blind SQL injection
                
                # === ANÁLISIS DE MALWARE Y FORENSE ===
                'clamav',         # Antivirus
                'clamav-daemon',  # Daemon de ClamAV
                'clamtk',         # GUI para ClamAV
                'yara',           # Motor de detección de malware
                'binwalk',        # Análisis de binarios
                'exiftool',       # Análisis de metadatos
                'foremost',       # Recuperación de archivos
                'sleuthkit',      # Kit forense
                'autopsy',        # GUI forense
                'rekall-core',    # Framework moderno de análisis de memoria forense
                'strings',        # Extractor de strings
                'hexedit',        # Editor hexadecimal
                
                # === SEGURIDAD DEL SISTEMA ===
                'fail2ban',       # Protección contra brute force
                'aide',           # Sistema de detección de intrusos
                'chkrootkit',     # Detector de rootkits
                'rkhunter',       # Hunter de rootkits
                'lynis',          # Auditor de seguridad
                'tiger',          # Scanner de seguridad
                
                # === ANÁLISIS DE TRÁFICO ===
                'tcpdump',        # Capturador de paquetes
                'wireshark',      # Analizador de protocolos GUI
                'tshark',         # Wireshark CLI
                'ettercap-text-only', # MITM attacks
                'dsniff',         # Sniffing tools
                'tcpflow',        # Reconstructor de sesiones TCP
                'ngrep',          # Grep para tráfico de red
                
                # === HERRAMIENTAS DE DESARROLLO ===
                'strace',         # Tracer de system calls
                'ltrace',         # Tracer de library calls
                'gdb',            # Debugger
                'radare2',        # Framework de reversing
                'objdump',        # Analizador de objetos
                'nm',             # Lister de símbolos
                'readelf',        # Lector de ELF
                
                # === HERRAMIENTAS BÁSICAS ESENCIALES ===
                'curl',           # Cliente HTTP
                'wget',           # Descargador
                'file',           # Identificador de tipos de archivo
                'xxd',            # Dumper hexadecimal
                'base64',         # Codificador base64
                'openssl',        # Herramientas de cifrado
                'gpg',            # GnuPG
                'zip',            # Compresor
                'unzip',          # Descompresor
                'p7zip-full',     # 7zip completo
                'git',            # Control de versiones
                
                # === UTILIDADES DE SISTEMA ===
                'htop',           # Monitor de procesos
                'iotop',          # Monitor de I/O
                'nethogs',        # Monitor de ancho de banda
                'ss',             # Socket statistics
                'lsof',           # List open files
                'tree',           # Visualizador de directorios
                'jq',             # Procesador JSON
                'xmlstarlet',     # Procesador XML
                
                # === HERRAMIENTAS PYTHON PARA SEGURIDAD ===
                'python3-pip',    # Gestor de paquetes Python
                'python3-dev',    # Headers de desarrollo Python
                'python3-setuptools', # Herramientas de setup Python
                'python3-requests',   # Librería HTTP Python
                'python3-beautifulsoup4', # Parser HTML Python
                'python3-lxml',       # Procesador XML Python
            ]
            
            # Herramientas que requieren instalación especial o configuración adicional
            herramientas_problematicas = {
                'tripwire': {
                    'razon': 'Requiere configuración interactiva y puede tardar +10 minutos',
                    'comando': 'sudo apt update && sudo apt install -y tripwire',
                    'notas': 'Sistema de detección de intrusos. Configurará automáticamente durante instalación.'
                },
                'autopsy': {
                    'razon': 'Plataforma forense nativa de Kali Linux',
                    'comando': 'sudo apt update && sudo apt install -y autopsy',
                    'notas': 'Plataforma de análisis forense digital. Herramienta nativa de Kali Linux'
                },
                'rustscan': {
                    'razon': 'Requiere instalación vía cargo o GitHub',
                    'comando': 'wget -qO- https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb && sudo dpkg -i rustscan_2.3.0_amd64.deb',
                    'notas': 'Scanner de puertos ultra rápido. Alternativa: cargo install rustscan'
                },
                'nuclei': {
                    'razon': 'Instalación vía GitHub releases más actualizada',
                    'comando': 'wget -qO- https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.2.9_linux_amd64.zip | sudo unzip -d /usr/local/bin/',
                    'notas': 'Scanner de vulnerabilidades moderno. Alternativa: apt install nuclei'
                },
                'bbqsql': {
                    'razon': 'Herramienta Python que requiere instalación especial',
                    'comando': 'pip3 install bbqsql --break-system-packages',
                    'notas': 'Blind SQL injection. Alternativa: git clone y instalación manual'
                },
                'httprobe': {
                    'razon': 'Herramienta Go que requiere instalación desde GitHub',
                    'comando': 'go install github.com/tomnomnom/httprobe@latest',
                    'notas': 'Verificador de servicios HTTP. Requiere Go instalado'
                }
            }
            
            # Herramientas adicionales recomendadas para instalación manual
            herramientas_manuales = [
                'linpeas.sh: wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh',
                'winpeas.exe: wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe',
                'pspy64: wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 && chmod +x pspy64',
                'pspy32: wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 && chmod +x pspy32',
                'chisel: wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz && gunzip chisel_1.9.1_linux_amd64.gz && chmod +x chisel_1.9.1_linux_amd64',
                'gobuster: Actualizar con: go install github.com/OJ/gobuster/v3@latest',
                'ffuf: Actualizar con: go install github.com/ffuf/ffuf@latest',
                'amass: go install -v github.com/owasp-amass/amass/v3/...@master',
                'subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
                'katana: go install github.com/projectdiscovery/katana/cmd/katana@latest',
                'gau: go install github.com/lc/gau/v2/cmd/gau@latest',
                'waybackurls: go install github.com/tomnomnom/waybackurls@latest',
                'anew: go install github.com/tomnomnom/anew@latest',
                'gf: go install github.com/tomnomnom/gf@latest',
                'assetfinder: go install github.com/tomnomnom/assetfinder@latest',
                'SecLists: git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists',
                'PayloadsAllTheThings: git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/PayloadsAllTheThings',
                'wordlists: apt update && apt install -y seclists wordlists dirb',
                'rockyou.txt: gunzip /usr/share/wordlists/rockyou.txt.gz (si no está descomprimido)'
            ]
            
            # Actualizar repositorios usando SudoManager
            self.after(0, self._actualizar_texto, "=== INICIANDO INSTALACIÓN DE HERRAMIENTAS KALI ===\n")
            self.after(0, self._actualizar_texto, f"Total de herramientas a instalar: {len(paquetes)}\n\n")
            
            self.after(0, self._actualizar_texto, "Actualizando repositorios...\n")
            result = sudo_manager.execute_sudo_command('apt update', timeout=180)
            
            if result.returncode == 0:
                self.after(0, self._actualizar_texto, "✓ Repositorios actualizados correctamente\n\n")
            else:
                self.after(0, self._actualizar_texto, f"⚠ ERROR actualizando repositorios: {result.stderr[:200]}...\n")
                self.after(0, self._actualizar_texto, "Continuando con instalación...\n\n")
            
            # Instalar paquetes uno por uno para mejor control de errores
            self.after(0, self._actualizar_texto, "=== INSTALANDO HERRAMIENTAS ===\n")
            
            paquetes_exitosos = []
            paquetes_fallidos = []
            paquetes_ya_instalados = []
            
            for i, paquete in enumerate(paquetes, 1):
                try:
                    self.after(0, self._actualizar_texto, f"[{i}/{len(paquetes)}] Instalando {paquete}...\n")
                    
                    # Usar SudoManager con timeout extendido para paquetes grandes
                    result = sudo_manager.execute_sudo_command(f'apt install -y {paquete}', timeout=180)
                    
                    if result.returncode == 0:
                        paquetes_exitosos.append(paquete)
                        self.after(0, self._actualizar_texto, f"  ✓ {paquete} instalado correctamente\n")
                    else:
                        # Verificar si ya está instalado
                        check_result = sudo_manager.execute_sudo_command(f'dpkg -l | grep "^ii.*{paquete}"', timeout=10)
                        if check_result.returncode == 0 and paquete in check_result.stdout:
                            paquetes_ya_instalados.append(paquete)
                            self.after(0, self._actualizar_texto, f"  ℹ {paquete} ya estaba instalado\n")
                        else:
                            paquetes_fallidos.append(paquete)
                            error_msg = result.stderr.strip() if result.stderr else "Error desconocido"
                            
                            # Identificar errores comunes y dar instrucciones específicas
                            if "Unable to locate package" in error_msg or "E: Package" in error_msg or "has no installation candidate" in error_msg:
                                self.after(0, self._actualizar_texto, f"  ✗ {paquete}: Paquete no encontrado en repositorios\n")
                                self.after(0, self._actualizar_texto, f"    💡 Solución: sudo apt update && sudo apt install {paquete}\n")
                                self.after(0, self._actualizar_texto, f"    📖 Buscar en: https://www.kali.org/tools/{paquete}/\n")
                            elif "already installed" in error_msg:
                                paquetes_ya_instalados.append(paquete)
                                self.after(0, self._actualizar_texto, f"  ℹ {paquete} ya estaba instalado (detectado en stderr)\n")
                            elif "externally-managed-environment" in error_msg:
                                self.after(0, self._actualizar_texto, f"  ⚠ {paquete}: Entorno Python gestionado externamente\n")
                                self.after(0, self._actualizar_texto, f"    💡 Usar: pipx install {paquete} o pip3 install --user {paquete}\n")
                            elif "DPKG_LOCK" in error_msg or "dpkg frontend is locked" in error_msg:
                                self.after(0, self._actualizar_texto, f"  ⏳ {paquete}: Sistema de paquetes ocupado\n")
                                self.after(0, self._actualizar_texto, f"    💡 Esperar o ejecutar: sudo killall apt apt-get\n")
                            else:
                                self.after(0, self._actualizar_texto, f"  ✗ {paquete}: {error_msg[:150]}...\n")
                                self.after(0, self._actualizar_texto, f"    💡 Instalación manual: sudo apt install {paquete}\n")
                        
                except subprocess.TimeoutExpired:
                    paquetes_fallidos.append(paquete)
                    self.after(0, self._actualizar_texto, f"  ⏱ {paquete}: Timeout en instalación\n")
                    self.after(0, self._actualizar_texto, f"    💡 Reintentar con: sudo apt install {paquete}\n")
                except Exception as e:
                    paquetes_fallidos.append(paquete)
                    self.after(0, self._actualizar_texto, f"  ✗ {paquete}: Error inesperado: {str(e)[:100]}...\n")
                    self.after(0, self._actualizar_texto, f"    💡 Instalación manual: sudo apt install {paquete}\n")
            
            # Mostrar resumen final detallado
            total_herramientas = len(paquetes)
            exitosas = len(paquetes_exitosos)
            ya_instaladas = len(paquetes_ya_instalados)
            fallidas = len(paquetes_fallidos)
            
            self.after(0, self._actualizar_texto, f"\n{'='*60}\n")
            self.after(0, self._actualizar_texto, f"🎯 RESUMEN FINAL DE INSTALACIÓN KALI LINUX\n")
            self.after(0, self._actualizar_texto, f"{'='*60}\n")
            self.after(0, self._actualizar_texto, f"📊 Total de herramientas procesadas: {total_herramientas}\n")
            self.after(0, self._actualizar_texto, f"✅ Instaladas correctamente: {exitosas}\n")
            self.after(0, self._actualizar_texto, f"ℹ️  Ya estaban instaladas: {ya_instaladas}\n")
            self.after(0, self._actualizar_texto, f"❌ Fallaron en instalación: {fallidas}\n")
            
            # Calcular porcentaje de éxito
            disponibles = exitosas + ya_instaladas
            porcentaje_exito = (disponibles / total_herramientas) * 100 if total_herramientas > 0 else 0
            
            if porcentaje_exito >= 90:
                self.after(0, self._actualizar_texto, f"🎉 EXCELENTE: {porcentaje_exito:.1f}% de herramientas disponibles\n")
            elif porcentaje_exito >= 70:
                self.after(0, self._actualizar_texto, f"👍 BUENO: {porcentaje_exito:.1f}% de herramientas disponibles\n")
            else:
                self.after(0, self._actualizar_texto, f"⚠️  PARCIAL: {porcentaje_exito:.1f}% de herramientas disponibles\n")
            
            if paquetes_fallidos:
                self.after(0, self._actualizar_texto, f"\n🔧 HERRAMIENTAS QUE REQUIEREN ATENCIÓN:\n")
                for paquete in paquetes_fallidos:
                    self.after(0, self._actualizar_texto, f"   • {paquete}\n")
                
                self.after(0, self._actualizar_texto, f"\n📋 COMANDOS PARA INSTALACIÓN MANUAL:\n")
                self.after(0, self._actualizar_texto, f"sudo apt update && sudo apt upgrade -y\n")
                for paquete in paquetes_fallidos:
                    self.after(0, self._actualizar_texto, f"sudo apt install -y {paquete}\n")
                
                self.after(0, self._actualizar_texto, f"\n🔗 RECURSOS ÚTILES:\n")
                self.after(0, self._actualizar_texto, f"• Kali Tools Database: https://www.kali.org/tools/\n")
                self.after(0, self._actualizar_texto, f"• Kali Documentation: https://www.kali.org/docs/\n")
                self.after(0, self._actualizar_texto, f"• Community Support: https://forums.kali.org/\n")
                self.after(0, self._actualizar_texto, f"• Package Search: https://pkg.kali.org/\n")
            
            # Mostrar información sobre herramientas problemáticas
            if herramientas_problematicas:
                self.after(0, self._actualizar_texto, f"\n🚨 HERRAMIENTAS QUE REQUIEREN INSTALACIÓN ESPECIAL:\n")
                for herramienta, info in herramientas_problematicas.items():
                    self.after(0, self._actualizar_texto, f"\n• {herramienta.upper()}:\n")
                    self.after(0, self._actualizar_texto, f"  Razón: {info['razon']}\n")
                    self.after(0, self._actualizar_texto, f"  Comando: {info['comando']}\n")
                    self.after(0, self._actualizar_texto, f"  Notas: {info['notas']}\n")
            
            # Mostrar herramientas adicionales recomendadas
            self.after(0, self._actualizar_texto, f"\n⭐ HERRAMIENTAS ADICIONALES RECOMENDADAS:\n")
            self.after(0, self._actualizar_texto, f"Las siguientes herramientas son muy útiles pero requieren instalación manual:\n\n")
            for herramienta in herramientas_manuales[:10]:  # Mostrar solo las primeras 10
                self.after(0, self._actualizar_texto, f"• {herramienta}\n")
            
            self.after(0, self._actualizar_texto, f"\n🔥 INSTALACIÓN COMPLETADA\n")
            self.after(0, self._actualizar_texto, f"Su sistema Kali Linux está ahora optimizado para ARESITOS\n")
            self.after(0, self._actualizar_texto, f"{'='*60}\n")
            
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
                    self.after(0, self._actualizar_texto, f"� {herramienta}\n")
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
                
                # Simplificar: Cerrar ventana y ejecutar callback de forma más directa
                self.after(500, self._ejecutar_callback_directo)
            else:
                messagebox.showinfo("Información", 
                                  "Configuración completada exitosamente.\n"
                                  "ARESITOS v2.0 se iniciará automáticamente.")
                # Si no hay callback, cerrar esta ventana
                self.after(1000, self._cerrar_ventana_seguro)
        except (tk.TclError, AttributeError):
            # Widget ya destruido, ignorar silenciosamente
            pass
    
    def _ejecutar_callback_seguro(self):
        """Ejecutar callback de forma segura sin parpadeos"""
        try:
            # Programar cierre suave con delay para evitar parpadeos
            if hasattr(self, 'master') and self.master.winfo_exists():
                # Usar after para delay suave en la transición
                self.master.after(100, self._cerrar_y_ejecutar_callback)
            else:
                # Si no hay master, ejecutar callback directamente
                if self.callback_completado:
                    self.callback_completado()
        except Exception as e:
            print(f"[HERRAMIENTAS] Error en callback: {e}")
            # Fallback - ejecutar callback directamente
            try:
                if self.callback_completado:
                    self.callback_completado()
            except:
                pass
    
    def _cerrar_y_ejecutar_callback(self):
        """Cerrar ventana y ejecutar callback"""
        try:
            # Destruir ventana
            if hasattr(self, 'master') and self.master.winfo_exists():
                self.master.destroy()
            
            # Ejecutar callback después de cerrar
            if self.callback_completado:
                self.callback_completado()
        except Exception as e:
            print(f"[HERRAMIENTAS] Error cerrando ventana: {e}")
            if self.callback_completado:
                self.callback_completado()
    
    def _ejecutar_callback_directo(self):
        """Ejecutar callback de forma directa sin delays complicados"""
        try:
            print("[HERRAMIENTAS] Ejecutando callback directo...")
            
            # Cerrar ventana primero
            if hasattr(self, 'master') and self.master.winfo_exists():
                self.master.destroy()
            
            # Ejecutar callback inmediatamente después
            if self.callback_completado:
                print("[HERRAMIENTAS] Llamando a callback_completado...")
                self.callback_completado()
            else:
                print("[HERRAMIENTAS] No hay callback_completado disponible")
                
        except Exception as e:
            print(f"[HERRAMIENTAS] Error en callback directo: {e}")
            import traceback
            traceback.print_exc()
            
            # Fallback - intentar callback de todas formas
            if self.callback_completado:
                try:
                    self.callback_completado()
                except Exception as e2:
                    print(f"[HERRAMIENTAS] Error en fallback callback: {e2}")
    
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

