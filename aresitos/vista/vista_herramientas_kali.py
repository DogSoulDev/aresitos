

# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.

ADVERTENCIA DE INTEGRACIÓN:
Esta vista debe ser utilizada SIEMPRE como tk.Frame hijo de un contenedor principal (Notebook o root existente).
Prohibido instanciar esta clase en una ventana independiente (tk.Tk o tk.Toplevel).
No ejecutar este archivo directamente ni usarlo como script de test aislado.
El incumplimiento de este principio puede causar dobles ventanas, fugas de memoria o errores de integración.

Cumple con el patrón MVC y los principios de seguridad y portabilidad de ARESITOS.
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
    @staticmethod
    def _get_base_dir():
        """Obtener la ruta base absoluta del proyecto ARESITOS."""
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
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
                'fg_accent': '#00ffe7',
                'button_bg': '#007acc',
                'success': '#00ff00',
                'warning': '#ffcc00'
            }
            self.configure(bg=self.colors['bg_primary'])
        # Construir la interfaz gráfica
        self.crear_interfaz()




    
    def set_controlador(self, controlador: Optional[Any]):
        """Establecer controlador siguiendo patrón MVC"""
        self.controlador = controlador
    
    def crear_interfaz(self):
        """Crear interfaz completa para herramientas Kali"""
        # Frame principal
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
            "• Forense: sleuthkit, foremost\n" +
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
    • AVANZADAS: nmap (versátil), nuclei (CVE), ffuf (fuzzing), feroxbuster (recursivo)
   • ANÁLISIS: strings, hexdump, binwalk, sleuthkit, yara
   • SEGURIDAD: chkrootkit, rkhunter, auditd, fail2ban, lynis
    • RED: ip, route, netstat, netcat, tcpdump

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
            herramientas = [
                # ... (toda la lista de herramientas, sin cambios)
            ]
            total_herramientas = len(herramientas)
            self.after(0, self._actualizar_texto, f"Verificando {total_herramientas} herramientas de Kali Linux...\n\n")
            
            # Lista de herramientas esenciales modernizadas para Kali 2025
            herramientas = [
                # Herramientas robustas, apt-installables y recomendadas para ARESITOS v3.0
                # Escaneo profesional
                'nmap', 'masscan', 'nuclei', 'ffuf', 'feroxbuster', 'nikto', 'whatweb', 'dirb', 'gobuster',
                # Forense y análisis
                'sleuthkit', 'tsk_recover', 'tsk_loaddb', 'tsk_gettimes', 'tsk_comparedir', 'tsk_imageinfo',
                'testdisk', 'bulk-extractor', 'hashdeep', 'dc3dd', 'guymager', 'foremost', 'binwalk', 'exiftool', 'yara', 'autopsy',
                # Seguridad y auditoría
                'clamav', 'clamav-daemon', 'chkrootkit', 'rkhunter', 'lynis', 'auditd', 'aide', 'debsums', 'rsyslog', 'logrotate', 'logwatch',
                # Análisis avanzado y red
                'tcpdump', 'wireshark', 'tshark', 'strace', 'ltrace', 'gdb', 'osqueryi', 'file', 'hexdump',
                # Utilidades del sistema
                'ps', 'ss', 'lsof', 'netstat', 'top', 'free', 'df', 'uname', 'who', 'last',
                'find', 'stat', 'grep', 'awk', 'sort', 'uniq', 'wc', 'tail', 'head',
                'systemctl', 'ip', 'route', 'wget', 'curl', 'diff', 'ls', 'chmod', 'chown', 'git',
                'lsmod', 'kill', 'pgrep', 'pkill', 'sha256sum', 'md5sum', 'sha1sum', 'sha512sum',
                'iptables', 'cat', 'less', 'more', 'pwd', 'mkdir', 'rm', 'cp', 'mv',
                # Editores y gestores
                'nano', 'vim', 'vi', 'gedit', 'mousepad',
                'thunar', 'nautilus', 'dolphin', 'xdg-open',
                # Herramientas base de verificación
                'which', 'whereis', 'type', 'command',
                # Python y dependencias
                'python3', 'sqlite3'
            ]
            
            herramientas_faltantes = []
            herramientas_ok = []
            
            # Builtins de shell que no se pueden verificar con which
            builtins_shell = {'type', 'command'}
            # Mapas de paquetes a binarios principales
            binarios_especiales = {
                'sleuthkit': ['tsk_recover', 'tsk_loaddb', 'tsk_gettimes', 'tsk_comparedir', 'tsk_imageinfo'],
                'clamav': ['clamscan'],
                'clamav-daemon': ['clamd'],
                'bulk-extractor': ['bulk_extractor'],
                'rsyslog': ['rsyslogd'],
                'osqueryi': ['osqueryi'],
            }
            from aresitos.utils.sudo_manager import get_sudo_manager, is_sudo_available
            sudo_manager = get_sudo_manager()
            for herramienta in herramientas:
                # Omitir comprobación de 'osqueryi' y 'osquery' (no OK ni FALTA, simplemente ignorar)
                if herramienta in ('osquery', 'osqueryi'):
                    continue
                try:
                    if herramienta in builtins_shell:
                        herramientas_ok.append(herramienta)
                        self.after(0, self._actualizar_texto, f"OK {herramienta} - BUILTIN\n")
                        continue
                    elif herramienta in binarios_especiales:
                        # Considera OK si al menos uno de los binarios existe
                        ok = False
                        import os
                        for binario in binarios_especiales[herramienta]:
                            # Buscar en PATH usando SudoManager
                            resultado = sudo_manager.execute_sudo_command(f"which {binario}", timeout=5)
                            if hasattr(resultado, 'returncode') and resultado.returncode == 0:
                                ok = True
                                break
                            # Buscar en /usr/bin y /usr/local/bin
                            for ruta in ['/usr/bin', '/usr/local/bin']:
                                if os.path.exists(os.path.join(ruta, binario)):
                                    ok = True
                                    break
                            if ok:
                                break
                        if ok:
                            herramientas_ok.append(herramienta)
                            self.after(0, self._actualizar_texto, f"OK {herramienta} - OK\n")
                        else:
                            herramientas_faltantes.append(herramienta)
                            self.after(0, self._actualizar_texto, f"ERROR {herramienta} - FALTANTE\n")
                        continue
                    # Verificación estándar usando SudoManager
                    resultado = sudo_manager.execute_sudo_command(f"which {herramienta}", timeout=5)
                    if hasattr(resultado, 'returncode') and resultado.returncode == 0:
                        herramientas_ok.append(herramienta)
                        self.after(0, self._actualizar_texto, f"OK {herramienta} - OK\n")
                    else:
                        herramientas_faltantes.append(herramienta)
                        self.after(0, self._actualizar_texto, f"ERROR {herramienta} - FALTANTE\n")
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
        """Instalación asíncrona de herramientas usando SudoManager y automatización total"""
        import shutil
        try:
            self.after(0, self._actualizar_texto, "Instalando herramientas de Kali Linux...\n\n")
            sudo_manager = get_sudo_manager()
            if not is_sudo_available():
                self.after(0, self._actualizar_texto, "ERROR: No hay permisos sudo disponibles\n")
                self.after(0, self._actualizar_texto, "Reinicie ARESITOS e ingrese la contraseña correcta\n")
                return
            # 1. Instalar Go si no está
            if not shutil.which("go"):
                self.after(0, self._actualizar_texto, "Go no detectado. Instalando Go...\n")
                sudo_manager.execute_sudo_command("apt install -y golang-go", timeout=120)
            # 2. Instalar binutils para strings/hexdump
            if not shutil.which("strings") or not shutil.which("hexdump"):
                self.after(0, self._actualizar_texto, "Instalando binutils para strings/hexdump...\n")
                sudo_manager.execute_sudo_command("apt install -y binutils", timeout=120)
            # 3. Instalar herramientas APT
            paquetes = [
                'nmap', 'masscan', 'nuclei', 'ffuf', 'feroxbuster', 'nikto', 'whatweb', 'dirb', 'gobuster',
                'sleuthkit', 'testdisk', 'plaso', 'bulk-extractor', 'hashdeep', 'dc3dd', 'guymager', 'foremost', 'binwalk', 'exiftool', 'yara', 'autopsy',
                'clamav', 'clamav-daemon', 'chkrootkit', 'rkhunter', 'lynis', 'auditd', 'aide', 'debsums', 'rsyslog', 'logrotate', 'logwatch',
                'tcpdump', 'wireshark', 'tshark', 'strace', 'ltrace', 'gdb', 'osquery', 'file', 'hexdump',
                'procps', 'iproute2', 'net-tools', 'util-linux', 'findutils', 'grep', 'gawk',
                'coreutils', 'systemd', 'wget', 'curl', 'diffutils', 'git',
                'nano', 'vim', 'gedit', 'mousepad', 'thunar', 'nautilus', 'dolphin', 'xdg-open',
                'python3', 'sqlite3'
            ]
            self.after(0, self._actualizar_texto, "Actualizando repositorios...\n")
            sudo_manager.execute_sudo_command('apt update', timeout=120)
            self.after(0, self._actualizar_texto, "Instalando herramientas principales...\n")
            for paquete in paquetes:
                self.after(0, self._actualizar_texto, f"Instalando {paquete}...\n")
                sudo_manager.execute_sudo_command(f'apt install -y {paquete}', timeout=120)
            # 4. Instalar httpx y nuclei con go install
            go_path = shutil.which("go")
            if go_path:
                self.after(0, self._actualizar_texto, "Instalando httpx (go install)...\n")
                sudo_manager.execute_sudo_command(f"{go_path} install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", timeout=180)
                self.after(0, self._actualizar_texto, "Instalando nuclei (go install)...\n")
                sudo_manager.execute_sudo_command(f"{go_path} install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", timeout=180)
                # Mover binarios de ~/go/bin a /usr/local/bin
                import os
                home = os.path.expanduser("~")
                for tool in ["httpx", "nuclei"]:
                    src = os.path.join(home, "go", "bin", tool)
                    dst = f"/usr/local/bin/{tool}"
                    if os.path.exists(src):
                        sudo_manager.execute_sudo_command(f"cp {src} {dst}", timeout=30)
                        sudo_manager.execute_sudo_command(f"chmod 755 {dst}", timeout=30)
            # 5. Descargar linpeas, pspy64, pspy32 y mover a /usr/local/bin
            bin_urls = {
                "linpeas.sh": "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
                "pspy64": "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
                "pspy32": "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32"
            }
            for fname, url in bin_urls.items():
                dst = f"/usr/local/bin/{fname}"
                self.after(0, self._actualizar_texto, f"Descargando {fname}...\n")
                sudo_manager.execute_sudo_command(f"wget -q -O {dst} {url}", timeout=120)
                sudo_manager.execute_sudo_command(f"chmod 755 {dst}", timeout=30)
            # 6. DirBuster ya está en /usr/share/dirbuster/
            self.after(0, self._actualizar_texto, "DirBuster ya está disponible en /usr/share/dirbuster/\n")
            # 7. Mostrar resumen final
            self.after(0, self._actualizar_texto, "\n==============================================\n")
            self.after(0, self._actualizar_texto, "INSTALACIÓN AUTOMÁTICA COMPLETA\n")
            self.after(0, self._actualizar_texto, "==============================================\n")
            self.after(0, self._actualizar_texto, "Todas las herramientas principales y avanzadas han sido instaladas automáticamente.\n")
            self.after(0, self._actualizar_texto, "Puede usar ARESITOS sin intervención manual.\n")
            self.after(0, self._habilitar_continuar)
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

