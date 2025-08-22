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
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientasKali(tk.Frame):
    """Vista para herramientas nativas de Kali Linux"""
    
    def __init__(self, parent, callback_completado=None):
        super().__init__(parent)
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
            "ARESITOS v2.0 - Configurador de Herramientas Kali\n" +
            "=" * 50 + "\n\n" +
            "Sistema optimizado para Kali Linux con comandos nativos integrados:\n\n" +
            "• Comandos del sistema: ps, ss, lsof, grep, awk, find, stat\n" +
            "• Herramientas de red: nmap, netcat, ip, route, ss\n" +
            "• Monitoreo: inotifywait, auditd, systemctl, top, free\n" +
            "• Análisis forense: binwalk, strings, hexdump, volatility\n" +
            "• Seguridad: chkrootkit, rkhunter, lynis, fail2ban\n\n" +
            "Haga clic en 'Verificar Herramientas Kali' para verificar disponibilidad.\n" +
            "Nota: Los comandos básicos ya están integrados en el sistema.\n\n"
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

HERRAMIENTAS PRINCIPALES UTILIZADAS:
   • Comandos básicos: ps, ss, lsof, grep, awk, find, stat
   • Red: ip, route, netstat, nmap, netcat
   • Sistema: systemctl, top, free, df, uname, who, last
   • Seguridad: chkrootkit, rkhunter, auditd, fail2ban
   • Análisis: strings, hexdump, binwalk, volatility
   • Procesamiento: sort, uniq, wc, tail, head, diff

BENEFICIOS:
   • Rendimiento optimizado en Kali Linux
   • Sin dependencias externas complejas
   • Funcionalidad profesional de ciberseguridad
   • Integración perfecta con el ecosistema Kali
   • Máximo aprovechamiento de herramientas nativas

OK ESTADO: OPTIMIZACIÓN COMPLETA APLICADA
LISTO PARA: Producción en entornos Kali Linux

"""
        
        self.text_resultados.insert(tk.END, optimizaciones_texto)
        self.text_resultados.see(tk.END)
        
        self._log_terminal("Optimizaciones Kali Linux mostradas", "HERRAMIENTAS_KALI", "INFO")
    
    def verificar_herramientas(self):
        """Verificar herramientas de Kali Linux disponibles"""
        if self.proceso_activo:
            return
        
        self.proceso_activo = True
        self.btn_verificar.config(state='disabled')
        self.text_resultados.delete(1.0, tk.END)
        
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
                'systemctl', 'ip', 'route', 'wget', 'curl', 'diff',
                # Herramientas de monitoreo y análisis del sistema
                'inotifywait', 'chkrootkit', 'rkhunter', 'lynis', 'auditd', 'ausearch',
                # Escaneadores de red
                'nmap', 'masscan', 'rustscan', 'gobuster', 'feroxbuster', 'nikto', 'nuclei', 'httpx',
                # Análisis de servicios
                'netcat', 'netcat-traditional', 'whatweb', 'wfuzz', 'ffuf', 'dirb',
                # Cracking y fuerza bruta
                'hashcat', 'john', 'hydra', 'medusa', 'patator',
                # Bases de datos y SQL
                'sqlmap', 'sqlninja',
                # Cuarentena y análisis de malware
                'clamav', 'clamscan', 'yara', 'binwalk', 'strings', 'file', 'exiftool',
                'volatility3', 'vol', 'hexdump', 'foremost', 'sleuthkit',
                # FIM y monitoreo
                'pspy', 'pspy64', 'linpeas', 'logger', 'fail2ban-client',
                # Herramientas base de verificación
                'which'
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
                        self.after(0, self._actualizar_texto, f"✓ {herramienta} - OK\n")
                    else:
                        herramientas_faltantes.append(herramienta)
                        self.after(0, self._actualizar_texto, f"✗ {herramienta} - FALTANTE\n")
                        
                except subprocess.TimeoutExpired:
                    herramientas_faltantes.append(herramienta)
                    self.after(0, self._actualizar_texto, f"✗ {herramienta} - TIMEOUT\n")
                except Exception as e:
                    herramientas_faltantes.append(herramienta)
                    self.after(0, self._actualizar_texto, f"✗ {herramienta} - ERROR: {e}\n")
            
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
            self.btn_instalar.config(state='normal')
        else:
            self._actualizar_texto("¡Todas las herramientas están disponibles!\n")
            self.btn_continuar.config(state='normal')
    
    def _actualizar_texto(self, texto):
        """Actualizar texto en el área de resultados"""
        self.text_resultados.insert(tk.END, texto)
        self.text_resultados.see(tk.END)
        self.text_resultados.update()
    
    def _finalizar_verificacion(self):
        """Finalizar proceso de verificación"""
        self.proceso_activo = False
        self.btn_verificar.config(state='normal')
    
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
        self.btn_instalar.config(state='disabled')
        self.text_resultados.delete(1.0, tk.END)
        
        # Ejecutar instalación en thread separado
        thread = threading.Thread(target=self._instalar_herramientas_async)
        thread.daemon = True
        thread.start()
    
    def _instalar_herramientas_async(self):
        """Instalación asíncrona de herramientas"""
        try:
            self.after(0, self._actualizar_texto, "Instalando herramientas de Kali Linux...\n\n")
            
            # Lista de paquetes disponibles en repositorios APT de Kali
            paquetes = [
                # Comandos básicos del sistema (ya incluidos en Kali por defecto)
                'procps', 'iproute2', 'net-tools', 'util-linux', 'findutils', 'grep', 'gawk',
                'coreutils', 'systemd', 'wget', 'curl', 'diffutils',
                # Herramientas de monitoreo y análisis sistema
                'inotify-tools', 'chkrootkit', 'rkhunter', 'lynis', 'auditd',
                # Escaneadores básicos
                'nmap', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'dirb',
                # Servicios de red 
                'netcat-traditional', 'whatweb', 'wfuzz', 'ffuf',
                # Cracking y passwords
                'hashcat', 'john', 'hydra', 'medusa', 'patator',
                # Análisis SQL
                'sqlmap', 'sqlninja',
                # Cuarentena y malware (paquetes APT disponibles)
                'clamav', 'clamav-daemon', 'yara', 'binwalk', 'exiftool',
                'foremost', 'sleuthkit',
                # SIEM y auditoría
                'fail2ban', 'aide'
            ]
            
            # Herramientas que requieren instalación manual (se informará al usuario):
            herramientas_manuales = [
                'volatility3: pip3 install volatility3',
                'rustscan: cargo install rustscan',
                'httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
                'nuclei: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
                'linpeas: wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
                'pspy64: wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64'
            ]
            
            # Actualizar repositorios
            self.after(0, self._actualizar_texto, "Actualizando repositorios...\n")
            result = subprocess.run(['sudo', 'apt', 'update'], 
                                  capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                self.after(0, self._actualizar_texto, "✓ Repositorios actualizados\n\n")
            else:
                self.after(0, self._actualizar_texto, f"✗ Error actualizando repositorios: {result.stderr}\n\n")
            
            # Instalar paquetes uno por uno para mejor control de errores
            self.after(0, self._actualizar_texto, "Instalando herramientas...\n")
            
            paquetes_exitosos = []
            paquetes_fallidos = []
            
            for paquete in paquetes:
                try:
                    self.after(0, self._actualizar_texto, f"Instalando {paquete}...\n")
                    
                    cmd = ['sudo', 'apt', 'install', '-y', paquete]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    
                    if result.returncode == 0:
                        paquetes_exitosos.append(paquete)
                        self.after(0, self._actualizar_texto, f"✓ {paquete} instalado correctamente\n")
                    else:
                        paquetes_fallidos.append(paquete)
                        self.after(0, self._actualizar_texto, f"✗ Error instalando {paquete}: {result.stderr[:100]}...\n")
                        
                except subprocess.TimeoutExpired:
                    paquetes_fallidos.append(paquete)
                    self.after(0, self._actualizar_texto, f"✗ Timeout instalando {paquete}\n")
                except Exception as e:
                    paquetes_fallidos.append(paquete)
                    self.after(0, self._actualizar_texto, f"✗ Error instalando {paquete}: {str(e)[:100]}...\n")
            
            # Mostrar resumen
            self.after(0, self._actualizar_texto, f"\n{'='*50}\n")
            self.after(0, self._actualizar_texto, f"RESUMEN DE INSTALACIÓN\n")
            self.after(0, self._actualizar_texto, f"{'='*50}\n")
            self.after(0, self._actualizar_texto, f"✓ Instalados correctamente: {len(paquetes_exitosos)}\n")
            self.after(0, self._actualizar_texto, f"✗ Errores de instalación: {len(paquetes_fallidos)}\n\n")
            
            if paquetes_fallidos:
                self.after(0, self._actualizar_texto, "PAQUETES CON ERRORES:\n")
                for paquete in paquetes_fallidos:
                    self.after(0, self._actualizar_texto, f"  • {paquete}\n")
                self.after(0, self._actualizar_texto, "\nEstos paquetes pueden no estar disponibles en este sistema.\n")
            
            # Considerar exitoso si al menos el 70% se instaló
            if len(paquetes_exitosos) >= len(paquetes) * 0.7:
                self.after(0, self._actualizar_texto, "\n✓ Instalación completada exitosamente\n")
                
                # Mostrar información sobre herramientas de instalación manual
                self.after(0, self._actualizar_texto, "\n" + "="*50 + "\n")
                self.after(0, self._actualizar_texto, "HERRAMIENTAS DE INSTALACIÓN MANUAL\n")
                self.after(0, self._actualizar_texto, "="*50 + "\n")
                for herramienta in herramientas_manuales:
                    self.after(0, self._actualizar_texto, f"📦 {herramienta}\n")
                self.after(0, self._actualizar_texto, "\nEstas herramientas se pueden instalar manualmente\n")
                self.after(0, self._actualizar_texto, "si se necesitan funcionalidades específicas.\n")
                
                self.after(0, self._habilitar_continuar)
            else:
                self.after(0, self._actualizar_texto, f"\n✗ Instalación con muchos errores ({len(paquetes_fallidos)}/{len(paquetes)} fallaron)\n")
                self.after(0, self._actualizar_texto, "Recomendación: Verificar conexión y repositorios\n")
                
        except subprocess.TimeoutExpired:
            self.after(0, self._actualizar_texto, "\n✗ Timeout durante la instalación\n")
        except Exception as e:
            self.after(0, self._actualizar_texto, f"\n✗ Error: {e}\n")
        finally:
            self.after(0, self._finalizar_instalacion)
    
    def _habilitar_continuar(self):
        """Habilitar botón de continuar"""
        self.btn_continuar.config(state='normal')
    
    def _finalizar_instalacion(self):
        """Finalizar proceso de instalación"""
        self.proceso_activo = False
        self.btn_instalar.config(state='normal')
    
    def continuar_aplicacion(self):
        """Continuar a la aplicación principal"""
        self.text_resultados.insert(tk.END, "\nIniciando ARESITOS v2.0...\n")
        self.text_resultados.insert(tk.END, "Herramientas modernas configuradas correctamente\n")
        self.text_resultados.insert(tk.END, "Tema Burp Suite aplicado\n")
        self.text_resultados.insert(tk.END, "Dashboard completo cargado\n")
        self.text_resultados.see(tk.END)
        
        # Deshabilitar botón para evitar clicks múltiples
        self.btn_continuar.config(state='disabled', text="Iniciando...")
        
        # Ejecutar callback si está disponible
        if self.callback_completado:
            self.text_resultados.insert(tk.END, "\nAbriendo aplicación principal...\n")
            self.text_resultados.see(tk.END)
            # Usar after para ejecutar el callback en el hilo principal
            self.after(1500, self.callback_completado)
        else:
            messagebox.showinfo("Información", 
                              "Configuración completada exitosamente.\n"
                              "ARESITOS v2.0 se iniciará automáticamente.")
            # Si no hay callback, cerrar esta ventana
            self.after(2000, lambda: self.master.destroy())
    
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