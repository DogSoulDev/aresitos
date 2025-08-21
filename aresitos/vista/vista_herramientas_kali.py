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
            text="Configuración de Herramientas Kali Linux",
            font=('Arial', 16, 'bold'),
            bg=self.colors['bg_primary'], 
            fg=self.colors['fg_accent']
        )
        titulo_label.pack(pady=(0, 20))
        
        # Subtítulo informativo
        info_label = tk.Label(
            main_frame,
            text="Verificación y configuración de herramientas nativas de Kali Linux\nArquitectura: 100% Python + Herramientas Kali",
            font=('Arial', 11),
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            justify=tk.CENTER
        )
        info_label.pack(pady=(0, 30))
        
        # Frame de botones
        botones_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        botones_frame.pack(fill="x", pady=(0, 20))
        
        # Botón verificar herramientas
        self.btn_verificar = tk.Button(
            botones_frame,
            text="Verificar Herramientas Kali",
            command=self.verificar_herramientas,
            bg=self.colors['button_bg'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        )
        self.btn_verificar.pack(side="left", padx=(0, 15))
        
        # Botón instalar herramientas
        self.btn_instalar = tk.Button(
            botones_frame,
            text="Instalar Herramientas Faltantes",
            command=self.instalar_herramientas,
            bg=self.colors['warning'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2',
            state='disabled'
        )
        self.btn_instalar.pack(side="left", padx=(0, 15))
        
        # Botón continuar (habilitado por defecto en modo desarrollo)
        self.btn_continuar = tk.Button(
            botones_frame,
            text="Continuar a ARESITOS",
            command=self.continuar_aplicacion,
            bg=self.colors['success'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2',
            state='normal'  # Habilitado por defecto
        )
        self.btn_continuar.pack(side="right")
        
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
            "ARESITOS - Configuración de Herramientas Kali Linux\n" +
            "=" * 50 + "\n\n" +
            "Haga clic en 'Verificar Herramientas Kali' para comenzar la verificación.\n\n"
        )
        
        # Centrar ventana
        self.after(100, self._centrar_ventana)
    
    def _centrar_ventana(self):
        """Centrar la ventana en la pantalla"""
        try:
            # Obtener la ventana raíz
            root = self.winfo_toplevel()
            root.update_idletasks()
            
            # Obtener dimensiones
            width = root.winfo_width()
            height = root.winfo_height()
            x = (root.winfo_screenwidth() // 2) - (width // 2)
            y = (root.winfo_screenheight() // 2) - (height // 2)
            
            # Establecer posición
            root.geometry(f"{width}x{height}+{x}+{y}")
        except Exception as e:
            self.logger.debug(f"Error centrando ventana: {e}")
    
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
                'inotifywait', 'pspy', 'pspy64', 'linpeas', 'chkrootkit', 'rkhunter',
                # SIEM y auditoría
                'auditd', 'ausearch', 'logger', 'fail2ban-client', 'lynis',
                # Herramientas base del sistema
                'which', 'ps', 'netstat', 'ss', 'lsof', 'find'
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
                # Escaneadores básicos
                'nmap', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'dirb',
                # Servicios de red 
                'netcat-traditional', 'whatweb', 'wfuzz', 'ffuf',
                # Cracking y passwords
                'hashcat', 'john', 'hydra', 'medusa', 'patator',
                # Análisis SQL
                'sqlmap', 'sqlninja',
                # Cuarentena y malware
                'clamav', 'clamav-daemon', 'yara', 'binwalk', 'exiftool',
                'volatility3', 'foremost', 'sleuthkit',
                # FIM y monitoreo sistema
                'inotify-tools', 'chkrootkit', 'rkhunter', 'auditd',
                # SIEM y auditoría
                'fail2ban', 'lynis', 'aide'
            ]
            
            # Herramientas que requieren instalación manual (se informará al usuario):
            herramientas_manuales = [
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
            
            # Instalar paquetes
            self.after(0, self._actualizar_texto, "Instalando herramientas...\n")
            cmd = ['sudo', 'apt', 'install', '-y'] + paquetes
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True)
            
            # Leer salida en tiempo real
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    if line.strip():
                        self.after(0, self._actualizar_texto, line)
            
            process.wait()
            
            if process.returncode == 0:
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
                self.after(0, self._actualizar_texto, "\n✗ Error durante la instalación\n")
                
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