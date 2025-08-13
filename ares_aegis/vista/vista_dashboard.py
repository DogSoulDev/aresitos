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
    from ares_aegis.vista.burp_theme import burp_theme
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
            text="🛡️ ARES AEGIS - Dashboard de Ciberseguridad",
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
    
    def crear_pestana_metricas(self):
        """Crear pestaña de métricas específicas para ciberseguridad."""
        metricas_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(metricas_frame, text="📊 Métricas del Sistema")
        
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
        
        tk.Label(cpu_frame, text="🔥 CPU Usage:", 
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.cpu_label = tk.Label(cpu_frame, text="0.0%",
                                 bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                 font=("Consolas", 10, "bold"))
        self.cpu_label.pack(side="right")
        
        # Uso de memoria
        memoria_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        memoria_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(memoria_frame, text="💾 Memory Usage:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.memoria_label = tk.Label(memoria_frame, text="0.0%",
                                     bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                     font=("Consolas", 10, "bold"))
        self.memoria_label.pack(side="right")
        
        # Procesos activos
        procesos_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        procesos_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(procesos_frame, text="⚙️ Procesos Activos:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.procesos_label = tk.Label(procesos_frame, text="0",
                                      bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                      font=("Consolas", 10, "bold"))
        self.procesos_label.pack(side="right")
        
        # Estado de servicios críticos
        servicios_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        servicios_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(servicios_frame, text="🛡️ Estado SIEM:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.siem_label = tk.Label(servicios_frame, text="🔴 Inactive",
                                  bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                  font=("Consolas", 10, "bold"))
        self.siem_label.pack(side="right")
        
        # Tiempo de actividad
        uptime_frame = tk.Frame(metricas_criticas_frame, bg=self.colors['bg_secondary'])
        uptime_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(uptime_frame, text="⏱️ Uptime Sistema:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.uptime_label = tk.Label(uptime_frame, text="Unknown",
                                    bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                    font=("Consolas", 10, "bold"))
        self.uptime_label.pack(side="right")
    
    def crear_pestana_red(self):
        """Crear pestaña de información de red."""
        red_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(red_frame, text="🌐 Información de Red")
        
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
            text="🏠 IP Local (LAN): Obteniendo...",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 11),
            anchor="w"
        )
        self.ip_local_label.pack(fill="x", padx=10, pady=5)
        
        # IP Pública (WAN)
        self.ip_publica_label = tk.Label(
            ip_frame,
            text="🌍 IP Pública (WAN): Obteniendo...",
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
        
        tk.Label(conexiones_frame, text="🔗 Conexiones Activas:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.conexiones_label = tk.Label(conexiones_frame, text="0",
                                        bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                        font=("Consolas", 10, "bold"))
        self.conexiones_label.pack(side="right")
        
        # Puertos en escucha
        puertos_frame = tk.Frame(stats_red_frame, bg=self.colors['bg_secondary'])
        puertos_frame.pack(fill="x", padx=10, pady=2)
        
        tk.Label(puertos_frame, text="👂 Puertos en Escucha:",
                bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")).pack(side="left")
        
        self.puertos_label = tk.Label(puertos_frame, text="0",
                                     bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'],
                                     font=("Consolas", 10, "bold"))
        self.puertos_label.pack(side="right")
    
    def crear_pestana_terminal(self):
        """Crear pestaña de terminal integrado."""
        terminal_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(terminal_frame, text="💻 Terminal")
        
        # Frame para comandos rápidos
        comandos_frame = tk.LabelFrame(
            terminal_frame,
            text="Comandos Rápidos de Ciberseguridad",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        comandos_frame.pack(fill="x", padx=10, pady=5)
        
        # Botones de comandos rápidos
        comandos_rapidos = [
            ("netstat -an", "Ver conexiones de red"),
            ("tasklist", "Listar procesos") if platform.system() == "Windows" else ("ps aux", "Listar procesos"),
            ("ipconfig /all", "Configuración de red") if platform.system() == "Windows" else ("ifconfig", "Configuración de red"),
            ("nslookup google.com", "Test DNS"),
            ("ping -n 4 8.8.8.8", "Test conectividad") if platform.system() == "Windows" else ("ping -c 4 8.8.8.8", "Test conectividad")
        ]
        
        # Crear grid de botones
        for i, (comando, descripcion) in enumerate(comandos_rapidos):
            row = i // 3
            col = i % 3
            btn = tk.Button(
                comandos_frame,
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
            comandos_frame.grid_columnconfigure(i, weight=1)
        
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
            self.ip_local_label.configure(text=f"🏠 IP Local (LAN): {ip_local}")
            
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
                text=f"🌍 IP Pública (WAN): {ip_publica}"
            ))
        except:
            self.after(0, lambda: self.ip_publica_label.configure(
                text="🌍 IP Pública (WAN): No disponible"
            ))
    
    def _actualizar_interfaces_red(self):
        """Actualizar información de interfaces de red."""
        try:
            self.interfaces_text.delete(1.0, tk.END)
            
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface, direcciones in interfaces.items():
                if interface in stats and stats[interface].isup:
                    self.interfaces_text.insert(tk.END, f"🔌 {interface}:\n")
                    
                    for direccion in direcciones:
                        if direccion.family == socket.AF_INET:  # IPv4
                            self.interfaces_text.insert(tk.END, f"   IPv4: {direccion.address}\n")
                        elif direccion.family == socket.AF_INET6:  # IPv6
                            self.interfaces_text.insert(tk.END, f"   IPv6: {direccion.address}\n")
                    
                    # Estado de la interface
                    stat = stats[interface]
                    estado = "🟢 UP" if stat.isup else "🔴 DOWN"
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
                    self.siem_label.configure(text="🟢 Active" if siem_activo else "🔴 Inactive")
                else:
                    self.siem_label.configure(text="🔴 Inactive")
            else:
                self.siem_label.configure(text="🔴 Inactive")
                
        except Exception as e:
            print(f"Error actualizando estado de servicios: {e}")
            self.siem_label.configure(text="🔴 Error")
    
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
