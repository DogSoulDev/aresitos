# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Herramientas Kali Linux
==========================================

Ventana especializada para mostrar, verificar e instalar todas las herramientas
de Kali Linux y otras herramientas del sistema necesarias para ARESITOS.

Esta vista se muestra después del login exitoso para garantizar que el usuario
tenga todas las herramientas instaladas antes de usar ARESITOS.

Autor: DogSoulDev
Fecha: 17 de Agosto de 2025
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import time
import os
from typing import Dict, List, Any, Optional

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientasKali(tk.Toplevel):
    """
    Vista especializada para gestión de herramientas de Kali Linux.
    Se muestra después del login para verificar e instalar herramientas.
    """
    
    def __init__(self, parent, callback_completado=None):
        super().__init__(parent)
        self.parent = parent
        self.callback_completado = callback_completado
        
        # Configuración de ventana
        self.title("ARESITOS - Herramientas de Kali Linux 2025")
        self.geometry("1000x700")
        self.resizable(True, True)
        
        # Hacer que la ventana esté siempre al frente
        self.transient(parent)
        self.grab_set()
        
        # Estado de instalación
        self.instalando = False
        self.herramientas_seleccionadas = set()
        self.thread_instalacion = None
        
        # Configurar tema
        self._configurar_tema()
        
        # Definir herramientas de Kali Linux 2025
        self._definir_herramientas_kali()
        
        # Crear interfaz
        self._crear_interfaz()
        
        # Verificar herramientas al inicio
        self._verificar_herramientas_iniciales()
        
        # Centrar ventana
        self._centrar_ventana()
    
    def _configurar_tema(self):
        """Configurar tema visual Burp Suite"""
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg='#1e1e1e')
            self.bg_primary = '#1e1e1e'
            self.bg_secondary = '#2d2d2d'
            self.bg_tertiary = '#3c3c3c'
            self.fg_primary = '#f0f0f0'
            self.fg_secondary = '#b0b0b0'
            self.accent_orange = '#ff6633'
            self.accent_green = '#4caf50'
            self.accent_red = '#f44336'
            self.accent_blue = '#2196f3'
        else:
            self.theme = None
            self.configure(bg='#f0f0f0')
            self.bg_primary = '#f0f0f0'
            self.bg_secondary = '#e0e0e0'
            self.bg_tertiary = '#d0d0d0'
            self.fg_primary = '#000000'
            self.fg_secondary = '#666666'
            self.accent_orange = '#ff6633'
            self.accent_green = '#4caf50'
            self.accent_red = '#f44336'
            self.accent_blue = '#2196f3'
    
    def _definir_herramientas_kali(self):
        """Definir todas las herramientas necesarias categorizadas"""
        self.herramientas_kali = {
            " Escaneo y Reconocimiento": {
                "nmap": {
                    "descripcion": "Network exploration tool and security/port scanner",
                    "paquete": "nmap",
                    "esencial": True,
                    "uso_aresitos": "Escaneo de puertos y servicios"
                },
                "masscan": {
                    "descripcion": "TCP port scanner, spews SYN packets asynchronously",
                    "paquete": "masscan",
                    "esencial": True,
                    "uso_aresitos": "Escaneo rápido de puertos"
                },
                "zmap": {
                    "descripcion": "Fast single packet network scanner",
                    "paquete": "zmap",
                    "esencial": False,
                    "uso_aresitos": "Escaneo masivo de redes"
                },
                "gobuster": {
                    "descripcion": "Directory/File, DNS and VHost busting tool",
                    "paquete": "gobuster",
                    "esencial": True,
                    "uso_aresitos": "Enumeración de directorios web"
                },
                "dirb": {
                    "descripcion": "Web Content Scanner",
                    "paquete": "dirb",
                    "esencial": True,
                    "uso_aresitos": "Búsqueda de directorios ocultos"
                },
                "nikto": {
                    "descripcion": "Web server scanner",
                    "paquete": "nikto",
                    "esencial": True,
                    "uso_aresitos": "Análisis de vulnerabilidades web"
                },
                "whatweb": {
                    "descripcion": "Web Application fingerprinter",
                    "paquete": "whatweb",
                    "esencial": False,
                    "uso_aresitos": "Identificación de tecnologías web"
                },
                "sublist3r": {
                    "descripcion": "Fast subdomains enumeration tool",
                    "paquete": "sublist3r",
                    "esencial": False,
                    "uso_aresitos": "Enumeración de subdominios"
                },
                "fierce": {
                    "descripcion": "Domain scanner",
                    "paquete": "fierce",
                    "esencial": False,
                    "uso_aresitos": "Reconocimiento DNS"
                },
                "dnsrecon": {
                    "descripcion": "DNS Enumeration Script",
                    "paquete": "dnsrecon",
                    "esencial": False,
                    "uso_aresitos": "Enumeración DNS avanzada"
                }
            },
            " Explotación": {
                "metasploit-framework": {
                    "descripcion": "Penetration testing framework",
                    "paquete": "metasploit-framework",
                    "esencial": True,
                    "uso_aresitos": "Framework de explotación"
                },
                "sqlmap": {
                    "descripcion": "Automatic SQL injection and database takeover tool",
                    "paquete": "sqlmap",
                    "esencial": True,
                    "uso_aresitos": "Testing de inyecciones SQL"
                },
                "hydra": {
                    "descripcion": "Very fast network logon cracker",
                    "paquete": "hydra",
                    "esencial": True,
                    "uso_aresitos": "Ataques de fuerza bruta"
                },
                "medusa": {
                    "descripcion": "Speedy, parallel, and modular login brute-forcer",
                    "paquete": "medusa",
                    "esencial": False,
                    "uso_aresitos": "Ataques de fuerza bruta alternativos"
                },
                "john": {
                    "descripcion": "John the Ripper password cracker",
                    "paquete": "john",
                    "esencial": True,
                    "uso_aresitos": "Cracking de passwords"
                },
                "hashcat": {
                    "descripcion": "Advanced password recovery",
                    "paquete": "hashcat",
                    "esencial": True,
                    "uso_aresitos": "Cracking avanzado de hashes"
                },
                "aircrack-ng": {
                    "descripcion": "WiFi security auditing tools suite",
                    "paquete": "aircrack-ng",
                    "esencial": False,
                    "uso_aresitos": "Auditoría WiFi"
                }
            },
            " Post-Explotación": {
                "netcat": {
                    "descripcion": "TCP/IP swiss army knife",
                    "paquete": "netcat-traditional",
                    "esencial": True,
                    "uso_aresitos": "Conexiones de red y shells"
                },
                "socat": {
                    "descripcion": "Multipurpose relay",
                    "paquete": "socat",
                    "esencial": False,
                    "uso_aresitos": "Tunneling y redirección"
                },
                "proxychains": {
                    "descripcion": "Proxy chains - redirect connections through proxy servers",
                    "paquete": "proxychains4",
                    "esencial": False,
                    "uso_aresitos": "Anonimización de conexiones"
                }
            },
            "🔬 Análisis Forense": {
                "binwalk": {
                    "descripcion": "Tool for analyzing binary images",
                    "paquete": "binwalk",
                    "esencial": False,
                    "uso_aresitos": "Análisis de archivos binarios"
                },
                "foremost": {
                    "descripcion": "Forensic program to recover lost files",
                    "paquete": "foremost",
                    "esencial": False,
                    "uso_aresitos": "Recuperación de archivos"
                },
                "volatility": {
                    "descripcion": "Memory forensics framework",
                    "paquete": "volatility3",
                    "esencial": False,
                    "uso_aresitos": "Análisis de memoria"
                },
                "sleuthkit": {
                    "descripcion": "File system forensic analysis tools",
                    "paquete": "sleuthkit",
                    "esencial": False,
                    "uso_aresitos": "Análisis de sistemas de archivos"
                }
            },
            " SIEM y Monitoreo": {
                "auditd": {
                    "descripcion": "Linux Audit Framework",
                    "paquete": "auditd",
                    "esencial": True,
                    "uso_aresitos": "Auditoría del sistema para SIEM"
                },
                "rsyslog": {
                    "descripcion": "Reliable system log daemon",
                    "paquete": "rsyslog",
                    "esencial": True,
                    "uso_aresitos": "Gestión centralizada de logs"
                },
                "fail2ban": {
                    "descripcion": "Ban hosts that cause multiple authentication errors",
                    "paquete": "fail2ban",
                    "esencial": True,
                    "uso_aresitos": "Protección contra ataques de fuerza bruta"
                },
                "sysdig": {
                    "descripcion": "System-level exploration and troubleshooting tool",
                    "paquete": "sysdig",
                    "esencial": False,
                    "uso_aresitos": "Monitoreo profundo del sistema"
                }
            },
            "📁 FIM y Sistema": {
                "inotify-tools": {
                    "descripcion": "Command-line programs providing a simple interface to inotify",
                    "paquete": "inotify-tools",
                    "esencial": True,
                    "uso_aresitos": "Monitoreo de archivos en tiempo real para FIM"
                },
                "aide": {
                    "descripcion": "Advanced Intrusion Detection Environment",
                    "paquete": "aide",
                    "esencial": True,
                    "uso_aresitos": "Detección de cambios en archivos"
                },
                "tripwire": {
                    "descripcion": "File and directory integrity checker",
                    "paquete": "tripwire",
                    "esencial": False,
                    "uso_aresitos": "Verificación de integridad"
                },
                "chkrootkit": {
                    "descripcion": "Rootkit detector",
                    "paquete": "chkrootkit",
                    "esencial": True,
                    "uso_aresitos": "Detección de rootkits"
                },
                "rkhunter": {
                    "descripcion": "Rootkit scanner",
                    "paquete": "rkhunter",
                    "esencial": True,
                    "uso_aresitos": "Búsqueda de rootkits y backdoors"
                }
            },
            " Herramientas del Sistema": {
                "curl": {
                    "descripcion": "Command line tool for transferring data",
                    "paquete": "curl",
                    "esencial": True,
                    "uso_aresitos": "Transferencia de datos y testing web"
                },
                "wget": {
                    "descripcion": "Network downloader",
                    "paquete": "wget",
                    "esencial": True,
                    "uso_aresitos": "Descarga de archivos"
                },
                "git": {
                    "descripcion": "Fast, scalable, distributed revision control system",
                    "paquete": "git",
                    "esencial": True,
                    "uso_aresitos": "Control de versiones y actualizaciones"
                },
                "python3-pip": {
                    "descripcion": "Python package installer",
                    "paquete": "python3-pip",
                    "esencial": True,
                    "uso_aresitos": "Instalación de paquetes Python"
                },
                "build-essential": {
                    "descripcion": "Informational list of build-essential packages",
                    "paquete": "build-essential",
                    "esencial": True,
                    "uso_aresitos": "Compilación de herramientas"
                }
            }
        }
    
    def _crear_interfaz(self):
        """Crear la interfaz principal de herramientas"""
        
        # Frame principal
        main_frame = tk.Frame(self, bg=self.bg_primary)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        titulo_frame = tk.Frame(main_frame, bg=self.bg_primary)
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo_label = tk.Label(
            titulo_frame,
            text=" HERRAMIENTAS DE KALI LINUX 2025 PARA ARESITOS",
            bg=self.bg_primary,
            fg=self.accent_orange,
            font=("Arial", 16, "bold")
        )
        titulo_label.pack()
        
        subtitulo_label = tk.Label(
            titulo_frame,
            text="Verificar e instalar herramientas necesarias para funcionamiento óptimo",
            bg=self.bg_primary,
            fg=self.fg_secondary,
            font=("Arial", 10)
        )
        subtitulo_label.pack()
        
        # Frame para controles
        controles_frame = tk.Frame(main_frame, bg=self.bg_secondary)
        controles_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de control
        btn_frame = tk.Frame(controles_frame, bg=self.bg_secondary)
        btn_frame.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.btn_verificar = tk.Button(
            btn_frame,
            text=" Verificar Todas",
            command=self._verificar_todas_herramientas,
            bg=self.accent_blue,
            fg='white',
            font=("Arial", 10, "bold"),
            width=15
        )
        self.btn_verificar.pack(side=tk.LEFT, padx=5)
        
        self.btn_seleccionar_esenciales = tk.Button(
            btn_frame,
            text=" Seleccionar Esenciales",
            command=self._seleccionar_esenciales,
            bg=self.accent_orange,
            fg='white',
            font=("Arial", 10, "bold"),
            width=18
        )
        self.btn_seleccionar_esenciales.pack(side=tk.LEFT, padx=5)
        
        self.btn_instalar_seleccionadas = tk.Button(
            btn_frame,
            text=" Instalar Seleccionadas",
            command=self._instalar_seleccionadas,
            bg=self.accent_green,
            fg='white',
            font=("Arial", 10, "bold"),
            width=18
        )
        self.btn_instalar_seleccionadas.pack(side=tk.LEFT, padx=5)
        
        self.btn_continuar = tk.Button(
            btn_frame,
            text="➡️ Continuar a ARESITOS",
            command=self._continuar_aresitos,
            bg='#6c757d',
            fg='white',
            font=("Arial", 10, "bold"),
            width=18
        )
        self.btn_continuar.pack(side=tk.RIGHT, padx=5)
        
        # Frame para estadísticas
        stats_frame = tk.Frame(controles_frame, bg=self.bg_secondary)
        stats_frame.pack(side=tk.RIGHT, padx=10, pady=10)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="Herramientas: 0/0 instaladas",
            bg=self.bg_secondary,
            fg=self.fg_primary,
            font=("Arial", 10, "bold")
        )
        self.stats_label.pack()
        
        # Notebook para categorías
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Crear pestañas por categoría
        self.frames_categorias = {}
        self.treeviews_categorias = {}
        
        for categoria, herramientas in self.herramientas_kali.items():
            self._crear_pestana_categoria(categoria, herramientas)
        
        # Frame para logs
        log_frame = tk.Frame(main_frame, bg=self.bg_secondary)
        log_frame.pack(fill=tk.X, pady=(10, 0))
        
        tk.Label(
            log_frame,
            text=" Log de Instalación:",
            bg=self.bg_secondary,
            fg=self.fg_primary,
            font=("Arial", 10, "bold")
        ).pack(anchor=tk.W, padx=5)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            bg=self.bg_tertiary,
            fg=self.fg_primary,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.X, padx=5, pady=5)
    
    def _crear_pestana_categoria(self, categoria: str, herramientas: Dict):
        """Crear pestaña para una categoría de herramientas"""
        
        # Frame para la categoría
        frame_categoria = tk.Frame(self.notebook, bg=self.bg_primary)
        self.notebook.add(frame_categoria, text=categoria)
        self.frames_categorias[categoria] = frame_categoria
        
        # Treeview para las herramientas
        columns = ("Estado", "Herramienta", "Descripción", "Uso en ARESITOS")
        tree = ttk.Treeview(frame_categoria, columns=columns, show="tree headings", height=15)
        
        # Configurar columnas
        tree.heading("#0", text="", anchor=tk.W)
        tree.column("#0", width=30, minwidth=30)
        
        tree.heading("Estado", text="Estado", anchor=tk.CENTER)
        tree.column("Estado", width=80, minwidth=80, anchor=tk.CENTER)
        
        tree.heading("Herramienta", text="Herramienta", anchor=tk.W)
        tree.column("Herramienta", width=150, minwidth=100)
        
        tree.heading("Descripción", text="Descripción", anchor=tk.W)
        tree.column("Descripción", width=300, minwidth=200)
        
        tree.heading("Uso en ARESITOS", text="Uso en ARESITOS", anchor=tk.W)
        tree.column("Uso en ARESITOS", width=250, minwidth=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame_categoria, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Empaquetado
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)
        
        # Poblar treeview
        for nombre, info in herramientas.items():
            esencial_text = " " if info["esencial"] else "   "
            tree.insert("", tk.END, iid=f"{categoria}_{nombre}", 
                       text=esencial_text,
                       values=(" Verificando...", nombre, info["descripcion"], info["uso_aresitos"]))
        
        # Bind para selección
        tree.bind("<Button-1>", lambda e, cat=categoria: self._on_tree_click(e, cat))
        tree.bind("<Double-1>", lambda e, cat=categoria: self._on_tree_double_click(e, cat))
        
        self.treeviews_categorias[categoria] = tree
    
    def _on_tree_click(self, event, categoria: str):
        """Manejar clic en treeview"""
        tree = self.treeviews_categorias[categoria]
        item = tree.identify_row(event.y)
        if item:
            # Toggle selection
            if item in self.herramientas_seleccionadas:
                self.herramientas_seleccionadas.remove(item)
                tree.set(item, "Estado", "⚪ No seleccionado")
            else:
                self.herramientas_seleccionadas.add(item)
                tree.set(item, "Estado", "🔵 Seleccionado")
    
    def _on_tree_double_click(self, event, categoria: str):
        """Manejar doble clic para instalar herramienta individual"""
        tree = self.treeviews_categorias[categoria]
        item = tree.identify_row(event.y)
        if item and not self.instalando:
            nombre_herramienta = item.split("_", 1)[1]
            self._instalar_herramienta_individual(categoria, nombre_herramienta)
    
    def _verificar_herramientas_iniciales(self):
        """Verificar todas las herramientas al abrir la ventana"""
        self._escribir_log(" Verificando herramientas instaladas...")
        
        def verificar_async():
            for categoria, herramientas in self.herramientas_kali.items():
                for nombre, info in herramientas.items():
                    estado = self._verificar_herramienta(info["paquete"])
                    item_id = f"{categoria}_{nombre}"
                    
                    if estado:
                        self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "OK Instalado"))
                    else:
                        self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "ERROR No instalado"))
            
            self.after(0, self._actualizar_estadisticas)
            self.after(0, lambda: self._escribir_log("OK Verificación completada"))
        
        thread = threading.Thread(target=verificar_async, daemon=True)
        thread.start()
    
    def _verificar_herramienta(self, paquete: str) -> bool:
        """Verificar si una herramienta está instalada"""
        try:
            # Verificar con dpkg
            result = subprocess.run(['dpkg', '-l', paquete], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'ii' in result.stdout:
                return True
            
            # Verificar con which
            result = subprocess.run(['which', paquete], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _actualizar_estado_herramienta(self, item_id: str, estado: str):
        """Actualizar estado visual de una herramienta"""
        categoria = item_id.split("_", 1)[0]
        if categoria in self.treeviews_categorias:
            tree = self.treeviews_categorias[categoria]
            try:
                tree.set(item_id, "Estado", estado)
            except:
                pass
    
    def _actualizar_estadisticas(self):
        """Actualizar estadísticas de herramientas"""
        total = 0
        instaladas = 0
        esenciales_instaladas = 0
        esenciales_total = 0
        
        for categoria, herramientas in self.herramientas_kali.items():
            tree = self.treeviews_categorias[categoria]
            for nombre, info in herramientas.items():
                total += 1
                if info["esencial"]:
                    esenciales_total += 1
                
                item_id = f"{categoria}_{nombre}"
                try:
                    estado = tree.set(item_id, "Estado")
                    if "OK" in estado:
                        instaladas += 1
                        if info["esencial"]:
                            esenciales_instaladas += 1
                except:
                    pass
        
        porcentaje = (instaladas / total * 100) if total > 0 else 0
        porcentaje_esenciales = (esenciales_instaladas / esenciales_total * 100) if esenciales_total > 0 else 0
        
        self.stats_label.config(
            text=f"Herramientas: {instaladas}/{total} ({porcentaje:.1f}%) | "
                 f"Esenciales: {esenciales_instaladas}/{esenciales_total} ({porcentaje_esenciales:.1f}%)"
        )
        
        # Cambiar color del botón continuar según el estado
        if porcentaje_esenciales >= 80:
            self.btn_continuar.config(bg=self.accent_green)
        elif porcentaje_esenciales >= 50:
            self.btn_continuar.config(bg=self.accent_orange)
        else:
            self.btn_continuar.config(bg=self.accent_red)
    
    def _verificar_todas_herramientas(self):
        """Verificar todas las herramientas nuevamente"""
        if self.instalando:
            messagebox.showwarning("Advertencia", "Instalación en progreso, espere...")
            return
        
        self._verificar_herramientas_iniciales()
    
    def _seleccionar_esenciales(self):
        """Seleccionar todas las herramientas esenciales"""
        self.herramientas_seleccionadas.clear()
        
        for categoria, herramientas in self.herramientas_kali.items():
            tree = self.treeviews_categorias[categoria]
            for nombre, info in herramientas.items():
                item_id = f"{categoria}_{nombre}"
                if info["esencial"]:
                    self.herramientas_seleccionadas.add(item_id)
                    tree.set(item_id, "Estado", "🔵 Seleccionado")
                else:
                    tree.set(item_id, "Estado", "⚪ No seleccionado")
        
        self._escribir_log(f"OK Seleccionadas {len(self.herramientas_seleccionadas)} herramientas esenciales")
    
    def _instalar_seleccionadas(self):
        """Instalar herramientas seleccionadas"""
        if self.instalando:
            messagebox.showwarning("Advertencia", "Instalación ya en progreso")
            return
        
        if not self.herramientas_seleccionadas:
            messagebox.showwarning("Advertencia", "No hay herramientas seleccionadas")
            return
        
        if not messagebox.askyesno("Confirmar", 
                                  f"¿Instalar {len(self.herramientas_seleccionadas)} herramientas seleccionadas?\\n\\n"
                                  "Este proceso puede tomar varios minutos."):
            return
        
        self.instalando = True
        self.btn_instalar_seleccionadas.config(state=tk.DISABLED)
        self.btn_verificar.config(state=tk.DISABLED)
        
        self.thread_instalacion = threading.Thread(target=self._proceso_instalacion_masiva, daemon=True)
        self.thread_instalacion.start()
    
    def _proceso_instalacion_masiva(self):
        """Proceso de instalación masiva en background"""
        try:
            self.after(0, lambda: self._escribir_log(" Iniciando instalación masiva..."))
            
            # Actualizar lista de paquetes
            self.after(0, lambda: self._escribir_log(" Actualizando lista de paquetes..."))
            result = subprocess.run(['sudo', 'apt', 'update'], 
                                  capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                self.after(0, lambda: self._escribir_log("ERROR Error actualizando lista de paquetes"))
                return
            
            # Instalar cada herramienta seleccionada
            total = len(self.herramientas_seleccionadas)
            for i, item_id in enumerate(self.herramientas_seleccionadas, 1):
                categoria, nombre = item_id.split("_", 1)
                paquete = self.herramientas_kali[categoria][nombre]["paquete"]
                
                self.after(0, lambda p=paquete, n=i, t=total: 
                          self._escribir_log(f" [{n}/{t}] Instalando {p}..."))
                
                # Instalar paquete
                result = subprocess.run(['sudo', 'apt', 'install', '-y', paquete], 
                                      capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "OK Instalado"))
                    self.after(0, lambda p=paquete: self._escribir_log(f"OK {p} instalado correctamente"))
                else:
                    self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "ERROR Error"))
                    self.after(0, lambda p=paquete: self._escribir_log(f"ERROR Error instalando {p}"))
            
            self.after(0, lambda: self._escribir_log(" Instalación masiva completada"))
            self.after(0, self._actualizar_estadisticas)
            
        except Exception as e:
            self.after(0, lambda: self._escribir_log(f"ERROR Error durante instalación: {str(e)}"))
        finally:
            self.instalando = False
            self.after(0, lambda: self.btn_instalar_seleccionadas.config(state=tk.NORMAL))
            self.after(0, lambda: self.btn_verificar.config(state=tk.NORMAL))
    
    def _instalar_herramienta_individual(self, categoria: str, nombre: str):
        """Instalar una herramienta individual"""
        paquete = self.herramientas_kali[categoria][nombre]["paquete"]
        
        if not messagebox.askyesno("Confirmar", f"¿Instalar {paquete}?"):
            return
        
        def instalar_async():
            try:
                self.after(0, lambda: self._escribir_log(f" Instalando {paquete}..."))
                
                result = subprocess.run(['sudo', 'apt', 'install', '-y', paquete], 
                                      capture_output=True, text=True, timeout=300)
                
                item_id = f"{categoria}_{nombre}"
                if result.returncode == 0:
                    self.after(0, lambda: self._actualizar_estado_herramienta(item_id, "OK Instalado"))
                    self.after(0, lambda: self._escribir_log(f"OK {paquete} instalado correctamente"))
                else:
                    self.after(0, lambda: self._actualizar_estado_herramienta(item_id, "ERROR Error"))
                    self.after(0, lambda: self._escribir_log(f"ERROR Error instalando {paquete}"))
                
                self.after(0, self._actualizar_estadisticas)
                
            except Exception as e:
                self.after(0, lambda: self._escribir_log(f"ERROR Error: {str(e)}"))
        
        thread = threading.Thread(target=instalar_async, daemon=True)
        thread.start()
    
    def _escribir_log(self, mensaje: str):
        """Escribir mensaje en el log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {mensaje}\\n")
        self.log_text.see(tk.END)
    
    def _continuar_aresitos(self):
        """Continuar a ARESITOS"""
        # Verificar herramientas esenciales
        esenciales_faltantes = []
        
        for categoria, herramientas in self.herramientas_kali.items():
            tree = self.treeviews_categorias[categoria]
            for nombre, info in herramientas.items():
                if info["esencial"]:
                    item_id = f"{categoria}_{nombre}"
                    try:
                        estado = tree.set(item_id, "Estado")
                        if "ERROR" in estado:
                            esenciales_faltantes.append(nombre)
                    except:
                        esenciales_faltantes.append(nombre)
        
        if esenciales_faltantes:
            respuesta = messagebox.askyesno(
                "Herramientas Esenciales Faltantes",
                f"Faltan {len(esenciales_faltantes)} herramientas esenciales:\\n\\n"
                f"{', '.join(esenciales_faltantes[:5])}{'...' if len(esenciales_faltantes) > 5 else ''}\\n\\n"
                "ARESITOS puede no funcionar correctamente.\\n"
                "¿Continuar de todos modos?"
            )
            if not respuesta:
                return
        
        # Cerrar ventana y continuar
        self._escribir_log("➡️ Continuando a ARESITOS...")
        self.grab_release()
        
        if self.callback_completado:
            self.callback_completado()
        
        self.destroy()
    
    def _centrar_ventana(self):
        """Centrar la ventana en la pantalla"""
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (self.winfo_width() // 2)
        y = (self.winfo_screenheight() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

# Ejemplo de uso
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal
    
    def callback_test():
        print("Callback ejecutado - continuando a ARESITOS")
        root.quit()
    
    ventana_herramientas = VistaHerramientasKali(root, callback_test)
    root.mainloop()
