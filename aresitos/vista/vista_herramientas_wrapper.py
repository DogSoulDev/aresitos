# -*- coding: utf-8 -*-
"""
ARESITOS - Wrapper de Vista Herramientas para Notebook
====================================================

Wrapper que permite integrar VistaHerramientasKali en el notebook principal
de ARESITOS manteniendo la funcionalidad de ventana independiente.

Autor: DogSoulDev  
Fecha: 19 de Agosto de 2025
"""

import tkinter as tk
from tkinter import ttk
from .vista_herramientas_kali import VistaHerramientasKali

try:
    from aresitos.vista.burp_theme import burp_theme
except ImportError:
    burp_theme = None

class VistaHerramientasWrapper(ttk.Frame):
    """
    Wrapper que integra VistaHerramientasKali en el notebook principal.
    Muestra un panel de control con botones para acceder a las herramientas.
    """
    
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.theme = burp_theme
        self.ventana_herramientas = None
        
        self.crear_interfaz()
    
    def crear_interfaz(self):
        """Crea la interfaz del wrapper"""
        # Frame principal
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Título
        titulo_frame = ttk.Frame(main_frame)
        titulo_frame.pack(fill="x", pady=(0, 20))
        
        titulo_label = ttk.Label(
            titulo_frame,
            text="🛠️ HERRAMIENTAS KALI LINUX 2025",
            font=("Arial", 16, "bold")
        )
        titulo_label.pack()
        
        subtitulo_label = ttk.Label(
            titulo_frame,
            text="Acceso a herramientas especializadas de penetration testing",
            font=("Arial", 10)
        )
        subtitulo_label.pack(pady=(5, 0))
        
        # Frame de botones principales
        botones_frame = ttk.LabelFrame(main_frame, text="Acceso Rápido", padding=20)
        botones_frame.pack(fill="x", pady=(0, 20))
        
        # Botón principal para abrir ventana completa
        btn_style = "Accent.TButton" if self.theme else "TButton"
        btn_ventana_completa = ttk.Button(
            botones_frame,
            text="🚀 Abrir Gestor Completo de Herramientas",
            command=self.abrir_ventana_herramientas,
            style=btn_style
        )
        btn_ventana_completa.pack(pady=10, fill="x")
        
        # Información sobre las herramientas
        info_frame = ttk.LabelFrame(main_frame, text="Herramientas Disponibles", padding=15)
        info_frame.pack(fill="both", expand=True)
        
        # Lista de categorías
        categorias_text = """
🔍 RECONOCIMIENTO Y ESCANEO:
   • rustscan - Escaner de puertos ultrarrápido
   • feroxbuster - Fuzzing de directorios web
   • nuclei - Scanner de vulnerabilidades
   • subfinder - Descubrimiento de subdominios
   • httpx - Verificación HTTP/HTTPS
   • katana - Web crawler avanzado

🛡️ ANÁLISIS FORENSE Y MONITOREO:
   • YARA - Detección de malware
   • Volatility3 - Análisis de memoria
   • ExifTool - Análisis de metadatos
   • OSQuery - Sistema de consultas SQL
   • Binwalk - Análisis de firmware

🔒 SEGURIDAD Y DETECCIÓN:
   • Filebeat - Recolección de logs
   • Suricata - Sistema de detección de intrusos
   • chkrootkit - Detector de rootkits
   • rkhunter - Hunter de rootkits
   • tiger - Auditor de seguridad

📊 HERRAMIENTAS DE ANÁLISIS:
   • Integración completa con módulos ARESITOS
   • Reportes automatizados
   • Análisis de cuarentena
   • Monitoreo en tiempo real
        """
        
        info_text = tk.Text(
            info_frame,
            wrap="word",
            height=15,
            bg=self.theme.get_color('bg_primary') if self.theme else 'white',
            fg=self.theme.get_color('fg_primary') if self.theme else 'black',
            font=("Consolas", 9),
            state="normal"
        )
        info_text.pack(fill="both", expand=True)
        info_text.insert("1.0", categorias_text)
        info_text.config(state="disabled")
        
        # Scrollbar para el texto
        scrollbar = ttk.Scrollbar(info_text)
        scrollbar.pack(side="right", fill="y")
        info_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=info_text.yview)
        
        # Frame de estado
        estado_frame = ttk.Frame(main_frame)
        estado_frame.pack(fill="x", pady=(10, 0))
        
        self.estado_label = ttk.Label(
            estado_frame,
            text="💡 Haz clic en 'Abrir Gestor Completo' para verificar e instalar herramientas",
            font=("Arial", 9),
            foreground="blue"
        )
        self.estado_label.pack()
    
    def abrir_ventana_herramientas(self):
        """Abre la ventana completa de herramientas"""
        try:
            if self.ventana_herramientas is None or not self.ventana_herramientas.winfo_exists():
                # Crear nueva ventana
                root = self.winfo_toplevel()
                self.ventana_herramientas = VistaHerramientasKali(
                    root, 
                    callback_completado=self.callback_herramientas_completado
                )
                self.estado_label.config(
                    text="🔧 Ventana de herramientas abierta - Verifica el estado de instalación",
                    foreground="green"
                )
            else:
                # Traer ventana al frente
                self.ventana_herramientas.lift()
                self.ventana_herramientas.focus_force()
                self.estado_label.config(
                    text="🔧 Ventana de herramientas ya está abierta",
                    foreground="orange"
                )
        except Exception as e:
            self.estado_label.config(
                text=f"❌ Error abriendo ventana de herramientas: {e}",
                foreground="red"
            )
    
    def callback_herramientas_completado(self):
        """Callback cuando se completa la verificación de herramientas"""
        self.estado_label.config(
            text="✅ Verificación de herramientas completada",
            foreground="green"
        )
        self.ventana_herramientas = None
    
    def cerrar_ventana_herramientas(self):
        """Cierra la ventana de herramientas si está abierta"""
        try:
            if self.ventana_herramientas and self.ventana_herramientas.winfo_exists():
                self.ventana_herramientas.destroy()
                self.ventana_herramientas = None
        except:
            pass
    
    def destroy(self):
        """Override del método destroy para limpiar recursos"""
        self.cerrar_ventana_herramientas()
        super().destroy()
