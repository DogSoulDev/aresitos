# -*- coding: utf-8 -*-

import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# Importar todas las vistas disponibles
from aresitos.vista.vista_dashboard import VistaDashboard
from aresitos.vista.vista_escaneo import VistaEscaneo
from aresitos.vista.vista_monitoreo import VistaMonitoreo
from aresitos.vista.vista_auditoria import VistaAuditoria
from aresitos.vista.vista_gestion_datos import VistaGestionDatos
from aresitos.vista.vista_herramientas import VistaHerramientas
from aresitos.vista.vista_reportes import VistaReportes
from aresitos.vista.vista_fim import VistaFIM
from aresitos.vista.vista_siem import VistaSIEM
from aresitos.vista.vista_actualizacion import VistaActualizacion

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaPrincipal(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        # Diagnósticos del sistema
        self._ejecutar_diagnosticos()
        
        # Solo aplicar tema si está disponible
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.setup_burp_theme(parent)
        else:
            self.theme = None
            
        self.crear_widgets()
    
    def _ejecutar_diagnosticos(self):
        """Ejecuta diagnósticos del sistema para detectar problemas"""
        print("DIAGNÓSTICOS DEL SISTEMA ARESITOS")
        print("=" * 50)
        
        # 1. Verificar importaciones críticas
        try:
            import tkinter
            print("✓ tkinter disponible")
        except Exception as e:
            print(f"ERROR con tkinter: {e}")
        
        # 2. Verificar archivos de configuración
        import os
        from pathlib import Path
        
        # Detectar directorio del proyecto
        script_dir = Path(__file__).parent.parent.parent
        config_dir = script_dir / "configuracion"
        
        print(f"Directorio base: {script_dir}")
        print(f"Directorio config: {config_dir}")
        
        config_files = [
            "aresitos_config.json",
            "aresitos_config_kali.json"
        ]
        
        for config_file in config_files:
            config_path = config_dir / config_file
            if config_path.exists():
                # Verificar permisos
                readable = os.access(str(config_path), os.R_OK)
                writable = os.access(str(config_path), os.W_OK)
                print(f"✓ {config_file} - Lectura: {readable}, Escritura: {writable}")
            else:
                print(f"ERROR {config_file} no encontrado")
        
        # 3. Verificar variable DISPLAY (importante en Linux)
        display = os.environ.get('DISPLAY')
        if display:
            print(f"✓ DISPLAY configurado: {display}")
        else:
            print("WARNING DISPLAY no configurado (puede causar problemas de GUI)")
        
        # 4. Verificar permisos del directorio actual
        current_dir = os.getcwd()
        dir_readable = os.access(current_dir, os.R_OK)
        dir_writable = os.access(current_dir, os.W_OK)
        print(f"Directorio actual: {current_dir}")
        print(f"   Permisos - Lectura: {dir_readable}, Escritura: {dir_writable}")
        
        print("=" * 50)

    def setup_burp_theme(self, parent):
        """Configura el tema visual de Burp Suite"""
        if not self.theme:
            return
            
        # Configurar el fondo de la ventana principal
        parent.configure(bg=self.theme.get_color('bg_primary'))
        self.configure(bg=self.theme.get_color('bg_primary'))
        
        # Configurar estilos TTK
        self.style = ttk.Style()
        self.theme.configure_ttk_style(self.style)

    def log_sistema(self, mensaje, nivel='INFO'):
        """Registra mensajes del sistema"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{nivel}] {timestamp}: {mensaje}")

    def configurar_icono_aplicacion(self):
        """Configura el icono de la aplicación en Kali Linux"""
        try:
            # Obtener ventana raíz
            root = self.winfo_toplevel()
            
            # Buscar archivo de icono en recursos
            icon_paths = [
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'recursos', 'AresAegis.png'),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'recursos', 'aresIcon.png'),
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'recursos', 'AresAegis.png'),
                '/usr/share/pixmaps/aresitos.png',  # Ubicación estándar en Linux
                '/opt/aresitos/recursos/AresAegis.png'  # Ubicación de instalación
            ]
            
            for icon_path in icon_paths:
                if os.path.exists(icon_path):
                    try:
                        # En Kali Linux, usar PhotoImage para PNG
                        if icon_path.endswith('.png'):
                            icon_image = tk.PhotoImage(file=icon_path)
                            root.iconphoto(True, icon_image)
                            # Mantener referencia para evitar garbage collection
                            setattr(root, '_icon_image', icon_image)
                            self.log_sistema(f"Icono configurado: {icon_path}")
                            return
                        # Para archivos .ico en Linux, intentar usar iconbitmap
                        elif icon_path.endswith('.ico'):
                            root.iconbitmap(icon_path)
                            self.log_sistema(f"Icono configurado: {icon_path}")
                            return
                    except Exception as e:
                        self.log_sistema(f"Error con icono {icon_path}: {e}", 'WARNING')
                        continue
            
            # Si no se encuentra icono, usar el titulo como identificación
            root.title("ARESITOS - Cybersecurity Professional Suite")
            self.log_sistema("Icono no encontrado, usando título por defecto", 'WARNING')
            
        except Exception as e:
            self.log_sistema(f"Error configurando icono: {e}", 'ERROR')

    def set_controlador(self, controlador):
        """Configurar el controlador principal y actualizar la interfaz"""
        print("Configurando controlador principal...")
        self.controlador = controlador
        
        if not self.controlador:
            print("Advertencia: Controlador es None, saltando configuración")
            return
        
        try:
            # Crear pestañas que requieren controlador
            print("Creando pestañas con controlador...")
            self.crear_pestanas_con_controlador()
            
            # Configurar controladores para todas las vistas
            print("Configurando controladores de vistas...")
            
            if hasattr(self, 'vista_dashboard'):
                self.vista_dashboard.set_controlador(controlador)
                print("Dashboard configurado")
                
            if hasattr(self.controlador, 'controlador_escaneador'):
                self.vista_escaneo.set_controlador(self.controlador.controlador_escaneador)
                print("Escaneador configurado")
            elif hasattr(self.controlador, '_controladores') and 'escaneador' in self.controlador._controladores:
                self.vista_escaneo.set_controlador(self.controlador._controladores['escaneador'])
                print("Escaneador configurado desde _controladores")
                
            if hasattr(self.controlador, 'controlador_monitoreo'):
                self.vista_monitoreo.set_controlador(self.controlador.controlador_monitoreo)
                print("Monitoreo configurado")
                
            if hasattr(self.controlador, 'controlador_auditoria'):
                self.vista_auditoria.set_controlador(self.controlador.controlador_auditoria)
                print("Auditoría configurado")
                
            if hasattr(self, 'vista_gestion_datos'):
                # Vista unificada para wordlists y diccionarios
                self.vista_gestion_datos.set_controlador(self.controlador)
                print("Gestión de datos configurado")
                
            if hasattr(self.controlador, 'controlador_herramientas'):
                self.vista_herramientas.set_controlador(self.controlador.controlador_herramientas)
                print("Herramientas configurado")
                
            if hasattr(self.controlador, 'controlador_reportes'):
                self.vista_reportes.set_controlador(self.controlador.controlador_reportes)
                print("Reportes configurado")
                
            if hasattr(self.controlador, '_controladores') and 'fim' in self.controlador._controladores:
                self.vista_fim.set_controlador(self.controlador._controladores['fim'])
                print("FIM configurado")
                
            if hasattr(self.controlador, '_controladores') and 'siem' in self.controlador._controladores:
                self.vista_siem.set_controlador(self.controlador._controladores['siem'])
                print("SIEM configurado")
                
            if hasattr(self, 'vista_actualizacion'):
                self.vista_actualizacion.set_controlador(controlador)
                print("Actualización configurado")
            
            # Forzar actualización de la interfaz
            print("Actualizando interfaz...")
            self.update_idletasks()
            self.update()
            
            # Forzar repintado del notebook
            if hasattr(self, 'notebook'):
                self.notebook.update_idletasks()
                self.notebook.update()
            
            print("Configuración de controladores completada exitosamente")
            
        except Exception as e:
            print(f"Error configurando controladores: {e}")
            import traceback
            traceback.print_exc()

    def crear_widgets(self):
        """Crear todos los widgets de la interfaz principal"""
        print("Creando interfaz de usuario...")
        
        try:
            # Configurar icono de la aplicación
            self.configurar_icono_aplicacion()
            
            # Configurar el contenedor principal
            self.pack(fill="both", expand=True)
            
            # Barra de título estilo Burp Suite
            print("  Creando barra de título...")
            self.crear_barra_titulo()
            
            # Notebook principal con tema
            print("  Creando notebook principal...")
            self.crear_notebook_principal()
            
            # Barra de estado
            print("  Creando barra de estado...")
            self.crear_barra_estado()
            
            # Forzar actualización inicial
            self.update_idletasks()
            self.update()
            
            print("Interfaz de usuario creada exitosamente")
            
        except Exception as e:
            print(f"Error crítico creando interfaz: {e}")
            import traceback
            traceback.print_exc()
            
            # Crear interfaz de emergencia
            self._crear_interfaz_emergencia(str(e))
    
    def _crear_interfaz_emergencia(self, error_msg):
        """Crear una interfaz básica de emergencia si falla la principal"""
        print("Creando interfaz de emergencia...")
        
        # Limpiar cualquier widget existente
        for widget in self.winfo_children():
            widget.destroy()
        
        # Frame principal de emergencia
        emergency_frame = tk.Frame(self, bg='#2b2b2b')
        emergency_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Título de error con ícono de texto
        title_label = tk.Label(
            emergency_frame,
            text="ARESITOS - MODO DE EMERGENCIA",
            font=('Arial', 16, 'bold'),
            fg='#ff6b6b',
            bg='#2b2b2b'
        )
        title_label.pack(pady=10)
        
        # Mensaje de error
        error_text = tk.Text(
            emergency_frame,
            height=10,
            width=80,
            bg='#1e1e1e',
            fg='#ffffff',
            font=('Courier', 10)
        )
        error_text.pack(pady=10, fill="both", expand=True)
        
        error_text.insert('1.0', f"Error en interfaz principal:\n\n{error_msg}\n\n")
        error_text.insert('end', "Posibles soluciones:\n")
        error_text.insert('end', "1. Verificar permisos de archivos de configuración\n")
        error_text.insert('end', "2. Ejecutar como root/administrador\n")
        error_text.insert('end', "3. Verificar instalación de dependencias\n")
        error_text.insert('end', "4. Reiniciar el sistema\n")
        
        # Botones de acción
        button_frame = tk.Frame(emergency_frame, bg='#2b2b2b')
        button_frame.pack(pady=10)
        
        retry_btn = tk.Button(
            button_frame,
            text="Reintentar",
            command=self._reintentar_interfaz,
            bg='#4a9eff',
            fg='white',
            font=('Arial', 12)
        )
        retry_btn.pack(side="left", padx=5)
        
        exit_btn = tk.Button(
            button_frame,
            text="Salir",
            command=self._salir_aplicacion,
            bg='#ff6b6b',
            fg='white',
            font=('Arial', 12)
        )
        exit_btn.pack(side="left", padx=5)
    
    def _reintentar_interfaz(self):
        """Reintentar crear la interfaz principal"""
        print("Reintentando crear interfaz...")
        try:
            # Limpiar widgets
            for widget in self.winfo_children():
                widget.destroy()
            
            # Recrear interfaz
            self.crear_widgets()
            
        except Exception as e:
            print(f"Error en reintento: {e}")
            self._crear_interfaz_emergencia(str(e))
    
    def _salir_aplicacion(self):
        """Salir de la aplicación"""
        print("Saliendo de ARESITOS...")
        import sys
        sys.exit(1)
    
    def crear_barra_titulo(self):
        """Crea la barra de título estilo Burp Suite"""
        if self.theme:
            titulo_frame = tk.Frame(self, bg=self.theme.get_color('bg_secondary'), height=50)
        else:
            titulo_frame = tk.Frame(self, bg='#f0f0f0', height=50)
        titulo_frame.pack(fill="x", padx=2, pady=(2, 0))
        titulo_frame.pack_propagate(False)
        
        # Logo y título
        if self.theme:
            titulo_label = tk.Label(
                titulo_frame,
                text=" ARESITOS",
                font=("Arial", 16, "bold"),
                fg=self.theme.get_color('fg_accent'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            titulo_label = tk.Label(
                titulo_frame,
                text=" ARESITOS",
                font=("Arial", 16, "bold"),
                fg='#ff6633',
                bg='#f0f0f0'
            )
        titulo_label.pack(side="left", padx=15, pady=10)
        
        # Subtítulo
        if self.theme:
            subtitulo_label = tk.Label(
                titulo_frame,
                text="Cybersecurity Professional Suite",
                font=("Arial", 9),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            subtitulo_label = tk.Label(
                titulo_frame,
                text="Cybersecurity Professional Suite",
                font=("Arial", 9),
                fg='#666666',
                bg='#f0f0f0'
            )
        subtitulo_label.pack(side="left", padx=(5, 0), pady=10)
        
        # Información del sistema y botón actualizar
        info_frame = tk.Frame(titulo_frame, bg=self.theme.get_color('bg_secondary') if self.theme else '#f0f0f0')
        info_frame.pack(side="right", padx=15, pady=10)
        
        # Botón de actualización
        if self.theme:
            self.btn_actualizar = tk.Button(
                info_frame,
                text="Actualizar Sistema",
                font=("Arial", 8, "bold"),
                fg='#ffffff',
                bg=self.theme.get_color('accent_orange'),
                relief=tk.FLAT,
                padx=10,
                pady=2,
                command=self.abrir_actualizador,
                cursor='hand2'
            )
        else:
            self.btn_actualizar = tk.Button(
                info_frame,
                text="Actualizar Sistema",
                font=("Arial", 8, "bold"),
                fg='#ffffff',
                bg='#ff6633',
                relief=tk.FLAT,
                padx=10,
                pady=2,
                command=self.abrir_actualizador,
                cursor='hand2'
            )
        self.btn_actualizar.pack(side="right", padx=(0, 10))
        
        if self.theme:
            info_label = tk.Label(
                info_frame,
                text="Kali Linux Ready",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            info_label = tk.Label(
                info_frame,
                text="Kali Linux Ready",
                font=("Arial", 8),
                fg='#666666',
                bg='#f0f0f0'
            )
        info_label.pack(side="right")
    
    def crear_notebook_principal(self):
        """Crea el notebook principal con estilo Burp Suite"""
        print("    Configurando notebook...")
        
        if self.theme:
            self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        else:
            self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=2, pady=2)
        
        print("    Creando pestañas principales...")
        pestanas_creadas = 0
        
        # 1. DASHBOARD - Vista principal con métricas en tiempo real
        try:
            print("      Creando Dashboard...")
            self.vista_dashboard = VistaDashboard(self.notebook)
            self.notebook.add(self.vista_dashboard, text="Dashboard")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista dashboard: {e}")
        
        # 2. SIEM - Security Information & Event Management (Prioritario)
        try:
            print("      Creando SIEM...")
            self.vista_siem = VistaSIEM(self.notebook)
            self.notebook.add(self.vista_siem, text="SIEM")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista SIEM: {e}")
        
        # 3. FIM - File Integrity Monitoring (Crítico para seguridad)
        try:
            print("      Creando FIM...")
            self.vista_fim = VistaFIM(self.notebook)
            self.notebook.add(self.vista_fim, text="FIM")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista FIM: {e}")
        
        # 4. MONITOREO Y CUARENTENA - Protección activa del sistema
        try:
            print("      Creando Monitoreo...")
            self.vista_monitoreo = VistaMonitoreo(self.notebook)
            self.notebook.add(self.vista_monitoreo, text="Cuarentena")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista monitoreo: {e}")
        
        # 5. ESCANEO - Detección de vulnerabilidades
        try:
            print("      Creando Escaneador...")
            self.vista_escaneo = VistaEscaneo(self.notebook)
            self.notebook.add(self.vista_escaneo, text="Escaneo")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista escaneo: {e}")
        
        # 6. AUDITORÍA - Auditoría de seguridad avanzada
        try:
            print("      Creando Auditoría...")
            self.vista_auditoria = VistaAuditoria(self.notebook)
            self.notebook.add(self.vista_auditoria, text="Auditoria")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista auditoría: {e}")
        
        # 7. HERRAMIENTAS - Herramientas de seguridad especializadas
        try:
            print("      Creando Herramientas...")
            self.vista_herramientas = VistaHerramientas(self.notebook)
            self.notebook.add(self.vista_herramientas, text="Herramientas")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista herramientas: {e}")
        
        # 8. WORDLISTS & DICCIONARIOS - Gestión de datos para pentesting
        try:
            print("      Creando Gestión de Datos...")
            self.vista_gestion_datos = VistaGestionDatos(self.notebook)
            self.notebook.add(self.vista_gestion_datos, text="Wordlists")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista gestión de datos: {e}")
        
        # 9. REPORTES - Documentación y análisis de resultados
        try:
            print("      Creando Reportes...")
            self.vista_reportes = VistaReportes(self.notebook)
            self.notebook.add(self.vista_reportes, text="Reportes")
            pestanas_creadas += 1
        except Exception as e:
            print(f"      Error creando vista reportes: {e}")
        
        # Actualizar el notebook después de crear las pestañas
        self.notebook.update_idletasks()
        self.notebook.update()
        
        print(f"    Notebook creado con {pestanas_creadas} pestañas")
        
        # Seleccionar la primera pestaña por defecto
        if pestanas_creadas > 0:
            self.notebook.select(0)
        
        # 10. ACTUALIZACIÓN - Sistema de actualización integral
        # Esta pestaña se crea después cuando el controlador esté disponible
    
    def crear_pestanas_con_controlador(self):
        """Crea las pestañas que requieren controlador inicializado"""
        if not self.controlador:
            return
            
        try:
            if hasattr(self.controlador, '_controladores') and 'actualizacion' in self.controlador._controladores:
                self.vista_actualizacion = VistaActualizacion(self.notebook, self.controlador._controladores['actualizacion'])
                self.notebook.add(self.vista_actualizacion, text="Actualizacion")
            else:
                print("Advertencia: Controlador de actualización no disponible, vista omitida")
        except Exception as e:
            print(f"Error creando vista actualización: {e}")
    
    def crear_barra_estado(self):
        """Crea la barra de estado inferior estilo Burp"""
        if self.theme:
            status_frame = tk.Frame(self, bg=self.theme.get_color('bg_secondary'), height=25)
        else:
            status_frame = tk.Frame(self, bg='#f0f0f0', height=25)
        status_frame.pack(fill="x", padx=2, pady=(0, 2))
        status_frame.pack_propagate(False)
        
        # Estado de la aplicación
        if self.theme:
            self.status_label = tk.Label(
                status_frame,
                text="ARESITOS Ready - All systems operational",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_primary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            self.status_label = tk.Label(
                status_frame,
                text="ARESITOS Ready - All systems operational",
                font=("Arial", 8),
                fg='#000000',
                bg='#f0f0f0'
            )
        self.status_label.pack(side="left", padx=10, pady=3)
        
        # Información técnica
        if self.theme:
            tech_label = tk.Label(
                status_frame,
                text="Python Native | No External Dependencies",
                font=("Arial", 8),
                fg=self.theme.get_color('fg_secondary'),
                bg=self.theme.get_color('bg_secondary')
            )
        else:
            tech_label = tk.Label(
                status_frame,
                text="Python Native | No External Dependencies",
                font=("Arial", 8),
                fg='#666666',
                bg='#f0f0f0'
            )
        tech_label.pack(side="right", padx=10, pady=3)
    
    def actualizar_estado(self, mensaje):
        """Actualiza el mensaje de la barra de estado"""
        if hasattr(self, 'status_label'):
            self.status_label.configure(text=mensaje)
    
    def abrir_actualizador(self):
        """Abrir ventana del actualizador del sistema"""
        try:
            # Importar y crear ventana del actualizador
            from tkinter import messagebox, Toplevel, Text, Scrollbar, Frame
            import threading
            import subprocess
            
            # Confirmar con el usuario
            respuesta = messagebox.askyesno(
                "Actualizar Sistema", 
                "¿Desea ejecutar la actualización completa del sistema?\n\n"
                "Esto incluye:\n"
                "• Sistema operativo Kali Linux\n"
                "• Herramientas de pentesting\n"
                "• Bases de datos de seguridad\n"
                "• Configuraciones del sistema\n\n"
                "⚠️ El proceso puede tomar 15-30 minutos\n"
                "⚠️ Se requieren permisos de administrador"
            )
            
            if not respuesta:
                return
            
            # Crear ventana del actualizador
            ventana_actualizador = Toplevel(self)
            ventana_actualizador.title("ARESITOS - Actualizador del Sistema")
            ventana_actualizador.geometry("800x600")
            
            if self.theme:
                ventana_actualizador.configure(bg=self.theme.get_color('bg_primary'))
            
            # Centrar ventana
            ventana_actualizador.transient(self.winfo_toplevel())
            ventana_actualizador.grab_set()
            
            # Frame principal
            if self.theme:
                main_frame = Frame(ventana_actualizador, bg=self.theme.get_color('bg_primary'))
            else:
                main_frame = Frame(ventana_actualizador)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Título
            if self.theme:
                titulo_label = tk.Label(
                    main_frame,
                    text="ACTUALIZADOR INTEGRAL ARESITOS",
                    font=("Arial", 14, "bold"),
                    fg=self.theme.get_color('accent_orange'),
                    bg=self.theme.get_color('bg_primary')
                )
            else:
                titulo_label = tk.Label(
                    main_frame,
                    text="ACTUALIZADOR INTEGRAL ARESITOS",
                    font=("Arial", 14, "bold"),
                    fg='#ff6633'
                )
            titulo_label.pack(pady=(0, 10))
            
            # Área de texto para logs
            text_frame = Frame(main_frame, bg=self.theme.get_color('bg_primary') if self.theme else 'white')
            text_frame.pack(fill=tk.BOTH, expand=True)
            
            # Texto con scroll
            if self.theme:
                text_area = Text(
                    text_frame,
                    bg=self.theme.get_color('bg_secondary'),
                    fg=self.theme.get_color('fg_primary'),
                    font=("Consolas", 9),
                    wrap=tk.WORD,
                    state=tk.DISABLED
                )
            else:
                text_area = Text(
                    text_frame,
                    font=("Consolas", 9),
                    wrap=tk.WORD,
                    state=tk.DISABLED
                )
            
            scrollbar = Scrollbar(text_frame, command=text_area.yview)
            text_area.configure(yscrollcommand=scrollbar.set)
            
            text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Frame de botones
            if self.theme:
                btn_frame = Frame(main_frame, bg=self.theme.get_color('bg_primary'))
            else:
                btn_frame = Frame(main_frame)
            btn_frame.pack(fill=tk.X, pady=(10, 0))
            
            # Botón cerrar
            if self.theme:
                btn_cerrar = tk.Button(
                    btn_frame,
                    text="Cerrar",
                    font=("Arial", 10),
                    bg=self.theme.get_color('accent_red') if hasattr(self.theme, 'accent_red') else '#cc0000',
                    fg='#ffffff',
                    command=ventana_actualizador.destroy,
                    padx=20
                )
            else:
                btn_cerrar = tk.Button(
                    btn_frame,
                    text="Cerrar",
                    font=("Arial", 10),
                    bg='#cc0000',
                    fg='#ffffff',
                    command=ventana_actualizador.destroy,
                    padx=20
                )
            btn_cerrar.pack(side=tk.RIGHT)
            
            def ejecutar_actualizacion():
                """Ejecutar actualización en hilo separado"""
                try:
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, "Iniciando actualización del sistema...\n")
                    text_area.insert(tk.END, "Ejecutando actualizador externo...\n\n")
                    text_area.config(state=tk.DISABLED)
                    text_area.see(tk.END)
                    
                    # Ejecutar actualizador externo
                    import os
                    actualizador_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'actualizador_aresitos.py')
                    
                    if os.path.exists(actualizador_path):
                        # Ejecutar con sudo y mostrar output en tiempo real
                        process = subprocess.Popen(
                            ['sudo', 'python3', actualizador_path, '--auto'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1,
                            universal_newlines=True
                        )
                        
                        # Leer output en tiempo real
                        if process.stdout:
                            for line in process.stdout:
                                if line.strip():
                                    text_area.config(state=tk.NORMAL)
                                    text_area.insert(tk.END, line)
                                    text_area.config(state=tk.DISABLED)
                                    text_area.see(tk.END)
                                    ventana_actualizador.update()
                        
                        process.wait()
                        
                        text_area.config(state=tk.NORMAL)
                        if process.returncode == 0:
                            text_area.insert(tk.END, "\n✅ Actualización completada exitosamente\n")
                        else:
                            text_area.insert(tk.END, f"\n⚠️ Actualización terminó con código: {process.returncode}\n")
                        text_area.config(state=tk.DISABLED)
                        text_area.see(tk.END)
                    else:
                        text_area.config(state=tk.NORMAL)
                        text_area.insert(tk.END, f"❌ Error: No se encontró el actualizador en {actualizador_path}\n")
                        text_area.config(state=tk.DISABLED)
                        
                except Exception as e:
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, f"❌ Error ejecutando actualización: {str(e)}\n")
                    text_area.config(state=tk.DISABLED)
            
            # Iniciar actualización en hilo separado
            threading.Thread(target=ejecutar_actualizacion, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error abriendo actualizador: {str(e)}")

    def abrir_terminal_kali(self):
        """Abre terminal nativo de Kali Linux con permisos completos"""
        try:
            # Terminales de Kali Linux en orden de preferencia
            terminales = ['gnome-terminal', 'konsole', 'xfce4-terminal', 'mate-terminal', 'xterm']
            
            for terminal in terminales:
                try:
                    # Usar terminal nativo de Kali con sesión completa
                    subprocess.Popen([terminal], 
                                   start_new_session=True,
                                   env=os.environ.copy())
                    self.log_sistema(f"Terminal {terminal} abierto exitosamente")
                    return
                except FileNotFoundError:
                    continue
            
            # Fallback con x-terminal-emulator
            try:
                subprocess.Popen(['x-terminal-emulator'], 
                               start_new_session=True,
                               env=os.environ.copy())
                self.log_sistema("Terminal x-terminal-emulator abierto exitosamente")
            except FileNotFoundError:
                raise Exception("No se encontró ningún emulador de terminal en Kali Linux")
                
        except Exception as e:
            error_msg = f"Error abriendo terminal de Kali: {str(e)}"
            self.log_sistema(error_msg, nivel='ERROR')
            messagebox.showerror("Error Terminal", error_msg)


# RESUMEN: Vista principal de la aplicación con interfaz de pestañas para módulos.
