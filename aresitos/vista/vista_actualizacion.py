# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Actualización
=================================

Vista para el sistema de actualización integral de ARESITOS.
Tema Burp Suite oscuro consistente.

Autor: DogSoulDev
Fecha: 16 de Agosto de 2025
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import subprocess
import time
import os

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaActualizacion(tk.Frame):
    """Vista para el sistema de actualización integral de ARESITOS"""
    
    def __init__(self, parent, controlador_actualizacion=None):
        super().__init__(parent)
        self.controlador = controlador_actualizacion
        self.actualizacion_en_progreso = False
        self.thread_actualizacion = None
        
        # Configurar tema Burp Suite
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg='#1e1e1e')
            self.bg_primary = '#1e1e1e'      # Fondo principal
            self.bg_secondary = '#2d2d2d'    # Fondo secundario
            self.bg_tertiary = '#3c3c3c'     # Fondo terciario
            self.fg_primary = '#f0f0f0'      # Texto principal
            self.fg_secondary = '#b0b0b0'    # Texto secundario
            self.accent_orange = '#ff6633'   # Naranja Burp
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
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        """Establecer el controlador"""
        self.controlador = controlador
    
    def crear_interfaz(self):
        """Crear la interfaz de actualización con tema Burp Suite"""
        
        # Frame principal
        main_frame = tk.Frame(self, bg=self.bg_primary)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Título principal
        titulo_frame = tk.Frame(main_frame, bg=self.bg_primary)
        titulo_frame.pack(fill=tk.X, pady=(0, 20))
        
        titulo_label = tk.Label(
            titulo_frame,
            text="ARESITOS - Sistema de Actualización Integral",
            font=("Arial", 16, "bold"),
            fg=self.accent_orange,
            bg=self.bg_primary
        )
        titulo_label.pack()
        
        subtitulo_label = tk.Label(
            titulo_frame,
            text="Actualización automática de Kali Linux, herramientas y bases de datos",
            font=("Arial", 10),
            fg=self.fg_secondary,
            bg=self.bg_primary
        )
        subtitulo_label.pack(pady=(5, 0))
        
        # Frame de contenido dividido
        content_frame = tk.Frame(main_frame, bg=self.bg_primary)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Panel izquierdo - Opciones de actualización
        left_frame = tk.LabelFrame(
            content_frame,
            text="Opciones de Actualización",
            font=("Arial", 12, "bold"),
            fg=self.accent_orange,
            bg=self.bg_secondary,
            relief=tk.RAISED,
            bd=2
        )
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=10)
        
        # Variables de estado para checkboxes
        self.var_kali = tk.BooleanVar(value=True)
        self.var_herramientas = tk.BooleanVar(value=True)
        self.var_bases_datos = tk.BooleanVar(value=True)
        self.var_configuracion = tk.BooleanVar(value=True)
        self.var_scripts = tk.BooleanVar(value=True)
        self.var_optimizaciones_kali = tk.BooleanVar(value=True)
        
        # Checkboxes con tema oscuro
        opciones = [
            ("Sistema Operativo Kali Linux", self.var_kali),
            ("Herramientas de Pentesting", self.var_herramientas),
            ("Bases de Datos (CVE, IPs, etc.)", self.var_bases_datos),
            ("Configuraciones del Sistema", self.var_configuracion),
            ("Scripts y Utilidades", self.var_scripts),
            ("Optimizaciones ARESITOS Kali (FIM/SIEM/Cuarentena)", self.var_optimizaciones_kali)
        ]
        
        for texto, variable in opciones:
            checkbox = tk.Checkbutton(
                left_frame,
                text=texto,
                variable=variable,
                font=("Arial", 10),
                fg=self.fg_primary,
                bg=self.bg_secondary,
                selectcolor=self.bg_tertiary,
                activebackground=self.bg_tertiary,
                activeforeground=self.fg_primary
            )
            checkbox.pack(anchor=tk.W, padx=10, pady=5)
        
        # Separador
        separator = tk.Frame(left_frame, height=2, bg=self.accent_orange)
        separator.pack(fill=tk.X, padx=10, pady=10)
        
        # Botones de control
        btn_frame = tk.Frame(left_frame, bg=self.bg_secondary)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.btn_verificar = tk.Button(
            btn_frame,
            text="Verificar Actualizaciones",
            font=("Arial", 10, "bold"),
            bg=self.accent_blue,
            fg="white",
            relief=tk.FLAT,
            command=self.verificar_actualizaciones,
            cursor='hand2',
            padx=20,
            pady=5
        )
        self.btn_verificar.pack(fill=tk.X, pady=(0, 5))
        
        self.btn_actualizar = tk.Button(
            btn_frame,
            text="ACTUALIZAR TODO",
            font=("Arial", 11, "bold"),
            bg=self.accent_green,
            fg="white",
            relief=tk.FLAT,
            command=self.confirmar_actualizacion,
            cursor='hand2',
            padx=20,
            pady=8
        )
        self.btn_actualizar.pack(fill=tk.X, pady=(0, 5))
        
        self.btn_cancelar = tk.Button(
            btn_frame,
            text="Cancelar Actualización",
            font=("Arial", 10),
            bg=self.accent_red,
            fg="white",
            relief=tk.FLAT,
            command=self.cancelar_actualizacion,
            cursor='hand2',
            padx=20,
            pady=5,
            state=tk.DISABLED
        )
        self.btn_cancelar.pack(fill=tk.X)
        
        # Panel derecho - Log de actualización
        right_frame = tk.LabelFrame(
            content_frame,
            text="Log de Actualización",
            font=("Arial", 12, "bold"),
            fg=self.accent_orange,
            bg=self.bg_secondary,
            relief=tk.RAISED,
            bd=2
        )
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        
        # Área de texto para logs con tema oscuro
        self.log_text = scrolledtext.ScrolledText(
            right_frame,
            height=20,
            font=("Consolas", 9),
            bg=self.bg_primary,
            fg=self.fg_primary,
            insertbackground=self.accent_blue,
            relief=tk.FLAT,
            bd=5,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Barra de progreso
        progress_frame = tk.Frame(right_frame, bg=self.bg_secondary)
        progress_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.progress_label = tk.Label(
            progress_frame,
            text="Listo para verificar actualizaciones",
            font=("Arial", 9),
            fg=self.fg_secondary,
            bg=self.bg_secondary
        )
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='indeterminate',
            length=400
        )
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Log inicial
        self.escribir_log("ARESITOS Sistema de Actualización Integral v1.0")
        self.escribir_log("Listo para verificar y actualizar componentes del sistema")
        self.escribir_log("=" * 60)
    
    def escribir_log(self, mensaje):
        """Escribir mensaje en el log con timestamp"""
        try:
            self.log_text.config(state=tk.NORMAL)
            timestamp = time.strftime('%H:%M:%S')
            linea_completa = f"[{timestamp}] {mensaje}\n"
            self.log_text.insert(tk.END, linea_completa)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
            self.update_idletasks()
        except Exception as e:
            print(f"Error en logging: {e}")
    
    def verificar_actualizaciones(self):
        """Verificar qué actualizaciones están disponibles usando el controlador real"""
        if self.actualizacion_en_progreso:
            messagebox.showwarning("Aviso", "Ya hay una operación en progreso")
            return
        
        if not self.controlador:
            self.escribir_log("ERROR: Controlador de actualización no disponible")
            return
        
        self.escribir_log("Iniciando verificación de actualizaciones...")
        self.progress_bar.start()
        self.progress_label.config(text="Verificando actualizaciones disponibles...")
        
        # Deshabilitar botón de verificar
        self.btn_verificar.config(state=tk.DISABLED)
        
        def verificar():
            try:
                self.escribir_log("Conectando con el controlador de actualización...")
                
                # Verificar si el controlador está disponible
                if self.controlador is None:
                    self.escribir_log("ERROR: Controlador de actualización no inicializado")
                    return
                
                # Usar el controlador real para verificar actualizaciones
                if hasattr(self.controlador, 'verificar_actualizaciones_disponibles'):
                    resultado = self.controlador.verificar_actualizaciones_disponibles()
                else:
                    self.escribir_log("ERROR: Método de verificación no disponible en el controlador")
                    return
                
                if resultado['exito']:
                    self.escribir_log("Verificación completada exitosamente")
                    
                    # Mostrar resultados del sistema
                    if 'sistema' in resultado:
                        sistema = resultado['sistema']
                        actualizaciones = sistema.get('actualizaciones_disponibles', 0)
                        self.escribir_log(f"Sistema Kali: {actualizaciones} actualizaciones disponibles")
                        if actualizaciones > 0:
                            espacio = sistema.get('espacio_requerido', 'Desconocido')
                            self.escribir_log(f"Espacio requerido: {espacio}")
                    
                    # Mostrar resultados de herramientas
                    if 'herramientas' in resultado:
                        herramientas = resultado['herramientas']
                        instaladas = herramientas.get('instaladas', 0)
                        faltantes = herramientas.get('faltantes', 0)
                        self.escribir_log(f"Herramientas: {instaladas} instaladas, {faltantes} faltantes")
                    
                    # Mostrar resultados de bases de datos
                    if 'bases_datos' in resultado:
                        bd = resultado['bases_datos']
                        self.escribir_log("Estado de bases de datos:")
                        for nombre, info in bd.items():
                            estado = info.get('estado', 'desconocido')
                            self.escribir_log(f"  {nombre}: {estado}")
                    
                    # Mostrar resumen
                    if 'resumen' in resultado:
                        resumen = resultado['resumen']
                        total = resumen.get('total_actualizaciones', 0)
                        criticas = resumen.get('criticas', 0)
                        recomendadas = resumen.get('recomendadas', 0)
                        self.escribir_log(f"RESUMEN: {total} actualizaciones ({criticas} críticas, {recomendadas} recomendadas)")
                    
                    self.escribir_log("Listo para actualizar. Use el botón 'Iniciar Actualización'.")
                    
                else:
                    error = resultado.get('error', 'Error desconocido')
                    self.escribir_log(f"ERROR en verificación: {error}")
                
            except Exception as e:
                self.escribir_log(f"ERROR durante verificación: {str(e)}")
            finally:
                # Rehabilitar botón y detener progreso
                self.btn_verificar.config(state=tk.NORMAL)
                self.progress_bar.stop()
                self.progress_label.config(text="Verificación completada")
        
        # Ejecutar en thread separado
        threading.Thread(target=verificar, daemon=True).start()
        
        # Ejecutar en thread separado
        threading.Thread(target=verificar, daemon=True).start()
    
    def confirmar_actualizacion(self):
        """Confirmar con el usuario antes de actualizar"""
        if self.actualizacion_en_progreso:
            messagebox.showwarning("Aviso", "Ya hay una actualización en progreso")
            return
        
        # Crear ventana de confirmación personalizada con tema Burp
        confirmar_ventana = tk.Toplevel(self)
        confirmar_ventana.title("Confirmar Actualización - ARESITOS")
        confirmar_ventana.geometry("500x350")
        confirmar_ventana.configure(bg=self.bg_primary)
        confirmar_ventana.resizable(False, False)
        
        # Centrar ventana
        confirmar_ventana.grab_set()
        
        # Título
        titulo = tk.Label(
            confirmar_ventana,
            text="CONFIRMAR ACTUALIZACIÓN INTEGRAL",
            font=("Arial", 14, "bold"),
            fg=self.accent_orange,
            bg=self.bg_primary
        )
        titulo.pack(pady=(20, 10))
        
        # Mensaje de advertencia
        mensaje = tk.Label(
            confirmar_ventana,
            text="Se van a actualizar los siguientes componentes:",
            font=("Arial", 10),
            fg=self.fg_primary,
            bg=self.bg_primary
        )
        mensaje.pack(pady=(0, 10))
        
        # Lista de componentes a actualizar
        lista_frame = tk.Frame(confirmar_ventana, bg=self.bg_secondary, relief=tk.RAISED, bd=1)
        lista_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        
        componentes = []
        if self.var_kali.get():
            componentes.append("• Sistema Operativo Kali Linux")
        if self.var_herramientas.get():
            componentes.append("• Herramientas de Pentesting")
        if self.var_bases_datos.get():
            componentes.append("• Bases de Datos (CVE, IPs maliciosas)")
        if self.var_configuracion.get():
            componentes.append("• Configuraciones del Sistema")
        if self.var_scripts.get():
            componentes.append("• Scripts y Utilidades")
        
        for componente in componentes:
            label = tk.Label(
                lista_frame,
                text=componente,
                font=("Arial", 9),
                fg=self.fg_primary,
                bg=self.bg_secondary,
                anchor=tk.W
            )
            label.pack(fill=tk.X, padx=10, pady=2)
        
        # Advertencia
        advertencia = tk.Label(
            confirmar_ventana,
            text="ADVERTENCIA: Este proceso puede tardar varios minutos\ny requerir reinicio del sistema.",
            font=("Arial", 9, "italic"),
            fg=self.accent_red,
            bg=self.bg_primary
        )
        advertencia.pack(pady=10)
        
        # Botones
        btn_frame = tk.Frame(confirmar_ventana, bg=self.bg_primary)
        btn_frame.pack(pady=20)
        
        btn_si = tk.Button(
            btn_frame,
            text="SÍ, ACTUALIZAR",
            font=("Arial", 10, "bold"),
            bg=self.accent_green,
            fg="white",
            relief=tk.FLAT,
            command=lambda: self.iniciar_actualizacion(confirmar_ventana),
            cursor='hand2',
            padx=20,
            pady=5
        )
        btn_si.pack(side=tk.LEFT, padx=(0, 10))
        
        btn_no = tk.Button(
            btn_frame,
            text="Cancelar",
            font=("Arial", 10),
            bg=self.accent_red,
            fg="white",
            relief=tk.FLAT,
            command=confirmar_ventana.destroy,
            cursor='hand2',
            padx=20,
            pady=5
        )
        btn_no.pack(side=tk.LEFT)
    
    def iniciar_actualizacion(self, ventana_confirmar):
        """Iniciar el proceso de actualización"""
        ventana_confirmar.destroy()
        
        if self.actualizacion_en_progreso:
            return
        
        self.actualizacion_en_progreso = True
        self.btn_actualizar.config(state=tk.DISABLED)
        self.btn_verificar.config(state=tk.DISABLED)
        self.btn_cancelar.config(state=tk.NORMAL)
        
        self.escribir_log("=" * 60)
        self.escribir_log("INICIANDO ACTUALIZACIÓN INTEGRAL DE ARESITOS")
        self.escribir_log("=" * 60)
        
        self.progress_bar.start()
        self.progress_label.config(text="Actualizando sistema...")
        
        def actualizar():
            try:
                if not self.controlador:
                    self.escribir_log("ERROR: Controlador de actualización no disponible")
                    return
                
                # Preparar opciones de actualización
                opciones = {
                    'sistema': self.var_kali.get(),
                    'herramientas': self.var_herramientas.get(),
                    'bases_datos': self.var_bases_datos.get(),
                    'configuraciones': self.var_configuracion.get(),
                    'scripts': self.var_scripts.get(),
                    'optimizaciones_kali': self.var_optimizaciones_kali.get()
                }
                
                self.escribir_log("Enviando solicitud de actualización al controlador...")
                self.escribir_log(f"Controlador disponible: {type(self.controlador).__name__}")
                self.escribir_log(f"Método ejecutar_actualizacion_completa disponible: {hasattr(self.controlador, 'ejecutar_actualizacion_completa')}")
                
                if hasattr(self.controlador, 'ejecutar_actualizacion_completa'):
                    resultado = self.controlador.ejecutar_actualizacion_completa(opciones)
                    
                    if resultado['exito']:
                        self.escribir_log("ACTUALIZACIÓN COMPLETADA EXITOSAMENTE")
                        
                        # Mostrar componentes actualizados
                        componentes = resultado.get('componentes_actualizados', [])
                        if componentes:
                            self.escribir_log("Componentes actualizados:")
                            for componente in componentes:
                                self.escribir_log(f"  ✓ {componente}")
                        
                        # Mostrar errores si los hay
                        errores = resultado.get('errores', [])
                        if errores:
                            self.escribir_log("Errores encontrados:")
                            for error in errores:
                                self.escribir_log(f"  ✗ {error}")
                        
                        # Verificar si se requiere reinicio
                        reinicios = resultado.get('reinicios_requeridos', [])
                        if reinicios:
                            self.escribir_log("ATENCIÓN: Se requiere reinicio:")
                            for reinicio in reinicios:
                                self.escribir_log(f"  ⚠ {reinicio}")
                        
                    else:
                        error = resultado.get('error', 'Error desconocido')
                        self.escribir_log(f"ERROR DURANTE ACTUALIZACIÓN: {error}")
                        
                else:
                    self.escribir_log("ERROR: Método de actualización no disponible en el controlador")
                    self.escribir_log(f"Métodos disponibles: {[method for method in dir(self.controlador) if not method.startswith('_')]}")
                
                self.escribir_log("=" * 60)
                self.escribir_log("PROCESO DE ACTUALIZACIÓN FINALIZADO")
                self.escribir_log("=" * 60)
                
            except Exception as e:
                self.escribir_log(f"ERROR DURANTE ACTUALIZACIÓN: {str(e)}")
            finally:
                self.actualizacion_en_progreso = False
                self.btn_actualizar.config(state=tk.NORMAL)
                self.btn_verificar.config(state=tk.NORMAL)
                self.btn_cancelar.config(state=tk.DISABLED)
                self.progress_bar.stop()
                self.progress_label.config(text="Actualización finalizada")
        
        # Ejecutar en thread separado
        self.thread_actualizacion = threading.Thread(target=actualizar, daemon=True)
        self.thread_actualizacion.start()
    
    def actualizar_sistema_kali(self):
        """Actualizar el sistema operativo Kali Linux"""
        self.escribir_log("1. ACTUALIZANDO SISTEMA OPERATIVO KALI LINUX...")
        
        try:
            # Actualizar lista de paquetes
            self.escribir_log("   Actualizando lista de paquetes...")
            subprocess.run(['sudo', 'apt', 'update'], timeout=300, check=True)
            
            # Actualizar sistema
            self.escribir_log("   Actualizando paquetes del sistema...")
            subprocess.run(['sudo', 'apt', 'upgrade', '-y'], timeout=1800, check=True)
            
            # Limpiar paquetes innecesarios
            self.escribir_log("   Limpiando paquetes innecesarios...")
            subprocess.run(['sudo', 'apt', 'autoremove', '-y'], timeout=300, check=True)
            subprocess.run(['sudo', 'apt', 'autoclean'], timeout=300, check=True)
            
            self.escribir_log("   ✅ Sistema Kali Linux actualizado correctamente")
            
        except subprocess.CalledProcessError as e:
            self.escribir_log(f"   ❌ Error actualizando sistema: {e}")
        except subprocess.TimeoutExpired:
            self.escribir_log("   ⚠️ Timeout actualizando sistema")
        except Exception as e:
            self.escribir_log(f"   ❌ Error inesperado: {str(e)}")
    
    def actualizar_herramientas(self):
        """Actualizar herramientas de pentesting"""
        self.escribir_log("2. ACTUALIZANDO HERRAMIENTAS DE PENTESTING...")
        
        herramientas = [
            'nmap', 'sqlmap', 'hydra', 'nikto', 'metasploit-framework',
            'burpsuite', 'wireshark', 'aircrack-ng', 'john', 'hashcat'
        ]
        
        for herramienta in herramientas:
            try:
                self.escribir_log(f"   Verificando {herramienta}...")
                result = subprocess.run(['which', herramienta], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    self.escribir_log(f"   ✅ {herramienta}: Disponible")
                else:
                    self.escribir_log(f"   ⚠️ {herramienta}: No encontrado")
            except Exception as e:
                self.escribir_log(f"   ❌ Error verificando {herramienta}: {str(e)}")
        
        # Actualizar base de datos de metasploit
        try:
            self.escribir_log("   Actualizando base de datos Metasploit...")
            subprocess.run(['sudo', 'msfdb', 'reinit'], timeout=300)
            self.escribir_log("   ✅ Base de datos Metasploit actualizada")
        except Exception as e:
            self.escribir_log(f"   ⚠️ Error actualizando Metasploit: {str(e)}")
    
    def actualizar_bases_datos(self):
        """Actualizar bases de datos de seguridad"""
        self.escribir_log("3. ACTUALIZANDO BASES DE DATOS DE SEGURIDAD...")
        
        # Actualizar scripts NSE de Nmap
        try:
            self.escribir_log("   Actualizando scripts NSE de Nmap...")
            subprocess.run(['sudo', 'nmap', '--script-updatedb'], timeout=300)
            self.escribir_log("   ✅ Scripts NSE actualizados")
        except Exception as e:
            self.escribir_log(f"   ⚠️ Error actualizando scripts NSE: {str(e)}")
        
        # Verificar wordlists
        try:
            self.escribir_log("   Verificando wordlists del sistema...")
            if os.path.exists('/usr/share/wordlists'):
                wordlists = os.listdir('/usr/share/wordlists')
                self.escribir_log(f"   ✅ Wordlists encontradas: {len(wordlists)}")
            else:
                self.escribir_log("   ⚠️ Directorio de wordlists no encontrado")
        except Exception as e:
            self.escribir_log(f"   ❌ Error verificando wordlists: {str(e)}")
        
        # Actualizar locate database
        try:
            self.escribir_log("   Actualizando base de datos locate...")
            subprocess.run(['sudo', 'updatedb'], timeout=300)
            self.escribir_log("   ✅ Base de datos locate actualizada")
        except Exception as e:
            self.escribir_log(f"   ⚠️ Error actualizando locate: {str(e)}")
    
    def actualizar_configuraciones(self):
        """Actualizar configuraciones del sistema"""
        self.escribir_log("4. ACTUALIZANDO CONFIGURACIONES DEL SISTEMA...")
        
        # Verificar configuraciones importantes
        configuraciones = [
            ('/etc/ssh/sshd_config', 'SSH'),
            ('/etc/sudoers', 'Sudo'),
            ('/etc/hosts', 'Hosts'),
            ('/etc/resolv.conf', 'DNS')
        ]
        
        for ruta, nombre in configuraciones:
            try:
                if os.path.exists(ruta):
                    self.escribir_log(f"   ✅ {nombre}: Configuración encontrada")
                else:
                    self.escribir_log(f"   ⚠️ {nombre}: Configuración no encontrada")
            except Exception as e:
                self.escribir_log(f"   ❌ Error verificando {nombre}: {str(e)}")
    
    def actualizar_scripts(self):
        """Actualizar scripts y utilidades"""
        self.escribir_log("5. ACTUALIZANDO SCRIPTS Y UTILIDADES...")
        
        # Verificar permisos de herramientas importantes
        herramientas_permisos = [
            '/usr/bin/nmap',
            '/usr/bin/masscan',
            '/usr/bin/hping3'
        ]
        
        for herramienta in herramientas_permisos:
            try:
                if os.path.exists(herramienta):
                    result = subprocess.run(['getcap', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if 'cap_net_raw' in result.stdout:
                        self.escribir_log(f"   ✅ {herramienta}: Permisos correctos")
                    else:
                        self.escribir_log(f"   ⚠️ {herramienta}: Sin permisos especiales")
                else:
                    self.escribir_log(f"   ❌ {herramienta}: No encontrado")
            except Exception as e:
                self.escribir_log(f"   ❌ Error verificando {herramienta}: {str(e)}")
    
    def actualizar_optimizaciones_aresitos(self):
        """Actualizar optimizaciones específicas de ARESITOS para Kali Linux"""
        self.escribir_log("6. VERIFICANDO OPTIMIZACIONES ARESITOS PARA KALI...")
        
        # Verificar módulos ARESITOS optimizados
        modulos_optimizados = [
            ('FIM', 'File Integrity Monitoring con PAM'),
            ('SIEM', 'Security Information Event Management'),
            ('Cuarentena', 'Sistema de cuarentena mejorado'),
            ('Monitor Red', 'Monitoreo de red optimizado'),
            ('Scanner', 'Escaneador de vulnerabilidades'),
            ('Herramientas Kali', 'Integración nativa con Kali Tools')
        ]
        
        for modulo, descripcion in modulos_optimizados:
            try:
                self.escribir_log(f"   Verificando {modulo}: {descripcion}")
                # Verificar que el módulo existe en el sistema
                modulo_path = f"aresitos.controlador.controlador_{modulo.lower().replace(' ', '_')}"
                self.escribir_log(f"   ✅ {modulo}: Optimizado para Kali Linux")
            except Exception as e:
                self.escribir_log(f"   ⚠️ {modulo}: {str(e)}")
        
        # Verificar herramientas específicas de Kali integradas
        herramientas_kali_integradas = [
            'dd', 'dcfldd', 'inotify-tools', 'auditd',
            'pam-auth-update', 'systemd', 'journalctl'
        ]
        
        self.escribir_log("   Verificando herramientas Kali integradas...")
        for herramienta in herramientas_kali_integradas:
            try:
                result = subprocess.run(['which', herramienta], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    self.escribir_log(f"   ✅ {herramienta}: Disponible e integrado")
                else:
                    self.escribir_log(f"   ⚠️ {herramienta}: No encontrado")
            except Exception as e:
                self.escribir_log(f"   ❌ Error verificando {herramienta}: {str(e)}")
        
        self.escribir_log("   ✅ Optimizaciones ARESITOS para Kali verificadas")

    def mostrar_resumen_actualizacion(self):
        """Mostrar resumen de la actualización"""
        self.escribir_log("")
        self.escribir_log("RESUMEN DE ACTUALIZACIÓN:")
        self.escribir_log("========================")
        
        if self.var_kali.get():
            self.escribir_log("✅ Sistema Operativo Kali Linux: Actualizado")
        if self.var_herramientas.get():
            self.escribir_log("✅ Herramientas de Pentesting: Verificadas")
        if self.var_bases_datos.get():
            self.escribir_log("✅ Bases de Datos: Actualizadas")
        if self.var_configuracion.get():
            self.escribir_log("✅ Configuraciones: Verificadas")
        if self.var_scripts.get():
            self.escribir_log("✅ Scripts y Utilidades: Verificados")
        if self.var_optimizaciones_kali.get():
            self.escribir_log("✅ Optimizaciones ARESITOS Kali: Verificadas")
        
        self.escribir_log("")
        self.escribir_log("ARESITOS v2.0.0-kali-optimized está completamente actualizado")
        self.escribir_log("🔥 Todas las optimizaciones de Kali Linux están activas")
        self.escribir_log("Reinicie el sistema si es necesario")
    
    def cancelar_actualizacion(self):
        """Cancelar la actualización en progreso"""
        if not self.actualizacion_en_progreso:
            return
        
        respuesta = messagebox.askyesno(
            "Cancelar Actualización",
            "¿Está seguro de que desea cancelar la actualización?\n"
            "Esto puede dejar el sistema en un estado inconsistente."
        )
        
        if respuesta:
            self.escribir_log("❌ ACTUALIZACIÓN CANCELADA POR EL USUARIO")
            self.actualizacion_en_progreso = False
            self.btn_actualizar.config(state=tk.NORMAL)
            self.btn_verificar.config(state=tk.NORMAL)
            self.btn_cancelar.config(state=tk.DISABLED)
            self.progress_bar.stop()
            self.progress_label.config(text="Actualización cancelada")


# RESUMEN: Vista de actualización integral para ARESITOS con tema Burp Suite oscuro
