# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import logging
import threading

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaEscaneo(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_activo = False
        self.thread_escaneo = None
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Configurar tema y colores de manera consistente
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
            # Configurar estilos TTK
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
            self.colors = {
                'bg_primary': burp_theme.get_color('bg_primary'),
                'bg_secondary': burp_theme.get_color('bg_secondary'), 
                'fg_primary': burp_theme.get_color('fg_primary'),
                'fg_secondary': burp_theme.get_color('fg_secondary'),
                'fg_accent': burp_theme.get_color('fg_accent'),
                'button_bg': burp_theme.get_color('button_bg'),
                'button_fg': burp_theme.get_color('button_fg'),
                'success': burp_theme.get_color('success'),
                'warning': burp_theme.get_color('warning'),
                'danger': burp_theme.get_color('danger'),
                'info': burp_theme.get_color('info')
            }
        else:
            self.theme = None
            self.colors = {
                'bg_primary': 'white',
                'bg_secondary': '#f0f0f0', 
                'fg_primary': 'black',
                'fg_secondary': 'gray',
                'fg_accent': 'black',
                'button_bg': 'lightgray',
                'button_fg': 'black',
                'success': 'green',
                'warning': 'orange',
                'danger': 'red',
                'info': 'blue'
            }
            
        self.crear_widgets()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        # Frame principal con tema
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        
        # Título con tema Burp Suite
        titulo_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill="x", pady=(0, 15))
        
        titulo_label = tk.Label(titulo_frame, text="ESCANEADOR DE VULNERABILIDADES", 
                              font=('Arial', 14, 'bold'),
                              bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo_label.pack()
        
        # Frame de botones con tema
        btn_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
            
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        # Botones con tema Burp Suite
        self.btn_escanear = tk.Button(btn_frame, text="Escanear Sistema", 
                                    command=self.ejecutar_escaneo,
                                    bg=self.colors['fg_accent'], fg='white', 
                                    font=('Arial', 10, 'bold'),
                                    relief='flat', padx=15, pady=8,
                                    activebackground=self.colors['danger'],
                                    activeforeground='white')
        self.btn_escanear.pack(side="left", padx=(0, 10))
        
        self.btn_verificar = tk.Button(btn_frame, text="Verificar Kali", 
                                     command=self.verificar_kali,
                                     bg=self.colors['info'], fg='white', 
                                     font=('Arial', 10, 'bold'),
                                     relief='flat', padx=15, pady=8,
                                     activebackground=self.colors['fg_accent'],
                                     activeforeground='white')
        self.btn_verificar.pack(side="left", padx=(0, 10))
            
        self.btn_cancelar_escaneo = tk.Button(btn_frame, text="Cancelar", 
                                            command=self.cancelar_escaneo,
                                            state="disabled",
                                            bg=self.colors['button_bg'], fg='white',
                                            font=('Arial', 10),
                                            relief='flat', padx=15, pady=8,
                                            activebackground=self.colors['danger'],
                                            activeforeground='white')
        self.btn_cancelar_escaneo.pack(side="left", padx=(0, 15))
        
        self.btn_logs = tk.Button(btn_frame, text="Ver Logs", 
                                command=self.ver_logs,
                                bg=self.colors['button_bg'], fg='white',
                                font=('Arial', 10),
                                relief='flat', padx=15, pady=8,
                                activebackground=self.colors['fg_accent'],
                                activeforeground='white')
        self.btn_logs.pack(side="left", padx=(0, 10))
        
        self.btn_eventos = tk.Button(btn_frame, text="Eventos SIEM", 
                                   command=self.ver_eventos,
                                   bg=self.colors['button_bg'], fg='white',
                                   font=('Arial', 10),
                                   relief='flat', padx=15, pady=8,
                                   activebackground=self.colors['fg_accent'],
                                   activeforeground='white')
        self.btn_eventos.pack(side="left")
        
        # Área de resultados con tema Burp Suite
        self.text_resultados = scrolledtext.ScrolledText(main_frame, height=25,
                                                       bg=self.colors['bg_secondary'], 
                                                       fg=self.colors['fg_primary'],
                                                       font=('Consolas', 10),
                                                       insertbackground=self.colors['fg_accent'],
                                                       selectbackground=self.colors['fg_accent'],
                                                       relief='flat', bd=1)
        
        self.text_resultados.pack(fill="both", expand=True)
    
    def ejecutar_escaneo(self):
        """Ejecutar escaneo del sistema."""
        if self.proceso_activo:
            return
            
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de escaneo configurado")
            return
        
        # Limpiar resultados anteriores
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Iniciando escaneo...\n\n")
        
        # Log al terminal integrado
        self._log_terminal("🚀 Iniciando escaneo del sistema", "ESCANEADOR", "INFO")
        
        # Configurar UI para escaneo
        self.proceso_activo = True
        self.btn_escanear.config(state="disabled")
        self.btn_cancelar_escaneo.config(state="normal")
        
        # Ejecutar escaneo en thread separado
        self.thread_escaneo = threading.Thread(target=self._ejecutar_escaneo_async)
        self.thread_escaneo.daemon = True
        self.thread_escaneo.start()
    
    def _log_terminal(self, mensaje, modulo="ESCANEADOR", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")
    
    def _ejecutar_escaneo_async(self):
        """Ejecutar escaneo de forma asíncrona."""
        try:
            if not self.proceso_activo:
                return
            
            # Verificar que el controlador esté configurado
            if not self.controlador:
                self._log_terminal("❌ Error: Controlador no configurado", "ESCANEADOR", "ERROR")
                self.after(0, self._mostrar_error_escaneo, "Controlador de escaneo no configurado")
                return
            
            self._log_terminal("🔍 Verificando herramientas de escaneo", "ESCANEADOR", "INFO")
            
            # Verificar si el método existe
            if not hasattr(self.controlador, 'ejecutar_escaneo_basico'):
                self._log_terminal("❌ Error: Método de escaneo no disponible", "ESCANEADOR", "ERROR")
                self.after(0, self._mostrar_error_escaneo, "Método de escaneo básico no disponible en el controlador")
                return
            
            # Obtener resultados del escaneo
            resultados = self.controlador.ejecutar_escaneo_basico("127.0.0.1")
            
            if not self.proceso_activo:
                return
            
            self._log_terminal("✅ Escaneo completado exitosamente", "ESCANEADOR", "SUCCESS")
            
            # Actualizar UI en el hilo principal
            self.after(0, self._mostrar_resultados_escaneo, resultados)
            
        except Exception as e:
            if self.proceso_activo:  # Solo mostrar error si no fue cancelado
                self._log_terminal(f"❌ Error durante el escaneo: {str(e)}", "ESCANEADOR", "ERROR")
                self.after(0, self._mostrar_error_escaneo, str(e))
        finally:
            self.after(0, self._finalizar_escaneo)
    
    def _mostrar_resultados_escaneo(self, resultados):
        """Mostrar resultados en la UI y en el terminal integrado."""
        if not self.proceso_activo:
            return
        
        # Log detallado en el terminal integrado
        self._log_terminal("📊 Mostrando resultados del escaneo", "ESCANEADOR", "INFO")
        
        # Mostrar en la UI tradicional
        self.text_resultados.insert(tk.END, "=== PUERTOS ===\n")
        puertos_encontrados = resultados.get('puertos', [])
        for linea in puertos_encontrados:
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        # Log de puertos al terminal integrado
        if puertos_encontrados:
            self._log_terminal(f"🔌 Encontrados {len(puertos_encontrados)} puertos", "ESCANEADOR", "SUCCESS")
            for puerto in puertos_encontrados[:3]:  # Mostrar solo los primeros 3
                self._log_terminal(f"  └─ {puerto}", "ESCANEADOR", "INFO")
        else:
            self._log_terminal("🔌 No se encontraron puertos activos", "ESCANEADOR", "INFO")
        
        self.text_resultados.insert(tk.END, "\n=== PROCESOS ===\n")
        procesos_encontrados = resultados.get('procesos', [])[:10]  # Mostrar solo 10
        for linea in procesos_encontrados:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de procesos al terminal integrado
        if procesos_encontrados:
            self._log_terminal(f"⚙️ Encontrados {len(procesos_encontrados)} procesos", "ESCANEADOR", "SUCCESS")
        
        self.text_resultados.insert(tk.END, "\n=== ANÁLISIS ===\n")
        analisis = resultados.get('análisis', [])
        for linea in analisis:
            self.text_resultados.insert(tk.END, f"{linea}\n")
            
        # Log de análisis al terminal integrado
        if analisis:
            self._log_terminal(f"🔍 Análisis completado: {len(analisis)} elementos", "ESCANEADOR", "SUCCESS")
            
        # Resumen final en terminal integrado
        total_elementos = len(puertos_encontrados) + len(procesos_encontrados) + len(analisis)
        self._log_terminal(f"✅ Escaneo finalizado: {total_elementos} elementos analizados", "ESCANEADOR", "SUCCESS")
    
    def _mostrar_error_escaneo(self, error):
        """Mostrar error en la UI."""
        self.text_resultados.insert(tk.END, f"\n Error durante el escaneo: {error}\n")
    
    def _finalizar_escaneo(self):
        """Finalizar el proceso de escaneo."""
        self.proceso_activo = False
        self.btn_escanear.config(state="normal")
        self.btn_cancelar_escaneo.config(state="disabled")
        self.thread_escaneo = None
    
    def cancelar_escaneo(self):
        """Cancelar el escaneo en curso."""
        if self.proceso_activo:
            self.proceso_activo = False
            self.text_resultados.insert(tk.END, "\n Escaneo cancelado por el usuario.\n")
    
    def verificar_kali(self):
        """Verificar compatibilidad y funcionalidad en Kali Linux."""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de escaneo configurado")
            return
            
        try:
            self.text_resultados.delete(1.0, tk.END)
            self.text_resultados.insert(tk.END, "=== VERIFICACIÓN KALI LINUX ===\n\n")
            
            # Deshabilitar botón durante verificación
            self.btn_verificar.config(state="disabled")
            
            # Ejecutar verificación a través del controlador
            resultado = self.controlador.verificar_funcionalidad_kali()
            
            # Mostrar resultados
            funcionalidad_ok = resultado.get('funcionalidad_completa', False)
            
            if funcionalidad_ok:
                self.text_resultados.insert(tk.END, " OK VERIFICACIÓN EXITOSA\n\n")
                self.text_resultados.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.text_resultados.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.text_resultados.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                self.text_resultados.insert(tk.END, "=== HERRAMIENTAS DISPONIBLES ===\n")
                for herramienta, estado in resultado.get('herramientas_disponibles', {}).items():
                    disponible = estado.get('disponible', False)
                    permisos = estado.get('permisos_ok', False)
                    icono = "OK" if disponible and permisos else "ERROR"
                    self.text_resultados.insert(tk.END, f"  {icono} {herramienta}\n")
                    
            else:
                self.text_resultados.insert(tk.END, " ERROR VERIFICACIÓN FALLÓ\n\n")
                self.text_resultados.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.text_resultados.insert(tk.END, f"Gestor de Permisos: {'OK' if resultado.get('gestor_permisos') else 'ERROR'}\n")
                self.text_resultados.insert(tk.END, f"Permisos Sudo: {'OK' if resultado.get('permisos_sudo') else 'ERROR'}\n\n")
                
                if resultado.get('recomendaciones'):
                    self.text_resultados.insert(tk.END, "=== RECOMENDACIONES ===\n")
                    for recomendacion in resultado['recomendaciones']:
                        self.text_resultados.insert(tk.END, f"  • {recomendacion}\n")
                
            if resultado.get('error'):
                self.text_resultados.insert(tk.END, f"\nWARNING Error: {resultado['error']}\n")
                
        except Exception as e:
            self.text_resultados.insert(tk.END, f" ERROR Error durante verificación: {str(e)}\n")
        finally:
            # Rehabilitar botón
            self.btn_verificar.config(state="normal")
            self._finalizar_escaneo()
    
    def ver_logs(self):
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Obteniendo logs...\n\n")
        
        try:
            logs = self.controlador.obtener_logs_escaneo()
        except AttributeError:
            logs = []
        for linea in logs:
            self.text_resultados.insert(tk.END, f"{linea}\n")
    
    def ver_eventos(self):
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Eventos SIEM:\n\n")
        
        eventos = self.controlador.obtener_eventos_siem()
        for evento in eventos:
            timestamp = evento.get('timestamp', '')
            if isinstance(timestamp, str):
                timestamp_str = timestamp
            else:
                timestamp_str = str(timestamp)
            self.text_resultados.insert(tk.END, 
                f"[{timestamp_str}] {evento.get('tipo', 'Desconocido')}: {evento.get('descripcion', 'Sin descripción')}\n")


# RESUMEN: Interfaz de escaneo de vulnerabilidades con opciones básicas y avanzadas.
