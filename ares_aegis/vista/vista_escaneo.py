# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

try:
    from ares_aegis.vista.burp_theme import burp_theme
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
        
        # Aplicar tema Burp Suite si está disponible
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg='#2b2b2b')
        else:
            self.theme = None
            
        self.crear_widgets()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_widgets(self):
        # Frame principal con tema
        if self.theme:
            main_frame = tk.Frame(self, bg='#2b2b2b')
            
            # Título
            titulo_frame = tk.Frame(main_frame, bg='#2b2b2b')
            titulo_frame.pack(fill="x", pady=(0, 15))
            
            titulo_label = tk.Label(titulo_frame, text="🔍 ESCANEADOR DE VULNERABILIDADES", 
                                  font=('Arial', 14, 'bold'),
                                  bg='#2b2b2b', fg='#ff6633')
            titulo_label.pack()
            
            # Frame de botones con tema
            btn_frame = tk.Frame(main_frame, bg='#2b2b2b')
        else:
            main_frame = ttk.Frame(self)
            btn_frame = ttk.Frame(main_frame)
            
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        # Botones con tema Burp Suite
        if self.theme:
            self.btn_escanear = tk.Button(btn_frame, text="🔍 Escanear Sistema", 
                                        command=self.ejecutar_escaneo,
                                        bg='#ff6633', fg='white', 
                                        font=('Arial', 10, 'bold'),
                                        relief='flat', bd=0, padx=15, pady=8,
                                        activebackground='#e55a2b', activeforeground='white')
            self.btn_escanear.pack(side="left", padx=(0, 10))
            
            self.btn_cancelar_escaneo = tk.Button(btn_frame, text="❌ Cancelar", 
                                                command=self.cancelar_escaneo,
                                                state="disabled",
                                                bg='#404040', fg='white',
                                                font=('Arial', 10),
                                                relief='flat', bd=0, padx=15, pady=8,
                                                activebackground='#505050', activeforeground='white')
            self.btn_cancelar_escaneo.pack(side="left", padx=(0, 15))
            
            self.btn_logs = tk.Button(btn_frame, text="📋 Ver Logs", 
                                    command=self.ver_logs,
                                    bg='#404040', fg='white',
                                    font=('Arial', 10),
                                    relief='flat', bd=0, padx=15, pady=8,
                                    activebackground='#505050', activeforeground='white')
            self.btn_logs.pack(side="left", padx=(0, 10))
            
            self.btn_eventos = tk.Button(btn_frame, text="🚨 Eventos SIEM", 
                                       command=self.ver_eventos,
                                       bg='#404040', fg='white',
                                       font=('Arial', 10),
                                       relief='flat', bd=0, padx=15, pady=8,
                                       activebackground='#505050', activeforeground='white')
            self.btn_eventos.pack(side="left")
            
            # Área de resultados con tema
            self.text_resultados = scrolledtext.ScrolledText(main_frame, height=25,
                                                           bg='#1e1e1e', fg='#ffffff',
                                                           font=('Consolas', 10),
                                                           insertbackground='#ff6633',
                                                           selectbackground='#404040')
        else:
            # Botones estándar sin tema
            self.btn_escanear = ttk.Button(btn_frame, text="Escanear Sistema", 
                                          command=self.ejecutar_escaneo)
            self.btn_escanear.pack(side="left", padx=(0, 5))
            
            self.btn_cancelar_escaneo = ttk.Button(btn_frame, text="❌ Cancelar", 
                                                  command=self.cancelar_escaneo,
                                                  state="disabled")
            self.btn_cancelar_escaneo.pack(side="left", padx=(0, 15))
            
            self.btn_logs = ttk.Button(btn_frame, text="Ver Logs", 
                                      command=self.ver_logs)
            self.btn_logs.pack(side="left", padx=(0, 5))
            
            self.btn_eventos = ttk.Button(btn_frame, text="Eventos SIEM", 
                                         command=self.ver_eventos)
            self.btn_eventos.pack(side="left")
            
            self.text_resultados = scrolledtext.ScrolledText(main_frame, height=28)
        
        self.text_resultados.pack(fill="both", expand=True)
    
    def ejecutar_escaneo(self):
        if not self.controlador:
            messagebox.showwarning("Advertencia", 
                                 "El controlador de escaneo no está configurado.\n"
                                 "Por favor, reinicie la aplicación.")
            return
        
        if self.proceso_activo:
            messagebox.showwarning("Advertencia", "Ya hay un escaneo en curso.")
            return
            
        self.proceso_activo = True
        self.btn_escanear.config(state="disabled")
        self.btn_cancelar_escaneo.config(state="normal")
        
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "🔄 Iniciando escaneo...\n\n")
        
        # Ejecutar escaneo en thread separado
        import threading
        self.thread_escaneo = threading.Thread(target=self._ejecutar_escaneo_async)
        self.thread_escaneo.daemon = True
        self.thread_escaneo.start()
    
    def _ejecutar_escaneo_async(self):
        """Ejecutar escaneo en thread separado."""
        try:
            # Verificar que el controlador esté configurado
            if not self.controlador:
                self.after(0, self._mostrar_error_escaneo, "Controlador de escaneo no configurado")
                return
            
            resultados = self.controlador.ejecutar_escaneo_basico()
            
            if not self.proceso_activo:  # Verificar si fue cancelado
                return
            
            # Actualizar UI en el hilo principal
            self.after(0, self._mostrar_resultados_escaneo, resultados)
            
        except Exception as e:
            if self.proceso_activo:  # Solo mostrar error si no fue cancelado
                self.after(0, self._mostrar_error_escaneo, str(e))
        finally:
            self.after(0, self._finalizar_escaneo)
    
    def _mostrar_resultados_escaneo(self, resultados):
        """Mostrar resultados en la UI."""
        if not self.proceso_activo:
            return
            
        self.text_resultados.insert(tk.END, "=== PUERTOS ===\n")
        for linea in resultados.get('puertos', []):
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        self.text_resultados.insert(tk.END, "\n=== PROCESOS ===\n")
        for linea in resultados.get('procesos', [])[:10]:  # Mostrar solo 10
            self.text_resultados.insert(tk.END, f"{linea}\n")
        
        self.text_resultados.insert(tk.END, "\n=== ANÁLISIS ===\n")
        for linea in resultados.get('analisis', []):
            self.text_resultados.insert(tk.END, f"{linea}\n")
    
    def _mostrar_error_escaneo(self, error):
        """Mostrar error en la UI."""
        self.text_resultados.insert(tk.END, f"\n❌ Error durante el escaneo: {error}\n")
    
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
            self.text_resultados.insert(tk.END, "\n⚠️ Escaneo cancelado por el usuario.\n")
            self._finalizar_escaneo()
    
    def ver_logs(self):
        if not self.controlador:
            return
            
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "Obteniendo logs...\n\n")
        
        logs = self.controlador.obtener_logs()
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