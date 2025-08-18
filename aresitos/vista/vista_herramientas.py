# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientas(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
        # Control de procesos
        self.proceso_verificacion_activo = False
        self.proceso_limpieza_activo = False
        self.thread_verificacion = None
        self.thread_limpieza = None
        
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
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        # Frame título con tema
        titulo_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Título con tema Burp Suite
        titulo = tk.Label(titulo_frame, text="Verificacion de Herramientas del Sistema",
                         font=('Arial', 16, 'bold'),
                         bg=self.colors['bg_primary'], fg=self.colors['fg_accent'])
        titulo.pack()
        
        # Frame principal con tema
        main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Frame izquierdo para herramientas con tema
        left_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Label de herramientas con tema
        label_tools = tk.Label(left_frame, text="Herramientas Disponibles", 
                             bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], 
                             font=('Arial', 12, 'bold'))
        label_tools.pack(anchor=tk.W, pady=(0, 5))
        
        # Text widget con tema Burp Suite
        self.herramientas_text = scrolledtext.ScrolledText(left_frame, height=20, width=50,
                                                          bg=self.colors['bg_secondary'],
                                                          fg=self.colors['fg_primary'],
                                                          insertbackground=self.colors['fg_accent'],
                                                          font=('Consolas', 10),
                                                          relief='flat', bd=1)
        self.herramientas_text.pack(fill=tk.BOTH, expand=True)
        
        # Frame derecho para acciones con tema
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Label de acciones con tema
        label_actions = tk.Label(right_frame, text="Acciones", 
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_accent'], 
                               font=('Arial', 12, 'bold'))
        label_actions.pack(anchor=tk.W, pady=(0, 10))
        
        # Botones con tema Burp Suite
        btn_verificar = tk.Button(right_frame, text="Verificar Herramientas", 
                                command=self.verificar_herramientas,
                                bg=self.colors['fg_accent'], fg=self.colors['fg_primary'], 
                                font=('Arial', 10, 'bold'),
                                relief='flat', padx=10, pady=5,
                                activebackground=self.colors['danger'],
                                activeforeground='white')
        btn_verificar.pack(fill=tk.X, pady=5)
        
        self.btn_cancelar_verificacion = tk.Button(right_frame, text=" Cancelar", 
                                                  command=self.cancelar_verificacion,
                                                  bg=self.colors['danger'], fg=self.colors['fg_primary'], 
                                                  font=('Arial', 10),
                                                  relief='flat', padx=10, pady=5,
                                                  state='disabled',
                                                  activebackground=self.colors['fg_accent'],
                                                  activeforeground='white')
        self.btn_cancelar_verificacion.pack(fill=tk.X, pady=5)
        
        # Botón limpiar sistema con tema
        btn_limpiar = tk.Button(right_frame, text="Limpiar Sistema", 
                              command=self.limpiar_sistema,
                              bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], 
                              font=('Arial', 10),
                              relief='flat', padx=10, pady=5,
                              activebackground=self.colors['fg_accent'],
                              activeforeground='white')
        btn_limpiar.pack(fill=tk.X, pady=5)
        
        # Botón cancelar limpieza con tema
        self.btn_cancelar_limpieza = tk.Button(right_frame, text=" Cancelar", 
                                              command=self.cancelar_limpieza,
                                              bg=self.colors['danger'], fg=self.colors['fg_primary'], 
                                              font=('Arial', 10),
                                              relief='flat', padx=10, pady=5,
                                              state='disabled',
                                              activebackground=self.colors['fg_accent'],
                                              activeforeground='white')
        self.btn_cancelar_limpieza.pack(fill=tk.X, pady=5)
        
        # Botón exportar con tema
        btn_exportar = tk.Button(right_frame, text="Exportar Lista", 
                               command=self.exportar_herramientas,
                               bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], 
                               font=('Arial', 10),
                               relief='flat', padx=10, pady=5,
                               activebackground=self.colors['fg_accent'],
                               activeforeground='white')
        btn_exportar.pack(fill=tk.X, pady=5)
    
    def verificar_herramientas(self):
        """Verificar herramientas del sistema."""
        if self.proceso_verificacion_activo:
            messagebox.showwarning("Atención", "Ya hay una verificación en curso.")
            return
        
        # Iniciar proceso
        self.proceso_verificacion_activo = True
        self._habilitar_cancelar_verificacion(True)
        
        # Ejecutar en hilo separado
        self.thread_verificacion = threading.Thread(
            target=self._verificar_herramientas_async,
            daemon=True
        )
        self.thread_verificacion.start()
    
    def _verificar_herramientas_async(self):
        """Verificar herramientas de forma asíncrona."""
        try:
            self.herramientas_text.config(state=tk.NORMAL)
            self.herramientas_text.delete(1.0, tk.END)
            self.herramientas_text.insert(tk.END, " Verificando herramientas de Kali Linux...\n\n")
            self.herramientas_text.update()
            
            herramientas_kali = [
                'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'wpscan',
                'burpsuite', 'metasploit-framework', 'john', 'hashcat',
                'aircrack-ng', 'reaver', 'hydra', 'medusa', 'ncrack',
                'wireshark', 'tcpdump', 'ettercap', 'dsniff', 'arpspoof',
                'lynis', 'rkhunter', 'chkrootkit', 'clamav', 'tripwire'
            ]
            
            import subprocess
            
            for i, herramienta in enumerate(herramientas_kali):
                if not self.proceso_verificacion_activo:
                    return
                
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, text=True, timeout=10)
                    if resultado.returncode == 0:
                        self.herramientas_text.insert(tk.END, f" {herramienta}: {resultado.stdout.strip()}\n")
                    else:
                        self.herramientas_text.insert(tk.END, f" {herramienta}: No encontrado\n")
                except Exception as e:
                    if self.proceso_verificacion_activo:
                        self.herramientas_text.insert(tk.END, f" {herramienta}: Error - {str(e)}\n")
                
                # Actualizar cada 5 herramientas
                if i % 5 == 0:
                    self.herramientas_text.update()
            
            if self.proceso_verificacion_activo:
                self.herramientas_text.insert(tk.END, "\n Verificación completada.\n")
                self.herramientas_text.config(state=tk.DISABLED)
                
        except Exception as e:
            if self.proceso_verificacion_activo:
                messagebox.showerror("Error", f"Error al verificar herramientas: {str(e)}")
        finally:
            if self.proceso_verificacion_activo:
                self._finalizar_proceso_verificacion()
    
    def cancelar_verificacion(self):
        """Cancelar la verificación de herramientas."""
        if self.proceso_verificacion_activo:
            self.proceso_verificacion_activo = False
            self.herramientas_text.config(state=tk.NORMAL)
            self.herramientas_text.insert(tk.END, "\n Verificación cancelada por el usuario.\n")
            self.herramientas_text.config(state=tk.DISABLED)
            self._finalizar_proceso_verificacion()
    
    def _habilitar_cancelar_verificacion(self, habilitar):
        """Habilitar o deshabilitar botón de cancelar verificación."""
        estado = "normal" if habilitar else "disabled"
        if hasattr(self, 'btn_cancelar_verificacion'):
            self.btn_cancelar_verificacion.config(state=estado)
    
    def _finalizar_proceso_verificacion(self):
        """Finalizar proceso de verificación."""
        self.proceso_verificacion_activo = False
        self._habilitar_cancelar_verificacion(False)
        self.thread_verificacion = None
    
    def limpiar_sistema(self):
        """Limpiar sistema con confirmación y cancelación."""
        if self.proceso_limpieza_activo:
            messagebox.showwarning("Atención", "Ya hay una limpieza en curso.")
            return
        
        if messagebox.askyesno("Confirmar", "¿Desea ejecutar la limpieza del sistema de Kali Linux?"):
            # Iniciar proceso
            self.proceso_limpieza_activo = True
            self._habilitar_cancelar_limpieza(True)
            
            # Ejecutar en hilo separado
            self.thread_limpieza = threading.Thread(
                target=self._limpiar_sistema_async,
                daemon=True
            )
            self.thread_limpieza.start()
    
    def _limpiar_sistema_async(self):
        """Limpiar sistema de forma asíncrona."""
        try:
            self.herramientas_text.config(state=tk.NORMAL)
            self.herramientas_text.delete(1.0, tk.END)
            self.herramientas_text.insert(tk.END, " Ejecutando limpieza del sistema...\n\n")
            self.herramientas_text.update()
            
            import subprocess
            
            comandos_limpieza = [
                (['apt', 'autoremove', '--yes'], 'Eliminando paquetes innecesarios'),
                (['apt', 'autoclean'], 'Limpiando cache de apt'),
                (['journalctl', '--vacuum-time=7d'], 'Limpiando logs antiguos'),
                (['find', '/tmp', '-type', 'f', '-atime', '+7', '-delete'], 'Limpiando archivos temporales')
            ]
            
            for i, (comando, descripcion) in enumerate(comandos_limpieza):
                if not self.proceso_limpieza_activo:
                    return
                
                self.herramientas_text.insert(tk.END, f"{descripcion}...\n")
                self.herramientas_text.update()
                
                try:
                    # Crear proceso que se pueda terminar
                    proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, text=True)
                    
                    # Verificar cancelación mientras se ejecuta
                    while proceso.poll() is None:
                        if not self.proceso_limpieza_activo:
                            proceso.terminate()
                            proceso.wait(timeout=5)
                            return
                        time.sleep(0.5)
                    
                    stdout, stderr = proceso.communicate()
                    
                    if self.proceso_limpieza_activo:
                        if proceso.returncode == 0:
                            self.herramientas_text.insert(tk.END, " Completado\n\n")
                        else:
                            self.herramientas_text.insert(tk.END, f" Error: {stderr}\n\n")
                        
                except Exception as e:
                    if self.proceso_limpieza_activo:
                        self.herramientas_text.insert(tk.END, f" Error: {str(e)}\n\n")
            
            if self.proceso_limpieza_activo:
                self.herramientas_text.insert(tk.END, " Limpieza completada.\n")
                self.herramientas_text.config(state=tk.DISABLED)
                messagebox.showinfo("Éxito", "Limpieza del sistema completada")
                
        except Exception as e:
            if self.proceso_limpieza_activo:
                messagebox.showerror("Error", f"Error durante la limpieza: {str(e)}")
        finally:
            if self.proceso_limpieza_activo:
                self._finalizar_proceso_limpieza()
    
    def cancelar_limpieza(self):
        """Cancelar la limpieza del sistema."""
        if self.proceso_limpieza_activo:
            self.proceso_limpieza_activo = False
            self.herramientas_text.config(state=tk.NORMAL)
            self.herramientas_text.insert(tk.END, "\n Limpieza cancelada por el usuario.\n")
            self.herramientas_text.config(state=tk.DISABLED)
            self._finalizar_proceso_limpieza()
    
    def _habilitar_cancelar_limpieza(self, habilitar):
        """Habilitar o deshabilitar botón de cancelar limpieza."""
        estado = "normal" if habilitar else "disabled"
        if hasattr(self, 'btn_cancelar_limpieza'):
            self.btn_cancelar_limpieza.config(state=estado)
    
    def _finalizar_proceso_limpieza(self):
        """Finalizar proceso de limpieza."""
        self.proceso_limpieza_activo = False
        self._habilitar_cancelar_limpieza(False)
        self.thread_limpieza = None
    
    def exportar_herramientas(self):
        try:
            contenido = self.herramientas_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay datos para exportar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Exportar Lista de Herramientas",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(contenido)
                messagebox.showinfo("Exito", f"Lista exportada a {archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar: {str(e)}")
