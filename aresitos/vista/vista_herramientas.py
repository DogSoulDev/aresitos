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
        
        if BURP_THEME_AVAILABLE:
            self.theme = burp_theme
            self.configure(bg='#2b2b2b')
        else:
            self.theme = None
        
        self.crear_interfaz()
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def crear_interfaz(self):
        if self.theme:
            titulo_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            titulo_frame = tk.Frame(self)
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo = tk.Label(titulo_frame, text="Verificacion de Herramientas del Sistema",
                         font=('Arial', 16, 'bold'),
                         bg='#2b2b2b' if self.theme else 'white',
                         fg='#ff6633' if self.theme else 'black')
        titulo.pack()
        
        if self.theme:
            main_frame = tk.Frame(self, bg='#2b2b2b')
        else:
            main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        if self.theme:
            left_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_tools = tk.Label(left_frame, text="Herramientas Disponibles", 
                                 bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_tools.pack(anchor=tk.W, pady=(0, 5))
        else:
            left_frame = ttk.LabelFrame(main_frame, text="Herramientas Disponibles", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.herramientas_text = scrolledtext.ScrolledText(left_frame, height=20, width=50,
                                                          bg='#1e1e1e' if self.theme else 'white',
                                                          fg='white' if self.theme else 'black',
                                                          insertbackground='white' if self.theme else 'black',
                                                          font=('Consolas', 10))
        self.herramientas_text.pack(fill=tk.BOTH, expand=True)
        
        if self.theme:
            right_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_actions = tk.Label(right_frame, text="Acciones", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_actions.pack(anchor=tk.W, pady=(0, 10))
        else:
            right_frame = ttk.LabelFrame(main_frame, text="Acciones", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        if self.theme:
            btn_verificar = tk.Button(right_frame, text="Verificar Herramientas", 
                                    command=self.verificar_herramientas,
                                    bg='#ff6633', fg='white', font=('Arial', 10, 'bold'))
            btn_verificar.pack(fill=tk.X, pady=5)
            
            self.btn_cancelar_verificacion = tk.Button(right_frame, text=" Cancelar", 
                                                      command=self.cancelar_verificacion,
                                                      bg='#cc3333', fg='white', font=('Arial', 10),
                                                      state='disabled')
            self.btn_cancelar_verificacion.pack(fill=tk.X, pady=5)
            
            btn_limpiar = tk.Button(right_frame, text="Limpiar Sistema", 
                                  command=self.limpiar_sistema,
                                  bg='#404040', fg='white', font=('Arial', 10))
            btn_limpiar.pack(fill=tk.X, pady=5)
            
            self.btn_cancelar_limpieza = tk.Button(right_frame, text=" Cancelar", 
                                                  command=self.cancelar_limpieza,
                                                  bg='#cc3333', fg='white', font=('Arial', 10),
                                                  state='disabled')
            self.btn_cancelar_limpieza.pack(fill=tk.X, pady=5)
            
            btn_exportar = tk.Button(right_frame, text="Exportar Lista", 
                                   command=self.exportar_herramientas,
                                   bg='#404040', fg='white', font=('Arial', 10))
            btn_exportar.pack(fill=tk.X, pady=5)
        else:
            ttk.Button(right_frame, text="Verificar Herramientas", 
                      command=self.verificar_herramientas).pack(fill=tk.X, pady=5)
            
            self.btn_cancelar_verificacion = ttk.Button(right_frame, text=" Cancelar", 
                                                       command=self.cancelar_verificacion,
                                                       state='disabled')
            self.btn_cancelar_verificacion.pack(fill=tk.X, pady=5)
            
            ttk.Button(right_frame, text="Limpiar Sistema", 
                      command=self.limpiar_sistema).pack(fill=tk.X, pady=5)
            
            self.btn_cancelar_limpieza = ttk.Button(right_frame, text=" Cancelar", 
                                                   command=self.cancelar_limpieza,
                                                   state='disabled')
            self.btn_cancelar_limpieza.pack(fill=tk.X, pady=5)
            
            ttk.Button(right_frame, text="Exportar Lista", 
                      command=self.exportar_herramientas).pack(fill=tk.X, pady=5)
    
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
