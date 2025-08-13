# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading

try:
    from ares_aegis.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientas(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        
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
            
            btn_limpiar = tk.Button(right_frame, text="Limpiar Sistema", 
                                  command=self.limpiar_sistema,
                                  bg='#404040', fg='white', font=('Arial', 10))
            btn_limpiar.pack(fill=tk.X, pady=5)
            
            btn_exportar = tk.Button(right_frame, text="Exportar Lista", 
                                   command=self.exportar_herramientas,
                                   bg='#404040', fg='white', font=('Arial', 10))
            btn_exportar.pack(fill=tk.X, pady=5)
        else:
            ttk.Button(right_frame, text="Verificar Herramientas", 
                      command=self.verificar_herramientas).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Limpiar Sistema", 
                      command=self.limpiar_sistema).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Exportar Lista", 
                      command=self.exportar_herramientas).pack(fill=tk.X, pady=5)
    
    def verificar_herramientas(self):
        def ejecutar_verificacion():
            try:
                self.herramientas_text.config(state=tk.NORMAL)
                self.herramientas_text.delete(1.0, tk.END)
                self.herramientas_text.insert(tk.END, "Verificando herramientas de Kali Linux...\n\n")
                self.herramientas_text.update()
                
                herramientas_kali = [
                    'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'wpscan',
                    'burpsuite', 'metasploit-framework', 'john', 'hashcat',
                    'aircrack-ng', 'reaver', 'hydra', 'medusa', 'ncrack',
                    'wireshark', 'tcpdump', 'ettercap', 'dsniff', 'arpspoof',
                    'lynis', 'rkhunter', 'chkrootkit', 'clamav', 'tripwire'
                ]
                
                import subprocess
                
                for herramienta in herramientas_kali:
                    try:
                        resultado = subprocess.run(['which', herramienta], 
                                                 capture_output=True, text=True)
                        if resultado.returncode == 0:
                            self.herramientas_text.insert(tk.END, f"✓ {herramienta}: {resultado.stdout.strip()}\n")
                        else:
                            self.herramientas_text.insert(tk.END, f"✗ {herramienta}: No encontrado\n")
                    except Exception as e:
                        self.herramientas_text.insert(tk.END, f"✗ {herramienta}: Error - {str(e)}\n")
                
                self.herramientas_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error al verificar herramientas: {str(e)}")
        
        threading.Thread(target=ejecutar_verificacion, daemon=True).start()
    
    def limpiar_sistema(self):
        if messagebox.askyesno("Confirmar", "¿Desea ejecutar la limpieza del sistema de Kali Linux?"):
            def ejecutar_limpieza():
                try:
                    self.herramientas_text.config(state=tk.NORMAL)
                    self.herramientas_text.delete(1.0, tk.END)
                    self.herramientas_text.insert(tk.END, "Ejecutando limpieza del sistema...\n\n")
                    self.herramientas_text.update()
                    
                    import subprocess
                    
                    comandos_limpieza = [
                        (['apt', 'autoremove', '--yes'], 'Eliminando paquetes innecesarios'),
                        (['apt', 'autoclean'], 'Limpiando cache de apt'),
                        (['journalctl', '--vacuum-time=7d'], 'Limpiando logs antiguos'),
                        (['find', '/tmp', '-type', 'f', '-atime', '+7', '-delete'], 'Limpiando archivos temporales')
                    ]
                    
                    for comando, descripcion in comandos_limpieza:
                        self.herramientas_text.insert(tk.END, f"{descripcion}...\n")
                        self.herramientas_text.update()
                        
                        try:
                            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
                            if resultado.returncode == 0:
                                self.herramientas_text.insert(tk.END, "✓ Completado\n\n")
                            else:
                                self.herramientas_text.insert(tk.END, f"✗ Error: {resultado.stderr}\n\n")
                        except Exception as e:
                            self.herramientas_text.insert(tk.END, f"✗ Error: {str(e)}\n\n")
                    
                    self.herramientas_text.insert(tk.END, "Limpieza completada.\n")
                    self.herramientas_text.config(state=tk.DISABLED)
                    messagebox.showinfo("Exito", "Limpieza del sistema completada")
                except Exception as e:
                    messagebox.showerror("Error", f"Error durante la limpieza: {str(e)}")
            
            threading.Thread(target=ejecutar_limpieza, daemon=True).start()
    
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
