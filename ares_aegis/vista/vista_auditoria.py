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

class VistaAuditoria(tk.Frame):
    
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
        
        titulo = tk.Label(titulo_frame, text="Auditoria y Analisis de Seguridad",
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
            label_results = tk.Label(left_frame, text="Resultados de Auditoria", 
                                   bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_results.pack(anchor=tk.W, pady=(0, 5))
        else:
            left_frame = ttk.LabelFrame(main_frame, text="Resultados de Auditoria", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.auditoria_text = scrolledtext.ScrolledText(left_frame, height=20, width=60,
                                                       bg='#1e1e1e' if self.theme else 'white',
                                                       fg='white' if self.theme else 'black',
                                                       insertbackground='white' if self.theme else 'black',
                                                       font=('Consolas', 10))
        self.auditoria_text.pack(fill=tk.BOTH, expand=True)
        
        if self.theme:
            right_frame = tk.Frame(main_frame, bg='#2b2b2b')
            label_tools = tk.Label(right_frame, text="Herramientas de Auditoria", 
                                 bg='#2b2b2b', fg='#ff6633', font=('Arial', 12, 'bold'))
            label_tools.pack(anchor=tk.W, pady=(0, 10))
        else:
            right_frame = ttk.LabelFrame(main_frame, text="Herramientas de Auditoria", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        if self.theme:
            buttons = [
                ("Ejecutar Lynis", self.ejecutar_lynis, '#ff6633'),
                ("Detectar Rootkits", self.detectar_rootkits, '#404040'),
                ("Analizar Servicios", self.analizar_servicios, '#404040'),
                ("Verificar Permisos", self.verificar_permisos, '#404040'),
                ("Informacion Hardware", self.obtener_info_hardware, '#404040'),
                ("Guardar Resultados", self.guardar_auditoria, '#404040'),
                ("Limpiar Pantalla", self.limpiar_auditoria, '#404040')
            ]
            
            for text, command, bg_color in buttons:
                btn = tk.Button(right_frame, text=text, command=command,
                              bg=bg_color, fg='white', font=('Arial', 10))
                btn.pack(fill=tk.X, pady=2)
        else:
            ttk.Button(right_frame, text="Ejecutar Lynis", 
                      command=self.ejecutar_lynis).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Detectar Rootkits", 
                      command=self.detectar_rootkits).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Analizar Servicios", 
                      command=self.analizar_servicios).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Verificar Permisos", 
                      command=self.verificar_permisos).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Informacion Hardware", 
                      command=self.obtener_info_hardware).pack(fill=tk.X, pady=5)
            ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            ttk.Button(right_frame, text="Guardar Resultados", 
                      command=self.guardar_auditoria).pack(fill=tk.X, pady=5)
            ttk.Button(right_frame, text="Limpiar Pantalla", 
                      command=self.limpiar_auditoria).pack(fill=tk.X, pady=5)
    
    def ejecutar_lynis(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Ejecutando auditoria Lynis en Kali Linux...\n")
                self.auditoria_text.update()
                
                import subprocess
                
                try:
                    resultado = subprocess.run(['lynis', 'audit', 'system'], 
                                             capture_output=True, text=True, timeout=600)
                    if resultado.returncode == 0:
                        self.auditoria_text.insert(tk.END, "✓ Auditoria Lynis completada\n")
                        self.auditoria_text.insert(tk.END, resultado.stdout[-2000:])
                    else:
                        self.auditoria_text.insert(tk.END, f"✗ Error en Lynis: {resultado.stderr}\n")
                except subprocess.TimeoutExpired:
                    self.auditoria_text.insert(tk.END, "⏱ Timeout - auditoria cancelada\n")
                except FileNotFoundError:
                    self.auditoria_text.insert(tk.END, "✗ Lynis no encontrado. Instale con: apt install lynis\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error ejecutando Lynis: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def detectar_rootkits(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Detectando rootkits con rkhunter y chkrootkit...\n")
                self.auditoria_text.update()
                
                import subprocess
                
                herramientas = [
                    (['rkhunter', '--check', '--skip-keypress'], 'rkhunter'),
                    (['chkrootkit'], 'chkrootkit')
                ]
                
                for comando, nombre in herramientas:
                    try:
                        self.auditoria_text.insert(tk.END, f"Ejecutando {nombre}...\n")
                        self.auditoria_text.update()
                        
                        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
                        if resultado.returncode == 0:
                            self.auditoria_text.insert(tk.END, f"✓ {nombre} completado\n")
                            if "INFECTED" in resultado.stdout or "infected" in resultado.stdout:
                                self.auditoria_text.insert(tk.END, "⚠ POSIBLES ROOTKITS DETECTADOS\n")
                            else:
                                self.auditoria_text.insert(tk.END, "✓ No se detectaron rootkits\n")
                        else:
                            self.auditoria_text.insert(tk.END, f"✗ Error en {nombre}\n")
                    except FileNotFoundError:
                        self.auditoria_text.insert(tk.END, f"✗ {nombre} no encontrado\n")
                    except subprocess.TimeoutExpired:
                        self.auditoria_text.insert(tk.END, f"⏱ Timeout en {nombre}\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error detectando rootkits: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_servicios(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Analizando servicios activos en Kali Linux...\n")
                self.auditoria_text.update()
                
                import subprocess
                
                try:
                    resultado = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                             capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self.auditoria_text.insert(tk.END, "✓ Servicios activos:\n\n")
                        lineas = resultado.stdout.split('\n')
                        for linea in lineas[1:21]:
                            if linea.strip() and 'service' in linea:
                                self.auditoria_text.insert(tk.END, f"  {linea}\n")
                        self.auditoria_text.insert(tk.END, "\n... (mostrando primeros 20)\n")
                    else:
                        self.auditoria_text.insert(tk.END, "✗ Error obteniendo servicios\n")
                except Exception as e:
                    self.auditoria_text.insert(tk.END, f"✗ Error: {str(e)}\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error analizando servicios: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_permisos(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Verificando permisos criticos del sistema...\n")
                self.auditoria_text.update()
                
                import subprocess
                import os
                
                rutas_criticas = [
                    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                    '/boot', '/usr/bin/passwd', '/usr/bin/sudo', '/etc/ssh'
                ]
                
                for ruta in rutas_criticas:
                    try:
                        if os.path.exists(ruta):
                            stat_result = os.stat(ruta)
                            permisos = oct(stat_result.st_mode)[-3:]
                            uid = stat_result.st_uid
                            gid = stat_result.st_gid
                            
                            self.auditoria_text.insert(tk.END, 
                                f"{ruta}: {permisos} (uid:{uid}, gid:{gid})\n")
                            
                            if ruta in ['/etc/shadow', '/etc/sudoers'] and permisos != '640':
                                self.auditoria_text.insert(tk.END, "  ⚠ Permisos inusuales\n")
                        else:
                            self.auditoria_text.insert(tk.END, f"{ruta}: No existe\n")
                    except Exception as e:
                        self.auditoria_text.insert(tk.END, f"{ruta}: Error - {str(e)}\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error verificando permisos: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def obtener_info_hardware(self):
        def ejecutar():
            try:
                self.auditoria_text.config(state=tk.NORMAL)
                self.auditoria_text.insert(tk.END, "Obteniendo informacion de hardware del sistema...\n")
                self.auditoria_text.update()
                
                import subprocess
                
                comandos_info = [
                    (['lscpu'], 'CPU'),
                    (['lsmem', '--summary'], 'Memoria'),
                    (['lsblk'], 'Discos'),
                    (['lspci', '-v'], 'PCI'),
                    (['lsusb'], 'USB'),
                    (['dmidecode', '-t', 'system'], 'Sistema')
                ]
                
                for comando, tipo in comandos_info:
                    try:
                        self.auditoria_text.insert(tk.END, f"\n=== {tipo} ===\n")
                        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=30)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.split('\n')[:15]
                            for linea in lineas:
                                if linea.strip():
                                    self.auditoria_text.insert(tk.END, f"{linea}\n")
                        else:
                            self.auditoria_text.insert(tk.END, f"✗ Error obteniendo {tipo}\n")
                    except FileNotFoundError:
                        self.auditoria_text.insert(tk.END, f"✗ Comando {comando[0]} no encontrado\n")
                    except subprocess.TimeoutExpired:
                        self.auditoria_text.insert(tk.END, f"⏱ Timeout en {tipo}\n")
                    except Exception as e:
                        self.auditoria_text.insert(tk.END, f"✗ Error: {str(e)}\n")
                
                self.auditoria_text.insert(tk.END, "\n")
                self.auditoria_text.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Error obteniendo info hardware: {str(e)}")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def guardar_auditoria(self):
        try:
            contenido = self.auditoria_text.get(1.0, tk.END)
            if not contenido.strip():
                messagebox.showwarning("Advertencia", "No hay resultados para guardar")
                return
            
            archivo = filedialog.asksaveasfilename(
                title="Guardar Resultados de Auditoria",
                defaultextension=".txt",
                filetypes=[("Archivo de texto", "*.txt"), ("Todos los archivos", "*.*")]
            )
            
            if archivo:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(contenido)
                messagebox.showinfo("Exito", f"Auditoria guardada en {archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def limpiar_auditoria(self):
        self.auditoria_text.config(state=tk.NORMAL)
        self.auditoria_text.delete(1.0, tk.END)
        self.auditoria_text.config(state=tk.DISABLED)
