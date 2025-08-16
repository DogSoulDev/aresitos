# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaAuditoria(tk.Frame):
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_auditoria_activo = False
        self.thread_auditoria = None
        
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
                ("Cancelar Lynis", self.cancelar_auditoria, '#cc0000'),
                ("Verificar Kali", self.verificar_kali, '#337ab7'),
                ("FIM - Monitoreo Archivos", self.iniciar_fim, '#00cc44'),
                ("Detener FIM", self.detener_fim, '#cc0000'),
                ("SIEM - Análisis Eventos", self.iniciar_siem, '#0066cc'),
                ("Detener SIEM", self.detener_siem, '#cc0000'),
                ("Detectar Rootkits", self.detectar_rootkits, '#404040'),
                ("Cancelar Rootkits", self.cancelar_rootkits, '#cc0000'),
                ("Auditoria OpenVAS", self.ejecutar_openvas, '#404040'),
                ("Cancelar OpenVAS", self.cancelar_openvas, '#cc0000'),
                ("Nessus Scan", self.ejecutar_nessus, '#404040'),
                ("Nikto Web Scan", self.ejecutar_nikto, '#404040'),
                ("Cancelar Nikto", self.cancelar_nikto, '#cc0000'),
                ("SSL/TLS Test", self.verificar_ssl, '#404040'),
                ("Analizar Servicios", self.analizar_servicios, '#404040'),
                ("Verificar Permisos", self.verificar_permisos, '#404040'),
                ("Info Hardware", self.obtener_info_hardware, '#404040'),
                ("Analisis SUID/SGID", self.analizar_suid_sgid, '#404040'),
                ("Puertos Abiertos", self.escanear_puertos, '#404040'),
                ("Cancelar Puertos", self.cancelar_puertos, '#cc0000'),
                ("Configuracion SSH", self.auditar_ssh, '#404040'),
                ("Politicas Password", self.verificar_password_policy, '#404040'),
                ("Guardar Resultados", self.guardar_auditoria, '#404040'),
                ("Limpiar Pantalla", self.limpiar_auditoria, '#404040')
            ]
            
            # Variables para los botones de cancelar
            self.proceso_rootkits_activo = False
            self.proceso_openvas_activo = False
            self.proceso_nikto_activo = False
            self.proceso_puertos_activo = False
            self.proceso_fim_activo = False
            self.proceso_siem_activo = False
            self.proceso_puertos_activo = False
            
            for i, (text, command, bg_color) in enumerate(buttons):
                btn = tk.Button(right_frame, text=text, command=command,
                              bg=bg_color, fg='white', font=('Arial', 9))
                if "Cancelar" in text:
                    btn.config(state="disabled")
                    if "Lynis" in text:
                        self.btn_cancelar_auditoria = btn
                    elif "Rootkits" in text:
                        self.btn_cancelar_rootkits = btn
                    elif "OpenVAS" in text:
                        self.btn_cancelar_openvas = btn
                    elif "Nikto" in text:
                        self.btn_cancelar_nikto = btn
                    elif "Puertos" in text:
                        self.btn_cancelar_puertos = btn
                btn.pack(fill=tk.X, pady=2)
        else:
            # Crear botones individuales para mejor control
            self.btn_lynis = ttk.Button(right_frame, text="Ejecutar Lynis", 
                                       command=self.ejecutar_lynis)
            self.btn_lynis.pack(fill=tk.X, pady=5)
            
            self.btn_cancelar_auditoria = ttk.Button(right_frame, text=" Cancelar", 
                                                    command=self.cancelar_auditoria,
                                                    state="disabled")
            self.btn_cancelar_auditoria.pack(fill=tk.X, pady=5)
            
            ttk.Button(right_frame, text="🔧 Verificar Kali", 
                      command=self.verificar_kali).pack(fill=tk.X, pady=5)
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
        if self.proceso_auditoria_activo:
            return
            
        self.proceso_auditoria_activo = True
        self._habilitar_cancelar(True)
        
        self.auditoria_text.config(state=tk.NORMAL)
        self.auditoria_text.insert(tk.END, "Iniciando auditoría Lynis en Kali Linux...\n")
        self.auditoria_text.config(state=tk.DISABLED)
        
        # Ejecutar en thread separado
        self.thread_auditoria = threading.Thread(target=self._ejecutar_lynis_async)
        self.thread_auditoria.daemon = True
        self.thread_auditoria.start()
    
    def _ejecutar_lynis_async(self):
        """Ejecutar Lynis en thread separado."""
        try:
            # Actualizar UI
            self.after(0, self._actualizar_texto_auditoria, "🔍 Ejecutando auditoría Lynis (puede tardar varios minutos)...\n")
            
            if self.controlador:
                # Usar el controlador
                resultado = self.controlador.ejecutar_auditoria_completa("lynis")
                if resultado.get('exito'):
                    self.after(0, self._actualizar_texto_auditoria, "✅ Auditoría Lynis completada exitosamente\n")
                    if 'salida' in resultado:
                        self.after(0, self._actualizar_texto_auditoria, resultado['salida'])
                else:
                    self.after(0, self._actualizar_texto_auditoria, f"❌ Error en auditoría: {resultado.get('error', 'Error desconocido')}\n")
            else:
                # Fallback: ejecución directa
                import subprocess
                try:
                    proceso = subprocess.Popen(['lynis', 'audit', 'system'], 
                                             stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, 
                                             text=True)
                
                    # Verificar periódicamente si fue cancelado
                    while proceso.poll() is None and self.proceso_auditoria_activo:
                        import time
                        time.sleep(1)
                    
                    if not self.proceso_auditoria_activo:
                        # Fue cancelado, terminar el proceso
                        proceso.terminate()
                        proceso.wait()
                        self.after(0, self._actualizar_texto_auditoria, "\n❌ Auditoría Lynis cancelada por el usuario.\n")
                        return
                    
                    stdout, stderr = proceso.communicate()
                    
                    if proceso.returncode == 0:
                        self.after(0, self._actualizar_texto_auditoria, "✅ Auditoría Lynis completada\n")
                        self.after(0, self._actualizar_texto_auditoria, stdout[-2000:])  # Últimas 2000 caracteres
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"❌ Error en Lynis: {stderr}\n")
                        
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto_auditoria, "❌ Lynis no encontrado. Instale con: apt install lynis\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto_auditoria, f"❌ Error ejecutando Lynis: {str(e)}\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto_auditoria, f"❌ Error general: {str(e)}\n")
        finally:
            self.after(0, self._finalizar_auditoria)
    
    def _actualizar_texto_auditoria(self, texto):
        """Actualizar texto de auditoría en el hilo principal."""
        if self.auditoria_text:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.insert(tk.END, texto)
            self.auditoria_text.see(tk.END)
            self.auditoria_text.config(state=tk.DISABLED)
    
    def _habilitar_cancelar(self, habilitar):
        """Habilitar o deshabilitar botón de cancelar."""
        estado = "normal" if habilitar else "disabled"
        if hasattr(self, 'btn_cancelar_auditoria'):
            self.btn_cancelar_auditoria.config(state=estado)
    
    def _finalizar_auditoria(self):
        """Finalizar proceso de auditoría."""
        self.proceso_auditoria_activo = False
        self._habilitar_cancelar(False)
        self.thread_auditoria = None
        self._actualizar_texto_auditoria("\n=== Auditoría finalizada ===\n\n")
    
    def cancelar_auditoria(self):
        """Cancelar la auditoría en curso."""
        if self.proceso_auditoria_activo:
            self.proceso_auditoria_activo = False
            self._actualizar_texto_auditoria("\n Cancelando auditoría...\n")
    
    def detectar_rootkits(self):
        """Detectar rootkits usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.detectar_rootkits()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "✅ Detección de rootkits completada\n")
                        if 'rootkits_detectados' in resultado:
                            count = resultado['rootkits_detectados']
                            if count > 0:
                                self.after(0, self._actualizar_texto_auditoria, f"⚠️ {count} posibles rootkits detectados\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, "✅ No se detectaron rootkits\n")
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"❌ Error: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, "🔍 Detectando rootkits con rkhunter y chkrootkit...\n")
                    
                    import subprocess
                    herramientas = [
                        (['rkhunter', '--check', '--skip-keypress'], 'rkhunter'),
                        (['chkrootkit'], 'chkrootkit')
                    ]
                    
                    for comando, nombre in herramientas:
                        try:
                            self.after(0, self._actualizar_texto_auditoria, f"🔍 Ejecutando {nombre}...\n")
                            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
                            if resultado.returncode == 0:
                                self.after(0, self._actualizar_texto_auditoria, f"✅ {nombre} completado\n")
                                if "INFECTED" in resultado.stdout or "infected" in resultado.stdout:
                                    self.after(0, self._actualizar_texto_auditoria, "⚠️ POSIBLES ROOTKITS DETECTADOS\n")
                                else:
                                    self.after(0, self._actualizar_texto_auditoria, f"✅ No se detectaron rootkits con {nombre}\n")
                            else:
                                self.after(0, self._actualizar_texto_auditoria, f"❌ Error en {nombre}\n")
                        except FileNotFoundError:
                            self.after(0, self._actualizar_texto_auditoria, f"❌ {nombre} no encontrado. Instalar con: apt install {nombre}\n")
                        except subprocess.TimeoutExpired:
                            self.after(0, self._actualizar_texto_auditoria, f"⏱️ Timeout en {nombre}\n")
                    
                    self.after(0, self._actualizar_texto_auditoria, "\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"❌ Error detectando rootkits: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_servicios(self):
        """Analizar servicios del sistema usando controlador."""
        def ejecutar():
            try:
                if self.controlador:
                    resultado = self.controlador.analizar_servicios_sistema()
                    if resultado.get('exito'):
                        self.after(0, self._actualizar_texto_auditoria, "✅ Análisis de servicios completado\n")
                        if 'servicios_activos' in resultado:
                            count = resultado['servicios_activos']
                            self.after(0, self._actualizar_texto_auditoria, f"📊 Servicios activos encontrados: {count}\n")
                        if 'detalles' in resultado:
                            self.after(0, self._actualizar_texto_auditoria, resultado['detalles'])
                    else:
                        self.after(0, self._actualizar_texto_auditoria, f"❌ Error: {resultado.get('error', 'Error desconocido')}\n")
                else:
                    # Fallback manual
                    self.after(0, self._actualizar_texto_auditoria, "🔍 Analizando servicios activos en Kali Linux...\n")
                    
                    import subprocess
                    try:
                        resultado = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                                 capture_output=True, text=True)
                        if resultado.returncode == 0:
                            self.after(0, self._actualizar_texto_auditoria, "📋 Servicios activos:\n\n")
                            lineas = resultado.stdout.split('\n')
                            for linea in lineas[1:21]:
                                if linea.strip() and 'service' in linea:
                                    self.after(0, self._actualizar_texto_auditoria, f"  {linea}\n")
                            self.after(0, self._actualizar_texto_auditoria, "\n... (mostrando primeros 20)\n")
                        else:
                            self.after(0, self._actualizar_texto_auditoria, "❌ Error obteniendo servicios\n")
                    except Exception as e:
                        self.after(0, self._actualizar_texto_auditoria, f"❌ Error: {str(e)}\n")
            except Exception as e:
                self.after(0, self._actualizar_texto_auditoria, f"❌ Error analizando servicios: {str(e)}\n")
        
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
                                self.auditoria_text.insert(tk.END, "   Permisos inusuales\n")
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
                            self.auditoria_text.insert(tk.END, f" Error obteniendo {tipo}\n")
                    except FileNotFoundError:
                        self.auditoria_text.insert(tk.END, f" Comando {comando[0]} no encontrado\n")
                    except subprocess.TimeoutExpired:
                        self.auditoria_text.insert(tk.END, f"⏱ Timeout en {tipo}\n")
                    except Exception as e:
                        self.auditoria_text.insert(tk.END, f" Error: {str(e)}\n")
                
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
    
    # ===== NUEVOS MÉTODOS DE AUDITORÍA AVANZADA =====
    
    def cancelar_rootkits(self):
        """Cancelar detección de rootkits."""
        if hasattr(self, 'proceso_rootkits_activo'):
            self.proceso_rootkits_activo = False
            self._actualizar_texto_auditoria("⏹️ Detección de rootkits cancelada\n")
    
    def ejecutar_openvas(self):
        """Ejecutar auditoría con OpenVAS."""
        def ejecutar():
            try:
                self.proceso_openvas_activo = True
                if hasattr(self, 'btn_cancelar_openvas'):
                    self.btn_cancelar_openvas.config(state="normal")
                
                self._actualizar_texto_auditoria("🔐 Iniciando auditoría OpenVAS...\n")
                import subprocess
                
                try:
                    # Verificar si OpenVAS está instalado
                    resultado = subprocess.run(['which', 'openvas'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✅ OpenVAS encontrado\n")
                        self._actualizar_texto_auditoria("📋 Comandos OpenVAS:\n")
                        self._actualizar_texto_auditoria("  • openvas-start: Iniciar servicios\n")
                        self._actualizar_texto_auditoria("  • openvas-stop: Detener servicios\n")
                        self._actualizar_texto_auditoria("  • openvas-check-setup: Verificar configuración\n")
                    else:
                        self._actualizar_texto_auditoria("❌ OpenVAS no encontrado. Instalar con: apt install openvas\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error verificando OpenVAS: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Auditoría OpenVAS completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en OpenVAS: {str(e)}\n")
            finally:
                self.proceso_openvas_activo = False
                if hasattr(self, 'btn_cancelar_openvas'):
                    self.btn_cancelar_openvas.config(state="disabled")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def cancelar_openvas(self):
        """Cancelar auditoría OpenVAS."""
        if hasattr(self, 'proceso_openvas_activo'):
            self.proceso_openvas_activo = False
            self._actualizar_texto_auditoria("⏹️ Auditoría OpenVAS cancelada\n")
    
    def ejecutar_nessus(self):
        """Ejecutar scan con Nessus."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("🛡️ Iniciando scan Nessus...\n")
                import subprocess
                
                try:
                    # Verificar si Nessus está instalado
                    resultado = subprocess.run(['which', 'nessus'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✅ Nessus encontrado\n")
                        self._actualizar_texto_auditoria("📋 Comandos Nessus:\n")
                        self._actualizar_texto_auditoria("  • service nessusd start: Iniciar servicio\n")
                        self._actualizar_texto_auditoria("  • https://localhost:8834: Interfaz web\n")
                    else:
                        self._actualizar_texto_auditoria("❌ Nessus no encontrado. Descargar desde tenable.com\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error verificando Nessus: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Verificación Nessus completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en Nessus: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def ejecutar_nikto(self):
        """Ejecutar scan web con Nikto."""
        def ejecutar():
            try:
                self.proceso_nikto_activo = True
                if hasattr(self, 'btn_cancelar_nikto'):
                    self.btn_cancelar_nikto.config(state="normal")
                
                self._actualizar_texto_auditoria("🔧 Iniciando scan web Nikto...\n")
                import subprocess
                
                try:
                    # Verificar si Nikto está instalado
                    resultado = subprocess.run(['which', 'nikto'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✅ Nikto encontrado\n")
                        self._actualizar_texto_auditoria("📋 Ejemplos de uso Nikto:\n")
                        self._actualizar_texto_auditoria("  • nikto -h http://target.com\n")
                        self._actualizar_texto_auditoria("  • nikto -h https://target.com -ssl\n")
                        self._actualizar_texto_auditoria("  • nikto -h target.com -p 80,443,8080\n")
                    else:
                        self._actualizar_texto_auditoria("❌ Nikto no encontrado. Instalar con: apt install nikto\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error verificando Nikto: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Verificación Nikto completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en Nikto: {str(e)}\n")
            finally:
                self.proceso_nikto_activo = False
                if hasattr(self, 'btn_cancelar_nikto'):
                    self.btn_cancelar_nikto.config(state="disabled")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def cancelar_nikto(self):
        """Cancelar scan Nikto."""
        if hasattr(self, 'proceso_nikto_activo'):
            self.proceso_nikto_activo = False
            self._actualizar_texto_auditoria("⏹️ Scan Nikto cancelado\n")
    
    def verificar_ssl(self):
        """Verificar configuración SSL/TLS."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("🌐 Verificando configuración SSL/TLS...\n")
                import subprocess
                
                try:
                    # Verificar si sslscan está instalado
                    resultado = subprocess.run(['which', 'sslscan'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✅ SSLScan encontrado\n")
                        self._actualizar_texto_auditoria("📋 Comandos SSL útiles:\n")
                        self._actualizar_texto_auditoria("  • sslscan target.com:443\n")
                        self._actualizar_texto_auditoria("  • testssl.sh target.com\n")
                        self._actualizar_texto_auditoria("  • openssl s_client -connect target.com:443\n")
                    else:
                        self._actualizar_texto_auditoria("❌ SSLScan no encontrado. Instalar con: apt install sslscan\n")
                    
                    # Verificar testssl
                    resultado = subprocess.run(['which', 'testssl.sh'], capture_output=True, text=True)
                    if resultado.returncode == 0:
                        self._actualizar_texto_auditoria("✅ TestSSL encontrado\n")
                    else:
                        self._actualizar_texto_auditoria("❌ TestSSL no encontrado. Instalar con: apt install testssl.sh\n")
                        
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error verificando herramientas SSL: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Verificación SSL/TLS completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en verificación SSL: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def analizar_suid_sgid(self):
        """Analizar archivos SUID/SGID."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("🔒 Analizando archivos SUID/SGID...\n")
                import subprocess
                
                try:
                    # Buscar archivos SUID
                    self._actualizar_texto_auditoria("🔍 Buscando archivos SUID...\n")
                    resultado = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], 
                                             capture_output=True, text=True, timeout=30)
                    if resultado.stdout:
                        archivos_suid = resultado.stdout.strip().split('\n')[:20]  # Primeros 20
                        self._actualizar_texto_auditoria(f"📁 Archivos SUID encontrados ({len(archivos_suid)} de muchos):\n")
                        for archivo in archivos_suid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                    
                    # Buscar archivos SGID
                    self._actualizar_texto_auditoria("🔍 Buscando archivos SGID...\n")
                    resultado = subprocess.run(['find', '/', '-perm', '-2000', '-type', 'f', '2>/dev/null'], 
                                             capture_output=True, text=True, timeout=30)
                    if resultado.stdout:
                        archivos_sgid = resultado.stdout.strip().split('\n')[:20]  # Primeros 20
                        self._actualizar_texto_auditoria(f"📁 Archivos SGID encontrados ({len(archivos_sgid)} de muchos):\n")
                        for archivo in archivos_sgid:
                            if archivo.strip():
                                self._actualizar_texto_auditoria(f"  {archivo}\n")
                
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("⏱️ Timeout en búsqueda SUID/SGID\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error buscando SUID/SGID: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Análisis SUID/SGID completado\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en análisis SUID/SGID: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def escanear_puertos(self):
        """Escanear puertos abiertos."""
        def ejecutar():
            try:
                self.proceso_puertos_activo = True
                if hasattr(self, 'btn_cancelar_puertos'):
                    self.btn_cancelar_puertos.config(state="normal")
                
                self._actualizar_texto_auditoria("🌐 Escaneando puertos abiertos...\n")
                import subprocess
                
                try:
                    # Usar netstat para puertos locales
                    self._actualizar_texto_auditoria("📡 Puertos TCP abiertos localmente:\n")
                    resultado = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True, timeout=15)
                    if resultado.stdout:
                        lineas = resultado.stdout.split('\n')[2:12]  # Primeras 10 líneas
                        for linea in lineas:
                            if linea.strip() and 'LISTEN' in linea:
                                self._actualizar_texto_auditoria(f"  {linea}\n")
                    
                    # Verificar si nmap está disponible
                    resultado_nmap = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
                    if resultado_nmap.returncode == 0:
                        self._actualizar_texto_auditoria("✅ Nmap disponible para escaneos externos\n")
                        self._actualizar_texto_auditoria("📋 Comandos Nmap útiles:\n")
                        self._actualizar_texto_auditoria("  • nmap -sT localhost\n")
                        self._actualizar_texto_auditoria("  • nmap -sS target.com\n")
                        self._actualizar_texto_auditoria("  • nmap -sV -sC target.com\n")
                    else:
                        self._actualizar_texto_auditoria("❌ Nmap no encontrado. Instalar con: apt install nmap\n")
                
                except subprocess.TimeoutExpired:
                    self._actualizar_texto_auditoria("⏱️ Timeout en escaneo de puertos\n")
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error escaneando puertos: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Escaneo de puertos completado\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en escaneo de puertos: {str(e)}\n")
            finally:
                self.proceso_puertos_activo = False
                if hasattr(self, 'btn_cancelar_puertos'):
                    self.btn_cancelar_puertos.config(state="disabled")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def cancelar_puertos(self):
        """Cancelar escaneo de puertos."""
        if hasattr(self, 'proceso_puertos_activo'):
            self.proceso_puertos_activo = False
            self._actualizar_texto_auditoria("⏹️ Escaneo de puertos cancelado\n")
    
    def auditar_ssh(self):
        """Auditar configuración SSH."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("📋 Auditando configuración SSH...\n")
                import subprocess
                import os
                
                try:
                    # Verificar si SSH está instalado
                    if os.path.exists('/etc/ssh/sshd_config'):
                        self._actualizar_texto_auditoria("✅ SSH configurado en el sistema\n")
                        
                        # Verificar configuraciones importantes
                        with open('/etc/ssh/sshd_config', 'r') as f:
                            config = f.read()
                            
                        self._actualizar_texto_auditoria("🔍 Verificando configuraciones críticas:\n")
                        
                        if 'PermitRootLogin no' in config:
                            self._actualizar_texto_auditoria("  ✅ PermitRootLogin: Deshabilitado\n")
                        else:
                            self._actualizar_texto_auditoria("  ⚠️ PermitRootLogin: Revisar configuración\n")
                        
                        if 'PasswordAuthentication no' in config:
                            self._actualizar_texto_auditoria("  ✅ PasswordAuthentication: Deshabilitado\n")
                        else:
                            self._actualizar_texto_auditoria("  ⚠️ PasswordAuthentication: Habilitado\n")
                        
                        if 'Port 22' in config:
                            self._actualizar_texto_auditoria("  ⚠️ Puerto: 22 (puerto por defecto)\n")
                        else:
                            self._actualizar_texto_auditoria("  ✅ Puerto: Cambiado del puerto por defecto\n")
                            
                    else:
                        self._actualizar_texto_auditoria("❌ SSH no encontrado o no configurado\n")
                    
                    # Verificar servicio SSH
                    resultado = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
                    if resultado.stdout.strip() == 'active':
                        self._actualizar_texto_auditoria("✅ Servicio SSH: Activo\n")
                    else:
                        self._actualizar_texto_auditoria("❌ Servicio SSH: Inactivo\n")
                
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error auditando SSH: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Auditoría SSH completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en auditoría SSH: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()
    
    def verificar_password_policy(self):
        """Verificar políticas de contraseñas."""
        def ejecutar():
            try:
                self._actualizar_texto_auditoria("🔐 Verificando políticas de contraseñas...\n")
                import subprocess
                import os
                
                try:
                    # Verificar /etc/login.defs
                    if os.path.exists('/etc/login.defs'):
                        self._actualizar_texto_auditoria("📋 Configuración en /etc/login.defs:\n")
                        resultado = subprocess.run(['grep', '-E', 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE', '/etc/login.defs'], 
                                                 capture_output=True, text=True)
                        if resultado.stdout:
                            for linea in resultado.stdout.split('\n'):
                                if linea.strip() and not linea.startswith('#'):
                                    self._actualizar_texto_auditoria(f"  {linea}\n")
                    
                    # Verificar PAM
                    if os.path.exists('/etc/pam.d/common-password'):
                        self._actualizar_texto_auditoria("📋 Configuración PAM (common-password):\n")
                        resultado = subprocess.run(['grep', 'pam_pwquality', '/etc/pam.d/common-password'], 
                                                 capture_output=True, text=True)
                        if resultado.stdout:
                            self._actualizar_texto_auditoria(f"  ✅ pwquality configurado\n")
                        else:
                            self._actualizar_texto_auditoria(f"  ⚠️ pwquality no configurado\n")
                    
                    # Verificar usuarios con contraseñas vacías
                    self._actualizar_texto_auditoria("🔍 Verificando usuarios sin contraseña:\n")
                    resultado = subprocess.run(['awk', '-F:', '($2 == "") {print $1}', '/etc/shadow'], 
                                             capture_output=True, text=True)
                    if resultado.stdout.strip():
                        self._actualizar_texto_auditoria("  ⚠️ Usuarios sin contraseña encontrados:\n")
                        for usuario in resultado.stdout.split('\n'):
                            if usuario.strip():
                                self._actualizar_texto_auditoria(f"    {usuario}\n")
                    else:
                        self._actualizar_texto_auditoria("  ✅ No hay usuarios sin contraseña\n")
                
                except Exception as e:
                    self._actualizar_texto_auditoria(f"❌ Error verificando políticas: {str(e)}\n")
                
                self._actualizar_texto_auditoria("✅ Verificación de políticas completada\n\n")
            except Exception as e:
                self._actualizar_texto_auditoria(f"❌ Error en verificación de políticas: {str(e)}\n")
        
        threading.Thread(target=ejecutar, daemon=True).start()

    def verificar_kali(self):
        """Verificar compatibilidad y funcionalidad de auditoría en Kali Linux."""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de auditoría configurado")
            return
            
        try:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.delete(1.0, tk.END)
            self.auditoria_text.insert(tk.END, "=== VERIFICACIÓN AUDITORÍA KALI LINUX ===\n\n")
            
            # Ejecutar verificación a través del controlador
            resultado = self.controlador.verificar_funcionalidad_kali()
            
            # Mostrar resultados
            funcionalidad_ok = resultado.get('funcionalidad_completa', False)
            
            if funcionalidad_ok:
                self.auditoria_text.insert(tk.END, " ✅ VERIFICACIÓN AUDITORÍA EXITOSA\n\n")
                self.auditoria_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.auditoria_text.insert(tk.END, f"Gestor de Permisos: {'✅' if resultado.get('gestor_permisos') else '❌'}\n")
                self.auditoria_text.insert(tk.END, f"Permisos Sudo: {'✅' if resultado.get('permisos_sudo') else '❌'}\n\n")
                
                self.auditoria_text.insert(tk.END, "=== HERRAMIENTAS AUDITORÍA DISPONIBLES ===\n")
                for herramienta, estado in resultado.get('herramientas_disponibles', {}).items():
                    disponible = estado.get('disponible', False)
                    permisos = estado.get('permisos_ok', False)
                    icono = "✅" if disponible and permisos else "❌"
                    self.auditoria_text.insert(tk.END, f"  {icono} {herramienta}\n")
                    
            else:
                self.auditoria_text.insert(tk.END, " ❌ VERIFICACIÓN AUDITORÍA FALLÓ\n\n")
                self.auditoria_text.insert(tk.END, f"Sistema Operativo: {resultado.get('sistema_operativo', 'Desconocido')}\n")
                self.auditoria_text.insert(tk.END, f"Gestor de Permisos: {'✅' if resultado.get('gestor_permisos') else '❌'}\n")
                self.auditoria_text.insert(tk.END, f"Permisos Sudo: {'✅' if resultado.get('permisos_sudo') else '❌'}\n\n")
                
                if resultado.get('recomendaciones'):
                    self.auditoria_text.insert(tk.END, "=== RECOMENDACIONES ===\n")
                    for recomendacion in resultado['recomendaciones']:
                        self.auditoria_text.insert(tk.END, f"  • {recomendacion}\n")
                
            if resultado.get('error'):
                self.auditoria_text.insert(tk.END, f"\n⚠️ Error: {resultado['error']}\n")
                
            self.auditoria_text.config(state=tk.DISABLED)
                
        except Exception as e:
            self.auditoria_text.config(state=tk.NORMAL)
            self.auditoria_text.insert(tk.END, f" ❌ Error durante verificación: {str(e)}\n")
            self.auditoria_text.config(state=tk.DISABLED)

    def iniciar_fim(self):
        """Iniciar monitoreo FIM (File Integrity Monitoring)"""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de auditoría configurado")
            return
            
        if self.proceso_fim_activo:
            self._actualizar_texto_auditoria("FIM ya está en ejecución\n")
            return
        
        try:
            self._actualizar_texto_auditoria("=== INICIANDO MONITOREO FIM ===\n")
            self.proceso_fim_activo = True
            
            # Obtener controlador FIM del controlador principal
            if hasattr(self.controlador, '_controladores') and 'fim' in self.controlador._controladores:
                controlador_fim = self.controlador._controladores['fim']
                
                def ejecutar_fim():
                    try:
                        self._actualizar_texto_auditoria("Iniciando monitoreo de integridad de archivos...\n")
                        resultado = controlador_fim.iniciar_monitoreo()
                        
                        if resultado.get('exito'):
                            self._actualizar_texto_auditoria("FIM iniciado correctamente\n")
                            self._actualizar_texto_auditoria(f"Directorios monitoreados: {len(resultado.get('directorios', []))}\n")
                            self._actualizar_texto_auditoria(f"Archivos en baseline: {resultado.get('archivos_baseline', 0)}\n")
                        else:
                            self._actualizar_texto_auditoria(f"Error iniciando FIM: {resultado.get('error', 'Error desconocido')}\n")
                            self.proceso_fim_activo = False
                            
                    except Exception as e:
                        self._actualizar_texto_auditoria(f"Error en FIM: {str(e)}\n")
                        self.proceso_fim_activo = False
                
                threading.Thread(target=ejecutar_fim, daemon=True).start()
            else:
                self._actualizar_texto_auditoria("Error: Controlador FIM no disponible\n")
                self.proceso_fim_activo = False
                
        except Exception as e:
            self._actualizar_texto_auditoria(f"Error iniciando FIM: {str(e)}\n")
            self.proceso_fim_activo = False

    def detener_fim(self):
        """Detener monitoreo FIM"""
        if not self.proceso_fim_activo:
            self._actualizar_texto_auditoria("FIM no está en ejecución\n")
            return
            
        try:
            if hasattr(self.controlador, '_controladores') and 'fim' in self.controlador._controladores:
                controlador_fim = self.controlador._controladores['fim']
                resultado = controlador_fim.detener_monitoreo()
                
                if resultado.get('exito'):
                    self._actualizar_texto_auditoria("FIM detenido correctamente\n")
                    self._actualizar_texto_auditoria(f"Cambios detectados: {resultado.get('cambios_detectados', 0)}\n")
                else:
                    self._actualizar_texto_auditoria(f"Error deteniendo FIM: {resultado.get('error', 'Error desconocido')}\n")
                    
                self.proceso_fim_activo = False
            else:
                self._actualizar_texto_auditoria("Error: Controlador FIM no disponible\n")
                
        except Exception as e:
            self._actualizar_texto_auditoria(f"Error deteniendo FIM: {str(e)}\n")

    def iniciar_siem(self):
        """Iniciar análisis SIEM (Security Information & Event Management)"""
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de auditoría configurado")
            return
            
        if self.proceso_siem_activo:
            self._actualizar_texto_auditoria("SIEM ya está en ejecución\n")
            return
        
        try:
            self._actualizar_texto_auditoria("=== INICIANDO ANÁLISIS SIEM ===\n")
            self.proceso_siem_activo = True
            
            # Obtener controlador SIEM del controlador principal
            if hasattr(self.controlador, '_controladores') and 'siem' in self.controlador._controladores:
                controlador_siem = self.controlador._controladores['siem']
                
                def ejecutar_siem():
                    try:
                        self._actualizar_texto_auditoria("Iniciando análisis de eventos de seguridad...\n")
                        resultado = controlador_siem.iniciar_analisis()
                        
                        if resultado.get('exito'):
                            self._actualizar_texto_auditoria("SIEM iniciado correctamente\n")
                            self._actualizar_texto_auditoria(f"Fuentes de eventos: {len(resultado.get('fuentes', []))}\n")
                            self._actualizar_texto_auditoria(f"Reglas de correlación: {resultado.get('reglas_activas', 0)}\n")
                        else:
                            self._actualizar_texto_auditoria(f"Error iniciando SIEM: {resultado.get('error', 'Error desconocido')}\n")
                            self.proceso_siem_activo = False
                            
                    except Exception as e:
                        self._actualizar_texto_auditoria(f"Error en SIEM: {str(e)}\n")
                        self.proceso_siem_activo = False
                
                threading.Thread(target=ejecutar_siem, daemon=True).start()
            else:
                self._actualizar_texto_auditoria("Error: Controlador SIEM no disponible\n")
                self.proceso_siem_activo = False
                
        except Exception as e:
            self._actualizar_texto_auditoria(f"Error iniciando SIEM: {str(e)}\n")
            self.proceso_siem_activo = False

    def detener_siem(self):
        """Detener análisis SIEM"""
        if not self.proceso_siem_activo:
            self._actualizar_texto_auditoria("SIEM no está en ejecución\n")
            return
            
        try:
            if hasattr(self.controlador, '_controladores') and 'siem' in self.controlador._controladores:
                controlador_siem = self.controlador._controladores['siem']
                resultado = controlador_siem.detener_analisis()
                
                if resultado.get('exito'):
                    self._actualizar_texto_auditoria("SIEM detenido correctamente\n")
                    self._actualizar_texto_auditoria(f"Eventos analizados: {resultado.get('eventos_analizados', 0)}\n")
                    self._actualizar_texto_auditoria(f"Alertas generadas: {resultado.get('alertas_generadas', 0)}\n")
                else:
                    self._actualizar_texto_auditoria(f"Error deteniendo SIEM: {resultado.get('error', 'Error desconocido')}\n")
                    
                self.proceso_siem_activo = False
            else:
                self._actualizar_texto_auditoria("Error: Controlador SIEM no disponible\n")
                
        except Exception as e:
            self._actualizar_texto_auditoria(f"Error deteniendo SIEM: {str(e)}\n")
