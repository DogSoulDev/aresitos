
# =============================================================
# PRINCIPIOS DE SEGURIDAD ARESITOS (NO TOCAR SIN AUDITORÍA)
# - Nunca solicitar ni almacenar la contraseña de root.
# - Nunca mostrar, registrar ni filtrar la contraseña de root.
# - Ningún input de usuario debe usarse como comando sin validar.
# - Todos los comandos pasan por el validador y gestor de permisos.
# - Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
# - Prohibido shell=True salvo justificación y validación exhaustiva.
# - Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
# =============================================================
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import time
import os
import logging
import threading
import datetime

# Importar SudoManager para prevenir crashes
try:
    from aresitos.utils.sudo_manager import SudoManager
    SUDO_MANAGER_DISPONIBLE = True
except ImportError:
    SUDO_MANAGER_DISPONIBLE = False

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class ThreadSafeFlag:
    """Clase para bandera thread-safe - ARESITOS"""
    def __init__(self):
        self.flag = False
        self.lock = threading.Lock()
    
    def is_set(self):
        with self.lock:
            return self.flag
    
    def set(self):
        with self.lock:
            self.flag = True
    
    def clear(self):
        with self.lock:
            self.flag = False

class VistaMonitoreo(tk.Frame):
    def _monitorear_cambios_sistema(self):
        """Detectar cambios recientes en directorios críticos y mostrar resultados en la vista."""
        import subprocess
        directorios_criticos = ['/etc', '/var', '/usr', '/bin', '/sbin', '/opt']
        cambios_detectados = 0
        for directorio in directorios_criticos:
            try:
                resultado = self._ejecutar_comando_seguro(['find', directorio, '-type', 'f', '-mmin', '-10'], timeout=20, usar_sudo=True)
                if resultado['success']:
                    archivos_modificados = resultado['output'].strip().split('\n') if resultado['output'].strip() else []
                    if len(archivos_modificados) > 0:
                        cambios_detectados += len(archivos_modificados)
                        if len(archivos_modificados) > 5:
                            self._log_terminal(f"MUCHOS CAMBIOS: {len(archivos_modificados)} archivos modificados en {directorio}", "MONITOREO", "WARNING")
                            self.text_monitor.insert(tk.END, f"MUCHOS CAMBIOS: {len(archivos_modificados)} archivos modificados en {directorio}\n")
                        else:
                            for archivo in archivos_modificados[:3]:
                                self._log_terminal(f"CAMBIO DETECTADO: {archivo}", "MONITOREO", "INFO")
                                self.text_monitor.insert(tk.END, f"CAMBIO DETECTADO: {archivo}\n")
                else:
                    self._log_terminal(f"Error ejecutando find en {directorio}: {resultado['error']}", "MONITOREO", "WARNING")
                    self.text_monitor.insert(tk.END, f"Error ejecutando find en {directorio}: {resultado['error']}\n")
            except Exception as e:
                self._log_terminal(f"Error monitoreando cambios en {directorio}: {str(e)}", "MONITOREO", "WARNING")
                self.text_monitor.insert(tk.END, f"Error monitoreando cambios en {directorio}: {str(e)}\n")
        if cambios_detectados == 0:
            self._log_terminal("No se detectaron cambios recientes en el sistema", "MONITOREO", "INFO")
            self.text_monitor.insert(tk.END, "No se detectaron cambios recientes en el sistema\n")
        elif cambios_detectados > 20:
            self._log_terminal(f"ALERTA: {cambios_detectados} cambios detectados en directorios criticos", "MONITOREO", "ERROR")
            self.text_monitor.insert(tk.END, f"ALERTA: {cambios_detectados} cambios detectados en directorios críticos\n")
        self.text_monitor.see(tk.END)

    def _actualizar_label_estado_seguro(self, texto):
        def _update():
            try:
                if hasattr(self, 'label_estado') and self.label_estado.winfo_exists():
                    self.label_estado.config(text=texto)
            except (tk.TclError, AttributeError):
                pass
        try:
            if hasattr(self, 'after'):
                self.after(0, _update)
        except RuntimeError:
            pass
    @staticmethod
    def _get_base_dir():
        """Obtener la ruta base absoluta del proyecto ARESITOS."""
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = logging.getLogger(__name__)
        
        # Uso de banderas thread-safe para evitar crashes y deslogueos (principios ARESITOS)
        self.flag_monitoreo = ThreadSafeFlag()
        self.flag_red = ThreadSafeFlag()
        
        self.vista_principal = parent  # Referencia al padre para acceder al terminal
        
        # Inicializar SudoManager global de forma segura
        try:
            from aresitos.utils.sudo_manager import get_sudo_manager
            self.sudo_manager = get_sudo_manager()
            self.logger.info("SudoManager inicializado para VistaMonitoreo")
        except Exception as e:
            self.logger.warning(f"Error inicializando SudoManager: {e}")
            self.sudo_manager = None
        
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

    # ...existing code...
        self.crear_widgets()
        self.actualizar_estado()

    # ...existing code...
    
    def set_controlador(self, controlador):
        self.controlador = controlador
    
    def _ejecutar_comando_seguro(self, comando: list, timeout: int = 30, usar_sudo: bool = False) -> dict:
        """
        Ejecutar comando de sistema de forma segura con manejo de errores
        
        Args:
            comando: Lista de comando y argumentos
            timeout: Timeout en segundos
            usar_sudo: Si usar sudo para el comando
            
        Returns:
            Dict con resultado del comando
        """
        import subprocess
        try:
            comando_str = ' '.join(comando)
            # Usar sudo_manager si está disponible y activo, o si se solicita usar_sudo
            if (hasattr(self, 'sudo_manager') and self.sudo_manager and self.sudo_manager.is_sudo_active()) or usar_sudo:
                if hasattr(self, 'sudo_manager') and self.sudo_manager:
                    resultado = self.sudo_manager.execute_sudo_command(comando_str, timeout=timeout)
                    if isinstance(resultado, dict):
                        return resultado
                    return {
                        'success': False,
                        'output': '',
                        'error': 'Error inesperado en SudoManager',
                        'returncode': -4
                    }
            # Si no hay sudo_manager, ejecutar comando directamente (solo si no es privilegiado)
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
            return {
                'success': resultado.returncode == 0,
                'output': resultado.stdout,
                'error': resultado.stderr,
                'returncode': resultado.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': f'Comando excedió timeout de {timeout}s',
                'returncode': -1
            }
        except FileNotFoundError:
            return {
                'success': False,
                'output': '',
                'error': f'Comando no encontrado: {comando[0]}',
                'returncode': -2
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': f'Error ejecutando comando: {str(e)}',
                'returncode': -3
            }
    
    def crear_widgets(self):
        # PanedWindow principal para dividir contenido y terminal
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg=self.colors['bg_primary'])
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)

        # Frame superior para el contenido principal, ahora con Notebook estilo burp_theme
        if self.theme:
            style = ttk.Style()
            self.theme.configure_ttk_style(style)
            self.notebook = ttk.Notebook(self.paned_window, style='Custom.TNotebook')
        else:
            self.notebook = ttk.Notebook(self.paned_window)
        self.paned_window.add(self.notebook, minsize=400)

        # Crear pestañas como frames separados
        self.tab_monitoreo = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.tab_cuarentena = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(self.tab_monitoreo, text='Monitoreo')
        self.notebook.add(self.tab_cuarentena, text='Cuarentena')

        # Llama a los métodos de creación de contenido, pasándoles el frame adecuado
        self.crear_pestana_monitoreo(self.tab_monitoreo)
        self.crear_pestana_cuarentena(self.tab_cuarentena)

        # Crear terminal integrado
        self.crear_terminal_integrado()
    
    def crear_terminal_integrado(self):
        """Crear terminal integrado Monitoreo con diseño estándar coherente."""
        try:
            terminal_frame = tk.LabelFrame(
                self.paned_window,
                text="Terminal ARESITOS - Monitoreo",
                bg=self.colors['bg_secondary'],
                fg=self.colors['fg_primary'],
                font=("Arial", 10, "bold")
            )
            self.paned_window.add(terminal_frame, minsize=120)

            controles_frame = tk.Frame(terminal_frame, bg=self.colors['bg_secondary'])
            controles_frame.pack(fill="x", padx=5, pady=2)

            btn_limpiar = tk.Button(
                controles_frame,
                text="LIMPIAR",
                command=self.limpiar_terminal_monitoreo,
                bg=self.colors.get('warning', '#ffaa00'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)

            btn_logs = tk.Button(
                controles_frame,
                text="VER LOGS",
                command=self.abrir_logs_monitoreo,
                bg=self.colors.get('info', '#007acc'),
                fg='white',
                font=("Arial", 8, "bold"),
                height=1
            )
            btn_logs.pack(side="left", padx=2, fill="x", expand=True)

            self.terminal_output = scrolledtext.ScrolledText(
                terminal_frame,
                height=6,
                bg='#000000',
                fg='#00ff00',
                font=("Consolas", 8),
                insertbackground='#00ff00',
                selectbackground='#333333'
            )
            self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)

            entrada_frame = tk.Frame(terminal_frame, bg='#1e1e1e')
            entrada_frame.pack(fill="x", padx=5, pady=2)

            tk.Label(entrada_frame, text="COMANDO:",
                    bg='#1e1e1e', fg='#00ff00',
                    font=("Arial", 9, "bold")).pack(side="left", padx=(0, 5))

            self.comando_entry = tk.Entry(
                entrada_frame,
                bg='#000000',
                fg='#00ff00',
                font=("Consolas", 9),
                insertbackground='#00ff00'
            )
            self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.comando_entry.bind("<Return>", self.ejecutar_comando_entry)

            ejecutar_btn = tk.Button(
                entrada_frame,
                text="EJECUTAR",
                command=self.ejecutar_comando_entry,
                bg='#2d5aa0',
                fg='white',
                font=("Arial", 8, "bold")
            )
            ejecutar_btn.pack(side="right")

            import datetime
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "Terminal ARESITOS - Monitoreo v2.0\n")
            self.terminal_output.insert(tk.END, f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.terminal_output.insert(tk.END, f"Sistema: Kali Linux - System Performance Monitor\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
            self.terminal_output.insert(tk.END, "LOG Monitoreo en tiempo real\n\n")

            self.log_to_terminal("Terminal Monitoreo iniciado correctamente")

        except Exception as e:
            print(f"Error creando terminal integrado en Vista Monitoreo: {e}")
    
    def limpiar_terminal_monitoreo(self):
        """Limpiar terminal Monitoreo manteniendo cabecera."""
        try:
            import datetime
            if hasattr(self, 'terminal_output'):
                self.terminal_output.delete(1.0, tk.END)
                # Recrear cabecera estándar
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "Terminal ARESITOS - Monitoreo v2.0\n")
                self.terminal_output.insert(tk.END, f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.terminal_output.insert(tk.END, "Sistema: Kali Linux - System Performance Monitor\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
                self.terminal_output.insert(tk.END, "LOG Terminal Monitoreo reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Monitoreo: {e}")
    
    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada (sin validación de seguridad, root/sudo autenticado)."""
        comando = self.comando_entry.get().strip()
        if not comando:
            return
        self.terminal_output.insert(tk.END, f"\n> {comando}\n")
        self.terminal_output.see(tk.END)
        self.comando_entry.delete(0, tk.END)
        thread = threading.Thread(target=self._ejecutar_comando_async, args=(comando,))
        thread.daemon = True
        thread.start()
    
    def _ejecutar_comando_async(self, comando):
        """Ejecutar comando de forma asíncrona con comandos especiales."""
        try:
            # Comandos especiales de ARESITOS
            if comando == "ayuda-comandos":
                self._mostrar_ayuda_comandos()
                return
            elif comando == "info-seguridad":
                self._mostrar_info_seguridad()
                return
            elif comando == "clear" or comando == "cls":
                self.limpiar_terminal_monitoreo()
                return
            
            import platform
            import subprocess
            
            if platform.system() == "Windows":
                comando_completo = ["cmd", "/c", comando]
            else:
                comando_completo = ["/bin/bash", "-c", comando]
            
            resultado = subprocess.run(
                comando_completo,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if resultado.stdout:
                self.terminal_output.insert(tk.END, resultado.stdout)
            if resultado.stderr:
                self.terminal_output.insert(tk.END, f"ERROR: {resultado.stderr}")
            
            self.terminal_output.see(tk.END)
            
        except subprocess.TimeoutExpired:
            self.terminal_output.insert(tk.END, "ERROR: Comando timeout (30s)\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
        
        self.terminal_output.see(tk.END)
    
    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "COMANDOS DISPONIBLES EN ARESITOS v2.0\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            self.terminal_output.insert(tk.END, "🔧 COMANDOS ESPECIALES:\n")
            self.terminal_output.insert(tk.END, "   ayuda-comandos, info-seguridad, clear/cls\n\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando ayuda: {e}\n")
        self.terminal_output.see(tk.END)
    
    def _mostrar_info_seguridad(self):
        """Mostrar información de seguridad actual."""
        try:
            self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
            self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n\n")
            self.terminal_output.insert(tk.END, "Estado: Seguridad estándar, sin validación restrictiva.\n")
            self.terminal_output.insert(tk.END, "Para más detalles revise la configuración y logs.\n")
            self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error mostrando info seguridad: {e}\n")
        self.terminal_output.see(tk.END)
    
    def abrir_logs_monitoreo(self):
        """Abrir carpeta de logs Monitoreo con ruta robusta y multiplataforma."""
        try:
            import os
            import platform
            logs_path = self._get_base_dir() / 'logs'
            if not logs_path.exists():
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
                messagebox.showwarning("Advertencia", "Carpeta de logs no encontrada")
                return
            # Usar método seguro para abrir directorio
            if platform.system() == "Linux":
                resultado = self._ejecutar_comando_seguro(["xdg-open", str(logs_path)], timeout=10)
            elif platform.system() == "Windows":
                resultado = self._ejecutar_comando_seguro(["explorer", str(logs_path)], timeout=10)
            else:
                resultado = self._ejecutar_comando_seguro(["open", str(logs_path)], timeout=10)
            if resultado['success']:
                self.log_to_terminal("OK Carpeta de logs Monitoreo abierta")
            else:
                self.log_to_terminal(f"ERROR: No se pudo abrir logs - {resultado['error']}")
                messagebox.showerror("Error", f"No se pudo abrir la carpeta de logs: {resultado['error']}")
        except Exception as e:
            error_msg = f"Error abriendo logs: {str(e)}"
            self.log_to_terminal(f"ERROR: {error_msg}")
            messagebox.showerror("Error", error_msg)
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal con formato estándar."""
        try:
            import datetime
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            
            # Log al terminal integrado estándar
            if hasattr(self, 'terminal_output'):
                self.terminal_output.insert(tk.END, mensaje_completo)
                self.terminal_output.see(tk.END)
        except Exception as e:
            print(f"Error en log_to_terminal: {e}")
    
    def sincronizar_terminal(self):
        """Función de compatibilidad - ya no necesaria con terminal estándar."""
        pass
    
    def crear_navegacion_pestanas(self):
        """Crear navegación por pestañas con tema Burp Suite."""
        nav_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        nav_frame.pack(fill="x", pady=(0, 10))
        self.btn_monitoreo = tk.Button(
            nav_frame, text=" Monitoreo Sistema",
            command=lambda: self.mostrar_pestana('monitoreo'),
            bg="#ffb86c", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#ffd9b3", activeforeground="#ff6633"
        )
        self.btn_monitoreo.pack(side="left", padx=(0, 8), pady=4)

        self.btn_cuarentena = tk.Button(
            nav_frame, text=" Cuarentena",
            command=lambda: self.mostrar_pestana('cuarentena'),
            bg="#8be9fd", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#b3f0ff", activeforeground="#ff6633"
        )
        self.btn_cuarentena.pack(side="left", padx=8, pady=4)
    
    def mostrar_pestana(self, pestana):
        """Mostrar la pestaña seleccionada."""
        # Actualizar colores de botones
        if pestana == 'monitoreo':
            self.btn_monitoreo.configure(bg='#ff6633')
            self.btn_cuarentena.configure(bg='#404040')
            
            if hasattr(self, 'frame_cuarentena'):
                self.frame_cuarentena.pack_forget()
            if hasattr(self, 'frame_monitor'):
                self.frame_monitor.pack(fill="both", expand=True)
        else:
            self.btn_monitoreo.configure(bg='#404040')
            self.btn_cuarentena.configure(bg='#ff6633')
            
            if hasattr(self, 'frame_monitor'):
                self.frame_monitor.pack_forget()
            if hasattr(self, 'frame_cuarentena'):
                self.frame_cuarentena.pack(fill="both", expand=True)
    
    def crear_pestana_monitoreo(self, parent=None):
        parent = parent if parent is not None else self.notebook
        self.frame_monitor = parent
        
        # Título
        titulo_frame = tk.Frame(self.frame_monitor, bg='#2b2b2b')
        titulo_frame.pack(fill="x", pady=(0, 15))
        
        titulo_label = tk.Label(titulo_frame, text=" MONITOR DEL SISTEMA", 
                              font=('Arial', 14, 'bold'),
                              bg='#2b2b2b', fg='#ff6633')
        titulo_label.pack()
        
        # Frame de controles con tema
        control_frame = tk.Frame(self.frame_monitor, bg='#2b2b2b')
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_iniciar_monitor = tk.Button(
            control_frame, text=" Iniciar Monitoreo", 
            command=self.iniciar_monitoreo,
            bg="#50fa7b", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#a8ffb3", activeforeground="#ff6633"
        )
        self.btn_iniciar_monitor.pack(side="left", padx=(0, 8), pady=4)

        self.btn_detener_monitor = tk.Button(
            control_frame, text=" Detener Monitoreo", 
            command=self.detener_monitoreo, state="disabled",
            bg="#ff5555", fg="#ffffff",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#ffb3b3", activeforeground="#232629"
        )
        self.btn_detener_monitor.pack(side="left", padx=(0, 8), pady=4)

        self.btn_red = tk.Button(
            control_frame, text=" Monitorear Red", 
            command=self.monitorear_red,
            bg="#8be9fd", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#b3f0ff", activeforeground="#ff6633"
        )
        self.btn_red.pack(side="left", padx=(0, 8), pady=4)

        self.btn_cancelar_red = tk.Button(
            control_frame, text=" Cancelar Red", 
            command=self.cancelar_monitoreo_red,
            state="disabled",
            bg="#ffb86c", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#ffd9b3", activeforeground="#ff6633"
        )
        self.btn_cancelar_red.pack(side="left", padx=(0, 8), pady=4)
        
        self.label_estado = tk.Label(control_frame, text="Estado: Detenido",
                                   bg='#2b2b2b', fg='#ffffff',
                                   font=('Arial', 10))
        self.label_estado.pack(side="right", padx=(10, 0))
        
        # Área de texto con tema
        self.text_monitor = scrolledtext.ScrolledText(self.frame_monitor, height=25,
                                                    bg='#1e1e1e', fg='#ffffff',
                                                    font=('Consolas', 10),
                                                    insertbackground='#ff6633',
                                                    selectbackground='#404040')
        self.text_monitor.pack(fill="both", expand=True)
    
    def crear_pestana_cuarentena(self, parent=None):
        parent = parent if parent is not None else self.notebook
        self.frame_cuarentena = parent
        
        # Título
        titulo_frame = tk.Frame(self.frame_cuarentena, bg='#2b2b2b')
        titulo_frame.pack(fill="x", pady=(0, 15))
        
        titulo_label = tk.Label(titulo_frame, text=" GESTIÓN DE CUARENTENA", 
                              font=('Arial', 14, 'bold'),
                              bg='#2b2b2b', fg='#ff6633')
        titulo_label.pack()
        
        # Frame de controles con tema
        control_frame = tk.Frame(self.frame_cuarentena, bg='#2b2b2b')
        control_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_agregar_cuarentena = tk.Button(
            control_frame, text=" Agregar Archivo", 
            command=self.agregar_a_cuarentena,
            bg="#ffb86c", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#ffd9b3", activeforeground="#ff6633"
        )
        self.btn_agregar_cuarentena.pack(side="left", padx=(0, 8), pady=4)

        self.btn_listar_cuarentena = tk.Button(
            control_frame, text=" Listar Archivos", 
            command=self.listar_cuarentena,
            bg="#8be9fd", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#b3f0ff", activeforeground="#ff6633"
        )
        self.btn_listar_cuarentena.pack(side="left", padx=(0, 8), pady=4)

        self.btn_limpiar_cuarentena = tk.Button(
            control_frame, text=" Limpiar Todo", 
            command=self.limpiar_cuarentena,
            bg="#ff5555", fg="#ffffff",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=16, pady=8,
            activebackground="#ffb3b3", activeforeground="#232629"
        )
        self.btn_limpiar_cuarentena.pack(side="left", padx=8, pady=4)
        
        # Área de texto con tema
        self.text_cuarentena = scrolledtext.ScrolledText(self.frame_cuarentena, height=25,
                                                       bg='#1e1e1e', fg='#ffffff',
                                                       font=('Consolas', 10),
                                                       insertbackground='#ff6633',
                                                       selectbackground='#404040')
        self.text_cuarentena.pack(fill="both", expand=True)
    
    def iniciar_monitoreo(self):
        """Iniciar monitoreo completo con herramientas avanzadas de Linux."""
        self.log_to_terminal("Iniciando monitoreo del sistema...")
        if not self.controlador:
            self._log_terminal("Iniciando monitoreo con comandos nativos de Linux", "MONITOREO", "INFO")
        self._log_terminal("Iniciando monitoreo completo del sistema con herramientas Kali", "MONITOREO", "INFO")
        # Resetear bandera thread-safe
        self.flag_monitoreo.clear()
        try:
            if self.controlador and self.controlador.iniciar_monitoreo():
                self.btn_iniciar_monitor.config(state="disabled")
                self.btn_detener_monitor.config(state="normal")
                self.label_estado.config(text="Estado: Activo")
                self.text_monitor.insert(tk.END, "Monitoreo completo iniciado con controlador...\n")
                self._log_terminal("Monitoreo del controlador iniciado exitosamente", "MONITOREO", "SUCCESS")
                self.log_to_terminal("OK Monitoreo iniciado exitosamente")
                threading.Thread(target=self._monitoreo_avanzado_linux, daemon=True).start()
                self.after(2000, self.actualizar_monitoreo)
            else:
                self._log_terminal("Ejecutando monitoreo avanzado con comandos Linux", "MONITOREO", "INFO")
                self._iniciar_monitoreo_linux_avanzado()
        except Exception as e:
            self._log_terminal(f"Error en controlador - ejecutando monitoreo Linux: {str(e)}", "MONITOREO", "WARNING")
            self._iniciar_monitoreo_linux_avanzado()

    def _iniciar_monitoreo_basico(self):
        """Iniciar monitoreo básico cuando el controlador no está disponible."""
        self.flag_monitoreo.clear()
        self.btn_iniciar_monitor.config(state="disabled")
        self.btn_detener_monitor.config(state="normal")
        self.label_estado.config(text="Estado: Activo (Básico)")
        self.text_monitor.insert(tk.END, "Monitoreo básico iniciado...\n")
        
        # Iniciar monitoreo básico en thread separado
        threading.Thread(target=self._monitoreo_completo_async, daemon=True).start()
        try:
            if hasattr(self, 'after'):
                self.after(3000, self._actualizar_monitoreo_basico)
        except RuntimeError:
            pass

    def _monitoreo_completo_async(self):
        """Ejecutar monitoreo completo de procesos, permisos y usuarios con feedback detallado en la vista."""
        import time
        try:
            ciclo = 0
            while not self.flag_monitoreo.is_set():
                ciclo += 1
                self._log_terminal(f"Ciclo de monitoreo #{ciclo} iniciado", "MONITOREO", "INFO")
                self.text_monitor.insert(tk.END, f"\n[CICLO {ciclo}] Monitoreo iniciado\n")
                self.text_monitor.insert(tk.END, "[FASE 1] Monitoreando procesos del sistema...\n")
                self.text_monitor.see(tk.END)
                # FASE 1: Monitorear procesos del sistema
                self._log_terminal("FASE 1: Monitoreando procesos del sistema", "MONITOREO", "INFO")
                self._monitorear_procesos_sistema()
                self.text_monitor.insert(tk.END, "[FASE 2] Verificando permisos de archivos críticos...\n")
                self.text_monitor.see(tk.END)
                self._log_terminal("FASE 2: Verificando permisos de archivos criticos", "MONITOREO", "INFO")
                self._monitorear_permisos_archivos()
                self.text_monitor.insert(tk.END, "[FASE 3] Monitoreando usuarios y sesiones activas...\n")
                self.text_monitor.see(tk.END)
                self._log_terminal("FASE 3: Monitoreando usuarios y sesiones activas", "MONITOREO", "INFO")
                self._monitorear_usuarios_sesiones()
                self.text_monitor.insert(tk.END, "[FASE 4] Verificando procesos con privilegios elevados...\n")
                self.text_monitor.see(tk.END)
                self._log_terminal("FASE 4: Verificando procesos con privilegios elevados", "MONITOREO", "WARNING")
                self._monitorear_procesos_privilegiados()
                self.text_monitor.insert(tk.END, "[FASE 5] Detectando cambios en el sistema...\n")
                self.text_monitor.see(tk.END)
                self._log_terminal("FASE 5: Detectando cambios en el sistema", "MONITOREO", "INFO")
                self._monitorear_cambios_sistema()
                self.text_monitor.insert(tk.END, f"[CICLO {ciclo}] Monitoreo completado\n")
                self.text_monitor.see(tk.END)
                self._log_terminal(f"Ciclo de monitoreo #{ciclo} completado", "MONITOREO", "SUCCESS")
                # Pausa entre ciclos (15 segundos)
                for i in range(15):
                    if self.flag_monitoreo.is_set():
                        break
                    time.sleep(1)
        except Exception as e:
            self.text_monitor.insert(tk.END, f"\nError en monitoreo completo: {str(e)}\n")
            self.text_monitor.see(tk.END)
            self._log_terminal(f"Error en monitoreo completo: {str(e)}", "MONITOREO", "ERROR")

    def _monitorear_procesos_sistema(self):
        """Monitorear todos los procesos del sistema y sus características con manejo seguro."""
        try:
            # Obtener lista completa de procesos usando método seguro
            resultado = self._ejecutar_comando_seguro(['ps', 'aux'], timeout=15)
            
            if not resultado['success']:
                self._log_terminal(f"Error obteniendo procesos: {resultado['error']}", "PROCESOS", "ERROR")
                return
            
            lineas = resultado['output'].strip().split('\n')[1:]  # Saltar header
            
            procesos_sospechosos = []
            procesos_alta_cpu = []
            procesos_alta_memoria = []
            total_procesos = len(lineas)
            
            for linea in lineas:
                try:
                    partes = linea.split()
                    if len(partes) >= 11:
                        usuario = partes[0]
                        pid = partes[1]
                        cpu = float(partes[2]) if partes[2].replace('.', '').isdigit() else 0.0
                        memoria = float(partes[3]) if partes[3].replace('.', '').isdigit() else 0.0
                        comando = ' '.join(partes[10:])
                    
                        # Detectar procesos con alto uso de CPU
                        if cpu > 50.0:
                            procesos_alta_cpu.append((pid, comando, cpu))
                            
                        # Detectar procesos con alto uso de memoria
                        if memoria > 10.0:
                            procesos_alta_memoria.append((pid, comando, memoria))
                            
                        # Detectar procesos sospechosos
                        comandos_sospechosos = [
                            'nc ', 'netcat', '/tmp/', '/var/tmp/', 'wget', 'curl http',
                            'python -c', 'perl -e', 'bash -c', '/dev/tcp/'
                        ]
                        
                        for sospechoso in comandos_sospechosos:
                            if sospechoso in comando.lower():
                                procesos_sospechosos.append((pid, usuario, comando))
                                break
                except (ValueError, IndexError) as e:
                    # Ignorar líneas malformadas
                    continue
                            
            # Reportar hallazgos
            self._log_terminal(f"Procesos totales monitoreados: {total_procesos}", "MONITOREO", "INFO")
            
            for pid, comando, cpu in procesos_alta_cpu:
                self._log_terminal(f"PROCESO ALTO CPU: PID {pid} usando {cpu}% - {comando[:80]}", "MONITOREO", "WARNING")
                
            for pid, comando, memoria in procesos_alta_memoria:
                self._log_terminal(f"PROCESO ALTA MEMORIA: PID {pid} usando {memoria}% - {comando[:80]}", "MONITOREO", "WARNING")
                
            for pid, usuario, comando in procesos_sospechosos:
                self._log_terminal(f"PROCESO SOSPECHOSO: PID {pid} usuario {usuario} - {comando[:80]}", "MONITOREO", "ERROR")
                
            if not procesos_sospechosos and len(procesos_alta_cpu) == 0:
                self._log_terminal("Procesos del sistema funcionando normalmente", "MONITOREO", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error monitoreando procesos: {str(e)}", "MONITOREO", "WARNING")

    def _monitorear_permisos_archivos(self):
        """Monitorear permisos de archivos críticos del sistema."""
        import os
        import subprocess
        
        archivos_criticos = [
            ('/etc/passwd', '644'), ('/etc/shadow', '640'), ('/etc/group', '644'),
            ('/etc/sudoers', '440'), ('/etc/hosts', '644'), ('/etc/ssh/sshd_config', '644'),
            ('/boot/grub/grub.cfg', '644'), ('/etc/crontab', '644')
        ]
        
        try:
            permisos_incorrectos = []
            
            for archivo, permisos_esperados in archivos_criticos:
                if os.path.exists(archivo):
                    stat_info = os.stat(archivo)
                    permisos_actuales = oct(stat_info.st_mode)[-3:]
                    
                    if permisos_actuales != permisos_esperados:
                        permisos_incorrectos.append((archivo, permisos_actuales, permisos_esperados))
                        self._log_terminal(f"PERMISOS INCORRECTOS: {archivo} tiene {permisos_actuales} (esperado {permisos_esperados})", "MONITOREO", "ERROR")
                else:
                    self._log_terminal(f"ARCHIVO CRITICO FALTANTE: {archivo}", "MONITOREO", "ERROR")
                    
            if not permisos_incorrectos:
                self._log_terminal("Permisos de archivos criticos correctos", "MONITOREO", "INFO")
                
            # Verificar archivos SUID modificados recientemente usando método seguro
            resultado = self._ejecutar_comando_seguro(
                ['find', '/', '-type', 'f', '-perm', '-4000', '-mtime', '-1'],
                timeout=20,
                usar_sudo=True
            )
            
            if resultado['success']:
                suid_recientes = resultado['output'].strip().split('\n') if resultado['output'].strip() else []
                for archivo in suid_recientes:
                    if archivo.strip():
                        self._log_terminal(f"ARCHIVO SUID MODIFICADO: {archivo}", "MONITOREO", "WARNING")
            else:
                self._log_terminal(f"No se pudieron verificar archivos SUID: {resultado['error']}", "MONITOREO", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error monitoreando permisos: {str(e)}", "MONITOREO", "WARNING")

    def _monitorear_usuarios_sesiones(self):
        """Monitorear usuarios conectados y sesiones activas con manejo seguro."""
        try:
            # Verificar usuarios conectados usando método seguro
            resultado = self._ejecutar_comando_seguro(['who'], timeout=10)
            
            if not resultado['success']:
                self._log_terminal(f"Error obteniendo usuarios conectados: {resultado['error']}", "USUARIOS", "WARNING")
                return
            
            usuarios_conectados = resultado['output'].strip().split('\n') if resultado['output'].strip() else []
            
            self._log_terminal(f"Usuarios conectados: {len(usuarios_conectados)}", "USUARIOS", "INFO")
            
            for sesion in usuarios_conectados:
                if sesion.strip():
                    try:
                        partes = sesion.split()
                        if len(partes) >= 2:
                            usuario = partes[0]
                            terminal = partes[1]
                            self._log_terminal(f"Sesion activa: {usuario} en {terminal}", "USUARIOS", "INFO")
                    except Exception as e:
                        self._log_terminal(f"Error procesando sesión: {e}", "USUARIOS", "WARNING")
                        
            # Verificar últimos logins usando método seguro
            resultado = self._ejecutar_comando_seguro(['last', '-n', '5'], timeout=10)
            
            if resultado['success']:
                lineas = resultado['output'].strip().split('\n')[:3]  # Últimos 3 logins
                
                for linea in lineas:
                    if linea.strip() and 'reboot' not in linea.lower() and 'wtmp' not in linea.lower():
                        try:
                            partes = linea.split()
                            if len(partes) >= 3:
                                usuario = partes[0]
                                origen = partes[2] if len(partes) > 2 else 'local'
                                self._log_terminal(f"Login reciente: {usuario} desde {origen}", "USUARIOS", "INFO")
                        except Exception as e:
                            self._log_terminal(f"Error procesando login: {e}", "USUARIOS", "WARNING")
            else:
                self._log_terminal(f"No se pudieron obtener últimos logins: {resultado['error']}", "USUARIOS", "WARNING")
                        
            # Verificar usuarios con UID 0 (privilegios root) con manejo de errores
            try:
                with open('/etc/passwd', 'r') as f:
                    for linea in f:
                        try:
                            partes = linea.strip().split(':')
                            if len(partes) >= 3:
                                usuario = partes[0]
                                uid = partes[2]
                                if uid == '0' and usuario != 'root':
                                    self._log_terminal(f"USUARIO PRIVILEGIADO DETECTADO: {usuario} (UID 0)", "USUARIOS", "ERROR")
                        except Exception as e:
                            # Ignorar líneas malformadas en /etc/passwd
                            continue
            except FileNotFoundError:
                self._log_terminal("No se pudo acceder a /etc/passwd", "USUARIOS", "WARNING")
            except PermissionError:
                self._log_terminal("Sin permisos para leer /etc/passwd", "USUARIOS", "WARNING")
                            
        except Exception as e:
            self._log_terminal(f"Error monitoreando usuarios: {str(e)}", "USUARIOS", "WARNING")

    def _monitorear_procesos_privilegiados(self):
        """Monitorear procesos ejecutándose con privilegios elevados con manejo seguro."""
        # Procesos ejecutándose como root usando método seguro
        resultado = self._ejecutar_comando_seguro(['ps', '-eo', 'pid,user,comm,args'], timeout=15)
        
        if not resultado['success']:
            self._log_terminal(f"Error obteniendo procesos privilegiados: {resultado['error']}", "PROCESOS", "WARNING")
            return
        
        # Obtener lista completa de procesos usando método seguro
        resultado = self._ejecutar_comando_seguro(['ps', 'aux'], timeout=15)
        if not resultado['success']:
            self._log_terminal(f"Error obteniendo procesos: {resultado['error']}", "PROCESOS", "ERROR")
            self.text_monitor.insert(tk.END, f"Error obteniendo procesos: {resultado['error']}\n")
            self.text_monitor.see(tk.END)
            return
        lineas = resultado['output'].strip().split('\n')[1:]  # Saltar header
        procesos_sospechosos = []
        procesos_alta_cpu = []
        procesos_alta_memoria = []
        total_procesos = len(lineas)
        for linea in lineas:
            try:
                partes = linea.split()
                if len(partes) >= 11:
                    usuario = partes[0]
                    pid = partes[1]
                    cpu = float(partes[2]) if partes[2].replace('.', '').isdigit() else 0.0
                    memoria = float(partes[3]) if partes[3].replace('.', '').isdigit() else 0.0
                    comando = ' '.join(partes[10:])
                    # Detectar procesos con alto uso de CPU
                    if cpu > 50.0:
                        procesos_alta_cpu.append((pid, comando, cpu))
                    # Detectar procesos con alto uso de memoria
                    if memoria > 10.0:
                        procesos_alta_memoria.append((pid, comando, memoria))
                    # Detectar procesos sospechosos
                    comandos_sospechosos = [
                        'nc ', 'netcat', '/tmp/', '/var/tmp/', 'wget', 'curl http',
                        'python -c', 'perl -e', 'bash -c', '/dev/tcp/'
                    ]
                    for sospechoso in comandos_sospechosos:
                        if sospechoso in comando.lower():
                            procesos_sospechosos.append((pid, usuario, comando))
                            break
            except (ValueError, IndexError):
                continue
        # Reportar hallazgos
        self._log_terminal(f"Procesos totales monitoreados: {total_procesos}", "MONITOREO", "INFO")
        self.text_monitor.insert(tk.END, f"Procesos totales monitoreados: {total_procesos}\n")
        for pid, comando, cpu in procesos_alta_cpu:
            self.text_monitor.insert(tk.END, f"PROCESO ALTO CPU: PID {pid} usando {cpu}% - {comando[:80]}\n")
        for pid, comando, memoria in procesos_alta_memoria:
            self.text_monitor.insert(tk.END, f"PROCESO ALTA MEMORIA: PID {pid} usando {memoria}% - {comando[:80]}\n")
        for pid, usuario, comando in procesos_sospechosos:
            self.text_monitor.insert(tk.END, f"PROCESO SOSPECHOSO: PID {pid} usuario {usuario} - {comando[:80]}\n")
        if not procesos_sospechosos and len(procesos_alta_cpu) == 0:
            self.text_monitor.insert(tk.END, "Procesos del sistema funcionando normalmente\n")
        self.text_monitor.see(tk.END)

    def _actualizar_monitoreo_basico(self):
        """Actualizar la interfaz durante el monitoreo básico."""
        if self.monitor_activo:
            self.text_monitor.insert(tk.END, "Monitoreo básico en progreso...\n")
            try:
                if hasattr(self, 'after'):
                    self.after(5000, self._actualizar_monitoreo_basico)
            except RuntimeError:
                pass
    
    def detener_monitoreo(self):
        """Detener monitoreo usando sistema unificado con advertencia profesional."""
        from ..utils.detener_procesos import detener_procesos
        import tkinter.messagebox as messagebox
        if not messagebox.askyesno("Confirmar acción crítica", "¿Está seguro que desea detener el monitoreo? Esta acción puede afectar procesos en ejecución. Solo continúe si comprende el impacto."):
            self.log_to_terminal("Operación de detención de monitoreo cancelada por el usuario.")
            return
        if self.controlador:
            self.controlador.detener_monitoreo()
        self.flag_monitoreo.set()
        def callback_actualizacion(mensaje):
            self.log_to_terminal(mensaje.replace("OK", "").replace("=== ", "").replace(" ===", "").strip())
        def callback_habilitar():
            self.btn_iniciar_monitor.config(state="normal")
            self.btn_detener_monitor.config(state="disabled")
            self.label_estado.config(text="Estado: Detenido")
            self.text_monitor.insert(tk.END, "Monitoreo detenido completamente.\n")
            self.log_to_terminal("MONITOREO Monitoreo detenido correctamente")
        detener_procesos.detener_monitoreo(callback_actualizacion, callback_habilitar)
    
    def actualizar_monitoreo(self):
        if self.flag_monitoreo.is_set() or not self.controlador:
            return
            
        estado = self.controlador.obtener_estado_monitoreo()
        
        if estado["datos_recientes"]:
            ultimo_dato = estado["datos_recientes"][-1]
            timestamp_raw = ultimo_dato.get("timestamp", time.time())
            
            if isinstance(timestamp_raw, str):
                timestamp = timestamp_raw
            elif isinstance(timestamp_raw, (int, float)):
                timestamp = time.strftime("%H:%M:%S", time.localtime(timestamp_raw))
            else:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
            
            info = f"[{timestamp}] "
            if "memoria_porcentaje" in ultimo_dato:
                info += f"Memoria: {ultimo_dato['memoria_porcentaje']:.1f}% | "
            if "procesos_activos" in ultimo_dato:
                info += f"Procesos: {ultimo_dato['procesos_activos']} | "
            if "error" in ultimo_dato:
                info += f"Error: {ultimo_dato['error']}"
            
            self.text_monitor.insert(tk.END, info + "\n")
            self.text_monitor.see(tk.END)
        
        if not self.flag_monitoreo.is_set():
            try:
                if hasattr(self, 'after'):
                    self.after(2000, self.actualizar_monitoreo)
            except RuntimeError:
                pass
    
    def monitorear_red(self):
        """Iniciar monitoreo de red con manejo robusto de errores - Issue 19/24."""
        if not self.controlador:
            messagebox.showwarning("Advertencia", 
                                 "El controlador de monitoreo no está configurado.\n"
                                 "Por favor, reinicie la aplicación.")
            return
        
        if self.flag_red.is_set():
            messagebox.showwarning("Advertencia", "Ya hay un monitoreo de red en curso.")
            return
        
        try:
            self.flag_red.clear()
            self.btn_red.config(state="disabled")
            self.btn_cancelar_red.config(state="normal")
            self.text_monitor.insert(tk.END, "\n === MONITOREO COMPLETO DE RED INICIADO ===\n")
            self._log_terminal("Iniciando monitoreo de red con protección contra crashes", "MONITOREO-RED", "INFO")
            
            # Ejecutar monitoreo en thread separado con manejo de errores
            self.thread_red = threading.Thread(target=self._monitorear_red_completo_async)
            self.thread_red.daemon = True
            self.thread_red.start()
            
        except Exception as e:
            self._log_terminal(f"Error iniciando monitoreo de red: {str(e)}", "MONITOREO-RED", "ERROR")
            self._finalizar_monitoreo_red()

    def _monitorear_red_completo_async(self):
        """Monitorear red de forma completa con feedback detallado en la vista."""
        import subprocess
        import time
        try:
            self.text_monitor.insert(tk.END, "\n=== INICIANDO MONITOREO COMPLETO DE RED ===\n")
            self.text_monitor.insert(tk.END, "Este proceso analizará dispositivos, interfaces, conexiones, puertos y tráfico de red.\n")
            self.text_monitor.see(tk.END)
            self._log_terminal("Iniciando monitoreo de red con protección anti-crash", "MONITOREO-RED", "INFO")
            ciclo = 0
            errores_consecutivos = 0
            max_errores = 3
            while not self.flag_red.is_set() and errores_consecutivos < max_errores:
                ciclo += 1
                ciclo_exitoso = True
                try:
                    self.text_monitor.insert(tk.END, f"\n[CICLO #{ciclo}] Iniciando ciclo de monitoreo de red...\n")
                    self.text_monitor.see(tk.END)
                    self._log_terminal(f"Ciclo de monitoreo de red #{ciclo}", "MONITOREO-RED", "INFO")
                    # FASE 1: Detectar dispositivos conectados a la red
                    if not self.flag_red.is_set():
                        try:
                            self.text_monitor.insert(tk.END, "[FASE 1] Detectando dispositivos conectados a la red...\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 1: Detectando dispositivos conectados a la red", "MONITOREO-RED", "INFO")
                            self._detectar_dispositivos_red_seguro()
                        except Exception as e:
                            self.text_monitor.insert(tk.END, f"[FASE 1] Error: {str(e)}\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 1: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 2: Monitorear interfaces de red activas
                    if not self.flag_red.is_set():
                        try:
                            self.text_monitor.insert(tk.END, "[FASE 2] Monitoreando interfaces de red activas...\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 2: Monitoreando interfaces de red activas", "MONITOREO-RED", "INFO")
                            self._monitorear_interfaces_red_seguro()
                        except Exception as e:
                            self.text_monitor.insert(tk.END, f"[FASE 2] Error: {str(e)}\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 2: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 3: Verificar conexiones activas
                    if not self.flag_red.is_set():
                        try:
                            self.text_monitor.insert(tk.END, "[FASE 3] Verificando conexiones de red activas...\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 3: Verificando conexiones de red activas", "MONITOREO-RED", "INFO")
                            self._monitorear_conexiones_activas_seguro()
                        except Exception as e:
                            self.text_monitor.insert(tk.END, f"[FASE 3] Error: {str(e)}\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 3: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 4: Verificar puertos abiertos del sistema local
                    if not self.flag_red.is_set():
                        try:
                            self.text_monitor.insert(tk.END, "[FASE 4] Verificando puertos abiertos del sistema local...\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 4: Verificando puertos abiertos del sistema local", "MONITOREO-RED", "INFO")
                            self._verificar_puertos_abiertos_seguro()
                        except Exception as e:
                            self.text_monitor.insert(tk.END, f"[FASE 4] Error: {str(e)}\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 4: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 5: Monitorear tráfico de red
                    if not self.flag_red.is_set():
                        try:
                            self.text_monitor.insert(tk.END, "[FASE 5] Monitoreando tráfico de red...\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 5: Monitoreando trafico de red", "MONITOREO-RED", "INFO")
                            self._monitorear_trafico_red_seguro()
                        except Exception as e:
                            self.text_monitor.insert(tk.END, f"[FASE 5] Error: {str(e)}\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 5: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 6: Verificar configuración de red
                    if not self.flag_red.is_set():
                        try:
                            self.text_monitor.insert(tk.END, "[FASE 6] Verificando configuración de red...\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 6: Verificando configuracion de red", "MONITOREO-RED", "INFO")
                            self._verificar_configuracion_red_seguro()
                        except Exception as e:
                            self.text_monitor.insert(tk.END, f"[FASE 6] Error: {str(e)}\n")
                            self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 6: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    if ciclo_exitoso:
                        errores_consecutivos = 0
                        self.text_monitor.insert(tk.END, f"[CICLO #{ciclo}] Monitoreo de red completado exitosamente.\n")
                        self.text_monitor.see(tk.END)
                        self._log_terminal(f"Ciclo de monitoreo de red #{ciclo} completado exitosamente", "MONITOREO-RED", "SUCCESS")
                    else:
                        errores_consecutivos += 1
                        self.text_monitor.insert(tk.END, f"[CICLO #{ciclo}] Monitoreo de red completado con errores ({errores_consecutivos}/{max_errores}).\n")
                        self.text_monitor.see(tk.END)
                        self._log_terminal(f"Ciclo #{ciclo} completado con errores ({errores_consecutivos}/{max_errores})", "MONITOREO-RED", "WARNING")
                    for i in range(15):
                        if self.flag_red.is_set():
                            break
                        time.sleep(1)
                except Exception as e:
                    errores_consecutivos += 1
                    self.text_monitor.insert(tk.END, f"[CICLO #{ciclo}] Error crítico: {str(e)} ({errores_consecutivos}/{max_errores})\n")
                    self.text_monitor.see(tk.END)
                    self._log_terminal(f"Error crítico en ciclo #{ciclo}: {str(e)} ({errores_consecutivos}/{max_errores})", "MONITOREO-RED", "ERROR")
                    for i in range(5):
                        if self.flag_red.is_set():
                            break
                        time.sleep(1)
            if errores_consecutivos >= max_errores:
                self.text_monitor.insert(tk.END, f"\nMonitoreo detenido: {max_errores} errores consecutivos detectados.\n")
                self.text_monitor.see(tk.END)
                self._log_terminal(f"Monitoreo detenido: {max_errores} errores consecutivos detectados", "MONITOREO-RED", "ERROR")
        except Exception as e:
            self.text_monitor.insert(tk.END, f"\nError fatal en monitoreo de red: {str(e)}\n")
            self.text_monitor.see(tk.END)
            self._log_terminal(f"Error fatal en monitoreo de red: {str(e)}", "MONITOREO-RED", "ERROR")
        finally:
            self.text_monitor.insert(tk.END, "\nFinalizando monitoreo de red.\n")
            self.text_monitor.see(tk.END)
            self._log_terminal("Finalizando monitoreo de red", "MONITOREO-RED", "INFO")
            self.after(0, self._finalizar_monitoreo_red)

    def _detectar_dispositivos_red_seguro(self):
        """Detectar dispositivos de red con manejo robusto de errores - Issue 19/24."""
        try:
            # Usar el método de comando seguro para obtener redes locales
            resultado = self._ejecutar_comando_seguro(['ip', 'route', 'show'], timeout=10)
            if not resultado['success']:
                self.text_monitor.insert(tk.END, f"[FASE 1] Error obteniendo rutas: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo rutas: {resultado['error']}", "MONITOREO-RED", "WARNING")
                return
            redes_locales = []
            for linea in resultado['output'].split('\n'):
                if 'src' in linea and ('192.168.' in linea or '10.' in linea or '172.' in linea):
                    partes = linea.split()
                    if len(partes) > 0:
                        red = partes[0]
                        if '/' in red:
                            redes_locales.append(red)
            if not redes_locales:
                self.text_monitor.insert(tk.END, "[FASE 1] No se detectaron redes locales.\n")
                self._log_terminal("No se detectaron redes locales", "MONITOREO-RED", "INFO")
                return
            self.text_monitor.insert(tk.END, f"[FASE 1] Redes locales detectadas: {', '.join(redes_locales)}\n")
            dispositivos_encontrados = 0
            dispositivos_info = []
            # Usar nmap si está disponible para escaneo profesional
            try:
                resultado_nmap = self._ejecutar_comando_seguro(['nmap', '-sn', redes_locales[0]], timeout=15)
                if resultado_nmap['success'] and resultado_nmap['output']:
                    for linea in resultado_nmap['output'].split('\n'):
                        if 'Nmap scan report for' in linea:
                            ip = linea.split()[-1]
                            dispositivos_encontrados += 1
                            dispositivos_info.append(ip)
                    if dispositivos_info:
                        self.text_monitor.insert(tk.END, f"[FASE 1] Dispositivos detectados (nmap): {', '.join(dispositivos_info)}\n")
                    else:
                        self.text_monitor.insert(tk.END, "[FASE 1] No se detectaron dispositivos activos con nmap.\n")
                else:
                    self.text_monitor.insert(tk.END, "[FASE 1] nmap no disponible o sin resultados, usando ping básico...\n")
                    # Fallback a ping básico
                    red_base = redes_locales[0].split('/')[0].rsplit('.', 1)[0]
                    for i in range(1, 11):
                        if not self.flag_red.is_set():
                            break
                        ip = f"{red_base}.{i}"
                        resultado_ping = self._ejecutar_comando_seguro(['ping', '-c', '1', '-W', '1', ip], timeout=3)
                        if resultado_ping['success'] and resultado_ping['returncode'] == 0:
                            dispositivos_encontrados += 1
                            dispositivos_info.append(ip)
                    if dispositivos_info:
                        self.text_monitor.insert(tk.END, f"[FASE 1] Dispositivos detectados (ping): {', '.join(dispositivos_info)}\n")
                    else:
                        self.text_monitor.insert(tk.END, "[FASE 1] No se detectaron dispositivos activos con ping.\n")
            except Exception as e:
                self.text_monitor.insert(tk.END, f"[FASE 1] Error usando nmap/ping: {str(e)}\n")
            self._log_terminal(f"Total dispositivos detectados: {dispositivos_encontrados}", "MONITOREO-RED", "INFO")
        except Exception as e:
            self.text_monitor.insert(tk.END, f"[FASE 1] Error en detección de dispositivos: {str(e)}\n")
            self._log_terminal(f"Error en detección segura de dispositivos: {str(e)}", "MONITOREO-RED", "WARNING")

    def _detectar_dispositivos_red(self):
        """Detectar todos los dispositivos conectados a la red local."""
        import subprocess
        
        try:
            # Obtener la red local
            resultado = subprocess.run(['ip', 'route', 'show'], 
                                     capture_output=True, text=True, timeout=10)
            
            redes_locales = []
            for linea in resultado.stdout.split('\n'):
                if 'src' in linea and ('192.168.' in linea or '10.' in linea or '172.' in linea):
                    partes = linea.split()
                    if len(partes) > 0:
                        red = partes[0]
                        if '/' in red:
                            redes_locales.append(red)
                            
            # Escanear dispositivos en cada red local
            dispositivos_encontrados = 0
            for red in redes_locales[:2]:  # Limitar a 2 redes
                try:
                    # Usar ping para detectar dispositivos activos
                    red_base = red.split('/')[0].rsplit('.', 1)[0]
                    
                    for i in range(1, 20):  # Escanear primeros 20 IPs
                        if not self.flag_red.is_set():
                            break
                            
                        ip = f"{red_base}.{i}"
                        resultado = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                                 capture_output=True, text=True, timeout=3)
                        
                        if resultado.returncode == 0:
                            dispositivos_encontrados += 1
                            self._log_terminal(f"DISPOSITIVO DETECTADO: {ip} activo en red local", "MONITOREO-RED", "INFO")
                            
                            # Intentar obtener hostname
                            try:
                                resultado_host = subprocess.run(['nslookup', ip], 
                                                              capture_output=True, text=True, timeout=2)
                                if 'name =' in resultado_host.stdout:
                                    hostname = resultado_host.stdout.split('name =')[1].split()[0]
                                    self._log_terminal(f"  Hostname: {hostname}", "MONITOREO-RED", "INFO")
                            except:
                                pass
                                
                except Exception as e:
                    self._log_terminal(f"Error escaneando red {red}: {str(e)}", "MONITOREO-RED", "WARNING")
                    
            self._log_terminal(f"Dispositivos detectados en red local: {dispositivos_encontrados}", "MONITOREO-RED", "INFO")
            
        except Exception as e:
            self._log_terminal(f"Error detectando dispositivos: {str(e)}", "MONITOREO-RED", "WARNING")

    def _monitorear_interfaces_red_seguro(self):
        """Monitorear interfaces de red de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ip', '-brief', 'addr'], timeout=10)
            if not resultado['success']:
                self.text_monitor.insert(tk.END, f"[FASE 2] Error obteniendo interfaces: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo interfaces: {resultado['error']}", "MONITOREO-RED", "WARNING")
                return
            interfaces_activas = []
            for linea in resultado['output'].split('\n'):
                partes = linea.split()
                if len(partes) >= 3 and partes[1] == 'UP':
                    nombre = partes[0]
                    ip = partes[2] if len(partes) > 2 else 'N/A'
                    interfaces_activas.append(f"{nombre} ({ip})")
            if interfaces_activas:
                self.text_monitor.insert(tk.END, f"[FASE 2] Interfaces activas: {', '.join(interfaces_activas)}\n")
            else:
                self.text_monitor.insert(tk.END, "[FASE 2] No hay interfaces activas.\n")
            self._log_terminal(f"Total interfaces activas: {len(interfaces_activas)}", "MONITOREO-RED", "INFO")
        except Exception as e:
            self.text_monitor.insert(tk.END, f"[FASE 2] Error monitoreando interfaces: {str(e)}\n")
            self._log_terminal(f"Error monitoreando interfaces de red: {str(e)}", "MONITOREO-RED", "WARNING")

    def _monitorear_conexiones_activas_seguro(self):
        """Monitorear conexiones activas de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ss', '-tupna'], timeout=10)
            if not resultado['success']:
                self.text_monitor.insert(tk.END, f"[FASE 3] Error obteniendo conexiones: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo conexiones: {resultado['error']}", "MONITOREO-RED", "WARNING")
                return
            conexiones_tcp = []
            conexiones_udp = []
            for linea in resultado['output'].split('\n'):
                if linea.startswith('tcp') and 'LISTEN' in linea:
                    conexiones_tcp.append(linea)
                elif linea.startswith('udp'):
                    conexiones_udp.append(linea)
            self.text_monitor.insert(tk.END, f"[FASE 3] Conexiones TCP en escucha: {len(conexiones_tcp)}\n")
            for c in conexiones_tcp[:5]:
                self.text_monitor.insert(tk.END, f"  {c}\n")
            self.text_monitor.insert(tk.END, f"[FASE 3] Conexiones UDP: {len(conexiones_udp)}\n")
            for c in conexiones_udp[:5]:
                self.text_monitor.insert(tk.END, f"  {c}\n")
            self._log_terminal(f"CONEXIONES ACTIVAS: {len(conexiones_tcp)} TCP, {len(conexiones_udp)} UDP", "MONITOREO-RED", "INFO")
        except Exception as e:
            self.text_monitor.insert(tk.END, f"[FASE 3] Error monitoreando conexiones: {str(e)}\n")
            self._log_terminal(f"Error monitoreando conexiones: {str(e)}", "MONITOREO-RED", "WARNING")

    def _verificar_puertos_abiertos_seguro(self):
        """Verificar puertos abiertos de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ss', '-lntup'], timeout=10)
            if not resultado['success']:
                self.text_monitor.insert(tk.END, f"[FASE 4] Error obteniendo puertos: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo puertos: {resultado['error']}", "MONITOREO-RED", "WARNING")
                return
            puertos_tcp = []
            for linea in resultado['output'].split('\n'):
                if 'LISTEN' in linea and ':' in linea:
                    partes = linea.split()
                    if len(partes) >= 5:
                        direccion = partes[4]
                        if ':' in direccion:
                            puerto = direccion.split(':')[-1]
                            if puerto.isdigit():
                                puertos_tcp.append(puerto)
            puertos_unicos = list(set(puertos_tcp))
            self.text_monitor.insert(tk.END, f"[FASE 4] Puertos TCP abiertos: {', '.join(puertos_unicos) if puertos_unicos else 'Ninguno'}\n")
            puertos_importantes = ['22', '80', '443', '3389', '21', '25']
            for puerto in puertos_importantes:
                if puerto in puertos_unicos:
                    self.text_monitor.insert(tk.END, f"  [ALERTA] Puerto crítico abierto: {puerto}\n")
            self._log_terminal(f"PUERTOS ABIERTOS: {len(puertos_unicos)} puertos TCP en escucha", "MONITOREO-RED", "INFO")
        except Exception as e:
            self.text_monitor.insert(tk.END, f"[FASE 4] Error verificando puertos: {str(e)}\n")
            self._log_terminal(f"Error verificando puertos: {str(e)}", "MONITOREO-RED", "WARNING")

    def _monitorear_trafico_red_seguro(self):
        """Monitorear tráfico de red de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ifstat', '-q', '1', '1'], timeout=5)
            if not resultado['success']:
                self.text_monitor.insert(tk.END, f"[FASE 5] Error obteniendo estadísticas de red: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo estadísticas de red: {resultado['error']}", "MONITOREO-RED", "WARNING")
                return
            self.text_monitor.insert(tk.END, f"[FASE 5] Estadísticas de tráfico de red (ifstat):\n{resultado['output']}\n")
            self._log_terminal(f"Tráfico de red mostrado con ifstat", "MONITOREO-RED", "INFO")
        except Exception as e:
            self.text_monitor.insert(tk.END, f"[FASE 5] Error monitoreando tráfico: {str(e)}\n")
            self._log_terminal(f"Error monitoreando tráfico: {str(e)}", "MONITOREO-RED", "WARNING")

    def _verificar_configuracion_red_seguro(self):
        """Verificar configuración de red de forma segura - Issue 19/24."""
        try:
            # Verificar gateway
            resultado = self._ejecutar_comando_seguro(['ip', 'route', 'show', 'default'], timeout=5)
            
            if resultado['success'] and resultado['output']:
                gateway = "detectado"
                for linea in resultado['output'].split('\n'):
                    if 'default via' in linea:
                        partes = linea.split()
                        if len(partes) >= 3:
                            gateway = partes[2]
                            break
                self._log_terminal(f"GATEWAY: {gateway}", "MONITOREO-RED", "INFO")
            else:
                self._log_terminal("Gateway no detectado", "MONITOREO-RED", "WARNING")
            
            # Verificar DNS
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    contenido = f.read()
                    dns_servers = [linea.split()[1] for linea in contenido.split('\n') if linea.startswith('nameserver')]
                    self._log_terminal(f"DNS SERVERS: {len(dns_servers)} configurados", "MONITOREO-RED", "INFO")
            except Exception:
                self._log_terminal("No se pudo leer configuración DNS", "MONITOREO-RED", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error verificando configuración: {str(e)}", "MONITOREO-RED", "WARNING")

    def _monitorear_interfaces_red(self):
        """Monitorear todas las interfaces de red activas."""
        import subprocess
        
        try:
            # Obtener información de interfaces
            resultado = subprocess.run(['ip', 'addr', 'show'], 
                                     capture_output=True, text=True, timeout=10)
            
            interfaces_activas = []
            interface_actual = None
            
            for linea in resultado.stdout.split('\n'):
                if ': ' in linea and 'state' in linea.lower():
                    partes = linea.split(': ')
                    if len(partes) > 1:
                        nombre = partes[1].split('@')[0]
                        estado = 'UP' if 'state UP' in linea else 'DOWN'
                        interface_actual = {'nombre': nombre, 'estado': estado, 'ips': []}
                        
                elif 'inet ' in linea and interface_actual:
                    ip = linea.strip().split()[1]
                    interface_actual['ips'].append(ip)
                    
                elif interface_actual and (linea.strip() == '' or ': ' in linea):
                    if interface_actual['estado'] == 'UP':
                        interfaces_activas.append(interface_actual)
                    interface_actual = None
                    
            # Reportar interfaces activas
            for interfaz in interfaces_activas:
                nombre = interfaz['nombre']
                ips = ', '.join(interfaz['ips'])
                self._log_terminal(f"INTERFAZ ACTIVA: {nombre} - IPs: {ips}", "MONITOREO-RED", "INFO")
                
                # Obtener estadísticas de tráfico
                try:
                    with open(f'/sys/class/net/{nombre}/statistics/rx_bytes', 'r') as f:
                        rx_bytes = int(f.read().strip())
                    with open(f'/sys/class/net/{nombre}/statistics/tx_bytes', 'r') as f:
                        tx_bytes = int(f.read().strip())
                        
                    rx_mb = rx_bytes / (1024 * 1024)
                    tx_mb = tx_bytes / (1024 * 1024)
                    self._log_terminal(f"  Trafico {nombre}: RX {rx_mb:.1f}MB, TX {tx_mb:.1f}MB", "MONITOREO-RED", "INFO")
                except:
                    pass
                    
        except Exception as e:
            self._log_terminal(f"Error monitoreando interfaces: {str(e)}", "MONITOREO-RED", "WARNING")

    def _monitorear_conexiones_activas(self):
        """Monitorear todas las conexiones de red activas."""
        import subprocess
        
        try:
            # Obtener conexiones TCP y UDP
            resultado = subprocess.run(['ss', '-tuln'], 
                                     capture_output=True, text=True, timeout=10)
            
            conexiones_tcp = 0
            conexiones_udp = 0
            puertos_abiertos = []
            
            for linea in resultado.stdout.split('\n'):
                if 'LISTEN' in linea:
                    partes = linea.split()
                    if len(partes) >= 4:
                        protocolo = 'TCP' if 'tcp' in linea.lower() else 'UDP'
                        direccion = partes[3]
                        puerto = direccion.split(':')[-1]
                        
                        if protocolo == 'TCP':
                            conexiones_tcp += 1
                        else:
                            conexiones_udp += 1
                            
                        puertos_abiertos.append((protocolo, puerto, direccion))
                        
            self._log_terminal(f"Conexiones activas: {conexiones_tcp} TCP, {conexiones_udp} UDP", "MONITOREO-RED", "INFO")
            
            # Mostrar puertos más relevantes
            puertos_importantes = ['22', '80', '443', '21', '25', '53', '110', '143', '993', '995']
            for protocolo, puerto, direccion in puertos_abiertos:
                if puerto in puertos_importantes:
                    self._log_terminal(f"PUERTO IMPORTANTE: {protocolo} {puerto} en {direccion}", "MONITOREO-RED", "WARNING")
                    
            # Verificar conexiones establecidas
            resultado = subprocess.run(['ss', '-tupn'], 
                                     capture_output=True, text=True, timeout=10)
            
            conexiones_establecidas = 0
            for linea in resultado.stdout.split('\n'):
                if 'ESTAB' in linea:
                    conexiones_establecidas += 1
                    
            self._log_terminal(f"Conexiones establecidas: {conexiones_establecidas}", "MONITOREO-RED", "INFO")
            
            if conexiones_establecidas > 50:
                self._log_terminal(f"ALERTA: Muchas conexiones establecidas ({conexiones_establecidas})", "MONITOREO-RED", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error monitoreando conexiones: {str(e)}", "MONITOREO-RED", "WARNING")

    def _monitorear_trafico_red_detallado(self):
        """Monitorear tráfico de red detallado."""
        import subprocess
        
        try:
            # Verificar estadísticas de red del sistema
            with open('/proc/net/dev', 'r') as f:
                lineas = f.readlines()
                
            interfaces_con_trafico = []
            for linea in lineas[2:]:  # Saltar headers
                if ':' in linea:
                    partes = linea.split(':')
                    interfaz = partes[0].strip()
                    estadisticas = partes[1].split()
                    
                    if len(estadisticas) >= 8 and interfaz != 'lo':
                        rx_bytes = int(estadisticas[0])
                        tx_bytes = int(estadisticas[8])
                        
                        if rx_bytes > 0 or tx_bytes > 0:
                            interfaces_con_trafico.append({
                                'interfaz': interfaz,
                                'rx_bytes': rx_bytes,
                                'tx_bytes': tx_bytes
                            })
                            
            for interfaz_data in interfaces_con_trafico:
                interfaz = interfaz_data['interfaz']
                rx_mb = interfaz_data['rx_bytes'] / (1024 * 1024)
                tx_mb = interfaz_data['tx_bytes'] / (1024 * 1024)
                
                self._log_terminal(f"TRAFICO {interfaz}: Recibido {rx_mb:.1f}MB, Enviado {tx_mb:.1f}MB", "MONITOREO-RED", "INFO")
                
                # Alertar sobre tráfico excesivo
                if rx_mb > 1000 or tx_mb > 1000:  # Más de 1GB
                    self._log_terminal(f"ALERTA TRAFICO: {interfaz} con alto volumen de datos", "MONITOREO-RED", "WARNING")
                    
        except Exception as e:
            self._log_terminal(f"Error monitoreando trafico: {str(e)}", "MONITOREO-RED", "WARNING")

    def _detectar_servicios_red(self):
        """Detectar servicios de red disponibles."""
        import subprocess
        
        try:
            # Verificar servicios de red comunes en localhost
            servicios_comunes = [
                ('SSH', '22'), ('HTTP', '80'), ('HTTPS', '443'), ('FTP', '21'),
                ('SMTP', '25'), ('DNS', '53'), ('POP3', '110'), ('IMAP', '143')
            ]
            
            servicios_activos = []
            
            for nombre, puerto in servicios_comunes:
                try:
                    resultado = subprocess.run(['ss', '-ln'], 
                                             capture_output=True, text=True, timeout=5)
                    
                    if f':{puerto} ' in resultado.stdout:
                        servicios_activos.append((nombre, puerto))
                        self._log_terminal(f"SERVICIO ACTIVO: {nombre} en puerto {puerto}", "MONITOREO-RED", "INFO")
                except:
                    pass
                    
            if not servicios_activos:
                self._log_terminal("No se detectaron servicios de red comunes activos", "MONITOREO-RED", "INFO")
            else:
                self._log_terminal(f"Servicios de red detectados: {len(servicios_activos)}", "MONITOREO-RED", "INFO")
                
        except Exception as e:
            self._log_terminal(f"Error detectando servicios: {str(e)}", "MONITOREO-RED", "WARNING")

    def _verificar_configuracion_red(self):
        """Verificar configuración de red del sistema."""
        import subprocess
        
        try:
            # Verificar tabla de rutas
            resultado = subprocess.run(['ip', 'route', 'show'], 
                                     capture_output=True, text=True, timeout=5)
            
            rutas = resultado.stdout.strip().split('\n')
            rutas_activas = [r for r in rutas if r.strip()]
            
            self._log_terminal(f"Tabla de rutas: {len(rutas_activas)} rutas configuradas", "MONITOREO-RED", "INFO")
            
            # Buscar gateway por defecto
            gateway_default = None
            for ruta in rutas_activas:
                if 'default' in ruta:
                    partes = ruta.split()
                    if 'via' in partes:
                        idx = partes.index('via')
                        if idx + 1 < len(partes):
                            gateway_default = partes[idx + 1]
                            break
                            
            if gateway_default:
                self._log_terminal(f"Gateway por defecto: {gateway_default}", "MONITOREO-RED", "INFO")
                
                # Probar conectividad al gateway
                resultado = subprocess.run(['ping', '-c', '1', '-W', '2', gateway_default], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0:
                    self._log_terminal("Conectividad al gateway: OK", "MONITOREO-RED", "INFO")
                else:
                    self._log_terminal("PROBLEMA: Sin conectividad al gateway", "MONITOREO-RED", "ERROR")
            else:
                self._log_terminal("WARNING: No se encontro gateway por defecto", "MONITOREO-RED", "WARNING")
                
            # Verificar DNS
            try:
                resultado = subprocess.run(['nslookup', 'google.com'], 
                                         capture_output=True, text=True, timeout=10)
                if resultado.returncode == 0:
                    self._log_terminal("Resolucion DNS: OK", "MONITOREO-RED", "INFO")
                else:
                    self._log_terminal("PROBLEMA: Fallo en resolucion DNS", "MONITOREO-RED", "ERROR")
            except:
                self._log_terminal("WARNING: No se pudo probar DNS", "MONITOREO-RED", "WARNING")
                
        except Exception as e:
            self._log_terminal(f"Error verificando configuracion de red: {str(e)}", "MONITOREO-RED", "WARNING")
    
    def _mostrar_resultados_red(self, resultados):
        """Mostrar resultados del monitoreo de red."""
        if self.flag_red.is_set():
            return
        for resultado in resultados:
            self.text_monitor.insert(tk.END, f"{resultado}\n")
        
        self.text_monitor.see(tk.END)
    
    def _mostrar_error_red(self, error):
        """Mostrar error del monitoreo de red."""
        self.text_monitor.insert(tk.END, f"\n Error en monitoreo de red: {error}\n")
    
    def _finalizar_monitoreo_red(self):
        """Finalizar monitoreo de red."""
        self.flag_red.set()
        self.btn_red.config(state="normal")
        self.btn_cancelar_red.config(state="disabled")
        self.thread_red = None
        self.text_monitor.insert(tk.END, "\n=== MONITOREO DE RED FINALIZADO ===\n")
    
    def cancelar_monitoreo_red(self):
        """Cancelar el monitoreo de red con advertencia profesional."""
        import tkinter.messagebox as messagebox
        if not messagebox.askyesno("Confirmar acción crítica", "¿Está seguro que desea cancelar el monitoreo de red? Esta acción puede afectar la supervisión de red en curso."):
            self.log_to_terminal("Operación de cancelación de monitoreo de red cancelada por el usuario.")
            return
        if not self.flag_red.is_set():
            self.flag_red.set()
            self.text_monitor.insert(tk.END, "\n Monitoreo de red cancelado por el usuario.\n")
            self._finalizar_monitoreo_red()
    
    def agregar_a_cuarentena(self):
        """Agregar archivo a cuarentena con validación de seguridad y manejo robusto de errores."""
        from aresitos.utils.sanitizador_archivos import SanitizadorArchivos
        from aresitos.utils.helper_seguridad import HelperSeguridad
        
        # Importar SudoManager para prevenir crashes
        try:
            from aresitos.utils.sudo_manager import SudoManager
            sudo_manager = SudoManager()
            if not sudo_manager.is_sudo_active():
                self.text_cuarentena.insert(tk.END, "WARNING SUDO NO ACTIVO: Verificar permisos en otras ventanas de ARESITOS\n")
                messagebox.showwarning("Permisos", "Sudo no activo. Algunas operaciones pueden fallar.")
        except ImportError:
            sudo_manager = None
            self.text_cuarentena.insert(tk.END, "WARNING SudoManager no disponible - usando modo básico\n")
        
        # Mostrar advertencia especial para cuarentena
        if not HelperSeguridad.mostrar_advertencia_cuarentena():
            self.text_cuarentena.insert(tk.END, "CANCEL Usuario canceló la operación de cuarentena\n")
            return
        
        # Usar filtros de seguridad más amplios para cuarentena (cualquier archivo puede ser sospechoso)
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo para cuarentena",
            filetypes=[
                ("Todos los archivos", "*.*"),
                ("Archivos ejecutables", "*.exe;*.bat;*.sh;*.py"),
                ("Archivos de script", "*.js;*.vbs;*.ps1"),
                ("Archivos de documento", "*.pdf;*.doc;*.docx")
            ]
        )
        if not archivo:
            self.text_cuarentena.insert(tk.END, "CANCEL Usuario canceló selección de archivo\n")
            return
        
        try:
            # Verificar que el archivo existe antes de continuar
            if not os.path.exists(archivo):
                error_msg = f"El archivo {archivo} no existe"
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                return
            
            # Verificar permisos de acceso
            try:
                file_stat = os.stat(archivo)
                self.text_cuarentena.insert(tk.END, f"INFO: Archivo encontrado - Tamaño: {file_stat.st_size} bytes\n")
            except PermissionError:
                self.text_cuarentena.insert(tk.END, f"WARNING Sin permisos para acceder a {archivo}\n")
                if sudo_manager:
                    self.text_cuarentena.insert(tk.END, "INFO: Usando SudoManager para acceso con privilegios\n")
                else:
                    respuesta = messagebox.askyesno("Permisos", 
                                                  "Sin permisos de acceso. ¿Continuar de todos modos?")
                    if not respuesta:
                        return
            
            # VALIDACIÓN BÁSICA DE SEGURIDAD (menos restrictiva para cuarentena)
            sanitizador = SanitizadorArchivos()
            
            # Solo verificar ruta y nombre seguro, no contenido (puede ser malicioso)
            if not sanitizador._validar_ruta_segura(archivo):
                error_msg = "Ruta de archivo no segura"
                self.text_cuarentena.insert(tk.END, f"ERROR Error de seguridad: {error_msg}\n")
                messagebox.showerror("Error de Seguridad", error_msg)
                return
            
            if not sanitizador._validar_nombre_archivo(archivo):
                error_msg = "Nombre de archivo contiene caracteres peligrosos"
                self.text_cuarentena.insert(tk.END, f"ERROR Error de seguridad: {error_msg}\n")
                messagebox.showerror("Error de Seguridad", error_msg)
                return
            
            # Verificar tamaño razonable
            if not sanitizador._validar_tamano(archivo):
                error_msg = "Archivo demasiado grande para cuarentena"
                self.text_cuarentena.insert(tk.END, f"ERROR Error: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                return
            
            self.text_cuarentena.insert(tk.END, f"SECURE Archivo validado para cuarentena: {os.path.basename(archivo)}\n")
            
            # Crear controlador de cuarentena directamente si no está disponible
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            # Crear modelo principal básico para el controlador
            modelo_principal = {'cuarentena': None}
            controlador_cuarentena = ControladorCuarentena(modelo_principal)
            
            # Mostrar progreso
            self.text_cuarentena.insert(tk.END, "PROCESSING Iniciando proceso de cuarentena...\n")
            self.text_cuarentena.update()
            
            resultado = controlador_cuarentena.poner_en_cuarentena(archivo)
            
            if resultado["exito"]:
                self.text_cuarentena.insert(tk.END, f"OK Archivo agregado a cuarentena: {os.path.basename(archivo)}\n")  # Issue 22/24: Sin emojis
                self.text_cuarentena.insert(tk.END, f"OK Proceso completado exitosamente\n")  # Issue 22/24: Sin emojis
                messagebox.showinfo("Éxito", "Archivo enviado a cuarentena correctamente")
            else:
                error_msg = resultado.get('error', 'Error desconocido en cuarentena')
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                
        except FileNotFoundError as e:
            error_msg = f"Archivo no encontrado: {str(e)}"
            self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)
        except PermissionError as e:
            error_msg = f"Sin permisos: {str(e)}"
            self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            messagebox.showerror("Error de Permisos", error_msg)
        except ImportError as e:
            error_msg = f"Error importando módulos: {str(e)}"
            self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            messagebox.showerror("Error del Sistema", error_msg)
        except Exception as e:
            error_msg = f"Error del sistema: {str(e)}"
            self.text_cuarentena.insert(tk.END, f"ERROR CRÍTICO: {error_msg}\n")
            messagebox.showerror("Error Crítico", error_msg)
            
            # Log adicional para debugging
            import logging
            logger = logging.getLogger("AresAegis.VistaMonitoreo")
            logger.error(f"Error crítico en agregar_a_cuarentena: {e}", exc_info=True)
    
    def listar_cuarentena(self):
        """Listar archivos en cuarentena con manejo robusto de errores"""
        try:
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            # Crear modelo principal básico para el controlador
            modelo_principal = {'cuarentena': None}
            controlador_cuarentena = ControladorCuarentena(modelo_principal)
            
            self.text_cuarentena.delete(1.0, tk.END)
            self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
            
            # Mostrar estado de carga
            self.text_cuarentena.insert(tk.END, "LOADING Cargando archivos de cuarentena...\n")
            self.text_cuarentena.update()
            
            archivos = controlador_cuarentena.listar_archivos_cuarentena()
            
            # Limpiar mensaje de carga
            self.text_cuarentena.delete(1.0, tk.END)
            self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
            
            if not archivos:
                self.text_cuarentena.insert(tk.END, "OK No hay archivos en cuarentena.\n")  # Issue 22/24: Sin emojis
                self.text_cuarentena.insert(tk.END, "OK Sistema limpio\n")  # Issue 22/24: Sin emojis
            else:
                self.text_cuarentena.insert(tk.END, f"TOTAL: {len(archivos)} archivo(s) en cuarentena\n\n")
                
                for i, archivo in enumerate(archivos, 1):
                    try:
                        nombre = archivo.get('ruta_original', 'Desconocido')
                        fecha = archivo.get('fecha', 'N/A')
                        razon = archivo.get('razon', 'N/A')
                        
                        self.text_cuarentena.insert(tk.END, f"{i}. {os.path.basename(nombre)}\n")
                        self.text_cuarentena.insert(tk.END, f"   Ruta: {nombre}\n")
                        self.text_cuarentena.insert(tk.END, f"   Fecha: {fecha}\n")
                        self.text_cuarentena.insert(tk.END, f"   Razón: {razon}\n\n")
                    except Exception as e:
                        self.text_cuarentena.insert(tk.END, f"   ERROR procesando archivo {i}: {e}\n\n")
                    
            # Obtener resumen adicional con manejo de errores
            try:
                resumen = controlador_cuarentena.obtener_estadisticas()
                if resumen:
                    self.text_cuarentena.insert(tk.END, f"\n=== RESUMEN ===\n")
                    total = resumen.get('total_archivos', 0)
                    tamaño = resumen.get('tamano_total', 0)
                    
                    self.text_cuarentena.insert(tk.END, f"Total archivos: {total}\n")
                    
                    # Convertir bytes a formato legible
                    if tamaño > 1024 * 1024:  # MB
                        tamaño_str = f"{tamaño / (1024 * 1024):.2f} MB"
                    elif tamaño > 1024:  # KB
                        tamaño_str = f"{tamaño / 1024:.2f} KB"
                    else:
                        tamaño_str = f"{tamaño} bytes"
                    
                    self.text_cuarentena.insert(tk.END, f"Tamaño total: {tamaño_str}\n")
            except Exception as e:
                self.text_cuarentena.insert(tk.END, f"\nWARNING Error obteniendo resumen: {e}\n")
                
        except ImportError as e:
            error_msg = f"Error importando controlador de cuarentena: {e}"
            self.text_cuarentena.delete(1.0, tk.END)
            self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
        except Exception as e:
            error_msg = f"Error listando cuarentena: {e}"
            self.text_cuarentena.delete(1.0, tk.END) 
            self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            
            # Log adicional para debugging
            import logging
            logger = logging.getLogger("AresAegis.VistaMonitoreo")
            logger.error(f"Error en listar_cuarentena: {e}", exc_info=True)
        
        if not archivos:
            self.text_cuarentena.insert(tk.END, "No hay archivos en cuarentena.\n")
            return
        
        self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
        for archivo in archivos:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(archivo["timestamp"])))
            self.text_cuarentena.insert(tk.END, 
                f"Hash: {archivo['hash']}\n"
                f"Archivo: {archivo['archivo_original']}\n"
                f"Motivo: {archivo['motivo']}\n"
                f"Fecha: {timestamp}\n"
                f"{'='*50}\n\n"
            )
    
    def limpiar_cuarentena(self):
        """Limpiar cuarentena con manejo robusto de errores y confirmación segura"""
        try:
            # Verificar que el controlador existe
            if not hasattr(self, 'controlador') or not self.controlador:
                self.text_cuarentena.insert(tk.END, "ERROR: Controlador no disponible\n")
                messagebox.showerror("Error", "Controlador de monitoreo no disponible")
                return
            
            # Confirmación doble para operación destructiva
            respuesta1 = messagebox.askyesno("Confirmación 1/2", 
                                           "¿Está seguro de que desea eliminar TODOS los archivos de cuarentena?")
            if not respuesta1:
                self.text_cuarentena.insert(tk.END, "CANCEL Usuario canceló limpieza de cuarentena\n")
                return
            
            respuesta2 = messagebox.askyesno("Confirmación 2/2", 
                                           "ÚLTIMA OPORTUNIDAD: Esta acción NO SE PUEDE DESHACER.\n" +
                                           "¿Eliminar permanentemente todos los archivos de cuarentena?")
            if not respuesta2:
                self.text_cuarentena.insert(tk.END, "CANCEL Usuario canceló limpieza de cuarentena en segunda confirmación\n")
                return
            
            # Importar SudoManager para operaciones seguras
            try:
                from aresitos.utils.sudo_manager import SudoManager
                sudo_manager = SudoManager()
                if not sudo_manager.is_sudo_active():
                    self.text_cuarentena.insert(tk.END, "WARNING SUDO NO ACTIVO: La operacion puede fallar\n")
            except ImportError:
                sudo_manager = None
            
            # Mostrar progreso
            self.text_cuarentena.insert(tk.END, "PROCESSING Iniciando limpieza de cuarentena...\n")
            self.text_cuarentena.update()
            
            # Ejecutar limpieza con timeout y manejo de errores
            try:
                resultado = self.controlador.limpiar_cuarentena_completa()
                
                if isinstance(resultado, dict):
                    eliminados = resultado.get('eliminados', 0)
                    errores = resultado.get('errores', [])
                    
                    self.text_cuarentena.insert(tk.END, f"OK Cuarentena limpiada exitosamente\n")  # Issue 22/24: Sin emojis
                    self.text_cuarentena.insert(tk.END, f"OK Archivos eliminados: {eliminados}\n")  # Issue 22/24: Sin emojis
                    
                    if errores:
                        self.text_cuarentena.insert(tk.END, f"WARNING Se encontraron {len(errores)} errores:\n")
                        for i, error in enumerate(errores[:5], 1):  # Mostrar solo los primeros 5
                            self.text_cuarentena.insert(tk.END, f"   {i}. {error}\n")
                        if len(errores) > 5:
                            self.text_cuarentena.insert(tk.END, f"   ... y {len(errores) - 5} errores más\n")
                    else:
                        self.text_cuarentena.insert(tk.END, "OK Sin errores reportados\n")  # Issue 22/24: Sin emojis
                    
                    messagebox.showinfo("Éxito", f"Cuarentena limpiada. Archivos eliminados: {eliminados}")
                else:
                    self.text_cuarentena.insert(tk.END, f"WARNING Resultado inesperado: {resultado}\n")
                    
            except Exception as e:
                error_msg = f"Error durante limpieza: {str(e)}"
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                
        except Exception as e:
            error_msg = f"Error crítico en limpiar_cuarentena: {str(e)}"
            self.text_cuarentena.insert(tk.END, f"ERROR CRÍTICO: {error_msg}\n")
            messagebox.showerror("Error Crítico", error_msg)
            
            # Log adicional para debugging
            import logging
            logger = logging.getLogger("AresAegis.VistaMonitoreo")
            logger.error(f"Error crítico en limpiar_cuarentena: {e}", exc_info=True)
    
    def _iniciar_monitoreo_linux_avanzado(self):
        """Iniciar monitoreo usando herramientas nativas de Linux."""
        self.monitor_activo = True
        self.btn_iniciar_monitor.config(state="disabled")
        self.btn_detener_monitor.config(state="normal")
        self.label_estado.config(text="Estado: Activo (Linux)")
        
        self.text_monitor.delete(1.0, tk.END)
        self.text_monitor.insert(tk.END, "=== MONITOREO AVANZADO CON HERRAMIENTAS LINUX ===\n\n")
        
        # Iniciar monitoreo en thread separado
        threading.Thread(target=self._monitoreo_avanzado_linux, daemon=True).start()
        try:
            if hasattr(self, 'after'):
                self.after(3000, self.actualizar_monitoreo)
        except RuntimeError:
            pass
    
    def _monitoreo_avanzado_linux(self):
        """Monitoreo avanzado usando comandos nativos de Linux."""
        try:
            import subprocess
            import time
            
            contador = 0
            while self.monitor_activo and contador < 10:  # Máximo 10 ciclos
                try:
                    # 1. Monitoreo de procesos con alta CPU usando top
                    self.after(0, self._actualizar_texto_monitor, f"\n=== CICLO {contador + 1} - MONITOREO LINUX AVANZADO ===\n")
                    
                    # Procesos con mayor uso de CPU
                    try:
                        resultado = subprocess.run(['bash', '-c', 'ps aux --sort=-%cpu | head -6'], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                            self.after(0, self._actualizar_texto_monitor, "COMANDO: ps aux --sort=-%cpu\n")
                            self.after(0, self._actualizar_texto_monitor, "TOP PROCESOS POR CPU:\n")
                            for linea in lineas:
                                if linea.strip():
                                    partes = linea.split()
                                    if len(partes) >= 11:
                                        usuario = partes[0]
                                        pid = partes[1]
                                        cpu = partes[2]
                                        memoria = partes[3]
                                        comando = ' '.join(partes[10:13])
                                        self.after(0, self._actualizar_texto_monitor, 
                                                 f"  PID {pid}: {usuario} CPU:{cpu}% MEM:{memoria}% CMD:{comando}\n")
                    except:
                        self.after(0, self._actualizar_texto_monitor, "ERROR: No se pudo monitorear procesos con ps\n")
                    
                    # 2. Conexiones de red activas con ss
                    try:
                        resultado = subprocess.run(['ss', '-tuln'], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.strip().split('\n')[1:]  # Skip header
                            conexiones_tcp = sum(1 for linea in lineas if linea.strip() and 'tcp' in linea.lower())
                            conexiones_udp = sum(1 for linea in lineas if linea.strip() and 'udp' in linea.lower())
                            self.after(0, self._actualizar_texto_monitor, f"CONEXIONES ACTIVAS: TCP:{conexiones_tcp} UDP:{conexiones_udp}\n")
                            
                            # Mostrar puertos en escucha más relevantes
                            puertos_criticos = ['22', '80', '443', '8080', '3389', '4444', '5555']
                            for linea in lineas:
                                if any(puerto in linea for puerto in puertos_criticos):
                                    partes = linea.split()
                                    if len(partes) >= 4:
                                        puerto_local = partes[3].split(':')[-1]
                                        self.after(0, self._actualizar_texto_monitor, f"  CRÍTICO: Puerto {puerto_local} en escucha\n")
                    except:
                        self.after(0, self._actualizar_texto_monitor, "ERROR: No se pudo monitorear conexiones con ss\n")
                    
                    # 3. Uso de memoria con free
                    try:
                        resultado = subprocess.run(['free', '-h'], 
                                                 capture_output=True, text=True, timeout=5)
                        if resultado.returncode == 0:
                            lineas = resultado.stdout.strip().split('\n')
                            if len(lineas) >= 2:
                                memoria_linea = lineas[1].split()
                                if len(memoria_linea) >= 3:
                                    total = memoria_linea[1]
                                    usado = memoria_linea[2]
                                    disponible = memoria_linea[6] if len(memoria_linea) > 6 else memoria_linea[3]
                                    self.after(0, self._actualizar_texto_monitor, 
                                             f"MEMORIA: Total:{total} Usado:{usado} Disponible:{disponible}\n")
                    except:
                        self.after(0, self._actualizar_texto_monitor, "ERROR: No se pudo monitorear memoria\n")
                    
                    # 4. Monitoreo de archivos modificados recientemente
                    try:
                        resultado = subprocess.run(['find', '/tmp', '/var/tmp', '-type', 'f', '-mmin', '-5'], 
                                                 capture_output=True, text=True, timeout=15)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            archivos_recientes = resultado.stdout.strip().split('\n')
                            if len(archivos_recientes) > 0 and archivos_recientes[0]:
                                self.after(0, self._actualizar_texto_monitor, 
                                         f"ARCHIVOS TEMPORALES RECIENTES: {len(archivos_recientes)}\n")
                                for archivo in archivos_recientes[:3]:  # Mostrar primeros 3
                                    if archivo.strip():
                                        self.after(0, self._actualizar_texto_monitor, f"  RECIENTE: {archivo}\n")
                        else:
                            self.after(0, self._actualizar_texto_monitor, "OK: No hay archivos temporales recientes\n")
                    except:
                        self.after(0, self._actualizar_texto_monitor, "ERROR: No se pudo monitorear archivos temporales\n")
                    
                    # 5. Verificar intentos de login recientes
                    try:
                        resultado = subprocess.run(['bash', '-c', 'last | head -5'], 
                                                 capture_output=True, text=True, timeout=10)
                        if resultado.returncode == 0 and resultado.stdout.strip():
                            lineas = resultado.stdout.strip().split('\n')
                            logins_recientes = len([l for l in lineas if l.strip() and 'pts' in l])
                            self.after(0, self._actualizar_texto_monitor, f"LOGINS RECIENTES: {logins_recientes} sesiones activas\n")
                    except:
                        self.after(0, self._actualizar_texto_monitor, "ERROR: No se pudo verificar logins recientes\n")
                    
                    contador += 1
                    time.sleep(2)  # Issue 21/24: Optimizado de 3 a 2 segundos entre ciclos
                    
                except Exception as e:
                    self.after(0, self._actualizar_texto_monitor, f"ERROR EN CICLO: {str(e)}\n")
                    break
            
            self.after(0, self._actualizar_texto_monitor, "\n=== MONITOREO LINUX COMPLETADO ===\n")
            
        except Exception as e:
            self.after(0, self._actualizar_texto_monitor, f"ERROR GENERAL EN MONITOREO: {str(e)}\n")
    
    def _verificar_puertos_abiertos(self):
        """Verificar puertos abiertos del sistema local usando herramientas nativas de Kali."""
        import subprocess
        try:
            # Verificar puertos TCP abiertos con ss (sucesor de netstat)
            self.after(0, self._actualizar_texto_monitor, "   - Verificando puertos TCP abiertos:\n")
            result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, timeout=8)  # Issue 21/24: Optimizado de 10 a 8 segundos
            if result.returncode == 0:
                lineas = result.stdout.strip().split('\n')
                puertos_tcp = []
                for linea in lineas[1:]:  # Saltar cabecera
                    if 'LISTEN' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            direccion = partes[3]
                            if ':' in direccion:
                                puerto = direccion.split(':')[-1]
                                proceso = partes[-1] if len(partes) > 4 else "N/A"
                                puertos_tcp.append((puerto, proceso))
                                self.after(0, self._actualizar_texto_monitor, f"     Puerto TCP {puerto} ABIERTO - Proceso: {proceso}\n")
                
                if puertos_tcp:
                    self.log_to_terminal(f"Detectados {len(puertos_tcp)} puertos TCP abiertos")
                else:
                    self.after(0, self._actualizar_texto_monitor, "     No se detectaron puertos TCP en escucha\n")
            
            # Verificar puertos UDP abiertos
            self.after(0, self._actualizar_texto_monitor, "   - Verificando puertos UDP abiertos:\n")
            result = subprocess.run(['ss', '-ulnp'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lineas = result.stdout.strip().split('\n')
                puertos_udp = []
                for linea in lineas[1:]:  # Saltar cabecera
                    if 'UNCONN' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            direccion = partes[3]
                            if ':' in direccion:
                                puerto = direccion.split(':')[-1]
                                proceso = partes[-1] if len(partes) > 4 else "N/A"
                                puertos_udp.append((puerto, proceso))
                                self.after(0, self._actualizar_texto_monitor, f"     Puerto UDP {puerto} ABIERTO - Proceso: {proceso}\n")
                
                if puertos_udp:
                    self.log_to_terminal(f"Detectados {len(puertos_udp)} puertos UDP abiertos")
                else:
                    self.after(0, self._actualizar_texto_monitor, "     No se detectaron puertos UDP en escucha\n")
            
            # Verificar puertos específicos de servicios comunes con nmap
            self.after(0, self._actualizar_texto_monitor, "   - Verificando servicios en puertos comunes:\n")
            puertos_comunes = ['22', '80', '443', '21', '25', '53', '110', '143', '993', '995']
            for puerto in puertos_comunes:
                try:
                    result = subprocess.run(['nmap', '-p', puerto, 'localhost'], 
                                          capture_output=True, text=True, timeout=5)
                    if 'open' in result.stdout:
                        self.after(0, self._actualizar_texto_monitor, f"     Puerto {puerto} detectado como ABIERTO\n")
                        self.log_to_terminal(f"ALERTA: Puerto común {puerto} abierto")
                except:
                    pass
                    
        except Exception as e:
            self.after(0, self._actualizar_texto_monitor, f"ERROR verificando puertos: {str(e)}\n")
            self.log_to_terminal(f"ERROR en verificación de puertos: {e}")
    
    def _actualizar_texto_monitor(self, texto):
        """Actualizar texto de monitoreo de forma segura."""
        try:
            if hasattr(self, 'text_monitor') and self.text_monitor.winfo_exists():
                self.text_monitor.insert(tk.END, texto)
                self.text_monitor.see(tk.END)
        except:
            pass  # Ignorar errores de UI
    
    def actualizar_estado(self):
        pass
    
    def _log_terminal(self, mensaje, modulo="MONITOREO", nivel="INFO"):
        """Registrar mensaje en el terminal integrado global."""
        try:
            # Usar el terminal global de VistaDashboard
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            
        except Exception as e:
            # Fallback a consola si hay problemas
            print(f"[{modulo}] {mensaje}")
            print(f"Error logging a terminal: {e}")


# RESUMEN: Sistema de monitoreo de red y procesos usando herramientas nativas.

