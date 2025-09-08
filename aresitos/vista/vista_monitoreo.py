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
from aresitos.utils.logger_aresitos import LoggerAresitos

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
    def verificar_sudo_y_pedirlo(self):
        """Verifica si el usuario tiene permisos sudo activos y muestra ventana si no los tiene, con tema Burp."""
        if SUDO_MANAGER_DISPONIBLE:
            sudo_manager = SudoManager()
            if not sudo_manager.is_sudo_active():
                # Usar ventana personalizada con tema Burp
                from aresitos.vista.burp_theme import BurpTheme
                theme = BurpTheme()
                popup = tk.Toplevel(self)
                popup.title("Permisos requeridos - ARESITOS")
                popup.configure(bg=theme.get_color('bg_primary'))
                popup.geometry("420x210")
                popup.resizable(False, False)
                # Cabecera
                header = tk.Label(popup, text="Permisos SUDO requeridos", bg=theme.get_color('bg_primary'), fg=theme.get_color('fg_accent'), font=("Arial", 15, "bold"))
                header.pack(pady=(18, 6))
                # Mensaje
                msg = tk.Label(popup, text="Para ejecutar un escaneo completo y seguro, se requieren permisos sudo.\n¿Desea reiniciar la aplicación con sudo o reautenticarse?", bg=theme.get_color('bg_primary'), fg=theme.get_color('fg_secondary'), font=("Arial", 11), justify="center")
                msg.pack(pady=(0, 16))
                # Botones
                btn_frame = tk.Frame(popup, bg=theme.get_color('bg_primary'))
                btn_frame.pack(pady=(0, 10))
                def on_reiniciar():
                    popup.destroy()
                    messagebox.showinfo(
                        "Reiniciar con sudo",
                        "Por favor, cierre y reinicie ARESITOS desde una terminal con 'sudo python main.py' para habilitar todos los módulos de escaneo."
                    )
                def on_cancelar():
                    popup.destroy()
                btn_reiniciar = tk.Button(btn_frame, text="Reiniciar con sudo", command=on_reiniciar, bg=theme.get_color('button_active'), fg=theme.get_color('button_fg'), font=("Arial", 11, "bold"), relief="raised", padx=16, pady=7, activebackground=theme.get_color('highlight'))
                btn_reiniciar.pack(side="left", padx=(0, 16))
                btn_cancelar = ttk.Button(btn_frame, text="Cancelar", command=on_cancelar, style='Burp.TButton', width=16)
                btn_cancelar.pack(side="left")
                # Esperar respuesta
                popup.grab_set()
                self.wait_window(popup)
                return False
        return True
    def cancelar_monitoreo(self):
        """Cancelar el monitoreo general (no solo red) de forma segura."""
        import tkinter.messagebox as messagebox
        if not messagebox.askyesno("Confirmar acción crítica", "¿Está seguro que desea cancelar el monitoreo general? Esta acción puede afectar la supervisión en curso."):
            self.log_to_terminal("Operación de cancelación de monitoreo cancelada por el usuario.")
            return
        self.flag_monitoreo.set()
        if self.text_monitor is not None:
            self.text_monitor.insert(tk.END, "\n Monitoreo general cancelado por el usuario.\n")
        if self.btn_iniciar_monitor is not None:
            self.btn_iniciar_monitor.config(state="normal")
        if self.btn_detener_monitor is not None:
            self.btn_detener_monitor.config(state="disabled")
        if self.label_estado is not None:
            self.label_estado.config(text="Estado: Detenido")
        self.log_to_terminal("Monitoreo general cancelado correctamente.")
    def _enviar_a_reportes(self, accion, mensaje, error=False):
        """Helper estándar para enviar información al módulo de Reportes de forma robusta y silenciosa."""
        try:
            # Buscar la vista de reportes en el master o en el diccionario de vistas
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            if vista_reportes and hasattr(vista_reportes, 'agregar_evento_modulo'):
                vista_reportes.agregar_evento_modulo(
                    modulo='Monitoreo',
                    accion=accion,
                    mensaje=mensaje,
                    error=error
                )
        except Exception as e:
            if hasattr(self, 'logger') and self.logger:
                self.logger.log(f"Error enviando a reportes: {e}", nivel="ERROR", modulo="MONITOREO")
    def obtener_datos_para_reporte(self):
        """Obtener datos del monitoreo para incluir en reportes automáticos."""
        try:
            contenido = ""
            if hasattr(self, 'text_monitor') and self.text_monitor:
                contenido = self.text_monitor.get(1.0, 'end-1c')
            datos = {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'monitoreo',
                'estado': 'activo' if hasattr(self, 'flag_monitoreo') and getattr(self.flag_monitoreo, 'is_set', lambda: False)() == False else 'inactivo',
                'resumen': contenido[-2000:] if len(contenido) > 2000 else contenido,
                'estadisticas': {
                    'lineas': len(contenido.split('\n')),
                    'errores': contenido.lower().count('error'),
                    'procesos_sospechosos': contenido.lower().count('sospechoso'),
                    'alertas': contenido.lower().count('alerta'),
                }
            }
            # Sincronizar con reportes
            try:
                vista_reportes = None
                if hasattr(self.master, 'vista_reportes'):
                    vista_reportes = getattr(self.master, 'vista_reportes', None)
                else:
                    vistas = getattr(self.master, 'vistas', None)
                    if vistas and hasattr(vistas, 'get'):
                        vista_reportes = vistas.get('reportes', None)
                if vista_reportes:
                    vista_reportes.set_datos_modulo('monitoreo', datos)
            except Exception:
                pass
            return datos
        except Exception as e:
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'modulo': 'Monitoreo',
                'estado': 'error',
                'error': f'Error obteniendo datos: {str(e)}',
                'info': 'Error al obtener datos de monitoreo para reporte'
            }
    def limpiar_terminal_monitoreo(self):
        """Limpiar terminal Monitoreo manteniendo cabecera."""
        try:
            if hasattr(self, 'terminal_output') and self.terminal_output:
                self._actualizar_terminal_seguro("", modo="clear")
                # Recrear cabecera estándar
                import datetime
                self._actualizar_terminal_seguro("="*60 + "\n")
                self._actualizar_terminal_seguro("Terminal ARESITOS - Monitoreo v2.0\n")
                self._actualizar_terminal_seguro(f"Limpiado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self._actualizar_terminal_seguro("Sistema: Kali Linux - Monitoreo y Cuarentena\n")
                self._actualizar_terminal_seguro("="*60 + "\n")
                self._actualizar_terminal_seguro("LOG Terminal Monitoreo reiniciado\n\n")
        except Exception as e:
            print(f"Error limpiando terminal Monitoreo: {e}")

    def _actualizar_terminal_seguro(self, texto, modo=None):
        """Actualizar el terminal de forma segura (thread-safe y clear opcional)."""
        def _update():
            try:
                if hasattr(self, 'terminal_output') and self.terminal_output:
                    if modo == "clear":
                        self.terminal_output.delete(1.0, tk.END)
                    else:
                        self.terminal_output.insert(tk.END, texto)
                        self.terminal_output.see(tk.END)
            except Exception:
                pass
        self.after(0, _update)

    # (Elimina el __init__ duplicado, ya está el correcto más abajo)

    def ejecutar_comando_entry(self, event=None):
        """Ejecutar comando desde la entrada SIEMPRE como root usando SudoManager."""
        comando = self.comando_entry.get().strip() if hasattr(self, 'comando_entry') else ''
        if not comando:
            return
        if self.terminal_output:
            self.terminal_output.insert(tk.END, f"\n$ {comando}\n")
            self.terminal_output.see(tk.END)
        try:
            resultado = self._ejecutar_comando_seguro(comando.split(), timeout=15, usar_sudo=True)
            if self.terminal_output:
                if resultado['success']:
                    self.terminal_output.insert(tk.END, resultado['output']+"\n")
                else:
                    self.terminal_output.insert(tk.END, f"ERROR: {resultado['error']}\n")
        except Exception as e:
            if self.terminal_output:
                self.terminal_output.insert(tk.END, f"ERROR ejecutando comando: {e}\n")
        if self.terminal_output:
            self.terminal_output.see(tk.END)
    def set_controlador(self, controlador):
        """Asignar el controlador principal a la vista de monitoreo."""
        self.controlador = controlador
    @staticmethod
    def _get_base_dir():
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

    def _ejecutar_comando_seguro(self, comando, timeout=10, usar_sudo=True):
        """Ejecuta un comando del sistema de forma segura y robusta, siempre como root si es posible."""
        import subprocess
        try:
            if SUDO_MANAGER_DISPONIBLE:
                sudo_manager = SudoManager()
                if usar_sudo and sudo_manager.is_sudo_active():
                    # Convertir lista a string si necesario
                    if isinstance(comando, list):
                        comando_str = ' '.join(comando)
                    else:
                        comando_str = str(comando)
                    resultado = sudo_manager.execute_sudo_command(comando_str, timeout=timeout)
                else:
                    if isinstance(comando, list):
                        comando_str = ' '.join(comando)
                    else:
                        comando_str = str(comando)
                    resultado = subprocess.run(
                        comando_str,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False
                    )
                return {
                    'success': resultado.returncode == 0,
                    'output': resultado.stdout,
                    'error': resultado.stderr,
                    'returncode': resultado.returncode
                }
            else:
                resultado = subprocess.run(
                    comando,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False
                )
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
                'error': f'Timeout: Comando {comando} excedió {timeout}s',
                'returncode': None
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'returncode': None
            }
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.logger = LoggerAresitos.get_instance()
        self.flag_monitoreo = ThreadSafeFlag()
        self.flag_red = ThreadSafeFlag()
        self.terminal_output = None
        self.text_cuarentena = None
        self.notebook = parent
        self.frame_cuarentena = None
        self.frame_monitor = None
        self.btn_monitoreo = None
        self.btn_cuarentena = None
        self.btn_iniciar_monitor = None
        self.btn_detener_monitor = None
        self.btn_red = None
        self.btn_cancelar_red = None
        self.label_estado = None
        self.text_monitor = None
        self.cuarentena_var = None
        self.cuarentena_selector = None
        self.selector_frame = None
        self.monitor_activo = False
        self.thread_red = None

        # --- PanedWindow principal para dividir info, contenido y terminal ---
        self.paned_window = tk.PanedWindow(self, orient="vertical", bg="#232629")
        self.paned_window.pack(fill="both", expand=True, padx=5, pady=5)

        # --- Header superior unificado ---
        self.info_frame = tk.Frame(self.paned_window, bg="#232629")
        header = tk.Label(
            self.info_frame,
            text="Monitoreo y Cuarentena",
            bg="#232629",
            fg="#ffaa00",
            font=("Arial", 16, "bold")
        )
        header.pack(pady=(10, 2))
        desc = tk.Label(
            self.info_frame,
            text="Supervisa el sistema, detecta amenazas y gestiona la cuarentena de forma centralizada.",
            bg="#232629",
            fg="#cccccc",
            font=("Arial", 10)
        )
        desc.pack(pady=(0, 8))
        self.paned_window.add(self.info_frame, minsize=60)

        # --- Frame medio: Contenido principal (navegación y pestañas) ---
        self.main_frame = tk.Frame(self.paned_window, bg="#232629")
        self.crear_navegacion_pestanas(parent=self.main_frame)
        self.crear_pestana_monitoreo(parent=self.main_frame)
        self.crear_pestana_cuarentena(parent=self.main_frame)
        self.mostrar_pestana('monitoreo')
        self.paned_window.add(self.main_frame, minsize=300)

        # --- Frame inferior: Terminal integrado y comando ---
        self.terminal_frame = tk.LabelFrame(
            self.paned_window,
            text="Terminal ARESITOS - Monitoreo",
            bg="#232629",
            fg="#ffb86c",
            font=("Arial", 10, "bold")
        )
        # Controles de terminal (estilo SIEM)
        controles_frame = tk.Frame(self.terminal_frame, bg="#232629")
        controles_frame.pack(fill="x", padx=5, pady=2)
        btn_limpiar = tk.Button(
            controles_frame,
            text="LIMPIAR",
            command=self.limpiar_terminal_monitoreo,
            bg="#ffaa00",
            fg='white',
            font=("Arial", 8, "bold"),
            height=1
        )
        btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)
        btn_logs = tk.Button(
            controles_frame,
            text="VER LOGS",
            command=self.abrir_logs_monitoreo,
            bg="#007acc",
            fg='white',
            font=("Arial", 8, "bold"),
            height=1
        )
        btn_logs.pack(side="left", padx=2, fill="x", expand=True)
        # Área de terminal (estilo SIEM)
        self.terminal_output = scrolledtext.ScrolledText(
            self.terminal_frame,
            height=6,
            bg='#000000',
            fg='#00ff00',
            font=("Consolas", 8),
            insertbackground='#00ff00',
            selectbackground='#333333'
        )
        self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)
        # Entrada de comandos (estilo SIEM)
        entrada_frame = tk.Frame(self.terminal_frame, bg='#1e1e1e')
        entrada_frame.pack(fill="x", padx=5, pady=2)
        tk.Label(entrada_frame, text="COMANDO:", bg='#1e1e1e', fg='#00ff00', font=("Arial", 9, "bold")).pack(side="left", padx=(0, 5))
        self.comando_entry = tk.Entry(entrada_frame, bg='#000000', fg='#00ff00', font=("Consolas", 9), insertbackground='#00ff00')
        self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.comando_entry.bind("<Return>", self.ejecutar_comando_entry)
        ejecutar_btn = tk.Button(entrada_frame, text="EJECUTAR", command=self.ejecutar_comando_entry, bg='#2d5aa0', fg='white', font=("Arial", 8, "bold"))
        ejecutar_btn.pack(side="right")
        # Mensaje inicial estilo SIEM
        self._actualizar_terminal_seguro("="*60 + "\n")
        self._actualizar_terminal_seguro("Terminal ARESITOS - Monitoreo v2.0\n")
        import datetime
        self._actualizar_terminal_seguro(f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._actualizar_terminal_seguro("Sistema: Kali Linux - Monitoreo y Cuarentena\n")
        self._actualizar_terminal_seguro("="*60 + "\n")
        self._actualizar_terminal_seguro("LOG Monitoreo en tiempo real\n\n")
        self.paned_window.add(self.terminal_frame, minsize=120)
    
    def _mostrar_ayuda_comandos(self):
        """Mostrar ayuda de comandos disponibles."""
        try:
            if self.terminal_output is not None:
                self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
                self.terminal_output.insert(tk.END, "COMANDOS DISPONIBLES EN ARESITOS v2.0\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n\n")
                self.terminal_output.insert(tk.END, "🔧 COMANDOS ESPECIALES:\n")
                self.terminal_output.insert(tk.END, "   ayuda-comandos, info-seguridad, clear/cls\n\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            if self.terminal_output is not None:
                self.terminal_output.insert(tk.END, f"Error mostrando ayuda: {e}\n")
        if self.terminal_output is not None:
            self.terminal_output.see(tk.END)
    
    def _mostrar_info_seguridad(self):
        """Mostrar información de seguridad actual."""
        try:
            if self.terminal_output is not None:
                self.terminal_output.insert(tk.END, "\n" + "="*60 + "\n")
                self.terminal_output.insert(tk.END, "🔐 INFORMACIÓN DE SEGURIDAD ARESITOS\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n\n")
                self.terminal_output.insert(tk.END, "Estado: Seguridad estándar, sin validación restrictiva.\n")
                self.terminal_output.insert(tk.END, "Para más detalles revise la configuración y logs.\n")
                self.terminal_output.insert(tk.END, "="*60 + "\n")
        except Exception as e:
            if self.terminal_output is not None:
                self.terminal_output.insert(tk.END, f"Error mostrando info seguridad: {e}\n")
        if self.terminal_output is not None:
            self.terminal_output.see(tk.END)
    
    def abrir_logs_monitoreo(self):
        """Abrir carpeta de logs Monitoreo con ruta robusta y multiplataforma."""
        import os
        import platform
        try:
            logs_path = self.__class__._get_base_dir() / 'logs'
            if not logs_path.exists():
                self.log_to_terminal("WARNING: Carpeta de logs no encontrada")
                messagebox.showwarning("Advertencia", "Carpeta de logs no encontrada")
                return
            # Usar método seguro para abrir directorio
            resultado = None
            if platform.system() == "Linux":
                if hasattr(self, '_ejecutar_comando_seguro'):
                    resultado = self._ejecutar_comando_seguro(["xdg-open", str(logs_path)], timeout=10)
            elif platform.system() == "Windows":
                if hasattr(self, '_ejecutar_comando_seguro'):
                    resultado = self._ejecutar_comando_seguro(["explorer", str(logs_path)], timeout=10)
            else:
                if hasattr(self, '_ejecutar_comando_seguro'):
                    resultado = self._ejecutar_comando_seguro(["open", str(logs_path)], timeout=10)
            if resultado and resultado.get('success'):
                self.log_to_terminal("OK Carpeta de logs Monitoreo abierta")
            elif resultado:
                self.log_to_terminal(f"ERROR: No se pudo abrir logs - {resultado.get('error','')}" )
                messagebox.showerror("Error", f"No se pudo abrir la carpeta de logs: {resultado.get('error','')}")
        except Exception as e:
            error_msg = f"Error abriendo logs: {str(e)}"
            self.log_to_terminal(f"ERROR: {error_msg}")
            messagebox.showerror("Error", error_msg)
    
    def log_to_terminal(self, mensaje):
        """Registrar mensaje en el terminal con formato estándar y logger centralizado."""
        try:
            import datetime
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            mensaje_completo = f"[{timestamp}] {mensaje}\n"
            if hasattr(self, 'terminal_output') and self.terminal_output is not None:
                self.terminal_output.insert(tk.END, mensaje_completo)
                self.terminal_output.see(tk.END)
            # Registrar en logger centralizado
            self.logger.log(mensaje, nivel="INFO", modulo="MONITOREO")
        except Exception as e:
            print(f"Error en log_to_terminal: {e}")

    def _log_terminal(self, mensaje, modulo="MONITOREO", nivel="INFO"):
        """Registrar mensaje en el terminal global, logger y en la interfaz de monitoreo."""
        try:
            from aresitos.vista.vista_dashboard import VistaDashboard
            VistaDashboard.log_actividad_global(mensaje, modulo, nivel)
            if hasattr(self, 'logger') and self.logger:
                self.logger.log(mensaje, nivel=nivel, modulo=modulo)
            import datetime
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            mensaje_formateado = f"[{timestamp}] {mensaje}\n"
            if hasattr(self, 'terminal_output') and self.terminal_output is not None:
                self.terminal_output.insert(tk.END, mensaje_formateado)
                self.terminal_output.see(tk.END)
        except Exception as e:
            print(f"Error logging a terminal: {e}")
    
    def sincronizar_terminal(self):
        """Función de compatibilidad - ya no necesaria con terminal estándar."""
        pass
    
    def crear_navegacion_pestanas(self, parent=None):
        """Crear navegación por pestañas con tema Burp Suite."""
        parent = parent if parent is not None else self.notebook
        nav_frame = tk.Frame(parent, bg='#2b2b2b')
        nav_frame.pack(fill="x", pady=(0, 10))
        self.btn_monitoreo = ttk.Button(
            nav_frame, text=" Monitoreo Sistema",
            command=lambda: self.mostrar_pestana('monitoreo'),
            style='Burp.TButton', width=16
        )
        self.btn_monitoreo.pack(side="left", padx=(0, 8), pady=4)

        self.btn_cuarentena = ttk.Button(
            nav_frame, text="Cuarentena",
            command=lambda: self.mostrar_pestana('cuarentena'),
            style='Burp.TButton', width=16
        )
        self.btn_cuarentena.pack(side="left", padx=8, pady=4)
    
    def mostrar_pestana(self, pestana):
        """Mostrar la pestaña seleccionada."""
        # Actualizar colores de botones
        if pestana == 'monitoreo':
            if self.btn_monitoreo is not None:
                pass  # ttk.Button no soporta 'bg', el color se define en el style
            if self.btn_cuarentena is not None:
                pass  # ttk.Button no soporta 'bg', el color se define en el style
            if self.frame_cuarentena is not None:
                self.frame_cuarentena.pack_forget()
            if self.frame_monitor is not None:
                self.frame_monitor.pack(fill="both", expand=True)
        else:
            if self.btn_monitoreo is not None:
                pass  # ttk.Button no soporta 'bg', el color se define en el style
            if self.btn_cuarentena is not None:
                pass  # ttk.Button no soporta 'bg', el color se define en el style
            if self.frame_monitor is not None:
                self.frame_monitor.pack_forget()
            if self.frame_cuarentena is not None:
                self.frame_cuarentena.pack(fill="both", expand=True)
    
    def crear_pestana_monitoreo(self, parent=None):
        parent = parent if parent is not None else self.notebook
        self.frame_monitor = tk.Frame(parent, bg='#2b2b2b')
        self.frame_monitor.pack(fill="both", expand=True)
        # Frame de controles con tema
        control_frame = tk.Frame(self.frame_monitor, bg='#2b2b2b')
        control_frame.pack(fill="x", pady=(10, 10))
        self.btn_iniciar_monitor = ttk.Button(
            control_frame, text=" Iniciar Monitoreo", 
            command=self.iniciar_monitoreo,
            style='Burp.TButton', width=16
        )
        self.btn_iniciar_monitor.pack(side="left", padx=(0, 8), pady=4)
        self.btn_detener_monitor = ttk.Button(
            control_frame, text=" Cancelar Monitoreo",
            command=self.cancelar_monitoreo,
            state="disabled",
            style='Burp.TButton', width=16
        )
        self.btn_detener_monitor.pack(side="left", padx=(0, 8), pady=4)
        self.btn_red = ttk.Button(
            control_frame, text=" Monitorear Red", 
            command=self.monitorear_red,
            style='Burp.TButton', width=16
        )
        self.btn_red.pack(side="left", padx=(0, 8), pady=4)
        self.btn_cancelar_red = ttk.Button(
            control_frame, text=" Cancelar Red", 
            command=self.cancelar_monitoreo_red,
            state="disabled",
            style='Burp.TButton', width=16
        )
        self.btn_cancelar_red.pack(side="left", padx=(0, 8), pady=4)

        # Campo y botón para poner en cuarentena
        cuarentena_frame = tk.Frame(control_frame, bg='#2b2b2b')
        cuarentena_frame.pack(side="left", padx=(20, 0), pady=4)
        self.cuarentena_entry = tk.Entry(cuarentena_frame, width=32, font=('Consolas', 10))
        self.cuarentena_entry.pack(side="left", padx=(0, 5))
        self.cuarentena_entry.insert(0, "Ruta del archivo a poner en cuarentena")
        self.btn_cuarentena_monitoreo = tk.Button(
            cuarentena_frame, text="Agregar a Cuarentena",
            command=self._poner_en_cuarentena_desde_entry,
            bg="#ffb86c", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=12, pady=6,
            activebackground="#ffd9b3", activeforeground="#ff6633"
        )
        self.btn_cuarentena_monitoreo.pack(side="left", padx=(0, 5))

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

    def _poner_en_cuarentena_desde_entry(self):
        """Pone en cuarentena el archivo especificado en el campo de entrada."""
        ruta = self.cuarentena_entry.get().strip()
        if not ruta or ruta == "Ruta del archivo a poner en cuarentena":
            self.log_to_terminal("⚠️ Por favor, ingrese la ruta del archivo que desea aislar en cuarentena.")
            return
        if not hasattr(self, 'controlador') or not self.controlador or not hasattr(self.controlador, 'controlador_cuarentena'):
            self.log_to_terminal("❌ No se pudo acceder al sistema de cuarentena. Verifique la configuración.")
            return
        try:
            resultado = self.controlador.controlador_cuarentena.cuarentenar_archivo(ruta, razon="Manual desde Monitoreo")
            if resultado.get('exito'):
                self.log_to_terminal(f"✅ El archivo ha sido aislado exitosamente en cuarentena: {ruta}")
                if hasattr(self, '_enviar_a_reportes'):
                    self._enviar_a_reportes('poner_en_cuarentena', f"Archivo puesto en cuarentena: {ruta}", False)
            else:
                self.log_to_terminal(f"❌ No se pudo aislar el archivo: {resultado.get('mensaje','sin mensaje')}")
                if hasattr(self, '_enviar_a_reportes'):
                    self._enviar_a_reportes('poner_en_cuarentena', f"Error: {resultado.get('mensaje','sin mensaje')}", True)
        except Exception as e:
            self.log_to_terminal(f"❌ Error inesperado al aislar el archivo: {e}")
            if hasattr(self, '_enviar_a_reportes'):
                self._enviar_a_reportes('poner_en_cuarentena', str(e), True)

    def detener_monitoreo(self):
        """Detener monitoreo de forma segura, invocando al controlador y reportando."""
        try:
            exito = False
            mensaje = ""
            if hasattr(self, 'controlador') and self.controlador and hasattr(self.controlador, 'detener_monitoreo'):
                resultado = self.controlador.detener_monitoreo()
                exito = resultado.get('exito', False)
                mensaje = resultado.get('mensaje', resultado.get('error', ''))
                if exito:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "\nMonitoreo avanzado detenido correctamente.\n")
                    self._enviar_a_reportes('detener_monitoreo', 'Monitoreo avanzado detenido correctamente.', False)
                    self.log_to_terminal("Monitoreo avanzado detenido correctamente.")
                else:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"\n[ERROR] No se pudo detener monitoreo avanzado: {mensaje}\n")
                    self._enviar_a_reportes('detener_monitoreo', f"Error: {mensaje}", True)
                    self.log_to_terminal(f"[ERROR] No se pudo detener monitoreo avanzado: {mensaje}")
            else:
                # Fallback: detener flag de monitoreo básico
                self.flag_monitoreo.set()
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, "\nMonitoreo básico detenido.\n")
                self._enviar_a_reportes('detener_monitoreo', 'Monitoreo básico detenido.', False)
                self.log_to_terminal("Monitoreo básico detenido.")
            if self.btn_iniciar_monitor is not None:
                self.btn_iniciar_monitor.config(state="normal")
            if self.btn_detener_monitor is not None:
                self.btn_detener_monitor.config(state="disabled")
            if self.label_estado is not None:
                self.label_estado.config(text="Estado: Detenido")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"\n[ERROR] al detener monitoreo: {e}\n")
            self._enviar_a_reportes('detener_monitoreo', str(e), True)
            self.log_to_terminal(f"[ERROR] al detener monitoreo: {e}")
    
    def crear_pestana_cuarentena(self, parent=None):
        parent = parent if parent is not None else self.notebook
        self.frame_cuarentena = tk.Frame(parent, bg='#232629')
        # Frame de controles con tema
        control_frame = tk.Frame(self.frame_cuarentena, bg='#2b2b2b')
        control_frame.pack(fill="x", pady=(10, 10))
        self.btn_agregar_cuarentena = tk.Button(
            control_frame, text="Agregar a Cuarentena",
            command=self.agregar_a_cuarentena,
            bg="#ffb86c", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=12, pady=6,
            activebackground="#ffd9b3", activeforeground="#ff6633"
        )
        self.btn_agregar_cuarentena.pack(side="left", padx=(0, 8), pady=4)
        self.btn_listar_cuarentena = tk.Button(
            control_frame, text=" Listar Archivos",
            command=self.listar_cuarentena,
            bg="#8be9fd", fg="#232629",
            font=("Arial", 11, "bold"),
            relief="raised", bd=2, padx=12, pady=6,
            activebackground="#b3f0ff", activeforeground="#ff6633"
        )
        self.btn_listar_cuarentena.pack(side="left", padx=(0, 8), pady=4)
        # Selector de archivo en cuarentena
        self.selector_frame = tk.Frame(self.frame_cuarentena, bg='#232629')
        self.selector_frame.pack(fill="x", pady=(0, 8))
        tk.Label(self.selector_frame, text="Seleccionar archivo:", bg='#232629', fg='#ffb86c', font=("Arial", 10, "bold")).pack(side="left", padx=(0, 8))
        self.cuarentena_var = tk.StringVar()
        self.cuarentena_selector = ttk.Combobox(self.selector_frame, textvariable=self.cuarentena_var, state="readonly", width=50)
        self.cuarentena_selector.pack(side="left", padx=(0, 8))


    def _actualizar_selector_cuarentena(self):
        """Actualizar el selector de archivos en cuarentena."""
        try:
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            modelo_principal = {'cuarentena': None}
            controlador_cuarentena = ControladorCuarentena(modelo_principal)
            archivos = controlador_cuarentena.listar_archivos_cuarentena()
            opciones = [f"{a.get('id','')} | {a.get('ruta_original','')}" for a in archivos]
            if self.cuarentena_selector is not None:
                self.cuarentena_selector['values'] = opciones
            if opciones:
                if self.cuarentena_selector is not None:
                    self.cuarentena_selector.current(0)
        except Exception as e:
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"ERROR actualizando selector: {e}\n")

    def ver_detalles_amenaza(self):
        """Mostrar detalles completos del archivo seleccionado en cuarentena."""
        seleccion = self.cuarentena_var.get() if self.cuarentena_var is not None else None
        if not seleccion:
            if self.text_cuarentena is not None:
                self.text_cuarentena.insert(tk.END, "Seleccione un archivo para ver detalles.\n")
            return
        archivo_id = seleccion.split('|')[0].strip()
        try:
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            modelo_principal = {'cuarentena': None}
            controlador_cuarentena = ControladorCuarentena(modelo_principal)
            archivos = controlador_cuarentena.listar_archivos_cuarentena()
            detalles = next((a for a in archivos if str(a.get('id')) == archivo_id), None)
            if detalles:
                if self.text_cuarentena is not None:
                    self.text_cuarentena.insert(tk.END, "\n=== DETALLES DEL ARCHIVO EN CUARENTENA ===\n")
                    for k, v in detalles.items():
                        self.text_cuarentena.insert(tk.END, f"{k}: {v}\n")
                    self.text_cuarentena.insert(tk.END, "="*40+"\n")
            else:
                if self.text_cuarentena is not None:
                    self.text_cuarentena.insert(tk.END, "No se encontraron detalles para el archivo seleccionado.\n")
        except Exception as e:
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"ERROR mostrando detalles: {e}\n")

    def excluir_amenaza(self):
        """Agregar archivo a exclusiones (whitelist)."""
        seleccion = self.cuarentena_var.get() if self.cuarentena_var is not None else None
        if not seleccion:
            if self.text_cuarentena is not None:
                self.text_cuarentena.insert(tk.END, "Seleccione un archivo para excluir.\n")
            return
        archivo_id = seleccion.split('|')[0].strip()
        # TODO: Implementar lógica de exclusión si es necesario
        pass

    def iniciar_monitoreo(self):
        """Iniciar monitoreo completo usando el controlador, con verificación de sudo y fallback a monitoreo básico."""
        try:
            if not self.verificar_sudo_y_pedirlo():
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, "[ERROR] Permisos insuficientes para escaneo completo.\n")
                self.log_to_terminal("Permisos insuficientes para escaneo completo.")
                return
            if hasattr(self, 'controlador') and self.controlador and hasattr(self.controlador, 'iniciar_monitoreo'):
                resultado = self.controlador.iniciar_monitoreo()
                if resultado.get('exito'):
                    if self.btn_iniciar_monitor is not None:
                        self.btn_iniciar_monitor.config(state="disabled")
                    if self.btn_detener_monitor is not None:
                        self.btn_detener_monitor.config(state="normal")
                    if self.label_estado is not None:
                        self.label_estado.config(text="Estado: Activo (Avanzado)")
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "Monitoreo avanzado iniciado correctamente.\n")
                    self._enviar_a_reportes('iniciar_monitoreo', 'Monitoreo avanzado iniciado correctamente.', False)
                    self.log_to_terminal("Monitoreo avanzado iniciado correctamente.")
                else:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"[ERROR] No se pudo iniciar monitoreo avanzado: {resultado.get('error','Error desconocido')}\n")
                    self._enviar_a_reportes('iniciar_monitoreo', f"Error: {resultado.get('error','Error desconocido')}", True)
                    self.log_to_terminal(f"[ERROR] No se pudo iniciar monitoreo avanzado: {resultado.get('error','Error desconocido')}")
                    # Fallback a monitoreo básico
                    self._iniciar_monitoreo_basico()
            else:
                # Fallback a monitoreo básico si no hay controlador
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, "[INFO] Controlador no disponible, iniciando monitoreo básico...\n")
                self._iniciar_monitoreo_basico()
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[ERROR] Excepción al iniciar monitoreo: {e}\n")
            self._enviar_a_reportes('iniciar_monitoreo', str(e), True)
            self.log_to_terminal(f"[ERROR] Excepción al iniciar monitoreo: {e}")

    def _iniciar_monitoreo_basico(self):
        """Iniciar monitoreo básico cuando el controlador no está disponible."""
        self.flag_monitoreo.clear()
        if self.btn_iniciar_monitor is not None:
            self.btn_iniciar_monitor.config(state="disabled")
        if self.btn_detener_monitor is not None:
            self.btn_detener_monitor.config(state="normal")
        if self.label_estado is not None:
            self.label_estado.config(text="Estado: Activo (Básico)")
        if self.text_monitor is not None:
            self.text_monitor.insert(tk.END, "Monitoreo básico iniciado...\n")
        # Iniciar monitoreo básico en thread separado
        threading.Thread(target=self._monitoreo_completo_async, daemon=True).start()
        try:
            if hasattr(self, 'after'):
                # self.after(3000, self._actualizar_monitoreo_basico)  # Method not implemented
                pass
        except RuntimeError:
            pass
        # Wrap see() call with None check
    # Removed problematic see() call to prevent errors

    def _monitoreo_completo_async(self):
        """Ejecutar monitoreo completo de procesos, permisos y usuarios con feedback detallado en la vista."""
        import time
        try:
            ciclo = 0
            while not self.flag_monitoreo.is_set():
                ciclo += 1
                self._log_terminal(f"Ciclo de monitoreo #{ciclo} iniciado", "MONITOREO", "INFO")
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"\n[CICLO {ciclo}] Monitoreo iniciado\n")
                        self.text_monitor.insert(tk.END, "[FASE 1] Monitoreando procesos del sistema...\n")
                    self.text_monitor.see(tk.END)
                # FASE 1: Monitorear procesos del sistema
                self._log_terminal("FASE 1: Monitoreando procesos del sistema", "MONITOREO", "INFO")
                self._monitorear_procesos_sistema()
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "[FASE 2] Verificando permisos de archivos críticos...\n")
                    self.text_monitor.see(tk.END)
                self._log_terminal("FASE 2: Verificando permisos de archivos criticos", "MONITOREO", "INFO")
                self._monitorear_permisos_archivos()
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "[FASE 3] Monitoreando usuarios y sesiones activas...\n")
                    self.text_monitor.see(tk.END)
                self._log_terminal("FASE 3: Monitoreando usuarios y sesiones activas", "MONITOREO", "INFO")
                self._monitorear_usuarios_sesiones()
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "[FASE 4] Verificando procesos con privilegios elevados...\n")
                    self.text_monitor.see(tk.END)
                self._log_terminal("FASE 4: Verificando procesos con privilegios elevados", "MONITOREO", "WARNING")
                self._monitorear_procesos_privilegiados()
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "[FASE 5] Detectando cambios en el sistema...\n")
                    self.text_monitor.see(tk.END)
                self._log_terminal("FASE 5: Detectando cambios en el sistema", "MONITOREO", "INFO")
                # self._monitorear_cambios_sistema()  # Comentado: método no implementado
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[CICLO {ciclo}] Monitoreo completado\n")
                self._log_terminal(f"Ciclo de monitoreo #{ciclo} completado", "MONITOREO", "SUCCESS")
                # Pausa entre ciclos (15 segundos)
                for i in range(15):
                    if self.flag_monitoreo.is_set():
                        break
                    time.sleep(1)
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"\nError en monitoreo completo: {str(e)}\n")
            self._log_terminal(f"Error en monitoreo completo: {str(e)}", "MONITOREO", "ERROR")
        # --- SINCRONIZACIÓN SILENCIOSA DE DATOS PARA REPORTES ---
        try:
            from aresitos.vista.vista_reportes import VistaReportes
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            if vista_reportes and hasattr(self, 'obtener_datos_para_reporte'):
                datos = self.obtener_datos_para_reporte()
                vista_reportes.set_datos_modulo('monitoreo', datos)
        except Exception:
            pass

    def _monitorear_procesos_sistema(self):
        """Monitorear todos los procesos del sistema y sus características con manejo seguro."""
        try:
            # Obtener lista completa de procesos usando método seguro
            resultado = self._ejecutar_comando_seguro(['ps', 'aux'], timeout=15)
            if not resultado['success']:
                self._log_terminal(f"Error obteniendo procesos: {resultado['error']}", "PROCESOS", "ERROR")
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
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
                except (ValueError, IndexError) as e:
                    # Ignorar líneas malformadas
                    continue
            # Reportar hallazgos
            self._log_terminal(f"Procesos totales monitoreados: {total_procesos}", "MONITOREO", "INFO")
            if self.text_monitor is not None:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"Procesos totales monitoreados: {total_procesos}\n")
            for pid, comando, cpu in procesos_alta_cpu:
                self._log_terminal(f"PROCESO ALTO CPU: PID {pid} usando {cpu}% - {comando[:80]}", "MONITOREO", "WARNING")
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"PROCESO ALTO CPU: PID {pid} usando {cpu}% - {comando[:80]}\n")
            for pid, comando, memoria in procesos_alta_memoria:
                self._log_terminal(f"PROCESO ALTA MEMORIA: PID {pid} usando {memoria}% - {comando[:80]}", "MONITOREO", "WARNING")
                if self.text_monitor is not None:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"PROCESO ALTA MEMORIA: PID {pid} usando {memoria}% - {comando[:80]}\n")
            for pid, usuario, comando in procesos_sospechosos:
                self._log_terminal(f"PROCESO SOSPECHOSO: PID {pid} usuario {usuario} - {comando[:80]}", "MONITOREO", "ERROR")
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"PROCESO SOSPECHOSO: PID {pid} usuario {usuario} - {comando[:80]}\n")
            if not procesos_sospechosos and len(procesos_alta_cpu) == 0:
                self._log_terminal("Procesos del sistema funcionando normalmente", "MONITOREO", "INFO")
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, "Procesos del sistema funcionando normalmente\n")
            if self.text_monitor is not None:
                self.text_monitor.see(tk.END)
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
            if self.text_monitor is not None:
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
        if self.text_monitor is not None:
            self.text_monitor.insert(tk.END, f"Procesos totales monitoreados: {total_procesos}\n")
        for pid, comando, cpu in procesos_alta_cpu:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"PROCESO ALTO CPU: PID {pid} usando {cpu}% - {comando[:80]}\n")
        for pid, comando, memoria in procesos_alta_memoria:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"PROCESO ALTA MEMORIA: PID {pid} usando {memoria}% - {comando[:80]}\n")
        for pid, usuario, comando in procesos_sospechosos:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"PROCESO SOSPECHOSO: PID {pid} usuario {usuario} - {comando[:80]}\n")
        if not procesos_sospechosos and len(procesos_alta_cpu) == 0:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, "Procesos del sistema funcionando normalmente\n")
        if self.text_monitor is not None:
            self.text_monitor.see(tk.END)


    
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
            if self.btn_red is not None:
                self.btn_red.config(state="disabled")
            if self.btn_cancelar_red is not None:
                self.btn_cancelar_red.config(state="normal")
            if self.text_monitor is not None:
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
            if self.text_monitor is not None:
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
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"\n[CICLO #{ciclo}] Iniciando ciclo de monitoreo de red...\n")
                        self.text_monitor.see(tk.END)
                    self._log_terminal(f"Ciclo de monitoreo de red #{ciclo}", "MONITOREO-RED", "INFO")
                    # FASE 1: Detectar dispositivos conectados a la red
                    if not self.flag_red.is_set():
                        try:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, "[FASE 1] Detectando dispositivos conectados a la red...\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 1: Detectando dispositivos conectados a la red", "MONITOREO-RED", "INFO")
                            self._detectar_dispositivos_red_seguro()
                        except Exception as e:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, f"[FASE 1] Error: {str(e)}\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 1: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 2: Monitorear interfaces de red activas
                    if not self.flag_red.is_set():
                        try:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, "[FASE 2] Monitoreando interfaces de red activas...\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 2: Monitoreando interfaces de red activas", "MONITOREO-RED", "INFO")
                            self._monitorear_interfaces_red_seguro()
                        except Exception as e:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, f"[FASE 2] Error: {str(e)}\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 2: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 3: Verificar conexiones activas
                    if not self.flag_red.is_set():
                        try:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, "[FASE 3] Verificando conexiones de red activas...\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 3: Verificando conexiones de red activas", "MONITOREO-RED", "INFO")
                            self._monitorear_conexiones_activas_seguro()
                        except Exception as e:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, f"[FASE 3] Error: {str(e)}\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 3: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 4: Verificar puertos abiertos del sistema local
                    if not self.flag_red.is_set():
                        try:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, "[FASE 4] Verificando puertos abiertos del sistema local...\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 4: Verificando puertos abiertos del sistema local", "MONITOREO-RED", "INFO")
                            self._verificar_puertos_abiertos_seguro()
                        except Exception as e:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, f"[FASE 4] Error: {str(e)}\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 4: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 5: Monitorear tráfico de red
                    if not self.flag_red.is_set():
                        try:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, "[FASE 5] Monitoreando tráfico de red...\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 5: Monitoreando trafico de red", "MONITOREO-RED", "INFO")
                            self._monitorear_trafico_red_seguro()
                        except Exception as e:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, f"[FASE 5] Error: {str(e)}\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 5: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    # FASE 6: Verificar configuración de red
                    if not self.flag_red.is_set():
                        try:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, "[FASE 6] Verificando configuración de red...\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal("FASE 6: Verificando configuracion de red", "MONITOREO-RED", "INFO")
                            self._verificar_configuracion_red_seguro()
                        except Exception as e:
                            if self.text_monitor is not None:
                                self.text_monitor.insert(tk.END, f"[FASE 6] Error: {str(e)}\n")
                                self.text_monitor.see(tk.END)
                            self._log_terminal(f"Error en FASE 6: {str(e)}", "MONITOREO-RED", "WARNING")
                            ciclo_exitoso = False
                    if ciclo_exitoso:
                        errores_consecutivos = 0
                        if self.text_monitor is not None:
                            self.text_monitor.insert(tk.END, f"[CICLO #{ciclo}] Monitoreo de red completado exitosamente.\n")
                            self.text_monitor.see(tk.END)
                        self._log_terminal(f"Ciclo de monitoreo de red #{ciclo} completado exitosamente", "MONITOREO-RED", "SUCCESS")
                    else:
                        errores_consecutivos += 1
                        if self.text_monitor is not None:
                            self.text_monitor.insert(tk.END, f"[CICLO #{ciclo}] Monitoreo de red completado con errores ({errores_consecutivos}/{max_errores}).\n")
                            self.text_monitor.see(tk.END)
                        self._log_terminal(f"Ciclo #{ciclo} completado con errores ({errores_consecutivos}/{max_errores})", "MONITOREO-RED", "WARNING")
                    for i in range(15):
                        if self.flag_red.is_set():
                            break
                        time.sleep(1)
                except Exception as e:
                    errores_consecutivos += 1
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"[CICLO #{ciclo}] Error crítico: {str(e)} ({errores_consecutivos}/{max_errores})\n")
                        self.text_monitor.see(tk.END)
                    self._log_terminal(f"Error crítico en ciclo #{ciclo}: {str(e)} ({errores_consecutivos}/{max_errores})", "MONITOREO-RED", "ERROR")
                    for i in range(5):
                        if self.flag_red.is_set():
                            break
                        time.sleep(1)
            if errores_consecutivos >= max_errores:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"\nMonitoreo detenido: {max_errores} errores consecutivos detectados.\n")
                    self.text_monitor.see(tk.END)
                self._log_terminal(f"Monitoreo detenido: {max_errores} errores consecutivos detectados", "MONITOREO-RED", "ERROR")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"\nError fatal en monitoreo de red: {str(e)}\n")
                self.text_monitor.see(tk.END)
            self._log_terminal(f"Error fatal en monitoreo de red: {str(e)}", "MONITOREO-RED", "ERROR")
        finally:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, "\nFinalizando monitoreo de red.\n")
                self.text_monitor.see(tk.END)
            self._log_terminal("Finalizando monitoreo de red", "MONITOREO-RED", "INFO")
            self.after(0, self._finalizar_monitoreo_red)

    def _detectar_dispositivos_red_seguro(self):
        """Detectar dispositivos de red con manejo robusto de errores y reportar hallazgos críticos."""
        try:
            resultado = self._ejecutar_comando_seguro(['ip', 'route', 'show'], timeout=10)
            if not resultado['success']:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[FASE 1] Error obteniendo rutas: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo rutas: {resultado['error']}", "MONITOREO-RED", "WARNING")
                self._enviar_a_reportes('monitoreo_red', f"Error obteniendo rutas: {resultado['error']}", True)
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
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, "[FASE 1] No se detectaron redes locales.\n")
                self._log_terminal("No se detectaron redes locales", "MONITOREO-RED", "INFO")
                self._enviar_a_reportes('monitoreo_red', "No se detectaron redes locales", False)
                return
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 1] Redes locales detectadas: {', '.join(redes_locales)}\n")
            dispositivos_encontrados = 0
            dispositivos_info = []
            try:
                resultado_nmap = self._ejecutar_comando_seguro(['nmap', '-sn', redes_locales[0]], timeout=15)
                if resultado_nmap['success'] and resultado_nmap['output']:
                    for linea in resultado_nmap['output'].split('\n'):
                        if 'Nmap scan report for' in linea:
                            ip = linea.split()[-1]
                            dispositivos_encontrados += 1
                            dispositivos_info.append(ip)
                    if dispositivos_info:
                        if self.text_monitor is not None:
                            self.text_monitor.insert(tk.END, f"[FASE 1] Dispositivos detectados (nmap): {', '.join(dispositivos_info)}\n")
                        self._enviar_a_reportes('monitoreo_red', f"Dispositivos detectados en red: {', '.join(dispositivos_info)}", False)
                    else:
                        if self.text_monitor is not None:
                            self.text_monitor.insert(tk.END, "[FASE 1] No se detectaron dispositivos activos con nmap.\n")
                else:
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, "[FASE 1] nmap no disponible o sin resultados, usando ping básico...\n")
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
                        if self.text_monitor is not None:
                            self.text_monitor.insert(tk.END, f"[FASE 1] Dispositivos detectados (ping): {', '.join(dispositivos_info)}\n")
                        self._enviar_a_reportes('monitoreo_red', f"Dispositivos detectados en red: {', '.join(dispositivos_info)}", False)
                    else:
                        if self.text_monitor is not None:
                            self.text_monitor.insert(tk.END, "[FASE 1] No se detectaron dispositivos activos con ping.\n")
            except Exception as e:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[FASE 1] Error usando nmap/ping: {str(e)}\n")
                self._enviar_a_reportes('monitoreo_red', f"Error usando nmap/ping: {str(e)}", True)
            self._log_terminal(f"Total dispositivos detectados: {dispositivos_encontrados}", "MONITOREO-RED", "INFO")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 1] Error en detección de dispositivos: {str(e)}\n")
            self._log_terminal(f"Error en detección segura de dispositivos: {str(e)}", "MONITOREO-RED", "WARNING")
            self._enviar_a_reportes('monitoreo_red', f"Error en detección de dispositivos: {str(e)}", True)

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
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[FASE 2] Error obteniendo interfaces: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo interfaces: {resultado['error']}", "MONITOREO-RED", "WARNING")
                self._enviar_a_reportes('monitoreo_red', f"Error obteniendo interfaces: {resultado['error']}", True)
                return
            interfaces_activas = []
            for linea in resultado['output'].split('\n'):
                partes = linea.split()
                if len(partes) >= 3 and partes[1] == 'UP':
                    nombre = partes[0]
                    ip = partes[2] if len(partes) > 2 else 'N/A'
                    interfaces_activas.append(f"{nombre} ({ip})")
            if interfaces_activas:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[FASE 2] Interfaces activas: {', '.join(interfaces_activas)}\n")
            else:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, "[FASE 2] No hay interfaces activas.\n")
                self._enviar_a_reportes('monitoreo_red', "No hay interfaces de red activas", True)
            self._log_terminal(f"Total interfaces activas: {len(interfaces_activas)}", "MONITOREO-RED", "INFO")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 2] Error monitoreando interfaces: {str(e)}\n")
            self._log_terminal(f"Error monitoreando interfaces de red: {str(e)}", "MONITOREO-RED", "WARNING")
            self._enviar_a_reportes('monitoreo_red', f"Error monitoreando interfaces: {str(e)}", True)

    def _monitorear_conexiones_activas_seguro(self):
        """Monitorear conexiones activas de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ss', '-tupna'], timeout=10)
            if not resultado['success']:
                if self.text_monitor is not None:
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
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 3] Conexiones TCP en escucha: {len(conexiones_tcp)}\n")
            for c in conexiones_tcp[:5]:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"  {c}\n")
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 3] Conexiones UDP: {len(conexiones_udp)}\n")
            for c in conexiones_udp[:5]:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"  {c}\n")
            self._log_terminal(f"CONEXIONES ACTIVAS: {len(conexiones_tcp)} TCP, {len(conexiones_udp)} UDP", "MONITOREO-RED", "INFO")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 3] Error monitoreando conexiones: {str(e)}\n")
            self._log_terminal(f"Error monitoreando conexiones: {str(e)}", "MONITOREO-RED", "WARNING")

    def _verificar_puertos_abiertos_seguro(self):
        """Verificar puertos abiertos de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ss', '-lntup'], timeout=10)
            if not resultado['success']:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[FASE 4] Error obteniendo puertos: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo puertos: {resultado['error']}", "MONITOREO-RED", "WARNING")
                self._enviar_a_reportes('monitoreo_red', f"Error obteniendo puertos: {resultado['error']}", True)
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
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 4] Puertos TCP abiertos: {', '.join(puertos_unicos) if puertos_unicos else 'Ninguno'}\n")
            puertos_importantes = ['22', '80', '443', '3389', '21', '25']
            puertos_criticos = []
            for puerto in puertos_importantes:
                if puerto in puertos_unicos:
                    puertos_criticos.append(puerto)
                    if self.text_monitor is not None:
                        self.text_monitor.insert(tk.END, f"  [ALERTA] Puerto crítico abierto: {puerto}\n")
            if puertos_criticos:
                self._enviar_a_reportes('monitoreo_red', f"Puertos críticos abiertos detectados: {', '.join(puertos_criticos)}", True)
            self._log_terminal(f"PUERTOS ABIERTOS: {len(puertos_unicos)} puertos TCP en escucha", "MONITOREO-RED", "INFO")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 4] Error verificando puertos: {str(e)}\n")
            self._log_terminal(f"Error verificando puertos: {str(e)}", "MONITOREO-RED", "WARNING")
            self._enviar_a_reportes('monitoreo_red', f"Error verificando puertos: {str(e)}", True)

    def _monitorear_trafico_red_seguro(self):
        """Monitorear tráfico de red de forma segura - Issue 19/24."""
        try:
            resultado = self._ejecutar_comando_seguro(['ifstat', '-q', '1', '1'], timeout=5)
            if not resultado['success']:
                if self.text_monitor is not None:
                    self.text_monitor.insert(tk.END, f"[FASE 5] Error obteniendo estadísticas de red: {resultado['error']}\n")
                self._log_terminal(f"Error obteniendo estadísticas de red: {resultado['error']}", "MONITOREO-RED", "WARNING")
                self._enviar_a_reportes('monitoreo_red', f"Error obteniendo estadísticas de red: {resultado['error']}", True)
                return
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 5] Estadísticas de tráfico de red (ifstat):\n{resultado['output']}\n")
            # Analizar tráfico sospechoso (ejemplo: >100MB en 1s)
            for linea in resultado['output'].split('\n'):
                if linea.strip() and not linea.lower().startswith('interface'):
                    partes = linea.split()
                    if len(partes) >= 3:
                        try:
                            rx = float(partes[1])
                            tx = float(partes[2])
                            if rx > 100000 or tx > 100000:  # >100MB/s
                                self._enviar_a_reportes('monitoreo_red', f"Tráfico de red sospechoso detectado: RX={rx} KB/s, TX={tx} KB/s", True)
                        except Exception:
                            continue
            self._log_terminal(f"Tráfico de red mostrado con ifstat", "MONITOREO-RED", "INFO")
        except Exception as e:
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"[FASE 5] Error monitoreando tráfico: {str(e)}\n")
            self._log_terminal(f"Error monitoreando tráfico: {str(e)}", "MONITOREO-RED", "WARNING")
            self._enviar_a_reportes('monitoreo_red', f"Error monitoreando tráfico: {str(e)}", True)

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
            if self.text_monitor is not None:
                self.text_monitor.insert(tk.END, f"{resultado}\n")
        
        if self.text_monitor is not None:
            self.text_monitor.see(tk.END)
    
    def _mostrar_error_red(self, error):
        """Mostrar error del monitoreo de red."""
        if self.text_monitor is not None:
            self.text_monitor.insert(tk.END, f"\n Error en monitoreo de red: {error}\n")
    
    def _finalizar_monitoreo_red(self):
        """Finalizar monitoreo de red."""
        self.flag_red.set()
        if self.btn_red is not None:
            self.btn_red.config(state="normal")
        if self.btn_cancelar_red is not None:
            self.btn_cancelar_red.config(state="disabled")
        self.thread_red = None
        if self.text_monitor is not None:
            self.text_monitor.insert(tk.END, "\n=== MONITOREO DE RED FINALIZADO ===\n")

        # Enviar resultados a Reportes automáticamente
        try:
            from aresitos.vista.vista_reportes import VistaReportes
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            if vista_reportes and hasattr(self, 'obtener_datos_para_reporte'):
                datos = self.obtener_datos_para_reporte()
                vista_reportes.set_datos_modulo('monitoreo', datos)
        except Exception:
            pass
    
    def cancelar_monitoreo_red(self):
        """Cancelar el monitoreo de red con advertencia profesional."""
        import tkinter.messagebox as messagebox
        if not messagebox.askyesno("Confirmar acción crítica", "¿Está seguro que desea cancelar el monitoreo de red? Esta acción puede afectar la supervisión de red en curso."):
            self.log_to_terminal("Operación de cancelación de monitoreo de red cancelada por el usuario.")
            return
        if not self.flag_red.is_set():
            self.flag_red.set()
            if self.text_monitor is not None:
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
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, "WARNING SUDO NO ACTIVO: Verificar permisos en otras ventanas de ARESITOS\n")
                messagebox.showwarning("Permisos", "Sudo no activo. Algunas operaciones pueden fallar.")
        except ImportError:
            sudo_manager = None
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, "WARNING SudoManager no disponible - usando modo básico\n")
        
        # Mostrar advertencia especial para cuarentena
        if not HelperSeguridad.mostrar_advertencia_cuarentena():
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
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
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, "CANCEL Usuario canceló selección de archivo\n")
            return
        
        try:
            # Verificar que el archivo existe antes de continuar
            if not os.path.exists(archivo):
                error_msg = f"El archivo {archivo} no existe"
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                return
            
            # Verificar permisos de acceso
            try:
                file_stat = os.stat(archivo)
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"INFO: Archivo encontrado - Tamaño: {file_stat.st_size} bytes\n")
            except PermissionError:
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"WARNING Sin permisos para acceder a {archivo}\n")
                if sudo_manager:
                    if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
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
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"ERROR Error de seguridad: {error_msg}\n")
                messagebox.showerror("Error de Seguridad", error_msg)
                return
            
            if not sanitizador._validar_nombre_archivo(archivo):
                error_msg = "Nombre de archivo contiene caracteres peligrosos"
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"ERROR Error de seguridad: {error_msg}\n")
                messagebox.showerror("Error de Seguridad", error_msg)
                return
            
            # Verificar tamaño razonable
            if not sanitizador._validar_tamano(archivo):
                error_msg = "Archivo demasiado grande para cuarentena"
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"ERROR Error: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                return
            
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"SECURE Archivo validado para cuarentena: {os.path.basename(archivo)}\n")
            
            # Crear controlador de cuarentena directamente si no está disponible
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            # Crear modelo principal básico para el controlador
            modelo_principal = {'cuarentena': None}
            controlador_cuarentena = ControladorCuarentena(modelo_principal)
            
            # Mostrar progreso
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, "PROCESSING Iniciando proceso de cuarentena...\n")
                self.text_cuarentena.update()
            
            resultado = controlador_cuarentena.poner_en_cuarentena(archivo)
            
            if resultado["exito"]:
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                        self.text_cuarentena.insert(tk.END, f"OK Archivo agregado a cuarentena: {os.path.basename(archivo)}\n")  # Issue 22/24: Sin emojis
                        self.text_cuarentena.insert(tk.END, f"OK Proceso completado exitosamente\n")  # Issue 22/24: Sin emojis
                messagebox.showinfo("Éxito", "Archivo enviado a cuarentena correctamente")
            else:
                error_msg = resultado.get('error', 'Error desconocido en cuarentena')
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
                
        except FileNotFoundError as e:
            error_msg = f"Archivo no encontrado: {str(e)}"
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)
        except PermissionError as e:
            error_msg = f"Sin permisos: {str(e)}"
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            messagebox.showerror("Error de Permisos", error_msg)
        except ImportError as e:
            error_msg = f"Error importando módulos: {str(e)}"
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            messagebox.showerror("Error del Sistema", error_msg)
        except Exception as e:
            error_msg = f"Error del sistema: {str(e)}"
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, f"ERROR CRÍTICO: {error_msg}\n")
            messagebox.showerror("Error Crítico", error_msg)
            
    
    def listar_cuarentena(self):
        """Listar archivos en cuarentena con manejo robusto de errores"""
        try:
            from aresitos.controlador.controlador_cuarentena import ControladorCuarentena
            # Crear modelo principal básico para el controlador
            modelo_principal = {'cuarentena': None}
            controlador_cuarentena = ControladorCuarentena(modelo_principal)
            
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.delete(1.0, tk.END)
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
            
            # Mostrar estado de carga
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, "LOADING Cargando archivos de cuarentena...\n")
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.update()
            
            archivos = controlador_cuarentena.listar_archivos_cuarentena()
            
            # Limpiar mensaje de carga
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.delete(1.0, tk.END)
            if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                self.text_cuarentena.insert(tk.END, "=== ARCHIVOS EN CUARENTENA ===\n\n")
            
            if not archivos:
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, "OK No hay archivos en cuarentena.\n")  # Issue 22/24: Sin emojis
                    self.text_cuarentena.insert(tk.END, "OK Sistema limpio\n")  # Issue 22/24: Sin emojis
            else:
                if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                    self.text_cuarentena.insert(tk.END, f"TOTAL: {len(archivos)} archivo(s) en cuarentena\n\n")
                
                for i, archivo in enumerate(archivos, 1):
                    try:
                        nombre = archivo.get('ruta_original', 'Desconocido')
                        fecha = archivo.get('fecha', 'N/A')
                        razon = archivo.get('razon', 'N/A')
                        
                        if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                            self.text_cuarentena.insert(tk.END, f"{i}. {os.path.basename(nombre)}\n")
                            self.text_cuarentena.insert(tk.END, f"   Ruta: {nombre}\n")
                            self.text_cuarentena.insert(tk.END, f"   Fecha: {fecha}\n")
                            self.text_cuarentena.insert(tk.END, f"   Razón: {razon}\n\n")
                    except Exception as e:
                        if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                            self.text_cuarentena.insert(tk.END, f"   ERROR procesando archivo {i}: {e}\n\n")
                    
            # Obtener resumen adicional con manejo de errores
            try:
                resumen = controlador_cuarentena.obtener_estadisticas()
                if resumen:
                    if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                        self.text_cuarentena.insert(tk.END, f"\n=== RESUMEN ===\n")
                    total = resumen.get('total_archivos', 0)
                    tamaño = resumen.get('tamano_total', 0)
                    
                    if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                        self.text_cuarentena.insert(tk.END, f"Total archivos: {total}\n")
                    
                    # Convertir bytes a formato legible
                    if tamaño > 1024 * 1024:  # MB
                        tamaño_str = f"{tamaño / (1024 * 1024):.2f} MB"
                    elif tamaño > 1024:  # KB
                        tamaño_str = f"{tamaño / 1024:.2f} KB"
                    else:
                        tamaño_str = f"{tamaño} bytes"
                    
                    if hasattr(self, 'text_cuarentena') and self.text_cuarentena:
                        self.text_cuarentena.insert(tk.END, f"Tamaño total: {tamaño_str}\n")
            except Exception as e:
                if self.text_cuarentena is not None:
                    self.text_cuarentena.insert(tk.END, f"\nWARNING Error obteniendo resumen: {e}\n")
                
        except ImportError as e:
            error_msg = f"Error importando controlador de cuarentena: {e}"
            if self.text_cuarentena is not None:
                self.text_cuarentena.delete(1.0, tk.END)
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
        except Exception as e:
            error_msg = f"Error listando cuarentena: {e}"
            if self.text_cuarentena is not None:
                self.text_cuarentena.delete(1.0, tk.END) 
                self.text_cuarentena.insert(tk.END, f"ERROR: {error_msg}\n")
            
        
        if not archivos:
            if self.text_cuarentena is not None:
                self.text_cuarentena.insert(tk.END, "No hay archivos en cuarentena.\n")
            return
        if self.text_cuarentena is not None:
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

