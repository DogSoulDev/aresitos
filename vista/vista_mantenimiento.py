import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from aresitos.vista.burp_theme import burp_theme


class VistaMantenimiento(tk.Frame):
    def __init__(self, master, controlador):
        super().__init__(master)
        self.controlador = controlador
        self.theme = burp_theme
        self.colors = {
            'bg_primary': burp_theme.get_color('bg_primary'),
            'bg_secondary': burp_theme.get_color('bg_secondary'),
            'fg_primary': burp_theme.get_color('fg_primary'),
            'fg_accent': burp_theme.get_color('fg_accent'),
            'button_bg': burp_theme.get_color('button_bg'),
            'button_fg': burp_theme.get_color('button_fg')
        }
        self.configure(bg=self.colors['bg_primary'])
        style = ttk.Style()
        burp_theme.configure_ttk_style(style)
        self.crear_interfaz()

    def crear_interfaz(self):

        # Título principal
        titulo_frame = tk.Frame(self, bg=self.colors['bg_secondary'])
        titulo_frame.pack(fill="x", padx=10, pady=5)
        titulo_label = tk.Label(
            titulo_frame,
            text="Mantenimiento y actualización de ARESITOS",
            font=("Arial", 16, "bold"),
            fg=self.colors['fg_accent'],
            bg=self.colors['bg_secondary']
        )
        titulo_label.pack()

        # Pestañas para secciones (solo una por ahora)
        self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Marco principal de mantenimiento
        mantenimiento_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(mantenimiento_frame, text="Opciones de mantenimiento")

        # Marco de acciones
        acciones_frame = tk.LabelFrame(
            mantenimiento_frame,
            text="Acciones de mantenimiento",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        acciones_frame.pack(fill="x", padx=10, pady=10)

        # Botones de acción
        botones = [
            ("Actualizar ARESITOS", self._on_actualizar),
            ("Crear copia de seguridad", self._on_backup),
            ("Restaurar copia de seguridad", self._on_restore),
            ("Seleccionar backup para restaurar", self._on_seleccionar_backup),
            ("Ver registros de actualización", self._on_ver_logs),
            ("Limpiar archivos temporales", self._on_limpiar),
            ("Ver estado del repositorio", self._on_estado),
            ("Comprobar integridad", self._on_integridad),
            ("Información de la versión", self._on_version),
            ("Reiniciar ARESITOS", self._on_reiniciar)
        ]
        for texto, comando in botones:
            btn = ttk.Button(acciones_frame, text=texto, command=comando, style='Burp.TButton')
            btn.pack(fill="x", padx=10, pady=4)

        # Área de registros
        log_frame = tk.LabelFrame(
            mantenimiento_frame,
            text="Registros de mantenimiento",
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=("Arial", 12, "bold")
        )
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_primary'],
            font=("Consolas", 10),
            insertbackground=self.colors['fg_accent']
        )
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)

    def mostrar_log(self, texto):
        self.log_area.insert(tk.END, texto + "\n")
        self.log_area.see(tk.END)

    def _on_actualizar(self):
        self.controlador.actualizar_aresitos(self)

    def _on_backup(self):
        self.controlador.crear_backup(self)

    def _on_restore(self):
        self.controlador.restaurar_backup(self)

    def _on_seleccionar_backup(self):
        # Permite seleccionar y restaurar backup desde la interfaz
        self.controlador.restaurar_backup(self)

    def _on_ver_logs(self):
        self.controlador.ver_logs_actualizacion(self)

    def _on_limpiar(self):
        self.controlador.limpiar_temporales(self)

    def _on_estado(self):
        self.controlador.ver_estado_repositorio(self)

    def _on_integridad(self):
        self.controlador.comprobar_integridad(self)

    def _on_version(self):
        self.controlador.ver_informacion_version(self)

    def _on_reiniciar(self):
        self.controlador.reiniciar_aresitos(self)
