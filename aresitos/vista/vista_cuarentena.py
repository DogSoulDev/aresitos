# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Cuarentena
Gestión visual y robusta de archivos, amenazas y eventos en cuarentena.
Cumple los principios de seguridad, MVC y robustez de ARESITOS.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import datetime
from aresitos.utils.logger_aresitos import LoggerAresitos
from aresitos.modelo.modelo_cuarentena import CuarentenaKali2025
from aresitos.controlador.controlador_cuarentena import ControladorCuarentena

class VistaCuarentena(tk.Frame):
    def __init__(self, parent, modelo_principal=None):
        super().__init__(parent)
        self.logger = LoggerAresitos.get_instance()
        self.modelo = CuarentenaKali2025()
        self.controlador = ControladorCuarentena(modelo_principal)
        # Configuración de colores y tema
        try:
            from aresitos.vista.burp_theme import burp_theme
            self.theme = burp_theme
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
        except Exception:
            self.theme = None
            self.colors = {
                'bg_primary': '#232629',
                'bg_secondary': '#282a36',
                'fg_primary': '#ffffff',
                'fg_secondary': '#bfbfbf',
                'fg_accent': '#ff6633',
                'button_bg': '#ffb86c',
                'button_fg': '#232629',
                'success': '#50fa7b',
                'warning': '#ffb86c',
                'danger': '#ff5555',
                'info': '#8be9fd'
            }
        # Título principal
        titulo = tk.Label(self, text="Gestión de Cuarentena de Amenazas", bg=self.colors['bg_primary'], fg=self.colors['fg_accent'], font=("Arial", 16, "bold"))
        titulo.pack(pady=10)
        self.texto_estado = tk.Label(self, text="", bg=self.colors['bg_primary'], fg=self.colors['success'], font=("Arial", 10))
        self.texto_estado.pack(pady=2)

        # Pestañas: Archivos | IPs
        self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- TABLA DE ARCHIVOS ---
        self.frame_archivos = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.lista_archivos = ttk.Treeview(self.frame_archivos, columns=("Archivo", "Hash", "Tipo", "Fecha", "Estado", "Acción"), show="headings")
        for col in ("Archivo", "Hash", "Tipo", "Fecha", "Estado", "Acción"):
            self.lista_archivos.heading(col, text=col)
            self.lista_archivos.column(col, width=180 if col=="Archivo" else (100 if col=="Acción" else 120))
        self.lista_archivos.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Menú contextual para archivos
        self.menu_archivos = tk.Menu(self, tearoff=0, bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], activebackground=self.colors['button_bg'], activeforeground=self.colors['button_fg'])
        self.menu_archivos.add_command(label="Restaurar", command=self.restaurar_archivo_seleccionado)
        self.menu_archivos.add_command(label="Eliminar", command=self.eliminar_archivo_seleccionado)
        self.menu_archivos.add_command(label="Ver Detalles", command=self.ver_detalles_archivo)
        self.menu_archivos.add_command(label="Analizar archivo", command=self.analizar_archivo_seleccionado)

        def mostrar_menu_archivos(event):
            iid = self.lista_archivos.identify_row(event.y)
            if iid:
                self.lista_archivos.selection_set(iid)
                estado = self.lista_archivos.item(iid)['values'][4]
                if estado == 'restaurado':
                    self.menu_archivos.entryconfig("Restaurar", state="disabled")
                else:
                    self.menu_archivos.entryconfig("Restaurar", state="normal")
                self.menu_archivos.tk_popup(event.x_root, event.y_root)
            else:
                self.lista_archivos.selection_remove(self.lista_archivos.selection())
        self.lista_archivos.bind("<Button-3>", mostrar_menu_archivos)

        # Botones principales debajo de la tabla
        btn_frame_a = tk.Frame(self.frame_archivos, bg=self.colors['bg_primary'])
        btn_frame_a.pack(fill=tk.X, pady=5)
        self.btn_agregar = ttk.Button(
            btn_frame_a, text="Agregar a Cuarentena",
            command=getattr(self, 'agregar_a_cuarentena', lambda: None),
            style='Burp.TButton', width=16
        )
        self.btn_agregar.pack(side="left", padx=(0, 8), pady=4)

        self.btn_listar = ttk.Button(
            btn_frame_a, text="Listar Archivos",
            command=getattr(self, 'listar_cuarentena', lambda: None),
            style='Burp.TButton', width=16
        )
        self.btn_listar.pack(side="left", padx=(0, 8), pady=4)
        self.notebook.add(self.frame_archivos, text="Archivos")
        self.notebook.add(self.frame_archivos, text="Cuarentena")
        # Si existe una pestaña de Monitoreo Sistem, cámbiala por Monitoreo S.
        for idx in range(self.notebook.index('end')):
            if self.notebook.tab(idx, 'text') == 'Monitoreo Sistem':
                self.notebook.tab(idx, text='Monitoreo S.')
        # --- TABLA DE IPs SOSPECHOSAS ---
        self.frame_ips = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.lista_ips = ttk.Treeview(self.frame_ips, columns=("IP", "Motivo", "Fecha", "Estado", "Acción"), show="headings")
        for col in ("IP", "Motivo", "Fecha", "Estado", "Acción"):
            self.lista_ips.heading(col, text=col)
            self.lista_ips.column(col, width=160 if col=="IP" else (100 if col=="Acción" else 120))
        self.lista_ips.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Menú contextual para IPs
        self.menu_ips = tk.Menu(self, tearoff=0, bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], activebackground=self.colors['button_bg'], activeforeground=self.colors['button_fg'])
        self.menu_ips.add_command(label="Eliminar", command=self.eliminar_ip_seleccionada)
        self.menu_ips.add_command(label="Ver Detalles", command=self.ver_detalles_ip)
        self.menu_ips.add_command(label="Analizar IP", command=self.analizar_ip_seleccionada)

        def mostrar_menu_ips(event):
            iid = self.lista_ips.identify_row(event.y)
            if iid:
                self.lista_ips.selection_set(iid)
                self.menu_ips.tk_popup(event.x_root, event.y_root)
            else:
                self.lista_ips.selection_remove(self.lista_ips.selection())
        self.lista_ips.bind("<Button-3>", mostrar_menu_ips)

        # Botones principales debajo de la tabla de IPs
        btn_frame_ip = tk.Frame(self.frame_ips, bg=self.colors['bg_primary'])
        btn_frame_ip.pack(fill=tk.X, pady=5)
        self.btn_actualizar_ip = tk.Button(
            btn_frame_ip, text="Actualizar",
            command=getattr(self, 'actualizar_lista_ips', lambda: None),
            bg=self.colors['button_bg'] if self.theme else 'lightgray',
            fg='white' if self.theme else 'black',
            font=('Arial', 10, 'bold'), relief='raised', padx=8, pady=4
        )
        self.btn_actualizar_ip.pack(side="left", padx=5)

        self.btn_eliminar_ip = tk.Button(
            btn_frame_ip, text="Eliminar",
            command=getattr(self, 'eliminar_ip_seleccionada', lambda: None),
            bg=self.colors['danger'] if self.theme else 'lightgray',
            fg='white' if self.theme else 'black',
            font=('Arial', 10, 'bold'), relief='raised', padx=8, pady=4
        )
        self.btn_eliminar_ip.pack(side="left", padx=5)

        self.btn_ver_detalles_ip = tk.Button(
            btn_frame_ip, text="Ver Detalles",
            command=getattr(self, 'ver_detalles_ip', lambda: None),
            bg=self.colors['info'] if self.theme else 'lightgray',
            fg='white' if self.theme else 'black',
            font=('Arial', 10, 'bold'), relief='raised', padx=8, pady=4
        )
        self.btn_ver_detalles_ip.pack(side="left", padx=5)
        self.notebook.add(self.frame_ips, text="IPs sospechosas")

        # Filtro de búsqueda para archivos
        filtro_frame = tk.Frame(self.frame_archivos, bg=self.colors['bg_primary'])
        filtro_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(filtro_frame, text="Buscar:", bg=self.colors['bg_primary'], fg=self.colors['fg_primary']).pack(side=tk.LEFT)
        self.entry_busqueda = tk.Entry(filtro_frame, width=30)
        self.entry_busqueda.pack(side=tk.LEFT, padx=5)

    # --- MÉTODOS DE ACCIÓN PARA ARCHIVOS ---
    def filtrar_archivos(self):
        filtro = self.entry_busqueda.get().strip().lower()
        for i in self.lista_archivos.get_children():
            self.lista_archivos.delete(i)
        try:
            archivos = self.modelo.listar_archivos_cuarentena()
            filtrados = [a for a in archivos if filtro in a['ruta_original'].lower() or filtro in a['tipo_amenaza'].lower() or filtro in a['hash_sha256'].lower()]
            for a in filtrados:
                self.lista_archivos.insert('', 'end', values=(a['ruta_original'], a['hash_sha256'], a['tipo_amenaza'], a['fecha_cuarentena'], a['estado'], "Acción..."))
            self.texto_estado.config(text=f"{len(filtrados)} archivos/amenazas filtrados.")
        except Exception as e:
            self.texto_estado.config(text=f"Error filtrando archivos: {e}")
            self.logger.log(f"Error filtrando archivos en cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")

    def limpiar_filtro_archivos(self):
        self.entry_busqueda.delete(0, tk.END)
        self.actualizar_lista_archivos()

    def actualizar_lista_archivos(self):
        for i in self.lista_archivos.get_children():
            self.lista_archivos.delete(i)
        try:
            archivos = self.modelo.listar_archivos_cuarentena()
            for a in archivos:
                color = self.colors['danger'] if a['estado'] == 'infectado' else (self.colors['warning'] if a['estado'] == 'sospechoso' else self.colors['success'])
                iid = self.lista_archivos.insert('', 'end', values=(a['ruta_original'], a['hash_sha256'], a['tipo_amenaza'], a['fecha_cuarentena'], a['estado'], "Acción..."))
                self.lista_archivos.tag_configure(a['estado'], background=color)
                self.lista_archivos.item(iid, tags=(a['estado'],))
            self.texto_estado.config(text=f"{len(archivos)} archivos/amenazas en cuarentena.")
            self.logger.log(f"Actualizada la lista de archivos en cuarentena ({len(archivos)} elementos)", nivel="INFO", modulo="CUARENTENA")
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
                    datos = {'archivos': archivos, 'timestamp': datetime.datetime.now().isoformat()}
                    vista_reportes.set_datos_modulo('cuarentena', datos)
            except Exception:
                pass
        except Exception as e:
            self.texto_estado.config(text=f"Error actualizando lista de archivos: {e}")
            self.logger.log(f"Error actualizando lista de archivos en cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")

    def actualizar_lista_ips(self):
        for i in self.lista_ips.get_children():
            self.lista_ips.delete(i)
        try:
            if hasattr(self.controlador, 'listar_ips_cuarentena'):
                ips = self.controlador.listar_ips_cuarentena()
            else:
                ips = []
            for ip in ips:
                self.lista_ips.insert('', 'end', values=(ip['ip'], ip['tipo_amenaza'], ip['razon'], ip['fecha_cuarentena'], ip['estado'], "Acción..."))
            self.logger.log(f"Actualizada la lista de IPs en cuarentena ({len(ips)} elementos)", nivel="INFO", modulo="CUARENTENA")
        except Exception as e:
            self.logger.log(f"Error actualizando lista de IPs en cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")

    def restaurar_archivo_seleccionado(self):
        item = self.lista_archivos.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione un archivo para restaurar.")
            return
        archivo = self.lista_archivos.item(item[0])['values'][0]
        if messagebox.askyesno("Restaurar", f"¿Restaurar {archivo} a su ubicación original?"):
            try:
                res = self.modelo.restaurar_archivo_cuarentena(archivo)
                self.logger.log(f"Restaurado archivo de cuarentena: {archivo}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista_archivos()
                self._finalizar_cuarentena()
            except Exception as e:
                self.logger.log(f"Error restaurando archivo de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo restaurar: {e}")

    def eliminar_archivo_seleccionado(self):
        item = self.lista_archivos.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione un archivo para eliminar.")
            return
        archivo = self.lista_archivos.item(item[0])['values'][0]
        if messagebox.askyesno("Eliminar", f"¿Eliminar definitivamente {archivo} de la cuarentena?"):
            try:
                res = self.modelo.eliminar_archivo_cuarentena(archivo)
                self.logger.log(f"Eliminado archivo de cuarentena: {archivo}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista_archivos()
                self._finalizar_cuarentena()
            except Exception as e:
                self.logger.log(f"Error eliminando archivo de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo eliminar: {e}")

    def ver_detalles_archivo(self):
        item = self.lista_archivos.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione un archivo para ver detalles.")
            return
        archivo = self.lista_archivos.item(item[0])['values'][0]
        detalles = self.modelo.obtener_detalles_archivo(archivo)
        detalle_str = "\n".join([f"{k}: {v}" for k, v in detalles.items()])
        messagebox.showinfo("Detalles de archivo en cuarentena", detalle_str)
        self.logger.log(f"Consultados detalles de archivo en cuarentena: {archivo}", nivel="INFO", modulo="CUARENTENA")

    def analizar_archivo_seleccionado(self):
        seleccion = self.lista_archivos.selection()
        if not seleccion:
            messagebox.showwarning("Advertencia", "Seleccione un archivo para analizar.")
            return
        iid = seleccion[0]
        valores = self.lista_archivos.item(iid)['values']
        ruta = valores[0]
        hash_archivo = valores[1]
        tipo = valores[2]
        try:
            from aresitos.utils.sudo_manager import SudoManager
            sudo_manager = SudoManager()
            comando = f"clamscan '{ruta}'"
            if sudo_manager.is_sudo_active():
                resultado = sudo_manager.execute_sudo_command(comando, timeout=60)
            else:
                import subprocess
                resultado = subprocess.run(comando, shell=True, capture_output=True, text=True, timeout=60)
            salida = resultado.stdout.strip()
            error = resultado.stderr.strip()
            mensaje = f"\n[ANÁLISIS DE ARCHIVO]\nRuta: {ruta}\nHash SHA256: {hash_archivo}\nTipo de amenaza: {tipo}\n\nResultado ClamAV:\n{salida}"
            if error:
                mensaje += f"\n[ERROR] {error}"
            messagebox.showinfo("Resultado del análisis", mensaje)
            self.logger.log(f"Análisis de archivo en cuarentena: {ruta}", nivel="INFO", modulo="CUARENTENA")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo analizar el archivo: {e}")
            self.logger.log(f"Error analizando archivo en cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")

    # --- MÉTODOS DE ACCIÓN PARA IPs ---
    def eliminar_ip_seleccionada(self):
        item = self.lista_ips.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione una IP para eliminar.")
            return
        ip = self.lista_ips.item(item[0])['values'][0]
        if messagebox.askyesno("Eliminar IP", f"¿Eliminar definitivamente la IP {ip} de la cuarentena?"):
            try:
                res = self.controlador.eliminar_ip_cuarentena(ip)
                self.logger.log(f"IP eliminada de cuarentena: {ip}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista_ips()
            except Exception as e:
                self.logger.log(f"Error eliminando IP de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo eliminar: {e}")

    def ver_detalles_ip(self):
        item = self.lista_ips.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione una IP para ver detalles.")
            return
        ip = self.lista_ips.item(item[0])['values'][0]
        detalles = self.controlador.obtener_detalles_ip(ip)
        detalle_str = "\n".join([f"{k}: {v}" for k, v in detalles.items()])
        messagebox.showinfo("Detalles de IP en cuarentena", detalle_str)
        self.logger.log(f"Consultados detalles de IP en cuarentena: {ip}", nivel="INFO", modulo="CUARENTENA")

    def analizar_ip_seleccionada(self):
        seleccion = self.lista_ips.selection()
        if not seleccion:
            messagebox.showwarning("Advertencia", "Seleccione una IP para analizar.")
            return
        iid = seleccion[0]
        valores = self.lista_ips.item(iid)['values']
        ip = valores[0]
        # Lógica real: consultar amenazas en la base de datos o API de reputación
        amenazas = self.modelo.obtener_detalles_ip(ip).get('amenazas', [])
        if amenazas:
            resultado = f"Análisis de la IP {ip}: Amenazas detectadas: {', '.join(amenazas)}"
        else:
            resultado = f"Análisis de la IP {ip}: Sin amenazas detectadas."
        messagebox.showinfo("Resultado del análisis de IP", resultado)
        self.logger.log(f"Análisis de IP en cuarentena: {ip}", nivel="INFO", modulo="CUARENTENA")

    def poner_en_cuarentena_desde_modulo(self, ruta_archivo, tipo_amenaza, razon):
        """Permite a otros módulos poner archivos/amenazas en cuarentena de forma centralizada."""
        res = self.modelo.poner_en_cuarentena(ruta_archivo, tipo_amenaza, razon)
        self.logger.log(f"Archivo puesto en cuarentena por otro módulo: {ruta_archivo} - {tipo_amenaza}", nivel="WARNING", modulo="CUARENTENA")
        self.actualizar_lista_archivos()
        self._finalizar_cuarentena()
        return res

    def _finalizar_cuarentena(self):
        """Finalizar proceso de cuarentena y enviar datos a Reportes."""
        try:
            archivos = self.modelo.listar_archivos_cuarentena()
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            if vista_reportes:
                datos = {'archivos': archivos, 'timestamp': datetime.datetime.now().isoformat()}
                vista_reportes.set_datos_modulo('cuarentena', datos)
        except Exception:
            pass
