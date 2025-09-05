# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Cuarentena
Gestión visual y robusta de archivos, amenazas y eventos en cuarentena.
Cumple los principios de seguridad, MVC y robustez de ARESITOS.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
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
        # Integrar burp_theme y colores
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
                'fg_primary': '#f8f8f2',
                'fg_secondary': '#bbbbbb',
                'fg_accent': '#ffaa00',
                'button_bg': '#ffaa00',
                'button_fg': 'black',
                'success': '#50fa7b',
                'warning': '#f1fa8c',
                'danger': '#ff5555',
                'info': '#007acc'
            }
        self.configure(bg=self.colors['bg_primary'])
        self._crear_interfaz()

    def _crear_interfaz(self):
        # Título
        titulo = tk.Label(self, text="Gestión de Cuarentena de Amenazas", bg=self.colors['bg_primary'], fg=self.colors['fg_accent'], font=("Arial", 16, "bold"))
        titulo.pack(pady=10)
        self.texto_estado = tk.Label(self, text="", bg=self.colors['bg_primary'], fg=self.colors['success'], font=("Arial", 10))
        self.texto_estado.pack(pady=2)

        # Pestañas: Archivos | IPs
        self.notebook = ttk.Notebook(self, style='Custom.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- TABLA DE ARCHIVOS ---
        frame_archivos = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.lista_archivos = ttk.Treeview(frame_archivos, columns=("Archivo", "Hash", "Tipo", "Fecha", "Estado", "Acción"), show="headings")
        for col in ("Archivo", "Hash", "Tipo", "Fecha", "Estado", "Acción"):
            self.lista_archivos.heading(col, text=col)
            self.lista_archivos.column(col, width=180 if col=="Archivo" else (100 if col=="Acción" else 120))
        self.lista_archivos.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.dropdown_vars_archivos = {}
        self.combobox_iid_archivos = {}

        # Menú contextual para archivos
        self.menu_archivos = tk.Menu(self, tearoff=0, bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], activebackground=self.colors['button_bg'], activeforeground=self.colors['button_fg'])
        self.menu_archivos.add_command(label="Restaurar", command=self.restaurar_archivo_seleccionado)
        self.menu_archivos.add_command(label="Eliminar", command=self.eliminar_archivo_seleccionado)
        self.menu_archivos.add_command(label="Ver Detalles", command=self.ver_detalles_archivo)

        def mostrar_menu_archivos(event):
            iid = self.lista_archivos.identify_row(event.y)
            if iid:
                self.lista_archivos.selection_set(iid)
                # Opcional: deshabilitar "Restaurar" si ya está restaurado
                estado = self.lista_archivos.item(iid)['values'][4]
                if estado == 'restaurado':
                    self.menu_archivos.entryconfig("Restaurar", state="disabled")
                else:
                    self.menu_archivos.entryconfig("Restaurar", state="normal")
                self.menu_archivos.tk_popup(event.x_root, event.y_root)
            else:
                self.lista_archivos.selection_remove(self.lista_archivos.selection())
        self.lista_archivos.bind("<Button-3>", mostrar_menu_archivos)

        btn_frame_a = tk.Frame(frame_archivos, bg=self.colors['bg_primary'])
        btn_frame_a.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame_a, text="Actualizar", command=self.actualizar_lista_archivos, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_a, text="Eliminar", command=self.eliminar_archivo_seleccionado, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_a, text="Restaurar", command=self.restaurar_archivo_seleccionado, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_a, text="Ver Detalles", command=self.ver_detalles_archivo, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        self.notebook.add(frame_archivos, text="Archivos")

        # --- TABLA DE IPs ---
        frame_ips = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.lista_ips = ttk.Treeview(frame_ips, columns=("IP", "Tipo", "Razón", "Fecha", "Estado", "Acción"), show="headings")
        for col in ("IP", "Tipo", "Razón", "Fecha", "Estado", "Acción"):
            self.lista_ips.heading(col, text=col)
            self.lista_ips.column(col, width=160 if col=="IP" else (100 if col=="Acción" else 120))
        self.lista_ips.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.dropdown_vars_ips = {}
        self.combobox_iid_ips = {}

        # Menú contextual para IPs
        self.menu_ips = tk.Menu(self, tearoff=0, bg=self.colors['bg_secondary'], fg=self.colors['fg_primary'], activebackground=self.colors['button_bg'], activeforeground=self.colors['button_fg'])
        self.menu_ips.add_command(label="Bloquear", command=self.bloquear_ip_seleccionada)
        self.menu_ips.add_command(label="Permitir", command=self.permitir_ip_seleccionada)
        self.menu_ips.add_command(label="Eliminar", command=self.eliminar_ip_seleccionada)
        self.menu_ips.add_command(label="Ver Detalles", command=self.ver_detalles_ip)

        def mostrar_menu_ips(event):
            iid = self.lista_ips.identify_row(event.y)
            if iid:
                self.lista_ips.selection_set(iid)
                estado = self.lista_ips.item(iid)['values'][4]
                # Solo habilitar acciones según estado
                if estado == 'bloqueada':
                    self.menu_ips.entryconfig("Bloquear", state="disabled")
                    self.menu_ips.entryconfig("Permitir", state="normal")
                elif estado == 'permitida':
                    self.menu_ips.entryconfig("Bloquear", state="normal")
                    self.menu_ips.entryconfig("Permitir", state="disabled")
                else:
                    self.menu_ips.entryconfig("Bloquear", state="normal")
                    self.menu_ips.entryconfig("Permitir", state="normal")
                self.menu_ips.tk_popup(event.x_root, event.y_root)
            else:
                self.lista_ips.selection_remove(self.lista_ips.selection())
        self.lista_ips.bind("<Button-3>", mostrar_menu_ips)
        btn_frame_i = tk.Frame(frame_ips, bg=self.colors['bg_primary'])
        btn_frame_i.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame_i, text="Actualizar", command=self.actualizar_lista_ips, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_i, text="Bloquear", command=self.bloquear_ip_seleccionada, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_i, text="Permitir", command=self.permitir_ip_seleccionada, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_i, text="Eliminar", command=self.eliminar_ip_seleccionada, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_i, text="Ver Detalles", command=self.ver_detalles_ip, style='Burp.TButton').pack(side=tk.LEFT, padx=5)
        self.notebook.add(frame_ips, text="IPs")

        # Inicializar ambas listas
        self.actualizar_lista_archivos()
        self.actualizar_lista_ips()

    def actualizar_lista_archivos(self):
        for i in self.lista_archivos.get_children():
            self.lista_archivos.delete(i)
        self.dropdown_vars_archivos.clear()
        self.combobox_iid_archivos = {}
        try:
            archivos = self.modelo.listar_archivos_cuarentena()
            for a in archivos:
                iid = self.lista_archivos.insert('', 'end', values=(a['ruta_original'], a['hash_sha256'], a['tipo_amenaza'], a['fecha_cuarentena'], a['estado'], "Acción..."))
                var = tk.StringVar(value="Acción...")
                cb = ttk.Combobox(self.lista_archivos, textvariable=var, values=["Restaurar", "Eliminar", "Ver Detalles"], width=10, state="readonly")
                self.combobox_iid_archivos[cb] = iid
                cb.bind("<<ComboboxSelected>>", self._on_accion_archivo)
                self.lista_archivos.set(iid, "Acción", "Acción...")
                self.lista_archivos.update_idletasks()
                bbox = self.lista_archivos.bbox(iid, "Acción")
                if bbox:
                    x, y, w, h = bbox
                    cb.place(in_=self.lista_archivos, x=x, y=y, width=w, height=h)
                self.dropdown_vars_archivos[iid] = cb
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

    def _on_accion_archivo(self, event):
        cb = event.widget
        iid = self.combobox_iid_archivos.get(cb)
        if iid is None:
            return
        accion = cb.get()
        self.lista_archivos.selection_set(iid)
        if accion == "Restaurar":
            self.restaurar_archivo_seleccionado()
        elif accion == "Eliminar":
            self.eliminar_archivo_seleccionado()
        elif accion == "Ver Detalles":
            self.ver_detalles_archivo()
        cb.set("Acción...")

    def actualizar_lista_ips(self):
        for i in self.lista_ips.get_children():
            self.lista_ips.delete(i)
        self.dropdown_vars_ips.clear()
        self.combobox_iid_ips = {}
        try:
            if hasattr(self.controlador, 'listar_ips_cuarentena'):
                ips = self.controlador.listar_ips_cuarentena()
            else:
                ips = []
            for ip in ips:
                iid = self.lista_ips.insert('', 'end', values=(ip['ip'], ip['tipo_amenaza'], ip['razon'], ip['fecha_cuarentena'], ip['estado'], "Acción..."))
                var = tk.StringVar(value="Acción...")
                cb = ttk.Combobox(self.lista_ips, textvariable=var, values=["Bloquear", "Permitir", "Eliminar", "Ver Detalles"], width=10, state="readonly")
                self.combobox_iid_ips[cb] = iid
                cb.bind("<<ComboboxSelected>>", self._on_accion_ip)
                self.lista_ips.set(iid, "Acción", "Acción...")
                self.lista_ips.update_idletasks()
                bbox = self.lista_ips.bbox(iid, "Acción")
                if bbox:
                    x, y, w, h = bbox
                    cb.place(in_=self.lista_ips, x=x, y=y, width=w, height=h)
                self.dropdown_vars_ips[iid] = cb
            self.logger.log(f"Actualizada la lista de IPs en cuarentena ({len(ips)} elementos)", nivel="INFO", modulo="CUARENTENA")
        except Exception as e:
            self.logger.log(f"Error actualizando lista de IPs en cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")

    def _on_accion_ip(self, event):
        cb = event.widget
        iid = self.combobox_iid_ips.get(cb)
        if iid is None:
            return
        accion = cb.get()
        self.lista_ips.selection_set(iid)
        if accion == "Bloquear":
            self.bloquear_ip_seleccionada()
        elif accion == "Permitir":
            self.permitir_ip_seleccionada()
        elif accion == "Eliminar":
            self.eliminar_ip_seleccionada()
        elif accion == "Ver Detalles":
            self.ver_detalles_ip()
        cb.set("Acción...")

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
            except Exception as e:
                self.logger.log(f"Error eliminando archivo de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo eliminar: {e}")

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
            except Exception as e:
                self.logger.log(f"Error restaurando archivo de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo restaurar: {e}")

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

    # --- MÉTODOS PARA IPs ---
    def bloquear_ip_seleccionada(self):
        item = self.lista_ips.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione una IP para bloquear.")
            return
        ip = self.lista_ips.item(item[0])['values'][0]
        if messagebox.askyesno("Bloquear IP", f"¿Bloquear la IP {ip}? (iptables/ipset)"):
            try:
                res = self.controlador.cambiar_estado_ip(ip, 'bloqueada')
                self.logger.log(f"IP bloqueada: {ip}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista_ips()
            except Exception as e:
                self.logger.log(f"Error bloqueando IP: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo bloquear: {e}")

    def permitir_ip_seleccionada(self):
        item = self.lista_ips.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione una IP para permitir.")
            return
        ip = self.lista_ips.item(item[0])['values'][0]
        if messagebox.askyesno("Permitir IP", f"¿Permitir la IP {ip}? (quitar bloqueo)"):
            try:
                res = self.controlador.cambiar_estado_ip(ip, 'permitida')
                self.logger.log(f"IP permitida: {ip}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista_ips()
            except Exception as e:
                self.logger.log(f"Error permitiendo IP: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo permitir: {e}")

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

    def poner_en_cuarentena_desde_modulo(self, ruta_archivo, tipo_amenaza, razon):
        """Permite a otros módulos poner archivos/amenazas en cuarentena de forma centralizada."""
        res = self.modelo.poner_en_cuarentena(ruta_archivo, tipo_amenaza, razon)
        self.logger.log(f"Archivo puesto en cuarentena por otro módulo: {ruta_archivo} - {tipo_amenaza}", nivel="WARNING", modulo="CUARENTENA")
        self.actualizar_lista_archivos()
        return res
