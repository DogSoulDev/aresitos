# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Cuarentena
Gestión visual y robusta de archivos, amenazas y eventos en cuarentena.
Cumple los principios de seguridad, MVC y robustez de ARESITOS.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
from aresitos.utils.logger_aresitos import LoggerAresitos
from aresitos.modelo.modelo_cuarentena import CuarentenaKali2025
from aresitos.controlador.controlador_cuarentena import ControladorCuarentena

class VistaCuarentena(tk.Frame):
    def __init__(self, parent, modelo_principal=None):
        super().__init__(parent)
        self.logger = LoggerAresitos.get_instance()
        self.modelo = CuarentenaKali2025()
        self.controlador = ControladorCuarentena(modelo_principal)
        self.configure(bg='#232629')
        self._crear_interfaz()

    def _crear_interfaz(self):
        titulo = tk.Label(self, text="Gestión de Cuarentena de Amenazas", bg='#232629', fg='#ffaa00', font=("Arial", 16, "bold"))
        titulo.pack(pady=10)
        self.texto_estado = tk.Label(self, text="", bg='#232629', fg='#50fa7b', font=("Arial", 10))
        self.texto_estado.pack(pady=2)
        self.lista = ttk.Treeview(self, columns=("Archivo", "Hash", "Tipo", "Fecha", "Estado"), show="headings")
        for col in ("Archivo", "Hash", "Tipo", "Fecha", "Estado"):
            self.lista.heading(col, text=col)
            self.lista.column(col, width=180 if col=="Archivo" else 120)
        self.lista.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        btn_frame = tk.Frame(self, bg='#232629')
        btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(btn_frame, text="Actualizar", command=self.actualizar_lista, bg='#ffaa00', fg='black').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Eliminar", command=self.eliminar_seleccionado, bg='#ff5555', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Restaurar", command=self.restaurar_seleccionado, bg='#50fa7b', fg='black').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Ver Detalles", command=self.ver_detalles, bg='#007acc', fg='white').pack(side=tk.LEFT, padx=5)
        self.actualizar_lista()

    def actualizar_lista(self):
        for i in self.lista.get_children():
            self.lista.delete(i)
        try:
            archivos = self.modelo.listar_archivos_cuarentena()
            for a in archivos:
                self.lista.insert('', 'end', values=(a['ruta_original'], a['hash_sha256'], a['tipo_amenaza'], a['fecha_cuarentena'], a['estado']))
            self.texto_estado.config(text=f"{len(archivos)} archivos/amenazas en cuarentena.")
            self.logger.log(f"Actualizada la lista de cuarentena ({len(archivos)} elementos)", nivel="INFO", modulo="CUARENTENA")
        except Exception as e:
            self.texto_estado.config(text=f"Error actualizando lista: {e}")
            self.logger.log(f"Error actualizando lista de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")

    def eliminar_seleccionado(self):
        item = self.lista.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione un elemento para eliminar.")
            return
        archivo = self.lista.item(item[0])['values'][0]
        if messagebox.askyesno("Eliminar", f"¿Eliminar definitivamente {archivo} de la cuarentena?"):
            try:
                res = self.modelo.eliminar_archivo_cuarentena(archivo)
                self.logger.log(f"Eliminado archivo de cuarentena: {archivo}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista()
            except Exception as e:
                self.logger.log(f"Error eliminando archivo de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo eliminar: {e}")

    def restaurar_seleccionado(self):
        item = self.lista.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione un elemento para restaurar.")
            return
        archivo = self.lista.item(item[0])['values'][0]
        if messagebox.askyesno("Restaurar", f"¿Restaurar {archivo} a su ubicación original?"):
            try:
                res = self.modelo.restaurar_archivo_cuarentena(archivo)
                self.logger.log(f"Restaurado archivo de cuarentena: {archivo}", nivel="INFO", modulo="CUARENTENA")
                self.actualizar_lista()
            except Exception as e:
                self.logger.log(f"Error restaurando archivo de cuarentena: {e}", nivel="ERROR", modulo="CUARENTENA")
                messagebox.showerror("Error", f"No se pudo restaurar: {e}")

    def ver_detalles(self):
        item = self.lista.selection()
        if not item:
            messagebox.showinfo("Cuarentena", "Seleccione un elemento para ver detalles.")
            return
        archivo = self.lista.item(item[0])['values'][0]
        detalles = self.modelo.obtener_detalles_archivo(archivo)
        detalle_str = "\n".join([f"{k}: {v}" for k, v in detalles.items()])
        messagebox.showinfo("Detalles de archivo en cuarentena", detalle_str)
        self.logger.log(f"Consultados detalles de archivo en cuarentena: {archivo}", nivel="INFO", modulo="CUARENTENA")

    def poner_en_cuarentena_desde_modulo(self, ruta_archivo, tipo_amenaza, razon):
        """Permite a otros módulos poner archivos/amenazas en cuarentena de forma centralizada."""
        res = self.modelo.poner_en_cuarentena(ruta_archivo, tipo_amenaza, razon)
        self.logger.log(f"Archivo puesto en cuarentena por otro módulo: {ruta_archivo} - {tipo_amenaza}", nivel="WARNING", modulo="CUARENTENA")
        self.actualizar_lista()
        return res
