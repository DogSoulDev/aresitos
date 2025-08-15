#!/usr/bin/env python3
"""
Vista para gestión de diccionarios de ciberseguridad
Autor: Aresitos
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Dict, List, Optional, Any

class VistaDiccionarios:
    def __init__(self, parent_frame, controlador):
        """Inicializa la vista de diccionarios"""
        self.parent_frame = parent_frame
        self.controlador = controlador
        
        # Variables de control
        self.diccionario_seleccionado = tk.StringVar()
        self.filtro_categoria = tk.StringVar(value="todos")
        self.filtro_busqueda = tk.StringVar()
        
        self._crear_interfaz()
        self._configurar_eventos()
        
    def _crear_interfaz(self):
        """Crea la interfaz de usuario"""
        # Frame principal
        main_frame = ttk.Frame(self.parent_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        title_label = ttk.Label(main_frame, text="Gestión de Diccionarios", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Frame de controles
        control_frame = ttk.LabelFrame(main_frame, text="Controles", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Fila de filtros
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Filtro por categoría
        ttk.Label(filter_frame, text="Categoría:").grid(row=0, column=0, padx=(0, 5))
        self.categoria_combo = ttk.Combobox(filter_frame, textvariable=self.filtro_categoria,
                                          values=["todos", "passwords", "usuarios", "directorios", 
                                                "subdominios", "api", "personalizado"],
                                          state="readonly", width=15)
        self.categoria_combo.grid(row=0, column=1, padx=(0, 20))
        
        # Búsqueda
        ttk.Label(filter_frame, text="Buscar:").grid(row=0, column=2, padx=(0, 5))
        self.busqueda_entry = ttk.Entry(filter_frame, textvariable=self.filtro_busqueda, width=20)
        self.busqueda_entry.grid(row=0, column=3, padx=(0, 20))
        
        # Botón de actualizar
        self.actualizar_btn = ttk.Button(filter_frame, text="Actualizar",
                                       command=self._actualizar_lista)
        self.actualizar_btn.grid(row=0, column=4)
        
        # Frame de acciones
        action_frame = ttk.Frame(control_frame)
        action_frame.pack(fill=tk.X)
        
        # Botones de acción
        self.crear_btn = ttk.Button(action_frame, text="Crear Diccionario",
                                   command=self._crear_diccionario)
        self.crear_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.importar_btn = ttk.Button(action_frame, text="Importar",
                                     command=self._importar_diccionario)
        self.importar_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.exportar_btn = ttk.Button(action_frame, text="Exportar",
                                     command=self._exportar_diccionario)
        self.exportar_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.editar_btn = ttk.Button(action_frame, text="Editar",
                                   command=self._editar_diccionario)
        self.editar_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.eliminar_btn = ttk.Button(action_frame, text="Eliminar",
                                     command=self._eliminar_diccionario)
        self.eliminar_btn.pack(side=tk.LEFT)
        
        # Frame de contenido principal
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Panel izquierdo - Lista de diccionarios
        left_panel = ttk.LabelFrame(content_frame, text="Diccionarios Disponibles", padding="10")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Treeview para diccionarios
        self.diccionarios_tree = ttk.Treeview(left_panel, 
                                            columns=('categoria', 'tamaño', 'modificado'),
                                            show='tree headings',
                                            height=15)
        
        # Configurar columnas
        self.diccionarios_tree.heading('#0', text='Nombre')
        self.diccionarios_tree.heading('categoria', text='Categoría')
        self.diccionarios_tree.heading('tamaño', text='Tamaño')
        self.diccionarios_tree.heading('modificado', text='Modificado')
        
        self.diccionarios_tree.column('#0', width=200)
        self.diccionarios_tree.column('categoria', width=100)
        self.diccionarios_tree.column('tamaño', width=80)
        self.diccionarios_tree.column('modificado', width=120)
        
        # Scrollbar para el tree
        dict_scrollbar = ttk.Scrollbar(left_panel, orient=tk.VERTICAL, 
                                     command=self.diccionarios_tree.yview)
        self.diccionarios_tree.configure(yscrollcommand=dict_scrollbar.set)
        
        self.diccionarios_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dict_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Panel derecho - Detalles y vista previa
        right_panel = ttk.LabelFrame(content_frame, text="Detalles del Diccionario", padding="10")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Frame de información
        info_frame = ttk.Frame(right_panel)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Información del diccionario
        self.info_text = tk.Text(info_frame, height=6, width=40, wrap=tk.WORD)
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, 
                                     command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        self.info_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        info_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Frame de vista previa
        preview_frame = ttk.LabelFrame(right_panel, text="Vista Previa", padding="10")
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        # Área de vista previa
        self.preview_text = tk.Text(preview_frame, height=12, width=40, wrap=tk.WORD)
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL,
                                        command=self.preview_text.yview)
        self.preview_text.configure(yscrollcommand=preview_scrollbar.set)
        
        self.preview_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Frame de estadísticas
        stats_frame = ttk.LabelFrame(main_frame, text="Estadísticas", padding="10")
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Labels de estadísticas
        self.stats_labels = {}
        stats_row = ttk.Frame(stats_frame)
        stats_row.pack(fill=tk.X)
        
        stats_info = [
            ("total_diccionarios", "Total de Diccionarios: "),
            ("total_entradas", "Total de Entradas: "),
            ("tamaño_total", "Tamaño Total: "),
            ("ultima_actualizacion", "Última Actualización: ")
        ]
        
        for i, (key, label) in enumerate(stats_info):
            col = i % 2
            row = i // 2
            
            if row > 0 and col == 0:
                stats_row = ttk.Frame(stats_frame)
                stats_row.pack(fill=tk.X, pady=(5, 0))
            
            label_widget = ttk.Label(stats_row, text=label)
            label_widget.grid(row=0, column=col*2, sticky=tk.W, padx=(0, 5))
            
            value_widget = ttk.Label(stats_row, text="0", foreground="blue")
            value_widget.grid(row=0, column=col*2+1, sticky=tk.W, padx=(0, 30))
            
            self.stats_labels[key] = value_widget
        
    def _configurar_eventos(self):
        """Configura los eventos de la interfaz"""
        # Evento de selección en el tree
        self.diccionarios_tree.bind('<<TreeviewSelect>>', self._on_diccionario_select)
        
        # Evento de doble clic
        self.diccionarios_tree.bind('<Double-1>', self._on_diccionario_double_click)
        
        # Eventos de filtrado
        self.categoria_combo.bind('<<ComboboxSelected>>', self._on_filtro_change)
        self.busqueda_entry.bind('<KeyRelease>', self._on_busqueda_change)
        
    def _actualizar_lista(self):
        """Actualiza la lista de diccionarios"""
        try:
            # Limpiar tree
            for item in self.diccionarios_tree.get_children():
                self.diccionarios_tree.delete(item)
            
            # Obtener diccionarios del controlador
            filtros = {
                'categoria': self.filtro_categoria.get() if self.filtro_categoria.get() != "todos" else None,
                'busqueda': self.filtro_busqueda.get() if self.filtro_busqueda.get() else None
            }
            
            diccionarios = self.controlador.obtener_diccionarios(filtros)
            
            # Poblar tree
            for diccionario in diccionarios:
                self.diccionarios_tree.insert('', 'end',
                                            text=diccionario['nombre'],
                                            values=(diccionario['categoria'],
                                                  diccionario['tamaño_formateado'],
                                                  diccionario['fecha_modificacion']))
            
            # Actualizar estadísticas
            self._actualizar_estadisticas()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al actualizar lista: {str(e)}")
    
    def _actualizar_estadisticas(self):
        """Actualiza las estadísticas mostradas"""
        try:
            stats = self.controlador.obtener_estadisticas()
            
            self.stats_labels['total_diccionarios'].config(text=str(stats['total_diccionarios']))
            self.stats_labels['total_entradas'].config(text=f"{stats['total_entradas']:,}")
            self.stats_labels['tamaño_total'].config(text=stats['tamaño_total_formateado'])
            self.stats_labels['ultima_actualizacion'].config(text=stats['ultima_actualizacion'])
            
        except Exception as e:
            print(f"Error actualizando estadísticas: {e}")
    
    def _on_diccionario_select(self, event):
        """Maneja la selección de un diccionario"""
        selection = self.diccionarios_tree.selection()
        if not selection:
            return
        
        item = self.diccionarios_tree.item(selection[0])
        nombre_diccionario = item['text']
        
        # Actualizar información
        self._mostrar_info_diccionario(nombre_diccionario)
        
        # Actualizar vista previa
        self._mostrar_preview_diccionario(nombre_diccionario)
    
    def _on_diccionario_double_click(self, event):
        """Maneja doble clic en diccionario"""
        self._editar_diccionario()
    
    def _on_filtro_change(self, event):
        """Maneja cambio en filtros"""
        self._actualizar_lista()
    
    def _on_busqueda_change(self, event):
        """Maneja cambio en búsqueda"""
        # Actualizar con delay para evitar demasiadas actualizaciones
        if hasattr(self, '_busqueda_timer'):
            self.parent_frame.after_cancel(self._busqueda_timer)
        
        self._busqueda_timer = self.parent_frame.after(500, self._actualizar_lista)
    
    def _mostrar_info_diccionario(self, nombre: str):
        """Muestra información detallada del diccionario"""
        try:
            info = self.controlador.obtener_info_diccionario(nombre)
            
            self.info_text.delete(1.0, tk.END)
            
            info_texto = f"""Nombre: {info['nombre']}
Categoría: {info['categoria']}
Descripción: {info.get('descripcion', 'Sin descripción')}
Tamaño: {info['tamaño_formateado']} ({info['numero_entradas']:,} entradas)
Fecha de creación: {info['fecha_creacion']}
Última modificación: {info['fecha_modificacion']}
Formato: {info.get('formato', 'Texto plano')}
Encoding: {info.get('encoding', 'UTF-8')}"""
            
            self.info_text.insert(1.0, info_texto)
            
        except Exception as e:
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(1.0, f"Error al cargar información: {str(e)}")
    
    def _mostrar_preview_diccionario(self, nombre: str):
        """Muestra vista previa del diccionario"""
        try:
            preview = self.controlador.obtener_preview_diccionario(nombre, lineas=50)
            
            self.preview_text.delete(1.0, tk.END)
            
            if preview:
                preview_texto = "\n".join(preview)
                if len(preview) == 50:
                    preview_texto += "\n\n... (más entradas disponibles)"
                
                self.preview_text.insert(1.0, preview_texto)
            else:
                self.preview_text.insert(1.0, "No se pudo cargar la vista previa")
                
        except Exception as e:
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(1.0, f"Error al cargar vista previa: {str(e)}")
    
    def _crear_diccionario(self):
        """Abre ventana para crear nuevo diccionario"""
        VentanaCrearDiccionario(self.parent_frame, self.controlador, self._actualizar_lista)
    
    def _importar_diccionario(self):
        """Importa diccionario desde archivo"""
        archivo = filedialog.askopenfilename(
            title="Seleccionar diccionario",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        
        if archivo:
            VentanaImportarDiccionario(self.parent_frame, self.controlador, 
                                     self._actualizar_lista, archivo)
    
    def _exportar_diccionario(self):
        """Exporta diccionario seleccionado"""
        selection = self.diccionarios_tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un diccionario para exportar")
            return
        
        item = self.diccionarios_tree.item(selection[0])
        nombre_diccionario = item['text']
        
        archivo = filedialog.asksaveasfilename(
            title="Exportar diccionario",
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
            initialfile=f"{nombre_diccionario}.txt"
        )
        
        if archivo:
            try:
                self.controlador.exportar_diccionario(nombre_diccionario, archivo)
                messagebox.showinfo("Éxito", "Diccionario exportado correctamente")
            except Exception as e:
                messagebox.showerror("Error", f"Error al exportar: {str(e)}")
    
    def _editar_diccionario(self):
        """Abre ventana para editar diccionario"""
        selection = self.diccionarios_tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un diccionario para editar")
            return
        
        item = self.diccionarios_tree.item(selection[0])
        nombre_diccionario = item['text']
        
        VentanaEditarDiccionario(self.parent_frame, self.controlador, 
                               self._actualizar_lista, nombre_diccionario)
    
    def _eliminar_diccionario(self):
        """Elimina diccionario seleccionado"""
        selection = self.diccionarios_tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un diccionario para eliminar")
            return
        
        item = self.diccionarios_tree.item(selection[0])
        nombre_diccionario = item['text']
        
        respuesta = messagebox.askyesno("Confirmar", 
                                       f"¿Está seguro de eliminar el diccionario '{nombre_diccionario}'?")
        
        if respuesta:
            try:
                self.controlador.eliminar_diccionario(nombre_diccionario)
                messagebox.showinfo("Éxito", "Diccionario eliminado correctamente")
                self._actualizar_lista()
            except Exception as e:
                messagebox.showerror("Error", f"Error al eliminar: {str(e)}")


class VentanaCrearDiccionario:
    def __init__(self, parent, controlador, callback_actualizar):
        """Ventana para crear nuevo diccionario"""
        self.controlador = controlador
        self.callback_actualizar = callback_actualizar
        
        # Crear ventana
        self.ventana = tk.Toplevel(parent)
        self.ventana.title("Crear Nuevo Diccionario")
        self.ventana.geometry("500x400")
        self.ventana.transient(parent)
        self.ventana.grab_set()
        
        self._crear_interfaz()
    
    def _crear_interfaz(self):
        """Crea la interfaz de la ventana"""
        main_frame = ttk.Frame(self.ventana, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Campos de entrada
        ttk.Label(main_frame, text="Nombre del diccionario:").pack(anchor=tk.W)
        self.nombre_entry = ttk.Entry(main_frame, width=50)
        self.nombre_entry.pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Categoría:").pack(anchor=tk.W)
        self.categoria_combo = ttk.Combobox(main_frame, 
                                          values=["passwords", "usuarios", "directorios", 
                                                "subdominios", "api", "personalizado"],
                                          state="readonly")
        self.categoria_combo.pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Descripción:").pack(anchor=tk.W)
        self.descripcion_text = tk.Text(main_frame, height=4)
        self.descripcion_text.pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Contenido inicial:").pack(anchor=tk.W)
        self.contenido_text = tk.Text(main_frame, height=10)
        self.contenido_text.pack(pady=(0, 10), fill=tk.BOTH, expand=True)
        
        # Botones
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(10, 0))
        
        ttk.Button(button_frame, text="Crear", command=self._crear).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancelar", command=self.ventana.destroy).pack(side=tk.LEFT)
    
    def _crear(self):
        """Crea el diccionario"""
        try:
            nombre = self.nombre_entry.get().strip()
            categoria = self.categoria_combo.get()
            descripcion = self.descripcion_text.get(1.0, tk.END).strip()
            contenido = self.contenido_text.get(1.0, tk.END).strip()
            
            if not nombre:
                messagebox.showerror("Error", "El nombre es obligatorio")
                return
            
            if not categoria:
                messagebox.showerror("Error", "La categoría es obligatoria")
                return
            
            self.controlador.crear_diccionario(nombre, categoria, descripcion, contenido)
            messagebox.showinfo("Éxito", "Diccionario creado correctamente")
            self.callback_actualizar()
            self.ventana.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al crear diccionario: {str(e)}")


class VentanaImportarDiccionario:
    def __init__(self, parent, controlador, callback_actualizar, archivo):
        """Ventana para importar diccionario"""
        self.controlador = controlador
        self.callback_actualizar = callback_actualizar
        self.archivo = archivo
        
        # Crear ventana
        self.ventana = tk.Toplevel(parent)
        self.ventana.title("Importar Diccionario")
        self.ventana.geometry("400x300")
        self.ventana.transient(parent)
        self.ventana.grab_set()
        
        self._crear_interfaz()
    
    def _crear_interfaz(self):
        """Crea la interfaz de la ventana"""
        main_frame = ttk.Frame(self.ventana, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text=f"Archivo: {self.archivo}").pack(anchor=tk.W, pady=(0, 20))
        
        # Campos de configuración
        ttk.Label(main_frame, text="Nombre del diccionario:").pack(anchor=tk.W)
        self.nombre_entry = ttk.Entry(main_frame, width=40)
        self.nombre_entry.pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Categoría:").pack(anchor=tk.W)
        self.categoria_combo = ttk.Combobox(main_frame,
                                          values=["passwords", "usuarios", "directorios",
                                                "subdominios", "api", "personalizado"],
                                          state="readonly")
        self.categoria_combo.pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Descripción:").pack(anchor=tk.W)
        self.descripcion_text = tk.Text(main_frame, height=4)
        self.descripcion_text.pack(pady=(0, 20), fill=tk.X)
        
        # Botones
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        ttk.Button(button_frame, text="Importar", command=self._importar).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancelar", command=self.ventana.destroy).pack(side=tk.LEFT)
    
    def _importar(self):
        """Importa el diccionario"""
        try:
            nombre = self.nombre_entry.get().strip()
            categoria = self.categoria_combo.get()
            descripcion = self.descripcion_text.get(1.0, tk.END).strip()
            
            if not nombre:
                messagebox.showerror("Error", "El nombre es obligatorio")
                return
            
            if not categoria:
                messagebox.showerror("Error", "La categoría es obligatoria")
                return
            
            self.controlador.importar_diccionario(self.archivo, nombre, categoria, descripcion)
            messagebox.showinfo("Éxito", "Diccionario importado correctamente")
            self.callback_actualizar()
            self.ventana.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al importar: {str(e)}")


class VentanaEditarDiccionario:
    def __init__(self, parent, controlador, callback_actualizar, nombre_diccionario):
        """Ventana para editar diccionario"""
        self.controlador = controlador
        self.callback_actualizar = callback_actualizar
        self.nombre_diccionario = nombre_diccionario
        
        # Crear ventana
        self.ventana = tk.Toplevel(parent)
        self.ventana.title(f"Editar Diccionario: {nombre_diccionario}")
        self.ventana.geometry("600x500")
        self.ventana.transient(parent)
        self.ventana.grab_set()
        
        self._crear_interfaz()
        self._cargar_datos()
    
    def _crear_interfaz(self):
        """Crea la interfaz de la ventana"""
        main_frame = ttk.Frame(self.ventana, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Información básica
        info_frame = ttk.LabelFrame(main_frame, text="Información", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text="Categoría:").pack(anchor=tk.W)
        self.categoria_combo = ttk.Combobox(info_frame,
                                          values=["passwords", "usuarios", "directorios",
                                                "subdominios", "api", "personalizado"],
                                          state="readonly")
        self.categoria_combo.pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(info_frame, text="Descripción:").pack(anchor=tk.W)
        self.descripcion_text = tk.Text(info_frame, height=3)
        self.descripcion_text.pack(fill=tk.X)
        
        # Contenido
        content_frame = ttk.LabelFrame(main_frame, text="Contenido", padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.contenido_text = tk.Text(content_frame)
        content_scrollbar = ttk.Scrollbar(content_frame, orient=tk.VERTICAL,
                                        command=self.contenido_text.yview)
        self.contenido_text.configure(yscrollcommand=content_scrollbar.set)
        
        self.contenido_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        content_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botones
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        ttk.Button(button_frame, text="Guardar", command=self._guardar).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancelar", command=self.ventana.destroy).pack(side=tk.LEFT)
    
    def _cargar_datos(self):
        """Carga los datos del diccionario"""
        try:
            info = self.controlador.obtener_info_diccionario(self.nombre_diccionario)
            contenido = self.controlador.obtener_contenido_diccionario(self.nombre_diccionario)
            
            self.categoria_combo.set(info['categoria'])
            self.descripcion_text.insert(1.0, info.get('descripcion', ''))
            self.contenido_text.insert(1.0, '\n'.join(contenido))
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar datos: {str(e)}")
    
    def _guardar(self):
        """Guarda los cambios"""
        try:
            categoria = self.categoria_combo.get()
            descripcion = self.descripcion_text.get(1.0, tk.END).strip()
            contenido = self.contenido_text.get(1.0, tk.END).strip()
            
            self.controlador.actualizar_diccionario(self.nombre_diccionario, 
                                                   categoria, descripcion, contenido)
            messagebox.showinfo("Éxito", "Diccionario actualizado correctamente")
            self.callback_actualizar()
            self.ventana.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")
