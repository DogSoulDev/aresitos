# =============================================================
# VISTA NOTICIAS - ARESITOS
# =============================================================
# Panel visual para mostrar noticias de ciberseguridad oficiales.
# Sin emojis, tokens ni dependencias externas. Todo en castellano.

import tkinter as tk
from tkinter import ttk
import webbrowser
from aresitos.controlador.controlador_noticias import ControladorNoticias

class VistaNoticias(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        try:
            from aresitos.vista.burp_theme import burp_theme
            self.theme = burp_theme if burp_theme else None
        except ImportError:
            self.theme = None
        self.controlador = ControladorNoticias()
        self.noticias = []
        self._setup_styles()
        self._crear_interfaz_moderno()
        self.actualizar_panel()

    def _setup_styles(self):
        style = ttk.Style()
        if self.theme:
            self.theme.configure_ttk_style(style)
        else:
            style.theme_use('clam')
            style.configure('Topbar.TFrame', background='#222831')
            style.configure('Topbar.TLabel', background='#222831', foreground='#ff6633', font=('Segoe UI', 18, 'bold'))
            style.configure('Search.TEntry', font=('Segoe UI', 11), padding=6)
            style.configure('Card.TFrame', background='#f7f7f7', relief='raised', borderwidth=2)
            style.configure('CardTitle.TLabel', font=('Segoe UI', 14, 'bold'), background='#f7f7f7', foreground='#232629')
            style.configure('CardMeta.TLabel', font=('Segoe UI', 9), background='#f7f7f7', foreground='#ff6633')
            style.configure('Card.TButton', font=('Segoe UI', 10, 'bold'), background='#ff6633', foreground='#fff')
            style.map('Card.TButton', background=[('active', '#ff884d')])
            style.configure('FAB.TButton', font=('Segoe UI', 12, 'bold'), background='#ff6633', foreground='#fff', padding=10)
            style.map('FAB.TButton', background=[('active', '#ff884d')])

    def _crear_interfaz_moderno(self):
        bg = self.theme.get_color('bg_primary') if self.theme else '#e3e6ea'
        self.configure(bg=bg)
        # Topbar con título y búsqueda
        topbar = ttk.Frame(self, style='Topbar.TFrame' if not self.theme else 'Burp.TFrame')
        topbar.pack(fill=tk.X, padx=0, pady=0)
        titulo = ttk.Label(topbar, text="Noticias de Ciberseguridad", style='Topbar.TLabel' if not self.theme else 'BurpTitle.TLabel')
        titulo.pack(side=tk.LEFT, padx=8, pady=8)
        self.busqueda_var = tk.StringVar()
        self.busqueda_entry = ttk.Entry(topbar, textvariable=self.busqueda_var, width=32, style='Search.TEntry' if not self.theme else 'Burp.TEntry')
        self.busqueda_entry.pack(side=tk.RIGHT, padx=16, pady=8)
        self.busqueda_entry.bind('<Return>', lambda e: self.filtrar_noticias())
        self.boton_actualizar = ttk.Button(topbar, text="Actualizar", command=self.actualizar_panel, style='Card.TButton' if not self.theme else 'Burp.TButton')
        self.boton_actualizar.pack(side=tk.RIGHT, padx=8, pady=8)

        # Panel de noticias con scroll
        noticias_frame = ttk.Frame(self, style='Burp.TFrame' if self.theme else '')
        noticias_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0,24))
        self.noticias_canvas = tk.Canvas(noticias_frame, bg=bg, highlightthickness=0, bd=0)
        self.noticias_scrollbar = ttk.Scrollbar(noticias_frame, orient="vertical", command=self.noticias_canvas.yview)
        self.noticias_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.noticias_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.panel_noticias = ttk.Frame(self.noticias_canvas, style='Burp.TFrame' if self.theme else '')
        self.panel_noticias_id = self.noticias_canvas.create_window((0,0), window=self.panel_noticias, anchor="nw")
        self.noticias_canvas.configure(yscrollcommand=self.noticias_scrollbar.set)
        def _on_noticias_frame_configure(event):
            self.noticias_canvas.configure(scrollregion=self.noticias_canvas.bbox("all"))
            # Responsive: ajusta el ancho de los cards al tamaño del canvas
            canvas_width = self.noticias_canvas.winfo_width()
            self.noticias_canvas.itemconfig(self.panel_noticias_id, width=canvas_width)
        self.panel_noticias.bind("<Configure>", _on_noticias_frame_configure)
        def _on_noticias_mousewheel(event):
            self.noticias_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self.noticias_canvas.bind_all("<MouseWheel>", _on_noticias_mousewheel)
        # Responsive: ajusta el ancho al redimensionar la ventana
        def _on_resize(event):
            self.noticias_canvas.itemconfig(self.panel_noticias_id, width=event.width)
        self.noticias_canvas.bind('<Configure>', _on_resize)

        # Botón flotante para gestión de fuentes
        self.fab_btn = ttk.Button(self, text="+ Fuentes RSS", command=self.abrir_modal_fuentes, style='FAB.TButton' if not self.theme else 'Burp.TButton')
        self.fab_btn.place(relx=1.0, rely=1.0, x=-32, y=-32, anchor='se')

    def abrir_modal_fuentes(self):
        modal = tk.Toplevel(self)
        modal.title("Gestionar fuentes RSS")
        modal.geometry("440x480")
        modal.transient(self.winfo_toplevel())
        modal.grab_set()
        modal.configure(bg='#f7f7f7')
        label = ttk.Label(modal, text="Fuentes RSS", font=("Segoe UI", 15, "bold"), foreground='#ff6633', background='#f7f7f7')
        label.pack(pady=16)
        entry_var = tk.StringVar()
        entry = ttk.Entry(modal, textvariable=entry_var, width=38, font=('Segoe UI', 11))
        entry.pack(pady=4)
        error_label = ttk.Label(modal, text="", foreground="red", background='#f7f7f7', font=('Segoe UI', 10))
        error_label.pack(pady=2)
        def agregar():
            url = entry_var.get().strip()
            if not url:
                error_label.config(text="Introduce una URL.")
                return
            if not self.controlador.modelo.validar_url_feed(url):
                error_label.config(text="La URL debe terminar en rss.xml, .xml o /feed.")
                return
            if self.controlador.agregar_feed(url):
                error_label.config(text="Fuente agregada.")
                entry_var.set("")
                mostrar_fuentes()
                self.actualizar_panel()
            else:
                error_label.config(text="No se pudo agregar (ya existe o no válida).")
        ttk.Button(modal, text="Agregar fuente", command=agregar, style='Card.TButton').pack(pady=4)
        # Scroll para lista de fuentes
        canvas = tk.Canvas(modal, bg='#f7f7f7', highlightthickness=0, width=400, height=300)
        scrollbar = ttk.Scrollbar(modal, orient="vertical", command=canvas.yview)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        lista_frame = ttk.Frame(canvas)
        lista_frame_id = canvas.create_window((0,0), window=lista_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        def _on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        lista_frame.bind("<Configure>", _on_frame_configure)
        def mostrar_fuentes():
            for widget in lista_frame.winfo_children():
                widget.destroy()
            fuentes = self.controlador.obtener_feeds()
            for url in fuentes:
                fila = ttk.Frame(lista_frame)
                fila.pack(fill=tk.X, padx=2, pady=4)
                label = ttk.Label(fila, text=url, font=("Segoe UI", 10), foreground='#ff6633', background='#f7f7f7')
                label.pack(side=tk.LEFT, fill=tk.X, expand=True)
                btn = ttk.Button(fila, text="Eliminar", command=lambda u=url: eliminar(u), style='Card.TButton', width=8)
                btn.pack(side=tk.RIGHT, padx=2)
        def eliminar(url):
            if self.controlador.eliminar_feed(url):
                error_label.config(text="Fuente eliminada.")
                mostrar_fuentes()
                self.actualizar_panel()
            else:
                error_label.config(text="No se pudo eliminar.")
        mostrar_fuentes()

    # Métodos vacíos eliminados, toda la gestión de fuentes está en el modal

    def actualizar_panel(self):
        self.mostrar_cargando()
        import threading
        threading.Thread(target=self._cargar_noticias_en_hilo, daemon=True).start()

    def mostrar_cargando(self):
        for widget in self.panel_noticias.winfo_children():
            widget.destroy()
        fg_accent = self.theme.get_color('fg_accent') if self.theme else '#ff6633'
        bg_card = self.theme.get_color('bg_secondary') if self.theme else '#f7f7f7'
        cargando = ttk.Label(self.panel_noticias, text="Cargando noticias...", font=("Segoe UI", 12, "italic"), foreground=fg_accent, background=bg_card)
        cargando.pack(pady=32)

    def _cargar_noticias_en_hilo(self):
        noticias = self.controlador.actualizar_noticias()
        self.noticias = noticias
        self.after(0, lambda: self.mostrar_noticias(noticias))

    def filtrar_noticias(self):
        texto = self.busqueda_var.get()
        filtradas = self.controlador.filtrar_noticias(texto)
        self.mostrar_noticias(filtradas)

    def mostrar_noticias(self, noticias):
        for widget in self.panel_noticias.winfo_children():
            widget.destroy()
        fg_accent = self.theme.get_color('fg_accent') if self.theme else '#ff6633'
        fg_primary = self.theme.get_color('fg_primary') if self.theme else '#232629'
        bg_card = self.theme.get_color('bg_secondary') if self.theme else '#f7f7f7'
        card_style = 'Card.TFrame' if not self.theme else 'Burp.TFrame'
        title_style = 'CardTitle.TLabel' if not self.theme else 'BurpTitle.TLabel'
        meta_style = 'CardMeta.TLabel' if not self.theme else 'Burp.TLabel'
        btn_style = 'Card.TButton' if not self.theme else 'Burp.TButton'
        if not noticias:
            empty = ttk.Label(self.panel_noticias, text="No se encontraron noticias.", font=("Segoe UI", 13, "italic"), foreground=fg_primary, background=bg_card)
            empty.pack(pady=32)
            return
        for noticia in noticias:
            card = ttk.Frame(self.panel_noticias, style=card_style)
            card.pack(fill=tk.X, padx=12, pady=12, anchor='n')
            titulo = ttk.Label(card, text=noticia['titulo'], style=title_style)
            titulo.pack(anchor='w', padx=12, pady=(12,2))
            meta = ttk.Label(card, text=f"{noticia.get('fecha','')} | {noticia.get('fuente','')}", style=meta_style)
            meta.pack(anchor='w', padx=12, pady=(0,8))
            boton = ttk.Button(card, text="Abrir", command=lambda url=noticia['enlace']: webbrowser.open(url), style=btn_style, width=12)
            boton.pack(anchor='e', padx=12, pady=(0,12))
