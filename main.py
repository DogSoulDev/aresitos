# -*- coding: utf-8 -*-

import tkinter as tk
from ares_aegis.vista.vista_principal import VistaPrincipal
from ares_aegis.controlador.controlador_principal import ControladorPrincipal
from ares_aegis.modelo.modelo_principal import ModeloPrincipal

class Aplicacion(tk.Tk):
    """Clase principal de la aplicación."""
    def __init__(self):
        super().__init__()
        self.title("Aresitos - Herramienta de Ciberseguridad")
        self.geometry("1400x900")
        self.minsize(1200, 800)  # Tamaño mínimo para mantener usabilidad
        
        # Centrar la ventana en la pantalla
        self.center_window()
        
        # Opcional: Maximizar automáticamente (comentado por defecto)
        # self.state('zoomed')  # Windows
        # self.attributes('-zoomed', True)  # Linux

        # Crear componentes MVC
        modelo = ModeloPrincipal()
        vista = VistaPrincipal(self)
        controlador = ControladorPrincipal(modelo, vista)

        # Asignar controlador a la vista
        vista.set_controlador(controlador)

        vista.pack(side="top", fill="both", expand=True)
    
    def center_window(self):
        """Centra la ventana en la pantalla."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

if __name__ == "__main__":
    app = Aplicacion()
    app.mainloop()

# RESUMEN: Punto de entrada de Aresitos. Inicializa la aplicación con arquitectura MVC,
# crea la ventana principal (800x600) y arranca el loop de la interfaz gráfica.
