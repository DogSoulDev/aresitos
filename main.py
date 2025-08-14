# -*- coding: utf-8 -*-

import tkinter as tk
import os
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
        
        # Configurar icono de la aplicación
        self.configurar_icono()
        
        # Centrar la ventana en la pantalla
        self.center_window()

        # Crear componentes MVC
        modelo = ModeloPrincipal()
        vista = VistaPrincipal(self)
        controlador = ControladorPrincipal(modelo, vista)

        # Asignar controlador a la vista
        vista.set_controlador(controlador)

        vista.pack(side="top", fill="both", expand=True)
    
    def configurar_icono(self):
        """Configura el icono de la aplicación."""
        try:
            # Ruta al icono
            ruta_script = os.path.dirname(os.path.abspath(__file__))
            ruta_icono = os.path.join(ruta_script, "ares_aegis", "recursos", "Aresitos.ico")
            
            if os.path.exists(ruta_icono):
                self.iconbitmap(ruta_icono)
            else:
                print(f"Advertencia: No se encontró el icono en {ruta_icono}")
        except Exception as e:
            print(f"Error configurando icono: {e}")
    
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
