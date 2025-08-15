# -*- coding: utf-8 -*-

import tkinter as tk
import os
import platform
from ares_aegis.vista.vista_principal import VistaPrincipal
from ares_aegis.controlador.controlador_principal import ControladorPrincipal
from ares_aegis.modelo.modelo_principal import ModeloPrincipal

def verificar_permisos_inicio():
    """Verificar permisos al inicio y mostrar recomendaciones."""
    if platform.system() == "Linux":
        try:
            # Verificar si tenemos capacidades para herramientas de red
            import subprocess
            result = subprocess.run(["getcap", "/usr/bin/nmap"], 
                                  capture_output=True, text=True, timeout=5)
            
            if "cap_net_raw" not in result.stdout:
                print("⚠️  AVISO: nmap podría no tener permisos para SYN scan")
                print("💡 Para funcionalidad completa: sudo ./configurar_kali.sh")
            
            # Verificar sudo sin contraseña
            result_sudo = subprocess.run(["sudo", "-n", "true"], 
                                       capture_output=True, timeout=5)
            if result_sudo.returncode != 0:
                print("⚠️  sudo requiere contraseña - funcionalidad limitada")
                print("💡 Para configurar: sudo ./configurar_kali.sh")
                
        except Exception:
            pass  # No mostrar errores si no se puede verificar

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
            # Configurar icono según el sistema operativo
            ruta_script = os.path.dirname(os.path.abspath(__file__))
            ruta_icono = os.path.join(ruta_script, "ares_aegis", "recursos", "Aresitos.ico")
            
            if os.path.exists(ruta_icono):
                try:
                    # En Windows y algunos sistemas, usar iconbitmap directamente
                    self.iconbitmap(ruta_icono)
                    print("✅ Icono cargado exitosamente")
                except Exception:
                    # En Linux/Unix, intentar convertir a PhotoImage usando PIL
                    pil_cargado = False
                    try:
                        # Importación dinámica de PIL para evitar errores de lint
                        import importlib
                        pil_image = importlib.import_module("PIL.Image")
                        pil_imagetk = importlib.import_module("PIL.ImageTk")
                        
                        # Abrir y redimensionar imagen
                        img = pil_image.open(ruta_icono)
                        img = img.resize((32, 32), pil_image.Resampling.LANCZOS)
                        self.icon_photo = pil_imagetk.PhotoImage(img)
                        self.iconphoto(False, self.icon_photo)
                        print("✅ Icono cargado exitosamente con PIL")
                        pil_cargado = True
                    except ImportError:
                        # Si PIL no está disponible, usar icono por defecto
                        print("⚠️  PIL no disponible, usando icono por defecto")
                        print("💡 Para mostrar iconos personalizados en Linux: pip install Pillow")
                    except Exception as e:
                        print(f"⚠️  No se pudo cargar el icono con PIL: {e}")
                    
                    if not pil_cargado:
                        # Fallback: intentar usar el icono como PhotoImage básico
                        try:
                            # Buscar un PNG alternativo si existe
                            ruta_png = ruta_icono.replace('.ico', '.png')
                            if os.path.exists(ruta_png):
                                self.icon_photo = tk.PhotoImage(file=ruta_png)
                                self.iconphoto(False, self.icon_photo)
                                print("✅ Icono PNG cargado como alternativa")
                        except Exception:
                            print("⚠️  Usando icono por defecto del sistema")
            else:
                print(f"⚠️  No se encontró el icono en {ruta_icono}")
        except Exception as e:
            print(f"❌ Error configurando icono: {e}")
    
    def center_window(self):
        """Centra la ventana en la pantalla."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

if __name__ == "__main__":
    print("🔱 Iniciando Aresitos 7.0 Beta...")
    
    # Verificar permisos al inicio
    verificar_permisos_inicio()
    
    print("🚀 Cargando interfaz...")
    app = Aplicacion()
    app.mainloop()
