# -*- coding: utf-8 -*-
"""
Aresitos - Punto de Entrada Principal
=====================================

Punto de entrada principal para Aresitos que redirige al sistema
de login GUI para una mejor experiencia de usuario.

Exclusivamente para Kali Linux.

Autor: DogSoulDev
Fecha: 16 de Agosto de 2025
"""

import os
import sys
import platform
from pathlib import Path

def verificar_kali_linux():
    """Verificación básica de Kali Linux"""
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'kali' in content
        return False
    except:
        return False

def main():
    """Función principal que redirige al login GUI"""
    print("ARESITOS - Sistema de Seguridad Cibernetica")
    print("=" * 50)
    
    # Verificar Kali Linux antes de continuar
    if not verificar_kali_linux():
        print("ERROR: ARESITOS requiere Kali Linux")
        print("Sistema operativo no compatible detectado")
        sys.exit(1)
    
    # Verificar si existe vista login
    directorio_actual = Path(__file__).parent
    vista_login_path = directorio_actual / 'aresitos' / 'vista' / 'vista_login.py'
    
    if vista_login_path.exists():
        print("Iniciando con interfaz de login...")
        try:
            # Importar y ejecutar vista login directamente
            sys.path.insert(0, str(directorio_actual))
            from aresitos.vista import vista_login
            
            # NO crear tk.Tk() aquí para evitar ventana en blanco
            vista_login.main()
            return
        except ImportError as e:
            print(f"Error importando vista login: {e}")
        except Exception as e:
            print(f"Error ejecutando vista login: {e}")
    
    # Fallback al método original solo si falla el login
    print("Usando metodo de inicio clasico...")
    iniciar_aplicacion_clasica()

def iniciar_aplicacion_clasica():
    """Metodo de inicio clasico sin login GUI"""
    try:
        import tkinter as tk
        
        # Cambiar a las rutas correctas de aresitos
        from aresitos.vista.vista_principal import VistaPrincipal
        from aresitos.controlador.controlador_principal import ControladorPrincipal  
        from aresitos.modelo.modelo_principal import ModeloPrincipal
        
        print("Modulos principales cargados")
        
        # Crear aplicacion principal
        root = tk.Tk()
        root.title("ARESITOS - Sistema de Seguridad")
        root.geometry("1200x800")
        
        # Inicializar MVC
        modelo = ModeloPrincipal()
        vista = VistaPrincipal(root)
        controlador = ControladorPrincipal(modelo, vista)
        
        vista.controlador = controlador
        
        # Centrar ventana
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (1200 // 2)
        y = (root.winfo_screenheight() // 2) - (800 // 2)
        root.geometry(f"1200x800+{x}+{y}")
        
        print("Aplicacion iniciada")
        root.mainloop()
        
    except ImportError as e:
        print(f"Error importando modulos: {e}")
        print("Verifique la instalacion de ARESITOS")
        print("Ejecute: python configurar.py")
    except Exception as e:
        print(f"Error iniciando aplicacion: {e}")

def verificar_permisos_inicio():
    """Verificar permisos al inicio y mostrar recomendaciones."""
    if platform.system() == "Linux":
        try:
            import subprocess
            # Verificar si tenemos capacidades para herramientas de red
            result = subprocess.run(["getcap", "/usr/bin/nmap"], 
                                  capture_output=True, text=True, timeout=5)
            
            if "cap_net_raw" not in result.stdout:
                print("AVISO: nmap podria no tener permisos para SYN scan")
                print("Para funcionalidad completa: sudo python configurar.py")
            
            # Verificar sudo sin contraseña
            result_sudo = subprocess.run(["sudo", "-n", "true"], 
                                       capture_output=True, timeout=5)
            if result_sudo.returncode != 0:
                print("sudo requiere contraseña - use el login GUI")
                print("Ejecute: python -m aresitos.vista.vista_login")
                
        except Exception:
            pass  # No mostrar errores si no se puede verificar

if __name__ == "__main__":
    main()
