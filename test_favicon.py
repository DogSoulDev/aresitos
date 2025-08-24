#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS - Test de Favicon
==========================

Script de prueba para verificar el funcionamiento del favicon
en diferentes configuraciones de sistema.

Autor: DogSoulDev
Fecha: 25 de Agosto de 2025
"""

import os
import sys
import tkinter as tk
from pathlib import Path

# Agregar ruta del proyecto
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_favicon():
    """Test completo del sistema de favicon"""
    print("ARESITOS - Test de Favicon v3.0")
    print("=" * 50)
    
    try:
        # Importar el gestor de favicon
        from aresitos.utils.favicon_manager import favicon_manager, aplicar_favicon_aresitos, get_favicon_info
        
        # Mostrar información del sistema
        info = get_favicon_info()
        print(f"Sistema operativo: {'Linux' if info['is_linux'] else 'Windows'}")
        print(f"Kali Linux detectado: {info['is_kali']}")
        print(f"Favicon cargado: {info['loaded']}")
        print(f"Ruta del favicon: {info['path']}")
        print(f"Directorio base: {info['base_path']}")
        print("-" * 50)
        
        if not info['loaded']:
            print("❌ ERROR: No se pudo cargar el favicon")
            print("Verificar que existe el archivo en:")
            print("  - aresitos/recursos/aresitos.png")
            print("  - aresitos/recursos/Aresitos.ico")
            return False
        
        # Crear ventana de prueba
        print("🪟 Creando ventana de prueba...")
        root = tk.Tk()
        root.title("ARESITOS - Test de Favicon")
        root.geometry("400x300")
        root.configure(bg='#2b2b2b')
        
        # Aplicar favicon
        print("🎨 Aplicando favicon...")
        if aplicar_favicon_aresitos(root):
            print("✅ Favicon aplicado exitosamente")
            
            # Crear contenido de prueba
            frame = tk.Frame(root, bg='#2b2b2b')
            frame.pack(expand=True, fill='both', padx=20, pady=20)
            
            # Título
            titulo = tk.Label(
                frame,
                text="ARESITOS v3.0",
                font=("Arial", 16, "bold"),
                fg='#ff6633',
                bg='#2b2b2b'
            )
            titulo.pack(pady=10)
            
            # Información
            info_text = f"""Test de Favicon Completado
            
Sistema: {'Linux (Kali)' if info['is_kali'] else 'Linux' if info['is_linux'] else 'Windows'}
Favicon: {Path(info['path']).name if info['path'] else 'No disponible'}
Estado: ✅ Funcionando correctamente

Verifica que aparece el icono de ARESITOS
en la esquina superior izquierda de esta ventana.
            """
            
            label_info = tk.Label(
                frame,
                text=info_text,
                font=("Arial", 10),
                fg='#ffffff',
                bg='#2b2b2b',
                justify='left'
            )
            label_info.pack(pady=10)
            
            # Botón de cierre
            btn_cerrar = tk.Button(
                frame,
                text="Cerrar Test",
                command=root.destroy,
                font=("Arial", 10, "bold"),
                fg='#ffffff',
                bg='#ff6633',
                relief='flat',
                padx=20,
                pady=5
            )
            btn_cerrar.pack(pady=20)
            
            # Centrar ventana
            root.update_idletasks()
            x = (root.winfo_screenwidth() // 2) - (400 // 2)
            y = (root.winfo_screenheight() // 2) - (300 // 2)
            root.geometry(f"400x300+{x}+{y}")
            
            print("🚀 Ventana de prueba lista")
            print("   Verifica que aparece el icono en la barra de título")
            print("   Presiona Ctrl+C o cierra la ventana para terminar")
            
            # Ejecutar interfaz
            root.mainloop()
            
            print("✅ Test completado exitosamente")
            return True
            
        else:
            print("❌ ERROR: No se pudo aplicar el favicon")
            root.destroy()
            return False
            
    except ImportError as e:
        print(f"❌ ERROR de importación: {e}")
        print("Verificar que el módulo favicon_manager está disponible")
        return False
    except Exception as e:
        print(f"❌ ERROR inesperado: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_recursos():
    """Verificar que los recursos están disponibles"""
    print("\n🔍 Verificando recursos...")
    
    recursos_dir = project_root / "aresitos" / "recursos"
    archivos_esperados = ["aresitos.png", "Aresitos.ico"]
    
    for archivo in archivos_esperados:
        ruta = recursos_dir / archivo
        if ruta.exists():
            tamaño = ruta.stat().st_size
            print(f"✅ {archivo}: {tamaño} bytes")
        else:
            print(f"❌ {archivo}: No encontrado")
    
    return True

if __name__ == "__main__":
    print("\nIniciando test de favicon...")
    
    # Verificar recursos primero
    test_recursos()
    
    # Ejecutar test principal
    try:
        success = test_favicon()
        if success:
            print("\n🎉 Test de favicon completado exitosamente")
            print("   El favicon de ARESITOS está funcionando correctamente")
        else:
            print("\n💥 Test de favicon falló")
            print("   Revisar la configuración del sistema")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹️  Test interrumpido por el usuario")
    except Exception as e:
        print(f"\n💥 Error en test: {e}")
        sys.exit(1)
