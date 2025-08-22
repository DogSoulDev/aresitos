#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS - Verificador de Recursos
==================================

Script para verificar y reparar problemas con archivos de recursos,
especialmente iconos que pueden estar corruptos.

Autor: DogSoulDev
Fecha: 23 de Agosto de 2025
"""

import os
import sys
import tkinter as tk
from pathlib import Path

def verificar_imagen(ruta_imagen):
    """
    Verificar si un archivo de imagen es válido
    
    Returns:
        bool: True si la imagen es válida
    """
    try:
        if not os.path.exists(ruta_imagen):
            return False, "Archivo no existe"
        
        # Verificar tamaño del archivo
        tamano = os.path.getsize(ruta_imagen)
        if tamano == 0:
            return False, "Archivo vacío"
        
        # Verificar formato PNG
        if ruta_imagen.endswith('.png'):
            with open(ruta_imagen, 'rb') as f:
                header = f.read(8)
                if header != b'\x89PNG\r\n\x1a\n':
                    return False, "Header PNG inválido"
        
        # Verificar formato ICO
        elif ruta_imagen.endswith('.ico'):
            with open(ruta_imagen, 'rb') as f:
                header = f.read(4)
                if header[:2] != b'\x00\x00':
                    return False, "Header ICO inválido"
        
        # Intentar cargar con tkinter
        try:
            test_root = tk.Tk()
            test_root.withdraw()
            
            if ruta_imagen.endswith('.png'):
                test_img = tk.PhotoImage(file=ruta_imagen)
            else:
                # Para ICO, usar iconbitmap
                test_root.iconbitmap(ruta_imagen)
                test_root.destroy()
                return True, "ICO válido"
            
            test_root.destroy()
            return True, "Imagen válida"
            
        except tk.TclError as e:
            return False, f"Error Tkinter: {str(e)}"
        
    except Exception as e:
        return False, f"Error verificando: {str(e)}"

def verificar_recursos():
    """Verificar todos los recursos de ARESITOS"""
    print("VERIFICADOR DE RECURSOS ARESITOS")
    print("=" * 40)
    
    # Detectar directorio de recursos
    script_dir = Path(__file__).parent
    recursos_dir = script_dir / "Aresitos" / "recursos"
    
    if not recursos_dir.exists():
        print(f"ERROR: Directorio de recursos no encontrado: {recursos_dir}")
        return False
    
    print(f"Directorio de recursos: {recursos_dir}")
    print()
    
    # Lista de archivos esperados
    archivos_esperados = [
        "Aresitos.ico",
        "Aresitos.png", 
        "vista_aresitos.png",
        "vista_herramientas.png",
        "vista_login.png"
    ]
    
    problemas = []
    
    for archivo in archivos_esperados:
        ruta_archivo = recursos_dir / archivo
        print(f"Verificando {archivo}...")
        
        if not ruta_archivo.exists():
            print(f"  ERROR: Archivo no encontrado")
            problemas.append(f"{archivo}: No encontrado")
            continue
        
        # Verificar tamaño
        tamano = ruta_archivo.stat().st_size
        print(f"  Tamaño: {tamano:,} bytes")
        
        if tamano == 0:
            print(f"  ERROR: Archivo vacío")
            problemas.append(f"{archivo}: Archivo vacío")
            continue
        
        # Verificar integridad
        valido, mensaje = verificar_imagen(str(ruta_archivo))
        
        if valido:
            print(f"  OK: {mensaje}")
        else:
            print(f"  ERROR: {mensaje}")
            problemas.append(f"{archivo}: {mensaje}")
    
    print()
    print("RESUMEN DE VERIFICACIÓN")
    print("=" * 40)
    
    if not problemas:
        print("✓ Todos los archivos de recursos están correctos")
        return True
    else:
        print(f"✗ Se encontraron {len(problemas)} problemas:")
        for problema in problemas:
            print(f"  - {problema}")
        
        print()
        print("SOLUCIONES RECOMENDADAS:")
        print("1. Re-clonar el repositorio desde GitHub")
        print("2. Verificar que los archivos no estén corruptos")
        print("3. Ejecutar: git pull origin master")
        
        return False

def crear_icono_fallback():
    """Crear un icono fallback simple en caso de corrupción"""
    try:
        script_dir = Path(__file__).parent
        recursos_dir = script_dir / "Aresitos" / "recursos"
        
        # Crear PNG simple con tkinter si no existe uno válido
        root = tk.Tk()
        root.withdraw()
        
        # Crear imagen simple de 32x32
        canvas = tk.Canvas(root, width=32, height=32, bg='#ff6633')
        canvas.create_text(16, 16, text="A", fill="white", font=("Arial", 16, "bold"))
        
        # Intentar guardar como PostScript y convertir
        fallback_path = recursos_dir / "aresitos_fallback.ps"
        canvas.postscript(file=str(fallback_path))
        
        root.destroy()
        
        print(f"Icono fallback creado: {fallback_path}")
        return True
        
    except Exception as e:
        print(f"Error creando icono fallback: {e}")
        return False

def main():
    """Función principal"""
    if len(sys.argv) > 1 and sys.argv[1] == '--fix':
        print("Modo reparación activado")
        crear_icono_fallback()
    
    verificado = verificar_recursos()
    
    if not verificado:
        print()
        print("Para intentar reparación: python verificar_recursos.py --fix")
    
    return 0 if verificado else 1

if __name__ == "__main__":
    sys.exit(main())
