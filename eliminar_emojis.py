#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para eliminar todos los emojis de los archivos del proyecto Aresitos.
Creado por: DogSoulDev y GitHub Copilot
"""

import os
import re
import glob

def detectar_emojis(texto):
    """Detecta si hay emojis en el texto"""
    patron_emoji = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # simbolos y pictogramas
        "\U0001F680-\U0001F6FF"  # transporte y mapas
        "\U0001F1E0-\U0001F1FF"  # banderas
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "\U0001F900-\U0001F9FF"  # simbolos suplementarios
        "\U00002600-\U000026FF"  # simbolos miscelaneos
        "\U00002700-\U000027BF"  # dingbats
        "]+", flags=re.UNICODE
    )
    return patron_emoji.search(texto) is not None

def limpiar_emojis(texto):
    """Elimina todos los emojis del texto"""
    patron_emoji = re.compile(
        "["
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF"
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "\U0001F900-\U0001F9FF"
        "\U00002600-\U000026FF"
        "\U00002700-\U000027BF"
        "]+", flags=re.UNICODE
    )
    return patron_emoji.sub('', texto)

def procesar_archivo(ruta_archivo):
    """Procesa un archivo individual para eliminar emojis"""
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            contenido_original = f.read()
        
        if not detectar_emojis(contenido_original):
            return False, "Sin emojis"
        
        contenido_limpio = limpiar_emojis(contenido_original)
        
        if contenido_limpio != contenido_original:
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                f.write(contenido_limpio)
            return True, "Emojis eliminados"
        
        return False, "Sin cambios"
        
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    """Función principal"""
    print("ELIMINADOR DE EMOJIS - PROYECTO ARESITOS")
    print("=" * 50)
    
    extensiones = ['*.py', '*.md', '*.txt', '*.json', '*.yml', '*.yaml']
    archivos_excluir = ['eliminar_emojis.py', 'Aresitos.ico', '.git']
    
    archivos_procesados = 0
    archivos_modificados = 0
    
    directorio_base = os.path.dirname(os.path.abspath(__file__))
    print(f"Escaneando directorio: {directorio_base}")
    print()
    
    for extension in extensiones:
        patron = os.path.join(directorio_base, '**', extension)
        archivos = glob.glob(patron, recursive=True)
        
        for archivo in archivos:
            ruta_relativa = os.path.relpath(archivo, directorio_base)
            
            if any(excluir in ruta_relativa for excluir in archivos_excluir):
                continue
            
            modificado, resultado = procesar_archivo(archivo)
            archivos_procesados += 1
            
            if modificado:
                archivos_modificados += 1
                print(f"MODIFICADO: {ruta_relativa}")
            elif "Error" in resultado:
                print(f"ERROR: {ruta_relativa} - {resultado}")
    
    print()
    print("=" * 50)
    print(f"Archivos procesados: {archivos_procesados}")
    print(f"Archivos modificados: {archivos_modificados}")
    print("Limpieza de emojis completada.")

if __name__ == "__main__":
    main()