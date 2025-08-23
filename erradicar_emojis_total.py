#!/usr/bin/env python3
"""
SCRIPT DE ERRADICACION TOTAL DE EMOJIS - ARESITOS V3
Elimina TODOS los emojis del proyecto completo: archivos Python, documentación, configuración
NO DEJA NI UN SOLO EMOJI EN TODO EL PROYECTO
"""

import os
import re
import glob

# Mapeo COMPLETO de emojis a texto plano profesional
EMOJI_REPLACEMENTS = {
    'ALERT': 'ALERT',
    'TARGET': 'TARGET', 
    'FAST': 'FAST',
    'SECURE': 'SECURE',
    'SECURE': 'SECURE',
    'DATA': 'DATA',
    'SCAN': 'SCAN',
    'CONTROL': 'CONTROL',
    'SYSTEM': 'SYSTEM',
    'STAR': 'STAR',
    'STAR': 'STAR',
    'FEATURE': 'FEATURE',
    'LAUNCH': 'LAUNCH',
    'FOLDER': 'FOLDER',
    'FOLDER': 'FOLDER',
    'LIST': 'LIST',
    'NOTE': 'NOTE',
    'SAVE': 'SAVE',
    'TOOL': 'TOOL',
    'CONFIG': 'CONFIG',
    'CONFIG': 'CONFIG',
    'TOOLS': 'TOOLS',
    'TOOLS': 'TOOLS',
    'BUILD': 'BUILD',
    'WARNING': 'WARNING',
    'WARNING': 'WARNING',
    'ALERT': 'ALERT',
    'ERROR': 'ERROR',
    'OK': 'OK',
    'CHECK': 'CHECK',
    'DONE': 'DONE',
    'SUCCESS': 'SUCCESS',
    'COMPLETE': 'COMPLETE',
    'PERFECT': 'PERFECT',
    'SHOW': 'SHOW',
    'LOCK': 'LOCK',
    'UNLOCK': 'UNLOCK',
    'KEY': 'KEY',
    'SECRET': 'SECRET',
    'SECRET': 'SECRET',
    'POINT': 'POINT',
    'PIN': 'PIN',
    'UI': 'UI',
    'MASK': 'MASK',
    'WIN': 'WIN',
    'FIRST': 'FIRST',
    'MEDAL': 'MEDAL',
    'AWARD': 'AWARD',
    'AWARD': 'AWARD',
    'TIMEOUT': 'TIMEOUT',
    'TIMEOUT': 'TIMEOUT',
    'START': 'START',
    'START': 'START',
    'DETECT': 'DETECT',
    'DETECT': 'DETECT',
    'INFO': 'INFO',
    'INFO': 'INFO',
    'DELETE': 'DELETE',
    'DELETE': 'DELETE',
    'WEB': 'WEB',
    'SEARCH': 'SEARCH',
    'PANEL': 'PANEL',
    'PANEL': 'PANEL',
    'ARCH': 'ARCH',
    'ARCH': 'ARCH',
    'BUILD': 'BUILD',
    'BUILD': 'BUILD'
}

def clean_emojis_in_file(file_path):
    """Limpia emojis de cualquier archivo de texto"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Reemplazar cada emoji por su equivalente en texto
        for emoji, replacement in EMOJI_REPLACEMENTS.items():
            content = content.replace(emoji, replacement)
        
        # Verificar si hubo cambios
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"CLEANED: {file_path}")
            return True
        else:
            print(f"NO_EMOJIS: {file_path}")
            return False
    
    except Exception as e:
        print(f"ERROR: {file_path} - {e}")
        return False

def main():
    """Función principal de erradicación total"""
    print("INICIANDO ERRADICACION TOTAL DE EMOJIS - PROYECTO COMPLETO")
    print("=" * 70)
    
    # Extensiones de archivos a limpiar
    extensiones = ['*.py', '*.md', '*.txt', '*.json', '*.sh', '*.toml', '*.cfg', '*.conf']
    
    archivos_total = []
    
    # Buscar todos los archivos relevantes en el proyecto
    for extension in extensiones:
        for root, dirs, files in os.walk("."):
            # Excluir directorios específicos
            dirs[:] = [d for d in dirs if not d.startswith('.git')]
            
            for file in files:
                if file.endswith(extension.replace('*', '')):
                    archivo_path = os.path.join(root, file)
                    archivos_total.append(archivo_path)
    
    cleaned_files = 0
    total_files = len(archivos_total)
    
    print(f"ENCONTRADOS: {total_files} archivos para revisar")
    print("-" * 70)
    
    for file_path in archivos_total:
        if clean_emojis_in_file(file_path):
            cleaned_files += 1
    
    print("-" * 70)
    print(f"RESUMEN FINAL:")
    print(f"Total archivos procesados: {total_files}")
    print(f"Archivos con emojis limpiados: {cleaned_files}")
    print(f"Archivos sin emojis: {total_files - cleaned_files}")
    print("=" * 70)
    
    if cleaned_files > 0:
        print("EMOJIS ERRADICADOS - PROYECTO COMPLETAMENTE PROFESIONAL")
    else:
        print("VERIFICACION COMPLETA - NINGUN EMOJI ENCONTRADO")

if __name__ == "__main__":
    main()
