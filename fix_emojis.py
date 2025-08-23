#!/usr/bin/env python3
"""
Script para eliminar emojis y reemplazarlos con texto profesional en ARESITOS V3
"""

import os
import re
from pathlib import Path

# Mapeo de emojis a texto profesional
EMOJI_REPLACEMENTS = {
    '🔥': '[CRITICAL]',
    '🔵': '[INFO]',
    '🟢': '[SUCCESS]',
    '🟡': '[WARNING]',
    '🔴': '[ERROR]',
    '⚠️': '[WARNING]',
    '📊': '[STATS]',
    '💀': '[THREAT]',
    '🎯': '[TARGET]',
    '🚀': '[LAUNCH]',
    '✅': '[OK]',
    '❌': '[FAIL]',
    '⭐': '[IMPORTANT]',
    '🔍': '[SCAN]',
    '🛡️': '[SECURITY]',
    '📈': '[TREND-UP]',
    '📉': '[TREND-DOWN]',
    '💻': '[SYSTEM]',
    '🌐': '[NETWORK]',
    '⚡': '[FAST]',
    '🔧': '[TOOLS]'
}

def fix_emojis_in_file(file_path):
    """Reemplazar emojis en un archivo específico."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        changes_made = 0
        
        # Reemplazar cada emoji
        for emoji, replacement in EMOJI_REPLACEMENTS.items():
            if emoji in content:
                count = content.count(emoji)
                content = content.replace(emoji, replacement)
                changes_made += count
                print(f"  Reemplazado {count}x '{emoji}' -> '{replacement}'")
        
        # Solo escribir si hubo cambios
        if changes_made > 0:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return changes_made
        
        return 0
    
    except Exception as e:
        print(f"ERROR procesando {file_path}: {e}")
        return 0

def main():
    """Función principal."""
    print("=== ARESITOS V3: ELIMINANDO EMOJIS ===\n")
    
    # Directorio base
    aresitos_dir = Path("Aresitos")
    
    if not aresitos_dir.exists():
        print("ERROR: Directorio 'Aresitos' no encontrado")
        return
    
    total_files = 0
    total_changes = 0
    
    # Procesar todos los archivos .py
    for py_file in aresitos_dir.rglob("*.py"):
        print(f"Procesando: {py_file}")
        changes = fix_emojis_in_file(py_file)
        if changes > 0:
            total_files += 1
            total_changes += changes
            print(f"  -> {changes} cambios realizados")
        else:
            print(f"  -> Sin cambios")
        print()
    
    print("=" * 50)
    print(f"RESUMEN FINAL:")
    print(f"  Archivos modificados: {total_files}")
    print(f"  Total de emojis reemplazados: {total_changes}")
    print("=" * 50)

if __name__ == "__main__":
    main()
