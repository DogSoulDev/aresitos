#!/bin/bash
# Script de limpieza para mantener el proyecto limpio

echo "🧹 Limpiando archivos temporales y caché..."

# Eliminar archivos de caché de Python
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
find . -name "*.pyo" -delete 2>/dev/null
find . -name "*.pyd" -delete 2>/dev/null

# Eliminar archivos temporales
find . -name "*.tmp" -delete 2>/dev/null
find . -name "*.temp" -delete 2>/dev/null
find . -name "*.log" -delete 2>/dev/null
find . -name "*~" -delete 2>/dev/null
find . -name "*.bak" -delete 2>/dev/null
find . -name "*.backup" -delete 2>/dev/null

# Eliminar directorios de caché específicos
rm -rf .pytest_cache/ 2>/dev/null
rm -rf .coverage 2>/dev/null
rm -rf .mypy_cache/ 2>/dev/null
rm -rf build/ 2>/dev/null
rm -rf dist/ 2>/dev/null
rm -rf *.egg-info/ 2>/dev/null

echo "✅ Limpieza completada!"
