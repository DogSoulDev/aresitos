@echo off
REM Script de limpieza para Windows

echo 🧹 Limpiando archivos temporales y caché...

REM Eliminar archivos de caché de Python
for /d /r . %%d in (*__pycache__*) do @if exist "%%d" rd /s /q "%%d"
del /s /q *.pyc 2>nul
del /s /q *.pyo 2>nul
del /s /q *.pyd 2>nul

REM Eliminar archivos temporales
del /s /q *.tmp 2>nul
del /s /q *.temp 2>nul
del /s /q *.log 2>nul
del /s /q *~ 2>nul
del /s /q *.bak 2>nul
del /s /q *.backup 2>nul

REM Eliminar directorios de caché específicos
if exist .pytest_cache rd /s /q .pytest_cache 2>nul
if exist .coverage del /q .coverage 2>nul
if exist .mypy_cache rd /s /q .mypy_cache 2>nul
if exist build rd /s /q build 2>nul
if exist dist rd /s /q dist 2>nul

echo ✅ Limpieza completada!
