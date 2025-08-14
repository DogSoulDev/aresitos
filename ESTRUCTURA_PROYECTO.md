#  ESTRUCTURA DEL PROYECTO - MANTENER INTACTA

##  IMPORTANTE: NO CREAR ARCHIVOS ADICIONALES

Este proyecto tiene una estructura específica que **DEBE MANTENERSE EXACTAMENTE IGUAL**.

###  Estructura Actual (NO MODIFICAR):
```
Ares-Aegis/
 .git/                    # Control de versiones
 .gitignore              # Archivos ignorados
 .gitattributes          # Configuración de Git
 .vscode/                # Configuración específica de VS Code
    settings.json       # Configuraciones para evitar archivos automáticos
 ares_aegis/             # Código principal
 configuracion/          # Archivos de configuración
 data/                   # Datos del proyecto
 tests/                  # Pruebas unitarias
 main.py                 # Punto de entrada
 requirements.txt        # Dependencias Python
 pyproject.toml          # Configuración del proyecto
 clean.sh               # Script de limpieza Unix
 clean.bat              # Script de limpieza Windows
 README.md              # Documentación principal
```

###  ARCHIVOS PROHIBIDOS (Se eliminan automáticamente):
- `__pycache__/` - Caché de Python
- `*.pyc`, `*.pyo`, `*.pyd` - Bytecode compilado
- `.pytest_cache/` - Caché de pytest
- `.coverage` - Archivos de cobertura
- `.mypy_cache/` - Caché de MyPy
- `build/`, `dist/` - Directorios de distribución
- `*.egg-info/` - Información de paquetes
- `*.tmp`, `*.temp`, `*.log` - Archivos temporales
- `*.bak`, `*.backup`, `*~` - Archivos de respaldo

###  Configuraciones de Protección:

#### VS Code Settings (.vscode/settings.json):
-  AutoSave deshabilitado
-  Formateo automático deshabilitado
-  Creación automática de entornos deshabilitada
-  Telemetría deshabilitada
-  Actualizaciones automáticas deshabilitadas

#### Git Ignore (.gitignore):
- Ignora todos los archivos temporales
- Ignora cachés de Python
- Ignora archivos de IDE (excepto configuraciones específicas)

###  Limpieza Automática:
```bash
# Unix/Linux/Mac
./clean.sh

# Windows
clean.bat
```

###  Al cerrar y abrir VS Code:
1. **NO** se deben crear archivos nuevos
2. **NO** se deben generar cachés
3. **NO** se deben crear configuraciones adicionales
4. La estructura debe permanecer **IDÉNTICA**

###  Si aparecen archivos no deseados:
1. Ejecutar script de limpieza: `./clean.sh` o `clean.bat`
2. Verificar `.gitignore` 
3. Verificar `.vscode/settings.json`
4. **NO COMMITEAR** archivos temporales

---
** RECORDATORIO: La estructura actual es FINAL y FUNCIONAL**
