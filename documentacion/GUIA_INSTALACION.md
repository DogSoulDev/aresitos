# ARESITOS v2.0 - Guía de Instalación

## Requisitos del Sistema

### Sistema Operativo Soportado
- **Kali Linux 2024.x o superior** (recomendado)
- **Parrot Security OS** (versiones recientes)
- **BlackArch Linux** (con adaptaciones menores)
- **Ubuntu/Debian** (modo desarrollo limitado)

### Requisitos Técnicos
- **Python**: 3.8 o superior (incluido en Kali Linux)
- **Espacio en disco**: 500MB mínimo para instalación completa
- **RAM**: 512MB mínimo (2GB recomendado para operaciones intensivas)
- **Permisos**: Acceso sudo para herramientas del sistema

### Herramientas de Kali Linux Necesarias
```bash
# 1. Crear carpeta Ares y clonar repositorio dentro
mkdir -p ~/Ares && cd ~/Ares
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar permisos necesarios
chmod +x configurar_kali.sh
chmod +x verificacion_final.py
find . -name "*.py" -exec chmod +x {} \;

# 3. Configurar automáticamente
sudo ./configurar_kali.sh

# 4. Ejecutar inmediatamente
python3 main.py
```

## Configuración Automática

### Script de Configuración
El script `configurar_kali.sh` instala y verifica automáticamente las herramientas necesarias:

#### Herramientas de Escaneado de Red
- **nmap**: Network mapper para descubrimiento y análisis de puertos
- **masscan**: Scanner de puertos de alta velocidad para redes grandes
- **gobuster**: Enumeración de directorios y archivos web mediante fuerza bruta
- **nuclei**: Scanner de vulnerabilidades basado en plantillas
- **ffuf**: Web fuzzer moderno para descubrimiento de contenido

#### Herramientas de Monitoreo del Sistema
- **inotifywait**: Monitoreo de archivos en tiempo real
- **auditd**: Sistema de auditoría de eventos del kernel Linux
- **pspy**: Monitor de procesos que no requiere privilegios root

#### Herramientas de Análisis Forense
- **volatility3**: Framework de análisis forense de memoria
- **binwalk**: Análisis y extracción de firmware
- **strings**: Extracción de cadenas de texto de archivos binarios
- **file**: Identificación de tipos de archivo por contenido
- **exiftool**: Lectura y escritura de metadatos de archivos

#### Herramientas de Seguridad Anti-Malware
- **clamscan**: Motor antivirus ClamAV para detección de malware
- **yara**: Engine de detección de patrones de malware
- **chkrootkit**: Detector de rootkits para sistemas Unix
- **rkhunter**: Herramienta de verificación de rootkits y backdoors

## Modos de Ejecución

### Modo Producción (Kali Linux)
```bash
# Ejecución estándar con funcionalidades completas
python3 main.py
```

### Modo Desarrollo (Otros Sistemas)
```bash
# Modo desarrollo para testing y desarrollo en sistemas no-Kali
python3 main.py --dev
```

## Estructura Post-Instalación

```
Aresitos/
├── main.py                     # Punto de entrada principal
├── configurar_kali.sh          # Script de configuración automática
├── aresitos/                   # Módulo principal de la aplicación
│   ├── controlador/            # Lógica de negocio (15 controladores)
│   ├── modelo/                 # Gestión de datos y persistencia (19 modelos)
│   ├── vista/                  # Interfaces de usuario (12 vistas)
│   │   ├── terminal_mixin.py   # Funcionalidad de terminales reutilizable
│   │   ├── burp_theme.py       # Tema visual profesional
│   │   └── vista_*.py          # Vistas con layout PanedWindow
│   └── utils/                  # Utilidades del sistema (4 módulos)
├── data/                       # Datos y recursos del sistema
│   ├── *.db                    # Bases de datos SQLite
│   ├── wordlists/              # Diccionarios para pentesting
│   ├── diccionarios/           # Diccionarios de términos técnicos
│   └── cheatsheets/            # Guías de comandos de Kali Linux
├── logs/                       # Sistema de logs centralizado
├── configuración/             # Archivos de configuración JSON
└── documentacion/              # Documentación técnica completa
```
## Verificación de Instalación

### Verificación Automática
```bash
# Verificar integridad de todos los componentes
python3 verificacion_final.py

# Verificar herramientas específicas de Kali Linux
python3 -c "from aresitos.utils.verificar_kali import verificar_herramientas; verificar_herramientas()"
```

### Verificación Manual de la Interfaz
```bash
# Iniciar la aplicación
python3 main.py
```

#### Módulos Disponibles
Al ejecutar Aresitos, debe tener acceso a los siguientes módulos:

1. **Dashboard**: Métricas del sistema con terminal de monitoreo
2. **Escaneado**: Análisis de vulnerabilidades con terminales integrados (nmap/nuclei)
3. **Monitoreo y Cuarentena**: Vigilancia de malware con terminal ClamAV
4. **Auditoría**: Evaluación de seguridad con terminales LinPEAS/chkrootkit
5. **Gestión de Datos**: Wordlists y diccionarios con terminal de generación
6. **Reportes**: Exportación de resultados con terminal de análisis
7. **FIM**: Monitoreo de integridad con terminal inotifywait
8. **SIEM**: Correlación de eventos con terminales Volatility/Binwalk

#### Verificación de Interfaz
Cada vista debe mostrar:
- **Panel izquierdo**: Controles y configuración del módulo
- **Panel derecho**: Terminal integrado con salida en tiempo real
- **Navegación**: Pestañas o botones para cambiar entre módulos
- **Tema visual**: Interfaz profesional estilo Burp Suite
# - 48 terminales activos en total
```

## 🔒 **Permisos y Seguridad**

## Configuración de Permisos y Seguridad

### Configuración de Permisos Básicos
```bash
# Permisos necesarios para archivos ejecutables
chmod +x configurar_kali.sh
chmod +x verificacion_final.py
chmod +x main.py

# Permisos para todos los archivos Python
find . -name "*.py" -exec chmod +x {} \;

# Permisos para directorios de datos
chmod -R 755 data/
chmod -R 755 logs/
chmod -R 755 configuración/
```

### Configuración Automática de Seguridad
El script `configurar_kali.sh` establece automáticamente:
- **Permisos sudo**: Configuración granular para herramientas específicas
- **Grupos de usuario**: Acceso controlado a herramientas del sistema
- **Rutas del sistema**: Configuración de PATH para herramientas
- **Verificación de integridad**: Validación de herramientas instaladas

### Características de Seguridad
- **Gestor de permisos**: Control granular de acceso sudo/root
- **Validación de entrada**: Sanitización completa de inputs
- **Logging de auditoría**: Trazabilidad de todas las operaciones
- **Ejecución segura**: Timeouts y validación de comandos

## Solución de Problemas Comunes

### Errores de Compatibilidad

#### "ARESITOS requiere Kali Linux"
```bash
# Utilizar modo desarrollo en otros sistemas operativos
python3 main.py --dev
```

#### "Herramienta X no encontrada"
```bash
# Reinstalar herramientas automáticamente
sudo ./configurar_kali.sh

# Verificar instalación específica
which nmap
which clamscan
```

#### "Error de permisos"
```bash
# Verificar que el usuario pertenece a los grupos correctos
sudo usermod -a -G sudo,adm $USER

# Reiniciar sesión para aplicar cambios de grupo
#### "Base de datos no encontrada"
```bash
# Recrear bases de datos automáticamente
python3 -c "from aresitos.modelo.modelo_principal import ModeloPrincipal; ModeloPrincipal()"
```

#### "Error de dependencias Python"
```bash
# Verificar versión de Python
python3 --version

# Verificar módulos disponibles
python3 -c "import tkinter, sqlite3, subprocess, threading; print('Módulos OK')"
```

### Problemas de Rendimiento

#### "Aplicación lenta"
```bash
# Verificar recursos del sistema
free -h
df -h

# Limpiar archivos temporales
find /tmp -name "*aresitos*" -delete
```

#### "Terminales no responden"
```bash
# Verificar procesos colgados
ps aux | grep python3
killall python3  # Si es necesario
```

## Verificación del Estado del Sistema

### Comandos de Diagnóstico
```bash
# Estado herramientas Kali
which nmap masscan gobuster nuclei ffuf

```bash
# Verificar estado de las bases de datos
ls -la data/*.db

# Monitorear logs en tiempo real
tail -f logs/aresitos.log

# Verificar procesos de Aresitos activos
ps aux | grep python3 | grep aresitos
```

### Indicadores de Salud del Sistema
Verificar que estén operativos:
- ✅ **Herramientas de Kali**: Todas disponibles y funcionales
- ✅ **Bases de datos**: Creadas y accesibles en directorio data/
- ✅ **Permisos**: Configurados correctamente para ejecución
- ✅ **Interfaz**: Todos los módulos cargan sin errores
- ✅ **Terminales**: Terminales integrados funcionando en cada vista
- ✅ **Layout**: Diseño PanedWindow con división controles/terminal
- ✅ **Threading**: Operaciones no bloqueantes activas
- ✅ **Logs**: Archivo de logs generándose en directorio logs/

## Guía de Primer Uso

### Flujo de Trabajo Inicial Recomendado

1. **Verificar el entorno**
   - Acceder al Dashboard
   - Verificar métricas del sistema
   - Confirmar que el terminal de monitoreo está activo

2. **Realizar test básico**
   - Ir al módulo de Escaneo
   - Configurar IP objetivo: `127.0.0.1`
   - Ejecutar "Escanear Sistema"
   - Observar salida en terminal integrado

3. **Configurar monitoreo FIM**
   - Acceder al módulo FIM
   - Ejecutar "Crear Baseline"
   - Iniciar "Monitoreo Continuo"
   - Verificar terminal inotifywait funcionando

4. **Activar sistema SIEM**
   - Ir al módulo SIEM
   - Iniciar "Monitoreo de Puertos"
   - Verificar eventos en dashboard
   - Confirmar terminal de análisis activo

5. **Explorar módulos adicionales**
   - Gestión de Datos: Wordlists y diccionarios
   - Reportes: Generación y análisis
   - Auditoría: Herramientas de verificación
   - Verificar que todos los terminales integrados funcionan correctamente

## Mantenimiento y Actualizaciones

### Actualización del Sistema
```bash
# Actualizar Aresitos desde el repositorio
cd ~/Ares/Aresitos
git pull origin main

# Ejecutar verificación post-actualización
python3 verificacion_final.py
```

### Limpieza Periódica
```bash
# Limpiar logs antiguos (opcional)
find logs/ -name "*.log" -mtime +30 -delete

# Limpiar archivos temporales
find /tmp -name "*aresitos*" -delete
```

---

**ARESITOS v2.0 - Guía de Instalación**
*Desarrollado por DogSoulDev para la comunidad de ciberseguridad*

# Actualizar bases de datos
freshclam
updatedb
```

## ✅ VERIFICACIÓN FINAL

### Script de Verificación
```python
# verificacion_final.py - Validación completa del sistema
import subprocess
import sys
import os

def verificar_herramienta(comando):
    """Verifica si una herramienta está instalada y funcional"""
    try:
        resultado = subprocess.run([comando, '--version'], 
                                 capture_output=True, text=True, timeout=10)
        return resultado.returncode == 0
    except:
        return False

def main():
    herramientas = [
        'nmap', 'masscan', 'gobuster', 'nuclei', 'ffuf',
        'volatility3', 'binwalk', 'sleuthkit', 'foremost', 'exiftool',
        'clamscan', 'yara', 'inotifywait', 'chkrootkit', 'rkhunter'
    ]
    
    print("🔍 VERIFICANDO HERRAMIENTAS KALI...")
    errores = []
    
    for herramienta in herramientas:
        if verificar_herramienta(herramienta):
            print(f"✅ {herramienta}")
        else:
            print(f"❌ {herramienta}")
            errores.append(herramienta)
    
    # Verificar estructura de archivos
    print("\n📁 VERIFICANDO ESTRUCTURA...")
    archivos_criticos = [
        'main.py',
        'aresitos/__init__.py',
        'aresitos/modelo/modelo_escaneador_kali2025.py',
        'aresitos/vista/vista_principal.py',
        'aresitos/controlador/controlador_principal_nuevo.py',
        'configuración/aresitos_config_kali.json'
    ]
    
    for archivo in archivos_criticos:
        if os.path.exists(archivo):
            print(f"✅ {archivo}")
        else:
            print(f"❌ {archivo}")
            errores.append(archivo)
    
    # Resultado final
    if errores:
        print(f"\n❌ VERIFICACIÓN FALLIDA. Errores: {len(errores)}")
        print("Ejecutar: sudo ./configurar_kali.sh")
        return False
    else:
        print("\n✅ SISTEMA VERIFICADO - LISTO PARA USAR")
        print("Ejecutar: python main.py")
        return True

if __name__ == "__main__":
    main()
```

## 🛠️ SOLUCIÓN DE PROBLEMAS

### Errores Comunes

#### 1. Herramientas Faltantes
```bash
# Error: comando no encontrado
sudo apt update
sudo apt install -y [herramienta]
```

#### 2. Permisos Insuficientes
```bash
# Error: Permission denied
sudo chown -R $USER:$USER /opt/aresitos
chmod +x *.sh
```

#### 3. Base de Datos ClamAV
```bash
# Error: ClamAV database not found
sudo freshclam
sudo systemctl start clamav-daemon
```

#### 4. Python Dependencies
```bash
# Error: módulo no encontrado
# ARESITOS usa SOLO stdlib - no instalar pip packages
python -c "import sys; print(sys.version)"
```

### Verificación Manual
```bash
# Verificar instalación completa
python -c "
import sqlite3, threading, subprocess, json, hashlib
print('✅ Python stdlib OK')
"

# Verificar herramientas críticas
nmap --version && echo "✅ nmap OK"
clamscan --version && echo "✅ clamscan OK"
inotifywait --help && echo "✅ inotify OK"
```

## 📋 CHECKLIST DE INSTALACIÓN

- [ ] **Kali Linux 2025** instalado y actualizado
- [ ] **Git** disponible para clonar repositorio
- [ ] **Permisos root** para instalación de herramientas
- [ ] **Conexión internet** para descargar dependencias
- [ ] **20GB espacio libre** en disco
- [ ] **8GB RAM** disponible (recomendado)
- [ ] **Ejecutar** `configurar_kali.sh` como root
- [ ] **Verificar** con `python verificacion_final.py`
- [ ] **Probar** ejecución con `python main.py`

## 🎯 COMANDOS ESENCIALES

```bash
# Instalación completa paso a paso
mkdir -p ~/Ares && cd ~/Ares
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh verificacion_final.py
sudo ./configurar_kali.sh
python verificacion_final.py
python main.py

# Verificación rápida
python -c "import aresitos; print('✅ ARESITOS OK')"

# Debug mode
python main.py --dev

# Logs de depuración
tail -f logs/aresitos.log
```

---

**TIEMPO INSTALACIÓN**: ~15 minutos  
**DIFICULTAD**: Básica  
**SOPORTE**: Solo Kali Linux 2025  
## 🎯 COMANDOS ESENCIALES

```bash
# Instalación completa paso a paso
mkdir -p ~/Ares && cd ~/Ares
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh verificacion_final.py
sudo ./configurar_kali.sh
python verificacion_final.py
python main.py

# Verificación rápida
python -c "import aresitos; print('✅ ARESITOS OK')"

# Debug mode
python main.py --dev

# Logs de depuración
tail -f logs/aresitos.log
```