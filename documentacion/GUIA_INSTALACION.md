# Guía de Instalación - ARESITOS

## 🔄 Política de Rutas Dinámicas y Portabilidad
Todas las rutas de recursos, datos y configuraciones en ARESITOS son ahora relativas al root del proyecto y se construyen dinámicamente usando `os.path` o `pathlib`. No se usan rutas absolutas, ni dependientes de `/home`, ni del `cwd`. Esto garantiza portabilidad, seguridad y compatibilidad con Kali Linux y otros entornos. Cualquier acceso a archivos, logs, wordlists, diccionarios o recursos debe seguir este principio.

## Requisitos

- **Kali Linux 2025** (recomendado)
- Python 3.8 o superior
- Permisos sudo
- 100MB de espacio en disco

## Instalación rápida

1. Clona el repositorio:
```bash
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
```
2. Ejecuta el script de configuración:
```bash
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh
```
3. Inicia la aplicación:
```bash
python3 main.py
```

## Instalación manual (opcional)

1. Instala dependencias principales:
```bash
sudo apt update
sudo apt install python3 python3-tk python3-venv nmap masscan nuclei gobuster ffuf feroxbuster wireshark autopsy sleuthkit git curl wget sqlite3
```
2. Ejecuta la aplicación:
```bash
python3 main.py
```

## Notas
- **Privilegios root persistentes:** Mientras ARESITOS esté abierto, los privilegios root (sudo) se mantienen activos para permitir instalaciones y operaciones avanzadas sin cortes. El root se libera automáticamente al cerrar la aplicación.
- Para modo desarrollo en otros sistemas: `python3 main.py --dev`
- Si tienes problemas de dependencias, ejecuta de nuevo `sudo ./configurar_kali.sh`.
- Consulta la documentación técnica en la carpeta `documentacion/`.
[INFO] Instalando herramienta CRÍTICA: tcpdump...
[✓] tcpdump ya está instalado
[INFO] Instalando herramienta CRÍTICA: iftop...
[✓] iftop ya está instalado
[INFO] Instalando herramienta CRÍTICA: netcat-openbsd...
[✓] netcat-openbsd ya está instalado
[INFO] Instalando herramienta CRÍTICA: htop...
[✓] htop ya está instalado
[INFO] Instalando herramienta CRÍTICA: lsof...
[✓] lsof ya está instalado
[INFO] Instalando herramienta CRÍTICA: psmisc...
[✓] psmisc ya está instalado
[INFO] Instalando herramienta CRÍTICA: iproute2...
[✓] iproute2 ya está instalado
```

### Paso 5: Instalación de Herramientas Opcionales
```bash
INSTALANDO herramientas OPCIONALES...
[INFO] Instalando herramienta opcional: rustscan...
[WARN] No se pudo instalar rustscan (continuando...)
[INFO] Instalando herramienta opcional: masscan...
[✓] masscan ya está instalado
[INFO] Instalando herramienta opcional: gobuster...
[✓] gobuster ya está instalado
[INFO] Instalando herramienta opcional: nikto...
[✓] nikto ya está instalado
[INFO] Instalando herramienta opcional: whatweb...
[✓] whatweb ya está instalado
[INFO] Instalando herramienta opcional: lynis...
[✓] lynis ya está instalado
[INFO] Instalando herramienta opcional: chkrootkit...
[✓] chkrootkit ya está instalado
[INFO] Instalando herramienta opcional: foremost...
[✓] foremost ya está instalado
[INFO] Instalando herramienta opcional: binwalk...
[✓] binwalk ya está instalado
[INFO] Instalando herramienta opcional: exiftool...
[✓] exiftool instalado correctamente
[INFO] Instalando herramienta opcional: feroxbuster...
[✓] feroxbuster ya está instalado
[INFO] Instalando herramienta opcional: httpx-toolkit...
[✓] httpx-toolkit ya está instalado
```

### Paso 6: Reporte de Instalación
```bash
REPORTE DE INSTALACIÓN
[✓] Todas las herramientas ESENCIALES instaladas correctamente
[WARN] Herramientas opcionales no instaladas: rustscan
[INFO] ARESITOS funcionará sin estas herramientas, pero con funcionalidad limitada
[INFO] Actualizando base de datos del sistema...
```

### Paso 7: Configuración de Permisos
```bash
PERMISOS Configurando permisos de red...
[INFO] Configurando permisos para nmap...
[✓] Permisos de nmap configurados
[INFO] Configurando permisos para tcpdump...
[✓] Permisos de tcpdump configurados
[INFO] Añadiendo usuario kali a grupos necesarios...
[✓] Usuario añadido al grupo wireshark
[✓] Usuario añadido al grupo netdev

CONFIG Configurando sudo para ARESITOS v2.0...
/etc/sudoers.d/aresitos-v2: parsed OK
[✓] Configuración sudo creada en /etc/sudoers.d/aresitos-v2
```

### Paso 8: Configuración Python
```bash
🐍 Configurando entorno Python para ARESITOS...
[WARN] Detectado entorno Python externally-managed (Kali Linux 2024+)
[INFO] Configurando solución compatible para ARESITOS...
[INFO] Instalando dependencias Python vía APT (recomendado)...
[INFO] Instalando python3-pil...
[✓] python3-pil instalado vía APT
[INFO] Instalando python3-requests...
[✓] python3-requests instalado vía APT
[INFO] Instalando python3-urllib3...
[✓] python3-urllib3 instalado vía APT

🧪 Verificando dependencias...
   OK tkinter: Interfaz gráfica
   OK PIL: Procesamiento de imágenes
   OK sqlite3: Base de datos
   OK json: Manejo de JSON
   OK threading: Multihilo
   OK subprocess: Ejecución de comandos
   OK os: Sistema operativo
   OK sys: Sistema Python

OK Todas las dependencias están disponibles
[✓] Configuración Python completada
```

### Paso 9: Verificación Final
```bash
🧪 Verificando configuración...
[✓] nmap disponible
[✓] nmap ejecutable sin contraseña
[✓] netstat disponible
[✓] netstat ejecutable sin contraseña
[✓] ss disponible
[✓] ss ejecutable sin contraseña
[✓] tcpdump disponible
[✓] tcpdump ejecutable sin contraseña
[INFO] Verificando membresía de grupos para kali...
[✓] Usuario en grupo wireshark

COMPLETADO CONFIGURACIÓN COMPLETADA
============================
[✓] Ares Aegis está configurado para Kali Linux

[INFO] Pasos siguientes:
  1. Cierre y reabra la terminal para aplicar cambios de grupo
  2. Execute el script de prueba: python3 /home/kali/test_ares_permissions.py
  3. Execute la verificación de permisos: python3 verificacion_permisos.py
  4. Inicie Ares Aegis: python3 main.py
```

### Paso 10: Inicio de la Aplicación
```bash
└─$ python3 main.py
Aresitos - Sistema de Seguridad Cibernética
==================================================
Iniciando con interfaz de login...
OK Tkinter disponible y funcional
Creando aplicación de login...
Aplicación de login creada
Iniciando interfaz gráfica...
```

## Configuración Automática

### Script de Configuración `configurar_kali.sh`
El script de configuración automática realiza todas las tareas necesarias para preparar Kali Linux:

#### ✅ **Herramientas Críticas Instaladas**
- **python3-dev, python3-venv, python3-tk**: Entorno Python completo
- **curl, wget, git**: Herramientas de descarga y control de versiones
- **nmap**: Escaneador de red principal
- **net-tools, iproute2**: Herramientas de red fundamentales
- **tcpdump**: Captura de tráfico de red
- **netcat-openbsd**: Utilidad de red versátil
- **htop, lsof, psmisc**: Monitoreo de sistema y procesos

#### ✅ **Herramientas de Seguridad Opcionales**
- **masscan**: Escaneador de puertos de alta velocidad
- **gobuster**: Enumeración de directorios web
- **nikto**: Escaneador de vulnerabilidades web
- **whatweb**: Identificador de tecnologías web
- **lynis**: Auditor de seguridad del sistema
- **chkrootkit**: Detector de rootkits
- **foremost**: Recuperación de archivos
- **binwalk**: Análisis de firmwares
- **exiftool**: Análisis de metadatos
- **feroxbuster**: Fuzzing de directorios
- **httpx-toolkit**: Herramientas HTTP modernas

#### ⚠️ **Herramientas que Requieren Instalación Manual**
- **rustscan**: Escaneador moderno (requiere Rust)
  ```bash
  # Para instalar rustscan manualmente:
  cargo install rustscan
  ```

#### 🔧 **Configuraciones Automáticas**
1. **Permisos de Red**: Configuración de nmap y tcpdump sin sudo
2. **Grupos de Usuario**: Adición a grupos wireshark y netdev
3. **Configuración Sudo**: Archivo `/etc/sudoers.d/aresitos-v2` para herramientas específicas
4. **Dependencias Python**: Instalación vía APT para compatibilidad con Kali 2024+
5. **Permisos de Archivos**: Configuración automática de todos los permisos necesarios

#### 🧪 **Verificación Automática**
El script verifica automáticamente:
- Disponibilidad de todas las herramientas críticas
- Permisos de ejecución sin contraseña
- Membresía en grupos necesarios
- Funcionamiento de dependencias Python
- Creación de scripts de prueba

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

#### 1. Problemas con APT (Error de Locks)
```bash
# Error típico:
# Could not get lock /var/lib/dpkg/lock-frontend. It is held by process XXXXX (apt)

# ✅ SOLUCIÓN RECOMENDADA (Método Seguro):
# 1. Esperar 5-10 minutos (otro proceso puede estar actualizando)
# 2. Verificar procesos activos:
sudo ps aux | grep apt
sudo ps aux | grep dpkg

# 3. Si hay procesos colgados, identificar el PID:
sudo lsof /var/lib/dpkg/lock-frontend
sudo lsof /var/lib/dpkg/lock

# 4. Terminar proceso específico (sustituir XXXXX por el PID real):
sudo kill -9 XXXXX

# ⚠️ MÉTODO DE ÚLTIMO RECURSO (Solo si lo anterior no funciona):
sudo rm /var/lib/dpkg/lock-frontend
sudo rm /var/lib/dpkg/lock
sudo rm /var/cache/apt/archives/lock
sudo dpkg --configure -a
sudo apt update

# 5. Reintentar instalación:
sudo apt install kali-tools-forensics
```

#### 2. Herramientas Faltantes
```bash
# Error: comando no encontrado
sudo apt update
sudo apt install -y [herramienta]
```

#### 3. Permisos Insuficientes
```bash
# Error: Permission denied
sudo chown -R $USER:$USER /opt/aresitos
chmod +x *.sh
```

#### 4. Base de Datos ClamAV
```bash
# Error: ClamAV database not found
sudo freshclam
sudo systemctl start clamav-daemon
```

#### 5. Python Dependencies
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
- [ ] **100MB espacio libre** en disco mínimo
- [ ] **2GB RAM** disponible (recomendado)
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
python -c "import aresitos; print('ARESITOS OK')"

# Debug mode
python main.py --dev

# Logs de depuración
tail -f logs/aresitos.log
```

## 📋 NOTAS IMPORTANTES DE INSTALACIÓN

### ✅ **Instalación Exitosa - Indicadores**
Si la instalación es exitosa, verás estos mensajes:
```
[✓] Todas las herramientas ESENCIALES instaladas correctamente
[✓] Configuración sudo creada en /etc/sudoers.d/aresitos-v2
[✓] Configuración Python completada
COMPLETADO CONFIGURACIÓN COMPLETADA
[✓] Ares Aegis está configurado para Kali Linux
```

### ⚠️ **Advertencias Normales (No son errores)**
Estos mensajes son normales y no impiden el funcionamiento:
```
[WARN] No se pudo instalar rustscan (continuando...)
[WARN] Detectado entorno Python externally-managed (Kali Linux 2024+)
[WARN] No se pudo instalar python3-sqlite3 vía APT
[WARN] No se pudo instalar python3-json vía APT
```

### 🔄 **Pasos Post-Instalación Importantes**
1. **Reiniciar sesión**: Para aplicar cambios de grupos
   ```bash
   # Cerrar y reabrir terminal o:
   newgrp wireshark
   ```

2. **Verificar scripts de prueba**:
   ```bash
   python3 /home/kali/test_ares_permissions.py
   python3 verificacion_permisos.py
   ```

3. **Inicio normal**:
   ```bash
   python3 main.py
   # Debería mostrar:
   # Aresitos - Sistema de Seguridad Cibernética
   # Iniciando con interfaz de login...
   # OK Tkinter disponible y funcional
   ```

### 🚨 **Solución de Problemas Comunes**

**Si falta python3-tk:**
```bash
sudo apt update && sudo apt install python3-tk
```

**Si hay errores de permisos:**
```bash
sudo ./configurar_kali.sh  # Reejecutar configuración
```

**Si rustscan no está disponible:**
```bash
# ARESITOS funciona sin rustscan, usa nmap como alternativa
# Para instalar rustscan manualmente:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo install rustscan
```

**Si fallan las dependencias Python:**
```bash
# El script maneja automáticamente las dependencias
# Todas las librerías críticas (tkinter, sqlite3, json) son nativas de Python
```

---

**✨ INSTALACIÓN COMPLETADA**  
*Una vez que veas "Iniciando interfaz gráfica..." tu instalación está lista.*

---

**TIEMPO INSTALACIÓN**: ~15 minutos  
**DIFICULTAD**: Básica  
**SOPORTE**: Solo Kali Linux 2025
