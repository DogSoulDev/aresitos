# Guía de Instalación - ARESITOS


## 🔄 Política de rutas dinámicas y portabilidad
Todas las rutas de recursos, datos y configuraciones en ARESITOS son relativas a la raíz del proyecto y se construyen dinámicamente usando `os.path` o `pathlib`. No se utilizan rutas absolutas ni dependientes de `/home` ni del directorio de trabajo actual. Esto garantiza portabilidad, seguridad y compatibilidad con Kali Linux y otros entornos.



## Requisitos y consumo real

- **Kali Linux 2025** (recomendado)
- Python 3.8 o superior
- Permisos sudo
- Espacio ocupado tras instalación base: ~25 MB
- Espacio recomendado para datos y reportes: 20 MB adicionales
- RAM recomendada: mínimo 1 GB libre (uso típico bajo, depende de los módulos activos)


## Instalación rápida

1. Clona el repositorio:
    ```bash
    git clone https://github.com/DogSoulDev/aresitos.git
    cd aresitos
    ```
2. Da permisos de ejecución a los scripts principales:
    ```bash
   chmod +x configurar_kali.sh main.py
    ```
3. Ejecuta el script de configuración (como root o con sudo):
    ```bash
   sudo ./configurar_kali.sh
    ```
4. Inicia la aplicación:
    ```bash
   python3 main.py
    ```


## Instalación manual (opcional)

1. Instala las dependencias principales:
    ```bash
   sudo apt update
   sudo apt install python3 python3-tk python3-venv nmap masscan nuclei gobuster ffuf feroxbuster wireshark autopsy sleuthkit hashdeep testdisk bulk-extractor dc3dd guymager git curl wget sqlite3
    ```
2. Inicia la aplicación:
    ```bash
   python3 main.py
    ```


## Notas
- **Privilegios root persistentes:** Mientras ARESITOS esté abierto, los privilegios root (sudo) se mantienen activos para permitir instalaciones y operaciones avanzadas sin cortes. El root se libera automáticamente al cerrar la aplicación.
- Para modo desarrollo en otros sistemas: `python3 main.py --dev`
- Si tienes problemas de dependencias, ejecuta de nuevo `sudo ./configurar_kali.sh`.
- Consulta la documentación técnica en la carpeta `documentacion/`.


### Instalación de herramientas opcionales
El script de configuración instala automáticamente las herramientas opcionales recomendadas para análisis forense y pentesting. Si alguna herramienta opcional no se instala, ARESITOS seguirá funcionando, pero con funcionalidad limitada en algunos módulos avanzados.


### Reporte de instalación
Al finalizar la instalación, se mostrará un resumen indicando si todas las herramientas esenciales y opcionales están disponibles. Si alguna herramienta opcional no se instala, se notificará como advertencia.


### Configuración de permisos
El script configura automáticamente los permisos necesarios para herramientas de red (nmap, tcpdump), añade el usuario a los grupos requeridos (wireshark, netdev) y crea la configuración sudo específica para ARESITOS en `/etc/sudoers.d/aresitos-v2`.


### Configuración de Python
ARESITOS solo utiliza la biblioteca estándar de Python. El script verifica que todos los módulos necesarios (tkinter, sqlite3, threading, subprocess, os, sys, json, hashlib) estén disponibles. No se requieren paquetes externos ni instalación vía pip.


### Verificación final
Al finalizar la configuración, asegúrate de cerrar y reabrir la terminal para aplicar los cambios de grupo. Inicia la aplicación con:
```bash
python3 main.py
```


### Inicio de la aplicación
Al ejecutar `python3 main.py`, se iniciará la interfaz gráfica de inicio de sesión y el panel principal de ARESITOS.


## Configuración automática

### Script de configuración `configurar_kali.sh`
El script de configuración automática instala todas las herramientas críticas y opcionales, configura permisos, grupos y sudo, y verifica que el entorno Python esté listo para ejecutar ARESITOS. Si alguna herramienta opcional no se instala, el sistema seguirá funcionando, pero con funciones limitadas en algunos módulos avanzados.


## Modos de ejecución

### Modo producción (Kali Linux)
```bash
python3 main.py
```

### Modo desarrollo (otros sistemas)
```bash
python3 main.py --dev
```



aresitos/
├── controlador/            # Lógica de negocio y orquestación
├── modelo/                 # Modelos de datos y acceso a bases
├── vista/                  # Interfaz gráfica y paneles
├── utils/                  # Utilidades y helpers
├── recursos/               # Imágenes, iconos y capturas
├── __init__.py
data/
├── *.db                    # Bases de datos SQLite
├── wordlists/              # Listas de palabras para pentesting
├── diccionarios/           # Diccionarios de términos técnicos
├── cheatsheets/            # Guías de comandos
├── cuarentena/             # Archivos y metadatos de cuarentena
## Estructura real tras la instalación

```
aresitos/
├── controlador/            # Lógica de negocio y orquestación
├── modelo/                 # Modelos de datos y acceso a bases
├── vista/                  # Interfaz gráfica y paneles
├── utils/                  # Utilidades y helpers
├── recursos/               # Imágenes, iconos y capturas
├── __init__.py

data/
├── *.db                    # Bases de datos SQLite
├── wordlists/              # Listas de palabras para pentesting
├── diccionarios/           # Diccionarios de términos técnicos
├── cheatsheets/            # Guías de comandos
├── cuarentena/             # Archivos y metadatos de cuarentena

logs/                       # Registros y logs de la aplicación
reportes/                   # Reportes generados (vacío por defecto)
configuración/              # Archivos de configuración JSON y textos
documentacion/              # Manuales técnicos y guías
main.py                     # Script principal
configurar_kali.sh          # Script de configuración automática
requirements.txt            # Solo para desarrollo
pyproject.toml              # Configuración de proyecto Python
LICENSE                     # Licencia del proyecto
README.md                   # Documentación principal
```

## Verificación de instalación


Para verificar que la instalación ha sido exitosa, simplemente inicia la aplicación:
```bash
python3 main.py
```
Si la interfaz gráfica se muestra correctamente y puedes acceder a los módulos principales, la instalación es correcta.


### Módulos disponibles
Al ejecutar ARESITOS, tendrás acceso a los siguientes módulos:

1. **Dashboard**: Métricas del sistema y terminal de monitoreo
2. **Escaneo**: Análisis de vulnerabilidades
3. **Monitoreo y cuarentena**: Vigilancia de procesos y archivos
4. **Auditoría**: Evaluación de seguridad
5. **Gestión de datos**: Wordlists y diccionarios
6. **Reportes**: Exportación de resultados
7. **FIM**: Monitoreo de integridad
8. **SIEM**: Correlación de eventos

Cada vista muestra controles, configuración y un terminal integrado con salida en tiempo real. El diseño visual es profesional y claro.


## 🔒 Permisos y seguridad


### Configuración de permisos básicos
```bash
# Permisos necesarios para archivos ejecutables
chmod +x configurar_kali.sh
chmod +x main.py

# Permisos para todos los archivos Python
find . -name "*.py" -exec chmod +x {} \;

# Permisos para directorios de datos
chmod -R 755 data/
chmod -R 755 logs/
chmod -R 755 configuración/
```


### Configuración automática de seguridad
El script `configurar_kali.sh` establece automáticamente:
- **Permisos sudo**: Configuración granular para herramientas específicas
- **Grupos de usuario**: Acceso controlado a herramientas del sistema
- **Rutas del sistema**: Configuración de PATH para herramientas
- **Verificación de integridad**: Validación de herramientas instaladas


### Características de seguridad
- **Gestor de permisos**: Control granular de acceso sudo/root
- **Validación de entrada**: Sanitización completa de entradas
- **Logging de auditoría**: Trazabilidad de todas las operaciones
- **Ejecución segura**: Timeouts y validación de comandos


## Solución de problemas comunes


### Errores de compatibilidad


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


### Problemas de rendimiento


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


## Verificación del estado del sistema



### Comandos de diagnóstico
```bash
# Estado herramientas Kali
which nmap masscan gobuster nuclei ffuf

# Verificar estado de las bases de datos
ls -la data/*.db

# Monitorear logs en tiempo real
tail -f logs/aresitos_errores.log

# Verificar procesos de Aresitos activos
ps aux | grep python3 | grep aresitos
```



### Indicadores de salud del sistema
Verifica que estén operativos:
- ✅ **Herramientas de Kali**: Todas disponibles y funcionales
- ✅ **Bases de datos**: Creadas y accesibles en `data/`
- ✅ **Permisos**: Configurados correctamente para ejecución
- ✅ **Interfaz**: Todos los módulos cargan sin errores
- ✅ **Terminales**: Terminales integrados funcionando en cada vista
- ✅ **Layout**: Diseño visual claro y profesional
- ✅ **Threading**: Operaciones no bloqueantes activas
- ✅ **Logs**: Archivo de logs generándose en `logs/`


## Guía de primer uso


### Flujo de trabajo inicial recomendado

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


## Mantenimiento y actualizaciones


### Actualización del sistema
```bash
# Actualizar Aresitos desde el repositorio
cd ~/Ares/Aresitos
git pull origin main

# Ejecutar verificación post-actualización
python3 verificacion_final.py
```


### Limpieza periódica
```bash
# Limpiar logs antiguos (opcional)
find logs/ -name "*.log" -mtime +30 -delete

# Limpiar archivos temporales
find /tmp -name "*aresitos*" -delete
```

---


**ARESITOS v2.0 - Guía de instalación**
*Desarrollado por DogSoulDev para la comunidad de ciberseguridad*




# Actualizar bases de datos de firmas (opcional)
freshclam
updatedb
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
- [ ] **Git** disponible para clonar el repositorio
- [ ] **Permisos root** para instalación de herramientas
- [ ] **Conexión a internet** para descargar dependencias
- [ ] **25 MB espacio libre** en disco mínimo (instalación base, medido real)
- [ ] **20 MB adicionales** para datos y reportes
- [ ] **1 GB RAM** disponible (mínimo recomendado, medido real)
- [ ] **Ejecutar** `configurar_kali.sh` como root
- [ ] **Probar** ejecución con `python3 main.py`

## 🎯 COMANDOS ESENCIALES

```bash
# Instalación completa paso a paso
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh main.py
sudo ./configurar_kali.sh
python3 main.py

# Verificación rápida
python3 -c "import aresitos; print('ARESITOS OK')"

# Modo desarrollo
python3 main.py --dev

# Logs de depuración
tail -f logs/aresitos_errores.log
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

**TIEMPO DE INSTALACIÓN**: ~10-15 minutos (medido real)  
**DIFICULTAD**: Básica  
**SOPORTE**: Solo Kali Linux 2025
