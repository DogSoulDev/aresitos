# ARESITOS v2.0 - Guía de Instalación

## 🚀 **Instalación Rápida**

### **Requisitos Sistema**
- **SO**: Kali Linux 2024.x+ (recomendado)
- **Python**: 3.8+ (incluido en Kali)
- **RAM**: 4GB mínimo, 8GB recomendado
- **Disco**: 10GB libres

### **Instalación Zero-Config**
```bash
# 1. Clonar repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar automáticamente
sudo ./configurar_kali.sh

# 3. Ejecutar inmediatamente
python3 main.py
```

## ⚙️ **Configuración Automática**

### **Script configurar_kali.sh**
El script de configuración instala y verifica automáticamente:

#### **Escaneadores Red**
- `nmap` - Network mapper avanzado
- `masscan` - Scanner puertos alta velocidad
- `gobuster` - Brute-force directorios/archivos
- `nuclei` - Scanner vulnerabilidades
- `ffuf` - Web fuzzer moderno

#### **Monitoreo Sistema**
- `inotifywait` - Monitoreo archivos tiempo real
- `auditd` - Auditoría sistema Linux
- `pspy` - Monitor procesos sin root

#### **Análisis Forense**
- `volatility3` - Análisis memoria
- `binwalk` - Análisis firmware
- `strings` - Extracción strings
- `file` - Identificación tipos archivo
- `exiftool` - Metadatos archivos

#### **Seguridad Malware**
- `clamscan` - Antivirus ClamAV
- `yara` - Detección patrones malware
- `chkrootkit` - Detector rootkits
- `rkhunter` - Hunter rootkits

## 🔧 **Modos de Ejecución**

### **Producción (Kali Linux)**
```bash
# Ejecución estándar con todas las funcionalidades
python3 main.py
```

### **Desarrollo (Windows/otros SO)**
```bash
# Modo desarrollo para testing y desarrollo
python3 main.py --dev
```

## � **Estructura Post-Instalación**
```
Aresitos/
├── main.py                     # Punto entrada
├── configurar_kali.sh          # Setup automático
├── aresitos/                   # Core aplicación
│   ├── controlador/            # 15 controladores
│   ├── modelo/                 # 19 modelos datos
│   ├── vista/                  # 12 vistas GUI
│   └── utils/                  # 4 utilidades
├── data/                       # Bases datos + recursos
│   ├── *.db                    # SQLite databases
│   ├── wordlists/              # Diccionarios pentesting
│   └── cheatsheets/            # Comandos Kali
├── logs/                       # Logs sistema
└── documentacion/              # Guías técnicas
```

## ✅ **Verificación Instalación**

### **Test Automático**
```bash
# Verificar todos los componentes
python3 verificacion_final.py

# Verificar herramientas Kali específicas
python3 -c "from aresitos.utils.verificar_kali import verificar_herramientas; verificar_herramientas()"
```

### **Test Manual Interface**
```bash
# Iniciar aplicación
python3 main.py

# Verificar pestañas disponibles:
# 1. Dashboard - Métricas sistema
# 2. Escaneo - Análisis vulnerabilidades  
# 3. Monitoreo y Cuarentena - Vigilancia malware
# 4. Auditoría - Evaluación seguridad
# 5. Wordlists y Diccionarios - Recursos
# 6. Reportes - Exportación resultados
# 7. FIM - Integridad archivos
# 8. SIEM - Correlación eventos
```

## 🔒 **Permisos y Seguridad**

### **Configuración Permisos**
```bash
# El script configurar_kali.sh configura automáticamente:
# - Permisos sudo para herramientas específicas
# - Grupos usuario para acceso herramientas
# - Configuración paths sistema
# - Verificación integridad herramientas
```

### **Gestión Segura**
- **GestorPermisosSeguro**: Control granular sudo/root
- **Validación entradas**: Sanitización completa inputs
- **Logging completo**: Trazabilidad todas operaciones
- **Subprocess seguro**: Timeouts y validación comandos

## 🐛 **Solución Problemas**

### **Errores Comunes**

#### **"ARESITOS requiere Kali Linux"**
```bash
# Usar modo desarrollo en otros SO
python3 main.py --dev
```

#### **"Herramienta X no encontrada"**
```bash
# Reinstalar herramientas automáticamente
sudo ./configurar_kali.sh
```

#### **"Error permisos"**
```bash
# Verificar usuario en grupos correctos
sudo usermod -a -G sudo,adm $USER
sudo ./configurar_kali.sh
```

#### **"Base datos no encontrada"**
```bash
# Recrear bases datos automáticamente
python3 -c "from aresitos.modelo.modelo_principal import ModeloPrincipal; ModeloPrincipal()"
```

## 📊 **Verificación Estado**

### **Comandos Útiles**
```bash
# Estado herramientas Kali
which nmap masscan gobuster nuclei ffuf

# Estado bases datos
ls -la data/*.db

# Estado logs
tail -f logs/aresitos.log

# Estado procesos
ps aux | grep python
```

### **Indicadores Salud Sistema**
- ✅ **Todas herramientas**: Disponibles y funcionales
- ✅ **Bases datos**: Creadas y accesibles
- ✅ **Permisos**: Configurados correctamente
- ✅ **Interfaz**: 8 pestañas cargando sin errores
- ✅ **Logs**: Generándose en directorio logs/

## 🚀 **Primer Uso Recomendado**

### **Flujo Inicial**
1. **Verificar entorno**: Dashboard → Métricas sistema OK
2. **Test básico**: Escaneo → IP: 127.0.0.1 → "Escanear Sistema"
3. **Configurar FIM**: FIM → "Crear Baseline" → "Iniciar Monitoreo"
4. **Activar SIEM**: SIEM → "Iniciar Monitoreo" → Dashboard eventos
5. **Explorar**: Wordlists, Reportes, Auditoría según necesidades

---

*Guía instalación ARESITOS v2.0 - DogSoulDev*
- `binwalk` - Firmware analysis
- `sleuthkit` - File system analysis
- `foremost` - File carving
- `exiftool` - Metadata extraction

#### Antimalware
- `clamav` - Antivirus engine
- `yara` - Pattern matching

#### Monitoreo
- `inotify-tools` - File monitoring
- `pspy` - Process monitoring

#### Auditoría
- `chkrootkit` - Rootkit detector
- `rkhunter` - Rootkit hunter

### Configuración Automática
```bash
# Actualizar repositorios
apt update && apt upgrade -y

# Instalar herramientas faltantes
apt install -y nmap masscan gobuster nuclei ffuf
apt install -y volatility3 binwalk sleuthkit foremost exiftool
apt install -y clamav clamav-daemon yara
apt install -y inotify-tools
apt install -y chkrootkit rkhunter

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
# Instalación completa
git clone [repo] && cd Ares-Aegis
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
