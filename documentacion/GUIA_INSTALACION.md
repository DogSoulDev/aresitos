# ARESITOS v2.0 - Guía de Instalación y Verificación

## 🚀 INSTALACIÓN RÁPIDA

### Requisitos
- **SO**: Kali Linux 2025 (EXCLUSIVO)
- **Python**: 3.9+ (incluido en Kali)
- **RAM**: 4GB mínimo, 8GB recomendado
- **Disco**: 20GB libres

### Instalación Automática
```bash
# 1. Clonar repositorio
git clone https://github.com/usuario/Ares-Aegis.git
cd Ares-Aegis

# 2. Configurar Kali (ejecutar como root)
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# 3. Verificar instalación
python verificacion_final.py

# 4. Ejecutar ARESITOS
python main.py
```

## 🔧 CONFIGURACIÓN INICIAL

### Herramientas Kali Verificadas
El script `configurar_kali.sh` instala y verifica:

#### Escaneadores
- `nmap` - Network mapper
- `masscan` - High-speed port scanner
- `gobuster` - Directory/file brute-forcer
- `nuclei` - Vulnerability scanner
- `ffuf` - Web fuzzer

#### Forense
- `volatility3` - Memory analysis
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
