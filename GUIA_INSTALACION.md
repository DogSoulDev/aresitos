# 📖 GUÍA DE INSTALACIÓN ARESITOS v3.0

## 🚀 **INSTALACIÓN RÁPIDA (30 segundos)**

### ⚡ **Método Automático Recomendado**
```bash
# Clonar y ejecutar configuración automática
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

### 🔧 **Método Manual Paso a Paso**
```bash
# 1. Clonar el repositorio
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos

# 2. Configurar entorno Kali
sudo ./configurar_kali.sh

# 3. Verificar instalación
python3 verificacion_final.py

# 4. Iniciar ARESITOS
python3 main.py
```

---

## 🔍 **REQUISITOS DEL SISTEMA**

### ✅ **Sistemas Soportados Oficialmente**
- **Kali Linux 2025** - Soporte completo optimizado ⭐
- **Kali Linux 2024** - Compatibilidad total verificada
- **Parrot Security OS** - Soporte nativo para todas las funciones
- **BlackArch Linux** - Funciones básicas (configuración manual)

### ⚠️ **Sistemas con Soporte Limitado**
- **Ubuntu/Debian** - Modo desarrollo únicamente
- **Otros Linux** - Funcionalidad básica sin garantías

### ❌ **Sistemas No Soportados**
- **Windows** - No compatible
- **macOS** - No compatible
- **Android/iOS** - No compatible

---

## 🛠️ **ESPECIFICACIONES TÉCNICAS**

### **Hardware Mínimo:**
- **RAM**: 4GB (8GB recomendado para escaneos masivos)
- **CPU**: Dual-core 2.0GHz (Quad-core recomendado)
- **Almacenamiento**: 2GB libres (incluye herramientas y bases de datos)
- **Red**: Interfaz de red funcional (ethernet/wifi)

### **Software Requerido:**
- **Python**: 3.9+ (incluido en Kali por defecto)
- **Sistema Base**: Kali Linux 2024/2025
- **Permisos**: sudo para configuración inicial
- **Internet**: Opcional (para actualizaciones de templates nuclei)

---

## 📦 **PROCESO DE INSTALACIÓN DETALLADO**

### **Paso 1: Preparación del Sistema**
```bash
# Actualizar sistema base (opcional pero recomendado)
sudo apt update && sudo apt upgrade -y

# Verificar Python y Git
python3 --version  # Debe ser 3.9+
git --version      # Debe estar instalado
```

### **Paso 2: Descarga del Proyecto**
```bash
# Opción A: Descarga via Git (recomendado)
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos

# Opción B: Descarga manual (si no tienes git)
wget https://github.com/DogSoulDev/aresitos/archive/refs/heads/master.zip
unzip master.zip
cd aresitos-master
```

### **Paso 3: Configuración Automática**
```bash
# Hacer ejecutable el configurador
chmod +x configurar_kali.sh

# Ejecutar configuración automática (requiere sudo)
sudo ./configurar_kali.sh

# El script instalará automáticamente:
# - Herramientas de escaneado (nmap, masscan, rustscan, nuclei)
# - Herramientas web (gobuster, feroxbuster, curl)
# - Herramientas de análisis (sqlmap, commix, nikto)
# - Configurará permisos especiales
# - Establecerá sudo sin contraseña para herramientas específicas
```

### **Paso 4: Verificación de la Instalación**
```bash
# Verificar que todo esté configurado correctamente
python3 verificacion_final.py

# El script verificará:
# - Todas las herramientas están instaladas
# - Los permisos están configurados
# - Las bases de datos están actualizadas
# - Python funciona correctamente
```

### **Paso 5: Primer Inicio**
```bash
# Iniciar ARESITOS
python3 main.py

# En el primer inicio:
# 1. Aparecerá la pantalla de login/verificación
# 2. Verificará automáticamente las herramientas
# 3. Te permitirá instalar herramientas faltantes si es necesario
# 4. Configurará la sesión sudo persistente
```

---

## 🔧 **SOLUCIÓN DE PROBLEMAS COMUNES**

### **Error: "Permiso denegado" al ejecutar configurar_kali.sh**
```bash
# Solución: Hacer el archivo ejecutable
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh
```

### **Error: "sudo: command not found"**
```bash
# Solución: Instalar sudo (en algunos sistemas mínimos)
su -
apt install sudo
usermod -aG sudo $USER
exit
# Reiniciar sesión
```

### **Error: "Herramientas no encontradas" en verificacion_final.py**
```bash
# Solución: Ejecutar configuración nuevamente
sudo ./configurar_kali.sh

# O instalar herramientas manualmente:
sudo apt update
sudo apt install nmap masscan gobuster feroxbuster curl sqlmap
```

### **Error: "ModuleNotFoundError: No module named 'tkinter'"**
```bash
# Solución: Instalar tkinter (debería estar por defecto en Kali)
sudo apt install python3-tk
```

### **Error: Pantalla en blanco o interface no aparece**
```bash
# Solución: Verificar display (si estás usando SSH)
export DISPLAY=:0.0

# O usar X11 forwarding
ssh -X usuario@ip_kali
```

### **Error: "Template updates failed" para nuclei**
```bash
# Solución: Actualizar templates manualmente
sudo nuclei -update-templates

# O sin sudo (como usuario normal)
nuclei -update-templates
```

---

## 🔐 **CONFIGURACIÓN DE PERMISOS**

### **Permisos Automáticos Configurados:**
El script `configurar_kali.sh` automáticamente configura:

```bash
# Permisos CAP_NET_RAW para escaneos SYN
sudo setcap cap_net_raw+epi /usr/bin/nmap
sudo setcap cap_net_raw+epi /usr/bin/masscan

# Sudo sin contraseña para herramientas específicas
# (Ver /etc/sudoers.d/aresitos-escaneador-v3)

# Permisos de grupo para captura de paquetes
sudo usermod -a -G wireshark $USER
```

### **Verificar Permisos Manualmente:**
```bash
# Verificar permisos CAP_NET_RAW
getcap /usr/bin/nmap
getcap /usr/bin/masscan

# Verificar configuración sudo
sudo -l | grep nmap

# Verificar grupos de usuario
groups
```

---

## 🚀 **OPTIMIZACIONES AVANZADAS**

### **Para Sistemas con Recursos Limitados:**
```bash
# Configurar ARESITOS para usar menos memoria
export ARESITOS_LOW_MEMORY=1
python3 main.py

# Deshabilitar actualizaciones automáticas de nuclei
export ARESITOS_NO_AUTO_UPDATE=1
```

### **Para Escaneos Masivos:**
```bash
# Configurar para escaneos de redes grandes
export ARESITOS_SCANNER_THREADS=10
export ARESITOS_SCANNER_TIMEOUT=300

# Usar SSD para mejorar rendimiento de base de datos
# (Mover directorio data/ a SSD si está disponible)
```

### **Para Entornos de Desarrollo:**
```bash
# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev

# Modo verbose para debugging
python3 main.py --verbose

# Modo debug completo
python3 main.py --debug
```

---

## 📋 **VERIFICACIÓN POST-INSTALACIÓN**

### **Checklist de Verificación:**
- [ ] El comando `python3 main.py` inicia ARESITOS sin errores
- [ ] La pantalla de login aparece correctamente
- [ ] La verificación de herramientas pasa sin errores críticos
- [ ] Puedes acceder al dashboard principal
- [ ] El escaneador puede ejecutar un escaneo básico
- [ ] Los reportes se generan correctamente
- [ ] No hay errores en el terminal/logs

### **Comando de Verificación Completa:**
```bash
# Ejecutar suite de verificación completa
python3 verificacion_final.py --complete

# Esto verificará:
# - Todas las herramientas instaladas
# - Permisos configurados correctamente
# - Bases de datos funcionales
# - Interfaces gráficas operativas
# - Módulos Python importables
```

---

## 🆘 **SOPORTE Y AYUDA**

### **Recursos de Documentación:**
- **Manual Técnico**: `/documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- **Guía de Desarrollo**: `/documentacion/ARQUITECTURA_DESARROLLO.md`
- **Troubleshooting**: Este documento
- **Changelog**: `/CHANGELOG.md`

### **Contacto para Soporte:**
- **GitHub Issues**: https://github.com/DogSoulDev/aresitos/issues
- **Email**: dogsouldev@protonmail.com
- **Documentación Online**: GitHub Wiki (próximamente)

### **Información de Sistema para Reportes:**
```bash
# Información útil para reportar problemas:
uname -a                    # Información del sistema
python3 --version          # Versión de Python
cat /etc/os-release        # Distribución exacta
git log --oneline -1       # Versión de ARESITOS
python3 -c "import sys; print(sys.path)"  # Rutas de Python
```

---

*Guía de instalación actualizada: 24 de Agosto de 2025*  
*Versión: ARESITOS v3.0.0*  
*Autor: DogSoulDev*
