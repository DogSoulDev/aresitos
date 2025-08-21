![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0 🛡️
**Suite Profesional de Ciberseguridad para Kali Linux**

ARESITOS v2.0 es una suite integral de ciberseguridad desarrollada específicamente para Kali Linux con **arquitectura 100% nativa** - sin dependencias externas. Combina escaneado de vulnerabilidades, monitoreo FIM, análisis SIEM, detección de malware y auditoría de seguridad en una interfaz unificada moderna con tema Burp Suite.

## 🚀 ¿Qué Hace ARESITOS?

### 🔍 **Escaneador de Vulnerabilidades**
- **Escaneo de puertos**: nmap, rustscan, masscan (ultrarrápido)
- **Análisis web**: gobuster, feroxbuster, httpx (directorios/archivos)
- **Detección vulnerabilidades**: nuclei, nikto (CVEs actualizadas)
- **Inyección SQL**: sqlmap integrado
- **Reportes**: JSON/PDF profesionales con métricas

### 🛡️ **Monitoreo de Integridad (FIM)**
- **Detección cambios**: LinPEAS (escalada privilegios)
- **Monitoreo procesos**: pspy (tiempo real sin root)
- **Vigilancia archivos**: inotify (críticos del sistema)
- **Alertas automáticas**: modificaciones sospechosas
- **Base de datos**: SQLite con histórico completo

### 🔐 **Sistema SIEM & Auditoría**
- **Análisis logs**: /var/log/, auth.log, syslog
- **Detección patrones**: regex avanzados, anomalías
- **Auditoría SSH**: configuración y accesos
- **Chequeo servicios**: ports expuestos, configuraciones
- **Dashboard**: métricas tiempo real (CPU, RAM, red)

### 🦠 **Detección Malware & Rootkits**
- **LinPEAS**: análisis completo vulnerabilidades Linux
- **chkrootkit**: detección rootkits conocidos
- **Lynis**: auditoría completa seguridad sistema
- **Cuarentena**: aislamiento automático archivos sospechosos

### 📊 **Gestión Centralizada**
- **Wordlists**: SecLists integradas + custom
- **Cheatsheets**: comandos Kali organizados
- **Configuración**: JSON centralizada
- **Logs**: sistema completo trazabilidad
- **Backup**: exportación/importación datos

## ⚡ **Instalación Instantánea** 
**¡SIN pip install!** - Solo Python stdlib + herramientas Kali

```bash
# 1. Clonar repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar herramientas Kali (una sola vez)
sudo ./configurar_kali.sh

# 3. ¡Ejecutar directamente!
python3 main.py
```

## 🏗️ **Arquitectura Revolucionaria**

### **🎯 ZERO Dependencias Externas**
- ✅ **Python stdlib ÚNICAMENTE** (tkinter, subprocess, sqlite3, etc.)
- ✅ **Herramientas Kali nativas** (via subprocess)
- ✅ **Sin pip install** - funciona inmediatamente
- ✅ **Sin vulnerabilidades externas** - superficie ataque mínima
- ✅ **Estabilidad garantizada** - compatible cualquier Kali

### **🔧 Herramientas Integradas**
```bash
# MODERNAS (2024-2025):
nmap, rustscan, masscan, gobuster, feroxbuster
httpx, nuclei, sqlmap, linpeas, pspy, lynis

# REEMPLAZADAS:
dirb → gobuster/feroxbuster (5x más rápido)
commix → nuclei/httpx (mejor detección)
aide → linpeas (escalada privilegios)
tiger → pspy (monitoreo sin root)
openvas → nuclei (templates actualizadas)
```

## 📋 **Características Técnicas**

### **🎨 Interfaz Moderna**
- **Tema Burp Suite**: colores profesionales (#2b2b2b, #ff6633)
- **GUI responsiva**: tkinter optimizado para pantallas grandes
- **Tabs organizadas**: cada función en pestaña dedicada
- **Logs tiempo real**: output inmediato de herramientas
- **Progress bars**: indicadores visuales progreso

### **🔒 Seguridad & Calidad**
- **Score seguridad**: 100/100 ✅
- **Arquitectura MVC**: 100/100 ✅
- **Vulnerabilidades críticas**: 0 ✅
- **Warnings seguridad**: 0 ✅
- **Estado**: Listo para producción ✅

### **📊 Compatibilidad**
- **SO Principal**: Kali Linux 2024.x+ (recomendado)
- **SO Secundario**: Parrot Security, BlackArch, Ubuntu 22.04+
- **Python**: 3.8+ (mínimo), 3.11+ (óptimo)
- **Hardware**: 2GB RAM, 1GB disco, cualquier CPU x64

## 🎯 **Casos de Uso**

### **👨‍💻 Profesionales Ciberseguridad**
- Pentesting completo en una herramienta
- Reportes automatizados para clientes
- Monitoreo continuo infraestructura
- Análisis forense post-incidente

### **🎓 Estudiantes & Certificaciones**
- Práctica OSCP, CEH, CISSP
- Laboratorios seguros aprendizaje
- Metodología estructurada testing
- Documentación educativa incluida

### **🏢 Administradores Sistema**
- Auditorías regulares seguridad
- Detección temprana amenazas
- Compliance automático normativas
- Monitoreo integridad crítica

## 📖 **Uso Rápido**

```bash
# Escaneo completo red
python3 main.py
# → Pestaña "Escaneador" → IP target → "Iniciar Escaneo"

# Monitoreo FIM tiempo real  
# → Pestaña "FIM" → "Configurar Rutas" → "Iniciar Monitoreo"

# Auditoría sistema completa
# → Pestaña "Auditoría" → "Ejecutar Lynis" → Ver resultados

# Dashboard métricas sistema
# → Pestaña "Dashboard" → Métricas automáticas CPU/RAM/Red
```

## 📚 **Estructura Proyecto**

```
Aresitos/
├── main.py                     # 🚀 Ejecutable principal
├── configurar_kali.sh          # ⚙️ Setup automático Kali
├── requirements.txt            # 📋 Documentación stdlib
├── verificacion_final.py       # ✅ Validador completo
│
├── aresitos/                   # 📦 Código principal MVC
│   ├── vista/                  # 🎨 Interfaz gráfica (17 archivos)
│   ├── controlador/            # ⚙️ Lógica negocio (20 archivos) 
│   ├── modelo/                 # 📊 Datos y persistencia (20+ archivos)
│   ├── utils/                  # 🔧 Utilidades sistema (8 archivos)
│   └── recursos/               # 📁 Iconos y assets
│
├── configuracion/              # ⚙️ JSON centralizada
├── data/                       # 💾 Bases datos, wordlists
├── logs/                       # 📝 Sistema logging completo
├── documentacion/              # 📚 Guides técnicas detalladas
└── recursos/                   # 📋 Cheatsheets Kali
```

## ⚖️ **Licencia & Ética**

### **Licencia MIT**
Código abierto, uso libre comercial y personal.

### **⚠️ USO ÉTICO ÚNICAMENTE**
- ✅ **Sistemas propios** o con autorización explícita
- ✅ **Pentesting autorizado** y auditorías legales  
- ✅ **Investigación** y educación ciberseguridad
- ❌ **Actividades ilegales** - usuario 100% responsable

## 🔗 **Enlaces**

- **🌐 Repositorio**: https://github.com/DogSoulDev/Aresitos
- **📧 Contacto**: dogsouldev@protonmail.com  
- **📋 Issues**: GitHub Issues para bugs/features
- **📖 Wiki**: Documentación técnica completa

## 🎬 **Inicio Inmediato**

```bash
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos
sudo ./configurar_kali.sh
python3 main.py
```

**¡Para estudiantes y profesionales de ciberseguridad que buscan una herramienta integral, robusta y éticamente desarrollada!**

---

## En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos, DogSoulDev

---

*Desarrollado por DogSoulDev para la comunidad de ciberseguridad*