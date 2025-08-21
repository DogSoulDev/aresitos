![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0 🛡️
**Suite Avanzada de Ciberseguridad para Kali Linux - Zero Dependencies**

Suite integral de ciberseguridad con **arquitectura 100% Python stdlib** sin dependencias externas. Combina escaneado avanzado, monitoreo FIM, análisis SIEM, detección de malware y cuarentena automática en interfaz moderna con tema Burp Suite.

## 🚀 **Funcionalidades Principales**

### 🔍 **Escaneador Inteligente**
- **50 puertos críticos**: SSH, RDP, SMB, bases de datos, servicios web
- **Procesos sospechosos**: Backdoors, rootkits, miners, shells inversas
- **Análisis DNS**: Túneles sospechosos y dominios maliciosos
- **Clasificación automática**: CRÍTICO/ALTO/MEDIO/BAJO

### 🛡️ **FIM (File Integrity Monitoring)**
- **Monitoreo tiempo real**: /etc/passwd, /etc/shadow, sudoers, configuraciones críticas
- **Herramientas integradas**: LinPEAS, chkrootkit, auditd
- **Base datos SQLite**: Histórico completo de cambios
- **Alertas inmediatas**: Modificaciones no autorizadas

### 🔐 **SIEM Avanzado**
- **Correlación eventos**: Análisis patrones entre FIM, Escaneador, Cuarentena
- **Dashboard dinámico**: CPU, RAM, red, amenazas en tiempo real
- **Logs centralizados**: Sistema completo con rotación automática
- **Detección anomalías**: Algoritmos nativos comportamientos sospechosos

### 🦠 **Cuarentena Automática**
- **Análisis malware**: ClamAV, YARA, Binwalk integrados
- **Respuesta inmediata**: Aislamiento automático amenazas críticas
- **Base datos**: Metadatos completos y preservación evidencia forense
- **Restauración segura**: Sistema recuperación falsos positivos

## ⚡ **Instalación Zero-Config**

```bash
# Crear carpeta Ares y clonar repositorio dentro
mkdir -p ~/Ares && cd ~/Ares
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Dar permisos de ejecución a scripts críticos
chmod +x configurar_kali.sh
chmod +x verificacion_final.py
find . -name "*.py" -exec chmod +x {} \;

# Configurar y ejecutar automáticamente
sudo ./configurar_kali.sh && python3 main.py
```

**Compatibilidad**: Kali 2024.x+, Parrot Security, BlackArch, Ubuntu 22.04+

## 🏗️ **Arquitectura Técnica**

### **🎯 Stack 100% Python Stdlib**
- **Core**: tkinter, subprocess, sqlite3, hashlib, os, logging
- **Herramientas Kali**: nmap, netstat, LinPEAS, ClamAV via subprocess
- **Sin vulnerabilidades externas**: Superficie ataque mínima
- **52 archivos verificados**: 0 errores, arquitectura MVC sólida

### **📊 Métricas de Calidad**
- **Controladores**: 15 archivos (lógica negocio)
- **Modelos**: 19 archivos (datos y persistencia) 
- **Vistas**: 12 archivos (interfaz gráfica Burp theme)
- **Utils**: 4 archivos (utilidades sistema)
- **Errores código**: 0 ✅ | **Duplicaciones**: 0 ✅ | **Stdlib**: 100% ✅

## 📖 **Uso Rápido**

```bash
# Desarrollo en Windows/Linux no-Kali
python3 main.py --dev

# Producción en Kali Linux
python3 main.py
```

### **🎯 Flujo Recomendado**
1. **Dashboard** → Verificar métricas sistema
2. **Escaneo** → IP objetivo → "Escanear Sistema" (automático)
3. **FIM** → "Crear Baseline" → "Iniciar Monitoreo"
4. **SIEM** → "Iniciar Monitoreo" → Correlación eventos tiempo real

##  **Estructura MVC**

```
Aresitos/
├── main.py                         # 🚀 Punto entrada
├── configurar_kali.sh              # ⚙️ Setup automático
├── aresitos/
│   ├── controlador/                # 15 controladores MVC
│   ├── modelo/                     # 19 modelos datos
│   ├── vista/                      # 12 vistas GUI
│   └── utils/                      # 4 utilidades sistema
├── data/                           # SQLite DBs + wordlists
└── documentacion/                  # Guías técnicas
```

## ⚖️ **Licencia & Ética**

**Open Source License** con atribución obligatoria:
- ✅ **Uso libre**: Personal, comercial, educativo, investigación
- ✅ **Modificación permitida**: Fork, personalización, integración  
- ✅ **Distribución libre**: Compartir, redistribuir, vender
- ⚠️ **Atribución obligatoria**: Mencionar a **DogSoulDev** y repositorio oficial

**⚠️ USO ÉTICO ÚNICAMENTE**: Sistemas propios, pentesting autorizado, investigación educativa. Prohibido actividades ilegales.

## 🔗 **Enlaces**
- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Contacto**: dogsouldev@protonmail.com

---

## En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos, DogSoulDev

---

*Desarrollado por DogSoulDev para la comunidad de ciberseguridad*