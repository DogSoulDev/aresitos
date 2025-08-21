![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0 🛡️
**Suite Avanzada de Ciberseguridad para Kali Linux - Zero Dependencies**

ARESITOS v2.0 es una suite integral de ciberseguridad desarrollada con **arquitectura 100% Python nativo** sin dependencias externas. Combina escaneado avanzado, monitoreo FIM, análisis SIEM en tiempo real, detección de malware y cuarentena automática en una interfaz moderna con tema Burp Suite. **55 archivos Python optimizados, 0 errores, funcionalidades profesionales**.

## 🚀 **Funcionalidades Técnicas Avanzadas**

### 🔍 **Escaneador Inteligente - 6 Fases de Análisis**
- **Puertos críticos**: Monitoreo 50 puertos más comunes para ciberataques (SSH, RDP, SMB, bases de datos)
- **Procesos sospechosos**: Detección automática backdoors, rootkits, miners, shells inversas
- **DNS tunneling**: Análisis conexiones sospechosas y dominios maliciosos
- **Módulos PAM**: Verificación integridad autenticación y configuraciones seguras
- **Herramientas nativas**: nmap, netstat, ss, ps - compatibilidad garantizada
- **Clasificación riesgo**: CRÍTICO/ALTO/MEDIO con análisis automático

### 🛡️ **FIM (File Integrity Monitoring) - Tiempo Real**
- **Monitoreo continuo**: Archivos críticos sistema (/etc/passwd, /etc/shadow, sudoers)
- **Integración SIEM**: Eventos automáticos amenazas detectadas
- **Herramientas Kali**: LinPEAS, chkrootkit, auditd para análisis profundo
- **Base de datos**: SQLite fim_kali2025.db con histórico completo
- **Alertas inmediatas**: Modificaciones no autorizadas en tiempo real

### 🔐 **SIEM Avanzado - Análisis Inteligente**
- **Correlación eventos**: Análisis patrones tiempo real entre FIM, Escaneador, Cuarentena
- **Detección anomalías**: Algoritmos nativos identificación comportamientos sospechosos
- **Logs centralizados**: Sistema logging completo con rotación automática
- **Dashboard dinámico**: Métricas CPU, RAM, red, amenazas en vivo
- **Referencias cruzadas**: Integración total entre todos los controladores

### 🦠 **Cuarentena Automática - Respuesta Inmediata**
- **Base datos**: cuarentena_kali2025.db con metadatos completos amenazas
- **Análisis malware**: ClamAV, YARA, Binwalk integrados para detección
- **Respuesta automática**: Aislamiento inmediato amenazas críticas y altas
- **Restauración**: Sistema seguro recuperación archivos falsos positivos
- **Forense**: Preservación evidencia para análisis posterior

## ⚡ **Instalación Zero-Config** 
**¡100% Python stdlib!** - Sin pip, sin dependencias, sin problemas

```bash
# 1. Clonar repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar permisos Kali (automático)
sudo ./configurar_kali.sh

# 3. ¡Ejecutar inmediatamente!
python3 main.py
```

**🎯 Compatibilidad Total**: Kali 2024.x+, Parrot Security, BlackArch, Ubuntu 22.04+

## 🏗️ **Arquitectura Técnica - MVC Optimizada**

### **🎯 ZERO Dependencies - 100% Nativo**
- ✅ **Python stdlib EXCLUSIVAMENTE** (tkinter, subprocess, sqlite3, hashlib, os, logging)
- ✅ **Herramientas Kali integradas** via subprocess con validación
- ✅ **Sin vulnerabilidades externas** - superficie de ataque mínima
- ✅ **Estabilidad garantizada** - compatible con cualquier versión Kali
- ✅ **55 archivos verificados** - 0 errores, 0 duplicaciones problemáticas

### **🔧 Stack Tecnológico**
```python
# CORE SYSTEM:
- Python 3.8+ (stdlib únicamente)
- SQLite3 (bases de datos locales)
- Tkinter (interfaz gráfica nativa)
- Subprocess (integración herramientas)

# HERRAMIENTAS KALI INTEGRADAS:
- nmap, netstat, ss, ps (escaneo/monitoreo)
- LinPEAS, chkrootkit, lynis (auditoría)
- ClamAV, YARA, Binwalk (malware)
- auditd, systemctl (servicios)
```

### **📊 Métricas de Calidad Verificadas**
- **Archivos Python**: 55 (16 controladores, 20 modelos, 13 vistas, 6 utils)
- **Errores código**: 0 ✅
- **Duplicaciones**: 0 problemáticas ✅  
- **Restricciones**: 100% cumplidas ✅
- **Arquitectura MVC**: Correctamente implementada ✅

## 📋 **Especificaciones Técnicas**

### **🎨 Interfaz Profesional**
- **Tema Burp Suite**: Esquema colores profesional (#2b2b2b, #ff6633, #1e1e1e)
- **GUI responsiva**: Tkinter optimizado con componentes personalizados
- **Navegación intuitiva**: Pestañas organizadas por funcionalidad
- **Output tiempo real**: Logs y resultados inmediatos de herramientas
- **Indicadores visuales**: Progress bars y estados de operación

### **🔒 Seguridad y Rendimiento**
- **Validación entrada**: Sanitización completa inputs usuario
- **Manejo errores**: Try-catch exhaustivo con logging
- **Permisos granulares**: Validación sudo/root donde necesario
- **Concurrencia**: Threading para operaciones no bloqueantes
- **Memoria optimizada**: Gestión eficiente recursos sistema

### **🎯 Detección Avanzada de Amenazas**
```python
# PUERTOS CRÍTICOS MONITOREADOS (50):
SSH(22), FTP(21), Telnet(23), SMTP(25), HTTP(80), HTTPS(443)
SMB(445), RDP(3389), MySQL(3306), PostgreSQL(5432), Redis(6379)
MongoDB(27017), Elasticsearch(9200), Docker(2375), VNC(5900)
# + 35 puertos adicionales de alto riesgo

# PROCESOS SOSPECHOSOS:
backdoor, rootkit, miner, cryptojack, netcat, reverse shell
# Detección automática con análisis de argumentos

# MONITOREO DNS:
Túneles DNS, dominios sospechosos, conexiones C&C
# Análisis tráfico saliente no autorizado
```

## 🎯 **Casos de Uso Profesionales**

### **👨‍💻 Pentesting y Red Team**
- **Reconocimiento automatizado**: Escaneo completo infraestructura objetivo
- **Monitoreo persistencia**: Detección temprana contramedidas blue team  
- **Análisis post-explotación**: Verificación integridad y detección artefactos
- **Documentación automática**: Logs detallados para informes profesionales

### **🛡️ Blue Team y SOC**
- **Detección amenazas**: Monitoreo continuo 50 puertos críticos + procesos
- **Respuesta automática**: Cuarentena inmediata amenazas críticas detectadas
- **Análisis forense**: Base de datos completa eventos de seguridad
- **Dashboards operativos**: Métricas tiempo real para NOC/SOC

### **🎓 Educación y Certificaciones**  
- **OSCP/CEH/CISSP**: Metodología estructurada testing penetración
- **Laboratorios seguros**: Entorno aislado para práctica ética
- **Casos reales**: Simulación escenarios ciberataques comunes
- **Documentación educativa**: Cheatsheets y guías técnicas incluidas

## 📖 **Comandos Esenciales**

```bash
# ⚡ INICIO RÁPIDO
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos && sudo ./configurar_kali.sh && python3 main.py

# 🔍 ESCANEO OBJETIVO
# GUI → Pestaña "Escaneador" → IP: 192.168.1.100 → "Escanear Sistema"
# Automático: 50 puertos críticos + procesos + DNS + PAM

# 🛡️ MONITOREO FIM  
# GUI → Pestaña "FIM" → "Crear Baseline" → "Iniciar Monitoreo"
# Detecta: modificaciones /etc/, nuevos procesos, cambios permisos

# 🔐 ANÁLISIS SIEM
# GUI → Pestaña "SIEM" → "Iniciar Monitoreo" → Dashboard automático
# Correlaciona: eventos FIM + Escaneador + Cuarentena en tiempo real

# 🦠 AUDITORÍA COMPLETA
# GUI → Pestaña "Auditoría" → "Ejecutar Lynis" → Reporte completo
# Incluye: configuración SSH, servicios expuestos, permisos críticos

# 📊 MÉTRICAS SISTEMA
# GUI → Pestaña "Dashboard" → Actualización automática cada 30s
# Monitorea: CPU, RAM, red, conexiones activas, procesos top
```

## 📚 **Estructura del Proyecto - MVC Profesional**

```
Aresitos/                           # 📦 Proyecto principal (55 archivos Python)
├── main.py                         # 🚀 Punto entrada aplicación
├── configurar_kali.sh              # ⚙️ Setup automático permisos Kali
├── verificacion_final.py           # ✅ Validador integridad código
│
├── aresitos/                       # � Core MVC Architecture
│   ├── controlador/                # ⚙️ Lógica negocio (16 archivos)
│   │   ├── controlador_escaneador_cuarentena.py    # 🔍 Escaneador integrado
│   │   ├── controlador_fim.py      # 🛡️ File Integrity Monitoring  
│   │   ├── controlador_siem_nuevo.py              # 🔐 Security Event Management
│   │   ├── controlador_principal_nuevo.py         # 🎯 Coordinador principal
│   │   └── ...                     # + 12 controladores especializados
│   │
│   ├── modelo/                     # 📊 Datos y persistencia (20 archivos)
│   │   ├── modelo_escaneador_avanzado_real.py     # 🔍 Motor escaneado
│   │   ├── modelo_siem.py          # � Análisis eventos seguridad
│   │   ├── modelo_fim.py           # 🛡️ Monitoreo integridad archivos
│   │   ├── modelo_cuarentena_kali2025.py          # 🦠 Gestión amenazas
│   │   └── ...                     # + 16 modelos datos
│   │
│   ├── vista/                      # 🎨 Interfaz gráfica (13 archivos)
│   │   ├── vista_principal.py      # 🏠 Ventana principal + tema Burp
│   │   ├── vista_escaneo.py        # 🔍 GUI escaneador
│   │   ├── vista_fim.py            # 🛡️ GUI monitoreo FIM
│   │   ├── vista_siem.py           # 🔐 GUI análisis SIEM
│   │   └── ...                     # + 9 vistas especializadas
│   │
│   └── utils/                      # 🔧 Utilidades sistema (6 archivos)
│       ├── gestor_permisos.py      # 🔐 Validación sudo/root
│       ├── verificacion_permisos.py # ✅ Chequeo herramientas Kali
│       └── ...                     # + 4 utilities
│
├── configuracion/                  # ⚙️ JSON configuración centralizada
│   ├── aresitos_config_kali.json   # 🔧 Configuración Kali optimizada
│   └── textos_castellano_corregido.json # 🌐 Localización español
│
├── data/                           # 💾 Bases datos y recursos
│   ├── cuarentena_kali2025.db      # 🦠 BD amenazas cuarentena
│   ├── fim_kali2025.db             # 🛡️ BD monitoreo integridad
│   ├── wordlists/                  # 📋 Diccionarios pentesting
│   └── cheatsheets/                # 📚 Comandos Kali organizados
│
├── logs/                           # 📝 Sistema logging completo
└── documentacion/                  # � Guides técnicas detalladas
    ├── ARQUITECTURA_DESARROLLO.md  # 🏗️ Arquitectura técnica
    └── DOCUMENTACION_TECNICA_CONSOLIDADA.md # 📋 Manual completo
```

**🎯 Métricas de Código**: 55 archivos Python, 0 errores, 0 duplicaciones, 100% stdlib

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

## 🎬 **Quick Start - Listo en 3 Comandos**

```bash
# 🚀 Instalación y ejecución inmediata
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos && sudo ./configurar_kali.sh
python3 main.py  # ✅ Sin pip install, sin dependencias, funcionando!
```

### **🎯 Primer Uso Recomendado**
1. **Verificar entorno**: Pestaña "Dashboard" → Comprobar métricas sistema
2. **Escaneo inicial**: Pestaña "Escaneador" → IP: localhost → "Escanear Sistema"  
3. **Configurar FIM**: Pestaña "FIM" → "Crear Baseline" → Monitoreo activo
4. **Activar SIEM**: Pestaña "SIEM" → "Iniciar Monitoreo" → Eventos tiempo real

**💡 Para profesionales que buscan seguridad robusta, arquitectura sólida y cumplimiento ético**

---

## En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos, DogSoulDev

---

*Desarrollado por DogSoulDev para la comunidad de ciberseguridad*