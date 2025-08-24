![ARESITOS](./aresitos/recursos/Aresitos.ico)

# ARESITOS - Sistema de Seguridad Cibernética v3.0

[![Versión](https://img.shields.io/badge/versión-v3.0%20Professional-brightgreen.svg)](https://github.com/DogSoulDev/aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC%20SOLID-orange.svg)](README.md)
[![Scanner](https://img.shields.io/badge/Scanner-Professional%20Grade-green.svg)](README.md)
[![SIEM](https://img.shields.io/badge/SIEM-Integrado-red.svg)](README.md)
[![FIM](https://img.shields.io/badge/FIM-Real%20Time-purple.svg)](README.md)

**ARESITOS v3.0** es una suite profesional de ciberseguridad con arquitectura MVC/SOLID diseñada específicamente para Kali Linux 2025. Integra escaneador de vulnerabilidades profesional, sistema SIEM en tiempo real, monitoreo FIM (File Integrity Monitoring), sistema de cuarentena inteligente y configuración automática del sistema. Desarrollado para pentesters, red teams y profesionales de ciberseguridad que requieren herramientas nativas, sin dependencias externas y completamente optimizadas.

## 🚀 **CARACTERÍSTICAS PRINCIPALES v3.0**

### 🔧 **Sistema de Configuración Automática**
- **Configuración One-Click**: Todo el sistema listo en una operación
- **Prevención Proactiva**: Elimina errores antes de que ocurran
- **Instalación Automática**: Herramientas esenciales y dependencias
- **Configuración de Servicios**: auditd, rsyslog, fail2ban automáticos
- **Permisos Inteligentes**: Corrección automática de directorios y accesos

### 🔍 **Escaneador Profesional Multi-Engine**
- **Múltiples Scanners**: nmap, masscan, rustscan con fallback inteligente
- **Detección de Vulnerabilidades**: nuclei con base CVE actualizada
- **Web Enumeration**: gobuster, ffuf, feroxbuster para discovery
- **Análisis Profundo**: Fingerprinting, correlación de servicios
- **Reportes Estructurados**: JSON/TXT con análisis de criticidad

### 🛡️ **Sistema SIEM Integrado**
- **Monitoreo Tiempo Real**: 50+ puertos críticos con alertas
- **Correlación de Eventos**: Motor de análisis comportamental
- **Threat Intelligence**: Base de datos IoCs local integrada
- **Alertas Priorizadas**: Sistema de notificaciones contextual

### 📁 **File Integrity Monitoring (FIM)**
- **Vigilancia Continua**: 60+ directorios críticos monitoreados
- **Detección de Cambios**: Checksums SHA256 para integridad
- **Alertas Inmediatas**: Notificación de modificaciones no autorizadas
- **Preservación Forense**: Evidencia digital con cadena de custodia

### 📊 **Sistema de Reportes Completo**
- **Cobertura Total**: Datos de todos los módulos ARESITOS
- **12 Parámetros**: Auditoría, wordlists, herramientas, logs, configuración
- **Múltiples Formatos**: JSON, TXT, CSV profesionales
- **Análisis Estadístico**: Métricas del sistema y operaciones

---

## ⚡ **INSTALACIÓN RÁPIDA (30 segundos)**

### 🛠️ **Método Automático - Recomendado**
```bash
# Clonar repositorio y configurar automáticamente
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

### 🔧 **Configuración Manual Avanzada**
```bash
# 1. Clonar repositorio
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos

# 2. Configurar sistema Kali
sudo ./configurar_kali.sh

# 3. Verificar instalación
python3 verificacion_final.py

# 4. Iniciar ARESITOS
python3 main.py
```

### 💻 **Modo Desarrollo (Testing)**
```bash
# Para pruebas en sistemas no-Kali (funcionalidad limitada)
python3 main.py --dev
```

---

## 🏗️ **ARQUITECTURA TÉCNICA ARESITOS v3.0**

### **Arquitectura MVC/SOLID Profesional**
```
ARESITOS v3.0/
├── 🎨 Vista (UI Layer)           - 8 interfaces especializadas
├── 🎮 Controlador (Logic)        - 6 controladores integrados
├── 💾 Modelo (Data)             - 8 modelos de datos sincronizados
├── 🔧 Utils (Infrastructure)    - Sudo manager y componentes
└── 📊 Data (Intelligence)       - Bases de conocimiento actualizadas
```

### **Principios de Diseño Implementados:**
- ✅ **Single Responsibility**: Cada clase con función específica
- ✅ **Open/Closed**: Extensible sin modificar código base
- ✅ **Liskov Substitution**: Interfaces consistentes
- ✅ **Interface Segregation**: APIs especializadas
- ✅ **Dependency Inversion**: Abstracciones robustas

### **Tecnologías Centrales:**
- 🐍 **Python 3.9+**: 100% nativo, sin dependencias externas
- 🖼️ **Tkinter**: Interfaz gráfica robusta y moderna
- 🔧 **Threading**: Operaciones asíncronas para mejor UX
- 🔐 **Subprocess**: Ejecución segura de comandos del sistema
- 💾 **JSON/SQLite**: Persistencia de datos eficiente

---

## 🖼️ **CAPTURAS DE PANTALLA**

### 1. **Sistema de Autenticación Inteligente**
![Vista Login](aresitos/recursos/vista_login.png)
*Verificación automática de herramientas y configuración de permisos*

### 2. **Configuración Automática del Sistema**
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)
*Instalación y configuración automática de herramientas esenciales*

### 3. **Centro de Operaciones Principal**
![Vista Principal](aresitos/recursos/vista_aresitos.png)
*Dashboard profesional con acceso a todos los módulos integrados*

---

## 📚 **MÓDULOS INTEGRADOS**

### 🎛️ **Dashboard**
- Monitor de sistema en tiempo real
- Métricas de red con visualización
- Estado de servicios críticos
- Terminal integrado persistente

### 🔍 **Escaneador Profesional**
- **5 Modos de Escaneo**: Integral, Avanzado, Red, Rápido, Profundo
- **Detección Automática**: Herramientas disponibles y fallback
- **Múltiples Engines**: nmap, masscan, rustscan, nuclei
- **Web Discovery**: gobuster, ffuf para enumeración
- **Exportación Avanzada**: Reportes detallados y estructurados

### 🛡️ **SIEM Tiempo Real**
- Monitoreo continuo de puertos críticos
- Detección de anomalías comportamentales
- Correlación automática de eventos
- Sistema de alertas inteligente

### 📁 **File Integrity Monitor**
- Vigilancia de directorios críticos
- Detección inmediata de cambios
- Verificación cryptográfica SHA256
- Preservación de evidencia forense

### 🔒 **Sistema de Cuarentena**
- Detección automática de malware
- Aislamiento seguro de amenazas
- Análisis de comportamiento sospechoso
- Gestión de falsos positivos

### 📊 **Generador de Reportes**
- Informes ejecutivos y técnicos
- Integración de todos los módulos
- Múltiples formatos de exportación
- Templates personalizables

### 📚 **Gestión de Inteligencia**
- Wordlists categorizadas especializadas
- Diccionarios por sector y técnica
- Base de vulnerabilidades local
- Cheatsheets integrados

### ⚙️ **Auditoría Automatizada**
- Lynis optimizado para Kali
- Chkrootkit con heurísticas avanzadas
- Análisis de configuraciones
- Recomendaciones priorizadas

---

## 🔧 **REQUISITOS Y COMPATIBILIDAD**

### **Sistemas Soportados:**
- ✅ **Kali Linux 2025** - Funcionalidad completa optimizada
- ✅ **Kali Linux 2024** - Compatibilidad total verificada
- ✅ **Parrot Security** - Soporte nativo completo
- ⚠️ **BlackArch** - Funciones básicas, configuración manual
- ⚠️ **Ubuntu/Debian** - Modo limitado para desarrollo
- ❌ **Windows/macOS** - No soportado oficialmente

### **Especificaciones Técnicas:**
- 🐍 **Python**: 3.9+ con optimizaciones async
- 💾 **RAM**: 4GB mínimo, 8GB recomendado
- 💿 **Almacenamiento**: 1GB para instalación completa
- 🌐 **Red**: Funciona offline, internet para actualizaciones
- 🔐 **Permisos**: sudo para configuración inicial
- ⚡ **Concurrencia**: Soporte para operaciones paralelas

---

## 📖 **DOCUMENTACIÓN Y SOPORTE**

### **Documentación Técnica:**
- 📚 **Manual Técnico**: `/documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- 🏗️ **Guía de Desarrollo**: `/documentacion/ARQUITECTURA_DESARROLLO.md`
- 🛡️ **Auditoría de Seguridad**: `/documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md`
- 💻 **Terminal Integrado**: `/documentacion/TERMINAL_INTEGRADO.md`

### **Repositorios y Contacto:**
- 🌐 **Repositorio Principal**: https://github.com/DogSoulDev/aresitos
- 🧪 **Repositorio de Testeos**: https://github.com/DogSoulDev/Ares-Aegis
- 🐛 **Reportar Issues**: GitHub Issues con templates
- 💌 **Email Desarrollo**: dogsouldev@protonmail.com
- 🔗 **LinkedIn**: [DogSoulDev](https://linkedin.com/in/dogsouldev)

---

## 📜 **LICENCIA Y USO ÉTICO**

### **Open Source Non-Commercial License**

#### **✅ USO PERMITIDO (GRATUITO)**
- 🎓 **Educación**: Universidades, estudiantes, investigación académica
- 🛡️ **Seguridad Personal**: Testing en sistemas propios o autorizados
- 🌐 **Open Source**: Proyectos de código abierto sin monetización
- 📚 **Aprendizaje**: Cursos, talleres, capacitación sin fines de lucro
- 🤝 **Comunidad**: Compartir conocimientos y mejoras

#### **❌ USO PROHIBIDO (COMERCIAL)**
- 💰 **Venta Directa**: No se puede vender ARESITOS o derivados
- 🏢 **Consultoría Comercial**: No usar para servicios pagos de pentesting
- 📦 **Productos Comerciales**: No incorporar en software comercial
- 💳 **Monetización**: Cursos pagos, suscripciones, licencias comerciales
- 🏪 **Servicios**: No ofrecer como SaaS o servicios managed

#### **📋 ATRIBUCIÓN OBLIGATORIA**
**TODO uso debe incluir:**
- 👨‍💻 **Creador**: DogSoulDev
- 📧 **Contacto**: dogsouldev@protonmail.com
- 🔗 **Fuente**: https://github.com/DogSoulDev/aresitos
- 📄 **Licencia**: Open Source Non-Commercial

### **🛡️ CÓDIGO DE ÉTICA**
- ✅ **Solo sistemas autorizados** - Con permiso explícito por escrito
- ✅ **Propósitos constructivos** - Mejorar la seguridad, no dañar
- ✅ **Divulgación responsable** - Reportar vulnerabilidades apropiadamente
- ❌ **Actividades ilegales** - Prohibido para hacking malicioso
- ❌ **Daño intencional** - No usar para comprometer sistemas

---

## 🐕 **DEDICATORIA ESPECIAL**

### En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.

### 🎯 **CAPACIDADES TÉCNICAS AVANZADAS v3.0**
**Suite Profesional de Seguridad con Arquitectura MVC/SOLID**

**🔍 Escaneador de Vulnerabilidades Profesional**
- **Engine Multi-Scanner**: Integración nativa nmap/masscan/rustscan con algoritmos de fallback inteligente
- **Detection Framework**: nuclei con base de datos CVE actualizada automáticamente, templates personalizados
- **Web Enumeration**: gobuster/ffuf/feroxbuster para descubrimiento de superficie de ataque
- **Intelligence Gathering**: Fingerprinting automatizado, correlación de servicios, análisis de dependencias
- **Export Engine**: Reportes estructurados JSON/TXT con análisis de criticidad y vectores de ataque

**🛡️ Sistema SIEM Integrado**
- **Real-time Monitoring**: 50+ puertos críticos con detección de anomalías comportamentales
- **Event Correlation**: Motor de correlación de eventos con machine learning básico
- **Threat Intelligence**: Base de datos de IoCs local, integración con feeds de amenazas
- **Alert Management**: Sistema de alertas priorizadas con contexto de amenaza completo

**📁 File Integrity Monitoring (FIM)**
- **Filesystem Watcher**: Monitoreo en tiempo real de 60+ directorios críticos del sistema
- **Cryptographic Hashing**: Checksums SHA256 para verificación de integridad absoluta
- **Change Detection**: Algoritmos de detección de modificaciones no autorizadas con baseline automático
- **Forensic Preservation**: Preservación de evidencia digital con cadena de custodia

---

## 🚀 **INSTALACIÓN INSTANTÁNEA (30 segundos)**

### ⚡ **Método Automático - Recomendado**
```bash
# Clonar y ejecutar configuración automática
git clone https://github.com/DogSoulDev/aresitos.git && cd aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

> **🔧 NOTA**: Si experimentas problemas con directorios duplicados, ejecuta:
> ```bash
> cd aresitos && sudo ./configurar_kali.sh
> ```
> El script ahora establece automáticamente el directorio de trabajo correcto.

> **⚠️ HERRAMIENTAS FORENSES OPCIONALES**: Si necesitas herramientas adicionales:
> ```bash
> # MÉTODO RECOMENDADO: Instalar paquete completo de forense
> sudo apt install kali-tools-forensics
> 
> # O instalar herramientas individuales (ejecutar UNO por vez):
> 
> # 1. Wireshark (análisis de tráfico)
> sudo apt install wireshark
> 
> # 2. Autopsy (forense digital)  
> sudo apt install autopsy
> 
> # 3. SleuthKit (investigación forense)
> sudo apt install sleuthkit
> ```
> **IMPORTANTE**: kali-tools-forensics incluye TODAS las herramientas forenses disponibles

### 🔧 **Método Manual - Control Total**
```bash
# 1. Descargar ARESITOS
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos

# 2. Configurar entorno Kali 2025
sudo ./configurar_kali.sh

# 3. Verificar instalación
python3 verificacion_final.py

# 4. ¡Iniciar ARESITOS v2.0!
python3 main.py
```

### 🛠️ **Modo Desarrollo (Otros Sistemas)**
```bash
# Para testing en sistemas no-Kali (funcionalidad limitada)
python3 main.py --dev
```

---

## 🖼️ **CAPTURAS DE PANTALLA DETALLADAS**

### 1. Sistema de Autenticación - Primera Impresión
![Vista Login](aresitos/recursos/vista_login.png)

**¿Qué es esta pantalla?**
La primera ventana que ves al iniciar aresitos. No es solo un login normal, es un sistema inteligente que verifica automáticamente que tu sistema Kali Linux esté configurado correctamente.

**¿Qué hace por ti?**
- **Verifica herramientas**: Comprueba que tengas instaladas más de 25 herramientas de ciberseguridad
- **Configura permisos**: Establece los permisos necesarios para usar herramientas avanzadas
- **Detecta problemas**: Si algo falta, te guía para solucionarlo automáticamente
- **Acceso seguro**: Controla quién puede usar el sistema con autenticación robusta

### 2. Vista de Herramientas - Configuración Automática
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)

**¿Qué es esta pantalla?**
Una ventana especial que aparece solo la primera vez que usas aresitos. Su trabajo es configurar automáticamente todas las herramientas de seguridad que necesitas.

**¿Qué hace por ti?**
- **Instala herramientas modernas**: nmap, nuclei, gobuster y más de 20 herramientas avanzadas
- **Configura permisos**: Te permite usar las herramientas sin escribir contraseñas constantemente
- **Actualiza bases de datos**: Descarga las últimas definiciones de vulnerabilidades
- **Prepara el entorno**: Deja todo listo para que puedas empezar a trabajar inmediatamente

### 3. Vista Principal - Centro de Comando
![Vista aresitos](aresitos/recursos/vista_aresitos.png)

**¿Qué es esta pantalla?**
El corazón de aresitos. Una vez configurado todo, esta es tu central de operaciones de ciberseguridad. Aquí tienes acceso a todas las funcionalidades del programa.

**¿Qué puedes hacer?**
- **🎯 Dashboard**: Ver el estado de tu sistema en tiempo real
- **🔍 Escaneador**: Buscar vulnerabilidades en otros sistemas o redes
- **🛡️ SIEM**: Monitorear eventos de seguridad y detectar amenazas
- **📁 FIM**: Vigilar cambios sospechosos en archivos importantes
- **🔒 Cuarentena**: Aislar archivos maliciosos de forma segura
- **📊 Reportes**: Generar informes profesionales de tus auditorías
- **📚 Gestión de Datos**: Administrar diccionarios y listas de palabras
- **⚙️ Auditoría**: Revisar la seguridad de tu propio sistema

---

## 🏗️ **ARQUITECTURA ARESITOS**

### 🔐 **Sistema de Autenticación Avanzado**
**Centro de Control de Acceso y Verificación del Sistema**

**Características Principales:**
- ✅ **Verificación automática** de herramientas Kali 2025
- ✅ **SudoManager integrado** - Sin solicitudes repetitivas de contraseña
- ✅ **Rate limiting** contra ataques de fuerza bruta
- ✅ **Configuración automática** de herramientas missing
- ✅ **Modo desarrollo** para testing en otros sistemas

**¿Cómo funciona?**
El sistema verifica automáticamente que tengas instaladas +25 herramientas críticas, configura permisos especiales y establece una sesión sudo persistente para toda la aplicación.

### ⚙️ **Configurador Inteligente de Herramientas**
**Instalación y Configuración Automática de Arsenal Completo**

**Herramientas del Escaneador Profesional v3.0:**
- 🔍 **Scanners Core**: nmap, masscan, rustscan con configuraciones optimizadas
- 🌐 **Web Discovery**: nuclei (CVE detection), gobuster, ffuf, feroxbuster
- �️ **Vulnerability**: Templates nuclei actualizados, análisis automático
- 📊 **Analysis**: Análisis de superficie de ataque, correlación de servicios
- � **Enumeration**: Detección de directorios, archivos, subdominios
- 🔑 **Intelligence**: Base de datos CVE integrada, fingerprinting avanzado

**Configuraciones Automáticas:**
- ✅ Permisos CAP_NET_RAW para escaneos SYN
- ✅ Bases de datos de vulnerabilidades actualizadas
- ✅ Wordlists y diccionarios especializados
- ✅ Templates nuclei premium y custom
- ✅ Configuración de firewall adaptativa

### 🎯 **Dashboard Profesional - Centro de Operaciones**
**Central de Comandos Unificada con Monitoreo en Tiempo Real**

#### **Módulos Integrados:**

🎛️ **Dashboard**
- Monitor de sistema en tiempo real (60s refresh)
- Métricas de red avanzadas con gráficos
- Status de servicios críticos
- Terminal integrado con historial persistent

🔍 **Escaneador Profesional v3.0**
- **5 Modos de Escaneo**: Integral, Avanzado, Red, Rápido, Profundo
- **Detección Automática**: Validación y uso de herramientas disponibles
- **Integración nuclei**: Templates actualizados, detección de CVEs
- **Escaneo Masivo**: masscan/rustscan para análisis de redes completas
- **Enumeración Web**: gobuster/ffuf para discovery de directorios
- **Exportación Avanzada**: Reportes JSON/TXT con análisis detallado
- **Fallback Inteligente**: Adaptación según herramientas instaladas

🛡️ **SIEM**
- Monitoreo de 50+ puertos críticos en tiempo real
- Correlación automática de eventos de seguridad
- Detección de anomalías comportamentales
- Alertas inteligentes con contexto completo

📁 **FIM**
- Vigilancia de 60+ directorios críticos del sistema
- Detección en tiempo real de modificaciones
- Checksums SHA256 para integridad absoluta
- Alertas inmediatas de cambios no autorizados

🔒 **Sistema de Cuarentena**
- Detección automática de malware conocido
- Aislamiento seguro preservando evidencia forense
- Análisis de comportamiento sospechoso
- Gestión de false positives inteligente

📊 **Generador de Reportes**
- Informes ejecutivos y técnicos
- Integración completa de todos los módulos
- Exportación múltiple: JSON, TXT, CSV
- Templates personalizables por industria

📚 **Gestor de Inteligencia**
- Base de datos de vulnerabilidades localizada
- Wordlists categorizadas por técnica
- Diccionarios especializados por sector
- Cheatsheets de herramientas integradas

⚙️ **Auditoría de Sistema Automatizada**
- Lynis con configuración optimizada para Kali
- Chkrootkit con heurísticas avanzadas
- Análisis de configuraciones de seguridad
- Recomendaciones priorizadas por riesgo

---

## 🔧 **INFORMACIÓN TÉCNICA AVANZADA**

### 🏗️ **Arquitectura SOLID + MVC v3.0**
```
ARESITOS v3.0 Professional Scanner/
├── 🎨 Vista (UI Layer)          - 13 interfaces especializadas + Escaneador Pro
├── 🎮 Controlador (Logic)       - 15 módulos + Controlador Escaneador Avanzado
├── 💾 Modelo (Data)            - 19 módulos + Modelos de Escaneo Profesional
├── 🔧 Utils (Infrastructure)   - Componentes + Gestión de Herramientas
└── 📊 Data (Intelligence)      - Bases de conocimiento + Templates nuclei
```

**Nuevas Características v3.0:**
- ✅ **Escaneador Modular**: 5 tipos de escaneo especializados
- ✅ **Validación Automática**: Detección inteligente de herramientas
- ✅ **Fallback System**: Adaptación según disponibilidad de tools
- ✅ **Export Engine**: Sistema avanzado de exportación de resultados
- ✅ **Progress Tracking**: Seguimiento detallado de progreso de escaneos
- ✅ **Tool Integration**: Integración nativa con arsenal Kali 2025

**Principios de Diseño:**
- ✅ **Single Responsibility**: Cada clase tiene una función específica
- ✅ **Open/Closed**: Extensible sin modificar código existente
- ✅ **Liskov Substitution**: Interfaces consistentes y predecibles
- ✅ **Interface Segregation**: APIs específicas para cada caso de uso
- ✅ **Dependency Inversion**: Abstracciones sobre implementaciones

### 💻 **Compatibilidad y Requisitos**

**Sistemas Soportados:**
- ✅ **Kali Linux 2025** - Funcionalidad completa optimizada
- ✅ **Kali Linux 2024** - Compatibilidad total verificada
- ✅ **Parrot Security** - Soporte nativo para todas las funciones
- ⚠️ **BlackArch** - Funciones básicas, configuración manual requerida
- ⚠️ **Ubuntu/Debian** - Modo limitado, ideal para desarrollo
- ❌ **Windows/macOS** - No soportado oficialmente

**Especificaciones Técnicas v3.0:**
- 🐍 **Python**: 3.9+ con optimizaciones async para escaneador
- 💾 **RAM**: 4GB mínimo, 8GB recomendado para escaneos masivos
- 💿 **Almacenamiento**: 1GB para instalación + templates nuclei
- 🌐 **Red**: Capacidad offline, internet para updates de nuclei
- 🔐 **Permisos**: CAP_NET_RAW para escaneos SYN, sudo para configuración
- ⚡ **Concurrencia**: Soporte para escaneos paralelos masivos

**Dependencias del Sistema:**
- ✅ **Librerías nativas**: Tkinter, subprocess, threading, json
- ✅ **Herramientas Kali**: Auto-instalación de arsenal completo
- ✅ **Configuración**: Automatizada 100% via configurar_kali.sh
- ❌ **PIP packages**: Zero external dependencies

---

### 🔧 **Comandos Esenciales**
```bash
# Verificar estado completo del sistema + escaneador
python3 verificacion_final.py

# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev

# Actualizar configuración + herramientas escaneador
sudo ./configurar_kali.sh --update

# Debug escaneador completo
python3 main.py --verbose --scanner-debug

# Actualizar templates nuclei
sudo nuclei -update-templates
```

---

## 📞 **SOPORTE Y COMUNIDAD**

### 📖 **Documentación Completa**
- 📚 **Manual técnico**: `/documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- 🏗️ **Guía desarrollo**: `/documentacion/ARQUITECTURA_DESARROLLO.md`
- 🛡️ **Auditoría seguridad**: `/documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md`
- 💻 **Terminal integrado**: `/documentacion/TERMINAL_INTEGRADO.md`

### 🤝 **Contacto y Contribución**
- 🌐 **Repositorio oficial**: https://github.com/DogSoulDev/aresitos
- 🐛 **Reportar issues**: GitHub Issues con templates predefinidos
- 💌 **Email desarrollo**: dogsouldev@protonmail.com
- 🔗 **LinkedIn**: [DogSoulDev](https://linkedin.com/in/dogsouldev)

---

## 📜 **LICENCIA Y USO ÉTICO**

### **Open Source Non-Commercial License**

#### **✅ USO PERMITIDO (GRATUITO)**
- 🎓 **Educación**: Universidades, estudiantes, investigación académica
- 🛡️ **Seguridad personal**: Testing en sistemas propios o autorizados
- 🌐 **Open Source**: Proyectos de código abierto sin monetización
- 📚 **Aprendizaje**: Cursos, talleres, capacitación sin fines de lucro
- 🤝 **Comunidad**: Compartir conocimientos y mejoras

#### **❌ USO PROHIBIDO (COMERCIAL)**
- 💰 **Venta directa**: No se puede vender ARESITOS o derivados
- 🏢 **Consultoría comercial**: No usar para servicios pagos de pentesting
- 📦 **Productos comerciales**: No incorporar en software comercial
- 💳 **Monetización**: Cursos pagos, suscripciones, licencias comerciales
- 🏪 **Servicios**: No ofrecer como SaaS o servicios managed

#### **📋 ATRIBUCIÓN OBLIGATORIA**
**TODO uso debe incluir:**
- 👨‍💻 **Creador**: DogSoulDev
- 📧 **Contacto**: dogsouldev@protonmail.com
- 🔗 **Fuente**: https://github.com/DogSoulDev/aresitos
- 📄 **Licencia**: Open Source Non-Commercial

### **🛡️ CÓDIGO DE ÉTICA**
- ✅ **Solo sistemas autorizados** - Con permiso explícito por escrito
- ✅ **Propósitos constructivos** - Mejorar la seguridad, no dañar
- ✅ **Divulgación responsable** - Reportar vulnerabilidades apropiadamente
- ❌ **Actividades ilegales** - Prohibido para hacking malicioso
- ❌ **Daño intencional** - No usar para comprometer sistemas

---

## 🐕 **DEDICATORIA ESPECIAL**

### En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.
