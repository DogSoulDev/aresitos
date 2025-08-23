![ARESITOS](Aresitos/recursos/Aresitos.ico)

# ARESITOS - Herramienta de Ciberseguridad Profesional

[![Versión](https://img.shields.io/badge/versión-v3.0-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC-orange.svg)](README.md)

**ARESITOS v3.0** es una herramienta de ciberseguridad profesional diseñada exclusivamente para Kali Linux. Integra escaneador de vulnerabilidades, SIEM, FIM, sistema de cuarentena y auditoría de seguridad en una interfaz unificada para estudiantes y profesionales de la seguridad.

## **Características Principales**

- **Escaneador Avanzado**: nmap, masscan, nuclei, gobuster integrados
- **SIEM en Tiempo Real**: Monitoreo y correlación de eventos de seguridad
- **FIM (File Integrity Monitoring)**: Vigilancia de integridad de archivos críticos
- **Sistema de Cuarentena**: Detección y aislamiento automático de malware
- **Auditoría Automatizada**: Análisis completo de seguridad del sistema
- **Dashboard Profesional**: Centro de operaciones con monitoreo en tiempo real
- **Arquitectura MVC**: Código limpio, mantenible y extensible
- **Solo Python Nativo**: Sin dependencias externas complejas

## **Instalación Profesional**

### **Método Automático - Recomendado**
```bash
# Instalación completa en un solo comando
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

### **Método Manual - Control Total**
```bash
# 1. Clonar el repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar entorno Kali Linux 2025
sudo ./configurar_kali.sh

# 3. Verificar instalación completa
python3 verificacion_final.py

# 4. Iniciar ARESITOS
python3 main.py
```

### **Modo Desarrollo (Sistemas No-Kali)**
```bash
# Para testing en otros sistemas Linux (funcionalidad limitada)
python3 main.py --dev
```

### **Configuración Avanzada**
```bash
# Actualizar herramientas y configuraciones
sudo ./configurar_kali.sh --update

# Verificar estado del sistema
python3 main.py --verify

# Modo debug completo
python3 main.py --verbose --scanner-debug
```

## 📸 **Capturas de Pantalla**

### Sistema de Autenticación
![Vista Login](Aresitos/recursos/vista_login.png)

### Vista de Herramientas 
![Vista Herramientas](Aresitos/recursos/vista_herramientas.png)

### Vista Principal
![Vista Aresitos](Aresitos/recursos/vista_aresitos.png)

---

## **Inicio Rápido**

```bash
# Instalación completa y ejecución en 30 segundos
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
sudo ./configurar_kali.sh && python3 main.py
```

## **Requisitos del Sistema**

### **Requisitos Mínimos**
- **Sistema Operativo**: Kali Linux 2024+ (recomendado 2025)
- **Python**: 3.8+ (incluido por defecto en Kali)
- **Memoria RAM**: 2GB mínimo, 4GB recomendado
- **Espacio en Disco**: 1GB libre para instalación completa
- **Permisos**: sudo para instalación de herramientas
- **Red**: Conexión a internet para actualizaciones

### **Arquitectura Soportada**
- [OK] **Kali Linux 2025** - Funcionalidad completa optimizada
- [OK] **Kali Linux 2024** - Compatibilidad total verificada
- [OK] **Parrot Security** - Soporte nativo completo
- [WARN] **BlackArch** - Funciones básicas, configuración manual
- [WARN] **Ubuntu/Debian** - Modo limitado para desarrollo
- [ERROR] **Windows/macOS** - No soportado oficialmente

---

## **Configurador Inteligente de Herramientas**

### **Arsenal Completo Auto-Instalado**

**Herramientas del Escaneador Profesional v3.0:**
- **Scanners Core**: nmap, masscan, rustscan con configuraciones optimizadas
- **Web Discovery**: nuclei (CVE detection), gobuster, ffuf, feroxbuster
- **Vulnerability Assessment**: Templates nuclei actualizados, análisis automático
- **Network Analysis**: Análisis de superficie de ataque, correlación de servicios
- **Enumeration**: Detección de directorios, archivos, subdominios
- **Threat Intelligence**: Base de datos CVE integrada, fingerprinting avanzado

**Configuraciones Automáticas:**
- [OK] Permisos CAP_NET_RAW para escaneos SYN
- [OK] Bases de datos de vulnerabilidades actualizadas
- [OK] Wordlists y diccionarios especializados por categoría
- [OK] Templates nuclei premium y personalizados
- [OK] Configuración de firewall adaptativa para herramientas

## **Dashboard Profesional - Centro de Operaciones**

### **Módulos Integrados**

**🎛️ Dashboard Principal**
- Monitor de sistema en tiempo real (actualización cada 60s)
- Métricas de red avanzadas con gráficos dinámicos
- Status de servicios críticos del sistema
- Terminal integrado con historial persistente

**🔍 Escaneador Profesional v3.0**
- **5 Modos de Escaneo**: Integral, Avanzado, Red, Rápido, Profundo
- **Detección Automática**: Validación y uso inteligente de herramientas
- **Integración nuclei**: Templates actualizados, detección automática de CVEs
- **Escaneo Masivo**: masscan/rustscan para análisis de redes completas
- **Enumeración Web**: gobuster/ffuf para discovery avanzado de directorios
- **Exportación Avanzada**: Reportes JSON/TXT/CSV con análisis detallado
- **Fallback Inteligente**: Adaptación automática según herramientas instaladas

**🛡️ SIEM (Security Information and Event Management)**
- Monitoreo de 50+ puertos críticos en tiempo real
- Correlación automática de eventos de seguridad
- Detección de anomalías comportamentales avanzadas
- Alertas inteligentes con contexto completo y recomendaciones

**📁 FIM (File Integrity Monitoring)**
- Vigilancia de 60+ directorios críticos del sistema
- Detección en tiempo real de modificaciones no autorizadas
- Checksums SHA256 para verificación de integridad absoluta
- Alertas inmediatas con detalles de cambios detectados

**🔒 Sistema de Cuarentena Automática**
- Detección automática de malware conocido y patrones sospechosos
- Aislamiento seguro preservando evidencia forense
- Análisis de comportamiento sospechoso con machine learning
- Gestión inteligente de falsos positivos

**📊 Generador de Reportes Profesionales**
- Informes ejecutivos y técnicos personalizables
- Integración completa de datos de todos los módulos
- Exportación múltiple: JSON, TXT, CSV, PDF
- Templates especializados por industria y tipo de auditoría

**📚 Gestor de Inteligencia y Recursos**
- Base de datos de vulnerabilidades actualizada y localizada
- Wordlists categorizadas por técnica y objetivo
- Diccionarios especializados por sector e industria
- Cheatsheets integradas de herramientas y técnicas

**⚙️ Auditoría de Sistema Automatizada**
- Lynis con configuración optimizada para Kali Linux
- Chkrootkit con heurísticas avanzadas y actualizadas
- Análisis profundo de configuraciones de seguridad
- Recomendaciones priorizadas por nivel de riesgo

---

## 🏗️ **Arquitectura Técnica Avanzada**

### 🔧 **Diseño SOLID + MVC v3.0**
```
ARESITOS v3.0 Professional Security Suite/
├── 🎨 Vista (UI Layer)          - 13 interfaces especializadas + Escaneador Pro
├── 🎮 Controlador (Logic)       - 15 módulos + Controlador Escaneador Avanzado
├── 💾 Modelo (Data)            - 19 módulos + Modelos de Escaneo Profesional
├── 🔧 Utils (Infrastructure)   - Componentes + Gestión Avanzada de Herramientas
└── 📊 Data (Intelligence)      - Bases de conocimiento + Templates nuclei
```

### ✨ **Nuevas Características v3.0**
- ✅ **Escaneador Modular**: 5 tipos de escaneo especializados y configurables
- ✅ **Validación Automática**: Detección inteligente de herramientas disponibles
- ✅ **Fallback System**: Adaptación automática según disponibilidad de tools
- ✅ **Export Engine**: Sistema avanzado de exportación con múltiples formatos
- ✅ **Progress Tracking**: Seguimiento detallado en tiempo real de escaneos
- ✅ **Tool Integration**: Integración nativa optimizada con arsenal Kali 2025

### 🎯 **Principios de Diseño Aplicados**
- ✅ **Single Responsibility**: Cada clase tiene una función específica y bien definida
- ✅ **Open/Closed**: Totalmente extensible sin modificar código existente
- ✅ **Liskov Substitution**: Interfaces consistentes y predecibles
- ✅ **Interface Segregation**: APIs específicas para cada caso de uso
- ✅ **Dependency Inversion**: Abstracciones sobre implementaciones concretas

### 💻 **Especificaciones Técnicas v3.0**
- 🐍 **Python**: 3.9+ con optimizaciones asíncronas para escaneador
- 💾 **RAM**: 4GB mínimo, 8GB recomendado para escaneos masivos
- 💿 **Almacenamiento**: 1GB para instalación + templates nuclei actualizados
- 🌐 **Conectividad**: Capacidad offline completa, internet para updates
- 🔐 **Permisos**: CAP_NET_RAW para escaneos SYN, sudo para configuración
- ⚡ **Concurrencia**: Soporte completo para escaneos paralelos masivos

### 🔗 **Dependencias del Sistema**
- ✅ **Librerías Python Nativas**: tkinter, subprocess, threading, json, sqlite3
- ✅ **Herramientas Kali**: Auto-instalación completa de arsenal de seguridad
- ✅ **Configuración**: 100% automatizada vía configurar_kali.sh
- ❌ **Dependencias Externas**: Zero external pip packages requeridos

---

## 📋 **Comandos Esenciales**

### 🔍 **Verificación y Diagnóstico**
```bash
# Verificación completa del sistema + escaneador
python3 verificacion_final.py

# Verificación de estabilidad antes de uso
python3 main.py --verify

# Diagnóstico completo del entorno
sudo ./configurar_kali.sh --diagnostico
```

### 🛠️ **Configuración y Mantenimiento**
```bash
# Actualizar configuración + herramientas del escaneador
sudo ./configurar_kali.sh --update

# Reinstalar herramientas dañadas
sudo ./configurar_kali.sh --repair

# Actualizar templates nuclei manualmente
sudo nuclei -update-templates
```

### 🐛 **Debugging y Desarrollo**
```bash
# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev

# Debug completo del escaneador
python3 main.py --verbose --scanner-debug

# Modo de desarrollo con logs detallados
python3 main.py --dev --verbose --debug-all
```

---

## 📞 **Soporte y Comunidad**

### 📖 **Documentación Técnica Completa**
- 📚 **Manual Técnico**: `/documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- 🏗️ **Guía de Desarrollo**: `/documentacion/ARQUITECTURA_DESARROLLO.md`
- 🛡️ **Auditoría de Seguridad**: `/documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md`
- 💻 **Terminal Integrado**: `/documentacion/TERMINAL_INTEGRADO.md`
- 🔧 **Guía de Instalación**: `/documentacion/GUIA_INSTALACION.md`

### 🤝 **Contacto y Contribución**
- 🌐 **Repositorio Oficial**: https://github.com/DogSoulDev/Aresitos
- 🐛 **Reportar Issues**: GitHub Issues con templates predefinidos
- 💬 **Discusiones**: GitHub Discussions para preguntas generales
- 💌 **Email de Desarrollo**: dogsouldev@protonmail.com
- 🔗 **LinkedIn Profesional**: [DogSoulDev](https://linkedin.com/in/dogsouldev)

### 🎓 **Recursos de Aprendizaje**
- 📺 **Video Tutoriales**: Canal oficial de YouTube (próximamente)
- 📖 **Guías de Uso**: Wiki completa en GitHub
- 🛠️ **Ejemplos Prácticos**: Repositorio de casos de uso
- 👥 **Comunidad**: Servidor Discord para soporte en tiempo real

---

## 📜 **Licencia y Uso Ético**

### 🏛️ **Open Source Non-Commercial License**

#### ✅ **Uso Permitido (Completamente Gratuito)**
- 🎓 **Educación**: Universidades, estudiantes, investigación académica
- 🛡️ **Seguridad Personal**: Testing en sistemas propios o con autorización explícita
- 🌐 **Proyectos Open Source**: Sin monetización directa o indirecta
- 📚 **Aprendizaje y Capacitación**: Cursos, talleres, seminarios sin fines de lucro
- 🤝 **Comunidad**: Compartir conocimientos, mejoras y contribuciones

#### ❌ **Uso Estrictamente Prohibido**
- 💰 **Venta Directa**: No se puede vender ARESITOS o sus derivados
- 🏢 **Consultoría Comercial**: No usar para servicios de pentesting pagos
- 📦 **Productos Comerciales**: No incorporar en software comercial sin autorización
- 💳 **Monetización**: Cursos pagos, suscripciones, licencias comerciales
- 🏪 **Servicios Managed**: No ofrecer como SaaS o servicios gestionados

#### 📋 **Atribución Obligatoria**
**TODO uso debe incluir claramente:**
- 👨‍💻 **Creador Original**: DogSoulDev
- 📧 **Contacto**: dogsouldev@protonmail.com
- 🔗 **Repositorio Fuente**: https://github.com/DogSoulDev/Aresitos
- 📄 **Tipo de Licencia**: Open Source Non-Commercial License

### 🛡️ **Código de Ética Profesional**

#### ✅ **Uso Responsable y Legal**
- 🎯 **Solo Sistemas Autorizados**: Con permiso explícito y documentado por escrito
- 🔒 **Propósitos Constructivos**: Exclusivamente para mejorar la seguridad
- 📢 **Divulgación Responsable**: Reportar vulnerabilidades de forma ética
- 📚 **Educación y Aprendizaje**: Fomentar el conocimiento en ciberseguridad
- 🤝 **Colaboración Comunitaria**: Contribuir al bien común de la seguridad

#### ❌ **Actividades Estrictamente Prohibidas**
- 🚫 **Hacking Malicioso**: Cualquier actividad ilegal o no autorizada
- 💣 **Daño Intencional**: No usar para comprometer o dañar sistemas
- 🕵️ **Espionaje No Autorizado**: Respeto absoluto a la privacidad
- 💰 **Beneficio Ilícito**: No usar para actividades fraudulentas
- 🎭 **Violación de Términos**: Respeto a las políticas de uso de servicios

### ⚖️ **Responsabilidad Legal**
El uso de ARESITOS implica la aceptación completa de esta licencia y código ético. El usuario es completamente responsable del cumplimiento de las leyes locales, nacionales e internacionales aplicables. Los desarrolladores no se hacen responsables del uso indebido de esta herramienta.

---

## 🐕 **Dedicatoria Especial**

### En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*

*Hasta que volvamos a vernos.*
