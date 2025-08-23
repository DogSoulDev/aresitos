![ARESITOS](Aresitos/recursos/Aresitos.ico)

# ARESITOS - Herramienta de Ciberseguridad

[![Versión](https://img.shields.io/badge/versión-v3.0-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC-orange.svg)](README.md)

**ARESITOS v3.0** es una herramienta de ciberseguridad profesional diseñada exclusivamente para Kali Linux. Integra escaneador de vulnerabilidades, SIEM, FIM, sistema de cuarentena y auditoría de seguridad en una interfaz unificada.

## Características Principales

- **Escaneador Avanzado**: nmap, masscan, nuclei integrados
- **SIEM en Tiempo Real**: Monitoreo y correlación de eventos 
- **FIM**: Vigilancia de integridad de archivos críticos
- **Sistema de Cuarentena**: Detección y aislamiento de malware
- **Auditoría Automatizada**: Análisis completo de seguridad del sistema
- **Arquitectura MVC**: Código limpio, mantenible y extensible
- **Solo Python Nativo**: Sin dependencias externas

## Instalación Instantánea

### Método Automático - Recomendado
```bash
# Clonar y ejecutar configuración automática
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

### Método Manual - Control Total
```bash
# 1. Descargar ARESITOS
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar entorno Kali 2025
sudo ./configurar_kali.sh

# 3. Verificar instalación
python3 verificacion_final.py

# 4. Iniciar ARESITOS
python3 main.py
```

### Modo Desarrollo (Otros Sistemas)
```bash
# Para testing en sistemas no-Kali (funcionalidad limitada)
python3 main.py --dev
```

## 📸 **Capturas de Pantalla**

### Sistema de Autenticación
![Vista Login](Aresitos/recursos/vista_login.png)

### Vista de Herramientas 
![Vista Herramientas](Aresitos/recursos/vista_herramientas.png)

### Vista Principal
![Vista Aresitos](Aresitos/recursos/vista_aresitos.png)

---

## ⚡ **Inicio Rápido**

```bash
# Instalar y ejecutar en 30 segundos
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
sudo ./configurar_kali.sh && python3 main.py
```

## 🔧 **Requisitos del Sistema**

- **Sistema Operativo**: Kali Linux 2024+ (exclusivamente)
- **Python**: 3.8+ (incluido por defecto en Kali)
- **Permisos**: sudo para instalación de herramientas
- **Espacio**: 100MB mínimo
- **Memoria**: 2GB RAM recomendado


---

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
- 🌐 **Repositorio oficial**: https://github.com/DogSoulDev/Aresitos
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
- 🔗 **Fuente**: https://github.com/DogSoulDev/Aresitos
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
