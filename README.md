![ARESITOS](Aresitos/recursos/Aresitos.ico)

# ARESITOS - Herramienta de Ciberseguridad Profesional

[![Versión](https://img.shields.io/badge/versión-v3.0-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC-orange.svg)](README.md)

**ARESITOS v3.0** es una herramienta de ciberseguridad profesional diseñada exclusivamente para Kali Linux. Integra escaneador de vulnerabilidades, SIEM, FIM, sistema de cuarentena y auditoría de seguridad en una interfaz unificada para estudiantes y profesionales de la seguridad.

> **📋 Repositorio de Testeos Anterior:** Si deseas revisar el código de pruebas y desarrollo previo a ARESITOS, puedes consultar el repositorio de testeos [Ares Aegis](https://github.com/DogSoulDev/Ares-Aegis) donde se realizaron las pruebas iniciales y desarrollo experimental.

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

**PANEL Dashboard Principal**
- Monitor de sistema en tiempo real (actualización cada 60s)
- Métricas de red avanzadas con gráficos dinámicos
- Status de servicios críticos del sistema
- Terminal integrado con historial persistente

**SCAN Escaneador Profesional v3.0**
- **5 Modos de Escaneo**: Integral, Avanzado, Red, Rápido, Profundo
- **Detección Automática**: Validación y uso inteligente de herramientas
- **Integración nuclei**: Templates actualizados, detección automática de CVEs
- **Escaneo Masivo**: masscan/rustscan para análisis de redes completas
- **Enumeración Web**: gobuster/ffuf para discovery avanzado de directorios
- **Exportación Avanzada**: Reportes JSON/TXT/CSV con análisis detallado
- **Fallback Inteligente**: Adaptación automática según herramientas instaladas

**SECURE SIEM (Security Information and Event Management)**
- Monitoreo de 50+ puertos críticos en tiempo real
- Correlación automática de eventos de seguridad
- Detección de anomalías comportamentales avanzadas
- Alertas inteligentes con contexto completo y recomendaciones

**FOLDER FIM (File Integrity Monitoring)**
- Vigilancia de 60+ directorios críticos del sistema
- Detección en tiempo real de modificaciones no autorizadas
- Checksums SHA256 para verificación de integridad absoluta
- Alertas inmediatas con detalles de cambios detectados

**LOCK Sistema de Cuarentena Automática**
- Detección automática de malware conocido y patrones sospechosos
- Aislamiento seguro preservando evidencia forense
- Análisis de comportamiento sospechoso con machine learning
- Gestión inteligente de falsos positivos

**DATA Generador de Reportes Profesionales**
- Informes ejecutivos y técnicos personalizables
- Integración completa de datos de todos los módulos
- Exportación múltiple: JSON, TXT, CSV, PDF
- Templates especializados por industria y tipo de auditoría

**📚 Gestor de Inteligencia y Recursos**
- Base de datos de vulnerabilidades actualizada y localizada
- Wordlists categorizadas por técnica y objetivo
- Diccionarios especializados por sector e industria
- Cheatsheets integradas de herramientas y técnicas

**CONFIG Auditoría de Sistema Automatizada**
- Lynis con configuración optimizada para Kali Linux
- Chkrootkit con heurísticas avanzadas y actualizadas
- Análisis profundo de configuraciones de seguridad
- Recomendaciones priorizadas por nivel de riesgo

---

## ARCH **Arquitectura Técnica Avanzada**

### TOOL **Diseño SOLID + MVC v3.0**
```
ARESITOS v3.0 Professional Security Suite/
├── UI Vista (UI Layer)          - 13 interfaces especializadas + Escaneador Pro
├── CONTROL Controlador (Logic)       - 15 módulos + Controlador Escaneador Avanzado
├── SAVE Modelo (Data)            - 19 módulos + Modelos de Escaneo Profesional
├── TOOL Utils (Infrastructure)   - Componentes + Gestión Avanzada de Herramientas
└── DATA Data (Intelligence)      - Bases de conocimiento + Templates nuclei
```

### FEATURE **Nuevas Características v3.0**
- OK **Escaneador Modular**: 5 tipos de escaneo especializados y configurables
- OK **Validación Automática**: Detección inteligente de herramientas disponibles
- OK **Fallback System**: Adaptación automática según disponibilidad de tools
- OK **Export Engine**: Sistema avanzado de exportación con múltiples formatos
- OK **Progress Tracking**: Seguimiento detallado en tiempo real de escaneos
- OK **Tool Integration**: Integración nativa optimizada con arsenal Kali 2025

### TARGET **Principios de Diseño Aplicados**
- OK **Single Responsibility**: Cada clase tiene una función específica y bien definida
- OK **Open/Closed**: Totalmente extensible sin modificar código existente
- OK **Liskov Substitution**: Interfaces consistentes y predecibles
- OK **Interface Segregation**: APIs específicas para cada caso de uso
- OK **Dependency Inversion**: Abstracciones sobre implementaciones concretas

### SYSTEM **Especificaciones Técnicas v3.0**
- 🐍 **Python**: 3.9+ con optimizaciones asíncronas para escaneador
- SAVE **RAM**: 4GB mínimo, 8GB recomendado para escaneos masivos
- 💿 **Almacenamiento**: 1GB para instalación + templates nuclei actualizados
- WEB **Conectividad**: Capacidad offline completa, internet para updates
- 🔐 **Permisos**: CAP_NET_RAW para escaneos SYN, sudo para configuración
- FAST **Concurrencia**: Soporte completo para escaneos paralelos masivos

### 🔗 **Dependencias del Sistema**
- OK **Librerías Python Nativas**: tkinter, subprocess, threading, json, sqlite3
- OK **Herramientas Kali**: Auto-instalación completa de arsenal de seguridad
- OK **Configuración**: 100% automatizada vía configurar_kali.sh
- ERROR **Dependencias Externas**: Zero external pip packages requeridos

---

## LIST **Comandos Esenciales**

### SCAN **Verificación y Diagnóstico**
```bash
# Verificación completa del sistema + escaneador
python3 verificacion_final.py

# Verificación de estabilidad antes de uso
python3 main.py --verify

# Diagnóstico completo del entorno
sudo ./configurar_kali.sh --diagnostico
```

### TOOLS **Configuración y Mantenimiento**
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
- DOCS **Manual Técnico**: `/documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- ARCH **Guía de Desarrollo**: `/documentacion/ARQUITECTURA_DESARROLLO.md`
- SECURE **Auditoría de Seguridad**: `/documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md`
- SYSTEM **Terminal Integrado**: `/documentacion/TERMINAL_INTEGRADO.md`
- TOOL **Guía de Instalación**: `/documentacion/GUIA_INSTALACION.md`

### CONTACT **Contacto y Contribución**
- WEB **Repositorio Oficial**: https://github.com/DogSoulDev/Aresitos
- BUG **Reportar Issues**: GitHub Issues con templates predefinidos
- CHAT **Discusiones**: GitHub Discussions para preguntas generales
- EMAIL **Email de Desarrollo**: dogsouldev@protonmail.com
- LINK **LinkedIn Profesional**: [DogSoulDev](https://linkedin.com/in/dogsouldev)

### LEARN **Recursos de Aprendizaje**
- VIDEO **Video Tutoriales**: Canal oficial de YouTube (próximamente)
- GUIDE **Guías de Uso**: Wiki completa en GitHub
- TOOLS **Ejemplos Prácticos**: Repositorio de casos de uso
- GROUP **Comunidad**: Servidor Discord para soporte en tiempo real

---

## 📜 **Licencia y Uso Ético**

### BUILD **Open Source Non-Commercial License**

#### OK **Uso Permitido (Completamente Gratuito)**
- LEARN **Educación**: Universidades, estudiantes, investigación académica
- SECURE **Seguridad Personal**: Testing en sistemas propios o con autorización explícita
- WEB **Proyectos Open Source**: Sin monetización directa o indirecta
- LEARN **Aprendizaje y Capacitación**: Cursos, talleres, seminarios sin fines de lucro
- SHARE **Comunidad**: Compartir conocimientos, mejoras y contribuciones

#### ERROR **Uso Estrictamente Prohibido**
- MONEY **Venta Directa**: No se puede vender ARESITOS o sus derivados
- BUSINESS **Consultoría Comercial**: No usar para servicios de pentesting pagos
- PACKAGE **Productos Comerciales**: No incorporar en software comercial sin autorización
- CREDIT **Monetización**: Cursos pagos, suscripciones, licencias comerciales
- SHOP **Servicios Managed**: No ofrecer como SaaS o servicios gestionados

#### LIST **Atribución Obligatoria**
**TODO uso debe incluir claramente:**
- CREATOR **Creador Original**: DogSoulDev
- EMAIL **Contacto**: dogsouldev@protonmail.com
- LINK **Repositorio Fuente**: https://github.com/DogSoulDev/Aresitos
- LICENSE **Tipo de Licencia**: Open Source Non-Commercial License

### SECURE **Código de Ética Profesional**

#### OK **Uso Responsable y Legal**
- TARGET **Solo Sistemas Autorizados**: Con permiso explícito y documentado por escrito
- LOCK **Propósitos Constructivos**: Exclusivamente para mejorar la seguridad
- ANNOUNCE **Divulgación Responsable**: Reportar vulnerabilidades de forma ética
- LEARN **Educación y Aprendizaje**: Fomentar el conocimiento en ciberseguridad
- SHARE **Colaboración Comunitaria**: Contribuir al bien común de la seguridad

#### ERROR **Actividades Estrictamente Prohibidas**
- STOP **Hacking Malicioso**: Cualquier actividad ilegal o no autorizada
- BOMB **Daño Intencional**: No usar para comprometer o dañar sistemas
- DETECT **Espionaje No Autorizado**: Respeto absoluto a la privacidad
- MONEY **Beneficio Ilícito**: No usar para actividades fraudulentas
- MASK **Violación de Términos**: Respeto a las políticas de uso de servicios

### LEGAL **Responsabilidad Legal**
El uso de ARESITOS implica la aceptación completa de esta licencia y código ético. El usuario es completamente responsable del cumplimiento de las leyes locales, nacionales e internacionales aplicables. Los desarrolladores no se hacen responsables del uso indebido de esta herramienta.

---

## DOG **Dedicatoria Especial**

### En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*

*Hasta que volvamos a vernos.*
