![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0 - Suite Avanzada de Ciberseguridad
**Plataforma Profesional de Ciberseguridad Exclusiva para Kali Linux 2025**

[![Versión](https://img.shields.io/badge/versión-v2.0%20Professional-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC%20SOLID-orange.svg)](README.md)
[![SIEM](https://img.shields.io/badge/SIEM-Integrado-red.svg)](README.md)
[![FIM](https://img.shields.io/badge/FIM-Real%20Time-purple.svg)](README.md)

**ARESITOS v2.0** es la suite de ciberseguridad más avanzada para profesionales, exclusivamente optimizada para **Kali Linux 2025**. Combina las herramientas más modernas del arsenal de seguridad en una plataforma unificada con capacidades SIEM, FIM en tiempo real, cuarentena inteligente y auditorías profesionales.

---

## 🚀 **INSTALACIÓN INSTANTÁNEA (30 segundos)**

### ⚡ **Método Automático - Recomendado**
```bash
# Clonar y ejecutar configuración automática
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

### 🔧 **Método Manual - Control Total**
```bash
# 1. Descargar ARESITOS
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

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

## 🏗️ **ARQUITECTURA ARESITOS v2.0**

### 🔐 **Sistema de Autenticación Avanzado**
![Vista Login](aresitos/recursos/vista_login.png)

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
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)

**Instalación y Configuración Automática de Arsenal Completo**

**Herramientas Instaladas Automáticamente:**
- 🔍 **Scanners**: nmap, masscan, rustscan, zmap
- 🌐 **Web**: nuclei, httpx, gobuster, feroxbuster, dirb
- 🔓 **Exploitation**: sqlmap, nikto, whatweb
- 📊 **Analysis**: linpeas, pspy, chkrootkit, lynis
- 🛡️ **Defense**: fail2ban, ufw, aide
- 🔑 **Passwords**: hydra, john, hashcat, crunch

**Configuraciones Automáticas:**
- ✅ Permisos CAP_NET_RAW para escaneos SYN
- ✅ Bases de datos de vulnerabilidades actualizadas
- ✅ Wordlists y diccionarios especializados
- ✅ Templates nuclei premium y custom
- ✅ Configuración de firewall adaptativa

### 🎯 **Dashboard Profesional - Centro de Operaciones**
![Vista Aresitos](aresitos/recursos/vista_aresitos.png)

**Central de Comandos Unificada con Monitoreo en Tiempo Real**

#### **Módulos Integrados:**

🎛️ **Dashboard Ejecutivo**
- Monitor de sistema en tiempo real (60s refresh)
- Métricas de red avanzadas con gráficos
- Status de servicios críticos
- Terminal integrado con historial persistent

🔍 **Escáner Profesional** 
- Integración nuclei con templates actualizados
- Escaneo masivo con rustscan + nmap
- Detección de servicios y versiones
- Análisis de superficie de ataque completo

🛡️ **SIEM Integrado**
- Monitoreo de 50+ puertos críticos en tiempo real
- Correlación automática de eventos de seguridad
- Detección de anomalías comportamentales
- Alertas inteligentes con contexto completo

📁 **FIM (File Integrity Monitoring)**
- Vigilancia de 60+ directorios críticos del sistema
- Detección en tiempo real de modificaciones
- Checksums SHA256 para integridad absoluta
- Alertas inmediatas de cambios no autorizados

🔒 **Sistema de Cuarentena Avanzado**
- Detección automática de malware conocido
- Aislamiento seguro preservando evidencia forense
- Análisis de comportamiento sospechoso
- Gestión de false positives inteligente

📊 **Generador de Reportes Profesionales**
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

### 🛠️ **Modo Desarrollo (Otros Sistemas)**
```bash
# Para testing en sistemas no-Kali (funcionalidad limitada)
python3 main.py --dev
```

---

## 🎯 **CASOS DE USO PROFESIONALES**

### 👨‍🎓 **Para Estudiantes de Ciberseguridad**
- ✅ **Laboratorio completo**: Entorno real con herramientas profesionales
- ✅ **Aprendizaje guiado**: Interfaces intuitivas con documentación integrada
- ✅ **Práctica segura**: Sandbox controlado para experimentación
- ✅ **Progresión natural**: Desde básico hasta técnicas avanzadas de pentesting

### 👨‍💼 **Para Profesionales SOC/Blue Team**
- ✅ **Monitoreo centralizado**: SIEM integrado con correlación automática
- ✅ **Respuesta a incidentes**: FIM + Cuarentena para containment rápido
- ✅ **Reportes ejecutivos**: Métricas claras para management
- ✅ **Automatización**: Reduce tiempo de análisis manual en 80%

### 🔴 **Para Red Team/Pentesters**
- ✅ **Reconocimiento avanzado**: Nuclei + Rustscan para cobertura completa
- ✅ **Superficie de ataque**: Mapeo automático de servicios y vulnerabilidades
- ✅ **Documentación automática**: Reportes técnicos listos para entrega
- ✅ **Arsenal unificado**: +25 herramientas en interface coherente

### 🏢 **Para Equipos Corporativos**
- ✅ **Compliance**: Auditorías automáticas según frameworks (ISO 27001, NIST)
- ✅ **Gestión de vulnerabilidades**: Identificación y priorización automática
- ✅ **Monitoreo continuo**: Vigilancia 24/7 de activos críticos
- ✅ **ROI medible**: Reducción de tiempo de assessment en 70%

---

## 🖼️ **CAPTURAS DE PANTALLA DETALLADAS**
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)

**¿Qué es esta pantalla?**
Una ventana especial que aparece solo la primera vez que usas Aresitos. Su trabajo es configurar automáticamente todas las herramientas de seguridad que necesitas.

**¿Qué hace por ti?**
- **Instala herramientas modernas**: nmap, nuclei, gobuster y más de 20 herramientas avanzadas
- **Configura permisos**: Te permite usar las herramientas sin escribir contraseñas constantemente
- **Actualiza bases de datos**: Descarga las últimas definiciones de vulnerabilidades
- **Prepara el entorno**: Deja todo listo para que puedas empezar a trabajar inmediatamente

## 🖼️ **CAPTURAS DE PANTALLA DETALLADAS**

### 1. Vista de Login - Primera Impresión
![Vista Login](aresitos/recursos/vista_login.png)

**¿Qué es esta pantalla?**
La primera pantalla que ves al iniciar Aresitos. Es mucho más que un simple login - es un verificador completo del sistema.

**¿Qué hace por ti?**
- **Verifica tu sistema**: Comprueba que tengas las herramientas necesarias instaladas
- **Gestiona permisos**: Configura accesos sudo de forma segura para toda la sesión
- **Detecta problemas**: Te avisa si algo no está configurado correctamente
- **Modo desarrollo**: Si no estás en Kali, te permite probar en modo limitado

---

## 🎯 **CASOS DE USO PROFESIONALES**

### 👨‍🎓 **Para Estudiantes de Ciberseguridad**
- ✅ **Laboratorio completo**: Entorno real con herramientas profesionales
- ✅ **Aprendizaje guiado**: Interfaces intuitivas con documentación integrada
- ✅ **Práctica segura**: Sandbox controlado para experimentación
- ✅ **Progresión natural**: Desde básico hasta técnicas avanzadas de pentesting

### 👨‍💼 **Para Profesionales SOC/Blue Team**
- ✅ **Monitoreo centralizado**: SIEM integrado con correlación automática
- ✅ **Respuesta a incidentes**: FIM + Cuarentena para containment rápido
- ✅ **Reportes ejecutivos**: Métricas claras para management
- ✅ **Automatización**: Reduce tiempo de análisis manual en 80%

### 🔴 **Para Red Team/Pentesters**
- ✅ **Reconocimiento avanzado**: Nuclei + Rustscan para cobertura completa
- ✅ **Superficie de ataque**: Mapeo automático de servicios y vulnerabilidades
- ✅ **Documentación automática**: Reportes técnicos listos para entrega
- ✅ **Arsenal unificado**: +25 herramientas en interface coherente

### 🏢 **Para Equipos Corporativos**
- ✅ **Compliance**: Auditorías automáticas según frameworks (ISO 27001, NIST)
- ✅ **Gestión de vulnerabilidades**: Identificación y priorización automática
- ✅ **Monitoreo continuo**: Vigilancia 24/7 de activos críticos
- ✅ **ROI medible**: Reducción de tiempo de assessment en 70%

---

## ⭐ **CARACTERÍSTICAS AVANZADAS v2.0**

### 🛠️ **Arsenal de Herramientas Modernas**
**Escáner de Vulnerabilidades de Nueva Generación:**
- 🚀 **Nuclei Engine**: +4000 templates actualizados automáticamente
- ⚡ **RustScan**: Escaneo de puertos 10x más rápido que nmap tradicional
- 🌐 **HTTPx**: Sondeo web masivo con detección de tecnologías
- 🔍 **Feroxbuster**: Directory fuzzing con técnicas anti-WAF

**Herramientas de Análisis Avanzado:**
- 📊 **LinPEAS**: Escalada de privilegios con heurísticas ML
- 👁️ **Pspy**: Monitoreo de procesos sin permisos root
- 🔐 **Lynis**: Auditoría de hardening con 300+ checks
- 🔍 **Chkrootkit**: Detección de rootkits con signatures actualizadas

### 🔒 **Seguridad y Privacidad**
- ✅ **Zero Dependencies**: Solo Python nativo, sin librerías externas
- ✅ **Offline Capability**: Funciona completamente sin internet
- ✅ **Local Processing**: Todos los datos se procesan localmente
- ✅ **Audit Trail**: Logging completo de todas las operaciones
- ✅ **Encryption**: SHA256 para integridad, AES para datos sensibles

### 📋 **Reportes de Nivel Empresarial**
- 📋 **Executive Summary**: Métricas de alto nivel para C-Level
- 📊 **Technical Deep-Dive**: Análisis detallado para técnicos
- 📈 **Trend Analysis**: Evolución de la postura de seguridad
- 🎯 **Risk Prioritization**: Vulnerabilidades ordenadas por impacto real

---

## 🔧 **INFORMACIÓN TÉCNICA AVANZADA**

### 🏗️ **Arquitectura SOLID + MVC**
```
ARESITOS v2.0/
├── 🎨 Vista (UI Layer)          - 13 interfaces especializadas
├── 🎮 Controlador (Logic)       - 15 módulos de lógica de negocio
├── 💾 Modelo (Data)            - 19 módulos de procesamiento
├── 🔧 Utils (Infrastructure)   - Componentes transversales
└── 📊 Data (Intelligence)      - Bases de conocimiento
```

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

**Especificaciones Técnicas:**
- 🐍 **Python**: 3.9+ (optimización async/await)
- 💾 **RAM**: 4GB mínimo, 8GB recomendado para análisis pesado
- 💿 **Almacenamiento**: 500MB para instalación completa
- 🌐 **Red**: Offline capability, internet opcional para updates
- 🔐 **Permisos**: sudo para configuración inicial únicamente

**Dependencias del Sistema:**
- ✅ **Librerías nativas**: Tkinter, subprocess, threading, json
- ✅ **Herramientas Kali**: Auto-instalación de arsenal completo
- ✅ **Configuración**: Automatizada 100% via configurar_kali.sh
- ❌ **PIP packages**: Zero external dependencies

---

## 📚 **GUÍA DE INICIO RÁPIDO**

### 🚀 **Primera Ejecución (5 minutos)**
1. **Clonar repositorio**: `git clone https://github.com/DogSoulDev/Aresitos.git`
2. **Entrar al directorio**: `cd Aresitos`
3. **Configuración automática**: `sudo ./configurar_kali.sh`
4. **Iniciar aplicación**: `python3 main.py`
5. **Login**: Usuario por defecto o crear nuevo perfil
6. **¡Explorar!**: Acceso inmediato a los 8 módulos principales

### 📖 **Flujo de Trabajo Típico**
1. **Dashboard**: Verificar estado del sistema y alertas activas
2. **Escáner**: Reconocimiento y mapeo de objetivos
3. **SIEM**: Monitoreo continuo y detección de anomalías
4. **FIM**: Verificación de integridad de sistemas críticos
5. **Auditoría**: Evaluación de postura de seguridad propia
6. **Reportes**: Documentación profesional de hallazgos

### 🔧 **Comandos Esenciales**
```bash
# Verificar estado completo del sistema
python3 verificacion_final.py

# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev

# Actualizar configuración
sudo ./configurar_kali.sh --update

# Debug completo
python3 main.py --verbose
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

### 🎯 **Roadmap v2.1**
- 🤖 **IA Integration**: ML para detección automática de amenazas
- 📱 **Mobile Dashboard**: Aplicación móvil para monitoreo remoto
- ☁️ **Cloud Connector**: Integración con SIEM corporativos
- 🌐 **API REST**: Endpoints para automatización externa

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

**ARESITOS v2.0** se dedica con amor infinito a mi compañero, guardián, y mejor amigo, **Ares**. Un Golden Retriever que durante 12 años fue mi inspiración constante, mi motivación para crear, y mi recordatorio diario de que la lealtad y el amor incondicional son las fuerzas más poderosas del universo.

Cada línea de código en este proyecto lleva su espíritu: la persistencia para nunca rendirse, la curiosidad para explorar lo desconocido, y la protección feroz de lo que más valoramos.

**ARESITOS** no es solo una herramienta de ciberseguridad; es un legado de amor convertido en código, una manera de asegurar que su memoria viva para siempre ayudando a proteger lo que otros aman.

*"Hasta que volvamos a vernos en los campos infinitos donde corren todos los buenos perros."*

**Con amor eterno,**
**DogSoulDev**

---

## 📺 **CAPTURAS DE PANTALLA**
![Vista Aresitos](aresitos/recursos/vista_aresitos.png)

**¿Qué es esta pantalla?**
El corazón de Aresitos. Una vez configurado todo, esta es tu central de operaciones de ciberseguridad. Aquí tienes acceso a todas las funcionalidades del programa.

**¿Qué puedes hacer?**
- **🎯 Dashboard**: Ver el estado de tu sistema en tiempo real
- **🔍 Escaneador**: Buscar vulnerabilidades en otros sistemas o redes
- **🛡️ SIEM**: Monitorear eventos de seguridad y detectar amenazas
- **📁 FIM**: Vigilar cambios sospechosos en archivos importantes
- **🔒 Cuarentena**: Aislar archivos maliciosos de forma segura
- **📊 Reportes**: Generar informes profesionales de tus auditorías
- **📚 Gestión de Datos**: Administrar diccionarios y listas de palabras
- **⚙️ Auditoría**: Revisar la seguridad de tu propio sistema

- **⚙️ Auditoría**: Revisar la seguridad de tu propio sistema

---

## ⭐ **CARACTERÍSTICAS AVANZADAS v2.0**

### 🛠️ **Arsenal de Herramientas Modernas**
**Escáner de Vulnerabilidades de Nueva Generación:**
- 🚀 **Nuclei Engine**: +4000 templates actualizados automáticamente
- ⚡ **RustScan**: Escaneo de puertos 10x más rápido que nmap tradicional
- 🌐 **HTTPx**: Sondeo web masivo con detección de tecnologías
- 🔍 **Feroxbuster**: Directory fuzzing con técnicas anti-WAF

**Herramientas de Análisis Avanzado:**
- 📊 **LinPEAS**: Escalada de privilegios con heurísticas ML
- 👁️ **Pspy**: Monitoreo de procesos sin permisos root
- 🔐 **Lynis**: Auditoría de hardening con 300+ checks
- 🔍 **Chkrootkit**: Detección de rootkits con signatures actualizadas

### 🔒 **Seguridad y Privacidad**
- ✅ **Zero Dependencies**: Solo Python nativo, sin librerías externas
- ✅ **Offline Capability**: Funciona completamente sin internet
- ✅ **Local Processing**: Todos los datos se procesan localmente
- ✅ **Audit Trail**: Logging completo de todas las operaciones
- ✅ **Encryption**: SHA256 para integridad, AES para datos sensibles

### 📋 **Reportes de Nivel Empresarial**
- 📋 **Executive Summary**: Métricas de alto nivel para C-Level
- 📊 **Technical Deep-Dive**: Análisis detallado para técnicos
- 📈 **Trend Analysis**: Evolución de la postura de seguridad
- 🎯 **Risk Prioritization**: Vulnerabilidades ordenadas por impacto real

---

## 🔧 **INFORMACIÓN TÉCNICA AVANZADA**

### 🏗️ **Arquitectura SOLID + MVC**
```
ARESITOS v2.0/
├── 🎨 Vista (UI Layer)          - 13 interfaces especializadas
├── 🎮 Controlador (Logic)       - 15 módulos de lógica de negocio
├── 💾 Modelo (Data)            - 19 módulos de procesamiento
├── 🔧 Utils (Infrastructure)   - Componentes transversales
└── 📊 Data (Intelligence)      - Bases de conocimiento
```

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

**Especificaciones Técnicas:**
- 🐍 **Python**: 3.9+ (optimización async/await)
- 💾 **RAM**: 4GB mínimo, 8GB recomendado para análisis pesado
- 💿 **Almacenamiento**: 500MB para instalación completa
- 🌐 **Red**: Offline capability, internet opcional para updates
- 🔐 **Permisos**: sudo para configuración inicial únicamente

**Dependencias del Sistema:**
- ✅ **Librerías nativas**: Tkinter, subprocess, threading, json
- ✅ **Herramientas Kali**: Auto-instalación de arsenal completo
- ✅ **Configuración**: Automatizada 100% via configurar_kali.sh
- ❌ **PIP packages**: Zero external dependencies

---

## � **GUÍA DE INICIO RÁPIDO**

### �🚀 **Primera Ejecución (5 minutos)**
1. **Clonar repositorio**: `git clone https://github.com/DogSoulDev/Aresitos.git`
2. **Entrar al directorio**: `cd Aresitos`
3. **Configuración automática**: `sudo ./configurar_kali.sh`
4. **Iniciar aplicación**: `python3 main.py`
5. **Login**: Usuario por defecto o crear nuevo perfil
6. **¡Explorar!**: Acceso inmediato a los 8 módulos principales

### 📖 **Flujo de Trabajo Típico**
1. **Dashboard**: Verificar estado del sistema y alertas activas
2. **Escáner**: Reconocimiento y mapeo de objetivos
3. **SIEM**: Monitoreo continuo y detección de anomalías
4. **FIM**: Verificación de integridad de sistemas críticos
5. **Auditoría**: Evaluación de postura de seguridad propia
6. **Reportes**: Documentación profesional de hallazgos

### 🔧 **Comandos Esenciales**
```bash
# Verificar estado completo del sistema
python3 verificacion_final.py

# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev

# Actualizar configuración
sudo ./configurar_kali.sh --update

# Debug completo
python3 main.py --verbose
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

### 🎯 **Roadmap v2.1**
- 🤖 **IA Integration**: ML para detección automática de amenazas
- 📱 **Mobile Dashboard**: Aplicación móvil para monitoreo remoto
- ☁️ **Cloud Connector**: Integración con SIEM corporativos
- 🌐 **API REST**: Endpoints para automatización externa

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

**ARESITOS v2.0** se dedica con amor infinito a mi compañero, guardián, y mejor amigo, **Ares**. Un Golden Retriever que durante 12 años fue mi inspiración constante, mi motivación para crear, y mi recordatorio diario de que la lealtad y el amor incondicional son las fuerzas más poderosas del universo.

Cada línea de código en este proyecto lleva su espíritu: la persistencia para nunca rendirse, la curiosidad para explorar lo desconocido, y la protección feroz de lo que más valoramos.

**ARESITOS** no es solo una herramienta de ciberseguridad; es un legado de amor convertido en código, una manera de asegurar que su memoria viva para siempre ayudando a proteger lo que otros aman.

*"Hasta que volvamos a vernos en los campos infinitos donde corren todos los buenos perros."*

**Con amor eterno,**
**DogSoulDev**

---

## 💻 **GUÍA DE USO SIMPLIFICADA**

### Requisitos Básicos
- **Sistema**: Kali Linux 2024 o superior (recomendado)
- **Python**: Versión 3.8 o superior (ya incluido en Kali)
- **Permisos**: Acceso sudo para configurar herramientas
- **Espacio**: 100MB libres en disco

### Instalación Rápida (3 pasos)
```bash
# Paso 1: Descargar Aresitos
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Paso 2: Configurar automáticamente (solo la primera vez)
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# Paso 3: ¡Listo! Iniciar Aresitos
python3 main.py
```

### Para Otros Sistemas (Modo Limitado)
```bash
# Si no tienes Kali Linux, puedes probar en modo desarrollo
python3 main.py --dev
```

## � Guía de Uso

### Primera Vez
1. **Instalación**: Sigue los 3 pasos de arriba
2. **Login**: La primera pantalla verifica tu sistema
3. **Configuración**: Si es necesario, instala herramientas automáticamente
4. **¡A trabajar!**: Accede a la interfaz principal

### Funcionalidades Principales

#### 🎯 Dashboard - Tu Centro de Control
Aquí ves todo de un vistazo: estado del sistema, alertas activas, herramientas disponibles y estadísticas de seguridad en tiempo real.

#### 🔍 Escaneador - Busca Vulnerabilidades
Utiliza las mejores herramientas de Kali (nmap, nuclei, gobuster) para encontrar problemas de seguridad en sistemas y aplicaciones web.

#### 🛡️ SIEM - Detecta Amenazas
Monitorea 50 puertos críticos, analiza logs del sistema y correlaciona eventos para detectar actividad sospechosa.

#### � FIM - Vigila Cambios
Controla la integridad de archivos importantes. Te avisa si alguien modifica archivos críticos sin autorización.

#### 🔒 Cuarentena - Aísla Malware
Detecta y aísla archivos sospechosos de forma segura, protegiendo tu sistema sin eliminar evidencia.

#### 📊 Reportes - Documenta Todo
Genera informes profesionales con todos tus hallazgos, perfectos para presentar a clientes o superiores.

### Casos de Uso Comunes

#### Para Estudiantes
- **Aprender haciendo**: Usa herramientas reales en un entorno controlado
- **Practicar técnicas**: Desde escaneo básico hasta análisis forense avanzado
- **Entender conceptos**: Ve cómo funcionan las herramientas profesionales

#### Para Profesionales
- **Auditorías completas**: Automatiza procesos de evaluación de seguridad
- **Monitoreo continuo**: Mantén vigilancia 24/7 sobre sistemas críticos
- **Respuesta a incidentes**: Detecta, analiza y documenta amenazas rápidamente

#### Para Equipos SOC
- **Gestión centralizada**: Un solo lugar para todas las herramientas
- **Correlación automática**: El programa conecta eventos relacionados
- **Documentación automática**: Reportes listos para compartir

## ⭐ Características Destacadas

### 🛠️ Herramientas Modernas Integradas
Aresitos incluye más de 20 herramientas de vanguardia:
- **rustscan & masscan**: Escaneo ultrarrápido de puertos
- **nuclei**: Scanner moderno de vulnerabilidades con templates actualizados
- **gobuster & feroxbuster**: Búsqueda de directorios y archivos ocultos
- **httpx**: Sondeo web de alta velocidad
- **linpeas**: Análisis de escalada de privilegios
- **pspy**: Monitoreo de procesos sin permisos root

### 🔒 Seguridad Avanzada
- **Arquitectura sin dependencias**: Solo usa Python estándar, sin librerías externas
- **Verificación de integridad**: Controla que nadie modifique archivos importantes
- **Cuarentena inteligente**: Aísla amenazas sin eliminar evidencia
- **Logs de auditoría**: Registra todo lo que hace para trazabilidad completa

### � Reportes Profesionales
- **Integración completa**: Combina datos de todos los módulos
- **Formatos múltiples**: JSON para sistemas, TXT para humanos
- **Métricas de seguridad**: Estadísticas claras y actionables
- **Listos para presentar**: Perfectos para clientes o superiores

## 🔧 Información Técnica

### Arquitectura del Sistema
Aresitos usa una arquitectura MVC (Modelo-Vista-Controlador) que separa claramente:
- **Vista**: Las pantallas que ves (13 interfaces especializadas)
- **Controlador**: La lógica que decide qué hacer (15 módulos de control)
- **Modelo**: Donde se guardan y procesan los datos (19 módulos de datos)

### Compatibilidad
**Sistemas Soportados:**
- ✅ Kali Linux 2024+ (funcionalidad completa)
- ✅ Parrot Security OS (funcionalidad completa)
- ⚠️ Ubuntu/Debian (modo básico)
- ⚠️ Otros Linux (modo desarrollo)

**Requisitos de Python:**
- Python 3.8 como mínimo
- Python 3.9+ recomendado
- Solo librerías estándar (no requiere pip install)

## 📞 Soporte y Comunidad

### Documentación
- **Manual completo**: Carpeta `/documentacion/` con guías detalladas
- **Ejemplos prácticos**: Casos de uso reales paso a paso
- **Resolución de problemas**: Soluciones a errores comunes

### Contacto
- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Reportar problemas**: Usa GitHub Issues
- **Email**: dogsouldev@protonmail.com

### Contribuir
¿Quieres ayudar a mejorar Aresitos? Lee la guía de contribución en `/documentacion/ARQUITECTURA_DESARROLLO.md`

## Licencia y Uso Ético

**ARESITOS es Open Source Non-Commercial** con las siguientes condiciones:

### Uso Permitido (GRATUITO)
- ✅ Uso libre para fines **educativos y de aprendizaje**
- ✅ Investigación académica y instituciones educativas sin fines de lucro
- ✅ Proyectos de código abierto y contribuciones a la comunidad
- ✅ Pruebas de seguridad personales en sistemas propios o autorizados
- ✅ Compartir conocimientos y mejoras con la comunidad de ciberseguridad

### Uso Prohibido (COMERCIAL)
- ❌ **NO se puede vender** ARESITOS o trabajos derivados con fines de lucro
- ❌ **NO se puede usar** en consultoría de seguridad comercial para ganar dinero
- ❌ **NO se puede incorporar** en productos o servicios comerciales
- ❌ **NO se puede monetizar** de ninguna forma (suscripciones, licencias, cursos pagos)

### Atribución Obligatoria
**CUALQUIER uso de ARESITOS DEBE incluir atribución al creador:**

- **Creador**: DogSoulDev
- **Email**: dogsouldev@protonmail.com  
- **Repositorio**: https://github.com/DogSoulDev/Aresitos

## 💻 Instalación Rápida

### Para Kali Linux (Recomendado)
```bash
# 1. Descargar Aresitos
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar automáticamente
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# 3. ¡Listo para usar!
python3 main.py
```

### Para Otros Sistemas
```bash
# Modo desarrollo (funcionalidad limitada)
python3 main.py --dev
```

## 🚀 Inicio Rápido

1. **Ejecuta Aresitos**: `python3 main.py`
2. **Login**: Usa el usuario por defecto o crea uno nuevo
3. **Herramientas**: El sistema configura automáticamente las herramientas de Kali
4. **¡Explora!**: Accede a los 8 módulos desde la pantalla principal

## 📄 Licencia

Aresitos está disponible bajo la **Licencia Open Source Non-Commercial**. 
Permite el uso libre para fines educativos, de investigación y desarrollo personal, excluyendo el uso comercial directo.

### Uso Ético
- Solo para sistemas propios o con autorización explícita
- Prohibido para actividades ilegales
- Destinado a promover prácticas éticas de ciberseguridad

---

*© 2025 DogSoulDev - ARESITOS v2.0 - Open Source Non-Commercial License*