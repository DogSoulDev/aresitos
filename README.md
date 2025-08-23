![ARESITOS](Aresitos/recursos/Aresitos.ico)

# ARESITOS - Tu Centro de Seguridad Digital

[![Versión](https://img.shields.io/badge/versión-v3.0-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[!---

## 🐕 **DEDICATORIA ESPECIAL**

### En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.

````img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC-orange.svg)](README.md)

**ARESITOS v3.0** es una herramienta de ciberseguridad integral, diseñada especialmente para estudiantes y profesionales que trabajan con Kali Linux. Funciona como un centro de control que te permite proteger y analizar sistemas de forma sencilla y efectiva.

## ¿Qué es ARESITOS?

ARESITOS es como tener un laboratorio de ciberseguridad completo en tu computadora. Imagínate una navaja suiza digital que te permite:

- **Escanear redes y sistemas** para encontrar vulnerabilidades
- **Vigilar tu sistema** en tiempo real para detectar amenazas
- **Proteger archivos importantes** monitoreando cambios no autorizados
- **Aislar archivos sospechosos** antes de que causen daño
- **Generar informes profesionales** de todo lo que encuentres

Todo esto desde una interfaz gráfica fácil de usar, sin necesidad de recordar comandos complicados.

## ¿Para quién está diseñado?

### 🎓 **Estudiantes de Ciberseguridad**
- Perfecto para aprender hacking ético y pentesting
- Interfaz visual que facilita el aprendizaje
- Incluye explicaciones de las herramientas que usa

### 🐧 **Usuarios de Kali Linux**
- Aprovecha al máximo las herramientas incluidas en Kali
- Configuración automática de todo el entorno
- Optimizado para el flujo de trabajo de seguridad

### 🔧 **Profesionales IT**
- Automatiza tareas repetitivas de seguridad
- Centraliza múltiples herramientas en una sola interfaz
- Genera reportes listos para presentar

## Instalación Súper Fácil

### Método Rápido (Recomendado)
```bash
# Descarga e instala todo automáticamente
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

### Paso a Paso
```bash
# 1. Descargar ARESITOS
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar todo automáticamente
sudo ./configurar_kali.sh

# 3. Comprobar que todo funciona
python3 verificacion_final.py

# 4. ¡A usar ARESITOS!
python3 main.py
```

## 📸 **Capturas de Pantalla**

### Sistema de Autenticación
![Vista Login](Aresitos/recursos/vista_login.png)

### Vista de Herramientas 
![Vista Herramientas](Aresitos/recursos/vista_herramientas.png)

### Vista Principal
![Vista Aresitos](Aresitos/recursos/vista_aresitos.png)

---

## 🚀 **¿Cómo Funciona ARESITOS?**

ARESITOS funciona como el centro de comando de tu seguridad digital. Al abrirlo, verás una pantalla principal con diferentes módulos, cada uno especializado en una tarea específica.

### 🏠 **Dashboard - Tu Centro de Control**
Es como el escritorio de tu computadora, pero para seguridad:
- Muestra el estado de tu sistema en tiempo real
- Te avisa si algo anda mal
- Tienes acceso rápido a todas las herramientas
- Incluye un terminal integrado para comandos avanzados

### 🔍 **Escaneador - Tu Detective Digital**
Esta es la parte que busca problemas en redes y sistemas:
- **Escaneo Rápido**: Para análisis básicos (5-10 minutos)
- **Escaneo Profundo**: Para análisis completos (30-60 minutos)
- **Escaneo de Red**: Para revisar toda tu red local
- **Escaneo Web**: Especializado en sitios web y aplicaciones

**¿Cómo funciona?** Usas herramientas como nmap (para encontrar computadoras) y nuclei (para encontrar vulnerabilidades), pero desde una interfaz visual donde solo tienes que hacer clic.

### 🛡️ **SIEM - Tu Guardián Silencioso**
SIEM significa "Información de Seguridad y Gestión de Eventos". En palabras simples:
- Vigila constantemente tu sistema
- Detecta actividad sospechosa
- Te alerta si alguien intenta entrar sin permiso
- Guarda un registro de todo lo que pasa

### 📁 **FIM - El Vigilante de tus Archivos**
FIM significa "Monitoreo de Integridad de Archivos":
- Vigila carpetas importantes de tu sistema
- Te avisa si alguien modifica archivos críticos
- Detecta si un virus cambió algo importante
- Como tener un guardia de seguridad para tus archivos más valiosos

### 🔒 **Sistema de Cuarentena - Tu Área de Aislamiento**
Cuando encuentra algo sospechoso:
- Lo aísla del resto del sistema
- Lo analiza de forma segura
- Te permite decidir qué hacer con él
- Mantiene tu sistema protegido mientras investigas

### 📊 **Reportes - Tu Secretario Digital**
Convierte toda la información técnica en reportes fáciles de entender:
- Resúmenes ejecutivos para jefes
- Detalles técnicos para especialistas
- Recomendaciones de seguridad
- Exporta en diferentes formatos (PDF, Word, Excel)

---

## 🏗️ **Arquitectura y Estructura del Proyecto**

ARESITOS está organizado de manera muy lógica para que sea fácil de entender y modificar:

### 📂 **Estructura de Carpetas**

```
Aresitos/
├── 🎨 vista/           → Lo que ves en pantalla (interfaces gráficas)
├── 🎮 controlador/     → La lógica que conecta todo
├── 💾 modelo/          → Donde se guardan y procesan los datos
├── 🔧 utils/           → Herramientas auxiliares y configuraciones
├── 📊 data/            → Bases de datos y archivos de trabajo
├── 📚 documentacion/   → Manuales y guías técnicas
├── ⚙️ configuración/   → Archivos de configuración
└── 📝 logs/            → Registros de actividad
```

### 🧠 **¿Qué hace cada parte?**

**Vista (Interfaz Gráfica):**
- Son las ventanas que ves
- Los botones que pulsas
- Los menús que usas
- Todo lo visual del programa

**Controlador (Cerebro):**
- Recibe lo que haces en la interfaz
- Decide qué hacer con esa información
- Coordina entre la vista y los datos
- Es como el director de orquesta

**Modelo (Datos y Lógica):**
- Hace el trabajo pesado (escaneos, análisis)
- Guarda la información
- Procesa los resultados
- Maneja las bases de datos

**Utils (Herramientas Auxiliares):**
- Funciones que usan varias partes del programa
- Configuraciones del sistema
- Utilidades para manejo de archivos
- Gestión de permisos y seguridad

---

## 🔧 **Requisitos del Sistema**

**Lo que necesitas:**
- **Sistema Operativo**: Kali Linux 2024 o más nuevo
- **Python**: Versión 3.8 o superior (ya viene en Kali)
- **Memoria RAM**: Mínimo 2GB, recomendado 4GB
- **Espacio en disco**: 1GB libre
- **Conexión a internet**: Para descargar actualizaciones

**Se instala automáticamente:**
- Todas las herramientas de hacking necesarias
- Bases de datos de vulnerabilidades
- Diccionarios para ataques de fuerza bruta
- Configuraciones optimizadas

---

## 🔗 **Flujo de Trabajo Típico**

### Para Estudiantes:
1. **Instalar** ARESITOS en tu Kali Linux
2. **Explorar** cada módulo desde el dashboard
3. **Practicar** con escaneos en tu red local
4. **Aprender** leyendo los reportes generados
5. **Experimentar** con diferentes configuraciones

### Para Profesionales:
1. **Configurar** ARESITOS en tu entorno de trabajo
2. **Automatizar** tareas repetitivas de seguridad
3. **Monitorear** sistemas críticos con SIEM y FIM
4. **Generar** reportes para clientes o supervisores
5. **Integrar** con otros sistemas de seguridad

---

## 🎓 **Herramientas que Utiliza**

ARESITOS no reinventa la rueda. Utiliza las mejores herramientas de la comunidad:

### 🔍 **Para Escaneo:**
- **nmap**: El rey de los escáneres de red
- **masscan**: Para escaneos súper rápidos
- **nuclei**: Para encontrar vulnerabilidades conocidas
- **gobuster**: Para descubrir directorios ocultos

### 🛡️ **Para Monitoreo:**
- **netstat**: Para vigilar conexiones de red
- **ps**: Para monitorear procesos del sistema
- **inotify**: Para detectar cambios en archivos

### 🔧 **Para Análisis:**
- **lynis**: Para auditorías de seguridad
- **chkrootkit**: Para detectar rootkits
- **rkhunter**: Para análisis adicional de seguridad

---

## 🤝 **¿Cómo Contribuir?**

ARESITOS es un proyecto de código abierto. Puedes ayudar de muchas formas:

### 📝 **Reportar Errores**
- Si encuentras un problema, créalo en GitHub Issues
- Incluye detalles sobre tu sistema y el error
- Mientras más información, mejor podremos ayudarte

### 💡 **Sugerir Mejoras**
- ¿Se te ocurre una función nueva?
- ¿Hay algo que podría ser más fácil de usar?
- Comparte tus ideas en GitHub Discussions

### 🔧 **Contribuir Código**
- El código está en GitHub para que lo explores
- Sigue las guías de contribución
- Todas las mejoras son bienvenidas

---

## 📞 **Soporte y Contacto**

### 📖 **Documentación Completa**
En la carpeta `documentacion/` encontrarás:
- **Guías técnicas detalladas**
- **Manuales de cada módulo**
- **Solución de problemas comunes**
- **Ejemplos de uso avanzado**

### 🤝 **Contacto Directo**
- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Email**: dogsouldev@protonmail.com
- **Issues**: Para reportar problemas o sugerencias
- **Discussions**: Para preguntas generales

---

## 📜 **Licencia y Uso Responsable**

### ✅ **Uso Permitido (Gratuito)**
ARESITOS es completamente gratuito para:
- **Estudiantes** y fines educativos
- **Investigación** académica y personal
- **Proyectos** de código abierto
- **Aprendizaje** y capacitación
- **Uso personal** en tus propios sistemas

### ❌ **Uso Prohibido**
No puedes usar ARESITOS para:
- **Vender** la herramienta o servicios comerciales con ella
- **Consultoría** comercial de pago
- **Productos** comerciales sin autorización
- **Actividades ilegales** de cualquier tipo

### 🛡️ **Código de Ética**
**IMPORTANTE**: ARESITOS debe usarse solo de forma ética y legal:
- ✅ **Solo en sistemas propios** o con permiso explícito
- ✅ **Para mejorar la seguridad**, no para dañar
- ✅ **Siguiendo las leyes** de tu país
- ❌ **Nunca para actividades maliciosas**

### 📋 **Atribución**
Si usas ARESITOS en proyectos o presentaciones, por favor menciona:
- **Creador**: DogSoulDev
- **Fuente**: https://github.com/DogSoulDev/Aresitos
- **Licencia**: Open Source No Comercial

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
