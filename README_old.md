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

---

### 2. Vista de Herramientas - Configuración Automática
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)

**¿Qué es esta pantalla?**
Una ventana especial que aparece solo la primera vez que usas Aresitos. Su trabajo es configurar automáticamente todas las herramientas de seguridad que necesitas.

**¿Qué hace por ti?**
- **Instala herramientas modernas**: nmap, nuclei, gobuster y más de 20 herramientas avanzadas
- **Configura permisos**: Te permite usar las herramientas sin escribir contraseñas constantemente
- **Actualiza bases de datos**: Descarga las últimas definiciones de vulnerabilidades
- **Prepara el entorno**: Deja todo listo para que puedas empezar a trabajar inmediatamente

### 3. Vista Principal - Centro de Comando
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

## 🚀 Proceso de Instalación

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

En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos.
DogSoulDev.