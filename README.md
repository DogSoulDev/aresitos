![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0 🛡️
**Suite Profesional de Ciberseguridad para Kali Linux - Arquitectura 100% Python**

Suite completa de ciberseguridad con **arquitectura 100% Python stdlib** sin dependencias externas. Combina escaneado avanzado de 10 fases, monitoreo FIM con detección de rootkits, análisis SIEM con 50 puertos críticos, gestión dinámica de datos y cuarentena automática en interfaz moderna con tema Burp Suite y **terminales integrados en tiempo real**.

## 🚀 **¿Qué hace ARESITOS?**

ARESITOS es una **suite integral de ciberseguridad** que te permite:

### 🔍 **Escaneado Avanzado de 10 Fases**
- **Fase 1-3**: Escaneo básico, servicios y vulnerabilidades en puertos críticos
- **Fase 4-6**: Análisis de procesos, configuraciones de red y servicios activos  
- **Fase 7**: Detección de backdoors y conexiones sospechosas
- **Fase 8**: Análisis avanzado con herramientas Kali (nmap, lsof, netstat)
- **Fase 9**: Verificación de configuraciones de seguridad del sistema
- **Fase 10**: Detección de rootkits con chkrootkit, rkhunter y lynis
- **Clasificación automática de riesgos**: CRÍTICO/ALTO/MEDIO/BAJO con detalles técnicos

### 🛡️ **Monitoreo de Integridad (FIM) Avanzado**
- **Vigilancia en tiempo real** de archivos críticos del sistema
- **Fase 2.5 especializada**: Análisis de módulos del kernel y detección de backdoors
- **Integración completa con Kali**: inotifywait, LinPEAS, chkrootkit, rkhunter, yara, clamav
- **Base de datos SQLite** con histórico completo de cambios y análisis forense
- **Alertas inmediatas** ante modificaciones no autorizadas con contexto completo

### 🔐 **SIEM Profesional con Monitoreo de 50 Puertos**
- **Monitoreo crítico** de puertos sensibles categorizados por tipo de servicio
- **Análisis de conexiones** con detección de IPs sospechosas y conexiones no autorizadas
- **Correlación de eventos** entre todos los módulos con métricas avanzadas
- **Dashboard en tiempo real** con estadísticas de CPU, RAM, red y amenazas
- **Logs centralizados** con rotación automática y análisis de patrones

### 🦠 **Cuarentena Inteligente**
- **Análisis de malware** con ClamAV, YARA, Binwalk y Volatility3
- **Respuesta automática** ante amenazas críticas con preservación forense
- **Sistema de cuarentena segura** con aislamiento completo de archivos
- **Análisis forense detallado** con herramientas especializadas de Kali

### 📊 **Gestión Dinámica de Datos**
- **Sistema completamente dinámico** para cheatsheets, diccionarios y wordlists
- **Actualización automática** de listas basada en archivos reales
- **Botones de gestión**: Refrescar, Abrir Carpeta, Estadísticas
- **Soporte multi-formato**: .txt, .md, .json con iconos diferenciados

## 💼 **¿Cómo te ayuda en tu día a día?**

### **👨‍💻 Para Estudiantes de Ciberseguridad:**
- **Aprende pentesting avanzado** con 80+ herramientas reales integradas
- **Comprende detección de rootkits** con chkrootkit, rkhunter y lynis
- **Practica análisis forense** con Volatility3, Binwalk y YARA
- **Interfaz educativa** con logs explicativos paso a paso

### **🔒 Para Profesionales de Seguridad:**
- **Automatiza auditorías completas** con escaneado de 10 fases
- **Monitoreo avanzado** de 50 puertos críticos en tiempo real
- **Detección de amenazas persistentes** con análisis de kernel
- **Reportes automáticos** con evidencia forense completa

### **🏢 Para Equipos SOC:**
- **SIEM ligero y potente** sin dependencias complejas
- **Terminales integrados** para respuesta rápida a incidentes
- **Dashboard centralizado** con métricas de amenazas en tiempo real
- **Gestión dinámica de IOCs** y wordlists de amenazas

## ⚡ **Instalación Ultra-Rápida**

```bash
# 1. Crear carpeta y clonar
mkdir -p ~/Ares && cd ~/Ares
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configuración automática
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# 3. ¡Ejecutar!
python3 main.py
```

**🎯 Compatibilidad**: Kali 2024.x+, Parrot Security, BlackArch, Ubuntu 22.04+

## 🏗️ **Características Técnicas Avanzadas**

### **✨ Nuevas Funcionalidades v2.0:**
- **🖥️ Terminales integrados** en todas las vistas con logs en tiempo real
- **📊 Dashboard mejorado** con cheatsheets dinámicos y búsqueda interactiva
- **🔧 Tema Burp Suite** consistente en toda la aplicación
- **⚡ 80+ herramientas Kali** optimizadas e integradas (nmap, chkrootkit, rkhunter, lynis, clamav)
- **🎯 Sistema dinámico completo** para cheatsheets, diccionarios y wordlists
- **🔍 Escaneador de 10 fases** con detección avanzada de rootkits
- **🛡️ SIEM con 50 puertos críticos** monitoreados en tiempo real
- **🦠 FIM con análisis de kernel** y detección de backdoors

### **🎯 Stack 100% Python Stdlib**
- **Core**: tkinter, subprocess, sqlite3, hashlib, threading, pathlib
- **Herramientas Kali**: nmap, masscan, gobuster, nikto, nuclei, chkrootkit, rkhunter, lynis, clamav
- **Análisis forense**: volatility3, binwalk, yara, john, hashcat, strings, exiftool
- **Sin dependencias externas**: Superficie de ataque mínima, instalación limpia
- **Arquitectura MVC robusta**: 54 archivos, gestión dinámica de datos

### **📊 Métricas de Código Actualizadas**
- **Controladores**: 15 archivos (lógica de negocio con nuevas funcionalidades)
- **Modelos**: 19 archivos (persistencia optimizada y gestión dinámica)
- **Vistas**: 12 archivos (interfaz con terminales integrados y sistema dinámico)
- **Utils**: 4 archivos (utilidades del sistema y verificaciones)
- **✅ Calidad**: 0 errores | Sistema dinámico completo | 50+ terminales activos

### **🔧 Nuevas Capacidades Técnicas:**
- **Sistema de archivos dinámico**: Listas que reflejan contenido real de carpetas
- **Botones de gestión avanzada**: Refrescar, Abrir Carpeta, Estadísticas automáticas
- **Detección de rootkits profesional**: chkrootkit + rkhunter + lynis integrados
- **Análisis de puertos críticos**: 50 puertos categorizados por servicio
- **Gestión multi-formato**: .txt, .md, .json con iconos y validación automática

## 🎮 **Uso Práctico**

### **🚀 Inicio Rápido**
```bash
# Desarrollo (Windows/Linux no-Kali)
python3 main.py --dev

# Producción (Kali Linux)
python3 main.py
```

### **🎯 Flujo de Trabajo Recomendado**
1. **Login** → Autenticación y configuración inicial
2. **Dashboard** → Verificar estado del sistema y acceder a cheatsheets dinámicos
3. **Gestión de Datos** → Verificar diccionarios y wordlists actualizados
4. **Escaneador** → IP objetivo → "Escanear Sistema Completo" (10 fases)
5. **FIM** → "Crear Baseline" → "Análisis de Kernel" → "Monitoreo Continuo"
6. **SIEM** → "Monitorear 50 Puertos" → "Análisis de Conexiones Críticas"
7. **Reportes** → Generar documentación con evidencia forense

### **💡 Casos de Uso Típicos**
- **Auditoría Completa**: Escaneado 10 fases + FIM con kernel + SIEM 50 puertos
- **Detección de Rootkits**: FIM Fase 2.5 + chkrootkit + rkhunter + lynis
- **Análisis de Malware**: Cuarentena + ClamAV + YARA + Volatility3 + Binwalk
- **Incident Response**: SIEM en tiempo real + análisis forense automatizado
- **Gestión de IOCs**: Sistema dinámico de wordlists y diccionarios actualizables

### **🔧 Nuevas Funcionalidades de Gestión**
- **Cheatsheets Dinámicos**: Lista actualizable, búsqueda interactiva, soporte .txt/.md
- **Gestión de Wordlists**: Refrescar lista, abrir carpeta, estadísticas automáticas
- **Diccionarios Inteligentes**: Sistema completamente dinámico basado en archivos reales
- **Botones de Gestión**: 🔄 Refrescar, 📁 Abrir Carpeta, 📊 Estadísticas en cada sección

## 📁 **Estructura del Proyecto**

```
Aresitos/
├── main.py                         # 🚀 Punto de entrada principal
├── configurar_kali.sh              # ⚙️ Setup automático de dependencias Kali
├── aresitos/
│   ├── controlador/                # 15 controladores MVC
│   │   ├── controlador_principal.py    # Controlador principal con gestión avanzada
│   │   ├── controlador_escaneo.py      # Escaneador de 10 fases
│   │   ├── controlador_fim.py          # FIM con análisis de kernel
│   │   ├── controlador_siem.py         # SIEM con 50 puertos críticos
│   │   └── controlador_cuarentena.py   # Análisis de malware avanzado
│   ├── modelo/                     # 19 modelos de datos
│   │   ├── modelo_escaneador_kali2025.py    # Escaneador avanzado
│   │   ├── modelo_fim_kali2025.py           # FIM con detección de rootkits
│   │   ├── modelo_siem_kali2025.py          # SIEM profesional
│   │   ├── modelo_gestor_wordlists.py       # Gestión dinámica de wordlists
│   │   └── modelo_gestor_diccionarios.py    # Gestión dinámica de diccionarios
│   ├── vista/                      # 12 vistas con terminales integrados
│   │   ├── vista_dashboard.py           # 🆕 Dashboard con cheatsheets dinámicos
│   │   ├── vista_gestion_datos.py       # 🆕 Gestión dinámica de datos
│   │   ├── vista_escaneo.py             # Escaneador de 10 fases
│   │   ├── vista_fim.py                 # FIM con análisis de kernel
│   │   ├── vista_siem.py                # SIEM con monitoreo avanzado
│   │   ├── terminal_mixin.py            # Sistema de terminales integrados
│   │   └── burp_theme.py               # Tema profesional Burp Suite
│   └── utils/                      # 4 utilidades del sistema
│       ├── verificar_kali.py           # Verificación de entorno Kali
│       └── gestor_permisos.py          # Gestión segura de permisos
├── data/                           # Datos dinámicos y bases de datos
│   ├── cheatsheets/                    # 🆕 Cheatsheets dinámicos (.txt/.md)
│   ├── diccionarios/                   # 🆕 Diccionarios JSON dinámicos
│   ├── wordlists/                      # 🆕 Wordlists dinámicas (.txt/.json)
│   ├── cuarentena/                     # Sistema de cuarentena segura
│   └── *.db                           # Bases de datos SQLite optimizadas
├── logs/                           # Sistema de logs centralizado
├── configuración/                  # Configuraciones JSON dinámicas
└── documentacion/                  # Guías técnicas completas
```

## 🔧 **Configuración Avanzada**

### **🎛️ Personalización**
- **Temas**: Burp Suite (oscuro) incluido, personalizable
- **Logs**: Niveles DEBUG/INFO/WARNING/ERROR configurables  
- **Base de datos**: SQLite optimizada para alto rendimiento
- **Herramientas**: Configuración por módulo independiente
- **🆕 Sistema dinámico**: Gestión automática de archivos y actualizaciones

### **🚀 Rendimiento Optimizado**
- **Multithreading**: Operaciones paralelas sin bloqueos en 10 fases
- **Memoria optimizada**: < 50MB RAM en operación normal
- **Tiempo de inicio**: < 3 segundos en Kali Linux
- **Escalabilidad**: Probado hasta 10,000 eventos simultáneos
- **🆕 Cache inteligente**: Sistema de índices automáticos para wordlists y diccionarios

### **🔒 Seguridad Mejorada**
- **Detección de rootkits**: chkrootkit + rkhunter + lynis integrados
- **Análisis de kernel**: Detección de módulos maliciosos en tiempo real
- **50 puertos críticos**: Monitoreo categorizado por tipo de servicio
- **Análisis forense**: Volatility3, Binwalk, YARA para malware avanzado

## 🆕 **Novedades de esta Versión**

### **✨ Sistema Completamente Dinámico**
- **Cheatsheets dinámicos**: La lista refleja exactamente los archivos en `/data/cheatsheets/`
- **Diccionarios actualizables**: Gestión automática de archivos JSON en tiempo real
- **Wordlists inteligentes**: Soporte .txt y .json con actualización automática
- **Botones de gestión**: 🔄 Refrescar, 📁 Abrir Carpeta, 📊 Estadísticas en cada sección

### **🔍 Escaneador Revolucionario de 10 Fases**
- **Fases 1-7**: Escaneado tradicional mejorado con más detalle
- **Fase 8**: Análisis avanzado con herramientas nativas de Kali
- **Fase 9**: Verificación de configuraciones de seguridad críticas
- **Fase 10**: Detección profesional de rootkits con múltiples herramientas

### **🛡️ FIM con Análisis de Kernel**
- **Fase 2.5 especializada**: Análisis de módulos del kernel con `lsmod`
- **Detección de backdoors**: Búsqueda de ejecutables sospechosos en `/tmp`
- **Monitoreo de procesos**: Análisis jerárquico con `ps auxf`
- **Integración completa**: chkrootkit, rkhunter, yara, clamav

### **🔐 SIEM con 50 Puertos Críticos**
- **Categorización avanzada**: Web, Base de datos, Sistema, Red, Seguridad
- **Análisis de conexiones**: Detección de IPs sospechosas y conexiones no autorizadas
- **Monitoreo en tiempo real**: Estado continuo de servicios críticos
- **Correlación inteligente**: Eventos entre módulos con contexto completo

## ⚖️ **Licencia & Uso Ético**

**📜 Open Source License** con atribución:
- ✅ **Uso libre**: Personal, comercial, educativo, investigación
- ✅ **Modificación permitida**: Fork, personalización, integración
- ✅ **Distribución libre**: Compartir, redistribuir, comercializar
- ⚠️ **Atribución obligatoria**: Mencionar **DogSoulDev** y repositorio

**🛡️ COMPROMISO ÉTICO**: Solo para sistemas propios, pentesting autorizado, investigación educativa. Prohibido para actividades ilegales.

## 🔗 **Enlaces y Soporte**
- **📂 Repositorio**: https://github.com/DogSoulDev/Aresitos
- **📧 Contacto**: dogsouldev@protonmail.com  
- **📚 Documentación**: `/documentacion/` en el proyecto
- **🐛 Issues**: GitHub Issues para reportar problemas

---

## En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos, DogSoulDev

---

*Desarrollado con ❤️ por DogSoulDev para la comunidad global de ciberseguridad*