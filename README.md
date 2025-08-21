![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0 🛡️
**Suite Profesional de Ciberseguridad para Kali Linux - Arquitectura 100% Python**

Suite completa de ciberseguridad con **arquitectura 100% Python stdlib** sin dependencias externas. Combina escaneado avanzado, monitoreo FIM, análisis SIEM, detección de malware y cuarentena automática en interfaz moderna con tema Burp Suite y **terminales integrados en tiempo real**.

## 🚀 **¿Qué hace ARESITOS?**

ARESITOS es una **suite integral de ciberseguridad** que te permite:

### 🔍 **Escaneado y Análisis**
- **Escaneo automático de vulnerabilidades** en puertos críticos (SSH, RDP, SMB, bases de datos)
- **Detección de procesos maliciosos** (backdoors, rootkits, miners, shells inversas)
- **Análisis de DNS y túneles sospechosos**
- **Clasificación automática de riesgos**: CRÍTICO/ALTO/MEDIO/BAJO

### 🛡️ **Monitoreo de Integridad (FIM)**
- **Vigilancia en tiempo real** de archivos críticos (/etc/passwd, /etc/shadow, sudoers)
- **Integración con herramientas Kali**: LinPEAS, chkrootkit, auditd
- **Base de datos SQLite** con histórico completo de cambios
- **Alertas inmediatas** ante modificaciones no autorizadas

### 🔐 **SIEM Profesional**
- **Correlación de eventos** entre todos los módulos
- **Dashboard en tiempo real** con métricas de CPU, RAM, red y amenazas
- **Logs centralizados** con rotación automática
- **Detección de anomalías** con algoritmos nativos

### 🦠 **Cuarentena Inteligente**
- **Análisis de malware** con ClamAV, YARA y Binwalk
- **Respuesta automática** ante amenazas críticas
- **Preservación forense** de evidencia
- **Sistema de restauración** para falsos positivos

## 💼 **¿Cómo te ayuda en tu día a día?**

### **👨‍💻 Para Estudiantes de Ciberseguridad:**
- **Aprende pentesting** con herramientas reales integradas
- **Comprende arquitecturas** MVC profesionales
- **Practica con 60+ comandos** nativos de Kali Linux
- **Interfaz educativa** con logs explicativos paso a paso

### **🔒 Para Profesionales de Seguridad:**
- **Automatiza auditorías** de sistemas Linux
- **Monitoreo continuo** de infraestructura crítica
- **Correlación de eventos** para detección avanzada
- **Reportes automáticos** para compliance y documentación

### **🏢 Para Equipos SOC:**
- **SIEM ligero** sin dependencias complejas
- **Terminales integrados** para respuesta rápida
- **Dashboard centralizado** para múltiples sistemas
- **Alertas en tiempo real** con contexto completo

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
- **📊 Dashboard mejorado** con métricas de sistema avanzadas
- **🔧 Tema Burp Suite** consistente en toda la aplicación
- **⚡ 60+ herramientas Kali** optimizadas e integradas
- **🎯 Interfaz PanedWindow** para mejor experiencia de usuario

### **🎯 Stack 100% Python Stdlib**
- **Core**: tkinter, subprocess, sqlite3, hashlib, threading
- **Herramientas Kali**: nmap, netstat, LinPEAS, ClamAV via subprocess
- **Sin dependencias externas**: Superficie de ataque mínima
- **Arquitectura MVC robusta**: 52 archivos, 0 errores

### **📊 Métricas de Código**
- **Controladores**: 15 archivos (lógica de negocio)
- **Modelos**: 19 archivos (persistencia y datos)
- **Vistas**: 12 archivos (interfaz con terminales integrados)
- **Utils**: 4 archivos (utilidades del sistema)
- **✅ Calidad**: 0 errores | 0 duplicaciones | 48 terminales activos

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
2. **Dashboard** → Verificar estado del sistema y métricas
3. **Escaneador** → IP objetivo → "Escanear Sistema Completo"
4. **FIM** → "Crear Baseline" → "Iniciar Monitoreo Continuo"
5. **SIEM** → "Iniciar Análisis" → Correlación automática de eventos
6. **Reportes** → Generar documentación profesional

### **💡 Casos de Uso Típicos**
- **Auditoría de Red**: Escaneo + FIM + SIEM activos simultáneamente
- **Incident Response**: Cuarentena automática + análisis forense
- **Compliance**: Reportes automáticos con evidencia completa
- **Formación**: Logs educativos en tiempo real para aprendizaje

## 📁 **Estructura del Proyecto**

```
Aresitos/
├── main.py                         # 🚀 Punto de entrada principal
├── configurar_kali.sh              # ⚙️ Setup automático de dependencias
├── aresitos/
│   ├── controlador/                # 15 controladores MVC
│   │   ├── controlador_principal.py
│   │   ├── controlador_escaneo.py
│   │   ├── controlador_fim.py
│   │   └── controlador_siem.py
│   ├── modelo/                     # 19 modelos de datos
│   │   ├── modelo_escaneador.py
│   │   ├── modelo_fim.py
│   │   └── modelo_siem.py
│   ├── vista/                      # 12 vistas con terminales integrados
│   │   ├── vista_dashboard.py
│   │   ├── terminal_mixin.py       # 🆕 Sistema de terminales
│   │   └── burp_theme.py          # 🆕 Tema profesional
│   └── utils/                      # 4 utilidades del sistema
├── data/                           # Bases de datos SQLite + wordlists
├── logs/                           # Sistema de logs centralizado
└── documentacion/                  # Guías técnicas completas
```

## 🔧 **Configuración Avanzada**

### **🎛️ Personalización**
- **Temas**: Burp Suite (oscuro) incluido, personalizable
- **Logs**: Niveles DEBUG/INFO/WARNING/ERROR configurables  
- **Base de datos**: SQLite optimizada para alto rendimiento
- **Herramientas**: Configuración por módulo independiente

### **🚀 Rendimiento**
- **Multithreading**: Operaciones paralelas sin bloqueos
- **Memoria optimizada**: < 50MB RAM en operación normal
- **Tiempo de inicio**: < 3 segundos en Kali Linux
- **Escalabilidad**: Probado hasta 10,000 eventos simultáneos

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