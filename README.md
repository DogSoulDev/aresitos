# 🛡️ ARESITOS - Advanced Security Toolkit

**Aresitos** es una suite integral de ciberseguridad desarrollada para profesionales en seguridad informática. Combina herramientas de escaneo, monitoreo, análisis de vulnerabilidades, gestión de wordlists y generación de reportes en una interfaz unificada y optimizada.

## 🎯 Características Principales

### 🔍 **Módulo de Escaneo y Análisis**
- Escaneo de puertos con nmap
- Análisis de servicios activos
- Detección de vulnerabilidades
- Sistema SIEM integrado
- Monitoreo de procesos

### 📊 **Módulo de Monitoreo en Tiempo Real**
- Monitoring de recursos del sistema
- Seguimiento de conexiones de red
- Sistema de cuarentena para archivos sospechosos
- Alertas de seguridad automáticas

### 🛠️ **Módulo de Utilidades Avanzadas**
- Verificación de herramientas de seguridad
- Auditorías con Lynis
- Detección de rootkits (chkrootkit)
- Gestión de wordlists para pentesting
- Diccionarios de ciberseguridad
- Análisis de permisos y configuraciones
- Limpieza automática del sistema

### 📋 **Sistema de Reportes**
- Reportes completos en JSON/TXT
- Análisis de riesgo con scoring
- Recomendaciones técnicas
- Exportación de datos

## 📋 Requisitos del Sistema

### **Sistemas Operativos Soportados**
- ✅ **Kali Linux** (Recomendado - Funcionalidad completa)
- ✅ **Ubuntu/Debian** (Funcionalidad extendida)
- ⚠️ **Otras distribuciones Linux** (Funcionalidad básica)
- ❌ **Windows** (No soportado)

### **Dependencias**
```bash
# Python 3.8 o superior
python3 --version

# Dependencias del sistema
sudo apt update
sudo apt install python3-tk python3-pip
```

### **Herramientas de Seguridad** (Opcionales)
```bash
# Herramientas críticas para funcionalidad completa
sudo apt install nmap lynis chkrootkit rkhunter netcat-traditional
```

## 🚀 Instalación

### **Instalación Rápida**
```bash
# Clonar repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Ejecutar directamente
python3 main.py
```

### **Verificación de Instalación**
```bash
# Verificar herramientas
nmap --version
lynis --version
chkrootkit -V
```

## 💻 Uso de la Aplicación

### **Iniciar Aresitos**
```bash
python3 main.py
```

### **Interfaz de Usuario**
La aplicación cuenta con una interfaz gráfica moderna de **1400x900** píxeles con las siguientes pestañas:

#### 🔍 **Escaneo y SIEM**
- Escaneo de red y puertos
- Análisis de vulnerabilidades
- Sistema de eventos de seguridad
- Análisis de logs

#### 📊 **Monitoreo y Cuarentena**
- Monitor en tiempo real
- Gestión de archivos en cuarentena
- Análisis de procesos sospechosos
- Alertas de seguridad

#### 🛠️ **Herramientas**
- Verificación de tools de seguridad
- Información de hardware
- Análisis de procesos
- Verificación de permisos
- Limpieza del sistema

#### 🔒 **Auditoría**
- Ejecución de Lynis
- Detección de rootkits
- Análisis de configuraciones

#### 📋 **Reportes**
- Generación de reportes técnicos
- Exportación en JSON/TXT
- Histórico de análisis

#### 📝 **Wordlists**
- Gestión de wordlists para pentesting
- Importación/exportación
- Wordlists predefinidas:
  - Passwords comunes
  - Usuarios estándar
  - Directorios web
  - Subdominios
  - Extensiones de archivos

#### 📚 **Diccionarios**
- Diccionarios técnicos de ciberseguridad
- Términos de vulnerabilidades
- Herramientas de seguridad
- Términos forenses

## 🧪 Testing

### **Ejecutar Suite Completa de Tests**
```bash
cd tests
python3 run_tests.py
```

### **Tests Específicos**
```bash
# Listar tests disponibles
python3 run_tests.py --list

# Ejecutar test específico
python3 run_tests.py --module test_escaneador
```

### **Tests Disponibles**
- `test_escaneador.py` - Funciones de escaneo
- `test_monitor.py` - Monitoreo del sistema
- `test_cuarentena.py` - Sistema de cuarentena
- `test_utilidades.py` - Utilidades del sistema
- `test_reportes.py` - Generación de reportes
- `test_wordlists_diccionarios.py` - Gestión de wordlists
- `test_integracion.py` - Tests de integración

## 📁 Arquitectura del Proyecto

```
Aresitos/
├── main.py                     # Punto de entrada - Ventana 1400x900
├── README.md                   # Documentación completa
├── .gitignore                  # Control de versiones
├── ares_aegis/                 # Paquete principal
│   ├── __init__.py
│   ├── modelo/                 # Lógica de negocio
│   │   ├── modelo_principal.py # Modelo principal MVC
│   │   ├── escaneador.py       # Escaneo y análisis
│   │   ├── monitor.py          # Monitoreo en tiempo real
│   │   ├── cuarentena.py       # Gestión de cuarentena
│   │   ├── utilidades.py       # Utilidades del sistema
│   │   ├── reportes.py         # Generación de reportes
│   │   ├── siem.py             # Sistema SIEM
│   │   ├── gestor_wordlists.py # Gestión de wordlists
│   │   └── gestor_diccionarios.py # Gestión de diccionarios
│   ├── vista/                  # Interfaz gráfica (tkinter)
│   │   ├── vista_principal.py  # Vista principal
│   │   ├── vista_escaneo.py    # Interfaz de escaneo
│   │   ├── vista_monitoreo.py  # Interfaz de monitoreo
│   │   └── vista_utilidades.py # Interfaz de utilidades
│   └── controlador/            # Controladores MVC
│       ├── controlador_principal.py
│       ├── controlador_escaneo.py
│       ├── controlador_monitoreo.py
│       └── controlador_utilidades.py
└── tests/                      # Suite de testing
    ├── __init__.py
    ├── run_tests.py            # Ejecutor de tests
    └── test_*.py               # Tests individuales (7 archivos)
```

## 🏗️ Arquitectura Técnica

### **Patrón MVC (Model-View-Controller)**
- **Modelo**: Lógica de negocio y manejo de datos
- **Vista**: Interfaz gráfica con tkinter optimizada
- **Controlador**: Coordinación entre modelo y vista

### **Características Técnicas**
- ✅ Interfaz optimizada (1400x900 px)
- ✅ Textos técnicos en inglés para profesionales
- ✅ Mensajes de error concisos
- ✅ Sin emoticonos - Interfaz profesional
- ✅ Threading para operaciones no bloqueantes
- ✅ Manejo robusto de errores
- ✅ Logging detallado

## 🔧 Funcionalidades Avanzadas

### **Sistema de Wordlists**
```bash
# Wordlists predefinidas incluidas:
- passwords_comunes (25 passwords críticos)
- usuarios_comunes (25 usuarios estándar)
- directorios_web (25 paths comunes)
- subdominios (25 subdominios típicos)
- extensiones_archivo (25 extensiones)
```

### **Diccionarios Técnicos**
- **Vulnerabilidades Comunes**: CVE, XSS, SQLi, etc.
- **Herramientas de Seguridad**: nmap, Metasploit, Wireshark, etc.
- **Términos Forenses**: Imaging, Timeline, Artifacts, etc.

### **Sistema de Reportes**
- Scoring de seguridad (0-100)
- Recomendaciones técnicas específicas
- Exportación en múltiples formatos
- Histórico de análisis

## 🛡️ Consideraciones de Seguridad

### **Permisos Requeridos**
- Algunos módulos requieren privilegios de administrador
- Se recomienda ejecutar con `sudo` para funcionalidad completa

### **Mejores Prácticas**
- Ejecutar en entorno controlado
- Revisar logs de auditoría regularmente
- Mantener herramientas actualizadas
- Backup de configuraciones críticas

## 🤝 Desarrollo y Contribución

### **Estructura de Desarrollo**
```bash
# Configurar entorno de desarrollo
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Ejecutar tests
cd tests && python3 run_tests.py

# Contribuir
git checkout -b feature/nueva-funcionalidad
git commit -am 'Add: nueva funcionalidad'
git push origin feature/nueva-funcionalidad
```

### **Estándares de Código**
- Python 3.8+
- PEP 8 compliance
- Documentación inline
- Tests unitarios obligatorios
- Arquitectura MVC estricta

## 📊 Changelog Recent

### **v2.0** - Interfaz Profesional
- ✅ Ventana redimensionada a 1400x900
- ✅ Textos técnicos optimizados
- ✅ Eliminación completa de emoticonos
- ✅ Mensajes en inglés técnico
- ✅ Interfaz profesional para expertos

### **v1.5** - Gestión de Wordlists
- ✅ Sistema completo de wordlists
- ✅ Diccionarios de ciberseguridad
- ✅ Importación/exportación de datos
- ✅ Suite de tests ampliada

## 📞 Soporte y Contacto

### **Reportar Issues**
- Usar GitHub Issues
- Incluir logs y versión del sistema
- Describir pasos para reproducir

### **Información del Desarrollador**
- **Autor**: DogSoulDev
- **GitHub**: [@DogSoulDev](https://github.com/DogSoulDev)
- **Proyecto**: [Aresitos](https://github.com/DogSoulDev/Aresitos)

## 📄 Licencia

Este proyecto está bajo la **Licencia MIT**. Ver archivo `LICENSE` para detalles completos.

---

## 🏆 Reconocimientos

- **Kali Linux Team** - Por las herramientas base de seguridad
- **Comunidad de Ciberseguridad** - Por el feedback y testing
- **Contribuidores Open Source** - Por las mejoras del proyecto

---

**⚠️ Disclaimer**: Aresitos está diseñado para profesionales en ciberseguridad y uso ético. El autor no se hace responsable del mal uso de esta herramienta.

**🎯 Target Audience**: Pentesting profesional, auditorías de seguridad, análisis forense, administradores de sistemas.
