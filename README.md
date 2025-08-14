# 🛡️ ARESITOS - Herramienta Avanzada de Auditoría de Seguridad

![Ares Aegis](recursos/AresAegis.png)

**Aresitos** es una herramienta integral de ciberseguridad desarrollada para profesionales de seguridad informática, parte del ecosistema **Ares Aegis**. Combina herramientas de escaneo, monitoreo, análisis de vulnerabilidades, gestión avanzada de wordlists y generación de reportes en una interfaz unificada y optimizada con **procesamiento de datos en tiempo real**.

## 🏗️ Información del Proyecto

**Aresitos** forma parte del ecosistema de herramientas de ciberseguridad **Ares Aegis**, siendo una de las primeras herramientas especializadas del conjunto. Este proyecto representa el desarrollo continuo de soluciones profesionales de seguridad.

### **Repositorios del Proyecto**
- **🚀 Repositorio Principal**: [Aresitos](https://github.com/DogSoulDev/Aresitos) - Herramienta principal de auditoría
- **🧪 Repositorio de Pruebas**: [Ares-Aegis](https://github.com/DogSoulDev/Ares-Aegis) - Entorno de desarrollo y testing

### **Créditos de Desarrollo**
- **👨‍💻 Creado por**: [DogSoulDev](https://github.com/DogSoulDev)
- **🤖 Editado y Optimizado por**: GitHub Copilot
- **🔄 Desarrollo Colaborativo**: Humano + IA para máxima eficiencia

## 🎯 Características Principales

### 🔍 **Módulo de Escaneo Avanzado**
- **Escaneo de puertos en tiempo real** con integración nmap
- **Análisis de servicios en vivo** y detección
- **Evaluación de vulnerabilidades** con base de datos CVE
- **Sistema SIEM avanzado** con correlación de eventos
- **Monitoreo de red** y detección de amenazas
- **Capacidades de escaneo sigiloso**

### 📊 **Monitoreo del Sistema en Tiempo Real**
- **Monitoreo de recursos en vivo** (CPU, Memoria, Disco, Red)
- **Análisis de comportamiento de procesos** con detección de anomalías
- **Seguimiento de conexiones de red** y alertas de actividad sospechosa
- **Monitoreo de Integridad de Archivos (FIM)** con verificación de hash
- **Alertas de seguridad automatizadas** y notificaciones
- **Búsqueda de amenazas en segundo plano**

### 🛠️ **Utilidades de Seguridad Profesionales**
- **Verificación de herramientas de seguridad** y validación
- **Auditoría de seguridad Lynis** integrada
- **Detección de rootkits** (chkrootkit, rkhunter)
- **Gestión avanzada de wordlists** con carga automática
- **Diccionarios técnicos de ciberseguridad** (13+ categorías)
- **Análisis de permisos y configuración**
- **Limpieza y optimización del sistema**

### 📋 **Reportes de Nivel Empresarial**
- **Reportes integrales** en formatos JSON/TXT/Markdown
- **Puntuación de riesgo** con métricas profesionales
- **Recomendaciones técnicas** y pasos de remediación
- **Exportación de datos** y análisis histórico
- **Resúmenes ejecutivos** para gerencia

### 📝 **Sistema Dinámico de Wordlists**
- **16+ categorías de wordlists** cargadas automáticamente
- **1,266 contraseñas avanzadas** + colecciones personalizadas
- **994 endpoints de API** + definiciones personalizadas
- **930 directorios web** + rutas empresariales
- **852 subdominios** + listas personalizadas
- **Extensible por el usuario** - agregar archivos JSON para carga automática

### 📚 **Base de Datos de Diccionarios Técnicos**
- **13+ diccionarios especializados** cargados automáticamente
- **418 términos de ciberseguridad** + definiciones personalizadas
- **406 herramientas de hacking** + descripciones técnicas
- **371 técnicas MITRE ATT&CK** y tácticas
- **300 tipos de vulnerabilidades** + información de exploits
- **Sistema de auto-descubrimiento** para nuevos diccionarios JSON

## 📋 Requisitos del Sistema

### **Sistemas Operativos Soportados**
- ✅ **Kali Linux** (Recomendado - Funcionalidad completa)
- ✅ **Ubuntu/Debian** (Funcionalidad extendida)
- ✅ **CentOS/RHEL** (Funcionalidad básica)
- ✅ **Windows** (Funcionalidad limitada - algunas características requieren WSL)
- ⚠️ **Otras distribuciones Linux** (Funcionalidad básica)

### **Dependencias**
```bash
# Python 3.8 o superior requerido
python3 --version

# Dependencias principales del sistema
pip install -r requirements.txt

# Paquetes requeridos:
# - tkinter (incluido en Python)
# - pillow>=10.0.0
# - requests>=2.31.0
# - psutil>=5.9.0
# - python-nmap>=0.7.1
# - scapy>=2.4.5
# - pandas>=2.0.0
# - matplotlib>=3.7.0
# - watchdog>=3.0.0
# - colorlog>=6.7.0
```

### **Herramientas de Seguridad** (Opcionales para funcionalidad completa)
```bash
# Herramientas críticas para conjunto completo de características
sudo apt install nmap masscan nikto gobuster sqlmap
sudo apt install lynis chkrootkit rkhunter
sudo apt install netcat-traditional socat
sudo apt install whatweb dirb
```

## 🚀 Instalación y Configuración

### **Instalación Rápida**
```bash
# Clonar el repositorio principal
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar Aresitos
python main.py
```

### **Instalación desde Repositorio de Desarrollo**
```bash
# Para desarrolladores - Repositorio de testing
git clone https://github.com/DogSoulDev/Ares-Aegis.git
cd Ares-Aegis

# Instalar dependencias de desarrollo
pip install -r requirements.txt

# Ejecutar versión de desarrollo
python main.py
```

### **Verificación de Instalación**
```bash
# Verificar herramientas críticas
nmap --version
lynis --version
python -c "import psutil; print('psutil OK')"
```

### **Verificación de Carga Automática de Datos**
Al iniciar, Ares Aegis automáticamente escanea y carga:
- **Wordlists** desde `data/wordlists/` (archivos TXT y JSON)
- **Diccionarios** desde `data/diccionarios/` (archivos JSON)
- **Configuración** desde el directorio `configuracion/`
- **Personalizaciones del usuario** detectadas automáticamente

## 💻 Interfaz Profesional

### **Ejecutar Aplicación**
```bash
python main.py
```

### **Interfaz GUI Moderna**
Interfaz profesional optimizada para analistas de seguridad con **actualizaciones en tiempo real**:

#### 🔍 **Pestaña Escaneo y SIEM**
- **Escaneo avanzado de puertos** con integración nmap
- **Evaluación de vulnerabilidades** y correlación CVE
- **Monitoreo de eventos de seguridad en tiempo real**
- **Análisis de logs** y detección de patrones
- **Descubrimiento y mapeo de red**

#### 📊 **Pestaña Monitoreo del Sistema**
- **Métricas del sistema en tiempo real** (CPU, RAM, Disco, Red)
- **Monitoreo de procesos** con detección de amenazas
- **Análisis de conexiones de red**
- **Monitoreo de integridad de archivos**
- **Gestión de alertas de seguridad**

#### 🛠️ **Pestaña Herramientas de Seguridad**
- **Verificación de herramientas de seguridad** y estado
- **Información de hardware** y análisis
- **Análisis de procesos** e investigación
- **Verificación de permisos** y endurecimiento
- **Limpieza del sistema** y optimización

#### 🔒 **Pestaña Auditoría de Seguridad**
- **Ejecución de auditoría Lynis**
- **Detección de rootkits** y análisis
- **Evaluación de configuración**
- **Verificación de cumplimiento**
- **Validación de línea base de seguridad**

#### 📋 **Pestaña Reportes Profesionales**
- **Generación de reportes técnicos**
- **Exportación JSON/TXT/Markdown**
- **Análisis histórico** y tendencias
- **Resúmenes ejecutivos**
- **Reportes de cumplimiento**

#### 🗂️ **Pestaña Gestión de Datos**
- **Vista unificada** de wordlists y diccionarios
- **Gestión simplificada** con 5 operaciones principales
- **Carga automática** desde archivos JSON
- **Funcionalidad de importar/exportar**
- **Arquitectura extensible por el usuario**

## 🏗️ Arquitectura Avanzada

### **Motor de Procesamiento en Tiempo Real**
```
Aresitos/
├── main.py                     # Lanzador de aplicación
├── requirements.txt            # Dependencias Python
├── README.md                   # Documentación completa
├── .gitignore                  # Control de versiones
├── .gitattributes             # Configuración Git
├── .vscode/                   # Configuración VS Code
├── pyproject.toml             # Configuración del proyecto
├── clean.sh / clean.bat       # Scripts de limpieza
├── ESTRUCTURA_PROYECTO.md     # Documentación de estructura
├── ares_aegis/                # Paquete principal de aplicación
│   ├── __init__.py
│   ├── modelo/                # Modelos de datos en tiempo real
│   │   ├── modelo_principal.py         # Coordinador principal
│   │   ├── modelo_escaneador.py        # Escáner en tiempo real
│   │   ├── modelo_siem.py              # SIEM con correlación
│   │   ├── modelo_monitor.py           # Monitor del sistema
│   │   ├── modelo_fim.py               # Integridad de archivos
│   │   ├── modelo_gestor_wordlists.py  # Gestor de wordlists
│   │   ├── modelo_gestor_diccionarios.py # Gestor de diccionarios
│   │   ├── modelo_reportes.py          # Generación de reportes
│   │   └── modelo_utilidades_sistema.py # Utilidades del sistema
│   ├── controlador/           # Controladores MVC
│   │   ├── controlador_principal.py    # Controlador principal
│   │   ├── controlador_escaneo.py      # Controlador de escaneo
│   │   ├── controlador_monitoreo.py    # Controlador de monitoreo
│   │   ├── controlador_auditoria.py    # Controlador de auditoría
│   │   ├── controlador_herramientas.py # Controlador de herramientas
│   │   ├── controlador_reportes.py     # Controlador de reportes
│   │   └── controlador_utilidades.py   # Controlador de utilidades
│   ├── vista/                 # UI Profesional (Tkinter con tema Burp Suite)
│   │   ├── vista_principal.py          # Interfaz principal
│   │   ├── vista_escaneo.py            # Interfaz de escaneo
│   │   ├── vista_monitoreo.py          # Panel de monitoreo
│   │   ├── vista_auditoria.py          # Interfaz de auditoría
│   │   ├── vista_herramientas.py       # Interfaz de herramientas
│   │   ├── vista_gestion_datos.py      # Gestión unificada de datos
│   │   ├── vista_reportes.py           # Interfaz de reportes
│   │   ├── vista_utilidades.py         # Interfaz de utilidades
│   │   └── burp_theme.py               # Tema profesional
│   ├── recursos/              # Recursos de aplicación
│   │   ├── AresAegis.png              # Logo principal
│   │   └── aresIcon.png               # Icono de aplicación
│   └── utils/                 # Módulos de utilidades
├── configuracion/             # Archivos de configuración
│   ├── ares_aegis_config.json         # Configuración principal
│   ├── ares_aegis_config_kali.json    # Configuración Kali
│   ├── firmas.txt                     # Firmas de seguridad
│   ├── notificaciones.json            # Configuración notificaciones
│   ├── sistema_ayuda.json             # Sistema de ayuda
│   └── textos_castellano.json         # Textos en español
├── data/                      # Datos cargados automáticamente
│   ├── wordlists/             # 16+ categorías de wordlists
│   │   ├── passwords_top1000.txt      # 1,266 contraseñas
│   │   ├── api_endpoints.txt          # 994 endpoints API
│   │   ├── web_directories.txt        # 930 directorios
│   │   ├── subdomains_common.txt      # 852 subdominios
│   │   └── ejemplo_usuario.json       # Personalizaciones usuario
│   └── diccionarios/          # 13+ diccionarios técnicos
│       ├── cybersecurity_terms.json   # 418 términos seguridad
│       ├── hacking_tools.json         # 406 descripciones herramientas
│       ├── mitre_attack.json          # 371 técnicas ATT&CK
│       ├── vulnerabilities.json       # 300 tipos vulnerabilidades
│       └── ejemplo_usuario.json       # Personalizaciones usuario
└── tests/                     # Suite de pruebas integral
    ├── __init__.py            # Inicialización del módulo
    └── [módulos de prueba]    # Pruebas unitarias e integración
```

## 🔧 Procesamiento de Datos en Tiempo Real

### **Sistema de Carga Automática de Datos**
```bash
# El sistema detecta y carga automáticamente:
- 16+ categorías de wordlists (5,000+ entradas)
- 13+ bases de datos de diccionarios (1,500+ definiciones)
- Archivos JSON del usuario (auto-descubrimiento)
- Actualizaciones de configuración (tiempo real)
```

### **Capacidades de Monitoreo en Vivo**
- **CPU/Memoria/Disco**: Integración psutil en tiempo real
- **Conexiones de Red**: Seguimiento de conexiones en vivo
- **Análisis de Procesos**: Detección de anomalías comportamentales
- **Cambios de Archivos**: Monitoreo de integridad basado en hash
- **Eventos de Seguridad**: Motor de correlación SIEM

### **Características Profesionales**
- **Sin datos simulados** - todas las métricas son en tiempo real
- **Sin modos demo** - funcionalidad lista para producción
- **Arquitectura empresarial** - escalable y robusta
- **Interfaz profesional** - optimizada para analistas

## 🧪 Pruebas Integrales

### **Ejecutar Suite de Pruebas Completa**
```bash
cd tests
python -m pytest
```

### **Categorías de Pruebas Específicas**
```bash
# Ejecutar pruebas unitarias
python -m pytest tests/unit/

# Ejecutar pruebas de integración
python -m pytest tests/integration/

# Ejecutar benchmarks de rendimiento
python -m pytest tests/performance/
```

## 🛡️ Seguridad y Uso Profesional

### **Implementación Profesional**
- Diseñado para **profesionales de ciberseguridad**
- Capacidades de **detección de amenazas en tiempo real**
- **Reportes de nivel empresarial** y documentación
- **Pistas de auditoría** listas para cumplimiento
- **Arquitectura escalable** para entornos de equipo

### **Consideraciones de Seguridad**
- Algunos módulos requieren **privilegios administrativos**
- Ejecución recomendada: `sudo python main.py` para funcionalidad completa
- **Registro de auditoría** para todas las operaciones de seguridad
- **Almacenamiento encriptado** para configuraciones sensibles

### **Mejores Prácticas**
- Ejecutar en **entornos controlados**
- **Actualizaciones regulares** de línea base de seguridad
- **Validación de herramientas** antes de operaciones críticas
- **Respaldo de configuraciones** y datos personalizados

## 🤝 Desarrollo y Contribución

### **Entorno de Desarrollo**
```bash
# Configurar entorno de desarrollo - Repositorio principal
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Para desarrollo avanzado - Repositorio de testing
git clone https://github.com/DogSoulDev/Ares-Aegis.git
cd Ares-Aegis

# Instalar dependencias de desarrollo
pip install -r requirements.txt

# Ejecutar pruebas integrales
python -m pytest tests/

# Crear rama de característica
git checkout -b feature/nueva-funcionalidad
git commit -am 'Agregar: nueva característica de seguridad'
git push origin feature/nueva-funcionalidad
```

### **Filosofía de Desarrollo**
- **🧠 Desarrollo Humano-IA**: Combinación de creatividad humana y precisión de IA
- **⚡ Iteración Rápida**: Desarrollo acelerado con GitHub Copilot
- **🔍 Calidad Asegurada**: Revisión humana de toda funcionalidad crítica
- **🌟 Innovación Continua**: Exploración de nuevas capacidades de seguridad

### **Estándares de Código**
- **Python 3.8+** requisito mínimo
- **Cumplimiento PEP 8** obligatorio
- **Documentación integral** requerida
- **Pruebas unitarias** para todas las nuevas características
- **Arquitectura MVC** estrictamente aplicada
- **Procesamiento en tiempo real** - sin datos simulados

## 📊 Registro de Cambios e Historial de Versiones

### **v3.0** - Plataforma de Seguridad en Tiempo Real
- ✅ **Refactorización completa** a arquitectura en tiempo real
- ✅ **SIEM avanzado** con correlación de eventos
- ✅ **Monitoreo de Integridad de Archivos** con verificación hash
- ✅ **Sistema de carga automática de datos** para wordlists/diccionarios
- ✅ **16+ categorías de wordlists** con 5,000+ entradas
- ✅ **13+ diccionarios técnicos** con 1,500+ definiciones
- ✅ **Interfaz profesional** optimizada para analistas
- ✅ **Suite de pruebas integral** con 100+ pruebas
- ✅ **Vista unificada de datos** simplificada
- ✅ **Tema Burp Suite** aplicado consistentemente

### **v2.5** - Mejoras Profesionales
- ✅ **Interfaz moderna** con tema personalizado
- ✅ **Integración tema Burp Suite**
- ✅ **Reportes avanzados** con múltiples formatos
- ✅ **Optimización de rendimiento** para grandes conjuntos de datos

### **v2.0** - Enfoque en Seguridad
- ✅ **Capacidades de escaneo avanzado**
- ✅ **Integración SIEM** con correlación
- ✅ **Panel de monitoreo en tiempo real**
- ✅ **Sistema de reportes profesional**

## 📞 Soporte y Contacto

### **Soporte Profesional**
- **GitHub Issues**: Problemas técnicos y solicitudes de características
- **Problemas de Seguridad**: Proceso de divulgación responsable
- **Documentación**: Documentación inline integral
- **Comunidad**: Comunidad profesional de ciberseguridad

### **Información del Desarrollador**
- **👨‍💻 Autor**: [DogSoulDev](https://github.com/DogSoulDev)
- **🤖 Co-desarrollador**: GitHub Copilot
- **📧 Email**: dogsouldev@protonmail.com
- **🚀 Repositorio Principal**: [Aresitos](https://github.com/DogSoulDev/Aresitos)
- **🧪 Repositorio de Testing**: [Ares-Aegis](https://github.com/DogSoulDev/Ares-Aegis)

### **Ecosistema Ares Aegis**
**Aresitos** es la primera herramienta del ecosistema **Ares Aegis**, con más herramientas especializadas en desarrollo:
- 🛡️ **Aresitos** - Auditoría y análisis de seguridad (Actual)
- 🔍 **Futuras herramientas** - Especialización en diferentes áreas de ciberseguridad
- 🌐 **Integración completa** - Ecosystem unificado de herramientas

## 📄 Licencia y Legal

Este proyecto está licenciado bajo la **Licencia MIT**. Ver archivo `LICENSE` para detalles completos.

---

## 🏆 Reconocimientos

- **👨‍💻 DogSoulDev** - Creador y arquitecto principal del proyecto
- **🤖 GitHub Copilot** - Co-desarrollador IA para optimización y funcionalidades avanzadas
- **Equipo Kali Linux** - Por las herramientas fundamentales de seguridad
- **Comunidad OWASP** - Por las metodologías de pruebas de seguridad
- **Corporación MITRE** - Por la integración del framework ATT&CK
- **Comunidad de Ciberseguridad** - Por retroalimentación y validación
- **Contribuidores Open Source** - Por revisiones de código y mejoras

### **Desarrollo Colaborativo Humano-IA**
Este proyecto representa una colaboración innovadora entre:
- 🧠 **Creatividad Humana**: Visión, arquitectura y dirección del proyecto
- 🤖 **Precisión de IA**: Implementación optimizada y funcionalidades avanzadas
- ⚡ **Sinergia**: Desarrollo acelerado manteniendo calidad profesional

---

**⚠️ Descargo Legal**: Aresitos está diseñado para profesionales de ciberseguridad y pruebas éticas de seguridad. Los autores (DogSoulDev y GitHub Copilot) no son responsables del mal uso de esta herramienta.

**🎯 Casos de Uso Profesional**: 
- **Pruebas de Penetración** y evaluaciones de seguridad
- **Auditoría de Seguridad** y validación de cumplimiento
- **Respuesta a Incidentes** y análisis forense
- **Endurecimiento del Sistema** y gestión de configuración
- **Gestión de Vulnerabilidades** y evaluación de riesgo
- **Actividades del Centro de Operaciones de Seguridad (SOC)**

**🔒 Audiencia Objetivo**: Profesionales de ciberseguridad, pentesters, auditores de seguridad, respondedores de incidentes, analistas SOC y administradores de sistemas.

---

## 🚀 Iniciación Rápida

### **Comando Único de Instalación**
```bash
# Instalación desde repositorio principal
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos && pip install -r requirements.txt && python main.py

# Instalación desde repositorio de desarrollo
git clone https://github.com/DogSoulDev/Ares-Aegis.git && cd Ares-Aegis && pip install -r requirements.txt && python main.py
```

### **Verificación Rápida**
```bash
# El programa debería mostrar:
🚀 Inicializando gestores de datos de Aresitos...
📂 Escaneando wordlists en: [ruta]/data/wordlists
📂 Escaneando diccionarios en: [ruta]/data/diccionarios
✅ [X] wordlists cargadas
✅ [Y] diccionarios cargados exitosamente
🎉 Inicialización de gestores completada
```

**¡Aresitos está listo para uso profesional!** 🛡️
