# ARESITOS - Herramienta Completa de Ciberseguridad

## 🔐 Herramienta Profesional de Seguridad para Sistemas Linux

**Aresitos** es una suite avanzada e integrada de ciberseguridad diseñada para profesionales de seguridad, administradores de sistemas e investigadores de ciberseguridad que trabajan en sistemas Linux, con optimización específica para entornos Kali Linux.

![Aresitos Icon](ares_aegis/recursos/Aresitos.ico)

---

## 🚀 CARACTERÍSTICAS PRINCIPALES

### 🔍 **Escaneo Avanzado de Vulnerabilidades**
- **Reconocimiento de Red**: Escaneo de puertos, enumeración de servicios y mapeo de red
- **Seguridad de Aplicaciones Web**: Detección automatizada de vulnerabilidades y testing de seguridad web
- **Evaluación de Sistema**: Detección de escalado de privilegios locales y auditoría de configuración
- **Generación de Payloads Personalizados**: Creación dinámica de payloads para escenarios de penetration testing

### 📊 **Monitoreo de Seguridad en Tiempo Real (SIEM)**
- **Correlación de Eventos**: Análisis avanzado de logs y reconocimiento de patrones
- **Detección de Amenazas**: Detección de anomalías basada en machine learning
- **Respuesta a Incidentes**: Generación automatizada de alertas y flujos de trabajo de respuesta
- **Visualización en Dashboard**: Métricas de seguridad y visualización de amenazas en tiempo real

### 🛡️ **Monitoreo de Integridad de Archivos (FIM)**
- **Creación de Baseline**: Hash criptográfico de archivos críticos del sistema
- **Detección de Cambios**: Monitoreo en tiempo real de modificaciones, adiciones y eliminaciones de archivos
- **Validación de Integridad**: Verificación automatizada de la integridad de archivos del sistema
- **Reportes de Cumplimiento**: Generación de reportes para marcos de cumplimiento de seguridad

### 🎯 **Gestión Profesional de Wordlists y Diccionarios**
- **Generación de Diccionarios Personalizados**: Creación de wordlists específicas por dominio
- **Soporte Multi-formato**: Listas de contraseñas, listas de subdominios, listas de enumeración de directorios
- **Filtrado Avanzado**: Filtrado y categorización basado en contenido
- **Optimización de Rendimiento**: Manejo eficiente en memoria de grandes conjuntos de datos

### 🔒 **Sistema de Cuarentena de Seguridad**
- **Aislamiento de Amenazas**: Contención automatizada de archivos y procesos sospechosos
- **Entorno Sandbox**: Entorno de ejecución seguro para análisis de malware
- **Mecanismos de Recuperación**: Restauración controlada de elementos en cuarentena
- **Preservación Forense**: Preservación de evidencia para análisis de incidentes

### 📈 **Reportes Avanzados y Analíticas**
- **Dashboards Ejecutivos**: Visualización de alto nivel de la postura de seguridad
- **Reportes Técnicos**: Evaluaciones detalladas de vulnerabilidades y guías de remediación
- **Reportes de Cumplimiento**: Generación automatizada de documentación de cumplimiento
- **Análisis Histórico**: Análisis de tendencias y evolución de la postura de seguridad

---

## 🏗️ **ARQUITECTURA DEL SISTEMA**

### **Patrón de Diseño Modelo-Vista-Controlador (MVC)**
```
ares_aegis/
├── modelo/           # Lógica de Negocio y Gestión de Datos
│   ├── modelo_escaneador.py         # Motor de escaneo principal
│   ├── modelo_siem.py               # Lógica de procesamiento SIEM
│   ├── modelo_fim.py                # Algoritmos de integridad de archivos
│   ├── modelo_gestor_wordlists.py   # Gestión de wordlists
│   ├── modelo_gestor_diccionarios.py # Gestión de diccionarios
│   ├── modelo_cheatsheets.py        # Gestión de cheatsheets
│   └── modelo_principal.py          # Coordinación central
├── vista/            # Componentes de Interfaz de Usuario
│   ├── vista_principal.py           # Ventana principal de la aplicación
│   ├── vista_escaneo.py             # Interfaz de escaneo
│   ├── vista_monitoreo.py           # Dashboard de monitoreo
│   ├── vista_gestion_datos.py       # Gestión unificada de datos
│   ├── vista_siem.py                # Interfaz SIEM
│   ├── vista_fim.py                 # Interfaz FIM
│   └── burp_theme.py                # Tema profesional de UI
└── controlador/      # Controladores de Lógica de Aplicación
    ├── controlador_principal.py     # Controlador principal
    ├── controlador_escaneo.py       # Gestión de escaneos
    ├── controlador_siem.py          # Coordinación SIEM
    ├── controlador_fim.py           # Control FIM
    └── gestor_configuracion.py      # Gestión de configuración
```

### **Tema Profesional de UI**
- **Inspirado en Burp Suite**: Tema oscuro con esquema de colores profesional (#2b2b2b, #ff6633)
- **Diseño Ergonómico**: Optimizado para sesiones extendidas de análisis de seguridad
- **Densidad de Información**: Utilización maximizada del espacio de pantalla
- **Accesibilidad**: Alto contraste y fuentes legibles para uso prolongado

---

## 🛠️ **INSTALACIÓN Y CONFIGURACIÓN**

### **Requisitos del Sistema**
- **Sistema Operativo**: Linux (Optimizado para Kali Linux 2023.x+)
- **Versión de Python**: Python 3.8+ (3.10+ recomendado)
- **Memoria**: Mínimo 4GB RAM (8GB+ recomendado para operaciones a gran escala)
- **Almacenamiento**: 2GB de espacio libre para instalación y logs
- **Red**: Conexión a internet para actualizaciones de inteligencia de amenazas

### **Dependencias**
#### Paquetes Python Principales
```bash
# Framework GUI
customtkinter>=5.0.0      # Componentes modernos de UI
pillow>=9.0.0              # Procesamiento de imágenes

# Red y Seguridad
requests>=2.28.0           # Librería cliente HTTP
psutil>=5.9.0              # Monitoreo del sistema
python-nmap>=0.7.1         # Mapeo de red
scapy>=2.4.5               # Manipulación de paquetes

# Procesamiento de Datos y Visualización
pandas>=1.5.0              # Análisis de datos
matplotlib>=3.6.0          # Gráficos y visualización

# Utilidades del Sistema
hashlib2>=1.0.0            # Algoritmos de hash avanzados
watchdog>=2.2.0            # Monitoreo del sistema de archivos
colorlog>=6.7.0            # Logging mejorado
```

#### Herramientas de Integración Kali Linux
```bash
# Reconocimiento de Red
nmap                       # Exploración de red
gobuster                   # Enumeración de directorios/archivos
hydra                      # Bruteforcer de login

# Seguridad de Aplicaciones Web
sqlmap                     # Explotación de inyección SQL
nikto                      # Escáner de servidor web

# Análisis de Red
wireshark                  # Analizador de protocolos de red
netcat                     # Navaja suiza de red
aircrack-ng               # Auditoría de seguridad inalámbrica

# Seguridad de Contraseñas
hashcat                    # Recuperación avanzada de contraseñas

# Forense y Análisis de Memoria
volatility3                # Framework de forense de memoria
```

### **Pasos de Instalación**

#### 1. Clonar Repositorio
```bash
git clone https://github.com/your-repo/ares-aegis.git
cd ares-aegis
```

#### 2. Instalar Dependencias Python
```bash
# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instalar requisitos
pip install -r requirements.txt
```

#### 3. Verificación de Herramientas del Sistema
```bash
# Verificar instalación de herramientas Kali
which nmap sqlmap gobuster hydra

# Si faltan herramientas, instalar via apt
sudo apt update
sudo apt install nmap sqlmap gobuster hydra nikto
```

#### 4. Lanzar Aplicación
```bash
python main.py
```

---

## 🎯 **GUÍA DE USO**

### **Configuración Inicial**
1. **Lanzar Aplicación**: Ejecutar `python main.py`
2. **Configurar Rutas**: Establecer directorios personalizados de wordlists y salida
3. **Configuración de Red**: Configurar interfaces de red y rangos de escaneo
4. **Integración SIEM**: Conectar a fuentes de logs existentes (opcional)

### **Flujos de Trabajo Principales**

#### **Flujo de Evaluación de Vulnerabilidades**
1. **Definición de Objetivo**: Especificar rangos IP, dominios o sistemas individuales
2. **Configuración de Escaneo**: Seleccionar tipos de escaneo (puerto, servicio, vulnerabilidad)
3. **Ejecución**: Monitorear progreso en tiempo real y resultados preliminares
4. **Análisis**: Revisar hallazgos detallados y evaluaciones de riesgo
5. **Reportes**: Generar reportes comprensivos de vulnerabilidades

#### **Flujo de Monitoreo de Seguridad**
1. **Configuración de Fuentes de Log**: Conectar a logs del sistema, dispositivos de red, aplicaciones
2. **Definición de Reglas**: Crear reglas de detección personalizadas y patrones de correlación
3. **Gestión de Alertas**: Configurar canales de notificación y procedimientos de escalado
4. **Investigación**: Usar herramientas forenses integradas para análisis de incidentes
5. **Respuesta**: Ejecutar playbooks de respuesta automatizada

#### **Flujo de Monitoreo de Integridad de Archivos**
1. **Creación de Baseline**: Generar huellas criptográficas de archivos críticos
2. **Configuración de Monitoreo**: Definir directorios y tipos de archivo a monitorear
3. **Detección de Cambios**: Recibir alertas en tiempo real sobre modificaciones de archivos
4. **Validación**: Verificar cambios legítimos vs. potenciales incidentes de seguridad
5. **Reportes**: Generar reportes de cumplimiento y auditoría

---

## 📊 **CARACTERÍSTICAS AVANZADAS**

### **Gestión de Cheatsheets**
- **18 Cheatsheets Especializados**: Guías completas para herramientas de Kali Linux
- **Comandos en Español**: Ejemplos prácticos con contexto en español
- **Categorías Incluidas**: Hydra, SQLMap, Gobuster, Wireshark, Nikto, Aircrack-ng, Netcat, Comandos Linux, Hashcat, Volatility
- **Referencias Rápidas**: Acceso rápido a comandos y sintaxis durante pentesting

### **Wordlists Especializadas en Español**
- **Contexto Corporativo**: Wordlists adaptadas al contexto empresarial hispanohablante
- **Subdominios Completos**: Listas extensas de subdominios comunes en español
- **Directorios Web**: Estructura de directorios típica en sitios web en español
- **Usuarios Comunes**: Nombres de usuario frecuentes en entornos hispanos

### **Integración de Inteligencia de Amenazas**
- **Feeds IOC**: Integración con feeds de amenazas comerciales y de código abierto
- **Análisis de Atribución**: Atribución de amenazas persistentes avanzadas (APT)
- **Threat Hunting**: Búsqueda proactiva de indicadores de compromiso
- **Compartir Inteligencia**: Exportar hallazgos en formatos STIX/TAXII

### **Cumplimiento y Auditoría**
- **Soporte de Frameworks**: Verificación de cumplimiento NIST, ISO 27001, PCI DSS
- **Auditoría Automatizada**: Monitoreo continuo de cumplimiento
- **Recolección de Evidencia**: Preservación de evidencia forense
- **Pistas de Auditoría**: Logging comprensivo de todas las actividades de seguridad

---

## 🔧 **CONFIGURACIÓN**

### **Archivos de Configuración**
- `configuracion/ares_aegis_config.json`: Configuración principal de la aplicación
- `configuracion/firmas.txt`: Definiciones de firmas personalizadas
- `configuracion/notificaciones.json`: Configuraciones de alertas y notificaciones
- `configuracion/sistema_ayuda.json`: Sistema de ayuda integrado
- `configuracion/textos_castellano.json`: Textos en español

### **Directorios de Datos**
- `data/wordlists/`: Wordlists personalizadas y curadas
- `data/cheatsheets/`: Materiales de referencia y guías de comandos
- `data/diccionarios/`: Diccionarios especializados
- `logs/`: Logs de aplicación y eventos de seguridad
- `reportes/`: Reportes de seguridad y evaluaciones generadas

### **Opciones de Configuración Avanzada**
```json
{
  "sistema": {
    "log_level": "INFO",
    "max_threads": 10,
    "timeout_requests": 30,
    "idioma": "es"
  },
  "escaneo": {
    "puertos_comunes": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
    "timeout_port": 5,
    "max_host_parallel": 50
  },
  "siem": {
    "retention_days": 90,
    "correlation_window": 300,
    "max_events_memory": 10000
  }
}
```

---

## 🚨 **CONSIDERACIONES DE SEGURIDAD**

### **Uso Ético**
- **Autorización Requerida**: Solo usar en sistemas propios o con permiso explícito para testing
- **Cumplimiento Legal**: Asegurar cumplimiento con leyes locales e internacionales
- **Divulgación Responsable**: Seguir prácticas de divulgación responsable para vulnerabilidades descubiertas
- **Documentación**: Mantener registros detallados de todas las actividades de testing de seguridad

### **Seguridad Operacional**
- **Almacenamiento Cifrado**: Todos los datos sensibles están cifrados en reposo
- **Comunicaciones Seguras**: Cifrado TLS para todas las comunicaciones de red
- **Controles de Acceso**: Control de acceso basado en roles para entornos multi-usuario
- **Logging de Auditoría**: Logging comprensivo de todas las actividades de usuario

---

## 🔄 **ACTUALIZACIONES Y MANTENIMIENTO**

### **Actualizaciones Automáticas**
- **Inteligencia de Amenazas**: Actualizaciones diarias de indicadores de amenaza y firmas
- **Base de Datos de Vulnerabilidades**: Actualizaciones regulares de datos CVE y vulnerabilidades
- **Actualizaciones de Aplicación**: Verificación automatizada de actualizaciones de software

### **Tareas de Mantenimiento**
- **Rotación de Logs**: Rotación y archivado automatizado de logs
- **Optimización de Base de Datos**: Optimización regular de bases de datos internas
- **Monitoreo de Rendimiento**: Monitoreo continuo del rendimiento del sistema
- **Procedimientos de Backup**: Backup automatizado de configuraciones y datos históricos

---

## 📄 **LICENCIA Y LEGAL**

### **Licencia de Software**
Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

### **Componentes de Terceros**
- Todas las librerías y herramientas de terceros se usan de acuerdo con sus respectivas licencias
- Información completa de atribución y licencia está disponible en el archivo [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES)

### **Descargo de Responsabilidad**
Esta herramienta está destinada únicamente para testing de seguridad autorizado y propósitos de investigación. Los usuarios son responsables de asegurar el cumplimiento con leyes y regulaciones aplicables. Los desarrolladores no asumen responsabilidad por el mal uso o daños resultantes del uso de este software.

---

## 📞 **INFORMACIÓN DE CONTACTO**

### **Equipo de Desarrollo**
- **Desarrollo Principal**: Estudiante de Ciberseguridad colaborando con la comunidad
- **Enfoque**: Herramienta educativa desarrollada por estudiantes para estudiantes
- **Filosofía**: Aprendizaje colaborativo y mejora continua

### **Soporte Comunitario**
- **GitHub Issues**: Para reportar problemas y solicitar características
- **Documentación**: Guías comprensivas de usuario y administrador
- **Recursos Educativos**: Tutoriales y materiales de certificación

---

*Aresitos - Fortaleciendo Realidades Digitales a través de Ciberseguridad Avanzada*

**Versión**: 1.0.0  
**Última Actualización**: Diciembre 2024  
**Construcción**: Edición Educativa Profesional
