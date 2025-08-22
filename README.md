![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0
**Suite Profesional de Ciberseguridad para Kali Linux**

Aresitos es una herramienta integral de ciberseguridad desarrollada exclusivamente para Kali Linux, diseñada para profesionales de seguridad informática y estudiantes de ciberseguridad. Combina técnicas avanzadas de escaneo, monitoreo de integridad, análisis forense y gestión de amenazas en una interfaz unificada y profesional.

## Características Principales

### Escaneado Avanzado de Seguridad
- **Escaneo de 10 fases progresivas** con análisis completo del sistema
- **Detección de vulnerabilidades** en servicios y configuraciones
- **Análisis de puertos críticos** con clasificación de riesgos
- **Detección avanzada de rootkits** con herramientas especializadas
- **Integración nativa** con herramientas de Kali Linux (nmap, masscan, nuclei)

### Monitoreo de Integridad de Archivos (FIM)
- **Vigilancia en tiempo real** de archivos críticos del sistema
- **Análisis de módulos del kernel** para detección de backdoors
- **Base de datos forense** con histórico completo de cambios
- **Alertas automáticas** ante modificaciones no autorizadas
- **Integración con herramientas forenses** (chkrootkit, rkhunter, lynis)

### Sistema de Información y Gestión de Eventos (SIEM)
- **Monitoreo de 50 puertos críticos** categorizados por servicio
- **Análisis de conexiones** y detección de actividad sospechosa
- **Correlación de eventos** entre módulos del sistema
- **Dashboard en tiempo real** con métricas de seguridad
- **Generación automática de reportes** con evidencia forense

### Gestión de Amenazas y Cuarentena
- **Sistema de cuarentena inteligente** para archivos sospechosos
- **Análisis de malware** con múltiples motores de detección
- **Respuesta automática** ante amenazas críticas
- **Preservación forense** de evidencia digital
- **Integración con herramientas de análisis** (ClamAV, YARA, Volatility)

### Gestión Dinámica de Datos
- **Sistema de wordlists** para pruebas de penetración
- **Diccionarios de amenazas** actualizables automáticamente
- **Cheatsheets integrados** para técnicas de pentesting
- **Base de conocimientos** de vulnerabilidades y exploits

## Arquitectura Técnica

### Stack Tecnológico
- **Lenguaje**: Python 3.8+ con librerías estándar
- **Arquitectura**: Modelo-Vista-Controlador (MVC)
- **Base de datos**: SQLite para persistencia optimizada
- **Interfaz**: Tkinter con tema profesional
- **Integración**: Herramientas nativas de Kali Linux

### Estructura del Proyecto

```
Aresitos/
├── 📄 main.py                          # Punto de entrada principal del sistema
├── ⚙️  configurar_kali.sh               # Script de configuración automática para Kali
├── 🔍 verificacion_final.py            # Verificación de integridad del proyecto
├── 📋 pyproject.toml                   # Configuración del proyecto Python
├── 📋 requirements.txt                 # Dependencias (solo documentación)
├── 📜 LICENSE                          # Licencia Open Source Non-Commercial
├── 📖 README.md                        # Este archivo - Documentación principal
│
├── 🏗️  aresitos/                        # Módulo principal de la aplicación
│   ├── 📦 __init__.py                  # Inicialización del paquete
│   │
│   ├── 🎮 controlador/                 # Lógica de negocio (15 módulos)
│   │   ├── controlador_principal_nuevo.py    # Controlador principal del sistema
│   │   ├── controlador_escaneo.py            # Escaneado de seguridad 10 fases
│   │   ├── controlador_fim.py                # Monitoreo integridad archivos
│   │   ├── controlador_siem_nuevo.py         # Sistema SIEM con 50 puertos
│   │   ├── controlador_cuarentena.py         # Gestión cuarentena malware
│   │   ├── controlador_dashboard.py          # Panel control métricas
│   │   ├── controlador_auditoria.py          # Auditoría seguridad sistema
│   │   ├── controlador_reportes.py           # Generación reportes
│   │   ├── controlador_monitoreo.py          # Monitoreo tiempo real
│   │   ├── controlador_herramientas.py       # Gestión herramientas Kali
│   │   ├── controlador_gestor_componentes.py # Gestión componentes dinámicos
│   │   ├── controlador_gestor_configuracion.py # Configuración sistema
│   │   ├── controlador_escaneador_cuarentena.py # Escaneado + cuarentena
│   │   ├── controlador_base.py               # Clase base controladores
│   │   └── controlador_principal_base.py     # Base controlador principal
│   │
│   ├── 🗄️  modelo/                      # Gestión de datos (19 módulos)
│   │   ├── modelo_principal.py               # Modelo principal del sistema
│   │   ├── modelo_escaneador_kali2025.py     # Escaneador avanzado Kali 2025
│   │   ├── modelo_fim_kali2025.py            # FIM optimizado Kali 2025
│   │   ├── modelo_siem_kali2025.py           # SIEM avanzado Kali 2025
│   │   ├── modelo_cuarentena_kali2025.py     # Cuarentena avanzada
│   │   ├── modelo_dashboard.py               # Datos dashboard tiempo real
│   │   ├── modelo_reportes.py                # Generación y gestión reportes
│   │   ├── modelo_monitor.py                 # Monitoreo sistema
│   │   ├── modelo_gestor_wordlists.py        # Gestión wordlists dinámicas
│   │   ├── modelo_gestor_diccionarios.py     # Gestión diccionarios
│   │   ├── modelo_constructor_wordlists.py   # Construcción wordlists
│   │   ├── modelo_utilidades_sistema.py      # Utilidades sistema
│   │   ├── modelo_escaneador_*.py            # Versiones escaneador
│   │   ├── modelo_cuarentena.py              # Cuarentena base
│   │   └── modelo_fim.py                     # FIM base
│   │
│   ├── 🖥️  vista/                       # Interfaces usuario (13 módulos)
│   │   ├── vista_principal.py                # Interfaz principal sistema
│   │   ├── vista_login.py                    # Pantalla autenticación
│   │   ├── vista_dashboard.py                # Dashboard métricas tiempo real
│   │   ├── vista_escaneo.py                  # Interface escaneado seguridad
│   │   ├── vista_fim.py                      # Interface monitoreo integridad
│   │   ├── vista_siem.py                     # Interface SIEM eventos
│   │   ├── vista_monitoreo.py                # Interface monitoreo + cuarentena
│   │   ├── vista_auditoria.py                # Interface auditoría sistema
│   │   ├── vista_reportes.py                 # Interface generación reportes
│   │   ├── vista_gestion_datos.py            # Gestión wordlists/diccionarios
│   │   ├── vista_herramientas_kali.py        # Interface herramientas Kali
│   │   ├── burp_theme.py                     # Tema visual profesional Burp
│   │   └── terminal_mixin.py                 # Terminales integrados reutilizables
│   │
│   ├── 🔧 utils/                        # Utilidades sistema (7 módulos)
│   │   ├── verificar_kali.py                 # Verificación entorno Kali Linux
│   │   ├── gestor_permisos.py                # Gestión permisos sudo/root
│   │   ├── verificacion_permisos.py          # Verificación permisos usuario
│   │   ├── configurar.py                     # Configuración sistema
│   │   ├── sanitizador_archivos.py           # 🆕 Sanitización archivos segura
│   │   └── helper_seguridad.py               # 🆕 Helpers interfaces seguridad
│   │
│   └── 🎨 recursos/                     # Recursos gráficos
│       └── Aresitos.ico                      # Icono aplicación
│
├── 🗂️  data/                            # Datos y bases de datos
│   ├── 📊 *.db                              # Bases datos SQLite (FIM, SIEM, cuarentena)
│   ├── 📄 *.json                            # Bases datos JSON (vulnerabilidades)
│   ├── 📚 cheatsheets/                      # Guías comando Kali (40+ archivos)
│   ├── 📖 diccionarios/                     # Diccionarios términos técnicos JSON
│   ├── 📝 wordlists/                        # Listas palabras pentesting
│   ├── 🔒 cuarentena/                       # Archivos cuarentena malware
│   └── 📈 analisis/                         # Datos análisis forense
│
├── ⚙️  configuración/                    # Configuración sistema
│   ├── aresitos_config.json                 # Configuración principal
│   ├── aresitos_config_kali.json            # Configuración específica Kali
│   ├── aresitos_config_backup.json          # Respaldo configuración
│   ├── aresitos_config_completo.json        # Configuración completa
│   ├── textos_castellano_corregido.json     # Textos interface español
│   └── MAPA_NAVEGACION_ESCANEADOR.md        # Guía navegación escaneador
│
├── 📋 logs/                             # Sistema logs centralizado
│   ├── .gitkeep                             # Preservar directorio en Git
│   └── *.log                                # Logs por módulo (auto-generados)
│
└── 📚 documentacion/                    # Documentación técnica completa
    ├── README.md                            # Índice documentación
    ├── DOCUMENTACION_TECNICA_CONSOLIDADA.md # Documentación técnica completa
    ├── ARQUITECTURA_DESARROLLO.md          # Guía desarrollo y arquitectura
    ├── GUIA_INSTALACION.md                 # Proceso instalación paso a paso
    ├── AUDITORIA_SEGURIDAD_ARESITOS.md     # Auditoría seguridad completa
    ├── SANITIZACION_ARCHIVOS.md            # 🆕 Sistema sanitización archivos
    └── TERMINAL_INTEGRADO.md               # Sistema terminales integrados
```

### Descripción de Componentes

#### 🎮 Capa Controlador (MVC)
Implementa la lógica de negocio y orquestación del sistema:
- **15 controladores especializados** para cada módulo funcional
- **Gestión de eventos** y coordinación entre componentes
- **Validación de entrada** y sanitización de datos
- **Control de flujo** de operaciones complejas

#### 🗄️ Capa Modelo (MVC)  
Gestiona persistencia de datos y lógica de dominio:
- **19 modelos de datos** optimizados para Kali Linux 2025
- **Bases de datos SQLite** para rendimiento y portabilidad
- **Gestión dinámica** de wordlists y diccionarios
- **Modelos especializados** para escaneado, FIM, SIEM y cuarentena

#### 🖥️ Capa Vista (MVC)
Interfaces de usuario profesionales con terminales integrados:
- **13 interfaces especializadas** para cada funcionalidad
- **Tema visual Burp Suite** consistente y profesional
- **Terminales integrados** en tiempo real con TerminalMixin
- **Layout PanedWindow** optimizado para productividad

#### 🔧 Utilidades del Sistema
Herramientas de soporte y verificación:
- **Verificación entorno Kali** y dependencias
- **Gestión segura de permisos** sudo/root
- **🆕 Sistema sanitización** archivos multi-capa
- **🆕 Helpers seguridad** para interfaces usuario

#### 🗂️ Gestión de Datos
Sistema de datos dinámico y configurable:
- **Bases de datos SQLite**: `fim_kali2025.db`, `cuarentena_kali2025.db`
- **Datos JSON**: `fim_database.json`, `vulnerability_database.json`
- **40+ Cheatsheets**: Guías completas de herramientas Kali Linux
- **Wordlists dinámicas**: Listas actualizables para pentesting
- **Diccionarios técnicos**: Términos de ciberseguridad en JSON
- **Sistema cuarentena**: Aislamiento seguro archivos maliciosos

#### ⚙️ Configuración del Sistema
- **Configuración principal**: Parámetros generales en JSON
- **Configuración Kali**: Optimizaciones específicas para Kali Linux
- **Textos en español**: Interface completamente en castellano
- **Mapas de navegación**: Guías de uso de módulos complejos
- **Respaldos automáticos**: Configuraciones de seguridad

### Estadísticas del Proyecto
- **📊 Archivos de código**: 54 archivos Python
- **🎮 Controladores**: 15 módulos de lógica de negocio
- **🗄️ Modelos**: 19 módulos de gestión de datos
- **🖥️ Vistas**: 13 interfaces de usuario especializadas
- **🔧 Utilidades**: 7 módulos de soporte y seguridad
- **📚 Cheatsheets**: 40+ guías de herramientas Kali
- **📖 Documentación**: 7 archivos técnicos completos
- **🔒 Funciones sanitizadas**: 5 funciones críticas de carga
- **🛡️ Capas de seguridad**: 5 niveles de validación por archivo

### Seguridad y Validación
- **Sanitización de archivos** con múltiples capas de validación
- **Verificación de permisos** para operaciones privilegiadas
- **Validación de entrada** para prevenir inyecciones
- **Logs de seguridad** para auditoría y trazabilidad

## Instalación y Configuración

### Requisitos del Sistema
- **Sistema Operativo**: Kali Linux 2024.x o superior
- **Python**: 3.8+ (incluido en Kali Linux)
- **Permisos**: Acceso sudo para herramientas del sistema
- **Espacio**: 500MB libres para datos y logs

### Proceso de Instalación
```bash
# Clonar el repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Ejecutar configuración automática
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# Iniciar la aplicación
python3 main.py
```

### Configuración para Desarrollo
```bash
# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev
```

## Guía de Uso

### Flujo de Trabajo Recomendado
1. **Autenticación**: Inicio de sesión y verificación de permisos
2. **Configuración inicial**: Establecer parámetros del sistema
3. **Escaneo de objetivos**: Análisis completo de sistemas remotos
4. **Monitoreo local**: Vigilancia del sistema Kali Linux
5. **Análisis de amenazas**: Investigación de actividad sospechosa
6. **Generación de reportes**: Documentación de hallazgos

### Casos de Uso Principales

#### Para Profesionales de Seguridad
- **Auditorías de seguridad** automatizadas y completas
- **Detección de amenazas persistentes** en tiempo real
- **Análisis forense** de incidentes de seguridad
- **Monitoreo continuo** de infraestructura crítica

#### Para Estudiantes de Ciberseguridad
- **Aprendizaje práctico** de técnicas de pentesting
- **Comprensión de herramientas** profesionales de Kali Linux
- **Análisis de vulnerabilidades** en entornos controlados
- **Desarrollo de habilidades** en respuesta a incidentes

#### Para Equipos SOC
- **Monitoreo centralizado** de eventos de seguridad
- **Respuesta rápida** a incidentes detectados
- **Gestión de indicadores** de compromiso (IOCs)
- **Correlación automática** de eventos múltiples

## Características de Seguridad

### Validación de Archivos
- **Sanitización automática** de archivos cargados
- **Verificación de tipos MIME** y extensiones
- **Detección de contenido malicioso** antes del procesamiento
- **Límites de tamaño** para prevenir ataques DoS

### Gestión de Permisos
- **Escalación controlada** de privilegios cuando necesario
- **Verificación de identidad** antes de operaciones críticas
- **Auditoría completa** de acciones administrativas
- **Aislamiento de procesos** para operaciones de riesgo

### Protección del Sistema
- **Detección de rootkits** con múltiples herramientas
- **Monitoreo de integridad** de archivos críticos
- **Análisis de comportamiento** de procesos del sistema
- **Alertas automáticas** ante actividad anómala

## Documentación Técnica

La documentación completa está disponible en la carpeta `/documentacion/`:

- **Guía de Instalación**: Proceso detallado de configuración
- **Manual de Usuario**: Instrucciones completas de uso
- **Documentación Técnica**: Arquitectura y desarrollo
- **Guía de Seguridad**: Buenas prácticas y configuración segura

## Compatibilidad

### Sistemas Soportados
- **Kali Linux**: 2024.x y superior (recomendado)
- **Parrot Security OS**: Versiones recientes
- **BlackArch Linux**: Con adaptaciones menores
- **Ubuntu/Debian**: Modo desarrollo limitado

### Herramientas Integradas
- **Escaneado**: nmap, masscan, gobuster, nikto, nuclei
- **Análisis forense**: volatility3, binwalk, yara, strings
- **Detección de rootkits**: chkrootkit, rkhunter, lynis
- **Análisis de malware**: clamav, john, hashcat, exiftool

## Contribución y Desarrollo

### Principios de Desarrollo
- **Arquitectura MVC** bien definida
- **Código limpio** siguiendo principios SOLID y DRY
- **Documentación completa** en español
- **Testing exhaustivo** en entornos Kali Linux

### Estructura de Contribución
Para contribuir al proyecto, consulte las guías en `/documentacion/ARQUITECTURA_DESARROLLO.md`

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

La atribución debe ser **claramente visible** y **NO puede ser removida** bajo ninguna circunstancia.

### Uso Ético
- Destinado exclusivamente para sistemas propios o con autorización explícita
- Prohibido para actividades ilegales o acceso no autorizado
- Promover prácticas éticas de ciberseguridad y educación

## Soporte y Contacto

- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Documentación**: Incluida en `/documentacion/`
- **Issues**: Reportar problemas en GitHub Issues
- **Contacto**: dogsouldev@protonmail.com

---

**Desarrollado por DogSoulDev para la comunidad de ciberseguridad**

## En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos, DogSoulDev