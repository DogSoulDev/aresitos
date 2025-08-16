# ARESITOS - Sistema de Ciberseguridad para Kali Linux

<p align="center">
  <img src="aresitos/recursos/Aresitos.ico" alt="ARESITOS" width="128" height="128">
</p>

## Herramienta de Análisis de Seguridad y Auditoría

**ARESITOS** es una suite de ciberseguridad desarrollada específicamente para profesionales de seguridad, ethical hackers, administradores de sistemas e investigadores que trabajan en entornos Kali Linux.

## CARACTERÍSTICAS PRINCIPALES

### Sistema de Escaneo de Seguridad
- Escaneo de vulnerabilidades del sistema usando herramientas de Kali Linux
- Detección de malware y rootkits con rkhunter y chkrootkit
- Análisis de puertos y servicios usando nmap y masscan
- Escaneo de archivos sospechosos
- Detección de configuraciones inseguras
- Integración real con herramientas nativas de Kali

### SIEM - Sistema de Monitoreo de Eventos
- Correlación de eventos de seguridad del sistema
- Monitoreo en tiempo real de logs del sistema
- Análisis de procesos y conexiones de red
- Detección de patrones sospechosos en logs
- Alertas automáticas basadas en reglas
- Integración con journalctl, ps, netstat

### FIM (File Integrity Monitoring)
- Monitoreo de integridad de archivos críticos del sistema
- Detección de modificaciones en tiempo real usando inotifywait
- Baseline criptográfico usando md5sum y stat
- Alertas de cambios no autorizados en archivos importantes
- Monitoreo de directorios sensibles del sistema

### Gestión de Wordlists y Diccionarios
- Constructor de wordlists personalizadas
- Base de datos con más de 16 categorías de términos
- Wordlists optimizadas para entornos hispanohablantes
- Diccionarios especializados: MITRE ATT&CK, herramientas de hacking
- Generación automática de listas para ataques de diccionario
- Integración con wordlists comunes de Kali Linux

### Sistema de Auditoría
- Auditoría completa del sistema usando lynis
- Análisis de configuraciones de seguridad
- Detección de vulnerabilidades con rkhunter y chkrootkit
- Reportes detallados de hallazgos de seguridad
- Verificación de servicios y procesos activos

### Centro de Reportes y Cheatsheets
- Más de 18 cheatsheets de herramientas de Kali Linux
- Guías de referencia para nmap, metasploit, sqlmap, hydra
- Generación de reportes técnicos de escaneos
- Documentación de hallazgos y vulnerabilidades
- Exportación de resultados en formato texto

## ARQUITECTURA DEL SISTEMA

### Patrón MVC (Modelo-Vista-Controlador)
```
aresitos/                          # Núcleo Principal de la Aplicación
├── controlador/                   # Controladores de Lógica de Negocio
│   ├── controlador_principal.py      # Orquestador central del sistema
│   ├── controlador_escaneador.py     # Motor de escaneo y reconocimiento
│   ├── controlador_fim.py            # Monitoreo de integridad de archivos
│   ├── controlador_siem.py           # Correlación de eventos y alertas
│   ├── controlador_auditoria_avanzada.py    # Auditoría avanzada
│   ├── controlador_auditoria_simple.py      # Auditoría básica
│   ├── controlador_monitor_red.py    # Monitoreo de red
│   ├── controlador_constructor_wordlists.py # Gestión de wordlists
│   ├── controlador_cuarentena.py     # Sistema de cuarentena
│   ├── controlador_reportes.py       # Generación de reportes
│   ├── controlador_base.py           # Controlador base
│   └── gestor_configuracion.py       # Gestión de configuraciones
├── modelo/                        # Modelos de Datos y Lógica de Negocio
│   ├── modelo_escaneador.py          # Motor de escaneo básico
│   ├── modelo_escaneador_avanzado.py # Motor de escaneo avanzado
│   ├── modelo_siem.py                # SIEM básico y avanzado
│   ├── fim.py                        # Monitoreo de integridad
│   ├── monitor_red.py                # Monitor de red
│   ├── monitor_procesos.py           # Monitor de procesos
│   ├── constructor_wordlists.py      # Constructor de wordlists
│   ├── constructor_wordlists_base.py # Base para wordlists
│   ├── gestor_cuarentena.py          # Gestor de cuarentena
│   ├── hallazgos_seguridad.py        # Gestión de hallazgos
│   ├── analizadores.py               # Analizadores especializados
│   ├── auditor_autenticacion.py      # Auditor de autenticación
│   └── utilidades_sistema.py         # Utilidades del sistema
├── vista/                         # Interfaces de Usuario
│   ├── interfaz_principal.py         # Ventana principal
│   ├── vista_principal.py            # Vista principal
│   ├── vista_login.py                # Vista de login
│   ├── vista_auditoria.py            # Vista de auditoría
│   ├── vista_actualizacion.py        # Vista de actualización
│   ├── vista_escaneo.py              # Vista de escaneo
│   ├── vista_fim.py                  # Vista de FIM
│   ├── vista_siem.py                 # Vista de SIEM
│   ├── vista_reportes.py             # Vista de reportes
│   ├── vista_dashboard.py            # Dashboard principal
│   ├── vista_diccionarios.py         # Vista de diccionarios
│   ├── vista_gestion_datos.py        # Gestión de datos
│   ├── vista_herramientas.py         # Vista de herramientas
│   ├── vista_utilidades.py           # Vista de utilidades
│   ├── vista_monitoreo.py            # Vista de monitoreo
│   ├── burp_theme.py                 # Tema visual tipo Burp Suite
│   └── componentes_ui/               # Componentes reutilizables
├── utils/                         # Utilidades del Sistema
│   ├── gestor_permisos.py            # Gestor de permisos seguro
│   ├── verificacion_permisos.py      # Verificación de permisos
│   ├── verificar_kali.py             # Verificación de Kali Linux
│   ├── configurar.py                 # Configurador del sistema
│   ├── actualizador_aresitos.py      # Actualizador del sistema
│   ├── validaciones.py               # Validación de inputs
│   ├── ayuda_logging.py              # Sistema de logging
│   ├── ayuda_rutas.py                # Gestión de rutas
│   ├── temas_kali.py                 # Tema visual Kali
│   └── temas_simple.py               # Tema alternativo
└── recursos/                      # Recursos Gráficos
    └── Aresitos.ico                  # Icono de la aplicación

configuracion/                     # Configuraciones del Sistema
├── ares_aegis_config.json            # Configuración principal
├── ares_aegis_config_kali.json       # Configuración para Kali
├── firmas.txt                        # Firmas de detección
├── notificaciones.json               # Sistema de notificaciones
├── sistema_ayuda.json                # Sistema de ayuda
└── textos_castellano.json            # Textos en español

data/                              # Base de Datos de Conocimiento
├── wordlists/                        # Wordlists especializadas
│   ├── api_endpoints.txt             # Endpoints de API
│   ├── combinaciones_basicas.txt     # Combinaciones básicas
│   ├── numeros_comunes.txt           # Números comunes
│   ├── palabras_españolas.txt        # Palabras en español
│   ├── passwords_worst_500.txt       # Peores contraseñas
│   ├── rockyou_top10k.txt           # RockYou top 10k
│   ├── seclists_directories.txt      # Directorios comunes
│   ├── seclists_subdomains.txt       # Subdominios comunes
│   ├── seclists_usernames.txt        # Nombres de usuario
│   ├── simbolos_especiales.txt       # Símbolos especiales
│   ├── web_extensions.txt            # Extensiones web
│   ├── listas_base.json             # Configuración de listas
│   ├── INDICE_WORDLISTS.md          # Índice de wordlists
│   └── generadas/                   # Wordlists generadas
└── cheatsheets/                      # Guías de referencia

recursos/                          # Recursos Adicionales
├── cve_database.json                 # Base de datos CVE
├── firmas.txt                        # Firmas de detección
├── ips_maliciosas_local.txt          # IPs maliciosas
├── reglas_respuesta.json             # Reglas de respuesta
└── software_cache.json               # Cache de software
```

### Módulos Principales Verificados para Kali Linux
- **Escaneador**: Utiliza nmap, masscan, nikto para escaneos de red y vulnerabilidades
- **FIM**: Utiliza find, stat, md5sum, inotifywait para monitoreo de integridad
- **SIEM**: Utiliza tail, grep, ps, netstat, journalctl para análisis de eventos
- **Auditoría**: Utiliza lynis, rkhunter, chkrootkit, systemctl para auditorías de sistema

## CONTENIDO INCLUIDO

### Wordlists Especializadas (16 categorías)
- **Passwords**: Contraseñas comunes y corporativas en español
- **Usuarios**: Nombres de usuario comunes en sistemas hispanos
- **Subdominios**: Lista extensa de subdominios comunes en español
- **Directorios Web**: Directorios comunes en aplicaciones web
- **Endpoints API**: Rutas comunes de APIs y servicios web
- **Extensiones**: Extensiones de archivos comunes
- **Puertos**: Lista de puertos comunes con descripciones

### Diccionarios Temáticos (13 categorías)
- **MITRE ATT&CK**: Técnicas y tácticas de ciberataques
- **Herramientas de Hacking**: Base de datos de herramientas de seguridad
- **Vulnerabilidades**: Lista de vulnerabilidades comunes
- **Tipos de Malware**: Clasificación de malware conocido
- **Protocolos de Red**: Protocolos de comunicación
- **Términos Forenses**: Vocabulario de análisis forense

### Cheatsheets Incluidas (18 guías)
- **nmap**: Comandos y técnicas de escaneo
- **metasploit**: Framework de penetration testing
- **sqlmap**: Inyección SQL automatizada
- **hydra**: Ataques de fuerza bruta
- **hashcat**: Cracking de contraseñas
- **wireshark**: Análisis de tráfico de red
- **burp suite**: Testing de aplicaciones web
- **john the ripper**: Cracking de hashes
- Y 10 cheatsheets adicionales de herramientas de Kali

## INSTALACIÓN Y CONFIGURACIÓN

### Requisitos del Sistema
- **Sistema Operativo**: Kali Linux 2024.x+ (Recomendado) / Ubuntu 20.04+ / Debian 11+
- **Versión de Python**: Python 3.8+ (3.10+ recomendado)
- **Memoria RAM**: Mínimo 4GB (8GB+ recomendado)
- **Almacenamiento**: 2GB libres
- **Red**: Conexión para feeds de inteligencia
- **Permisos**: Privilegios sudo para integración completa

### Instalación Rápida para Kali Linux

```bash
# 1. Clonar el repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Crear entorno virtual (OBLIGATORIO en Kali 2024+)
python3 -m venv venv_aresitos
source venv_aresitos/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Verificar instalación
python3 main.py
```

### Dependencias Python Principales
```bash
# Framework GUI Moderno
customtkinter>=5.2.0      # Componentes modernos de interfaz
pillow>=10.0.0             # Procesamiento de imágenes

# Red y Seguridad
requests>=2.31.0           # Cliente HTTP
psutil>=5.9.0              # Monitoreo del sistema
python-nmap>=0.7.1         # Wrapper para Nmap
scapy>=2.4.5               # Manipulación de paquetes

# Análisis de Datos
pandas>=2.0.0              # Análisis de datasets
matplotlib>=3.7.0          # Gráficos y dashboards

# Sistema y Monitoreo
watchdog>=3.0.0            # Monitoreo de archivos
colorlog>=6.7.0            # Sistema de logging
```

### Herramientas Integradas de Kali Linux
```bash
# Reconocimiento y Mapeo de Red
nmap                       # Exploración de red
masscan                    # Escaneo de puertos masivo
nikto                      # Escáner de vulnerabilidades web

# Análisis de Sistema y Archivos
find                       # Búsqueda de archivos
stat                       # Información de archivos
md5sum                     # Checksums MD5
inotifywait               # Monitoreo de archivos

# Monitoreo de Sistema
tail, grep, ps            # Herramientas de análisis
netstat                   # Estadísticas de red
journalctl                # Logs del sistema

# Auditoría de Seguridad
lynis                     # Auditoría de sistema
rkhunter                  # Detección de rootkits
chkrootkit                # Verificación de rootkits
systemctl                 # Control de servicios
```

## SOLUCIÓN DE PROBLEMAS

### Error: "externally-managed-environment" en Kali Linux
```bash
# Kali Linux 2024+ requiere entorno virtual OBLIGATORIO
python3 -m venv venv_aresitos
source venv_aresitos/bin/activate
pip install -r requirements.txt
```

### Error: "ModuleNotFoundError: No module named 'psutil'"
```bash
# Verificar que el entorno virtual esté activo
source venv_aresitos/bin/activate
pip install psutil customtkinter requests pandas matplotlib
```

### Error: Permisos insuficientes
```bash
# Verificar permisos
python3 aresitos/utils/verificacion_permisos.py

# Ejecutar con permisos elevados si es necesario
sudo python3 main.py
```

### Error: "No module named 'tkinter'"
```bash
# Instalar tkinter del sistema
sudo apt install -y python3-tk python3-dev
```

## CONFIGURACIÓN DE PERMISOS PARA KALI LINUX

### Verificación Manual
```bash
# Verificar que las herramientas estén disponibles
which nmap netstat ss lynis rkhunter

# Verificar permisos específicos usando el sistema integrado
python3 aresitos/utils/verificacion_permisos.py
```

## GUÍA DE USO

### Primera Ejecución
```bash
# Activar entorno virtual
source venv_aresitos/bin/activate

# Lanzar ARESITOS
python3 main.py
```

### Verificación de Módulos Kali
Cada módulo principal incluye verificación automática que:
- Verifica la disponibilidad de herramientas
- Comprueba permisos necesarios
- Muestra el estado del gestor de permisos
- Proporciona recomendaciones de configuración

### Workflows Principales

#### Escaneo de Seguridad
1. Acceder al módulo "Escaneador"
2. Verificar que las herramientas estén disponibles (nmap, masscan, nikto)
3. Configurar objetivo (IP, rango de red, archivo de hosts)
4. Seleccionar tipo de escaneo (puertos, vulnerabilidades, servicios)
5. Ejecutar escaneo y revisar resultados en tiempo real
6. Revisar reporte generado con hallazgos

#### Monitoreo de Integridad (FIM)
1. Acceder al módulo "FIM"
2. Verificar herramientas del sistema (find, stat, md5sum, inotifywait)
3. Configurar rutas críticas del sistema a monitorear
4. Iniciar monitoreo en tiempo real de cambios en archivos
5. Revisar alertas cuando se detecten modificaciones
6. Analizar baseline de integridad de archivos

#### Análisis de Eventos (SIEM)
1. Acceder al módulo "SIEM"
2. Verificar configuración de herramientas (journalctl, ps, netstat)
3. Configurar fuentes de logs del sistema a monitorear
4. Iniciar correlación de eventos en tiempo real
5. Analizar alertas de seguridad generadas automáticamente
6. Revisar patrones sospechosos detectados

#### Auditoría de Sistema
1. Acceder al módulo "Auditoría"
2. Verificar herramientas de auditoría (lynis, rkhunter, chkrootkit)
3. Seleccionar tipo de auditoría (completa, específica, rootkits)
4. Ejecutar análisis completo del sistema
5. Revisar hallazgos y vulnerabilidades detectadas
6. Implementar recomendaciones de seguridad

#### Uso de Wordlists y Diccionarios
1. Acceder al módulo de "Wordlists"
2. Seleccionar categoría necesaria (passwords, usuarios, subdominios)
3. Generar wordlist personalizada o usar existente
4. Exportar lista para uso con herramientas externas
5. Utilizar con herramientas como hydra, john, hashcat

#### Consulta de Cheatsheets
1. Acceder al módulo de "Herramientas"
2. Seleccionar herramienta de interés (nmap, metasploit, etc.)
3. Consultar comandos y técnicas específicas
4. Copiar comandos para uso directo en terminal
5. Seguir guías paso a paso para técnicas avanzadas

## ESTRUCTURA DE ARCHIVOS ACTUAL

Después de la limpieza y organización, el proyecto mantiene únicamente archivos esenciales:

```
Ares-Aegis/
├── main.py                       # Punto de entrada principal
├── requirements.txt              # Dependencias Python
├── README.md                     # Documentación principal
├── setup.py                      # Configuración del proyecto
├── installer.py                  # Instalador del sistema
├── verificar.py                  # Verificador de sistema
├── aresitos/                     # Código principal organizado en MVC
├── configuracion/                # Archivos de configuración
├── data/                         # Wordlists y diccionarios
├── recursos/                     # Recursos gráficos y datos
├── tests/                        # Pruebas del sistema
├── debian/                       # Configuración para paquetes .deb
├── installer_temp/               # Archivos temporales del instalador
├── .git/                         # Control de versiones
├── .gitignore                    # Archivos ignorados por Git
└── .gitattributes               # Configuración de Git
```

## CARACTERÍSTICAS DESTACADAS

### Funcionalidad Real y Práctica
- Integración directa con herramientas nativas de Kali Linux
- Escaneador que realmente funciona con nmap, masscan, nikto
- FIM funcional usando herramientas del sistema (inotifywait, md5sum)
- SIEM básico pero efectivo para monitoreo de logs
- Auditorías reales con lynis, rkhunter, chkrootkit

### Recursos Útiles para Pentesting
- Más de 16 categorías de wordlists listas para usar
- Cheatsheets prácticos de 18 herramientas de Kali Linux
- Diccionarios especializados con términos de ciberseguridad
- Wordlists optimizadas para entornos hispanohablantes
- Endpoints y directorios comunes para testing web

### Facilidad de Uso
- Interfaz gráfica intuitiva inspirada en Burp Suite
- Verificación automática de herramientas disponibles
- Configuración sencilla para Kali Linux
- Reportes claros y fáciles de entender
- Guías paso a paso en los cheatsheets

### Organización y Mantenimiento
- Arquitectura MVC bien estructurada
- Código limpio y documentado
- Control de versiones con Git
- Proyecto sin archivos innecesarios
- Documentación actualizada

## SOPORTE Y COMUNIDAD

### Canales de Soporte
- **GitHub Issues**: Reportar problemas y bugs
- **Documentación**: README.md completo con guías
- **Comunidad**: Contribuciones abiertas
- **Enfoque Educativo**: De estudiante a estudiante

### Contribuciones
Para contribuir al proyecto:
1. Fork del repositorio
2. Crear feature branch
3. Implementar mejoras
4. Ejecutar tests de seguridad
5. Documentar cambios
6. Pull Request con descripción detallada

## CONSIDERACIONES LEGALES Y ÉTICAS

### Uso Ético y Legal
- **AUTORIZACIÓN OBLIGATORIA**: Usar solo en sistemas propios o con autorización explícita
- **CUMPLIMIENTO LEGAL**: Respetar las leyes de ciberseguridad locales
- **DIVULGACIÓN RESPONSABLE**: Reportar vulnerabilidades de forma responsable
- **DOCUMENTACIÓN**: Mantener registros de las actividades realizadas
- **PROPÓSITO EDUCATIVO**: Herramienta diseñada para aprendizaje de ciberseguridad

### Licencia
**ARESITOS** está licenciado bajo **MIT License** con atribución requerida.

```
MIT License con Atribución Requerida
Copyright (c) 2025 DogSoulDev

PERMISOS: Uso, modificación, distribución
CONDICIONES: Mantener atribución al creador original
PROHIBICIONES: Uso ilegal, eliminación de créditos
```

---

## ARESITOS - SISTEMA DE CIBERSEGURIDAD

### Estado del Proyecto
- **Estado**: FUNCIONAL
- **Enfoque**: Herramienta práctica de ciberseguridad
- **Compatibilidad**: Kali Linux 2024.x+
- **Arquitectura**: MVC organizada

### Información del Proyecto
- **Versión**: Sistema estable y funcional
- **Fecha**: 16 de Agosto de 2025
- **Autor**: DogSoulDev
- **Repositorio**: Aresitos
- **Tipo**: Software libre para educación en ciberseguridad

---

## DEDICATORIA ESPECIAL

### En Memoria de Ares

*Este programa gratuito lo comparto con todos los compañeros de ciberseguridad en honor a mi hijo y perro, **Ares** - 25/04/2013 a 5/08/2025 DEP.*

*Hasta que volvamos a vernos,*  
**DogSoulDev**

---

*© 2025 ARESITOS Project. Desarrollado por DogSoulDev*
