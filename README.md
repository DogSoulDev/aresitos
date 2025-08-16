# ARESITOS - Sistema de Ciberseguridad para Kali Linux

<p align="center">
  <img src="aresitos/recursos/Aresitos.ico" alt="ARESITOS" width="128" height="128">
</p>

## Suite de Análisis de Seguridad y Auditoría

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
- Detección de modificaciones usando polling manual
- Baseline criptográfico usando hashlib nativo
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

## INSTALACIÓN Y CONFIGURACIÓN

### Requisitos del Sistema
- **Sistema Operativo**: Kali Linux 2024.x+ (Recomendado)
- **Versión de Python**: Python 3.8+ (3.10+ recomendado)
- **Memoria RAM**: Mínimo 4GB (8GB+ recomendado)
- **Almacenamiento**: 2GB libres
- **Red**: Conexión para feeds de inteligencia
- **Permisos**: Privilegios sudo para integración completa

### Instalación en Kali Linux

```bash
# 1. Clonar el repositorio
┌──(venv)─(kali㉿kali)-[~]
└─$ git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Crear entorno virtual (OBLIGATORIO en Kali 2024+)
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ python3 -m venv venv_aresitos
source venv_aresitos/bin/activate

# 3. Instalar dependencias
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ pip install -r requirements.txt

# 4. Ejecutar ARESITOS
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ python3 main.py
```

### Dependencias Python Mínimas
```bash
# Dependencia crítica para monitoreo del sistema
psutil>=5.9.0              # Información del sistema y procesos

# Bibliotecas Python nativas incluidas (no requieren instalación):
# - tkinter (interfaz gráfica)
# - subprocess (ejecución de comandos del sistema)
# - hashlib (hashing MD5/SHA256 para integridad)
# - json (persistencia de configuración)
# - threading (operaciones concurrentes)
# - datetime (timestamps y fechas)
# - logging (sistema de logs)
# - socket (networking básico)
# - os/pathlib (manejo de archivos y rutas)
# - re (expresiones regulares)
# - tempfile (archivos temporales)
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
│   ├── escaneador_avanzado.py        # Motor de escaneo avanzado
│   ├── siem_avanzado.py              # SIEM avanzado
│   ├── modelo_fim.py                 # Monitoreo de integridad FIM
│   ├── monitor_red.py                # Monitor de red
│   ├── monitor_procesos.py           # Monitor de procesos
│   ├── constructor_wordlists.py      # Constructor de wordlists
│   ├── constructor_wordlists_base.py # Base para wordlists
│   ├── gestor_cuarentena.py          # Gestor de cuarentena
│   ├── hallazgos_seguridad.py        # Gestión de hallazgos
│   ├── analizadores.py               # Analizadores especializados
│   ├── auditor_autenticacion.py      # Auditor de autenticación
│   ├── escaneador_vulnerabilidades_red.py # Escaneo de red
│   ├── escaneador_vulnerabilidades_sistema.py # Escaneo de sistema
│   ├── escaneador.py                 # Escaneador base
│   ├── siem.py                       # SIEM básico
│   └── utilidades_sistema.py         # Utilidades del sistema
├── vista/                         # Interfaces de Usuario
│   ├── vista_principal.py            # Vista principal con diagnósticos
│   ├── vista_login.py                # Vista de login con permisos automáticos
│   ├── vista_auditoria.py            # Vista de auditoría
│   ├── vista_actualizacion.py        # Vista de actualización
│   ├── vista_escaneo.py              # Vista de escaneo
│   ├── vista_fim.py                  # Vista de FIM
│   ├── vista_siem.py                 # Vista de SIEM
│   ├── vista_reportes.py             # Vista de reportes
│   ├── vista_dashboard.py            # Dashboard principal
│   ├── vista_gestion_datos.py        # Gestión de datos
│   ├── vista_herramientas.py         # Vista de herramientas
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
├── aresitos_config.json              # Configuración principal
├── aresitos_config_kali.json         # Configuración para Kali
└── MAPA_NAVEGACION_ESCANEADOR.md     # Documentación de navegación

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

logs/                              # Sistema de Logs
└── (logs generados automáticamente)

documentacion/                     # Documentación Adicional
└── guias/                            # Guías de usuario

tests/                             # Pruebas del Sistema
└── (archivos de testing)
```

### Módulos Principales Verificados para Kali Linux
- **Escaneador**: Utiliza nmap, masscan, nikto para escaneos de red y vulnerabilidades
- **FIM**: Utiliza polling manual con hashlib nativo para monitoreo de integridad
- **SIEM**: Utiliza tail, grep, ps, netstat, journalctl para análisis de eventos
- **Auditoría**: Utiliza lynis, rkhunter, chkrootkit, systemctl para auditorías de sistema

## SOLUCIÓN DE PROBLEMAS

### Error: "externally-managed-environment" en Kali Linux
```bash
# Kali Linux 2024+ requiere entorno virtual OBLIGATORIO
┌──(kali㉿kali)-[~/Aresitos]
└─$ python3 -m venv venv_aresitos
source venv_aresitos/bin/activate
pip install -r requirements.txt
```

### Error: "ModuleNotFoundError: No module named 'psutil'"
```bash
# Verificar que el entorno virtual esté activo
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ source venv_aresitos/bin/activate
pip install psutil
```

### Error: Permisos insuficientes
```bash
# El sistema de login automáticamente configura permisos
# Si hay problemas, verificar manualmente:
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ python3 aresitos/utils/verificacion_permisos.py
```

### Error: "No module named 'tkinter'"
```bash
# Instalar tkinter del sistema
┌──(kali㉿kali)-[~/Aresitos]
└─$ sudo apt install -y python3-tk python3-dev
```

### Interfaz muestra pantalla gris
```bash
# Sistema de diagnóstico automático detectará el problema
# Revisar output del sistema de diagnósticos integrado
# Verificar variable DISPLAY: echo $DISPLAY
# En SSH usar: ssh -X usuario@host
```

## CARACTERÍSTICAS AVANZADAS

### Sistema de Login con Permisos Automáticos
- **Autenticación root**: Login seguro con contraseña de root
- **Configuración automática de permisos**: chmod automático en archivos críticos
- **Detección inteligente de rutas**: Detecta automáticamente directorio del proyecto
- **Múltiples ubicaciones soportadas**: `/home/kali/Aresitos`, `/home/kali/Desktop/Aresitos`, etc.

### Diagnósticos Automáticos del Sistema
- **Verificación de tkinter**: Detecta problemas de GUI automáticamente
- **Análisis de permisos**: Verifica permisos de archivos de configuración
- **Detección de DISPLAY**: Identifica problemas de X11 forwarding
- **Interfaz de emergencia**: Modo de fallback si la interfaz principal falla

### Gestión Avanzada de Errores
- **Logs detallados**: Sistema de logging comprehensivo
- **Fallbacks inteligentes**: Múltiples niveles de recuperación
- **Diagnósticos en tiempo real**: Información inmediata sobre problemas
- **Reintentos automáticos**: Sistema de recuperación automática

## GUÍA DE USO

### Primera Ejecución
```bash
# Activar entorno virtual
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ source venv_aresitos/bin/activate

# Lanzar ARESITOS (con login automático de permisos)
┌──(venv)─(kali㉿kali)-[~/Aresitos]
└─$ python3 main.py
```

### Workflows Principales

#### Escaneo de Seguridad
1. **Login**: Ingresar contraseña root para configuración automática de permisos
2. **Dashboard**: Acceder al módulo "Escaneo" desde la interfaz principal
3. **Configuración**: Configurar objetivo (IP, rango de red, archivo de hosts)
4. **Selección**: Seleccionar tipo de escaneo (puertos, vulnerabilidades, servicios)
5. **Ejecución**: Ejecutar escaneo y revisar resultados en tiempo real
6. **Reportes**: Revisar reporte generado con hallazgos

#### Monitoreo de Integridad (FIM)
1. **Acceso**: Acceder al módulo "FIM" desde la interfaz
2. **Configuración**: Configurar rutas críticas del sistema a monitorear
3. **Baseline**: Establecer baseline de integridad inicial
4. **Monitoreo**: Iniciar monitoreo continuo de cambios en archivos
5. **Alertas**: Revisar alertas cuando se detecten modificaciones
6. **Análisis**: Analizar cambios y determinar si son legítimos

#### Análisis de Eventos (SIEM)
1. **Configuración**: Acceder al módulo "SIEM" y configurar fuentes de logs
2. **Monitoreo**: Iniciar correlación de eventos en tiempo real
3. **Análisis**: Analizar alertas de seguridad generadas automáticamente
4. **Investigación**: Revisar patrones sospechosos detectados
5. **Respuesta**: Implementar medidas de respuesta a incidentes

#### Sistema de Auditoría
1. **Selección**: Acceder al módulo "Auditoría" y seleccionar tipo de auditoría
2. **Ejecución**: Ejecutar análisis completo del sistema con lynis/rkhunter
3. **Análisis**: Revisar hallazgos y vulnerabilidades detectadas
4. **Priorización**: Priorizar hallazgos por criticidad
5. **Remediación**: Implementar recomendaciones de seguridad

#### Gestión de Wordlists
1. **Navegación**: Acceder al módulo "Wordlists"
2. **Selección**: Seleccionar categoría (passwords, usuarios, subdominios)
3. **Generación**: Generar wordlist personalizada o usar existente
4. **Exportación**: Exportar lista para uso con herramientas externas
5. **Integración**: Utilizar con herramientas como hydra, john, hashcat

## CONTENIDO INCLUIDO

### Wordlists Especializadas (Más de 16 categorías)
- **Passwords**: `passwords_worst_500.txt`, `rockyou_top10k.txt`
- **Usuarios**: `seclists_usernames.txt`
- **Subdominios**: `seclists_subdomains.txt`
- **Directorios Web**: `seclists_directories.txt`
- **Endpoints API**: `api_endpoints.txt`
- **Extensiones**: `web_extensions.txt`
- **Palabras en Español**: `palabras_españolas.txt`
- **Números Comunes**: `numeros_comunes.txt`
- **Símbolos Especiales**: `simbolos_especiales.txt`
- **Combinaciones Básicas**: `combinaciones_basicas.txt`

### Estructura de Archivos Optimizada
```
Aresitos/
├── main.py                       # Punto de entrada con verificaciones
├── requirements.txt              # Solo psutil (dependencia mínima)
├── README.md                     # Documentación actualizada
├── aresitos/                     # Código principal MVC
│   ├── controlador/              # Lógica de negocio
│   ├── modelo/                   # Modelos de datos
│   ├── vista/                    # Interfaces de usuario
│   ├── utils/                    # Utilidades del sistema
│   └── recursos/                 # Recursos gráficos (Aresitos.ico)
├── configuracion/                # Configuraciones JSON
├── data/                         # Wordlists y diccionarios
├── logs/                         # Logs del sistema
├── documentacion/                # Documentación adicional
└── tests/                        # Pruebas del sistema
```

## CARACTERÍSTICAS DESTACADAS

### Funcionalidad Real y Práctica
- **Integración nativa**: Herramientas de Kali Linux completamente integradas
- **Escaneador funcional**: nmap, masscan, nikto con interfaz gráfica
- **FIM eficiente**: Monitoreo de integridad usando hashlib nativo
- **SIEM operativo**: Análisis de logs y eventos del sistema
- **Auditorías reales**: lynis, rkhunter, chkrootkit con reportes

### Sistema de Permisos Inteligente
- **Login automático**: Configuración de permisos al iniciar sesión
- **Detección múltiple**: Soporta diferentes ubicaciones del proyecto
- **Permisos granulares**: chmod específico para cada tipo de archivo
- **Recuperación automática**: Sistema de fallback para errores de permisos

### Recursos Completos para Pentesting
- **16+ wordlists especializadas**: Listas optimizadas para diferentes usos
- **18+ cheatsheets**: Guías de herramientas de Kali Linux
- **Diccionarios temáticos**: MITRE ATT&CK, herramientas, vulnerabilidades
- **Optimización hispana**: Contenido adaptado para entornos en español

### Robustez y Confiabilidad
- **Arquitectura MVC**: Código bien estructurado y mantenible
- **Manejo de errores**: Sistema comprehensivo de recuperación
- **Diagnósticos automáticos**: Detección proactiva de problemas
- **Interfaz de emergencia**: Modo de fallback para errores críticos

## SOPORTE Y COMUNIDAD

### Canales de Soporte
- **GitHub Issues**: [https://github.com/DogSoulDev/Aresitos/issues](https://github.com/DogSoulDev/Aresitos/issues)
- **Documentación**: README.md completo con guías paso a paso
- **Código abierto**: Contribuciones y mejoras bienvenidas

### Contribuciones
Para contribuir al proyecto:
1. **Fork**: Crear fork del repositorio
2. **Branch**: Crear feature branch para cambios
3. **Desarrollo**: Implementar mejoras siguiendo arquitectura MVC
4. **Testing**: Ejecutar pruebas en Kali Linux
5. **Documentación**: Actualizar documentación relevante
6. **Pull Request**: Enviar PR con descripción detallada

## CONSIDERACIONES LEGALES Y ÉTICAS

### Uso Responsable
- **AUTORIZACIÓN REQUERIDA**: Usar solo en sistemas propios o con autorización explícita por escrito
- **CUMPLIMIENTO LEGAL**: Respetar todas las leyes locales e internacionales de ciberseguridad
- **DIVULGACIÓN RESPONSABLE**: Reportar vulnerabilidades siguiendo principios de divulgación responsable
- **PROPÓSITO EDUCATIVO**: Herramienta diseñada para aprendizaje y mejora de seguridad

### Limitaciones de Responsabilidad
- **Uso bajo propia responsabilidad**: El autor no se hace responsable del mal uso
- **Herramienta educativa**: Diseñada para aprendizaje de ciberseguridad
- **Verificar legalidad**: Verificar leyes locales antes de usar
- **Entornos controlados**: Usar preferiblemente en laboratorios y entornos de prueba

## INFORMACIÓN DEL PROYECTO

### Estado Actual
- **Estado**: ✅ FUNCIONAL Y ESTABLE
- **Última actualización**: 16 de Agosto de 2025
- **Compatibilidad**: Kali Linux 2024.x+
- **Arquitectura**: MVC organizada y documentada
- **Dependencias**: Mínimas (solo psutil)

### Información del Desarrollador
- **Autor**: DogSoulDev
- **Repositorio**: [https://github.com/DogSoulDev/Aresitos](https://github.com/DogSoulDev/Aresitos)
- **Licencia**: MIT License con atribución requerida
- **Tipo**: Software libre educativo

## DEDICATORIA ESPECIAL

### En Memoria de Ares

*Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo y compañero, **Ares** - 25/04/2013 a 5/08/2025 DEP.*

*Un proyecto desarrollado con amor para ayudar a otros en su camino de aprendizaje de ciberseguridad.*

*Hasta que volvamos a vernos,*  
**DogSoulDev**

---

*© 2025 ARESITOS Project. Desarrollado por DogSoulDev con 💙 para la comunidad de ciberseguridad*
