# ARESITOS - Sistema de Ciberseguridad Optimizado para Kali Linux

<p align="center">
  <img src="aresitos/recursos/Aresitos.ico" alt="ARESITOS" width="128" height="128">
</p>

## Suite de Análisis de Seguridad y Auditoría - VERSIÓN KALI-OPTIMIZADA

**ARESITOS v2.1.0-seguro-kali** es una suite de ciberseguridad desarrollada específicamente para profesionales de seguridad, ethical hackers, administradores de sistemas e investigadores que trabajan en entornos Kali Linux, utilizando **exclusivamente herramientas nativas de Kali** y **Python nativo** sin dependencias externas.

## CARACTERÍSTICAS PRINCIPALES - SEGURAS Y OPTIMIZADAS PARA KALI LINUX

### 🔒 Seguridad Reforzada (NUEVO v2.1.0)
- **Auditoría de seguridad completa**: 69 vulnerabilidades identificadas y corregidas
- **Código securizado**: Eliminación de subprocess shell=True y validación de entradas
- **Permisos seguros**: Corrección de permisos excesivos (777 → 755/644)
- **Validación de entrada**: Sanitización robusta de datos del usuario
- **Cumplimiento de estándares**: OWASP Top 10 y NIST Cybersecurity Framework
- **Documentación de seguridad**: Reporte completo en `documentacion/seguridad_corregida.md`

### Sistema de Escaneo de Seguridad Avanzado y Seguro
- **Escaneo de vulnerabilidades** del sistema usando herramientas nativas de Kali Linux
- **Detección de malware y rootkits** con rkhunter, chkrootkit y lynis integrados
- **Ejecución segura**: Subprocess sin shell=True para prevenir inyección de comandos
- **Validación de objetivos**: Verificación robusta de IPs y rangos de red
- **Análisis de puertos y servicios** usando nmap, masscan, zmap y ncat nativos
- **Escaneo de archivos sospechosos** con verificación SHA256 y análisis forense
- **Detección de configuraciones inseguras** con auditoría automática
- **Integración real** con 50+ herramientas nativas de Kali Linux

### SIEM - Sistema de Monitoreo de Eventos Mejorado y Seguro
- **Ejecución securizada**: Comandos con argumentos en lista para prevenir inyección
- **Correlación de eventos** de seguridad del sistema con journalctl nativo
- **Monitoreo en tiempo real** de logs usando herramientas nativas seguras
- **Análisis de procesos y conexiones** de red con ps, ss y netstat sin shell=True
- **Detección de patrones sospechosos** en logs con regex avanzados
- **Alertas automáticas** basadas en reglas personalizables
- **Integración forense** con DD/DCFLDD para análisis de discos

### FIM (File Integrity Monitoring) Optimizado
- **Monitoreo de integridad** de archivos críticos del sistema
- **Detección de modificaciones** usando hashing SHA256 nativo
- **Alertas de cambios** no autorizados en archivos importantes
- **Monitoreo PAM específico** de `/etc/pam.d/` con find y stat nativos
- **Verificación de permisos** detallada con herramientas de sistema

### Gestión de Wordlists y Diccionarios
- **Constructor de wordlists** personalizadas con más de 20 categorías
- **Base de datos** con 16+ categorías especializadas de términos
- **Wordlists optimizadas** para entornos hispanohablantes
- **Diccionarios especializados**: MITRE ATT&CK, herramientas de hacking, CVE
- **Integración completa** con wordlists comunes de Kali Linux

## INSTALACIÓN RÁPIDA Y SEGURA EN KALI LINUX

### Requisitos del Sistema
- **Sistema Operativo**: Kali Linux 2024.x+ (Recomendado y Optimizado)
- **Versión de Python**: Python 3.8+ (3.10+ recomendado) - Solo librerías nativas
- **Memoria RAM**: Mínimo 4GB (8GB+ recomendado para forense)
- **Almacenamiento**: 2GB libres para logs y análisis
- **Permisos**: Privilegios sudo para integración completa con herramientas Kali

### Instalación Paso a Paso

```bash
# 1. Clonar el repositorio seguro
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Crear entorno virtual (OBLIGATORIO en Kali 2024+)
python3 -m venv venv_aresitos
source venv_aresitos/bin/activate

# 3. Instalar dependencias mínimas (Solo psutil)
pip install -r requirements.txt

# 4. Verificar seguridad y optimizaciones Kali (RECOMENDADO)
python3 verificacion_seguridad.py

# 5. Ejecutar ARESITOS seguro y optimizado
python3 main.py
```

### Dependencias Python Mínimas
```bash
# ÚNICA dependencia externa crítica para monitoreo del sistema
psutil>=5.9.0              # Información del sistema y procesos

# Bibliotecas Python NATIVAS incluidas (NO requieren instalación):
# - tkinter (interfaz gráfica)
# - subprocess (ejecución de comandos del sistema)
# - hashlib (hashing MD5/SHA256 para integridad)
# - json (persistencia de configuración)
# - threading (operaciones concurrentes)
# - datetime (timestamps y fechas)
# - logging (sistema de logs)
```

## HERRAMIENTAS NATIVAS DE KALI LINUX INTEGRADAS (50+ VERIFICADAS)

### Reconocimiento y Mapeo de Red
- **nmap, masscan, zmap**: Exploración de red y puertos
- **nikto, dirb, gobuster**: Escáner de vulnerabilidades web
- **netdiscover, arping**: Descubrimiento de hosts

### Análisis de Sistema y Archivos
- **find, stat, lsof**: Búsqueda y análisis de archivos
- **md5sum, sha256sum**: Checksums y verificación de integridad
- **head, tail, grep, awk**: Análisis de logs y texto

### Auditoría de Seguridad y Forense
- **lynis**: Auditoría completa de sistema
- **rkhunter, chkrootkit**: Detección de rootkits y malware
- **dd, dcfldd**: Herramientas forenses de disco

### Herramientas de Pentesting
- **john, hashcat**: Cracking de passwords
- **hydra, medusa**: Ataques de fuerza bruta
- **sqlmap**: Inyección SQL
- **metasploit-framework**: Framework de explotación

## ARQUITECTURA DEL SISTEMA OPTIMIZADA Y SEGURA

### Patrón MVC (Modelo-Vista-Controlador) con Optimizaciones Kali
```
aresitos/                          # Núcleo Principal Optimizado
├── controlador/                   # Controladores con Herramientas Nativas
│   ├── controlador_principal.py      # Orquestador central del sistema
│   ├── controlador_escaneador.py     # Motor con nmap, masscan, zmap
│   ├── controlador_fim.py            # FIM con monitoreo PAM específico
│   ├── controlador_siem.py           # SIEM con journalctl, ss, ps nativos
│   ├── controlador_auditoria.py      # Auditoría con lynis/rkhunter
│   └── gestor_configuracion.py       # Gestión configs específicas Kali
├── modelo/                        # Modelos con Integración Nativa
│   ├── escaneador_avanzado.py        # Motor escaneo con herramientas Kali
│   ├── siem_avanzado.py              # SIEM con análisis logs nativos
│   ├── modelo_fim.py                 # FIM con SHA256 y find nativo
│   └── constructor_wordlists.py      # Constructor con listas Kali
├── vista/                         # Interfaces Optimizadas para Kali
│   ├── vista_principal.py            # Vista principal con diagnósticos Kali
│   ├── vista_login.py                # Login con permisos automáticos
│   ├── vista_escaneo.py              # Escaneo con herramientas integradas
│   └── vista_siem.py                 # SIEM con forense DD/DCFLDD
└── utils/                         # Utilidades Optimizadas
    ├── verificacion_permisos.py      # Verificación permisos robusta
    └── configurar.py                 # Configurador con herramientas nativas
```

## GUÍA DE USO OPTIMIZADA

### Primera Ejecución Segura en Kali Linux
```bash
# 1. Activar entorno virtual (OBLIGATORIO)
source venv_aresitos/bin/activate

# 2. Verificar seguridad y optimizaciones
python3 verificacion_seguridad.py

# 3. Lanzar ARESITOS con login automático
python3 main.py

# 4. Ingresar contraseña root cuando se solicite
# 5. Disfrutar de las 50+ herramientas integradas de forma segura
```

### Workflows Principales

#### Escaneo de Seguridad Avanzado
1. **Login**: Ingresar contraseña root para configuración automática
2. **Dashboard**: Acceder al módulo "Escaneo" desde la interfaz principal
3. **Configuración**: Configurar objetivo (IP, rango de red, archivo de hosts)
4. **Ejecución**: Ejecutar escaneo y revisar resultados en tiempo real
5. **Reportes**: Revisar reporte generado con hallazgos y metadatos

#### Monitoreo de Integridad (FIM)
1. **Acceso**: Acceder al módulo "FIM" desde la interfaz
2. **Configuración**: Configurar rutas críticas incluyendo monitoreo PAM
3. **Baseline**: Establecer baseline de integridad con verificaciones
4. **Monitoreo**: Iniciar monitoreo continuo con alertas inmediatas
5. **Alertas**: Recibir notificaciones cuando se detecten modificaciones

#### Análisis de Eventos (SIEM)
1. **Configuración**: Acceder al módulo "SIEM" con herramientas verificadas
2. **Fuentes**: Configurar análisis de journalctl, logs, procesos y red
3. **Monitoreo**: Iniciar correlación con ss, ps, grep, tail nativos
4. **Análisis**: Utilizar DD/DCFLDD para análisis de discos
5. **Reportes**: Generar documentación completa de incidentes

## SOLUCIÓN DE PROBLEMAS

### Verificación Automática de Seguridad y Sistema
```bash
# Ejecutar verificación completa de seguridad
python3 verificacion_seguridad.py

# El script verificará automáticamente:
# - Estado de seguridad del código (vulnerabilidades corregidas)
# - 50+ herramientas nativas de Kali Linux
# - Configuraciones específicas de Kali
# - Permisos de archivos seguros
```

### Error: "externally-managed-environment" en Kali Linux
```bash
# Verificar que el entorno virtual esté activo
source venv_aresitos/bin/activate
pip install psutil

# Verificar instalación
python3 -c "import psutil; print('psutil OK')"
```

### Error: "No module named 'tkinter'"
```bash
# Instalar tkinter del sistema
sudo apt update && sudo apt install -y python3-tk python3-dev

# Verificar instalación
python3 -c "import tkinter; print('tkinter OK')"
```

## CONSIDERACIONES LEGALES Y ÉTICAS

### Uso Responsable y Autorizado
- **AUTORIZACIÓN OBLIGATORIA**: Usar ÚNICAMENTE en sistemas propios o con autorización explícita por escrito
- **CUMPLIMIENTO LEGAL**: Respetar todas las leyes locales e internacionales de ciberseguridad
- **PROPÓSITO EDUCATIVO**: Herramienta diseñada para aprendizaje y mejora de seguridad
- **ENTORNOS CONTROLADOS**: Usar preferiblemente en laboratorios, VMs y entornos de prueba autorizados

### Limitaciones de Responsabilidad
- **USO BAJO PROPIA RESPONSABILIDAD**: El autor no se hace responsable del mal uso de la herramienta
- **HERRAMIENTA EDUCATIVA**: Diseñada exclusivamente para aprendizaje de ciberseguridad
- **VERIFICAR LEGALIDAD**: Verificar leyes locales y regulaciones antes de usar

## INFORMACIÓN DEL PROYECTO

### Autor y Desarrollo
- **Autor**: **DogSoulDev** (Desarrollador Senior de Ciberseguridad)
- **Repositorio oficial**: [https://github.com/DogSoulDev/Aresitos](https://github.com/DogSoulDev/Aresitos)
- **Licencia**: MIT License con atribución requerida
- **Tipo**: Software libre educativo para ciberseguridad

### Soporte y Comunidad
- **GitHub Issues**: [https://github.com/DogSoulDev/Aresitos/issues](https://github.com/DogSoulDev/Aresitos/issues)
- **Documentación completa**: README.md actualizado con guías paso a paso
- **Código abierto**: Contribuciones y mejoras bienvenidas de la comunidad

---

## En Memoria de Ares

*Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, **Ares** - 25/04/2013 a 5/08/2025 DEP.*

*Hasta que volvamos a vernos,*  
**DogSoulDev**
---

*© 2025 ARESITOS Project. Desarrollado por DogSoulDev con 💙 para la comunidad de ciberseguridad*
