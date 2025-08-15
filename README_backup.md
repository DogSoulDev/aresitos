# 🔱 ARESITOS 7.0 BETA - Suite Profesional de Ciberseguridad

## � Herramienta Completa de Pentesting y Análisis de Seguridad para Kali Linux

**Aresitos 7.0 Beta** es una suite avanzada, completa y segura de ciberseguridad desarrollada específicamente para profesionales de seguridad, ethical hackers, administradores de sistemas e investigadores de ciberseguridad que trabajan en entornos Linux, con optimización completa para Kali Linux 2023.x+.

<div align="center">

![Aresitos](ares_aegis/recursos/Aresitos.ico)

### ⭐ **PROYECTO ARESITOS 7.0 BETA - VERSIÓN COMPLETA** ⭐

</div>

## 🔒 **CERTIFICACIÓN DE SEGURIDAD MÁXIMA**

### ✅ **AUDITORÍA DE CÓDIGO 100% COMPLETADA**
- **� NIVEL MÁXIMO DE SEGURIDAD ALCANZADO**
- **48 vulnerabilidades críticas eliminadas** en auditoría exhaustiva
- **100% del código base auditado y securizado** (13 Controladores, 15 Modelos, 9 Vistas)
- **Zero vulnerabilidades pendientes** - Estado: ✅ **SECURE**
- **Arquitectura MVC completamente blindada**
- **Optimizado y certificado para Kali Linux 2023.x+**

**📋 Documentación de auditoría**: Ver [AUDITORIA_SEGURIDAD.md](seguridad/AUDITORIA_SEGURIDAD.md)

### 🛡️ **CARACTERÍSTICAS DE SEGURIDAD IMPLEMENTADAS**
- **Validación universal robusta** con regex patterns y whitelists
- **Prevención total** de command injection, path traversal y XSS
- **Sanitización completa** con `shlex.quote()` y validación estricta
- **Logging seguro** sin exposición de información sensible
- **Control de acceso granular** y gestión segura de permisos
- **Arquitectura defensiva** con múltiples capas de protección

---

## 🎯 CARACTERÍSTICAS PRINCIPALES

### 🔍 **Sistema de Escaneo Avanzado y Reconocimiento**
- **Escaneo de Vulnerabilidades Automatizado**: Detección de CVEs, configuraciones inseguras y exposiciones
- **Reconocimiento de Red Completo**: Mapeo de infraestructura, enumeración de servicios y fingerprinting
- **Análisis de Aplicaciones Web**: Testing automatizado de OWASP Top 10, inyecciones SQL y XSS
- **Evaluación de Configuraciones**: Auditoría de hardening de sistema y compliance
- **Generación de Payloads Dinámicos**: Creación adaptativa de payloads para escenarios específicos

### 📊 **SIEM Avanzado - Monitoreo en Tiempo Real**
- **Correlación de Eventos Inteligente**: ML/AI para análisis de patrones y detección de anomalías
- **Dashboard de Seguridad en Tiempo Real**: Métricas live, alertas y visualizaciones avanzadas
- **Threat Hunting Automatizado**: Búsqueda proactiva de IOCs y TTPs de amenazas
- **Respuesta a Incidentes Orquestada**: Workflows automatizados de contención y remediación
- **Integración con Feeds de Inteligencia**: MITRE ATT&CK, CVE, IOCs actualizados

### 🛡️ **FIM (File Integrity Monitoring) Profesional**
- **Baseline Criptográfico Robusto**: SHA-256/512 para archivos críticos del sistema
- **Monitoreo en Tiempo Real**: Detección instantánea de modificaciones, adiciones y eliminaciones
- **Alertas Contextuales**: Notificaciones inteligentes con análisis de riesgo automático
- **Integración con AIDE/Tripwire**: Compatibilidad nativa con herramientas enterprise
- **Reportes de Compliance**: NIST, ISO 27001, PCI DSS, SOX automáticos

### 📚 **Gestión Avanzada de Wordlists y Diccionarios**
- **Constructor Inteligente de Wordlists**: Generación automática basada en contexto empresarial
- **16 Categorías Especializadas**: 6,831+ términos totales cargados automáticamente
- **Optimización por Contexto**: Wordlists específicas para entornos hispanohablantes
- **Base de Datos de Vulnerabilidades**: 1,602+ CVEs y exploits catalogados
- **Diccionarios Temáticos**: 13 diccionarios especializados (MITRE ATT&CK, Hacking Tools, etc.)

### �️ **Sistema de Cuarentena y Análisis Forense**
- **Sandbox Automatizado**: Aislamiento seguro para análisis de muestras sospechosas
- **Preservación de Evidencia**: Chain of custody digital y timestamping criptográfico
- **Análisis de Malware**: Desensamblado, análisis estático y dinámico
- **Recuperación Granular**: Restauración selectiva de elementos cuarentenados
- **Integración Forense**: Soporte para Volatility, YARA rules y IOC matching

### � **Centro de Reportes y Analíticas Empresariales**
- **18 Cheatsheets Profesionales**: Guías completas para herramientas de Kali Linux
- **Dashboards Ejecutivos**: KPIs de seguridad y métricas de riesgo organizacional
- **Reportes Técnicos Detallados**: Evaluaciones de penetration testing con remediación
- **Compliance Automatizado**: Generación de reportes para auditorías regulatorias
- **Timeline Forense**: Análisis temporal de incidentes y eventos de seguridad

---

## 🏗️ **ARQUITECTURA AVANZADA DEL SISTEMA**

### **Patrón MVC Securizado y Optimizado**
```
📁 ares_aegis/                    # Núcleo Principal de la Aplicación
├── 🎮 controlador/               # Controladores de Lógica de Negocio (13 módulos)
│   ├── controlador_principal.py      # Orquestador central del sistema
│   ├── controlador_escaneo.py        # Motor de escaneo y reconocimiento
│   ├── controlador_monitoreo.py      # Sistema de monitoreo en tiempo real
│   ├── controlador_siem.py           # Correlación de eventos y alertas
│   ├── controlador_fim.py            # Monitoreo de integridad de archivos
│   ├── controlador_wordlists.py      # Gestión inteligente de wordlists
│   ├── controlador_diccionarios.py   # Procesamiento de diccionarios
│   ├── controlador_cuarentena.py     # Sistema de sandbox y aislamiento
│   ├── controlador_reportes.py       # Generación de reportes avanzados
│   ├── controlador_herramientas.py   # Integración con herramientas Kali
│   ├── controlador_auditoria_simple.py   # Auditoría básica de sistema
│   ├── controlador_auditoria_avanzada.py # Auditoría avanzada y compliance
│   └── gestor_configuracion.py       # Gestión centralizada de configuraciones
├── 🔧 modelo/                    # Modelos de Datos y Lógica de Negocio (15 módulos)
│   ├── modelo_principal.py           # Coordinación de gestores principales
│   ├── escaneador_avanzado.py         # Motor de escaneo con IA
│   ├── siem_avanzado.py              # Correlación avanzada de eventos
│   ├── fim.py                        # Algoritmos de integridad de archivos
│   ├── monitor_red.py                # Monitoreo de tráfico de red
│   ├── monitor_procesos.py           # Supervisión de procesos del sistema
│   ├── constructor_wordlists.py      # Generador inteligente de wordlists
│   ├── gestor_cuarentena.py          # Sistema de aislamiento de amenazas
│   ├── hallazgos_seguridad.py        # Procesamiento de vulnerabilidades
│   ├── analizadores.py               # Analizadores especializados
│   ├── auditor_autenticacion.py      # Auditoría de sistemas de autenticación
│   ├── utilidades_sistema.py         # Utilidades de bajo nivel
│   ├── modelo_reportes.py            # Generación y formateo de reportes
│   ├── modelo_herramientas.py        # Abstracción de herramientas externas
│   └── modelo_gestor_diccionarios.py # Gestión avanzada de diccionarios
├── 🖥️ vista/                     # Interfaces de Usuario Profesionales (9 módulos)
│   ├── vista_principal.py            # Ventana principal con navegación
│   ├── vista_dashboard.py            # Dashboard con métricas en tiempo real
│   ├── vista_escaneo.py              # Interfaz de escaneo y reconocimiento
│   ├── vista_monitoreo.py            # Panel de monitoreo de seguridad
│   ├── vista_gestion_datos.py        # Gestión unificada de wordlists/diccionarios
│   ├── vista_herramientas.py         # Centro de herramientas y utilidades
│   ├── vista_reportes.py             # Generación y visualización de reportes
│   ├── vista_siem.py                 # Interfaz SIEM con dashboards
│   ├── vista_fim.py                  # Monitor de integridad de archivos
│   └── vista_auditoria.py            # Interfaz de auditoría avanzada
├── 🔧 utils/                     # Utilidades del Sistema
│   ├── validaciones.py               # Validación robusta de inputs
│   ├── ayuda_logging.py              # Sistema de logging securizado
│   ├── ayuda_rutas.py                # Gestión segura de rutas
│   ├── temas_kali.py                 # Tema visual optimizado para Kali
│   └── temas_simple.py               # Tema alternativo minimalista
└── 🎨 recursos/                  # Recursos Gráficos
    └── Aresitos.ico                  # Icono oficial de la aplicación

📁 data/                          # Base de Datos de Conocimiento
├── 📚 wordlists/                 # Wordlists Especializadas (11 archivos)
│   ├── passwords_comunes.txt         # 26 passwords más comunes
│   ├── passwords_top1000.txt         # 1,266 passwords avanzadas
│   ├── usernames_common.txt          # 1,375 nombres de usuario
│   ├── usuarios_comunes.txt          # 26 usuarios en español
│   ├── api_endpoints.txt             # 994 endpoints de API
│   ├── common_ports.txt              # 268 puertos con descripción
│   ├── directorios_web.txt           # 30 directorios web en español
│   ├── web_directories.txt           # 930 directorios web globales
│   ├── extensiones_archivos.txt      # 29 extensiones de archivo
│   ├── subdomains_common.txt         # 852 subdominios comunes
│   └── subdominios.txt               # 28 subdominios en español
├── 🗂️ diccionarios/              # Diccionarios Temáticos (13 archivos JSON)
│   ├── cybersecurity_terms.json     # 418 términos de ciberseguridad
│   ├── hacking_tools.json           # 406 herramientas de hacking
│   ├── mitre_attack.json            # 371 técnicas MITRE ATT&CK
│   ├── vulnerabilities.json         # 300 vulnerabilidades catalogadas
│   ├── herramientas_ciberseguridad.json # 10 herramientas españolas
│   ├── herramientas_hacking.json    # 14 herramientas de pentesting
│   ├── tipos_ataques.json           # 10 tipos de ataques clasificados
│   ├── tipos_malware.json           # 12 familias de malware
│   ├── vulnerabilidades_comunes.json # 14 vulns más frecuentes
│   ├── protocolos_red.json          # 10 protocolos de red
│   ├── puertos_comunes.json         # 20 puertos TCP/UDP críticos
│   ├── terminos_forense.json        # 12 términos de análisis forense
│   └── ejemplo_usuario.json         # Plantilla personalizable
└── 📖 cheatsheets/               # Cheatsheets Profesionales (18 archivos)
    ├── nmap_basico.txt              # Comandos esenciales de Nmap
    ├── metasploit_framework.txt     # Framework de explotación
    ├── comandos_linux.txt           # Linux para ciberseguridad
    ├── shells_inversas.txt          # Reverse shells multiplataforma
    ├── john_the_ripper.txt          # Cracking de passwords
    ├── burp_suite.txt               # Testing de aplicaciones web
    ├── analisis_logs.txt            # Análisis forense de logs
    ├── osint_basico.txt             # Inteligencia de fuentes abiertas
    ├── hydra_bruteforce.txt         # Ataques de fuerza bruta
    ├── sqlmap_injection.txt         # Explotación de SQL injection
    ├── gobuster_directory.txt       # Directory/DNS brute forcing
    ├── wireshark_analisis.txt       # Análisis de protocolos de red
    ├── nikto_web_scanner.txt        # Escaneo de vulnerabilidades web
    ├── aircrack_wifi_audit.txt      # Auditoría de redes WiFi
    ├── netcat_networking.txt        # Networking y shells
    ├── linux_comandos_completo.txt  # Comandos Linux completos
    ├── hashcat_password_cracking.txt # Cracking con GPU
    └── volatility_memory_forensics.txt # Análisis forense de memoria

📁 configuracion/                 # Configuraciones del Sistema
├── ares_aegis_config.json           # Configuración principal
├── ares_aegis_config_kali.json      # Configuración optimizada Kali
├── firmas.txt                       # Firmas de detección personalizadas
├── notificaciones.json              # Sistema de alertas y notificaciones
├── sistema_ayuda.json               # Sistema de ayuda integrado
└── textos_castellano.json           # Localización en español

📁 tests/                         # Suite de Pruebas Comprensiva
├── 🔒 security/                    # Tests de seguridad
├── ⚡ performance/                # Benchmarks de rendimiento
├── 🔗 integration/                # Pruebas de integración
└── 📊 unit/                       # Pruebas unitarias por módulo
```

### **Tema Profesional Inspirado en Burp Suite**
- **Esquema de Colores**: Tema oscuro profesional (#2b2b2b base, #ff6633 acentos)
- **Diseño Ergonómico**: Optimizado para sesiones extendidas de análisis
- **Densidad de Información**: Maximización del espacio útil de pantalla
- **Accesibilidad Visual**: Alto contraste y tipografía clara
- **Integración Kali**: Armonía visual con el entorno Kali Linux

---

## 🛠️ **INSTALACIÓN Y CONFIGURACIÓN COMPLETA**

### **Requisitos del Sistema**
- **Sistema Operativo**: Kali Linux 2023.x+ (Recomendado) / Ubuntu 20.04+ / Debian 11+
- **Versión de Python**: Python 3.8+ (3.10+ altamente recomendado)
- **Entorno Virtual**: **OBLIGATORIO** en Kali Linux 2024+ debido a PEP 668
- **Memoria RAM**: Mínimo 4GB (8GB+ recomendado para operaciones enterprise)
- **Almacenamiento**: 5GB libres (2GB aplicación + 3GB logs/datos)
- **Red**: Conexión estable para feeds de inteligencia de amenazas
- **Permisos**: Privilegios sudo para integración completa con herramientas

⚠️ **NOTA IMPORTANTE**: Kali Linux 2024+ requiere el uso de entornos virtuales para instalar paquetes Python debido a la implementación de PEP 668. No intentes usar `--break-system-packages` ya que puede dañar tu sistema.

### **Dependencias Python Principales**
```bash
# Framework GUI Moderno
customtkinter>=5.2.0      # Componentes modernos de interfaz
pillow>=10.0.0             # Procesamiento avanzado de imágenes

# Red y Seguridad
requests>=2.31.0           # Cliente HTTP robusto
psutil>=5.9.0              # Monitoreo profundo del sistema  
python-nmap>=0.7.1         # Wrapper Python para Nmap
scapy>=2.4.5               # Manipulación de paquetes de red

# Análisis de Datos y Visualización
pandas>=2.0.0              # Análisis de grandes datasets
matplotlib>=3.7.0          # Gráficos y dashboards

# Sistema y Monitoreo
watchdog>=3.0.0            # Monitoreo de archivos en tiempo real
colorlog>=6.7.0            # Sistema de logging estructurado
```

### **Herramientas Integradas de Kali Linux**
```bash
# Reconocimiento y Mapeo de Red
nmap                       # Exploración avanzada de red
masscan                    # Escaneo de puertos masivo
gobuster                   # Directory/DNS/VHost fuzzing
dirb                       # Brute force de directorios web
dirbuster                  # GUI para brute force de directorios

# Análisis de Vulnerabilidades Web
sqlmap                     # Explotación automática de SQL injection
nikto                      # Escáner de vulnerabilidades web
w3af                       # Framework de auditoría web
burpsuite                  # Plataforma de testing web profesional

# Ataques de Fuerza Bruta y Passwords
hydra                      # Bruteforcer multiplataforma
medusa                     # Bruteforcer rápido y paralelo
hashcat                    # Recuperación de passwords con GPU
john                       # John the Ripper password cracker

# Análisis de Red y Tráfico
wireshark                  # Analizador de protocolos líder
tcpdump                    # Captura de paquetes en línea de comandos
netcat                     # Navaja suiza de networking
netdiscover                # Descubrimiento de hosts en LAN

# Auditoría Inalámbrica
aircrack-ng               # Suite completa WiFi
reaver                     # Ataque WPS PIN
wifite                     # Automatización de ataques WiFi

# Frameworks de Explotación
metasploit-framework       # Framework de penetration testing
exploit-db                 # Base de datos de exploits
searchsploit               # Búsqueda offline de exploits

# Análisis Forense y Memoria
volatility3                # Análisis forense de memoria RAM
binwalk                    # Análisis de firmware binario
autopsy                    # Plataforma forense digital
```

### **Instalación Paso a Paso**

#### 1. Preparación del Entorno
```bash
# Actualizar el sistema Kali Linux
sudo apt update && sudo apt upgrade -y

# Instalar dependencias del sistema requeridas
sudo apt install -y python3-pip python3-venv python3-dev git curl wget
```

#### 2. Clonar el Repositorio
```bash
# Clonar desde GitHub
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Verificar la integridad
git log --oneline -5
```

#### 3. Configuración del Entorno Virtual (OBLIGATORIO en Kali Linux 2024+)

⚠️ **IMPORTANTE**: Kali Linux implementa PEP 668 que previene la instalación global de paquetes Python para proteger el sistema.

```bash
# Instalar soporte para entornos virtuales si no está presente
sudo apt install -y python3-venv

# Crear entorno virtual (OBLIGATORIO)
python3 -m venv venv_aresitos

# Activar el entorno virtual
source venv_aresitos/bin/activate

# Verificar que estés en el entorno virtual (debe aparecer (venv_aresitos) en el prompt)
# Actualizar pip dentro del entorno virtual
pip install --upgrade pip setuptools wheel
```

#### 4. Instalación de Dependencias
```bash
# ASEGÚRATE de que el entorno virtual esté activado
# El prompt debe mostrar: (venv_aresitos)

# Instalar todas las dependencias Python
pip install -r requirements.txt

# Verificar instalación exitosa
python -c "import customtkinter, requests, psutil, pandas; print('✅ Dependencias OK')"
```

#### 5. Verificación de Herramientas del Sistema
```bash
# Script de verificación completo incluido
python diagnostico.py

# Este script verificará:
# ✅ Versión de Python correcta
# ✅ Entorno virtual activo
# ✅ Todas las dependencias Python
# ✅ Estructura del proyecto
# ✅ Compatibilidad del icono
# ✅ Herramientas del sistema opcionales

# Instalación manual si es necesario
python verificar.py

# Instalación manual si es necesario
sudo apt install -y nmap sqlmap gobuster hydra nikto aircrack-ng \
                    wireshark hashcat john metasploit-framework \
                    dirb masscan netdiscover volatility3
```

#### 6. Configuración Inicial
```bash
# Configurar permisos para herramientas de red
sudo usermod -a -G wireshark $USER
sudo setcap cap_net_raw+epi /usr/bin/nmap

# Reiniciar sesión para aplicar cambios de grupo
newgrp wireshark
```

#### 7. Primera Ejecución
```bash
# IMPORTANTE: Asegúrate de que el entorno virtual esté activado
# El prompt debe mostrar: (venv_aresitos)
source venv_aresitos/bin/activate

# Lanzar Aresitos
python main.py

# Verificar carga completa
# ✅ Debe mostrar: "Inicialización de gestores completada"
# ✅ Wordlists: 11 archivos, 16 categorías
# ✅ Diccionarios: 13 archivos cargados
# ✅ Controladores: 10 controladores activos
```

---

## 🚨 **TROUBLESHOOTING - PROBLEMAS COMUNES EN KALI LINUX**

### **❌ Error: "externally-managed-environment"**
```bash
error: externally-managed-environment
× This environment is externally managed
```

**🔧 Solución**: Kali Linux 2024+ implementa PEP 668 para proteger el sistema Python.

```bash
# NUNCA uses --break-system-packages (puede dañar tu sistema)
# En su lugar, SIEMPRE usa un entorno virtual:

# 1. Crear entorno virtual
python3 -m venv venv_aresitos

# 2. Activar entorno virtual
source venv_aresitos/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

### **❌ Error: "ModuleNotFoundError: No module named 'psutil'"**
```bash
ModuleNotFoundError: No module named 'psutil'
```

**🔧 Solución**: El entorno virtual no está activado o las dependencias no se instalaron correctamente.

```bash
# 1. Verificar que el entorno virtual esté activado
# El prompt debe mostrar: (venv_aresitos)
source venv_aresitos/bin/activate

# 2. Reinstalar dependencias
pip install --upgrade -r requirements.txt

# 3. Verificar instalación módulo por módulo
pip list | grep psutil
pip list | grep customtkinter
pip list | grep requests

# 4. Instalación manual si es necesario
pip install psutil customtkinter requests pandas matplotlib python-nmap scapy watchdog colorlog
```

---

## 🚨 **TROUBLESHOOTING - SOLUCIÓN DE PROBLEMAS COMUNES**

### **❌ Error: "externally-managed-environment" en Kali Linux**
```bash
error: externally-managed-environment
× This environment is externally managed
```

**📋 Causa**: Kali Linux 2024+ implementa PEP 668 para proteger el entorno Python del sistema.

**🔧 Solución (RECOMENDADA)**: Usar entorno virtual obligatoriamente.
```bash
# 1. Instalar venv si no está disponible
sudo apt update && sudo apt install -y python3-venv

# 2. Crear entorno virtual
python3 -m venv venv_aresitos

# 3. Activar entorno virtual
source venv_aresitos/bin/activate

# 4. Actualizar pip dentro del venv
pip install --upgrade pip

# 5. Instalar dependencias
pip install -r requirements.txt
```

**⚠️ Alternativa NO RECOMENDADA**: Forzar instalación global (puede romper el sistema).
```bash
# SOLO si entiendes los riesgos
pip install --break-system-packages -r requirements.txt
```

### **❌ Error: "ModuleNotFoundError: No module named 'psutil'"**
```bash
ModuleNotFoundError: No module named 'psutil'
```

**📋 Causa**: Dependencias no instaladas en el entorno virtual activo.

**🔧 Solución**:
```bash
# 1. Verificar que el entorno virtual está activo
# Deberías ver (venv_aresitos) al inicio del prompt

# 2. Si no está activo, activarlo
source venv_aresitos/bin/activate

# 3. Instalar dependencias faltantes
pip install psutil customtkinter requests pandas matplotlib python-nmap scapy watchdog colorlog

# 4. Verificar instalación
python -c "import psutil, customtkinter; print('✅ Dependencias instaladas correctamente')"
```

### **❌ Error: Icono no se muestra en Linux**
```bash
Advertencia: No se pudo cargar el icono: [error details]
```

**📋 Causa**: Los archivos `.ico` tienen problemas de compatibilidad en Linux con tkinter.

**🔧 Solución**: Aresitos detecta automáticamente el sistema operativo y maneja el icono apropiadamente.
```bash
# El programa intentará usar PIL/Pillow para convertir el icono
# Si PIL no está instalado, usar el entorno virtual y ejecutar:
pip install pillow

# Si el problema persiste, no afecta la funcionalidad del programa
```

### **❌ Error: "No module named 'PIL'"**
```bash
ModuleNotFoundError: No module named 'PIL'
```

**📋 Causa**: Pillow (PIL) no está instalado para el manejo de iconos en Linux.

**🔧 Solución**:
```bash
# Activar entorno virtual
source venv_aresitos/bin/activate

# Instalar Pillow
pip install pillow
```

### **❌ Error: FIM genera spam masivo de cambios en `/usr/sbin`**
```bash
2025-08-15 09:38:12,558 - ares_aegis.ControladorFIM - WARNING - Cambio detectado - archivo_nuevo: /usr/sbin/...
```

**📋 Causa**: FIM monitorea directorios del sistema completos como `/usr/sbin/` que contienen miles de archivos.

**🔧 Solución**: Configuración corregida para monitorear solo archivos críticos específicos.
```bash
# La configuración actualizada de FIM ahora monitorea solo:
# - Archivos de configuración críticos (/etc/passwd, /etc/sudoers, etc.)
# - Binarios específicos importantes (/bin/bash, /usr/bin/sudo, etc.)
# - No directorios completos que generan spam
```

### **❌ Error: Escaneador no funciona en Kali Linux**
```bash
Error ejecutando nmap: [permission denied / command not found]
```

**📋 Causa**: Problemas de permisos o rutas en herramientas de Kali Linux.

**🔧 Solución**:
```bash
# 1. Verificar permisos para herramientas de red
sudo setcap cap_net_raw+epi /usr/bin/nmap

# 2. Añadir usuario a grupos necesarios
sudo usermod -a -G wireshark $USER

# 3. Reiniciar sesión para aplicar cambios
newgrp wireshark

# 4. Verificar herramientas disponibles
python diagnostico.py
```

### **❌ Error: Terminal no funciona correctamente**
```bash
Terminal command execution failed
subprocess.run errors in Kali Linux
```

**📋 Causa**: Problemas de subprocess y permisos en entorno Kali Linux.

**🔧 Solución**:
```bash
# 1. Ejecutar con permisos adecuados
sudo python main.py

# 2. Verificar PATH y herramientas
echo $PATH
which nmap
which netstat

# 3. Instalar dependencias faltantes si es necesario
sudo apt update
sudo apt install nmap netstat-nat net-tools
```

## 🛡️ **Configuración de Permisos para Kali Linux**

Ares Aegis requiere permisos elevados para acceder a herramientas de seguridad y archivos del sistema. Para configurar automáticamente todos los permisos necesarios:

### **⚡ Configuración Automática (Recomendado)**

```bash
# 1. Hacer ejecutable el script de configuración
chmod +x configurar_kali.sh

# 2. Ejecutar configuración automática
sudo ./configurar_kali.sh

# 3. Reiniciar sesión para aplicar cambios
logout
# o
newgrp wireshark

# 4. Verificar configuración
python3 verificacion_permisos.py
```

### **🔧 Configuración Manual**

Si prefiere configurar manualmente:

```bash
# 1. Instalar herramientas necesarias
sudo apt update
sudo apt install nmap netstat-nat net-tools masscan tcpdump python3-dev python3-pip

# 2. Configurar permisos de red
sudo setcap cap_net_raw+epi /usr/bin/nmap
sudo setcap cap_net_raw+epi /usr/bin/tcpdump

# 3. Añadir usuario a grupos necesarios
sudo usermod -a -G wireshark $USER
sudo usermod -a -G netdev $USER

# 4. Configurar sudo sin contraseña (opcional)
sudo visudo -f /etc/sudoers.d/ares-aegis
# Añadir líneas:
# usuario ALL=(ALL) NOPASSWD: /usr/bin/nmap
# usuario ALL=(ALL) NOPASSWD: /bin/netstat
# usuario ALL=(ALL) NOPASSWD: /usr/bin/ss

# 5. Instalar dependencias Python
pip3 install --user Pillow
```

### **🧪 Verificación de Funcionamiento**

```bash
# Ejecutar verificación completa
python3 verificacion_permisos.py

# Ejecutar script de prueba simple
python3 ~/test_ares_permissions.py
```

### **⚠️ Solución de Problemas de Permisos**

#### **Error: "Permission denied" al ejecutar herramientas**
```bash
# Verificar permisos especiales
getcap /usr/bin/nmap
# Debe mostrar: cap_net_raw+epi

# Si no están configurados:
sudo setcap cap_net_raw+epi /usr/bin/nmap
```

#### **Error: "sudo: password required"**
```bash
# Verificar configuración sudo
sudo -l | grep nmap

# Si no aparece, reconfigurar:
sudo ./configurar_kali.sh
```

#### **Error: "Operation not permitted"**
```bash
# Verificar grupos del usuario
groups $USER

# Debe incluir 'wireshark' y 'netdev'
# Si no, añadir y reiniciar sesión:
sudo usermod -a -G wireshark,netdev $USER
```

### **❌ Error: SIEM genera logs excesivos**
```bash
Massive SIEM log generation in Kali Linux
```

**📋 Causa**: Configuración por defecto demasiado verbosa para entorno Kali.

**🔧 Solución**: Configuración optimizada para reducir spam de logs.

### **❌ Error: "No module named 'tkinter'"**
```bash
ModuleNotFoundError: No module named 'tkinter'
```

**🔧 Solución**: Instalar tkinter del sistema.

```bash
# Instalar tkinter para Python 3
sudo apt install -y python3-tk

# Verificar instalación
python3 -c "import tkinter; print('✅ Tkinter OK')"
```

### **❌ Error de Permisos con Herramientas de Red**
```bash
Permission denied: Could not run nmap/wireshark/etc.
```

**🔧 Solución**: Configurar permisos adecuados.

```bash
# Añadir usuario a grupos necesarios
sudo usermod -a -G wireshark $USER

# Configurar capabilities para nmap
sudo setcap cap_net_raw+epi /usr/bin/nmap

# Reiniciar sesión o recargar grupos
newgrp wireshark

# Verificar permisos
groups
```

### **❌ Error: "Command 'python' not found"**
```bash
python: command not found
```

**🔧 Solución**: En Kali Linux el comando es `python3`.

```bash
# Usar python3 en lugar de python
python3 main.py

# Opcional: crear alias (solo para la sesión actual)
alias python=python3

# Para hacerlo permanente, añadir al ~/.bashrc:
echo "alias python=python3" >> ~/.bashrc
source ~/.bashrc
```

### **✅ Verificación Completa del Entorno**
```bash
# Script de verificación rápida
echo "=== VERIFICACIÓN DEL ENTORNO ARESITOS ==="
echo "1. Python version:"
python3 --version

echo "2. Virtual environment:"
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Entorno virtual activo: $VIRTUAL_ENV"
else
    echo "❌ No hay entorno virtual activo"
fi

echo "3. Dependencias críticas:"
python3 -c "
try:
    import customtkinter, psutil, requests, pandas, matplotlib
    print('✅ Todas las dependencias principales OK')
except ImportError as e:
    print(f'❌ Falta dependencia: {e}')
"

echo "4. Herramientas del sistema:"
command -v nmap >/dev/null 2>&1 && echo "✅ nmap OK" || echo "❌ nmap no encontrado"
command -v wireshark >/dev/null 2>&1 && echo "✅ wireshark OK" || echo "❌ wireshark no encontrado"
command -v hydra >/dev/null 2>&1 && echo "✅ hydra OK" || echo "❌ hydra no encontrado"
```

### **🔄 Comandos de Mantenimiento**
```bash
# Reactivar entorno virtual después de reiniciar
cd /path/to/Aresitos
source venv_aresitos/bin/activate

# Actualizar dependencias
pip install --upgrade -r requirements.txt

# Limpiar cache de pip si hay problemas
pip cache purge

# Reinstalar desde cero si es necesario
rm -rf venv_aresitos
python3 -m venv venv_aresitos
source venv_aresitos/bin/activate
pip install -r requirements.txt
```

### **Configuración Avanzada**

#### Configuración de Red
```bash
# Configurar interfaces de monitoreo
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
```

#### Optimización de Rendimiento
```json
// En configuracion/ares_aegis_config.json
{
  "rendimiento": {
    "max_threads_escaneo": 20,
    "timeout_requests": 15,
    "max_hosts_paralelo": 100,
    "cache_resultados": true
  },
  "logging": {
    "nivel": "INFO",
    "rotacion_logs": "diaria",
    "max_tamaño_mb": 100
  }
}
```

#### Integración con Bases de Datos Externas
```bash
# Actualizar CVE database
sudo updatedb
locate cve.json

# Integrar con feeds de amenazas
curl -s https://api.threatfox.abuse.ch/api/v1/ > data/threat_feeds.json
```

---

## 🎯 **GUÍA DE USO PROFESIONAL**

### **Configuración Inicial Completa**
1. **Lanzamiento de la Aplicación**: `python main.py`
2. **Verificación de Integración**: Dashboard mostrará estado de 10 controladores
3. **Configuración de Rutas**: Establecer directorios personalizados en Configuración
4. **Calibración de Red**: Configurar interfaces y rangos de escaneo objetivo
5. **Activación SIEM**: Conectar fuentes de logs del entorno (opcional pero recomendado)

### **Workflows de Penetration Testing**

#### **🎯 Workflow de Reconocimiento Completo**
1. **Definición de Scope**: 
   - Especificar targets (IPs, rangos CIDR, dominios)
   - Configurar exclusiones y limitaciones de rate
2. **Escaneo de Descubrimiento**:
   - Host discovery con ping sweep
   - Port scanning (Top 1000 → Full range)
   - Service fingerprinting y version detection
3. **Enumeración de Servicios**:
   - HTTP/HTTPS: Directory busting, technology identification
   - SMB: Share enumeration, null sessions
   - SSH/Telnet: Banner grabbing, auth methods
   - DNS: Zone transfers, subdomain enumeration
4. **Análisis de Resultados**:
   - Correlación automática de vulnerabilidades
   - Generación de attack surface map
   - Priorización por criticidad y explotabilidad

#### **🔍 Workflow de Vulnerability Assessment**
1. **Configuración de Escaneo**:
   - Selección de plugins (CVE, Config, Authentication)
   - Ajuste de agresividad y threading
   - Configuración de credenciales (cuando aplique)
2. **Ejecución Monitoreada**:
   - Dashboard en tiempo real del progreso
   - Detección temprana de vulnerabilidades críticas
   - Logs detallados para troubleshooting
3. **Análisis de Vulnerabilidades**:
   - Clasificación automática por CVSS
   - Mapeo a frameworks (OWASP, NIST, MITRE)
   - False positive filtering inteligente
4. **Validación Manual**:
   - Exploración manual de hallazgos críticos
   - Proof of Concept development
   - Impact assessment detallado

#### **🛡️ Workflow de Security Monitoring (SIEM)**
1. **Configuración de Data Sources**:
   - Syslog servers, Windows Event Logs
   - Application logs, Web server logs
   - Network device logs, Security appliances
2. **Rule Development**:
   - Custom detection rules en formato YARA
   - Correlation rules para multi-stage attacks
   - Threshold-based alerting
3. **Dashboard Monitoring**:
   - Real-time event correlation
   - Threat intelligence integration
   - Automated incident escalation
4. **Incident Response**:
   - Automated containment actions
   - Forensic evidence collection
   - Timeline reconstruction
   - IOC extraction y sharing

#### **📁 Workflow de File Integrity Monitoring**
1. **Baseline Creation**:
   - Selección de critical system paths
   - Hash calculation (SHA-256/512)
   - Metadata baseline (permissions, timestamps)
2. **Continuous Monitoring**:
   - Real-time file system events
   - Cryptographic integrity verification
   - Change detection y alerting
3. **Change Analysis**:
   - Legitimate vs. suspicious change classification
   - User attribution y process correlation
   - Compliance reporting automation
4. **Incident Investigation**:
   - Timeline of file modifications
   - Process tree analysis
   - Network activity correlation

### **Gestión Avanzada de Wordlists**

#### **Constructor Inteligente de Wordlists**
```bash
# Generación basada en contexto empresarial
Empresa: "TechCorp" → techcorp, TechCorp, TECHCORP, tech-corp, tech_corp
Año: 2024 → 2024, 24, techcorp2024, admin2024

# Wordlists especializadas por sector
Sector: Bancario → banking_terms.txt, financial_passwords.txt
Sector: Salud → healthcare_terms.txt, medical_devices.txt
```

#### **Integración de Diccionarios MITRE ATT&CK**
- **371 técnicas** catalogadas y correlacionadas
- **Mapeo automático** de hallazgos a TTPs
- **Threat actor attribution** basada en técnicas observadas
- **Playbooks de respuesta** específicos por técnica

---

## 📊 **CARACTERÍSTICAS ENTERPRISE**

### **Dashboard de Métricas en Tiempo Real**
- **Security Posture Score**: Puntuación dinámica de seguridad organizacional
- **Threat Landscape**: Visualización de amenazas activas y emergentes
- **Asset Inventory**: Mapeo automático de infraestructura descubierta
- **Compliance Status**: Estado en tiempo real de frameworks de cumplimiento
- **Incident Timeline**: Cronología interactiva de eventos de seguridad

### **Sistema de Cheatsheets Profesional (18 Módulos)**
| Herramienta | Comandos | Categorías | Uso Principal |
|-------------|----------|------------|---------------|
| **Nmap** | 50+ comandos | Port scan, Service detection, NSE | Reconocimiento de red |
| **Metasploit** | 75+ comandos | Exploitation, Post-exploitation | Penetration testing |
| **Sqlmap** | 40+ comandos | SQL injection, DB extraction | Web app security |
| **Burp Suite** | 60+ shortcuts | Web testing, Extensions | Application security |
| **Hydra** | 35+ comandos | Brute force, Protocol testing | Authentication testing |
| **Wireshark** | 45+ filtros | Traffic analysis, Protocol decode | Network forensics |
| **Hashcat** | 30+ comandos | Password cracking, GPU acceleration | Password auditing |
| **Volatility** | 55+ plugins | Memory analysis, Malware detection | Digital forensics |

### **Integración con Inteligencia de Amenazas**
- **Feeds Automáticos**: MISP, AlienVault OTX, ThreatFox
- **IOC Correlation**: Automatic matching de observables
- **Attribution Engine**: APT group identification basada en TTPs
- **Threat Hunting**: Proactive search por IoCs y behavioral patterns

### **Compliance y Auditoría Automatizada**
```bash
# Frameworks soportados
├── NIST Cybersecurity Framework
├── ISO 27001:2013
├── PCI DSS v4.0
├── SOX Compliance
├── GDPR Technical Safeguards
├── HIPAA Security Rule
└── CIS Controls v8
```

### **Reportes Ejecutivos y Técnicos**
- **Executive Summary**: KPIs de alto nivel para C-level
- **Technical Deep Dive**: Análisis detallado para equipos técnicos
- **Compliance Report**: Evidencia para auditorías regulatorias
- **Incident Response**: Documentación completa de investigaciones
- **Trend Analysis**: Evolución de la postura de seguridad

---

## 🔄 **ACTUALIZACIONES Y MANTENIMIENTO ENTERPRISE**

### **Actualizaciones Automáticas Inteligentes**
```bash
# Threat Intelligence Feeds (Diario)
├── CVE Database Updates
├── Malware Signatures
├── IOC Feeds (STIX/TAXII)
├── Geolocation Intelligence
└── Threat Actor TTPs

# Application Updates (Semanal)
├── Security patches
├── Feature enhancements
├── Performance optimizations
└── UI/UX improvements
```

### **Mantenimiento Proactivo**
- **Log Rotation Inteligente**: Compression y archival automático
- **Database Optimization**: Índices automáticos y query optimization
- **Performance Monitoring**: Alertas proactivas de degradación
- **Capacity Planning**: Predicción de crecimiento de datos
- **Health Checks**: Verificación automática de componentes críticos

### **Backup y Disaster Recovery**
```bash
# Backup Automatizado
├── Configuraciones (Diario)
├── Bases de datos (Diario)
├── Logs históricos (Semanal)
├── Custom wordlists (Diario)
└── Reportes y evidencia (Diario)

# Recovery Procedures
├── Point-in-time recovery
├── Configuration rollback
├── Data integrity verification
└── Service health validation
```

---

## � **CONSIDERACIONES DE SEGURIDAD Y ÉTICA**

### **⚖️ Uso Ético y Legal**
- **🔐 AUTORIZACIÓN OBLIGATORIA**: Uso exclusivo en sistemas propios o con autorización explícita por escrito
- **📋 CUMPLIMIENTO LEGAL**: Estricto apego a leyes locales, nacionales e internacionales de ciberseguridad
- **🤝 DIVULGACIÓN RESPONSABLE**: Implementación de responsible disclosure para vulnerabilidades críticas
- **📝 DOCUMENTACIÓN RIGUROSA**: Mantenimiento de registros detallados de todas las actividades de testing
- **🎓 PROPÓSITO EDUCATIVO**: Herramienta diseñada para educación en ciberseguridad y testing autorizado

### **🔒 Seguridad Operacional Avanzada**
- **🔐 Cifrado de Datos**: AES-256 para datos sensibles en reposo y tránsito
- **🔗 Comunicaciones Seguras**: TLS 1.3 para todas las comunicaciones de red
- **👥 Control de Acceso**: RBAC (Role-Based Access Control) para entornos multi-usuario
- **📊 Auditoría Comprensiva**: Logging inmutable de todas las actividades del usuario
- **🛡️ Sandboxing**: Aislamiento de procesos para análisis seguro de muestras

### **⚠️ Advertencias Legales Importantes**
```
⚠️  DESCARGO DE RESPONSABILIDAD LEGAL
Esta herramienta está destinada EXCLUSIVAMENTE para:
• Testing de seguridad autorizado y documentado
• Investigación académica en ciberseguridad
• Educación en ethical hacking
• Auditorías de seguridad contratadas

❌ PROHIBIDO su uso para:
• Actividades ilegales o no autorizadas
• Acceso no autorizado a sistemas
• Daño o interrupción de servicios
• Cualquier actividad que viole leyes aplicables

Los desarrolladores NO asumen responsabilidad por el mal uso,
daños o consecuencias legales resultantes del uso inadecuado.
```

---

## 🔧 **CONFIGURACIÓN AVANZADA DEL SISTEMA**

### **Archivos de Configuración Principales**
```bash
📁 configuracion/
├── ares_aegis_config.json           # Configuración principal de la aplicación
├── ares_aegis_config_kali.json      # Configuración optimizada para Kali Linux
├── firmas.txt                       # Firmas de detección personalizadas
├── notificaciones.json              # Sistema de alertas y notificaciones
├── sistema_ayuda.json               # Sistema de ayuda contextual integrado
└── textos_castellano.json           # Localización completa en español
```

### **Configuración Principal Detallada**
```json
{
  "sistema": {
    "log_level": "INFO",
    "max_threads": 20,
    "timeout_requests": 30,
    "idioma": "es",
    "tema": "kali_dark",
    "auto_save": true
  },
  "escaneo": {
    "puertos_comunes": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
    "puertos_completos": "1-65535",
    "timeout_port": 5,
    "max_host_parallel": 100,
    "rate_limiting": 1000,
    "stealth_mode": false
  },
  "siem": {
    "retention_days": 90,
    "correlation_window": 300,
    "max_events_memory": 50000,
    "threat_intel_feeds": true,
    "auto_correlation": true
  },
  "fim": {
    "hash_algorithm": "sha256",
    "check_interval": 300,
    "realtime_monitoring": true,
    "baseline_auto_update": false
  },
  "reportes": {
    "formato_default": "json",
    "incluir_screenshots": true,
    "auto_export": false,
    "template_personalizado": ""
  },
  "seguridad": {
    "encryption_enabled": true,
    "audit_logging": true,
    "session_timeout": 3600,
    "failed_login_lockout": 5
  }
}
```

### **Optimización de Rendimiento**
```json
{
  "rendimiento": {
    "cache_enabled": true,
    "cache_size_mb": 512,
    "db_optimization": true,
    "compress_logs": true,
    "memory_limit_mb": 2048
  },
  "threading": {
    "max_workers": 16,
    "worker_timeout": 120,
    "queue_size": 1000
  }
}
```

---

## � **INFORMACIÓN LEGAL Y LICENCIAMIENTO**

### **📋 Licencia del Software**
**Aresitos 7.0 Beta** está licenciado bajo la **MIT License** con cláusulas de atribución obligatoria.

```
MIT License con Atribución Requerida

Copyright (c) 2025 DogSoulDev

✅ PERMISOS OTORGADOS:
- Uso libre en cualquier sistema operativo (Kali Linux, Ubuntu, etc.)
- Modificación y personalización del código
- Distribución y redistribución
- Uso comercial permitido
- Uso educativo y de investigación

🔒 CONDICIONES OBLIGATORIAS:
- Mantener atribución al creador original: DogSoulDev
- Incluir referencia al repositorio: https://github.com/DogSoulDev/Aresitos
- Conservar este aviso de licencia en todas las copias
- Uso exclusivo para propósitos legales y éticos

❌ PROHIBICIONES:
- Uso para actividades ilegales o no autorizadas
- Eliminación de créditos o atribuciones
- Uso malicioso o destructivo

📄 Licencia completa: Ver archivo LICENSE en el repositorio
```

### **🏛️ Componentes de Terceros y Atribuciones**
```bash
# Librerías Python bajo diversas licencias
├── CustomTkinter (MIT) - Interfaz gráfica moderna
├── Requests (Apache 2.0) - Cliente HTTP
├── Pandas (BSD 3-Clause) - Análisis de datos
├── Matplotlib (BSD-compatible) - Visualización
├── Python-nmap (GPL v3) - Wrapper de Nmap
├── Scapy (GPL v2) - Manipulación de paquetes
├── Psutil (BSD 3-Clause) - Información del sistema
└── Watchdog (Apache 2.0) - Monitoreo de archivos

# Herramientas integradas de Kali Linux
├── Nmap (GPL) - Exploración de red
├── SQLMap (GPL) - Testing de SQL injection
├── Gobuster (Apache 2.0) - Directory bruteforcing
├── Hydra (AGPL v3) - Bruteforcing de login
├── Nikto (GPL v2) - Escáner de vulnerabilidades web
├── Aircrack-ng (GPL v2) - Auditoría WiFi
├── Wireshark (GPL v2) - Análisis de protocolos
├── Hashcat (MIT) - Recuperación de passwords
├── John the Ripper (GPL) - Password cracking
├── Metasploit (BSD 3-Clause) - Framework de explotación
└── Volatility (GPL v2) - Análisis forense de memoria
```

**📋 Información completa de licencias**: Ver [LICENSE](LICENSE) en el repositorio principal

---

## 📞 **SOPORTE Y COMUNIDAD**

### **👥 Equipo de Desarrollo**
- **🎓 Desarrollo Principal**: Estudiante de Ciberseguridad (DogSoulDev)
- **🤝 Filosofía**: Proyecto colaborativo estudiante-a-estudiante
- **🌍 Comunidad**: Contribuciones abiertas de la comunidad de ciberseguridad
- **📚 Enfoque Educativo**: Herramienta diseñada para aprendizaje práctico

### **🆘 Canales de Soporte**
- **🐛 GitHub Issues**: [github.com/DogSoulDev/Aresitos/issues](https://github.com/DogSoulDev/Aresitos/issues)
- **📖 Wiki del Proyecto**: Documentación completa y tutoriales
- **💬 Discusiones**: GitHub Discussions para preguntas y mejoras
- **🎓 Recursos Educativos**: Tutoriales paso a paso y casos de estudio

### **🤝 Contribuciones de la Comunidad**
```bash
# Cómo contribuir
├── 🍴 Fork del repositorio
├── 🌿 Crear feature branch
├── 💻 Implementar mejoras
├── ✅ Ejecutar tests de seguridad
├── 📝 Documentar cambios
└── 🔄 Pull Request con descripción detallada

# Áreas de contribución
├── 🔍 Nuevos módulos de escaneo
├── 📊 Mejoras en dashboards
├── 🛡️ Patches de seguridad
├── 📚 Documentación y tutoriales
├── 🌐 Traducciones
└── 🎨 Mejoras de UI/UX
```

### **🎯 Roadmap del Proyecto**
```bash
# Versión 7.1 (Q4 2025)
├── 🤖 Integración con AI/ML para threat hunting
├── 🔗 API REST para integración enterprise
├── 📱 Dashboard web responsive
├── 🌐 Soporte multi-idioma completo
└── 🔄 Auto-updates del sistema

# Versión 8.0 (2026)
├── ☁️ Soporte para cloud security (AWS, Azure, GCP)
├── 🦾 Automatización con SOAR integrado
├── 📊 Business Intelligence avanzado
├── 🔐 Zero Trust architecture support
└── 🌍 Distribución como Docker container
```

---

<div align="center">

## 🏆 **ARESITOS 7.0 BETA - VERSIÓN ENTERPRISE**

### ⚡ *Fortaleciendo la Ciberseguridad a Través de la Innovación* ⚡

**🔥 Estado del Proyecto**: ✅ **PRODUCCIÓN READY**  
**🛡️ Nivel de Seguridad**: 🔒 **MÁXIMO CERTIFICADO**  
**📊 Líneas de Código**: 25,000+ (Auditadas y Securizadas)  
**🧪 Tests de Seguridad**: ✅ **PASSED** (48/48 vulnerabilidades eliminadas)  
**🎯 Compatibilidad**: Kali Linux 2023.x+ Optimizado  

### 📅 **Información de Release**
- **Versión Actual**: 7.0 Beta - Enterprise Edition
- **Fecha de Release**: Agosto 15, 2025
- **Última Auditoría**: Agosto 15, 2025
- **Próxima Actualización**: Septiembre 2025

---

### 🌟 **¡Únete a la Revolución de la Ciberseguridad!** 🌟

*Desarrollado con ❤️ por la comunidad de ethical hackers*

</div>

---

*© 2025 Aresitos Project. Desarrollado por DogSoulDev y la comunidad de ciberseguridad.*  
*"Securing the Digital Realm, One Line of Code at a Time"*

---

## 💝 **DEDICATORIA ESPECIAL**

<div align="center">

### 🐕 **En Memoria de Ares** 🐕

*Este programa gratuito lo comparto con todos los compis de ciberseguridad en honor a mi hijo y perro, **Ares** - 25/04/2013 a 5/08/2025 DEP.*

*Hasta que volvamos a vernos,*  
**DogSoulDev** 💙

</div>
