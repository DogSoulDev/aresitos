# ![Aresitos](aresitos/recursos/Aresitos.ico) ARESITOS v2.0
**Suite de Ciberseguridad para Kali Linux con Herramientas 2025**

ARESITOS es una suite completa de herramientas de ciberseguridad diseñada específicamente para Kali Linux, que integra las herramientas más modernas de pentesting 2025, escaneado de vulnerabilidades, monitoreo de integridad de archivos (FIM) y sistema SIEM en una interfaz unificada.

## Autor
- **Desarrollador**: DogSoulDev  
- **Email**: dogsouldev@protonmail.com  
- **Repositorio**: https://github.com/DogSoulDev/Aresitos

## Características Principales

### 🚀 Escaneador de Vulnerabilidades v2.0 + Kali 2025
**Herramientas Clásicas:**
- Integración nativa con nmap, nikto, gobuster, nuclei
- Detección real de malware con ClamAV, chkrootkit y rkhunter
- Base de datos CVE integrada con scoring CVSS

**Herramientas Kali 2025:**
- **rustscan**: Escaneo de puertos ultrarrápido en Rust
- **feroxbuster**: Fuzzing de directorios web avanzado
- **nuclei**: Scanner de vulnerabilidades con templates actualizados
- **subfinder**: Enumeración de subdominios masiva
- **httpx**: Sondeo HTTP con detección de tecnologías
- **katana**: Web crawling y spider avanzado

### 🛡️ Sistema FIM (File Integrity Monitoring) + Kali 2025
**Capacidades Base:**
- Monitoreo en tiempo real de archivos críticos del sistema
- Detección de cambios no autorizados en archivos sensibles
- Alertas automáticas ante modificaciones sospechosas

**Herramientas Kali 2025:**
- **YARA**: Detección avanzada de patrones de malware
- **ExifTool**: Análisis forense de metadatos
- **Volatility3**: Análisis de memoria RAM y dumps
- **Tiger**: Auditoría de seguridad del sistema
- **AIDE**: Verificación de integridad mejorada
- **Samhain**: HIDS (Host Intrusion Detection System)

### 📊 Sistema SIEM Integrado + Kali 2025
**Análisis Tradicional:**
- Análisis de logs del sistema Kali Linux
- Correlación de eventos de seguridad
- Detección de patrones de ataque

**Herramientas Kali 2025:**
- **OSQuery**: Monitoreo de endpoints con consultas SQL
- **Filebeat**: Envío centralizado de logs
- **Suricata**: Detección de intrusiones de red
- **Zeek**: Monitoreo de seguridad de red
- **Wazuh**: Plataforma de monitoreo unificada
- **tcpdump**: Captura avanzada de tráfico de red

### 🔒 Sistema de Cuarentena + Análisis Forense Kali 2025
**Funcionalidades Base:**
- Aislamiento seguro de archivos maliciosos
- Gestión de amenazas detectadas
- Restauración controlada de archivos

**Análisis Forense Kali 2025:**
- **YARA**: Análisis de malware con reglas especializadas
- **Volatility3**: Análisis forense de memoria
- **Binwalk**: Análisis de firmware y archivos binarios
- **Foremost**: Recuperación de archivos eliminados
- **chkrootkit/rkhunter**: Detección de rootkits avanzada
- **strings/hexdump**: Análisis de contenido binario

## Estructura del Proyecto

```
aresitos/
├── main.py                           # Punto de entrada principal
├── configurar_kali.sh                # Script de instalación
├── requirements.txt                  # Dependencias Python
├── pyproject.toml                   # Configuración del proyecto
├── verificacion_seguridad.py        # Verificador de sistema
├── verificador_herramientas_windows.py # Verificador de herramientas
├── aresitos/                        # Código fuente principal
│   ├── __init__.py
│   ├── controlador/                 # Lógica de control (MVC)
│   │   ├── controlador_escaneador_cuarentena.py
│   │   ├── controlador_escaneo.py
│   │   ├── controlador_fim.py
│   │   ├── controlador_monitoreo.py
│   │   ├── controlador_principal_nuevo.py
│   │   ├── controlador_reportes.py
│   │   ├── controlador_siem_nuevo.py
│   │   └── gestor_componentes.py
│   ├── controladores/               # Controladores adicionales
│   │   ├── controlador_actualizacion.py
│   │   ├── controlador_auditoria.py
│   │   ├── controlador_dashboard.py
│   │   ├── controlador_herramientas.py
│   │   ├── controlador_utilidades.py
│   │   ├── controlador_wordlists.py
│   │   └── gestor_configuracion.py
│   ├── modelo/                      # Modelos de datos y lógica
│   │   ├── escaneador_avanzado.py
│   │   ├── modelo_escaneador_avanzado.py
│   │   ├── modelo_escaneador_base.py
│   │   ├── modelo_escaneador_kali2025.py    # 🆕 Herramientas Kali 2025
│   │   ├── modelo_fim.py
│   │   ├── modelo_fim_kali2025.py           # 🆕 FIM + Kali 2025
│   │   ├── modelo_monitor.py
│   │   ├── modelo_principal.py
│   │   ├── modelo_reportes.py
│   │   ├── modelo_siem.py
│   │   ├── modelo_siem_kali2025.py          # 🆕 SIEM + Kali 2025
│   │   ├── modelo_cuarentena_kali2025.py    # 🆕 Cuarentena + Forense
│   │   └── monitor_kali_limpio.py
│   ├── vista/                       # Interfaces gráficas
│   │   ├── vista_herramientas_kali.py       # Vista principal herramientas
│   │   └── vista_herramientas_kali_def.py   # 🆕 Definiciones Kali 2025
│   └── utils/                       # Utilidades y herramientas
├── configuracion/                   # Archivos de configuración
│   ├── ares_aegis_config_kali.json
│   ├── aresitos_config_kali.json
│   ├── aresitos_config.json
│   ├── textos_castellano_corregido.json
│   └── MAPA_NAVEGACION_ESCANEADOR.md
├── data/                           # Bases de datos y wordlists
│   ├── fim_database.json
│   ├── vulnerability_database.json
│   ├── cheatsheets/
│   ├── diccionarios/
│   └── wordlists/
├── logs/                           # Archivos de registro
├── recursos/                       # Recursos estáticos
│   └── cheatsheets/
└── documentacion/                  # Documentación del proyecto
    ├── AUDITORIA_SEGURIDAD_LOGIN.md
    ├── auditoria_seguridad.md
    ├── seguridad_corregida.md
    ├── auditoria/
    ├── correcciones/
    ├── desarrollo/
    └── guias/
```

## Requisitos del Sistema

### Sistema Operativo
- **Kali Linux** (recomendado)
- Distribuciones Linux compatibles con herramientas de pentesting

### Dependencias
- Python 3.8 o superior
- **Herramientas Clásicas**: nmap, nikto, gobuster, nuclei, clamav
- **Herramientas Kali 2025**: rustscan, feroxbuster, subfinder, httpx, katana, yara, volatility3, exiftool, osquery, filebeat, suricata, binwalk, foremost
- Interfaz gráfica X11 (para GUI)

### Dependencias Python
```
psutil>=5.9.0          # Monitoreo del sistema
tkinter                # Interfaz gráfica
json                   # Configuración
subprocess             # Ejecución de herramientas
logging                # Sistema de logs
pathlib                # Manejo de rutas
datetime               # Timestamps
```

## Instalación

### Instalación Automática
```bash
# Clonar el repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Ejecutar script de instalación
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh
```

### Instalación Manual
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias del sistema (herramientas clásicas)
sudo apt install -y python3 python3-pip python3-tk
sudo apt install -y nmap nikto gobuster nuclei clamav clamav-daemon
sudo apt install -y chkrootkit rkhunter lynis

# Instalar herramientas Kali 2025
sudo apt install -y rustscan feroxbuster subfinder httpx katana
sudo apt install -y yara volatility3 exiftool osquery
sudo apt install -y filebeat suricata zeek binwalk foremost
sudo apt install -y chkrootkit rkhunter aide samhain tiger

# Instalar dependencias Python
pip3 install -r requirements.txt

# Configurar permisos
sudo chmod +x main.py
```

## Uso

### Ejecución Básica
```bash
# Ejecutar ARESITOS
python3 main.py

# Modo desarrollo (opcional)
python3 main.py --dev
```

### Login y Autenticación
1. Ejecutar main.py
2. Ingresar contraseña root del sistema
3. El sistema verificará automáticamente la compatibilidad con Kali Linux

### Módulos Principales

#### 🚀 Escaneador de Vulnerabilidades
1. Acceder al módulo "Escaneador"
2. Seleccionar herramientas (clásicas o Kali 2025)
3. Configurar objetivo (IP, rango de red, archivo de hosts)
4. Elegir tipo de escaneo (rápido, completo, personalizado)
5. Revisar reportes generados en data/reportes/

**Herramientas disponibles:**
- **Escaneo de puertos**: nmap, rustscan
- **Fuzzing web**: gobuster, feroxbuster
- **Vulnerabilidades**: nuclei (actualizado), nikto
- **Reconocimiento**: subfinder, httpx, katana

#### 🛡️ Monitoreo FIM
1. Acceder al módulo "FIM"
2. Configurar rutas críticas a monitorear
3. Seleccionar herramientas de análisis (YARA, ExifTool, Tiger)
4. Iniciar monitoreo en tiempo real
5. Revisar alertas en el dashboard

**Capacidades avanzadas:**
- Detección de malware con YARA
- Análisis forense con Volatility3
- Auditoría con Tiger y AIDE

#### 📊 Sistema SIEM
1. Acceder al módulo "SIEM"
2. Configurar fuentes de logs (tradicionales + OSQuery)
3. Establecer reglas de correlación
4. Iniciar monitores (Filebeat, Suricata, Zeek)
5. Revisar eventos de seguridad

**Monitoreo avanzado:**
- Endpoints con OSQuery (consultas SQL)
- Red con Suricata y Zeek
- Logs centralizados con Filebeat

#### 🔒 Sistema de Cuarentena y Análisis Forense
1. Acceder al módulo "Cuarentena"
2. Seleccionar archivos para análisis
3. Ejecutar análisis completo (YARA + Binwalk + Volatility3)
4. Revisar detección de rootkits (chkrootkit + rkhunter)
5. Gestionar archivos en cuarentena

**Análisis forense:**
- Análisis de malware especializado
- Recuperación de archivos con Foremost
- Análisis de memoria con Volatility3

## Configuración

### Archivos de Configuración
- `configuracion/aresitos_config.json`: Configuración principal
- `configuracion/aresitos_config_kali.json`: Configuración específica de Kali
- `configuracion/ares_aegis_config_kali.json`: Configuración Ares Aegis
- `configuracion/textos_castellano_corregido.json`: Textos de la interfaz

### Logs del Sistema
- `logs/aresitos.log`: Log principal del sistema
- `logs/aresitos_errors.log`: Log de errores
- `logs/verificacion_permisos.log`: Log de verificación de permisos

### Bases de Datos
- `data/fim_database.json`: Base de datos FIM
- `data/vulnerability_database.json`: Base de datos de vulnerabilidades
- `/var/lib/aresitos/`: Bases de datos Kali 2025 (SQLite)

## Verificación del Sistema

```bash
# Verificar instalación y configuración
python3 verificacion_seguridad.py

# Verificar herramientas disponibles
python3 verificador_herramientas_windows.py

# Los scripts verificarán:
# - Estructura de archivos del proyecto
# - Herramientas de Kali Linux disponibles (clásicas + 2025)
# - Permisos y configuraciones
# - Integridad del sistema MVC
# - Disponibilidad de herramientas modernas (rustscan, feroxbuster, etc.)
```

## Seguridad

ARESITOS implementa múltiples capas de seguridad:

- **Gestión segura de permisos**: Control de operaciones privilegiadas
- **Validación de entrada**: Sanitización de todos los inputs del usuario
- **Ejecución segura**: Prevención de inyección de comandos
- **Logging seguro**: Ocultación automática de credenciales en logs
- **Cuarentena de amenazas**: Aislamiento seguro de archivos maliciosos
- **Análisis forense**: Herramientas especializadas para investigación
- **Detección avanzada**: YARA, Volatility3 y herramientas modernas
- **Monitoreo en tiempo real**: SIEM con OSQuery y Suricata

## Soporte y Documentación

### Documentación
- Manual completo: `documentacion/guias/GUIA_COMPLETA.md`
- Auditorías de seguridad: `documentacion/auditoria/`
- Documentación técnica: `documentacion/desarrollo/`

### Reportes de Problemas
- GitHub Issues: https://github.com/DogSoulDev/Aresitos/issues

### Contribuciones
Las contribuciones son bienvenidas. Por favor, seguir las guías de contribución del proyecto.

## Licencia

MIT License - Ver archivo LICENSE para detalles completos.

## Versión

**ARESITOS v2.0** - Suite de Ciberseguridad Profesional para Kali Linux  
**Integración Kali 2025**: Herramientas modernas de pentesting  
**Fecha de lanzamiento**: Agosto 2025  
**Estado**: Producción estable

### Novedades v2.0 + Kali 2025
- ✅ **50+ herramientas modernas** integradas
- ✅ **Análisis forense avanzado** con Volatility3
- ✅ **SIEM mejorado** con OSQuery y Suricata  
- ✅ **Detección de malware** con YARA especializado
- ✅ **Escaneado ultrarrápido** con rustscan
- ✅ **Arquitectura MVC** mantenida y extendida
- ✅ **Compatibilidad total** con herramientas clásicas

---
En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos,
DogSoulDev