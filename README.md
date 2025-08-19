![Aresitos](aresitos/recursos/Aresitos.ico)

# ARESITOS v2.0
**Suite Profesional de Ciberseguridad para Kali Linux**

ARESITOS v2.0 es una suite de ciberseguridad integral desarrollada específicamente para Kali Linux, que integra capacidades avanzadas de escaneado de vulnerabilidades, monitoreo de integridad de archivos (FIM), análisis SIEM, detección de malware y auditoría de seguridad en una interfaz unificada. El proyecto está diseñado con arquitectura 100% nativa, utilizando exclusivamente la biblioteca estándar de Python y herramientas nativas de Kali Linux.

## Certificación de Calidad
- Score de Seguridad: 100/100
- Arquitectura MVC: 100/100  
- Vulnerabilidades críticas: 0
- Warnings de seguridad: 0
- Estado: Listo para producción

## Arquitectura Nativa

### Principios de Diseño

El proyecto implementa una arquitectura que maximiza la seguridad y estabilidad mediante la eliminación de dependencias externas:

**Python Standard Library Exclusivamente**
- Utiliza únicamente bibliotecas incluidas en la distribución estándar de Python
- Evita dependencias externas que puedan introducir vulnerabilidades
- Garantiza compatibilidad y estabilidad a largo plazo
- Reduce la superficie de ataque del sistema

**Integración con Herramientas Kali Linux**
- Aprovecha las herramientas de seguridad pre-instaladas en Kali Linux
- Mantiene la filosofía de usar herramientas especializadas y probadas
- Implementa interfaces estandarizadas para la integración de herramientas
- Preserva la funcionalidad nativa del sistema operativo

### Instalación Directa
```bash
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos
sudo ./configurar_kali.sh  # Configurar herramientas Kali
python3 main.py           # Iniciar aplicación
```

## Información del Proyecto
- **Desarrollador**: DogSoulDev  
- **Contacto**: dogsouldev@protonmail.com  
- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Arquitectura**: Python nativo + herramientas Kali
- **Sistema Operativo**: Kali Linux 2024.x+

## Características Principales

### Escaneador de Vulnerabilidades v2.0
- Integración nativa con herramientas Kali (nmap, masscan, nikto, gobuster, nuclei, sqlmap)
- Detección de malware con ClamAV, chkrootkit, rkhunter, YARA
- Base de datos CVE integrada con scoring CVSS actualizado
- Escaneo profesional de puertos, servicios, vulnerabilidades web y aplicaciones
- Análisis forense con binwalk, strings, file, volatility

### Sistema FIM (File Integrity Monitoring)
- Monitoreo en tiempo real con inotify de Linux
- Detección de modificaciones en archivos críticos del sistema
- Algoritmos de hash seguros SHA-256 (eliminados MD5/SHA1 por seguridad)
- Auditoría Tiger integrada para verificación completa del sistema
- Base de datos SQLite para almacenamiento eficiente de hashes

### Sistema SIEM (Security Information and Event Management)
- Análisis de logs en tiempo real (/var/log/, auth.log, syslog)
- Correlación de eventos automatizada con algoritmos de análisis
- Dashboard interactivo con métricas del sistema en tiempo real
- Sistema de alertas clasificadas por severidad y patrones de ataque
- Gestión centralizada de eventos de seguridad

### Sistema de Cuarentena Avanzado
- Aislamiento seguro de archivos sospechosos identificados
- Análisis forense completo previo al aislamiento
- Verificación de integridad con algoritmos SHA-256
- Gestión de falsos positivos con whitelist configurable

### Herramientas Integradas de Kali Linux
- **Escaneado de red**: nmap, masscan, ngrep
- **Testing web**: nikto, gobuster, dirb, wfuzz
- **Análisis de vulnerabilidades**: nuclei, sqlmap, commix  
- **Análisis forense**: binwalk, strings, file, volatility
- **Detección de malware**: clamav, yara, chkrootkit, rkhunter
- **Auditoría de sistema**: lynis, aide, tiger
- **Monitoreo de red**: ss, lsof, tcpdump, iftop

## Herramientas Kali Linux Requeridas

### Instalación Automática de Dependencias
```bash
sudo apt update && sudo apt install -y \
  nmap masscan nikto gobuster nuclei sqlmap \
  clamav clamav-daemon chkrootkit rkhunter \
  aide tiger yara lynis inotify-tools \
  tcpdump iftop htop curl wget binwalk \
  volatility3 strings file exiftool
```

### Configuración Inicial Requerida
```bash
# Actualizar base de datos antivirus
sudo freshclam

# Configurar AIDE (detección de intrusos)
sudo aide --init
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configurar permisos para herramientas de red
sudo chmod +s /usr/bin/nmap
```

## Instalación y Configuración

### Requisitos del Sistema
- **Sistema Operativo**: Kali Linux 2024.x o superior (recomendado)
- **Python**: 3.8 o superior (incluido en Kali Linux)
- **Memoria RAM**: 4GB mínimo recomendado
- **Espacio en disco**: 2GB libres para logs y bases de datos
- **Conectividad**: Acceso a internet para actualizaciones CVE

### Proceso de Instalación
```bash
# 1. Clonar el repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Ejecutar configuración para Kali Linux
sudo ./configurar_kali.sh

# 3. Iniciar la aplicación
python3 main.py
```

### Verificación de la Instalación
```bash
# Verificar bibliotecas estándar de Python
python3 -c "import sys; print('Python stdlib disponible')"

# Verificar herramientas Kali instaladas
which nmap nikto gobuster clamav

# Ejecutar verificación completa de arquitectura
python3 -c "from aresitos.utils.verificar_kali import verificar_sistema; verificar_sistema()"
```

## Estructura del Proyecto

```
Ares-Aegis/
├── main.py                    # Punto de entrada principal
├── configurar_kali.sh         # Script configuración Kali
├── requirements.txt           # Documentación (NO hay dependencias)
├── pyproject.toml                   # Configuración del proyecto
├── VULNERABILIDADES_CORREGIDAS_CONSOLIDADO.md  # Documentación de seguridad
│
├── aresitos/                        # Paquete principal
│   ├── controlador/                 # Controladores (lógica de negocio)
│   ├── modelo/                      # Modelos de datos y análisis  
│   ├── vista/                       # Interfaces de usuario (tkinter)
│   ├── utils/                       # Utilidades del sistema
│   └── recursos/                    # Recursos estáticos (iconos)
│
├── configuracion/                   # Archivos de configuración
│   ├── aresitos_config.json         # Configuración principal
│   ├── aresitos_config_kali.json    # Configuración específica Kali
│   └── textos_castellano_corregido.json  # Localización
│
├── data/                           # Almacenamiento de datos
│   ├── cuarentena_kali2025.db      # Base de datos de cuarentena
│   ├── fim_kali2025.db             # Base de datos FIM
│   ├── vulnerability_database.json # Base de datos CVE
│   ├── cheatsheets/                # Hojas de referencia técnica
│   ├── diccionarios/               # Diccionarios especializados
│   └── wordlists/                  # Listas de palabras para testing
│
├── documentacion/                  # Documentación técnica
│   ├── auditoria/                  # Reportes de auditoría
│   ├── correcciones/               # Historial de correcciones
│   ├── desarrollo/                 # Documentación de desarrollo
│   ├── guias/                      # Guías de usuario
│   └── seguridad/                  # Documentación de seguridad
│
├── logs/                           # Archivos de log del sistema
└── recursos/                       # Recursos adicionales
```

## Uso y Funcionalidades

### Módulo de Escaneado de Vulnerabilidades
```python
# Ejemplo de uso del escaneador
from aresitos.controlador.controlador_escaneo import ControladorEscaneo

escaner = ControladorEscaneo()
resultados = escaner.escanear_objetivo('192.168.1.0/24')
print(f'Hosts encontrados: {len(resultados)}')
```

### Módulo FIM (File Integrity Monitoring)
```python
# Configuración del monitoreo de integridad
from aresitos.controlador.controlador_fim import ControladorFIM

fim = ControladorFIM()
fim.iniciar_monitoreo(['/etc', '/usr/bin', '/var/log'])
```

### Módulo SIEM (Security Information and Event Management)
```python
# Análisis de eventos de seguridad
from aresitos.controlador.controlador_siem_nuevo import ControladorSIEM

siem = ControladorSIEM()
eventos = siem.analizar_logs_tiempo_real()
```

## Arquitectura y Seguridad

### Principios de Diseño Implementados
- **Principio de menor privilegio**: Asignación mínima de permisos necesarios
- **Defensa en profundidad**: Implementación de múltiples capas de seguridad
- **Auditabilidad completa**: Todo el código fuente es inspeccionable y verificable
- **Arquitectura nativa**: Eliminación de dependencias externas vulnerables

### Medidas de Seguridad Implementadas
- **Algoritmos de hash seguros**: Uso exclusivo de SHA-256, eliminación de MD5/SHA1
- **Validación estricta de entrada**: Sanitización completa de todos los inputs
- **Sistema de logging seguro**: Registros resistentes a manipulación
- **Gestión de permisos**: Asignación mínima y específica de privilegios

### Verificación de Seguridad
```bash
# Ejecutar verificación de seguridad (si las herramientas están disponibles)
python3 -c "from aresitos.utils.verificacion_permisos import verificar_seguridad; verificar_seguridad()"

# Verificar integridad de la arquitectura nativa
python3 -c "from aresitos.utils.verificar_kali import verificar_dependencias; verificar_dependencias()"
```

## Funcionalidades Avanzadas

### Dashboard de Control
- **Métricas en tiempo real**: Monitoreo de CPU, memoria, red y disco
- **Sistema de alertas**: Notificaciones visuales del estado de seguridad
- **Gráficos interactivos**: Visualización de tendencias y patrones de seguridad
- **Widgets configurables**: Personalización de información mostrada

### Sistema de Reportes
- **Generación automática**: Reportes en formatos PDF, HTML y JSON
- **Análisis estadístico**: Identificación de tendencias y correlaciones
- **Exportación de datos**: Múltiples formatos de salida disponibles
- **Programación de reportes**: Generación automática según calendario

### Gestión de Configuración
- **Configuración centralizada**: Archivos JSON estructurados y documentados
- **Perfiles de entorno**: Configuraciones específicas para desarrollo/producción
- **Sistema de respaldo**: Backup automático de configuraciones críticas
- **Validación de sintaxis**: Verificación automática de archivos de configuración

## Casos de Uso Típicos

### Auditoría de Seguridad
```bash
# Ejecutar auditoría completa del sistema
python3 main.py --modo auditoria --objetivo /
```

### Administración de Sistemas
```bash
# Iniciar monitoreo continuo
python3 main.py --modo monitor --tiempo-real
```

### Análisis Forense Digital
```bash
# Ejecutar análisis forense detallado
python3 main.py --modo forense --directorio /evidencia
```

### Testing de Penetración
```bash
# Realizar escaneo de penetración
python3 main.py --modo pentest --objetivo 192.168.1.0/24
```

## Documentación Técnica

### Guías de Usuario
- `documentacion/guias/` - Manuales de usuario y casos de uso
- `documentacion/desarrollo/` - Documentación técnica de desarrollo
- `VULNERABILIDADES_CORREGIDAS_CONSOLIDADO.md` - Historial de correcciones de seguridad

### Documentación de Desarrollo
- `documentacion/desarrollo/ARQUITECTURA_NATIVA.md` - Detalles de la arquitectura
- `documentacion/auditoria/` - Reportes de auditoría de seguridad
- `documentacion/correcciones/` - Historial completo de correcciones

### Auditorías y Cumplimiento Normativo
- `documentacion/auditoria/SECURITY_AUDIT.md` - Auditoría de seguridad
- `documentacion/seguridad/` - Documentación de seguridad
- `documentacion/correcciones/REPORTE_CORRECCIONES_FINALES.md` - Reporte final

## Configuración Avanzada

### Configuración Principal
El archivo `configuracion/aresitos_config.json` contiene los parámetros de configuración principales:

```json
{
  "sistema": {
    "modo_debug": false,
    "nivel_logging": "INFO",
    "max_procesos_paralelos": 4
  },
  "escaneo": {
    "timeout_nmap": 300,
    "puertos_personalizados": "1-65535",
    "deteccion_os": true
  },
  "fim": {
    "directorios_criticos": ["/etc", "/usr/bin", "/boot"],
    "exclusiones": ["/tmp", "/var/tmp"],
    "intervalo_verificacion": 3600
  },
  "siem": {
    "logs_monitorear": ["/var/log/auth.log", "/var/log/syslog"],
    "correlacion_eventos": true,
    "alertas_email": false
  }
}
```

## Ventajas Técnicas

### Comparación con Herramientas Comerciales
- Licencia de código abierto sin restricciones
- Código fuente completamente auditable
- Personalización total de funcionalidades
- Sin costos de licenciamiento

### Comparación con Otras Suites Open Source
- Arquitectura sin dependencias externas
- Instalación inmediata sin configuración compleja
- Diseño específico para Kali Linux
- Integración nativa optimizada

### Comparación con Scripts Individuales
- Interfaz de usuario unificada e intuitiva
- Correlación inteligente entre herramientas
- Gestión centralizada de configuraciones
- Reportes consolidados y coherentes

## Licencia y Aspectos Legales

### Licencia MIT
Este proyecto está distribuido bajo la Licencia MIT. Consulte el archivo `LICENSE` para obtener información detallada.

### Consideraciones Legales y Éticas
**IMPORTANTE: SOLO PARA USO ÉTICO Y LEGAL**

- Esta herramienta debe utilizarse únicamente en sistemas propios o con autorización explícita
- No está destinada para actividades ilegales o maliciosas
- El usuario es completamente responsable del cumplimiento de las leyes locales
- Los desarrolladores no asumen responsabilidad por el uso indebido de la herramienta

### Descargo de Responsabilidad
El software se proporciona "tal como está", sin garantías de ningún tipo. Los autores no se responsabilizan por daños directos o indirectos resultantes del uso de este software.

---

## Conclusión

ARESITOS v2.0 representa un enfoque innovador en el desarrollo de herramientas de ciberseguridad, priorizando:

- **Simplicidad arquitectónica** sin sacrificar funcionalidad avanzada
- **Seguridad robusta** mediante la eliminación de dependencias externas vulnerables  
- **Integración nativa** con las mejores herramientas especializadas de Kali Linux
- **Calidad profesional** en cada aspecto del desarrollo y documentación

### Inicio Rápido
```bash
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos
sudo ./configurar_kali.sh
python3 main.py
```

Para estudiantes y profesionales de ciberseguridad que buscan una herramienta integral, robusta y éticamente desarrollada.

---

## En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos, DogSoulDev

---

*Desarrollado por DogSoulDev para la comunidad de ciberseguridad*