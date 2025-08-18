# ![Aresitos](aresitos/recursos/Aresitos.ico) ARESITOS v2.0
**Suite de Ciberseguridad para Kali Linux**

ARESITOS es una suite completa de herramientas de ciberseguridad diseñada específicamente para Kali Linux, que integra escaneado de vulnerabilidades, monitoreo de integridad de archivos (FIM) y sistema SIEM en una interfaz unificada.

## Autor
- **Desarrollador**: DogSoulDev  
- **Email**: dogsouldev@protonmail.com  
- **Repositorio**: https://github.com/DogSoulDev/Aresitos

## Características Principales

### Escaneador de Vulnerabilidades v2.0
- Integración nativa con herramientas de Kali Linux (nmap, nikto, gobuster, nuclei)
- Detección real de malware con ClamAV, chkrootkit y rkhunter
- Base de datos CVE integrada con scoring CVSS
- Escaneo de puertos, servicios y vulnerabilidades web

### Sistema FIM (File Integrity Monitoring)
- Monitoreo en tiempo real de archivos críticos del sistema
- Detección de cambios no autorizados en archivos sensibles
- Alertas automáticas ante modificaciones sospechosas
- Base de datos de integridad persistente

### Sistema SIEM Integrado
- Análisis de logs del sistema Kali Linux
- Correlación de eventos de seguridad
- Detección de patrones de ataque
- Reportes de seguridad automatizados

### Sistema de Cuarentena
- Aislamiento seguro de archivos maliciosos
- Gestión de amenazas detectadas
- Restauración controlada de archivos

## Estructura del Proyecto

```
aresitos/
├── main.py                    # Punto de entrada principal
├── configurar_kali.sh         # Script de instalación
├── requirements.txt           # Dependencias
├── pyproject.toml            # Configuración del proyecto
├── aresitos/                 # Código fuente principal
│   ├── controlador/          # Lógica de control (MVC)
│   ├── modelo/              # Modelos de datos y lógica
│   ├── vista/               # Interfaces gráficas
│   └── utils/               # Utilidades y herramientas
├── configuracion/           # Archivos de configuración
├── data/                   # Bases de datos y wordlists
├── logs/                   # Archivos de registro
├── recursos/               # Recursos estáticos
└── documentacion/          # Documentación del proyecto
```

## Requisitos del Sistema

### Sistema Operativo
- **Kali Linux** (recomendado)
- Distribuciones Linux compatibles con herramientas de pentesting

### Dependencias
- Python 3.8 o superior
- Herramientas de Kali Linux: nmap, nikto, gobuster, nuclei, clamav
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

# Instalar dependencias del sistema
sudo apt install -y python3 python3-pip python3-tk
sudo apt install -y nmap nikto gobuster nuclei clamav clamav-daemon
sudo apt install -y chkrootkit rkhunter lynis

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

#### Escaneador de Vulnerabilidades
1. Acceder al módulo "Escaneador"
2. Configurar objetivo (IP, rango de red, archivo de hosts)
3. Seleccionar tipo de escaneo (rápido, completo, personalizado)
4. Revisar reportes generados en data/reportes/

#### Monitoreo FIM
1. Acceder al módulo "FIM"
2. Configurar rutas críticas a monitorear
3. Iniciar monitoreo en tiempo real
4. Revisar alertas en el dashboard

#### Sistema SIEM
1. Acceder al módulo "SIEM"
2. Seleccionar fuentes de logs a analizar
3. Configurar reglas de correlación
4. Revisar eventos de seguridad

## Configuración

### Archivos de Configuración
- `configuracion/aresitos_config.json`: Configuración principal
- `configuracion/aresitos_config_kali.json`: Configuración específica de Kali
- `configuracion/textos_castellano_corregido.json`: Textos de la interfaz

### Logs del Sistema
- `logs/aresitos.log`: Log principal del sistema
- `logs/aresitos_errors.log`: Log de errores
- `logs/verificacion_permisos.log`: Log de verificación de permisos

## Verificación del Sistema

```bash
# Verificar instalación y configuración
python3 verificacion_seguridad.py

# El script verificará:
# - Estructura de archivos del proyecto
# - Herramientas de Kali Linux disponibles
# - Permisos y configuraciones
# - Integridad del sistema MVC
```

## Seguridad

ARESITOS implementa múltiples capas de seguridad:

- **Gestión segura de permisos**: Control de operaciones privilegiadas
- **Validación de entrada**: Sanitización de todos los inputs del usuario
- **Ejecución segura**: Prevención de inyección de comandos
- **Logging seguro**: Ocultación automática de credenciales en logs
- **Cuarentena de amenazas**: Aislamiento seguro de archivos maliciosos

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
**Fecha de lanzamiento**: Agosto 2025  
**Estado**: Producción estable

---
En Memoria de Ares
Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos,
DogSoulDev