# Aresitos - Herramienta de Ciberseguridad

**Suite profesional de ciberseguridad para Kali Linux**

## Descripción

**Aresitos** es una herramienta completa de ciberseguridad diseñada específicamente para Kali Linux. Integra múltiples funcionalidades de seguridad en una interfaz unificada y fácil de usar.

## Características Principales

- **Escáner de Vulnerabilidades**: Detección automatizada usando herramientas nativas de Kali
- **SIEM Integrado**: Monitoreo de seguridad en tiempo real
- **File Integrity Monitoring (FIM)**: Vigilancia de archivos críticos del sistema
- **Sistema de Cuarentena**: Aislamiento seguro de amenazas detectadas
- **Auditoría de Sistema**: Evaluación automática de la postura de seguridad
- **Generación de Reportes**: Informes profesionales en múltiples formatos
- **Terminal Integrado**: Acceso directo a herramientas del sistema

## Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Configurar el entorno (solo para Kali Linux)
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# Ejecutar Aresitos
python3 main.py
```

## Requisitos del Sistema

- **Sistema Operativo**: Kali Linux (recomendado)
- **Python**: 3.9 o superior
- **Memoria RAM**: 4GB mínimo
- **Espacio en disco**: 500MB para instalación completa

## Arquitectura

Aresitos utiliza una arquitectura **MVC (Modelo-Vista-Controlador)** limpia y modular:

- **Vista**: Interfaces de usuario con tkinter nativo
- **Controlador**: Lógica de negocio y coordinación
- **Modelo**: Procesamiento de datos y análisis
- **Utils**: Utilidades y componentes transversales

## Módulos Principales

### 🎯 Dashboard
Centro de control con métricas del sistema en tiempo real

### 🔍 Escáner
Reconocimiento y análisis de vulnerabilidades usando:
- nmap para escaneo de puertos
- nuclei para vulnerabilidades web
- rustscan para escaneos rápidos

### 🛡️ SIEM
Sistema de monitoreo de eventos de seguridad:
- Detección de anomalías
- Correlación de eventos
- Alertas automáticas

### 📁 FIM (File Integrity Monitoring)
Vigilancia de archivos críticos:
- Detección de cambios en tiempo real
- Verificación de integridad con checksums
- Alertas de modificaciones no autorizadas

### 🔒 Cuarentena
Sistema de aislamiento de amenazas:
- Detección automática de malware
- Aislamiento seguro preservando evidencia
- Gestión de archivos en cuarentena

### 📊 Reportes
Generación de informes profesionales:
- Reportes ejecutivos y técnicos
- Múltiples formatos de exportación
- Análisis de tendencias

### ⚙️ Auditoría
Evaluación automática de seguridad:
- Análisis de configuraciones
- Detección de vulnerabilidades del sistema
- Recomendaciones de hardening

## Uso Básico

1. **Inicio**: Ejecutar `python3 main.py`
2. **Login**: Autenticarse en el sistema
3. **Dashboard**: Verificar el estado general del sistema
4. **Módulos**: Navegar entre las diferentes funcionalidades
5. **Reportes**: Generar informes de los análisis realizados

## Herramientas Integradas

Aresitos integra las siguientes herramientas nativas de Kali Linux:

- **Análisis**: nmap, masscan, rustscan, nuclei
- **Web**: gobuster, feroxbuster, nikto, whatweb
- **Sistema**: lynis, chkrootkit, linpeas, pspy
- **Forense**: strings, file, hexdump
- **Red**: ss, netstat, iptables, ufw

## Configuración

La configuración se realiza automáticamente durante la instalación. Para configuraciones avanzadas, consulte los archivos en la carpeta `configuración/`.

## Documentación

Documentación detallada disponible en la carpeta `documentacion/`:

- `DOCUMENTACION_TECNICA_CONSOLIDADA.md`: Manual técnico completo
- `ARQUITECTURA_DESARROLLO.md`: Guía de desarrollo
- `GUIA_INSTALACION.md`: Instrucciones de instalación detalladas

## Soporte

- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Issues**: Reportar problemas en GitHub Issues
- **Email**: dogsouldev@protonmail.com

## Licencia

Open Source Non-Commercial License

### Uso Permitido
- Educación e investigación
- Uso personal en sistemas propios
- Proyectos de código abierto

### Uso Prohibido
- Uso comercial sin autorización
- Servicios de consultoría pagados
- Incorporación en productos comerciales

## Dedicatoria

Este proyecto está dedicado con amor a **Ares**, mi compañero Golden Retriever que fue la inspiración para crear esta herramienta de ciberseguridad.

*"Protegiendo lo que más valoramos"*

---

**Creado por DogSoulDev**
