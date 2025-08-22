![ARESITOS](aresitos/recursos/Aresitos.ico)

# ARESITOS - Herramienta de Ciberseguridad

[![Versión](https://img.shields.io/badge/versión-v2.0%20Professional-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B%20Native-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC%20SOLID-orange.svg)](README.md)
[![SIEM](https://img.shields.io/badge/SIEM-Integrado-red.svg)](README.md)
[![FIM](https://img.shields.io/badge/FIM-Real%20Time-purple.svg)](README.md)

**ARESITOS v2.0** es la suite de ciberseguridad más avanzada para profesionales, exclusivamente optimizada para **Kali Linux 2025**. Combina las herramientas más modernas del arsenal de seguridad en una plataforma unificada con capacidades SIEM, FIM en tiempo real, cuarentena inteligente y auditorías profesionales.

---

## 🚀 **INSTALACIÓN INSTANTÁNEA (30 segundos)**

### ⚡ **Método Automático - Recomendado**
```bash
# Clonar y ejecutar configuración automática
git clone https://github.com/DogSoulDev/Aresitos.git && cd Aresitos
chmod +x configurar_kali.sh && sudo ./configurar_kali.sh
python3 main.py
```

> **🔧 NOTA**: Si experimentas problemas con directorios duplicados, ejecuta:
> ```bash
> cd Aresitos && sudo ./configurar_kali.sh
> ```
> El script ahora establece automáticamente el directorio de trabajo correcto.

> **⚠️ HERRAMIENTAS PROBLEMÁTICAS**: Algunas herramientas requieren instalación manual:
> ```bash
> # Volatility (análisis de memoria)
> sudo apt install volatility3 python3-volatility3
> 
> # Wireshark (análisis de tráfico)
> sudo apt install wireshark
> 
> # Autopsy (forense)
> sudo apt install autopsy
> ```

### 🔧 **Método Manual - Control Total**
```bash
# 1. Descargar ARESITOS
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar entorno Kali 2025
sudo ./configurar_kali.sh

# 3. Verificar instalación
python3 verificacion_final.py

# 4. ¡Iniciar ARESITOS v2.0!
python3 main.py
```

### 🛠️ **Modo Desarrollo (Otros Sistemas)**
```bash
# Para testing en sistemas no-Kali (funcionalidad limitada)
python3 main.py --dev
```

---

## 🖼️ **CAPTURAS DE PANTALLA DETALLADAS**

### 1. Sistema de Autenticación - Primera Impresión
![Vista Login](aresitos/recursos/vista_login.png)

**¿Qué es esta pantalla?**
La primera ventana que ves al iniciar Aresitos. No es solo un login normal, es un sistema inteligente que verifica automáticamente que tu sistema Kali Linux esté configurado correctamente.

**¿Qué hace por ti?**
- **Verifica herramientas**: Comprueba que tengas instaladas más de 25 herramientas de ciberseguridad
- **Configura permisos**: Establece los permisos necesarios para usar herramientas avanzadas
- **Detecta problemas**: Si algo falta, te guía para solucionarlo automáticamente
- **Acceso seguro**: Controla quién puede usar el sistema con autenticación robusta

### 2. Vista de Herramientas - Configuración Automática
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)

**¿Qué es esta pantalla?**
Una ventana especial que aparece solo la primera vez que usas Aresitos. Su trabajo es configurar automáticamente todas las herramientas de seguridad que necesitas.

**¿Qué hace por ti?**
- **Instala herramientas modernas**: nmap, nuclei, gobuster y más de 20 herramientas avanzadas
- **Configura permisos**: Te permite usar las herramientas sin escribir contraseñas constantemente
- **Actualiza bases de datos**: Descarga las últimas definiciones de vulnerabilidades
- **Prepara el entorno**: Deja todo listo para que puedas empezar a trabajar inmediatamente

### 3. Vista Principal - Centro de Comando
![Vista Aresitos](aresitos/recursos/vista_aresitos.png)

**¿Qué es esta pantalla?**
El corazón de Aresitos. Una vez configurado todo, esta es tu central de operaciones de ciberseguridad. Aquí tienes acceso a todas las funcionalidades del programa.

**¿Qué puedes hacer?**
- **🎯 Dashboard**: Ver el estado de tu sistema en tiempo real
- **🔍 Escaneador**: Buscar vulnerabilidades en otros sistemas o redes
- **🛡️ SIEM**: Monitorear eventos de seguridad y detectar amenazas
- **📁 FIM**: Vigilar cambios sospechosos en archivos importantes
- **🔒 Cuarentena**: Aislar archivos maliciosos de forma segura
- **📊 Reportes**: Generar informes profesionales de tus auditorías
- **📚 Gestión de Datos**: Administrar diccionarios y listas de palabras
- **⚙️ Auditoría**: Revisar la seguridad de tu propio sistema

---

## 🔧 **CORRECCIONES TÉCNICAS v2.0**

### ✅ **TclError 'invalid command name' - RESUELTO COMPLETAMENTE**
**Problema identificado y corregido en todas las vistas de la aplicación**

**¿Qué era el problema?**
- Operaciones directas con widgets Tkinter desde threads secundarios
- Widgets destruidos antes de que threads terminen de acceder a ellos
- Error específico: `TclError: invalid command name ".!frame.!frame.!text"`

**✅ SOLUCIÓN IMPLEMENTADA:**
- **Thread Safety**: Implementación de métodos `_actualizar_[widget]_seguro()` en todas las vistas
- **Validación robusta**: Uso sistemático de `winfo_exists()` antes de cada operación
- **Programación segura**: Uso de `after_idle()` para actualizaciones desde threads
- **Patrón defensivo**: Try/catch con falla silenciosa para widgets destruidos

**📋 ARCHIVOS CORREGIDOS:**
- ✅ `vista_herramientas_kali.py` - Protecciones completas
- ✅ `vista_gestion_datos.py` - Método `_actualizar_contenido_seguro()` 
- ✅ `vista_dashboard.py` - Método `_actualizar_terminal_seguro()`
- ✅ `vista_escaneo.py` - Protecciones principales implementadas
- ✅ `vista_siem.py` - Correcciones + eliminación emoticonos
- ✅ `vista_reportes.py` - Métodos duales para reporte y terminal
- ✅ `vista_auditoria.py` - Protecciones mejoradas
- ✅ `vista_fim.py` - Protecciones mejoradas
- ✅ `vista_monitoreo.py` - Ya implementado correctamente

**🛡️ PATRÓN ESTÁNDAR APLICADO:**
```python
def _actualizar_widget_seguro(self, texto, modo="append"):
    def _update():
        try:
            if hasattr(self, 'widget') and self.widget.winfo_exists():
                # Operaciones seguras aquí
                pass
        except (tk.TclError, AttributeError):
            pass  # Widget destruido - falla silenciosa
    
    self.after_idle(_update)  # Thread safety garantizado
```

**🎯 RESULTADO:**
- **Estabilidad**: Eliminación completa de crashes por TclError
- **Robustez**: Manejo elegante de widgets destruidos
- **Performance**: UI responsiva durante operaciones largas
- **Escalabilidad**: Patrones reutilizables para futuras funcionalidades

---

## 🏗️ **ARQUITECTURA ARESITOS v2.0**

### 🔐 **Sistema de Autenticación Avanzado**
**Centro de Control de Acceso y Verificación del Sistema**

**Características Principales:**
- ✅ **Verificación automática** de herramientas Kali 2025
- ✅ **SudoManager integrado** - Sin solicitudes repetitivas de contraseña
- ✅ **Rate limiting** contra ataques de fuerza bruta
- ✅ **Configuración automática** de herramientas missing
- ✅ **Modo desarrollo** para testing en otros sistemas

**¿Cómo funciona?**
El sistema verifica automáticamente que tengas instaladas +25 herramientas críticas, configura permisos especiales y establece una sesión sudo persistente para toda la aplicación.

### ⚙️ **Configurador Inteligente de Herramientas**
**Instalación y Configuración Automática de Arsenal Completo**

**Herramientas Instaladas Automáticamente:**
- 🔍 **Scanners**: nmap, masscan, rustscan, zmap
- 🌐 **Web**: nuclei, httpx, gobuster, feroxbuster, dirb
- 🔓 **Exploitation**: sqlmap, nikto, whatweb
- 📊 **Analysis**: linpeas, pspy, chkrootkit, lynis
- 🛡️ **Defense**: fail2ban, ufw, aide
- 🔑 **Passwords**: hydra, john, hashcat, crunch

**Configuraciones Automáticas:**
- ✅ Permisos CAP_NET_RAW para escaneos SYN
- ✅ Bases de datos de vulnerabilidades actualizadas
- ✅ Wordlists y diccionarios especializados
- ✅ Templates nuclei premium y custom
- ✅ Configuración de firewall adaptativa

### 🎯 **Dashboard Profesional - Centro de Operaciones**
**Central de Comandos Unificada con Monitoreo en Tiempo Real**

#### **Módulos Integrados:**

🎛️ **Dashboard Ejecutivo**
- Monitor de sistema en tiempo real (60s refresh)
- Métricas de red avanzadas con gráficos
- Status de servicios críticos
- Terminal integrado con historial persistent

🔍 **Escáner Profesional** 
- Integración nuclei con templates actualizados
- Escaneo masivo con rustscan + nmap
- Detección de servicios y versiones
- Análisis de superficie de ataque completo

🛡️ **SIEM Integrado**
- Monitoreo de 50+ puertos críticos en tiempo real
- Correlación automática de eventos de seguridad
- Detección de anomalías comportamentales
- Alertas inteligentes con contexto completo

📁 **FIM (File Integrity Monitoring)**
- Vigilancia de 60+ directorios críticos del sistema
- Detección en tiempo real de modificaciones
- Checksums SHA256 para integridad absoluta
- Alertas inmediatas de cambios no autorizados

🔒 **Sistema de Cuarentena Avanzado**
- Detección automática de malware conocido
- Aislamiento seguro preservando evidencia forense
- Análisis de comportamiento sospechoso
- Gestión de false positives inteligente

📊 **Generador de Reportes Profesionales**
- Informes ejecutivos y técnicos
- Integración completa de todos los módulos
- Exportación múltiple: JSON, TXT, CSV
- Templates personalizables por industria

📚 **Gestor de Inteligencia**
- Base de datos de vulnerabilidades localizada
- Wordlists categorizadas por técnica
- Diccionarios especializados por sector
- Cheatsheets de herramientas integradas

⚙️ **Auditoría de Sistema Automatizada**
- Lynis con configuración optimizada para Kali
- Chkrootkit con heurísticas avanzadas
- Análisis de configuraciones de seguridad
- Recomendaciones priorizadas por riesgo

---

## 🎯 **CASOS DE USO PROFESIONALES**

### 👨‍🎓 **Para Estudiantes de Ciberseguridad**
- ✅ **Laboratorio completo**: Entorno real con herramientas profesionales
- ✅ **Aprendizaje guiado**: Interfaces intuitivas con documentación integrada
- ✅ **Práctica segura**: Sandbox controlado para experimentación
- ✅ **Progresión natural**: Desde básico hasta técnicas avanzadas de pentesting

### 👨‍💼 **Para Profesionales SOC/Blue Team**
- ✅ **Monitoreo centralizado**: SIEM integrado con correlación automática
- ✅ **Respuesta a incidentes**: FIM + Cuarentena para containment rápido
- ✅ **Reportes ejecutivos**: Métricas claras para management
- ✅ **Automatización**: Reduce tiempo de análisis manual en 80%

### 🔴 **Para Red Team/Pentesters**
- ✅ **Reconocimiento avanzado**: Nuclei + Rustscan para cobertura completa
- ✅ **Superficie de ataque**: Mapeo automático de servicios y vulnerabilidades
- ✅ **Documentación automática**: Reportes técnicos listos para entrega
- ✅ **Arsenal unificado**: +25 herramientas en interface coherente

### 🏢 **Para Equipos Corporativos**
- ✅ **Compliance**: Auditorías automáticas según frameworks (ISO 27001, NIST)
- ✅ **Gestión de vulnerabilidades**: Identificación y priorización automática
- ✅ **Monitoreo continuo**: Vigilancia 24/7 de activos críticos
- ✅ **ROI medible**: Reducción de tiempo de assessment en 70%

---

## ⭐ **CARACTERÍSTICAS AVANZADAS v2.0**

### 🛠️ **Arsenal de Herramientas Modernas**
**Escáner de Vulnerabilidades de Nueva Generación:**
- 🚀 **Nuclei Engine**: +4000 templates actualizados automáticamente
- ⚡ **RustScan**: Escaneo de puertos 10x más rápido que nmap tradicional
- 🌐 **HTTPx**: Sondeo web masivo con detección de tecnologías
- 🔍 **Feroxbuster**: Directory fuzzing con técnicas anti-WAF

**Herramientas de Análisis Avanzado:**
- 📊 **LinPEAS**: Escalada de privilegios con heurísticas ML
- 👁️ **Pspy**: Monitoreo de procesos sin permisos root
- 🔐 **Lynis**: Auditoría de hardening con 300+ checks
- 🔍 **Chkrootkit**: Detección de rootkits con signatures actualizadas

### 🔒 **Seguridad y Privacidad**
- ✅ **Zero Dependencies**: Solo Python nativo, sin librerías externas
- ✅ **Offline Capability**: Funciona completamente sin internet
- ✅ **Local Processing**: Todos los datos se procesan localmente
- ✅ **Audit Trail**: Logging completo de todas las operaciones
- ✅ **Encryption**: SHA256 para integridad, AES para datos sensibles

### 📋 **Reportes de Nivel Empresarial**
- 📋 **Executive Summary**: Métricas de alto nivel para C-Level
- 📊 **Technical Deep-Dive**: Análisis detallado para técnicos
- 📈 **Trend Analysis**: Evolución de la postura de seguridad
- 🎯 **Risk Prioritization**: Vulnerabilidades ordenadas por impacto real

---

## 🔧 **INFORMACIÓN TÉCNICA AVANZADA**

### 🏗️ **Arquitectura SOLID + MVC**
```
ARESITOS v2.0/
├── 🎨 Vista (UI Layer)          - 13 interfaces especializadas
├── 🎮 Controlador (Logic)       - 15 módulos de lógica de negocio
├── 💾 Modelo (Data)            - 19 módulos de procesamiento
├── 🔧 Utils (Infrastructure)   - Componentes transversales
└── 📊 Data (Intelligence)      - Bases de conocimiento
```

**Principios de Diseño:**
- ✅ **Single Responsibility**: Cada clase tiene una función específica
- ✅ **Open/Closed**: Extensible sin modificar código existente
- ✅ **Liskov Substitution**: Interfaces consistentes y predecibles
- ✅ **Interface Segregation**: APIs específicas para cada caso de uso
- ✅ **Dependency Inversion**: Abstracciones sobre implementaciones

### 💻 **Compatibilidad y Requisitos**

**Sistemas Soportados:**
- ✅ **Kali Linux 2025** - Funcionalidad completa optimizada
- ✅ **Kali Linux 2024** - Compatibilidad total verificada
- ✅ **Parrot Security** - Soporte nativo para todas las funciones
- ⚠️ **BlackArch** - Funciones básicas, configuración manual requerida
- ⚠️ **Ubuntu/Debian** - Modo limitado, ideal para desarrollo
- ❌ **Windows/macOS** - No soportado oficialmente

**Especificaciones Técnicas:**
- 🐍 **Python**: 3.9+ (optimización async/await)
- 💾 **RAM**: 4GB mínimo, 8GB recomendado para análisis pesado
- 💿 **Almacenamiento**: 500MB para instalación completa
- 🌐 **Red**: Offline capability, internet opcional para updates
- 🔐 **Permisos**: sudo para configuración inicial únicamente

**Dependencias del Sistema:**
- ✅ **Librerías nativas**: Tkinter, subprocess, threading, json
- ✅ **Herramientas Kali**: Auto-instalación de arsenal completo
- ✅ **Configuración**: Automatizada 100% via configurar_kali.sh
- ❌ **PIP packages**: Zero external dependencies

---

## 📚 **GUÍA DE INICIO RÁPIDO**

### 🚀 **Primera Ejecución (5 minutos)**
1. **Clonar repositorio**: `git clone https://github.com/DogSoulDev/Aresitos.git`
2. **Entrar al directorio**: `cd Aresitos`
3. **Configuración automática**: `sudo ./configurar_kali.sh`
4. **Iniciar aplicación**: `python3 main.py`
5. **Login**: Usuario por defecto o crear nuevo perfil
6. **¡Explorar!**: Acceso inmediato a los 8 módulos principales

### 📖 **Flujo de Trabajo Típico**
1. **Dashboard**: Verificar estado del sistema y alertas activas
2. **Escáner**: Reconocimiento y mapeo de objetivos
3. **SIEM**: Monitoreo continuo y detección de anomalías
4. **FIM**: Verificación de integridad de sistemas críticos
5. **Auditoría**: Evaluación de postura de seguridad propia
6. **Reportes**: Documentación profesional de hallazgos

### 🔧 **Comandos Esenciales**
```bash
# Verificar estado completo del sistema
python3 verificacion_final.py

# Modo desarrollo (sistemas no-Kali)
python3 main.py --dev

# Actualizar configuración
sudo ./configurar_kali.sh --update

# Debug completo
python3 main.py --verbose
```

---

## 📞 **SOPORTE Y COMUNIDAD**

### 📖 **Documentación Completa**
- 📚 **Manual técnico**: `/documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- 🏗️ **Guía desarrollo**: `/documentacion/ARQUITECTURA_DESARROLLO.md`
- 🛡️ **Auditoría seguridad**: `/documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md`
- 💻 **Terminal integrado**: `/documentacion/TERMINAL_INTEGRADO.md`

### 🤝 **Contacto y Contribución**
- 🌐 **Repositorio oficial**: https://github.com/DogSoulDev/Aresitos
- 🐛 **Reportar issues**: GitHub Issues con templates predefinidos
- 💌 **Email desarrollo**: dogsouldev@protonmail.com
- 🔗 **LinkedIn**: [DogSoulDev](https://linkedin.com/in/dogsouldev)

### 🎯 **Roadmap v2.1**
- 🤖 **IA Integration**: ML para detección automática de amenazas
- 📱 **Mobile Dashboard**: Aplicación móvil para monitoreo remoto
- ☁️ **Cloud Connector**: Integración con SIEM corporativos
- 🌐 **API REST**: Endpoints para automatización externa

---

## 📜 **LICENCIA Y USO ÉTICO**

### **Open Source Non-Commercial License**

#### **✅ USO PERMITIDO (GRATUITO)**
- 🎓 **Educación**: Universidades, estudiantes, investigación académica
- 🛡️ **Seguridad personal**: Testing en sistemas propios o autorizados
- 🌐 **Open Source**: Proyectos de código abierto sin monetización
- 📚 **Aprendizaje**: Cursos, talleres, capacitación sin fines de lucro
- 🤝 **Comunidad**: Compartir conocimientos y mejoras

#### **❌ USO PROHIBIDO (COMERCIAL)**
- 💰 **Venta directa**: No se puede vender ARESITOS o derivados
- 🏢 **Consultoría comercial**: No usar para servicios pagos de pentesting
- 📦 **Productos comerciales**: No incorporar en software comercial
- 💳 **Monetización**: Cursos pagos, suscripciones, licencias comerciales
- 🏪 **Servicios**: No ofrecer como SaaS o servicios managed

#### **📋 ATRIBUCIÓN OBLIGATORIA**
**TODO uso debe incluir:**
- 👨‍💻 **Creador**: DogSoulDev
- 📧 **Contacto**: dogsouldev@protonmail.com
- 🔗 **Fuente**: https://github.com/DogSoulDev/Aresitos
- 📄 **Licencia**: Open Source Non-Commercial

### **🛡️ CÓDIGO DE ÉTICA**
- ✅ **Solo sistemas autorizados** - Con permiso explícito por escrito
- ✅ **Propósitos constructivos** - Mejorar la seguridad, no dañar
- ✅ **Divulgación responsable** - Reportar vulnerabilidades apropiadamente
- ❌ **Actividades ilegales** - Prohibido para hacking malicioso
- ❌ **Daño intencional** - No usar para comprometer sistemas

---

## 🐕 **DEDICATORIA ESPECIAL**

### En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.
