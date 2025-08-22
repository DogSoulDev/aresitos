![ARESITOS](aresitos/recursos/Aresitos.png)

# Aresitos Beta 12 Estable
**Suite Profesional de Ciberseguridad para Kali Linux**

[![Versión](https://img.shields.io/badge/versión-Beta%2012%20Estable-brightgreen.svg)](https://github.com/DogSoulDev/Aresitos)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2024%2B-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-yellow.svg)](https://www.python.org/)
[![Arquitectura](https://img.shields.io/badge/Arquitectura-MVC%20Nativa-orange.svg)](README.md)

Aresitos es una herramienta integral de ciberseguridad desarrollada exclusivamente para Kali Linux. Está diseñada para profesionales de seguridad informática y estudiantes que quieren aprender ciberseguridad de manera práctica. La aplicación combina las mejores herramientas de Kali Linux en una interfaz fácil de usar, permitiendo realizar auditorías de seguridad, detectar amenazas y generar reportes profesionales.

## 🖥️ Flujo del Programa

### 1. Vista de Login - Inicio Seguro
![Vista Login](aresitos/recursos/vista_login.png)

**¿Qué es esta pantalla?**
La primera ventana que verás al abrir Aresitos. Aquí el programa verifica que tengas los permisos necesarios y las herramientas de Kali Linux instaladas correctamente.

**¿Qué puedes hacer?**
- **Verificar tu sistema**: El programa comprueba automáticamente si tienes las herramientas necesarias
- **Configurar herramientas**: Si algo falta, te ayuda a instalarlo
- **Acceder de forma segura**: Solo usuarios autorizados pueden usar el programa
- **Elegir modo**: Puedes usar modo completo (Kali Linux) o modo desarrollo (otros sistemas)

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

## 🚀 Proceso de Instalación

### Requisitos Básicos
- **Sistema**: Kali Linux 2024 o superior (recomendado)
- **Python**: Versión 3.8 o superior (ya incluido en Kali)
- **Permisos**: Acceso sudo para configurar herramientas
- **Espacio**: 100MB libres en disco

### Instalación Rápida (3 pasos)
```bash
# Paso 1: Descargar Aresitos
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Paso 2: Configurar automáticamente (solo la primera vez)
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# Paso 3: ¡Listo! Iniciar Aresitos
python3 main.py
```

### Para Otros Sistemas (Modo Limitado)
```bash
# Si no tienes Kali Linux, puedes probar en modo desarrollo
python3 main.py --dev
```

## � Guía de Uso

### Primera Vez
1. **Instalación**: Sigue los 3 pasos de arriba
2. **Login**: La primera pantalla verifica tu sistema
3. **Configuración**: Si es necesario, instala herramientas automáticamente
4. **¡A trabajar!**: Accede a la interfaz principal

### Funcionalidades Principales

#### 🎯 Dashboard - Tu Centro de Control
Aquí ves todo de un vistazo: estado del sistema, alertas activas, herramientas disponibles y estadísticas de seguridad en tiempo real.

#### 🔍 Escaneador - Busca Vulnerabilidades
Utiliza las mejores herramientas de Kali (nmap, nuclei, gobuster) para encontrar problemas de seguridad en sistemas y aplicaciones web.

#### 🛡️ SIEM - Detecta Amenazas
Monitorea 50 puertos críticos, analiza logs del sistema y correlaciona eventos para detectar actividad sospechosa.

#### � FIM - Vigila Cambios
Controla la integridad de archivos importantes. Te avisa si alguien modifica archivos críticos sin autorización.

#### 🔒 Cuarentena - Aísla Malware
Detecta y aísla archivos sospechosos de forma segura, protegiendo tu sistema sin eliminar evidencia.

#### 📊 Reportes - Documenta Todo
Genera informes profesionales con todos tus hallazgos, perfectos para presentar a clientes o superiores.

### Casos de Uso Comunes

#### Para Estudiantes
- **Aprender haciendo**: Usa herramientas reales en un entorno controlado
- **Practicar técnicas**: Desde escaneo básico hasta análisis forense avanzado
- **Entender conceptos**: Ve cómo funcionan las herramientas profesionales

#### Para Profesionales
- **Auditorías completas**: Automatiza procesos de evaluación de seguridad
- **Monitoreo continuo**: Mantén vigilancia 24/7 sobre sistemas críticos
- **Respuesta a incidentes**: Detecta, analiza y documenta amenazas rápidamente

#### Para Equipos SOC
- **Gestión centralizada**: Un solo lugar para todas las herramientas
- **Correlación automática**: El programa conecta eventos relacionados
- **Documentación automática**: Reportes listos para compartir

## ⭐ Características Destacadas

### 🛠️ Herramientas Modernas Integradas
Aresitos incluye más de 20 herramientas de vanguardia:
- **rustscan & masscan**: Escaneo ultrarrápido de puertos
- **nuclei**: Scanner moderno de vulnerabilidades con templates actualizados
- **gobuster & feroxbuster**: Búsqueda de directorios y archivos ocultos
- **httpx**: Sondeo web de alta velocidad
- **linpeas**: Análisis de escalada de privilegios
- **pspy**: Monitoreo de procesos sin permisos root

### 🔒 Seguridad Avanzada
- **Arquitectura sin dependencias**: Solo usa Python estándar, sin librerías externas
- **Verificación de integridad**: Controla que nadie modifique archivos importantes
- **Cuarentena inteligente**: Aísla amenazas sin eliminar evidencia
- **Logs de auditoría**: Registra todo lo que hace para trazabilidad completa

### � Reportes Profesionales
- **Integración completa**: Combina datos de todos los módulos
- **Formatos múltiples**: JSON para sistemas, TXT para humanos
- **Métricas de seguridad**: Estadísticas claras y actionables
- **Listos para presentar**: Perfectos para clientes o superiores

## 🔧 Información Técnica

### Arquitectura del Sistema
Aresitos usa una arquitectura MVC (Modelo-Vista-Controlador) que separa claramente:
- **Vista**: Las pantallas que ves (13 interfaces especializadas)
- **Controlador**: La lógica que decide qué hacer (15 módulos de control)
- **Modelo**: Donde se guardan y procesan los datos (19 módulos de datos)

### Compatibilidad
**Sistemas Soportados:**
- ✅ Kali Linux 2024+ (funcionalidad completa)
- ✅ Parrot Security OS (funcionalidad completa)
- ⚠️ Ubuntu/Debian (modo básico)
- ⚠️ Otros Linux (modo desarrollo)

**Requisitos de Python:**
- Python 3.8 como mínimo
- Python 3.9+ recomendado
- Solo librerías estándar (no requiere pip install)

## 📞 Soporte y Comunidad

### Documentación
- **Manual completo**: Carpeta `/documentacion/` con guías detalladas
- **Ejemplos prácticos**: Casos de uso reales paso a paso
- **Resolución de problemas**: Soluciones a errores comunes

### Contacto
- **Repositorio**: https://github.com/DogSoulDev/Aresitos
- **Reportar problemas**: Usa GitHub Issues
- **Email**: dogsouldev@protonmail.com

### Contribuir
¿Quieres ayudar a mejorar Aresitos? Lee la guía de contribución en `/documentacion/ARQUITECTURA_DESARROLLO.md`

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

## 💻 Instalación Rápida

### Para Kali Linux (Recomendado)
```bash
# 1. Descargar Aresitos
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# 2. Configurar automáticamente
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh

# 3. ¡Listo para usar!
python3 main.py
```

### Para Otros Sistemas
```bash
# Modo desarrollo (funcionalidad limitada)
python3 main.py --dev
```

## 🚀 Inicio Rápido

1. **Ejecuta Aresitos**: `python3 main.py`
2. **Login**: Usa el usuario por defecto o crea uno nuevo
3. **Herramientas**: El sistema configura automáticamente las herramientas de Kali
4. **¡Explora!**: Accede a los 8 módulos desde la pantalla principal

## 📄 Licencia

Aresitos está disponible bajo la **Licencia Open Source Non-Commercial**. 
Permite el uso libre para fines educativos, de investigación y desarrollo personal, excluyendo el uso comercial directo.

### Uso Ético
- Solo para sistemas propios o con autorización explícita
- Prohibido para actividades ilegales
- Destinado a promover prácticas éticas de ciberseguridad

---

En Memoria de Ares

Este programa se comparte gratuitamente con la comunidad de ciberseguridad en honor a mi hijo, compañero y perro, Ares - 25/04/2013 a 5/08/2025 DEP.

Hasta que volvamos a vernos.
DogSoulDev.