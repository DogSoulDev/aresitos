# ![ARESITOS](aresitos/recursos/aresitos.png)
# ARESITOS - Herramienta de Ciberseguridad



> **Recomendación importante:**
> Antes de instalar o ejecutar ARESITOS, asegúrate de tener tu sistema Kali Linux completamente actualizado para evitar problemas de dependencias o incompatibilidades:
> ```sh
> sudo apt update && sudo apt upgrade -y
> ```

---

## Proyecto TFM - UCAM - Campus Internacional de Ciberseguridad

Este proyecto ha sido desarrollado como parte del Trabajo Fin de Máster (TFM) en Ciberseguridad de la Universidad Católica San Antonio de Murcia (UCAM), en colaboración con el Campus Internacional de Ciberseguridad.

ARESITOS representa una solución profesional, académica y práctica para la gestión y automatización de auditorías de seguridad, integrando los estándares y mejores prácticas del sector.

---

# Descripción General

ARESITOS es una herramienta de ciberseguridad 100% Python nativo (sin librerías externas) para sistemas operativos Kali Linux. Integra escaneo de vulnerabilidades, SIEM, FIM, cuarentena, dashboard, reportes y utilidades forenses, todo bajo arquitectura MVC y principios SOLID/DRY. El sistema aprovecha herramientas nativas de Kali Linux y automatiza su verificación e instalación, garantizando robustez, seguridad y compatibilidad total con entornos forenses y de auditoría.

---


## Instalación rápida (Kali Linux recomendado)

> ⚠️ **Advertencia importante sobre la instalación de herramientas**
>
> Cuando utilices el **Configurador de Herramientas Kali** para instalar las herramientas faltantes, el proceso puede tardar varios minutos. Algunas utilidades avanzadas (como nuclei o httpx) se instalan mediante Go y requieren descargas y compilación adicionales.
> 
> **Ten paciencia y no cierres la aplicación** hasta que el proceso finalice y se muestre el mensaje de instalación completa.

```bash
# 1. Clona el repositorio y entra en la carpeta
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos

# 2. Da permisos de ejecución a los scripts principales
chmod +x configurar_kali.sh main.py

# 3. Ejecuta el script de configuración (como root o con sudo)
sudo ./configurar_kali.sh

# 4. (Opcional) Si tienes problemas de permisos, da ejecución a todos los .py
find . -name "*.py" -exec chmod +x {} \;

# 5. Inicia la aplicación
python3 main.py
```

Si tienes errores de acceso a carpetas:
```bash
chmod -R 755 data/ logs/ configuración/
```

### Herramientas forenses opcionales
```bash
sudo apt install kali-tools-forensics wireshark autopsy sleuthkit hashdeep testdisk bulk-extractor dc3dd guymager
```

### Modo desarrollo (otros sistemas)
```bash
python3 main.py --dev
```

> **Nota:** El modo desarrollo solo habilita la interfaz gráfica y utilidades básicas. Las funciones avanzadas requieren Kali Linux y privilegios adecuados.

### Requisitos principales
- **Python:** 3.8 o superior
- **Sistema operativo:** Kali Linux 2025 (recomendado, soporte parcial en otros Linux)
- **Dependencias nativas:** nmap, masscan, nuclei, gobuster, ffuf, feroxbuster, wireshark, autopsy, sleuthkit, hashdeep, testdisk, foremost, bulk-extractor, dc3dd, guymager, git, curl, wget, sqlite3, python3-tk, python3-venv
- **Espacio en disco ocupado (instalación base):** ~19 MB
- **RAM recomendada:** mínimo 1 GB libre (uso típico bajo, depende de los módulos activos)
- **Espacio recomendado para datos:** 20 MB libres adicionales para bases de datos, cuarentena y reportes

---

## Flujo de uso
1. **Login**: Verificación automática de entorno, dependencias, permisos y privilegios.
2. **Herramientas**: Detección, verificación visual (check verde/cruz roja) e instalación guiada de todas las herramientas requeridas.
3. **Principal**: Acceso a dashboard, escaneo, SIEM, FIM, cuarentena, monitoreo y reportes.

---


## Capturas de pantalla y explicación de módulos

ARESITOS cuenta con una interfaz profesional y modular. A continuación se muestran capturas de cada sección principal, junto con una breve explicación de su función:

### 1. Instalación y entorno
![Instalación](aresitos/recursos/capturas/1_instalacion.png)
**Explicación:** Pantalla de instalación y verificación de entorno. Aquí se comprueba que todas las dependencias y herramientas estén listas antes de iniciar.

### 2. Login
![Login](aresitos/recursos/capturas/2_login.png)
**Explicación:** Acceso seguro al sistema. Se validan permisos, entorno y usuario antes de permitir el uso de la suite.

### 3. Herramientas
![Herramientas](aresitos/recursos/capturas/3_herramientas.png)
**Explicación:** Panel de verificación e instalación de herramientas críticas y opcionales de Kali Linux. Permite instalar, actualizar y comprobar el estado de cada utilidad.

### 4. Dashboard
![Dashboard](aresitos/recursos/capturas/4_dashboard.png)
**Explicación:** Panel principal con métricas del sistema, estado de módulos, logs en tiempo real y acceso rápido a las funciones principales.

### 5. Escaneo
![Escaneo](aresitos/recursos/capturas/5_escaneo.png)
**Explicación:** Módulo de escaneo de vulnerabilidades. Permite analizar puertos, servicios, configuraciones y detectar debilidades usando herramientas nativas y bases de datos actualizadas.

### 6. SIEM
![SIEM](aresitos/recursos/capturas/6_SIEM.png)
**Explicación:** Sistema de gestión y correlación de eventos de seguridad. Analiza logs, detecta anomalías y muestra alertas en tiempo real.

### 7. FIM (File Integrity Monitoring)
![FIM](aresitos/recursos/capturas/7_FIM.png)
**Explicación:** Monitoriza la integridad de archivos críticos del sistema. Detecta cambios no autorizados y genera alertas forenses.

### 8. Monitoreo y Cuarentena
![Monitoreo y Cuarentena](aresitos/recursos/capturas/8_Monitoreo y Cuarentena.png)
**Explicación:** Supervisa procesos, recursos y amenazas. Permite aislar archivos sospechosos en cuarentena y analizar su comportamiento.

### 9. Auditoría
![Auditoría](aresitos/recursos/capturas/9_Auditoria.png)
**Explicación:** Herramientas de auditoría profesional (lynis, chkrootkit, linpeas, etc). Permite ejecutar análisis avanzados y obtener recomendaciones de seguridad.

### 10. Wordlists y Diccionarios
![Wordlists y Diccionarios](aresitos/recursos/capturas/10_wordlistsydiccionarios.png)
**Explicación:** Gestión de wordlists y diccionarios para escaneo, fuerza bruta y análisis. Permite cargar, validar y actualizar recursos de forma segura.

### 11. Reportes
![Reportes](aresitos/recursos/capturas/11_reportes.png)
**Explicación:** Generación, visualización y exportación de reportes profesionales en múltiples formatos (TXT, JSON, CSV). Incluye terminal integrado para trazabilidad completa.

---

## Arquitectura y estructura del proyecto

**Modelo-Vista-Controlador (MVC) + Principios SOLID**

```
aresitos/
├── controlador/           # Lógica de negocio, orquestación de módulos y flujos
│   ├── __init__.py
│   ├── controlador_principal.py      # Punto de entrada de la lógica de control
│   ├── controlador_escaneo.py        # Lógica de escaneo de vulnerabilidades
│   ├── controlador_reportes.py       # Generación y gestión de reportes
│   ├── controlador_dashboard.py      # Dashboard y métricas
│   ├── controlador_fim.py            # Integridad de archivos (FIM)
│   ├── controlador_cuarentena.py     # Gestión de cuarentena
│   ├── controlador_siem.py           # SIEM y correlación de eventos
│   ├── controlador_monitoreo.py      # Monitoreo de procesos y recursos
│   ├── controlador_herramientas.py   # Instalación/verificación de herramientas
│   ├── controlador_auditoria.py      # Auditoría avanzada (lynis, chkrootkit, etc)
│   ├── controlador_componentes.py    # Componentes auxiliares
│   ├── controlador_configuracion.py  # Configuración avanzada
│   └── ...
├── modelo/                # Modelos de datos, acceso a bases SQLite, wordlists, diccionarios, cuarentena, FIM, SIEM, reportes
│   ├── __init__.py
│   ├── modelo_principal.py          # Modelo principal de la aplicación
│   ├── modelo_cuarentena.py         # Gestión de archivos en cuarentena
│   ├── modelo_fim.py                # Integridad de archivos (FIM)
│   ├── modelo_dashboard.py          # Métricas y datos de dashboard
│   ├── modelo_diccionarios.py       # Diccionarios y wordlists
│   ├── modelo_escaneador.py         # Escaneo de vulnerabilidades
│   ├── modelo_escaneador_base.py    # Base para escaneadores
│   ├── modelo_monitor.py            # Monitoreo de recursos
│   ├── modelo_reportes.py           # Reportes y exportación
│   ├── modelo_siem.py               # SIEM y eventos
│   ├── modelo_sistema.py            # Información del sistema
│   ├── modelo_wordlists.py          # Gestión de wordlists
│   ├── modelo_wordlists_gestor.py   # Gestor de wordlists
│   └── ...
├── vista/                  # Interfaz gráfica Tkinter: paneles, terminal integrado, dashboard, escaneo, reportes, monitoreo, herramientas
│   ├── __init__.py
│   ├── vista_principal.py           # Vista principal y orquestación de paneles
│   ├── vista_dashboard.py           # Dashboard de métricas y terminal
│   ├── vista_escaneo.py             # Panel de escaneo de vulnerabilidades
│   ├── vista_reportes.py            # Panel de reportes
│   ├── vista_monitoreo.py           # Monitoreo y cuarentena
│   ├── vista_herramientas_kali.py   # Instalación/verificación de herramientas
│   ├── vista_auditoria.py           # Auditoría avanzada
│   ├── vista_fim.py                 # Integridad de archivos
│   ├── vista_login.py               # Login y control de acceso
│   ├── vista_datos.py               # Visualización de datos
│   ├── burp_theme.py                # Temas visuales
│   ├── terminal_mixin.py            # Terminal integrado
│   └── ...
├── utils/                  # Utilidades y módulos auxiliares: configuración, detección de red, sanitización, permisos, sistema, logging, etc.
│   ├── __init__.py
│   ├── configurar.py                 # Configuración y utilidades generales
│   ├── detector_red.py               # Detección de red y objetivos
│   ├── detector_sistema.py           # Detección robusta de sistema operativo/distribución
│   ├── permisos_sistema.py           # Verificación de root/admin multiplataforma
│   ├── sanitizador_archivos.py       # Sanitización y validación de archivos
│   ├── gestor_permisos.py            # Gestión avanzada de permisos
│   ├── logger_aresitos.py            # Logging centralizado
│   ├── sudo_manager.py               # Gestión de privilegios y sudo
│   ├── detener_procesos.py           # Control de procesos
│   ├── thread_safe_gui.py            # GUI thread-safe
│   ├── crash_fix_kali.py             # Fixes para Kali
│   └── ...
├── recursos/               # Imágenes, capturas de pantalla y recursos gráficos
│   ├── aresitos.ico
│   ├── aresitos.png
│   ├── capturas/                    # Capturas de pantalla para documentación
│   │   ├── 1_instalacion.png
│   │   ├── 2_login.png
│   │   ├── ...
│   └── ...
├── data/                   # Datos persistentes: bases de datos SQLite, cuarentena, wordlists, diccionarios, cheatsheets
│   ├── fim_kali2025.db               # Base de datos de integridad de archivos
│   ├── cuarentena_kali2025.db        # Base de datos de cuarentena
│   ├── siem_aresitos.db              # Base de datos SIEM
│   ├── siem_kali2025.db              # Base de datos SIEM alternativa
│   ├── vulnerability_database.json   # Base de datos de vulnerabilidades
│   ├── wordlists/                    # Wordlists para escaneo y fuerza bruta
│   ├── diccionarios/                 # Diccionarios
│   ├── cheatsheets/                  # Cheatsheets
│   ├── cuarentena/                   # Archivos y metadatos de cuarentena
│   │   ├── archivos/
│   │   ├── metadatos/
│   │   ├── respaldos/
│   │   └── ...
│   └── ...
├── configuración/          # Archivos de configuración JSON, textos, mapas de navegación, traducciones
│   ├── aresitos_config_completo.json # Configuración global
│   ├── textos_castellano_corregido.json # Traducciones y textos
│   ├── MAPA_NAVEGACION_ESCANEADOR.md # Mapa de navegación
│   └── ...
├── logs/                   # Resultados de escaneo, actividad y logs de la aplicación
│   ├── aresitos_errores.log
│   ├── ...
├── reportes/               # Reportes generados (JSON, TXT, CSV)
├── documentacion/          # Manuales técnicos, arquitectura, guías de instalación y uso
│   ├── GUIA_TECNICA_ARESITOS.md
│   ├── GUIA_INSTALACION.md
│   └── ...
├── main.py                 # Script principal de arranque de la aplicación
├── configurar_kali.sh      # Script de configuración y dependencias para Kali Linux
├── requirements.txt        # Requisitos Python (solo para desarrollo, no se usan librerías externas en producción)
├── pyproject.toml          # Configuración de proyecto Python
├── LICENSE                 # Licencia del proyecto
└── README.md               # Documentación principal del proyecto
```

**Explicación concreta:**
- El proyecto sigue una arquitectura estricta MVC, donde cada carpeta tiene una responsabilidad clara y separada.
- Los controladores gestionan la lógica de negocio y la interacción entre la interfaz gráfica (vistas) y los datos (modelos).
- El sistema es robusto, modular, seguro y fácilmente extensible, cumpliendo los principios SOLID y DRY.

- **Cuarentena:** aislamiento de archivos sospechosos, preservación de evidencia
- **Reportes:** exportación en JSON, TXT, CSV
- **Inteligencia:** base de datos de vulnerabilidades, wordlists, diccionarios, cheatsheets
- **Auditoría:** integración con lynis y chkrootkit
- **Logs:** carpeta `logs/` con resultados de escaneo y actividad

**Sanitización y seguridad:**
- Validación de extensiones, nombres, rutas y tipos MIME en subida de archivos
- Módulo de sanitización en `utils/sanitizador_archivos.py`

**Documentación y soporte**
Manuales y guías disponibles:

- `DOCUMENTACION_TECNICA_CONSOLIDADA.md`: Manual técnico completo y actualizado del sistema.
- `ARQUITECTURA_DESARROLLO.md`: Guía de arquitectura, patrones y estructura del proyecto.
- `AUDITORIA_SEGURIDAD_ARESITOS.md`: Auditoría de seguridad, controles y recomendaciones.
- `GUIA_INSTALACION.md`: Guía de instalación, solución de problemas y mejores prácticas.
- `HERRAMIENTAS_FASE_3_ACTUALIZACION.md`: Herramientas avanzadas y configuraciones de Fase 3.
- `REVISION_MVC_ARESITOS.md`: Revisión exhaustiva de conexiones y flujos MVC.
- `SANITIZACION_ARCHIVOS.md`: Resumen de la implementación de seguridad en carga de archivos.
- `TERMINAL_INTEGRADO.md`: Manual del terminal integrado y sus ventajas.

Repositorio oficial: https://github.com/DogSoulDev/aresitos
Email: dogsouldev@protonmail.com
- Módulo de sanitización en `utils/sanitizador_archivos.py`

---

## Documentación y soporte

**Manuales y guías disponibles:**
- [`DOCUMENTACION_TECNICA_CONSOLIDADA.md`](documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md): Manual técnico completo y actualizado del sistema.
- [`ARQUITECTURA_DESARROLLO.md`](documentacion/ARQUITECTURA_DESARROLLO.md): Guía de arquitectura, patrones y estructura del proyecto.
- [`AUDITORIA_SEGURIDAD_ARESITOS.md`](documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md): Auditoría de seguridad, controles y recomendaciones.
- [`GUIA_INSTALACION.md`](documentacion/GUIA_INSTALACION.md): Guía de instalación, solución de problemas y mejores prácticas.
- [`HERRAMIENTAS_FASE_3_ACTUALIZACION.md`](documentacion/HERRAMIENTAS_FASE_3_ACTUALIZACION.md): Herramientas avanzadas y configuraciones de Fase 3.
- [`REVISION_MVC_ARESITOS.md`](documentacion/REVISION_MVC_ARESITOS.md): Revisión exhaustiva de conexiones y flujos MVC.
- [`SANITIZACION_ARCHIVOS.md`](documentacion/SANITIZACION_ARCHIVOS.md): Resumen de la implementación de seguridad en carga de archivos.
- [`TERMINAL_INTEGRADO.md`](documentacion/TERMINAL_INTEGRADO.md): Manual del terminal integrado y sus ventajas.

Repositorio oficial: https://github.com/DogSoulDev/aresitos
Email: dogsouldev@protonmail.com

---

## Licencia y uso ético

**Open Source Non-Commercial License**

**Permitido:**
- Educación, investigación, testing en sistemas propios o autorizados, proyectos open source sin monetización, aprendizaje y comunidad.

**Prohibido:**
- Venta, consultoría comercial, productos comerciales, monetización, SaaS o servicios gestionados.

**Atribución obligatoria:**
- Creador: DogSoulDev
- Contacto: dogsouldev@protonmail.com
- Fuente: https://github.com/DogSoulDev/aresitos
- Licencia: Open Source Non-Commercial

**Código de ética:**
- Solo sistemas autorizados (permiso explícito)
- Propósitos constructivos
- Divulgación responsable
- Prohibido hacking malicioso o daño intencional

---

## Reconocimientos y agradecimientos

Este proyecto no habría sido posible sin el apoyo y la formación recibida en el Campus Internacional de Ciberseguridad y la Universidad Católica San Antonio de Murcia (UCAM).

---



## Instalación manual paso a paso (alternativa)

Si la instalación rápida falla o tienes un entorno personalizado, puedes instalar ARESITOS manualmente siguiendo estos pasos:

1. **Clona el repositorio y entra en la carpeta:**
   ```sh
   git clone https://github.com/DogSoulDev/aresitos.git
   cd aresitos
   ```
2. **Instala dependencias del sistema (Kali Linux):**
   ```sh
   sudo apt update && sudo apt install -y python3 python3-tk python3-venv nmap masscan nuclei gobuster ffuf feroxbuster wireshark autopsy sleuthkit hashdeep testdisk bulk-extractor dc3dd guymager git curl wget sqlite3
   ```
3. **Da permisos de ejecución a los scripts principales:**
   ```sh
   chmod +x configurar_kali.sh main.py
   ```
4. **Configura permisos para los archivos Python (opcional):**
   ```sh
   find . -name "*.py" -exec chmod +x {} \;
   ```
5. **Configura permisos para carpetas de datos y logs:**
   ```sh
   chmod -R 755 data/ logs/ configuración/
   ```
6. **Ejecuta el script de configuración (como root o con sudo):**
   ```sh
   sudo ./configurar_kali.sh
   ```
7. **Inicia la aplicación:**
   ```sh
   python3 main.py
   ```

> **Nota:** Si usas otra distribución Linux, adapta los comandos de instalación de dependencias a tu gestor de paquetes (por ejemplo, `apt`, `dnf`, `yum`, `zypper`, etc.).

---

## Solución de problemas de instalación

- Si ves errores de permisos, ejecuta:
  ```sh
  chmod -R 755 data/ logs/ configuración/
  find . -name "*.py" -exec chmod +x {} \;
  ```
- Si falta alguna dependencia, instálala manualmente con `sudo apt install <paquete>`.
- Si usas entorno Python gestionado (externally-managed), instala dependencias vía APT, no con pip.
- Si tienes problemas con la interfaz gráfica, asegúrate de tener instalado `python3-tk`.
- Si el script de configuración no detecta alguna herramienta, instálala manualmente y vuelve a ejecutar el script.
- Consulta la guía `documentacion/GUIA_INSTALACION.md` para más detalles y soluciones avanzadas.

---

---

## DEDICATORIA

En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.

---