# ARESITOS - Herramienta de Ciberseguridad

![ARESITOS](aresitos/recursos/aresitos.png)

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
sudo apt install kali-tools-forensics wireshark autopsy sleuthkit hashdeep testdisk plaso bulk-extractor dc3dd guymager
```

### Modo desarrollo (otros sistemas)
```bash
python3 main.py --dev
```

> **Nota:** El modo desarrollo solo habilita la interfaz gráfica y utilidades básicas. Las funciones avanzadas requieren Kali Linux y privilegios adecuados.

### Requisitos principales
- **Python:** 3.8 o superior
- **Sistema operativo:** Kali Linux 2025 (recomendado, soporte parcial en otros Linux)
- **Dependencias nativas:** nmap, masscan, nuclei, gobuster, ffuf, feroxbuster, wireshark, autopsy, sleuthkit, hashdeep, testdisk, foremost, plaso, bulk-extractor, dc3dd, guymager, git, curl, wget, sqlite3, python3-tk, python3-venv
- **Espacio en disco ocupado (instalación base):** ~19 MB
- **RAM recomendada:** mínimo 1 GB libre (uso típico bajo, depende de los módulos activos)
- **Espacio recomendado para datos:** 20 MB libres adicionales para bases de datos, cuarentena y reportes

---

## Flujo de uso
1. **Login**: Verificación automática de entorno, dependencias, permisos y privilegios.
2. **Herramientas**: Detección, verificación visual (check verde/cruz roja) e instalación guiada de todas las herramientas requeridas.
3. **Principal**: Acceso a dashboard, escaneo, SIEM, FIM, cuarentena, monitoreo y reportes.

---

## Capturas de pantalla

![Vista Login](aresitos/recursos/capturas/vista_login.png)
![Vista Herramientas](aresitos/recursos/capturas/vista_herramientas.png)
![Vista Principal](aresitos/recursos/capturas/vista_principal.png)

---

## Arquitectura y estructura del proyecto

**Modelo-Vista-Controlador (MVC) + Principios SOLID**

```
aresitos/
├── controlador/     # Controladores principales y secundarios. Orquestan la lógica de negocio, gestionan la interacción entre vistas y modelos, y coordinan módulos como escaneo, SIEM, FIM, cuarentena, reportes, monitoreo, herramientas, auditoría, etc.
│   ├── controlador_principal.py      # Punto de entrada de la lógica de control
│   ├── controlador_escaneo.py       # Lógica de escaneo de vulnerabilidades
│   ├── controlador_reportes.py      # Generación y gestión de reportes
├── modelo/          # Modelos de datos, acceso a bases SQLite, gestión de wordlists, diccionarios, cuarentena, FIM, SIEM, reportes, etc.
│   ├── modelo_principal.py          # Modelo principal de la aplicación
│   ├── modelo_cuarentena.py         # Gestión de archivos en cuarentena
│   ├── modelo_fim.py                # Integridad de archivos (FIM)
│   └── ...                          # Otros modelos de datos
├── vista/           # Interfaz gráfica Tkinter: paneles, terminal integrado, dashboard, escaneo, reportes, monitoreo, herramientas, etc.
│   ├── vista_principal.py           # Vista principal y orquestación de paneles
│   ├── vista_dashboard.py           # Dashboard de métricas y terminal
│   ├── vista_escaneo.py             # Panel de escaneo de vulnerabilidades
│   ├── vista_reportes.py            # Panel de reportes
│   └── ...                          # Otras vistas especializadas
├── utils/           # Utilidades y módulos auxiliares: configuración, detección de red, sanitización, permisos, comandos, detección de sistema, iconos, etc.
│   ├── configurar.py                 # Configuración y utilidades generales
│   ├── detector_red.py               # Detección de red y objetivos
│   ├── sanitizador_archivos.py       # Sanitización y validación de archivos
│   ├── comandos_sistema.py           # Verificación centralizada de comandos/herramientas
│   ├── detector_sistema.py           # Detección robusta de sistema operativo/distribución
│   ├── permisos_sistema.py           # Verificación de root/admin multiplataforma
│   └── ...                          # Otros scripts de soporte
├── recursos/        # Imágenes, iconos, capturas de pantalla y recursos gráficos
│   ├── aresitos.png                  # Icono principal
│   ├── iconos/                      # Iconos adicionales
│   └── ...
├── data/            # Datos persistentes: bases de datos SQLite, cuarentena, wordlists, diccionarios, cheatsheets
│   ├── fim_kali2025.db               # Base de datos de integridad de archivos
│   ├── cuarentena_kali2025.db        # Base de datos de cuarentena
│   ├── wordlists/                    # Wordlists para escaneo y fuerza bruta
│   └── ...
├── configuración/   # Archivos de configuración JSON, textos, mapas de navegación, traducciones
│   ├── aresitos_config_completo.json # Configuración global
│   ├── textos_castellano_corregido.json # Traducciones y textos
│   └── ...
├── logs/            # Resultados de escaneo, actividad y logs de la aplicación
├── reportes/        # Reportes generados (JSON, TXT, CSV)
├── documentacion/   # Manuales técnicos, arquitectura, guías de instalación y uso
├── main.py          # Script principal de arranque de la aplicación
├── configurar_kali.sh # Script de configuración y dependencias para Kali Linux
├── requirements.txt # Requisitos Python (solo para desarrollo, no se usan librerías externas en producción)
└── README.md        # Documentación principal del proyecto
```

**Explicación concreta:**
- El proyecto sigue una arquitectura estricta MVC, donde cada carpeta tiene una responsabilidad clara y separada.
- Los controladores gestionan la lógica de negocio y la interacción entre la interfaz gráfica (vistas) y los datos (modelos).
- El sistema es robusto, modular, seguro y fácilmente extensible, cumpliendo los principios SOLID y DRY.

- Cuarentena: aislamiento de archivos sospechosos, preservación de evidencia
- Reportes: exportación en JSON, TXT, CSV
- Inteligencia: base de datos de vulnerabilidades, wordlists, diccionarios, cheatsheets
- Auditoría: integración con lynis y chkrootkit
- Logs: carpeta `logs/` con resultados de escaneo y actividad
**Sanitización y seguridad:**
- Validación de extensiones, nombres, rutas y tipos MIME en subida de archivos
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

## Logos institucionales

<p align="center">
  <img src="aresitos/recursos/tfm/logo.png" alt="Logo TFM" width="120" style="margin: 0 20px;"/>
  <img src="aresitos/recursos/tfm/logo_tele.png" alt="Logo Teleco" width="120" style="margin: 0 20px;"/>
  <img src="aresitos/recursos/tfm/logo_uni.png" alt="Logo UCAM" width="120" style="margin: 0 20px;"/>
</p>

---

## DEDICATORIA

En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.
