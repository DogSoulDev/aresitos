
![ARESITOS](aresitos/recursos/aresitos.png)

# ARESITOS - Herramienta de Ciberseguridad

Herramienta de Ciberseguridad para Kali Linux: escaneo de vulnerabilidades, SIEM, FIM, cuarentena y dashboard integrados.


### Instalación rápida (Kali Linux recomendado)
```bash
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh main.py
sudo ./configurar_kali.sh
# MUY IMPORTANTE: SIEMPRE ejecuta estos comandos de permisos DESPUÉS de usar sudo ./configurar_kali.sh
# Esto asegura que tu usuario tenga acceso a las carpetas creadas por root durante la configuración
sudo chown -R $USER:$USER aresitos/data/cuarentena
chmod -R 755 aresitos/data/cuarentena
python3 main.py
```
> **Importante:** Si tienes errores de permisos, asegúrate de que los scripts principales tengan permisos de ejecución **y que la carpeta `aresitos/data/cuarentena` sea escribible por tu usuario**. Si ejecutas `sudo ./configurar_kali.sh`, es obligatorio ejecutar los comandos de `chown` y `chmod` después:
> ```bash
> sudo chown -R $USER:$USER aresitos/data/cuarentena
> chmod -R 755 aresitos/data/cuarentena
> ```
> No ejecutes main.py con sudo. El propio programa te pedirá la contraseña root cuando sea necesario.

### Herramientas forenses opcionales
```bash
sudo apt install kali-tools-forensics wireshark autopsy sleuthkit
```

### Modo desarrollo (otros sistemas)
```bash
python3 main.py --dev
```

### Requisitos principales

- **Espacio en disco ocupado (instalación base):** ~19 MB
- **Número de archivos del proyecto:** 1340
- **RAM recomendada:** mínimo 1 GB libre (uso típico bajo, depende de los módulos activos)
- **Espacio recomendado para datos:** 20 MB libres adicionales para bases de datos, cuarentena y reportes

- Python 3.8+
- Kali Linux 2025 (recomendado)
- nmap, masscan, nuclei, gobuster, ffuf, feroxbuster, wireshark, autopsy, sleuthkit, git, curl, wget, sqlite3, python3-tk, python3-venv

---

## Flujo de uso
1. **Login**: Verifica entorno, dependencias y permisos.
2. **Herramientas**: Configura y valida herramientas de Kali Linux.
3. **Principal**: Acceso a dashboard, escaneo, SIEM, FIM, cuarentena y reportes.

---

## Capturas de pantalla

![Vista Login](aresitos/recursos/vista_login.png)
![Vista Herramientas](aresitos/recursos/vista_herramientas.png)
![Vista Principal](aresitos/recursos/vista_principal.png)

---


## Arquitectura y estructura del proyecto

**Modelo-Vista-Controlador (MVC) + Principios SOLID**

```
aresitos/
├── controlador/     # Controladores principales y secundarios. Orquestan la lógica de negocio, gestionan la interacción entre vistas y modelos, y coordinan módulos como escaneo, SIEM, FIM, cuarentena, reportes, monitoreo, herramientas, auditoría, etc.
│   ├── controlador_principal.py      # Punto de entrada de la lógica de control
│   ├── controlador_escaneo.py       # Lógica de escaneo de vulnerabilidades
│   ├── controlador_reportes.py      # Generación y gestión de reportes
│   └── ...                          # Otros controladores especializados
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
├── utils/           # Utilidades y módulos auxiliares: configuración, detección de red, sanitización, permisos, iconos, etc.
│   ├── configurar.py                 # Configuración y utilidades generales
│   ├── detector_red.py               # Detección de red y objetivos
│   ├── sanitizador_archivos.py       # Sanitización y validación de archivos
│   └── ...                          # Otros scripts de soporte
├── recursos/        # Imágenes, iconos, favicon, capturas de pantalla y recursos gráficos
│   ├── aresitos.png                  # Favicon principal
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
- Los modelos encapsulan el acceso y la gestión de datos, bases de datos, cuarentena, FIM, SIEM, wordlists y reportes.
- Las vistas implementan la interfaz gráfica en Tkinter, con paneles independientes para cada módulo (dashboard, escaneo, reportes, monitoreo, etc.), integrando un terminal interactivo y soporte para temas visuales.
- Los módulos utils proporcionan utilidades nativas para detección de red, configuración, sanitización de archivos, gestión de permisos y recursos gráficos.
- Toda la lógica es Python nativo, sin librerías externas, y aprovecha herramientas y comandos de Kali Linux para las funciones avanzadas de ciberseguridad.
- El sistema es robusto, modular, seguro y fácilmente extensible, cumpliendo los principios SOLID y DRY.

**Componentes técnicos principales:**
- Escaneador profesional: nmap, masscan, nuclei, gobuster, ffuf, feroxbuster
- SIEM: monitoreo de puertos críticos, correlación de eventos, alertas
- FIM: vigilancia de directorios, detección de cambios, hashes SHA256
- Cuarentena: aislamiento de archivos sospechosos, preservación de evidencia
- Dashboard: métricas, estado de servicios, historial de terminal
- Reportes: exportación en JSON, TXT, CSV
- Inteligencia: base de datos de vulnerabilidades, wordlists, diccionarios, cheatsheets
- Auditoría: integración con lynis y chkrootkit

**Persistencia y logs:**
- Bases de datos SQLite: `fim_kali2025.db`, `cuarentena_kali2025.db`, `siem_aresitos.db`
- Configuración: `aresitos_config_completo.json`, `textos_castellano_corregido.json`
- Logs: carpeta `logs/` con resultados de escaneo y actividad

**Sanitización y seguridad:**
- Validación de extensiones, nombres, rutas y tipos MIME en subida de archivos
- Módulo de sanitización en `utils/sanitizador_archivos.py`
- Capas de seguridad para evitar ejecución de archivos peligrosos

**Integración de herramientas externas:**
- Detección automática de herramientas instaladas
- Configuración de permisos CAP_NET_RAW para escaneos SYN
- Actualización automática de templates nuclei y diccionarios

---

## Comandos útiles

```bash
# Verificar estado y dependencias del sistema
python3 verificacion_final.py

# Ejecutar Aresitos (modo normal)
python3 main.py

# Ejecutar en modo desarrollo (otros sistemas)
python3 main.py --dev

# Actualizar configuración y herramientas de Kali
sudo ./configurar_kali.sh --update

# Debug avanzado del escaneador
python3 main.py --verbose --scanner-debug

# Actualizar templates de nuclei
sudo nuclei -update-templates
```

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

## DEDICATORIA ESPECIAL

En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.
