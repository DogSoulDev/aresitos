> **Recomendación importante:**
>
> Antes de instalar o ejecutar ARESITOS, asegúrate de tener tu sistema Kali Linux completamente actualizado para evitar problemas de dependencias o incompatibilidades:
>
> ```sh
> sudo apt update && sudo apt upgrade -y
> ```
>

![ARESITOS](aresitos/recursos/aresitos.png)

# ARESITOS - Herramienta de Ciberseguridad

ARESITOS es una herramienta de ciberseguridad 100% Python nativo (sin librerías externas) para sistemas operativos Kali Linux. Integra escaneo de vulnerabilidades, SIEM, FIM, cuarentena, dashboard, reportes y utilidades forenses, todo bajo arquitectura MVC y principios SOLID/DRY. El sistema aprovecha herramientas nativas de Kali Linux y automatiza su verificación e instalación, garantizando robustez, seguridad y compatibilidad total con entornos forenses y de auditoría.

**Principales módulos:**

## Seguridad avanzada y protección anti-logout

ARESITOS implementa una doble capa de protección para evitar que cualquier acción de usuario (botón, terminal, herramienta forense) pueda provocar un cierre de sesión (logout), crash del entorno gráfico o ejecución de comandos peligrosos en Kali Linux.

**1. Protección anti-logout/crash en detención de procesos**
El sistema unificado de detención de procesos (`utils/detener_procesos.py`) filtra y protege explícitamente procesos de sesión, terminales, shells y servicios críticos. Ejemplo real:

```python
procesos_protegidos = [
	'systemd', 'init', 'login', 'sshd', 'Xorg', 'gdm', 'lightdm', 'NetworkManager',
	'dbus-daemon', 'udisksd', 'polkitd', 'upowerd', 'wpa_supplicant', 'gnome-shell',
	'plasmashell', 'xfce4-session', 'lxsession', 'openbox', 'kdeinit', 'kded', 'kdm',
	'sddm', 'agetty', 'bash', 'zsh', 'fish', 'pwsh', 'tmux', 'screen', 'python', 'python3',
	<p align="center">
]
if any(p in comando for p in procesos_protegidos):
	callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) no será terminado por seguridad\n")
	continue
# Protección extra: no matar procesos con DISPLAY/XDG_SESSION/TTY de usuario
try:
	environ = subprocess.check_output(['cat', f'/proc/{pid}/environ']).decode(errors='ignore')
		callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) tiene entorno gráfico/terminal, no será terminado\n")
		continue
except Exception:
	pass
```

**2. Validación de comandos peligrosos en terminales y herramientas**
El validador de comandos (`utils/seguridad_comandos.py`) bloquea comandos peligrosos como:

```python
self.comandos_prohibidos = [
	'kill', 'pgrep', 'pkill', 'shutdown', 'reboot', 'poweroff', 'init', 'telinit',
	'bash', 'sh', 'zsh', 'fish', 'exec', 'eval', 'source', 'su', 'sudo', 'passwd',
	# ...otros comandos peligrosos...
]
```

**Ejemplo real de uso en la vista de reportes:**
```python
def ejecutar_comando_entry(self, event=None):
	comando = self.comando_entry.get().strip()
	from aresitos.utils.seguridad_comandos import validador_comandos
	es_valido, comando_sanitizado, mensaje = validador_comandos.validar_comando_completo(comando)
	if not es_valido:
		self.terminal_output.insert(tk.END, f"{mensaje}\n")
		return
	# ...ejecutar comando seguro...
```

**Resultado:**
- Ningún botón de "detener/cancelar" puede provocar logout ni crash de sesión.
- No es posible ejecutar comandos que puedan cerrar sesión, matar procesos críticos o comprometer la estabilidad del sistema desde ningún terminal integrado ni vista de ARESITOS.
- Escaneo de vulnerabilidades (nmap, masscan, nuclei, gobuster, ffuf, feroxbuster)
- SIEM: monitoreo de puertos, correlación de eventos, alertas
- FIM: vigilancia de integridad de archivos y directorios
- Cuarentena: aislamiento y gestión de archivos sospechosos
- Dashboard: métricas, estado de servicios, historial de terminal
- Reportes: exportación en JSON, TXT, CSV
- Integración forense: autopsy, sleuthkit, wireshark, hashdeep, etc.

### Instalación rápida (Kali Linux recomendado)
```bash
git clone https://github.com/DogSoulDev/aresitos.git

> **Importante:**
> - No ejecutes main.py con sudo. El propio programa solicitará privilegios solo cuando sea necesario.
> - Tras ejecutar `sudo ./configurar_kali.sh`, ejecuta siempre los comandos de `chown` y `chmod` anteriores para evitar problemas de acceso.
> - El sistema detecta y verifica automáticamente todas las herramientas requeridas, mostrando advertencias y permitiendo instalación guiada desde la interfaz.

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

## DEDICATORIA

En Memoria de Ares
*25 de Abril 2013 - 5 de Agosto 2025*
Hasta que volvamos a vernos.
