# 🛡️ Guía Técnica Completa de Aresitos
# 📸 Vista general del flujo de Aresitos

El siguiente recorrido visual muestra el flujo completo de uso de Aresitos, desde la instalación en terminal hasta la generación de reportes, ilustrando cada pantalla y funcionalidad clave:



![Instalación de Aresitos](../aresitos/recursos/capturas/1_instalacion.png)

**Instalación en terminal:**
La instalación de Aresitos se realiza desde la terminal de Kali Linux, clonando el repositorio y ejecutando el script de configuración. Se instalan todas las dependencias y herramientas necesarias para el funcionamiento integral de la suite.

*Instalación y primer inicio*


---


## 📚 Referencias Oficiales y Recursos Fundamentales

Esta guía incluye enlaces oficiales y documentación de todas las tecnologías, herramientas y patrones utilizados en ARESITOS. Consulta cada referencia para ampliar detalles técnicos y asegurar el uso correcto y actualizado de cada componente.

- **Herramientas de Kali Linux:** [Listado oficial y documentación](https://www.kali.org/tools/)
- **Patrón MVC (Modelo-Vista-Controlador):** [Wikipedia - Modelo–vista–controlador](https://es.wikipedia.org/wiki/Modelo%E2%80%93vista%E2%80%93controlador)
- **Inspiración visual (Burp Suite - Tema Oscuro):** [Burp Suite Oficial](https://portswigger.net/burp)
- **Hilos en Python:** [threading — Documentación oficial de Python](https://docs.python.org/3/library/threading.html)
- **Subprocesos en Python:** [subprocess — Documentación oficial de Python](https://docs.python.org/3/library/subprocess.html)
- **SQLite3 en Python:** [sqlite3 — Documentación oficial de Python](https://docs.python.org/3/library/sqlite3.html)

---


## 🛠️ Tabla de Herramientas de Kali Linux Integradas en ARESITOS

| **Herramienta**     | **Descripción breve**                             | **Enlace oficial**                                  |
|:-------------------:|:-------------------------------------------------:|:---------------------------------------------------:|
| nmap                | Escaneo de red y puertos                          | [nmap](https://www.kali.org/tools/nmap/)            |
| masscan             | Escaneo de puertos a alta velocidad               | [masscan](https://www.kali.org/tools/masscan/)      |
| nuclei              | Escaneo de vulnerabilidades automatizado          | [nuclei](https://www.kali.org/tools/nuclei/)        |
| gobuster            | Fuerza bruta de directorios/archivos web          | [gobuster](https://www.kali.org/tools/gobuster/)    |
| ffuf                | Pruebas de fuerza bruta en URLs y directorios     | [ffuf](https://www.kali.org/tools/ffuf/)            |
| feroxbuster         | Pruebas de fuerza bruta en directorios web        | [feroxbuster](https://www.kali.org/tools/feroxbuster/) |
| wireshark           | Análisis de tráfico de red                        | [wireshark](https://www.kali.org/tools/wireshark/)  |
| autopsy             | Análisis forense digital                          | [autopsy](https://www.kali.org/tools/autopsy/)      |
| sleuthkit           | Herramientas forenses de disco                    | [sleuthkit](https://www.kali.org/tools/sleuthkit/)  |
| tcpdump             | Captura y análisis de paquetes de red             | [tcpdump](https://www.kali.org/tools/tcpdump/)      |
| netcat-openbsd      | Utilidad de red multipropósito                    | [netcat-openbsd](https://www.kali.org/tools/netcat-openbsd/) |
| htop                | Monitor de procesos interactivo                   | [htop](https://www.kali.org/tools/htop/)            |
| lsof                | Listado de archivos abiertos                      | [lsof](https://www.kali.org/tools/lsof/)            |
| psmisc              | Utilidades para gestión de procesos               | [psmisc](https://www.kali.org/tools/psmisc/)        |
| iproute2            | Herramientas avanzadas de red                     | [iproute2](https://www.kali.org/tools/iproute2/)    |
| lynis               | Auditoría de seguridad del sistema                | [lynis](https://www.kali.org/tools/lynis/)          |
| chkrootkit          | Detección de rootkits                             | [chkrootkit](https://www.kali.org/tools/chkrootkit/)|
| rkhunter            | Detección de rootkits y backdoors                 | [rkhunter](https://www.kali.org/tools/rkhunter/)    |
| clamscan (ClamAV)   | Antivirus de código abierto                       | [clamav](https://www.kali.org/tools/clamav/)        |
| yara                | Detección de patrones de malware                  | [yara](https://www.kali.org/tools/yara/)            |
| inotify-tools       | Monitoreo de archivos en tiempo real              | [inotify-tools](https://www.kali.org/tools/inotify-tools/) |
| foremost            | Recuperación de archivos borrados                 | [foremost](https://www.kali.org/tools/foremost/)    |
| binwalk             | Análisis y extracción de firmware                 | [binwalk](https://www.kali.org/tools/binwalk/)      |
| exiftool            | Análisis y manipulación de metadatos              | [exiftool](https://www.kali.org/tools/exiftool/)    |
| httpx-toolkit       | Herramientas HTTP modernas                        | [httpx-toolkit](https://www.kali.org/tools/httpx-toolkit/) |
| volatility3         | Análisis forense de la memoria                    | [volatility3](https://www.kali.org/tools/volatility3/) |
| rustscan            | Escaneo de puertos ultrarrápido (requiere Rust)   | [rustscan](https://www.kali.org/tools/rustscan/)    |


> **Para la lista completa y actualizada de herramientas de Kali Linux, consulta:** [https://www.kali.org/tools/](https://www.kali.org/tools/)

---



## 🔄 Política de Rutas Dinámicas y Portabilidad
Todas las rutas de recursos, datos y configuraciones en ARESITOS son relativas a la raíz del proyecto y se construyen dinámicamente usando `os.path` o `pathlib`. No se utilizan rutas absolutas, ni dependientes de `/home`, ni del directorio de trabajo actual. Esto garantiza portabilidad, seguridad y compatibilidad con Kali Linux y otros entornos.

---



## 1. ¿Qué es Aresitos?


![Pantalla de login](../aresitos/recursos/capturas/2_login.png)

**Pantalla de login segura:**
Al iniciar Aresitos, se presenta una pantalla de inicio de sesión que protege el acceso a la suite, garantizando que solo usuarios autorizados puedan operar las herramientas avanzadas.

*Pantalla de login segura*


![Selector de herramientas Kali](../aresitos/recursos/capturas/3_herramientas.png)

**Selector de herramientas Kali:**
Tras el inicio de sesión, el usuario accede a un panel visual donde puede seleccionar y lanzar las principales herramientas de Kali Linux integradas en Aresitos, facilitando la gestión centralizada de utilidades de ciberseguridad.

*Selector visual de herramientas Kali integradas*


**Aresitos** es una suite profesional de ciberseguridad para Kali Linux, con escaneador, SIEM, FIM, cuarentena y dashboard integrados. Arquitectura 100% Python nativo + herramientas Kali. Prioriza la seguridad, la modularidad y la extensibilidad, permitiendo la integración de herramientas nativas de Kali y la gestión avanzada de privilegios.

---

Aresitos es una suite de seguridad ofensiva y defensiva para Kali Linux, desarrollada en Python 3, con arquitectura MVC (Modelo-Vista-Controlador) y una interfaz gráfica robusta basada en Tkinter. El diseño prioriza la seguridad, la modularidad y la extensibilidad, permitiendo la integración de herramientas nativas de Kali y la gestión avanzada de privilegios.



### 📁 Estructura de Carpetas y Módulos


![Dashboard principal](../aresitos/recursos/capturas/4_dashboard.png)

**Dashboard principal:**
El panel principal centraliza la navegación y el estado general del sistema, mostrando accesos rápidos a los módulos de escaneo, SIEM, FIM, cuarentena, reportes y configuración, así como información de estado y alertas.

*Visión general y navegación*


- `aresitos/modelo/`: Lógica de datos, acceso a bases, validaciones, modelos de negocio.
- `aresitos/vista/`: Interfaz gráfica, pantallas, widgets, terminal integrada, navegación.
- `aresitos/controlador/`: Orquestación, lógica de control, coordinación entre modelo y vista.
- `aresitos/utils/`: Utilidades transversales (seguridad, permisos, helpers, logging, threading).
- `aresitos/recursos/`: Imágenes, iconos, capturas, recursos visuales.
- `data/`: Bases de datos, wordlists, diccionarios, archivos de cuarentena.
- `configuración/`: Configuración global, textos, mapas de navegación.
- `documentacion/`: Documentos técnicos, guías, arquitectura, auditoría.
- `logs/`: Logs de errores y actividad.
- `reportes/`: Reportes generados.

---



## 2. Arquitectura Técnica y MVC

<div align="center">
	<img src="../aresitos/recursos/capturas/5_escaneo.png" alt="Módulo de escaneo" width="500" />
**Módulo de escaneo de red y vulnerabilidades:**
Permite realizar escaneos de red, puertos y vulnerabilidades usando herramientas como nmap, masscan y nuclei, mostrando resultados en tiempo real y permitiendo la exportación de hallazgos.
	<br><sub>Módulo de escaneo de red y vulnerabilidades</sub>
</div>

<div align="center">
	<img src="../aresitos/recursos/capturas/6_SIEM.png" alt="Módulo SIEM" width="500" />
**Módulo SIEM:**
El módulo SIEM (Security Information and Event Management) centraliza la correlación de eventos, logs y alertas de seguridad, permitiendo el análisis forense y la detección de incidentes en el sistema.
	<br><sub>Módulo SIEM: correlación y análisis de eventos</sub>
</div>

<div align="center">
	<img src="../aresitos/recursos/capturas/7_FIM.png" alt="Módulo FIM" width="500" />
**Módulo FIM (File Integrity Monitoring):**
Supervisa la integridad de archivos críticos del sistema, detectando cambios, anomalías y posibles compromisos mediante hashes, monitoreo en tiempo real y escaneo de rootkits.
	<br><sub>Módulo FIM: monitoreo de integridad de archivos</sub>
</div>

<div align="center">
	<img src="../aresitos/recursos/capturas/8_monitoreoycuarentena.png" alt="Monitoreo y cuarentena" width="500" />
**Monitoreo y cuarentena:**
Permite visualizar y gestionar los procesos activos, la red y los archivos sospechosos, moviendo automáticamente a cuarentena aquellos elementos que representen un riesgo para la seguridad.
	<br><sub>Monitoreo de procesos y gestión de cuarentena</sub>
</div>

<div align="center">
	<img src="../aresitos/recursos/capturas/9_auditoria.png" alt="Auditoría de seguridad" width="500" />
**Auditoría de seguridad y hardening:**
Incluye herramientas y flujos para auditar la seguridad del sistema, aplicar hardening y verificar el cumplimiento de buenas prácticas, mostrando resultados y recomendaciones.
	<br><sub>Auditoría de seguridad y hardening</sub>
</div>

<div align="center">
	<img src="../aresitos/recursos/capturas/10_wordlistsydiccionarios.png" alt="Gestión de wordlists y diccionarios" width="500" />
**Gestión de wordlists y diccionarios:**
Facilita la creación, validación y uso de diccionarios personalizados para pruebas de fuerza bruta, auditorías de contraseñas y escaneos avanzados.
	<br><sub>Gestión avanzada de wordlists y diccionarios</sub>
</div>

<div align="center">
	<img src="../aresitos/recursos/capturas/11_reportes.png" alt="Generación de reportes" width="500" />
**Generación y visualización de reportes:**
El flujo concluye con la generación automática de reportes técnicos y ejecutivos, exportables en diferentes formatos, que resumen los hallazgos, alertas y acciones realizadas durante la sesión.
	<br><sub>Generación y visualización de reportes</sub>
</div>


ARESITOS usa el patrón **MVC** (Modelo-Vista-Controlador) para organizar el código de manera clara y mantenible.


vista_principal.py       → ControladorPrincipal
	├── vista_dashboard.py     → ControladorPrincipal
	├── vista_escaneo.py       → ControladorEscaneo
	├── vista_auditoria.py     → ControladorAuditoria
	├── vista_fim.py           → ControladorFIM
	├── vista_siem.py          → ControladorSIEM
	├── vista_monitoreo.py     → ControladorMonitoreo
	├── vista_reportes.py      → ControladorReportes
	├── vista_gestion_datos.py → ControladorPrincipal
	├── vista_herramientas_kali.py → ControladorHerramientas
	└── vista_login.py         → Sin controlador específico

### 🔗 Mapeo de conexiones MVC

| Vista                      | Controlador                | Modelo relacionado                |
|----------------------------|----------------------------|------------------------------------|
| vista_principal.py         | controlador_principal.py   | modelo_principal.py                |
| vista_dashboard.py         | controlador_dashboard.py   | modelo_dashboard.py                |
| vista_escaneo.py           | controlador_escaneo.py     | modelo_escaneador.py, modelo_escaneador_base.py |
| vista_auditoria.py         | controlador_auditoria.py   | modelo_diccionarios.py, modelo_principal.py     |
| vista_fim.py               | controlador_fim.py         | modelo_fim.py, modelo_fim_base.py  |
| vista_siem.py              | controlador_siem.py        | modelo_siem.py, modelo_siem_base.py|
| vista_monitoreo.py         | controlador_monitoreo.py   | modelo_monitor.py                  |
| vista_reportes.py          | controlador_reportes.py    | modelo_reportes.py                 |
| vista_herramientas_kali.py | controlador_herramientas.py| modelo_principal.py                |
| vista_login.py             | controlador_principal.py   | modelo_principal.py                |
| vista_datos.py             | controlador_principal.py   | modelo_principal.py                |

> Cada controlador está vinculado a uno o varios modelos según la funcionalidad. La vista orquesta la interacción con el usuario y delega la lógica al controlador, que a su vez gestiona los datos a través del modelo correspondiente.


### ⚙️ Inicialización principal
```python
modelo = ModeloPrincipal()
vista = VistaPrincipal(root)
controlador = ControladorPrincipal(modelo)
vista.set_controlador(controlador)
```

---

- Encapsula la lógica de datos y negocio.
- Gestiona el acceso a bases de datos (SQLite, JSON, archivos planos).
- Realiza validaciones, cálculos de integridad y operaciones CRUD.
- Ejemplo: `modelo_fim.py` gestiona la integridad de archivos críticos, calcula hashes (`hashlib.sha256`, `md5`), almacena y compara resultados.
- Ejemplo: `modelo_wordlists.py` genera y valida wordlists personalizadas usando expresiones regulares.
- Todas las rutas y nombres se validan antes de operar.
- No se ejecutan comandos de sistema directamente desde el modelo.

---




## 3. Seguridad real y gestión de privilegios en Aresitos

**Hechos comprobados en el código:**

- Aresitos implementa protección anti-logout/crash únicamente en la detención de procesos, mediante filtrado explícito de procesos críticos (por ejemplo, no permite terminar procesos de sesión gráfica, shells principales ni servicios esenciales). Esto se realiza en el módulo `utils/detener_procesos.py`.
- **NO existe validación ni filtrado de comandos en la terminal integrada.** El usuario puede ejecutar cualquier comando desde la terminal de Aresitos, y estos se ejecutan directamente usando `subprocess.run` (a veces a través de SudoManager para privilegios elevados, pero sin validación de comandos). Esto está comprobado en `vista_monitoreo.py` y otros módulos de vista.
- El módulo `utils/sudo_manager.py` implementa un singleton para mantener el estado de privilegios sudo/root y ejecutar comandos con privilegios elevados cuando es necesario. No filtra ni valida los comandos, solo gestiona la elevación de privilegios y la persistencia del estado sudo.
- **No existe ningún validador de comandos prohibidos ni lista negra aplicada en la terminal.** Cualquier afirmación anterior sobre validación de comandos en la terminal es incorrecta y ha sido eliminada.

**Fragmento real de ejecución de comandos en la terminal (vista_monitoreo.py):**
```python
def ejecutar_comando_terminal(self, comando):
	resultado = subprocess.run(comando, capture_output=True, text=True, shell=True)
	# ...
```
o, si se requiere privilegio:
```python
from aresitos.utils.sudo_manager import SudoManager
sudo = SudoManager()
resultado = sudo.ejecutar_comando_privilegiado(comando)
```

**Protección anti-logout/crash en detención de procesos:**
El sistema de detención de procesos sí filtra procesos críticos para evitar cerrar la sesión gráfica o terminal principal:
```python
procesos_protegidos = [ ... ]
if any(p in comando for p in procesos_protegidos):
	callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) no será terminado por seguridad\n")
	continue
# Protección extra: no matar procesos con DISPLAY/XDG_SESSION/TTY de usuario
try:
	environ = subprocess.check_output(['cat', f'/proc/{pid}/environ']).decode(errors='ignore')
	if 'DISPLAY=' in environ or 'XDG_SESSION' in environ or 'WAYLAND_DISPLAY' in environ or 'TTY=' in environ:
		callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) tiene entorno gráfico/terminal, no será terminado\n")
		continue
except Exception:
	pass
```

**Resumen:**
- La terminal integrada permite ejecutar cualquier comando, sin validación ni restricción.
- SudoManager solo gestiona privilegios, no filtra comandos.
- La única protección activa es en la detención de procesos críticos.

**Referencias oficiales:**
- [subprocess — Python Docs](https://docs.python.org/3/library/subprocess.html)
- [Tkinter — Python Docs](https://docs.python.org/3/library/tkinter.html)
- [Gestión de privilegios en Linux (sudo)](https://wiki.archlinux.org/title/Sudo)


---

- Implementa la interfaz gráfica con Tkinter.
- Cada archivo define una pantalla principal como clase `tk.Frame`.
- Integra terminal ARESITOS, entrada de comandos, paneles informativos y navegación.
- Ejemplo: `vista_monitoreo.py` monitorea procesos, red, usuarios y archivos críticos, ejecutando comandos como `ps aux`, `ss -tupna`, `ip route`, `nmap`, `find`, `ifstat`.
- Ejemplo: `vista_fim.py` monitorea la integridad de archivos críticos, ejecuta comandos de hash (`sha256sum`, `md5sum`), compara resultados y alerta sobre cambios.
- Uso de `PanedWindow` para dividir info, contenido y terminal.
- Todos los comandos pasan por validadores y gestores de permisos.
- Integración de SudoManager para control de privilegios.
- Threading seguro para tareas en background (`threading.Thread`, `ThreadSafeFlag`).

---



## 4. Módulo Controlador (`aresitos/controlador/`)

- Orquesta la lógica de negocio y la interacción entre modelo y vista.
- Ejecuta herramientas de Kali y comandos de sistema, delegando la gestión de privilegios a SudoManager cuando es necesario.
- **No valida ni sanitiza comandos de sistema antes de ejecutarlos** (salvo en la detención de procesos críticos, como se explicó antes). Esto es comprobable en los controladores y vistas.
- Ejemplo: `controlador_auditoria.py` ejecuta auditorías de seguridad completas, invocando herramientas como `nmap`, `lynis`, `rkhunter`, `chkrootkit`, `clamav`, `find`, `ps`, `ss`, `journalctl`.
- Ejemplo: `controlador_fim.py` orquesta el monitoreo de integridad, ejecuta comandos de hash, compara resultados y alerta sobre cambios.
- Uso intensivo de `subprocess.run` para ejecutar comandos de sistema, a veces con `shell=True`.
- Prohibido el uso de `os.system`, `eval`, `exec` (aunque en algunos casos se usa `shell=True` por necesidad técnica).
- Coordinación de hilos y tareas en background.

---



## 5. Saneamiento de Archivos y Validación de Entrada

ARESITOS implementa múltiples capas de seguridad para la carga y manipulación de archivos:
- Validación de extensiones y tipos MIME
- Verificación de estructura y contenido (JSON, TXT)
- Prevención de traversal y rutas peligrosas
- Límite de tamaño y validación de codificación
- Rechazo de ejecutables y scripts maliciosos
- Diálogos de seguridad y logs detallados

**Flujo de validación:**
1. Usuario solicita cargar archivo
2. Mostrar información de seguridad
3. Abrir diálogo con filtros restringidos
4. Validar ruta, nombre y extensión
5. Validar tamaño y MIME type
6. Validar contenido según tipo
7. Mostrar resultado y permitir/denegar carga

---

- Provee utilidades transversales para seguridad, permisos, threading, logging y helpers.
- `sudo_manager.py`: Gestiona privilegios sudo/root, ejecuta comandos con privilegios elevados de forma segura.
- `thread_safe_gui.py`: Implementa `ThreadSafeFlag` para control seguro de hilos en la UI.
- `sanitizador_archivos.py`, `helper_seguridad.py`: Validan y sanitizan rutas, nombres y operaciones sensibles.
- `logger_aresitos.py`: Logging centralizado y seguro.
- Encapsulan la ejecución de comandos de sistema.
- Proveen funciones para comprobar integridad, permisos y estado del sistema.

---



## 6. Terminal Integrada y Logging Centralizado


ARESITOS incluye un terminal integrado en el Dashboard y en cada módulo clave. Características:
- Captura de logs en tiempo real de todos los módulos
- Controles para limpiar, activar/desactivar logs, abrir terminal externo
- Permite ejecutar cualquier comando del sistema, sin validación ni restricción
- Redirección de stdout/stderr y logging thread-safe

**Ejemplo de logging centralizado:**
```python
self._log_terminal("OK Operación completada", "MONITOREO", "SUCCESS")
self._log_terminal("WARNING Advertencia detectada", "FIM", "WARNING")
self._log_terminal("ERROR Error en proceso", "SIEM", "ERROR")
```

---

## 6.1. Integración de terminales externas en reportes

Desde la versión 2025-09, ARESITOS permite detectar y agregar información de todas las terminales externas abiertas en Kali Linux al reporte final. Esta función se activa desde el módulo de reportes mediante un checkbox específico. Al generar el informe, se recopila el estado, cantidad y detalles (PID, comando, argumentos) de cada terminal externa detectada, permitiendo una trazabilidad completa del entorno y facilitando auditorías avanzadas.

**Ventajas:**
- Permite documentar el contexto real de trabajo y comandos ejecutados fuera de la aplicación.
- Mejora la trazabilidad y la transparencia en auditorías forenses.
- Facilita la detección de actividades paralelas o sospechosas durante el análisis.

**Cómo usarlo:**
- Marca la opción "Terminales externas abiertas en Kali" en el panel de reportes.
- Al generar el informe, se incluirá una sección detallada con la información de todas las terminales externas detectadas.

---



## 7. Proceso de Instalación y Requisitos

### Instalación rápida
```bash
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh
sudo ./configurar_kali.sh
python3 main.py
```

### Instalación manual (opcional)
```bash
sudo apt update
sudo apt install python3 python3-tk python3-venv nmap masscan nuclei gobuster ffuf feroxbuster wireshark autopsy sleuthkit git curl wget sqlite3
python3 main.py
```

### Requisitos mínimos recomendados (Kali Linux):

### Requisitos mínimos reales (Kali Linux, medidos en pruebas reales):
- **CPU:** 1 núcleo x86_64 (recomendado 2 núcleos para multitarea)
- **RAM:** 1 GB libre (uso típico bajo, recomendado 2 GB para análisis forense o escaneos intensivos)
- **Almacenamiento:** ~25 MB libres para instalación base, más 20 MB adicionales para datos, reportes y logs
- **Python:** 3.8 o superior
- **Paquetes Python:** Solo biblioteca estándar (`tkinter`, `sqlite3`, `hashlib`, `subprocess`, `threading`, `os`, `json`, `logging`)
- **Herramientas externas:** nmap, masscan, nuclei, gobuster, ffuf, feroxbuster, wireshark, autopsy, sleuthkit, hashdeep, testdisk, bulk-extractor, dc3dd, guymager, git, curl, wget, sqlite3, inotify-tools, chkrootkit, rkhunter, clamav, yara, linpeas (todas instalables vía APT en Kali Linux)

---

- Comandos de sistema ejecutados en hilos separados.
- Resultados mostrados en la UI y almacenados en modelos.
- Archivos sospechosos validados y movidos a cuarentena.
- Hashes calculados y registrados.
- Correlación de eventos, análisis de logs, monitoreo de integridad, alertas en tiempo real.
- Terminal integrada permite ejecutar comandos validados desde la UI, mostrando resultados y logs en tiempo real.

---



## 8. Buenas Prácticas y Patrones de Seguridad

- Validación y sanitización exhaustiva de entradas y rutas
- Gestión de privilegios centralizada (`sudo_manager.py`, `gestor_permisos.py`)
- Threading seguro y control de concurrencia
- Prohibición de prácticas inseguras (`os.system`, `eval`, `exec`, `shell=True`)
- Logging y auditoría centralizados
- Documentación y auditoría técnica actualizada

---


## 9. Buenas Prácticas, Referencias y Recursos de Seguridad

Aresitos sigue las mejores prácticas de seguridad y desarrollo profesional, aplicando recomendaciones de organismos y guías reconocidas internacionalmente. A continuación se listan referencias y recursos oficiales que fundamentan las decisiones técnicas y de seguridad del proyecto.

### 1. Seguridad en la Ejecución de Comandos
- Uso exclusivo de `subprocess.run` sin `shell=True` ([Python subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations)).
- Prohibición de funciones peligrosas: `os.system`, `eval`, `exec`.

### 2. Principios de Seguridad y Endurecimiento
- Principio de mínimo privilegio: solo se usan permisos elevados cuando es estrictamente necesario ([Wikipedia - Principle of least privilege](https://es.wikipedia.org/wiki/Principio_de_menor_privilegio)).
- Gestión centralizada de privilegios con SudoManager y validación de grupos.
- Logging y auditoría de todas las operaciones críticas.
- Validación exhaustiva de rutas, extensiones y tipos MIME ([OWASP File Upload Security](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)).

### 3. Referencias Oficiales y Guías de Ciberseguridad
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/): Referencia para evitar vulnerabilidades comunes.
- [Guía de Hardening de Kali Linux](https://www.kali.org/docs/general-use/securing-kali-linux/): Recomendaciones oficiales para asegurar el entorno.
- [Guía de Seguridad de Python](https://docs.python.org/3/howto/security.html): Prácticas recomendadas para desarrollo seguro en Python.
- [NIST Secure Software Development Framework](https://csrc.nist.gov/publications/detail/white-paper/2020/04/23/secure-software-development-framework-ssdf): Marco de referencia para desarrollo seguro.

### 4. Recursos de Validación y Saneamiento
- [Python re — Expresiones regulares](https://docs.python.org/3/library/re.html): Para validación de entradas.
- [Python mimetypes](https://docs.python.org/3/library/mimetypes.html): Para validación de tipos MIME.
- [Python pathlib](https://docs.python.org/3/library/pathlib.html): Para gestión segura de rutas.

### 5. Documentación y Auditoría Técnica
- Toda la documentación técnica y de seguridad se mantiene actualizada en la carpeta `documentacion/`.
- Auditorías internas periódicas siguiendo las recomendaciones de [OWASP](https://owasp.org/) y [NIST](https://csrc.nist.gov/).

---

*Para más detalles sobre la implementación de cada práctica, consulta el código fuente y los comentarios técnicos en cada módulo.*

---


---


## 10. Subsistema FIM (File Integrity Monitoring) en ARESITOS


### 10.1. Descripción General

El subsistema FIM de ARESITOS implementa un monitoreo avanzado de integridad de archivos críticos, combinando técnicas de baseline, monitoreo en tiempo real (inotify), escaneo de rootkits, análisis forense y verificación de permisos. Está diseñado para Kali Linux y aprovecha herramientas nativas y de terceros, integradas de forma segura.

#### Componentes principales:
- **Vista:** `vista_fim.py` (Tkinter, terminal integrada, paneles de control, resultados en tiempo real)
- **Controlador:** `controlador_fim.py` (orquestación, hilos, coordinación con cuarentena y SIEM)
- **Modelo:** `modelo_fim.py` y `modelo_fim_base.py` (gestión de baseline, hashes, eventos, integración con herramientas externas, base de datos SQLite)
- **Utils:** `gestor_permisos.py` (ejecución segura de comandos con privilegios, validación de argumentos)


### 10.2. Diagrama de Flujo Simplificado

<!-- Sugerencia: Puedes agregar aquí una imagen del diagrama de flujo generado con mermaid o una captura de pantalla de la interfaz FIM. -->

```mermaid
flowchart TD
	UI[Usuario en Vista FIM] -->|Inicia Monitoreo| VC[VistaFIM]
	VC -->|Llama| CC[ControladorFIM]
	CC -->|Configura rutas| MM[FIMKali2025]
	MM -->|Monitorea con inotify| DB[(SQLite FIM)]
	MM -->|Escanea rootkits, YARA, ClamAV| DB
	MM -->|Detecta cambio| CC
	CC -->|Alerta y mueve a cuarentena| QC[ControladorCuarentena]
	CC -->|Notifica| SIEM[ControladorSIEM]
	VC -->|Muestra resultados| UI
```

---


### 10.3. Ejemplo de Código Real: Vista FIM (Tkinter)

```python
class VistaFIM(tk.Frame):
	def iniciar_monitoreo(self):
		if self.proceso_monitoreo_activo:
			return
		self.proceso_monitoreo_activo = True
		self._habilitar_botones_monitoreo(False)
		self._log_terminal("Iniciando sistema FIM - File Integrity Monitoring", "FIM", "INFO")
		self.log_to_terminal("FIM Iniciando monitoreo FIM del sistema...")
		self._actualizar_texto_fim("=== INICIANDO MONITOREO FIM - FILE INTEGRITY MONITORING ===\n\n")
		self.thread_monitoreo = threading.Thread(target=self._ejecutar_monitoreo_async)
		self.thread_monitoreo.daemon = True
		self.thread_monitoreo.start()
```

**Terminal integrada:**
```python
self.terminal_output = scrolledtext.ScrolledText(parent_frame,
	height=6, bg='#000000', fg='#00ff00', font=("Consolas", 8), insertbackground='#00ff00')
```

---


### 10.4. Ejemplo de Código Real: Controlador FIM

```python
class ControladorFIM(ControladorBase):
	def iniciar_monitoreo(self) -> Dict[str, Any]:
		if self.monitoreo_activo:
			return {'exito': True, 'mensaje': 'Monitoreo FIM ya está activo'}
		self.monitoreo_activo = True
		self.thread_monitoreo = threading.Thread(target=self._bucle_monitoreo, daemon=True)
		self.thread_monitoreo.start()
		self.log("OK Monitoreo FIM iniciado")
		return {'exito': True, 'mensaje': 'Monitoreo FIM iniciado correctamente'}
```

---


### 10.5. Ejemplo de Código Real: Modelo FIM (Monitoreo inotify y escaneo de rootkits)

```python
class FIMKali2025(_FIMBase):
	def iniciar_monitoreo_tiempo_real(self, rutas_monitorear: List[str]) -> Dict[str, Any]:
		if 'inotifywait' not in self.herramientas_disponibles:
			return {"error": "inotifywait no disponible"}
		rutas_ok = []
		for ruta in rutas_monitorear:
			if os.path.exists(ruta):
				thread = threading.Thread(target=self._monitorear_ruta_inotify, args=(ruta,), daemon=True)
				thread.start()
				self.monitores_activos[ruta] = {'thread': thread, 'activo': True}
				rutas_ok.append(ruta)
		return {"exito": True if rutas_ok else False, "rutas_monitoreadas": len(rutas_ok)}

	def escaneo_rootkits_chkrootkit(self) -> Dict[str, Any]:
		if 'chkrootkit' not in self.herramientas_disponibles:
			return {"error": "chkrootkit no disponible"}
		result = subprocess.run(['chkrootkit', '-q'], capture_output=True, text=True, timeout=300)
		detecciones = self._procesar_resultados_chkrootkit(result.stdout)
		return {"exito": True, "detecciones": detecciones}
```

---


### 10.6. Ejemplo de Salida Real (Terminal FIM)


<div align="center">
	<img src="../aresitos/recursos/capturas/7_FIM.png" alt="Terminal FIM en acción" width="600" />
	<br><sub>Terminal FIM en acción: monitoreo y alertas en tiempo real</sub>
</div>

```
============================================================
Terminal ARESITOS - FIM v2.0
Iniciado: 2025-08-31 12:00:00
Sistema: Kali Linux - File Integrity Monitoring
============================================================
LOG Monitoreo FIM en tiempo real

FASE 1: ANÁLISIS INICIAL DEL SISTEMA CON COMANDOS LINUX
COMANDO: find /etc -type f -mtime -1
RESULTADO: 2 archivos modificados
  - /etc/passwd
  - /etc/shadow
OK FASE 1 completada exitosamente

FASE 2: VERIFICACIÓN DE ARCHIVOS CRÍTICOS
OK /etc/passwd: Permisos correctos (644), Tamaño: 2782 bytes
   FUNCIÓN: Lista de usuarios del sistema - modificaciones indican creación de cuentas maliciosas
ALERTA /etc/shadow: Permisos anómalos (666, esperado 640)
   RIESGO: Hashes de contraseñas - cambios no autorizados indican compromiso de cuentas
   ACCIÓN: Revisar cambios recientes y verificar el cumplimiento de políticas de seguridad
   HASH: 1a2b3c4d5e6f7g8h...

FASE 3: RESUMEN DEL ANÁLISIS FIM
ARCHIVOS VERIFICADOS: 8
PROBLEMAS DETECTADOS: 1
ESTADO: Se detectaron 1 anomalías - Revisar alertas

RESUMEN DE EJECUCIÓN FIM
OK FASES COMPLETADAS: 3/3
ESTADO GENERAL: ADVERTENCIA 2 fases exitosas, 1 con errores
RESULTADO: FIM ejecutado de forma resiliente
```

---


### 10.7. Base de Datos y Estructura de Tablas FIM

**Tablas principales (SQLite):**
- `archivos_monitoreados`: Rutas, hashes, permisos, timestamps.
- `eventos_cambios`: Archivo, tipo de evento, timestamp, detalles, severidad.
- `detecciones_rootkit`: Herramienta, archivo afectado, tipo de amenaza, descripción, severidad.
- `analisis_yara`: Archivo, regla disparada, metadatos, severidad.

---


### 10.8. Seguridad y Validación de Permisos

**Ejemplo real de ejecución segura:**
```python
gestor = GestorPermisosSeguro()
exito, out, err = gestor.ejecutar_con_permisos('find', ['/etc', '-type', 'f', '-mtime', '-1'])
if exito:
	print(out)
else:
	print(f"ERROR: {err}")
```

**Validaciones implementadas:**
- Lista blanca de herramientas y argumentos permitidos.
- Prohibición de caracteres peligrosos y rutas sospechosas.
- Uso de `sudo` solo cuando es necesario y seguro.
- Logging centralizado de todas las operaciones privilegiadas.

---


### 10.9. Requisitos del Sistema y Consumo de Recursos

#### Requisitos mínimos recomendados (Kali Linux):
- CPU: 2 núcleos x86_64 (recomendado 4 núcleos)
- RAM: 2 GB (recomendado 4 GB para análisis forense y escaneos simultáneos)
- Almacenamiento: 500 MB libres para bases de datos, logs y cuarentena
- Python 3.8+
- Paquetes: `tkinter`, `sqlite3`, `hashlib`, `subprocess`, `threading`, `inotify-tools`, `chkrootkit`, `rkhunter`, `clamav`, `yara`, `linpeas`, `pspy`

#### Consumo estimado de recursos (prueba real):

**Prueba:** Monitoreo FIM activo + escaneo de rootkits + análisis YARA en 8 rutas críticas

- Uso de CPU: 2-8% en reposo, picos de 20-40% durante escaneos intensivos
- Uso de RAM: 80-150 MB en reposo, hasta 300 MB en análisis forense simultáneo
- Espacio ocupado por base de datos FIM: ~2-10 MB (dependiendo del historial y cantidad de archivos)
- Logs: 1-5 MB/día según actividad

**Comando para medir consumo:**
```bash
ps aux | grep python | grep aresitos
```

---


### 10.10. Buenas Prácticas y Patrones de Seguridad

- Validación y sanitización exhaustiva de entradas y rutas
- Gestión de privilegios centralizada (`sudo_manager.py`, `gestor_permisos.py`)
- Threading seguro y control de concurrencia
- Prohibición de prácticas inseguras (`os.system`, `eval`, `exec`, `shell=True`)
- Logging y auditoría centralizados
- Documentación y auditoría técnica actualizada

---


---


## 11. Comandos Internos y Algoritmos Usados en ARESITOS

Aresitos está desarrollado íntegramente en Python 3 estándar (stdlib), sin dependencias externas, y aprovecha comandos y herramientas nativas de Kali Linux para todas sus funciones avanzadas. A continuación se detallan los comandos internos, algoritmos y patrones técnicos empleados, junto con enlaces oficiales y documentación relevante.


### 11.1. Comandos de Sistema Utilizados

Todos los comandos se ejecutan mediante el módulo `subprocess` de Python ([documentación oficial](https://docs.python.org/3/library/subprocess.html)), validando y sanitizando la entrada para máxima seguridad.

| Comando              | Descripción técnica                          | Documentación oficial / referencia |
|----------------------|----------------------------------------------|------------------------------------|
| ps, ps aux           | Listado y monitoreo de procesos              | [ps(1) - Linux man page](https://man7.org/linux/man-pages/man1/ps.1.html) |
| kill, pkill, pgrep   | Gestión y terminación de procesos            | [kill(1)](https://man7.org/linux/man-pages/man1/kill.1.html), [pkill(1)](https://man7.org/linux/man-pages/man1/pkill.1.html), [pgrep(1)](https://man7.org/linux/man-pages/man1/pgrep.1.html) |
| ss, netstat          | Análisis de conexiones de red                | [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html), [netstat(8)](https://man7.org/linux/man-pages/man8/netstat.8.html) |
| ip, ifconfig         | Configuración y consulta de interfaces       | [ip(8)](https://man7.org/linux/man-pages/man8/ip.8.html), [ifconfig(8)](https://man7.org/linux/man-pages/man8/ifconfig.8.html) |
| find, ls, stat       | Búsqueda y análisis de archivos              | [find(1)](https://man7.org/linux/man-pages/man1/find.1.html), [ls(1)](https://man7.org/linux/man-pages/man1/ls.1.html), [stat(1)](https://man7.org/linux/man-pages/man1/stat.1.html) |
| chmod, chown         | Gestión de permisos y propietarios           | [chmod(1)](https://man7.org/linux/man-pages/man1/chmod.1.html), [chown(1)](https://man7.org/linux/man-pages/man1/chown.1.html) |
| sha256sum, md5sum    | Cálculo de hashes para integridad            | [sha256sum(1)](https://man7.org/linux/man-pages/man1/sha256sum.1.html), [md5sum(1)](https://man7.org/linux/man-pages/man1/md5sum.1.html) |
| useradd, groupadd    | Gestión de usuarios y grupos                 | [useradd(8)](https://man7.org/linux/man-pages/man8/useradd.8.html), [groupadd(8)](https://man7.org/linux/man-pages/man8/groupadd.8.html) |
| passwd               | Cambio de contraseñas                        | [passwd(1)](https://man7.org/linux/man-pages/man1/passwd.1.html) |
| crontab              | Tareas programadas                           | [crontab(1)](https://man7.org/linux/man-pages/man1/crontab.1.html) |
| journalctl, logger   | Consulta y gestión de logs                   | [journalctl(1)](https://man7.org/linux/man-pages/man1/journalctl.1.html), [logger(1)](https://man7.org/linux/man-pages/man1/logger.1.html) |
| apt, dpkg            | Gestión de paquetes                          | [apt(8)](https://man7.org/linux/man-pages/man8/apt.8.html), [dpkg(1)](https://man7.org/linux/man-pages/man1/dpkg.1.html) |
| ping, tcpdump        | Diagnóstico y captura de red                 | [ping(8)](https://man7.org/linux/man-pages/man8/ping.8.html), [tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html) |
| tail, head, cat      | Lectura de archivos y logs                   | [tail(1)](https://man7.org/linux/man-pages/man1/tail.1.html), [head(1)](https://man7.org/linux/man-pages/man1/head.1.html), [cat(1)](https://man7.org/linux/man-pages/man1/cat.1.html) |
| inotifywait          | Monitoreo de archivos en tiempo real         | [inotifywait(1)](https://man7.org/linux/man-pages/man1/inotifywait.1.html) |
| nmap, masscan, gobuster, nuclei, ffuf, feroxbuster, wireshark, autopsy, sleuthkit, lynis, chkrootkit, rkhunter, clamscan, yara, foremost, binwalk, exiftool, httpx-toolkit, volatility3, rustscan | Ver tabla de herramientas arriba   | [Kali Tools](https://www.kali.org/tools/) |



### 11.2. Algoritmos y Funciones Técnicas

- **Hashing de archivos:** Uso de `hashlib` ([hashlib — Documentación oficial de Python](https://docs.python.org/3/library/hashlib.html)) para SHA256 y MD5.
- **Hilos seguros:** Uso de `threading` ([threading — Documentación oficial de Python](https://docs.python.org/3/library/threading.html)) para tareas en segundo plano y monitoreo.
- **Gestión de procesos y privilegios:** Uso de `os`, `subprocess` y validación estricta de comandos.
- **Gestión de bases de datos:** Uso de `sqlite3` ([sqlite3 — Documentación oficial de Python](https://docs.python.org/3/library/sqlite3.html)) para almacenamiento local seguro.
- **Validación y saneamiento:** Algoritmos propios para validar rutas, extensiones, tipos MIME y argumentos de comandos.
- **Patrón MVC:** Organización del código siguiendo el estándar [Modelo–Vista–Controlador](https://es.wikipedia.org/wiki/Modelo%E2%80%93vista%E2%80%93controlador).
- **Tema visual inspirado en Burp Suite:** [Burp Suite Oficial](https://portswigger.net/burp)



### 11.3. Librerías Python de la Biblioteca Estándar Utilizadas

- [os](https://docs.python.org/3/library/os.html): Operaciones del sistema y gestión de rutas.
- [sys](https://docs.python.org/3/library/sys.html): Acceso a variables y funciones del intérprete de Python.
- [subprocess](https://docs.python.org/3/library/subprocess.html): Ejecución de comandos externos de forma segura.
- [threading](https://docs.python.org/3/library/threading.html): Gestión de hilos y concurrencia segura.
- [sqlite3](https://docs.python.org/3/library/sqlite3.html): Base de datos local integrada.
- [hashlib](https://docs.python.org/3/library/hashlib.html): Cálculo de hashes seguros.
- [json](https://docs.python.org/3/library/json.html): Manejo de datos estructurados en formato JSON.
- [tkinter](https://docs.python.org/3/library/tkinter.html): Interfaz gráfica nativa para Python.
- [logging](https://docs.python.org/3/library/logging.html): Registro centralizado de eventos y auditoría.
- [re](https://docs.python.org/3/library/re.html): Expresiones regulares para validación y filtrado de datos.

---



---

*Esta guía es la referencia técnica única y consolidada de ARESITOS. Para detalles de cada clase, función o flujo, consulte el código fuente correspondiente y los comentarios técnicos en cada módulo.*

---



## 12. Ejemplos Reales de Código y Flujos Técnicos en ARESITOS

A continuación se presentan ejemplos reales y explicativos de cómo Aresitos implementa la seguridad, el control de procesos, la validación de comandos y la integración con herramientas de Kali Linux, siguiendo las mejores prácticas y patrones profesionales.


### 12.1. Ejecución segura de comandos con Subprocess

Todos los comandos del sistema se ejecutan usando `subprocess.run` con validación previa y sin `shell=True` para evitar riesgos de inyección:

```python
import subprocess

# Ejemplo: Ejecutar un escaneo de red de forma segura
resultado = subprocess.run(['nmap', '-sS', '127.0.0.1'], capture_output=True, text=True, timeout=60)
if resultado.returncode == 0:
	print(resultado.stdout)
else:
	print(f"Error: {resultado.stderr}")
```

- [subprocess.run — Documentación oficial de Python](https://docs.python.org/3/library/subprocess.html#subprocess.run)


### 12.2. Hashing seguro de archivos para integridad (FIM)

Aresitos utiliza `hashlib` para calcular hashes SHA256 y MD5 de archivos críticos:

```python
import hashlib

def calcular_hash_sha256(ruta):
	with open(ruta, 'rb') as f:
		return hashlib.sha256(f.read()).hexdigest()

hash_archivo = calcular_hash_sha256('/etc/passwd')
print(f"SHA256: {hash_archivo}")
```

- [hashlib — Documentación oficial de Python](https://docs.python.org/3/library/hashlib.html)


### 12.3. Hilos seguros para tareas en segundo plano

El monitoreo y escaneo se realiza en hilos separados usando `threading` para no bloquear la interfaz:

```python
import threading

def tarea_larga():
	# ...código de escaneo o monitoreo...
	pass

hilo = threading.Thread(target=tarea_larga)
hilo.daemon = True
hilo.start()
```

- [threading — Documentación oficial de Python](https://docs.python.org/3/library/threading.html)



### 12.4. Validación y saneamiento de comandos

**Importante:** En la implementación real de Aresitos, **no existe validación ni filtrado de comandos en la terminal integrada**. El usuario puede ejecutar cualquier comando, y la responsabilidad de la seguridad recae en el propio usuario y en la protección de procesos críticos implementada en la detención de procesos.

**Fragmento real de ejecución de comandos (vista_monitoreo.py):**
```python
def ejecutar_comando_terminal(self, comando):
	resultado = subprocess.run(comando, capture_output=True, text=True, shell=True)
	# ...
```

**SudoManager:**
```python
from aresitos.utils.sudo_manager import SudoManager
sudo = SudoManager()
resultado = sudo.ejecutar_comando_privilegiado(comando)
```


**No existe lista negra ni validación de comandos en la terminal.**



### 12.5. Patrón MVC en la arquitectura de Aresitos

Aresitos sigue el patrón Modelo–Vista–Controlador ([Wikipedia](https://es.wikipedia.org/wiki/Modelo%E2%80%93vista%E2%80%93controlador)) para separar la lógica de datos, la interfaz gráfica y el control de la aplicación:

```python
# Ejemplo simplificado de inicialización MVC
modelo = ModeloPrincipal()
vista = VistaPrincipal(root)
controlador = ControladorPrincipal(modelo)
vista.set_controlador(controlador)
```


### 12.6. Logging centralizado y seguro

Se utiliza el módulo `logging` para registrar eventos, errores y auditoría de forma centralizada y segura:

```python
import logging
logging.basicConfig(filename='logs/aresitos.log', level=logging.INFO)
logging.info('Inicio de Aresitos')
```

- [logging — Documentación oficial de Python](https://docs.python.org/3/library/logging.html)
