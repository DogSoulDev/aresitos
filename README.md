![ARESITOS](aresitos/recursos/aresitos.png)
# ARESITOS - Herramienta de Ciberseguridad

<div align="center">
   <img src="aresitos/recursos/tfm/logo_tele.png" alt="Logo TFM" width="120" style="margin:10px;"/>
   <img src="aresitos/recursos/tfm/logo_uni.png" alt="Logo UCAM" width="120" style="margin:10px;"/>
   <img src="aresitos/recursos/tfm/logo.png" alt="Logo Ciberseguridad" width="120" style="margin:10px;"/>
</div>

---

## Descripción

ARESITOS es una Herramienta de Ciberseguridad profesional para auditoría y gestión, desarrollada como parte del TFM en la UCAM y el Campus Internacional de Ciberseguridad. Integra módulos de escaneo, SIEM, FIM, cuarentena, reportes y utilidades forenses, siguiendo estándares y buenas prácticas.

### ¿Qué puede hacer realmente ARESITOS desde el punto de vista defensivo (Blue Team)?

Como desarrollador, quiero ser claro y honesto sobre lo que ARESITOS ofrece. No es una solución mágica ni un producto comercial, sino una herramienta práctica pensada para ayudar en tareas defensivas de ciberseguridad, especialmente en entornos Linux/Kali.

ARESITOS integra varias utilidades y módulos que permiten:

- Ejecutar escaneos de red y vulnerabilidades con herramientas conocidas (nmap, masscan, nuclei, gobuster, ffuf, feroxbuster). El objetivo es facilitar la detección de servicios y posibles vectores de ataque, pero siempre usando motores externos, no desarrollos propios.

- Monitorizar eventos y correlacionar alertas básicas en tiempo real (SIEM). El sistema puede detectar patrones simples de fuerza bruta, actividad sospechosa y mostrar información útil, pero no pretende competir con SIEMs profesionales.

- Comprobar la integridad de archivos críticos (FIM) y detectar cambios inesperados. Esto ayuda a identificar manipulaciones o incidentes, aunque la monitorización es local y depende de la configuración del usuario.

- Aislar archivos y procesos sospechosos en cuarentena, permitiendo su análisis posterior con herramientas forenses externas (sleuthkit, autopsy, hashdeep, testdisk, bulk-extractor, etc.). No se realiza análisis avanzado dentro del programa, solo se facilita el flujo.

- Realizar auditorías básicas de configuración y buscar rootkits con utilidades como lynis, aide, debsums, chkrootkit y rkhunter. El programa automatiza la ejecución y muestra los resultados, pero no interpreta ni recomienda acciones.

- Gestionar diccionarios y wordlists para fuerza bruta y auditoría, centralizando recursos que suelen estar dispersos.

- Generar reportes automáticos siguiendo la estructura ISO/IEC 27001, para documentar hallazgos y acciones. Los informes se basan en los datos recogidos por los módulos, sin análisis avanzado.

Ventajas reales para el Blue Team:

- Centraliza y automatiza tareas defensivas habituales, ahorrando tiempo y evitando errores manuales.
- Permite tener una visión rápida del estado del sistema y de los servicios expuestos.
- Facilita la documentación y la respuesta ante incidentes, aunque la profundidad depende de las herramientas externas.
- Todo el código es abierto y auditable, sin dependencias ocultas ni telemetría.

Limitaciones:

- No sustituye soluciones profesionales ni comerciales. Es una ayuda para equipos pequeños, laboratorios, formación o entornos donde no se dispone de grandes recursos.
- La correlación de eventos y la monitorización son básicas y dependen de la configuración y del uso correcto de las herramientas.
- El análisis forense y la remediación requieren conocimientos técnicos y el uso de herramientas externas.

En resumen, ARESITOS busca ser una caja de herramientas defensiva, honesta y útil, sin prometer más de lo que realmente puede hacer. Si tienes dudas, sugerencias o quieres mejorar el proyecto, cualquier aportación es bienvenida.
---

## Instalación rápida en Kali Linux


```bash
# Instalación rápida en Kali Linux
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh main.py
find . -name "*.py" -exec chmod +x {} \;
chmod -R 755 data/ logs/ configuración/
sudo ./configurar_kali.sh
python3 main.py
```

Todas las herramientas necesarias se instalarán y verificarán automáticamente desde la interfaz gráfica de ARESITOS. No es necesario instalar manualmente los paquetes del sistema, el programa lo gestiona por ti.

Si tienes errores de acceso a carpetas:
```bash
chmod -R 755 data/ logs/ configuración/
```

Para modo desarrollo (otros sistemas):
```bash
python3 main.py --dev
```

---

## Capturas de pantalla y explicación de módulos

### 1. Instalación y entorno
![Instalación](aresitos/recursos/capturas/1_instalacion.png)
Pantalla de instalación y verificación de entorno.

### 2. Inicio de sesión
![Login](aresitos/recursos/capturas/2_login.png)
Acceso seguro al sistema.

### 3. Dashboard
![Dashboard](aresitos/recursos/capturas/4_dashboard.png)
Panel principal con métricas y acceso rápido.

### 4. Escaneo
![Escaneo](aresitos/recursos/capturas/5_escaneo.png)
Escaneo de vulnerabilidades y servicios.

### 5. SIEM
![SIEM](aresitos/recursos/capturas/6_SIEM.png)
Correlación de eventos y alertas en tiempo real.

### 6. FIM
![FIM](aresitos/recursos/capturas/7_FIM.png)
Monitorización de integridad de archivos.

### 7. Monitoreo y Cuarentena
![Monitoreo y Cuarentena](aresitos/recursos/capturas/8_Monitoreo y Cuarentena.png)
Supervisión de procesos y aislamiento de amenazas.

### 8. Auditoría
![Auditoría](aresitos/recursos/capturas/9_Auditoria.png)
Herramientas avanzadas de auditoría.

### 9. Wordlists y Diccionarios
![Wordlists y Diccionarios](aresitos/recursos/capturas/10_wordlistsydiccionarios.png)
Gestión de recursos para escaneo y fuerza bruta.

### 10. Reportes
![Reportes](aresitos/recursos/capturas/11_reportes.png)
Generación y exportación de informes profesionales.

---

## Arquitectura y estructura del proyecto

El proyecto sigue el patrón Modelo-Vista-Controlador (MVC), con estructura modular y separación clara entre lógica, interfaz y datos.

```
aresitos/
├── controlador/           # Lógica de negocio y orquestación
├── modelo/                # Modelos de datos y acceso a bases
├── vista/                 # Interfaz gráfica Tkinter
├── utils/                 # Utilidades y módulos auxiliares
├── recursos/              # Imágenes y capturas
├── data/                  # Bases de datos y recursos
├── configuración/         # Configuración y textos
├── logs/                  # Resultados y actividad
├── reportes/              # Informes generados
├── documentacion/         # Manuales y guías
├── main.py                # Script principal
├── configurar_kali.sh     # Script de configuración
├── requirements.txt       # Requisitos Python
├── LICENSE                # Licencia
└── README.md              # Documentación principal
```

---

## Licencia y uso ético

**Licencia Open Source No Comercial**
- Permitido: Educación, investigación, pruebas en sistemas propios o autorizados, proyectos de código abierto sin monetización.
- Prohibido: Venta, consultoría comercial, productos comerciales, monetización, SaaS o servicios gestionados.

**Atribución obligatoria:**
- Autor: DogSoulDev
- Contacto: dogsouldev@protonmail.com
- Repositorio: https://github.com/DogSoulDev/aresitos

---

## Reportes profesionales ISO/IEC 27001

ARESITOS permite generar reportes siguiendo la estructura recomendada por la norma ISO/IEC 27001:
- Portada (organización, contacto, fecha, título)
- Resumen ejecutivo
- Descripción del incidente
- Cronología
- Acciones tomadas
- Impacto y análisis
- Lecciones aprendidas
- Recomendaciones
- Anexos

Ejemplo:
```
================================================================================
INFORME DE INCIDENTE DE SEGURIDAD DE LA INFORMACIÓN - ISO/IEC 27001
================================================================================
Organización: Ejemplo S.A.
Persona de contacto: Juan Pérez
Correo electrónico: juan.perez@ejemplo.com
Teléfono: +34 600 123 456
Fecha de generación del informe: 2025-09-05 12:00
...
================================================================================
Reporte generado por ARESITOS conforme a ISO/IEC 27001 - https://github.com/DogSoulDev/aresitos
```

---

## Solución de problemas

- Si ves errores de permisos:
  ```bash
  chmod -R 755 data/ logs/ configuración/
  find . -name "*.py" -exec chmod +x {} \;
  ```
- Si falta alguna dependencia:
  ```bash
  sudo apt install <paquete>
  ```
- Si tienes problemas con la interfaz gráfica, instala `python3-tk`.
- Consulta la guía `documentacion/GUIA_INSTALACION.md` para más detalles.

---

## DEDICATORIA

**En memoria de Ares**
*25 de abril de 2013 - 5 de agosto de 2025*
Hasta que volvamos a encontrarnos.

---

## Escaneo de red y gestión de cuarentena

El módulo de escaneo de red permite detectar servicios, vulnerabilidades, IPs y DNS asociados al sistema operativo y la red del usuario. Tras cada escaneo, toda la información técnica útil (incluyendo IPs, DNS y vulnerabilidades detectadas) puede ser puesta en cuarentena de forma centralizada mediante el botón "Agregar IP a cuarentena". Se ha eliminado el botón "Mandar a cuarentena" para simplificar el flujo y evitar duplicidades.

Ahora, el usuario puede aislar manualmente cualquier IP, DNS o vulnerabilidad detectada, garantizando un proceso más robusto y transparente. La cuarentena se gestiona desde un único punto, facilitando el análisis y la respuesta ante incidentes.

---