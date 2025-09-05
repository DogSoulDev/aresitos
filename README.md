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

---

## Instalación rápida en Kali Linux

```bash
# Clona el repositorio y accede a la carpeta
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-tk python3-venv nmap masscan nuclei gobuster ffuf feroxbuster wireshark autopsy sleuthkit hashdeep testdisk bulk-extractor dc3dd guymager git curl wget sqlite3

git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh main.py
find . -name "*.py" -exec chmod +x {} \;
chmod -R 755 data/ logs/ configuración/
sudo ./configurar_kali.sh
python3 main.py
```

> Si tienes errores de acceso a carpetas:
> ```bash
> chmod -R 755 data/ logs/ configuración/
> ```

> Para modo desarrollo (otros sistemas):
> ```bash
> python3 main.py --dev
> ```

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