
![ARESITOS](aresitos/recursos/aresitos.png)

# ARESITOS - Herramienta de Ciberseguridad

Suite profesional para Kali Linux: escaneo de vulnerabilidades, SIEM, FIM, cuarentena y dashboard integrados. Flujo real: **Login → Herramientas → Principal**.


## Instalación rápida y requisitos


### Instalación rápida (Kali Linux recomendado)
```bash
git clone https://github.com/DogSoulDev/aresitos.git
cd aresitos
chmod +x configurar_kali.sh main.py verificacion_final.py
sudo ./configurar_kali.sh
# IMPORTANTE: Da permisos de escritura a la carpeta de cuarentena para evitar errores de permisos
chmod -R 755 aresitos/data/cuarentena
chown -R $USER:$USER aresitos/data/cuarentena
python3 main.py
```
> **Importante:** Si tienes errores de permisos, asegúrate de que los scripts principales tengan permisos de ejecución **y que la carpeta `aresitos/data/cuarentena` sea escribible por tu usuario**:
> ```bash
> chmod +x configurar_kali.sh main.py verificacion_final.py
> chmod -R 755 aresitos/data/cuarentena
> chown -R $USER:$USER aresitos/data/cuarentena
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
├── controlador/     # Lógica de negocio y orquestación de módulos
├── modelo/          # Acceso y gestión de datos, SQLite, wordlists, diccionarios
├── vista/           # Interfaz gráfica Tkinter, terminal integrado, paneles
├── utils/           # Utilidades, configuración, detección de red, sanitización
├── recursos/        # Imágenes y recursos gráficos
├── data/            # Bases de datos SQLite, cuarentena, wordlists, cheatsheets
└── configuración/   # Configuración JSON, textos, mapas de navegación
```

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
# Verificar estado completo del sistema
python3 verificacion_final.py

# Modo desarrollo
python3 main.py --dev

# Actualizar configuración y herramientas
sudo ./configurar_kali.sh --update

# Debug escaneador
python3 main.py --verbose --scanner-debug

# Actualizar templates nuclei
sudo nuclei -update-templates
```

---

## Documentación y soporte

- Manual técnico: `documentacion/DOCUMENTACION_TECNICA_CONSOLIDADA.md`
- Guía de desarrollo: `documentacion/ARQUITECTURA_DESARROLLO.md`
- Auditoría de seguridad: `documentacion/AUDITORIA_SEGURIDAD_ARESITOS.md`
- Terminal integrado: `documentacion/TERMINAL_INTEGRADO.md`

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
