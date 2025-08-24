# ÍNDICE DE CHEATSHEETS DE ARES AEGIS

## Descripción
Esta carpeta contiene cheatsheets de ciberseguridad para profesionales. Los archivos pueden ser editados, guardados y personalizados según las necesidades del usuario.

## Cheatsheets Disponibles

### 1. **nmap_basico.txt**
- **Descripción**: Comandos esenciales de Nmap para escaneo de puertos y redes
- **Categorías**: Escaneos básicos, detección de servicios, evasión de firewalls, scripts NSE
- **Uso**: Reconocimiento de infraestructura y mapeo de redes

### 2. **metasploit_framework.txt**
- **Descripción**: Framework de explotación Metasploit
- **Categorías**: Comandos básicos, payloads, meterpreter, auxiliares, base de datos
- **Uso**: Explotación de vulnerabilidades y post-explotación

### 3. **comandos_linux.txt**
- **Descripción**: Comandos Linux orientados a ciberseguridad
- **Categorías**: Reconocimiento del sistema, escalación de privilegios, análisis de logs, red, forense
- **Uso**: Administración de sistemas y análisis forense

### 4. **shells_inversas.txt**
- **Descripción**: Reverse shells en múltiples lenguajes de programación
- **Categorías**: Bash, Netcat, Python, PHP, Perl, Ruby, Java, PowerShell, listeners
- **Uso**: Establecimiento de conexiones remotas

### 5. **john_the_ripper.txt**
- **Descripción**: Herramienta de cracking de passwords John the Ripper
- **Categorías**: Comandos básicos, tipos de hash, modos de ataque, extracción de hashes
- **Uso**: Auditoría de passwords y cracking

### 6. **burp_suite.txt**
- **Descripción**: Herramienta profesional de testing de aplicaciones web
- **Categorías**: Atajos de teclado, configuración proxy, intruder, payloads, scanner, extensiones
- **Uso**: Testing de seguridad en aplicaciones web

### 7. **analisis_logs.txt**
- **Descripción**: Análisis forense de logs del sistema
- **Categorías**: Ubicaciones de logs, comandos de análisis, detección de ataques, filtrado por tiempo
- **Uso**: Análisis forense y detección de incidentes

### 8. **osint_basico.txt**
- **Descripción**: Inteligencia de fuentes abiertas (OSINT)
- **Categorías**: Búsqueda de dominios, subdominios, Google dorks, Shodan, redes sociales, metadatos
- **Uso**: Recopilación de información y reconocimiento

### 9. **hydra_bruteforce.txt**
- **Descripción**: Herramienta de fuerza bruta multiplataforma Hydra
- **Categorías**: Ataques a SSH, FTP, HTTP, SMTP, SMB, RDP, bases de datos, evasión de protecciones
- **Uso**: Auditoría de contraseñas y testing de autenticación

### 10. **sqlmap_injection.txt**
- **Descripción**: Herramienta automática de detección y explotación de SQL injection
- **Categorías**: Detección, enumeración, extracción de datos, técnicas avanzadas, bypass WAF
- **Uso**: Testing de seguridad en aplicaciones web y bases de datos

### 11. **gobuster_directory.txt**
- **Descripción**: Herramienta de fuerza bruta para directorios, archivos y subdominios
- **Categorías**: Directory brute force, DNS enumeration, virtual host discovery, fuzzing
- **Uso**: Reconocimiento web y descubrimiento de contenido oculto

### 12. **wireshark_analisis.txt**
- **Descripción**: Analizador de protocolos de red más avanzado del mundo
- **Categorías**: Análisis de tráfico, filtros, detección de malware, forense de red, protocolos
- **Uso**: Análisis de tráfico de red, troubleshooting e investigación forense

### 13. **nikto_web_scanner.txt**
- **Descripción**: Escáner de vulnerabilidades web con base de datos de 6700+ checks
- **Categorías**: Escaneo de vulnerabilidades, configuraciones inseguras, bypass WAF
- **Uso**: Auditoría de seguridad en servidores web y aplicaciones

### 14. **aircrack_wifi_audit.txt**
- **Descripción**: Suite completa de herramientas para auditoría de seguridad WiFi
- **Categorías**: Captura de handshakes, ataques WEP/WPA, access points falsos, monitoreo
- **Uso**: Auditoría de seguridad en redes inalámbricas

### 15. **netcat_networking.txt**
- **Descripción**: La navaja suiza de herramientas de red (nc)
- **Categorías**: Transferencia de archivos, reverse shells, port scanning, tunneling, honeypots
- **Uso**: Networking, pentesting, transferencia de datos y shells remotas

### 16. **linux_comandos_completo.txt**
- **Descripción**: Comandos esenciales de Linux para profesionales de ciberseguridad
- **Categorías**: Navegación, procesos, red, archivos, logs, forense, escalación de privilegios
- **Uso**: Administración de sistemas, análisis forense y operaciones de seguridad

### 17. **hashcat_password_cracking.txt**
- **Descripción**: Herramienta de cracking de passwords más avanzada con soporte GPU
- **Categorías**: Ataques de diccionario, máscaras, reglas, optimización, múltiples formatos hash
- **Uso**: Auditoría de contraseñas, análisis forense y testing de políticas de seguridad

### 18. **volatility_memory_forensics.txt**
- **Descripción**: Framework de análisis forense de memoria RAM más completo
- **Categorías**: Análisis de procesos, red, registro, archivos, detección de malware, timeline
- **Uso**: Incident response, análisis forense digital y detección de amenazas avanzadas

## Instrucciones de Uso

### Cargar Cheatsheets
1. Seleccionar categoría en el panel izquierdo
2. El contenido se carga automáticamente en el panel derecho
3. Usar la función de búsqueda para encontrar comandos específicos

### Editar Cheatsheets
1. Modificar el contenido directamente en el área de texto
2. Hacer clic en "Guardar Cambios" para persistir las modificaciones
3. Los cambios se guardan automáticamente en el archivo correspondiente

### Copiar Comandos
1. Seleccionar el texto deseado en el área de comandos
2. Hacer clic en "Copiar Comando" para enviarlo al portapapeles
3. Pegar en terminal o aplicación destino

### Buscar en Cheatsheets
1. Escribir término de búsqueda en el campo correspondiente
2. Presionar Enter o hacer clic en "Buscar"
3. Los resultados se resaltan automáticamente
4. Navegación automática al primer resultado

## Personalización

### Agregar Nuevos Cheatsheets
1. Crear archivo .txt en la carpeta `data/cheatsheets/`
2. Actualizar `cheatsheets_config.json` con la nueva categoría
3. Reiniciar Ares Aegis para cargar los cambios

### Formato Recomendado
```
# TÍTULO DEL CHEATSHEET

## Categoría 1
comando1                          # Descripción
comando2                          # Descripción

## Categoría 2
comando3                          # Descripción
comando4                          # Descripción
```

## Notas Técnicas
- **Codificación**: UTF-8
- **Formato**: Texto plano (.txt)
- **Editable**: Sí, en tiempo real
- **Persistencia**: Automática al guardar
- **Búsqueda**: Insensible a mayúsculas/minúsculas
- **Compatibilidad**: Todos los sistemas operativos

---
**Ares Aegis - Suite de Ciberseguridad Profesional**  
Versión: 1.0 | Fecha: Agosto 2025
