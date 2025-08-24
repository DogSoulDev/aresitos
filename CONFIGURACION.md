# 🔧 CONFIGURACIÓN Y ADMINISTRACIÓN - ARESITOS v3.0

## ⚙️ **CONFIGURACIÓN INICIAL**

### 🎯 **Configuración Automática vs Manual**

#### **Configuración Automática (Recomendada):**
```bash
# Configuración completa en un comando
sudo ./configurar_kali.sh

# Qué hace automáticamente:
# ✅ Instala 50+ herramientas de seguridad
# ✅ Configura permisos CAP_NET_RAW
# ✅ Establece sudo sin contraseña para herramientas específicas
# ✅ Actualiza bases de datos de vulnerabilidades
# ✅ Configura grupos de usuario necesarios
# ✅ Optimiza configuraciones del sistema
```

#### **Configuración Manual Avanzada:**
```bash
# 1. Instalar herramientas core manualmente
sudo apt update
sudo apt install nmap masscan gobuster feroxbuster curl sqlmap commix nikto

# 2. Configurar permisos especiales
sudo setcap cap_net_raw+epi /usr/bin/nmap
sudo setcap cap_net_raw+epi /usr/bin/masscan

# 3. Configurar grupos de usuario
sudo usermod -a -G wireshark $USER

# 4. Configurar sudo (opcional)
sudo visudo -f /etc/sudoers.d/aresitos-custom
```

---

## 🔐 **GESTIÓN DE PERMISOS Y SEGURIDAD**

### **Permisos Configurados Automáticamente:**

#### **CAP_NET_RAW (Escaneos SYN):**
```bash
# Herramientas con permisos especiales:
/usr/bin/nmap          # Escaneos SYN sin sudo
/usr/bin/masscan       # Escaneos masivos rápidos
/usr/bin/tcpdump       # Captura de paquetes

# Verificar permisos:
getcap /usr/bin/nmap
getcap /usr/bin/masscan
```

#### **Configuración Sudo Sin Contraseña:**
```bash
# Archivo: /etc/sudoers.d/aresitos-escaneador-v3
# Herramientas permitidas sin contraseña:
# - nmap, masscan, rustscan
# - nuclei, nikto, whatweb
# - gobuster, feroxbuster, sqlmap
# - Acceso a logs del sistema
# - Comandos de análisis de red
```

#### **Grupos de Usuario:**
```bash
# Grupos configurados automáticamente:
wireshark    # Captura de paquetes con Wireshark
netdev       # Configuración de interfaces de red

# Verificar membresía:
groups $USER
```

### **Seguridad y Buenas Prácticas:**

#### **Lista Blanca de Herramientas:**
```python
# Solo estas herramientas pueden ejecutarse:
herramientas_permitidas = {
    'nmap', 'masscan', 'rustscan', 'nuclei',
    'gobuster', 'feroxbuster', 'curl', 'sqlmap',
    'commix', 'nikto', 'whatweb', 'hashcat',
    # ... lista completa verificada
}
```

#### **Validación de Argumentos:**
```python
# Argumentos seguros permitidos:
argumentos_seguros = {
    '--help', '-h', '--version', '-v',
    '--target', '-t', '--port', '-p',
    '--output', '-o', '--verbose'
}
```

---

## 📊 **CONFIGURACIÓN DE MÓDULOS**

### 🔍 **Escaneador Profesional**

#### **Configuración de Herramientas:**
```bash
# Archivo: aresitos/controlador/controlador_herramientas.py
# Herramientas core configuradas:
SCANNER_TOOLS = {
    'nmap': 'Escaneador principal con scripts NSE',
    'masscan': 'Escaneo masivo ultrarrápido', 
    'rustscan': 'Scanner moderno en Rust',
    'nuclei': 'Detección de vulnerabilidades CVE',
    'gobuster': 'Directory/file brute forcer',
    'feroxbuster': 'Content discovery tool',
    'curl': 'HTTP probing y testing'
}
```

#### **Modos de Escaneo Configurables:**
```python
SCAN_MODES = {
    'integral': {
        'tools': ['nmap', 'nuclei', 'gobuster'],
        'intensity': 'high',
        'timeout': 1800
    },
    'rapido': {
        'tools': ['rustscan', 'curl'],
        'intensity': 'low', 
        'timeout': 300
    }
}
```

### 🛡️ **Sistema SIEM**

#### **Puertos Monitoreados por Defecto:**
```python
CRITICAL_PORTS = [
    22,   # SSH
    23,   # Telnet  
    53,   # DNS
    80,   # HTTP
    443,  # HTTPS
    21,   # FTP
    25,   # SMTP
    110,  # POP3
    143,  # IMAP
    993,  # IMAPS
    995,  # POP3S
    3389, # RDP
    5432, # PostgreSQL
    3306, # MySQL
    1433, # SQL Server
    # ... lista completa configurable
]
```

#### **Configuración de Alertas:**
```python
ALERT_CONFIG = {
    'critical_threshold': 5,      # Conexiones simultáneas
    'warning_threshold': 3,       # Intentos fallidos
    'monitor_interval': 30,       # Segundos entre verificaciones
    'log_retention': 7            # Días de retención de logs
}
```

### 📁 **File Integrity Monitoring (FIM)**

#### **Directorios Monitoreados:**
```python
MONITORED_DIRS = [
    '/etc/',           # Configuraciones del sistema
    '/bin/',           # Binarios del sistema
    '/sbin/',          # Binarios de administración
    '/usr/bin/',       # Binarios de usuario
    '/usr/sbin/',      # Binarios de administración de usuario
    '/home/',          # Directorios de usuario
    '/var/log/',       # Logs del sistema
    '/boot/',          # Archivos de arranque
    # ... lista completa personalizable
]
```

#### **Configuración de Checksums:**
```python
FIM_CONFIG = {
    'hash_algorithm': 'sha256',
    'scan_interval': 300,         # 5 minutos
    'exclude_patterns': [
        '*.log', '*.tmp', '*.cache',
        '/proc/', '/sys/', '/dev/'
    ],
    'real_time_monitoring': True
}
```

---

## 🗄️ **GESTIÓN DE BASES DE DATOS**

### **Bases de Datos Incluidas:**

#### **vulnerability_database.json:**
```json
{
  "metadatos": {
    "version": "3.0.0",
    "total_vulnerabilidades": 500,
    "fuentes": ["CVE Database", "NIST NVD", "OWASP"]
  },
  "herramientas_automaticas": [
    "nmap", "rustscan", "masscan", "nuclei", "curl"
  ]
}
```

#### **hacking_tools.json:**
```json
{
  "Nmap": "Network Mapper - Port scanning and network discovery",
  "Curl": "Command line tool for transferring data with URLs",
  "Feroxbuster": "Fast, simple, recursive content discovery tool",
  "Gobuster": "Directory/File, DNS and VHost busting tool"
}
```

### **Gestión de Wordlists:**

#### **Ubicaciones Estándar:**
```bash
/usr/share/wordlists/
├── dirb/                 # Directorios web
├── dirbuster/           # Archivos y directorios
├── fasttrack/           # Passwords comunes
├── metasploit/          # Exploits y payloads
├── nmap/                # Scripts NSE
└── rockyou.txt          # Passwords más comunes
```

#### **Wordlists Personalizadas:**
```bash
aresitos/data/wordlists/
├── custom_dirs.txt      # Directorios personalizados
├── api_endpoints.txt    # Endpoints de API
├── subdomains.txt       # Subdominios comunes
└── technology_stack.txt # Stack tecnológico
```

---

## ⚙️ **CONFIGURACIONES AVANZADAS**

### **Variables de Entorno:**

#### **Optimización de Rendimiento:**
```bash
# .bashrc o .zshrc
export ARESITOS_SCANNER_THREADS=8      # Hilos para escaneo
export ARESITOS_SCANNER_TIMEOUT=600    # Timeout en segundos
export ARESITOS_LOW_MEMORY=0           # Modo bajo consumo
export ARESITOS_DEBUG=0                # Modo debug
export ARESITOS_NO_AUTO_UPDATE=0       # Deshabilitar updates automáticos
```

#### **Configuración de Logs:**
```bash
export ARESITOS_LOG_LEVEL=INFO         # DEBUG, INFO, WARNING, ERROR
export ARESITOS_LOG_FILE=/var/log/aresitos.log
export ARESITOS_LOG_ROTATION=daily     # daily, weekly, monthly
```

### **Configuración de Red:**

#### **Interfaces y Routing:**
```python
NETWORK_CONFIG = {
    'default_interface': 'auto',        # Auto-detectar
    'scan_source_ip': 'auto',          # IP origen para escaneos
    'max_concurrent_scans': 5,         # Escaneos simultáneos
    'bandwidth_limit': '10M',          # Límite de ancho de banda
    'respect_rate_limits': True        # Respetar rate limits
}
```

#### **Configuración de Proxies:**
```python
PROXY_CONFIG = {
    'http_proxy': None,                # http://proxy:port
    'https_proxy': None,               # https://proxy:port
    'socks_proxy': None,               # socks5://proxy:port
    'bypass_list': ['localhost', '127.0.0.1']
}
```

---

## 🔧 **MANTENIMIENTO Y ACTUALIZACIONES**

### **Actualizaciones del Sistema:**

#### **Actualización Automática:**
```bash
# Crear script de actualización automática
cat > /usr/local/bin/aresitos-update << 'EOF'
#!/bin/bash
cd /opt/aresitos
git pull origin master
sudo ./configurar_kali.sh --update
python3 verificacion_final.py
EOF

chmod +x /usr/local/bin/aresitos-update
```

#### **Actualización Manual:**
```bash
# Actualizar código fuente
git pull origin master

# Actualizar herramientas
sudo ./configurar_kali.sh --update

# Actualizar templates nuclei
nuclei -update-templates

# Actualizar bases de datos
python3 utils/update_databases.py
```

### **Mantenimiento de Bases de Datos:**

#### **Limpieza Regular:**
```bash
# Limpiar logs antiguos
find logs/ -name "*.log" -mtime +30 -delete

# Limpiar reportes antiguos  
find reportes/ -name "*.json" -mtime +90 -delete

# Limpiar cache temporal
rm -rf data/cache/*
```

#### **Backup de Configuración:**
```bash
# Crear backup de configuración
tar -czf aresitos-config-$(date +%Y%m%d).tar.gz \
    configuración/ data/ logs/

# Restaurar desde backup
tar -xzf aresitos-config-YYYYMMDD.tar.gz
```

### **Monitoreo de Performance:**

#### **Logs de Sistema:**
```bash
# Monitorear uso de recursos
tail -f /var/log/aresitos.log | grep PERFORMANCE

# Monitorear errores
tail -f /var/log/aresitos.log | grep ERROR

# Estadísticas de escaneos
grep "SCAN_COMPLETED" /var/log/aresitos.log | wc -l
```

#### **Métricas de Rendimiento:**
```python
PERFORMANCE_METRICS = {
    'scans_per_hour': 0,
    'average_scan_time': 0,
    'memory_usage_mb': 0,
    'cpu_usage_percent': 0,
    'network_throughput_mbps': 0
}
```

---

## 🚨 **SOLUCIÓN DE PROBLEMAS AVANZADOS**

### **Problemas de Permisos:**

#### **Permisos CAP_NET_RAW Perdidos:**
```bash
# Restablecer permisos CAP_NET_RAW
sudo setcap cap_net_raw+epi /usr/bin/nmap
sudo setcap cap_net_raw+epi /usr/bin/masscan

# Verificar que se aplicaron
getcap /usr/bin/nmap
getcap /usr/bin/masscan
```

#### **Problemas con Sudo:**
```bash
# Verificar configuración sudo
sudo visudo -c -f /etc/sudoers.d/aresitos-escaneador-v3

# Re-crear configuración sudo
sudo ./configurar_kali.sh --sudo-only
```

### **Problemas de Red:**

#### **Escaneos Bloqueados por Firewall:**
```bash
# Verificar iptables
sudo iptables -L

# Permitir tráfico ARESITOS (temporal)
sudo iptables -I OUTPUT -j ACCEPT
sudo iptables -I INPUT -j ACCEPT
```

#### **Problemas con DNS:**
```bash
# Verificar resolución DNS
nslookup google.com

# Configurar DNS alternativo
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

### **Problemas de Rendimiento:**

#### **Alto Uso de Memoria:**
```bash
# Modo bajo consumo
export ARESITOS_LOW_MEMORY=1
export ARESITOS_SCANNER_THREADS=2
python3 main.py
```

#### **Escaneos Lentos:**
```bash
# Optimizar para velocidad
export ARESITOS_SCANNER_THREADS=10
export ARESITOS_SCANNER_TIMEOUT=120
python3 main.py
```

---

## 📋 **CHECKLIST DE CONFIGURACIÓN**

### **Configuración Inicial Completa:**
- [ ] Ejecutado `sudo ./configurar_kali.sh` exitosamente
- [ ] Permisos CAP_NET_RAW configurados para nmap/masscan
- [ ] Usuario agregado a grupos wireshark/netdev
- [ ] Configuración sudo sin contraseña aplicada
- [ ] Herramientas core instaladas (nmap, curl, gobuster, etc.)
- [ ] Templates nuclei actualizados
- [ ] Verificación completa pasada sin errores

### **Configuración Avanzada:**
- [ ] Variables de entorno configuradas según necesidades
- [ ] Configuración de red optimizada
- [ ] Logs y monitoreo configurados
- [ ] Backup automático programado
- [ ] Actualizaciones automáticas configuradas
- [ ] Configuración de proxies (si es necesario)

### **Verificación Post-Configuración:**
- [ ] ARESITOS inicia sin errores
- [ ] Todos los módulos funcionan correctamente
- [ ] Escaneos básicos ejecutan exitosamente
- [ ] Reportes se generan correctamente
- [ ] No hay errores en logs del sistema

---

*Documentación de configuración actualizada: 24 de Agosto de 2025*  
*Versión: ARESITOS v3.0.0*  
*Autor: DogSoulDev*
