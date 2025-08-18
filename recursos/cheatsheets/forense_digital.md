#  CHEATSHEET DE FORENSE DIGITAL

## ** ANÁLISIS FORENSE CON HERRAMIENTAS NATIVAS**

### **� PRESERVACIÓN DE EVIDENCIA**

#### **Creación de Imágenes Forenses**
```bash
# dd para crear imagen bit a bit
dd if=/dev/sdb of=/casos/evidencia.img bs=4096 conv=noerror,sync status=progress

# Verificación de integridad
sha256sum /dev/sdb > /casos/hash_original.txt
sha256sum /casos/evidencia.img > /casos/hash_imagen.txt

# Montaje de imagen en solo lectura
mkdir /mnt/evidencia
mount -o ro,loop /casos/evidencia.img /mnt/evidencia

# Información del dispositivo
fdisk -l /dev/sdb
file -s /dev/sdb*
```

#### **Documentación de la Escena**
```bash
# Información del sistema
uname -a > /casos/info_sistema.txt
date >> /casos/info_sistema.txt
uptime >> /casos/info_sistema.txt

# Procesos en ejecución
ps aux > /casos/procesos.txt
ps -eo pid,ppid,cmd,etime > /casos/procesos_detalle.txt

# Conexiones de red
ss -tuln > /casos/conexiones.txt
lsof -i > /casos/archivos_red.txt

# Usuarios conectados
who > /casos/usuarios_conectados.txt
last > /casos/historial_conexiones.txt
```

### **� ANÁLISIS DE ARCHIVOS**

#### **Búsqueda de Archivos Específicos**
```bash
# Archivos por extensión
find /mnt/evidencia -name "*.doc" -o -name "*.pdf" -o -name "*.txt" > /casos/documentos.txt

# Archivos modificados en fechas específicas
find /mnt/evidencia -type f -newermt "2024-01-01" ! -newermt "2024-01-31"

# Archivos por tamaño
find /mnt/evidencia -type f -size +100M > /casos/archivos_grandes.txt

# Archivos ocultos
find /mnt/evidencia -name ".*" -type f > /casos/archivos_ocultos.txt

# Archivos sin extensión
find /mnt/evidencia -type f ! -name "*.*" > /casos/sin_extension.txt
```

#### **Análisis de Metadatos**
```bash
# Información detallada de archivo
stat /path/to/file

# Tipo de archivo real
file /path/to/file

# Strings en archivos binarios
strings /path/to/binary > /casos/strings_output.txt

# Hexdump para análisis manual
hexdump -C /path/to/file | head -20

# Examinar headers de archivos
head -c 100 /path/to/file | hexdump -C
```

#### **Análisis de Imágenes y Multimedia**
```bash
# Metadatos de imágenes con file
file imagen.jpg

# Información EXIF básica con strings
strings imagen.jpg | grep -E "(Make|Model|DateTime|GPS)"

# Análisis de archivos multimedia
file video.mp4
strings video.mp4 | head -50
```

### **� ANÁLISIS TEMPORAL**

#### **Línea de Tiempo de Archivos**
```bash
# Timeline básico con find
find /mnt/evidencia -type f -printf "%T+ %p\n" | sort > /casos/timeline.txt

# Archivos modificados por día
find /mnt/evidencia -type f -mtime -7 -ls > /casos/modificados_7dias.txt

# Archivos accedidos recientemente
find /mnt/evidencia -type f -atime -1 -ls > /casos/accedidos_1dia.txt

# Análisis de logs por fecha
grep "2024-01-15" /var/log/syslog > /casos/logs_fecha.txt
```

#### **Análisis de Timestamps**
```bash
# Función para mostrar todos los timestamps
show_timestamps() {
    local file="$1"
    echo "=== Timestamps para $file ==="
    stat "$file" | grep -E "(Access|Modify|Change|Birth)"
}

# Detectar posible manipulación de timestamps
detect_timestamp_anomalies() {
    find /mnt/evidencia -type f -printf "%T@ %A@ %C@ %p\n" | \
    awk '{if($1 > $2 || $1 > $3) print "ANOMALÍA: " $4}'
}
```

### **� ANÁLISIS DE MEMORIA Y PROCESOS**

#### **Información de Memoria**
```bash
# Memoria disponible
free -h > /casos/memoria.txt
cat /proc/meminfo >> /casos/memoria.txt

# Mapas de memoria de procesos
for pid in $(ps -eo pid --no-headers); do
    if [ -r "/proc/$pid/maps" ]; then
        echo "=== PID $pid ===" >> /casos/memory_maps.txt
        cat "/proc/$pid/maps" >> /casos/memory_maps.txt 2>/dev/null
    fi
done
```

#### **Análisis de Procesos**
```bash
# Procesos con rutas completas
ps -eo pid,ppid,cmd,etime,user > /casos/procesos_completo.txt

# Archivos abiertos por proceso
for pid in $(ps -eo pid --no-headers); do
    if [ -d "/proc/$pid" ]; then
        echo "=== PID $pid ===" >> /casos/archivos_abiertos.txt
        lsof -p "$pid" >> /casos/archivos_abiertos.txt 2>/dev/null
    fi
done

# Árbol de procesos
pstree -p > /casos/arbol_procesos.txt

# Variables de entorno de procesos
for pid in $(ps -eo pid --no-headers | head -20); do
    if [ -r "/proc/$pid/environ" ]; then
        echo "=== PID $pid ENV ===" >> /casos/entornos.txt
        tr '\0' '\n' < "/proc/$pid/environ" >> /casos/entornos.txt
    fi
done
```

### ** ANÁLISIS DE RED**

#### **Conexiones y Puertos**
```bash
# Estado completo de red
ss -tulnp > /casos/red_completo.txt

# Tabla de enrutamiento
ip route > /casos/rutas.txt
route -n >> /casos/rutas.txt

# Configuración de interfaces
ip addr > /casos/interfaces.txt
ifconfig -a >> /casos/interfaces.txt 2>/dev/null

# ARP table
arp -a > /casos/arp_table.txt
ip neigh > /casos/neighbors.txt
```

#### **Análisis de Logs de Red**
```bash
# Conexiones en logs
grep -E "(ssh|ftp|http|telnet)" /var/log/auth.log > /casos/conexiones_logs.txt

# IPs más frecuentes en logs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr > /casos/ips_frecuentes.txt

# Análisis de firewall
iptables -L -n > /casos/firewall_rules.txt
ufw status verbose >> /casos/firewall_rules.txt 2>/dev/null
```

### ** ANÁLISIS DE USUARIOS Y AUTENTICACIÓN**

#### **Información de Usuarios**
```bash
# Lista de usuarios
cat /etc/passwd > /casos/usuarios.txt
getent passwd >> /casos/usuarios.txt

# Grupos del sistema
cat /etc/group > /casos/grupos.txt

# Últimos logins
last > /casos/ultimos_logins.txt
lastlog > /casos/ultimo_login_usuarios.txt

# Intentos de login fallidos
grep "Failed password" /var/log/auth.log > /casos/logins_fallidos.txt

# Comandos sudo ejecutados
grep "COMMAND" /var/log/auth.log > /casos/comandos_sudo.txt
```

#### **Análisis de SSH**
```bash
# Claves SSH autorizadas
for user_home in /home/*; do
    if [ -f "$user_home/.ssh/authorized_keys" ]; then
        echo "=== $user_home ===" >> /casos/ssh_keys.txt
        cat "$user_home/.ssh/authorized_keys" >> /casos/ssh_keys.txt
    fi
done

# Configuración SSH
cat /etc/ssh/sshd_config > /casos/ssh_config.txt

# Logs de SSH
grep "sshd" /var/log/auth.log > /casos/ssh_logs.txt
```

### ** ANÁLISIS DE SISTEMA DE ARCHIVOS**

#### **Permisos y Propiedades**
```bash
# Archivos SUID/SGID
find /mnt/evidencia -type f \( -perm -4000 -o -perm -2000 \) -ls > /casos/suid_sgid.txt

# Archivos con permisos extraños
find /mnt/evidencia -type f -perm 777 > /casos/permisos_777.txt

# Directorios con sticky bit
find /mnt/evidencia -type d -perm +1000 > /casos/sticky_bit.txt

# Archivos sin propietario
find /mnt/evidencia -nouser -o -nogroup > /casos/sin_propietario.txt
```

#### **Análisis de Configuración**
```bash
# Archivos de configuración importantes
config_files=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/hosts"
    "/etc/crontab"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/apache2/apache2.conf"
    "/etc/nginx/nginx.conf"
)

for file in "${config_files[@]}"; do
    if [ -f "/mnt/evidencia$file" ]; then
        echo "=== $file ===" >> /casos/configuraciones.txt
        cat "/mnt/evidencia$file" >> /casos/configuraciones.txt
        echo "" >> /casos/configuraciones.txt
    fi
done
```

### ** BÚSQUEDA DE EVIDENCIA**

#### **Palabras Clave y Patrones**
```bash
# Búsqueda de contraseñas en archivos
grep -r -i "password" /mnt/evidencia --include="*.txt" --include="*.conf" > /casos/passwords_found.txt

# Búsqueda de emails
grep -r -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" /mnt/evidencia > /casos/emails_found.txt

# Búsqueda de números de tarjeta de crédito
grep -r -E "4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}" /mnt/evidencia > /casos/credit_cards.txt

# Búsqueda de URLs
grep -r -E "https?://[^\s]+" /mnt/evidencia > /casos/urls_found.txt

# Búsqueda de hashes
grep -r -E "[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}" /mnt/evidencia > /casos/hashes_found.txt
```

#### **Análisis de Logs del Sistema**
```bash
# Eventos importantes en syslog
grep -E "(error|fail|denied|invalid)" /var/log/syslog > /casos/eventos_importantes.txt

# Análisis de cron
cat /var/log/cron > /casos/cron_logs.txt
crontab -l > /casos/crontab_usuario.txt 2>/dev/null

# Logs de aplicaciones
ls -la /var/log/ > /casos/logs_disponibles.txt

# Kernel messages
dmesg > /casos/kernel_messages.txt
```

### ** SCRIPTS FORENSES**

#### **Script de Recolección de Evidencia**
```bash
#!/bin/bash
# evidence_collector.sh

CASE_DIR="/casos/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$CASE_DIR"

echo "=== RECOLECCIÓN DE EVIDENCIA ===" | tee "$CASE_DIR/evidence.log"
echo "Fecha: $(date)" | tee -a "$CASE_DIR/evidence.log"
echo "Investigador: $USER" | tee -a "$CASE_DIR/evidence.log"

# Información del sistema
echo "[*] Recolectando información del sistema..." | tee -a "$CASE_DIR/evidence.log"
uname -a > "$CASE_DIR/system_info.txt"
uptime >> "$CASE_DIR/system_info.txt"
free -h >> "$CASE_DIR/system_info.txt"

# Procesos activos
echo "[*] Capturando procesos..." | tee -a "$CASE_DIR/evidence.log"
ps aux > "$CASE_DIR/processes.txt"

# Red
echo "[*] Capturando información de red..." | tee -a "$CASE_DIR/evidence.log"
ss -tuln > "$CASE_DIR/network.txt"
lsof -i >> "$CASE_DIR/network.txt"

# Usuarios
echo "[*] Información de usuarios..." | tee -a "$CASE_DIR/evidence.log"
who > "$CASE_DIR/users.txt"
last >> "$CASE_DIR/users.txt"

# Hash del sistema
echo "[*] Generando hashes..." | tee -a "$CASE_DIR/evidence.log"
find /bin /sbin /usr/bin -type f -exec sha256sum {} \; > "$CASE_DIR/system_hashes.txt" 2>/dev/null

echo "[*] Recolección completada en $CASE_DIR" | tee -a "$CASE_DIR/evidence.log"
```

#### **Script de Análisis de Timeline**
```bash
#!/bin/bash
# timeline_analysis.sh

TARGET_DIR="$1"
OUTPUT_FILE="$2"

if [[ -z "$TARGET_DIR" || -z "$OUTPUT_FILE" ]]; then
    echo "Uso: $0 <directorio_evidencia> <archivo_salida>"
    exit 1
fi

echo "=== TIMELINE ANALYSIS ===" > "$OUTPUT_FILE"
echo "Directorio: $TARGET_DIR" >> "$OUTPUT_FILE"
echo "Fecha: $(date)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Timeline de archivos modificados
echo "=== ARCHIVOS MODIFICADOS ===" >> "$OUTPUT_FILE"
find "$TARGET_DIR" -type f -printf "%T+ %p\n" | sort >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# Timeline de accesos
echo "=== ARCHIVOS ACCEDIDOS ===" >> "$OUTPUT_FILE"
find "$TARGET_DIR" -type f -printf "%A+ %p\n" | sort >> "$OUTPUT_FILE"

echo "Timeline generado en $OUTPUT_FILE"
```

### ** ANÁLISIS ESTADÍSTICO**

#### **Estadísticas de Archivos**
```bash
# Tipos de archivo más comunes
find /mnt/evidencia -type f -exec file {} \; | cut -d: -f2 | sort | uniq -c | sort -nr > /casos/tipos_archivo.txt

# Extensiones más comunes
find /mnt/evidencia -type f -name "*.*" | sed 's/.*\.//' | sort | uniq -c | sort -nr > /casos/extensiones.txt

# Tamaños de archivo
find /mnt/evidencia -type f -printf "%s %p\n" | sort -nr > /casos/tamaños_archivo.txt

# Archivos por usuario
find /mnt/evidencia -type f -printf "%u %p\n" | sort | uniq -c > /casos/archivos_por_usuario.txt
```

### ** VERIFICACIÓN DE INTEGRIDAD**

#### **Hashes de Verificación**
```bash
# MD5 de archivos importantes
find /mnt/evidencia -type f -size -100M -exec md5sum {} \; > /casos/md5_hashes.txt

# SHA256 para mayor seguridad
find /mnt/evidencia -type f -size -100M -exec sha256sum {} \; > /casos/sha256_hashes.txt

# Verificación de integridad
verify_integrity() {
    local hash_file="$1"
    local base_dir="$2"
    
    while IFS= read -r line; do
        hash=$(echo "$line" | cut -d' ' -f1)
        file=$(echo "$line" | cut -d' ' -f3-)
        
        if [ -f "$file" ]; then
            current_hash=$(sha256sum "$file" | cut -d' ' -f1)
            if [ "$hash" != "$current_hash" ]; then
                echo "ALTERADO: $file"
            fi
        else
            echo "FALTANTE: $file"
        fi
    done < "$hash_file"
}
```

---

**⚖ NOTA LEGAL**: Este cheatsheet es para uso forense legal y educativo únicamente. Siempre cumple con las leyes locales y obtén las autorizaciones judiciales necesarias antes de realizar análisis forense.

** Ares Aegis** - Herramientas Forenses para Investigadores de Ciberseguridad
