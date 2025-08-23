# CHEATSHEET DE ANÁLISIS DE RED

## **HERRAMIENTAS NATIVAS DE RED**

### **DESCUBRIMIENTO DE HOSTS**

#### **Ping Sweep**
```bash
# Ping simple
ping -c 1 192.168.1.1

# Ping sweep básico
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i 2>/dev/null | grep "64 bytes" &
done
wait

# Ping sweep con timeout
for ip in 192.168.1.{1..254}; do
    timeout 1 ping -c 1 "$ip" >/dev/null 2>&1 && echo "$ip is alive" &
done
wait
```

#### **ARP Discovery**
```bash
# Tabla ARP actual
arp -a

# Scan ARP de red local
for i in {1..254}; do
    arping -c 1 -W 1 192.168.1.$i 2>/dev/null | grep "Unicast reply" &
done
wait

# Análisis de tabla ARP
arp -a | grep -E "([0-9a-f]{2}:){5}[0-9a-f]{2}"
```

### ** ESCANEO DE PUERTOS**

#### **Netcat Port Scanning**
```bash
# Puerto individual
nc -zv 192.168.1.100 22

# Rango de puertos
nc -zv 192.168.1.100 1-1000

# Puertos TCP comunes
for port in 21 22 23 25 53 80 110 143 443 993 995; do
    nc -zv 192.168.1.100 $port 2>&1 | grep succeeded
done

# Puertos UDP
nc -zuv 192.168.1.100 53
```

#### **Escaneo con /dev/tcp**
```bash
# Test de puerto TCP
check_port() {
    local host=$1
    local port=$2
    timeout 3 bash -c "</dev/tcp/$host/$port" 2>/dev/null && echo "Puerto $port abierto"
}

# Escaneo rápido
for port in {1..1000}; do
    check_port 192.168.1.100 $port &
done
wait
```

#### **Banner Grabbing**
```bash
# HTTP Banner
echo "GET / HTTP/1.0" | nc 192.168.1.100 80

# SSH Banner
nc 192.168.1.100 22

# SMTP Banner
echo "EHLO test" | nc 192.168.1.100 25

# Telnet Banner
echo "" | nc 192.168.1.100 23
```

### ** ANÁLISIS DE CONEXIONES ACTIVAS**

#### **Comando ss (Socket Statistics)**
```bash
# Todas las conexiones
ss -tuln

# Solo TCP
ss -tln

# Solo UDP
ss -uln

# Conexiones establecidas
ss -t state established

# Procesos asociados
ss -tlnp

# Estadísticas de red
ss -s

# Conexiones por estado
ss -t state listening
ss -t state syn-sent
ss -t state time-wait
```

#### **Comando netstat (Legacy)**
```bash
# Todas las conexiones
netstat -tuln

# Con procesos
netstat -tulnp

# Estadísticas
netstat -s

# Tabla de enrutamiento
netstat -rn

# Conexiones activas
netstat -an | grep ESTABLISHED
```

#### **Análisis con lsof**
```bash
# Conexiones de red por proceso
lsof -i

# Puerto específico
lsof -i :80

# TCP/UDP específico
lsof -iTCP
lsof -iUDP

# Por proceso
lsof -p 1234 -i

# Archivos abiertos por usuario
lsof -u www-data -i
```

### ** MONITOREO DE TRÁFICO**

#### **Análisis de Interfaces**
```bash
# Interfaces de red
ip link show
ip addr show

# Estadísticas de interfaz
cat /proc/net/dev

# Tráfico en tiempo real
watch -n 1 'cat /proc/net/dev | column -t'

# Información de ruta
ip route show
route -n
```

#### **Análisis de Paquetes Básico**
```bash
# tcpdump básico (si disponible)
tcpdump -i eth0 -n

# Captura específica
tcpdump -i eth0 host 192.168.1.100
tcpdump -i eth0 port 80

# Sin tcpdump: monitoreo de conexiones
watch -n 1 'ss -tuln | wc -l'
```

### **SYMBOL ANÁLISIS DNS**

#### **Resolución DNS**
```bash
# nslookup básico
nslookup google.com

# Dig (si disponible)
dig google.com
dig @8.8.8.8 google.com

# host command
host google.com

# Resolución inversa
nslookup 8.8.8.8
```

#### **Enumeración DNS**
```bash
# Registros comunes
nslookup -type=MX domain.com
nslookup -type=TXT domain.com
nslookup -type=NS domain.com

# Subdominios comunes
for sub in www mail ftp admin; do
    nslookup $sub.domain.com 2>/dev/null | grep -v "NXDOMAIN"
done
```

### ** DETECCIÓN DE SERVICIOS**

#### **Identificación de Servicios**
```bash
# Banner grabbing por protocolo
get_http_banner() {
    echo -e "GET / HTTP/1.0\r\n\r\n" | nc -w 3 $1 80 2>/dev/null
}

get_ssh_banner() {
    nc -w 3 $1 22 2>/dev/null | head -1
}

get_smtp_banner() {
    echo -e "QUIT\r\n" | nc -w 3 $1 25 2>/dev/null
}

# Detección de servicio web
curl -I http://192.168.1.100 2>/dev/null | head -1
```

#### **Fingerprinting de OS**
```bash
# TTL analysis
ping -c 1 192.168.1.100 | grep ttl

# TCP window size
echo "" | nc 192.168.1.100 80 2>/dev/null | hexdump -C

# SSH version
nc 192.168.1.100 22 2>/dev/null | head -1
```

### ** DETECCIÓN DE ANOMALÍAS**

#### **Conexiones Sospechosas**
```bash
# Top IPs conectadas
ss -tuln | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr

# Puertos no estándar
ss -tuln | awk '{print $4}' | cut -d: -f2 | sort -n | uniq

# Procesos con conexiones múltiples
lsof -i | awk '{print $2}' | sort | uniq -c | sort -nr

# Conexiones a IPs externas
ss -tn | awk '{print $4}' | grep -v 127.0.0.1 | grep -v 192.168 | grep -v 10.0
```

#### **Análisis de Tráfico**
```bash
# Monitoreo de conexiones nuevas
baseline_connections=$(ss -tn | wc -l)
sleep 60
current_connections=$(ss -tn | wc -l)
echo "Diferencia de conexiones: $((current_connections - baseline_connections))"

# Procesos con más conexiones
lsof -i -n | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
```

### ** SCRIPTS DE AUTOMATIZACIÓN**

#### **Network Discovery Script**
```bash
#!/bin/bash
# network_discovery.sh

NETWORK="192.168.1"

echo "=== NETWORK DISCOVERY ==="
echo "Escaneando red $NETWORK.0/24"

# Host discovery
echo "[*] Descubriendo hosts activos..."
active_hosts=()
for i in {1..254}; do
    if ping -c 1 -W 1 "$NETWORK.$i" >/dev/null 2>&1; then
        echo "[+] Host activo: $NETWORK.$i"
        active_hosts+=("$NETWORK.$i")
    fi
done

# Port scan en hosts activos
echo -e "\n[*] Escaneando puertos en hosts activos..."
for host in "${active_hosts[@]}"; do
    echo "[*] Escaneando $host..."
    for port in 21 22 23 25 53 80 110 143 443 993 995; do
        nc -zv "$host" "$port" 2>&1 | grep succeeded && echo "  [+] Puerto $port abierto"
    done
done
```

#### **Connection Monitor Script**
```bash
#!/bin/bash
# connection_monitor.sh

LOG_FILE="/tmp/connection_monitor.log"

monitor_connections() {
    while true; do
        timestamp=$(date)
        connections=$(ss -tn | wc -l)
        echo "$timestamp - Conexiones activas: $connections" >> "$LOG_FILE"
        
        # Alertar si hay muchas conexiones
        if [ "$connections" -gt 100 ]; then
            echo "ALERTA: Muchas conexiones detectadas ($connections)" >> "$LOG_FILE"
        fi
        
        sleep 60
    done
}

echo "Iniciando monitoreo de conexiones..."
monitor_connections &
echo "Monitor iniciado con PID: $!"
```

#### **Service Detection Script**
```bash
#!/bin/bash
# service_detection.sh

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Uso: $0 <IP_TARGET>"
    exit 1
fi

echo "=== DETECCIÓN DE SERVICIOS ==="
echo "Target: $TARGET"

# Common ports
ports=(21 22 23 25 53 80 110 143 443 993 995 3306 5432)

for port in "${ports[@]}"; do
    if nc -zv "$TARGET" "$port" 2>&1 | grep -q succeeded; then
        echo "[+] Puerto $port abierto"
        
        # Banner grabbing específico
        case $port in
            80|8080)
                echo "  HTTP Banner:"
                echo -e "GET / HTTP/1.0\r\n\r\n" | nc -w 3 "$TARGET" "$port" | head -10
                ;;
            22)
                echo "  SSH Banner:"
                nc -w 3 "$TARGET" "$port" | head -1
                ;;
            25)
                echo "  SMTP Banner:"
                echo -e "EHLO test\r\n" | nc -w 3 "$TARGET" "$port" | head -5
                ;;
        esac
    fi
done
```

### ** ANÁLISIS DE RENDIMIENTO**

#### **Latencia y Conectividad**
```bash
# Ping estadísticas
ping -c 10 8.8.8.8 | tail -1

# Traceroute básico
traceroute 8.8.8.8

# MTU discovery
ping -M do -s 1472 8.8.8.8

# Bandwidth estimation básico
time curl -o /dev/null -s http://speedtest.com/mini.php
```

#### **Monitoreo de Interfaces**
```bash
# Estadísticas de interfaz
cat /sys/class/net/eth0/statistics/rx_bytes
cat /sys/class/net/eth0/statistics/tx_bytes

# Errores de red
cat /sys/class/net/eth0/statistics/rx_errors
cat /sys/class/net/eth0/statistics/tx_errors

# Monitor de tráfico simple
monitor_traffic() {
    interface="$1"
    while true; do
        rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes")
        tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes")
        echo "$(date): RX: $rx_bytes bytes, TX: $tx_bytes bytes"
        sleep 5
    done
}
```

### ** TROUBLESHOOTING DE RED**

#### **Diagnóstico de Conectividad**
```bash
# Test básico de conectividad
test_connectivity() {
    local target="$1"
    
    echo "=== DIAGNÓSTICO DE CONECTIVIDAD ==="
    echo "Target: $target"
    
    # Ping test
    if ping -c 3 "$target" >/dev/null 2>&1; then
        echo "[+] Ping exitoso"
    else
        echo "[-] Ping fallido"
        return 1
    fi
    
    # DNS resolution
    if nslookup "$target" >/dev/null 2>&1; then
        echo "[+] Resolución DNS exitosa"
    else
        echo "[-] Fallo en resolución DNS"
    fi
    
    # Port 80 test
    if nc -zv "$target" 80 2>/dev/null; then
        echo "[+] Puerto 80 accesible"
    else
        echo "[-] Puerto 80 no accesible"
    fi
}
```

---

** NOTA DE SEGURIDAD**: Estas herramientas son para diagnóstico de red y pruebas autorizadas únicamente. Siempre obtén permiso antes de escanear redes que no sean de tu propiedad.

** ARESITOS** - Análisis de Red para Profesionales de Ciberseguridad
