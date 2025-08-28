#!/bin/bash
# -*- coding: utf-8 -*-
#
# ARESITOS v3.0 - Script de Configuración para Kali Linux
# =======================================================
#
# Script de configuración automática para preparar Kali Linux
# para ejecutar ARESITOS con todas las funcionalidades del escaneador profesional.
#
# Funciones principales:
# - Instalar herramientas de ciberseguridad avanzadas (nmap, masscan, rustscan, nuclei)
# - Configurar permisos sudo para herramientas específicas de escaneo
# - Configurar permisos de red para escaneo multiherramienta
# - Instalar herramientas forenses y SIEM
# - Actualizar bases de datos de vulnerabilidades
# - Verificar funcionamiento completo del sistema escaneador
#
# Autor: DogSoulDev
# Fecha: 23 de Agosto de 2025
# Versión: 3.0
# Proyecto: ARESITOS - Suite de Ciberseguridad Profesional
#
# IMPORTANTE: Este script debe ejecutarse como root o con sudo
# sudo ./configurar_kali.sh
#

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Establecer directorio de trabajo del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
echo -e "${CYAN}[SETUP]${NC} Directorio de trabajo establecido en: $SCRIPT_DIR"

# Función para imprimir con colores
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Verificar que se ejecuta como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root o con sudo"
        echo "Uso: sudo $0"
        exit 1
    fi
}

# Detectar el usuario que ejecutó sudo
detect_user() {
    if [[ -n "$SUDO_USER" ]]; then
        REAL_USER="$SUDO_USER"
        USER_HOME=$(eval echo ~$SUDO_USER)
    else
        REAL_USER=$(whoami)
        USER_HOME="$HOME"
    fi
    
    print_info "Usuario detectado: $REAL_USER"
    print_info "Directorio home: $USER_HOME"
}

# Actualizar repositorios
update_repositories() {
    print_header "🔄 Actualizando repositorios..."
    
    apt update
    if [[ $? -eq 0 ]]; then
        print_success "Repositorios actualizados"
    else
        print_warning "Error actualizando repositorios"
    fi
}

# Instalar herramientas necesarias
install_tools() {
    print_header "Instalando herramientas de escaneador profesional ARESITOS v3.0..."
    
    # Lista de herramientas ESENCIALES para escaneador profesional
    ESSENTIAL_TOOLS=(
        # Python y herramientas básicas (CRÍTICAS)
        "python3-dev"
        "python3-venv" 
        "python3-tk"
        "curl"
        "wget"
        "git"

        # Herramientas de escaneador PROFESIONAL (CORE)
        "nmap"                  # Escaneador principal - CRÍTICO
        "masscan"              # Escaneo masivo rápido
        "net-tools"            # netstat, ifconfig
        "iproute2"             # ss, ip commands
        "tcpdump"              # Captura de paquetes
        "iftop"                # Monitor de red
        "netcat-openbsd"       # Netcat

    # Herramientas forense y SIEM VERIFICADAS (paquetes correctos)
    "sleuthkit"            # Toolkit forense (incluye tsk_*)
    "foremost"             # Recuperación de archivos
    "binwalk"              # Análisis de firmware
    "binutils"             # Incluye strings
    "exiftool"             # Metadatos
    "testdisk"             # Incluye photorec
    "plaso"                # Análisis de líneas de tiempo forense
    "bulk-extractor"       # Extracción forense de datos
    "hashdeep"             # Hashing forense
    "dc3dd"                # Clonado forense de discos
    "guymager"             # Adquisición forense de discos

        # Utilidades del sistema ESTABLES
        "htop"
        "lsof"
        "psmisc"
        "dnsutils"             # dig, nslookup
        "whois"                # Información WHOIS
    )
    
    # Lista de herramientas AVANZADAS para escaneador profesional
    ADVANCED_TOOLS=(
    # Herramientas de escaneador avanzado (todas disponibles via APT)
    "ffuf"                 # Fuzzer web rápido (VERIFICADO en repos Kali)
    "feroxbuster"          # Scanner de directorios Rust (VERIFICADO en repos Kali)
    "nuclei"               # Motor de vulnerabilidades (VERIFICADO en repos Kali)
    "nikto"                # Scanner web
    "whatweb"              # Identificación web
    "dirb"                 # Brute force directorios
    # Herramientas de seguridad adicionales
    "lynis"                # Auditoría de seguridad
    "chkrootkit"           # Detección de rootkits
    "rkhunter"             # Hunter de rootkits
    "clamav"               # Antivirus
    # Herramientas forense adicionales (todas disponibles por APT)
    "yara"                 # Pattern matching
    "testdisk"             # Recuperación de particiones y archivos
    "plaso"                # Análisis de líneas de tiempo forense
    "bulk-extractor"       # Extracción forense de datos
    "hashdeep"             # Hashing forense
    "dc3dd"                # Clonado forense de discos
    "guymager"             # Adquisición forense de discos
    )
    
    # Herramientas especiales que requieren instalación manual
    SPECIAL_TOOLS=(
        "subfinder"            # Subdomain finder (Go, opcional, no recomendado para ARESITOS)
    )
    
    print_info "Actualizando lista de paquetes..."
    print_info "Incluyendo herramientas forenses avanzadas: testdisk, photorec, plaso, bulk-extractor, hashdeep, dc3dd, guymager, tsk_recover, tsk_loaddb, tsk_gettimes, tsk_comparedir, tsk_imageinfo"
    apt update -qq
    
    # Instalar herramientas ESENCIALES (críticas para funcionamiento)
    print_header "Instalando herramientas ESENCIALES..."
    FAILED_ESSENTIAL=()
    
    for tool in "${ESSENTIAL_TOOLS[@]}"; do
        print_info "Instalando herramienta CRÍTICA: $tool..."
        
        if dpkg -l | grep -q "^ii  $tool "; then
            print_success "$tool ya está instalado"
        else
            DEBIAN_FRONTEND=noninteractive apt install -y "$tool" >/dev/null 2>&1
            
            if [[ $? -eq 0 ]]; then
                print_success "$tool instalado correctamente"
            else
                print_error "FALLO CRÍTICO: Error instalando $tool"
                FAILED_ESSENTIAL+=("$tool")
            fi
        fi
    done
    
    # Instalar herramientas AVANZADAS para escaneador profesional
    print_header "Instalando herramientas AVANZADAS de escaneador..."
    FAILED_ADVANCED=()
    
    for tool in "${ADVANCED_TOOLS[@]}"; do
        print_info "Instalando herramienta avanzada: $tool..."
        if dpkg -l | grep -q "^ii  $tool "; then
            print_success "$tool ya está instalado"
        else
            DEBIAN_FRONTEND=noninteractive apt install -y "$tool" >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                print_success "$tool instalado correctamente"
            else
                print_warning "No se pudo instalar $tool (continuando...)"
                FAILED_ADVANCED+=("$tool")
            fi
        fi
    done

    # Instalar rustscan si no está disponible en apt (descarga binario oficial)
    if ! command -v rustscan >/dev/null 2>&1; then
        print_info "rustscan no está en los repositorios o no se pudo instalar. Intentando instalar binario oficial..."
        LATEST_RS_URL=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest | grep browser_download_url | grep linux_amd64 | cut -d '"' -f 4 | head -n1)
        if [[ -n "$LATEST_RS_URL" ]]; then
            cd /tmp
            curl -LO "$LATEST_RS_URL"
            TAR_FILE=$(basename "$LATEST_RS_URL")
            tar -xzf "$TAR_FILE" 2>/dev/null || tar -xf "$TAR_FILE" 2>/dev/null
            if [[ -f rustscan || -f ./rustscan ]]; then
                chmod +x rustscan
                mv rustscan /usr/local/bin/
                print_success "rustscan instalado desde binario oficial"
            else
                print_warning "No se pudo instalar rustscan desde binario (continuando...)"
                FAILED_ADVANCED+=("rustscan-bin")
            fi
            cd "$SCRIPT_DIR"
        else
            print_warning "No se pudo obtener binario oficial de rustscan (continuando...)"
            FAILED_ADVANCED+=("rustscan-bin")
        fi
    fi
    
    # Instalar herramientas especiales para escaneador profesional
    print_header "Instalando herramientas especiales del escaneador..."
    
    # Nuclei - verificar templates actualizados
    if command -v nuclei >/dev/null 2>&1; then
        print_info "Actualizando templates de nuclei..."
        sudo -u "$REAL_USER" nuclei -update-templates >/dev/null 2>&1 &
        NUCLEI_PID=$!
        # Esperar máximo 60 segundos para actualización de templates
        timeout=60
        while kill -0 "$NUCLEI_PID" 2>/dev/null && [[ $timeout -gt 0 ]]; do
            sleep 2
            ((timeout-=2))
        done
        if kill -0 "$NUCLEI_PID" 2>/dev/null; then
            kill "$NUCLEI_PID" 2>/dev/null
            print_warning "Timeout actualizando templates nuclei"
        else
            print_success "Templates de nuclei actualizados"
        fi
    fi
    
    # Verificar herramientas especiales de Go (subfinder, opcional)
    if command -v go >/dev/null 2>&1; then
        print_info "Go detectado, puede instalar subfinder si lo desea (opcional, no recomendado para ARESITOS)"
        # Subfinder para enumeración de subdominios (opcional)
        if ! command -v subfinder >/dev/null 2>&1; then
            print_info "Puede instalar subfinder manualmente si lo requiere: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        else
            print_success "subfinder ya está disponible"
        fi
    else
        print_info "Go no detectado - herramientas adicionales no instaladas"
        print_info "Para instalar: apt install golang-go"
    fi
    
    # Reporte final del escaneador profesional
    echo
    print_header "REPORTE DE INSTALACIÓN - ESCANEADOR PROFESIONAL v3.0"
    
    if [[ ${#FAILED_ESSENTIAL[@]} -eq 0 ]]; then
        print_success "Todas las herramientas ESENCIALES del escaneador instaladas"
    else
        print_error "HERRAMIENTAS CRÍTICAS FALLIDAS: ${FAILED_ESSENTIAL[*]}"
        print_warning "ARESITOS Escaneador puede no funcionar correctamente"
    fi
    
    if [[ ${#FAILED_ADVANCED[@]} -gt 0 ]]; then
        print_warning "Herramientas avanzadas no instaladas: ${FAILED_ADVANCED[*]}"
        print_info "El escaneador funcionará con funcionalidad básica"
    else
        print_success "Todas las herramientas avanzadas del escaneador disponibles"
    fi
    
    # Verificar capacidades del escaneador
    print_info "Verificando capacidades del escaneador ARESITOS..."
    
    SCANNER_CAPABILITIES=()
    
    if command -v nmap >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Escaneo integral con nmap + scripts NSE")
    fi
    if command -v masscan >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Escaneo masivo ultrarrápido con masscan")
    fi
    if command -v rustscan >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Escaneo rápido de puertos con rustscan")
    fi
    if command -v nuclei >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Detección de vulnerabilidades CVE con nuclei")
    fi
    if command -v gobuster >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Enumeración de directorios con gobuster")
    fi
    if command -v ffuf >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Fuzzing web avanzado con ffuf")
    fi
    if command -v feroxbuster >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("Enumeración recursiva con feroxbuster")
    fi
    
    # Mostrar capacidades
    if [[ ${#SCANNER_CAPABILITIES[@]} -gt 0 ]]; then
        print_success "CAPACIDADES DEL ESCANEADOR ARESITOS:"
        for capability in "${SCANNER_CAPABILITIES[@]}"; do
            echo "    $capability"
        done
    fi
    print_info "Total de herramientas del escaneador profesional: ${#SCANNER_CAPABILITIES[@]}/7"
    
    # Actualizar base de datos de locate
    print_info "Actualizando base de datos del sistema..."
    updatedb >/dev/null 2>&1 || {
        print_warning "No se pudo actualizar base de datos locate"
    }
}

# Configurar permisos especiales para herramientas de red
configure_network_permissions() {
    print_header "PERMISOS Configurando permisos de red..."
    
    # nmap - permitir raw sockets
    if command -v nmap >/dev/null 2>&1; then
        print_info "Configurando permisos para nmap..."
        setcap cap_net_raw+epi /usr/bin/nmap
        
        if [[ $? -eq 0 ]]; then
            print_success "Permisos de nmap configurados"
        else
            print_warning "Error configurando permisos de nmap"
        fi
    fi
    
    # tcpdump - permitir captura de paquetes
    if command -v tcpdump >/dev/null 2>&1; then
        print_info "Configurando permisos para tcpdump..."
        setcap cap_net_raw+epi /usr/bin/tcpdump
        
        if [[ $? -eq 0 ]]; then
            print_success "Permisos de tcpdump configurados"
        else
            print_warning "Error configurando permisos de tcpdump"
        fi
    fi
    
    # Añadir usuario a grupos necesarios
    print_info "Añadiendo usuario $REAL_USER a grupos necesarios..."
    
    # Grupo wireshark para captura de paquetes
    if getent group wireshark >/dev/null 2>&1; then
        usermod -a -G wireshark "$REAL_USER"
        print_success "Usuario añadido al grupo wireshark"
    fi
    
    # Grupo netdev para interfaces de red
    if getent group netdev >/dev/null 2>&1; then
        usermod -a -G netdev "$REAL_USER"
        print_success "Usuario añadido al grupo netdev"
    fi
}

# Configurar sudo sin contraseña para herramientas específicas
    # Configurar sudo sin contraseña para herramientas del escaneador profesional
configure_sudo() {
    print_header "🔐 Configurando sudo para ESCANEADOR PROFESIONAL ARESITOS v3.0..."
    
    SUDO_FILE="/etc/sudoers.d/aresitos-escaneador-v3"
    
    # Crear archivo de configuración sudo para escaneador profesional
    cat > "$SUDO_FILE" << EOF
# Configuración sudo para ARESITOS v3.0 - ESCANEADOR PROFESIONAL
# Suite de Ciberseguridad para Kali Linux con capacidades de escaneador avanzado
# Permite ejecutar herramientas de escaneador profesional sin contraseña
# Generado automáticamente el $(date)

# Usuario: $REAL_USER
# === HERRAMIENTAS DE ESCANEADOR PRINCIPAL ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/masscan
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/rustscan
$REAL_USER ALL=(ALL) NOPASSWD: /usr/local/bin/rustscan
$REAL_USER ALL=(ALL) NOPASSWD: /home/$REAL_USER/.cargo/bin/rustscan

# === HERRAMIENTAS DE DETECCIÓN DE VULNERABILIDADES ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nuclei
$REAL_USER ALL=(ALL) NOPASSWD: /usr/local/bin/nuclei
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nikto
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/whatweb

# === HERRAMIENTAS DE ENUMERACIÓN WEB ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/gobuster
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/dirb
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/ffuf
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/feroxbuster

# === HERRAMIENTAS DE MONITOREO Y RED ===
$REAL_USER ALL=(ALL) NOPASSWD: /bin/netstat
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/ss
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/lsof
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
$REAL_USER ALL=(ALL) NOPASSWD: /bin/ps
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/pgrep
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/iftop
$REAL_USER ALL=(ALL) NOPASSWD: /bin/ping
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/dig
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nslookup
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/whois

# === HERRAMIENTAS DE SEGURIDAD Y AUDITORÍA ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/lynis
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/chkrootkit
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/rkhunter
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/clamscan
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/clamdscan

    # === HERRAMIENTAS FORENSES AVANZADAS ===
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/fls
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/ils
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/istat
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/mmls
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/fsstat
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/sleuthkit
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/binwalk
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/foremost
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/strings
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/hexdump
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/xxd
    $REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/exiftool

# === ACCESO A LOGS DEL SISTEMA PARA SIEM ===
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/auth.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/syslog*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/kern.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/daemon.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/mail.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/tail /var/log/*
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/head /var/log/*
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/grep * /var/log/*

# === COMANDOS DE SISTEMA PARA ANÁLISIS ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/journalctl
$REAL_USER ALL=(ALL) NOPASSWD: /bin/dmesg
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/last
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/lastlog
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/who
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/w

# === ACCESO A CONFIGURACIONES DEL SISTEMA ===
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /etc/passwd
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /etc/shadow
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /etc/group
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /etc/hosts
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /etc/ssh/sshd_config
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /etc/crontab
$REAL_USER ALL=(ALL) NOPASSWD: /bin/ls /etc/
$REAL_USER ALL=(ALL) NOPASSWD: /bin/ls /var/log/
$REAL_USER ALL=(ALL) NOPASSWD: /bin/ls /var/spool/cron/

# === GESTIÓN DE SERVICIOS ===
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl status *
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl list-units
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active *
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-enabled *

EOF

    # Verificar sintaxis del archivo sudoers
    visudo -c -f "$SUDO_FILE"
    
    if [[ $? -eq 0 ]]; then
        chmod 440 "$SUDO_FILE"
        print_success "Configuración sudo creada en $SUDO_FILE"
    else
        print_error "Error en la sintaxis del archivo sudo"
        rm -f "$SUDO_FILE"
        return 1
    fi
}

# Instalar dependencias Python con manejo inteligente de entornos
install_python_deps() {
    print_header "🐍 Configurando entorno Python para ARESITOS..."
    
    # Detectar si estamos en un entorno externally-managed
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    EXTERNALLY_MANAGED_FILE="/usr/lib/python${PYTHON_VERSION}/EXTERNALLY-MANAGED"
    
    if [[ -f "$EXTERNALLY_MANAGED_FILE" ]]; then
        print_warning "Detectado entorno Python externally-managed (Kali Linux 2024+)"
        print_info "Configurando solución compatible para ARESITOS..."
        
        # SOLUCIÓN 1: Instalar dependencias vía APT cuando sea posible
        print_info "Instalando dependencias Python vía APT (recomendado)..."
        
        PYTHON_APT_PACKAGES=(
            "python3-pil"              # Pillow vía APT
            "python3-requests"         # requests vía APT
            "python3-urllib3"          # urllib3 vía APT
        )
        
        # Nota: python3-sqlite3 y python3-json son parte del stdlib, no requieren instalación
        print_info "sqlite3 y json son módulos nativos de Python - no requieren instalación"
        
        for package in "${PYTHON_APT_PACKAGES[@]}"; do
            print_info "Instalando $package..."
            DEBIAN_FRONTEND=noninteractive apt install -y "$package" >/dev/null 2>&1
            
            if [[ $? -eq 0 ]]; then
                print_success "$package instalado vía APT"
            else
                print_warning "No se pudo instalar $package vía APT"
            fi
        done
        
        # SOLUCIÓN 2: Crear script para bypass temporal si es necesario
        print_info "Creando script de bypass para dependencias críticas..."
        
        BYPASS_SCRIPT="/tmp/install_python_deps_aresitos.py"
        cat > "$BYPASS_SCRIPT" << 'EOF'
#!/usr/bin/env python3
"""
Script de bypass para instalar dependencias Python críticas de ARESITOS
Solo instala las dependencias mínimas indispensables
"""
import subprocess
import sys
import os

def install_with_break_system_packages():
    """Instalar con --break-system-packages solo para dependencias críticas"""
    critical_packages = [
        "Pillow",  # Para interfaz gráfica
    ]
    
    print("INSTALANDO dependencias críticas con bypass...")
    
    for package in critical_packages:
        try:
            print(f"   Instalando {package}...")
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "--break-system-packages", 
                "--user", 
                package
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print(f"   OK {package} instalado correctamente")
            else:
                print(f"   WARN️ Error instalando {package}: {result.stderr}")
                
        except Exception as e:
            print(f"   ERROR Excepción instalando {package}: {e}")

def verify_dependencies():
    """Verificar que las dependencias están disponibles"""
    print("\n🧪 Verificando dependencias...")
    
    dependencies = {
        "tkinter": "Interfaz gráfica",
        "PIL": "Procesamiento de imágenes", 
        "sqlite3": "Base de datos",
        "json": "Manejo de JSON",
        "threading": "Multihilo",
        "subprocess": "Ejecución de comandos",
        "os": "Sistema operativo",
        "sys": "Sistema Python"
    }
    
    missing = []
    
    for dep, desc in dependencies.items():
        try:
            __import__(dep)
            print(f"   OK {dep}: {desc}")
        except ImportError:
            print(f"   ERROR {dep}: {desc} - NO DISPONIBLE")
            missing.append(dep)
    
    if missing:
        print(f"\nWARN️ Dependencias faltantes: {', '.join(missing)}")
        print("ARESITOS puede tener funcionalidad limitada")
    else:
        print("\nOK Todas las dependencias están disponibles")
    
    return len(missing) == 0

if __name__ == "__main__":
    print("🐍 Configurador de dependencias Python para ARESITOS")
    print("=" * 55)
    
    # Verificar primero
    if verify_dependencies():
        print("\nCOMPLETADO No es necesario instalar dependencias adicionales")
        sys.exit(0)
    
    # Instalar dependencias críticas faltantes
    install_with_break_system_packages()
    
    # Verificar de nuevo
    print("\n" + "=" * 55)
    final_check = verify_dependencies()
    
    if final_check:
        print("\nCOMPLETADO Configuración Python completada exitosamente")
    else:
        print("\nWARN️ Algunas dependencias no pudieron instalarse")
        print("ARESITOS debería funcionar con funcionalidad básica")
EOF
        
        # Ejecutar script de bypass como usuario no-root
        chown "$REAL_USER:$REAL_USER" "$BYPASS_SCRIPT"
        chmod +x "$BYPASS_SCRIPT"
        
        print_info "Ejecutando configuración de dependencias Python..."
        sudo -u "$REAL_USER" python3 "$BYPASS_SCRIPT"
        
        # Limpiar archivo temporal
        rm -f "$BYPASS_SCRIPT"
        
        # SOLUCIÓN 3: Crear entorno virtual si es necesario (opcional)
        VENV_PATH="$USER_HOME/.aresitos_venv"
        if [[ ! -d "$VENV_PATH" ]]; then
            print_info "Creando entorno virtual opcional para ARESITOS..."
            sudo -u "$REAL_USER" python3 -m venv "$VENV_PATH" >/dev/null 2>&1
            
            if [[ $? -eq 0 ]]; then
                print_success "Entorno virtual creado en $VENV_PATH"
                
                # Crear script de activación
                ACTIVATION_SCRIPT="$USER_HOME/activate_aresitos_venv.sh"
                cat > "$ACTIVATION_SCRIPT" << EOF
#!/bin/bash
# Script para activar entorno virtual de ARESITOS si es necesario
echo "🐍 Activando entorno virtual ARESITOS..."
source "$VENV_PATH/bin/activate"
echo "OK Entorno virtual activado"
echo "Para instalar dependencias: pip install Pillow"
echo "Para ejecutar ARESITOS: python3 main.py"
EOF
                chown "$REAL_USER:$REAL_USER" "$ACTIVATION_SCRIPT"
                chmod +x "$ACTIVATION_SCRIPT"
                
                print_success "Script de activación creado: $ACTIVATION_SCRIPT"
            else
                print_warning "No se pudo crear entorno virtual"
            fi
        fi
        
    else
        # Instalación tradicional para sistemas más antiguos
        print_info "Entorno Python tradicional detectado"
        print_info "Instalando dependencias con pip..."
        
        sudo -u "$REAL_USER" pip3 install --user Pillow >/dev/null 2>&1
        
        if [[ $? -eq 0 ]]; then
            print_success "Dependencias Python instaladas con pip"
        else
            print_warning "Error instalando dependencias con pip"
        fi
    fi
    
    # Verificación final
    print_info "Verificando instalación Python..."
    
    # Crear script de verificación simple
    VERIFY_SCRIPT="/tmp/verify_python_aresitos.py"
    cat > "$VERIFY_SCRIPT" << 'EOF'
import sys
try:
    import tkinter
    print("OK tkinter: OK")
except ImportError:
    print("ERROR tkinter: FALTA")
    sys.exit(1)

try:
    from PIL import Image
    print("OK Pillow: OK")
except ImportError:
    print("WARN️ Pillow: FALTA (funcionalidad de imágenes limitada)")

print("🐍 Python configurado para ARESITOS")
EOF
    
    sudo -u "$REAL_USER" python3 "$VERIFY_SCRIPT"
    PYTHON_CHECK_RESULT=$?
    rm -f "$VERIFY_SCRIPT"
    
    if [[ $PYTHON_CHECK_RESULT -eq 0 ]]; then
        print_success "Configuración Python completada"
    else
        print_warning "Configuración Python con advertencias (ARESITOS debería funcionar)"
    fi
}

# Verificar configuración
verify_setup() {
    print_header "🧪 Verificando configuración..."
    
    # Verificar herramientas críticas del escaneador profesional
    TOOLS_TO_CHECK=("nmap" "masscan" "ss" "tcpdump" "rustscan" "nuclei" "gobuster")
    
    print_header "🧪 Verificando herramientas del ESCANEADOR PROFESIONAL..."
    
    CORE_TOOLS_OK=0
    ADVANCED_TOOLS_OK=0
    
    # Verificar herramientas core
    for tool in "nmap" "ss" "tcpdump"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "CORE $tool disponible"
            ((CORE_TOOLS_OK++))
            
            # Verificar permisos sudo de forma silenciosa para herramientas críticas
            if [[ "$tool" == "nmap" || "$tool" == "tcpdump" ]]; then
                sudo -u "$REAL_USER" sudo -n "$tool" --version >/dev/null 2>&1
                if [[ $? -eq 0 ]]; then
                    print_success "CORE $tool ejecutable sin contraseña"
                else
                    print_warning "CORE $tool requiere contraseña"
                fi
            fi
        else
            print_error "CORE $tool no encontrado"
        fi
    done
    
    # Verificar herramientas avanzadas
    for tool in "masscan" "rustscan" "nuclei" "gobuster"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "AVANZADO $tool disponible"
            ((ADVANCED_TOOLS_OK++))
        else
            print_info "AVANZADO $tool no disponible"
        fi
    done
    
    # Mostrar resumen de capacidades del escaneador
    print_header "📊 RESUMEN ESCANEADOR PROFESIONAL"
    print_info "Herramientas CORE disponibles: $CORE_TOOLS_OK/3"
    print_info "Herramientas AVANZADAS disponibles: $ADVANCED_TOOLS_OK/4"
    
    if [[ $CORE_TOOLS_OK -eq 3 ]]; then
        print_success "✅ ESCANEADOR BÁSICO completamente funcional"
    else
        print_warning "⚠️ ESCANEADOR BÁSICO con limitaciones"
    fi
    
    if [[ $ADVANCED_TOOLS_OK -ge 2 ]]; then
        print_success "✅ ESCANEADOR AVANZADO disponible"
    else
        print_info "ℹ️ ESCANEADOR AVANZADO con funcionalidad limitada"
    fi
    
    # Verificar herramientas forenses (opcional - no mostrar errores)
    FORENSIC_TOOLS=("wireshark" "autopsy" "fls")
    forensic_count=0
    
    for tool in "${FORENSIC_TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            ((forensic_count++))
        fi
    done
    
    if [[ $forensic_count -gt 0 ]]; then
        print_success "$forensic_count herramientas forenses disponibles"
    else
        print_info "Herramientas forenses no instaladas (opcionales)"
    fi
    
    # Verificar grupos
    print_info "Verificando membresía de grupos para $REAL_USER..."
    if groups "$REAL_USER" | grep -q wireshark; then
        print_success "Usuario en grupo wireshark"
    else
        print_info "Usuario no en grupo wireshark (ejecutar: sudo usermod -a -G wireshark $REAL_USER)"
    fi
}

# Función para configurar permisos de archivos ARESITOS
configure_aresitos_permissions() {
    print_header "⚙️ CONFIGURANDO PERMISOS ARESITOS"
    
    print_info "Configurando permisos de ejecución para archivos ARESITOS..."
    
    # Permisos para scripts principales
    if [ -f "main.py" ]; then
        chmod +x main.py
        print_success "Permisos configurados para main.py"
    fi
    
    if [ -f "verificacion_final.py" ]; then
        chmod +x verificacion_final.py
        print_success "Permisos configurados para verificacion_final.py"
    fi
    
    if [ -f "configurar_kali.sh" ]; then
        chmod +x configurar_kali.sh
        print_success "Permisos configurados para configurar_kali.sh"
    fi
    
    # Permisos para todos los archivos Python
    print_info "Configurando permisos para archivos Python..."
    find . -name "*.py" -exec chmod +x {} \; 2>/dev/null
    print_success "Permisos configurados para archivos Python"
    
    # Permisos para directorios de datos
    print_info "Configurando permisos para directorios de datos..."
    print_info "Directorio actual: $SCRIPT_DIR"

    # Crear directorios si no existen (en el directorio del proyecto)
    mkdir -p "$SCRIPT_DIR/data/" "$SCRIPT_DIR/logs/" "$SCRIPT_DIR/configuración/"

    # Configurar permisos
    chmod -R 755 "$SCRIPT_DIR/data/" 2>/dev/null
    chmod -R 755 "$SCRIPT_DIR/logs/" 2>/dev/null
    chmod -R 755 "$SCRIPT_DIR/configuración/" 2>/dev/null

    if [ -d "$SCRIPT_DIR/aresitos/" ]; then
        chmod -R 755 "$SCRIPT_DIR/aresitos/" 2>/dev/null
        print_success "Permisos configurados para directorio aresitos/"
    fi

    # Permisos específicos para bases de datos
    if [ -f "$SCRIPT_DIR/data/cuarentena_kali2025.db" ]; then
        chmod 664 "$SCRIPT_DIR/data/cuarentena_kali2025.db"
        print_success "Permisos configurados para base de datos cuarentena"
    fi

    if [ -f "$SCRIPT_DIR/data/fim_kali2025.db" ]; then
        chmod 664 "$SCRIPT_DIR/data/fim_kali2025.db"
        print_success "Permisos configurados para base de datos FIM"
    fi

    # Configurar propietario para el usuario no-root
    if [ "$DETECTED_USER" != "root" ]; then
        chown -R "$DETECTED_USER":"$DETECTED_USER" "$SCRIPT_DIR" 2>/dev/null
        print_success "Propietario configurado para usuario $DETECTED_USER"
    fi

    print_success "Permisos ARESITOS configurados correctamente"
}

# Crear script de prueba
create_test_script() {
    print_header "📝 Creando script de prueba..."
    
    TEST_SCRIPT="$USER_HOME/test_ares_permissions.py"
    
    cat > "$TEST_SCRIPT" << 'EOF'
#!/usr/bin/env python3
"""Script de prueba para verificar permisos de Ares Aegis"""
import subprocess
import sys

def test_tool(tool, args):
    try:
        result = subprocess.run([tool] + args, 
                               capture_output=True, 
                               text=True, 
                               timeout=10)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

print("🧪 Probando herramientas de Ares Aegis...")
print("="*50)

tests = [
    ("nmap", ["--version"]),
    ("netstat", ["--version"]),
    ("ss", ["--version"]),
]

for tool, args in tests:
    success, stdout, stderr = test_tool(tool, args)
    status = "OK" if success else "ERROR"
    print(f"{status} {tool}: {'OK' if success else 'FAIL'}")
    if success and stdout:
        print(f"   {stdout.split()[0] if stdout else 'Sin versión'}")

print("\nPERMISOS Probando permisos sudo...")
print("="*30)

sudo_tests = [
    ("sudo", ["nmap", "--version"]),
    ("sudo", ["netstat", "--help"]),
]

for cmd, args in sudo_tests:
    success, stdout, stderr = test_tool(cmd, args)
    status = "OK" if success else "ERROR"
    tool_name = args[0] if args else cmd
    print(f"{status} sudo {tool_name}: {'OK' if success else 'FAIL'}")

print("\nOK Pruebas completadas")
EOF

    chown "$REAL_USER:$REAL_USER" "$TEST_SCRIPT"
    chmod +x "$TEST_SCRIPT"
    
    print_success "Script de prueba creado: $TEST_SCRIPT"
    print_info "Ejecute: python3 $TEST_SCRIPT"
}

# Función principal
main() {
    print_header "🛡️ CONFIGURADOR ARESITOS v3.0 - ESCANEADOR PROFESIONAL PARA KALI LINUX"
    print_header "=============================================================================="
    
    check_root
    detect_user
    
    echo
    print_info "ARESITOS v3.0 incluye un ESCANEADOR PROFESIONAL con capacidades avanzadas:"
    echo
    print_info "🎯 CAPACIDADES DEL ESCANEADOR PROFESIONAL:"
    echo "  • Escaneo integral con nmap (detección de servicios y scripts)"
    echo "  • Escaneo masivo rápido con masscan/rustscan" 
    echo "  • Detección de vulnerabilidades con nuclei"
    echo "  • Enumeración de directorios web con gobuster/ffuf"
    echo "  • Escaneo de redes completas con análisis automático"
    echo "  • Exportación de reportes en JSON/TXT"
    echo "  • Validación automática de herramientas disponibles"
    echo "  • Fallback inteligente según herramientas instaladas"
    echo
    print_info "🔧 ACCIONES DE CONFIGURACIÓN:"
    echo "  • Actualizar repositorios e instalar herramientas del escaneador"
    echo "  • Configurar permisos de red especiales para escaneo avanzado"
    echo "  • Configurar sudo sin contraseña para herramientas del escaneador"
    echo "  • Instalar dependencias Python para interfaz gráfica"
    echo "  • Verificar funcionamiento completo del escaneador profesional"
    echo
    
    read -p "¿Continuar? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Configuración cancelada"
        exit 0
    fi
    
    echo
    update_repositories
    install_tools
    configure_network_permissions
    configure_sudo
    configure_aresitos_permissions
    install_python_deps
    verify_setup
    create_test_script
    
    echo
    print_header "COMPLETADO CONFIGURACIÓN COMPLETADA"
    print_header "============================"
    
    print_success "Ares Aegis está configurado para Kali Linux"
    echo
    print_info "Pasos siguientes:"
    echo "  1. Cierre y reabra la terminal para aplicar cambios de grupo"
    echo "  2. Execute el script de prueba: python3 $USER_HOME/test_ares_permissions.py"
    echo "  3. Execute la verificación de permisos: python3 $SCRIPT_DIR/verificacion_permisos.py"
    echo "  4. Inicie Ares Aegis: python3 $SCRIPT_DIR/main.py"
    echo
    print_warning "IMPORTANTE: Reinicie la sesión para aplicar cambios de grupos"
}

# Ejecutar función principal
main "$@"
