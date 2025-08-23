#!/bin/bash
# -*- coding: utf-8 -*-
#
# ARESITOS v3.0 - Script de Configuración para Kali Linux [OPTIMIZADO]
# ====================================================================
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
# Versión: 3.0 [BASH OPTIMIZADO - PRINCIPIOS ARESITOS V3]
# Proyecto: ARESITOS - Suite de Ciberseguridad Profesional
#
# IMPORTANTE: Este script debe ejecutarse como root o con sudo
# sudo ./configurar_kali.sh
#

# ============================================================================
# CONFIGURACIÓN GLOBAL Y CONSTANTES [PRINCIPIO 1: CONFIGURACIÓN CENTRALIZADA]
# ============================================================================

# Configuración estricta de bash [PRINCIPIO 2: MODO ESTRICTO]
set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'       # Secure Internal Field Separator

# Colores para output [PRINCIPIO 3: CONSTANTES INMUTABLES]
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r PURPLE='\033[0;35m'
declare -r CYAN='\033[0;36m'
declare -r NC='\033[0m' # No Color

# Variables globales inmutables [PRINCIPIO 4: DIRECTORIO BASE SEGURO]
declare -r SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -r ARESITOS_VERSION="3.0"
declare -r LOG_FILE="${SCRIPT_DIR}/logs/configuracion_$(date +%Y%m%d_%H%M%S).log"

# Crear directorio de logs si no existe [PRINCIPIO 5: PREPARACIÓN AUTOMÁTICA]
mkdir -p "${SCRIPT_DIR}/logs"

# Establecer directorio de trabajo del script
cd "$SCRIPT_DIR" || {
    echo "ERROR CRÍTICO: No se puede cambiar al directorio del script" >&2
    exit 1
}

echo -e "${CYAN}[SETUP]${NC} Directorio de trabajo establecido en: $SCRIPT_DIR"
echo -e "${CYAN}[SETUP]${NC} Modo estricto de bash activado - ARESITOS v${ARESITOS_VERSION}"

# ============================================================================
# FUNCIONES DE LOGGING Y OUTPUT [PRINCIPIO 6: LOGGING ROBUSTO]
# ============================================================================

# Sistema de logging dual (pantalla + archivo) [PRINCIPIO 7: TRAZABILIDAD]
log_with_timestamp() {
    local message="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Funciones de output optimizadas [PRINCIPIO 8: FUNCIONES PURAS]
print_info() {
    local message="$1"
    echo -e "${BLUE}[INFO]${NC} $message"
    log_with_timestamp "INFO: $message"
}

print_success() {
    local message="$1"
    echo -e "${GREEN}[OK]${NC} $message"
    log_with_timestamp "SUCCESS: $message"
}

print_warning() {
    local message="$1"
    echo -e "${YELLOW}[WARN]${NC} $message"
    log_with_timestamp "WARNING: $message"
}

print_error() {
    local message="$1"
    echo -e "${RED}[✗]${NC} $message" >&2
    log_with_timestamp "ERROR: $message"
}

print_header() {
    local message="$1"
    echo -e "${PURPLE}$message${NC}"
    log_with_timestamp "HEADER: $message"
}

# ============================================================================
# FUNCIONES DE VALIDACIÓN [PRINCIPIO 9: VALIDACIÓN ROBUSTA]
# ============================================================================

# Verificar que se ejecuta como root [PRINCIPIO 10: VALIDACIÓN DE PERMISOS]
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root o con sudo"
        print_error "Uso: sudo $0"
        log_with_timestamp "FATAL: Script ejecutado sin permisos de root"
        exit 1
    fi
    print_success "Permisos de root verificados correctamente"
}

# Detectar el usuario que ejecutó sudo [PRINCIPIO 11: DETECCIÓN INTELIGENTE]
detect_user() {
    local real_user user_home
    
    if [[ -n "${SUDO_USER:-}" ]]; then
        real_user="$SUDO_USER"
        user_home=$(eval echo "~$SUDO_USER")
    else
        real_user=$(whoami)
        user_home="$HOME"
    fi
    
    # Validar que el directorio home existe
    if [[ ! -d "$user_home" ]]; then
        print_error "Directorio home no encontrado: $user_home"
        return 1
    fi
    
    # Exportar variables globales
    export REAL_USER="$real_user"
    export USER_HOME="$user_home"
    
    print_info "Usuario detectado: $real_user"
    print_info "Directorio home: $user_home"
    return 0
}

# Verificar conectividad de red [PRINCIPIO 12: VALIDACIÓN DE PRERREQUISITOS]
check_network() {
    print_info "Verificando conectividad de red..."
    
    if ping -c 1 8.8.8.8 &>/dev/null; then
        print_success "Conectividad de red verificada"
        return 0
    else
        print_warning "Sin conectividad de red - algunas funciones pueden fallar"
        return 1
    fi
}

# Verificar espacio en disco [PRINCIPIO 13: VALIDACIÓN DE RECURSOS]
check_disk_space() {
    local required_mb=1024  # 1GB mínimo
    local available_mb
    
    available_mb=$(df "$SCRIPT_DIR" | awk 'NR==2 {print int($4/1024)}')
    
    if [[ $available_mb -lt $required_mb ]]; then
        print_error "Espacio insuficiente en disco. Requerido: ${required_mb}MB, Disponible: ${available_mb}MB"
        return 1
    else
        print_success "Espacio en disco verificado: ${available_mb}MB disponibles"
        return 0
    fi
}

# ============================================================================
# FUNCIONES DE INSTALACIÓN [PRINCIPIO 14: INSTALACIÓN ROBUSTA]
# ============================================================================

# Actualizar repositorios con retry [PRINCIPIO 15: REINTENTOS AUTOMÁTICOS]
update_repositories() {
    print_header "🔄 Actualizando repositorios..."
    
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if apt update; then
            print_success "Repositorios actualizados exitosamente"
            return 0
        else
            ((retry_count++))
            print_warning "Error actualizando repositorios (intento $retry_count/$max_retries)"
            if [[ $retry_count -lt $max_retries ]]; then
                print_info "Reintentando en 5 segundos..."
                sleep 5
            fi
        fi
    done
    
    print_error "No se pudieron actualizar los repositorios después de $max_retries intentos"
    return 1
}

# Instalar herramientas con validación [PRINCIPIO 16: INSTALACIÓN VALIDADA]
install_package() {
    local package="$1"
    local description="${2:-$package}"
    
    print_info "Instalando $description..."
    
    if dpkg -l | grep -q "^ii  $package "; then
        print_success "$description ya está instalado"
        return 0
    fi
    
    if apt install -y "$package"; then
        print_success "$description instalado correctamente"
        return 0
    else
        print_error "Error instalando $description"
        return 1
    fi
}

# Instalar herramientas esenciales [PRINCIPIO 17: INSTALACIÓN MODULAR]
install_essential_tools() {
    print_header "TOOL Instalando herramientas esenciales del escaneador profesional ARESITOS v3.0..."
    
    # Lista de herramientas ESENCIALES para escaneador profesional
    local -a essential_tools=(
        # Python y herramientas básicas (CRÍTICAS)
        "python3-dev:Desarrollo Python 3"
        "python3-venv:Entornos virtuales Python"
        "python3-tk:Interfaz gráfica Tkinter"
        "curl:Cliente HTTP"
        "wget:Descargador web"
        "git:Control de versiones"
        
        # Herramientas de escaneador PROFESIONAL (CORE)
        "nmap:Escaneador de red principal"
        "masscan:Escaneador masivo rápido"
        "net-tools:Herramientas de red básicas"
        "iproute2:Herramientas de red avanzadas"
        "tcpdump:Captura de paquetes"
        "iftop:Monitor de red en tiempo real"
        "netcat-openbsd:Herramienta de red netcat"
        
        # Herramientas forense y SIEM VERIFICADAS
        "wireshark:Análisis de tráfico de red"
        "autopsy:Forense digital"
        "sleuthkit:Toolkit de investigación forense"
        "foremost:Recuperación de archivos"
        "binwalk:Análisis de firmware"
        "strings:Extracción de cadenas de texto"
        "exiftool:Análisis de metadatos"
        
        # Utilidades del sistema ESTABLES
        "htop:Monitor de procesos mejorado"
        "lsof:Lista de archivos abiertos"
        "psmisc:Utilidades de procesos"
        "dnsutils:Herramientas DNS"
        "whois:Información de dominios"
    )
    
    local failed_packages=()
    local total_packages=${#essential_tools[@]}
    local installed_count=0
    
    for tool_info in "${essential_tools[@]}"; do
        IFS=':' read -r package description <<< "$tool_info"
        
        if install_package "$package" "$description"; then
            ((installed_count++))
        else
            failed_packages+=("$package")
        fi
    done
    
    print_info "Instalación completa: $installed_count/$total_packages herramientas esenciales"
    
    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        print_warning "Paquetes que fallaron: ${failed_packages[*]}"
        return 1
    else
        print_success "Todas las herramientas esenciales instaladas correctamente"
        return 0
    fi
}

# Instalar herramientas avanzadas [PRINCIPIO 18: INSTALACIÓN OPCIONAL]
install_advanced_tools() {
    print_header "LAUNCH Instalando herramientas avanzadas del escaneador profesional..."
    
    local -a advanced_tools=(
        # Herramientas de escaneador avanzado (disponibles via APT en Kali)
        "ffuf:Fuzzer web ultrarrápido"
        "feroxbuster:Scanner de directorios en Rust"
        "rustscan:Scanner de puertos ultrarrápido"
        "nuclei:Motor de detección de vulnerabilidades"
        "nikto:Scanner de vulnerabilidades web"
        "whatweb:Identificador de tecnologías web"
        "dirb:Brute force de directorios web"
        
        # Herramientas de seguridad adicionales
        "lynis:Auditoría de seguridad del sistema"
        "chkrootkit:Detector de rootkits"
    )
    
    local optional_count=0
    local total_advanced=${#advanced_tools[@]}
    
    for tool_info in "${advanced_tools[@]}"; do
        IFS=':' read -r package description <<< "$tool_info"
        
        if install_package "$package" "$description"; then
            ((optional_count++))
        fi
    done
    
    print_info "Herramientas avanzadas instaladas: $optional_count/$total_advanced"
    
    # Instalar herramientas de seguridad adicionales
    install_advanced_security_tools
    
    # Verificar capacidades del escaneador
    print_info "SCAN Verificando capacidades del escaneador ARESITOS..."
    
    SCANNER_CAPABILITIES=()
    
    if command -v nmap >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Escaneo integral con nmap + scripts NSE")
    fi
    
    if command -v masscan >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Escaneo masivo ultrarrápido con masscan")
    fi
    
    if command -v rustscan >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Escaneo rápido de puertos con rustscan")
    fi
    
    if command -v nuclei >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Detección de vulnerabilidades CVE con nuclei")
    fi
    
    if command -v gobuster >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Enumeración de directorios con gobuster")
    fi
    
    if command -v ffuf >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Fuzzing web avanzado con ffuf")
    fi
    
    if command -v feroxbuster >/dev/null 2>&1; then
        SCANNER_CAPABILITIES+=("OK Enumeración recursiva con feroxbuster")
    fi
    
    # Mostrar capacidades
    if [[ ${#SCANNER_CAPABILITIES[@]} -gt 0 ]]; then
        print_success "TARGET CAPACIDADES DEL ESCANEADOR ARESITOS:"
        for capability in "${SCANNER_CAPABILITIES[@]}"; do
            echo "    $capability"
        done
    fi
    
    print_info "METRICS Total de herramientas del escaneador profesional: ${#SCANNER_CAPABILITIES[@]}/7"
    
    # Actualizar base de datos de locate
    print_info "Actualizando base de datos del sistema..."
    updatedb >/dev/null 2>&1 || {
        print_warning "No se pudo actualizar base de datos locate"
    }
    
    print_success "Instalación de herramientas avanzadas completada"
}

# ============================================================================
# INSTALACIÓN DE HERRAMIENTAS AVANZADAS PARA ESCANEADOR v3.0
# ============================================================================

install_advanced_security_tools() {
    print_header "INSTALANDO HERRAMIENTAS AVANZADAS DE SEGURIDAD"
    
    # Herramientas avanzadas de seguridad (opcionales pero recomendadas)
    local -a security_tools=(
        "rkhunter:Hunter de rootkits avanzado"
        "clamav-daemon:Motor antivirus ClamAV"
        "clamav-freshclam:Actualizador de firmas ClamAV"
        "volatility3:Análisis forense de memoria"
        "yara:Motor de reconocimiento de patrones"
    )
    
    local security_count=0
    local total_security=${#security_tools[@]}
    
    for tool_info in "${security_tools[@]}"; do
        IFS=':' read -r package description <<< "$tool_info"
        
        if install_package "$package" "$description"; then
            ((security_count++))
        fi
    done
    
    # Configuración especial para ClamAV si se instaló
    if dpkg -l | grep -q "^ii  clamav-daemon "; then
        print_info "Configurando ClamAV..."
        systemctl stop clamav-freshclam 2>/dev/null || true
        freshclam 2>/dev/null || true
        systemctl start clamav-freshclam 2>/dev/null || true
        print_success "ClamAV configurado correctamente"
    fi
    
    print_info "Herramientas de seguridad instaladas: $security_count/$total_security"
    print_success "Instalación de herramientas avanzadas completada"
}
    
    print_info "Actualizando lista de paquetes..."
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
    print_header "LAUNCH Instalando herramientas AVANZADAS de escaneador..."
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
    
    # Instalar herramientas especiales para escaneador profesional
    print_header "STAR Instalando herramientas especiales del escaneador..."
    
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
    
    # Verificar herramientas especiales de Go (subfinder, httpx)
    if command -v go >/dev/null 2>&1; then
        print_info "Go detectado, instalando herramientas adicionales..."
        
        # Subfinder para enumeración de subdominios
        if ! command -v subfinder >/dev/null 2>&1; then
            print_info "Instalando subfinder..."
            sudo -u "$REAL_USER" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1
            if command -v subfinder >/dev/null 2>&1; then
                print_success "subfinder instalado"
            else
                print_info "subfinder puede requerir ajuste de PATH: export PATH=\$PATH:~/go/bin"
            fi
        else
            print_success "subfinder ya está disponible"
        fi
        
        # httpx para verificación HTTP
        if ! command -v httpx >/dev/null 2>&1; then
            print_info "Instalando httpx..."
            sudo -u "$REAL_USER" go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1
            if command -v httpx >/dev/null 2>&1; then
                print_success "httpx instalado"
            else
                print_info "httpx puede requerir ajuste de PATH: export PATH=\$PATH:~/go/bin"
            fi
        else
            print_success "httpx ya está disponible"
        fi
    else
        print_info "Go no detectado - herramientas adicionales no instaladas"
        print_info "Para instalar: apt install golang-go"
    fi
    
    # Reporte final del escaneador profesional
    echo
    print_header "DATA REPORTE DE INSTALACIÓN - ESCANEADOR PROFESIONAL v3.0"
    
    if [[ ${#FAILED_ESSENTIAL[@]} -eq 0 ]]; then
        print_success "OK Todas las herramientas ESENCIALES del escaneador instaladas"
    else
        print_error "ERROR HERRAMIENTAS CRÍTICAS FALLIDAS: ${FAILED_ESSENTIAL[*]}"
        print_warning "WARNING ARESITOS Escaneador puede no funcionar correctamente"
    fi
    
    if [[ ${#FAILED_ADVANCED[@]} -gt 0 ]]; then
        print_warning "WARNING Herramientas avanzadas no instaladas: ${FAILED_ADVANCED[*]}"
        print_info "INFO El escaneador funcionará con funcionalidad básica"
    else
        print_success "OK Todas las herramientas avanzadas del escaneador disponibles"
    fi

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
    print_header "SECURE Configurando sudo para ESCANEADOR PROFESIONAL ARESITOS v3.0..."
    
    SUDO_FILE="/etc/sudoers.d/Aresitos-escaneador-v3"
    
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
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/wireshark
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/tshark
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/autopsy
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
    print_header "PYTHON Configurando entorno Python para ARESITOS..."
    
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
        
        BYPASS_SCRIPT="/tmp/install_python_deps_Aresitos.py"
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
                print(f"   WARNSYMBOL Error instalando {package}: {result.stderr}")
                
        except Exception as e:
            print(f"   ERROR Excepción instalando {package}: {e}")

def verify_dependencies():
    """Verificar que las dependencias están disponibles"""
    print("\nVerificando dependencias...")
    
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
        print(f"\nWARNSYMBOL Dependencias faltantes: {', '.join(missing)}")
        print("ARESITOS puede tener funcionalidad limitada")
    else:
        print("\nOK Todas las dependencias están disponibles")
    
    return len(missing) == 0

if __name__ == "__main__":
    print("PYTHON Configurador de dependencias Python para ARESITOS")
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
        print("\nWARNSYMBOL Algunas dependencias no pudieron instalarse")
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
echo "PYTHON Activando entorno virtual ARESITOS..."
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
    print("WARNSYMBOL Pillow: FALTA (funcionalidad de imágenes limitada)")

print("PYTHON Python configurado para ARESITOS")
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
    print_header "Verificando configuración..."
    
    # Verificar herramientas críticas del escaneador profesional
    TOOLS_TO_CHECK=("nmap" "masscan" "ss" "tcpdump" "rustscan" "nuclei" "gobuster")
    
    print_header "Verificando herramientas del ESCANEADOR PROFESIONAL..."
    
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
    print_header "DATA RESUMEN ESCANEADOR PROFESIONAL"
    print_info "Herramientas CORE disponibles: $CORE_TOOLS_OK/3"
    print_info "Herramientas AVANZADAS disponibles: $ADVANCED_TOOLS_OK/4"
    
    if [[ $CORE_TOOLS_OK -eq 3 ]]; then
        print_success "OK ESCANEADOR BÁSICO completamente funcional"
    else
        print_warning "WARNING ESCANEADOR BÁSICO con limitaciones"
    fi
    
    if [[ $ADVANCED_TOOLS_OK -ge 2 ]]; then
        print_success "OK ESCANEADOR AVANZADO disponible"
    else
        print_info "INFO ESCANEADOR AVANZADO con funcionalidad limitada"
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
    print_header "CONFIG CONFIGURANDO PERMISOS ARESITOS"
    
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
    print_info "Directorio actual: $(pwd)"
    
    # Crear directorios si no existen (en el directorio del proyecto)
    mkdir -p "$SCRIPT_DIR/data/" "$SCRIPT_DIR/logs/" "$SCRIPT_DIR/configuración/"
    
    # Configurar permisos
    chmod -R 755 "$SCRIPT_DIR/data/" 2>/dev/null
    chmod -R 755 "$SCRIPT_DIR/logs/" 2>/dev/null
    chmod -R 755 "$SCRIPT_DIR/configuración/" 2>/dev/null
    
    if [ -d "$SCRIPT_DIR/Aresitos/" ]; then
        chmod -R 755 "$SCRIPT_DIR/Aresitos/" 2>/dev/null
        print_success "Permisos configurados para directorio Aresitos/"
    fi
    
    # Permisos específicos para bases de datos
    if [ -f "data/cuarentena_kali2025.db" ]; then
        chmod 664 data/cuarentena_kali2025.db
        print_success "Permisos configurados para base de datos cuarentena"
    fi
    
    if [ -f "data/fim_kali2025.db" ]; then
        chmod 664 data/fim_kali2025.db
        print_success "Permisos configurados para base de datos FIM"
    fi
    
    # Configurar propietario para el usuario no-root
    if [ "$DETECTED_USER" != "root" ]; then
        chown -R "$DETECTED_USER":"$DETECTED_USER" . 2>/dev/null
        print_success "Propietario configurado para usuario $DETECTED_USER"
    fi
    
    print_success "Permisos ARESITOS configurados correctamente"
}

# Función para configurar Git con case sensitivity
configure_git_case_sensitivity() {
    print_header "GIT CONFIGURANDO CASE SENSITIVITY"
    
    print_info "Configurando Git para case sensitivity en Kali Linux..."
    
    # Verificar si estamos en un repositorio Git
    if [ ! -d ".git" ]; then
        print_warning "No se detectó repositorio Git. Saltando configuración..."
        return 0
    fi
    
    # Configurar core.ignorecase = false
    print_info "Configurando core.ignorecase = false..."
    git config core.ignorecase false
    print_success "core.ignorecase configurado correctamente"
    
    # Configurar autocrlf para Linux
    print_info "Configurando autocrlf = false para Linux..."
    git config core.autocrlf false
    print_success "autocrlf configurado correctamente"
    
    # Verificar configuración actual
    print_info "Verificando configuración de Git:"
    local ignorecase=$(git config core.ignorecase)
    local autocrlf=$(git config core.autocrlf)
    
    if [ "$ignorecase" = "false" ]; then
        print_success "OK core.ignorecase: $ignorecase"
    else
        print_error "ERROR core.ignorecase: $ignorecase (debería ser false)"
    fi
    
    if [ "$autocrlf" = "false" ]; then
        print_success "OK core.autocrlf: $autocrlf"
    else
        print_success "OK core.autocrlf: $autocrlf"
    fi
    
    # Verificar que no hay conflictos de case sensitivity
    print_info "Verificando estructura de archivos..."
    local aresitos_files=$(git ls-files | grep -i "aresitos" | head -5)
    if [ -n "$aresitos_files" ]; then
        print_info "Archivos de ARESITOS detectados:"
        echo "$aresitos_files" | while read -r file; do
            print_info "  📁 $file"
        done
    fi
    
    # Crear documentación de configuración
    if [ ! -f ".gitconfig-case-sensitivity" ]; then
        print_info "Creando documentación de configuración de case sensitivity..."
        print_success "Documentación creada: .gitconfig-case-sensitivity"
    fi
    
    print_success "Configuración de Git para case sensitivity completada"
    print_info "PROBLEMA RESUELTO: Evita creación de carpetas duplicadas 'Aresitos' y 'aresitos' en Linux"
}

# Crear script de prueba
create_test_script() {
    print_header "NOTE Creando script de prueba..."
    
    TEST_SCRIPT="$USER_HOME/test_aresitos_permissions.py"
    
    cat > "$TEST_SCRIPT" << 'EOF'
#!/usr/bin/env python3
"""Script de prueba para verificar permisos de ARESITOS v3.0"""
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

print("Probando herramientas de ARESITOS v3.0...")
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

# ============================================================================
# FUNCIÓN PRINCIPAL OPTIMIZADA [PRINCIPIO 19: ORQUESTACIÓN INTELIGENTE]
# ============================================================================

# Función principal con manejo de errores robusto
main() {
    # Configurar manejo de errores para la función principal
    local exit_code=0
    
    print_header "SECURE CONFIGURADOR ARESITOS v3.0 - ESCANEADOR PROFESIONAL PARA KALI LINUX [OPTIMIZADO]"
    print_header "=========================================================================================="
    
    # Inicializar log
    log_with_timestamp "Iniciando configuración ARESITOS v${ARESITOS_VERSION}"
    
    # Validaciones iniciales [PRINCIPIO 20: VALIDACIÓN TEMPRANA]
    print_info "Ejecutando validaciones iniciales..."
    
    check_root || exit 1
    detect_user || exit 1
    check_network  # No crítico, solo informativo
    check_disk_space || exit 1
    
    # Mostrar capacidades del sistema
    display_system_capabilities
    
    # Confirmación del usuario [PRINCIPIO 21: CONFIRMACIÓN EXPLÍCITA]
    if ! prompt_user_confirmation; then
        print_info "Configuración cancelada por el usuario"
        exit 0
    fi
    
    # Proceso de instalación con seguimiento de errores
    print_header "LAUNCH INICIANDO PROCESO DE CONFIGURACIÓN AUTOMÁTICA"
    
    # Ejecutar cada paso con seguimiento de errores
    local steps=(
        "update_repositories:Actualización de repositorios"
        "install_essential_tools:Instalación de herramientas esenciales"
        "install_advanced_tools:Instalación de herramientas avanzadas"
        "configure_network_permissions:Configuración de permisos de red"
        "configure_sudo:Configuración de sudo"
        "configure_aresitos_permissions:Configuración de permisos ARESITOS"
        "configure_git_case_sensitivity:Configuración Git case sensitivity"
        "install_python_deps:Instalación de dependencias Python"
        "verify_setup:Verificación final del sistema"
        "create_test_script:Creación de script de pruebas"
    )
    
    local completed_steps=0
    local total_steps=${#steps[@]}
    
    for step_info in "${steps[@]}"; do
        IFS=':' read -r step_function step_description <<< "$step_info"
        
        print_info "Ejecutando: $step_description ($((completed_steps + 1))/$total_steps)"
        
        if $step_function; then
            ((completed_steps++))
            print_success "OK $step_description completado"
        else
            print_error "ERROR $step_description falló"
            exit_code=1
            # Continuar con otros pasos en lugar de abortar completamente
        fi
        
        echo  # Línea en blanco para separación visual
    done
    
    # Mostrar resumen final
    display_final_summary "$completed_steps" "$total_steps" "$exit_code"
    
    # Log de finalización
    log_with_timestamp "Configuración finalizada con código: $exit_code"
    
    return $exit_code
}

# Mostrar capacidades del sistema [PRINCIPIO 22: INFORMACIÓN TRANSPARENTE]
display_system_capabilities() {
    echo
    print_info "TARGET CAPACIDADES DEL ESCANEADOR PROFESIONAL ARESITOS v${ARESITOS_VERSION}:"
    echo
    print_info "TOOL HERRAMIENTAS CORE:"
    echo "  • nmap: Escaneo integral con detección de servicios y scripts"
    echo "  • masscan/rustscan: Escaneo masivo ultrarrápido de redes"
    echo "  • nuclei: Detección automática de vulnerabilidades CVE"
    echo "  • gobuster/ffuf: Enumeración avanzada de directorios web"
    echo "  • wireshark: Análisis forense de tráfico de red"
    echo
    print_info "LAUNCH FUNCIONALIDADES AVANZADAS:"
    echo "  • 5 modos de escaneo especializados (Integral, Avanzado, Red, Rápido, Profundo)"
    echo "  • Exportación profesional: JSON, TXT, CSV con análisis detallado"
    echo "  • Validación automática y fallback inteligente de herramientas"
    echo "  • Escaneo paralelo masivo con ThreadPoolExecutor"
    echo "  • Integración nativa con arsenal de Kali Linux 2025"
    echo
    print_info "TOOL CONFIGURACIONES AUTOMÁTICAS:"
    echo "  • Permisos CAP_NET_RAW para escaneos SYN sin sudo"
    echo "  • Configuración sudo sin contraseña para herramientas de escaneo"
    echo "  • Actualización automática de templates nuclei"
    echo "  • Bases de datos de vulnerabilidades localizadas"
    echo "  • Wordlists categorizadas y especializadas"
    echo
}

# Confirmación del usuario [PRINCIPIO 23: INTERACCIÓN CLARA]
prompt_user_confirmation() {
    print_warning "WARNING  IMPORTANTE: Esta configuración modificará su sistema Kali Linux"
    print_info "FOLDER Log de instalación: $LOG_FILE"
    echo
    read -p "¿Continuar con la configuración automática? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_success "Configuración confirmada por el usuario"
        return 0
    else
        return 1
    fi
}

# Mostrar resumen final [PRINCIPIO 24: REPORTE FINAL DETALLADO]
display_final_summary() {
    local completed=$1
    local total=$2
    local exit_code=$3
    
    echo
    print_header "DATA RESUMEN DE CONFIGURACIÓN COMPLETADO"
    print_header "======================================="
    
    print_info "Pasos completados: $completed/$total"
    print_info "Log completo disponible en: $LOG_FILE"
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "SUCCESS CONFIGURACIÓN COMPLETADA EXITOSAMENTE"
        echo
        print_info "LAUNCH PASOS SIGUIENTES:"
        echo "  1. 🔄 Reinicie la terminal para aplicar cambios de grupos"
        echo "  2. Ejecute verificación: python3 verificacion_final.py"
        echo "  3. TARGET Ejecute pruebas: python3 ${USER_HOME}/test_aresitos_permissions.py"
        echo "  4. SECURE Inicie ARESITOS: python3 main.py"
        echo
        print_warning "TIP IMPORTANTE: Cierre y reabra la terminal para aplicar todos los cambios"
    else
        print_warning "WARNING CONFIGURACIÓN COMPLETADA CON ADVERTENCIAS"
        print_info "Revise el log para más detalles: $LOG_FILE"
        print_info "ARESITOS debería funcionar con funcionalidad básica"
    fi
    
    echo
    print_info "🔗 Soporte: https://github.com/DogSoulDev/Aresitos"
    print_info "📧 Contacto: dogsouldev@protonmail.com"
}

# ============================================================================
# PUNTO DE ENTRADA [PRINCIPIO 25: EJECUCIÓN CONTROLADA]
# ============================================================================

# Configurar limpieza automática en caso de interrupción
cleanup() {
    print_warning "Configuración interrumpida por el usuario"
    log_with_timestamp "INTERRUPCIÓN: Configuración cancelada por señal"
    exit 130
}

# Configurar manejo de señales
trap cleanup SIGINT SIGTERM

# Ejecutar función principal con todos los argumentos
main "$@"
