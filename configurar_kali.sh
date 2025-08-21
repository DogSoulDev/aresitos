#!/bin/bash
# -*- coding: utf-8 -*-
"""
ARESITOS v2.0 - Script de Configuración para Kali Linux
=======================================================

Script de configuración automática para preparar Kali Linux
para ejecutar ARESITOS con todas las funcionalidades.

Funciones principales:
- Instalar herramientas de ciberseguridad necesarias
- Configurar permisos sudo para herramientas específicas
- Configurar permisos de red para escaneo
- Actualizar bases de datos de vulnerabilidades
- Verificar funcionamiento completo del sistema

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
Versión: 2.0
Proyecto: ARESITOS - Suite de Ciberseguridad

IMPORTANTE: Este script debe ejecutarse como root o con sudo
sudo ./configurar_kali.sh
"""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Función para imprimir con colores
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
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
    print_header "🛠️ Instalando herramientas de ciberseguridad ARESITOS v2.0..."
    
    # Lista completa de herramientas necesarias para ARESITOS v2.0
    TOOLS=(
        # Herramientas básicas del sistema
        "python3-dev"
        "python3-pip"
        "python3-tk"
        "curl"
        "wget"
        "git"
        
        # Herramientas de red y monitoreo (MODERNAS)
        "nmap"
        "rustscan"
        "masscan"
        "netstat-nat"
        "net-tools"
        "tcpdump"
        "iftop"
        "nethogs"
        "ss"
        
        # Herramientas de escaneo web (ACTUALIZADAS)
        "nikto"
        "gobuster" 
        "feroxbuster"
        "httpx-toolkit"
        "whatweb"
        
        # Herramientas de seguridad y análisis (SIMPLIFICADAS)
        "lynis"
        "chkrootkit"
        
        # Herramientas de análisis forense (ESENCIALES)
        "foremost"
        "binwalk"
        "exiftool"
        
        # Utilidades del sistema
        "htop"
        "lsof"
        "strace"
        "ltrace"
        "psmisc"
    )
    
    print_info "Actualizando lista de paquetes..."
    apt update -qq
    
    for tool in "${TOOLS[@]}"; do
        print_info "Verificando $tool..."
        
        if dpkg -l | grep -q "^ii  $tool "; then
            print_success "$tool ya está instalado"
        else
            print_info "Instalando $tool..."
            DEBIAN_FRONTEND=noninteractive apt install -y "$tool" >/dev/null 2>&1
            
            if [[ $? -eq 0 ]]; then
                print_success "$tool instalado correctamente"
            else
                print_error "Error instalando $tool"
            fi
        fi
    done
    
    # Instalar nuclei manualmente si no está disponible
    print_info "Verificando nuclei..."
    if ! command -v nuclei >/dev/null 2>&1; then
        print_info "Instalando nuclei desde GitHub..."
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest >/dev/null 2>&1 || {
            print_warning "No se pudo instalar nuclei (requiere Go)"
        }
    else
        print_success "nuclei ya está instalado"
    fi
    
    # Actualizar base de datos de ClamAV
    print_info "Actualizando base de datos de ClamAV..."
    sudo -u clamav freshclam >/dev/null 2>&1 || {
        print_warning "Error actualizando ClamAV (continuando)"
    }
}

# Configurar permisos especiales para herramientas de red
configure_network_permissions() {
    print_header "🔐 Configurando permisos de red..."
    
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
configure_sudo() {
    print_header "⚡ Configurando sudo para ARESITOS v2.0..."
    
    SUDO_FILE="/etc/sudoers.d/aresitos-v2"
    
    # Crear archivo de configuración sudo actualizado
    cat > "$SUDO_FILE" << EOF
# Configuración sudo para ARESITOS v2.0
# Suite de Ciberseguridad para Kali Linux
# Permite ejecutar herramientas de seguridad sin contraseña
# Generado automáticamente el $(date)

# Usuario: $REAL_USER
# === HERRAMIENTAS DE ESCANEO ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/masscan
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nikto
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/gobuster
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/whatweb
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/nuclei

# === HERRAMIENTAS DE MONITOREO ===
$REAL_USER ALL=(ALL) NOPASSWD: /bin/netstat
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/ss
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/lsof
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
$REAL_USER ALL=(ALL) NOPASSWD: /bin/ps
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/pgrep

# === HERRAMIENTAS DE SEGURIDAD ===
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/lynis
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/chkrootkit
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/rkhunter
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/clamscan
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/clamdscan

# === ACCESO A LOGS DEL SISTEMA ===
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/auth.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/syslog*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/kern.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/daemon.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/mail.log*
$REAL_USER ALL=(ALL) NOPASSWD: /bin/tail /var/log/*
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/head /var/log/*

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

# Instalar dependencias Python
install_python_deps() {
    print_header "🐍 Instalando dependencias Python..."
    
    # Cambiar al usuario real para pip
    sudo -u "$REAL_USER" pip3 install --user Pillow
    
    if [[ $? -eq 0 ]]; then
        print_success "Dependencias Python instaladas"
    else
        print_warning "Error instalando dependencias Python"
    fi
}

# Verificar configuración
verify_setup() {
    print_header "🧪 Verificando configuración..."
    
    # Verificar herramientas
    TOOLS_TO_CHECK=("nmap" "netstat" "ss" "tcpdump")
    
    for tool in "${TOOLS_TO_CHECK[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "$tool disponible"
            
            # Verificar permisos sudo
            sudo -u "$REAL_USER" sudo -n "$tool" --version >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                print_success "$tool ejecutable sin contraseña"
            else
                print_warning "$tool requiere contraseña"
            fi
        else
            print_error "$tool no encontrado"
        fi
    done
    
    # Verificar grupos
    print_info "Verificando membresía de grupos para $REAL_USER..."
    groups "$REAL_USER" | grep -q wireshark && print_success "Usuario en grupo wireshark" || print_warning "Usuario NO en grupo wireshark"
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
    status = "✅" if success else "❌"
    print(f"{status} {tool}: {'OK' if success else 'FAIL'}")
    if success and stdout:
        print(f"   {stdout.split()[0] if stdout else 'Sin versión'}")

print("\n🔐 Probando permisos sudo...")
print("="*30)

sudo_tests = [
    ("sudo", ["nmap", "--version"]),
    ("sudo", ["netstat", "--help"]),
]

for cmd, args in sudo_tests:
    success, stdout, stderr = test_tool(cmd, args)
    status = "✅" if success else "❌"
    tool_name = args[0] if args else cmd
    print(f"{status} sudo {tool_name}: {'OK' if success else 'FAIL'}")

print("\n✅ Pruebas completadas")
EOF

    chown "$REAL_USER:$REAL_USER" "$TEST_SCRIPT"
    chmod +x "$TEST_SCRIPT"
    
    print_success "Script de prueba creado: $TEST_SCRIPT"
    print_info "Ejecute: python3 $TEST_SCRIPT"
}

# Función principal
main() {
    print_header "🛡️ CONFIGURADOR DE PERMISOS ARES AEGIS PARA KALI LINUX"
    print_header "=========================================================="
    
    check_root
    detect_user
    
    echo
    print_info "Este script configurará Ares Aegis para funcionar correctamente en Kali Linux"
    print_info "Se realizarán las siguientes acciones:"
    echo "  • Actualizar repositorios"
    echo "  • Instalar herramientas de seguridad necesarias"
    echo "  • Configurar permisos de red especiales"
    echo "  • Configurar sudo sin contraseña para herramientas específicas"
    echo "  • Instalar dependencias Python"
    echo "  • Verificar configuración"
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
    install_python_deps
    verify_setup
    create_test_script
    
    echo
    print_header "🎉 CONFIGURACIÓN COMPLETADA"
    print_header "============================"
    
    print_success "Ares Aegis está configurado para Kali Linux"
    echo
    print_info "Pasos siguientes:"
    echo "  1. Cierre y reabra la terminal para aplicar cambios de grupo"
    echo "  2. Execute el script de prueba: python3 $USER_HOME/test_ares_permissions.py"
    echo "  3. Execute la verificación de permisos: python3 verificacion_permisos.py"
    echo "  4. Inicie Ares Aegis: python3 main.py"
    echo
    print_warning "IMPORTANTE: Reinicie la sesión para aplicar cambios de grupos"
}

# Ejecutar función principal
main "$@"
