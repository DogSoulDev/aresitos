#!/bin/bash
# ARESITOS - Configuración del Sistema de Actualización
# ===================================================
#
# Script para configurar permisos y dependencias del actualizador
# Exclusivamente para Kali Linux
#
# Autor: DogSoulDev
# Fecha: 16 de Agosto de 2025

echo "🚀 CONFIGURANDO SISTEMA DE ACTUALIZACIÓN ARESITOS"
echo "================================================="

# Verificar que estamos en Kali Linux
if ! grep -qi "kali" /etc/os-release 2>/dev/null; then
    echo "❌ Error: Este script requiere Kali Linux"
    exit 1
fi

# Verificar permisos sudo
if ! sudo -n true 2>/dev/null; then
    echo "❌ Error: Se requieren permisos sudo"
    echo "   Ejecute: sudo ./configurar_actualizador.sh"
    exit 1
fi

echo "✅ Sistema Kali Linux detectado"
echo "✅ Permisos sudo verificados"

# Crear directorios necesarios
echo "📁 Creando estructura de directorios..."
mkdir -p logs/
mkdir -p recursos/
chmod 755 logs/
chmod 755 recursos/

# Configurar permisos para el actualizador
echo "🔐 Configurando permisos del actualizador..."
chmod +x actualizador_aresitos.py

# Verificar herramientas críticas
echo "🔧 Verificando herramientas críticas..."
herramientas=("python3" "apt" "curl" "wget" "sudo")

for herramienta in "${herramientas[@]}"; do
    if command -v "$herramienta" >/dev/null 2>&1; then
        echo "  ✅ $herramienta: instalado"
    else
        echo "  ❌ $herramienta: NO ENCONTRADO"
        echo "     Instale con: sudo apt install $herramienta"
    fi
done

# Verificar conectividad
echo "🌐 Verificando conectividad..."
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "  ✅ Conexión a internet: OK"
else
    echo "  ⚠️ Advertencia: Sin conexión a internet"
fi

# Crear alias para ejecución fácil
echo "⚙️ Configurando alias del sistema..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Agregar alias al bashrc si no existe
if ! grep -q "alias aresitos-update" ~/.bashrc 2>/dev/null; then
    echo "" >> ~/.bashrc
    echo "# ARESITOS Actualizador" >> ~/.bashrc
    echo "alias aresitos-update='sudo python3 $SCRIPT_DIR/actualizador_aresitos.py'" >> ~/.bashrc
    echo "  ✅ Alias 'aresitos-update' agregado a ~/.bashrc"
else
    echo "  ✅ Alias ya configurado"
fi

# Información final
echo ""
echo "🎉 CONFIGURACIÓN COMPLETADA"
echo "=========================="
echo ""
echo "📋 COMANDOS DISPONIBLES:"
echo "   • Actualización completa: sudo python3 actualizador_aresitos.py"
echo "   • Desde terminal: aresitos-update (después de reiniciar terminal)"
echo "   • Desde ARESITOS: Usar botón 'Actualizar Sistema'"
echo ""
echo "💡 RECOMENDACIONES:"
echo "   • Ejecutar actualización semanalmente"
echo "   • Mantener respaldos antes de actualizar"
echo "   • Verificar logs en directorio logs/"
echo ""
echo "✅ El sistema está listo para actualizaciones automáticas"
