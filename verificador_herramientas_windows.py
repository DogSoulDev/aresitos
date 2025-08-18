#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verificador de Herramientas para Entorno Windows
Simula la verificación de herramientas de Kali Linux en entorno Windows
"""

import subprocess
import sys
import os
from pathlib import Path

class VerificadorHerramientasWindows:
    """Verificador adaptado para Windows que simula el estado de herramientas Kali"""
    
    def __init__(self):
        self.herramientas_simuladas = {
            'nmap': {'instalado': True, 'version': '7.80', 'comando': 'nmap --version'},
            'metasploit-framework': {'instalado': False, 'version': None, 'comando': 'msfconsole --version'},
            'wireshark': {'instalado': True, 'version': '3.4.0', 'comando': 'wireshark --version'},
            'burpsuite': {'instalado': False, 'version': None, 'comando': 'burpsuite --version'},
            'john': {'instalado': False, 'version': None, 'comando': 'john --version'},
            'hashcat': {'instalado': False, 'version': None, 'comando': 'hashcat --version'},
            'aircrack-ng': {'instalado': False, 'version': None, 'comando': 'aircrack-ng --version'},
            'sqlmap': {'instalado': False, 'version': None, 'comando': 'sqlmap --version'},
            'gobuster': {'instalado': False, 'version': None, 'comando': 'gobuster version'},
            'hydra': {'instalado': False, 'version': None, 'comando': 'hydra -h'},
            'nikto': {'instalado': False, 'version': None, 'comando': 'nikto -Version'},
            'netcat': {'instalado': True, 'version': 'Windows built-in', 'comando': 'nc -h'},
            'volatility': {'instalado': False, 'version': None, 'comando': 'volatility --version'},
            'suricata': {'instalado': False, 'version': None, 'comando': 'suricata --version'},
            'sysdig': {'instalado': False, 'version': None, 'comando': 'sysdig --version'}
        }
        
        self.contadores = {
            'instaladas': 0,
            'no_instaladas': 0,
            'errores': 0
        }
    
    def verificar_herramienta(self, nombre_herramienta):
        """Verifica si una herramienta específica está disponible"""
        info = self.herramientas_simuladas.get(nombre_herramienta, {})
        
        if info.get('instalado'):
            print(f"✅ {nombre_herramienta}: INSTALADO - v{info.get('version', 'N/A')}")
            self.contadores['instaladas'] += 1
            return True
        else:
            print(f"❌ {nombre_herramienta}: NO INSTALADO")
            self.contadores['no_instaladas'] += 1
            return False
    
    def verificar_todas_herramientas(self):
        """Verifica todas las herramientas conocidas"""
        print("🔍 Verificando herramientas de ciberseguridad en Windows...")
        print("=" * 60)
        
        for herramienta in self.herramientas_simuladas.keys():
            self.verificar_herramienta(herramienta)
        
        print("=" * 60)
        print(f"📊 RESUMEN:")
        print(f"   Instaladas: {self.contadores['instaladas']}")
        print(f"   No instaladas: {self.contadores['no_instaladas']}")
        print(f"   Errores: {self.contadores['errores']}")
        
        return self.contadores
    
    def verificar_python_packages(self):
        """Verifica paquetes de Python relacionados con ciberseguridad"""
        paquetes_requeridos = [
            'requests', 'beautifulsoup4', 'selenium', 'paramiko', 
            'scapy', 'pycryptodome', 'colorama', 'tqdm'
        ]
        
        print("\n🐍 Verificando paquetes de Python...")
        print("=" * 40)
        
        for paquete in paquetes_requeridos:
            try:
                import importlib
                importlib.import_module(paquete)
                print(f"✅ {paquete}: DISPONIBLE")
            except ImportError:
                print(f"❌ {paquete}: NO INSTALADO")
    
    def recomendar_instalaciones(self):
        """Proporciona recomendaciones de instalación para Windows"""
        print("\n📋 RECOMENDACIONES PARA WINDOWS:")
        print("=" * 50)
        
        recomendaciones = {
            'nmap': 'Descargar desde: https://nmap.org/download.html',
            'wireshark': 'Descargar desde: https://www.wireshark.org/download.html',
            'metasploit-framework': 'Instalar via Chocolatey: choco install metasploit',
            'burpsuite': 'Descargar desde: https://portswigger.net/burp/communitydownload',
            'python-packages': 'pip install requests beautifulsoup4 selenium paramiko scapy',
            'virtualbox': 'Para ejecutar Kali Linux en VM',
            'wsl2': 'Windows Subsystem for Linux para herramientas nativas'
        }
        
        for herramienta, recomendacion in recomendaciones.items():
            print(f"🔧 {herramienta}:")
            print(f"   {recomendacion}")
            print()
    
    def generar_reporte_txt(self):
        """Genera reporte en archivo de texto"""
        reporte_path = Path("reporte_herramientas_windows.txt")
        
        with open(reporte_path, 'w', encoding='utf-8') as f:
            f.write("REPORTE DE VERIFICACIÓN DE HERRAMIENTAS\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Sistema operativo: Windows\n")
            f.write(f"Python version: {sys.version}\n\n")
            
            for nombre, info in self.herramientas_simuladas.items():
                estado = "INSTALADO" if info['instalado'] else "NO INSTALADO"
                version = info.get('version', 'N/A')
                f.write(f"{nombre}: {estado} - v{version}\n")
            
            f.write(f"\nRESUMEN:\n")
            f.write(f"Instaladas: {self.contadores['instaladas']}\n")
            f.write(f"No instaladas: {self.contadores['no_instaladas']}\n")
        
        print(f"📄 Reporte guardado en: {reporte_path.absolute()}")

def main():
    """Función principal"""
    print("🛡️  ARES AEGIS - Verificador de Herramientas Windows")
    print("=" * 60)
    
    verificador = VerificadorHerramientasWindows()
    
    # Verificar herramientas principales
    verificador.verificar_todas_herramientas()
    
    # Verificar paquetes Python
    verificador.verificar_python_packages()
    
    # Mostrar recomendaciones
    verificador.recomendar_instalaciones()
    
    # Generar reporte
    verificador.generar_reporte_txt()
    
    print("\n✅ Verificación completada!")

if __name__ == "__main__":
    main()
