#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ARESITOS v3.0 - Sistema de Favicon Linux Avanzado
=============================================================================

Módulo especializado para resolver problemas de favicon en distribuciones Linux
modernas, especialmente optimizado para Kali Linux 2025.
Implementa técnicas avanzadas para entornos GNOME/Wayland/X11.

Principios ARESITOS aplicados:
- Adaptabilidad: Múltiples métodos para diferentes entornos Linux
- Robustez: Manejo exhaustivo de errores y fallbacks
- Eficiencia: Optimizado para sistemas Linux modernos
- Seguridad: Validación estricta de archivos antes de uso
- Interoperabilidad: Compatible con X11, Wayland y gestores de ventanas
- Transparencia: Logging detallado del proceso de aplicación
- Optimización: Técnicas específicas para distribuciones Linux actuales
- Sostenibilidad: Código mantenible y bien documentado
- Simplicidad: Solo bibliotecas estándar de Python, sin dependencias externas

Desarrollador: ARESITOS Team
Versión: 3.0
Fecha: 2025
Licencia: MIT
"""

import os
import sys
import logging
import tkinter as tk
from tkinter import PhotoImage
import subprocess
import platform
from pathlib import Path

# PRINCIPIO ARESITOS: Solo bibliotecas estándar de Python
# No usar dependencias externas para mantener simplicidad y robustez

class FaviconLinuxAvanzado:
    """
    Gestor de favicon especializado para distribuciones Linux modernas.
    
    Maneja las peculiaridades específicas del entorno GNOME/Wayland/X11
    en Kali Linux 2025 y sistemas modernos similares.
    
    Principios ARESITOS implementados:
    - Solo bibliotecas estándar
    - Múltiples métodos de fallback
    - Detección automática del entorno
    """
    
    def __init__(self):
        """Inicializar el gestor de favicon avanzado para Linux"""
        self.logger = logging.getLogger(__name__)
        self.base_path = Path(__file__).parent.parent
        self.recursos_path = self.base_path / "recursos"
        
        # Detectar información del entorno Linux
        self.entorno_info = self._detectar_entorno_linux()
        
        # Buscar archivos de favicon disponibles
        self.favicon_paths = self._buscar_favicons()
        
        self.logger.info("FaviconLinuxAvanzado inicializado")
        self.logger.info(f"Entorno detectado: {self.entorno_info}")
        self.logger.info(f"Favicons disponibles: {len(self.favicon_paths)}")
    
    def _detectar_entorno_linux(self) -> dict:
        """Detectar información detallada del entorno Linux"""
        entorno = {
            'desktop_env': os.environ.get('XDG_CURRENT_DESKTOP', '').lower(),
            'session_type': os.environ.get('XDG_SESSION_TYPE', '').lower(),
            'display': os.environ.get('DISPLAY', ''),
            'wayland_display': os.environ.get('WAYLAND_DISPLAY', ''),
            'window_manager': '',
            'is_gnome': False,
            'is_kde': False,
            'is_xfce': False,
            'is_wayland': False,
            'is_x11': False
        }
        
        # Detectar tipo de sesión
        entorno['is_wayland'] = entorno['session_type'] == 'wayland' or bool(entorno['wayland_display'])
        entorno['is_x11'] = entorno['session_type'] == 'x11' or bool(entorno['display'])
        
        # Detectar entorno de escritorio
        desktop = entorno['desktop_env']
        entorno['is_gnome'] = 'gnome' in desktop
        entorno['is_kde'] = 'kde' in desktop or 'plasma' in desktop
        entorno['is_xfce'] = 'xfce' in desktop
        
        # Detectar gestor de ventanas específico
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                procesos = result.stdout.lower()
                if 'mutter' in procesos:
                    entorno['window_manager'] = 'mutter'
                elif 'kwin' in procesos:
                    entorno['window_manager'] = 'kwin'
                elif 'xfwm4' in procesos:
                    entorno['window_manager'] = 'xfwm4'
                elif 'i3' in procesos:
                    entorno['window_manager'] = 'i3'
        except Exception:
            pass
        
        return entorno
    
    def _buscar_favicons(self) -> list:
        """Buscar archivos de favicon disponibles"""
        archivos_posibles = [
            "aresitos.png",
            "Aresitos.ico", 
            "aresitos.gif",
            "aresitos.bmp"
        ]
        
        archivos_encontrados = []
        for archivo in archivos_posibles:
            ruta = self.recursos_path / archivo
            if ruta.exists() and self._validar_archivo_imagen(ruta):
                archivos_encontrados.append(str(ruta))
        
        return archivos_encontrados
    
    def _validar_archivo_imagen(self, ruta: Path) -> bool:
        """Validar que el archivo es una imagen válida usando solo stdlib"""
        try:
            # Verificaciones básicas
            if not ruta.exists() or not ruta.is_file():
                return False
            
            # Verificar tamaño del archivo (no muy grande)
            if ruta.stat().st_size > 2 * 1024 * 1024:  # 2MB máximo
                return False
            
            # Verificar extensión
            extensiones_validas = {'.png', '.ico', '.gif', '.bmp'}
            if ruta.suffix.lower() not in extensiones_validas:
                return False
            
            # Para PNG, verificar header básico
            if ruta.suffix.lower() == '.png':
                with open(ruta, 'rb') as f:
                    header = f.read(8)
                    # PNG signature
                    if header != b'\x89PNG\r\n\x1a\n':
                        return False
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Error validando archivo {ruta}: {e}")
            return False
    
    def aplicar_favicon_kali_2025(self, ventana) -> bool:
        """
        Aplicar favicon optimizado para Kali Linux 2025 y sistemas modernos
        Usa solo bibliotecas estándar de Python
        """
        try:
            if not self.favicon_paths:
                self.logger.warning("No hay archivos de favicon disponibles")
                return False
            
            # Priorizar PNG para mejor compatibilidad en Linux
            favicon_prioritario = None
            for ruta in self.favicon_paths:
                if ruta.endswith('.png'):
                    favicon_prioritario = ruta
                    break
            
            if not favicon_prioritario:
                favicon_prioritario = self.favicon_paths[0]
            
            # Método 1: wm iconphoto (mejor para Linux moderno)
            if self._aplicar_wm_iconphoto(ventana, favicon_prioritario):
                return True
            
            # Método 2: iconphoto estándar
            if self._aplicar_iconphoto_estandar(ventana, favicon_prioritario):
                return True
            
            # Método 3: iconbitmap (fallback)
            if self._aplicar_iconbitmap_fallback(ventana, favicon_prioritario):
                return True
            
            self.logger.error("Todos los métodos de favicon fallaron")
            return False
            
        except Exception as e:
            self.logger.error(f"Error aplicando favicon Kali 2025: {e}")
            return False
    
    def _aplicar_wm_iconphoto(self, ventana, ruta_favicon: str) -> bool:
        """Método wm iconphoto - el más compatible con Linux moderno"""
        try:
            # Solo funciona con PNG usando PhotoImage nativo de tkinter
            if not ruta_favicon.endswith('.png'):
                return False
            
            # Cargar imagen con PhotoImage nativo
            photo = PhotoImage(file=ruta_favicon)
            
            # Aplicar usando wm iconphoto
            ventana.tk.call('wm', 'iconphoto', ventana._w, photo)
            
            # Mantener referencia para evitar garbage collection
            ventana._favicon_ref = photo
            
            self.logger.info(f"✓ wm iconphoto aplicado exitosamente: {Path(ruta_favicon).name}")
            return True
            
        except Exception as e:
            self.logger.warning(f"wm iconphoto falló: {e}")
            return False
    
    def _aplicar_iconphoto_estandar(self, ventana, ruta_favicon: str) -> bool:
        """Método iconphoto estándar"""
        try:
            # Solo funciona con PNG usando PhotoImage nativo
            if not ruta_favicon.endswith('.png'):
                return False
            
            photo = PhotoImage(file=ruta_favicon)
            ventana.iconphoto(True, photo)
            
            # Mantener referencia
            ventana._favicon_ref = photo
            
            self.logger.info(f"✓ iconphoto estándar aplicado: {Path(ruta_favicon).name}")
            return True
            
        except Exception as e:
            self.logger.warning(f"iconphoto estándar falló: {e}")
            return False
    
    def _aplicar_iconbitmap_fallback(self, ventana, ruta_favicon: str) -> bool:
        """Método iconbitmap como último recurso"""
        try:
            ventana.iconbitmap(ruta_favicon)
            self.logger.info(f"✓ iconbitmap fallback aplicado: {Path(ruta_favicon).name}")
            return True
            
        except Exception as e:
            self.logger.warning(f"iconbitmap fallback falló: {e}")
            return False
    
    def obtener_informacion_debug(self) -> dict:
        """Obtener información completa para debugging"""
        return {
            "entorno_linux": self.entorno_info,
            "favicon_paths": self.favicon_paths,
            "recursos_path": str(self.recursos_path),
            "base_path": str(self.base_path)
        }

# Función de conveniencia que sigue los principios ARESITOS
def aplicar_favicon_kali_2025(ventana) -> bool:
    """
    Función de conveniencia para aplicar favicon en Kali Linux 2025
    
    Args:
        ventana: Ventana Tkinter donde aplicar el favicon
        
    Returns:
        bool: True si se aplicó exitosamente, False en caso contrario
    """
    try:
        gestor = FaviconLinuxAvanzado()
        return gestor.aplicar_favicon_kali_2025(ventana)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error en aplicar_favicon_kali_2025: {e}")
        return False

def obtener_info_sistema_linux() -> dict:
    """
    Obtener información del sistema Linux para debugging
    
    Returns:
        dict: Información detallada del entorno
    """
    try:
        gestor = FaviconLinuxAvanzado()
        return gestor.obtener_informacion_debug()
    except Exception as e:
        logging.getLogger(__name__).error(f"Error obteniendo info sistema: {e}")
        return {}

# Verificación del módulo
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("ARESITOS - Test Favicon Linux Avanzado")
    print("=" * 50)
    
    # Obtener información del sistema
    info = obtener_info_sistema_linux()
    print("Información del entorno:")
    for clave, valor in info.get('entorno_linux', {}).items():
        print(f"  {clave}: {valor}")
    
    print(f"Favicons disponibles: {len(info.get('favicon_paths', []))}")
    for favicon in info.get('favicon_paths', []):
        print(f"  - {Path(favicon).name}")
