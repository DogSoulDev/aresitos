# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor de Favicon
============================

Gestor centralizado para favicon compatible con Kali Linux.
Implementa los principios ARESITOS para manejo de iconos.

Principios ARESITOS aplicados:
- Adaptabilidad: Soporte multiplataforma
- Responsabilidad: Función específica para iconos
- Eficiencia: Carga única y reutilización
- Simplicidad: API clara y directa
- Integridad: Validación robusta
- Transparencia: Logging detallado
- Optimización: Performance óptimo
- Seguridad: Validación de rutas

Autor: DogSoulDev
Fecha: 25 de Agosto de 2025
"""

import os
import sys
import platform
import logging
from pathlib import Path
from typing import Optional

class FaviconManager:
    """Gestor centralizado de favicon para ARESITOS v3.0"""
    
    def __init__(self):
        """Inicializar el gestor de favicon"""
        self.favicon_path = None
        self.favicon_loaded = False
        self.base_path = Path(__file__).parent.parent
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Detectar sistema operativo para optimización
        self.is_linux = platform.system() == "Linux"
        self.is_kali = self._detectar_kali()
        
        # Cargar favicon automáticamente
        self._cargar_favicon()
    
    def _detectar_kali(self) -> bool:
        """Detectar si estamos en Kali Linux"""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    return 'kali' in content
        except Exception:
            pass
        return False
    
    def _cargar_favicon(self) -> None:
        """Cargar favicon siguiendo principios ARESITOS"""
        try:
            # Ruta base de recursos
            recursos_path = self.base_path / "recursos"
            
            # Priorizar PNG para Kali Linux (mejor compatibilidad)
            if self.is_linux:
                favicon_candidates = [
                    recursos_path / "aresitos.png",
                    recursos_path / "Aresitos.ico",
                ]
            else:
                favicon_candidates = [
                    recursos_path / "Aresitos.ico",
                    recursos_path / "aresitos.png",
                ]
            
            # Buscar primer favicon válido
            for candidate in favicon_candidates:
                if self._validar_favicon(candidate):
                    self.favicon_path = str(candidate)
                    self.favicon_loaded = True
                    self.logger.info(f"Favicon cargado: {self.favicon_path}")
                    break
            
            if not self.favicon_loaded:
                self.logger.warning("No se encontró favicon válido")
                
        except Exception as e:
            self.logger.error(f"Error cargando favicon: {e}")
    
    def _validar_favicon(self, path: Path) -> bool:
        """Validar archivo de favicon"""
        try:
            # Verificar existencia
            if not path.exists():
                return False
            
            # Verificar que es archivo
            if not path.is_file():
                return False
            
            # Verificar tamaño razonable (< 1MB)
            if path.stat().st_size > 1024 * 1024:
                return False
            
            # Verificar extensión
            valid_extensions = {'.ico', '.png', '.gif', '.bmp'}
            if path.suffix.lower() not in valid_extensions:
                return False
            
            return True
            
        except Exception:
            return False
    
    def aplicar_favicon(self, root_window) -> bool:
        """
        Aplicar favicon a ventana Tkinter
        
        Args:
            root_window: Ventana Tkinter principal
            
        Returns:
            bool: True si se aplicó exitosamente
        """
        if not self.favicon_loaded or not self.favicon_path:
            return False
        
        try:
            import tkinter as tk
            
            # Método 1: Para Linux - usar wm iconphoto (más compatible)
            if self.is_linux:
                try:
                    # Cargar imagen como PhotoImage (PNG funciona mejor en Linux)
                    if self.favicon_path.endswith('.png'):
                        icon_image = tk.PhotoImage(file=self.favicon_path)
                        # Usar wm iconphoto que es más compatible con gestores de ventanas Linux
                        root_window.tk.call('wm', 'iconphoto', root_window._w, icon_image)
                        self.logger.info("Favicon aplicado usando wm iconphoto (Linux)")
                        return True
                    else:
                        # Si no hay PNG, intentar con ICO usando iconbitmap
                        root_window.iconbitmap(self.favicon_path)
                        self.logger.info("Favicon aplicado usando iconbitmap (Linux fallback)")
                        return True
                        
                except Exception as e:
                    self.logger.warning(f"Método Linux falló: {e}")
                    # Fallback adicional para Linux
                    try:
                        # Método alternativo usando iconphoto con True flag
                        icon_image = tk.PhotoImage(file=self.favicon_path)
                        root_window.iconphoto(True, icon_image)
                        self.logger.info("Favicon aplicado usando iconphoto con flag True")
                        return True
                    except Exception as e2:
                        self.logger.warning(f"Fallback iconphoto falló: {e2}")
                        return False
            else:
                # Método 2: Para Windows - usar iconbitmap directamente
                root_window.iconbitmap(self.favicon_path)
                self.logger.info("Favicon aplicado usando iconbitmap (Windows)")
                return True
                
        except Exception as e:
            self.logger.error(f"Error aplicando favicon: {e}")
            return False
    
    def get_favicon_path(self) -> Optional[str]:
        """Obtener ruta del favicon cargado"""
        return self.favicon_path if self.favicon_loaded else None
    
    def is_loaded(self) -> bool:
        """Verificar si el favicon está cargado"""
        return self.favicon_loaded
    
    def get_info(self) -> dict:
        """Obtener información del favicon para debugging"""
        return {
            "loaded": self.favicon_loaded,
            "path": self.favicon_path,
            "is_linux": self.is_linux,
            "is_kali": self.is_kali,
            "base_path": str(self.base_path)
        }

# Instancia global del gestor de favicon
favicon_manager = FaviconManager()

def aplicar_favicon_aresitos(root_window) -> bool:
    """
    Función de conveniencia para aplicar favicon de ARESITOS
    Incluye método específico optimizado para Kali Linux
    
    Args:
        root_window: Ventana Tkinter
        
    Returns:
        bool: True si se aplicó exitosamente
    """
    return favicon_manager.aplicar_favicon(root_window)

def aplicar_favicon_kali_optimizado(root_window) -> bool:
    """
    Método específico optimizado para Kali Linux basado en investigación
    Usa wm iconphoto que es más compatible con gestores de ventanas Linux
    
    Args:
        root_window: Ventana Tkinter
        
    Returns:
        bool: True si se aplicó exitosamente
    """
    try:
        import tkinter as tk
        from pathlib import Path
        
        # Buscar PNG específicamente para mejor compatibilidad en Kali
        base_path = Path(__file__).parent.parent
        recursos_path = base_path / "recursos"
        png_path = recursos_path / "aresitos.png"
        
        if png_path.exists():
            try:
                # Método recomendado por la comunidad Linux/Tkinter
                icon_image = tk.PhotoImage(file=str(png_path))
                root_window.tk.call('wm', 'iconphoto', root_window._w, icon_image)
                print(f"[KALI] Favicon aplicado usando wm iconphoto: {png_path.name}")
                return True
            except Exception as e:
                print(f"[KALI] Error con wm iconphoto: {e}")
                # Fallback con iconphoto normal
                try:
                    icon_image = tk.PhotoImage(file=str(png_path))
                    root_window.iconphoto(True, icon_image)
                    print(f"[KALI] Favicon aplicado usando iconphoto: {png_path.name}")
                    return True
                except Exception as e2:
                    print(f"[KALI] Error con iconphoto: {e2}")
                    return False
        else:
            print(f"[KALI] PNG no encontrado: {png_path}")
            return False
            
    except Exception as e:
        print(f"[KALI] Error general favicon: {e}")
        return False

def get_favicon_info() -> dict:
    """Obtener información del favicon para debugging"""
    return favicon_manager.get_info()
