# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Gestor de Favicon Multiplataforma
=================================================

Sistema avanzado de gestión de favicons con soporte específico para Kali Linux 2025
y otros sistemas modernos. Implementa múltiples métodos de fallback.

Principios ARESITOS aplicados:
- Adaptabilidad: Detección automática del mejor método por sistema
- Responsabilidad: Gestión centralizada de iconos
- Eficiencia: Carga única y reutilización optimizada
- Simplicidad: API clara para diferentes casos de uso
- Integridad: Validación exhaustiva de archivos
- Transparencia: Logging detallado del proceso
- Optimización: Métodos específicos por OS/WM
- Seguridad: Validación de rutas y archivos

Autor: ARESITOS Team
Fecha: 25 de Agosto de 2025
Versión: 3.0
"""

import os
import sys
import platform
import logging
from pathlib import Path
from typing import Optional

# Importar módulo avanzado para Linux
try:
    from .favicon_linux_advanced import aplicar_favicon_kali_2025
    LINUX_ADVANCED_DISPONIBLE = True
except ImportError:
    LINUX_ADVANCED_DISPONIBLE = False
    aplicar_favicon_kali_2025 = None

class FaviconManager:
    """Gestor avanzado de favicon para ARESITOS v3.0 con soporte específico para Kali 2025"""
    
    def __init__(self):
        """Inicializar el gestor de favicon con detección automática del sistema"""
        self.favicon_path = None
        self.favicon_loaded = False
        self.base_path = Path(__file__).parent.parent
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Detectar sistema y entorno
        self.sistema_info = self._detectar_sistema_completo()
        
        # Cargar favicon automáticamente
        self._cargar_favicon()
    
    def _detectar_sistema_completo(self) -> dict:
        """Detectar información completa del sistema para optimización"""
        info = {
            'os': platform.system().lower(),
            'release': platform.release(),
            'is_linux': platform.system() == "Linux",
            'is_kali': False,
            'is_kali_2025': False,
            'desktop_env': os.environ.get('XDG_CURRENT_DESKTOP', '').lower(),
            'session_type': os.environ.get('XDG_SESSION_TYPE', '').lower(),
            'display': os.environ.get('DISPLAY', ''),
            'wayland_display': os.environ.get('WAYLAND_DISPLAY', '')
        }
        
        # Detectar Kali Linux específicamente
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'kali' in content:
                        info['is_kali'] = True
                        # Detectar Kali 2025
                        if '2025' in content or 'rolling' in content:
                            info['is_kali_2025'] = True
        except Exception:
            pass
        
        self.logger.info(f"Sistema detectado: {info}")
        return info
    
    def _cargar_favicon(self) -> None:
        """Cargar favicon siguiendo principios ARESITOS con priorización inteligente"""
        try:
            # Ruta base de recursos
            recursos_path = self.base_path / "recursos"
            iconos_path = recursos_path / "iconos"
            
            # Estrategia de priorización según el sistema
            if self.sistema_info['is_kali_2025']:
                # Para Kali 2025, priorizar PNG para mejor compatibilidad con GNOME/Wayland
                favicon_candidates = [
                    iconos_path / "aresitos_icono.png",
                    recursos_path / "aresitos.png",
                    iconos_path / "aresitos_icono.ico",
                    recursos_path / "Aresitos.ico",
                ]
            elif self.sistema_info['is_linux']:
                # Para otros Linux, PNG sigue siendo preferido
                favicon_candidates = [
                    iconos_path / "aresitos_icono.png",
                    recursos_path / "aresitos.png",
                    iconos_path / "aresitos_icono.ico",
                    recursos_path / "Aresitos.ico",
                ]
            else:
                # Para Windows, ICO es preferido
                favicon_candidates = [
                    iconos_path / "aresitos_icono.ico",
                    recursos_path / "Aresitos.ico",
                    iconos_path / "aresitos_icono.png",
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
        """Validar archivo de favicon con verificaciones exhaustivas"""
        try:
            # Verificar existencia
            if not path.exists():
                return False
            
            # Verificar que es archivo
            if not path.is_file():
                return False
            
            # Verificar tamaño razonable (< 2MB)
            size = path.stat().st_size
            if size == 0 or size > 2 * 1024 * 1024:
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
        Aplicar favicon usando la mejor estrategia para el sistema detectado
        
        Args:
            root_window: Ventana Tkinter principal
            
        Returns:
            bool: True si se aplicó exitosamente
        """
        if not self.favicon_loaded or not self.favicon_path:
            self.logger.warning("Favicon no cargado, no se puede aplicar")
            return False
        
        # Seleccionar estrategia según el sistema
        if self.sistema_info['is_kali_2025']:
            return self._aplicar_favicon_kali_2025(root_window)
        elif self.sistema_info['is_linux']:
            return self._aplicar_favicon_linux_general(root_window)
        else:
            return self._aplicar_favicon_windows(root_window)
    
    def _aplicar_favicon_kali_2025(self, root_window) -> bool:
        """Método específico optimizado para Kali Linux 2025"""
        try:
            # Intentar usar el módulo especializado
            if LINUX_ADVANCED_DISPONIBLE and aplicar_favicon_kali_2025:
                try:
                    if aplicar_favicon_kali_2025(root_window):
                        self.logger.info("✓ Favicon aplicado con módulo Linux avanzado")
                        return True
                except Exception as e:
                    self.logger.warning(f"Módulo Linux avanzado falló: {e}")
            else:
                self.logger.info("Módulo Linux avanzado no disponible, usando método alternativo")
            
            # Fallback a método Linux general optimizado
            return self._aplicar_favicon_linux_general(root_window)
            
        except Exception as e:
            self.logger.error(f"Error aplicando favicon Kali 2025: {e}")
            return False
    
    def _aplicar_favicon_linux_general(self, root_window) -> bool:
        """Método optimizado para sistemas Linux en general"""
        if not self.favicon_path:
            self.logger.warning("Favicon path no disponible")
            return False
            
        try:
            import tkinter as tk
            
            # Estrategia múltiple para Linux
            metodos_exitosos = 0
            
            # Método 1: wm_iconphoto (recomendado para GNOME/modern WM)
            if self.favicon_path.endswith('.png'):
                try:
                    icon_image = tk.PhotoImage(file=self.favicon_path)
                    root_window.wm_iconphoto(True, icon_image)
                    metodos_exitosos += 1
                    self.logger.info("✓ wm_iconphoto aplicado exitosamente")
                except Exception as e:
                    self.logger.warning(f"wm_iconphoto falló: {e}")
            
            # Método 2: iconbitmap (para X11/ICO)
            if self.favicon_path.endswith('.ico') and self.sistema_info['session_type'] == 'x11':
                try:
                    root_window.iconbitmap(self.favicon_path)
                    metodos_exitosos += 1
                    self.logger.info("✓ iconbitmap aplicado exitosamente")
                except Exception as e:
                    self.logger.warning(f"iconbitmap falló: {e}")
            
            # Método 3: tk.call wm iconphoto (método alternativo)
            if self.favicon_path.endswith('.png'):
                try:
                    icon_image = tk.PhotoImage(file=self.favicon_path)
                    root_window.tk.call('wm', 'iconphoto', root_window._w, icon_image)
                    metodos_exitosos += 1
                    self.logger.info("✓ tk.call wm iconphoto aplicado exitosamente")
                except Exception as e:
                    self.logger.warning(f"tk.call wm iconphoto falló: {e}")
            
            # Optimizaciones adicionales para Linux
            try:
                root_window.wm_class("ARESITOS", "ARESITOS")
                root_window.update_idletasks()
            except Exception:
                pass
            
            if metodos_exitosos > 0:
                self.logger.info(f"✓ Favicon Linux aplicado ({metodos_exitosos} métodos exitosos)")
                return True
            else:
                self.logger.warning("✗ Ningún método de favicon Linux funcionó")
                return False
                
        except Exception as e:
            self.logger.error(f"Error aplicando favicon Linux: {e}")
            return False
    
    def _aplicar_favicon_windows(self, root_window) -> bool:
        """Método optimizado para Windows"""
        if not self.favicon_path:
            self.logger.warning("Favicon path no disponible")
            return False
            
        try:
            # Para Windows, iconbitmap es el método estándar y más confiable
            root_window.iconbitmap(self.favicon_path)
            self.logger.info("✓ Favicon Windows aplicado usando iconbitmap")
            return True
                
        except Exception as e:
            self.logger.error(f"Error aplicando favicon Windows: {e}")
            # Fallback con PhotoImage para PNG
            if self.favicon_path.endswith('.png'):
                try:
                    import tkinter as tk
                    icon_image = tk.PhotoImage(file=self.favicon_path)
                    root_window.wm_iconphoto(False, icon_image)
                    self.logger.info("✓ Favicon Windows aplicado usando PhotoImage fallback")
                    return True
                except Exception as e2:
                    self.logger.error(f"Fallback Windows también falló: {e2}")
            return False
    
    def get_favicon_path(self) -> Optional[str]:
        """Obtener ruta del favicon cargado"""
        return self.favicon_path if self.favicon_loaded else None
    
    def is_loaded(self) -> bool:
        """Verificar si el favicon está cargado"""
        return self.favicon_loaded
    
    def get_info(self) -> dict:
        """Obtener información completa del favicon y sistema para debugging"""
        return {
            "loaded": self.favicon_loaded,
            "path": self.favicon_path,
            "base_path": str(self.base_path),
            "sistema_info": self.sistema_info
        }

# Instancia global del gestor de favicon
favicon_manager = FaviconManager()

def aplicar_favicon_aresitos(root_window) -> bool:
    """
    Función principal para aplicar favicon de ARESITOS
    Método estándar compatible con la mayoría de sistemas
    
    Args:
        root_window: Ventana Tkinter
        
    Returns:
        bool: True si se aplicó exitosamente
    """
    return favicon_manager.aplicar_favicon(root_window)

def aplicar_favicon_kali_optimizado(root_window) -> bool:
    """
    Método específico optimizado para Kali Linux con técnicas avanzadas
    Compatible con Kali 2025 y sistemas GNOME/Wayland
    
    Args:
        root_window: Ventana Tkinter
        
    Returns:
        bool: True si se aplicó exitosamente
    """
    # Si es Kali 2025, usar método específico
    if favicon_manager.sistema_info.get('is_kali_2025', False):
        return favicon_manager._aplicar_favicon_kali_2025(root_window)
    else:
        return favicon_manager._aplicar_favicon_linux_general(root_window)

def aplicar_favicon_principal(root_window) -> bool:
    """
    Función principal inteligente que detecta automáticamente el mejor método
    
    Args:
        root_window: Ventana Tkinter
        
    Returns:
        bool: True si se aplicó exitosamente
    """
    return favicon_manager.aplicar_favicon(root_window)

def get_favicon_info() -> dict:
    """Obtener información completa del favicon y sistema para debugging"""
    return favicon_manager.get_info()

# Alias para compatibilidad hacia atrás
aplicar_favicon = aplicar_favicon_principal
