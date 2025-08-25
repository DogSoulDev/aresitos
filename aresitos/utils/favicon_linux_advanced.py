#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
ARESITOS v3.0 - Sistema de Favicon Kali Linux 2025 Específico
=============================================================================

Módulo especializado para resolver problemas de favicon en Kali Linux 2025.
Implementa técnicas específicas para el entorno GNOME/Wayland moderno.

Principios ARESITOS aplicados:
- Adaptabilidad: Múltiples métodos para diferentes entornos
- Robustez: Manejo exhaustivo de errores
- Eficiencia: Optimizado para sistemas modernos
- Seguridad: Validación de archivos antes de uso
- Interoperabilidad: Compatible con X11 y Wayland
- Transparencia: Logging detallado del proceso
- Optimización: Técnicas específicas para Kali 2025
- Sostenibilidad: Código mantenible y documentado

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

class FaviconKali2025:
    """
    Gestor de favicon especializado para Kali Linux 2025.
    
    Maneja las peculiaridades específicas del entorno GNOME/Wayland
    en Kali Linux 2025 y sistemas modernos similares.
    """
    
    def __init__(self):
        """Inicializa el gestor de favicon con configuración específica."""
        self.logger = logging.getLogger(__name__)
        self.metodos_aplicados = []
        self.session_type = self._detectar_session_type()
        self.gnome_version = self._detectar_gnome_version()
        self.kali_version = self._detectar_kali_version()
        # Rutas de favicon prioritarias para Kali 2025 (incluye rutas reales existentes)
        self.rutas_favicon = [
            "aresitos/recursos/iconos/aresitos_icono.ico",
            "aresitos/recursos/iconos/aresitos_icono.png",
            "aresitos/recursos/Aresitos.ico",
            "aresitos/recursos/aresitos.png",
            "recursos/iconos/aresitos_icono.ico",
            "recursos/iconos/aresitos_icono.png",
            "recursos/Aresitos.ico",
            "recursos/aresitos.png",
            "iconos/aresitos_icono.ico",
            "iconos/aresitos_icono.png"
        ]
        self.logger.info(f"FaviconKali2025 iniciado - Session: {self.session_type}, GNOME: {self.gnome_version}")

    def _detectar_session_type(self):
        """Detecta si está ejecutándose en X11 o Wayland."""
        try:
            session_type = os.environ.get('XDG_SESSION_TYPE', 'unknown')
            wayland_display = os.environ.get('WAYLAND_DISPLAY', '')
            x11_display = os.environ.get('DISPLAY', '')
            
            if session_type == 'wayland' or wayland_display:
                return 'wayland'
            elif session_type == 'x11' or x11_display:
                return 'x11'
            else:
                return 'unknown'
        except Exception as e:
            self.logger.warning(f"Error detectando session type: {e}")
            return 'unknown'

    def _detectar_gnome_version(self):
        """Detecta la versión de GNOME."""
        try:
            result = subprocess.run(['gnome-shell', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version_line = result.stdout.strip()
                # Extrae número de versión (ej: "GNOME Shell 45.0")
                version = version_line.split()[-1] if version_line else "unknown"
                return version
        except Exception as e:
            self.logger.warning(f"Error detectando GNOME version: {e}")
        return "unknown"

    def _detectar_kali_version(self):
        """Detecta la versión de Kali Linux."""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('VERSION='):
                            version = line.split('=')[1].strip('"\'')
                            return version
        except Exception as e:
            self.logger.warning(f"Error detectando Kali version: {e}")
        return "unknown"

    def _encontrar_favicon(self):
        """Encuentra el archivo de favicon con la mejor calidad disponible (solo PNG o ICO nativos)."""
        for ruta in self.rutas_favicon:
            ruta_completa = Path(ruta)
            if ruta_completa.exists():
                # Solo acepta archivos PNG o ICO válidos
                if ruta_completa.suffix.lower() not in ['.png', '.ico']:
                    continue
                size = ruta_completa.stat().st_size
                if size == 0:
                    self.logger.warning(f"Archivo favicon vacío: {ruta_completa}")
                    continue
                self.logger.info(f"Favicon encontrado: {ruta_completa}")
                return str(ruta_completa)
        self.logger.error("No se encontró ningún favicon válido")
        return None

    def _metodo_wm_iconphoto_mejorado(self, ventana, ruta_favicon):
        """
        Método wm_iconphoto específico para Kali 2025 (solo nativo, sin PIL).
        """
        try:
            metodo = "wm_iconphoto_kali2025_nativo"
            if ruta_favicon.endswith('.png'):
                photo = PhotoImage(file=ruta_favicon)
                ventana.wm_iconphoto(True, photo)
                self.logger.info(f"✓ {metodo} aplicado (modo nativo)")
                self.metodos_aplicados.append(metodo)
                return True
            else:
                self.logger.warning(f"Archivo no es PNG: {ruta_favicon}")
                return False
        except Exception as e:
            self.logger.warning(f"Error en {metodo}: {e}")
            return False

    def _metodo_iconbitmap_x11(self, ventana, ruta_favicon):
        """Método iconbitmap para X11 con manejo de errores mejorado."""
        try:
            metodo = "iconbitmap_x11"
            
            if self.session_type == 'x11' and ruta_favicon.endswith('.ico'):
                ventana.iconbitmap(ruta_favicon)
                self.logger.info(f"✓ {metodo} aplicado exitosamente")
                self.metodos_aplicados.append(metodo)
                return True
            else:
                self.logger.info(f"✗ {metodo} no aplicado (session: {self.session_type}, archivo: {ruta_favicon})")
        
        except Exception as e:
            self.logger.warning(f"Error en {metodo}: {e}")
        
        return False

    def _metodo_wm_attributes_gnome(self, ventana):
        """Método específico para atributos de ventana en GNOME."""
        try:
            metodo = "wm_attributes_gnome"
            
            # Establece atributos específicos para GNOME Shell
            ventana.wm_attributes('-type', 'normal')
            
            # Para Wayland, intenta establecer class hints
            if self.session_type == 'wayland':
                ventana.wm_class("ARESITOS", "ARESITOS")
            
            self.logger.info(f"✓ {metodo} aplicado")
            self.metodos_aplicados.append(metodo)
            return True
            
        except Exception as e:
            self.logger.warning(f"Error en {metodo}: {e}")
        
        return False

    def _metodo_geometry_focus(self, ventana):
        """Método para optimizar geometría y foco en Kali 2025."""
        try:
            metodo = "geometry_focus_kali2025"
            
            # Centra la ventana
            ventana.update_idletasks()
            width = ventana.winfo_reqwidth()
            height = ventana.winfo_reqheight()
            x = (ventana.winfo_screenwidth() // 2) - (width // 2)
            y = (ventana.winfo_screenheight() // 2) - (height // 2)
            ventana.geometry(f"{width}x{height}+{x}+{y}")
            
            # Fuerza el foco y actualización
            ventana.focus_force()
            ventana.lift()
            ventana.update()
            
            self.logger.info(f"✓ {metodo} aplicado")
            self.metodos_aplicados.append(metodo)
            return True
            
        except Exception as e:
            self.logger.warning(f"Error en {metodo}: {e}")
        
        return False

    def _metodo_desktop_file_integration(self, ventana):
        """Integración con archivos .desktop para mejor reconocimiento del WM."""
        try:
            metodo = "desktop_file_integration"
            
            # Establece WM_CLASS para mejor integración con .desktop
            ventana.wm_class("aresitos", "ARESITOS")
            
            # Establece título consistente
            ventana.title("ARESITOS v3.0 - Sistema de Seguridad Avanzado")
            
            self.logger.info(f"✓ {metodo} aplicado")
            self.metodos_aplicados.append(metodo)
            return True
            
        except Exception as e:
            self.logger.warning(f"Error en {metodo}: {e}")
        
        return False

    def _metodo_force_icon_refresh(self, ventana):
        """Método para forzar actualización de iconos en sistemas modernos."""
        try:
            metodo = "force_icon_refresh"
            
            # Secuencia de comandos para forzar actualización
            ventana.withdraw()
            ventana.update_idletasks()
            ventana.deiconify()
            ventana.update()
            
            # Intenta enviar eventos al window manager
            try:
                ventana.tk.call('wm', 'iconify', ventana._w)
                ventana.tk.call('wm', 'deiconify', ventana._w)
            except:
                pass
            
            self.logger.info(f"✓ {metodo} aplicado")
            self.metodos_aplicados.append(metodo)
            return True
            
        except Exception as e:
            self.logger.warning(f"Error en {metodo}: {e}")
        
        return False

    def aplicar_favicon_kali_2025(self, ventana):
        """
        Aplica favicon con métodos específicos para Kali Linux 2025.
        
        Args:
            ventana: Ventana Tkinter donde aplicar el favicon
            
        Returns:
            bool: True si se aplicó al menos un método exitosamente
        """
        self.logger.info("=== Iniciando aplicación de favicon para Kali Linux 2025 ===")
        self.logger.info(f"Entorno detectado: {self.session_type}, GNOME: {self.gnome_version}, Kali: {self.kali_version}")
        
        # Busca el favicon
        ruta_favicon = self._encontrar_favicon()
        if not ruta_favicon:
            self.logger.error("No se puede continuar sin archivo de favicon")
            return False
        
        # Resetea contador de métodos
        self.metodos_aplicados = []
        exito_total = False
        
        # Método 1: WM IconPhoto mejorado (principal para Wayland/GNOME)
        if self._metodo_wm_iconphoto_mejorado(ventana, ruta_favicon):
            exito_total = True
        
        # Método 2: IconBitmap para X11
        if self._metodo_iconbitmap_x11(ventana, ruta_favicon):
            exito_total = True
        
        # Método 3: Atributos GNOME específicos
        if self._metodo_wm_attributes_gnome(ventana):
            exito_total = True
        
        # Método 4: Integración con archivos .desktop
        if self._metodo_desktop_file_integration(ventana):
            exito_total = True
        
        # Método 5: Optimización de geometría y foco
        if self._metodo_geometry_focus(ventana):
            exito_total = True
        
        # Método 6: Forzar actualización de iconos
        if self._metodo_force_icon_refresh(ventana):
            exito_total = True
        
        # Reporte final
        self.logger.info(f"=== Aplicación de favicon completada ===")
        self.logger.info(f"Métodos exitosos: {len(self.metodos_aplicados)}/{6}")
        self.logger.info(f"Métodos aplicados: {', '.join(self.metodos_aplicados)}")
        
        if exito_total:
            self.logger.info("✓ Favicon aplicado exitosamente para Kali Linux 2025")
        else:
            self.logger.warning("✗ No se pudo aplicar ningún método de favicon")
        
        return exito_total

# Función de conveniencia para uso directo
def aplicar_favicon_kali_2025(ventana):
    """
    Función de conveniencia para aplicar favicon en Kali Linux 2025.
    
    Args:
        ventana: Ventana Tkinter donde aplicar el favicon
        
    Returns:
        bool: True si se aplicó exitosamente
    """
    gestor = FaviconKali2025()
    return gestor.aplicar_favicon_kali_2025(ventana)

if __name__ == "__main__":
    # Test del módulo
    print("=== Test del módulo FaviconKali2025 ===")
    
    # Configura logging para test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Crea ventana de prueba
    root = tk.Tk()
    root.title("Test Favicon Kali 2025")
    root.geometry("400x300")
    
    # Aplica favicon
    gestor = FaviconKali2025()
    exito = gestor.aplicar_favicon_kali_2025(root)
    
    # Muestra resultado
    resultado_label = tk.Label(
        root, 
        text=f"Favicon aplicado: {'✓ SÍ' if exito else '✗ NO'}\n"
             f"Métodos exitosos: {len(gestor.metodos_aplicados)}\n"
             f"Session: {gestor.session_type}\n"
             f"GNOME: {gestor.gnome_version}",
        justify=tk.CENTER,
        pady=20
    )
    resultado_label.pack(expand=True)
    
    print(f"Test completado. Favicon aplicado: {exito}")
    print(f"Métodos aplicados: {gestor.metodos_aplicados}")
    
    # Ejecuta interfaz de test por 5 segundos
    root.after(5000, root.destroy)
    root.mainloop()
