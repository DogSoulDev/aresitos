# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor Centralizado de Iconos
========================================

Gestor unificado para cargar y aplicar el icono Aresitos.ico de manera consistente
en todas las ventanas de la aplicación.

Autor: DogSoulDev
Fecha: 22 de Agosto de 2025
"""

import os
import tkinter as tk
from tkinter import ttk
from typing import Optional, Union


class GestorIconos:
    """Gestor centralizado para manejar iconos de ARESITOS de forma consistente"""
    
    _icono_path: Optional[str] = None
    _icono_cargado: bool = False
    
    @classmethod
    def obtener_ruta_icono(cls) -> Optional[str]:
        """
        Obtener la ruta correcta al icono Aresitos.ico
        
        Returns:
            str: Ruta absoluta al icono o None si no existe
        """
        if cls._icono_path is None:
            # Determinar ruta base desde cualquier ubicación en el proyecto
            ruta_actual = os.path.dirname(os.path.abspath(__file__))
            
            # Posibles ubicaciones del icono
            posibles_rutas = [
                # Desde utils/ -> ../recursos/
                os.path.join(ruta_actual, '..', 'recursos', 'Aresitos.ico'),
                # Desde raíz del proyecto
                os.path.join(ruta_actual, '..', '..', 'aresitos', 'recursos', 'Aresitos.ico'),
                # Ruta absoluta directa (para casos especiales)
                os.path.join(os.path.dirname(ruta_actual), 'recursos', 'Aresitos.ico')
            ]
            
            # Buscar la primera ruta que exista
            for ruta in posibles_rutas:
                ruta_normalizada = os.path.normpath(ruta)
                if os.path.exists(ruta_normalizada):
                    cls._icono_path = ruta_normalizada
                    break
            
            # Solo mostrar mensaje una vez al encontrar el icono
            if cls._icono_path and not cls._icono_cargado:
                pass  # Log silencioso para evitar spam
        
        return cls._icono_path
    
    @classmethod
    def aplicar_icono_ventana(cls, ventana: Union[tk.Tk, tk.Toplevel]) -> bool:
        """
        Aplicar el icono Aresitos.ico a una ventana Tkinter con manejo robusto de errores
        
        Args:
            ventana: Ventana Tkinter (Tk o Toplevel)
            
        Returns:
            bool: True si el icono se aplicó correctamente, False en caso contrario
        """
        try:
            ruta_icono = cls.obtener_ruta_icono()
            
            if not ruta_icono or not os.path.exists(ruta_icono):
                # Silenciosamente fallar sin logs repetitivos
                return False
            
            # Método 1: Intentar PNG primero (más compatible en Linux)
            import platform
            if platform.system() == "Linux":
                ruta_png = ruta_icono.replace('.ico', '.png')
                if os.path.exists(ruta_png):
                    try:
                        # Verificar que el archivo PNG es válido antes de cargar
                        with open(ruta_png, 'rb') as f:
                            header = f.read(8)
                            # Verificar signature PNG válida
                            if header == b'\x89PNG\r\n\x1a\n':
                                icono_img = tk.PhotoImage(file=ruta_png)
                                ventana.iconphoto(True, icono_img)
                                # Mantener referencia para evitar garbage collection
                                setattr(ventana, '_icono_ref', icono_img)
                                cls._icono_cargado = True
                                return True
                    except (tk.TclError, IOError, OSError):
                        # PNG no válido o corrupto, continuar con ICO
                        pass
            
            # Método 2: Intentar iconbitmap con .ico
            try:
                # Verificar que el archivo ICO existe y es legible
                if os.access(ruta_icono, os.R_OK):
                    ventana.iconbitmap(ruta_icono)
                    cls._icono_cargado = True
                    return True
            except tk.TclError:
                # ICO no soportado o corrupto
                pass
            
            # Método 3: Usar icono por defecto del sistema si disponible
            try:
                # En Linux, usar icono genérico del sistema
                if platform.system() == "Linux":
                    ventana.iconname("ARESITOS")
                return True
            except (tk.TclError, AttributeError):
                pass
                
            return False
                
        except Exception:
            # Fallar silenciosamente para evitar logs excesivos
            return False
    
    @classmethod
    def aplicar_icono_photoimage(cls, ventana: Union[tk.Tk, tk.Toplevel]) -> bool:
        """
        Aplicar icono usando PhotoImage como alternativa (para casos especiales)
        
        Args:
            ventana: Ventana Tkinter
            
        Returns:
            bool: True si se aplicó correctamente
        """
        try:
            ruta_icono = cls.obtener_ruta_icono()
            
            if ruta_icono and os.path.exists(ruta_icono):
                # Crear PhotoImage desde el icono (solo funciona con formatos soportados)
                icono_img = tk.PhotoImage(file=ruta_icono)
                ventana.iconphoto(True, icono_img)
                
                # Mantener referencia para evitar garbage collection
                if not hasattr(ventana, '__dict__'):
                    # Para algunos tipos de ventana, usar setattr
                    setattr(ventana, '_icono_ref', icono_img)
                else:
                    ventana.__dict__['_icono_ref'] = icono_img
                
                return True
            else:
                return False
                
        except tk.TclError:
            # PhotoImage no puede cargar .ico, usar iconbitmap como fallback
            return cls.aplicar_icono_ventana(ventana)
        except Exception as e:
            print(f"[GestorIconos] Error en PhotoImage: {e}")
            return False
    
    @classmethod
    def configurar_ventana_completa(cls, ventana: Union[tk.Tk, tk.Toplevel], titulo: str = "ARESITOS v2.0") -> bool:
        """
        Configurar ventana completa con icono y título estándar
        
        Args:
            ventana: Ventana Tkinter
            titulo: Título de la ventana
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        try:
            # Configurar título
            ventana.title(titulo)
            
            # Aplicar icono silenciosamente
            icono_aplicado = cls.aplicar_icono_ventana(ventana)
            
            # Solo mostrar mensaje de éxito, no de fallo
            if icono_aplicado:
                pass  # Silencioso para evitar spam en logs
            
            return icono_aplicado
            
        except Exception:
            return False
    
    @classmethod
    def verificar_estado_icono(cls) -> dict:
        """
        Verificar el estado actual del sistema de iconos
        
        Returns:
            dict: Información sobre el estado del icono
        """
        ruta = cls.obtener_ruta_icono()
        
        return {
            'icono_encontrado': ruta is not None,
            'ruta_icono': ruta,
            'archivo_existe': os.path.exists(ruta) if ruta else False,
            'icono_cargado': cls._icono_cargado,
            'tamano_archivo': os.path.getsize(ruta) if ruta and os.path.exists(ruta) else 0
        }


# Función de conveniencia para uso directo
def configurar_icono_ventana(ventana: Union[tk.Tk, tk.Toplevel], titulo: str = "ARESITOS v2.0") -> bool:
    """
    Función de conveniencia para configurar icono en una ventana
    
    Args:
        ventana: Ventana Tkinter
        titulo: Título de la ventana
        
    Returns:
        bool: True si se configuró correctamente
    """
    return GestorIconos.configurar_ventana_completa(ventana, titulo)


# Función para obtener información de depuración
def info_debug_iconos() -> None:
    """Imprimir información de depuración sobre el estado de los iconos"""
    estado = GestorIconos.verificar_estado_icono()
    print("\n=== INFORMACIÓN DEBUG ICONOS ===")
    for clave, valor in estado.items():
        print(f"{clave}: {valor}")
    print("================================\n")
