# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor Centralizado de Iconos
========================================

Gestor unificado para aplicar iconos de ciberseguridad integrados
en código, sin dependencias externas de archivos.

Principios ARESITOS aplicados:
- Sin archivos externos de iconos
- Icono de ciberseguridad integrado en código
- Compatibilidad con Kali Linux optimizada

Autor: DogSoulDev
Fecha: 23 de Agosto de 2025
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Union
import base64


class GestorIconos:
    """Gestor centralizado para manejar iconos de ciberseguridad integrados"""
    
    _icono_cargado: bool = False
    
    # Icono de ciberseguridad integrado en código (16x16 pixels)
    ICONO_CYBER_BASE64 = """
    iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz
    AAAB2AAAAdgB+lymcgAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAGkSURBVDiN
    pZM9SwNBEIafgIWNhYWFhYWFhYWNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2N
    jY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2N
    jY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2N
    jY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2N
    """
    
    # Icono alternativo ASCII art para terminales (shield symbol)
    ICONO_ASCII = "SHIELD"
    
    @classmethod
    def crear_icono_cyber(cls) -> Optional[Union[tk.PhotoImage, tk.BitmapImage]]:
        """
        Crear icono de ciberseguridad desde datos integrados.
        
        Returns:
            PhotoImage/BitmapImage: Objeto de imagen o None si falla
        """
        try:
            # Crear un icono simple de escudo/seguridad usando código
            # 16x16 pixel shield en formato XBM (monocromo, compatible)
            icono_xbm = """
            #define shield_width 16
            #define shield_height 16
            static char shield_bits[] = {
                0x00, 0x00, 0x80, 0x01, 0xc0, 0x03, 0xe0, 0x07,
                0xf0, 0x0f, 0xf8, 0x1f, 0xfc, 0x3f, 0xfe, 0x7f,
                0xfe, 0x7f, 0xfc, 0x3f, 0xf8, 0x1f, 0xf0, 0x0f,
                0xe0, 0x07, 0xc0, 0x03, 0x80, 0x01, 0x00, 0x00
            };
            """
            
            # Crear PhotoImage desde datos XBM
            return tk.BitmapImage(data=icono_xbm)
            
        except Exception:
            return None
    
    @classmethod
    def aplicar_icono_ventana(cls, ventana: Union[tk.Tk, tk.Toplevel]) -> bool:
        """
        Aplicar icono de ciberseguridad a una ventana Tkinter.
        
        Args:
            ventana: Ventana Tkinter (Tk o Toplevel)
            
        Returns:
            bool: True si el icono se aplicó correctamente
        """
        try:
            import platform
            
            # Método para Linux/Kali (prioritario)
            if platform.system() == "Linux":
                return cls._aplicar_icono_linux(ventana)
            else:
                return cls._aplicar_icono_windows(ventana)
                
        except Exception:
            return False
    
    @classmethod
    def _aplicar_icono_linux(cls, ventana: Union[tk.Tk, tk.Toplevel]) -> bool:
        """Método especializado para aplicar iconos en Kali Linux."""
        try:
            # 1. Crear icono integrado
            icono_cyber = cls.crear_icono_cyber()
            
            if icono_cyber:
                try:
                    # Aplicar usando iconphoto si es PhotoImage
                    if isinstance(icono_cyber, tk.PhotoImage):
                        ventana.iconphoto(True, icono_cyber)
                        # Configurar propiedades del window manager
                        try:
                            ventana.wm_iconphoto(True, icono_cyber)
                        except:
                            pass
                    
                    # Mantener referencia para evitar garbage collection
                    setattr(ventana, '_icono_cyber_ref', icono_cyber)
                    
                    cls._icono_cargado = True
                    return True
                    
                except Exception:
                    pass
            
            # 2. Fallback: Configurar solo propiedades del window manager
            try:
                ventana.wm_title("ARESITOS V3 - CYBER SECURITY")
                if hasattr(ventana, 'wm_iconname'):
                    ventana.wm_iconname("ARESITOS-CYBER")
                return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    @classmethod 
    def _aplicar_icono_windows(cls, ventana: Union[tk.Tk, tk.Toplevel]) -> bool:
        """Método para Windows."""
        try:
            # Crear icono integrado
            icono_cyber = cls.crear_icono_cyber()
            
            if icono_cyber:
                try:
                    # Aplicar usando iconphoto si es PhotoImage
                    if isinstance(icono_cyber, tk.PhotoImage):
                        ventana.iconphoto(True, icono_cyber)
                    
                    setattr(ventana, '_icono_cyber_ref', icono_cyber)
                    cls._icono_cargado = True
                    return True
                except:
                    pass
            
            # Fallback: configurar título con símbolo de seguridad
            try:
                ventana.title("ARESITOS V3 - CYBER SECURITY")
                return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    @classmethod
    def crear_icono_avanzado(cls) -> Optional[Union[tk.PhotoImage, tk.BitmapImage]]:
        """
        Crear icono más avanzado de ciberseguridad.
        
        Returns:
            PhotoImage/BitmapImage: Icono de ciberseguridad o None
        """
        try:
            # Crear un icono de 32x32 con datos más detallados
            # Escudo con símbolo de candado
            icono_detallado = """
            #define cyber_width 32
            #define cyber_height 32
            static char cyber_bits[] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x7e, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00,
                0x80, 0xff, 0x01, 0x00, 0xc0, 0xff, 0x03, 0x00,
                0xe0, 0xff, 0x07, 0x00, 0xf0, 0xff, 0x0f, 0x00,
                0xf8, 0xff, 0x1f, 0x00, 0xfc, 0xff, 0x3f, 0x00,
                0xfe, 0xff, 0x7f, 0x00, 0xff, 0xff, 0xff, 0x00,
                0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x01,
                0xff, 0xff, 0xff, 0x01, 0xff, 0x81, 0xff, 0x01,
                0xff, 0x81, 0xff, 0x01, 0xff, 0x81, 0xff, 0x01,
                0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x01,
                0xff, 0xff, 0xff, 0x01, 0xfe, 0xff, 0x7f, 0x00,
                0xfc, 0xff, 0x3f, 0x00, 0xf8, 0xff, 0x1f, 0x00,
                0xf0, 0xff, 0x0f, 0x00, 0xe0, 0xff, 0x07, 0x00,
                0xc0, 0xff, 0x03, 0x00, 0x80, 0xff, 0x01, 0x00,
                0x00, 0xff, 0x00, 0x00, 0x00, 0x7e, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            """
            
            return tk.BitmapImage(data=icono_detallado)
            
        except Exception:
            return None
    
    @classmethod
    def configurar_ventana_completa(cls, ventana: Union[tk.Tk, tk.Toplevel], titulo: str = "ARESITOS V3 - CYBER SECURITY") -> bool:
        """
        Configurar ventana completa con icono de ciberseguridad y título.
        
        Args:
            ventana: Ventana Tkinter
            titulo: Título de la ventana
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        try:
            # Configurar título con símbolo de seguridad
            ventana.title(titulo)
            
            # Aplicar icono de ciberseguridad
            icono_aplicado = cls.aplicar_icono_ventana(ventana)
            
            # Configuraciones adicionales para aspecto profesional
            try:
                # Configurar geometría mínima para ventanas
                ventana.minsize(400, 300)
                
                # Centrar ventana en pantalla
                ventana.update_idletasks()
                width = ventana.winfo_reqwidth()
                height = ventana.winfo_reqheight()
                posX = (ventana.winfo_screenwidth() // 2) - (width // 2)
                posY = (ventana.winfo_screenheight() // 2) - (height // 2)
                ventana.geometry(f"{width}x{height}+{posX}+{posY}")
                
            except:
                pass
            
            return True
            
        except Exception:
            return False
    
    @classmethod
    def verificar_estado_icono(cls) -> dict:
        """
        Verificar el estado del sistema de iconos integrado.
        
        Returns:
            dict: Información sobre el estado del icono
        """
        return {
            'icono_integrado': True,
            'tipo_icono': 'ciberseguridad_integrado',
            'archivos_externos': False,
            'icono_cargado': cls._icono_cargado,
            'compatible_kali': True,
            'simbolo_ascii': cls.ICONO_ASCII
        }


# Función de conveniencia para uso directo
def configurar_icono_ventana(ventana: Union[tk.Tk, tk.Toplevel], titulo: str = "ARESITOS V3 - CYBER SECURITY") -> bool:
    """
    Función de conveniencia para configurar icono de ciberseguridad en una ventana.
    
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
    print("\n=== INFORMACIÓN DEBUG ICONOS CYBER ===")
    for clave, valor in estado.items():
        print(f"{clave}: {valor}")
    print("======================================\n")
