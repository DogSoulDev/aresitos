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
            
            # Log de depuración
            if cls._icono_path:
                print(f"[GestorIconos] Icono encontrado: {cls._icono_path}")
            else:
                print(f"[GestorIconos] ADVERTENCIA: Icono Aresitos.ico no encontrado en ubicaciones esperadas")
                print(f"[GestorIconos] Rutas buscadas: {posibles_rutas}")
        
        return cls._icono_path
    
    @classmethod
    def aplicar_icono_ventana(cls, ventana: Union[tk.Tk, tk.Toplevel]) -> bool:
        """
        Aplicar el icono Aresitos.ico a una ventana Tkinter
        
        Args:
            ventana: Ventana Tkinter (Tk o Toplevel)
            
        Returns:
            bool: True si el icono se aplicó correctamente, False en caso contrario
        """
        try:
            ruta_icono = cls.obtener_ruta_icono()
            
            if ruta_icono and os.path.exists(ruta_icono):
                # En Linux, usar PhotoImage primero (más compatible)
                import platform
                if platform.system() == "Linux":
                    try:
                        # Buscar PNG alternativo (más compatible en Linux)
                        ruta_png = ruta_icono.replace('.ico', '.png')
                        if os.path.exists(ruta_png):
                            icono_img = tk.PhotoImage(file=ruta_png)
                            ventana.iconphoto(True, icono_img)
                            # Mantener referencia
                            if hasattr(ventana, '__dict__'):
                                ventana.__dict__['_icono_ref'] = icono_img
                            else:
                                setattr(ventana, '_icono_ref', icono_img)
                            cls._icono_cargado = True
                            print(f"[GestorIconos] Icono PNG aplicado en Linux: {ruta_png}")
                            return True
                    except Exception as e:
                        print(f"[GestorIconos] PNG falló, intentando ICO: {e}")
                
                # Método tradicional con iconbitmap
                ventana.iconbitmap(ruta_icono)
                cls._icono_cargado = True
                print(f"[GestorIconos] Icono ICO aplicado: {ruta_icono}")
                return True
            else:
                print(f"[GestorIconos] No se pudo aplicar icono - archivo no encontrado: {ruta_icono}")
                return False
                
        except tk.TclError as e:
            print(f"[GestorIconos] Error Tkinter aplicando icono: {e}")
            # Intentar método alternativo
            return cls.aplicar_icono_photoimage(ventana)
        except Exception as e:
            print(f"[GestorIconos] Error general aplicando icono: {e}")
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
            
            # Aplicar icono
            icono_aplicado = cls.aplicar_icono_ventana(ventana)
            
            if not icono_aplicado:
                print(f"[GestorIconos] Ventana '{titulo}' configurada sin icono")
            else:
                print(f"[GestorIconos] Ventana '{titulo}' configurada exitosamente con icono")
            
            return icono_aplicado
            
        except Exception as e:
            print(f"[GestorIconos] Error configurando ventana: {e}")
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
