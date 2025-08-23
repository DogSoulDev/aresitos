# -*- coding: utf-8 -*-
"""
Aresitos - Helper de Seguridad para Interfaces
==============================================

Funciones auxiliares para mostrar información de seguridad 
en las interfaces de usuario de Aresitos.

Exclusivamente para Kali Linux.

Autor: DogSoulDev
Fecha: 22 de Agosto de 2025
"""

import tkinter as tk
from tkinter import messagebox
from typing import List, Dict, Any, Optional

class HelperSeguridad:
    """
    Clase helper para mostrar información de seguridad en las interfaces.
    """
    
    @staticmethod
    def mostrar_info_carga_archivo(tipo_archivo: str, parent=None) -> bool:
        """
        Mostrar información sobre qué tipos de archivos son seguros cargar.
        
        Args:
            tipo_archivo: Tipo de archivo a cargar
            parent: Ventana padre para el diálogo
            
        Returns:
            True si el usuario quiere continuar, False si cancela
        """
        from Aresitos.utils.sanitizador_archivos import SanitizadorArchivos
        
        extensiones = SanitizadorArchivos.obtener_extensiones_permitidas(tipo_archivo)
        
        if not extensiones:
            extensiones_texto = "Ninguna extensión específica permitida"
        else:
            extensiones_texto = ", ".join(extensiones)
        
        mensaje = f"""
LOCK INFORMACIÓN DE SEGURIDAD - CARGA DE ARCHIVOS

Tipo de archivo: {tipo_archivo.upper()}
Extensiones permitidas: {extensiones_texto}

[WARNING]  MEDIDAS DE SEGURIDAD ACTIVAS:
• Solo se permiten archivos con extensiones válidas
• Verificación de contenido y estructura de archivo
• Validación de tamaño máximo (50MB)
• Detección de caracteres peligrosos en nombres
• Prevención de ataques de traversal de directorios

[SECURITY]  ARCHIVOS RECHAZADOS AUTOMÁTICAMENTE:
• Ejecutables (.exe, .bat, .sh no válidos)
• Archivos con rutas peligrosas (../, ~/)
• Archivos con nombres de sistema reservados
• Contenido malformado o corrupto

¿Desea continuar con la carga del archivo?
        """
        
        result = messagebox.askyesno(
            "Seguridad - Carga de Archivos", 
            mensaje
        )
        return result
    
    @staticmethod
    def mostrar_advertencia_cuarentena(parent=None) -> bool:
        """
        Mostrar advertencia especial para archivos de cuarentena.
        
        Args:
            parent: Ventana padre para el diálogo
            
        Returns:
            True si el usuario quiere continuar, False si cancela
        """
        mensaje = """
LOCK ADVERTENCIA - ARCHIVO PARA CUARENTENA

[WARNING]  ATENCIÓN: Está a punto de cargar un archivo potencialmente peligroso.

[SECURITY]  MEDIDAS DE PROTECCIÓN:
• El archivo será aislado inmediatamente
• No se ejecutará automáticamente
• Se aplicará análisis de seguridad
• Acceso restringido y monitorizado

🚨 IMPORTANTE:
• Solo continúe si confía en el origen del archivo
• Los archivos maliciosos pueden dañar el sistema
• Use esta función solo para análisis de seguridad

¿Está seguro de que desea continuar?
        """
        
        result = messagebox.askyesno(
            "ADVERTENCIA - Cuarentena de Archivos", 
            mensaje
        )
        return result
    
    @staticmethod
    def mostrar_resultado_validacion(resultado: Dict[str, Any], parent=None) -> bool:
        """
        Mostrar resultado detallado de validación de archivo.
        
        Args:
            resultado: Diccionario con resultado de validación
            parent: Ventana padre para el diálogo
            
        Returns:
            True si el usuario quiere continuar (solo con advertencias), False si hay errores
        """
        if not resultado['valido']:
            # Archivo rechazado - mostrar errores
            errores = resultado.get('errores', [])
            if isinstance(errores, list):
                errores_texto = '\n• '.join(errores)
            else:
                errores_texto = str(errores)
            
            mensaje = f"""
🚫 ARCHIVO RECHAZADO POR SEGURIDAD

[FAIL] Errores encontrados:
• {errores_texto}

[SECURITY] El archivo no cumple con los estándares de seguridad de Aresitos.
Por favor, verifique el archivo y vuelva a intentarlo.
            """
            
            messagebox.showerror(
                "Archivo Rechazado", 
                mensaje
            )
            return False
        
        else:
            # Archivo válido, verificar advertencias
            advertencias = resultado.get('advertencias', [])
            
            if advertencias:
                if isinstance(advertencias, list):
                    advertencias_texto = '\n• '.join(advertencias)
                else:
                    advertencias_texto = str(advertencias)
                
                mensaje = f"""
[WARNING]  ARCHIVO ACEPTADO CON ADVERTENCIAS

[OK] El archivo ha pasado las validaciones básicas de seguridad.

[WARNING]  Advertencias encontradas:
• {advertencias_texto}

¿Desea continuar cargando el archivo?
                """
                
                return messagebox.askyesno(
                    "Advertencias de Seguridad", 
                    mensaje
                )
            
            return True  # Archivo válido sin advertencias
    
    @staticmethod
    def mostrar_ayuda_formatos(tipo_archivo: str, parent=None):
        """
        Mostrar ayuda sobre formatos de archivo soportados.
        
        Args:
            tipo_archivo: Tipo de archivo
            parent: Ventana padre para el diálogo
        """
        ayuda_formatos = {
            'wordlists': """
NOTE FORMATOS SOPORTADOS - WORDLISTS

[OK] Archivos de texto (.txt):
• Una palabra por línea
• Codificación UTF-8
• Sin caracteres de control

[OK] Listas (.list):
• Formato similar a .txt
• Estructura lineal simple

[OK] Diccionarios (.dic):
• Formato de texto plano
• Compatible con herramientas estándar

💡 Ejemplo de contenido válido:
admin
password
test123
usuario
            """,
            
            'diccionarios': """
NOTE FORMATOS SOPORTADOS - DICCIONARIOS

[OK] Archivos JSON (.json):
• Estructura JSON válida
• Codificación UTF-8
• Máximo 50MB

💡 Ejemplo de estructura:
{
    "nombre_diccionario": {
        "termino1": "definición1",
        "termino2": "definición2"
    }
}
            """,
            
            'reportes': """
NOTE FORMATOS SOPORTADOS - REPORTES

[OK] Archivos JSON (.json):
• Estructura JSON válida con metadatos
• Información de escaneos y resultados

[OK] Archivos de texto (.txt):
• Texto plano con información de reportes
• Codificación UTF-8

💡 Los reportes contienen información de:
• Escaneos de seguridad
• Resultados de auditorías
• Análisis de vulnerabilidades
            """
        }
        
        mensaje = ayuda_formatos.get(tipo_archivo, "Información no disponible para este tipo de archivo.")
        
        messagebox.showinfo(
            f"Ayuda - Formatos {tipo_archivo.capitalize()}", 
            mensaje
        )
