# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.

Aresitos - Sanitizador de Archivos
==================================
Módulo de seguridad para validar archivos antes de cargarlos al sistema.
Previene ataques mediante archivos maliciosos.

Exclusivamente para Kali Linux.

Autor: DogSoulDev
Fecha: 22 de Agosto de 2025
"""

import os
import mimetypes
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

class SanitizadorArchivos:
    """
    Clase para sanitizar y validar archivos antes de cargarlos en Aresitos.
    Implementa múltiples capas de seguridad.
    """
    
    # Extensiones permitidas por tipo de archivo
    EXTENSIONES_PERMITIDAS = {
        'wordlists': ['.txt', '.list', '.dic'],
        'diccionarios': ['.json'],
        'reportes': ['.json', '.txt'],
        'configuracion': ['.json', '.conf', '.cfg'],
        'logs': ['.log', '.txt'],
        'cheatsheets': ['.txt', '.md']
    }
    
    # MIME types permitidos
    MIME_TYPES_PERMITIDOS = {
        'text/plain',
        'application/json',
        'text/markdown',
        'application/x-empty'  # Para archivos vacíos
    }
    
    # Tamaño máximo de archivo (50MB)
    TAMANO_MAXIMO = 50 * 1024 * 1024
    
    # Patrones peligrosos en nombres de archivo
    PATRONES_PELIGROSOS = [
        '..', '/', '\\', ':', '*', '?', '"', '<', '>', '|',
        'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3',
        'lpt1', 'lpt2', 'lpt3'
    ]
    
    def __init__(self):
        """Inicializar sanitizador."""
        self.errores = []
        self.advertencias = []
    
    def validar_archivo(self, ruta_archivo: str, tipo_esperado: str) -> Dict[str, Union[bool, str, List[str]]]:
        """
        Validar archivo completo con múltiples capas de seguridad.
        
        Args:
            ruta_archivo: Ruta al archivo a validar
            tipo_esperado: Tipo esperado ('wordlists', 'diccionarios', etc.)
            
        Returns:
            Dict con resultado de validación
        """
        self.errores = []
        self.advertencias = []
        
        try:
            # Verificar que el archivo existe
            if not os.path.exists(ruta_archivo):
                self.errores.append("El archivo no existe")
                return self._crear_resultado(False)
            
            # Validar ruta del archivo
            if not self._validar_ruta_segura(ruta_archivo):
                return self._crear_resultado(False)
            
            # Validar nombre del archivo
            if not self._validar_nombre_archivo(ruta_archivo):
                return self._crear_resultado(False)
            
            # Validar extensión
            if not self._validar_extension(ruta_archivo, tipo_esperado):
                return self._crear_resultado(False)
            
            # Validar tamaño
            if not self._validar_tamano(ruta_archivo):
                return self._crear_resultado(False)
            
            # Validar MIME type
            if not self._validar_mime_type(ruta_archivo):
                return self._crear_resultado(False)
            
            # Validar contenido según tipo
            if not self._validar_contenido(ruta_archivo, tipo_esperado):
                return self._crear_resultado(False)
            
            return self._crear_resultado(True)
            
        except Exception as e:
            self.errores.append(f"Error durante validación: {str(e)}")
            return self._crear_resultado(False)
    
    def _validar_ruta_segura(self, ruta_archivo: str) -> bool:
        """Validar que la ruta del archivo es segura."""
        try:
            # Resolver ruta absoluta
            ruta_absoluta = os.path.abspath(ruta_archivo)
            
            # Verificar que no hay traversal de directorios peligrosos
            if '..' in ruta_archivo or '~' in ruta_archivo:
                self.errores.append("Ruta de archivo contiene caracteres peligrosos")
                return False
                
            return True
        except Exception as e:
            self.errores.append(f"Error validando ruta: {str(e)}")
            return False
    
    def _validar_nombre_archivo(self, ruta_archivo: str) -> bool:
        """Validar que el nombre del archivo es seguro."""
        nombre_archivo = os.path.basename(ruta_archivo).lower()
        
        # Verificar patrones peligrosos
        for patron in self.PATRONES_PELIGROSOS:
            if patron in nombre_archivo:
                self.errores.append(f"Nombre de archivo contiene patrón peligroso: {patron}")
                return False
        
        # Verificar longitud del nombre
        if len(nombre_archivo) > 255:
            self.errores.append("Nombre de archivo demasiado largo")
            return False
        
        # Verificar que no sea solo espacios o puntos
        if nombre_archivo.strip().replace('.', '') == '':
            self.errores.append("Nombre de archivo inválido")
            return False
            
        return True
    
    def _validar_extension(self, ruta_archivo: str, tipo_esperado: str) -> bool:
        """Validar extensión del archivo."""
        extension = Path(ruta_archivo).suffix.lower()
        
        if tipo_esperado not in self.EXTENSIONES_PERMITIDAS:
            self.errores.append(f"Tipo de archivo no soportado: {tipo_esperado}")
            return False
        
        extensiones_validas = self.EXTENSIONES_PERMITIDAS[tipo_esperado]
        
        if extension not in extensiones_validas:
            self.errores.append(
                f"Extensión '{extension}' no permitida para {tipo_esperado}. "
                f"Extensiones válidas: {', '.join(extensiones_validas)}"
            )
            return False
            
        return True
    
    def _validar_tamano(self, ruta_archivo: str) -> bool:
        """Validar tamaño del archivo."""
        try:
            tamano = os.path.getsize(ruta_archivo)
            
            if tamano > self.TAMANO_MAXIMO:
                self.errores.append(
                    f"Archivo demasiado grande: {tamano} bytes. "
                    f"Máximo permitido: {self.TAMANO_MAXIMO} bytes"
                )
                return False
            
            if tamano == 0:
                self.advertencias.append("El archivo está vacío")
                
            return True
        except Exception as e:
            self.errores.append(f"Error verificando tamaño: {str(e)}")
            return False
    
    def _validar_mime_type(self, ruta_archivo: str) -> bool:
        """Validar MIME type del archivo."""
        try:
            mime_type, _ = mimetypes.guess_type(ruta_archivo)
            
            # Si no se puede determinar, verificar por contenido
            if mime_type is None:
                mime_type = self._detectar_mime_por_contenido(ruta_archivo)
            
            if mime_type and mime_type not in self.MIME_TYPES_PERMITIDOS:
                self.errores.append(f"Tipo MIME no permitido: {mime_type}")
                return False
                
            return True
        except Exception as e:
            self.errores.append(f"Error verificando MIME type: {str(e)}")
            return False
    
    def _detectar_mime_por_contenido(self, ruta_archivo: str) -> str:
        """Detectar MIME type leyendo el contenido del archivo."""
        try:
            with open(ruta_archivo, 'rb') as f:
                primeros_bytes = f.read(1024)
            
            # Verificar si es texto plano UTF-8
            try:
                primeros_bytes.decode('utf-8')
                return 'text/plain'
            except UnicodeDecodeError:
                pass
            
            # Verificar si es JSON válido
            try:
                with open(ruta_archivo, 'r', encoding='utf-8') as f:
                    json.load(f)
                return 'application/json'
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
                
            return 'application/octet-stream'
            
        except Exception:
            return 'application/octet-stream'
    
    def _validar_contenido(self, ruta_archivo: str, tipo_esperado: str) -> bool:
        """Validar contenido del archivo según su tipo."""
        try:
            if tipo_esperado == 'diccionarios':
                return self._validar_json(ruta_archivo)
            elif tipo_esperado == 'wordlists':
                return self._validar_wordlist(ruta_archivo)
            elif tipo_esperado == 'reportes':
                extension = Path(ruta_archivo).suffix.lower()
                if extension == '.json':
                    return self._validar_json(ruta_archivo)
                else:
                    return self._validar_texto_plano(ruta_archivo)
            else:
                return self._validar_texto_plano(ruta_archivo)
                
        except Exception as e:
            self.errores.append(f"Error validando contenido: {str(e)}")
            return False
    
    def _validar_json(self, ruta_archivo: str) -> bool:
        """Validar que el archivo es JSON válido."""
        try:
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                contenido = f.read()
            
            # Verificar que no está vacío
            if not contenido.strip():
                self.errores.append("Archivo JSON está vacío")
                return False
            
            # Validar JSON
            json.loads(contenido)
            return True
            
        except json.JSONDecodeError as e:
            self.errores.append(f"Archivo JSON inválido: {str(e)}")
            return False
        except Exception as e:
            self.errores.append(f"Error leyendo JSON: {str(e)}")
            return False
    
    def _validar_wordlist(self, ruta_archivo: str) -> bool:
        """Validar wordlist (archivo de texto)."""
        return self._validar_texto_plano(ruta_archivo)
    
    def _validar_texto_plano(self, ruta_archivo: str) -> bool:
        """Validar archivo de texto plano."""
        try:
            with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
                # Leer una muestra para verificar
                muestra = f.read(8192)
            
            # Verificar que contiene texto válido
            if len(muestra.strip()) == 0:
                self.advertencias.append("El archivo de texto está vacío")
            
            # Verificar caracteres de control peligrosos
            caracteres_peligrosos = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05']
            for char in caracteres_peligrosos:
                if char in muestra:
                    self.errores.append("Archivo contiene caracteres de control peligrosos")
                    return False
            
            return True
            
        except Exception as e:
            self.errores.append(f"Error validando texto plano: {str(e)}")
            return False
    
    def _crear_resultado(self, valido: bool) -> Dict[str, Union[bool, str, List[str]]]:
        """Crear diccionario de resultado."""
        return {
            'valido': valido,
            'errores': self.errores.copy(),
            'advertencias': self.advertencias.copy(),
            'mensaje': self._generar_mensaje()
        }
    
    def _generar_mensaje(self) -> str:
        """Generar mensaje de resultado."""
        if self.errores:
            return f"Archivo rechazado: {'; '.join(self.errores)}"
        elif self.advertencias:
            return f"Archivo aceptado con advertencias: {'; '.join(self.advertencias)}"
        else:
            return "Archivo validado exitosamente"
    
    @staticmethod
    def obtener_extensiones_permitidas(tipo: str) -> List[str]:
        """Obtener lista de extensiones permitidas para un tipo."""
        sanitizador = SanitizadorArchivos()
        return sanitizador.EXTENSIONES_PERMITIDAS.get(tipo, [])
    
    @staticmethod
    def generar_filtros_dialogo(tipo: str) -> List[Tuple[str, str]]:
        """Generar filtros para diálogos de archivo."""
        extensiones = SanitizadorArchivos.obtener_extensiones_permitidas(tipo)
        
        if not extensiones:
            return [("Todos los archivos", "*.*")]
        
        filtros = []
        
        # Crear filtros específicos
        if tipo == 'wordlists':
            filtros.append(("Archivos de texto", "*.txt"))
            filtros.append(("Listas de palabras", "*.list"))
            filtros.append(("Diccionarios", "*.dic"))
        elif tipo == 'diccionarios':
            filtros.append(("Archivos JSON", "*.json"))
        elif tipo == 'reportes':
            filtros.append(("Archivos JSON", "*.json"))
            filtros.append(("Archivos de texto", "*.txt"))
        
        # Agregar filtro para todas las extensiones permitidas
        patron_extensiones = ' '.join([f"*{ext}" for ext in extensiones])
        filtros.insert(0, (f"Archivos permitidos", patron_extensiones))
        
        return filtros
