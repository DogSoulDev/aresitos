"""
Modelo para gestión de cheatsheets de ciberseguridad.
Ares Aegis - Suite de Ciberseguridad
"""

import os
import json
from typing import List, Dict, Optional


class ModeloGestorCheatsheets:
    """Gestor de cheatsheets para expertos en ciberseguridad."""
    
    def __init__(self):
        self.directorio_cheatsheets = os.path.join("data", "cheatsheets")
        self.archivo_config = os.path.join(self.directorio_cheatsheets, "cheatsheets_config.json")
        self.categorias = {}
        self.inicializar()
    
    def inicializar(self):
        """Inicializar el gestor de cheatsheets."""
        self._crear_directorio_si_no_existe()
        self._cargar_configuracion()
        self._escanear_cheatsheets_disponibles()
    
    def _crear_directorio_si_no_existe(self):
        """Crear directorio de cheatsheets si no existe."""
        if not os.path.exists(self.directorio_cheatsheets):
            os.makedirs(self.directorio_cheatsheets)
    
    def _cargar_configuracion(self):
        """Cargar configuración de cheatsheets."""
        try:
            if os.path.exists(self.archivo_config):
                with open(self.archivo_config, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.categorias = {
                        cat['id']: cat for cat in config['cheatsheets_config']['categorias']
                    }
        except Exception as e:
            print(f"Error cargando configuración de cheatsheets: {e}")
            self._crear_configuracion_por_defecto()
    
    def _crear_configuracion_por_defecto(self):
        """Crear configuración por defecto."""
        config_default = {
            "cheatsheets_config": {
                "version": "1.0",
                "descripcion": "Configuración de cheatsheets para Ares Aegis",
                "categorias": [
                    {
                        "id": "nmap",
                        "nombre": "Nmap - Escaneo de Puertos",
                        "archivo": "nmap_basico.txt",
                        "descripcion": "Comandos básicos y avanzados de Nmap"
                    },
                    {
                        "id": "metasploit",
                        "nombre": "Metasploit Framework",
                        "archivo": "metasploit_framework.txt",
                        "descripcion": "Framework de explotación Metasploit"
                    },
                    {
                        "id": "linux_commands",
                        "nombre": "Comandos Linux Seguridad",
                        "archivo": "comandos_linux.txt",
                        "descripcion": "Comandos Linux orientados a ciberseguridad"
                    },
                    {
                        "id": "reverse_shells",
                        "nombre": "Shells Inversas",
                        "archivo": "shells_inversas.txt",
                        "descripcion": "Reverse shells en múltiples lenguajes"
                    },
                    {
                        "id": "john_ripper",
                        "nombre": "John the Ripper",
                        "archivo": "john_the_ripper.txt",
                        "descripcion": "Cracking de passwords con John"
                    },
                    {
                        "id": "burp_suite",
                        "nombre": "Burp Suite",
                        "archivo": "burp_suite.txt",
                        "descripcion": "Herramienta de testing web"
                    },
                    {
                        "id": "log_analysis",
                        "nombre": "Análisis de Logs",
                        "archivo": "analisis_logs.txt",
                        "descripcion": "Análisis forense de logs del sistema"
                    },
                    {
                        "id": "osint",
                        "nombre": "OSINT Básico",
                        "archivo": "osint_basico.txt",
                        "descripcion": "Inteligencia de fuentes abiertas"
                    }
                ],
                "configuración": {
                    "directorio_cheatsheets": "data/cheatsheets/",
                    "extension_archivos": ".txt",
                    "codificacion": "utf-8",
                    "editable": True,
                    "auto_guardar": True
                }
            }
        }
        
        try:
            with open(self.archivo_config, 'w', encoding='utf-8') as f:
                json.dump(config_default, f, indent=4, ensure_ascii=False)
            self.categorias = {
                cat['id']: cat for cat in config_default['cheatsheets_config']['categorias']
            }
        except Exception as e:
            print(f"Error creando configuración por defecto: {e}")
    
    def _escanear_cheatsheets_disponibles(self):
        """Escanear archivos de cheatsheets disponibles."""
        try:
            archivos = os.listdir(self.directorio_cheatsheets)
            archivos_txt = [f for f in archivos if f.endswith('.txt')]
            print(f"Cheatsheets encontrados: {len(archivos_txt)} archivos")
        except Exception as e:
            print(f"Error escaneando cheatsheets: {e}")
    
    def obtener_categorias(self) -> List[str]:
        """Obtener lista de categorías disponibles."""
        return [cat['nombre'] for cat in self.categorias.values()]
    
    def obtener_cheatsheet(self, nombre_categoria: str) -> Optional[str]:
        """Obtener contenido de un cheatsheet por nombre de categoría."""
        try:
            # Buscar la categoría por nombre
            categoria_info = None
            for cat in self.categorias.values():
                if cat['nombre'] == nombre_categoria:
                    categoria_info = cat
                    break
            
            if not categoria_info:
                return None
            
            archivo_path = os.path.join(self.directorio_cheatsheets, categoria_info['archivo'])
            
            if os.path.exists(archivo_path):
                with open(archivo_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                return f"# CHEATSHEET: {nombre_categoria}\n\nArchivo no encontrado: {archivo_path}\n\nPuedes crear este cheatsheet editando este contenido y guardando."
                
        except Exception as e:
            print(f"Error obteniendo cheatsheet: {e}")
            return f"Error cargando cheatsheet: {str(e)}"
    
    def guardar_cheatsheet(self, nombre_categoria: str, contenido: str) -> bool:
        """Guardar contenido de un cheatsheet."""
        try:
            # Buscar la categoría por nombre
            categoria_info = None
            for cat in self.categorias.values():
                if cat['nombre'] == nombre_categoria:
                    categoria_info = cat
                    break
            
            if not categoria_info:
                # Crear archivo con nombre basado en la categoría
                archivo = f"{nombre_categoria.lower().replace(' ', '_').replace('-', '_')}.txt"
            else:
                archivo = categoria_info['archivo']
            
            archivo_path = os.path.join(self.directorio_cheatsheets, archivo)
            
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(archivo_path), exist_ok=True)
            
            # Guardar contenido
            with open(archivo_path, 'w', encoding='utf-8') as f:
                f.write(contenido)
            
            return True
            
        except Exception as e:
            print(f"Error guardando cheatsheet: {e}")
            return False
    
    def crear_nuevo_cheatsheet(self, nombre_categoria: str, descripcion: str = "") -> bool:
        """Crear un nuevo cheatsheet."""
        try:
            archivo = f"{nombre_categoria.lower().replace(' ', '_').replace('-', '_')}.txt"
            archivo_path = os.path.join(self.directorio_cheatsheets, archivo)
            
            # Contenido inicial
            contenido_inicial = f"""# {nombre_categoria.upper()}

## Descripción
{descripcion if descripcion else 'Cheatsheet personalizado para ' + nombre_categoria}

## Comandos Básicos
# Agrega aquí los comandos básicos

## Comandos Avanzados
# Agrega aquí los comandos avanzados

## Notas
# Agrega aquí notas adicionales
"""
            
            with open(archivo_path, 'w', encoding='utf-8') as f:
                f.write(contenido_inicial)
            
            # Actualizar configuración
            nuevo_id = nombre_categoria.lower().replace(' ', '_').replace('-', '_')
            nueva_categoria = {
                "id": nuevo_id,
                "nombre": nombre_categoria,
                "archivo": archivo,
                "descripcion": descripcion if descripcion else f"Cheatsheet personalizado para {nombre_categoria}"
            }
            
            self.categorias[nuevo_id] = nueva_categoria
            self._actualizar_configuracion()
            
            return True
            
        except Exception as e:
            print(f"Error creando nuevo cheatsheet: {e}")
            return False
    
    def _actualizar_configuracion(self):
        """Actualizar archivo de configuración."""
        try:
            config = {
                "cheatsheets_config": {
                    "version": "1.0",
                    "descripcion": "Configuración de cheatsheets para Ares Aegis",
                    "categorias": list(self.categorias.values()),
                    "configuración": {
                        "directorio_cheatsheets": "data/cheatsheets/",
                        "extension_archivos": ".txt",
                        "codificacion": "utf-8",
                        "editable": True,
                        "auto_guardar": True
                    }
                }
            }
            
            with open(self.archivo_config, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
                
        except Exception as e:
            print(f"Error actualizando configuración: {e}")
    
    def eliminar_cheatsheet(self, nombre_categoria: str) -> bool:
        """Eliminar un cheatsheet."""
        try:
            # Buscar la categoría por nombre
            categoria_info = None
            categoria_id = None
            for cat_id, cat in self.categorias.items():
                if cat['nombre'] == nombre_categoria:
                    categoria_info = cat
                    categoria_id = cat_id
                    break
            
            if not categoria_info:
                return False
            
            archivo_path = os.path.join(self.directorio_cheatsheets, categoria_info['archivo'])
            
            # Eliminar archivo
            if os.path.exists(archivo_path):
                os.remove(archivo_path)
            
            # Eliminar de configuración
            del self.categorias[categoria_id]
            self._actualizar_configuracion()
            
            return True
            
        except Exception as e:
            print(f"Error eliminando cheatsheet: {e}")
            return False
    
    def buscar_en_cheatsheets(self, termino_busqueda: str) -> Dict[str, List[str]]:
        """Buscar término en todos los cheatsheets."""
        resultados = {}
        
        for categoria in self.categorias.values():
            contenido = self.obtener_cheatsheet(categoria['nombre'])
            if contenido:
                lineas_encontradas = []
                for num_linea, linea in enumerate(contenido.split('\n'), 1):
                    if termino_busqueda.lower() in linea.lower():
                        lineas_encontradas.append(f"Línea {num_linea}: {linea.strip()}")
                
                if lineas_encontradas:
                    resultados[categoria['nombre']] = lineas_encontradas
        
        return resultados
