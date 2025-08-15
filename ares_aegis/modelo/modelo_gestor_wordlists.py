# -*- coding: utf-8 -*-

import os
import json
import datetime
import shutil
from typing import List, Dict, Optional, Any

class ModeloGestorWordlists:
    def __init__(self):
        self.directorio_wordlists = self._crear_directorio_wordlists()
        self.wordlists_predefinidas = self._obtener_wordlists_predefinidas()
        
        # Inicializar constructor de wordlists
        try:
            from ares_aegis.modelo.constructor_wordlists import ConstructorWordlists
            self.constructor_wordlists = ConstructorWordlists(self.directorio_wordlists)
        except ImportError as e:
            print(f"Warning: Constructor de wordlists no disponible: {e}")
            self.constructor_wordlists = None
        
        self._inicializar_wordlists_basicas()
        self._cargar_wordlists_desde_data()
    
    def _cargar_wordlists_desde_data(self):
        """Carga automáticamente todas las wordlists desde el directorio data/wordlists"""
        directorio_data = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "wordlists")
        
        if not os.path.exists(directorio_data):
            print(f"Directorio data/wordlists no encontrado: {directorio_data}")
            return
        
        print(f"Escaneando wordlists en: {directorio_data}")
        
        # 1. Cargar archivos JSON de configuración automáticamente
        archivos_json = [f for f in os.listdir(directorio_data) if f.endswith('.json')]
        for archivo_json in archivos_json:
            self._cargar_configuracion_json(os.path.join(directorio_data, archivo_json))
        
        # 2. Mapeo de archivos TXT a categorías (para compatibilidad)
        archivos_wordlists = {
            "passwords_comunes.txt": "passwords",
            "passwords_top1000.txt": "passwords_avanzadas", 
            "usernames_common.txt": "usuarios",
            "usuarios_comunes.txt": "usuarios_es",
            "api_endpoints.txt": "endpoints_api",
            "common_ports.txt": "puertos_comunes",
            "directorios_web.txt": "directorios_web",
            "web_directories.txt": "directorios_web_en",
            "extensiones_archivos.txt": "extensiones",
            "subdomains_common.txt": "subdominios",
            "subdominios.txt": "subdominios_es"
        }
        
        # 3. Cargar archivos TXT conocidos
        wordlists_cargadas = 0
        
        for archivo, categoria in archivos_wordlists.items():
            ruta_archivo = os.path.join(directorio_data, archivo)
            
            if os.path.exists(ruta_archivo):
                try:
                    with open(ruta_archivo, 'r', encoding='utf-8') as f:
                        contenido = [linea.strip() for linea in f.readlines() if linea.strip() and not linea.startswith('#')]
                    
                    if contenido:
                        self.wordlists_predefinidas[categoria] = contenido
                        print(f"   {archivo}: {len(contenido)} entradas cargadas en '{categoria}'")
                        wordlists_cargadas += 1
                    
                except Exception as e:
                    print(f"   Error cargando {archivo}: {e}")
            else:
                print(f"   Archivo no encontrado: {archivo}")
        
        # Cargar configuración JSON si existe
        config_path = os.path.join(directorio_data, "wordlists_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                for categoria, datos in config.items():
                    if isinstance(datos, list):
                        self.wordlists_predefinidas[categoria] = datos
                        print(f"   Configuración JSON: '{categoria}' con {len(datos)} entradas")
                        
            except Exception as e:
                print(f"   Error cargando configuración JSON: {e}")
        
        print(f" Total wordlists cargadas: {wordlists_cargadas}")
        print(f" Categorías disponibles: {len(self.wordlists_predefinidas)}")
        
        # Crear archivo de índice actualizado
        self._crear_indice_wordlists()
    
    def _crear_directorio_wordlists(self) -> str:
        # Primero intentar usar el directorio data/wordlists del proyecto
        directorio_proyecto = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "wordlists")
        if os.path.exists(directorio_proyecto):
            return directorio_proyecto
        
        # Si no existe, crear en home del usuario
        directorio = os.path.join(os.path.expanduser("~"), "aresitos_wordlists")
        try:
            os.makedirs(directorio, exist_ok=True)
            return directorio
        except Exception:
            import tempfile
            directorio = os.path.join(tempfile.gettempdir(), "aresitos_wordlists")
            os.makedirs(directorio, exist_ok=True)
            return directorio
    
    def _obtener_wordlists_predefinidas(self) -> Dict[str, List[str]]:
        return {
            "passwords_comunes": [
                "123456", "password", "123456789", "12345678", "12345",
                "1234567", "admin", "123123", "qwerty", "abc123",
                "Password", "password123", "admin123", "root", "toor",
                "pass", "test", "guest", "user", "demo", "letmein",
                "welcome", "monkey", "dragon", "master", "shadow"
            ],
            "usuarios_comunes": [
                "admin", "administrator", "root", "user", "guest",
                "test", "demo", "oracle", "postgres", "mysql",
                "sa", "operator", "manager", "support", "service",
                "backup", "www", "web", "ftp", "mail", "email",
                "api", "dev", "developer", "staging", "prod"
            ],
            "directorios_web": [
                "admin", "administrator", "wp-admin", "wp-content",
                "uploads", "images", "css", "js", "javascript",
                "includes", "inc", "config", "conf", "backup",
                "backups", "temp", "tmp", "cache", "logs",
                "log", "phpmyadmin", "mysql", "database", "db",
                "api", "rest", "v1", "v2", "test", "dev"
            ],
            "subdominios": [
                "www", "mail", "ftp", "webmail", "email", "admin",
                "ns1", "ns2", "mx", "pop", "smtp", "imap",
                "blog", "forum", "shop", "store", "api", "dev",
                "test", "staging", "beta", "demo", "support",
                "help", "docs", "cdn", "static", "assets"
            ],
            "extensiones_archivos": [
                ".txt", ".log", ".conf", ".config", ".cfg", ".ini",
                ".xml", ".json", ".yml", ".yaml", ".sql", ".db",
                ".bak", ".backup", ".old", ".orig", ".save",
                ".tmp", ".temp", ".swp", ".~", ".zip", ".tar",
                ".gz", ".rar", ".7z", ".pdf", ".doc", ".xls"
            ]
        }
    
    def _inicializar_wordlists_basicas(self):
        for nombre, contenido in self.wordlists_predefinidas.items():
            ruta_archivo = os.path.join(self.directorio_wordlists, f"{nombre}.txt")
            if not os.path.exists(ruta_archivo):
                try:
                    with open(ruta_archivo, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(contenido))
                except Exception:
                    pass
    
    def listar_wordlists(self) -> List[Dict[str, Any]]:
        wordlists = []
        
        if not os.path.exists(self.directorio_wordlists):
            return wordlists
        
        try:
            for archivo in os.listdir(self.directorio_wordlists):
                if archivo.endswith('.txt'):
                    ruta_completa = os.path.join(self.directorio_wordlists, archivo)
                    stat_info = os.stat(ruta_completa)
                    
                    try:
                        with open(ruta_completa, 'r', encoding='utf-8') as f:
                            lineas = sum(1 for _ in f)
                    except:
                        lineas = 0
                    
                    wordlists.append({
                        'nombre': archivo[:-4],
                        'archivo': archivo,
                        'ruta': ruta_completa,
                        'tamaño': stat_info.st_size,
                        'lineas': lineas,
                        'modificado': datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
        except Exception:
            pass
        
        return sorted(wordlists, key=lambda x: x['nombre'])
    
    def cargar_wordlist(self, ruta_origen: str, nombre_destino: Optional[str] = None) -> Dict[str, Any]:
        try:
            if not os.path.exists(ruta_origen):
                return {'exito': False, 'error': 'Archivo no encontrado'}
            
            if not nombre_destino:
                nombre_destino = os.path.splitext(os.path.basename(ruta_origen))[0]
            
            if not nombre_destino.endswith('.txt'):
                nombre_destino += '.txt'
            
            ruta_destino = os.path.join(self.directorio_wordlists, nombre_destino)
            
            shutil.copy2(ruta_origen, ruta_destino)
            
            return {
                'exito': True,
                'archivo': nombre_destino,
                'ruta': ruta_destino
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def obtener_contenido_wordlist(self, nombre: str) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.txt'):
                nombre += '.txt'
            
            ruta_archivo = os.path.join(self.directorio_wordlists, nombre)
            
            if not os.path.exists(ruta_archivo):
                return {'exito': False, 'error': 'Wordlist no encontrada'}
            
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                contenido = f.read()
            
            lineas = contenido.split('\n')
            return {
                'exito': True,
                'contenido': contenido,
                'lineas': len(lineas),
                'nombre': nombre
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def guardar_wordlist(self, nombre: str, contenido: str) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.txt'):
                nombre += '.txt'
            
            ruta_archivo = os.path.join(self.directorio_wordlists, nombre)
            
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                f.write(contenido)
            
            return {
                'exito': True,
                'archivo': nombre,
                'ruta': ruta_archivo
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def eliminar_wordlist(self, nombre: str) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.txt'):
                nombre += '.txt'
            
            ruta_archivo = os.path.join(self.directorio_wordlists, nombre)
            
            if not os.path.exists(ruta_archivo):
                return {'exito': False, 'error': 'Wordlist no encontrada'}
            
            os.remove(ruta_archivo)
            
            return {'exito': True, 'mensaje': f'Wordlist {nombre} eliminada'}
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def exportar_wordlist(self, nombre: str, ruta_destino: str) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.txt'):
                nombre += '.txt'
            
            ruta_origen = os.path.join(self.directorio_wordlists, nombre)
            
            if not os.path.exists(ruta_origen):
                return {'exito': False, 'error': 'Wordlist no encontrada'}
            
            shutil.copy2(ruta_origen, ruta_destino)
            
            return {
                'exito': True,
                'archivo_exportado': ruta_destino
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def buscar_en_wordlist(self, nombre: str, termino: str) -> Dict[str, Any]:
        try:
            resultado = self.obtener_contenido_wordlist(nombre)
            if not resultado['exito']:
                return resultado
            
            lineas = resultado['contenido'].split('\n')
            coincidencias = [linea for linea in lineas if termino.lower() in linea.lower()]
            
            return {
                'exito': True,
                'coincidencias': coincidencias,
                'total': len(coincidencias)
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def _crear_indice_wordlists(self):
        """Crea un archivo de índice con todas las wordlists disponibles"""
        try:
            indice_path = os.path.join(self.directorio_wordlists, "INDICE_WORDLISTS_CARGADAS.md")
            
            with open(indice_path, 'w', encoding='utf-8') as f:
                f.write("# Índice de Wordlists Cargadas - Aresitos\n\n")
                f.write(f"**Generado el:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Total de categorías:** {len(self.wordlists_predefinidas)}\n\n")
                
                for categoria, wordlist in self.wordlists_predefinidas.items():
                    f.write(f"## {categoria.replace('_', ' ').title()}\n")
                    f.write(f"- **Entradas:** {len(wordlist)}\n")
                    if len(wordlist) > 0:
                        f.write(f"- **Ejemplos:** {', '.join(wordlist[:5])}\n")
                    f.write("\n")
                
                f.write("---\n")
                f.write("*Índice generado automáticamente por Aresitos*\n")
            
            print(f" Índice creado: {indice_path}")
            
        except Exception as e:
            print(f" Error creando índice: {e}")

    def _cargar_configuracion_json(self, ruta_json: str):
        """Carga wordlists desde un archivo JSON de configuración"""
        try:
            with open(ruta_json, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            archivo_nombre = os.path.basename(ruta_json)
            print(f" Procesando: {archivo_nombre}")
            
            # Si el JSON tiene estructura de wordlists
            if isinstance(config, dict):
                # Caso 1: JSON con categorías múltiples
                if any(isinstance(v, list) for v in config.values()):
                    for categoria, lista in config.items():
                        if isinstance(lista, list) and lista:
                            nombre_categoria = f"json_{categoria}"
                            self.wordlists_predefinidas[nombre_categoria] = lista
                            print(f"    Categoría '{categoria}': {len(lista)} elementos")
                
                # Caso 2: JSON con lista simple en una clave específica
                elif 'wordlist' in config and isinstance(config['wordlist'], list):
                    nombre_categoria = f"json_{os.path.splitext(archivo_nombre)[0]}"
                    self.wordlists_predefinidas[nombre_categoria] = config['wordlist']
                    print(f"    Wordlist '{nombre_categoria}': {len(config['wordlist'])} elementos")
                
                # Caso 3: JSON de configuración con múltiples listas
                else:
                    for key, value in config.items():
                        if isinstance(value, list) and value:
                            nombre_categoria = f"json_{key}"
                            self.wordlists_predefinidas[nombre_categoria] = value
                            print(f"    Lista '{key}': {len(value)} elementos")
            
            # Si el JSON es una lista directa
            elif isinstance(config, list) and config:
                nombre_categoria = f"json_{os.path.splitext(archivo_nombre)[0]}"
                self.wordlists_predefinidas[nombre_categoria] = config
                print(f"    Lista directa: {len(config)} elementos")
                
        except Exception as e:
            print(f" Error cargando {ruta_json}: {e}")

# RESUMEN: Gestor de wordlists para ciberseguridad que maneja almacenamiento en ~/aresitos_wordlists,
# incluye wordlists predefinidas (passwords, usuarios, directorios, subdominios, extensiones) y
# proporciona CRUD completo: listar, cargar, editar, eliminar, exportar y buscar en wordlists.
# Ahora con carga automática desde data/wordlists del proyecto.
