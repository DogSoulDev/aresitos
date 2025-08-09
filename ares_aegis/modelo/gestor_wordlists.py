# -*- coding: utf-8 -*-

import os
import json
import datetime
import shutil
from typing import List, Dict, Optional, Any

class GestorWordlists:
    def __init__(self):
        self.directorio_wordlists = self._crear_directorio_wordlists()
        self.wordlists_predefinidas = self._obtener_wordlists_predefinidas()
        self._inicializar_wordlists_basicas()
    
    def _crear_directorio_wordlists(self) -> str:
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

# RESUMEN: Gestor de wordlists para ciberseguridad que maneja almacenamiento en ~/aresitos_wordlists,
# incluye wordlists predefinidas (passwords, usuarios, directorios, subdominios, extensiones) y
# proporciona CRUD completo: listar, cargar, editar, eliminar, exportar y buscar en wordlists.
