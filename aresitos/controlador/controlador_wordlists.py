# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Wordlists
Gestión de wordlists para pentesting y análisis de seguridad
"""

import os
import json
import threading
import re
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from aresitos.controlador.controlador_base import ControladorBase


class ControladorWordlists(ControladorBase):
    """Controlador para gestión de wordlists y listas de palabras."""
    
    def __init__(self, modelo):
        super().__init__(modelo, "ControladorWordlists")
        self.modelo = modelo
        self.wordlists_cargadas = {}
        self.estadisticas = {
            'wordlists_totales': 0,
            'entradas_totales': 0,
            'categorias': [],
            'ultima_actualizacion': None
        }
        self.ruta_wordlists = Path("data/wordlists")
        self._lock = threading.Lock()
        
        # Configuraciones de seguridad
        self.extensiones_permitidas = {'.txt', '.wordlist', '.dict'}
        self.patron_nombre_seguro = re.compile(r'^[a-zA-Z0-9_-]+$')
        self.tamano_max_archivo = 50 * 1024 * 1024  # 50MB
        
        self.logger.info("Controlador de Wordlists inicializado")
        self._inicializar_impl()  # Llamada al método requerido por la clase base
        
    def _validar_path_seguro(self, ruta):
        """Valida que el path sea seguro y esté dentro de directorios permitidos"""
        try:
            path_obj = Path(ruta).resolve()
            base_permitida = self.ruta_wordlists.resolve()
            
            # Verificar que esté dentro del directorio base
            if not str(path_obj).startswith(str(base_permitida)):
                return False
                
            # Verificar extensión
            if path_obj.suffix not in self.extensiones_permitidas:
                return False
                
            return True
        except:
            return False
            
    def _validar_regex_segura(self, patron):
        """Valida que el regex no sea malicioso (prevención ReDoS)"""
        # Límite estricto de longitud
        if len(patron) > 50:
            return False
            
        # Patterns críticos que causan ReDoS
        patrones_peligrosos = [
            r'\(\?\=.*\)\*',     # Lookahead con repetición
            r'\(\?\!.*\)\+',     # Lookahead negativo con repetición  
            r'\(\.\*\)\{',       # .* con cuantificadores
            r'\(\[\^\]\*\)',     # Negación con repetición
            r'\*\+',             # Repetición anidada
            r'\+\*',             # Repetición anidada
            r'\{\d+,\}',         # Cuantificadores abiertos
            r'\(\?\:.*\)\*\+',   # Grupos no captura con repetición
        ]
        
        for peligroso in patrones_peligrosos:
            if re.search(peligroso, patron):
                logging.warning(f"Regex peligrosa bloqueada: {patron}")
                return False
                
        # Límite de grupos de captura
        if patron.count('(') > 3:
            return False
            
        try:
            # Compilar con timeout implícito para verificar sintaxis
            compiled = re.compile(patron)
            # Test rápido con string corta
            compiled.search("test")
            return True
        except (re.error, Exception):
            return False
    
    def _inicializar_impl(self) -> None:
        """Implementación específica de inicialización."""
        try:
            # Cargar wordlists automáticamente al inicializar
            self.cargar_wordlists()
            self.logger.info("Inicialización de wordlists completada")
        except Exception as e:
            self.logger.error(f"Error en inicialización de wordlists: {e}")
    
    def cargar_wordlists(self) -> Dict[str, Any]:
        """Cargar todas las wordlists disponibles."""
        try:
            with self._lock:
                # Verificar constructor de wordlists del modelo
                if hasattr(self.modelo, 'gestor_wordlists') and hasattr(self.modelo.gestor_wordlists, 'constructor_wordlists'):
                    constructor = self.modelo.gestor_wordlists.constructor_wordlists
                    if constructor:
                        # El constructor está disponible pero no tiene método obtener_todas_las_wordlists
                        # Usar las wordlists cargadas del gestor
                        if hasattr(self.modelo.gestor_wordlists, 'wordlists_predefinidas'):
                            self.wordlists_cargadas = self.modelo.gestor_wordlists.wordlists_predefinidas
                            self._actualizar_estadisticas()
                            self.logger.info(f"Cargadas {len(self.wordlists_cargadas)} wordlists desde gestor")
                            return self.wordlists_cargadas
                        else:
                            self.logger.warning("Gestor de wordlists sin datos predefinidos")
                            return {}
                    else:
                        self.logger.info("Constructor de wordlists disponible pero no inicializado")
                        return {}
                else:
                    self.logger.info("Constructor de wordlists no disponible - usando modo básico")
                    return {}
                    
        except Exception as e:
            self.logger.error(f"Error cargando wordlists: {e}")
            return {}
    
    def obtener_wordlist(self, categoria: str) -> List[str]:
        """Obtener wordlist específica por categoría."""
        try:
            if categoria in self.wordlists_cargadas:
                return self.wordlists_cargadas[categoria]
            
            # Intentar cargar desde el modelo
            if hasattr(self.modelo, 'gestor_wordlists') and hasattr(self.modelo.gestor_wordlists, 'constructor_wordlists'):
                constructor = self.modelo.gestor_wordlists.constructor_wordlists
                if constructor and hasattr(constructor, 'obtener_wordlist'):
                    wordlist = constructor.obtener_wordlist(categoria)
                    if wordlist:
                        with self._lock:
                            self.wordlists_cargadas[categoria] = wordlist
                        return wordlist
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error obteniendo wordlist {categoria}: {e}")
            return []
    
    def obtener_categorias_disponibles(self) -> List[str]:
        """Obtener lista de categorías de wordlists disponibles."""
        try:
            if hasattr(self.modelo, 'gestor_wordlists') and hasattr(self.modelo.gestor_wordlists, 'constructor_wordlists'):
                constructor = self.modelo.gestor_wordlists.constructor_wordlists
                if constructor and hasattr(constructor, 'obtener_categorias'):
                    return constructor.obtener_categorias()
            return list(self.wordlists_cargadas.keys())
            
        except Exception as e:
            self.logger.error(f"Error obteniendo categorías: {e}")
            return []
    
    def buscar_en_wordlist(self, categoria: str, patron: str) -> List[str]:
        """Buscar patrón en una wordlist específica."""
        try:
            wordlist = self.obtener_wordlist(categoria)
            if not wordlist:
                return []
            
            patron_lower = patron.lower()
            resultados = [
                entrada for entrada in wordlist 
                if patron_lower in entrada.lower()
            ]
            
            self.logger.info(f"Encontradas {len(resultados)} coincidencias para '{patron}' en {categoria}")
            return resultados
            
        except Exception as e:
            self.logger.error(f"Error buscando en wordlist {categoria}: {e}")
            return []
    
    def combinar_wordlists(self, categorias: List[str]) -> List[str]:
        """Combinar múltiples wordlists en una sola."""
        try:
            resultado = []
            for categoria in categorias:
                wordlist = self.obtener_wordlist(categoria)
                resultado.extend(wordlist)
            
            # Eliminar duplicados manteniendo orden
            resultado_unico = list(dict.fromkeys(resultado))
            
            self.logger.info(f"Combinadas {len(categorias)} wordlists en {len(resultado_unico)} entradas únicas")
            return resultado_unico
            
        except Exception as e:
            self.logger.error(f"Error combinando wordlists: {e}")
            return []
    
    def generar_wordlist_personalizada(self, base: str, configuración: Dict[str, Any]) -> List[str]:
        """Generar wordlist personalizada basada en configuración."""
        try:
            if hasattr(self.modelo, 'gestor_wordlists') and hasattr(self.modelo.gestor_wordlists, 'constructor_wordlists'):
                constructor = self.modelo.gestor_wordlists.constructor_wordlists
                if constructor and hasattr(constructor, 'generar_wordlist_personalizada'):
                    return constructor.generar_wordlist_personalizada(base, configuración)
            
            # Generación básica si no hay constructor avanzado
            resultado = [base]
            
            if configuración.get('incluir_numeros', False):
                for i in range(10):
                    resultado.extend([f"{base}{i}", f"{i}{base}"])
            
            if configuración.get('incluir_simbolos', False):
                simbolos = ['!', '@', '#', '$', '%']
                for simbolo in simbolos:
                    resultado.extend([f"{base}{simbolo}", f"{simbolo}{base}"])
            
            if configuración.get('variaciones_caso', False):
                resultado.extend([base.upper(), base.lower(), base.title()])
            
            return list(set(resultado))
            
        except Exception as e:
            self.logger.error(f"Error generando wordlist personalizada: {e}")
            return []
    
    def exportar_wordlist(self, categoria: str, ruta_destino: str) -> bool:
        """Exportar wordlist a archivo con validación de seguridad robusta."""
        try:
            # Validar nombre de categoría
            if not self.patron_nombre_seguro.match(categoria):
                logging.warning(f"Categoría insegura bloqueada: {categoria}")
                return False
            
            # Sanitizar nombre de archivo usando solo el basename
            nombre_archivo = os.path.basename(ruta_destino)
            if not self.patron_nombre_seguro.match(os.path.splitext(nombre_archivo)[0]):
                logging.warning(f"Nombre de archivo inseguro: {nombre_archivo}")
                return False
                
            wordlist = self.obtener_wordlist(categoria)
            if not wordlist:
                return False
            
            # Construir ruta segura usando solo el nombre de archivo
            ruta_segura = self.ruta_wordlists / f"{categoria}.txt"
            
            with open(ruta_segura, 'w', encoding='utf-8') as archivo:
                for entrada in wordlist:
                    archivo.write(f"{entrada}\n")
            
            self.logger.info(f"Wordlist {categoria} exportada a {ruta_segura}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exportando wordlist {categoria}: {e}")
            return False
    
    def importar_wordlist(self, ruta_archivo: str, categoria: str) -> bool:
        """Importar wordlist desde archivo con validación de seguridad robusta."""
        try:
            # Validar nombre de categoría
            if not self.patron_nombre_seguro.match(categoria):
                logging.warning(f"Nombre de categoría inseguro: {categoria}")
                return False
            
            # Sanitizar nombre de archivo usando solo el basename
            nombre_archivo = os.path.basename(ruta_archivo)
            nombre_base = os.path.splitext(nombre_archivo)[0]
            if not self.patron_nombre_seguro.match(nombre_base):
                logging.warning(f"Nombre de archivo inseguro: {nombre_archivo}")
                return False
            
            # Construir path seguro dentro del directorio de wordlists
            path_seguro = self.ruta_wordlists / nombre_archivo
            
            if not path_seguro.exists():
                logging.warning(f"Archivo no encontrado: {path_seguro}")
                return False
                
            # Verificar tamaño de archivo
            if path_seguro.stat().st_size > self.tamano_max_archivo:
                logging.warning(f"Archivo demasiado grande: {path_seguro}")
                return False
            
            with open(path_seguro, 'r', encoding='utf-8') as archivo:
                entradas = [linea.strip() for linea in archivo if linea.strip()]
            
            with self._lock:
                self.wordlists_cargadas[categoria] = entradas
                self._actualizar_estadisticas()
            
            self.logger.info(f"Importada wordlist {categoria} con {len(entradas)} entradas")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importando wordlist desde {ruta_archivo}: {e}")
            return False
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas de wordlists."""
        with self._lock:
            return self.estadisticas.copy()
    
    def _actualizar_estadisticas(self) -> None:
        """Actualizar estadísticas internas."""
        try:
            self.estadisticas['wordlists_totales'] = len(self.wordlists_cargadas)
            self.estadisticas['entradas_totales'] = sum(
                len(wordlist) for wordlist in self.wordlists_cargadas.values()
            )
            self.estadisticas['categorias'] = list(self.wordlists_cargadas.keys())
            self.estadisticas['ultima_actualizacion'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error actualizando estadísticas: {e}")
    
    def optimizar_wordlist(self, categoria: str) -> bool:
        """Optimizar wordlist eliminando duplicados y ordenando."""
        try:
            wordlist = self.obtener_wordlist(categoria)
            if not wordlist:
                return False
            
            # Eliminar duplicados y ordenar
            wordlist_optimizada = sorted(list(set(wordlist)))
            
            with self._lock:
                self.wordlists_cargadas[categoria] = wordlist_optimizada
                self._actualizar_estadisticas()
            
            self.logger.info(f"Wordlist {categoria} optimizada: {len(wordlist)} -> {len(wordlist_optimizada)} entradas")
            return True
            
        except Exception as e:
            self.logger.error(f"Error optimizando wordlist {categoria}: {e}")
            return False
    
    def filtrar_wordlist(self, categoria: str, filtros: Dict[str, Any]) -> List[str]:
        """Filtrar wordlist según criterios específicos."""
        try:
            wordlist = self.obtener_wordlist(categoria)
            if not wordlist:
                return []
            
            resultado = wordlist.copy()
            
            # Filtro por longitud mínima
            if 'longitud_min' in filtros:
                resultado = [entrada for entrada in resultado if len(entrada) >= filtros['longitud_min']]
            
            # Filtro por longitud máxima
            if 'longitud_max' in filtros:
                resultado = [entrada for entrada in resultado if len(entrada) <= filtros['longitud_max']]
            
            # Filtro por contiene
            if 'contiene' in filtros:
                resultado = [entrada for entrada in resultado if filtros['contiene'].lower() in entrada.lower()]
            
            # Filtro por no contiene
            if 'no_contiene' in filtros:
                resultado = [entrada for entrada in resultado if filtros['no_contiene'].lower() not in entrada.lower()]
            
            # Filtro por expresión regular
            if 'regex' in filtros:
                patron_regex = filtros['regex']
                if not self._validar_regex_segura(patron_regex):
                    logging.warning(f"Regex insegura bloqueada: {patron_regex}")
                    return []
                    
                try:
                    patron = re.compile(patron_regex, re.IGNORECASE)
                    resultado = [entrada for entrada in resultado if patron.search(entrada)]
                except re.error:
                    logging.error(f"Error en regex: {patron_regex}")
                    return []
            
            self.logger.info(f"Wordlist {categoria} filtrada: {len(wordlist)} -> {len(resultado)} entradas")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error filtrando wordlist {categoria}: {e}")
            return []
    
    def obtener_informacion_completa(self) -> Dict[str, Any]:
        """Obtener información completa de wordlists cargadas."""
        try:
            with self._lock:
                info = {
                    'total_wordlists': len(self.wordlists_cargadas),
                    'total_categorias': len(self.wordlists_cargadas),
                    'total_entradas': sum(len(wordlist) for wordlist in self.wordlists_cargadas.values()),
                    'categorias': {},
                    'archivos_cargados': [],
                    'estadisticas': self.estadisticas.copy()
                }
                
                # Información detallada por categoría
                for categoria, wordlist in self.wordlists_cargadas.items():
                    info['categorias'][categoria] = {
                        'count': len(wordlist),
                        'muestra': wordlist[:5] if wordlist else [],
                        'tipo': 'wordlist'
                    }
                
                # Intentar obtener archivos cargados del modelo
                if hasattr(self.modelo, 'gestor_wordlists'):
                    gestor = self.modelo.gestor_wordlists
                    if hasattr(gestor, 'archivos_cargados'):
                        info['archivos_cargados'] = list(gestor.archivos_cargados)
                    elif hasattr(gestor, 'obtener_archivos_cargados'):
                        info['archivos_cargados'] = gestor.obtener_archivos_cargados()
                
                return info
                
        except Exception as e:
            self.logger.error(f"Error obteniendo información completa: {e}")
            return {
                'total_wordlists': 0,
                'total_categorias': 0,
                'total_entradas': 0,
                'categorias': {},
                'archivos_cargados': [],
                'error': str(e)
            }


# RESUMEN: Controlador para gestión completa de wordlists de pentesting.
# Incluye carga, búsqueda, combinación, generación personalizada y optimización.
