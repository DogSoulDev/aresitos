# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Wordlists
Gestión de wordlists para pentesting y análisis de seguridad
"""

import os
import json
import threading
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from ares_aegis.controlador.controlador_base import ControladorBase


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
        
        self.logger.info("Controlador de Wordlists inicializado")
        self._inicializar_impl()  # Llamada al método requerido por la clase base
    
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
                if hasattr(self.modelo, 'constructor_wordlists'):
                    self.wordlists_cargadas = self.modelo.constructor_wordlists.obtener_todas_las_wordlists()
                    self._actualizar_estadisticas()
                    self.logger.info(f"Cargadas {len(self.wordlists_cargadas)} wordlists")
                    return self.wordlists_cargadas
                else:
                    self.logger.warning("Constructor de wordlists no disponible en el modelo")
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
            if hasattr(self.modelo, 'constructor_wordlists'):
                wordlist = self.modelo.constructor_wordlists.obtener_wordlist(categoria)
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
            if hasattr(self.modelo, 'constructor_wordlists'):
                return self.modelo.constructor_wordlists.obtener_categorias()
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
    
    def generar_wordlist_personalizada(self, base: str, configuracion: Dict[str, Any]) -> List[str]:
        """Generar wordlist personalizada basada en configuración."""
        try:
            if hasattr(self.modelo, 'constructor_wordlists'):
                return self.modelo.constructor_wordlists.generar_wordlist_personalizada(base, configuracion)
            
            # Generación básica si no hay constructor avanzado
            resultado = [base]
            
            if configuracion.get('incluir_numeros', False):
                for i in range(10):
                    resultado.extend([f"{base}{i}", f"{i}{base}"])
            
            if configuracion.get('incluir_simbolos', False):
                simbolos = ['!', '@', '#', '$', '%']
                for simbolo in simbolos:
                    resultado.extend([f"{base}{simbolo}", f"{simbolo}{base}"])
            
            if configuracion.get('variaciones_caso', False):
                resultado.extend([base.upper(), base.lower(), base.title()])
            
            return list(set(resultado))
            
        except Exception as e:
            self.logger.error(f"Error generando wordlist personalizada: {e}")
            return []
    
    def exportar_wordlist(self, categoria: str, ruta_destino: str) -> bool:
        """Exportar wordlist a archivo."""
        try:
            wordlist = self.obtener_wordlist(categoria)
            if not wordlist:
                return False
            
            with open(ruta_destino, 'w', encoding='utf-8') as archivo:
                for entrada in wordlist:
                    archivo.write(f"{entrada}\n")
            
            self.logger.info(f"Wordlist {categoria} exportada a {ruta_destino}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exportando wordlist {categoria}: {e}")
            return False
    
    def importar_wordlist(self, ruta_archivo: str, categoria: str) -> bool:
        """Importar wordlist desde archivo."""
        try:
            if not os.path.exists(ruta_archivo):
                return False
            
            with open(ruta_archivo, 'r', encoding='utf-8') as archivo:
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
                import re
                patron = re.compile(filtros['regex'], re.IGNORECASE)
                resultado = [entrada for entrada in resultado if patron.search(entrada)]
            
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
