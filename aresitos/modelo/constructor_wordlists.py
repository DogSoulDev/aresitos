# -*- coding: utf-8 -*-
"""
Ares Aegis - Constructor de Wordlists
Modelo para generar y gestionar wordlists personalizadas
"""

import os
import re
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from pathlib import Path


class ConstructorWordlists:
    """Constructor avanzado de wordlists personalizadas para pentesting."""
    
    def __init__(self, directorio_base: Optional[str] = None):
        """Inicializar el constructor de wordlists."""
        self.directorio_base = directorio_base or "data/wordlists"
        self.logger = logging.getLogger(__name__)
        
        # Patrones de validación seguros
        self.patron_seguro = re.compile(r'^[a-zA-Z0-9_\-\.@#$%&*+!?]+$')
        self.longitud_maxima = 100
        self.longitud_minima = 1
        
        # Categorías disponibles
        self.categorias_disponibles = {
            'passwords': 'Contraseñas comunes y variaciones',
            'usuarios': 'Nombres de usuario típicos',
            'subdominios': 'Subdominios para enumeración',
            'directorios': 'Directorios web comunes',
            'archivos': 'Nombres de archivos sensibles',
            'puertos': 'Puertos de servicios',
            'endpoints': 'Endpoints de API',
            'extensiones': 'Extensiones de archivo'
        }
        
        # Plantillas predefinidas
        self.plantillas = self._cargar_plantillas()
        
        self.logger.info("Constructor de wordlists inicializado")
    
    def _validar_entrada_segura(self, entrada: str) -> bool:
        """Validar que la entrada sea segura."""
        if not entrada or len(entrada) < self.longitud_minima or len(entrada) > self.longitud_maxima:
            return False
        
        if not self.patron_seguro.match(entrada):
            return False
            
        # Prevenir caracteres peligrosos
        caracteres_peligrosos = ['..', '/', '\\', '|', ';', '&', '>', '<', '`', '$', '(', ')']
        return not any(char in entrada for char in caracteres_peligrosos)
    
    def _cargar_plantillas(self) -> Dict[str, Dict[str, Any]]:
        """Cargar plantillas predefinidas para generación de wordlists."""
        return {
            'password_variations': {
                'suffixes': ['123', '!', '2023', '2024', '2025', '01', '1'],
                'prefixes': ['admin', 'user', 'test'],
                'transformations': ['upper', 'lower', 'title', 'reverse']
            },
            'subdomain_patterns': {
                'services': ['mail', 'ftp', 'www', 'api', 'admin'],
                'environments': ['dev', 'test', 'staging', 'prod'],
                'numbers': ['1', '2', '01', '02']
            },
            'directory_patterns': {
                'admin': ['admin', 'administrator', 'panel', 'control'],
                'backup': ['backup', 'backups', 'bak', 'old'],
                'config': ['config', 'conf', 'cfg', 'settings']
            }
        }
    
    def obtener_categorias(self) -> List[str]:
        """Obtener lista de categorías disponibles."""
        return list(self.categorias_disponibles.keys())
    
    def generar_wordlist_personalizada(self, base: str, configuracion: Dict[str, Any]) -> List[str]:
        """Generar wordlist personalizada basada en una palabra base."""
        try:
            if not self._validar_entrada_segura(base):
                self.logger.warning(f"Entrada no válida: {base}")
                return []
            
            resultado = set([base])  # Usar set para evitar duplicados
            
            # Aplicar transformaciones básicas
            if configuracion.get('incluir_variaciones_caso', True):
                resultado.update([
                    base.lower(),
                    base.upper(), 
                    base.title(),
                    base.capitalize()
                ])
            
            # Agregar números
            if configuracion.get('incluir_numeros', False):
                numeros = configuracion.get('numeros_personalizados', ['123', '1', '01', '2023', '2024', '2025'])
                for num in numeros:
                    if self._validar_entrada_segura(f"{base}{num}"):
                        resultado.add(f"{base}{num}")
                    if self._validar_entrada_segura(f"{num}{base}"):
                        resultado.add(f"{num}{base}")
            
            # Agregar símbolos
            if configuracion.get('incluir_simbolos', False):
                simbolos = configuracion.get('simbolos_personalizados', ['!', '@', '#', '$', '%'])
                for simbolo in simbolos:
                    if self._validar_entrada_segura(f"{base}{simbolo}"):
                        resultado.add(f"{base}{simbolo}")
                    if self._validar_entrada_segura(f"{simbolo}{base}"):
                        resultado.add(f"{simbolo}{base}")
            
            # Aplicar plantillas específicas
            categoria = configuracion.get('categoria', 'general')
            if categoria in self.plantillas:
                resultado.update(self._aplicar_plantilla(base, categoria))
            
            # Filtrar y validar resultado final
            resultado_final = []
            for palabra in resultado:
                if self._validar_entrada_segura(palabra):
                    resultado_final.append(palabra)
            
            # Aplicar límites de seguridad
            max_entradas = configuracion.get('max_entradas', 1000)
            if len(resultado_final) > max_entradas:
                resultado_final = resultado_final[:max_entradas]
                self.logger.warning(f"Wordlist truncada a {max_entradas} entradas por seguridad")
            
            self.logger.info(f"Wordlist generada: {len(resultado_final)} entradas desde '{base}'")
            return sorted(resultado_final)
            
        except Exception as e:
            self.logger.error(f"Error generando wordlist personalizada: {e}")
            return []
    
    def _aplicar_plantilla(self, base: str, categoria: str) -> Set[str]:
        """Aplicar plantilla específica según categoría."""
        resultado = set()
        
        try:
            if categoria == 'password_variations':
                plantilla = self.plantillas['password_variations']
                
                # Agregar sufijos
                for sufijo in plantilla['suffixes']:
                    nueva_palabra = f"{base}{sufijo}"
                    if self._validar_entrada_segura(nueva_palabra):
                        resultado.add(nueva_palabra)
                
                # Agregar prefijos
                for prefijo in plantilla['prefixes']:
                    nueva_palabra = f"{prefijo}{base}"
                    if self._validar_entrada_segura(nueva_palabra):
                        resultado.add(nueva_palabra)
            
            elif categoria == 'subdomain_patterns':
                plantilla = self.plantillas['subdomain_patterns']
                
                # Combinar con servicios
                for servicio in plantilla['services']:
                    nueva_palabra = f"{servicio}.{base}"
                    if self._validar_entrada_segura(nueva_palabra):
                        resultado.add(nueva_palabra)
                
                # Combinar con entornos
                for entorno in plantilla['environments']:
                    nueva_palabra = f"{entorno}-{base}"
                    if self._validar_entrada_segura(nueva_palabra):
                        resultado.add(nueva_palabra)
            
            elif categoria == 'directory_patterns':
                plantilla = self.plantillas['directory_patterns']
                
                for tipo, variaciones in plantilla.items():
                    for variacion in variaciones:
                        nueva_palabra = f"{base}-{variacion}"
                        if self._validar_entrada_segura(nueva_palabra):
                            resultado.add(nueva_palabra)
                            
        except Exception as e:
            self.logger.error(f"Error aplicando plantilla {categoria}: {e}")
        
        return resultado
    
    def combinar_wordlists(self, wordlists: List[List[str]], configuracion: Optional[Dict[str, Any]] = None) -> List[str]:
        """Combinar múltiples wordlists en una sola."""
        try:
            if not configuracion:
                configuracion = {}
            
            resultado = set()
            
            # Combinar todas las listas
            for wordlist in wordlists:
                for palabra in wordlist:
                    if self._validar_entrada_segura(palabra):
                        resultado.add(palabra)
            
            # Aplicar configuraciones de combinación
            if configuracion.get('generar_combinaciones', False):
                max_combinaciones = configuracion.get('max_combinaciones', 100)
                combinaciones_generadas = 0
                
                palabras_lista = list(resultado)
                for i, palabra1 in enumerate(palabras_lista):
                    if combinaciones_generadas >= max_combinaciones:
                        break
                    for j, palabra2 in enumerate(palabras_lista[i+1:], i+1):
                        if combinaciones_generadas >= max_combinaciones:
                            break
                        
                        # Combinaciones simples
                        comb1 = f"{palabra1}{palabra2}"
                        comb2 = f"{palabra2}{palabra1}"
                        
                        if self._validar_entrada_segura(comb1):
                            resultado.add(comb1)
                            combinaciones_generadas += 1
                        
                        if self._validar_entrada_segura(comb2):
                            resultado.add(comb2)
                            combinaciones_generadas += 1
            
            resultado_final = sorted(list(resultado))
            
            # Aplicar límites
            max_entradas = configuracion.get('max_entradas', 5000)
            if len(resultado_final) > max_entradas:
                resultado_final = resultado_final[:max_entradas]
                self.logger.warning(f"Wordlist combinada truncada a {max_entradas} entradas")
            
            self.logger.info(f"Wordlists combinadas: {len(resultado_final)} entradas únicas")
            return resultado_final
            
        except Exception as e:
            self.logger.error(f"Error combinando wordlists: {e}")
            return []
    
    def optimizar_wordlist(self, wordlist: List[str]) -> List[str]:
        """Optimizar wordlist eliminando duplicados y aplicando filtros."""
        try:
            # Eliminar duplicados y filtrar entradas válidas
            wordlist_unica = []
            vistas = set()
            
            for palabra in wordlist:
                if palabra not in vistas and self._validar_entrada_segura(palabra):
                    wordlist_unica.append(palabra)
                    vistas.add(palabra)
            
            # Ordenar alfabéticamente
            resultado = sorted(wordlist_unica)
            
            self.logger.info(f"Wordlist optimizada: {len(wordlist)} -> {len(resultado)} entradas")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error optimizando wordlist: {e}")
            return wordlist
    
    def validar_wordlist(self, wordlist: List[str]) -> Dict[str, Any]:
        """Validar integridad y seguridad de una wordlist."""
        try:
            total_entradas = len(wordlist)
            entradas_validas = 0
            entradas_duplicadas = 0
            entradas_inseguras = 0
            
            palabras_vistas = set()
            
            for palabra in wordlist:
                if palabra in palabras_vistas:
                    entradas_duplicadas += 1
                else:
                    palabras_vistas.add(palabra)
                
                if self._validar_entrada_segura(palabra):
                    entradas_validas += 1
                else:
                    entradas_inseguras += 1
            
            porcentaje_validez = (entradas_validas / total_entradas * 100) if total_entradas > 0 else 0
            
            resultado = {
                'total_entradas': total_entradas,
                'entradas_validas': entradas_validas,
                'entradas_duplicadas': entradas_duplicadas,
                'entradas_inseguras': entradas_inseguras,
                'porcentaje_validez': round(porcentaje_validez, 2),
                'es_valida': porcentaje_validez >= 90 and entradas_inseguras == 0
            }
            
            self.logger.info(f"Validación completada: {resultado['porcentaje_validez']}% válida")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error validando wordlist: {e}")
            return {
                'total_entradas': 0,
                'entradas_validas': 0,
                'entradas_duplicadas': 0,
                'entradas_inseguras': 0,
                'porcentaje_validez': 0,
                'es_valida': False,
                'error': str(e)
            }
    
    def exportar_wordlist(self, wordlist: List[str], nombre_archivo: str) -> Dict[str, Any]:
        """Exportar wordlist a archivo con validación de seguridad."""
        try:
            # Validar nombre de archivo
            if not re.match(r'^[a-zA-Z0-9_\-]+$', nombre_archivo):
                return {'exito': False, 'error': 'Nombre de archivo no válido'}
            
            if not nombre_archivo.endswith('.txt'):
                nombre_archivo += '.txt'
            
            # Construir ruta segura
            ruta_archivo = os.path.join(self.directorio_base, nombre_archivo)
            ruta_normalizada = os.path.normpath(ruta_archivo)
            
            # Verificar que la ruta esté dentro del directorio base
            if not ruta_normalizada.startswith(os.path.normpath(self.directorio_base)):
                return {'exito': False, 'error': 'Ruta de archivo no permitida'}
            
            # Optimizar wordlist antes de exportar
            wordlist_optimizada = self.optimizar_wordlist(wordlist)
            
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(ruta_normalizada), exist_ok=True)
            
            # Escribir archivo
            with open(ruta_normalizada, 'w', encoding='utf-8') as f:
                for palabra in wordlist_optimizada:
                    f.write(f"{palabra}\n")
            
            resultado = {
                'exito': True,
                'archivo': nombre_archivo,
                'ruta': ruta_normalizada,
                'entradas': len(wordlist_optimizada),
                'fecha_creacion': datetime.now().isoformat()
            }
            
            self.logger.info(f"Wordlist exportada: {nombre_archivo} ({len(wordlist_optimizada)} entradas)")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error exportando wordlist: {e}")
            return {'exito': False, 'error': str(e)}


# RESUMEN: Constructor avanzado de wordlists para Ares Aegis.
# Genera wordlists personalizadas, combina listas existentes y optimiza contenido.
# Incluye validación de seguridad y exportación segura de archivos.
