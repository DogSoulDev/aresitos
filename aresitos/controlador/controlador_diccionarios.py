# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Diccionarios
Gestión de diccionarios y datos de referencia para análisis de seguridad
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


class ControladorDiccionarios(ControladorBase):
    """Controlador para gestión de diccionarios de datos de seguridad."""
    
    def __init__(self, modelo):
        super().__init__(modelo, "ControladorDiccionarios")
        self.modelo = modelo
        self.diccionarios_cargados = {}
        self.estadisticas = {
            'diccionarios_totales': 0,
            'entradas_totales': 0,
            'categorias': [],
            'ultima_actualizacion': None
        }
        self.ruta_diccionarios = Path("data")
        self._lock = threading.Lock()
        
        # Validaciones de seguridad
        self.patron_nombre_seguro = re.compile(r'^[a-zA-Z0-9_-]+$')
        self.extensiones_permitidas = {'.json', '.dict'}
        self.tamano_max_archivo = 10 * 1024 * 1024  # 10MB
        
        self.logger.info("Controlador de Diccionarios inicializado")
        self._inicializar_impl()  # Llamada al método requerido por la clase base
        
    def _validar_path_seguro(self, ruta):
        """Valida que el path sea seguro"""
        try:
            # Solo permitir nombres base, no paths completos
            nombre_archivo = os.path.basename(ruta)
            nombre_base = os.path.splitext(nombre_archivo)[0]
            extension = os.path.splitext(nombre_archivo)[1]
            
            # Validar nombre y extensión
            if not self.patron_nombre_seguro.match(nombre_base):
                return False
            if extension not in self.extensiones_permitidas:
                return False
                
            return True
        except (IOError, OSError, PermissionError, FileNotFoundError):
            return False
            
    def _validar_categoria_segura(self, categoria):
        """Valida nombres de categoría"""
        if not categoria or not self.patron_nombre_seguro.match(categoria):
            return False
        return True
    
    def _inicializar_impl(self) -> None:
        """Implementación específica de inicialización."""
        try:
            # Cargar diccionarios automáticamente al inicializar
            self.cargar_diccionarios()
            self.logger.info("Inicialización de diccionarios completada")
        except Exception as e:
            self.logger.error(f"Error en inicialización de diccionarios: {e}")
    
    def cargar_diccionarios(self) -> Dict[str, Any]:
        """Cargar todos los diccionarios disponibles."""
        try:
            with self._lock:
                # Verificar gestor de diccionarios del modelo
                if hasattr(self.modelo, 'gestor_diccionarios'):
                    self.diccionarios_cargados = self.modelo.gestor_diccionarios.obtener_todos_los_diccionarios()
                    self._actualizar_estadisticas()
                    self.logger.info(f"Cargados {len(self.diccionarios_cargados)} diccionarios")
                    return self.diccionarios_cargados
                else:
                    self.logger.warning("Gestor de diccionarios no disponible en el modelo")
                    return {}
                    
        except Exception as e:
            self.logger.error(f"Error cargando diccionarios: {e}")
            return {}
    
    def obtener_diccionario(self, categoria: str) -> Dict[str, Any]:
        """Obtener diccionario específico por categoría."""
        try:
            if categoria in self.diccionarios_cargados:
                return self.diccionarios_cargados[categoria]
            
            # Intentar cargar desde el modelo
            if hasattr(self.modelo, 'gestor_diccionarios'):
                diccionario = self.modelo.gestor_diccionarios.obtener_diccionario(categoria)
                if diccionario:
                    with self._lock:
                        self.diccionarios_cargados[categoria] = diccionario
                    return diccionario
            
            return {}
            
        except Exception as e:
            self.logger.error(f"Error obteniendo diccionario {categoria}: {e}")
            return {}
    
    def buscar_en_diccionario(self, categoria: str, clave: str) -> Any:
        """Buscar valor en diccionario por clave."""
        try:
            diccionario = self.obtener_diccionario(categoria)
            if not diccionario:
                return None
            
            # Búsqueda exacta
            if clave in diccionario:
                return diccionario[clave]
            
            # Búsqueda por similitud (case insensitive)
            clave_lower = clave.lower()
            for k, v in diccionario.items():
                if k.lower() == clave_lower:
                    return v
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error buscando en diccionario {categoria}: {e}")
            return None
    
    def buscar_patron_en_diccionario(self, categoria: str, patron: str) -> Dict[str, Any]:
        """Buscar patrón en claves y valores del diccionario."""
        try:
            diccionario = self.obtener_diccionario(categoria)
            if not diccionario:
                return {}
            
            patron_lower = patron.lower()
            resultados = {}
            
            for clave, valor in diccionario.items():
                # Buscar en clave
                if patron_lower in clave.lower():
                    resultados[clave] = valor
                # Buscar en valor si es string
                elif isinstance(valor, str) and patron_lower in valor.lower():
                    resultados[clave] = valor
                # Buscar en valores de lista
                elif isinstance(valor, list):
                    for item in valor:
                        if isinstance(item, str) and patron_lower in item.lower():
                            resultados[clave] = valor
                            break
            
            self.logger.info(f"Encontrados {len(resultados)} resultados para '{patron}' en {categoria}")
            return resultados
            
        except Exception as e:
            self.logger.error(f"Error buscando patrón en diccionario {categoria}: {e}")
            return {}
    
    def obtener_categorias_disponibles(self) -> List[str]:
        """Obtener lista de categorías de diccionarios disponibles."""
        try:
            if hasattr(self.modelo, 'gestor_diccionarios'):
                return self.modelo.gestor_diccionarios.obtener_categorias()
            return list(self.diccionarios_cargados.keys())
            
        except Exception as e:
            self.logger.error(f"Error obteniendo categorías: {e}")
            return []
    
    def obtener_informacion_vulnerabilidad(self, cve_id: str) -> Dict[str, Any]:
        """Obtener información detallada de una vulnerabilidad."""
        try:
            # Buscar en diccionario de CVE
            vulnerabilidades = self.obtener_diccionario('cve_database')
            if vulnerabilidades and cve_id in vulnerabilidades:
                return vulnerabilidades[cve_id]
            
            # Búsqueda alternativa
            resultado = self.buscar_en_diccionario('vulnerabilidades_conocidas', cve_id)
            if resultado:
                return resultado
            
            return {}
            
        except Exception as e:
            self.logger.error(f"Error obteniendo información de vulnerabilidad {cve_id}: {e}")
            return {}
    
    def obtener_informacion_puerto(self, puerto: int) -> Dict[str, Any]:
        """Obtener información sobre un puerto específico."""
        try:
            puertos = self.obtener_diccionario('puertos_comunes')
            puerto_str = str(puerto)
            
            if puertos and puerto_str in puertos:
                return puertos[puerto_str]
            
            return {
                'puerto': puerto,
                'servicio': 'desconocido',
                'descripcion': f'Puerto {puerto} - información no disponible',
                'riesgo': 'bajo'
            }
            
        except Exception as e:
            self.logger.error(f"Error obteniendo información del puerto {puerto}: {e}")
            return {}
    
    def obtener_firmas_malware(self) -> List[str]:
        """Obtener lista de firmas de malware conocido."""
        try:
            firmas = self.obtener_diccionario('firmas_malware')
            if firmas:
                return list(firmas.keys())
            
            # Alternativo desde archivos
            firmas_archivo = self.buscar_en_diccionario('archivos_firmas', 'malware')
            if firmas_archivo:
                return firmas_archivo
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error obteniendo firmas de malware: {e}")
            return []
    
    def verificar_ip_maliciosa(self, ip: str) -> Dict[str, Any]:
        """Verificar si una IP está en listas de IPs maliciosas."""
        try:
            ips_maliciosas = self.obtener_diccionario('ips_maliciosas')
            if ips_maliciosas and ip in ips_maliciosas:
                return {
                    'es_maliciosa': True,
                    'información': ips_maliciosas[ip],
                    'fuente': 'base_datos_local'
                }
            
            # Verificar en rangos de red
            rangos_maliciosos = self.obtener_diccionario('rangos_maliciosos')
            if rangos_maliciosos:
                for rango, info in rangos_maliciosos.items():
                    if self._ip_en_rango(ip, rango):
                        return {
                            'es_maliciosa': True,
                            'información': info,
                            'fuente': 'rango_de_red'
                        }
            
            return {
                'es_maliciosa': False,
                'información': 'IP no encontrada en listas de amenazas',
                'fuente': 'verificacion_local'
            }
            
        except Exception as e:
            self.logger.error(f"Error verificando IP maliciosa {ip}: {e}")
            return {'es_maliciosa': False, 'error': str(e)}
    
    def obtener_configuraciones_seguridad(self, tipo_sistema: str) -> Dict[str, Any]:
        """Obtener configuraciones de seguridad recomendadas."""
        try:
            configuraciones = self.obtener_diccionario('configuraciones_seguridad')
            if configuraciones and tipo_sistema in configuraciones:
                return configuraciones[tipo_sistema]
            
            # Configuraciones genéricas
            return {
                'configuraciones_basicas': [
                    'Actualizar sistema operativo',
                    'Configurar firewall',
                    'Deshabilitar servicios innecesarios',
                    'Configurar logging de seguridad'
                ],
                'herramientas_recomendadas': [
                    'antivirus',
                    'monitor_integridad',
                    'analizador_logs'
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Error obteniendo configuraciones para {tipo_sistema}: {e}")
            return {}
    
    def exportar_diccionario(self, categoria: str, ruta_destino: str) -> bool:
        """Exportar diccionario a archivo JSON con validación de seguridad."""
        try:
            # Validar categoría
            if not self._validar_categoria_segura(categoria):
                logging.warning(f"Categoría insegura bloqueada: {categoria}")
                return False
                
            # Validar path de destino
            if not self._validar_path_seguro(ruta_destino):
                logging.warning(f"Path de exportación inseguro: {ruta_destino}")
                return False
                
            diccionario = self.obtener_diccionario(categoria)
            if not diccionario:
                return False
            
            # Construir path seguro en directorio de datos
            nombre_archivo = f"{categoria}.json"
            ruta_segura = self.ruta_diccionarios / nombre_archivo
            
            with open(ruta_segura, 'w', encoding='utf-8') as archivo:
                json.dump(diccionario, archivo, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Diccionario {categoria} exportado correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exportando diccionario {categoria}: {e}")
            return False
    
    def importar_diccionario(self, ruta_archivo: str, categoria: str) -> bool:
        """Importar diccionario desde archivo JSON con validación de seguridad."""
        try:
            # Validar categoría
            if not self._validar_categoria_segura(categoria):
                logging.warning(f"Categoría insegura bloqueada: {categoria}")
                return False
                
            # Validar path de archivo
            if not self._validar_path_seguro(ruta_archivo):
                logging.warning(f"Path de importación inseguro: {ruta_archivo}")
                return False
                
            # Construir path seguro en directorio de datos
            nombre_archivo = os.path.basename(ruta_archivo)
            ruta_segura = self.ruta_diccionarios / nombre_archivo
            
            if not ruta_segura.exists():
                logging.warning(f"Archivo no encontrado: {nombre_archivo}")
                return False
                
            # Verificar tamaño de archivo
            if ruta_segura.stat().st_size > self.tamano_max_archivo:
                logging.warning(f"Archivo demasiado grande: {nombre_archivo}")
                return False
            
            with open(ruta_segura, 'r', encoding='utf-8') as archivo:
                diccionario = json.load(archivo)
            
            # Validar que sea un diccionario válido
            if not isinstance(diccionario, dict):
                logging.warning(f"Archivo no contiene diccionario válido: {nombre_archivo}")
                return False
            
            with self._lock:
                self.diccionarios_cargados[categoria] = diccionario
                self._actualizar_estadisticas()
            
            self.logger.info(f"Importado diccionario {categoria} con {len(diccionario)} entradas")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importando diccionario desde {ruta_archivo}: {e}")
            return False
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas de diccionarios."""
        with self._lock:
            return self.estadisticas.copy()
    
    def _actualizar_estadisticas(self) -> None:
        """Actualizar estadísticas internas."""
        try:
            self.estadisticas['diccionarios_totales'] = len(self.diccionarios_cargados)
            self.estadisticas['entradas_totales'] = sum(
                len(diccionario) if isinstance(diccionario, dict) else 1
                for diccionario in self.diccionarios_cargados.values()
            )
            self.estadisticas['categorias'] = list(self.diccionarios_cargados.keys())
            self.estadisticas['ultima_actualizacion'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error actualizando estadísticas: {e}")
    
    def _ip_en_rango(self, ip: str, rango: str) -> bool:
        """Verificar si una IP está en un rango CIDR específico usando funciones nativas."""
        try:
            # Implementación simple para rangos CIDR básicos
            if '/' not in rango:
                return ip == rango
            
            # Separar IP y máscara
            red_ip, prefijo = rango.split('/')
            prefijo = int(prefijo)
            
            # Convertir IPs a enteros para comparación
            ip_num = self._ip_a_numero(ip)
            red_num = self._ip_a_numero(red_ip)
            
            # Crear máscara
            mascara = (0xFFFFFFFF << (32 - prefijo)) & 0xFFFFFFFF
            
            # Comparar redes
            return (ip_num & mascara) == (red_num & mascara)
            
        except Exception as e:
            self.logger.debug(f"Error verificando IP en rango: {e}")
            return False
    
    def _ip_a_numero(self, ip: str) -> int:
        """Convertir IP string a número entero."""
        try:
            partes = ip.split('.')
            if len(partes) != 4:
                return 0
            
            numero = 0
            for i, parte in enumerate(partes):
                numero += int(parte) << (8 * (3 - i))
            
            return numero
        except (ValueError, TypeError, AttributeError):
            return 0
        except (ValueError, TypeError, AttributeError):
            return False
    
    def actualizar_diccionario_cve(self) -> bool:
        """Actualizar diccionario de CVE con nuevas vulnerabilidades."""
        try:
            # En un entorno real, esto descargaría datos actualizados
            self.logger.info("Actualizando diccionario CVE...")
            
            # Por ahora, verificar si el diccionario existe
            cve_dict = self.obtener_diccionario('cve_database')
            if cve_dict:
                self.logger.info(f"Diccionario CVE contiene {len(cve_dict)} entradas")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error actualizando diccionario CVE: {e}")
            return False
    
    def buscar_vulnerabilidades_por_software(self, software: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Buscar vulnerabilidades conocidas para software específico."""
        try:
            vulnerabilidades = []
            
            # Buscar en diccionario de CVE
            cve_dict = self.obtener_diccionario('cve_database')
            if cve_dict:
                for cve_id, info in cve_dict.items():
                    if isinstance(info, dict) and 'software' in info:
                        if software.lower() in info['software'].lower():
                            if not version or version in str(info.get('version_afectada', '')):
                                vulnerabilidades.append({
                                    'cve_id': cve_id,
                                    'descripcion': info.get('descripcion', ''),
                                    'severidad': info.get('severidad', 'unknown'),
                                    'fecha': info.get('fecha', ''),
                                    'software': info.get('software', ''),
                                    'version_afectada': info.get('version_afectada', '')
                                })
            
            self.logger.info(f"Encontradas {len(vulnerabilidades)} vulnerabilidades para {software}")
            return vulnerabilidades
            
        except Exception as e:
            self.logger.error(f"Error buscando vulnerabilidades para {software}: {e}")
            return []
    
    def obtener_informacion_completa(self) -> Dict[str, Any]:
        """Obtener información completa de diccionarios cargados."""
        try:
            with self._lock:
                info = {
                    'total_diccionarios': len(self.diccionarios_cargados),
                    'total_entradas': 0,
                    'diccionarios': {},
                    'archivos_cargados': [],
                    'estadisticas': self.estadisticas.copy()
                }
                
                # Información detallada por diccionario
                for nombre, diccionario in self.diccionarios_cargados.items():
                    if isinstance(diccionario, dict):
                        entradas = len(diccionario)
                        info['total_entradas'] += entradas
                        
                        # Obtener una muestra de claves
                        claves_muestra = list(diccionario.keys())[:5]
                        
                        info['diccionarios'][nombre] = {
                            'entradas': entradas,
                            'claves_muestra': claves_muestra,
                            'tipo': 'diccionario',
                            'descripcion': f'Diccionario de {nombre.replace("_", " ").title()}'
                        }
                    else:
                        info['diccionarios'][nombre] = {
                            'entradas': 1,
                            'claves_muestra': [],
                            'tipo': 'datos',
                            'descripcion': f'Datos de {nombre}'
                        }
                
                # Intentar obtener archivos cargados del modelo
                if hasattr(self.modelo, 'gestor_diccionarios'):
                    gestor = self.modelo.gestor_diccionarios
                    if hasattr(gestor, 'archivos_cargados'):
                        info['archivos_cargados'] = list(gestor.archivos_cargados)
                    elif hasattr(gestor, 'obtener_archivos_cargados'):
                        info['archivos_cargados'] = gestor.obtener_archivos_cargados()
                
                return info
                
        except Exception as e:
            self.logger.error(f"Error obteniendo información completa: {e}")
            return {
                'total_diccionarios': 0,
                'total_entradas': 0,
                'diccionarios': {},
                'archivos_cargados': [],
                'error': str(e)
            }


# RESUMEN: Controlador para gestión completa de diccionarios de datos de seguridad.
# Incluye CVE, puertos, IPs maliciosas, configuraciones y búsquedas avanzadas.
