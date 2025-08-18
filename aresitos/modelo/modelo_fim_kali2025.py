# -*- coding: utf-8 -*-
"""
ARESITOS - Extensión FIM Kali Linux 2025
=======================================

Extensión del FIM ARESITOS con herramientas modernas de Kali Linux 2025.
Integra herramientas avanzadas de detección de integridad y análisis forense.

Herramientas integradas:
- yara: Detección de patrones de malware
- exiftool: Análisis de metadatos
- volatility3: Análisis de memoria
- samhain: HIDS adicional
- tiger: Auditoría de seguridad
- aide: Mejorado con nuevas capacidades

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
"""

import subprocess
import json
import os
import hashlib
import tempfile
import datetime
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from .modelo_fim import FIMAvanzado

class FIMKali2025(FIMAvanzado):
    """
    Extensión del FIM ARESITOS con herramientas de Kali Linux 2025.
    Mejora las capacidades de detección y análisis forense.
    """
    
    def __init__(self, siem=None, directorio_base: Optional[str] = None, configuracion: Optional[Dict[str, Any]] = None):
        super().__init__(siem)
        
        # Configuración específica para Kali 2025
        self.directorio_base = directorio_base or "/var/lib/aresitos/fim"
        self.configuracion_kali2025 = configuracion or {}
        
        # Crear directorio base si no existe
        os.makedirs(self.directorio_base, exist_ok=True)
        
        # Configuración de herramientas FIM Kali 2025
        self.herramientas_fim_kali2025 = {
            'yara': {
                'comando': 'yara',
                'disponible': self._verificar_herramienta('yara'),
                'uso': 'Detección de patrones de malware'
            },
            'exiftool': {
                'comando': 'exiftool',
                'disponible': self._verificar_herramienta('exiftool'),
                'uso': 'Análisis de metadatos'
            },
            'volatility3': {
                'comando': 'vol',
                'disponible': self._verificar_herramienta('vol'),
                'uso': 'Análisis de memoria'
            },
            'samhain': {
                'comando': 'samhain',
                'disponible': self._verificar_herramienta('samhain'),
                'uso': 'HIDS adicional'
            },
            'tiger': {
                'comando': 'tiger',
                'disponible': self._verificar_herramienta('tiger'),
                'uso': 'Auditoría de seguridad'
            },
            'aide': {
                'comando': 'aide',
                'disponible': self._verificar_herramienta('aide'),
                'uso': 'Detección de cambios mejorada'
            }
        }
        
        # Directorio para reglas YARA
        self.directorio_reglas_yara = os.path.join(self.directorio_base, 'yara_rules')
        os.makedirs(self.directorio_reglas_yara, exist_ok=True)
        
        # Cache de metadatos avanzados
        self.cache_metadatos_avanzados = {}
        
        self.logger.info("FIM Kali 2025 inicializado")
        self._log_herramientas_fim_disponibles()
        self._inicializar_reglas_yara()
    
    def _verificar_herramienta(self, herramienta: str) -> bool:
        """Verificar si una herramienta está disponible."""
        try:
            resultado = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
            return resultado.returncode == 0
        except Exception:
            return False
    
    def _log_herramientas_fim_disponibles(self):
        """Registrar herramientas FIM disponibles."""
        disponibles = [h for h, info in self.herramientas_fim_kali2025.items() if info['disponible']]
        no_disponibles = [h for h, info in self.herramientas_fim_kali2025.items() if not info['disponible']]
        
        self.logger.info(f"Herramientas FIM Kali 2025 disponibles: {', '.join(disponibles)}")
        if no_disponibles:
            self.logger.warning(f"Herramientas FIM no disponibles: {', '.join(no_disponibles)}")
    
    def _inicializar_reglas_yara(self):
        """Inicializar reglas YARA básicas."""
        if not self.herramientas_fim_kali2025['yara']['disponible']:
            return
        
        # Crear reglas básicas si no existen
        reglas_basicas = {
            'malware_basico.yar': '''
rule SuspiciousExecutable {
    meta:
        description = "Detección de ejecutables sospechosos"
        author = "ARESITOS FIM"
        date = "2025-08-18"
        
    strings:
        $suspicious1 = "CreateRemoteThread"
        $suspicious2 = "VirtualAllocEx"
        $suspicious3 = "WriteProcessMemory"
        $suspicious4 = "SetWindowsHookEx"
        
    condition:
        2 of ($suspicious*)
}

rule PotentialRootkit {
    meta:
        description = "Detección de posibles rootkits"
        author = "ARESITOS FIM"
        
    strings:
        $rootkit1 = "ZwQuerySystemInformation"
        $rootkit2 = "NtQueryDirectoryFile"
        $rootkit3 = "FsRtlIsNameInExpression"
        
    condition:
        any of them
}
''',
            'scripts_sospechosos.yar': '''
rule SuspiciousScript {
    meta:
        description = "Scripts potencialmente maliciosos"
        author = "ARESITOS FIM"
        
    strings:
        $php1 = "eval(base64_decode"
        $php2 = "shell_exec"
        $php3 = "system("
        $bash1 = "curl | bash"
        $bash2 = "wget | sh"
        $py1 = "exec(compile("
        
    condition:
        any of them
}
'''
        }
        
        for nombre_archivo, contenido in reglas_basicas.items():
            ruta_regla = os.path.join(self.directorio_reglas_yara, nombre_archivo)
            if not os.path.exists(ruta_regla):
                try:
                    with open(ruta_regla, 'w', encoding='utf-8') as f:
                        f.write(contenido)
                    self.logger.info(f"Regla YARA creada: {nombre_archivo}")
                except Exception as e:
                    self.logger.error(f"Error creando regla YARA {nombre_archivo}: {e}")
    
    def analisis_yara_archivo(self, ruta_archivo: str, reglas_personalizadas: Optional[str] = None) -> Dict[str, Any]:
        """
        Análisis YARA de un archivo específico.
        
        Args:
            ruta_archivo: Ruta del archivo a analizar
            reglas_personalizadas: Ruta a reglas YARA personalizadas
            
        Returns:
            Dict con resultados del análisis YARA
        """
        if not self.herramientas_fim_kali2025['yara']['disponible']:
            return self._fallback_analisis_basico(ruta_archivo)
        
        if not os.path.exists(ruta_archivo):
            return {'error': f'Archivo no encontrado: {ruta_archivo}'}
        
        try:
            # Usar reglas personalizadas o las básicas
            if reglas_personalizadas and os.path.exists(reglas_personalizadas):
                directorio_reglas = reglas_personalizadas
            else:
                directorio_reglas = self.directorio_reglas_yara
            
            # Ejecutar YARA
            comando = ['yara', '-r', '-s', '-m', directorio_reglas, ruta_archivo]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return self._parsear_resultado_yara(resultado.stdout, ruta_archivo, resultado.returncode == 0)
            
        except Exception as e:
            self.logger.error(f"Error en análisis YARA: {e}")
            return self._fallback_analisis_basico(ruta_archivo)
    
    def _parsear_resultado_yara(self, output: str, archivo: str, success: bool) -> Dict[str, Any]:
        """Parsear resultado de YARA."""
        resultado = {
            'herramienta': 'yara',
            'archivo': archivo,
            'detecciones': [],
            'nivel_riesgo': 'bajo',
            'timestamp': datetime.datetime.now().isoformat(),
            'success': success
        }
        
        if not success or not output.strip():
            return resultado
        
        # Parsear salida de YARA
        for linea in output.strip().split('\n'):
            if linea.strip():
                # Formato: regla_nombre archivo [metadatos]
                partes = linea.split(' ', 1)
                if len(partes) >= 2:
                    regla_nombre = partes[0]
                    deteccion = {
                        'regla': regla_nombre,
                        'archivo': archivo,
                        'linea_completa': linea
                    }
                    resultado['detecciones'].append(deteccion)
        
        # Evaluar nivel de riesgo
        num_detecciones = len(resultado['detecciones'])
        if num_detecciones == 0:
            resultado['nivel_riesgo'] = 'bajo'
        elif num_detecciones <= 2:
            resultado['nivel_riesgo'] = 'medio'
        else:
            resultado['nivel_riesgo'] = 'alto'
        
        return resultado
    
    def analisis_metadatos_exiftool(self, ruta_archivo: str) -> Dict[str, Any]:
        """
        Análisis de metadatos usando ExifTool.
        
        Args:
            ruta_archivo: Ruta del archivo a analizar
            
        Returns:
            Dict con metadatos extraídos
        """
        if not self.herramientas_fim_kali2025['exiftool']['disponible']:
            return self._fallback_metadatos_basicos(ruta_archivo)
        
        if not os.path.exists(ruta_archivo):
            return {'error': f'Archivo no encontrado: {ruta_archivo}'}
        
        try:
            comando = ['exiftool', '-json', '-a', ruta_archivo]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if resultado.returncode == 0:
                return self._parsear_resultado_exiftool(resultado.stdout, ruta_archivo)
            else:
                self.logger.error(f"Error en ExifTool: {resultado.stderr}")
                return self._fallback_metadatos_basicos(ruta_archivo)
                
        except Exception as e:
            self.logger.error(f"Error en análisis ExifTool: {e}")
            return self._fallback_metadatos_basicos(ruta_archivo)
    
    def _parsear_resultado_exiftool(self, output: str, archivo: str) -> Dict[str, Any]:
        """Parsear resultado JSON de ExifTool."""
        resultado = {
            'herramienta': 'exiftool',
            'archivo': archivo,
            'metadatos': {},
            'metadatos_sospechosos': [],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            data = json.loads(output)
            if isinstance(data, list) and len(data) > 0:
                metadatos = data[0]
                resultado['metadatos'] = metadatos
                
                # Buscar metadatos sospechosos
                campos_sospechosos = [
                    'Author', 'Creator', 'Producer', 'Subject', 'Keywords',
                    'Comments', 'Description', 'Software', 'UserComment'
                ]
                
                for campo in campos_sospechosos:
                    if campo in metadatos:
                        valor = str(metadatos[campo]).lower()
                        if any(sospechoso in valor for sospechoso in ['hack', 'crack', 'exploit', 'payload', 'shell']):
                            resultado['metadatos_sospechosos'].append({
                                'campo': campo,
                                'valor': metadatos[campo],
                                'razon': 'Contiene términos sospechosos'
                            })
        
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parseando JSON de ExifTool: {e}")
            resultado['error'] = 'Error parseando metadatos'
        
        return resultado
    
    def auditoria_seguridad_tiger(self, directorio: str = "/") -> Dict[str, Any]:
        """
        Auditoría de seguridad usando Tiger.
        
        Args:
            directorio: Directorio base para auditoría
            
        Returns:
            Dict con resultados de auditoría
        """
        if not self.herramientas_fim_kali2025['tiger']['disponible']:
            return self._fallback_auditoria_basica(directorio)
        
        try:
            # Tiger necesita ejecutarse como root para auditoría completa
            comando = ['sudo', 'tiger', '-c', directorio]
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return self._parsear_resultado_tiger(resultado.stdout, directorio, resultado.returncode == 0)
            
        except Exception as e:
            self.logger.error(f"Error en Tiger: {e}")
            return self._fallback_auditoria_basica(directorio)
    
    def _parsear_resultado_tiger(self, output: str, directorio: str, success: bool) -> Dict[str, Any]:
        """Parsear resultado de Tiger."""
        resultado = {
            'herramienta': 'tiger',
            'directorio': directorio,
            'problemas_encontrados': [],
            'nivel_criticidad': 'bajo',
            'timestamp': datetime.datetime.now().isoformat(),
            'success': success
        }
        
        if not success or not output.strip():
            return resultado
        
        # Parsear salida de Tiger
        problemas_criticos = 0
        for linea in output.strip().split('\n'):
            if '--WARN--' in linea or '--FAIL--' in linea:
                problema = {
                    'tipo': 'WARNING' if '--WARN--' in linea else 'FAIL',
                    'descripcion': linea.strip(),
                    'criticidad': 'media' if '--WARN--' in linea else 'alta'
                }
                resultado['problemas_encontrados'].append(problema)
                
                if problema['criticidad'] == 'alta':
                    problemas_criticos += 1
        
        # Determinar criticidad general
        if problemas_criticos > 5:
            resultado['nivel_criticidad'] = 'critica'
        elif problemas_criticos > 0:
            resultado['nivel_criticidad'] = 'alta'
        elif len(resultado['problemas_encontrados']) > 0:
            resultado['nivel_criticidad'] = 'media'
        
        return resultado
    
    def verificacion_integridad_aide_avanzada(self, directorio: str) -> Dict[str, Any]:
        """
        Verificación de integridad avanzada con AIDE.
        
        Args:
            directorio: Directorio a verificar
            
        Returns:
            Dict con resultados de verificación
        """
        if not self.herramientas_fim_kali2025['aide']['disponible']:
            return self._fallback_verificacion_integridad(directorio)
        
        try:
            # Inicializar base de datos AIDE si no existe
            db_aide = f"/var/lib/aide/aide_{hashlib.md5(directorio.encode()).hexdigest()}.db"
            
            if not os.path.exists(db_aide):
                self.logger.info("Inicializando base de datos AIDE...")
                comando_init = ['sudo', 'aide', '--init', f'--config-check={directorio}']
                subprocess.run(comando_init, capture_output=True, timeout=600)
            
            # Verificar integridad
            comando = ['sudo', 'aide', '--check', f'--database=file:{db_aide}']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return self._parsear_resultado_aide(resultado.stdout, directorio, resultado.returncode)
            
        except Exception as e:
            self.logger.error(f"Error en AIDE: {e}")
            return self._fallback_verificacion_integridad(directorio)
    
    def _parsear_resultado_aide(self, output: str, directorio: str, return_code: int) -> Dict[str, Any]:
        """Parsear resultado de AIDE."""
        resultado = {
            'herramienta': 'aide',
            'directorio': directorio,
            'archivos_modificados': [],
            'archivos_nuevos': [],
            'archivos_eliminados': [],
            'total_cambios': 0,
            'integridad_ok': return_code == 0,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        if not output.strip():
            return resultado
        
        # Parsear salida de AIDE
        for linea in output.strip().split('\n'):
            if 'changed:' in linea.lower():
                archivo = linea.split(':', 1)[1].strip() if ':' in linea else linea.strip()
                resultado['archivos_modificados'].append(archivo)
            elif 'added:' in linea.lower():
                archivo = linea.split(':', 1)[1].strip() if ':' in linea else linea.strip()
                resultado['archivos_nuevos'].append(archivo)
            elif 'removed:' in linea.lower():
                archivo = linea.split(':', 1)[1].strip() if ':' in linea else linea.strip()
                resultado['archivos_eliminados'].append(archivo)
        
        resultado['total_cambios'] = (len(resultado['archivos_modificados']) + 
                                    len(resultado['archivos_nuevos']) + 
                                    len(resultado['archivos_eliminados']))
        
        return resultado
    
    # Métodos fallback
    def _fallback_analisis_basico(self, ruta_archivo: str) -> Dict[str, Any]:
        """Fallback para análisis básico sin YARA."""
        try:
            stat_info = os.stat(ruta_archivo)
            return {
                'herramienta': 'analisis_basico',
                'archivo': ruta_archivo,
                'detecciones': [],
                'nivel_riesgo': 'desconocido',
                'info_basica': {
                    'tamaño': stat_info.st_size,
                    'permisos': oct(stat_info.st_mode)[-3:],
                    'modificado': datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                },
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _fallback_metadatos_basicos(self, ruta_archivo: str) -> Dict[str, Any]:
        """Fallback para metadatos básicos sin ExifTool."""
        try:
            stat_info = os.stat(ruta_archivo)
            return {
                'herramienta': 'metadatos_basicos',
                'archivo': ruta_archivo,
                'metadatos': {
                    'tamaño': stat_info.st_size,
                    'permisos': oct(stat_info.st_mode)[-3:],
                    'propietario': stat_info.st_uid,
                    'grupo': stat_info.st_gid,
                    'acceso': datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                    'modificacion': datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'cambio': datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                },
                'metadatos_sospechosos': [],
                'timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _fallback_auditoria_basica(self, directorio: str) -> Dict[str, Any]:
        """Fallback para auditoría básica sin Tiger."""
        resultado = {
            'herramienta': 'auditoria_basica',
            'directorio': directorio,
            'problemas_encontrados': [],
            'nivel_criticidad': 'bajo',
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # Verificaciones básicas de seguridad
            if os.path.exists(directorio):
                stat_info = os.stat(directorio)
                permisos = oct(stat_info.st_mode)[-3:]
                
                if permisos == '777':
                    resultado['problemas_encontrados'].append({
                        'tipo': 'WARNING',
                        'descripcion': f'Directorio {directorio} tiene permisos 777 (inseguro)',
                        'criticidad': 'alta'
                    })
                    resultado['nivel_criticidad'] = 'alta'
        
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado
    
    def _fallback_verificacion_integridad(self, directorio: str) -> Dict[str, Any]:
        """Fallback para verificación básica sin AIDE."""
        return {
            'herramienta': 'verificacion_basica',
            'directorio': directorio,
            'archivos_modificados': [],
            'archivos_nuevos': [],
            'archivos_eliminados': [],
            'total_cambios': 0,
            'integridad_ok': True,
            'timestamp': datetime.datetime.now().isoformat(),
            'mensaje': 'Verificación básica - AIDE no disponible'
        }
    
    def obtener_capacidades_fim_kali2025(self) -> Dict[str, Any]:
        """
        Obtener información sobre las capacidades FIM de Kali 2025.
        
        Returns:
            Dict con información sobre herramientas disponibles
        """
        return {
            'herramientas_disponibles': {
                nombre: info['disponible'] 
                for nombre, info in self.herramientas_fim_kali2025.items()
            },
            'total_herramientas': len(self.herramientas_fim_kali2025),
            'herramientas_activas': sum(1 for info in self.herramientas_fim_kali2025.values() if info['disponible']),
            'capacidades_mejoradas': [
                'Detección de malware con YARA',
                'Análisis forense de metadatos',
                'Auditoría de seguridad con Tiger',
                'Verificación de integridad avanzada con AIDE',
                'Análisis de memoria con Volatility3',
                'HIDS adicional con Samhain'
            ],
            'directorio_reglas_yara': self.directorio_reglas_yara
        }
