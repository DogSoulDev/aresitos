# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador Principal con Cuarentena Integrada
Gestiona el escáner con cuarentena automática para amenazas detectadas
OPTIMIZADO con PRINCIPIOS ARESITOS V3: Python nativo + Kali tools + Thread Safety
"""

import logging
import os
import ipaddress
import threading
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class ControladorEscaneadorCuarentena:
    """
    Controlador principal que integra el escáner con el sistema de cuarentena.
    OPTIMIZADO con PRINCIPIOS ARESITOS V3: Thread Safety + Manejo Dinámico
    """
    
    def __init__(self):
        """Inicializa el controlador integrado con thread safety."""
        self.logger = logging.getLogger(f"ARESITOS.{self.__class__.__name__}")
        
        # Thread Safety (PRINCIPIO ARESITOS V3)
        self._lock = threading.RLock()
        self._cache = {}
        self._estado_inicializado = False
        
        # Configuración por defecto
        self.configuración = {
            'cuarentena_automatica': True,
            'niveles_cuarentena': ['critico', 'alto'],  # Niveles que van a cuarentena automáticamente
            'notificar_cuarentena': True,
            'backup_antes_cuarentena': True
        }
        
        # Inicializar componentes (se configuran después)
        self.escáner: Optional[Any] = None
        self.cuarentena: Optional[Any] = None
        
        # Inicialización thread-safe
        with self._lock:
            self._inicializar_componentes()
            self._estado_inicializado = True
            
        # Referencias para integración entre controladores
        self._siem_conectado = None
        self._fim_conectado = None
    
    def _inicializar_componentes(self):
        """Inicializa el escáner y el sistema de cuarentena."""
        # Inicializar escáner con fallback dinámico
        try:
            from ..modelo.modelo_escaneador import EscaneadorCompleto
            self.escáner = EscaneadorCompleto()
            self.logger.info("OK Escaneador Completo inicializado")
        except ImportError:
            try:
                from ..modelo.modelo_escaneador_sistema import EscaneadorSistema
                self.escáner = EscaneadorSistema()
                self.logger.info("OK Escaneador Sistema inicializado")
            except ImportError:
                self.logger.error("Error importando módulos de escaneador")
                self.escáner = self._crear_escaneador_mock()
                self.logger.warning("WARNING Usando escáner mock")
        
        # Inicializar cuarentena
        try:
            from .controlador_cuarentena import ControladorCuarentena
            self.cuarentena = ControladorCuarentena()
            self.logger.info("OK Sistema de cuarentena inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando cuarentena: {e}")
            self.cuarentena = None
            self.logger.warning("WARNING Usando cuarentena mock")
    
    def _crear_escaneador_mock(self):
        """Crear escaneador mock con métodos dinámicos (PRINCIPIO ARESITOS V3)"""
        class EscaneadorMock:
            def __init__(self):
                self.logger = logging.getLogger("EscaneadorMock")
                
            def escanear_completo(self):
                """Mock de escaneo completo"""
                from datetime import datetime
                return type('ResultadoMock', (), {
                    'vulnerabilidades': [],
                    'exito': True,
                    'timestamp': datetime.now(),
                    'tipo': 'mock'
                })()
                
            def detectar_malware(self):
                """Mock de detección de malware"""
                return self.escanear_completo()
                
            def escanear_vulnerabilidades_sistema(self):
                """Mock de escaneo de vulnerabilidades"""
                return self.escanear_completo()
                
            def __getattr__(self, name):
                """Método dinámico para cualquier atributo no definido"""
                def mock_method(*args, **kwargs):
                    self.logger.warning(f"Método mock llamado: {name}")
                    return {'exito': False, 'error': 'Método no implementado en mock'}
                return mock_method
        
        return EscaneadorMock()
    
    def ejecutar_escaneo_con_cuarentena(self, tipo_escaneo: str = 'completo') -> Dict[str, Any]:
        """
        Ejecuta un escaneo con cuarentena automática de amenazas.
        OPTIMIZADO con PRINCIPIOS ARESITOS V3: Acceso dinámico + Thread Safety
        
        Args:
            tipo_escaneo: Tipo de escaneo a realizar
            
        Returns:
            Dict con resultados del escaneo y cuarentena
        """
        with self._lock:
            self.logger.info(f"LAUNCH Iniciando escaneo {tipo_escaneo} con cuarentena automática")
            
            resultado = {
                'timestamp_inicio': datetime.now().isoformat(),
                'tipo_escaneo': tipo_escaneo,
                'vulnerabilidades_encontradas': [],
                'amenazas_en_cuarentena': [],
                'resumen_cuarentena': {},
                'exito': False,
                'errores': []
            }
            
            try:
                # Verificar que el escáner esté disponible
                if not self.escáner:
                    return {
                        'exito': False,
                        'errores': ['Escáner no disponible'],
                        'resultados': {}
                    }
                
                # 1. Ejecutar escaneo con acceso dinámico (PRINCIPIO ARESITOS V3)
                resultado_escaneo = None
                
                if tipo_escaneo == 'completo':
                    # Usar getattr para acceso dinámico
                    metodo_escaneo = getattr(self.escáner, 'escanear_completo', None)
                    if metodo_escaneo:
                        resultado_escaneo = metodo_escaneo()
                    else:
                        # Fallback dinámico
                        metodo_sistema = getattr(self.escáner, 'escanear_sistema', None)
                        if metodo_sistema:
                            resultado_escaneo = metodo_sistema()
                
                elif tipo_escaneo == 'malware':
                    metodo_malware = getattr(self.escáner, 'detectar_malware', None)
                    if metodo_malware:
                        resultado_escaneo = metodo_malware()
                    else:
                        # Fallback a escaneo básico
                        metodo_basico = getattr(self.escáner, 'ejecutar_escaneo_basico', None)
                        if metodo_basico:
                            resultado_escaneo = metodo_basico()
                
                elif tipo_escaneo == 'vulnerabilidades':
                    metodo_vulns = getattr(self.escáner, 'escanear_vulnerabilidades_sistema', None)
                    if metodo_vulns:
                        resultado_escaneo = metodo_vulns()
                    else:
                        # Fallback a verificación Kali
                        metodo_kali = getattr(self.escáner, 'verificar_funcionalidad_kali', None)
                        if metodo_kali:
                            resultado_escaneo = metodo_kali()
                else:
                    raise ValueError(f"Tipo de escaneo no válido: {tipo_escaneo}")
                
                if not resultado_escaneo:
                    raise ValueError(f"No se pudo ejecutar escaneo tipo: {tipo_escaneo}")
                
                # 2. Procesar vulnerabilidades encontradas con acceso dinámico
                vulnerabilidades_procesadas = []
                amenazas_cuarentena = []
                
                # Acceso dinámico a vulnerabilidades
                vulnerabilidades = getattr(resultado_escaneo, 'vulnerabilidades', [])
                if not vulnerabilidades and hasattr(resultado_escaneo, 'get'):
                    # Si es dict, intentar obtener vulnerabilidades
                    vulnerabilidades = resultado_escaneo.get('vulnerabilidades_encontradas', [])
                
                for vuln in vulnerabilidades:
                    # Acceso dinámico a atributos de vulnerabilidad
                    vuln_info = {
                        'id': getattr(vuln, 'id', 'N/A'),
                        'tipo': getattr(vuln, 'tipo', 'Desconocido'),
                        'descripcion': getattr(vuln, 'descripcion', 'Sin descripción'),
                        'nivel_riesgo': str(getattr(vuln, 'nivel_riesgo', 'medio')),
                        'archivo_afectado': getattr(vuln, 'archivo_afectado', 'N/A'),
                        'timestamp': getattr(vuln, 'timestamp', datetime.now()).isoformat() if hasattr(vuln, 'timestamp') else datetime.now().isoformat()
                    }
                    
                    # Si vuln es dict, usar acceso directo
                    if isinstance(vuln, dict):
                        vuln_info.update({
                            'id': vuln.get('id', 'N/A'),
                            'tipo': vuln.get('tipo', 'Desconocido'),
                            'descripcion': vuln.get('descripcion', 'Sin descripción'),
                            'nivel_riesgo': str(vuln.get('nivel_riesgo', 'medio')),
                            'archivo_afectado': vuln.get('archivo_afectado', 'N/A'),
                            'timestamp': vuln.get('timestamp', datetime.now().isoformat())
                        })
                    
                    vulnerabilidades_procesadas.append(vuln_info)
                    
                    # 3. Procesar con cuarentena si es necesario
                    if self._debe_ir_a_cuarentena_dinamico(vuln_info):
                        if self._procesar_amenaza_cuarentena_dinamico(vuln_info):
                            amenazas_cuarentena.append(vuln_info)
                            self.logger.warning(f"WARNING Amenaza enviada a cuarentena: {vuln_info['tipo']}")
                
                # 4. Obtener resumen de cuarentena
                resumen_cuarentena = self._obtener_resumen_cuarentena()
                
                # 5. Preparar resultado final
                resultado.update({
                    'vulnerabilidades_encontradas': vulnerabilidades_procesadas,
                    'amenazas_en_cuarentena': amenazas_cuarentena,
                    'resumen_cuarentena': resumen_cuarentena,
                    'exito': True,
                    'timestamp_fin': datetime.now().isoformat(),
                    'estadisticas': {
                        'total_vulnerabilidades': len(vulnerabilidades_procesadas),
                        'criticas': len([v for v in vulnerabilidades_procesadas if v['nivel_riesgo'] == 'critico']),
                        'altas': len([v for v in vulnerabilidades_procesadas if v['nivel_riesgo'] == 'alto']),
                        'en_cuarentena': len(amenazas_cuarentena)
                    }
                })
                
                # 6. Log de resumen
                self._log_resumen_escaneo(resultado)
                
                return resultado
                
            except Exception as e:
                error_msg = f"Error durante escaneo con cuarentena: {e}"
                self.logger.error(error_msg)
                resultado['errores'].append(error_msg)
                resultado['timestamp_fin'] = datetime.now().isoformat()
                return resultado
    
    def _debe_ir_a_cuarentena(self, vulnerabilidad) -> bool:
        """Determina si una vulnerabilidad debe ir a cuarentena automáticamente."""
        if not self.configuración['cuarentena_automatica']:
            return False
        
        nivel = getattr(vulnerabilidad, 'nivel_riesgo', None)
        if nivel:
            nivel_str = getattr(nivel, 'value', str(nivel))
        else:
            nivel_str = 'medio'
            
        return nivel_str in self.configuración['niveles_cuarentena']
    
    def _debe_ir_a_cuarentena_dinamico(self, vuln_info: Dict[str, Any]) -> bool:
        """Determina dinámicamente si una vulnerabilidad debe ir a cuarentena (PRINCIPIO ARESITOS V3)."""
        if not self.configuración['cuarentena_automatica']:
            return False
        
        nivel = vuln_info.get('nivel_riesgo', 'medio')
        return str(nivel).lower() in self.configuración['niveles_cuarentena']
    
    def _procesar_amenaza_cuarentena(self, vulnerabilidad) -> bool:
        """Procesa una amenaza con el sistema de cuarentena."""
        try:
            # Acceso dinámico a atributos de vulnerabilidad
            amenaza_info = {
                'archivo': getattr(vulnerabilidad, 'archivo_afectado', 'N/A'),
                'tipo': getattr(vulnerabilidad, 'tipo', 'Desconocido'),
                'descripcion': getattr(vulnerabilidad, 'descripcion', 'Sin descripción'),
                'severidad': self._convertir_nivel_riesgo(str(getattr(vulnerabilidad, 'nivel_riesgo', 'medio'))),
                'fuente_deteccion': 'EscaneadorAvanzado',
                'fecha_deteccion': getattr(vulnerabilidad, 'timestamp', datetime.now()).isoformat() if hasattr(vulnerabilidad, 'timestamp') else datetime.now().isoformat(),
                'metadatos': {
                    'vulnerability_id': getattr(vulnerabilidad, 'id', 'N/A'),
                    'cve_id': getattr(vulnerabilidad, 'cve_id', None),
                    'puerto_afectado': getattr(vulnerabilidad, 'puerto_afectado', None),
                    'servicio_afectado': getattr(vulnerabilidad, 'servicio_afectado', None),
                    'solucion_recomendada': getattr(vulnerabilidad, 'solucion_recomendada', None)
                }
            }
            
            return self._procesar_amenaza_cuarentena_core(amenaza_info)
            
        except Exception as e:
            self.logger.error(f"Error procesando amenaza en cuarentena: {e}")
            return False
    
    def _procesar_amenaza_cuarentena_dinamico(self, vuln_info: Dict[str, Any]) -> bool:
        """Procesa dinámicamente una amenaza con el sistema de cuarentena (PRINCIPIO ARESITOS V3)."""
        try:
            amenaza_info = {
                'archivo': vuln_info.get('archivo_afectado', 'N/A'),
                'tipo': vuln_info.get('tipo', 'Desconocido'),
                'descripcion': vuln_info.get('descripcion', 'Sin descripción'),
                'severidad': self._convertir_nivel_riesgo(str(vuln_info.get('nivel_riesgo', 'medio'))),
                'fuente_deteccion': 'EscaneadorAvanzado',
                'fecha_deteccion': vuln_info.get('timestamp', datetime.now().isoformat()),
                'metadatos': {
                    'vulnerability_id': vuln_info.get('id', 'N/A'),
                    'cve_id': vuln_info.get('cve_id', None),
                    'puerto_afectado': vuln_info.get('puerto_afectado', None),
                    'servicio_afectado': vuln_info.get('servicio_afectado', None),
                    'solucion_recomendada': vuln_info.get('solucion_recomendada', None)
                }
            }
            
            return self._procesar_amenaza_cuarentena_core(amenaza_info)
            
        except Exception as e:
            self.logger.error(f"Error procesando amenaza dinámicamente: {e}")
            return False
    
    def _procesar_amenaza_cuarentena_core(self, amenaza_info: Dict[str, Any]) -> bool:
        """Procesamiento core de amenazas con SIEM integration (PRINCIPIO ARESITOS V3)."""
        try:
            # Procesar amenaza con cuarentena (si está disponible)
            if self.cuarentena:
                metodo_procesar = getattr(self.cuarentena, 'procesar_amenaza_detectada', None)
                if metodo_procesar:
                    resultado = metodo_procesar(amenaza_info)
                else:
                    self.logger.warning("Método procesar_amenaza_detectada no disponible")
                    resultado = False
            else:
                resultado = False
                self.logger.warning("Cuarentena no disponible para procesar amenaza")
            
            # Si es amenaza crítica, notificar también al SIEM
            if resultado and amenaza_info.get('severidad', '').lower() == 'crítica':
                try:
                    # Usar SIEM conectado directamente
                    if self._siem_conectado:
                        evento_siem = {
                            'tipo': 'AMENAZA_CRITICA_CUARENTENADA',
                            'descripcion': f'Archivo crítico enviado a cuarentena: {amenaza_info["descripcion"]}',
                            'archivo': amenaza_info["archivo"],
                            'severidad': 'critica'
                        }
                        metodo_generar_evento = getattr(self._siem_conectado, 'generar_evento', None)
                        if metodo_generar_evento:
                            metodo_generar_evento(
                                evento_siem['tipo'], 
                                evento_siem['descripcion'], 
                                evento_siem['severidad']
                            )
                            self.logger.info("Evento crítico notificado al SIEM")
                    # Fallback: intentar usar SIEM del controlador de cuarentena  
                    else:
                        try:
                            # Intentar obtener SIEM desde cuarentena de manera segura
                            siem_cuarentena = getattr(self.cuarentena, 'siem', None)
                            if siem_cuarentena and hasattr(siem_cuarentena, 'generar_evento'):
                                evento_siem = {
                                    'tipo': 'AMENAZA_CRITICA_CUARENTENADA',
                                    'descripcion': f'Archivo crítico enviado a cuarentena: {amenaza_info["descripcion"]}',
                                    'archivo': amenaza_info["archivo"],
                                    'severidad': 'critica'
                                }
                                siem_cuarentena.generar_evento(
                                    evento_siem['tipo'], 
                                    evento_siem['descripcion'], 
                                    evento_siem['severidad']
                                )
                                self.logger.info("Evento crítico notificado al SIEM via cuarentena")
                        except (AttributeError, TypeError) as e:
                            self.logger.debug(f"No se pudo notificar al SIEM via cuarentena: {e}")
                except Exception as e:
                    self.logger.warning(f"Error notificando al SIEM: {e}")
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en procesamiento core de amenaza: {e}")
            return False
    
    def _convertir_nivel_riesgo(self, nivel: str) -> str:
        """Convierte nivel de riesgo a formato de cuarentena."""
        conversion = {
            'critico': 'Crítica',
            'alto': 'Alta',
            'medio': 'Media',
            'bajo': 'Baja',
            'info': 'Baja'
        }
        return conversion.get(nivel, 'Media')
    
    def _obtener_resumen_cuarentena(self) -> Dict[str, Any]:
        """Obtiene resumen del estado de cuarentena con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            if self.cuarentena:
                metodo_resumen = getattr(self.cuarentena, 'obtener_resumen_cuarentena', None)
                if metodo_resumen:
                    return metodo_resumen()
                else:
                    # Fallback: intentar obtener estado básico
                    metodo_estado = getattr(self.cuarentena, 'obtener_estado', None)
                    if metodo_estado:
                        return metodo_estado()
                    else:
                        return {'mensaje': 'Cuarentena disponible pero sin método de resumen', 'cuarentena_activa': True}
            else:
                return {'mensaje': 'Sistema de cuarentena no disponible', 'cuarentena_activa': False}
        except Exception as e:
            self.logger.error(f"Error obteniendo resumen de cuarentena: {e}")
            return {'error': str(e), 'cuarentena_activa': False}
    
    def _log_resumen_escaneo(self, resultado: Dict[str, Any]):
        """Registra resumen del escaneo en los logs."""
        stats = resultado.get('estadisticas', {})
        
        self.logger.info("=" * 60)
        self.logger.info(" RESUMEN DE ESCANEO CON CUARENTENA")
        self.logger.info("=" * 60)
        self.logger.info(f" Tipo de escaneo: {resultado.get('tipo_escaneo', 'N/A')}")
        self.logger.info(f" Total vulnerabilidades: {stats.get('total_vulnerabilidades', 0)}")
        self.logger.info(f" Críticas: {stats.get('criticas', 0)}")
        self.logger.info(f" Altas: {stats.get('altas', 0)}")
        self.logger.info(f" En cuarentena: {stats.get('en_cuarentena', 0)}")
        
        if stats.get('en_cuarentena', 0) > 0:
            self.logger.warning(f"WARNING {stats['en_cuarentena']} amenazas fueron puestas en cuarentena automáticamente")
        
        self.logger.info("=" * 60)
    
    def gestionar_cuarentena(self) -> Dict[str, Any]:
        """Proporciona interfaz para gestionar la cuarentena."""
        try:
            resumen = self._obtener_resumen_cuarentena()
            
            return {
                'resumen': resumen,
                'acciones_disponibles': [
                    'listar_archivos_cuarentena',
                    'restaurar_archivo',
                    'eliminar_definitivamente',
                    'limpiar_cuarentena_antigua',
                    'generar_reporte_cuarentena'
                ],
                'configuracion_actual': self.configuración
            }
            
        except Exception as e:
            self.logger.error(f"Error gestionando cuarentena: {e}")
            return {'error': str(e)}
    
    def restaurar_desde_cuarentena(self, ruta_archivo: str) -> bool:
        """Restaura un archivo específico desde la cuarentena con acceso dinámico (PRINCIPIO ARESITOS V3)."""
        try:
            if self.cuarentena:
                metodo_restaurar = getattr(self.cuarentena, 'restaurar_archivo', None)
                if metodo_restaurar:
                    resultado = metodo_restaurar(ruta_archivo)
                    if resultado:
                        self.logger.info(f"OK Archivo restaurado: {ruta_archivo}")
                    else:
                        self.logger.warning(f"ERROR No se pudo restaurar: {ruta_archivo}")
                    return resultado
                else:
                    self.logger.error("Método de restauración no disponible en cuarentena")
                    return False
            else:
                self.logger.error("Sistema de cuarentena no disponible")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restaurando archivo: {e}")
            return False
    
    def configurar_cuarentena(self, nueva_config: Dict[str, Any]) -> bool:
        """Actualiza la configuración de cuarentena."""
        try:
            self.configuración.update(nueva_config)
            self.logger.info("OK Configuración de cuarentena actualizada")
            return True
        except Exception as e:
            self.logger.error(f"Error actualizando configuración: {e}")
            return False
    
    def configurar_integraciones(self, controlador_siem=None, controlador_fim=None, controlador_cuarentena=None):
        """
        Configurar integraciones con otros controladores del sistema.
        MÉTODO CLAVE para conectividad entre controladores con Thread Safety (PRINCIPIO ARESITOS V3).
        """
        with self._lock:
            try:
                conexiones = 0
                
                if controlador_siem:
                    self._siem_conectado = controlador_siem
                    conexiones += 1
                    self.logger.info("🔗 Escaneador conectado al SIEM")
                    
                if controlador_fim:
                    self._fim_conectado = controlador_fim
                    conexiones += 1
                    self.logger.info("🔗 Escaneador conectado al FIM")
                    
                if controlador_cuarentena:
                    # Actualizar referencia de cuarentena si se proporciona una nueva
                    self.cuarentena = controlador_cuarentena
                    conexiones += 1
                    self.logger.info("🔗 Escaneador conectado a nueva instancia de Cuarentena")
                
                # Guardar en cache de integraciones
                self._cache['integraciones'] = {
                    'siem_conectado': self._siem_conectado is not None,
                    'fim_conectado': self._fim_conectado is not None,
                    'cuarentena_conectada': self.cuarentena is not None,
                    'total_conexiones': conexiones,
                    'timestamp': datetime.now().isoformat()
                }
                
                self.logger.info(f"OK Integraciones configuradas: {conexiones} controladores conectados")
                return True
                
            except Exception as e:
                self.logger.error(f"Error configurando integraciones: {e}")
                return False
    
    # === MÉTODOS REQUERIDOS POR LA INTERFAZ ===
    
    def ejecutar_escaneo_basico(self) -> Dict[str, Any]:
        """Ejecuta un escaneo básico del sistema."""
        self.logger.info(" Iniciando escaneo básico del sistema")
        
        try:
            import socket
            import subprocess
            import shutil
            
            resultado = {
                'puertos': [],
                'procesos': [],
                'análisis': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # 1. Escanear puertos locales abiertos usando ss
            try:
                if shutil.which('ss'):
                    cmd_result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                    if cmd_result.returncode == 0:
                        lines = cmd_result.stdout.strip().split('\n')
                        puertos_encontrados = set()
                        
                        for line in lines[1:]:  # Skip header
                            if 'LISTEN' in line:
                                partes = line.split()
                                if len(partes) >= 4:
                                    direccion_local = partes[3]
                                    if ':' in direccion_local:
                                        puerto = direccion_local.split(':')[-1]
                                        try:
                                            puerto_num = int(puerto)
                                            puertos_encontrados.add(puerto_num)
                                            resultado['puertos'].append(f"Puerto {puerto_num}/tcp abierto")
                                        except ValueError:
                                            continue
                        
                        self.logger.info(f"Encontrados {len(puertos_encontrados)} puertos abiertos")
                    else:
                        # Fallback con netstat
                        cmd_result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
                        if cmd_result.returncode == 0:
                            for line in cmd_result.stdout.split('\n'):
                                if 'LISTEN' in line and ':' in line:
                                    resultado['puertos'].append("Puerto detectado con netstat")
            except Exception as e:
                self.logger.warning(f"Error escaneando puertos: {e}")
                resultado['análisis'].append("ERROR: No se pudieron escanear puertos")
            
            # 2. Procesos en ejecución usando ps
            try:
                cmd_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                if cmd_result.returncode == 0:
                    lines = cmd_result.stdout.strip().split('\n')
                    procesos_importantes = []
                    
                    for line in lines[1:]:  # Skip header
                        if any(keyword in line.lower() for keyword in 
                               ['ssh', 'apache', 'nginx', 'mysql', 'postgres', 'ftp', 'telnet', 'http']):
                            partes = line.split(None, 10)
                            if len(partes) >= 11:
                                pid = partes[1]
                                usuario = partes[0]
                                comando = partes[10]
                                procesos_importantes.append(f"PID {pid}: {comando[:50]} ({usuario})")
                            
                            if len(procesos_importantes) >= 15:
                                break
                    
                    resultado['procesos'] = procesos_importantes
                    self.logger.info(f"Encontrados {len(procesos_importantes)} procesos importantes")
                else:
                    resultado['análisis'].append("ERROR: No se pudieron listar procesos")
                    
            except Exception as e:
                self.logger.warning(f"Error listando procesos: {e}")
                resultado['análisis'].append("ERROR: Error listando procesos del sistema")
            
            # 3. Análisis básico
            total_puertos = len(resultado['puertos'])
            total_procesos = len(resultado['procesos'])
            resultado['análisis'].append(f"OK Escaneo completado - {total_puertos} puertos, {total_procesos} procesos")
            resultado['análisis'].append(f" {total_procesos} procesos de interés detectados")
            
            # Recomendaciones básicas basadas en puertos detectados
            puertos_texto = ' '.join(resultado['puertos'])
            if 'Puerto 22' in puertos_texto:
                resultado['análisis'].append("WARNING SSH activo - verificar configuración de seguridad")
            if 'Puerto 80' in puertos_texto or 'Puerto 443' in puertos_texto:
                resultado['análisis'].append(" Servidor web detectado - revisar configuración")
            
            self.logger.info("OK Escaneo básico completado exitosamente")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en escaneo básico: {e}")
            return {
                'puertos': [f"Error: {str(e)}"],
                'procesos': [],
                'análisis': [f"ERROR durante el escaneo: {str(e)}"],
                'timestamp': datetime.now().isoformat()
            }
    
    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """Verifica funcionalidad específica para Kali Linux."""
        self.logger.info(" Verificando funcionalidad en Kali Linux")
        
        resultado = {
            'funcionalidad_completa': False,
            'sistema_operativo': 'Desconocido',
            'gestor_permisos': False,
            'permisos_sudo': False,
            'herramientas_disponibles': {},
            'recomendaciones': [],
            'error': None
        }
        
        try:
            import platform
            import subprocess
            import os
            
            # 1. Verificar sistema operativo
            resultado['sistema_operativo'] = platform.system()
            
            # 2. Verificar permisos
            if platform.system() == 'Linux':
                # En Linux/Kali, verificar si es root verificando usuario
                try:
                    current_user = os.environ.get('USER', os.environ.get('USERNAME', ''))
                    resultado['gestor_permisos'] = current_user == 'root'
                except (ImportError, ModuleNotFoundError):
                    resultado['gestor_permisos'] = False
            else:
                # En Windows, asumimos permisos administrativos si podemos escribir en system32
                try:
                    import tempfile
                    test_file = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'temp_test.txt')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    resultado['gestor_permisos'] = True
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    resultado['gestor_permisos'] = False
            
            # 3. Verificar sudo
            try:
                proc = subprocess.run(['sudo', '-n', 'true'], 
                                    capture_output=True, timeout=5)
                resultado['permisos_sudo'] = proc.returncode == 0
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                resultado['permisos_sudo'] = False
            
            # 4. Verificar herramientas de Kali
            herramientas = {
                'nmap': ['nmap', '--version'],
                'netstat': ['netstat', '--version'],
                'ss': ['ss', '--version'],
                'iptables': ['iptables', '--version'],
                'systemctl': ['systemctl', '--version']
            }
            
            for nombre, comando in herramientas.items():
                try:
                    proc = subprocess.run(comando, capture_output=True, timeout=3)
                    disponible = proc.returncode == 0
                    resultado['herramientas_disponibles'][nombre] = {
                        'disponible': disponible,
                        'permisos_ok': disponible
                    }
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    resultado['herramientas_disponibles'][nombre] = {
                        'disponible': False,
                        'permisos_ok': False
                    }
            
            # 5. Generar recomendaciones
            if not resultado['gestor_permisos']:
                resultado['recomendaciones'].append("Gestor de permisos no disponible")
                resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
            
            if not resultado['permisos_sudo']:
                resultado['recomendaciones'].append("Configurar permisos sudo correctamente")
            
            herramientas_faltantes = [
                nombre for nombre, info in resultado['herramientas_disponibles'].items()
                if not info['disponible']
            ]
            
            if herramientas_faltantes:
                resultado['recomendaciones'].append(
                    f"Instalar herramientas faltantes: {', '.join(herramientas_faltantes)}"
                )
                resultado['recomendaciones'].append("Instalar herramientas auditoría: sudo apt install lynis rkhunter chkrootkit")
            
            # 6. Determinar si es funcional
            herramientas_ok = sum(1 for info in resultado['herramientas_disponibles'].values() 
                                if info['disponible']) >= len(herramientas) * 0.7
            
            resultado['funcionalidad_completa'] = (
                resultado['sistema_operativo'] == 'Linux' and
                (resultado['gestor_permisos'] or resultado['permisos_sudo']) and
                herramientas_ok
            )
            
            self.logger.info(f"OK Verificación Kali completada - Funcional: {resultado['funcionalidad_completa']}")
            return resultado
            
        except Exception as e:
            error_msg = f"Error durante verificación: {e}"
            self.logger.error(error_msg)
            resultado['error'] = error_msg
            return resultado
    
    def obtener_logs_escaneo(self) -> List[str]:
        """Obtiene logs del escáner."""
        try:
            logs = [
                f"[{datetime.now().strftime('%H:%M:%S')}] Sistema de escaneo iniciado",
                f"[{datetime.now().strftime('%H:%M:%S')}] Controlador integrado con cuarentena: {'OK' if self.cuarentena else 'ERROR'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Escaneador avanzado: {'OK' if hasattr(self.escáner, 'escanear_completo') else 'ERROR'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Cuarentena automática: {'OK' if self.configuración['cuarentena_automatica'] else 'ERROR'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Sistema listo para operaciones"
            ]
            return logs
        except Exception as e:
            return [f"Error obteniendo logs: {e}"]
    
    def obtener_eventos_siem(self) -> List[Dict[str, Any]]:
        """Obtiene eventos del SIEM relacionados con escaneo."""
        try:
            eventos = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'ESCANEADOR_INICIADO',
                    'descripcion': 'Sistema de escaneo con cuarentena iniciado correctamente'
                },
                {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'CONFIGURACION_CUARENTENA',
                    'descripcion': f"Cuarentena automática: {self.configuración['cuarentena_automatica']}"
                }
            ]
            return eventos
        except Exception as e:
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'ERROR',
                    'descripcion': f'Error obteniendo eventos SIEM: {e}'
                }
            ]
    
    def ejecutar_escaneo_completo(self) -> Dict[str, Any]:
        """Ejecuta un escaneo completo del sistema."""
        return self.ejecutar_escaneo_con_cuarentena('completo')

    def _validar_objetivo_escaneo(self, objetivo: str) -> bool:
        """
        Valida si un objetivo es válido para escaneo en Kali Linux.
        Implementa validaciones de seguridad para pentesting ético.
        
        Args:
            objetivo: IP, hostname o dominio a validar
            
        Returns:
            bool: True si el objetivo es válido para escaneo
        """
        try:
            resultado = self._validar_objetivo_detallado(objetivo)
            return resultado.get('valido', False)
        except Exception as e:
            self.logger.error(f"Error validando objetivo {objetivo}: {e}")
            return False
    
    def _validar_objetivo_detallado(self, objetivo: str) -> Dict[str, Any]:
        """
        Valida si un objetivo es válido para escaneo con detalles completos.
        Implementa validaciones de seguridad para pentesting ético.
        """
        resultado = {
            'valido': False,
            'tipo': 'desconocido',
            'objetivo_procesado': objetivo,
            'errores': [],
            'advertencias': [],
            'recomendaciones': []
        }
        
        try:
            import re
            import socket
            
            # Limpiar objetivo
            objetivo = objetivo.strip()
            
            if not objetivo:
                resultado['errores'].append("Objetivo vacío")
                return resultado
            
            # Validar IP
            try:
                ip = ipaddress.ip_address(objetivo)
                resultado['tipo'] = 'ip'
                resultado['objetivo_procesado'] = str(ip)
                
                # Verificar redes permitidas para Kali (pentesting ético)
                redes_permitidas = [
                    '127.0.0.0/8',      # Localhost
                    '10.0.0.0/8',       # RFC 1918 - Redes privadas
                    '172.16.0.0/12',    # RFC 1918 - Redes privadas  
                    '192.168.0.0/16',   # RFC 1918 - Redes privadas
                    '169.254.0.0/16'    # Link-local
                ]
                
                ip_permitida = False
                for red in redes_permitidas:
                    if ip in ipaddress.ip_network(red):
                        ip_permitida = True
                        break
                
                if ip_permitida:
                    resultado['valido'] = True
                    resultado['recomendaciones'].append(f"IP {ip} en rango permitido para pentesting")
                else:
                    resultado['errores'].append(f"IP {ip} fuera de rangos permitidos para pentesting ético")
                    
            except ipaddress.AddressValueError:
                # Podría ser hostname/dominio
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', objetivo):
                    resultado['tipo'] = 'hostname'
                    
                    # Verificar si es localhost o dominio local
                    if objetivo.lower() in ['localhost', 'kali', 'kali.local'] or objetivo.endswith('.local'):
                        resultado['valido'] = True
                        resultado['recomendaciones'].append(f"Hostname {objetivo} es válido para pentesting local")
                    else:
                        resultado['advertencias'].append(f"Hostname {objetivo} podría no ser apropiado para pentesting ético")
                        # Permitir pero con advertencia
                        resultado['valido'] = True
                else:
                    resultado['errores'].append(f"Formato de objetivo inválido: {objetivo}")
            
            # Logging de validación
            if resultado['valido']:
                self.logger.info(f"OK Objetivo {objetivo} validado para escaneo")
            else:
                self.logger.warning(f"ERROR Objetivo {objetivo} rechazado: {', '.join(resultado['errores'])}")
                
        except Exception as e:
            resultado['errores'].append(f"Error validando objetivo: {str(e)}")
            self.logger.error(f"Error en validación de objetivo: {e}")
        
        return resultado

    def escanear_sistema(self) -> Dict[str, Any]:
        """
        Método principal para escanear el sistema con herramientas de Kali Linux.
        OPTIMIZADO: Funciona con herramientas básicas de Linux.
        """
        try:
            import time
            import shutil
            
            self.logger.info("Iniciando escaneo completo del sistema con herramientas de Kali Linux")
            
            resultado = {
                'exito': False,
                'timestamp': datetime.now().isoformat(),
                'metodo_escaneo': 'Herramientas nativas de Linux/Kali',
                'escaneos_ejecutados': [],
                'vulnerabilidades_encontradas': [],
                'resumen': {},
                'tiempo_total': 0
            }
            
            tiempo_inicio = time.time()
            
            # 1. Escaneo de puertos locales (MEJORADO) - 50 puertos críticos para ciberataques
            self.logger.info("1/6 Escaneando puertos críticos para ciberataques...")
            try:
                resultado_puertos = self._escanear_puertos_locales()
                if resultado_puertos.get('exito'):
                    resultado['escaneos_ejecutados'].append('puertos_criticos')
                    puertos_abiertos = resultado_puertos.get('puertos_abiertos', [])
                    resultado['resumen']['puertos_abiertos'] = len(puertos_abiertos)
                    resultado['resumen']['puertos_criticos'] = resultado_puertos.get('total_criticos', 0)
                    resultado['puertos_abiertos'] = puertos_abiertos
                    
                    # Buscar vulnerabilidades críticas en puertos
                    for puerto in puertos_abiertos:
                        if isinstance(puerto, dict) and puerto.get('critico'):
                            resultado['vulnerabilidades_encontradas'].append({
                                'tipo': 'PUERTO_CRITICO_EXPUESTO',
                                'severidad': 'ALTA',
                                'descripcion': f"Puerto crítico para ciberataques abierto: {puerto['puerto']} ({puerto['servicio']})",
                                'puerto': puerto['puerto'],
                                'servicio': puerto['servicio'],
                                'detalles': puerto
                            })
                self.logger.info("OK Escaneo de puertos críticos completado")
            except Exception as e:
                self.logger.warning(f"Error en escaneo de puertos: {e}")
            
            # 2. Escaneo de procesos activos (SIEMPRE disponible)
            self.logger.info("2/5 Escaneando procesos activos...")
            try:
                resultado_procesos = self._escanear_procesos_activos()
                if resultado_procesos.get('exito'):
                    resultado['escaneos_ejecutados'].append('procesos_activos')
                    procesos = resultado_procesos.get('procesos', [])
                    resultado['resumen']['procesos_analizados'] = len(procesos)
                    resultado['procesos_detectados'] = procesos[:20]  # Limitar a 20
                    
                    # Buscar procesos sospechosos
                    procesos_sospechosos = ['nc', 'netcat', 'ncat', 'backdoor', 'rootkit']
                    for proceso in procesos:
                        if isinstance(proceso, dict):
                            comando = proceso.get('comando', '').lower()
                            if any(sospechoso in comando for sospechoso in procesos_sospechosos):
                                resultado['vulnerabilidades_encontradas'].append({
                                    'tipo': 'PROCESO_SOSPECHOSO',
                                    'severidad': 'ALTA',
                                    'descripcion': f"Proceso potencialmente sospechoso: {comando}",
                                    'proceso': proceso
                                })
                self.logger.info("OK Escaneo de procesos completado")
            except Exception as e:
                self.logger.warning(f"Error en escaneo de procesos: {e}")
            
            # 3. Escaneo de servicios del sistema
            self.logger.info("3/5 Escaneando servicios del sistema...")
            try:
                resultado_servicios = self._escanear_servicios_sistema()
                if resultado_servicios.get('exito'):
                    resultado['escaneos_ejecutados'].append('servicios_sistema')
                    servicios = resultado_servicios.get('servicios', [])
                    resultado['resumen']['servicios_analizados'] = len(servicios)
                    resultado['servicios_activos'] = servicios[:15]  # Limitar a 15
                self.logger.info("OK Escaneo de servicios completado")
            except Exception as e:
                self.logger.warning(f"Error en escaneo de servicios: {e}")
            
            # 4. Escaneo con nmap (SOLO si está disponible)
            self.logger.info("4/5 Verificando disponibilidad de nmap...")
            if shutil.which('nmap'):
                try:
                    self.logger.info("nmap encontrado, ejecutando escaneo avanzado...")
                    resultado_nmap = self._escanear_con_nmap()
                    if resultado_nmap.get('exito'):
                        resultado['escaneos_ejecutados'].append('nmap')
                        resultado['resumen']['hosts_nmap'] = resultado_nmap.get('hosts_encontrados', 0)
                        resultado['escaneo_nmap'] = resultado_nmap
                    self.logger.info("OK Escaneo nmap completado")
                except Exception as e:
                    self.logger.warning(f"Error con nmap: {e}")
            else:
                self.logger.info("nmap no disponible, omitiendo escaneo avanzado")
            
            # 5. Verificación básica de integridad (usando find)
            self.logger.info("5/5 Verificando integridad básica del sistema...")
            try:
                archivos_criticos = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
                archivos_verificados = 0
                
                for archivo in archivos_criticos:
                    try:
                        import os
                        import stat
                        if os.path.exists(archivo):
                            st = os.stat(archivo)
                            permisos = oct(st.st_mode)[-3:]
                            
                            # Verificar permisos seguros
                            if archivo == '/etc/shadow' and permisos != '640' and permisos != '600':
                                resultado['vulnerabilidades_encontradas'].append({
                                    'tipo': 'PERMISOS_INSEGUROS',
                                    'severidad': 'ALTA',
                                    'descripcion': f"Permisos inseguros en {archivo}: {permisos}",
                                    'archivo': archivo,
                                    'permisos': permisos
                                })
                            
                            archivos_verificados += 1
                    except (ValueError, TypeError, AttributeError):
                        pass
                
                if archivos_verificados > 0:
                    resultado['escaneos_ejecutados'].append('integridad_basica')
                    resultado['resumen']['archivos_verificados'] = archivos_verificados
                
                self.logger.info("OK Verificación de integridad completada")
            except Exception as e:
                self.logger.warning(f"Error en verificación de integridad: {e}")
            
            # Calcular tiempo total
            tiempo_total = time.time() - tiempo_inicio
            resultado['tiempo_total'] = round(tiempo_total, 2)
            
            # Generar resumen final
            total_vulnerabilidades = len(resultado['vulnerabilidades_encontradas'])
            escaneos_completados = len(resultado['escaneos_ejecutados'])
            
            resultado['resumen'].update({
                'total_vulnerabilidades': total_vulnerabilidades,
                'escaneos_completados': escaneos_completados,
                'vulnerabilidades_criticas': len([v for v in resultado['vulnerabilidades_encontradas'] 
                                                 if v.get('severidad') == 'CRITICA']),
                'vulnerabilidades_altas': len([v for v in resultado['vulnerabilidades_encontradas'] 
                                              if v.get('severidad') == 'ALTA']),
                'porcentaje_completado': round((escaneos_completados / 5) * 100, 1)
            })
            
            # Evaluar éxito general
            if escaneos_completados >= 3:  # Al menos 3 de 5 escaneos
                resultado['exito'] = True
                self.logger.info(f"Escaneo exitoso en {tiempo_total:.2f}s - {total_vulnerabilidades} vulnerabilidades")
            else:
                resultado['exito'] = False
                resultado['error'] = f"Solo {escaneos_completados}/5 escaneos completados"
                self.logger.warning(f"Escaneo parcial: {escaneos_completados}/5 completados")
            
            # Registrar evento del escaneo
            try:
                self.logger.info(f"ESCANEO_SISTEMA_COMPLETO: {total_vulnerabilidades} vulnerabilidades detectadas")
            except Exception as e:
                self.logger.error(f"Error registrando evento de escaneo: {str(e)}")
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error en escaneo del sistema: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }

    def _escanear_puertos_locales(self) -> Dict[str, Any]:
        """Escanear puertos abiertos en el sistema local incluyendo los 50 puertos más comunes para ciberataques"""
        try:
            import subprocess
            puertos_encontrados = []
            
            # 50 puertos más comunes para ciberataques (CRÍTICOS PARA MONITOREO)
            puertos_criticos = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,  # Básicos críticos
                445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379,               # Servicios comunes
                1433, 1521, 2049, 2121, 2375, 3128, 5060, 5061, 5432,            # Bases de datos y proxy
                6667, 8080, 8443, 8888, 9090, 9200, 9300, 10000, 11211,          # Web y aplicaciones
                27017, 27018, 50070, 6379, 7001, 8000, 8008, 8081, 8090,         # NoSQL y desarrollo
                9000, 9001, 9043, 9080, 9443, 10051, 11211, 50000                 # Monitoreo y cache
            ]
            
            # Usar netstat para detectar puertos abiertos
            cmd = ['netstat', '-tuln']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')
                for linea in lineas:
                    if 'LISTEN' in linea or 'UDP' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            direccion_local = partes[3]
                            if ':' in direccion_local:
                                puerto = direccion_local.split(':')[-1]
                                if puerto.isdigit():
                                    puerto_num = int(puerto)
                                    
                                    # Determinar criticidad del puerto
                                    es_critico = puerto_num in puertos_criticos
                                    riesgo = 'ALTO' if es_critico else 'MEDIO'
                                    
                                    # Clasificar el servicio por puerto
                                    servicio = self._identificar_servicio_puerto(puerto_num)
                                    
                                    puertos_encontrados.append({
                                        'puerto': puerto_num,
                                        'protocolo': 'TCP' if 'tcp' in linea.lower() else 'UDP',
                                        'estado': 'LISTENING',
                                        'direccion': direccion_local,
                                        'critico': es_critico,
                                        'riesgo': riesgo,
                                        'servicio': servicio
                                    })
            
            # Fallback con ss si netstat no funciona
            if not puertos_encontrados:
                try:
                    cmd_ss = ['ss', '-tuln']
                    result_ss = subprocess.run(cmd_ss, capture_output=True, text=True, timeout=30)
                    if result_ss.returncode == 0:
                        lineas_ss = result_ss.stdout.split('\n')
                        for linea in lineas_ss[1:]:  # Skip header
                            if 'LISTEN' in linea:
                                partes = linea.split()
                                if len(partes) >= 4:
                                    direccion_local = partes[3]
                                    if ':' in direccion_local:
                                        puerto = direccion_local.split(':')[-1]
                                        if puerto.isdigit():
                                            puerto_num = int(puerto)
                                            es_critico = puerto_num in puertos_criticos
                                            servicio = self._identificar_servicio_puerto(puerto_num)
                                            
                                            puertos_encontrados.append({
                                                'puerto': puerto_num,
                                                'protocolo': 'TCP',
                                                'estado': 'LISTENING',
                                                'direccion': direccion_local,
                                                'critico': es_critico,
                                                'riesgo': 'ALTO' if es_critico else 'MEDIO',
                                                'servicio': servicio
                                            })
                except Exception as e:
                    self.logger.warning(f"Error con comando ss: {e}")
            
            return {
                'puertos_abiertos': puertos_encontrados, 
                'exito': True,
                'total_criticos': len([p for p in puertos_encontrados if p.get('critico')]),
                'total_puertos': len(puertos_encontrados)
            }
            
        except Exception as e:
            self.logger.error(f"Error escaneando puertos: {e}")
            return {'puertos_abiertos': [], 'exito': False, 'error': str(e)}
    
    def _identificar_servicio_puerto(self, puerto: int) -> str:
        """Identificar servicio común por número de puerto"""
        servicios_comunes = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC/DCE', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2121: 'FTP-Proxy',
            2375: 'Docker', 3128: 'Squid', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 6667: 'IRC', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 8888: 'HTTP-Dev', 9090: 'HTTP-Mgmt', 9200: 'Elasticsearch',
            27017: 'MongoDB', 50070: 'Hadoop'
        }
        return servicios_comunes.get(puerto, 'Unknown')
    
    def _monitorear_dns_y_red(self) -> Dict[str, Any]:
        """Monitorear actividad DNS y conexiones de red sospechosas"""
        try:
            import subprocess
            import socket
            
            resultado = {
                'conexiones_activas': [],
                'dns_queries_sospechosas': [],
                'ips_externas_conectadas': [],
                'dominios_sospechosos': [],
                'exito': False
            }
            
            # Dominios sospechosos comunes (DNS tunneling, C&C, malware)
            dominios_sospechosos = [
                'bit.ly', 'tinyurl.com', 'pastebin.com', '0x0.st', 'transfer.sh',
                'duckdns.org', 'no-ip.com', 'ddns.net', 'freeddns.org',
                '.tk', '.ml', '.ga', '.cf', '.onion'
            ]
            
            # IPs sospechosas (rangos conocidos por actividad maliciosa)
            rangos_sospechosos = [
                '127.0.0.1', '0.0.0.0'  # Localhost como base, expandir según necesidad
            ]
            
            # Monitorear conexiones activas con netstat
            try:
                cmd = ['netstat', '-tuln', '--numeric-ports']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                
                if result.returncode == 0:
                    lineas = result.stdout.split('\n')
                    for linea in lineas:
                        if 'ESTABLISHED' in linea or 'SYN_SENT' in linea:
                            partes = linea.split()
                            if len(partes) >= 5:
                                direccion_local = partes[3]
                                direccion_remota = partes[4]
                                estado = partes[5] if len(partes) > 5 else 'UNKNOWN'
                                
                                # Extraer IP remota
                                if ':' in direccion_remota:
                                    ip_remota = direccion_remota.split(':')[0]
                                    puerto_remoto = direccion_remota.split(':')[-1]
                                    
                                    # Verificar si es IP externa (no localhost ni red local)
                                    if not ip_remota.startswith(('127.', '192.168.', '10.', '172.')):
                                        resultado['ips_externas_conectadas'].append({
                                            'ip': ip_remota,
                                            'puerto': puerto_remoto,
                                            'estado': estado,
                                            'local': direccion_local
                                        })
                                
                                resultado['conexiones_activas'].append({
                                    'local': direccion_local,
                                    'remota': direccion_remota,
                                    'estado': estado,
                                    'sospechosa': not direccion_remota.startswith(('127.', '192.168.', '10.'))
                                })
            except Exception as e:
                self.logger.warning(f"Error monitoreando conexiones: {e}")
            
            # Verificar resolución DNS para detectar túneles DNS
            try:
                # Verificar archivos de configuración DNS
                dns_files = ['/etc/resolv.conf', '/etc/hosts']
                for dns_file in dns_files:
                    try:
                        import os
                        if os.path.exists(dns_file):
                            with open(dns_file, 'r') as f:
                                contenido = f.read()
                                # Buscar entradas sospechosas
                                for dominio in dominios_sospechosos:
                                    if dominio in contenido:
                                        resultado['dominios_sospechosos'].append({
                                            'dominio': dominio,
                                            'archivo': dns_file,
                                            'tipo': 'configuracion_dns'
                                        })
                    except Exception as e:
                        self.logger.debug(f"Error leyendo {dns_file}: {e}")
            except Exception as e:
                self.logger.warning(f"Error verificando configuración DNS: {e}")
            
            # Usar ss como alternativa si está disponible
            try:
                cmd_ss = ['ss', '-tuln']
                result_ss = subprocess.run(cmd_ss, capture_output=True, text=True, timeout=20)
                if result_ss.returncode == 0 and not resultado['conexiones_activas']:
                    lineas_ss = result_ss.stdout.split('\n')
                    for linea in lineas_ss[1:]:  # Skip header
                        if 'ESTAB' in linea or 'LISTEN' in linea:
                            partes = linea.split()
                            if len(partes) >= 4:
                                local = partes[3]
                                remota = partes[4] if len(partes) > 4 else 'N/A'
                                resultado['conexiones_activas'].append({
                                    'local': local,
                                    'remota': remota,
                                    'estado': 'ESTAB' if 'ESTAB' in linea else 'LISTEN',
                                    'herramienta': 'ss'
                                })
            except Exception as e:
                self.logger.debug(f"Error con comando ss: {e}")
            
            resultado['exito'] = True
            resultado['total_conexiones'] = len(resultado['conexiones_activas'])
            resultado['total_ips_externas'] = len(resultado['ips_externas_conectadas'])
            resultado['total_dominios_sospechosos'] = len(resultado['dominios_sospechosos'])
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error monitoreando DNS y red: {e}")
            return {'exito': False, 'error': str(e)}
    
    def _monitorear_modulos_pam(self) -> Dict[str, Any]:
        """Monitorear módulos PAM para detectar modificaciones sospechosas"""
        try:
            import subprocess
            import os
            
            resultado = {
                'archivos_pam_monitoreados': [],
                'modificaciones_sospechosas': [],
                'configuraciones_inseguras': [],
                'permisos_incorrectos': [],
                'exito': False
            }
            
            # Archivos PAM críticos para monitorear
            archivos_pam_criticos = [
                '/etc/pam.d/common-auth',
                '/etc/pam.d/common-account', 
                '/etc/pam.d/common-password',
                '/etc/pam.d/common-session',
                '/etc/pam.d/sudo',
                '/etc/pam.d/sshd',
                '/etc/pam.d/login',
                '/etc/pam.d/passwd'
            ]
            
            # Patrones sospechosos en configuración PAM
            patrones_sospechosos = [
                'pam_permit.so',  # Permite acceso sin autenticación
                'nullok',         # Permite passwords vacíos
                'try_first_pass', # Reutiliza passwords previos
                'pam_rootok.so',  # Permite acceso root sin password
                'pam_succeed_if.so uid = 0'  # Bypasses para root
            ]
            
            for archivo_pam in archivos_pam_criticos:
                try:
                    if os.path.exists(archivo_pam):
                        # Verificar permisos del archivo
                        st = os.stat(archivo_pam)
                        permisos = oct(st.st_mode)[-3:]
                        owner_uid = st.st_uid
                        group_gid = st.st_gid
                        
                        archivo_info = {
                            'archivo': archivo_pam,
                            'permisos': permisos,
                            'owner_uid': owner_uid,
                            'group_gid': group_gid,
                            'existe': True
                        }
                        
                        # Verificar permisos seguros (debe ser 644 o más restrictivo)
                        if permisos not in ['644', '640', '600', '444']:
                            resultado['permisos_incorrectos'].append({
                                'archivo': archivo_pam,
                                'permisos_actuales': permisos,
                                'permisos_recomendados': '644',
                                'severidad': 'ALTA'
                            })
                        
                        # Verificar contenido del archivo
                        try:
                            with open(archivo_pam, 'r') as f:
                                contenido = f.read()
                                
                                # Buscar patrones sospechosos
                                for patron in patrones_sospechosos:
                                    if patron in contenido:
                                        resultado['configuraciones_inseguras'].append({
                                            'archivo': archivo_pam,
                                            'patron_sospechoso': patron,
                                            'tipo': 'configuracion_insegura',
                                            'severidad': 'CRITICA'
                                        })
                                
                                # Verificar modificaciones recientes usando stat
                                mtime = st.st_mtime
                                import time
                                tiempo_actual = time.time()
                                if (tiempo_actual - mtime) < 86400:  # Modificado en últimas 24h
                                    resultado['modificaciones_sospechosas'].append({
                                        'archivo': archivo_pam,
                                        'tiempo_modificacion': mtime,
                                        'horas_desde_modificacion': (tiempo_actual - mtime) / 3600,
                                        'tipo': 'modificacion_reciente'
                                    })
                        
                        except (PermissionError, IOError) as e:
                            archivo_info['error_lectura'] = str(e)
                        
                        resultado['archivos_pam_monitoreados'].append(archivo_info)
                
                except (OSError, IOError) as e:
                    resultado['archivos_pam_monitoreados'].append({
                        'archivo': archivo_pam,
                        'existe': False,
                        'error': str(e)
                    })
            
            # Verificar integridad con dpkg si está disponible (Debian/Kali)
            try:
                cmd = ['dpkg', '-V', 'libpam-modules']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    # Sin salida significa que los archivos PAM no han sido modificados
                    pass
                else:
                    # Hay diferencias en los archivos PAM
                    if result.stdout.strip():
                        resultado['modificaciones_sospechosas'].append({
                            'tipo': 'integridad_dpkg',
                            'detalles': result.stdout.strip(),
                            'severidad': 'ALTA'
                        })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # dpkg no disponible o timeout
                pass
            
            resultado['exito'] = True
            resultado['total_archivos_monitoreados'] = len(resultado['archivos_pam_monitoreados'])
            resultado['total_modificaciones_sospechosas'] = len(resultado['modificaciones_sospechosas'])
            resultado['total_configuraciones_inseguras'] = len(resultado['configuraciones_inseguras'])
            resultado['total_permisos_incorrectos'] = len(resultado['permisos_incorrectos'])
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error monitoreando módulos PAM: {e}")
            return {'exito': False, 'error': str(e)}

    def _escanear_procesos_activos(self) -> Dict[str, Any]:
        """Escanear procesos activos en el sistema detectando actividades sospechosas"""
        try:
            import subprocess
            procesos_encontrados = []
            procesos_sospechosos = []
            
            # Patrones de procesos sospechosos para monitoreo avanzado
            patrones_sospechosos = [
                'nc', 'netcat', 'ncat', 'backdoor', 'rootkit', 'miner', 'cryptojack',
                'wget', 'curl', 'python -c', 'perl -e', 'bash -i', '/dev/tcp',
                'socat', 'reverse', 'shell', 'exploit', 'metasploit', 'msfvenom',
                'powershell', 'cmd.exe', 'wscript', 'cscript', 'rundll32'
            ]
            
            # Procesos críticos del sistema que deben monitorearse
            procesos_criticos = [
                'ssh', 'sshd', 'apache', 'apache2', 'nginx', 'mysql', 'mysqld',
                'postgres', 'postgresql', 'redis', 'mongodb', 'docker', 'systemd',
                'init', 'kernel', 'kthreadd', 'dhcp', 'dns', 'bind', 'named'
            ]
            
            # Usar ps para obtener procesos
            cmd = ['ps', 'auxww']  # Incluir argumentos completos
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')[1:]  # Saltar header
                for linea in lineas[:100]:  # Aumentar límite a 100 procesos
                    if linea.strip():
                        partes = linea.split(None, 10)
                        if len(partes) >= 11:
                            usuario = partes[0]
                            pid = partes[1]
                            cpu = partes[2]
                            memoria = partes[3]
                            comando_completo = partes[10]
                            comando_base = comando_completo.split()[0] if comando_completo else ''
                            
                            # Determinar si el proceso es sospechoso
                            es_sospechoso = any(patron in comando_completo.lower() for patron in patrones_sospechosos)
                            es_critico = any(critico in comando_base.lower() for critico in procesos_criticos)
                            
                            # Detectar uso anómalo de CPU/Memoria
                            try:
                                cpu_val = float(cpu)
                                mem_val = float(memoria)
                                uso_alto = cpu_val > 80.0 or mem_val > 70.0
                            except (ValueError, TypeError):
                                uso_alto = False
                            
                            # Detectar procesos ejecutándose como root pero sospechosos
                            root_sospechoso = usuario == 'root' and es_sospechoso
                            
                            proceso_info = {
                                'usuario': usuario,
                                'pid': pid,
                                'cpu': cpu,
                                'memoria': memoria,
                                'comando': comando_completo[:100],  # Limitar longitud
                                'comando_base': comando_base,
                                'sospechoso': es_sospechoso,
                                'critico': es_critico,
                                'uso_alto_recursos': uso_alto,
                                'root_sospechoso': root_sospechoso,
                                'riesgo': 'ALTO' if (es_sospechoso or root_sospechoso) else ('MEDIO' if es_critico else 'BAJO')
                            }
                            
                            procesos_encontrados.append(proceso_info)
                            
                            # Agregar a lista de sospechosos si cumple criterios
                            if es_sospechoso or root_sospechoso or uso_alto:
                                procesos_sospechosos.append(proceso_info)
            
            return {
                'procesos': procesos_encontrados, 
                'exito': True,
                'procesos_sospechosos': procesos_sospechosos,
                'total_sospechosos': len(procesos_sospechosos),
                'total_procesos': len(procesos_encontrados)
            }
            
        except Exception as e:
            self.logger.error(f"Error escaneando procesos: {e}")
            return {'procesos': [], 'exito': False, 'error': str(e)}

    def _escanear_servicios_sistema(self) -> Dict[str, Any]:
        """Escanear servicios del sistema"""
        try:
            import subprocess
            servicios_encontrados = []
            
            # Usar systemctl para obtener servicios
            cmd = ['systemctl', 'list-units', '--type=service', '--state=active']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')
                for linea in lineas:
                    if '.service' in linea and 'active' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            servicios_encontrados.append({
                                'nombre': partes[0],
                                'estado': partes[1],
                                'actividad': partes[2],
                                'descripcion': ' '.join(partes[4:]) if len(partes) > 4 else ''
                            })
            
            return {'servicios': servicios_encontrados[:20], 'exito': True}  # Limitar a 20
            
        except Exception as e:
            self.logger.error(f"Error escaneando servicios: {e}")
            return {'servicios': [], 'exito': False, 'error': str(e)}

    def verificar_kali_linux(self) -> Dict[str, Any]:
        """
        Verifica la configuración de Kali Linux.
        Método requerido por la vista de escaneo.
        
        Returns:
            Dict con información de verificación de Kali
        """
        try:
            import platform
            import subprocess
            
            resultado = {
                'sistema_operativo': platform.system(),
                'distribucion': 'Desconocida',
                'version_kernel': platform.release(),
                'arquitectura': platform.machine(),
                'kali_detectado': False,
                'herramientas_kali': [],
                'recomendaciones': []
            }
            
            # Detectar si es Kali Linux
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = f.read()
                    if 'kali' in os_info.lower():
                        resultado['kali_detectado'] = True
                        resultado['distribucion'] = 'Kali Linux'
                        
                        # Verificar herramientas comunes de Kali
                        herramientas_kali = ['nmap', 'nikto', 'sqlmap', 'gobuster', 'feroxbuster', 'hydra']
                        for herramienta in herramientas_kali:
                            try:
                                subprocess.run(['which', herramienta], 
                                             capture_output=True, check=True)
                                resultado['herramientas_kali'].append(herramienta)
                            except subprocess.CalledProcessError:
                                resultado['recomendaciones'].append(
                                    f"Instalar {herramienta}: sudo apt install {herramienta}"
                                )
                    
            except FileNotFoundError:
                resultado['recomendaciones'].append("Sistema no es Kali Linux")
                
            # Verificar permisos sudo
            try:
                subprocess.run(['sudo', '-n', 'true'], 
                             capture_output=True, check=True)
                resultado['sudo_disponible'] = True
            except subprocess.CalledProcessError:
                resultado['sudo_disponible'] = False
                resultado['recomendaciones'].append("Configurar permisos sudo necesarios")
                
            self.logger.info(f"OK Verificación de Kali completada: {resultado['distribucion']}")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error verificando Kali Linux: {e}")
            return {
                'error': str(e),
                'kali_detectado': False,
                'recomendaciones': ['Error en verificación del sistema']
            }

    # =================== MÉTODOS AVANZADOS CON HERRAMIENTAS DE KALI ===================
    
    def _escanear_con_nmap(self) -> Dict[str, Any]:
        """Escanear puertos locales con nmap (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando escaneo con Nmap...")
            
            # Escanear localhost con nmap
            cmd = ['nmap', '-sT', '-O', '--top-ports', '1000', 'localhost']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            puertos_nmap = []
            servicios_detectados = []
            
            if result.returncode == 0:
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    # Parsear puertos abiertos
                    if '/tcp' in linea and 'open' in linea:
                        partes = linea.split()
                        if len(partes) >= 3:
                            puerto_info = partes[0].split('/')[0]
                            estado = partes[1]
                            servicio = partes[2] if len(partes) > 2 else 'unknown'
                            
                            puertos_nmap.append({
                                'puerto': int(puerto_info),
                                'protocolo': 'TCP',
                                'estado': estado,
                                'servicio': servicio,
                                'herramienta': 'nmap'
                            })
                            
                            servicios_detectados.append(servicio)
                
                return {
                    'exito': True,
                    'puertos_encontrados': puertos_nmap,
                    'total_puertos': len(puertos_nmap),
                    'servicios_detectados': list(set(servicios_detectados)),
                    'raw_output': result.stdout,
                    'herramienta': 'nmap'
                }
            else:
                return {
                    'exito': False,
                    'error': result.stderr,
                    'puertos_encontrados': [],
                    'herramienta': 'nmap'
                }
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout en escaneo nmap")
            return {
                'exito': False,
                'error': 'Timeout en escaneo nmap',
                'puertos_encontrados': [],
                'herramienta': 'nmap'
            }
        except Exception as e:
            self.logger.error(f"Error en escaneo nmap: {e}")
            return {
                'exito': False,
                'error': str(e),
                'puertos_encontrados': [],
                'herramienta': 'nmap'
            }
    
    def _escanear_con_masscan(self) -> Dict[str, Any]:
        """Escanear puertos con masscan (herramienta de Kali para escaneos rápidos)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando escaneo rápido con Masscan...")
            
            # Escanear rango local con masscan
            cmd = ['masscan', '127.0.0.1', '-p1-1000', '--rate=1000']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            puertos_masscan = []
            
            if result.returncode == 0:
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    if 'open' in linea and '127.0.0.1' in linea:
                        # Parsear formato: "Discovered open port 22/tcp on 127.0.0.1"
                        partes = linea.split()
                        for parte in partes:
                            if '/' in parte and parte.replace('/', '').replace('tcp', '').replace('udp', '').isdigit():
                                puerto_info = parte.split('/')[0]
                                protocolo = parte.split('/')[1].upper()
                                
                                puertos_masscan.append({
                                    'puerto': int(puerto_info),
                                    'protocolo': protocolo,
                                    'estado': 'open',
                                    'herramienta': 'masscan'
                                })
                
                return {
                    'exito': True,
                    'puertos_encontrados': puertos_masscan,
                    'total_puertos': len(puertos_masscan),
                    'raw_output': result.stdout,
                    'herramienta': 'masscan'
                }
            else:
                return {
                    'exito': False,
                    'error': result.stderr,
                    'puertos_encontrados': [],
                    'herramienta': 'masscan'
                }
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout en escaneo masscan")
            return {
                'exito': False,
                'error': 'Timeout en escaneo masscan',
                'puertos_encontrados': [],
                'herramienta': 'masscan'
            }
        except Exception as e:
            self.logger.error(f"Error en escaneo masscan: {e}")
            return {
                'exito': False,
                'error': str(e),
                'puertos_encontrados': [],
                'herramienta': 'masscan'
            }
    
    def _escanear_web_con_nikto(self) -> Dict[str, Any]:
        """Escanear vulnerabilidades web con nikto (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando análisis web con Nikto...")
            
            # Verificar si hay servicios web en puertos comunes
            puertos_web = [80, 443, 8080, 8443, 3000, 5000]
            resultados_nikto = []
            
            for puerto in puertos_web:
                try:
                    # Probar si el puerto está abierto
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(('127.0.0.1', puerto))
                    sock.close()
                    
                    if result == 0:  # Puerto abierto
                        self.logger.info(f"Puerto web {puerto} detectado, analizando con Nikto...")
                        
                        # Ejecutar nikto
                        protocolo = 'https' if puerto in [443, 8443] else 'http'
                        url = f"{protocolo}://127.0.0.1:{puerto}"
                        
                        cmd = ['nikto', '-h', url, '-timeout', '30']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                        
                        vulnerabilidades = []
                        if result.returncode == 0:
                            lineas = result.stdout.split('\\n')
                            for linea in lineas:
                                if '+' in linea and any(keyword in linea.lower() for keyword in 
                                    ['vulnerability', 'vuln', 'security', 'exposure', 'risk']):
                                    vulnerabilidades.append(linea.strip())
                        
                        resultados_nikto.append({
                            'puerto': puerto,
                            'url': url,
                            'vulnerabilidades_encontradas': vulnerabilidades,
                            'total_vulnerabilidades': len(vulnerabilidades),
                            'raw_output': result.stdout[:1000],  # Limitar output
                            'herramienta': 'nikto'
                        })
                
                except Exception as e:
                    self.logger.debug(f"Error verificando puerto {puerto}: {e}")
                    continue
            
            return {
                'exito': True,
                'servicios_web_analizados': resultados_nikto,
                'total_servicios': len(resultados_nikto),
                'herramienta': 'nikto'
            }
                
        except Exception as e:
            self.logger.error(f"Error en análisis nikto: {e}")
            return {
                'exito': False,
                'error': str(e),
                'servicios_web_analizados': [],
                'herramienta': 'nikto'
            }
    
    def _enumeracion_web_gobuster(self) -> Dict[str, Any]:
        """Enumeración de directorios web con gobuster (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando enumeración de directorios con Gobuster...")
            
            # Verificar si hay servicios web
            puertos_web = [80, 443, 8080]
            resultados_gobuster = []
            
            for puerto in puertos_web:
                try:
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(('127.0.0.1', puerto))
                    sock.close()
                    
                    if result == 0:  # Puerto abierto
                        protocolo = 'https' if puerto == 443 else 'http'
                        url = f"{protocolo}://127.0.0.1:{puerto}"
                        
                        # Usar wordlist común de gobuster/feroxbuster modernizada
                        wordlist = '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
                        if not os.path.exists(wordlist):
                            wordlist = '/usr/share/seclists/Discovery/Web-Content/common.txt'
                        
                        if os.path.exists(wordlist):
                            cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist, '-t', '10', '-q']
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                            
                            directorios_encontrados = []
                            if result.returncode == 0:
                                lineas = result.stdout.split('\\n')
                                for linea in lineas:
                                    if '(Status:' in linea:
                                        directorios_encontrados.append(linea.strip())
                            
                            resultados_gobuster.append({
                                'puerto': puerto,
                                'url': url,
                                'directorios_encontrados': directorios_encontrados,
                                'total_directorios': len(directorios_encontrados),
                                'herramienta': 'gobuster'
                            })
                        
                except Exception as e:
                    self.logger.debug(f"Error en gobuster puerto {puerto}: {e}")
                    continue
            
            return {
                'exito': True,
                'enumeracion_directorios': resultados_gobuster,
                'total_servicios': len(resultados_gobuster),
                'herramienta': 'gobuster'
            }
                
        except Exception as e:
            self.logger.error(f"Error en enumeración gobuster: {e}")
            return {
                'exito': False,
                'error': str(e),
                'enumeracion_directorios': [],
                'herramienta': 'gobuster'
            }
    
    def _detectar_rootkits_chkrootkit(self) -> Dict[str, Any]:
        """Detectar rootkits con chkrootkit (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando detección de rootkits con chkrootkit...")
            
            cmd = ['chkrootkit', '-q']  # Modo silencioso
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            detecciones = []
            if result.returncode == 0:
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    if linea.strip() and 'INFECTED' in linea.upper():
                        detecciones.append(linea.strip())
            
            return {
                'exito': True,
                'rootkits_detectados': detecciones,
                'total_detecciones': len(detecciones),
                'sistema_limpio': len(detecciones) == 0,
                'raw_output': result.stdout[:1000],
                'herramienta': 'chkrootkit'
            }
                
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en chkrootkit',
                'rootkits_detectados': [],
                'herramienta': 'chkrootkit'
            }
        except Exception as e:
            self.logger.error(f"Error en chkrootkit: {e}")
            return {
                'exito': False,
                'error': str(e),
                'rootkits_detectados': [],
                'herramienta': 'chkrootkit'
            }
    
    def _detectar_rootkits_rkhunter(self) -> Dict[str, Any]:
        """Detectar rootkits con rkhunter (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando detección de rootkits con rkhunter...")
            
            cmd = ['rkhunter', '--check', '--skip-keypress', '--report-warnings-only']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            warnings = []
            detecciones_criticas = []
            
            if result.returncode in [0, 1]:  # 0 = limpio, 1 = warnings
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    if 'WARNING' in linea.upper():
                        warnings.append(linea.strip())
                    elif 'INFECTED' in linea.upper() or 'ROOTKIT' in linea.upper():
                        detecciones_criticas.append(linea.strip())
            
            return {
                'exito': True,
                'warnings': warnings,
                'detecciones_criticas': detecciones_criticas,
                'total_warnings': len(warnings),
                'total_criticas': len(detecciones_criticas),
                'sistema_limpio': len(detecciones_criticas) == 0,
                'herramienta': 'rkhunter'
            }
                
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en rkhunter',
                'warnings': [],
                'detecciones_criticas': [],
                'herramienta': 'rkhunter'
            }
        except Exception as e:
            self.logger.error(f"Error en rkhunter: {e}")
            return {
                'exito': False,
                'error': str(e),
                'warnings': [],
                'detecciones_criticas': [],
                'herramienta': 'rkhunter'
            }
    
    def _compilar_vulnerabilidades(self, resultado_nmap, resultado_nikto, resultado_chkrootkit, resultado_rkhunter) -> List[Dict[str, Any]]:
        """Compilar todas las vulnerabilidades encontradas en un formato unificado"""
        vulnerabilidades = []
        
        try:
            # Vulnerabilidades de servicios (nmap)
            if resultado_nmap.get('exito') and resultado_nmap.get('puertos_encontrados'):
                for puerto in resultado_nmap['puertos_encontrados']:
                    # Servicios comunes con vulnerabilidades conocidas
                    servicios_riesgo = {
                        'ssh': 'Servicio SSH expuesto - revisar configuración',
                        'telnet': 'Telnet detectado - protocolo inseguro',
                        'ftp': 'FTP detectado - revisar configuración de seguridad',
                        'http': 'Servidor web detectado - revisar configuración',
                        'https': 'Servidor web SSL detectado - verificar certificados'
                    }
                    
                    servicio = puerto.get('servicio', '').lower()
                    if servicio in servicios_riesgo:
                        vulnerabilidades.append({
                            'tipo': 'Servicio Expuesto',
                            'descripcion': servicios_riesgo[servicio],
                            'puerto': puerto['puerto'],
                            'servicio': servicio,
                            'severidad': 'Media',
                            'herramienta': 'nmap'
                        })
            
            # Vulnerabilidades web (nikto)
            if resultado_nikto.get('exito') and resultado_nikto.get('servicios_web_analizados'):
                for servicio in resultado_nikto['servicios_web_analizados']:
                    for vuln in servicio.get('vulnerabilidades_encontradas', []):
                        vulnerabilidades.append({
                            'tipo': 'Vulnerabilidad Web',
                            'descripcion': vuln,
                            'puerto': servicio['puerto'],
                            'url': servicio['url'],
                            'severidad': 'Alta',
                            'herramienta': 'nikto'
                        })
            
            # Rootkits (chkrootkit)
            if resultado_chkrootkit.get('exito') and resultado_chkrootkit.get('rootkits_detectados'):
                for rootkit in resultado_chkrootkit['rootkits_detectados']:
                    vulnerabilidades.append({
                        'tipo': 'Rootkit Detectado',
                        'descripcion': rootkit,
                        'severidad': 'Crítica',
                        'herramienta': 'chkrootkit'
                    })
            
            # Warnings críticos (rkhunter)
            if resultado_rkhunter.get('exito'):
                for critica in resultado_rkhunter.get('detecciones_criticas', []):
                    vulnerabilidades.append({
                        'tipo': 'Detección Crítica',
                        'descripcion': critica,
                        'severidad': 'Crítica',
                        'herramienta': 'rkhunter'
                    })
                
                # Warnings importantes
                for warning in resultado_rkhunter.get('warnings', [])[:5]:  # Limitar a 5
                    vulnerabilidades.append({
                        'tipo': 'Warning de Seguridad',
                        'descripcion': warning,
                        'severidad': 'Media',
                        'herramienta': 'rkhunter'
                    })
            
            return vulnerabilidades
            
        except Exception as e:
            self.logger.error(f"Error compilando vulnerabilidades: {e}")
            return [{'tipo': 'Error', 'descripcion': f'Error compilando vulnerabilidades: {str(e)}', 'severidad': 'Baja'}]
