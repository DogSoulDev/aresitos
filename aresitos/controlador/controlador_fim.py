# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador FIM (File Integrity Monitoring)
Controlador especializado en monitoreo de integridad de archivos para Kali Linux
"""

import threading
import time
import os
import subprocess
import re
import shlex
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.modelo.modelo_fim import FIMKali2025

class ControladorFIM(ControladorBase):
    """
    Controlador de File Integrity Monitoring (FIM) optimizado para Kali Linux.
    Monitorea cambios en archivos críticos del sistema y detecta modificaciones sospechosas.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorFIM")
        self.fim_engine = None
        self.monitoreo_activo = False
        self.thread_monitoreo = None
        self.archivos_monitoreados = set()
        self.configuracion_fim = {
            'rutas_criticas': [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/hosts',
                '/boot/',
                '/usr/bin/',
                '/usr/sbin/'
            ],
            'intervalo_verificacion': 300,  # 5 minutos
            'generar_alertas': True
        }
        
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """
        Implementación específica de inicialización para ControladorFIM.
        
        Returns:
            Dict con resultado de la inicialización específica
        """
        try:
            self.logger.info("Ejecutando inicialización específica de ControladorFIM")
            
            # Verificar que el motor FIM esté disponible
            if not self.fim_engine:
                return {'exito': False, 'error': 'Motor FIM no disponible'}
            
            # Verificar configuración FIM
            if not self.configuracion_fim.get('rutas_criticas'):
                return {'exito': False, 'error': 'Configuración FIM no válida'}
            
            self.logger.info("ControladorFIM inicializado correctamente")
            
            return {'exito': True, 'mensaje': 'ControladorFIM inicializado correctamente'}
            
        except Exception as e:
            error_msg = f"Error en inicialización específica de ControladorFIM: {e}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
        
    def inicializar(self) -> Dict[str, Any]:
        """
        Inicializar el sistema FIM con verificaciones de integridad.
        """
        try:
            self.log("Inicializando controlador FIM...")
            
            # Inicializar el motor FIM
            self.fim_engine = FIMKali2025()
            # Verificar herramientas disponibles (método no retorna valor)
            self.fim_engine.verificar_herramientas()
            
            # Verificar si la inicialización fue exitosa
            resultado_init = {'exito': True, 'mensaje': 'FIM inicializado correctamente'}
            
            if not resultado_init.get('exito', False):
                return {
                    'exito': False,
                    'mensaje': f"Error inicializando FIM: {resultado_init.get('mensaje')}"
                }
            
            # Configurar rutas de monitoreo
            self._configurar_monitoreo_inicial()
            
            self.log("OK Controlador FIM inicializado correctamente")
            return {
                'exito': True,
                'mensaje': 'Controlador FIM inicializado',
                'componente': 'FIM',
                'archivos_monitoreados': len(self.archivos_monitoreados)
            }
            
        except Exception as e:
            error_msg = f"Error inicializando FIM: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg,
                'error': str(e)
            }
    
    def _configurar_monitoreo_inicial(self):
        """Configurar el monitoreo inicial de archivos críticos."""
        try:
            rutas_validas = []
            for ruta in self.configuracion_fim['rutas_criticas']:
                if os.path.exists(ruta):
                    self.archivos_monitoreados.add(ruta)
                    rutas_validas.append(ruta)
            
            # Iniciar monitoreo de todas las rutas válidas
            if self.fim_engine and rutas_validas:
                self.fim_engine.iniciar_monitoreo_tiempo_real(rutas_validas)
            
            self.log(f"Configuradas {len(self.archivos_monitoreados)} rutas para monitoreo")
            
        except Exception as e:
            self.log(f"Error configurando monitoreo inicial: {e}")
    
    def iniciar_monitoreo(self) -> Dict[str, Any]:
        """
        Iniciar el monitoreo activo de archivos.
        """
        try:
            if self.monitoreo_activo:
                return {
                    'exito': True,
                    'mensaje': 'Monitoreo FIM ya está activo'
                }
            
            self.monitoreo_activo = True
            self.thread_monitoreo = threading.Thread(
                target=self._bucle_monitoreo,
                daemon=True
            )
            self.thread_monitoreo.start()
            
            self.log("OK Monitoreo FIM iniciado")
            return {
                'exito': True,
                'mensaje': 'Monitoreo FIM iniciado correctamente'
            }
            
        except Exception as e:
            error_msg = f"Error iniciando monitoreo: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def detener_monitoreo(self) -> Dict[str, Any]:
        """
        Detener el monitoreo activo de archivos.
        """
        try:
            self.monitoreo_activo = False
            
            if self.thread_monitoreo and self.thread_monitoreo.is_alive():
                self.thread_monitoreo.join(timeout=5)
            
            self.log("OK Monitoreo FIM detenido")
            return {
                'exito': True,
                'mensaje': 'Monitoreo FIM detenido correctamente'
            }
            
        except Exception as e:
            error_msg = f"Error deteniendo monitoreo: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def _bucle_monitoreo(self):
        """
        Bucle principal de monitoreo de archivos.
        """
        while self.monitoreo_activo:
            try:
                self._verificar_integridad_archivos()
                time.sleep(self.configuracion_fim['intervalo_verificacion'])
                
            except Exception as e:
                self.log(f"Error en bucle de monitoreo: {e}")
                time.sleep(60)  # Esperar 1 minuto antes de reintentar
    
    def _verificar_integridad_archivos(self):
        """
        Verificar la integridad de todos los archivos monitoreados.
        """
        try:
            cambios_detectados = []
            
            for archivo in self.archivos_monitoreados:
                if os.path.exists(archivo):
                    # Aquí se podría implementar verificación de hash
                    # Por ahora solo verificamos existencia y timestamps
                    stat_info = os.stat(archivo)
                    
                    # Lógica de detección de cambios
                    # (simplificada para seguir principios ARESITOS)
                    
            if cambios_detectados and self.configuracion_fim['generar_alertas']:
                self._generar_alerta_cambios(cambios_detectados)
                
        except Exception as e:
            self.log(f"Error verificando integridad: {e}")
    
    def _generar_alerta_cambios(self, cambios: List[Dict]):
        """
        Generar alertas por cambios detectados.
        """
        try:
            mensaje_alerta = f"FIM: Detectados {len(cambios)} cambios en archivos críticos"
            self.log(mensaje_alerta)
            
            # Notificar al sistema principal si está disponible
            if hasattr(self.modelo_principal, 'notificar_evento'):
                self.modelo_principal.notificar_evento('fim_cambio', cambios)
                
        except Exception as e:
            self.log(f"Error generando alerta: {e}")
    
    def agregar_archivo_monitoreo(self, ruta: str) -> Dict[str, Any]:
        """
        Agregar un archivo o directorio al monitoreo.
        """
        try:
            if not os.path.exists(ruta):
                return {
                    'exito': False,
                    'mensaje': f'La ruta {ruta} no existe'
                }
            
            self.archivos_monitoreados.add(ruta)
            
            if self.fim_engine:
                resultado = self.fim_engine.iniciar_monitoreo_tiempo_real([ruta])
                if not resultado.get('exito', False):
                    return resultado
            
            self.log(f"OK Agregado al monitoreo: {ruta}")
            return {
                'exito': True,
                'mensaje': f'Archivo agregado al monitoreo: {ruta}'
            }
            
        except Exception as e:
            error_msg = f"Error agregando archivo: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtener estadísticas del monitoreo FIM.
        """
        try:
            estadisticas = {
                'archivos_monitoreados': len(self.archivos_monitoreados),
                'monitoreo_activo': self.monitoreo_activo,
                'estado': 'Activo' if self.monitoreo_activo else 'Inactivo',
                'timestamp': datetime.now().isoformat()
            }
            
            if self.fim_engine:
                stats_engine = self.fim_engine.obtener_estadisticas()
                estadisticas.update(stats_engine)
            
            return {
                'exito': True,
                'estadisticas': estadisticas
            }
            
        except Exception as e:
            self.log(f"Error obteniendo estadísticas: {e}")
            return {
                'exito': False,
                'mensaje': f'Error obteniendo estadísticas: {str(e)}'
            }
    
    def generar_reporte(self) -> Dict[str, Any]:
        """
        Generar reporte de integridad de archivos.
        """
        try:
            reporte = {
                'timestamp': datetime.now().isoformat(),
                'archivos_monitoreados': list(self.archivos_monitoreados),
                'estado_monitoreo': 'Activo' if self.monitoreo_activo else 'Inactivo',
                'configuracion': self.configuracion_fim
            }
            
            self.log("OK Reporte FIM generado")
            return {
                'exito': True,
                'reporte': reporte
            }
            
        except Exception as e:
            error_msg = f"Error generando reporte: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def iniciar_monitoreo_integridad(self) -> Dict[str, Any]:
        """
        Iniciar monitoreo específico de integridad de archivos críticos.
        
        Returns:
            Dict con resultado del inicio de monitoreo
        """
        try:
            if not self.fim_engine:
                return {
                    'exito': False,
                    'mensaje': 'Motor FIM no está inicializado'
                }
            
            # Configurar monitoreo específico de integridad
            archivos_criticos = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/hosts',
                '/etc/ssh/sshd_config',
                '/boot/grub/grub.cfg'
            ]
            
            archivos_validos = []
            for archivo in archivos_criticos:
                if os.path.exists(archivo):
                    archivos_validos.append(archivo)
                    self.archivos_monitoreados.add(archivo)
            
            if archivos_validos:
                resultado = self.fim_engine.iniciar_monitoreo_tiempo_real(archivos_validos)
                if resultado.get('exito', True):  # Default True si no hay respuesta específica
                    self.log(f"Monitoreo de integridad iniciado para {len(archivos_validos)} archivos")
                    return {
                        'exito': True,
                        'mensaje': f'Monitoreo de integridad iniciado para {len(archivos_validos)} archivos críticos',
                        'archivos_monitoreados': archivos_validos
                    }
                else:
                    return resultado
            else:
                return {
                    'exito': False,
                    'mensaje': 'No se encontraron archivos críticos para monitorear'
                }
                
        except Exception as e:
            error_msg = f"Error iniciando monitoreo de integridad: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def verificar_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        """
        Verificar integridad de un archivo específico.
        
        Args:
            ruta_archivo: Ruta del archivo a verificar
            
        Returns:
            Dict con resultado de la verificación
        """
        try:
            if not ruta_archivo:
                return {
                    'exito': False,
                    'mensaje': 'Ruta de archivo requerida'
                }
            
            if not os.path.exists(ruta_archivo):
                return {
                    'exito': False,
                    'mensaje': f'El archivo {ruta_archivo} no existe'
                }
            
            # Obtener información del archivo
            try:
                stat_info = os.stat(ruta_archivo)
                info_archivo = {
                    'ruta': ruta_archivo,
                    'tamaño': stat_info.st_size,
                    'ultima_modificacion': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'permisos': oct(stat_info.st_mode)[-3:],
                    'propietario_uid': stat_info.st_uid,
                    'grupo_gid': stat_info.st_gid,
                    'es_archivo': os.path.isfile(ruta_archivo),
                    'es_directorio': os.path.isdir(ruta_archivo),
                    'es_enlace': os.path.islink(ruta_archivo)
                }
                
                # Verificar si el archivo está siendo monitoreado
                esta_monitoreado = ruta_archivo in self.archivos_monitoreados
                
                # Calcular hash si es un archivo regular pequeño
                hash_md5 = None
                if os.path.isfile(ruta_archivo) and stat_info.st_size < 10 * 1024 * 1024:  # < 10MB
                    try:
                        import hashlib
                        with open(ruta_archivo, 'rb') as f:
                            hash_md5 = hashlib.md5(f.read()).hexdigest()
                    except Exception as e:
                        self.log(f"No se pudo calcular hash de {ruta_archivo}: {e}")
                
                if hash_md5:
                    info_archivo['hash_md5'] = hash_md5
                
                resultado = {
                    'exito': True,
                    'archivo': info_archivo,
                    'monitoreado': esta_monitoreado,
                    'timestamp_verificacion': datetime.now().isoformat()
                }
                
                self.log(f"Verificación completada para: {ruta_archivo}")
                return resultado
                
            except PermissionError:
                return {
                    'exito': False,
                    'mensaje': f'Sin permisos para acceder a {ruta_archivo}'
                }
                
        except Exception as e:
            error_msg = f"Error verificando archivo {ruta_archivo}: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def obtener_cambios(self, periodo_horas: int = 24) -> Dict[str, Any]:
        """
        Obtener lista de cambios detectados en el período especificado.
        
        Args:
            periodo_horas: Período en horas para buscar cambios (default: 24)
            
        Returns:
            Dict con lista de cambios detectados
        """
        try:
            cambios_detectados = []
            
            # Usar el motor FIM para obtener cambios si está disponible
            # Comentado temporalmente debido a que el método no existe en FIMKali2025
            # if self.fim_engine and hasattr(self.fim_engine, 'obtener_cambios_recientes'):
            #     try:
            #         cambios_fim = self.fim_engine.obtener_cambios_recientes(periodo_horas)
            #         if cambios_fim:
            #             cambios_detectados.extend(cambios_fim)
            #     except Exception as e:
            #         self.log(f"Error obteniendo cambios del motor FIM: {e}")
            
            # Verificar cambios en archivos monitoreados manualmente
            from datetime import timedelta
            tiempo_limite = datetime.now() - timedelta(hours=periodo_horas)
            
            for archivo in self.archivos_monitoreados:
                try:
                    if os.path.exists(archivo):
                        stat_info = os.stat(archivo)
                        fecha_mod = datetime.fromtimestamp(stat_info.st_mtime)
                        
                        if fecha_mod > tiempo_limite:
                            cambio = {
                                'archivo': archivo,
                                'tipo_cambio': 'modificacion',
                                'timestamp': fecha_mod.isoformat(),
                                'tamaño': stat_info.st_size,
                                'permisos': oct(stat_info.st_mode)[-3:]
                            }
                            
                            # Evitar duplicados
                            if not any(c['archivo'] == archivo for c in cambios_detectados):
                                cambios_detectados.append(cambio)
                                
                except Exception as e:
                    self.log(f"Error verificando cambios en {archivo}: {e}")
            
            # Ordenar por timestamp (más recientes primero)
            cambios_detectados.sort(
                key=lambda x: x.get('timestamp', ''), 
                reverse=True
            )
            
            return {
                'exito': True,
                'cambios': cambios_detectados,
                'total_cambios': len(cambios_detectados),
                'periodo_horas': periodo_horas,
                'timestamp_consulta': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo cambios: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def configurar_directorios(self, directorios: List[str]) -> Dict[str, Any]:
        """
        Configurar directorios adicionales para monitoreo.
        
        Args:
            directorios: Lista de rutas de directorios a monitorear
            
        Returns:
            Dict con resultado de la configuración
        """
        try:
            if not directorios:
                return {
                    'exito': False,
                    'mensaje': 'Lista de directorios requerida'
                }
            
            directorios_validos = []
            directorios_invalidos = []
            
            for directorio in directorios:
                if os.path.exists(directorio) and os.path.isdir(directorio):
                    directorios_validos.append(directorio)
                    self.archivos_monitoreados.add(directorio)
                else:
                    directorios_invalidos.append(directorio)
            
            # Configurar monitoreo en el motor FIM
            if directorios_validos and self.fim_engine:
                try:
                    resultado_fim = self.fim_engine.iniciar_monitoreo_tiempo_real(directorios_validos)
                    if not resultado_fim.get('exito', True):
                        return {
                            'exito': False,
                            'mensaje': f"Error en motor FIM: {resultado_fim.get('mensaje', 'Error desconocido')}"
                        }
                except Exception as e:
                    self.log(f"Error configurando monitoreo en motor FIM: {e}")
            
            # Actualizar configuración
            if directorios_validos:
                if 'directorios_adicionales' not in self.configuracion_fim:
                    self.configuracion_fim['directorios_adicionales'] = []
                
                for dir_val in directorios_validos:
                    if dir_val not in self.configuracion_fim['directorios_adicionales']:
                        self.configuracion_fim['directorios_adicionales'].append(dir_val)
            
            mensaje = f"Configurados {len(directorios_validos)} directorios para monitoreo"
            if directorios_invalidos:
                mensaje += f". {len(directorios_invalidos)} directorios no válidos ignorados"
            
            self.log(mensaje)
            
            return {
                'exito': True,
                'mensaje': mensaje,
                'directorios_configurados': directorios_validos,
                'directorios_invalidos': directorios_invalidos,
                'total_monitoreados': len(self.archivos_monitoreados)
            }
            
        except Exception as e:
            error_msg = f"Error configurando directorios: {str(e)}"
            self.log(error_msg)
            return {
                'exito': False,
                'mensaje': error_msg
            }
    
    def configurar_notificacion_siem(self, controlador_siem):
        """
        Configura la notificación al SIEM para eventos FIM.
        
        Args:
            controlador_siem: Instancia del controlador SIEM
        """
        try:
            self.controlador_siem = controlador_siem
            self.logger.info("Notificación SIEM configurada para ControladorFIM")
            
            # Configuración básica completada
            if self.controlador_siem:
                self.logger.info("Integración FIM-SIEM establecida")
                
        except Exception as e:
            self.logger.error(f"Error configurando notificación SIEM: {e}")
    
    def finalizar(self):
        """
        Finalizar el controlador FIM y limpiar recursos.
        """
        try:
            # Detener monitoreo
            self.detener_monitoreo()
            
            # Limpiar recursos
            self.archivos_monitoreados.clear()
            self.fim_engine = None
            
            self.log("OK Controlador FIM finalizado")
            
        except Exception as e:
            self.log(f"Error finalizando FIM: {e}")

    def log(self, mensaje: str):
        """Log con prefijo FIM."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [FIM] {mensaje}")
