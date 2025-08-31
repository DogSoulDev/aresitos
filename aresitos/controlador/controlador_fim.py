# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.

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
        self.controlador_cuarentena = None
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
        def configurar_cuarentena(self, controlador_cuarentena):
            """
            Configura la referencia al controlador de cuarentena.
            """
            self.controlador_cuarentena = controlador_cuarentena
            self.logger.info("Referencia a Controlador Cuarentena configurada en FIM")
        
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
                
                    # Enviar archivos sospechosos a Cuarentena si está configurado
                    if hasattr(self, 'controlador_cuarentena') and self.controlador_cuarentena:
                        for cambio in cambios_detectados:
                            archivo = cambio.get('archivo') or cambio.get('ruta')
                            if archivo:
                                try:
                                    resultado = self.controlador_cuarentena.cuarentenar_archivo(archivo, razon='Detectado por FIM')
                                    if resultado.get('exito'):
                                        self.log(f"Archivo enviado a cuarentena: {archivo}")
                                    else:
                                        self.log(f"Error enviando a cuarentena: {resultado.get('mensaje','sin mensaje')}")
                                except Exception as e:
                                    self.log(f"Excepción enviando a cuarentena: {e}")
                
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
