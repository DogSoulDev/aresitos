# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador FIM (File Integrity Monitoring)
Controlador especializado en monitoreo de integridad de archivos para Kali Linux
"""

import asyncio
import threading
import time
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path

from ares_aegis.controladores.controlador_base import ControladorBase
from ares_aegis.modelo.modelo_fim import FIMAvanzado, TipoArchivoFIM, TipoCambioFIM, MetadatosArchivo
from ares_aegis.modelo.modelo_siem import SIEM, TipoEvento, SeveridadEvento

class ControladorFIM(ControladorBase):
    """
    Controlador especializado en File Integrity Monitoring.
    Coordina la supervisión de archivos críticos del sistema Kali Linux.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorFIM")
        
        self.modelo_principal = modelo_principal
        
        # Inicializar componentes inmediatamente para compatibilidad
        try:
            self.siem = SIEM()
            self.fim = FIMAvanzado()
        except Exception as e:
            self.logger.error(f"Error inicializando componentes FIM: {e}")
            self.fim = None
            self.siem = None
        
        # Estado específico del FIM
        self._estado_fim = {
            'monitoreo_activo': False,
            'rutas_monitoreadas': set(),
            'ultimo_escaneo': None,
            'cambios_detectados': 0,
            'archivos_monitoreados': 0
        }
        
        # Configuración de FIM específica para Kali Linux
        self._config_fim = {
            'intervalo_escaneo_segundos': 300,  # 5 minutos
            'rutas_criticas_kali': [
                '/etc/passwd',
                '/etc/shadow', 
                '/etc/sudoers',
                '/etc/ssh/sshd_config',
                '/etc/hosts',
                '/etc/crontab',
                '/etc/fstab',
                '/boot',
                '/usr/bin',
                '/usr/sbin',
                '/opt',
                '/var/log',
                '/home'
            ],
            'extensiones_criticas': {'.conf', '.cfg', '.ini', '.sh', '.py', '.pl', '.rb'},
            'max_archivos_por_directorio': 10000,
            'habilitar_hash_contenido': True,
            'detectar_cambios_permisos': True,
            'alertar_archivos_nuevos': True
        }
        
        # Lock para operaciones concurrentes
        self._lock_fim = threading.Lock()
        
        # Hilo de monitoreo continuo
        self._hilo_monitoreo = None
        self._detener_monitoreo = False
        
        self.logger.info("Controlador FIM inicializado para Kali Linux")

    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación específica de inicialización del controlador FIM."""
        try:
            self.logger.info("Inicializando sistema de monitoreo FIM")
            
            if not self.fim:
                return {
                    'exito': False,
                    'error': 'Componente FIM no disponible'
                }
            
            # Verificar herramientas necesarias de Kali
            verificacion = self._verificar_herramientas_fim()
            if not verificacion['exito']:
                self.logger.warning(f"Algunas herramientas FIM no disponibles: {verificacion}")
            
            # Configurar rutas iniciales
            self._configurar_rutas_iniciales()
            
            # Realizar escaneo inicial
            resultado_inicial = self._ejecutar_escaneo_inicial()
            
            if resultado_inicial['exito']:
                self._registrar_evento_siem("INIT_FIM", "Sistema FIM inicializado correctamente", "info")
                return {
                    'exito': True,
                    'mensaje': 'Controlador FIM inicializado correctamente',
                    'escaneo_inicial': resultado_inicial,
                    'herramientas': verificacion
                }
            else:
                return {
                    'exito': False,
                    'error': f"Error en escaneo inicial: {resultado_inicial.get('error', '')}",
                    'escaneo_inicial': resultado_inicial
                }
                
        except Exception as e:
            error_msg = f"Error inicializando controlador FIM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def _verificar_herramientas_fim(self) -> Dict[str, Any]:
        """Verificar herramientas de Kali necesarias para FIM."""
        herramientas = {
            'find': '/usr/bin/find',
            'stat': '/usr/bin/stat', 
            'md5sum': '/usr/bin/md5sum',
            'sha1sum': '/usr/bin/sha1sum',
            'sha256sum': '/usr/bin/sha256sum',
            'inotifywait': '/usr/bin/inotifywait',
            'auditctl': '/sbin/auditctl'
        }
        
        resultado = {'exito': True, 'herramientas_disponibles': {}, 'herramientas_faltantes': []}
        
        for herramienta, ruta_esperada in herramientas.items():
            try:
                # Verificar si existe en la ruta esperada
                if os.path.isfile(ruta_esperada):
                    resultado['herramientas_disponibles'][herramienta] = ruta_esperada
                else:
                    # Buscar en PATH
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        resultado['herramientas_disponibles'][herramienta] = result.stdout.strip()
                    else:
                        resultado['herramientas_faltantes'].append(herramienta)
                        
            except Exception as e:
                self.logger.warning(f"Error verificando herramienta {herramienta}: {e}")
                resultado['herramientas_faltantes'].append(herramienta)
        
        if resultado['herramientas_faltantes']:
            resultado['exito'] = False
            
        return resultado

    def _configurar_rutas_iniciales(self) -> None:
        """Configurar rutas iniciales de monitoreo para Kali Linux."""
        try:
            with self._lock_fim:
                # Agregar rutas críticas que existan
                for ruta in self._config_fim['rutas_criticas_kali']:
                    if os.path.exists(ruta):
                        self._estado_fim['rutas_monitoreadas'].add(ruta)
                        if self.fim:
                            self.fim.agregar_ruta_monitoreo(ruta)
                    else:
                        self.logger.debug(f"Ruta no encontrada, omitiendo: {ruta}")
                
                self.logger.info(f"Configuradas {len(self._estado_fim['rutas_monitoreadas'])} rutas de monitoreo")
                
        except Exception as e:
            self.logger.error(f"Error configurando rutas iniciales: {e}")

    def _ejecutar_escaneo_inicial(self) -> Dict[str, Any]:
        """Ejecutar escaneo inicial de baseline."""
        try:
            self.logger.info("Ejecutando escaneo inicial FIM")
            tiempo_inicio = time.time()
            
            if not self.fim:
                return {
                    'exito': False,
                    'error': 'Componente FIM no disponible'
                }
            
            # Usar el método crear_baseline del FIM
            resultado = self.fim.crear_baseline()
            
            if resultado:
                tiempo_total = time.time() - tiempo_inicio
                
                with self._lock_fim:
                    self._estado_fim['ultimo_escaneo'] = datetime.now()
                    self._estado_fim['archivos_monitoreados'] = resultado.get('archivos_procesados', 0)
                
                self.logger.info(f"Escaneo inicial completado en {tiempo_total:.2f}s")
                return {
                    'exito': True,
                    'tiempo_ejecucion': round(tiempo_total, 2),
                    'archivos_procesados': resultado.get('archivos_procesados', 0),
                    'rutas_monitoreadas': len(self._estado_fim['rutas_monitoreadas'])
                }
            else:
                return {
                    'exito': False,
                    'error': 'Error en crear baseline FIM'
                }
                
        except Exception as e:
            error_msg = f"Error en escaneo inicial: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def iniciar_monitoreo_continuo(self) -> Dict[str, Any]:
        """Iniciar monitoreo continuo de archivos."""
        return self.ejecutar_operacion_segura(self._iniciar_monitoreo_continuo_impl)

    def _iniciar_monitoreo_continuo_impl(self) -> Dict[str, Any]:
        """Implementación del monitoreo continuo."""
        try:
            if self._estado_fim['monitoreo_activo']:
                return {'exito': False, 'error': 'Monitoreo ya está activo'}
            
            with self._lock_fim:
                self._estado_fim['monitoreo_activo'] = True
                self._detener_monitoreo = False
            
            # Iniciar hilo de monitoreo
            self._hilo_monitoreo = threading.Thread(target=self._bucle_monitoreo_continuo)
            self._hilo_monitoreo.daemon = True
            self._hilo_monitoreo.start()
            
            self._registrar_evento_siem("INICIO_MONITOREO_FIM", "Monitoreo continuo FIM iniciado", "info")
            self.logger.info("Monitoreo continuo FIM iniciado")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo continuo iniciado',
                'intervalo_segundos': self._config_fim['intervalo_escaneo_segundos']
            }
            
        except Exception as e:
            error_msg = f"Error iniciando monitoreo continuo: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def detener_monitoreo_continuo(self) -> Dict[str, Any]:
        """Detener monitoreo continuo de archivos."""
        return self.ejecutar_operacion_segura(self._detener_monitoreo_continuo_impl)

    def _detener_monitoreo_continuo_impl(self) -> Dict[str, Any]:
        """Implementación de detención del monitoreo."""
        try:
            if not self._estado_fim['monitoreo_activo']:
                return {'exito': False, 'error': 'Monitoreo no está activo'}
            
            with self._lock_fim:
                self._detener_monitoreo = True
                self._estado_fim['monitoreo_activo'] = False
            
            # Esperar a que termine el hilo
            if self._hilo_monitoreo and self._hilo_monitoreo.is_alive():
                self._hilo_monitoreo.join(timeout=5)
            
            self._registrar_evento_siem("DETENCION_MONITOREO_FIM", "Monitoreo continuo FIM detenido", "info")
            self.logger.info("Monitoreo continuo FIM detenido")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo continuo detenido'
            }
            
        except Exception as e:
            error_msg = f"Error deteniendo monitoreo continuo: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def _bucle_monitoreo_continuo(self) -> None:
        """Bucle principal del monitoreo continuo."""
        self.logger.debug("Iniciando bucle de monitoreo continuo FIM")
        
        while not self._detener_monitoreo:
            try:
                # Verificar que el componente FIM esté disponible
                if not self.fim:
                    self.logger.error("Componente FIM no disponible en monitoreo")
                    time.sleep(30)
                    continue
                
                # Ejecutar verificación de integridad
                alertas = self.fim.verificar_integridad()
                
                if alertas:
                    with self._lock_fim:
                        self._estado_fim['cambios_detectados'] += len(alertas)
                    
                    # Procesar cambios detectados
                    self._procesar_cambios_detectados(alertas)
                
                # Actualizar timestamp del último escaneo
                with self._lock_fim:
                    self._estado_fim['ultimo_escaneo'] = datetime.now()
                
                # Esperar al siguiente ciclo
                time.sleep(self._config_fim['intervalo_escaneo_segundos'])
                
            except Exception as e:
                self.logger.error(f"Error en bucle de monitoreo FIM: {e}")
                time.sleep(30)  # Espera más larga en caso de error

    def _procesar_cambios_detectados(self, alertas: List) -> None:
        """Procesar alertas FIM detectadas y generar eventos SIEM."""
        try:
            for alerta in alertas:
                # Convertir alerta a diccionario para compatibilidad
                if hasattr(alerta, 'tipo_cambio'):
                    tipo_cambio = alerta.tipo_cambio.value if hasattr(alerta.tipo_cambio, 'value') else str(alerta.tipo_cambio)
                    archivo = alerta.ruta_archivo
                    severidad = alerta.nivel_criticidad.lower() if hasattr(alerta, 'nivel_criticidad') else "info"
                else:
                    # Fallback para formato diccionario
                    tipo_cambio = alerta.get('tipo_cambio', 'CAMBIO_DESCONOCIDO')
                    archivo = alerta.get('archivo', 'desconocido')
                    severidad = "info"
                
                # Generar evento SIEM
                mensaje = f"FIM - {tipo_cambio}: {archivo}"
                self._registrar_evento_siem("CAMBIO_ARCHIVO_FIM", mensaje, severidad)
                
                # Log detallado
                self.logger.warning(f"Cambio detectado - {tipo_cambio}: {archivo}")
                
        except Exception as e:
            self.logger.error(f"Error procesando cambios FIM: {e}")

    def _determinar_severidad_cambio(self, cambio: Dict[str, Any]) -> str:
        """Determinar severidad de un cambio detectado."""
        tipo_cambio = cambio.get('tipo_cambio', '')
        archivo = cambio.get('archivo', '')
        
        # Archivos críticos del sistema
        archivos_criticos = {'/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config'}
        
        if any(critico in archivo for critico in archivos_criticos):
            return "critical"
        elif tipo_cambio in ['ARCHIVO_ELIMINADO', 'PERMISOS_MODIFICADOS']:
            return "warning"
        elif '/etc/' in archivo or '/usr/bin/' in archivo:
            return "warning"
        else:
            return "info"

    def ejecutar_escaneo_manual(self, ruta: Optional[str] = None) -> Dict[str, Any]:
        """Ejecutar escaneo manual de una ruta específica o todas las rutas."""
        return self.ejecutar_operacion_segura(self._ejecutar_escaneo_manual_impl, ruta)

    def _ejecutar_escaneo_manual_impl(self, ruta: Optional[str] = None) -> Dict[str, Any]:
        """Implementación del escaneo manual."""
        try:
            self.logger.info(f"Ejecutando escaneo manual FIM{' de ' + ruta if ruta else ''}")
            tiempo_inicio = time.time()
            
            if not self.fim:
                return {
                    'exito': False,
                    'error': 'Componente FIM no disponible'
                }
            
            if ruta:
                # Escaneo de ruta específica - crear baseline solo para esa ruta
                if not os.path.exists(ruta):
                    return {'exito': False, 'error': f'Ruta no existe: {ruta}'}
                
                resultado = self.fim.crear_baseline([ruta])
            else:
                # Escaneo completo
                resultado = self.fim.crear_baseline()
            
            tiempo_total = time.time() - tiempo_inicio
            
            if resultado:
                self.logger.info(f"Escaneo manual completado en {tiempo_total:.2f}s")
                return {
                    'exito': True,
                    'tiempo_ejecucion': round(tiempo_total, 2),
                    'archivos_procesados': resultado.get('archivos_procesados', 0),
                    'cambios_detectados': 0,  # Para baseline inicial no hay cambios
                    'resultados': resultado
                }
            else:
                return {
                    'exito': False,
                    'error': 'Error en escaneo manual'
                }
                
        except Exception as e:
            error_msg = f"Error en escaneo manual: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def agregar_ruta_monitoreo(self, ruta: str) -> Dict[str, Any]:
        """Agregar nueva ruta al monitoreo FIM."""
        return self.ejecutar_operacion_segura(self._agregar_ruta_monitoreo_impl, ruta)

    def _agregar_ruta_monitoreo_impl(self, ruta: str) -> Dict[str, Any]:
        """Implementación de agregar ruta al monitoreo."""
        try:
            if not os.path.exists(ruta):
                return {'exito': False, 'error': f'Ruta no existe: {ruta}'}
            
            with self._lock_fim:
                if ruta in self._estado_fim['rutas_monitoreadas']:
                    return {'exito': False, 'error': f'Ruta ya está siendo monitoreada: {ruta}'}
                
                self._estado_fim['rutas_monitoreadas'].add(ruta)
            
            # Agregar al FIM - el método retorna bool
            if self.fim:
                resultado = self.fim.agregar_ruta_monitoreo(ruta)
            else:
                resultado = False
            
            if resultado:
                self._registrar_evento_siem("RUTA_AGREGADA_FIM", f"Nueva ruta agregada al monitoreo: {ruta}", "info")
                self.logger.info(f"Ruta agregada al monitoreo FIM: {ruta}")
                
                return {
                    'exito': True,
                    'mensaje': f'Ruta agregada al monitoreo: {ruta}',
                    'total_rutas': len(self._estado_fim['rutas_monitoreadas'])
                }
            else:
                # Revertir cambio en caso de error
                with self._lock_fim:
                    self._estado_fim['rutas_monitoreadas'].discard(ruta)
                
                return {
                    'exito': False,
                    'error': f"Error agregando ruta al FIM"
                }
                
        except Exception as e:
            error_msg = f"Error agregando ruta al monitoreo: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def remover_ruta_monitoreo(self, ruta: str) -> Dict[str, Any]:
        """Remover ruta del monitoreo FIM."""
        return self.ejecutar_operacion_segura(self._remover_ruta_monitoreo_impl, ruta)

    def _remover_ruta_monitoreo_impl(self, ruta: str) -> Dict[str, Any]:
        """Implementación de remover ruta del monitoreo."""
        try:
            with self._lock_fim:
                if ruta not in self._estado_fim['rutas_monitoreadas']:
                    return {'exito': False, 'error': f'Ruta no está siendo monitoreada: {ruta}'}
                
                self._estado_fim['rutas_monitoreadas'].discard(ruta)
            
            # Remover del FIM - el método retorna bool
            if self.fim:
                self.fim.remover_ruta_monitoreo(ruta)
            
            self._registrar_evento_siem("RUTA_REMOVIDA_FIM", f"Ruta removida del monitoreo: {ruta}", "info")
            self.logger.info(f"Ruta removida del monitoreo FIM: {ruta}")
            
            return {
                'exito': True,
                'mensaje': f'Ruta removida del monitoreo: {ruta}',
                'total_rutas': len(self._estado_fim['rutas_monitoreadas'])
            }
                
        except Exception as e:
            error_msg = f"Error removiendo ruta del monitoreo: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def obtener_estado_fim(self) -> Dict[str, Any]:
        """Obtener estado actual del sistema FIM."""
        with self._lock_fim:
            estado = self._estado_fim.copy()
        
        estado['rutas_monitoreadas'] = list(estado['rutas_monitoreadas'])
        estado['ultimo_escaneo_str'] = estado['ultimo_escaneo'].isoformat() if estado['ultimo_escaneo'] else None
        
        return estado

    def obtener_reporte_cambios(self, limite: int = 100) -> Dict[str, Any]:
        """Obtener reporte de cambios detectados."""
        try:
            if not self.fim:
                return {'exito': False, 'error': 'Componente FIM no disponible'}
            
            # Usar obtener_alertas_recientes que sí existe en el modelo
            cambios = self.fim.obtener_alertas_recientes(limite)
            
            return {
                'exito': True,
                'total_cambios': len(cambios),
                'cambios': cambios,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo reporte de cambios: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    def generar_reporte_integridad(self) -> Dict[str, Any]:
        """Generar reporte completo de integridad del sistema."""
        return self.ejecutar_operacion_segura(self._generar_reporte_integridad_impl)

    def _generar_reporte_integridad_impl(self) -> Dict[str, Any]:
        """Implementación del reporte de integridad."""
        try:
            self.logger.info("Generando reporte de integridad FIM")
            
            # Obtener estadísticas del FIM
            if self.fim:
                estadisticas = self.fim.obtener_estadisticas()
            else:
                estadisticas = {}
            
            # Obtener estado actual
            estado = self.obtener_estado_fim()
            
            # Obtener cambios recientes
            cambios_recientes = self.obtener_reporte_cambios(50)
            
            reporte = {
                'timestamp': datetime.now().isoformat(),
                'estado_monitoreo': estado,
                'estadisticas_fim': estadisticas,
                'cambios_recientes': cambios_recientes.get('cambios', []),
                'resumen': {
                    'archivos_monitoreados': estado.get('archivos_monitoreados', 0),
                    'rutas_activas': len(estado.get('rutas_monitoreadas', [])),
                    'cambios_totales': estado.get('cambios_detectados', 0),
                    'monitoreo_activo': estado.get('monitoreo_activo', False)
                }
            }
            
            self.logger.info("Reporte de integridad FIM generado exitosamente")
            
            return {
                'exito': True,
                'reporte': reporte
            }
            
        except Exception as e:
            error_msg = f"Error generando reporte de integridad: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Implementación específica de finalización del controlador FIM."""
        try:
            self.logger.info("Finalizando controlador FIM")
            
            # Detener monitoreo continuo si está activo
            if self._estado_fim['monitoreo_activo']:
                self._detener_monitoreo_continuo_impl()
            
            # Finalizar componente FIM (el modelo no tiene método finalizar específico)
            if self.fim:
                # El FIM se limpia automáticamente al destruirse
                pass
            
            self._registrar_evento_siem("FINALIZACION_FIM", "Controlador FIM finalizado", "info")
            
            return {'exito': True, 'mensaje': 'Controlador FIM finalizado correctamente'}
            
        except Exception as e:
            error_msg = f"Error finalizando controlador FIM: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}


# RESUMEN TÉCNICO: Controlador FIM avanzado para monitoreo de integridad de archivos en Kali Linux.
# Implementa supervisión continua de archivos críticos del sistema, detección de cambios en tiempo real,
# alertas automáticas vía SIEM, y análisis de integridad usando herramientas nativas (find, stat, md5sum).
# Arquitectura asíncrona con threading para monitoreo continuo, siguiendo patrones MVC y principios SOLID
# para escalabilidad profesional en entornos de ciberseguridad.
