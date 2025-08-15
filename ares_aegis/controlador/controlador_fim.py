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
import re
import shlex
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from pathlib import Path

from ares_aegis.controlador.controlador_base import ControladorBase
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
        
        # SECURITY: Rutas permitidas para monitoreo FIM en Kali (SECURITY FIX)
        self._rutas_permitidas_fim = {
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
            '/home',
            '/root',
            '/etc'
        }
        
        # SECURITY: Rutas prohibidas (nunca monitorear) (SECURITY FIX)
        self._rutas_prohibidas_fim = {
            '/dev',
            '/proc',
            '/sys',
            '/tmp',
            '/var/tmp',
            '/run',
            '/media',
            '/mnt'
        }
        
        # Hilo de monitoreo continuo
        self._hilo_monitoreo = None
        self._detener_monitoreo = False
        
        self.logger.info("Controlador FIM inicializado para Kali Linux")

    def _validar_ruta_fim(self, ruta: str) -> Dict[str, Any]:
        """
        Valida que la ruta sea segura para monitoreo FIM en Kali Linux.
        KALI OPTIMIZATION: Solo permite rutas críticas del sistema.
        """
        if not ruta or not isinstance(ruta, str):
            return {'valido': False, 'error': 'Ruta no válida'}
        
        # Limpiar espacios y caracteres peligrosos
        ruta = ruta.strip()
        
        # SECURITY FIX: Prevenir command injection
        if re.search(r'[;&|`$(){}[\]<>]', ruta):
            return {'valido': False, 'error': 'Ruta contiene caracteres no seguros'}
        
        # Normalizar ruta para prevenir path traversal
        try:
            ruta_normalizada = os.path.normpath(os.path.abspath(ruta))
        except Exception:
            return {'valido': False, 'error': 'Error normalizando ruta'}
        
        # SECURITY: Verificar que no esté en rutas prohibidas
        for ruta_prohibida in self._rutas_prohibidas_fim:
            if ruta_normalizada.startswith(ruta_prohibida):
                return {
                    'valido': False,
                    'error': f'Ruta {ruta_prohibida} está prohibida para monitoreo FIM'
                }
        
        # KALI SECURITY: Verificar que esté en rutas permitidas
        ruta_permitida = False
        for ruta_permitida_base in self._rutas_permitidas_fim:
            if ruta_normalizada.startswith(ruta_permitida_base) or ruta_normalizada == ruta_permitida_base:
                ruta_permitida = True
                break
        
        if not ruta_permitida:
            return {
                'valido': False,
                'error': f'Ruta {ruta_normalizada} no está en rutas permitidas para monitoreo FIM'
            }
        
        # Verificar que la ruta exista
        if not os.path.exists(ruta_normalizada):
            return {'valido': False, 'error': f'Ruta no existe: {ruta_normalizada}'}
        
        return {
            'valido': True,
            'ruta_sanitizada': ruta_normalizada,
            'tipo': 'file' if os.path.isfile(ruta_normalizada) else 'directory'
        }

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
        """
        Implementación del escaneo manual con validación de seguridad.
        KALI OPTIMIZATION: Solo permite escanear rutas críticas validadas.
        """
        # SECURITY FIX: Validar ruta si se especifica
        if ruta is not None:
            validacion = self._validar_ruta_fim(ruta)
            if not validacion['valido']:
                self.logger.warning(f"Ruta FIM rechazada para escaneo: {validacion['error']}")
                return {
                    'exito': False,
                    'error': f"Ruta no válida: {validacion['error']}",
                    'ruta_rechazada': "[SANITIZADO]"  # SECURITY: No loggear ruta sin validar
                }
            ruta_segura = validacion['ruta_sanitizada']
            tipo_escaneo = f"ruta {validacion['tipo']}"
        else:
            ruta_segura = None
            tipo_escaneo = "completo"
        
        try:
            self.logger.info(f"Ejecutando escaneo manual FIM {tipo_escaneo}")  # SECURITY: No loggear ruta sensible
            tiempo_inicio = time.time()
            
            if not self.fim:
                return {
                    'exito': False,
                    'error': 'Componente FIM no disponible'
                }
            
            if ruta_segura:
                # SECURITY: Escaneo de ruta específica validada
                resultado = self.fim.crear_baseline([ruta_segura])
            else:
                # Escaneo completo
                resultado = self.fim.crear_baseline()
            
            tiempo_total = time.time() - tiempo_inicio
            
            if resultado:
                self.logger.info(f"Escaneo manual {tipo_escaneo} completado en {tiempo_total:.2f}s")  # SECURITY: No loggear ruta sensible
                return {
                    'exito': True,
                    'tiempo_ejecucion': round(tiempo_total, 2),
                    'archivos_procesados': resultado.get('archivos_procesados', 0),
                    'cambios_detectados': 0,  # Para baseline inicial no hay cambios
                    'tipo_escaneo': tipo_escaneo,  # SECURITY: Info de tipo sin ruta sensible
                    'ruta_validacion': validacion if ruta is not None else None,  # SECURITY: Info validación
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
        """
        Implementación de agregar ruta al monitoreo con validación de seguridad.
        KALI OPTIMIZATION: Solo permite rutas críticas del sistema.
        """
        # SECURITY FIX: Validar ruta antes de cualquier operación
        validacion = self._validar_ruta_fim(ruta)
        if not validacion['valido']:
            self.logger.warning(f"Ruta FIM rechazada: {validacion['error']}")
            return {
                'exito': False,
                'error': f"Ruta no válida: {validacion['error']}",
                'ruta_rechazada': "[SANITIZADO]"  # SECURITY: No loggear ruta sin validar
            }
        
        ruta_segura = validacion['ruta_sanitizada']
        
        try:
            with self._lock_fim:
                if ruta_segura in self._estado_fim['rutas_monitoreadas']:
                    return {'exito': False, 'error': f'Ruta ya está siendo monitoreada'}
                
                self._estado_fim['rutas_monitoreadas'].add(ruta_segura)
            
            # Agregar al FIM - el método retorna bool
            if self.fim:
                resultado = self.fim.agregar_ruta_monitoreo(ruta_segura)
            else:
                resultado = False
            
            if resultado:
                self._registrar_evento_siem("RUTA_AGREGADA_FIM", f"Nueva ruta tipo {validacion['tipo']} agregada al monitoreo", "info")  # SECURITY: No loggear ruta sensible
                self.logger.info(f"Ruta {validacion['tipo']} agregada al monitoreo FIM")  # SECURITY: Solo loggear tipo
                
                return {
                    'exito': True,
                    'mensaje': f'Ruta {validacion["tipo"]} agregada al monitoreo',  # SECURITY: No exponer ruta real
                    'ruta_validacion': validacion,  # SECURITY: Info de validación para auditoría
                    'total_rutas': len(self._estado_fim['rutas_monitoreadas'])
                }
            else:
                # Revertir cambio en caso de error
                with self._lock_fim:
                    self._estado_fim['rutas_monitoreadas'].discard(ruta_segura)  # SECURITY: Usar ruta validada
                
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
        """
        Implementación de remover ruta del monitoreo con validación de seguridad.
        KALI OPTIMIZATION: Solo permite remover rutas previamente validadas.
        """
        # SECURITY FIX: Validar ruta antes de cualquier operación
        validacion = self._validar_ruta_fim(ruta)
        if not validacion['valido']:
            self.logger.warning(f"Ruta FIM rechazada para remoción: {validacion['error']}")
            return {
                'exito': False,
                'error': f"Ruta no válida: {validacion['error']}",
                'ruta_rechazada': "[SANITIZADO]"  # SECURITY: No loggear ruta sin validar
            }
        
        ruta_segura = validacion['ruta_sanitizada']
        
        try:
            with self._lock_fim:
                if ruta_segura not in self._estado_fim['rutas_monitoreadas']:
                    return {'exito': False, 'error': f'Ruta no está siendo monitoreada'}
                
                self._estado_fim['rutas_monitoreadas'].discard(ruta_segura)
            
            # Remover del FIM - el método retorna bool
            if self.fim:
                self.fim.remover_ruta_monitoreo(ruta_segura)
            
            self._registrar_evento_siem("RUTA_REMOVIDA_FIM", f"Ruta tipo {validacion['tipo']} removida del monitoreo", "info")  # SECURITY: No loggear ruta sensible
            self.logger.info(f"Ruta {validacion['tipo']} removida del monitoreo FIM")  # SECURITY: Solo loggear tipo
            
            return {
                'exito': True,
                'mensaje': f'Ruta {validacion["tipo"]} removida del monitoreo',  # SECURITY: No exponer ruta real
                'ruta_validacion': validacion,  # SECURITY: Info de validación para auditoría
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
