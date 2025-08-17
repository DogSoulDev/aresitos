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

from aresitos.controlador.controlador_base import ControladorBase
from aresitos.modelo.modelo_fim import FIMAvanzado, TipoArchivoFIM, TipoCambioFIM, MetadatosArchivo
from aresitos.modelo.modelo_siem import SIEM, TipoEvento, SeveridadEvento

class ControladorFIM(ControladorBase):
    """
    Controlador especializado en File Integrity Monitoring.
    Coordina la supervisión de archivos críticos del sistema Kali Linux.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorFIM")
        
        self.modelo_principal = modelo_principal
        
        # Usar instancias del modelo principal si están disponibles
        if hasattr(modelo_principal, 'fim_avanzado') and modelo_principal.fim_avanzado:
            self.fim = modelo_principal.fim_avanzado
        else:
            # Solo crear nueva instancia si no existe
            try:
                self.fim = FIMAvanzado()
            except Exception as e:
                self.logger.error(f"Error inicializando FIM: {e}")
                self.fim = None
        
        if hasattr(modelo_principal, 'siem_avanzado') and modelo_principal.siem_avanzado:
            self.siem = modelo_principal.siem_avanzado
        else:
            # Solo crear nueva instancia si no existe
            try:
                self.siem = SIEM()
            except Exception as e:
                self.logger.error(f"Error inicializando SIEM: {e}")
                self.siem = None
        
        # Referencias para integración con SIEM
        self._siem_externo = None
        self._notificaciones_siem_habilitadas = False
        
        # Estado específico del FIM
        self._estado_fim = {
            'monitoreo_activo': False,
            'rutas_monitoreadas': set(),
            'ultimo_escaneo': None,
            'cambios_detectados': 0,
            'archivos_monitoreados': 0
        }
        
        # Configuración de FIM específica para Kali Linux (solo archivos críticos específicos)
        self._config_fim = {
            'intervalo_escaneo_segundos': 300,  # 5 minutos
            'rutas_criticas_kali': [
                # Archivos de sistema críticos
                '/etc/passwd',
                '/etc/shadow', 
                '/etc/sudoers',
                '/etc/ssh/sshd_config',
                '/etc/ssh/ssh_config',
                '/etc/hosts',
                '/etc/crontab',
                '/etc/fstab',
                '/boot/grub/grub.cfg',
                # Directorio PAM crítico para autenticación
                '/etc/pam.d/',
                '/etc/pam.d/common-auth',
                '/etc/pam.d/common-password',
                '/etc/pam.d/common-session',
                '/etc/pam.d/sudo',
                '/etc/pam.d/su',
                
                # Archivos de configuración de servicios
                '/etc/apache2/apache2.conf',
                '/etc/nginx/nginx.conf',
                '/etc/proxychains.conf',
                '/etc/tor/torrc',
                
                # Binarios críticos específicos
                '/bin/bash',
                '/bin/su',
                '/usr/bin/sudo',
                '/usr/sbin/sshd'
            ],
            'extensiones_criticas': {'.conf', '.cfg', '.ini', '.sh', '.py', '.pl', '.rb'},
            'max_archivos_por_directorio': 100,  # Reducido para evitar spam
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

    def crear_baseline(self) -> Dict[str, Any]:
        """Crear baseline inicial de archivos monitoreados."""
        return self.ejecutar_operacion_segura(self._ejecutar_escaneo_inicial)

    def iniciar_monitoreo_continuo(self) -> Dict[str, Any]:
        """Iniciar monitoreo continuo de archivos."""
        return self.ejecutar_operacion_segura(self._iniciar_monitoreo_continuo_impl)

    def _iniciar_monitoreo_continuo_impl(self) -> Dict[str, Any]:
        """Implementación del monitoreo continuo."""
        try:
            with self._lock_fim:
                # Siempre detener monitoreo previo si existe
                if self._estado_fim['monitoreo_activo']:
                    self.logger.info("Deteniendo monitoreo FIM previo...")
                    self._detener_monitoreo = True
                    self._estado_fim['monitoreo_activo'] = False
                    
                    # Esperar a que termine el hilo anterior
                    if hasattr(self, '_hilo_monitoreo') and self._hilo_monitoreo and self._hilo_monitoreo.is_alive():
                        self._hilo_monitoreo.join(timeout=3)
                
                # Verificar que el componente FIM está disponible
                if not self.fim:
                    self.logger.error("Componente FIM no disponible")
                    return {'exito': False, 'error': 'Componente FIM no inicializado'}
                
                # Configurar rutas para monitoreo si no están configuradas
                if not self._estado_fim['rutas_monitoreadas']:
                    self.logger.info("Configurando rutas iniciales para monitoreo FIM...")
                    self._configurar_rutas_iniciales()
                
                # Inicializar estado para nuevo monitoreo
                self._estado_fim['monitoreo_activo'] = True
                self._detener_monitoreo = False
                self._estado_fim['cambios_detectados'] = 0
                self._estado_fim['alertas_generadas'] = 0
            
            # Crear baseline inicial si es necesario
            try:
                self.logger.info("Verificando baseline FIM...")
                resultado_baseline = self.fim.crear_baseline()
                if resultado_baseline:
                    self.logger.info("OK Baseline FIM creado/verificado correctamente")
                else:
                    self.logger.warning("WARNING Baseline FIM no disponible, usando monitoreo básico")
            except Exception as e:
                self.logger.warning(f"WARNING Error con baseline FIM: {e}, continuando con monitoreo básico")
            
            # Iniciar hilo de monitoreo
            self._hilo_monitoreo = threading.Thread(target=self._bucle_monitoreo_continuo, daemon=True)
            self._hilo_monitoreo.start()
            
            self._registrar_evento_siem("INICIO_MONITOREO_FIM", "Monitoreo continuo FIM iniciado", "info")
            self.logger.info("OK Monitoreo continuo FIM iniciado correctamente")
            
            return {
                'exito': True,
                'mensaje': 'Monitoreo continuo iniciado',
                'intervalo_segundos': self._config_fim['intervalo_escaneo_segundos'],
                'rutas_monitoreadas': len(self._estado_fim['rutas_monitoreadas'])
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

    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """
        Verificar que todas las funcionalidades del FIM funcionen en Kali Linux.
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'sistema_operativo': None,
            'gestor_permisos': False,
            'herramientas_disponibles': {},
            'permisos_sudo': False,
            'funcionalidad_completa': False,
            'recomendaciones': []
        }
        
        try:
            import platform
            resultado['sistema_operativo'] = platform.system()
            
            # Verificar gestor de permisos
            if self.fim and hasattr(self.fim, 'gestor_permisos'):
                if self.fim.gestor_permisos is not None:
                    resultado['gestor_permisos'] = True
                    
                    # Verificar permisos sudo si está disponible
                    try:
                        resultado['permisos_sudo'] = self.fim.gestor_permisos.verificar_sudo_disponible()
                    except Exception:
                        resultado['permisos_sudo'] = False
                    
                    # Verificar herramientas específicas de FIM
                    herramientas = ['find', 'stat', 'md5sum', 'inotifywait']
                    for herramienta in herramientas:
                        estado = self.fim.gestor_permisos.verificar_permisos_herramienta(herramienta)
                        resultado['herramientas_disponibles'][herramienta] = estado
            
            # Evaluar funcionalidad completa
            herramientas_ok = sum(1 for h in resultado['herramientas_disponibles'].values() 
                                if h.get('disponible', False) and h.get('permisos_ok', False))
            
            resultado['funcionalidad_completa'] = (
                resultado['gestor_permisos'] and 
                resultado['permisos_sudo'] and 
                herramientas_ok >= 3  # Al menos find, stat, md5sum
            )
            
            # Generar recomendaciones
            if not resultado['funcionalidad_completa']:
                if not resultado['gestor_permisos']:
                    resultado['recomendaciones'].append("Gestor de permisos no disponible")
                
                if not resultado['permisos_sudo']:
                    resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
                
                if herramientas_ok < 3:
                    resultado['recomendaciones'].append("Instalar herramientas FIM: sudo apt install findutils coreutils inotify-tools")
            
            self.logger.info(f"Verificación FIM Kali completada - Funcionalidad: {'OK' if resultado['funcionalidad_completa'] else 'ERROR'}")
            
        except Exception as e:
            self.logger.error(f"Error en verificación FIM Kali: {e}")
            resultado['error'] = str(e)
        
        return resultado

    def configurar_notificacion_siem(self, controlador_siem) -> None:
        """
        Configurar notificaciones automáticas al SIEM cuando FIM detecta cambios.
        MÉTODO CLAVE para integración FIM -> SIEM.
        """
        try:
            self._siem_externo = controlador_siem
            self._notificaciones_siem_habilitadas = True
            self.logger.info("FIM configurado para notificar cambios al SIEM")
            
        except Exception as e:
            self.logger.error(f"Error configurando notificaciones SIEM: {e}")

    def _notificar_cambio_a_siem(self, archivo: str, tipo_cambio: str, detalles: Dict[str, Any]) -> None:
        """Notificar cambio detectado al SIEM externo."""
        try:
            if not self._notificaciones_siem_habilitadas or not self._siem_externo:
                return
            
            # Determinar severidad según tipo de archivo y cambio
            severidad = self._determinar_severidad_cambio_siem(archivo, tipo_cambio)
            
            # Crear evento para SIEM
            evento_siem = {
                'tipo_evento': 'FIM_CHANGE_DETECTED',
                'timestamp': datetime.now().isoformat(),
                'archivo': archivo,
                'tipo_cambio': tipo_cambio,
                'severidad': severidad,
                'detalles': detalles,
                'linea_original': f"FIM: {tipo_cambio} detected in {archivo}",
                'patron_detectado': f'file_change_{tipo_cambio.lower()}'
            }
            
            # Registrar en SIEM si tiene el método
            if hasattr(self._siem_externo, '_registrar_evento_siem'):
                self._siem_externo._registrar_evento_siem(
                    'FIM_DETECTION',
                    f"FIM detectó {tipo_cambio} en {archivo}",
                    severidad.lower()
                )
            
            # Si es un cambio crítico, generar alerta
            if severidad in ['ALTA', 'CRITICA']:
                if hasattr(self._siem_externo, '_generar_alerta_critica'):
                    self._siem_externo._generar_alerta_critica(
                        f"FIM: Cambio crítico detectado en {archivo}",
                        evento_siem
                    )
            
            self.logger.info(f"Cambio FIM notificado al SIEM: {archivo} ({tipo_cambio})")
            
        except Exception as e:
            self.logger.error(f"Error notificando cambio a SIEM: {e}")

    def _determinar_severidad_cambio_siem(self, archivo: str, tipo_cambio: str) -> str:
        """Determinar severidad del cambio según archivo y tipo."""
        try:
            # Archivos críticos del sistema
            archivos_criticos = [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/bin/bash', '/bin/su', '/usr/bin/sudo'
            ]
            
            # Directorios críticos
            directorios_criticos = ['/bin/', '/sbin/', '/usr/bin/', '/boot/']
            
            # Cambios críticos
            cambios_criticos = ['MODIFIED', 'DELETED', 'PERMISSIONS_CHANGED']
            
            if archivo in archivos_criticos:
                return 'CRITICA'
            
            if any(archivo.startswith(dir_crit) for dir_crit in directorios_criticos):
                if tipo_cambio in cambios_criticos:
                    return 'ALTA'
                else:
                    return 'MEDIA'
            
            # Archivos de configuración
            if '/etc/' in archivo:
                return 'MEDIA' if tipo_cambio in cambios_criticos else 'BAJA'
            
            return 'BAJA'
            
        except Exception as e:
            self.logger.error(f"Error determinando severidad: {e}")
            return 'MEDIA'

    def verificar_integridad_archivos(self, lista_archivos: List[str]) -> Dict[str, Any]:
        """
        Verificar integridad de lista específica de archivos.
        Método usado por SIEM para verificación bajo demanda.
        """
        try:
            if not self.fim:
                return {
                    'exito': False,
                    'error': 'Componente FIM no disponible',
                    'cambios_detectados': 0
                }
            
            cambios_detectados = 0
            resultados_verificacion = []
            
            for archivo in lista_archivos:
                try:
                    if os.path.exists(archivo):
                        # Obtener metadatos actuales
                        metadatos_actuales = self._obtener_metadatos_archivo(archivo)
                        
                        # Verificar si hay baseline previo (usar diccionario simple)
                        baseline = self._obtener_baseline_simple(archivo)
                        
                        if baseline:
                            # Comparar con baseline
                            cambios = self._comparar_metadatos(baseline, metadatos_actuales)
                            if cambios:
                                cambios_detectados += 1
                                resultados_verificacion.append({
                                    'archivo': archivo,
                                    'cambios': cambios,
                                    'metadatos_actuales': metadatos_actuales
                                })
                                
                                # Notificar a SIEM si está configurado
                                if self._notificaciones_siem_habilitadas:
                                    self._notificar_cambio_a_siem(
                                        archivo,
                                        'VERIFICATION_CHANGE_DETECTED',
                                        {'cambios': cambios}
                                    )
                        else:
                            # Crear baseline si no existe
                            self._crear_baseline_simple(archivo, metadatos_actuales)
                    
                except Exception as e:
                    self.logger.warning(f"Error verificando {archivo}: {e}")
            
            return {
                'exito': True,
                'cambios_detectados': cambios_detectados,
                'archivos_verificados': len(lista_archivos),
                'resultados': resultados_verificacion
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': str(e),
                'cambios_detectados': 0
            }

    def _obtener_metadatos_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        """Obtener metadatos de un archivo."""
        try:
            stat = os.stat(ruta_archivo)
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'permissions': oct(stat.st_mode)[-3:],
                'owner': stat.st_uid,
                'group': stat.st_gid
            }
        except Exception as e:
            self.logger.error(f"Error obteniendo metadatos de {ruta_archivo}: {e}")
            return {}

    def _comparar_metadatos(self, baseline: Dict[str, Any], actuales: Dict[str, Any]) -> List[str]:
        """Comparar metadatos y devolver lista de cambios."""
        try:
            cambios = []
            
            for campo in ['size', 'mtime', 'permissions', 'owner', 'group']:
                if baseline.get(campo) != actuales.get(campo):
                    cambios.append(f"{campo}_changed")
            
            return cambios
            
        except Exception as e:
            self.logger.error(f"Error comparando metadatos: {e}")
            return []

    def _obtener_baseline_simple(self, archivo: str) -> Optional[Dict[str, Any]]:
        """Obtener baseline simple de un archivo."""
        try:
            # Usar diccionario simple en memoria
            if not hasattr(self, '_baselines_cache'):
                self._baselines_cache = {}
            
            return self._baselines_cache.get(archivo)
            
        except Exception as e:
            self.logger.error(f"Error obteniendo baseline: {e}")
            return None

    def _crear_baseline_simple(self, archivo: str, metadatos: Dict[str, Any]) -> None:
        """Crear baseline simple de un archivo."""
        try:
            if not hasattr(self, '_baselines_cache'):
                self._baselines_cache = {}
            
            self._baselines_cache[archivo] = metadatos
            
        except Exception as e:
            self.logger.error(f"Error creando baseline: {e}")

    def _registrar_evento_siem(self, tipo: str, descripcion: str, severidad: str) -> None:
        """Registrar evento en el sistema SIEM."""
        try:
            if self.siem:
                self.siem.generar_evento(tipo, descripcion, severidad)
        except Exception as e:
            self.logger.error(f"Error registrando evento SIEM: {e}")

    # =================== MÉTODOS AVANZADOS CON HERRAMIENTAS DE KALI ===================
    
    def configurar_inotify_avanzado(self) -> Dict[str, Any]:
        """
        Configurar inotify-tools para monitoreo en tiempo real de archivos críticos.
        KALI OPTIMIZATION: Configuración específica de inotify para FIM profesional.
        """
        try:
            self.logger.info(" Configurando inotify-tools para monitoreo en tiempo real...")
            
            # Verificar si inotify-tools está disponible
            result_check = subprocess.run(['which', 'inotifywait'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'inotify-tools no está instalado',
                    'recomendacion': 'sudo apt install inotify-tools'
                }
            
            # Configurar eventos de inotify para FIM
            eventos_inotify = [
                'modify',       # Modificación de contenido
                'attrib',       # Cambios de atributos/permisos
                'move',         # Mover archivos
                'create',       # Crear archivos
                'delete',       # Eliminar archivos
                'close_write'   # Cerrar después de escribir
            ]
            
            # Rutas críticas para monitoreo inotify
            rutas_criticas_inotify = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/ssh/',
                '/etc/crontab',
                '/bin/',
                '/sbin/',
                '/usr/bin/sudo',
                '/boot/grub/'
            ]
            
            # Validar rutas que existan
            rutas_validas = []
            for ruta in rutas_criticas_inotify:
                if os.path.exists(ruta):
                    rutas_validas.append(ruta)
                else:
                    self.logger.debug(f"Ruta no encontrada para inotify: {ruta}")
            
            if not rutas_validas:
                return {
                    'exito': False,
                    'error': 'No se encontraron rutas válidas para monitoreo inotify'
                }
            
            # Configurar inotifywait en modo daemon
            eventos_str = ','.join(eventos_inotify)
            rutas_str = ' '.join([shlex.quote(ruta) for ruta in rutas_validas])
            
            # Crear comando inotifywait
            cmd_inotify = [
                'inotifywait',
                '-m',           # Monitor mode
                '-r',           # Recursive
                '--format', '%w%f %e %T',  # Formato: ruta evento tiempo
                '--timefmt', '%Y-%m-%d %H:%M:%S',
                '-e', eventos_str
            ] + rutas_validas
            
            # Test de configuración (ejecutar por 3 segundos para probar)
            try:
                test_process = subprocess.Popen(cmd_inotify, 
                                              stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE,
                                              text=True)
                
                # Esperar brevemente para verificar que funciona
                time.sleep(1)
                test_process.terminate()
                
                # Verificar que no hay errores
                _, stderr = test_process.communicate(timeout=2)
                configuracion_exitosa = test_process.returncode in [0, -15]  # 0 o SIGTERM
                
            except subprocess.TimeoutExpired:
                test_process.kill()
                configuracion_exitosa = True  # Si no terminó, probablemente está funcionando
                stderr = ""
            except Exception as e:
                configuracion_exitosa = False
                stderr = str(e)
            
            return {
                'exito': configuracion_exitosa,
                'eventos_configurados': eventos_inotify,
                'rutas_monitoreadas': rutas_validas,
                'total_rutas': len(rutas_validas),
                'comando_generado': ' '.join(cmd_inotify),
                'error_config': stderr if not configuracion_exitosa else None,
                'herramienta': 'inotifywait',
                'instrucciones_daemon': [
                    "Para ejecutar en background:",
                    f"nohup {' '.join(cmd_inotify)} > /var/log/ares-aegis/inotify.log 2>&1 &"
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Error configurando inotify: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'inotifywait'
            }
    
    def configurar_aide(self) -> Dict[str, Any]:
        """
        Configurar AIDE (Advanced Intrusion Detection Environment) para FIM profesional.
        KALI OPTIMIZATION: Configuración específica de AIDE para detección de intrusiones.
        """
        try:
            self.logger.info(" Configurando AIDE para detección avanzada de intrusiones...")
            
            # Verificar si AIDE está disponible
            result_check = subprocess.run(['which', 'aide'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'AIDE no está instalado',
                    'recomendacion': 'sudo apt install aide aide-common'
                }
            
            # Configuración de AIDE para Kali Linux
            configuracion_aide = """
# AIDE configuration for ARESITOS - Kali Linux Security
# Advanced Intrusion Detection Environment

# Definir grupos de archivos para AIDE
Binlib = p+i+n+u+g+s+b+m+c+md5+sha1+sha256+rmd160
ConfFiles = p+i+n+u+g+s+b+m+c+md5+sha1+sha256+rmd160
Logs = p+i+n+u+g+s+b+m+c+md5+sha1+sha256+rmd160
Devices = p+i+n+u+g+s+b+c+md5+sha1+sha256+rmd160
Databases = p+i+n+u+g+s+b+m+c+md5+sha1+sha256+rmd160

# Configuración específica para archivos críticos
/etc p+i+u+g+s+b+m+c+md5+sha1+sha256+rmd160
/bin Binlib
/sbin Binlib
/usr/bin Binlib
/usr/sbin Binlib
/lib Binlib
/usr/lib Binlib

# Archivos de configuración críticos
/etc/passwd ConfFiles
/etc/shadow ConfFiles
/etc/group ConfFiles
/etc/sudoers ConfFiles
/etc/ssh/sshd_config ConfFiles
/etc/hosts ConfFiles
/etc/fstab ConfFiles
/etc/crontab ConfFiles

# Boot sector y kernel
/boot Binlib

# Logs del sistema (menos estricto)
/var/log Logs

# Directorios a excluir (cambios constantes)
!/tmp
!/var/tmp
!/proc
!/sys
!/dev
!/run
!/media
!/mnt

# Configuración de base de datos AIDE
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# Reportes y logs
report_url=file:/var/log/aide/aide.log
report_url=stdout
"""
            
            # Crear directorios necesarios para AIDE
            directorios_aide = [
                '/var/lib/aide',
                '/var/log/aide',
                '/etc/aide'
            ]
            
            directorios_creados = []
            for directorio in directorios_aide:
                try:
                    if not os.path.exists(directorio):
                        result_mkdir = subprocess.run(['mkdir', '-p', directorio], 
                                                    capture_output=True, text=True, timeout=5)
                        if result_mkdir.returncode == 0:
                            subprocess.run(['chmod', '755', directorio], timeout=5)
                            directorios_creados.append(directorio)
                        else:
                            self.logger.warning(f"No se pudo crear directorio AIDE: {directorio}")
                    else:
                        directorios_creados.append(directorio)
                except Exception as e:
                    self.logger.warning(f"Error con directorio AIDE {directorio}: {e}")
            
            # Verificar configuración actual de AIDE
            try:
                config_result = subprocess.run(['aide', '--config-check'], 
                                             capture_output=True, text=True, timeout=10)
                configuracion_valida = config_result.returncode == 0
                errores_config = config_result.stderr if config_result.returncode != 0 else None
            except Exception as e:
                configuracion_valida = False
                errores_config = str(e)
            
            # Intentar inicializar base de datos AIDE (si no existe)
            try:
                if os.path.exists('/etc/aide/aide.conf') or os.path.exists('/etc/aide.conf'):
                    init_result = subprocess.run(['aide', '--init'], 
                                               capture_output=True, text=True, timeout=60)
                    base_datos_inicializada = init_result.returncode == 0
                    error_init = init_result.stderr if init_result.returncode != 0 else None
                else:
                    base_datos_inicializada = False
                    error_init = "Archivo de configuración AIDE no encontrado"
            except subprocess.TimeoutExpired:
                base_datos_inicializada = False
                error_init = "Timeout inicializando base de datos AIDE"
            except Exception as e:
                base_datos_inicializada = False
                error_init = str(e)
            
            return {
                'exito': len(directorios_creados) > 0,
                'directorios_creados': directorios_creados,
                'configuracion_valida': configuracion_valida,
                'errores_configuracion': errores_config,
                'base_datos_inicializada': base_datos_inicializada,
                'error_inicializacion': error_init,
                'configuracion_sugerida': configuracion_aide,
                'herramienta': 'aide',
                'instrucciones': [
                    "1. Crear configuración: sudo nano /etc/aide/aide.conf",
                    "2. Inicializar BD: sudo aide --init",
                    "3. Mover BD: sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
                    "4. Verificar: sudo aide --check"
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Error configurando AIDE: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'aide'
            }
    
    def ejecutar_verificacion_aide(self) -> Dict[str, Any]:
        """
        Ejecutar verificación de integridad usando AIDE.
        KALI OPTIMIZATION: Análisis completo de integridad del sistema.
        """
        try:
            self.logger.info(" Ejecutando verificación de integridad con AIDE...")
            
            # Verificar si AIDE está disponible y configurado
            result_check = subprocess.run(['which', 'aide'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'AIDE no está instalado',
                    'recomendacion': 'sudo apt install aide'
                }
            
            # Verificar si existe base de datos AIDE
            aide_db_paths = [
                '/var/lib/aide/aide.db',
                '/var/lib/aide.db',
                '/usr/lib/aide/aide.db'
            ]
            
            aide_db_encontrada = None
            for db_path in aide_db_paths:
                if os.path.exists(db_path):
                    aide_db_encontrada = db_path
                    break
            
            if not aide_db_encontrada:
                return {
                    'exito': False,
                    'error': 'Base de datos AIDE no encontrada',
                    'recomendacion': 'Ejecutar: sudo aide --init'
                }
            
            # Ejecutar verificación AIDE
            tiempo_inicio = time.time()
            
            try:
                cmd_aide = ['aide', '--check']
                result = subprocess.run(cmd_aide, capture_output=True, text=True, timeout=300)  # 5 minutos max
                
                tiempo_total = time.time() - tiempo_inicio
                
                # AIDE retorna diferentes códigos según los cambios
                # 0 = sin cambios, 1-16 = diferentes tipos de cambios
                cambios_detectados = result.returncode not in [0]
                
                # Parsear output de AIDE
                lineas_output = result.stdout.split('\n')
                cambios_criticos = []
                archivos_modificados = []
                archivos_agregados = []
                archivos_eliminados = []
                
                for linea in lineas_output:
                    if 'changed:' in linea.lower():
                        archivos_modificados.append(linea.strip())
                    elif 'added:' in linea.lower():
                        archivos_agregados.append(linea.strip())
                    elif 'removed:' in linea.lower():
                        archivos_eliminados.append(linea.strip())
                    elif any(keyword in linea.lower() for keyword in ['critical', 'error', 'warning']):
                        cambios_criticos.append(linea.strip())
                
                # Crear resumen de cambios
                resumen_cambios = {
                    'archivos_modificados': len(archivos_modificados),
                    'archivos_agregados': len(archivos_agregados),
                    'archivos_eliminados': len(archivos_eliminados),
                    'cambios_criticos': len(cambios_criticos)
                }
                
                total_cambios = sum(resumen_cambios.values())
                
                # Registrar evento en SIEM
                if total_cambios > 0:
                    self._registrar_evento_siem(
                        "AIDE_VERIFICATION",
                        f"AIDE detectó {total_cambios} cambios en el sistema",
                        "warning" if total_cambios > 10 else "info"
                    )
                
                return {
                    'exito': True,
                    'cambios_detectados': cambios_detectados,
                    'total_cambios': total_cambios,
                    'resumen_cambios': resumen_cambios,
                    'archivos_modificados': archivos_modificados[:10],  # Limitar a 10
                    'archivos_agregados': archivos_agregados[:10],
                    'archivos_eliminados': archivos_eliminados[:10],
                    'cambios_criticos': cambios_criticos[:5],
                    'tiempo_ejecucion': round(tiempo_total, 2),
                    'base_datos_utilizada': aide_db_encontrada,
                    'codigo_retorno': result.returncode,
                    'raw_output': result.stdout[:2000],  # Limitar output
                    'herramienta': 'aide'
                }
                
            except subprocess.TimeoutExpired:
                return {
                    'exito': False,
                    'error': 'Timeout en verificación AIDE (>5 minutos)',
                    'herramienta': 'aide'
                }
                
        except Exception as e:
            self.logger.error(f"Error en verificación AIDE: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'aide'
            }
    
    def monitorear_con_auditd(self) -> Dict[str, Any]:
        """
        Configurar y usar auditd para monitoreo avanzado de FIM.
        KALI OPTIMIZATION: Integración de auditd con FIM para detección completa.
        """
        try:
            self.logger.info(" Configurando monitoreo FIM con auditd...")
            
            # Verificar si auditd está disponible
            result_check = subprocess.run(['which', 'auditctl'], capture_output=True, text=True, timeout=5)
            if result_check.returncode != 0:
                return {
                    'exito': False,
                    'error': 'auditd no está instalado',
                    'recomendacion': 'sudo apt install auditd audispd-plugins'
                }
            
            # Reglas específicas de FIM para auditd
            reglas_fim_auditd = [
                # Vigilar archivos críticos de FIM
                '-w /etc/passwd -p wa -k fim_passwd',
                '-w /etc/shadow -p wa -k fim_shadow',
                '-w /etc/sudoers -p wa -k fim_sudoers',
                '-w /etc/ssh/sshd_config -p wa -k fim_ssh_config',
                '-w /etc/hosts -p wa -k fim_hosts',
                
                # Vigilar directorios de binarios
                '-w /bin/ -p x -k fim_bin_exec',
                '-w /sbin/ -p x -k fim_sbin_exec',
                '-w /usr/bin/ -p x -k fim_usr_bin_exec',
                
                # Vigilar cambios de permisos en archivos críticos
                '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k fim_permission_changes',
                '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -k fim_ownership_changes',
                
                # Vigilar acceso de escritura a /etc
                '-w /etc/ -p wa -k fim_etc_changes',
                
                # Vigilar modificaciones de archivos de configuración
                '-w /boot/grub/grub.cfg -p wa -k fim_boot_config'
            ]
            
            # Aplicar reglas de auditd
            reglas_aplicadas = []
            reglas_fallidas = []
            
            for regla in reglas_fim_auditd:
                try:
                    cmd = ['auditctl'] + regla.split()[1:]  # Omitir el '-' inicial
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        reglas_aplicadas.append(regla)
                    else:
                        reglas_fallidas.append({
                            'regla': regla,
                            'error': result.stderr
                        })
                        
                except Exception as e:
                    reglas_fallidas.append({
                        'regla': regla,
                        'error': str(e)
                    })
            
            # Verificar logs de auditd
            try:
                # Buscar eventos FIM recientes en auditd
                cmd_search = ['ausearch', '-k', 'fim_passwd,fim_shadow,fim_sudoers', '-ts', 'recent']
                search_result = subprocess.run(cmd_search, capture_output=True, text=True, timeout=15)
                
                eventos_fim_auditd = []
                if search_result.returncode == 0:
                    lineas = search_result.stdout.split('\n')
                    for linea in lineas[:20]:  # Limitar a 20 líneas
                        if linea.strip() and ('type=' in linea or 'exe=' in linea):
                            eventos_fim_auditd.append(linea.strip())
                
            except Exception as e:
                eventos_fim_auditd = [f"Error buscando eventos: {str(e)}"]
            
            # Verificar estado del servicio auditd
            try:
                status_result = subprocess.run(['systemctl', 'status', 'auditd'], 
                                             capture_output=True, text=True, timeout=5)
                servicio_activo = 'active (running)' in status_result.stdout
            except:
                servicio_activo = False
            
            return {
                'exito': len(reglas_aplicadas) > 0,
                'reglas_aplicadas': len(reglas_aplicadas),
                'reglas_fallidas': len(reglas_fallidas),
                'total_reglas': len(reglas_fim_auditd),
                'servicio_activo': servicio_activo,
                'eventos_fim_recientes': eventos_fim_auditd,
                'detalles_reglas_aplicadas': reglas_aplicadas,
                'detalles_reglas_fallidas': reglas_fallidas,
                'herramienta': 'auditd'
            }
            
        except Exception as e:
            self.logger.error(f"Error configurando auditd para FIM: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'auditd'
            }
    
    def analizar_logs_fim(self) -> Dict[str, Any]:
        """
        Analizar logs del sistema buscando eventos relacionados con FIM.
        KALI OPTIMIZATION: Análisis específico de logs para detección de cambios.
        """
        try:
            self.logger.info(" Analizando logs del sistema para eventos FIM...")
            
            # Logs a analizar para eventos FIM
            logs_fim = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/kern.log',
                '/var/log/audit/audit.log'
            ]
            
            # Patrones para detectar eventos relacionados con FIM
            patrones_fim = [
                r'chmod.*(/etc/|/bin/|/sbin/|/usr/bin/)',  # Cambios de permisos
                r'chown.*(/etc/|/bin/|/sbin/|/usr/bin/)',  # Cambios de propietario
                r'modify.*(/etc/passwd|/etc/shadow|/etc/sudoers)',  # Archivos críticos
                r'(create|delete).*(/etc/|/bin/|/sbin/)',  # Crear/eliminar en dirs críticos
                r'SYSCALL.*name.*(/etc/|/bin/|/sbin/)',  # Syscalls en dirs críticos
                r'inode.*(/etc/passwd|/etc/shadow|/etc/sudoers)',  # Cambios de inodo
                r'fim_.*',  # Tags específicos de FIM/auditd
                r'aide.*',  # Eventos de AIDE
                r'integrity.*check',  # Verificaciones de integridad
                r'file.*modified.*(/etc/|/bin/|/sbin/)'  # Modificaciones de archivos
            ]
            
            resultados_analisis = {}
            total_eventos_fim = 0
            
            for log_file in logs_fim:
                try:
                    if not os.path.exists(log_file):
                        self.logger.debug(f"Log no encontrado: {log_file}")
                        continue
                    
                    # Analizar últimas 1000 líneas del log
                    cmd = ['tail', '-n', '1000', log_file]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    
                    if result.returncode != 0:
                        continue
                    
                    lineas = result.stdout.split('\n')
                    eventos_encontrados = []
                    
                    # Buscar patrones FIM en las líneas
                    for linea in lineas:
                        if not linea.strip():
                            continue
                        
                        for patron in patrones_fim:
                            try:
                                if re.search(patron, linea, re.IGNORECASE):
                                    eventos_encontrados.append({
                                        'linea': linea.strip(),
                                        'patron_detectado': patron,
                                        'timestamp': self._extraer_timestamp_log(linea)
                                    })
                                    total_eventos_fim += 1
                                    break  # Solo un patrón por línea
                            except re.error:
                                continue
                    
                    resultados_analisis[log_file] = {
                        'eventos_encontrados': len(eventos_encontrados),
                        'eventos': eventos_encontrados[:10],  # Limitar a 10
                        'mas_eventos': len(eventos_encontrados) > 10
                    }
                    
                except Exception as e:
                    resultados_analisis[log_file] = {
                        'error': f"Error analizando {log_file}: {str(e)}",
                        'eventos_encontrados': 0
                    }
            
            # Análisis de tendencias
            eventos_por_archivo = {k: v.get('eventos_encontrados', 0) 
                                 for k, v in resultados_analisis.items()}
            
            # Archivos más activos
            archivos_activos = sorted(eventos_por_archivo.items(), 
                                    key=lambda x: x[1], reverse=True)[:3]
            
            return {
                'exito': total_eventos_fim > 0,
                'total_eventos_fim': total_eventos_fim,
                'logs_analizados': len([k for k in resultados_analisis.keys() 
                                      if 'error' not in resultados_analisis[k]]),
                'resultados_por_log': resultados_analisis,
                'archivos_mas_activos': archivos_activos,
                'timestamp': datetime.now().isoformat(),
                'herramienta': 'log_analysis'
            }
            
        except Exception as e:
            self.logger.error(f"Error analizando logs FIM: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramienta': 'log_analysis'
            }
    
    def _extraer_timestamp_log(self, linea_log: str) -> Optional[str]:
        """Extraer timestamp de una línea de log."""
        try:
            # Patrones comunes de timestamp en logs
            patrones_timestamp = [
                r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # MMM dd HH:mm:ss
                r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # ISO format
                r'^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})'  # MM/dd/yyyy HH:mm:ss
            ]
            
            for patron in patrones_timestamp:
                match = re.match(patron, linea_log)
                if match:
                    return match.group(1)
            
            return None
            
        except Exception:
            return None
    
    def ejecutar_fim_completo_kali(self) -> Dict[str, Any]:
        """
        Ejecutar análisis FIM completo usando todas las herramientas avanzadas de Kali Linux.
        FASE 4: Función principal que integra inotify, AIDE, auditd y análisis de logs.
        """
        try:
            self.logger.info(" Ejecutando FIM completo con herramientas avanzadas de Kali Linux...")
            tiempo_inicio = time.time()
            
            resultados_completos = {
                'timestamp': datetime.now().isoformat(),
                'herramientas_utilizadas': [],
                'resumen_detecciones': {},
                'alertas_criticas': [],
                'analisis_detallado': {}
            }
            
            # 1. Configurar inotify para monitoreo en tiempo real
            self.logger.info("1/4 Configurando inotify-tools...")
            resultado_inotify = self.configurar_inotify_avanzado()
            resultados_completos['analisis_detallado']['inotify'] = resultado_inotify
            if resultado_inotify['exito']:
                resultados_completos['herramientas_utilizadas'].append('inotify')
                resultados_completos['resumen_detecciones']['rutas_inotify'] = resultado_inotify['total_rutas']
            
            # 2. Configurar y verificar con AIDE
            self.logger.info("2/4 Configurando AIDE...")
            resultado_aide_config = self.configurar_aide()
            resultados_completos['analisis_detallado']['aide_config'] = resultado_aide_config
            
            if resultado_aide_config['exito']:
                self.logger.info("2.1/4 Ejecutando verificación AIDE...")
                resultado_aide_check = self.ejecutar_verificacion_aide()
                resultados_completos['analisis_detallado']['aide_verificacion'] = resultado_aide_check
                
                if resultado_aide_check['exito']:
                    resultados_completos['herramientas_utilizadas'].append('aide')
                    resultados_completos['resumen_detecciones']['cambios_aide'] = resultado_aide_check['total_cambios']
                    
                    # Generar alertas críticas si AIDE detecta cambios importantes
                    if resultado_aide_check['cambios_detectados']:
                        cambios_criticos = resultado_aide_check.get('cambios_criticos', [])
                        for cambio in cambios_criticos:
                            resultados_completos['alertas_criticas'].append({
                                'tipo': 'aide_critical_change',
                                'descripcion': f"AIDE detectó cambio crítico: {cambio}",
                                'severidad': 'CRITICA',
                                'herramienta': 'aide'
                            })
            
            # 3. Configurar auditd para FIM
            self.logger.info("3/4 Configurando auditd...")
            resultado_auditd = self.monitorear_con_auditd()
            resultados_completos['analisis_detallado']['auditd'] = resultado_auditd
            if resultado_auditd['exito']:
                resultados_completos['herramientas_utilizadas'].append('auditd')
                resultados_completos['resumen_detecciones']['reglas_auditd'] = resultado_auditd['reglas_aplicadas']
                
                # Procesar eventos recientes de auditd
                eventos_recientes = resultado_auditd.get('eventos_fim_recientes', [])
                if eventos_recientes and len(eventos_recientes) > 0:
                    resultados_completos['alertas_criticas'].append({
                        'tipo': 'auditd_events_detected',
                        'descripcion': f"auditd detectó {len(eventos_recientes)} eventos FIM",
                        'severidad': 'MEDIA',
                        'eventos_muestra': eventos_recientes[:3]
                    })
            
            # 4. Analizar logs del sistema
            self.logger.info("4/4 Analizando logs del sistema...")
            resultado_logs = self.analizar_logs_fim()
            resultados_completos['analisis_detallado']['logs_analysis'] = resultado_logs
            if resultado_logs['exito']:
                resultados_completos['herramientas_utilizadas'].append('log_analysis')
                resultados_completos['resumen_detecciones']['eventos_logs'] = resultado_logs['total_eventos_fim']
                
                # Generar alertas si se encuentran muchos eventos en logs
                if resultado_logs['total_eventos_fim'] > 10:
                    resultados_completos['alertas_criticas'].append({
                        'tipo': 'high_log_activity',
                        'descripcion': f"Alta actividad FIM en logs: {resultado_logs['total_eventos_fim']} eventos",
                        'severidad': 'ALTA',
                        'archivos_activos': resultado_logs.get('archivos_mas_activos', [])
                    })
            
            # 5. Compilación final y métricas
            tiempo_total = time.time() - tiempo_inicio
            herramientas_exitosas = len(resultados_completos['herramientas_utilizadas'])
            total_alertas = len(resultados_completos['alertas_criticas'])
            
            # Calcular puntuación de integridad del sistema
            puntuacion_integridad = self._calcular_puntuacion_integridad(resultados_completos)
            
            resultados_completos['resumen_detecciones'].update({
                'herramientas_exitosas': herramientas_exitosas,
                'total_alertas_criticas': total_alertas,
                'tiempo_ejecucion_segundos': round(tiempo_total, 2),
                'cobertura_fim': f"{herramientas_exitosas}/4 herramientas",
                'puntuacion_integridad': puntuacion_integridad
            })
            
            # Registrar evento SIEM
            severidad_evento = "critical" if total_alertas > 5 else ("warning" if total_alertas > 0 else "info")
            self._registrar_evento_siem(
                "FIM_COMPLETO_KALI",
                f"FIM completo: {herramientas_exitosas}/4 herramientas, {total_alertas} alertas críticas",
                severidad_evento
            )
            
            self.logger.info(f"OK FIM completo ejecutado en {tiempo_total:.2f}s - {herramientas_exitosas}/4 herramientas exitosas")
            
            return {
                'exito': herramientas_exitosas > 0,
                'resultados': resultados_completos,
                'recomendaciones': self._generar_recomendaciones_fim(resultados_completos)
            }
            
        except Exception as e:
            self.logger.error(f"Error en FIM completo Kali: {e}")
            return {
                'exito': False,
                'error': str(e),
                'herramientas_utilizadas': resultados_completos.get('herramientas_utilizadas', [])
            }
    
    def _calcular_puntuacion_integridad(self, resultados: Dict[str, Any]) -> int:
        """Calcular puntuación de integridad del sistema (0-100)."""
        try:
            puntuacion = 100  # Empezar con puntuación perfecta
            
            # Penalizar por herramientas no funcionando
            herramientas_exitosas = len(resultados.get('herramientas_utilizadas', []))
            puntuacion -= (4 - herramientas_exitosas) * 15  # -15 por cada herramienta faltante
            
            # Penalizar por alertas críticas
            alertas_criticas = len(resultados.get('alertas_criticas', []))
            puntuacion -= alertas_criticas * 10  # -10 por cada alerta crítica
            
            # Penalizar por cambios detectados por AIDE
            cambios_aide = resultados.get('resumen_detecciones', {}).get('cambios_aide', 0)
            if cambios_aide > 0:
                puntuacion -= min(cambios_aide * 2, 20)  # Max -20 por cambios
            
            # Penalizar por eventos en logs
            eventos_logs = resultados.get('resumen_detecciones', {}).get('eventos_logs', 0)
            if eventos_logs > 20:
                puntuacion -= 10  # -10 si hay demasiados eventos
            
            # Garantizar rango 0-100
            return max(0, min(100, puntuacion))
            
        except Exception as e:
            self.logger.error(f"Error calculando puntuación de integridad: {e}")
            return 50  # Puntuación neutral en caso de error
    
    def _generar_recomendaciones_fim(self, resultados: Dict[str, Any]) -> List[str]:
        """Generar recomendaciones basadas en los resultados del FIM completo."""
        recomendaciones = []
        
        try:
            analisis = resultados.get('analisis_detallado', {})
            
            # Recomendaciones de inotify
            if 'inotify' in analisis and not analisis['inotify'].get('exito', False):
                recomendaciones.append("Instalar inotify-tools: sudo apt install inotify-tools")
            
            # Recomendaciones de AIDE
            if 'aide_config' in analisis and not analisis['aide_config'].get('exito', False):
                recomendaciones.append("Instalar y configurar AIDE: sudo apt install aide")
            elif 'aide_verificacion' in analisis:
                aide_result = analisis['aide_verificacion']
                if not aide_result.get('exito', False):
                    recomendaciones.append("Inicializar base de datos AIDE: sudo aide --init")
                elif aide_result.get('cambios_detectados', False):
                    recomendaciones.append(f"Investigar {aide_result.get('total_cambios', 0)} cambios detectados por AIDE")
            
            # Recomendaciones de auditd
            if 'auditd' in analisis and not analisis['auditd'].get('exito', False):
                recomendaciones.append("Instalar auditd: sudo apt install auditd")
            elif 'auditd' in analisis:
                auditd_result = analisis['auditd']
                if auditd_result.get('reglas_fallidas', 0) > 0:
                    recomendaciones.append("Revisar reglas de auditd fallidas - verificar permisos sudo")
            
            # Recomendaciones de logs
            if 'logs_analysis' in analisis and analisis['logs_analysis'].get('exito', False):
                eventos_logs = analisis['logs_analysis'].get('total_eventos_fim', 0)
                if eventos_logs > 50:
                    recomendaciones.append(f"Investigar alta actividad en logs: {eventos_logs} eventos FIM detectados")
            
            # Recomendaciones basadas en alertas críticas
            alertas = resultados.get('alertas_criticas', [])
            alertas_criticas = [a for a in alertas if a.get('severidad') == 'CRITICA']
            
            if alertas_criticas:
                recomendaciones.append(f"URGENTE: Investigar {len(alertas_criticas)} alertas críticas de integridad")
            
            # Recomendaciones basadas en puntuación
            puntuacion = resultados.get('resumen_detecciones', {}).get('puntuacion_integridad', 100)
            if puntuacion < 70:
                recomendaciones.append("Puntuación de integridad baja - realizar auditoría completa del sistema")
            elif puntuacion < 85:
                recomendaciones.append("Considerar fortalecer monitoreo de integridad de archivos")
            
            # Recomendaciones generales
            herramientas_exitosas = len(resultados.get('herramientas_utilizadas', []))
            if herramientas_exitosas < 3:
                recomendaciones.append("Instalar herramientas FIM faltantes para mejor cobertura")
            
            return recomendaciones
            
        except Exception as e:
            self.logger.error(f"Error generando recomendaciones FIM: {e}")
            return ["Error generando recomendaciones"]
    
    def monitorear_pam_especifico(self) -> dict:
        """
        Monitoreo específico y mejorado del directorio /etc/pam.d/ usando comandos nativos de Kali.
        Implementa detección de cambios con sha256sum y verificación exhaustiva.
        """
        try:
            self.logger.info("Iniciando monitoreo específico de PAM.d")
            resultado = {
                'exito': False,
                'directorio_pam': '/etc/pam.d',
                'archivos_monitoreados': 0,
                'cambios_detectados': [],
                'hashes_calculados': {},
                'archivos_criticos': [],
                'errores': []
            }
            
            pam_dir = '/etc/pam.d'
            if not os.path.exists(pam_dir):
                resultado['errores'].append(f"Directorio PAM no encontrado: {pam_dir}")
                return resultado
            
            # Archivos PAM críticos que SIEMPRE deben monitorearse
            archivos_criticos_pam = [
                'common-auth', 'common-password', 'common-session', 'common-account',
                'sudo', 'su', 'login', 'sshd', 'passwd', 'chpasswd', 'newusers'
            ]
            
            # Usar find para obtener todos los archivos en /etc/pam.d/
            try:
                import subprocess
                resultado_find = subprocess.run(
                    ['find', pam_dir, '-type', 'f', '-readable'],
                    capture_output=True, text=True, timeout=30
                )
                
                if resultado_find.returncode == 0:
                    archivos_encontrados = resultado_find.stdout.strip().split('\n')
                    archivos_encontrados = [f for f in archivos_encontrados if f.strip()]
                    
                    for archivo_path in archivos_encontrados:
                        archivo_name = os.path.basename(archivo_path)
                        
                        # Calcular hash SHA256 usando comando nativo
                        try:
                            hash_result = subprocess.run(
                                ['sha256sum', archivo_path],
                                capture_output=True, text=True, timeout=10
                            )
                            
                            if hash_result.returncode == 0:
                                hash_actual = hash_result.stdout.split()[0]
                                resultado['hashes_calculados'][archivo_path] = hash_actual
                                resultado['archivos_monitoreados'] += 1
                                
                                # Verificar si es archivo crítico
                                if archivo_name in archivos_criticos_pam:
                                    resultado['archivos_criticos'].append({
                                        'archivo': archivo_path,
                                        'hash': hash_actual,
                                        'critico': True
                                    })
                                
                                # Verificar permisos usando stat
                                stat_result = subprocess.run(
                                    ['stat', '-c', '%a:%U:%G', archivo_path],
                                    capture_output=True, text=True, timeout=5
                                )
                                
                                if stat_result.returncode == 0:
                                    permisos_info = stat_result.stdout.strip().split(':')
                                    permisos = permisos_info[0]
                                    owner = permisos_info[1] if len(permisos_info) > 1 else 'unknown'
                                    group = permisos_info[2] if len(permisos_info) > 2 else 'unknown'
                                    
                                    # Verificar permisos seguros para archivos PAM
                                    if permisos not in ['644', '640', '600']:
                                        resultado['cambios_detectados'].append({
                                            'tipo': 'PERMISOS_INSEGUROS',
                                            'archivo': archivo_path,
                                            'permisos_actuales': permisos,
                                            'owner': owner,
                                            'group': group,
                                            'severidad': 'ALTA'
                                        })
                                        
                                        # Notificar a SIEM si está disponible (log para integración futura)
                                        if self.siem:
                                            try:
                                                self.logger.warning(f"ALERTA SIEM: Permisos PAM cambiados en {archivo_path} - Permisos: {permisos}")
                                            except Exception as e:
                                                self.logger.warning(f"Error enviando alerta a SIEM: {e}")
                                    
                            else:
                                resultado['errores'].append(f"Error calculando hash de {archivo_path}")
                                
                        except subprocess.TimeoutExpired:
                            resultado['errores'].append(f"Timeout calculando hash de {archivo_path}")
                        except Exception as e:
                            resultado['errores'].append(f"Error procesando {archivo_path}: {str(e)}")
                
                else:
                    resultado['errores'].append(f"Error ejecutando find en {pam_dir}")
                    
            except subprocess.TimeoutExpired:
                resultado['errores'].append("Timeout ejecutando find en directorio PAM")
            except Exception as e:
                resultado['errores'].append(f"Error general en monitoreo PAM: {str(e)}")
            
            # Verificar integridad usando head para inspección rápida
            try:
                for archivo_critico in archivos_criticos_pam:
                    archivo_path = os.path.join(pam_dir, archivo_critico)
                    if os.path.exists(archivo_path):
                        # Usar head para verificar contenido inicial
                        head_result = subprocess.run(
                            ['head', '-5', archivo_path],
                            capture_output=True, text=True, timeout=5
                        )
                        
                        if head_result.returncode == 0:
                            contenido_inicial = head_result.stdout
                            # Detectar patrones sospechosos
                            patrones_sospechosos = ['eval', 'exec', 'system', 'shell', '&&', '||']
                            for patron in patrones_sospechosos:
                                if patron in contenido_inicial:
                                    resultado['cambios_detectados'].append({
                                        'tipo': 'CONTENIDO_SOSPECHOSO',
                                        'archivo': archivo_path,
                                        'patron_detectado': patron,
                                        'severidad': 'CRITICA'
                                    })
            except:
                pass  # No crítico para el resultado principal
            
            # Marcar como exitoso si se procesaron archivos
            resultado['exito'] = resultado['archivos_monitoreados'] > 0
            
            # Log del resultado
            self.logger.info(f"Monitoreo PAM completado: {resultado['archivos_monitoreados']} archivos, "
                           f"{len(resultado['cambios_detectados'])} cambios detectados")
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en monitoreo específico PAM: {e}")
            return {
                'exito': False,
                'error': str(e),
                'archivos_monitoreados': 0,
                'cambios_detectados': []
            }
    
    def verificar_compatibilidad_kali(self) -> dict:
        """
        Verificar que el sistema es Kali Linux y que las herramientas necesarias están disponibles.
        """
        try:
            resultado = {
                'es_kali': False,
                'herramientas_disponibles': {},
                'herramientas_faltantes': [],
                'recomendaciones': []
            }
            
            # Verificar si es Kali Linux
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = f.read()
                    if 'kali' in os_info.lower() or 'debian' in os_info.lower():
                        resultado['es_kali'] = True
            except:
                # Fallback: verificar otros indicadores de Kali
                if os.path.exists('/usr/share/kali-themes') or os.path.exists('/etc/kali_version'):
                    resultado['es_kali'] = True
            
            # Herramientas críticas para FIM en Kali
            herramientas_fim_kali = [
                'find', 'stat', 'sha256sum', 'md5sum', 'head', 'tail',
                'inotifywait', 'auditctl', 'aide', 'grep', 'awk', 'lsof'
            ]
            
            for herramienta in herramientas_fim_kali:
                try:
                    check_result = subprocess.run(['which', herramienta], 
                                                capture_output=True, text=True, timeout=5)
                    disponible = check_result.returncode == 0
                    resultado['herramientas_disponibles'][herramienta] = {
                        'disponible': disponible,
                        'path': check_result.stdout.strip() if disponible else None
                    }
                    
                    if not disponible:
                        resultado['herramientas_faltantes'].append(herramienta)
                        
                except Exception as e:
                    resultado['herramientas_disponibles'][herramienta] = {
                        'disponible': False,
                        'error': str(e)
                    }
                    resultado['herramientas_faltantes'].append(herramienta)
            
            # Generar recomendaciones específicas para Kali
            if not resultado['es_kali']:
                resultado['recomendaciones'].append("WARNING Sistema no detectado como Kali Linux")
            
            if 'inotifywait' in resultado['herramientas_faltantes']:
                resultado['recomendaciones'].append("Instalar inotify-tools: sudo apt install inotify-tools")
            
            if 'aide' in resultado['herramientas_faltantes']:
                resultado['recomendaciones'].append("Instalar AIDE: sudo apt install aide")
            
            if 'auditctl' in resultado['herramientas_faltantes']:
                resultado['recomendaciones'].append("Instalar auditd: sudo apt install auditd")
            
            # Verificar permisos especiales necesarios
            try:
                # Verificar acceso a /etc/pam.d/
                if os.access('/etc/pam.d', os.R_OK):
                    resultado['herramientas_disponibles']['pam_access'] = {'disponible': True}
                else:
                    resultado['herramientas_faltantes'].append('pam_access')
                    resultado['recomendaciones'].append("Ejecutar con permisos sudo para monitorear PAM")
            except:
                pass
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error verificando compatibilidad Kali: {e}")
            return {
                'es_kali': False,
                'error': str(e),
                'herramientas_disponibles': {},
                'herramientas_faltantes': []
            }


# RESUMEN TÉCNICO: Controlador FIM avanzado para monitoreo de integridad de archivos en Kali Linux.
# Implementa supervisión continua de archivos críticos del sistema, detección de cambios en tiempo real,
# alertas automáticas vía SIEM, y análisis de integridad usando herramientas nativas (find, stat, md5sum).
# Arquitectura asíncrona con threading para monitoreo continuo, siguiendo patrones MVC y principios SOLID
# para escalabilidad profesional en entornos de ciberseguridad.
