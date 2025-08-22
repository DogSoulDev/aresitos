# -*- coding: utf-8 -*-
"""
Ares Aegis - Escaneador Avanzado
Funcionalidades avanzadas de seguridad y operaciones de escaneo
"""

import subprocess
import datetime
import tempfile
import hashlib
import getpass
import stat
import os
import re
from typing import Dict, List, Any, Optional
from .modelo_escaneador_base import EscaneadorBase, SecurityError

# Importar la clase real completa para compatibilidad
try:
    from .modelo_escaneador_avanzado_real import EscaneadorAvanzadoReal
    ESCANEADOR_REAL_DISPONIBLE = True
except ImportError:
    EscaneadorAvanzadoReal = None
    ESCANEADOR_REAL_DISPONIBLE = False

class EscaneadorAvanzado(EscaneadorBase):
    """
    Escaneador con funcionalidades avanzadas de seguridad.
    
    Características adicionales:
    - Sistema de detección de anomalías
    - Cache seguro con verificación de integridad
    - Sandbox para ejecución de comandos
    - Reportes de seguridad avanzados
    - Métricas y monitoreo en tiempo real
    """
    
    def __init__(self, siem=None):
        super().__init__(siem)
        
        # Sistema de métricas y monitoreo de seguridad
        self._metricas_seguridad = {
            'intentos_fallidos': 0,
            'comandos_bloqueados': 0,
            'alertas_seguridad': [],
            'patrones_anomalos': {},
            'sesion_iniciada': datetime.datetime.now(),
            'ultima_actividad': datetime.datetime.now(),
            'operaciones_por_minuto': [],
            'ips_consultadas': set(),
            'dominios_consultados': set()
        }
        
        # Configuración de límites avanzados
        self.limites_avanzados = {
            'max_ips_por_sesion': 100,
            'max_dominios_por_sesion': 50,
            'max_operaciones_por_minuto': 30,
            'tiempo_bloqueo_anomalia': 300,  # 5 minutos
            'umbral_alerta_critica': 10
        }
        
        self.logger.info("Escaneador Avanzado Ares Aegis inicializado")

    def _detectar_anomalias(self, operacion: str, objetivo: str) -> bool:
        """
        Sistema de detección de anomalías.
        
        Args:
            operacion: Tipo de operación
            objetivo: Objetivo de la operación
            
        Returns:
            bool: True si se detecta anomalía
            
        Raises:
            SecurityError: Si se detecta actividad sospechosa
        """
        ahora = datetime.datetime.now()
        
        # Actualizar última actividad
        self._metricas_seguridad['ultima_actividad'] = ahora
        
        # 1. Verificar frecuencia de operaciones
        ventana_tiempo = 60  # 1 minuto
        operaciones_recientes = [
            timestamp for timestamp in self._metricas_seguridad['operaciones_por_minuto']
            if (ahora - timestamp).total_seconds() <= ventana_tiempo
        ]
        
        if len(operaciones_recientes) >= self.limites_avanzados['max_operaciones_por_minuto']:
            self._registrar_alerta('ALTA_FRECUENCIA', f"Más de {self.limites_avanzados['max_operaciones_por_minuto']} ops/min")
            raise SecurityError("Frecuencia de operaciones sospechosa detectada")
        
        # 2. Verificar diversidad de objetivos
        if operacion in ['escaneo_puertos', 'escaneo_servicios']:
            if self._es_ip(objetivo):
                self._metricas_seguridad['ips_consultadas'].add(objetivo)
                if len(self._metricas_seguridad['ips_consultadas']) > self.limites_avanzados['max_ips_por_sesion']:
                    self._registrar_alerta('DEMASIADAS_IPS', f"Más de {self.limites_avanzados['max_ips_por_sesion']} IPs en sesión")
                    raise SecurityError("Demasiadas IPs diferentes consultadas")
            else:
                self._metricas_seguridad['dominios_consultados'].add(objetivo)
                if len(self._metricas_seguridad['dominios_consultados']) > self.limites_avanzados['max_dominios_por_sesion']:
                    self._registrar_alerta('DEMASIADOS_DOMINIOS', f"Más de {self.limites_avanzados['max_dominios_por_sesion']} dominios en sesión")
                    raise SecurityError("Demasiados dominios diferentes consultados")
        
        # 3. Detectar patrones repetitivos sospechosos
        patron_key = f"{operacion}_{objetivo}"
        if patron_key in self._metricas_seguridad['patrones_anomalos']:
            self._metricas_seguridad['patrones_anomalos'][patron_key] += 1
        else:
            self._metricas_seguridad['patrones_anomalos'][patron_key] = 1
        
        if self._metricas_seguridad['patrones_anomalos'][patron_key] > 5:
            self._registrar_alerta('PATRON_REPETITIVO', f"Patrón {patron_key} repetido {self._metricas_seguridad['patrones_anomalos'][patron_key]} veces")
        
        # Registrar operación
        self._metricas_seguridad['operaciones_por_minuto'].append(ahora)
        
        # Limpiar operaciones antiguas (más de 1 hora)
        limite_tiempo = ahora - datetime.timedelta(hours=1)
        self._metricas_seguridad['operaciones_por_minuto'] = [
            timestamp for timestamp in self._metricas_seguridad['operaciones_por_minuto']
            if timestamp > limite_tiempo
        ]
        
        return False

    def _es_ip(self, cadena: str) -> bool:
        """Verificar si una cadena es una dirección IP."""
        try:
            partes = cadena.split('.')
            if len(partes) != 4:
                return False
            for parte in partes:
                if not 0 <= int(parte) <= 255:
                    return False
            return True
        except (ValueError, TypeError, AttributeError):
            return False

    def _registrar_alerta(self, tipo: str, descripcion: str):
        """
        Registrar alerta de seguridad.
        
        Args:
            tipo: Tipo de alerta
            descripcion: Descripción de la alerta
        """
        alerta = {
            'timestamp': datetime.datetime.now().isoformat(),
            'tipo': tipo,
            'descripcion': descripcion,
            'usuario': getpass.getuser(),
            'pid': os.getpid()
        }
        
        self._metricas_seguridad['alertas_seguridad'].append(alerta)
        
        # Mantener solo las últimas 100 alertas
        if len(self._metricas_seguridad['alertas_seguridad']) > 100:
            self._metricas_seguridad['alertas_seguridad'] = self._metricas_seguridad['alertas_seguridad'][-100:]
        
        # Log crítico si hay muchas alertas
        if len(self._metricas_seguridad['alertas_seguridad']) >= self.limites_avanzados['umbral_alerta_critica']:
            self.logger.critical(f"ALERTA CRÍTICA: {len(self._metricas_seguridad['alertas_seguridad'])} alertas de seguridad registradas")
        else:
            self.logger.warning(f"ALERTA SEGURIDAD [{tipo}]: {descripcion}")

    def _crear_sandbox_comando(self, comando: List[str]) -> Dict[str, Any]:
        """
        Crear sandbox para ejecución de comandos.
        
        Args:
            comando: Comando a ejecutar en sandbox
            
        Returns:
            dict: Configuración del sandbox
        """
        # Crear directorio temporal aislado
        sandbox_dir = tempfile.mkdtemp(prefix='ares_sandbox_')
        
        # Configuración del sandbox
        sandbox_config = {
            'working_dir': sandbox_dir,
            'env_vars': {
                'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                'HOME': sandbox_dir,
                'TMPDIR': sandbox_dir,
                'LC_ALL': 'C',
                'LANG': 'C',
                'SHELL': '/bin/sh',
                'USER': 'sandbox',
                'LOGNAME': 'sandbox'
            },
            'limits': {
                'max_memory': 256 * 1024 * 1024,  # 256MB
                'max_cpu_time': 300,  # 5 minutos
                'max_files': 50,
                'max_processes': 5
            },
            'blocked_syscalls': [
                'ptrace', 'kill', 'killpg', 'tkill', 'tgkill',
                'reboot', 'kexec_load', 'init_module', 'delete_module'
            ]
        }
        
        # Registrar sandbox para limpieza posterior
        self._archivos_temporales.add(sandbox_dir)
        
        return sandbox_config

    def _ejecutar_en_sandbox(self, comando: List[str], sandbox_config: Dict[str, Any], 
                           timeout: int = 120) -> subprocess.CompletedProcess:
        """
        Ejecutar comando en entorno sandbox.
        
        Args:
            comando: Comando a ejecutar
            sandbox_config: Configuración del sandbox
            timeout: Timeout en segundos
            
        Returns:
            subprocess.CompletedProcess: Resultado de la ejecución
        """
        try:
            # Configurar variables de entorno del sandbox
            env = sandbox_config['env_vars'].copy()
            
            # En sistemas Unix, usar limitaciones adicionales
            if os.name != 'nt' and os.geteuid() == 0:
                # Solo si somos root podemos usar ciertas limitaciones
                preexec_fn = lambda: self._configurar_sandbox_unix(sandbox_config)
            else:
                preexec_fn = None
            
            # Ejecutar comando con restricciones
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=sandbox_config['working_dir'],
                preexec_fn=preexec_fn,
                check=False
            )
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en sandbox: {e}")
            raise SecurityError(f"Error ejecutando en sandbox: {e}")

    def _configurar_sandbox_unix(self, sandbox_config: Dict[str, Any]):
        """Configurar restricciones Unix para sandbox."""
        try:
            # Solo en sistemas Unix
            if os.name == 'nt':
                return  # No aplicar en Windows
                
            import resource
            
            # Verificar que existan los límites antes de usarlos
            if hasattr(resource, 'RLIMIT_AS') and hasattr(resource, 'setrlimit'):
                resource.setrlimit(resource.RLIMIT_AS, 
                                 (sandbox_config['limits']['max_memory'], 
                                  sandbox_config['limits']['max_memory']))
            
            if hasattr(resource, 'RLIMIT_CPU'):
                resource.setrlimit(resource.RLIMIT_CPU,
                                 (sandbox_config['limits']['max_cpu_time'], 
                                  sandbox_config['limits']['max_cpu_time']))
            
            if hasattr(resource, 'RLIMIT_NOFILE'):
                resource.setrlimit(resource.RLIMIT_NOFILE,
                                 (sandbox_config['limits']['max_files'], 
                                  sandbox_config['limits']['max_files']))
            
            if hasattr(resource, 'RLIMIT_NPROC'):
                resource.setrlimit(resource.RLIMIT_NPROC,
                                 (sandbox_config['limits']['max_processes'], 
                                  sandbox_config['limits']['max_processes']))
            
            # Cambiar grupo de proceso (solo Unix)
            if hasattr(os, 'setpgrp'):
                os.setpgrp()
            
        except Exception as e:
            # No fallar si no se pueden establecer todas las restricciones
            pass

    def _validar_comando_avanzado(self, comando: List[str]) -> bool:
        """
        Validación avanzada de comandos.
        
        Args:
            comando: Comando a validar
            
        Returns:
            bool: True si el comando es válido
            
        Raises:
            SecurityError: Si el comando es peligroso
        """
        if not comando or not isinstance(comando, list):
            raise SecurityError("Comando inválido o vacío")
        
        herramienta = comando[0]
        
        # Lista blanca estricta de herramientas modernizadas
        herramientas_permitidas = {
            'nmap', 'masscan', 'nikto', 'gobuster', 'feroxbuster', 'httpx',
            'sqlmap', 'whatweb', 'ss', 'netstat', 'lsof',
            'ping', 'dig', 'nslookup', 'host', 'nuclei', 'rustscan'
        }
        
        if herramienta not in herramientas_permitidas:
            raise SecurityError(f"Herramienta no permitida: {herramienta}")
        
        # Verificar argumentos peligrosos
        argumentos_peligrosos = [
            '--script', '-oX', '-oN', '-oG', '--script-args',
            '--datadir', '--servicedb', '--versiondb',
            '>', '<', '|', '&', ';', '`', '$', '$(', '${',
            'rm ', 'del ', 'format', 'fdisk', 'mkfs'
        ]
        
        comando_str = ' '.join(comando)
        for arg_peligroso in argumentos_peligrosos:
            if arg_peligroso in comando_str:
                raise SecurityError(f"Argumento peligroso detectado: {arg_peligroso}")
        
        # Verificar longitud de argumentos
        for arg in comando[1:]:
            if len(arg) > 500:
                raise SecurityError(f"Argumento excesivamente largo: {len(arg)} caracteres")
        
        return True

    def _inicializar_cache_seguro(self):
        """Inicializar sistema de cache seguro."""
        self._cache_resultados = {
            'escaneos': {},
            'herramientas': {},
            'validaciones': {},
            'metadatos': {
                'created': datetime.datetime.now(),
                'max_size': 1000,
                'ttl_segundos': 3600,  # 1 hora
                'hits': 0,
                'misses': 0
            }
        }

    def _obtener_cache_key(self, operacion: str, objetivo: str, **kwargs) -> str:
        """
        Generar clave de cache segura.
        
        Args:
            operacion: Tipo de operación
            objetivo: Objetivo de la operación
            **kwargs: Parámetros adicionales
            
        Returns:
            str: Clave de cache
        """
        # Crear hash de los parámetros para evitar colisiones
        params_str = f"{operacion}_{objetivo}_{sorted(kwargs.items())}"
        return hashlib.sha256(params_str.encode()).hexdigest()[:16]

    def _obtener_desde_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Obtener resultado desde cache si es válido.
        
        Args:
            cache_key: Clave del cache
            
        Returns:
            Optional[Dict]: Resultado si existe y es válido, None en caso contrario
        """
        if not hasattr(self, '_cache_resultados'):
            self._inicializar_cache_seguro()
        
        if cache_key in self._cache_resultados['escaneos']:
            entrada = self._cache_resultados['escaneos'][cache_key]
            ahora = datetime.datetime.now()
            
            # Verificar TTL
            if (ahora - entrada['timestamp']).total_seconds() < self._cache_resultados['metadatos']['ttl_segundos']:
                self._cache_resultados['metadatos']['hits'] += 1
                self.logger.debug(f"Cache HIT para {cache_key}")
                return entrada['resultado']
            else:
                # Eliminar entrada expirada
                del self._cache_resultados['escaneos'][cache_key]
        
        self._cache_resultados['metadatos']['misses'] += 1
        self.logger.debug(f"Cache MISS para {cache_key}")
        return None

    def _guardar_en_cache(self, cache_key: str, resultado: Dict[str, Any]):
        """
        Guardar resultado en cache.
        
        Args:
            cache_key: Clave del cache
            resultado: Resultado a guardar
        """
        if not hasattr(self, '_cache_resultados'):
            self._inicializar_cache_seguro()
        
        # Verificar límite de tamaño
        if len(self._cache_resultados['escaneos']) >= self._cache_resultados['metadatos']['max_size']:
            # Eliminar las entradas más antiguas
            self._limpiar_cache_antiguo()
        
        self._cache_resultados['escaneos'][cache_key] = {
            'timestamp': datetime.datetime.now(),
            'resultado': resultado,
            'hash': hashlib.sha256(str(resultado).encode()).hexdigest()[:8]
        }

    def _limpiar_cache_antiguo(self):
        """Limpiar entradas de cache antiguas."""
        if not hasattr(self, '_cache_resultados'):
            return
        
        ahora = datetime.datetime.now()
        claves_a_eliminar = []
        
        for cache_key, entrada in self._cache_resultados['escaneos'].items():
            if (ahora - entrada['timestamp']).total_seconds() > self._cache_resultados['metadatos']['ttl_segundos']:
                claves_a_eliminar.append(cache_key)
        
        for clave in claves_a_eliminar:
            del self._cache_resultados['escaneos'][clave]
        
        # Si aún está lleno, eliminar las más antiguas
        if len(self._cache_resultados['escaneos']) >= self._cache_resultados['metadatos']['max_size']:
            entradas_ordenadas = sorted(
                self._cache_resultados['escaneos'].items(),
                key=lambda x: x[1]['timestamp']
            )
            
            # Mantener solo la mitad más reciente
            mitad = len(entradas_ordenadas) // 2
            for clave, _ in entradas_ordenadas[:mitad]:
                del self._cache_resultados['escaneos'][clave]

    def _validar_integridad_cache(self) -> bool:
        """
        Validar integridad del cache.
        
        Returns:
            bool: True si el cache es íntegro
        """
        if not hasattr(self, '_cache_resultados'):
            return True
        
        entradas_corruptas = []
        
        for cache_key, entrada in self._cache_resultados['escaneos'].items():
            # Verificar hash de integridad
            hash_actual = hashlib.sha256(str(entrada['resultado']).encode()).hexdigest()[:8]
            if hash_actual != entrada['hash']:
                entradas_corruptas.append(cache_key)
        
        # Eliminar entradas corruptas
        for clave in entradas_corruptas:
            del self._cache_resultados['escaneos'][clave]
            self.logger.warning(f"Entrada de cache corrupta eliminada: {clave}")
        
        return len(entradas_corruptas) == 0

    def generar_reporte_seguridad(self) -> Dict[str, Any]:
        """
        Generar reporte completo de seguridad.
        
        Returns:
            Dict: Reporte de seguridad con métricas
        """
        ahora = datetime.datetime.now()
        duracion_sesion = (ahora - self._metricas_seguridad['sesion_iniciada']).total_seconds()
        
        # Estadísticas de cache
        cache_stats = {}
        if hasattr(self, '_cache_resultados'):
            total_requests = self._cache_resultados['metadatos']['hits'] + self._cache_resultados['metadatos']['misses']
            hit_rate = (self._cache_resultados['metadatos']['hits'] / total_requests * 100) if total_requests > 0 else 0
            cache_stats = {
                'cache_hits': self._cache_resultados['metadatos']['hits'],
                'cache_misses': self._cache_resultados['metadatos']['misses'],
                'hit_rate_percent': round(hit_rate, 2),
                'cache_size': len(self._cache_resultados['escaneos'])
            }
        
        # Análisis de patrones
        patrones_mas_frecuentes = sorted(
            self._metricas_seguridad['patrones_anomalos'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # Calcular operaciones por minuto promedio
        ops_por_minuto = len(self._metricas_seguridad['operaciones_por_minuto'])
        if duracion_sesion > 60:
            ops_promedio = ops_por_minuto / (duracion_sesion / 60)
        else:
            ops_promedio = ops_por_minuto
        
        reporte = {
            'timestamp': ahora.isoformat(),
            'sesion': {
                'inicio': self._metricas_seguridad['sesion_iniciada'].isoformat(),
                'duracion_segundos': round(duracion_sesion, 2),
                'ultima_actividad': self._metricas_seguridad['ultima_actividad'].isoformat()
            },
            'operaciones': {
                'total_operaciones': sum(self._contador_operaciones.values()),
                'por_tipo': dict(self._contador_operaciones),
                'promedio_por_minuto': round(ops_promedio, 2),
                'operaciones_recientes': len(self._metricas_seguridad['operaciones_por_minuto'])
            },
            'seguridad': {
                'intentos_fallidos': self._metricas_seguridad['intentos_fallidos'],
                'comandos_bloqueados': self._metricas_seguridad['comandos_bloqueados'],
                'total_alertas': len(self._metricas_seguridad['alertas_seguridad']),
                'alertas_recientes': self._metricas_seguridad['alertas_seguridad'][-5:] if self._metricas_seguridad['alertas_seguridad'] else []
            },
            'objetivos': {
                'ips_consultadas': len(self._metricas_seguridad['ips_consultadas']),
                'dominios_consultados': len(self._metricas_seguridad['dominios_consultados']),
                'diversidad_objetivos': len(self._metricas_seguridad['ips_consultadas']) + len(self._metricas_seguridad['dominios_consultados'])
            },
            'patrones': {
                'patrones_detectados': len(self._metricas_seguridad['patrones_anomalos']),
                'mas_frecuentes': patrones_mas_frecuentes
            },
            'cache': cache_stats,
            'salud_sistema': {
                'cache_integro': self._validar_integridad_cache() if hasattr(self, '_cache_resultados') else True,
                'archivos_temporales': len(self._archivos_temporales),
                'herramientas_disponibles': len([h for h, disponible in self.herramientas_disponibles.items() if disponible])
            },
            'configuración': {
                'timeouts': {
                    'defecto': self.config_seguridad['timeout_comando_defecto'],
                    'maximo': self.config_seguridad['timeout_maximo']
                },
                'limites': {
                    'max_ops_por_minuto': self.limites_avanzados['max_operaciones_por_minuto'],
                    'max_ips_por_sesion': self.limites_avanzados['max_ips_por_sesion'],
                    'max_dominios_por_sesion': self.limites_avanzados['max_dominios_por_sesion']
                }
            }
        }
        
        return reporte

    def obtener_estadisticas_rendimiento(self) -> Dict[str, Any]:
        """
        Obtener estadísticas de rendimiento del sistema usando comandos nativos.
        
        Returns:
            Dict: Estadísticas de rendimiento
        """
        try:
            estadisticas = {
                'timestamp': datetime.datetime.now().isoformat(),
                'cpu': self._obtener_cpu_nativo(),
                'memoria': self._obtener_memoria_nativo(),
                'disco': self._obtener_disco_nativo(),
                'red': self._obtener_red_nativo()
            }
            return estadisticas
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            return {'error': str(e)}
    
    def _obtener_cpu_nativo(self) -> Dict[str, Any]:
        """Obtener estadísticas de CPU usando comandos nativos."""
        try:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '%Cpu(s):' in line or 'Cpu(s):' in line:
                        # Buscar porcentaje idle
                        match = re.search(r'(\d+\.\d+)%?\s*id', line)
                        if match:
                            idle = float(match.group(1))
                            return {'porcentaje_uso': 100.0 - idle}
            return {'porcentaje_uso': 0.0}
        except (ValueError, TypeError, AttributeError):
            return {'porcentaje_uso': 0.0}
    
    def _obtener_memoria_nativo(self) -> Dict[str, Any]:
        """Obtener estadísticas de memoria usando comandos nativos."""
        try:
            result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.startswith('Mem:'):
                        parts = line.split()
                        if len(parts) >= 7:
                            total = int(parts[1])
                            usado = int(parts[2])
                            disponible = int(parts[6]) if len(parts) > 6 else int(parts[3])
                            return {
                                'total_mb': total,
                                'usado_mb': usado,
                                'disponible_mb': disponible,
                                'porcentaje_uso': (usado / total) * 100.0
                            }
            return {'total_mb': 0, 'usado_mb': 0, 'disponible_mb': 0, 'porcentaje_uso': 0.0}
        except (ValueError, TypeError, AttributeError):
            return {'total_mb': 0, 'usado_mb': 0, 'disponible_mb': 0, 'porcentaje_uso': 0.0}
    
    def _obtener_disco_nativo(self) -> Dict[str, Any]:
        """Obtener estadísticas de disco usando comandos nativos."""
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    parts = lines[1].split()
                    if len(parts) >= 6:
                        return {
                            'total': parts[1],
                            'usado': parts[2],
                            'disponible': parts[3],
                            'porcentaje_uso': float(parts[4].rstrip('%'))
                        }
            return {'total': '0G', 'usado': '0G', 'disponible': '0G', 'porcentaje_uso': 0.0}
        except (ValueError, TypeError, AttributeError):
            return {'total': '0G', 'usado': '0G', 'disponible': '0G', 'porcentaje_uso': 0.0}
    
    def _obtener_red_nativo(self) -> Dict[str, Any]:
        """Obtener estadísticas de red usando comandos nativos."""
        try:
            result = subprocess.run(['ss', '-s'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                total_conexiones = 0
                for line in result.stdout.split('\n'):
                    if 'TCP:' in line:
                        # Extraer número de conexiones TCP
                        match = re.search(r'(\d+) established', line)
                        if match:
                            total_conexiones = int(match.group(1))
                return {'conexiones_tcp': total_conexiones}
            return {'conexiones_tcp': 0}
        except (ValueError, TypeError, AttributeError):
            return {'conexiones_tcp': 0}
        
        return estadisticas

    def limpiar_sesion_segura(self):
        """Limpiar sesión de forma segura."""
        try:
            # Limpiar cache
            if hasattr(self, '_cache_resultados'):
                self._cache_resultados['escaneos'].clear()
                self.logger.info("Cache de resultados limpiado")
            
            # Limpiar archivos temporales
            self._limpiar_recursos()
            
            # Generar reporte final
            reporte_final = self.generar_reporte_seguridad()
            self.logger.info(f"Sesión finalizada - Total operaciones: {sum(self._contador_operaciones.values())}")
            
            # Resetear métricas
            self._metricas_seguridad = {
                'intentos_fallidos': 0,
                'comandos_bloqueados': 0,
                'alertas_seguridad': [],
                'patrones_anomalos': {},
                'sesion_iniciada': datetime.datetime.now(),
                'ultima_actividad': datetime.datetime.now(),
                'operaciones_por_minuto': [],
                'ips_consultadas': set(),
                'dominios_consultados': set()
            }
            
            return reporte_final
            
        except Exception as e:
            self.logger.error(f"Error limpiando sesión: {e}")
            return {'error': f'Error en limpieza: {e}'}

    def _limpiar_recursos(self):
        """Limpiar archivos temporales y recursos."""
        for archivo in list(self._archivos_temporales):
            try:
                if os.path.exists(archivo):
                    # Sobrescribir antes de eliminar si es archivo
                    if os.path.isfile(archivo):
                        with open(archivo, 'wb') as f:
                            f.write(os.urandom(os.path.getsize(archivo)))
                    # Si es directorio, eliminar recursivamente
                    if os.path.isdir(archivo):
                        import shutil
                        shutil.rmtree(archivo)
                    else:
                        os.remove(archivo)
                self._archivos_temporales.discard(archivo)
            except Exception as e:
                self.logger.error(f"Error limpiando archivo temporal: {e}")

    def __del__(self):
        """Destructor para limpieza automática."""
        try:
            self._limpiar_recursos()
        except (ValueError, TypeError, AttributeError):
            pass
