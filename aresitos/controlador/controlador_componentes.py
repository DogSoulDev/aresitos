# -*- coding: utf-8 -*-
"""
ARESITOS V3 - Gestor de Componentes Optimizado
Gestión centralizada de componentes con arquitectura Python nativo + Kali tools
"""

import threading
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Set, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from aresitos.controlador.controlador_base import ControladorBase

class GestorComponentes(ControladorBase):
    """
    Gestor centralizado de componentes ARESITOS V3.
    Arquitectura: Python nativo + herramientas Kali Linux optimizado
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "GestorComponentes")
        
        # Thread safety
        self._lock_componentes = threading.RLock()
        self._lock_cache = threading.RLock()
        
        # Cache inteligente de estado de componentes
        self._cache_estado = {}
        self._cache_timeout = 30  # 30 segundos
        self._ultima_actualizacion = {}
        
        # Estado de componentes optimizado
        self._componentes_estado = {
            'siem': {
                'inicializado': False, 
                'instancia': None, 
                'error': None,
                'prioridad': 1,
                'critico': True,
                'dependencias': []
            },
            'fim': {
                'inicializado': False, 
                'instancia': None, 
                'error': None,
                'prioridad': 2,
                'critico': True,
                'dependencias': ['siem']
            },
            'escaneador': {
                'inicializado': False, 
                'instancia': None, 
                'error': None,
                'prioridad': 3,
                'critico': True,
                'dependencias': ['siem']
            },
            'cuarentena': {
                'inicializado': False, 
                'instancia': None, 
                'error': None,
                'prioridad': 4,
                'critico': False,
                'dependencias': ['escaneador', 'siem']
            },
            'auditoria': {
                'inicializado': False, 
                'instancia': None, 
                'error': None,
                'prioridad': 5,
                'critico': False,
                'dependencias': ['siem', 'fim']
            },
            'reportes': {
                'inicializado': False, 
                'instancia': None, 
                'error': None,
                'prioridad': 6,
                'critico': False,
                'dependencias': ['siem']
            }
        }
        
        # Orden optimizado por prioridad y dependencias
        self._orden_inicializacion = sorted(
            self._componentes_estado.keys(),
            key=lambda x: self._componentes_estado[x]['prioridad']
        )
        
        # Configuración de timeouts optimizada
        self._timeouts_componentes = {
            'inicializacion': 30,
            'operacion': 60,
            'finalizacion': 15,
            'health_check': 5
        }
        
        # Pool de threads para operaciones paralelas
        self._thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ComponentesAresitos")
        
        self.logger.info("[INIT] Gestor de Componentes ARESITOS V3 inicializado")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación optimizada de inicialización del gestor."""
        try:
            # Verificar estado inicial
            with self._lock_componentes:
                componentes_disponibles = 0
                for componente in self._componentes_estado.values():
                    if componente['instancia'] is not None:
                        componentes_disponibles += 1
            
            self.logger.info(f"[INIT] Gestión de {len(self._componentes_estado)} componentes ARESITOS V3")
            
            return {
                'exito': True, 
                'mensaje': 'Gestor de componentes ARESITOS V3 inicializado',
                'componentes_disponibles': componentes_disponibles,
                'arquitectura': 'Python nativo + Kali tools'
            }
        except Exception as e:
            error_msg = f"Error en inicialización del gestor: {str(e)}"
            self.logger.error(f"[ERROR] {error_msg}")
            return {'exito': False, 'error': error_msg}
    
    def _obtener_estado_desde_cache(self, nombre_componente: str) -> Optional[Dict[str, Any]]:
        """Obtener estado desde cache con timeout inteligente."""
        with self._lock_cache:
            if nombre_componente not in self._cache_estado:
                return None
            
            tiempo_actual = datetime.now()
            ultima_act = self._ultima_actualizacion.get(nombre_componente)
            
            if ultima_act and (tiempo_actual - ultima_act).total_seconds() < self._cache_timeout:
                return self._cache_estado[nombre_componente]
            
            # Cache expirado
            return None
    
    def _actualizar_cache_estado(self, nombre_componente: str, estado: Dict[str, Any]) -> None:
        """Actualizar cache de estado de componente."""
        with self._lock_cache:
            self._cache_estado[nombre_componente] = estado.copy()
            self._ultima_actualizacion[nombre_componente] = datetime.now()
    
    def _verificar_dependencias_componente(self, nombre_componente: str) -> bool:
        """Verificar que las dependencias de un componente estén inicializadas."""
        if nombre_componente not in self._componentes_estado:
            return False
        
        dependencias = self._componentes_estado[nombre_componente]['dependencias']
        
        for dep in dependencias:
            if dep not in self._componentes_estado:
                self.logger.warning(f"[DEP] Dependencia desconocida: {dep} para {nombre_componente}")
                continue
            
            if not self._componentes_estado[dep]['inicializado']:
                self.logger.warning(f"[DEP] Dependencia no inicializada: {dep} para {nombre_componente}")
                return False
        
        return True
    
    def inicializar_componentes_ordenado(self) -> Dict[str, Any]:
        """Inicializar componentes con manejo optimizado de dependencias."""
        try:
            self.logger.info("[INIT] Iniciando componentes en orden de dependencias ARESITOS V3...")
            
            resultados = {
                'componentes_iniciados': [],
                'componentes_fallidos': [],
                'componentes_opcionales': [],
                'errores': {},
                'tiempo_total': 0,
                'arquitectura': 'Python nativo + Kali tools'
            }
            
            tiempo_inicio = datetime.now()
            
            # Inicializar componentes críticos primero
            componentes_criticos = [c for c in self._orden_inicializacion 
                                  if self._componentes_estado[c]['critico']]
            componentes_opcionales = [c for c in self._orden_inicializacion 
                                    if not self._componentes_estado[c]['critico']]
            
            # Fase 1: Componentes críticos
            self.logger.info("[PHASE1] Inicializando componentes críticos...")
            for nombre_componente in componentes_criticos:
                resultado = self._procesar_inicializacion_componente(nombre_componente, resultados)
                if not resultado and self._componentes_estado[nombre_componente]['critico']:
                    self.logger.error(f"[CRITICAL] Componente crítico {nombre_componente} falló")
            
            # Fase 2: Componentes opcionales (no bloquean el sistema)
            self.logger.info("[PHASE2] Inicializando componentes opcionales...")
            for nombre_componente in componentes_opcionales:
                self._procesar_inicializacion_componente(nombre_componente, resultados, es_opcional=True)
            
            tiempo_total = (datetime.now() - tiempo_inicio).total_seconds()
            resultados['tiempo_total'] = round(tiempo_total, 2)
            
            # Evaluar éxito
            componentes_exitosos = len(resultados['componentes_iniciados'])
            total_componentes = len(self._orden_inicializacion)
            componentes_criticos_ok = sum(1 for c in componentes_criticos 
                                        if c in resultados['componentes_iniciados'])
            
            # Sistema funcional si al menos SIEM está OK
            sistema_funcional = 'siem' in resultados['componentes_iniciados']
            
            resultado_final = {
                'exito': sistema_funcional,
                'sistema_funcional': sistema_funcional,
                'componentes_exitosos': componentes_exitosos,
                'componentes_criticos_ok': componentes_criticos_ok,
                'total_componentes': total_componentes,
                'porcentaje_exito': round((componentes_exitosos / total_componentes) * 100, 1),
                'detalles': resultados
            }
            
            mensaje = f"Inicialización ARESITOS V3: {componentes_exitosos}/{total_componentes} componentes"
            self.logger.info(f"[SUCCESS] {mensaje}")
            
            return resultado_final
            
        except Exception as e:
            error_msg = f"Error crítico en inicialización de componentes: {str(e)}"
            self.logger.error(f"[CRITICAL] {error_msg}")
            return {'exito': False, 'error': error_msg}
    
    def _procesar_inicializacion_componente(self, nombre_componente: str, resultados: Dict, es_opcional: bool = False) -> bool:
        """Procesar inicialización de un componente individual."""
        try:
            self.logger.info(f"[COMP] Inicializando: {nombre_componente}")
            
            # Verificar dependencias
            if not self._verificar_dependencias_componente(nombre_componente):
                error_msg = f"Dependencias no satisfechas para {nombre_componente}"
                if not es_opcional:
                    resultados['componentes_fallidos'].append(nombre_componente)
                    resultados['errores'][nombre_componente] = error_msg
                    self.logger.error(f"[DEP_ERROR] {error_msg}")
                    return False
                else:
                    resultados['componentes_opcionales'].append(nombre_componente)
                    self.logger.warning(f"[DEP_SKIP] {error_msg} (opcional)")
                    return False
            
            # Inicializar componente
            with self._lock_componentes:
                resultado = self._inicializar_componente_individual(nombre_componente)
            
            if resultado['exito']:
                resultados['componentes_iniciados'].append(nombre_componente)
                self._componentes_estado[nombre_componente]['inicializado'] = True
                self.logger.info(f"[OK] Componente {nombre_componente} inicializado")
                return True
            else:
                if es_opcional:
                    resultados['componentes_opcionales'].append(nombre_componente)
                    self.logger.warning(f"[OPTIONAL_FAIL] {nombre_componente}: {resultado.get('error', 'Sin detalles')}")
                else:
                    resultados['componentes_fallidos'].append(nombre_componente)
                    resultados['errores'][nombre_componente] = resultado.get('error', 'Error desconocido')
                    self.logger.error(f"[FAIL] Componente {nombre_componente}: {resultado.get('error')}")
                return False
                
        except Exception as e:
            error_msg = f"Excepción inicializando {nombre_componente}: {str(e)}"
            if es_opcional:
                resultados['componentes_opcionales'].append(nombre_componente)
                self.logger.warning(f"[OPTIONAL_EXCEPTION] {error_msg}")
            else:
                resultados['componentes_fallidos'].append(nombre_componente)
                resultados['errores'][nombre_componente] = error_msg
                self.logger.error(f"[EXCEPTION] {error_msg}")
            return False
    
    def _inicializar_componente_individual(self, nombre_componente: str) -> Dict[str, Any]:
        """Inicializar componente individual con manejo optimizado."""
        try:
            inicio_tiempo = time.time()
            
            # Usar mapeo optimizado
            metodos_inicializacion = {
                'siem': self._inicializar_siem,
                'fim': self._inicializar_fim,
                'escaneador': self._inicializar_escaneador,
                'cuarentena': self._inicializar_cuarentena,
                'auditoria': self._inicializar_auditoria,
                'reportes': self._inicializar_reportes
            }
            
            if nombre_componente not in metodos_inicializacion:
                return {'exito': False, 'error': f'Componente desconocido: {nombre_componente}'}
            
            # Ejecutar inicialización con timeout
            metodo = metodos_inicializacion[nombre_componente]
            resultado = metodo()
            
            tiempo_transcurrido = round(time.time() - inicio_tiempo, 2)
            resultado['tiempo_inicializacion'] = tiempo_transcurrido
            
            # Actualizar cache
            self._actualizar_cache_estado(nombre_componente, resultado)
            
            return resultado
                
        except Exception as e:
            error_msg = f"Error en inicialización de {nombre_componente}: {str(e)}"
            self.logger.error(f"[COMP_ERROR] {error_msg}")
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_siem(self) -> Dict[str, Any]:
        """Inicializar SIEM con arquitectura ARESITOS V3."""
        try:
            self.logger.info("[SIEM] Inicializando SIEM Kali2025...")
            
            # Intentar importar SIEM optimizado con fallback robusto
            siem_instance = None
            siem_class = None
            version_usada = "mock"
            
            try:
                # Intentar SIEM estándar que sí existe
                from aresitos.modelo.modelo_siem import SIEMKali2025
                siem_class = SIEMKali2025
                version_usada = "estándar"
                self.logger.info("[SIEM] Usando SIEMKali2025 estándar")
            except (ImportError, AttributeError, ModuleNotFoundError) as e:
                self.logger.debug(f"[SIEM] ModeloSIEM no disponible: {e}")
                # Crear mock SIEM para mantener funcionalidad
                class MockSIEM:
                    def __init__(self):
                        self.version = "mock_v1.0"
                        self.eventos = []
                    
                    def _guardar_evento_seguridad(self, evento):
                        self.eventos.append(evento)
                        return True
                    
                    def obtener_eventos(self):
                        return self.eventos
                    
                    def health_check(self):
                        return {"estado": "mock_activo", "eventos": len(self.eventos)}
                
                siem_class = MockSIEM
                version_usada = "mock"
                self.logger.warning("[SIEM] Usando SIEM mock para funcionalidad básica")
            
            # Crear instancia SIEM de forma segura
            try:
                siem_instance = siem_class()
            except Exception as e:
                return {'exito': False, 'error': f'Error creando instancia SIEM: {str(e)}'}
            
            # Test básico de funcionalidad
            if hasattr(siem_instance, '_guardar_evento_seguridad'):
                evento_test = {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'INIT_SIEM_V3',
                    'mensaje': 'SIEM ARESITOS V3 inicializado correctamente',
                    'nivel': 'info',
                    'componente': 'GestorComponentes'
                }
                try:
                    siem_instance._guardar_evento_seguridad(evento_test)
                    self.logger.info("[SIEM] Test de evento ejecutado correctamente")
                except Exception as e:
                    self.logger.warning(f"[SIEM] Warning en test de evento: {e}")
            
            # Guardar referencia thread-safe
            with self._lock_componentes:
                self._componentes_estado['siem']['instancia'] = siem_instance
                
                # Hacer disponible en modelo principal de forma segura
                try:
                    if hasattr(self.modelo_principal, 'siem_avanzado'):
                        self.modelo_principal.siem_avanzado = siem_instance
                        self.logger.info("[SIEM] Instancia asignada a modelo principal como siem_avanzado")
                    elif hasattr(self.modelo_principal, 'siem'):
                        self.modelo_principal.siem = siem_instance
                        self.logger.info("[SIEM] Instancia asignada a modelo principal como siem")
                    else:
                        self.logger.warning("[SIEM] No se encontró atributo para SIEM en modelo principal")
                except Exception as e:
                    self.logger.warning(f"[SIEM] Error asignando instancia a modelo principal: {e}")
            
            return {
                'exito': True, 
                'mensaje': f'SIEM ARESITOS V3 inicializado correctamente (versión: {version_usada})',
                'componente': 'SIEM',
                'version': version_usada,
                'tipo_instancia': type(siem_instance).__name__,
                'funcionalidades': ['eventos', 'correlacion', 'alertas'] if version_usada != "mock" else ['eventos_mock']
            }
            
        except Exception as e:
            error_msg = f"Error crítico inicializando SIEM: {str(e)}"
            self.logger.error(f"[SIEM_ERROR] {error_msg}")
            with self._lock_componentes:
                self._componentes_estado['siem']['error'] = error_msg
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_fim(self) -> Dict[str, Any]:
        """Inicializar FIM con optimización ARESITOS V3."""
        try:
            self.logger.info("[FIM] Inicializando FIM con baseline inteligente...")
            
            # Intentar importar FIM optimizado con fallback robusto
            fim_instance = None
            fim_class = None
            version_usada = "mock"
            
            try:
                from aresitos.modelo.modelo_fim_kali2025 import FIMKali2025
                fim_class = FIMKali2025
                version_usada = "Kali2025"
                self.logger.info("[FIM] Usando FIMKali2025 optimizado")
            except (ImportError, AttributeError, ModuleNotFoundError) as e:
                self.logger.debug(f"[FIM] FIMKali2025 no disponible: {e}")
                try:
                    from aresitos.modelo.modelo_fim import FIMKali2025
                    fim_class = FIMKali2025
                    version_usada = "estándar"
                    self.logger.warning("[FIM] Usando FIM estándar")
                except (ImportError, AttributeError, ModuleNotFoundError) as e:
                    self.logger.debug(f"[FIM] FIM estándar no disponible: {e}")
                    # Crear mock FIM para mantener funcionalidad
                    class MockFIM:
                        def __init__(self):
                            self.version = "mock_v1.0"
                            self.baseline = {}
                        
                        def establecer_baseline(self, baseline_info):
                            self.baseline = baseline_info
                            return True
                        
                        def set_baseline(self, baseline_info):
                            return self.establecer_baseline(baseline_info)
                        
                        def health_check(self):
                            return {"estado": "mock_activo", "archivos": len(self.baseline)}
                    
                    fim_class = MockFIM
                    version_usada = "mock"
                    self.logger.warning("[FIM] Usando FIM mock para funcionalidad básica")
            
            # Crear instancia FIM de forma segura
            try:
                fim_instance = fim_class()
            except Exception as e:
                return {'exito': False, 'error': f'Error creando instancia FIM: {str(e)}'}
            
            # Configurar rutas críticas optimizadas para Kali Linux
            rutas_criticas = [
                '/etc/passwd', '/etc/shadow', '/etc/group',
                '/etc/hosts', '/etc/resolv.conf',
                '/etc/ssh/sshd_config', '/etc/sudoers',
                '/etc/crontab', '/etc/fstab',
                '/boot/grub/grub.cfg'
            ]
            
            # Crear baseline inteligente con verificación de existencia
            baseline_info = {}
            archivos_monitoreados = 0
            
            for ruta in rutas_criticas:
                try:
                    import os
                    import hashlib
                    
                    if os.path.exists(ruta) and os.access(ruta, os.R_OK):
                        # Crear hash MD5 eficiente
                        hasher = hashlib.md5()
                        try:
                            with open(ruta, 'rb') as f:
                                # Leer en chunks para archivos grandes
                                for chunk in iter(lambda: f.read(4096), b""):
                                    hasher.update(chunk)
                            
                            stat_info = os.stat(ruta)
                            baseline_info[ruta] = {
                                'hash': hasher.hexdigest(),
                                'size': stat_info.st_size,
                                'mtime': stat_info.st_mtime,
                                'permissions': oct(stat_info.st_mode)[-3:]
                            }
                            archivos_monitoreados += 1
                            
                        except PermissionError:
                            self.logger.warning(f"[FIM] Sin permisos para leer: {ruta}")
                        except Exception as e:
                            self.logger.warning(f"[FIM] Error procesando {ruta}: {e}")
                    else:
                        self.logger.debug(f"[FIM] Archivo no accesible: {ruta}")
                        
                except Exception as e:
                    self.logger.warning(f"[FIM] Error con {ruta}: {e}")
                    continue
            
            # Registrar baseline en FIM si tiene el método
            baseline_registrado = False
            for metodo_baseline in ['establecer_baseline', 'set_baseline', 'create_baseline']:
                if hasattr(fim_instance, metodo_baseline):
                    try:
                        metodo = getattr(fim_instance, metodo_baseline)
                        metodo(baseline_info)
                        baseline_registrado = True
                        self.logger.info(f"[FIM] Baseline establecido ({metodo_baseline}) con {archivos_monitoreados} archivos")
                        break
                    except Exception as e:
                        self.logger.warning(f"[FIM] Error estableciendo baseline ({metodo_baseline}): {e}")
                        continue
            
            if not baseline_registrado:
                self.logger.info("[FIM] Instancia FIM no soporta baseline automático")
            
            # Guardar referencia thread-safe
            with self._lock_componentes:
                self._componentes_estado['fim']['instancia'] = fim_instance
                
                # Hacer disponible en modelo principal de forma segura
                try:
                    if hasattr(self.modelo_principal, 'fim_avanzado'):
                        self.modelo_principal.fim_avanzado = fim_instance
                        self.logger.info("[FIM] Instancia asignada a modelo principal como fim_avanzado")
                    elif hasattr(self.modelo_principal, 'fim'):
                        self.modelo_principal.fim = fim_instance
                        self.logger.info("[FIM] Instancia asignada a modelo principal como fim")
                    else:
                        self.logger.warning("[FIM] No se encontró atributo para FIM en modelo principal")
                except Exception as e:
                    self.logger.warning(f"[FIM] Error asignando instancia a modelo principal: {e}")
            
            return {
                'exito': True,
                'componente': 'FIM',
                'version': version_usada,
                'archivos_monitoreados': archivos_monitoreados,
                'baseline_creado': baseline_registrado,
                'baseline_archivos': len(baseline_info),
                'tipo_instancia': type(fim_instance).__name__,
                'mensaje': f'FIM ARESITOS V3 inicializado con {archivos_monitoreados} archivos críticos (baseline: {baseline_registrado})'
            }
            
        except Exception as e:
            error_msg = f"Error inicializando FIM: {str(e)}"
            self.logger.error(f"[FIM_ERROR] {error_msg}")
            with self._lock_componentes:
                self._componentes_estado['fim']['error'] = error_msg
            return {'exito': False, 'error': error_msg}

    def _inicializar_escaneador(self) -> Dict[str, Any]:
        """Inicializar Escaneador con arquitectura ARESITOS V3."""
        try:
            self.logger.info("[SCANNER] Inicializando Escaneador consolidado...")
            
            # Intentar importar escaneadores optimizados con fallback robusto
            escaneador_instance = None
            escaneador_class = None
            version_usada = "mock"
            
            try:
                # Usar escaneador unificado
                from aresitos.modelo.modelo_escaneador import EscaneadorCompleto
                escaneador_class = EscaneadorCompleto
                version_usada = "unificado"
                self.logger.info("[SCANNER] Usando EscaneadorCompleto unificado")
            except (ImportError, AttributeError, ModuleNotFoundError) as e:
                try:
                    # Fallback a escaneador estándar
                    from aresitos.modelo.modelo_escaneador import EscaneadorCompleto
                    escaneador_class = EscaneadorCompleto
                    version_usada = "estándar"
                    self.logger.info("[SCANNER] Usando EscaneadorCompleto estándar")
                except (ImportError, AttributeError, ModuleNotFoundError) as e:
                    self.logger.debug(f"[SCANNER] EscaneadorCompleto no disponible: {e}")
                    # Crear mock escaneador para mantener funcionalidad
                class MockEscaneador:
                    def __init__(self):
                        self.version = "mock_v1.0"
                        self.resultados = []
                    
                    def escanear_red(self, target="127.0.0.1"):
                        return {"exito": True, "tipo": "mock", "resultados": []}
                    
                    def health_check(self):
                        return {"estado": "mock_activo", "herramientas": ["mock"]}
                
                escaneador_class = MockEscaneador
                version_usada = "mock"
                self.logger.warning("[SCANNER] Usando Escaneador mock para funcionalidad básica")
            
            # Crear instancia Escaneador de forma segura
            try:
                escaneador_instance = escaneador_class()
            except Exception as e:
                return {'exito': False, 'error': f'Error creando instancia Escaneador: {str(e)}'}
            
            # Verificar herramientas Kali disponibles (no bloquear si faltan)
            herramientas_disponibles = []
            herramientas_kali = ['nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'nuclei']
            
            import subprocess
            import shutil
            
            for herramienta in herramientas_kali:
                try:
                    if shutil.which(herramienta):
                        herramientas_disponibles.append(herramienta)
                except Exception:
                    pass
            
            self.logger.info(f"[SCANNER] Herramientas Kali disponibles: {len(herramientas_disponibles)}")
            
            # Test básico de conectividad
            conectividad_ok = False
            try:
                resultado = subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                                        capture_output=True, timeout=5)
                conectividad_ok = resultado.returncode == 0
            except Exception:
                pass
            
            # Guardar referencia thread-safe
            with self._lock_componentes:
                self._componentes_estado['escaneador']['instancia'] = escaneador_instance
                
                # Hacer disponible en modelo principal de forma segura
                try:
                    if hasattr(self.modelo_principal, 'escaneador_avanzado'):
                        self.modelo_principal.escaneador_avanzado = escaneador_instance
                        self.logger.info("[SCANNER] Instancia asignada a modelo principal como escaneador_avanzado")
                    elif hasattr(self.modelo_principal, 'escaneador_consolidado'):
                        self.modelo_principal.escaneador_consolidado = escaneador_instance
                        self.logger.info("[SCANNER] Instancia asignada a modelo principal como escaneador_consolidado")
                    elif hasattr(self.modelo_principal, 'escaneador'):
                        self.modelo_principal.escaneador = escaneador_instance
                        self.logger.info("[SCANNER] Instancia asignada a modelo principal como escaneador")
                    else:
                        self.logger.warning("[SCANNER] No se encontró atributo para Escaneador en modelo principal")
                except Exception as e:
                    self.logger.warning(f"[SCANNER] Error asignando instancia a modelo principal: {e}")
            
            return {
                'exito': True,
                'componente': 'Escaneador',
                'version': version_usada,
                'herramientas_disponibles': herramientas_disponibles,
                'total_herramientas': len(herramientas_disponibles),
                'conectividad': conectividad_ok,
                'tipo_instancia': type(escaneador_instance).__name__,
                'mensaje': f'Escaneador ARESITOS V3 inicializado ({version_usada}) con {len(herramientas_disponibles)} herramientas Kali'
            }
            
        except Exception as e:
            error_msg = f"Error inicializando Escaneador: {str(e)}"
            self.logger.error(f"[SCANNER_ERROR] {error_msg}")
            with self._lock_componentes:
                self._componentes_estado['escaneador']['error'] = error_msg
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_cuarentena(self) -> Dict[str, Any]:
        """Inicializar Cuarentena como componente opcional."""
        try:
            self.logger.info("[QUARANTINE] Inicializando sistema de cuarentena...")
            
            # Intentar importar sistemas de cuarentena
            cuarentena_instance = None
            version_usada = "mock"
            
            try:
                from aresitos.modelo.modelo_cuarentena_kali2025 import CuarentenaKali2025
                cuarentena_instance = CuarentenaKali2025()
                version_usada = "Kali2025"
                self.logger.info("[QUARANTINE] Usando CuarentenaKali2025")
            except (ImportError, AttributeError, ModuleNotFoundError) as e:
                self.logger.debug(f"[QUARANTINE] CuarentenaKali2025 no disponible: {e}")
                # Crear mock para mantener funcionalidad básica
                self.logger.warning("[QUARANTINE] Creando sistema mock de cuarentena")
                
                class MockCuarentena:
                    def obtener_estadisticas(self):
                        return {
                            "total_archivos": 0, 
                            "estado": "no_disponible",
                            "version": "mock"
                        }
                    
                    def procesar_amenaza(self, amenaza):
                        return {"exito": False, "razon": "Sistema mock"}
                    
                    def listar_amenazas(self):
                        return []
                
                cuarentena_instance = MockCuarentena()
                version_usada = "mock"
            
            # Verificar funcionalidad básica con manejo robusto
            estadisticas = {}
            try:
                # Intentar diferentes métodos de estadísticas
                metodos_estadisticas = ['obtener_estadisticas', 'get_estadisticas', 'get_stats', 'statistics', 'status']
                estadisticas_obtenidas = False
                
                for metodo_nombre in metodos_estadisticas:
                    if hasattr(cuarentena_instance, metodo_nombre):
                        try:
                            metodo = getattr(cuarentena_instance, metodo_nombre)
                            estadisticas = metodo()
                            estadisticas_obtenidas = True
                            break
                        except Exception as e:
                            self.logger.debug(f"[QUARANTINE] Error con {metodo_nombre}: {e}")
                            continue
                
                if not estadisticas_obtenidas:
                    estadisticas = {"estado": "funcional", "version": version_usada, "metodo": "default"}
                
                if not isinstance(estadisticas, dict):
                    estadisticas = {"error": "Formato inválido", "resultado": str(estadisticas), "version": version_usada}
                    
            except Exception as e:
                estadisticas = {"error": str(e), "version": version_usada}
            
            # Guardar referencia thread-safe
            with self._lock_componentes:
                self._componentes_estado['cuarentena']['instancia'] = cuarentena_instance
                
                # Hacer disponible en modelo principal de forma segura
                try:
                    if hasattr(self.modelo_principal, 'gestor_cuarentena'):
                        self.modelo_principal.gestor_cuarentena = cuarentena_instance
                        self.logger.info("[QUARANTINE] Instancia asignada a modelo principal como gestor_cuarentena")
                    elif hasattr(self.modelo_principal, 'cuarentena_avanzada'):
                        self.modelo_principal.cuarentena_avanzada = cuarentena_instance
                        self.logger.info("[QUARANTINE] Instancia asignada a modelo principal como cuarentena_avanzada")
                    elif hasattr(self.modelo_principal, 'cuarentena'):
                        self.modelo_principal.cuarentena = cuarentena_instance
                        self.logger.info("[QUARANTINE] Instancia asignada a modelo principal como cuarentena")
                    else:
                        self.logger.warning("[QUARANTINE] No se encontró atributo para Cuarentena en modelo principal")
                except Exception as e:
                    self.logger.warning(f"[QUARANTINE] Error asignando instancia a modelo principal: {e}")
            
            return {
                'exito': True,
                'componente': 'Cuarentena',
                'version': version_usada,
                'estadisticas': estadisticas,
                'tipo_instancia': type(cuarentena_instance).__name__,
                'mensaje': f'Cuarentena {version_usada} inicializada correctamente'
            }
            
        except Exception as e:
            error_msg = f"Error inicializando Cuarentena: {str(e)}"
            self.logger.warning(f"[QUARANTINE_WARN] {error_msg}")
            with self._lock_componentes:
                self._componentes_estado['cuarentena']['error'] = error_msg
            # Cuarentena no es crítica, no fallar el sistema
            return {'exito': True, 'mensaje': f'Cuarentena no disponible (opcional): {error_msg}'}
    
    def _inicializar_auditoria(self) -> Dict[str, Any]:
        """Inicializar Auditoría como componente opcional."""
        try:
            self.logger.info("[AUDIT] Configurando sistema de auditoría...")
            
            # Auditoría es opcional y se basa en otros componentes
            siem_disponible = self._componentes_estado['siem']['inicializado']
            fim_disponible = self._componentes_estado['fim']['inicializado']
            
            # Crear referencia básica de auditoría
            auditoria_info = {
                'siem_integrado': siem_disponible,
                'fim_integrado': fim_disponible,
                'logs_sistema': True,  # Siempre disponible en Linux
                'timestamp_inicio': datetime.now().isoformat()
            }
            
            with self._lock_componentes:
                # Guardar configuración en lugar de instancia
                self._componentes_estado['auditoria']['instancia'] = auditoria_info
            
            mensaje = f"Auditoría configurada (SIEM: {siem_disponible}, FIM: {fim_disponible})"
            self.logger.info(f"[AUDIT] {mensaje}")
            
            return {
                'exito': True,
                'componente': 'Auditoría',
                'configuracion': auditoria_info,
                'mensaje': mensaje
            }
            
        except Exception as e:
            error_msg = f"Error configurando Auditoría: {str(e)}"
            self.logger.warning(f"[AUDIT_WARN] {error_msg}")
            with self._lock_componentes:
                self._componentes_estado['auditoria']['error'] = error_msg
            return {'exito': True, 'mensaje': f'Auditoría no disponible (opcional): {error_msg}'}
    
    def _inicializar_reportes(self) -> Dict[str, Any]:
        """Inicializar Reportes como componente opcional."""
        try:
            self.logger.info("[REPORTS] Configurando sistema de reportes...")
            
            # Verificar qué componentes están disponibles para reportes
            componentes_reportes = {}
            for nombre, estado in self._componentes_estado.items():
                if estado['inicializado'] and nombre != 'reportes':
                    componentes_reportes[nombre] = {
                        'disponible': True,
                        'instancia_tipo': type(estado['instancia']).__name__ if estado['instancia'] else 'None'
                    }
            
            # Configurar capacidades de reportes
            reportes_config = {
                'componentes_integrados': list(componentes_reportes.keys()),
                'total_fuentes': len(componentes_reportes),
                'formatos_soportados': ['JSON', 'TXT', 'HTML'],
                'timestamp_config': datetime.now().isoformat()
            }
            
            with self._lock_componentes:
                # Guardar configuración en lugar de instancia específica
                self._componentes_estado['reportes']['instancia'] = reportes_config
            
            mensaje = f"Reportes configurados con {len(componentes_reportes)} fuentes de datos"
            self.logger.info(f"[REPORTS] {mensaje}")
            
            return {
                'exito': True,
                'componente': 'Reportes',
                'configuracion': reportes_config,
                'mensaje': mensaje
            }
            
        except Exception as e:
            error_msg = f"Error configurando Reportes: {str(e)}"
            self.logger.warning(f"[REPORTS_WARN] {error_msg}")
            with self._lock_componentes:
                self._componentes_estado['reportes']['error'] = error_msg
            return {'exito': True, 'mensaje': f'Reportes no disponibles (opcional): {error_msg}'}
    
    def obtener_estado_componentes(self) -> Dict[str, Any]:
        """Obtener estado actual optimizado con cache inteligente."""
        try:
            # Intentar usar cache primero
            cache_key = "estado_global"
            estado_cached = self._obtener_estado_desde_cache(cache_key)
            if estado_cached:
                self.logger.debug("[CACHE] Usando estado desde cache")
                return estado_cached
            
            # Generar estado actual thread-safe
            with self._lock_componentes:
                estado_actual = {}
                
                for nombre, info in self._componentes_estado.items():
                    estado_actual[nombre] = {
                        'inicializado': info['inicializado'],
                        'disponible': info['instancia'] is not None,
                        'critico': info['critico'],
                        'prioridad': info['prioridad'],
                        'dependencias': info['dependencias'],
                        'error': info['error'],
                        'tipo_instancia': type(info['instancia']).__name__ if info['instancia'] else None,
                        'version': getattr(info['instancia'], 'version', 'N/A') if info['instancia'] else 'N/A'
                    }
            
            # Calcular métricas optimizadas
            total_componentes = len(self._componentes_estado)
            componentes_iniciados = sum(1 for info in self._componentes_estado.values() if info['inicializado'])
            componentes_disponibles = sum(1 for info in self._componentes_estado.values() if info['instancia'] is not None)
            componentes_criticos = sum(1 for info in self._componentes_estado.values() if info['critico'])
            componentes_criticos_ok = sum(1 for info in self._componentes_estado.values() 
                                        if info['critico'] and info['inicializado'])
            
            # Evaluar salud del sistema
            salud_sistema = "CRITICO"
            if componentes_criticos_ok >= componentes_criticos:
                salud_sistema = "OPTIMO"
            elif componentes_criticos_ok >= (componentes_criticos * 0.7):
                salud_sistema = "FUNCIONAL"
            elif componentes_criticos_ok > 0:
                salud_sistema = "DEGRADADO"
            
            resumen = {
                'total_componentes': total_componentes,
                'componentes_iniciados': componentes_iniciados,
                'componentes_disponibles': componentes_disponibles,
                'componentes_criticos': componentes_criticos,
                'componentes_criticos_ok': componentes_criticos_ok,
                'porcentaje_iniciados': round((componentes_iniciados / total_componentes) * 100, 1),
                'porcentaje_disponibles': round((componentes_disponibles / total_componentes) * 100, 1),
                'porcentaje_criticos_ok': round((componentes_criticos_ok / componentes_criticos) * 100, 1) if componentes_criticos > 0 else 0,
                'salud_sistema': salud_sistema,
                'arquitectura': 'ARESITOS V3 - Python nativo + Kali tools'
            }
            
            resultado = {
                'exito': True,
                'estado_componentes': estado_actual,
                'resumen': resumen,
                'timestamp': datetime.now().isoformat(),
                'cache_usado': False
            }
            
            # Actualizar cache
            self._actualizar_cache_estado(cache_key, resultado)
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error obteniendo estado de componentes: {str(e)}"
            self.logger.error(f"[STATE_ERROR] {error_msg}")
            return {'exito': False, 'error': error_msg}
    
    def obtener_componente(self, nombre_componente: str) -> Optional[Any]:
        """Obtener referencia thread-safe a un componente específico."""
        try:
            with self._lock_componentes:
                if nombre_componente in self._componentes_estado:
                    return self._componentes_estado[nombre_componente]['instancia']
                return None
        except Exception as e:
            self.logger.error(f"[COMP_GET_ERROR] Error obteniendo componente {nombre_componente}: {e}")
            return None
    
    def health_check_componente(self, nombre_componente: str) -> Dict[str, Any]:
        """Realizar health check de un componente específico."""
        try:
            if nombre_componente not in self._componentes_estado:
                return {'exito': False, 'error': f'Componente {nombre_componente} no existe'}
            
            with self._lock_componentes:
                info = self._componentes_estado[nombre_componente]
                instancia = info['instancia']
            
            if not instancia:
                return {
                    'exito': False, 
                    'componente': nombre_componente,
                    'estado': 'no_inicializado',
                    'mensaje': 'Componente no tiene instancia'
                }
            
            # Health check básico
            health_info = {
                'componente': nombre_componente,
                'inicializado': info['inicializado'],
                'tipo': type(instancia).__name__,
                'critico': info['critico'],
                'timestamp': datetime.now().isoformat()
            }
            
            # Health check específico si el componente lo soporta
            if hasattr(instancia, 'health_check'):
                try:
                    health_especifico = instancia.health_check()
                    health_info['health_especifico'] = health_especifico
                except Exception as e:
                    health_info['health_error'] = str(e)
            
            return {
                'exito': True,
                'health_info': health_info,
                'estado': 'saludable' if info['inicializado'] else 'no_saludable'
            }
            
        except Exception as e:
            error_msg = f"Error en health check de {nombre_componente}: {str(e)}"
            self.logger.error(f"[HEALTH_ERROR] {error_msg}")
            return {'exito': False, 'error': error_msg}
    
    def finalizar_componentes(self) -> Dict[str, Any]:
        """Finalizar componentes de manera ordenada y segura."""
        try:
            self.logger.info("[SHUTDOWN] Iniciando finalización ordenada de componentes...")
            
            # Finalizar en orden inverso de inicialización
            orden_finalizacion = list(reversed(self._orden_inicializacion))
            
            resultados = {
                'componentes_finalizados': [],
                'errores_finalizacion': {},
                'tiempo_total': 0
            }
            
            tiempo_inicio = time.time()
            
            # Usar ThreadPoolExecutor para finalización paralela de componentes no críticos
            componentes_criticos = [c for c in orden_finalizacion 
                                  if self._componentes_estado[c]['critico']]
            componentes_opcionales = [c for c in orden_finalizacion 
                                    if not self._componentes_estado[c]['critico']]
            
            # Fase 1: Finalizar componentes opcionales en paralelo
            if componentes_opcionales:
                self.logger.info("[SHUTDOWN] Finalizando componentes opcionales en paralelo...")
                future_to_componente = {}
                
                with ThreadPoolExecutor(max_workers=3) as executor:
                    for componente in componentes_opcionales:
                        future = executor.submit(self._finalizar_componente_individual, componente)
                        future_to_componente[future] = componente
                    
                    for future in as_completed(future_to_componente, timeout=30):
                        componente = future_to_componente[future]
                        try:
                            resultado = future.result()
                            if resultado['exito']:
                                resultados['componentes_finalizados'].append(componente)
                            else:
                                resultados['errores_finalizacion'][componente] = resultado['error']
                        except Exception as e:
                            resultados['errores_finalizacion'][componente] = str(e)
            
            # Fase 2: Finalizar componentes críticos secuencialmente
            self.logger.info("[SHUTDOWN] Finalizando componentes críticos secuencialmente...")
            for componente in componentes_criticos:
                try:
                    resultado = self._finalizar_componente_individual(componente)
                    if resultado['exito']:
                        resultados['componentes_finalizados'].append(componente)
                        self.logger.info(f"[SHUTDOWN] Componente crítico {componente} finalizado")
                    else:
                        resultados['errores_finalizacion'][componente] = resultado['error']
                        self.logger.error(f"[SHUTDOWN] Error finalizando {componente}: {resultado['error']}")
                except Exception as e:
                    error_msg = f"Excepción finalizando {componente}: {str(e)}"
                    resultados['errores_finalizacion'][componente] = error_msg
                    self.logger.error(f"[SHUTDOWN] {error_msg}")
            
            # Finalizar ThreadPool
            try:
                self._thread_pool.shutdown(wait=True)
                self.logger.info("[SHUTDOWN] ThreadPool finalizado")
            except Exception as e:
                self.logger.warning(f"[SHUTDOWN] Error cerrando ThreadPool: {e}")
            
            tiempo_total = round(time.time() - tiempo_inicio, 2)
            resultados['tiempo_total'] = tiempo_total
            
            # Limpiar cache
            with self._lock_cache:
                self._cache_estado.clear()
                self._ultima_actualizacion.clear()
            
            total_finalizados = len(resultados['componentes_finalizados'])
            total_errores = len(resultados['errores_finalizacion'])
            
            self.logger.info(f"[SHUTDOWN] Finalización completada: {total_finalizados} OK, {total_errores} errores")
            
            return {
                'exito': total_errores == 0,
                'componentes_finalizados': total_finalizados,
                'total_errores': total_errores,
                'tiempo_total': tiempo_total,
                'resultados': resultados
            }
            
        except Exception as e:
            error_msg = f"Error crítico finalizando componentes: {str(e)}"
            self.logger.error(f"[SHUTDOWN_CRITICAL] {error_msg}")
            return {'exito': False, 'error': error_msg}
    
    def _finalizar_componente_individual(self, nombre_componente: str) -> Dict[str, Any]:
        """Finalizar un componente individual de manera segura."""
        try:
            with self._lock_componentes:
                if nombre_componente not in self._componentes_estado:
                    return {'exito': False, 'error': f'Componente {nombre_componente} no existe'}
                
                instancia = self._componentes_estado[nombre_componente]['instancia']
                
                if instancia:
                    # Intentar finalización específica del componente
                    if hasattr(instancia, 'finalizar'):
                        try:
                            instancia.finalizar()
                            self.logger.debug(f"[SHUTDOWN] Método finalizar() ejecutado en {nombre_componente}")
                        except Exception as e:
                            self.logger.warning(f"[SHUTDOWN] Error en finalizar() de {nombre_componente}: {e}")
                    
                    elif hasattr(instancia, 'close'):
                        try:
                            instancia.close()
                            self.logger.debug(f"[SHUTDOWN] Método close() ejecutado en {nombre_componente}")
                        except Exception as e:
                            self.logger.warning(f"[SHUTDOWN] Error en close() de {nombre_componente}: {e}")
                    
                    elif hasattr(instancia, 'cleanup'):
                        try:
                            instancia.cleanup()
                            self.logger.debug(f"[SHUTDOWN] Método cleanup() ejecutado en {nombre_componente}")
                        except Exception as e:
                            self.logger.warning(f"[SHUTDOWN] Error en cleanup() de {nombre_componente}: {e}")
                
                # Limpiar estado del componente
                self._componentes_estado[nombre_componente]['inicializado'] = False
                self._componentes_estado[nombre_componente]['instancia'] = None
                self._componentes_estado[nombre_componente]['error'] = None
            
            return {'exito': True, 'mensaje': f'Componente {nombre_componente} finalizado correctamente'}
            
        except Exception as e:
            error_msg = f"Error finalizando {nombre_componente}: {str(e)}"
            return {'exito': False, 'error': error_msg}
    
    def __del__(self):
        """Destructor para limpieza automática."""
        try:
            if hasattr(self, '_thread_pool') and self._thread_pool:
                self._thread_pool.shutdown(wait=False)
        except Exception:
            pass  # Ignorar errores en destructor
