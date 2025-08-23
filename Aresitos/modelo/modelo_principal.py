# -*- coding: utf-8 -*-
"""
Aresitos V3 - Modelo Principal Optimizado
==========================================

Modelo principal que coordina todos los gestores de datos siguiendo
los principios ARESITOS V3: Python nativo + herramientas Kali Linux.

Autor: ARESITOS Security Team
Versión: 3.0
Fecha: 2025-08-23
"""

import os
import logging
import subprocess
import json
from typing import Optional, Dict, Any, List
from datetime import datetime
import threading
import time

class ModeloPrincipal:
    """
    Modelo principal optimizado de la aplicación que coordina todos los gestores
    siguiendo los principios ARESITOS V3.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Sistema de estado
        self._estado_sistema = {
            'inicializado': False,
            'componentes_activos': {},
            'errores_inicializacion': [],
            'timestamp_inicio': datetime.now()
        }
        
        # Gestores de datos optimizados
        self.gestor_wordlists = None
        self.gestor_diccionarios = None
        self.escaneador_avanzado = None
        self.siem_avanzado = None
        self.monitor_avanzado = None
        self.fim_avanzado = None
        self.dashboard = None
        self.cuarentena = None
        
        # Cache de métricas del sistema
        self._cache_metricas = {}
        self._cache_timeout = 30  # 30 segundos
        self._lock = threading.RLock()
        
        # Configuración del sistema
        self.config_sistema = self._cargar_configuracion_sistema()
        
    
    def _cargar_configuracion_sistema(self) -> Dict[str, Any]:
        """Cargar configuración del sistema desde archivos JSON."""
        config_default = {
            'herramientas_kali': {
                'verificar_existencia': True,
                'timeout_comandos': 30,
                'max_reintentos': 3
            },
            'componentes': {
                'escaneador': True,
                'siem': True,
                'monitor': True,
                'fim': True,
                'dashboard': True,
                'cuarentena': True
            },
            'optimizaciones': {
                'cache_metricas': True,
                'threads_componentes': True,
                'logs_detallados': False
            }
        }
        
        try:
            # Buscar archivos de configuración
            config_paths = [
                'configuración/Aresitos_config.json',
                'configuración/Aresitos_config_kali.json',
                'config/Aresitos.json'
            ]
            
            for path in config_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            config_loaded = json.load(f)
                            config_default.update(config_loaded)
                            self.logger.info(f"Configuración cargada desde: {path}")
                            break
                    except (json.JSONDecodeError, IOError) as e:
                        self.logger.warning(f"Error cargando config desde {path}: {e}")
                        
        except Exception as e:
            self.logger.warning(f"Error cargando configuración: {e}")
        
        return config_default
    
    def _verificar_herramientas_kali(self) -> Dict[str, bool]:
        """Verificar disponibilidad de herramientas nativas de Kali Linux."""
        herramientas_core = {
            'nmap': False,
            'masscan': False,
            'ps': False,
            'free': False,
            'df': False,
            'ss': False,
            'netstat': False,
            'find': False,
            'grep': False,
            'awk': False
        }
        
        try:
            for herramienta in herramientas_core.keys():
                try:
                    resultado = subprocess.run(
                        ['which', herramienta],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    herramientas_core[herramienta] = resultado.returncode == 0
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    herramientas_core[herramienta] = False
                    
            disponibles = sum(1 for disponible in herramientas_core.values() if disponible)
            self.logger.info(f"Herramientas verificadas: {disponibles}/{len(herramientas_core)}")
            
        except Exception as e:
            self.logger.error(f"Error verificando herramientas: {e}")
        
        return herramientas_core
        # Inicializar automáticamente
        self._inicializar_gestores()
    
    def _inicializar_gestores(self):
        """Inicializa todos los gestores de datos optimizados siguiendo ARESITOS V3."""
        try:
            self.logger.info("[LAUNCH] Inicializando gestores ARESITOS V3...")
            self._estado_sistema['inicializado'] = False
            
            # Verificar herramientas del sistema
            herramientas_disponibles = self._verificar_herramientas_kali()
            self._estado_sistema['herramientas_kali'] = herramientas_disponibles
            
            # Inicializar componentes en orden de dependencia
            self._inicializar_dashboard()
            self._inicializar_escaneador()
            self._inicializar_siem()
            self._inicializar_monitor()
            self._inicializar_fim()
            self._inicializar_cuarentena()
            
            # Verificar estado final
            self._verificar_estado_componentes()
            
            self.logger.info("[OK] Inicialización de gestores ARESITOS V3 completada")
            
        except Exception as e:
            self.logger.error(f"[FAIL] Error en inicialización de gestores: {e}")
            self._estado_sistema['errores_inicializacion'].append(str(e))
    
    def _inicializar_dashboard(self):
        """Inicializar Dashboard optimizado."""
        try:
            if self.config_sistema['componentes']['dashboard']:
                from Aresitos.modelo.modelo_dashboard import ModeloDashboard
                self.dashboard = ModeloDashboard()
                self._estado_sistema['componentes_activos']['dashboard'] = True
                self.logger.info("[OK] Dashboard optimizado inicializado")
        except Exception as e:
            self.logger.warning(f"[WARNING] Dashboard no disponible: {e}")
            self._estado_sistema['componentes_activos']['dashboard'] = False
    
    def _inicializar_escaneador(self):
        """Inicializar Escaneador consolidado."""
        try:
            if self.config_sistema['componentes']['escaneador']:
                # Intentar escaneador optimizado primero
                try:
                    from Aresitos.modelo.modelo_escaneador import EscaneadorCompleto
                    self.escaneador_avanzado = EscaneadorCompleto()
                    self._estado_sistema['componentes_activos']['escaneador'] = True
                    self.logger.info("[OK] Escaneador consolidado inicializado")
                except ImportError:
                    # Fallback a escaneadores específicos
                    try:
                        from Aresitos.modelo.modelo_escaneador_red import EscaneadorRed
                        from Aresitos.modelo.modelo_escaneador_sistema import EscaneadorSistema
                        self.escaneador_red = EscaneadorRed()
                        self.escaneador_sistema = EscaneadorSistema()
                        self._estado_sistema['componentes_activos']['escaneador'] = True
                        self.logger.info("[OK] Escaneadores especializados inicializados")
                    except ImportError as e2:
                        raise e2
        except Exception as e:
            self.logger.warning(f"[WARNING] Escaneador no disponible: {e}")
            self._estado_sistema['componentes_activos']['escaneador'] = False
    
    def _inicializar_siem(self):
        """Inicializar SIEM optimizado."""
        try:
            if self.config_sistema['componentes']['siem']:
                from Aresitos.modelo.modelo_siem import SIEMKali2025
                self.siem_avanzado = SIEMKali2025()
                self._estado_sistema['componentes_activos']['siem'] = True
                self.logger.info("[OK] SIEM Kali2025 inicializado")
        except Exception as e:
            self.logger.warning(f"[WARNING] SIEM no disponible: {e}")
            self._estado_sistema['componentes_activos']['siem'] = False
    
    def _inicializar_monitor(self):
        """Inicializar Monitor avanzado."""
        try:
            if self.config_sistema['componentes']['monitor']:
                from Aresitos.modelo.modelo_monitor import MonitorAvanzadoNativo
                self.monitor_avanzado = MonitorAvanzadoNativo(siem=self.siem_avanzado)
                self._estado_sistema['componentes_activos']['monitor'] = True
                self.logger.info("[OK] Monitor avanzado inicializado")
        except Exception as e:
            self.logger.warning(f"[WARNING] Monitor no disponible: {e}")
            self._estado_sistema['componentes_activos']['monitor'] = False
    
    def _inicializar_fim(self):
        """Inicializar FIM optimizado."""
        try:
            if self.config_sistema['componentes']['fim']:
                # Intentar FIM Kali2025 optimizado primero
                try:
                    from Aresitos.modelo.modelo_fim_kali2025 import FIMKali2025
                    self.fim_avanzado = FIMKali2025()
                    self._estado_sistema['componentes_activos']['fim'] = True
                    self.logger.info("[OK] FIM Kali2025 optimizado inicializado")
                except ImportError:
                    # Fallback al FIM original
                    try:
                        from Aresitos.modelo.modelo_fim import FIMKali2025
                        self.fim_avanzado = FIMKali2025()
                        self._estado_sistema['componentes_activos']['fim'] = True
                        self.logger.info("[OK] FIM original inicializado")
                    except ImportError as e2:
                        raise e2
        except Exception as e:
            self.logger.warning(f"[WARNING] FIM no disponible: {e}")
            self._estado_sistema['componentes_activos']['fim'] = False
    
    def _inicializar_cuarentena(self):
        """Inicializar sistema de cuarentena."""
        try:
            if self.config_sistema['componentes']['cuarentena']:
                from Aresitos.modelo.modelo_cuarentena_kali2025 import CuarentenaKali2025
                self.cuarentena = CuarentenaKali2025()
                self._estado_sistema['componentes_activos']['cuarentena'] = True
                self.logger.info("[OK] Cuarentena Kali2025 inicializada")
        except Exception as e:
            self.logger.warning(f"[WARNING] Cuarentena no disponible: {e}")
            self._estado_sistema['componentes_activos']['cuarentena'] = False
    
    def _verificar_estado_componentes(self):
        """Verificar estado final de los componentes."""
        componentes_activos = sum(1 for activo in self._estado_sistema['componentes_activos'].values() if activo)
        total_componentes = len(self._estado_sistema['componentes_activos'])
        
        self._estado_sistema['inicializado'] = componentes_activos >= (total_componentes * 0.5)  # Al menos 50%
        
        self.logger.info(f"[STATS] Componentes activos: {componentes_activos}/{total_componentes}")
        
        if self._estado_sistema['inicializado']:
            self.logger.info("[TARGET] Sistema ARESITOS V3 inicializado correctamente")
        else:
            self.logger.warning("[WARNING] Sistema parcialmente inicializado")
    
    def _cache_get(self, key: str) -> Optional[Any]:
        """Obtener valor del cache si no ha expirado."""
        with self._lock:
            if key in self._cache_metricas:
                timestamp, valor = self._cache_metricas[key]
                if time.time() - timestamp < self._cache_timeout:
                    return valor
                else:
                    del self._cache_metricas[key]
            return None
    
    def _cache_set(self, key: str, valor: Any) -> None:
        """Establecer valor en cache."""
        with self._lock:
            self._cache_metricas[key] = (time.time(), valor)
    
    def obtener_estadisticas_generales(self) -> Dict[str, Any]:
        """Obtiene estadísticas generales optimizadas de todos los gestores."""
        # Verificar cache
        cached = self._cache_get('estadisticas_generales')
        if cached:
            return cached
        
        estadisticas = {
            'timestamp': datetime.now().isoformat(),
            'sistema_inicializado': self._estado_sistema['inicializado'],
            'componentes_activos': 0,
            'componentes_totales': 0,
            'herramientas_kali_disponibles': 0,
            'herramientas_kali_totales': 0,
            'metricas_sistema': {},
            'estado_componentes': self._estado_sistema['componentes_activos'].copy()
        }
        
        try:
            # Contar componentes activos
            componentes_activos = sum(1 for activo in self._estado_sistema['componentes_activos'].values() if activo)
            total_componentes = len(self._estado_sistema['componentes_activos'])
            
            estadisticas['componentes_activos'] = componentes_activos
            estadisticas['componentes_totales'] = total_componentes
            
            # Verificar herramientas Kali
            if 'herramientas_kali' in self._estado_sistema:
                herramientas_disponibles = sum(1 for disponible in self._estado_sistema['herramientas_kali'].values() if disponible)
                total_herramientas = len(self._estado_sistema['herramientas_kali'])
                
                estadisticas['herramientas_kali_disponibles'] = herramientas_disponibles
                estadisticas['herramientas_kali_totales'] = total_herramientas
            
            # Obtener métricas del sistema usando Dashboard si está disponible
            if self.dashboard:
                try:
                    metricas_sistema = self.dashboard.obtener_metricas_sistema()
                    estadisticas['metricas_sistema'] = metricas_sistema
                except Exception as e:
                    self.logger.warning(f"Error obteniendo métricas del dashboard: {e}")
            
            # Estadísticas específicas por componente
            if self.monitor_avanzado:
                try:
                    estadisticas['monitor_activo'] = self.monitor_avanzado.monitoreando
                except Exception:
                    estadisticas['monitor_activo'] = False
            
            if self.fim_avanzado:
                try:
                    # El FIM puede tener diferentes atributos según la versión
                    fim_estado = False
                    if hasattr(self.fim_avanzado, 'monitoreando'):
                        fim_estado = getattr(self.fim_avanzado, 'monitoreando', False)
                    elif hasattr(self.fim_avanzado, 'activo'):
                        fim_estado = getattr(self.fim_avanzado, 'activo', False)
                    estadisticas['fim_monitoreando'] = fim_estado
                except Exception:
                    estadisticas['fim_monitoreando'] = False
            
            # Guardar en cache
            self._cache_set('estadisticas_generales', estadisticas)
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
            estadisticas['error'] = str(e)
        
        return estadisticas
    
    def verificar_integridad_datos(self) -> Dict[str, Any]:
        """Verifica la integridad optimizada de todos los datos cargados."""
        verificacion = {
            'timestamp': datetime.now().isoformat(),
            'sistema_ok': self._estado_sistema['inicializado'],
            'componentes_ok': {},
            'herramientas_ok': {},
            'errores': self._estado_sistema['errores_inicializacion'].copy(),
            'warnings': [],
            'puntuacion_salud': 0
        }
        
        try:
            # Verificar cada componente
            total_puntos = 0
            puntos_obtenidos = 0
            
            for componente, activo in self._estado_sistema['componentes_activos'].items():
                total_puntos += 1
                verificacion['componentes_ok'][componente] = activo
                if activo:
                    puntos_obtenidos += 1
                else:
                    verificacion['warnings'].append(f"Componente {componente} no activo")
            
            # Verificar herramientas Kali
            if 'herramientas_kali' in self._estado_sistema:
                for herramienta, disponible in self._estado_sistema['herramientas_kali'].items():
                    verificacion['herramientas_ok'][herramienta] = disponible
                    if not disponible:
                        verificacion['warnings'].append(f"Herramienta {herramienta} no disponible")
            
            # Calcular puntuación de salud (0-100)
            if total_puntos > 0:
                verificacion['puntuacion_salud'] = round((puntos_obtenidos / total_puntos) * 100, 2)
            
            # Verificaciones específicas de componentes
            self._verificar_componentes_especificos(verificacion)
            
        except Exception as e:
            verificacion['errores'].append(f"Error en verificación: {e}")
        
        return verificacion
    
    def _verificar_componentes_especificos(self, verificacion: Dict[str, Any]):
        """Verificar funcionalidad específica de componentes."""
        try:
            # Verificar Dashboard
            if self.dashboard:
                try:
                    metricas = self.dashboard.obtener_metricas_sistema()
                    if not metricas or 'error' in metricas:
                        verificacion['warnings'].append("Dashboard con errores en métricas")
                except Exception:
                    verificacion['warnings'].append("Dashboard no responde correctamente")
            
            # Verificar Monitor
            if self.monitor_avanzado:
                try:
                    if not hasattr(self.monitor_avanzado, 'monitoreando'):
                        verificacion['warnings'].append("Monitor sin estado de monitoreo")
                except Exception:
                    verificacion['warnings'].append("Monitor con errores de estado")
            
            # Verificar SIEM
            if self.siem_avanzado:
                try:
                    if not hasattr(self.siem_avanzado, 'patrones_detectados'):
                        verificacion['warnings'].append("SIEM sin patrones de detección")
                except Exception:
                    verificacion['warnings'].append("SIEM con errores de configuración")
            
        except Exception as e:
            verificacion['errores'].append(f"Error verificando componentes específicos: {e}")
    
    def obtener_resumen_sistema(self) -> Dict[str, Any]:
        """Obtener resumen completo del estado del sistema."""
        return {
            'timestamp': datetime.now().isoformat(),
            'estado_general': self._estado_sistema.copy(),
            'estadisticas': self.obtener_estadisticas_generales(),
            'integridad': self.verificar_integridad_datos(),
            'tiempo_funcionamiento': (datetime.now() - self._estado_sistema['timestamp_inicio']).total_seconds()
        }
    
    def reinicializar_componente(self, componente: str) -> Dict[str, Any]:
        """Reinicializar un componente específico."""
        try:
            self.logger.info(f"🔄 Reinicializando componente: {componente}")
            
            if componente == 'dashboard':
                self._inicializar_dashboard()
            elif componente == 'escaneador':
                self._inicializar_escaneador()
            elif componente == 'siem':
                self._inicializar_siem()
            elif componente == 'monitor':
                self._inicializar_monitor()
            elif componente == 'fim':
                self._inicializar_fim()
            elif componente == 'cuarentena':
                self._inicializar_cuarentena()
            else:
                return {
                    'exito': False,
                    'error': f'Componente {componente} no reconocido'
                }
            
            # Limpiar cache
            with self._lock:
                self._cache_metricas.clear()
            
            estado_final = self._estado_sistema['componentes_activos'].get(componente, False)
            
            return {
                'exito': estado_final,
                'componente': componente,
                'estado': 'activo' if estado_final else 'inactivo',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error reinicializando {componente}: {e}")
            return {
                'exito': False,
                'error': str(e),
                'componente': componente
            }
    
    def detener_todos_componentes(self) -> Dict[str, Any]:
        """Detener todos los componentes activos de forma segura."""
        try:
            self.logger.info("🛑 Deteniendo todos los componentes...")
            resultados = {}
            
            # Detener Monitor
            if self.monitor_avanzado and hasattr(self.monitor_avanzado, 'detener_monitoreo'):
                try:
                    resultado = self.monitor_avanzado.detener_monitoreo()
                    resultados['monitor'] = resultado.get('exito', False)
                except Exception as e:
                    self.logger.warning(f"Error deteniendo monitor: {e}")
                    resultados['monitor'] = False
            
            # Detener FIM
            if self.fim_avanzado:
                try:
                    # Verificar si tiene método de detener
                    if hasattr(self.fim_avanzado, 'detener_monitoreo'):
                        resultado = getattr(self.fim_avanzado, 'detener_monitoreo')()
                        if resultado and hasattr(resultado, 'get'):
                            resultados['fim'] = resultado.get('exito', False)
                        else:
                            resultados['fim'] = resultado is not None
                    elif hasattr(self.fim_avanzado, 'detener'):
                        resultado = getattr(self.fim_avanzado, 'detener')()
                        resultados['fim'] = True
                    else:
                        resultados['fim'] = True  # No hay método específico
                except Exception as e:
                    self.logger.warning(f"Error deteniendo FIM: {e}")
                    resultados['fim'] = False
            
            # Limpiar referencias
            self.monitor_avanzado = None
            self.fim_avanzado = None
            self.siem_avanzado = None
            self.escaneador_avanzado = None
            self.dashboard = None
            self.cuarentena = None
            
            # Actualizar estado
            for componente in self._estado_sistema['componentes_activos']:
                self._estado_sistema['componentes_activos'][componente] = False
            
            self._estado_sistema['inicializado'] = False
            
            # Limpiar cache
            with self._lock:
                self._cache_metricas.clear()
            
            self.logger.info("[OK] Todos los componentes detenidos")
            
            return {
                'exito': True,
                'componentes_detenidos': resultados,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error deteniendo componentes: {e}")
            return {
                'exito': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

# RESUMEN: Modelo principal optimizado ARESITOS V3 que coordina todos los gestores
# usando Python nativo + herramientas Kali, con cache inteligente, verificaciones
# de integridad, métricas del sistema y gestión robusta de componentes.
