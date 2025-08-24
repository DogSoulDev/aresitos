# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor de Componentes
Gestión centralizada de todos los componentes del sistema
"""

import threading
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Set

class GestorComponentes:
    """
    Gestor centralizado de componentes del sistema.
    Maneja la inicialización, coordinación y finalización de componentes.
    """
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.logger = logging.getLogger(f"aresitos.{self.__class__.__name__}")
        
        # Estado de componentes
        self._componentes_estado = {
            'siem': {'inicializado': False, 'instancia': None, 'error': None},
            'fim': {'inicializado': False, 'instancia': None, 'error': None},
            'escáner': {'inicializado': False, 'instancia': None, 'error': None},
            'cuarentena': {'inicializado': False, 'instancia': None, 'error': None},
            'auditoría': {'inicializado': False, 'instancia': None, 'error': None},
            'reportes': {'inicializado': False, 'instancia': None, 'error': None}
        }
        
        # Orden de inicialización (dependencias)
        self._orden_inicializacion = [
            'siem',      # Primero - base para logging
            'fim',       # Segundo - usa SIEM
            'escáner', # Tercero - usa SIEM
            'cuarentena', # Cuarto - usa escáner
            'auditoría',  # Quinto - usa todos los anteriores
            'reportes'    # Último - recopila de todos
        ]
        
        # Configuración de timeouts
        self._timeouts_componentes = {
            'inicializacion': 30,
            'operacion': 60,
            'finalizacion': 15
        }
        
        self.logger.info("Gestor de Componentes inicializado")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación de inicialización del gestor de componentes."""
        return {'exito': True, 'mensaje': 'Gestor de componentes inicializado'}
    
    def inicializar_componentes_ordenado(self) -> Dict[str, Any]:
        """Inicializar componentes en el orden correcto."""
        try:
            self.logger.info("Iniciando componentes en orden de dependencias...")
            
            resultados = {
                'componentes_iniciados': [],
                'componentes_fallidos': [],
                'errores': {},
                'tiempo_total': 0
            }
            
            tiempo_inicio = datetime.now()
            
            for nombre_componente in self._orden_inicializacion:
                self.logger.info(f"Inicializando componente: {nombre_componente}")
                
                try:
                    resultado = self._inicializar_componente_individual(nombre_componente)
                    
                    if resultado['exito']:
                        resultados['componentes_iniciados'].append(nombre_componente)
                        self._componentes_estado[nombre_componente]['inicializado'] = True
                        self.logger.info(f"Componente {nombre_componente} inicializado")
                    else:
                        resultados['componentes_fallidos'].append(nombre_componente)
                        resultados['errores'][nombre_componente] = resultado.get('error', 'Error desconocido')
                        self.logger.error(f"Componente {nombre_componente}: {resultado.get('error')}")
                        
                except Exception as e:
                    error_msg = f"Excepción inicializando {nombre_componente}: {str(e)}"
                    resultados['componentes_fallidos'].append(nombre_componente)
                    resultados['errores'][nombre_componente] = error_msg
                    self.logger.error(error_msg)
            
            tiempo_total = (datetime.now() - tiempo_inicio).total_seconds()
            resultados['tiempo_total'] = round(tiempo_total, 2)
            
            # Evaluar éxito general
            componentes_exitosos = len(resultados['componentes_iniciados'])
            total_componentes = len(self._orden_inicializacion)
            
            exito_general = componentes_exitosos >= (total_componentes * 0.5)  # Al menos 50%
            
            resultado_final = {
                'exito': exito_general,
                'componentes_exitosos': componentes_exitosos,
                'total_componentes': total_componentes,
                'porcentaje_exito': round((componentes_exitosos / total_componentes) * 100, 1),
                'detalles': resultados
            }
            
            mensaje = f"Inicialización completada: {componentes_exitosos}/{total_componentes} componentes"
            self.logger.info(mensaje)
            
            return resultado_final
            
        except Exception as e:
            error_msg = f"Error en inicialización de componentes: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_componente_individual(self, nombre_componente: str) -> Dict[str, Any]:
        """Inicializar un componente individual."""
        try:
            if nombre_componente == 'siem':
                return self._inicializar_siem()
            elif nombre_componente == 'fim':
                return self._inicializar_fim()
            elif nombre_componente == 'escáner':
                return self._inicializar_escaneador()
            elif nombre_componente == 'cuarentena':
                return self._inicializar_cuarentena()
            elif nombre_componente == 'auditoría':
                return self._inicializar_auditoria()
            elif nombre_componente == 'reportes':
                return self._inicializar_reportes()
            else:
                return {'exito': False, 'error': f'Componente desconocido: {nombre_componente}'}
                
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def _inicializar_siem(self) -> Dict[str, Any]:
        """Inicializar componente SIEM."""
        try:
            # Usar modelo real existente
            from aresitos.modelo.modelo_siem import SIEMKali2025 as ModeloSIEM
            siem_instance = ModeloSIEM()
            
            # SIEM inicializado correctamente
            self.logger.info("SIEM real inicializado con SIEMKali2025")
            
            # Guardar referencia
            self._componentes_estado['siem']['instancia'] = siem_instance
            
            # Hacer disponible en modelo principal
            if hasattr(self.modelo_principal, 'siem_avanzado'):
                self.modelo_principal.siem_avanzado = siem_instance
            
            return {'exito': True, 'mensaje': 'SIEM inicializado correctamente'}
            
        except Exception as e:
            error_msg = f"Error inicializando SIEM: {str(e)}"
            self._componentes_estado['siem']['error'] = error_msg
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_fim(self) -> Dict[str, Any]:
        """Inicializar componente FIM."""
        try:
            # Usar modelo real existente
            from aresitos.modelo.modelo_fim import FIMKali2025 as ModeloFIM
            fim_instance = ModeloFIM()
            
            # Verificar funcionalidad básica
            if hasattr(fim_instance, 'obtener_estadisticas'):
                stats = fim_instance.obtener_estadisticas()
                if not isinstance(stats, dict):
                    raise Exception("FIM no retorna estadísticas válidas")
            
            self.logger.info("FIM real inicializado con FIMKali2025")
            
            # Guardar referencia
            self._componentes_estado['fim']['instancia'] = fim_instance
            
            # Hacer disponible en modelo principal
            if hasattr(self.modelo_principal, 'fim_avanzado'):
                self.modelo_principal.fim_avanzado = fim_instance
            
            return {'exito': True, 'mensaje': 'FIM inicializado correctamente'}
            
        except Exception as e:
            error_msg = f"Error inicializando FIM: {str(e)}"
            self._componentes_estado['fim']['error'] = error_msg
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_escaneador(self) -> Dict[str, Any]:
        """Inicializar componente Escaneador."""
        try:
            # Usar modelo real existente
            from aresitos.modelo.modelo_escaneador import EscaneadorKali2025 as ModeloEscaneador
            escaneador_instance = ModeloEscaneador()
            
            # Configurar escáner real con herramientas Kali
            self.logger.info("Escaneador real inicializado con EscaneadorKali2025")
            
            # Guardar referencia
            self._componentes_estado['escáner']['instancia'] = escaneador_instance
            
            # Hacer disponible en modelo principal
            if hasattr(self.modelo_principal, 'escaneador_avanzado'):
                self.modelo_principal.escaneador_avanzado = escaneador_instance
            
            return {'exito': True, 'mensaje': 'Escaneador inicializado correctamente'}
            
        except Exception as e:
            error_msg = f"Error inicializando Escaneador: {str(e)}"
            self._componentes_estado['escáner']['error'] = error_msg
            return {'exito': False, 'error': error_msg}
    
    def _inicializar_cuarentena(self) -> Dict[str, Any]:
        """Inicializar componente Cuarentena."""
        try:
            # Usar modelo real existente de cuarentena
            from aresitos.modelo.modelo_cuarentena import CuarentenaKali2025 as ModeloCuarentena
            cuarentena_instance = ModeloCuarentena()
            
            self.logger.info("Cuarentena real inicializada con CuarentenaKali2025")
            
            # Verificar funcionalidad básica
            if hasattr(cuarentena_instance, 'obtener_estadisticas'):
                stats = cuarentena_instance.obtener_estadisticas()
                if not isinstance(stats, dict):
                    # No crítico, continuar
                    pass
            
            # Guardar referencia
            self._componentes_estado['cuarentena']['instancia'] = cuarentena_instance
            
            # Hacer disponible en modelo principal
            if hasattr(self.modelo_principal, 'gestor_cuarentena'):
                self.modelo_principal.gestor_cuarentena = cuarentena_instance
            
            return {'exito': True, 'mensaje': 'Cuarentena inicializada correctamente'}
            
        except Exception as e:
            error_msg = f"Error inicializando Cuarentena: {str(e)}"
            self._componentes_estado['cuarentena']['error'] = error_msg
            # Cuarentena no es crítica
            return {'exito': True, 'mensaje': f'Cuarentena no disponible: {error_msg}'}
    
    def _inicializar_auditoria(self) -> Dict[str, Any]:
        """Inicializar componente Auditoría."""
        try:
            # Auditoría es opcional, no fallar si no está disponible
            return {'exito': True, 'mensaje': 'Auditoría configurada como opcional'}
            
        except Exception as e:
            error_msg = f"Error inicializando Auditoría: {str(e)}"
            self._componentes_estado['auditoría']['error'] = error_msg
            # Auditoría no es crítica
            return {'exito': True, 'mensaje': f'Auditoría no disponible: {error_msg}'}
    
    def _inicializar_reportes(self) -> Dict[str, Any]:
        """Inicializar componente Reportes."""
        try:
            # Reportes es opcional, no fallar si no está disponible
            return {'exito': True, 'mensaje': 'Reportes configurados como opcionales'}
            
        except Exception as e:
            error_msg = f"Error inicializando Reportes: {str(e)}"
            self._componentes_estado['reportes']['error'] = error_msg
            # Reportes no es crítico
            return {'exito': True, 'mensaje': f'Reportes no disponibles: {error_msg}'}
    
    def obtener_estado_componentes(self) -> Dict[str, Any]:
        """Obtener estado actual de todos los componentes."""
        try:
            estado_actual = {}
            
            for nombre, info in self._componentes_estado.items():
                estado_actual[nombre] = {
                    'inicializado': info['inicializado'],
                    'disponible': info['instancia'] is not None,
                    'error': info['error'],
                    'tipo_instancia': type(info['instancia']).__name__ if info['instancia'] else None
                }
            
            # Calcular métricas generales
            total_componentes = len(self._componentes_estado)
            componentes_iniciados = sum(1 for info in self._componentes_estado.values() if info['inicializado'])
            componentes_disponibles = sum(1 for info in self._componentes_estado.values() if info['instancia'] is not None)
            
            resumen = {
                'total_componentes': total_componentes,
                'componentes_iniciados': componentes_iniciados,
                'componentes_disponibles': componentes_disponibles,
                'porcentaje_iniciados': round((componentes_iniciados / total_componentes) * 100, 1),
                'porcentaje_disponibles': round((componentes_disponibles / total_componentes) * 100, 1)
            }
            
            return {
                'exito': True,
                'estado_componentes': estado_actual,
                'resumen': resumen,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error obteniendo estado de componentes: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def obtener_componente(self, nombre_componente: str) -> Optional[Any]:
        """Obtener referencia a un componente específico."""
        try:
            if nombre_componente in self._componentes_estado:
                return self._componentes_estado[nombre_componente]['instancia']
            return None
        except Exception as e:
            self.logger.error(f"Error obteniendo componente {nombre_componente}: {e}")
            return None
    
    def finalizar_componentes(self) -> Dict[str, Any]:
        """Finalizar todos los componentes de manera ordenada."""
        try:
            self.logger.info("Finalizando componentes...")
            
            # Finalizar en orden inverso
            orden_finalizacion = list(reversed(self._orden_inicializacion))
            
            resultados = {
                'componentes_finalizados': [],
                'errores_finalizacion': {}
            }
            
            for nombre_componente in orden_finalizacion:
                try:
                    instancia = self._componentes_estado[nombre_componente]['instancia']
                    if instancia and hasattr(instancia, 'finalizar'):
                        instancia.finalizar()
                    
                    # Limpiar estado
                    self._componentes_estado[nombre_componente]['inicializado'] = False
                    self._componentes_estado[nombre_componente]['instancia'] = None
                    
                    resultados['componentes_finalizados'].append(nombre_componente)
                    self.logger.info(f"Componente {nombre_componente} finalizado")
                    
                except Exception as e:
                    error_msg = f"Error finalizando {nombre_componente}: {str(e)}"
                    resultados['errores_finalizacion'][nombre_componente] = error_msg
                    self.logger.error(error_msg)
            
            return {
                'exito': True,
                'resultados': resultados
            }
            
        except Exception as e:
            error_msg = f"Error finalizando componentes: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}

