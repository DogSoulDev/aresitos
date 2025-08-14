# -*- coding: utf-8 -*-

import logging
from typing import Optional

class ModeloPrincipal:
    """Modelo principal de la aplicación que coordina todos los gestores de datos."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Gestores de datos
        self.gestor_wordlists = None
        self.gestor_diccionarios = None
        self.escaneador_avanzado = None
        self.siem_avanzado = None
        self.monitor_avanzado = None
        self.fim_avanzado = None
        
        # Inicializar automáticamente
        self._inicializar_gestores()
    
    def _inicializar_gestores(self):
        """Inicializa todos los gestores de datos automáticamente"""
        try:
            print("Inicializando gestores de datos de Aresitos...")
            
            # Inicializar gestor de wordlists
            try:
                from ares_aegis.modelo.modelo_gestor_wordlists import ModeloGestorWordlists
                self.gestor_wordlists = ModeloGestorWordlists()
                print("Gestor de Wordlists inicializado")
            except Exception as e:
                print("Error inicializando gestor de wordlists: {e}")
            
            # Inicializar gestor de diccionarios
            try:
                from ares_aegis.modelo.modelo_gestor_diccionarios import ModeloGestorDiccionarios
                self.gestor_diccionarios = ModeloGestorDiccionarios()
                print("Gestor de Diccionarios inicializado")
            except Exception as e:
                print(f"Error inicializando gestor de diccionarios: {e}")
            
            # Inicializar componentes avanzados
            try:
                from ares_aegis.modelo.modelo_escaneador import EscaneadorAvanzado
                self.escaneador_avanzado = EscaneadorAvanzado()
                print("Escaneador Avanzado inicializado")
            except Exception as e:
                print(f"Error inicializando escaneador avanzado: {e}")
            
            try:
                from ares_aegis.modelo.modelo_siem import SIEMAvanzado
                self.siem_avanzado = SIEMAvanzado()
                print("SIEM Avanzado inicializado")
            except Exception as e:
                print(f"Error inicializando SIEM avanzado: {e}")
            
            try:
                from ares_aegis.modelo.modelo_monitor import MonitorAvanzado
                self.monitor_avanzado = MonitorAvanzado()
                print("Monitor Avanzado inicializado")
            except Exception as e:
                print(f"Error inicializando monitor avanzado: {e}")
            
            try:
                from ares_aegis.modelo.modelo_fim import FIMAvanzado
                self.fim_avanzado = FIMAvanzado()
                print("FIM Avanzado inicializado")
            except Exception as e:
                print(f"Error inicializando FIM avanzado: {e}")
            
            print("Inicialización de gestores completada")
            
        except Exception as e:
            self.logger.error(f"Error en inicialización de gestores: {e}")
            print(f" Error general en inicialización: {e}")
    
    def obtener_estadisticas_generales(self) -> dict:
        """Obtiene estadísticas generales de todos los gestores"""
        estadisticas = {
            'gestores_activos': 0,
            'wordlists_disponibles': 0,
            'diccionarios_disponibles': 0,
            'componentes_avanzados': 0
        }
        
        try:
            if self.gestor_wordlists:
                estadisticas['gestores_activos'] += 1
                estadisticas['wordlists_disponibles'] = len(self.gestor_wordlists.wordlists_predefinidas)
            
            if self.gestor_diccionarios:
                estadisticas['gestores_activos'] += 1
                estadisticas['diccionarios_disponibles'] = len(self.gestor_diccionarios.diccionarios_predefinidos)
            
            componentes = [self.escaneador_avanzado, self.siem_avanzado, self.monitor_avanzado, self.fim_avanzado]
            estadisticas['componentes_avanzados'] = sum(1 for comp in componentes if comp is not None)
            
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas: {e}")
        
        return estadisticas
    
    def verificar_integridad_datos(self) -> dict:
        """Verifica la integridad de todos los datos cargados"""
        verificacion = {
            'wordlists_ok': False,
            'diccionarios_ok': False,
            'componentes_ok': False,
            'errores': []
        }
        
        try:
            # Verificar wordlists
            if self.gestor_wordlists and len(self.gestor_wordlists.wordlists_predefinidas) > 0:
                verificacion['wordlists_ok'] = True
            else:
                verificacion['errores'].append("Wordlists no cargadas correctamente")
            
            # Verificar diccionarios
            if self.gestor_diccionarios and len(self.gestor_diccionarios.diccionarios_predefinidos) > 0:
                verificacion['diccionarios_ok'] = True
            else:
                verificacion['errores'].append("Diccionarios no cargados correctamente")
            
            # Verificar componentes avanzados
            componentes_activos = sum(1 for comp in [self.escaneador_avanzado, self.siem_avanzado, 
                                                   self.monitor_avanzado, self.fim_avanzado] if comp is not None)
            if componentes_activos >= 2:  # Al menos 2 componentes activos
                verificacion['componentes_ok'] = True
            else:
                verificacion['errores'].append("Componentes avanzados no inicializados correctamente")
            
        except Exception as e:
            verificacion['errores'].append(f"Error en verificación: {e}")
        
        return verificacion

# RESUMEN: Modelo principal expandido que coordina todos los gestores de datos,
# carga automáticamente wordlists y diccionarios desde data/, inicializa componentes
# avanzados y proporciona estadísticas e integridad de datos para Aresitos.
