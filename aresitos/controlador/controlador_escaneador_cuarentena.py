# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal con Cuarentena Integrada
Gestiona el escaneador con cuarentena automática para amenazas detectadas
"""

import logging
import os
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

class MockResultado:
    """Resultado mock para el escaneador."""
    def __init__(self):
        self.vulnerabilidades = []
        self.exito = False
        self.errores = ["Escaneador no disponible"]

class MockEscaneador:
    """Escaneador mock para fallback."""
    def escanear_completo(self):
        return MockResultado()
    
    def detectar_malware(self):
        return MockResultado()
        
    def escanear_vulnerabilidades_sistema(self):
        return MockResultado()

class MockCuarentena:
    """Cuarentena mock para fallback."""
    def procesar_amenaza_detectada(self, amenaza):
        return False
    
    def obtener_resumen_cuarentena(self):
        return {"total_archivos": 0, "mensaje": "Cuarentena no disponible"}
        
    def restaurar_archivo(self, ruta):
        return False

class ControladorEscaneadorCuarentena:
    """
    Controlador principal que integra el escaneador con el sistema de cuarentena.
    """
    
    def __init__(self):
        """Inicializa el controlador integrado."""
        self.logger = logging.getLogger(f"AresAegis.{self.__class__.__name__}")
        
        # Configuración por defecto
        self.configuracion = {
            'cuarentena_automatica': True,
            'niveles_cuarentena': ['critico', 'alto'],  # Niveles que van a cuarentena automáticamente
            'notificar_cuarentena': True,
            'backup_antes_cuarentena': True
        }
        
        # Inicializar componentes con tipos Union para flexibilidad
        self.escaneador: Union[MockEscaneador, Any] = MockEscaneador()
        self.cuarentena: Union[MockCuarentena, Any] = MockCuarentena()
        
        self._inicializar_componentes()
    
    def _inicializar_componentes(self):
        """Inicializa el escaneador y el sistema de cuarentena."""
        # Inicializar escaneador
        try:
            from ..modelo.escaneador_avanzado import EscaneadorAvanzadoReal
            self.escaneador = EscaneadorAvanzadoReal()
            self.logger.info("✅ Escaneador avanzado inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando escaneador: {e}")
            self.escaneador = MockEscaneador()
            self.logger.warning("⚠️ Usando escaneador mock")
        
        # Inicializar cuarentena
        try:
            from .controlador_cuarentena import ControladorCuarentena
            self.cuarentena = ControladorCuarentena()
            self.logger.info("✅ Sistema de cuarentena inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando cuarentena: {e}")
            self.cuarentena = MockCuarentena()
            self.logger.warning("⚠️ Usando cuarentena mock")
    
    def ejecutar_escaneo_con_cuarentena(self, tipo_escaneo: str = 'completo') -> Dict[str, Any]:
        """
        Ejecuta un escaneo con cuarentena automática de amenazas.
        
        Args:
            tipo_escaneo: Tipo de escaneo a realizar
            
        Returns:
            Dict con resultados del escaneo y cuarentena
        """
        self.logger.info(f"🚀 Iniciando escaneo {tipo_escaneo} con cuarentena automática")
        
        resultado = {
            'timestamp_inicio': datetime.now().isoformat(),
            'tipo_escaneo': tipo_escaneo,
            'vulnerabilidades_encontradas': [],
            'amenazas_en_cuarentena': [],
            'resumen_cuarentena': {},
            'exito': False,
            'errores': []
        }
        
        try:
            # 1. Ejecutar escaneo
            if tipo_escaneo == 'completo':
                resultado_escaneo = self.escaneador.escanear_completo()
            elif tipo_escaneo == 'malware':
                resultado_escaneo = self.escaneador.detectar_malware()
            elif tipo_escaneo == 'vulnerabilidades':
                resultado_escaneo = self.escaneador.escanear_vulnerabilidades_sistema()
            else:
                raise ValueError(f"Tipo de escaneo no válido: {tipo_escaneo}")
            
            # 2. Procesar vulnerabilidades encontradas
            vulnerabilidades_procesadas = []
            amenazas_cuarentena = []
            
            for vuln in resultado_escaneo.vulnerabilidades:
                vuln_info = {
                    'id': vuln.id,
                    'tipo': vuln.tipo,
                    'descripcion': vuln.descripcion,
                    'nivel_riesgo': vuln.nivel_riesgo.value,
                    'archivo_afectado': vuln.archivo_afectado,
                    'timestamp': vuln.timestamp.isoformat() if vuln.timestamp else None
                }
                vulnerabilidades_procesadas.append(vuln_info)
                
                # 3. Procesar con cuarentena si es necesario
                if self._debe_ir_a_cuarentena(vuln):
                    if self._procesar_amenaza_cuarentena(vuln):
                        amenazas_cuarentena.append(vuln_info)
                        self.logger.warning(f"🔒 Amenaza enviada a cuarentena: {vuln.tipo}")
            
            # 4. Obtener resumen de cuarentena
            resumen_cuarentena = self._obtener_resumen_cuarentena()
            
            # 5. Preparar resultado final
            resultado.update({
                'vulnerabilidades_encontradas': vulnerabilidades_procesadas,
                'amenazas_en_cuarentena': amenazas_cuarentena,
                'resumen_cuarentena': resumen_cuarentena,
                'exito': resultado_escaneo.exito,
                'timestamp_fin': datetime.now().isoformat(),
                'estadisticas': {
                    'total_vulnerabilidades': len(vulnerabilidades_procesadas),
                    'criticas': len([v for v in vulnerabilidades_procesadas if v['nivel_riesgo'] == 'critico']),
                    'altas': len([v for v in vulnerabilidades_procesadas if v['nivel_riesgo'] == 'alto']),
                    'en_cuarentena': len(amenazas_cuarentena)
                }
            })
            
            # 6. Log de resumen
            self._log_resumen_escaneo(resultado)
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error durante escaneo con cuarentena: {e}"
            self.logger.error(error_msg)
            resultado['errores'].append(error_msg)
            resultado['timestamp_fin'] = datetime.now().isoformat()
            return resultado
    
    def _debe_ir_a_cuarentena(self, vulnerabilidad) -> bool:
        """Determina si una vulnerabilidad debe ir a cuarentena automáticamente."""
        if not self.configuracion['cuarentena_automatica']:
            return False
        
        nivel = vulnerabilidad.nivel_riesgo.value
        return nivel in self.configuracion['niveles_cuarentena']
    
    def _procesar_amenaza_cuarentena(self, vulnerabilidad) -> bool:
        """Procesa una amenaza con el sistema de cuarentena."""
        try:
            amenaza_info = {
                'archivo': vulnerabilidad.archivo_afectado,
                'tipo': vulnerabilidad.tipo,
                'descripcion': vulnerabilidad.descripcion,
                'severidad': self._convertir_nivel_riesgo(vulnerabilidad.nivel_riesgo.value),
                'fuente_deteccion': 'EscaneadorAvanzado',
                'fecha_deteccion': vulnerabilidad.timestamp.isoformat() if vulnerabilidad.timestamp else None,
                'metadatos': {
                    'vulnerability_id': vulnerabilidad.id,
                    'cve_id': vulnerabilidad.cve_id,
                    'puerto_afectado': vulnerabilidad.puerto_afectado,
                    'servicio_afectado': vulnerabilidad.servicio_afectado,
                    'solucion_recomendada': vulnerabilidad.solucion_recomendada
                }
            }
            
            return self.cuarentena.procesar_amenaza_detectada(amenaza_info)
            
        except Exception as e:
            self.logger.error(f"Error procesando amenaza en cuarentena: {e}")
            return False
    
    def _convertir_nivel_riesgo(self, nivel: str) -> str:
        """Convierte nivel de riesgo a formato de cuarentena."""
        conversion = {
            'critico': 'Crítica',
            'alto': 'Alta',
            'medio': 'Media',
            'bajo': 'Baja',
            'info': 'Baja'
        }
        return conversion.get(nivel, 'Media')
    
    def _obtener_resumen_cuarentena(self) -> Dict[str, Any]:
        """Obtiene resumen del estado de cuarentena."""
        try:
            if hasattr(self.cuarentena, 'obtener_resumen_cuarentena'):
                return self.cuarentena.obtener_resumen_cuarentena()
            else:
                return {'mensaje': 'Sistema de cuarentena activo'}
        except Exception as e:
            self.logger.error(f"Error obteniendo resumen de cuarentena: {e}")
            return {'error': str(e)}
    
    def _log_resumen_escaneo(self, resultado: Dict[str, Any]):
        """Registra resumen del escaneo en los logs."""
        stats = resultado.get('estadisticas', {})
        
        self.logger.info("=" * 60)
        self.logger.info("📊 RESUMEN DE ESCANEO CON CUARENTENA")
        self.logger.info("=" * 60)
        self.logger.info(f"🔍 Tipo de escaneo: {resultado.get('tipo_escaneo', 'N/A')}")
        self.logger.info(f"📈 Total vulnerabilidades: {stats.get('total_vulnerabilidades', 0)}")
        self.logger.info(f"🔴 Críticas: {stats.get('criticas', 0)}")
        self.logger.info(f"🟠 Altas: {stats.get('altas', 0)}")
        self.logger.info(f"🔒 En cuarentena: {stats.get('en_cuarentena', 0)}")
        
        if stats.get('en_cuarentena', 0) > 0:
            self.logger.warning(f"⚠️ {stats['en_cuarentena']} amenazas fueron puestas en cuarentena automáticamente")
        
        self.logger.info("=" * 60)
    
    def gestionar_cuarentena(self) -> Dict[str, Any]:
        """Proporciona interfaz para gestionar la cuarentena."""
        try:
            resumen = self._obtener_resumen_cuarentena()
            
            return {
                'resumen': resumen,
                'acciones_disponibles': [
                    'listar_archivos_cuarentena',
                    'restaurar_archivo',
                    'eliminar_definitivamente',
                    'limpiar_cuarentena_antigua',
                    'generar_reporte_cuarentena'
                ],
                'configuracion_actual': self.configuracion
            }
            
        except Exception as e:
            self.logger.error(f"Error gestionando cuarentena: {e}")
            return {'error': str(e)}
    
    def restaurar_desde_cuarentena(self, ruta_archivo: str) -> bool:
        """Restaura un archivo específico desde la cuarentena."""
        try:
            if hasattr(self.cuarentena, 'restaurar_archivo'):
                resultado = self.cuarentena.restaurar_archivo(ruta_archivo)
                if resultado:
                    self.logger.info(f"✅ Archivo restaurado: {ruta_archivo}")
                else:
                    self.logger.warning(f"❌ No se pudo restaurar: {ruta_archivo}")
                return resultado
            else:
                self.logger.error("Método de restauración no disponible")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restaurando archivo: {e}")
            return False
    
    def configurar_cuarentena(self, nueva_config: Dict[str, Any]) -> bool:
        """Actualiza la configuración de cuarentena."""
        try:
            self.configuracion.update(nueva_config)
            self.logger.info("✅ Configuración de cuarentena actualizada")
            return True
        except Exception as e:
            self.logger.error(f"Error actualizando configuración: {e}")
            return False
