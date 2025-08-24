# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador de Cuarentena
Gestiona las operaciones de cuarentena integradas con el sistema de escaneo
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Importar controlador base
from aresitos.controlador.controlador_base import ControladorBase

# Importar modelo real de cuarentena
from aresitos.modelo.modelo_cuarentena import CuarentenaKali2025

# Importar SudoManager para prevenir crashes
try:
    from aresitos.utils.sudo_manager import SudoManager
    SUDO_MANAGER_DISPONIBLE = True
except ImportError:
    SUDO_MANAGER_DISPONIBLE = False


class ControladorCuarentena(ControladorBase):
    """
    Controlador para gestionar el sistema de cuarentena siguiendo principios ARESITOS.
    Utiliza CuarentenaKali2025 como modelo y herramientas nativas de Kali Linux.
    """
    
    def __init__(self, modelo_principal, directorio_cuarentena: Optional[str] = None):
        """
        Inicializa el controlador de cuarentena.
        
        Args:
            modelo_principal: Modelo principal del sistema
            directorio_cuarentena: Directorio personalizado para cuarentena
        """
        super().__init__(modelo_principal, "ControladorCuarentena")
        
        # Inicializar SudoManager para prevenir crashes
        if SUDO_MANAGER_DISPONIBLE:
            try:
                self.sudo_manager = SudoManager()
                self.logger.info("SudoManager inicializado para operaciones seguras")
            except Exception as e:
                self.logger.warning(f"Error inicializando SudoManager: {e}")
                self.sudo_manager = None
        else:
            self.sudo_manager = None
            self.logger.warning("SudoManager no disponible")
        
        # Inicializar modelo de cuarentena real
        try:
            self.cuarentena = CuarentenaKali2025(directorio_cuarentena)
            self.logger.info(f"Sistema de cuarentena CuarentenaKali2025 inicializado: {self.cuarentena.directorio_cuarentena}")
        except Exception as e:
            self.logger.error(f"Error inicializando sistema de cuarentena: {e}")
            raise
        
        # Configuración de tipos de amenaza y sus severidades
        self.tipos_amenaza = {
            'virus': 'Crítica',
            'malware': 'Crítica', 
            'trojan': 'Crítica',
            'backdoor': 'Crítica',
            'rootkit': 'Crítica',
            'adware': 'Alta',
            'spyware': 'Alta',
            'vulnerabilidad_critica': 'Crítica',
            'vulnerabilidad_alta': 'Alta',
            'vulnerabilidad_media': 'Media',
            'vulnerabilidad_baja': 'Baja',
            'archivo_sospechoso': 'Media',
            'configuracion_insegura': 'Media',
            'puerto_abierto_peligroso': 'Alta',
            'servicio_vulnerable': 'Alta',
            'certificado_invalido': 'Media',
            'credenciales_debiles': 'Alta'
        }
        
        self.logger.info("Controlador de cuarentena inicializado completamente")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """
        Implementación específica de inicialización para ControladorCuarentena.
        
        Returns:
            Dict con resultado de la inicialización específica
        """
        try:
            self.logger.info("Ejecutando inicialización específica de ControladorCuarentena")
            
            # Verificar que el modelo de cuarentena esté disponible
            if not self.cuarentena:
                return {'exito': False, 'error': 'Modelo de cuarentena no disponible'}
            
            # Verificar que el directorio de cuarentena existe
            if not os.path.exists(self.cuarentena.directorio_cuarentena):
                try:
                    os.makedirs(self.cuarentena.directorio_cuarentena, exist_ok=True)
                    self.logger.info(f"Directorio de cuarentena creado: {self.cuarentena.directorio_cuarentena}")
                except Exception as e:
                    return {'exito': False, 'error': f'No se pudo crear directorio de cuarentena: {e}'}
            
            self.logger.info("ControladorCuarentena inicializado correctamente")
            
            return {'exito': True, 'mensaje': 'ControladorCuarentena inicializado correctamente'}
            
        except Exception as e:
            error_msg = f"Error en inicialización específica de ControladorCuarentena: {e}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def procesar_amenaza_detectada(self, amenaza_info: Dict[str, Any]) -> bool:
        """
        Procesa una amenaza detectada y decide si ponerla en cuarentena.
        
        Args:
            amenaza_info: Información de la amenaza detectada
            
        Returns:
            True si la amenaza fue procesada correctamente
        """
        try:
            ruta_archivo = amenaza_info.get('archivo', '')
            tipo_amenaza = amenaza_info.get('tipo', 'desconocido')
            severidad = amenaza_info.get('severidad', 'Media')
            razon = amenaza_info.get('descripcion', f'Amenaza {tipo_amenaza} detectada')
            
            # Validar si debe ir a cuarentena según severidad
            debe_cuarentena = severidad in ['Crítica', 'Alta']
            
            if debe_cuarentena and ruta_archivo and os.path.exists(ruta_archivo):
                resultado = self.poner_en_cuarentena(ruta_archivo, tipo_amenaza, razon)
                if resultado.get('exito'):
                    self.logger.info(f"Amenaza {tipo_amenaza} procesada y puesta en cuarentena: {ruta_archivo}")
                    return True
                else:
                    self.logger.error(f"Error procesando amenaza {tipo_amenaza}: {resultado.get('mensaje')}")
                    return False
            else:
                self.logger.info(f"Amenaza {tipo_amenaza} de severidad {severidad} no requiere cuarentena")
                return True
                
        except Exception as e:
            self.logger.error(f"Error procesando amenaza detectada: {e}")
            return False
    
    def poner_en_cuarentena(self, ruta_archivo: str, tipo_amenaza: str = "desconocido", razon: str = "") -> Dict[str, Any]:
        """
        Pone un archivo en cuarentena usando el modelo CuarentenaKali2025.
        
        Args:
            ruta_archivo: Ruta del archivo a poner en cuarentena
            tipo_amenaza: Tipo de amenaza detectada
            razon: Razón específica para la cuarentena
            
        Returns:
            Diccionario con resultado de la operación
        """
        return self.ejecutar_operacion_segura(
            lambda: self.cuarentena.poner_en_cuarentena(ruta_archivo, tipo_amenaza, razon)
        )
    
    def quitar_de_cuarentena(self, ruta_original: str, restaurar: bool = True) -> Dict[str, Any]:
        """
        Quita un archivo de cuarentena.
        
        Args:
            ruta_original: Ruta original del archivo
            restaurar: Si True, restaurar archivo; si False, eliminarlo
            
        Returns:
            Diccionario con resultado de la operación
        """
        return self.ejecutar_operacion_segura(
            lambda: self.cuarentena.quitar_de_cuarentena(ruta_original=ruta_original, restaurar=restaurar)
        )
    
    def quitar_por_id(self, id_cuarentena: int, restaurar: bool = True) -> Dict[str, Any]:
        """
        Quita un archivo de cuarentena por ID.
        
        Args:
            id_cuarentena: ID del archivo en cuarentena
            restaurar: Si True, restaurar archivo; si False, eliminarlo
            
        Returns:
            Diccionario con resultado de la operación
        """
        return self.ejecutar_operacion_segura(
            lambda: self.cuarentena.quitar_de_cuarentena(id_cuarentena=id_cuarentena, restaurar=restaurar)
        )
    
    def listar_archivos_cuarentena(self, estado: str = "activo") -> List[Dict[str, Any]]:
        """
        Lista archivos en cuarentena.
        
        Args:
            estado: Estado de los archivos ('activo', 'restaurado', 'eliminado', 'todos')
            
        Returns:
            Lista de diccionarios con información de archivos
        """
        try:
            return self.cuarentena.listar_archivos_cuarentena(estado)
        except Exception as e:
            self.logger.error(f"Error listando archivos en cuarentena: {e}")
            return []
    
    def verificar_integridad(self) -> Dict[str, Any]:
        """
        Verifica la integridad de todos los archivos en cuarentena.
        
        Returns:
            Diccionario con estadísticas de verificación
        """
        return self.ejecutar_operacion_segura(
            lambda: self.cuarentena.verificar_integridad()
        )
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del sistema de cuarentena.
        
        Returns:
            Diccionario con estadísticas
        """
        return self.ejecutar_operacion_segura(
            lambda: self.cuarentena.obtener_estadisticas()
        )
    
    def limpiar_cuarentena_antigua(self, dias_antiguedad: int = 30) -> Dict[str, Any]:
        """
        Limpia archivos en cuarentena más antiguos que X días.
        
        Args:
            dias_antiguedad: Días de antigüedad para eliminar
            
        Returns:
            Diccionario con resultado de la operación
        """
        return self.ejecutar_operacion_segura(
            lambda: self.cuarentena.limpiar_cuarentena_antigua(dias_antiguedad)
        )
    
    def generar_reporte_cuarentena(self) -> Dict[str, Any]:
        """
        Genera un reporte completo del estado de la cuarentena.
        
        Returns:
            Diccionario con reporte completo
        """
        try:
            estadisticas = self.obtener_estadisticas()
            archivos_activos = self.listar_archivos_cuarentena("activo")
            verificacion = self.verificar_integridad()
            
            # Calcular métricas adicionales
            tipos_amenaza_count = {}
            archivos_recientes = []
            archivos_criticos = []
            
            for archivo in archivos_activos[:20]:  # Limitar a 20 para reporte
                # Contar tipos de amenaza
                tipo = archivo.get('tipo_amenaza', 'desconocido')
                tipos_amenaza_count[tipo] = tipos_amenaza_count.get(tipo, 0) + 1
                
                # Archivos recientes (últimos 5)
                if len(archivos_recientes) < 5:
                    archivos_recientes.append({
                        'archivo': archivo.get('ruta_original', ''),
                        'tipo': archivo.get('tipo_amenaza', ''),
                        'fecha': archivo.get('fecha_cuarentena', '')
                    })
                
                # Archivos críticos
                severidad = self.tipos_amenaza.get(tipo, 'Media')
                if severidad == 'Crítica':
                    archivos_criticos.append({
                        'archivo': archivo.get('ruta_original', ''),
                        'tipo': archivo.get('tipo_amenaza', ''),
                        'fecha': archivo.get('fecha_cuarentena', '')
                    })
            
            reporte = {
                'timestamp': datetime.now().isoformat(),
                'estadisticas_generales': estadisticas,
                'verificacion_integridad': verificacion,
                'tipos_amenaza_detectados': tipos_amenaza_count,
                'archivos_recientes': archivos_recientes,
                'archivos_criticos': archivos_criticos,
                'total_archivos_activos': len(archivos_activos),
                'estado_sistema': 'OPERATIVO' if verificacion.get('exito', False) else 'CON_PROBLEMAS'
            }
            
            self.logger.info("Reporte de cuarentena generado exitosamente")
            return {'exito': True, 'reporte': reporte}
            
        except Exception as e:
            error_msg = f"Error generando reporte de cuarentena: {e}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def validar_funcionalidad(self) -> Dict[str, Any]:
        """
        Valida que todas las funcionalidades del controlador están operativas.
        
        Returns:
            Diccionario con resultado de validación
        """
        validacion = {
            'timestamp': datetime.now().isoformat(),
            'exito': False,
            'pruebas': {},
            'errores': []
        }
        
        try:
            # Prueba 1: Verificar acceso a directorio de cuarentena
            try:
                directorio_existe = os.path.exists(self.cuarentena.directorio_cuarentena)
                directorio_escribible = os.access(self.cuarentena.directorio_cuarentena, os.W_OK) if directorio_existe else False
                validacion['pruebas']['directorio_cuarentena'] = {
                    'existe': directorio_existe,
                    'escribible': directorio_escribible,
                    'ruta': self.cuarentena.directorio_cuarentena
                }
            except Exception as e:
                validacion['errores'].append(f"Error verificando directorio: {e}")
                validacion['pruebas']['directorio_cuarentena'] = {'error': str(e)}
            
            # Prueba 2: Verificar base de datos
            try:
                db_existe = os.path.exists(self.cuarentena.db_path)
                validacion['pruebas']['base_datos'] = {
                    'existe': db_existe,
                    'ruta': self.cuarentena.db_path
                }
            except Exception as e:
                validacion['errores'].append(f"Error verificando base de datos: {e}")
                validacion['pruebas']['base_datos'] = {'error': str(e)}
            
            # Prueba 3: Verificar estadísticas
            try:
                stats = self.obtener_estadisticas()
                validacion['pruebas']['estadisticas'] = {
                    'funcional': stats.get('total_archivos', -1) >= 0,
                    'datos': stats
                }
            except Exception as e:
                validacion['errores'].append(f"Error obteniendo estadísticas: {e}")
                validacion['pruebas']['estadisticas'] = {'error': str(e)}
            
            # Evaluación final
            pruebas_exitosas = sum(1 for p in validacion['pruebas'].values() 
                                 if isinstance(p, dict) and not p.get('error'))
            total_pruebas = len(validacion['pruebas'])
            
            validacion['exito'] = pruebas_exitosas == total_pruebas and len(validacion['errores']) == 0
            validacion['resumen'] = f"{pruebas_exitosas}/{total_pruebas} pruebas exitosas"
            
            self.logger.info(f"Validación de funcionalidad completada: {validacion['resumen']}")
            
        except Exception as e:
            validacion['errores'].append(f"Error general en validación: {e}")
            self.logger.error(f"Error en validación de funcionalidad: {e}")
        
        return validacion
