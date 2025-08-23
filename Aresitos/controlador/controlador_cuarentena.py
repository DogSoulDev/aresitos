# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Controlador de Cuarentena Optimizado
===================================================

Controlador optimizado que integra el sistema de cuarentena Kali 2025
con el resto del ecosistema ARESITOS siguiendo principios v3.0.

Autor: ARESITOS Team
Versión: 3.0.0
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Importar modelo optimizado
try:
    from ..modelo.modelo_cuarentena_kali2025 import CuarentenaKali2025
    CUARENTENA_KALI2025_DISPONIBLE = True
except ImportError:
    CUARENTENA_KALI2025_DISPONIBLE = False

class ControladorCuarentena:
    """
    Controlador optimizado de cuarentena ARESITOS v3.0.
    Integra herramientas nativas de Kali Linux para análisis de amenazas.
    """
    
    def __init__(self, directorio_cuarentena: Optional[str] = None):
        """Inicializar controlador de cuarentena optimizado"""
        
        self.version = "3.0"
        self.logger = logging.getLogger(f"ARESITOS.{self.__class__.__name__}")
        
        # Inicializar sistema de cuarentena optimizado
        if CUARENTENA_KALI2025_DISPONIBLE:
            try:
                self.cuarentena = CuarentenaKali2025(directorio_cuarentena)
                self.log("✓ Sistema de cuarentena Kali 2025 inicializado")
            except Exception as e:
                self.log(f"Error inicializando cuarentena Kali 2025: {e}")
                self.cuarentena = None
        else:
            self.log("⚠️ Cuarentena Kali 2025 no disponible")
            self.cuarentena = None
    
    def log(self, mensaje: str):
        """Logging unificado del controlador"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [CONTROLADOR CUARENTENA] {mensaje}")
    
    # ========================================
    # MÉTODOS PRINCIPALES DE CUARENTENA
    # ========================================
    
    def procesar_amenaza_detectada(self, amenaza_info: Dict[str, Any]) -> bool:
        """
        Procesar amenaza detectada por cualquier sistema ARESITOS
        
        Args:
            amenaza_info: Información de la amenaza detectada
                - archivo: Ruta del archivo (si aplica)
                - tipo: Tipo de amenaza
                - descripcion: Descripción de la amenaza
                - severidad: Severidad detectada
                - fuente_deteccion: Sistema que detectó la amenaza
                
        Returns:
            bool: True si se procesó exitosamente
        """
        if not self.cuarentena:
            self.log("Sistema de cuarentena no disponible")
            return False
        
        try:
            archivo = amenaza_info.get('archivo')
            descripcion = amenaza_info.get('descripcion', 'Amenaza detectada')
            fuente = amenaza_info.get('fuente_deteccion', 'Sistema')
            
            if archivo and os.path.exists(archivo):
                # Cuarentenar archivo con análisis automático
                resultado = self.cuarentena.poner_en_cuarentena(
                    ruta_archivo=archivo,
                    motivo=descripcion,
                    fuente_deteccion=fuente
                )
                
                if resultado.get('exito'):
                    self.log(f"✓ Amenaza cuarentenada: {archivo}")
                    return True
                else:
                    self.log(f"✗ Error cuarentenando: {resultado.get('error', 'Desconocido')}")
                    return False
            else:
                # Amenaza sin archivo asociado - registrar en logs
                self.log(f"⚠️ Amenaza sin archivo: {descripcion}")
                return True
                
        except Exception as e:
            self.log(f"Error procesando amenaza: {e}")
            return False
    
    def cuarentenar_archivo(self, ruta_archivo: str, razon: str = "Detección manual") -> Dict[str, Any]:
        """
        Cuarentenar archivo específico (usado por GUI y otros controladores)
        
        Args:
            ruta_archivo: Ruta del archivo a cuarentenar
            razon: Razón de la cuarentena
            
        Returns:
            Dict con resultado de la operación
        """
        if not self.cuarentena:
            return {"exito": False, "error": "Sistema de cuarentena no disponible"}
        
        try:
            resultado = self.cuarentena.poner_en_cuarentena(ruta_archivo, razon, "Manual")
            
            if resultado.get('exito'):
                self.log(f"✓ Archivo cuarentenado manualmente: {ruta_archivo}")
            
            return resultado
            
        except Exception as e:
            self.log(f"Error en cuarentena manual: {e}")
            return {"exito": False, "error": str(e)}
    
    def listar_archivos_cuarentena(self) -> List[Dict[str, Any]]:
        """Listar todos los archivos en cuarentena"""
        if not self.cuarentena:
            return []
        
        try:
            return self.cuarentena.listar_archivos_cuarentena()
        except Exception as e:
            self.log(f"Error listando archivos: {e}")
            return []
    
    def obtener_resumen_cuarentena(self) -> Dict[str, Any]:
        """Obtener resumen completo del estado de cuarentena"""
        if not self.cuarentena:
            return {"error": "Sistema de cuarentena no disponible"}
        
        try:
            return self.cuarentena.obtener_resumen_cuarentena()
        except Exception as e:
            self.log(f"Error obteniendo resumen: {e}")
            return {"error": str(e)}
    
    def restaurar_archivo(self, archivo_id: int, ruta_destino: Optional[str] = None) -> bool:
        """
        Restaurar archivo desde cuarentena
        
        Args:
            archivo_id: ID del archivo en cuarentena
            ruta_destino: Ruta de destino (opcional)
            
        Returns:
            bool: True si se restauró exitosamente
        """
        if not self.cuarentena:
            return False
        
        try:
            resultado = self.cuarentena.restaurar_archivo(archivo_id, ruta_destino)
            
            if resultado.get('exito'):
                self.log(f"✓ Archivo restaurado: {resultado.get('archivo_restaurado', 'Desconocido')}")
                return True
            else:
                self.log(f"✗ Error restaurando: {resultado.get('error', 'Desconocido')}")
                return False
                
        except Exception as e:
            self.log(f"Error restaurando archivo: {e}")
            return False
    
    def eliminar_definitivamente(self, archivo_id: int) -> bool:
        """
        Eliminar definitivamente archivo de cuarentena
        
        Args:
            archivo_id: ID del archivo en cuarentena
            
        Returns:
            bool: True si se eliminó exitosamente
        """
        if not self.cuarentena:
            return False
        
        try:
            resultado = self.cuarentena.eliminar_archivo_cuarentena(archivo_id)
            
            if resultado.get('exito'):
                self.log(f"✓ Archivo eliminado: {resultado.get('archivo_eliminado', 'Desconocido')}")
                return True
            else:
                self.log(f"✗ Error eliminando: {resultado.get('error', 'Desconocido')}")
                return False
                
        except Exception as e:
            self.log(f"Error eliminando archivo: {e}")
            return False
    
    def limpiar_cuarentena_antigua(self, dias: int = 30) -> int:
        """
        Limpiar archivos antiguos de cuarentena
        
        Args:
            dias: Días de antigüedad para eliminar
            
        Returns:
            int: Número de archivos eliminados
        """
        if not self.cuarentena:
            return 0
        
        try:
            resultado = self.cuarentena.limpiar_cuarentena_antigua(dias)
            
            eliminados = resultado.get('archivos_eliminados', 0)
            if eliminados > 0:
                self.log(f"✓ Limpieza completada: {eliminados} archivos eliminados")
            
            return eliminados
            
        except Exception as e:
            self.log(f"Error limpiando cuarentena: {e}")
            return 0
    
    # ========================================
    # MÉTODOS DE COMPATIBILIDAD CON VISTA EXISTENTE
    # ========================================
    
    def poner_archivo_en_cuarentena(self, ruta_archivo: str) -> Dict[str, Any]:
        """Método de compatibilidad para la vista existente"""
        try:
            resultado = self.cuarentenar_archivo(ruta_archivo, "Agregado desde GUI")
            return {
                'exito': resultado.get('exito', False),
                'error': resultado.get('error', '')
            }
        except Exception as e:
            return {
                'exito': False,
                'error': f"Error en cuarentena: {str(e)}"
            }
    
    # ========================================
    # MÉTODOS DE INTEGRACIÓN CON OTROS SISTEMAS ARESITOS
    # ========================================
    
    def notificar_desde_siem(self, evento_siem: Dict[str, Any]) -> Dict[str, Any]:
        """Procesar notificación desde SIEM"""
        if not self.cuarentena:
            return {"exito": False, "error": "Sistema no disponible"}
        
        try:
            resultado = self.cuarentena.procesar_amenaza_desde_siem(evento_siem)
            
            if resultado.get('exito'):
                self.log("✓ Evento SIEM procesado")
            
            return resultado
            
        except Exception as e:
            self.log(f"Error procesando evento SIEM: {e}")
            return {"exito": False, "error": str(e)}
    
    def notificar_desde_fim(self, evento_fim: Dict[str, Any]) -> Dict[str, Any]:
        """Procesar notificación desde FIM"""
        if not self.cuarentena:
            return {"exito": False, "error": "Sistema no disponible"}
        
        try:
            resultado = self.cuarentena.procesar_amenaza_desde_fim(evento_fim)
            
            if resultado.get('exito'):
                self.log("✓ Evento FIM procesado")
            
            return resultado
            
        except Exception as e:
            self.log(f"Error procesando evento FIM: {e}")
            return {"exito": False, "error": str(e)}
    
    def notificar_desde_escaneador(self, evento_escaneador: Dict[str, Any]) -> Dict[str, Any]:
        """Procesar notificación desde Escaneador"""
        if not self.cuarentena:
            return {"exito": False, "error": "Sistema no disponible"}
        
        try:
            resultado = self.cuarentena.procesar_amenaza_desde_escaneador(evento_escaneador)
            
            if resultado.get('exito'):
                self.log("✓ Evento ESCANEADOR procesado")
            
            return resultado
            
        except Exception as e:
            self.log(f"Error procesando evento ESCANEADOR: {e}")
            return {"exito": False, "error": str(e)}
    
    def generar_reporte_cuarentena(self) -> Dict[str, Any]:
        """Generar reporte completo para el sistema de reportes"""
        if not self.cuarentena:
            return {"error": "Sistema de cuarentena no disponible"}
        
        try:
            reporte = self.cuarentena.generar_reporte_completo()
            self.log("✓ Reporte de cuarentena generado")
            return reporte
            
        except Exception as e:
            self.log(f"Error generando reporte: {e}")
            return {"error": str(e)}
    
    @property  
    def directorio_cuarentena(self) -> str:
        """Propiedad de compatibilidad"""
        if self.cuarentena:
            return self.cuarentena.directorio_cuarentena
        return "data/cuarentena"
