#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARES AEGIS - UTILIDADES DE LOGGING
==================================

Sistema de logging centralizado para Ares Aegis con configuración
profesional, formateo personalizado y rotación de archivos.

Autor: Ares Aegis Security Suite
Fecha: 2024
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Configuración global de logging
LOGGER_CONFIGURADO = False
LOGGERS_CACHE: Dict[str, logging.Logger] = {}

def obtener_logger(nombre: str, nivel: str = "INFO") -> logging.Logger:
    """
    Obtener logger configurado para un módulo específico.
    
    Args:
        nombre: Nombre del logger (generalmente __name__)
        nivel: Nivel de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        logging.Logger: Logger configurado
    """
    global LOGGER_CONFIGURADO, LOGGERS_CACHE
    
    # Si ya existe en cache, devolverlo
    if nombre in LOGGERS_CACHE:
        return LOGGERS_CACHE[nombre]
    
    # Configurar logging global si no está configurado
    if not LOGGER_CONFIGURADO:
        _configurar_logging_global()
        LOGGER_CONFIGURADO = True
    
    # Crear logger específico
    logger = logging.getLogger(nombre)
    
    # No agregar handlers adicionales si ya tiene el handler global
    if not logger.handlers:
        # Configurar nivel específico si es diferente
        nivel_obj = getattr(logging, nivel.upper(), logging.INFO)
        logger.setLevel(nivel_obj)
    
    # Cachear logger
    LOGGERS_CACHE[nombre] = logger
    
    return logger

def _configurar_logging_global():
    """Configurar el sistema de logging global."""
    try:
        # Crear directorio de logs si no existe
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        # Configuración del root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Limpiar handlers existentes
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Formatter personalizado
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler para consola
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # Handler para archivo con rotación
        archivo_log = logs_dir / "aresitos.log"
        file_handler = logging.handlers.RotatingFileHandler(
            archivo_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Handler para errores críticos
        error_log = logs_dir / "aresitos_errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        root_logger.addHandler(error_handler)
        
    except Exception as e:
        # Fallback a configuración básica si falla
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        print(f"⚠️ Advertencia: Error configurando logging avanzado: {e}")
        print("📝 Usando configuración básica de logging")

def configurar_logger_modulo(
    nombre: str, 
    archivo: Optional[str] = None,
    nivel: str = "INFO"
) -> logging.Logger:
    """
    Configurar logger específico para un módulo con archivo dedicado.
    
    Args:
        nombre: Nombre del logger
        archivo: Archivo específico para este logger (opcional)
        nivel: Nivel de logging
        
    Returns:
        logging.Logger: Logger configurado
    """
    logger = obtener_logger(nombre, nivel)
    
    if archivo:
        try:
            # Crear directorio si no existe
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            
            # Handler específico para este módulo
            archivo_path = logs_dir / archivo
            handler = logging.handlers.RotatingFileHandler(
                archivo_path,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=2,
                encoding='utf-8'
            )
            
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            handler.setLevel(getattr(logging, nivel.upper(), logging.INFO))
            
            # Evitar duplicar handlers
            if not any(isinstance(h, logging.handlers.RotatingFileHandler) 
                      and h.baseFilename == str(archivo_path.absolute()) 
                      for h in logger.handlers):
                logger.addHandler(handler)
                
        except Exception as e:
            logger.warning(f"No se pudo configurar archivo de log {archivo}: {e}")
    
    return logger

def log_evento_seguridad(
    evento: str, 
    nivel: str = "WARNING",
    datos_adicionales: Optional[Dict[str, Any]] = None
):
    """
    Registrar evento de seguridad específico.
    
    Args:
        evento: Descripción del evento
        nivel: Nivel de criticidad
        datos_adicionales: Información adicional del evento
    """
    logger = obtener_logger("aresitos.seguridad")
    nivel_obj = getattr(logging, nivel.upper(), logging.WARNING)
    
    mensaje = f"🛡️ EVENTO SEGURIDAD: {evento}"
    if datos_adicionales:
        mensaje += f" | Datos: {datos_adicionales}"
    
    logger.log(nivel_obj, mensaje)

def log_operacion_sistema(
    operacion: str,
    resultado: str = "EXITOSO",
    tiempo_ms: Optional[float] = None
):
    """
    Registrar operación del sistema.
    
    Args:
        operacion: Descripción de la operación
        resultado: Resultado de la operación
        tiempo_ms: Tiempo de ejecución en milisegundos
    """
    logger = obtener_logger("aresitos.sistema")
    
    mensaje = f"⚙️ {operacion}: {resultado}"
    if tiempo_ms is not None:
        mensaje += f" ({tiempo_ms:.2f}ms)"
    
    if resultado == "EXITOSO":
        logger.info(mensaje)
    else:
        logger.warning(mensaje)

def obtener_estadisticas_logging() -> Dict[str, Any]:
    """
    Obtener estadísticas del sistema de logging.
    
    Returns:
        Dict[str, Any]: Estadísticas de logging
    """
    try:
        logs_dir = Path("logs")
        estadisticas = {
            "loggers_activos": len(LOGGERS_CACHE),
            "directorio_logs": str(logs_dir.absolute()) if logs_dir.exists() else "No existe",
            "archivos_log": [],
            "configuracion_global": LOGGER_CONFIGURADO
        }
        
        if logs_dir.exists():
            for archivo in logs_dir.glob("*.log"):
                estadisticas["archivos_log"].append({
                    "nombre": archivo.name,
                    "tamaño_kb": archivo.stat().st_size // 1024,
                    "modificado": datetime.fromtimestamp(archivo.stat().st_mtime).isoformat()
                })
        
        return estadisticas
        
    except Exception as e:
        return {
            "error": f"Error obteniendo estadísticas: {e}",
            "loggers_activos": len(LOGGERS_CACHE),
            "configuracion_global": LOGGER_CONFIGURADO
        }

# Función de compatibilidad para código existente
def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Alias para obtener_logger para compatibilidad."""
    return obtener_logger(name, level)

# Configuración automática al importar
if __name__ != "__main__":
    # Auto-configurar al importar el módulo
    pass
else:
    # Test básico si se ejecuta directamente
    logger = obtener_logger(__name__)
    logger.info("✅ Sistema de logging de Ares Aegis iniciado correctamente")
    print("📊 Estadísticas:", obtener_estadisticas_logging())
