# -*- coding: utf-8 -*-
"""
ARESITOS - Gestor de Configuración
Gestión centralizada de configuración del sistema
"""

import json
import os
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path

# Importar modelo base para mantener patrón MVC
try:
    from ..modelo.modelo_principal import ModeloPrincipal
    MODELO_DISPONIBLE = True
except ImportError:
    # Fallback para mantener funcionalidad
    MODELO_DISPONIBLE = False

class GestorConfiguracion:
    """
    Gestor centralizado de configuración para ARESITOS.
    Maneja carga, guardado y validación de configuraciones.
    """
    
    def __init__(self, directorio_config: Optional[str] = None, modelo_principal=None):
        """
        Inicializar gestor de configuración.
        
        Args:
            directorio_config: Directorio donde se almacenan las configuraciones
            modelo_principal: Modelo principal para patrón MVC
        """
        self.directorio_config = directorio_config or self._obtener_directorio_config()
        self.modelo_principal = modelo_principal  # Mantener patrón MVC
        self._configuraciones = {}
        self._lock = threading.Lock()
        self._configuracion_por_defecto = self._obtener_configuracion_por_defecto()
        
        # Asegurar que el directorio existe
        Path(self.directorio_config).mkdir(parents=True, exist_ok=True)
        
        # Cargar configuración inicial
        self._cargar_configuracion_inicial()
    
    def _obtener_directorio_config(self) -> str:
        """Obtener directorio de configuración por defecto."""
        # Intentar usar directorio relativo al proyecto
        directorio_actual = Path(__file__).parent.parent.parent
        directorio_config = directorio_actual / "configuración"
        
        if directorio_config.exists():
            return str(directorio_config)
        
        # Fallback a directorio actual
        return str(Path.cwd() / "configuración")
    
    def _obtener_configuracion_por_defecto(self) -> Dict[str, Any]:
        """Obtener configuración por defecto del sistema."""
        return {
            "sistema": {
                "version": "2.0.0",
                "nombre": "ARESITOS",
                "debug": False,
                "log_level": "INFO",
                "max_hilos": 4,
                "timeout_operaciones": 60
            },
            "escáner": {
                "puerto_inicial": 1,
                "puerto_final": 1000,
                "timeout_conexion": 3,
                "max_puertos_simultaneos": 50,
                "intentos_maximos": 3
            },
            "monitor": {
                "intervalo_actualizacion": 5,
                "max_procesos_mostrar": 20,
                "alertas_cpu": 85,
                "alertas_memoria": 80,
                "alertas_disco": 90
            },
            "siem": {
                "max_eventos": 1000,
                "niveles_log": ["info", "warning", "error", "critical"],
                "archivo_eventos": "eventos_siem.log",
                "rotacion_logs": True
            },
            "reportes": {
                "directorio_reportes": "reportes",
                "formatos_soportados": ["json", "txt", "html"],
                "max_reportes_guardados": 50,
                "incluir_graficos": False
            },
            "seguridad": {
                "verificar_integridad": True,
                "logs_auditoria": True,
                "nivel_paranoia": "medio",
                "backup_automatico": True
            },
            "interfaz": {
                "tema": "kali_dark",
                "idioma": "es",
                "resolucion_minima": "1400x900",
                "animaciones": True,
                "notificaciones": True
            },
            "red": {
                "timeout_ping": 3,
                "max_intentos_conexion": 3,
                "detectar_proxies": True,
                "usar_tor": False
            }
        }
    
    def _cargar_configuracion_inicial(self) -> None:
        """Cargar configuración inicial desde archivos."""
        try:
            # Buscar archivo de configuración principal
            archivos_config = [
                "aresitos_config.json",
                "aresitos_config_kali.json",
                "config.json"
            ]
            
            configuracion_cargada = None
            
            for archivo in archivos_config:
                ruta_archivo = Path(self.directorio_config) / archivo
                if ruta_archivo.exists():
                    configuracion_cargada = self._cargar_archivo_json(str(ruta_archivo))
                    if configuracion_cargada:
                        break
            
            if configuracion_cargada:
                # Fusionar con configuración por defecto
                self._configuraciones = self._fusionar_configuraciones(
                    self._configuracion_por_defecto,
                    configuracion_cargada
                )
            else:
                # Usar configuración por defecto
                self._configuraciones = self._configuracion_por_defecto.copy()
                
                # Guardar configuración por defecto
                self._guardar_configuracion_por_defecto()
                
        except Exception as e:
            print(f"Error cargando configuración inicial: {e}")
            self._configuraciones = self._configuracion_por_defecto.copy()
    
    def _cargar_archivo_json(self, ruta_archivo: str) -> Optional[Dict[str, Any]]:
        """Cargar configuración desde archivo JSON."""
        try:
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error cargando archivo {ruta_archivo}: {e}")
            return None
    
    def _fusionar_configuraciones(self, config_base: Dict[str, Any], 
                                 config_nueva: Dict[str, Any]) -> Dict[str, Any]:
        """Fusionar dos configuraciones recursivamente."""
        resultado = config_base.copy()
        
        for clave, valor in config_nueva.items():
            if (clave in resultado and 
                isinstance(resultado[clave], dict) and 
                isinstance(valor, dict)):
                resultado[clave] = self._fusionar_configuraciones(resultado[clave], valor)
            else:
                resultado[clave] = valor
        
        return resultado
    
    def _guardar_configuracion_por_defecto(self) -> None:
        """Guardar configuración por defecto en archivo."""
        try:
            ruta_archivo = Path(self.directorio_config) / "aresitos_config.json"
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                json.dump(self._configuraciones, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Error guardando configuración por defecto: {e}")
    
    def obtener(self, clave: str, valor_defecto: Any = None) -> Any:
        """
        Obtener valor de configuración usando notación de punto.
        
        Args:
            clave: Clave de configuración (ej: "sistema.version")
            valor_defecto: Valor por defecto si no se encuentra la clave
        
        Returns:
            Valor de configuración o valor por defecto
        """
        with self._lock:
            try:
                partes = clave.split('.')
                valor = self._configuraciones
                
                for parte in partes:
                    if isinstance(valor, dict) and parte in valor:
                        valor = valor[parte]
                    else:
                        return valor_defecto
                
                return valor
                
            except (ValueError, TypeError, AttributeError):
                return valor_defecto
    
    def establecer(self, clave: str, valor: Any) -> bool:
        """
        Establecer valor de configuración usando notación de punto.
        
        Args:
            clave: Clave de configuración (ej: "sistema.debug")
            valor: Nuevo valor
        
        Returns:
            True si se estableció correctamente
        """
        with self._lock:
            try:
                partes = clave.split('.')
                config_ref = self._configuraciones
                
                # Navegar hasta el penúltimo nivel
                for parte in partes[:-1]:
                    if parte not in config_ref:
                        config_ref[parte] = {}
                    config_ref = config_ref[parte]
                
                # Establecer valor final
                config_ref[partes[-1]] = valor
                return True
                
            except (ValueError, TypeError, AttributeError):
                return False
    
    def obtener_seccion(self, seccion: str) -> Dict[str, Any]:
        """
        Obtener sección completa de configuración.
        
        Args:
            seccion: Nombre de la sección
        
        Returns:
            Diccionario con la sección completa
        """
        with self._lock:
            return self._configuraciones.get(seccion, {}).copy()
    
    def establecer_seccion(self, seccion: str, configuración: Dict[str, Any]) -> bool:
        """
        Establecer sección completa de configuración.
        
        Args:
            seccion: Nombre de la sección
            configuración: Diccionario con la nueva configuración
        
        Returns:
            True si se estableció correctamente
        """
        with self._lock:
            try:
                self._configuraciones[seccion] = configuración.copy()
                return True
            except (ValueError, TypeError, AttributeError):
                return False
    
    def guardar_configuracion(self, nombre_archivo: str = "aresitos_config.json") -> bool:
        """
        Guardar configuración actual en archivo.
        
        Args:
            nombre_archivo: Nombre del archivo donde guardar
        
        Returns:
            True si se guardó correctamente
        """
        with self._lock:
            try:
                ruta_archivo = Path(self.directorio_config) / nombre_archivo
                with open(ruta_archivo, 'w', encoding='utf-8') as f:
                    json.dump(self._configuraciones, f, indent=4, ensure_ascii=False)
                return True
            except Exception as e:
                print(f"Error guardando configuración: {e}")
                return False
    
    def cargar_configuracion(self, nombre_archivo: str) -> bool:
        """
        Cargar configuración desde archivo.
        
        Args:
            nombre_archivo: Nombre del archivo a cargar
        
        Returns:
            True si se cargó correctamente
        """
        try:
            ruta_archivo = Path(self.directorio_config) / nombre_archivo
            if not ruta_archivo.exists():
                return False
            
            configuracion_nueva = self._cargar_archivo_json(str(ruta_archivo))
            if configuracion_nueva:
                with self._lock:
                    self._configuraciones = self._fusionar_configuraciones(
                        self._configuracion_por_defecto,
                        configuracion_nueva
                    )
                return True
            
        except Exception as e:
            print(f"Error cargando configuración desde {nombre_archivo}: {e}")
        
        return False
    
    def resetear_configuracion(self) -> None:
        """Resetear configuración a valores por defecto."""
        with self._lock:
            self._configuraciones = self._configuracion_por_defecto.copy()
    
    def validar_configuracion(self) -> Dict[str, Any]:
        """
        Validar configuración actual.
        
        Returns:
            Dict con resultado de validación
        """
        errores = []
        advertencias = []
        
        try:
            # Validar sección sistema
            sistema = self.obtener_seccion("sistema")
            if not sistema.get("version"):
                errores.append("Versión del sistema no especificada")
            
            if sistema.get("max_hilos", 0) < 1:
                advertencias.append("Número de hilos muy bajo")
            
            # Validar sección escáner
            escáner = self.obtener_seccion("escáner")
            puerto_inicial = escáner.get("puerto_inicial", 0)
            puerto_final = escáner.get("puerto_final", 0)
            
            if puerto_inicial >= puerto_final:
                errores.append("Rango de puertos inválido")
            
            # Validar sección monitor
            monitor = self.obtener_seccion("monitor")
            if monitor.get("intervalo_actualizacion", 0) < 1:
                advertencias.append("Intervalo de actualización muy bajo")
            
            # Validar directorios
            directorio_reportes = self.obtener("reportes.directorio_reportes")
            if directorio_reportes:
                ruta_reportes = Path(directorio_reportes)
                if not ruta_reportes.exists():
                    try:
                        ruta_reportes.mkdir(parents=True, exist_ok=True)
                    except (ValueError, TypeError, AttributeError):
                        errores.append(f"No se puede crear directorio de reportes: {directorio_reportes}")
            
        except Exception as e:
            errores.append(f"Error durante validación: {str(e)}")
        
        return {
            'valida': len(errores) == 0,
            'errores': errores,
            'advertencias': advertencias,
            'total_errores': len(errores),
            'total_advertencias': len(advertencias)
        }
    
    def obtener_configuracion_completa(self) -> Dict[str, Any]:
        """Obtener copia completa de la configuración."""
        with self._lock:
            return self._configuraciones.copy()
    
    def listar_archivos_configuracion(self) -> List[str]:
        """
        Listar archivos de configuración disponibles.
        
        Returns:
            Lista de nombres de archivos
        """
        try:
            directorio = Path(self.directorio_config)
            if not directorio.exists():
                return []
            
            archivos = []
            for archivo in directorio.iterdir():
                if archivo.is_file() and archivo.suffix.lower() == '.json':
                    archivos.append(archivo.name)
            
            return sorted(archivos)
            
        except (ValueError, TypeError, AttributeError):
            return []
    
    def crear_backup_configuracion(self) -> str:
        """
        Crear backup de la configuración actual.
        
        Returns:
            Nombre del archivo de backup creado
        """
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_backup = f"backup_config_{timestamp}.json"
            
            if self.guardar_configuracion(nombre_backup):
                return nombre_backup
            
        except Exception as e:
            print(f"Error creando backup: {e}")
        
        return ""
    
    def aplicar_configuracion_perfil(self, perfil: str) -> bool:
        """
        Aplicar configuración predefinida según perfil.
        
        Args:
            perfil: Tipo de perfil (desarrollo, produccion, auditoría)
        
        Returns:
            True si se aplicó correctamente
        """
        perfiles = {
            "desarrollo": {
                "sistema.debug": True,
                "sistema.log_level": "DEBUG",
                "sistema.timeout_operaciones": 120,
                "monitor.intervalo_actualizacion": 2,
                "seguridad.nivel_paranoia": "bajo"
            },
            "produccion": {
                "sistema.debug": False,
                "sistema.log_level": "INFO",
                "sistema.timeout_operaciones": 60,
                "monitor.intervalo_actualizacion": 5,
                "seguridad.nivel_paranoia": "alto"
            },
            "auditoría": {
                "sistema.debug": False,
                "sistema.log_level": "WARNING",
                "seguridad.logs_auditoria": True,
                "seguridad.verificar_integridad": True,
                "seguridad.nivel_paranoia": "alto",
                "siem.max_eventos": 5000
            }
        }
        
        if perfil not in perfiles:
            return False
        
        try:
            for clave, valor in perfiles[perfil].items():
                self.establecer(clave, valor)
            return True
        except (ValueError, TypeError, AttributeError):
            return False

# RESUMEN TÉCNICO: Gestor centralizado de configuración para ARESITOS con soporte para
# múltiples archivos JSON, fusión inteligente de configuraciones, validación automática,
# notación de punto para acceso jerárquico, perfiles predefinidos y sistema de backup.
# Thread-safe con configuración por defecto robusta para entornos de ciberseguridad.
