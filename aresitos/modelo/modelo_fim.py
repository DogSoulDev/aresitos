# -*- coding: utf-8 -*-
"""
Ares Aegis - FIM Avanzado (File Integrity Monitoring)
Sistema avanzado de monitoreo de integridad de archivos para Kali Linux
"""

import os
import json
import hashlib
import stat
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Set, List, Any, Optional
from collections import deque
from dataclasses import dataclass, asdict
from enum import Enum

# Importar el gestor de permisos seguro
try:
    from ..utils.gestor_permisos import obtener_gestor_permisos
    GESTOR_PERMISOS_DISPONIBLE = True
except ImportError:
    # Fallback si no está disponible
    GESTOR_PERMISOS_DISPONIBLE = False
    obtener_gestor_permisos = None

class TipoArchivoFIM(Enum):
    """Tipos de archivo para clasificación FIM."""
    EJECUTABLE = "ejecutable"
    CONFIGURACION = "configuracion"
    LOG = "log"
    BIBLIOTECA = "biblioteca"
    SCRIPT = "script"
    DOCUMENTO = "documento"
    BINARIO = "binario"
    DESCONOCIDO = "desconocido"

class TipoCambioFIM(Enum):
    """Tipos de cambio detectados por FIM."""
    ARCHIVO_NUEVO = "archivo_nuevo"
    ARCHIVO_ELIMINADO = "archivo_eliminado"
    CONTENIDO_MODIFICADO = "contenido_modificado"
    PERMISOS_MODIFICADOS = "permisos_modificados"
    PROPIETARIO_MODIFICADO = "propietario_modificado"
    TIMESTAMP_MODIFICADO = "timestamp_modificado"

@dataclass
class MetadatosArchivo:
    """Metadatos completos de un archivo para FIM."""
    ruta: str
    nombre_archivo: str
    extension: str
    tipo_archivo: TipoArchivoFIM
    tamaño_bytes: int
    hash_md5: str
    hash_sha1: str
    hash_sha256: str
    permisos_octal: str
    permisos_texto: str
    propietario_uid: int
    propietario_nombre: str
    grupo_gid: int
    grupo_nombre: str
    fecha_creacion: datetime
    fecha_modificacion: datetime
    fecha_acceso: datetime
    timestamp_registro: datetime
    
    @classmethod
    def desde_archivo(cls, ruta_archivo: str) -> 'MetadatosArchivo':
        """Crear metadatos desde un archivo existente."""
        try:
            ruta_path = Path(ruta_archivo)
            stat_info = ruta_path.stat()
            
            # Calcular hashes
            hash_md5, hash_sha1, hash_sha256 = cls._calcular_hashes(ruta_archivo)
            
            # Obtener información de propietario
            propietario_nombre = "desconocido"
            grupo_nombre = "desconocido"
            
            try:
                import platform
                
                if platform.system() != "Windows":
                    try:
                        import pwd
                        import grp
                        # Usar getattr para acceso seguro a funciones
                        getpwuid = getattr(pwd, 'getpwuid', None)
                        getgrgid = getattr(grp, 'getgrgid', None)
                        
                        if getpwuid and getgrgid:
                            propietario_info = getpwuid(stat_info.st_uid)
                            grupo_info = getgrgid(stat_info.st_gid)
                            propietario_nombre = propietario_info.pw_name
                            grupo_nombre = grupo_info.gr_name
                        else:
                            propietario_nombre = str(stat_info.st_uid)
                            grupo_nombre = str(stat_info.st_gid)
                    except (KeyError, AttributeError, ImportError):
                        propietario_nombre = str(getattr(stat_info, 'st_uid', 'unknown'))
                        grupo_nombre = str(getattr(stat_info, 'st_gid', 'unknown'))
                else:
                    propietario_nombre = "usuario_windows"
                    grupo_nombre = "grupo_windows"
            except Exception:
                pass  # Mantener valores por defecto
            
            # Determinar tipo de archivo
            tipo_archivo = cls._determinar_tipo_archivo(ruta_path)
            
            return cls(
                ruta=str(ruta_path.absolute()),
                nombre_archivo=ruta_path.name,
                extension=ruta_path.suffix.lower(),
                tipo_archivo=tipo_archivo,
                tamaño_bytes=stat_info.st_size,
                hash_md5=hash_md5,
                hash_sha1=hash_sha1,
                hash_sha256=hash_sha256,
                permisos_octal=oct(stat_info.st_mode)[-3:],
                permisos_texto=stat.filemode(stat_info.st_mode),
                propietario_uid=stat_info.st_uid,
                propietario_nombre=propietario_nombre,
                grupo_gid=stat_info.st_gid,
                grupo_nombre=grupo_nombre,
                fecha_creacion=datetime.fromtimestamp(stat_info.st_ctime),
                fecha_modificacion=datetime.fromtimestamp(stat_info.st_mtime),
                fecha_acceso=datetime.fromtimestamp(stat_info.st_atime),
                timestamp_registro=datetime.now()
            )
        except Exception as e:
            raise Exception(f"Error creando metadatos para {ruta_archivo}: {str(e)}")
    
    @staticmethod
    def _calcular_hashes(ruta_archivo: str) -> tuple:
        """Calcular hashes MD5, SHA1 y SHA256 de un archivo."""
        try:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            
            with open(ruta_archivo, 'rb') as archivo:
                # Leer en chunks para archivos grandes
                for chunk in iter(lambda: archivo.read(8192), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return (
                md5_hash.hexdigest(),
                sha1_hash.hexdigest(),
                sha256_hash.hexdigest()
            )
        except Exception:
            return ("", "", "")
    
    @staticmethod
    def _determinar_tipo_archivo(ruta_path: Path) -> TipoArchivoFIM:
        """Determinar el tipo de archivo basado en extensión y ubicación."""
        extension = ruta_path.suffix.lower()
        ruta_str = str(ruta_path).lower()
        
        # Ejecutables
        if (extension in ['.exe', '.bin', '.sh', '.py', '.pl', '.rb', '.js'] or
            '/bin/' in ruta_str or '/sbin/' in ruta_str):
            return TipoArchivoFIM.EJECUTABLE
        
        # Configuración
        if (extension in ['.conf', '.cfg', '.ini', '.xml', '.json', '.yaml', '.yml'] or
            '/etc/' in ruta_str or '.config' in ruta_str):
            return TipoArchivoFIM.CONFIGURACION
        
        # Logs
        if (extension in ['.log', '.logs'] or '/var/log/' in ruta_str):
            return TipoArchivoFIM.LOG
        
        # Bibliotecas
        if (extension in ['.so', '.dll', '.dylib', '.a'] or '/lib/' in ruta_str):
            return TipoArchivoFIM.BIBLIOTECA
        
        # Scripts
        if extension in ['.sh', '.bash', '.zsh', '.fish', '.py', '.pl', '.rb', '.php']:
            return TipoArchivoFIM.SCRIPT
        
        # Documentos
        if extension in ['.txt', '.doc', '.pdf', '.md', '.rst', '.html', '.htm']:
            return TipoArchivoFIM.DOCUMENTO
        
        # Binarios
        if extension in ['.bin', '.dat', '.img', '.iso']:
            return TipoArchivoFIM.BINARIO
        
        return TipoArchivoFIM.DESCONOCIDO

@dataclass
class AlertaFIM:
    """Alerta generada por el sistema FIM."""
    timestamp: datetime
    tipo_cambio: TipoCambioFIM
    ruta_archivo: str
    detalles_cambio: Dict[str, Any]
    metadatos_anteriores: Optional[MetadatosArchivo]
    metadatos_actuales: Optional[MetadatosArchivo]
    nivel_criticidad: str
    procesada: bool = False

class FIMAvanzado:
    """Sistema avanzado de Monitoreo de Integridad de Archivos para Ares Aegis."""
    
    _instancia_global = None  # Singleton para evitar duplicaciones
    
    def __init__(self, siem=None):
        """Inicializar FIM avanzado."""
        # Evitar inicialización múltiple
        if FIMAvanzado._instancia_global is not None:
            self.__dict__ = FIMAvanzado._instancia_global.__dict__
            return
        
        self.siem = siem
        self.logger = self._configurar_logger()
        
        # Inicializar gestor de permisos
        if GESTOR_PERMISOS_DISPONIBLE and obtener_gestor_permisos is not None:
            self.gestor_permisos = obtener_gestor_permisos()
            self.logger.info("OK FIM: Gestor de permisos inicializado")
        else:
            self.gestor_permisos = None
            self.logger.warning("WARNING FIM: Gestor de permisos no disponible - monitoreo limitado")
        
        # Configuración
        self.archivo_base_datos = self._determinar_ruta_base_datos()
        self.rutas_monitoreadas: Set[str] = set()
        self.rutas_excluidas: Set[str] = set()
        self.intervalo_verificacion = 300  # 5 minutos
        
        # Base de datos en memoria
        self.base_datos: Dict[str, MetadatosArchivo] = {}
        
        # Alertas y estadísticas
        self.alertas_generadas: deque = deque(maxlen=1000)
        self.estadisticas = {
            "inicio_monitoreo": None,
            "archivos_monitoreados": 0,
            "verificaciones_realizadas": 0,
            "cambios_detectados": 0,
            "amenazas_detectadas": 0,
            "tiempo_ultima_verificacion": None
        }
        
        # Cargar configuración
        self._cargar_configuracion_kali()
        self._cargar_base_datos()
        
        # Establecer como instancia global
        FIMAvanzado._instancia_global = self
        
        self.logger.info(" FIM Avanzado inicializado correctamente")
    
    def _configurar_logger(self) -> logging.Logger:
        """Configurar logger específico para FIM."""
        logger = logging.getLogger("aresitos.fim")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def _determinar_ruta_base_datos(self) -> str:
        """Determinar ruta para archivo de base de datos FIM."""
        try:
            # Intentar directorio del proyecto
            directorio_actual = Path(__file__).parent.parent.parent
            directorio_data = directorio_actual / "data"
            directorio_data.mkdir(exist_ok=True)
            return str(directorio_data / "fim_database.json")
        except Exception:
            # Fallback a directorio temporal
            import tempfile
            return os.path.join(tempfile.gettempdir(), "ares_fim_database.json")
    
    def _cargar_configuracion_kali(self) -> None:
        """Cargar configuración específica para Kali Linux."""
        # Rutas críticas para monitorear en Kali Linux (solo archivos específicos importantes)
        rutas_criticas = [
            # Archivos de configuración críticos del sistema
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
            '/etc/sudoers', '/etc/security/access.conf', '/etc/security/limits.conf',
            '/etc/pam.d/common-auth', '/etc/pam.d/common-password', '/etc/login.defs',
            
            # Red y servicios críticos
            '/etc/hosts', '/etc/hosts.allow', '/etc/hosts.deny',
            '/etc/resolv.conf', '/etc/ssh/sshd_config', '/etc/ssh/ssh_config',
            
            # Sistema y kernel (solo archivos específicos)
            '/etc/fstab', '/etc/crontab', '/boot/grub/grub.cfg',
            '/etc/systemd/system.conf', '/etc/systemd/user.conf',
            
            # Aplicaciones críticas (solo archivos de configuración principales)
            '/etc/apache2/apache2.conf', '/etc/nginx/nginx.conf',
            '/etc/mysql/my.cnf', '/etc/postgresql/postgresql.conf',
            '/etc/fail2ban/fail2ban.conf', '/etc/fail2ban/jail.conf',
            
            # Herramientas de pentesting (Kali específico - solo configs importantes)
            '/etc/proxychains.conf', '/etc/tor/torrc',
            
            # Binarios críticos específicos (no directorios completos)
            '/bin/bash', '/bin/sh', '/bin/su', '/bin/sudo',
            '/sbin/init', '/sbin/iptables', '/sbin/ip6tables',
            '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/ssh',
            '/usr/sbin/sshd', '/usr/sbin/cron'
        ]
        
        # Solo añadir archivos específicos que existan (no directorios)
        for ruta in rutas_criticas:
            if os.path.exists(ruta) and os.path.isfile(ruta):
                self.rutas_monitoreadas.add(os.path.abspath(ruta))
        
        # Rutas a excluir (alta frecuencia de cambios)
        rutas_excluidas = [
            '/proc/', '/sys/', '/dev/', '/run/', '/tmp/',
            '/var/log/', '/var/cache/', '/var/tmp/',
            '/var/spool/', '/var/run/', '/var/lock/',
            '/home/*/.cache/', '/root/.cache/',
            '/var/lib/locate/', '/var/lib/mlocate/',
            # Kali específico
            '/root/.msf4/logs/', '/tmp/metasploit*/',
            '/usr/share/exploitdb/.git/'
        ]
        
        self.rutas_excluidas.update(rutas_excluidas)
        self.logger.info(f"Configuración cargada: {len(self.rutas_monitoreadas)} rutas monitoreadas")
    
    def _cargar_base_datos(self) -> None:
        """Cargar base de datos FIM desde archivo."""
        try:
            if os.path.exists(self.archivo_base_datos):
                with open(self.archivo_base_datos, 'r', encoding='utf-8') as archivo:
                    datos = json.load(archivo)
                    
                    for ruta, datos_archivo in datos.items():
                        # Recrear objeto MetadatosArchivo
                        metadatos = MetadatosArchivo(**datos_archivo)
                        
                        # Convertir fechas string a datetime
                        for campo_fecha in ['fecha_creacion', 'fecha_modificacion', 
                                          'fecha_acceso', 'timestamp_registro']:
                            if isinstance(getattr(metadatos, campo_fecha), str):
                                try:
                                    setattr(metadatos, campo_fecha, 
                                           datetime.fromisoformat(getattr(metadatos, campo_fecha)))
                                except Exception:
                                    setattr(metadatos, campo_fecha, datetime.now())
                        
                        # Convertir enum
                        if isinstance(metadatos.tipo_archivo, str):
                            try:
                                metadatos.tipo_archivo = TipoArchivoFIM(metadatos.tipo_archivo)
                            except ValueError:
                                metadatos.tipo_archivo = TipoArchivoFIM.DESCONOCIDO
                        
                        self.base_datos[ruta] = metadatos
                
                self.logger.info(f"Base de datos FIM cargada: {len(self.base_datos)} archivos")
            else:
                self.logger.info("No existe base de datos FIM previa")
        except Exception as e:
            self.logger.error(f"Error cargando base de datos FIM: {e}")
    
    def _guardar_base_datos(self) -> None:
        """Guardar base de datos FIM a archivo."""
        try:
            # Convertir a formato serializable
            datos_serializables = {}
            for ruta, metadatos in self.base_datos.items():
                datos_metadatos = asdict(metadatos)
                
                # Convertir datetime a string
                for campo_fecha in ['fecha_creacion', 'fecha_modificacion', 
                                  'fecha_acceso', 'timestamp_registro']:
                    if isinstance(datos_metadatos[campo_fecha], datetime):
                        datos_metadatos[campo_fecha] = datos_metadatos[campo_fecha].isoformat()
                
                # Convertir enum a string
                if isinstance(datos_metadatos['tipo_archivo'], TipoArchivoFIM):
                    datos_metadatos['tipo_archivo'] = datos_metadatos['tipo_archivo'].value
                
                datos_serializables[ruta] = datos_metadatos
            
            # Guardar a archivo
            with open(self.archivo_base_datos, 'w', encoding='utf-8') as archivo:
                json.dump(datos_serializables, archivo, indent=2, ensure_ascii=False)
            
            self.logger.debug(f"Base de datos FIM guardada: {len(datos_serializables)} archivos")
        except Exception as e:
            self.logger.error(f"Error guardando base de datos FIM: {e}")
    
    def crear_baseline(self, rutas_adicionales: Optional[List[str]] = None) -> Dict[str, Any]:
        """Crear línea base de integridad de archivos."""
        self.logger.info("Iniciando creación de línea base FIM")
        inicio_tiempo = time.time()
        
        archivos_procesados = 0
        errores = 0
        
        # Limpiar base de datos actual
        self.base_datos.clear()
        
        # Agregar rutas adicionales si se especifican
        rutas_a_procesar = self.rutas_monitoreadas.copy()
        if rutas_adicionales:
            for ruta in rutas_adicionales:
                if os.path.exists(ruta):
                    rutas_a_procesar.add(os.path.abspath(ruta))
        
        # Procesar todas las rutas
        for ruta in rutas_a_procesar:
            try:
                if os.path.isfile(ruta):
                    # Es un archivo individual
                    try:
                        metadatos = MetadatosArchivo.desde_archivo(ruta)
                        self.base_datos[ruta] = metadatos
                        archivos_procesados += 1
                    except Exception as e:
                        self.logger.warning(f"Error procesando archivo {ruta}: {e}")
                        errores += 1
                
                elif os.path.isdir(ruta):
                    # Es un directorio
                    for root, dirs, files in os.walk(ruta):
                        for archivo in files:
                            ruta_archivo = os.path.join(root, archivo)
                            
                            # Verificar si está excluido
                            if any(exclusion in ruta_archivo for exclusion in self.rutas_excluidas):
                                continue
                            
                            try:
                                metadatos = MetadatosArchivo.desde_archivo(ruta_archivo)
                                self.base_datos[ruta_archivo] = metadatos
                                archivos_procesados += 1
                                
                                # Log progreso cada 1000 archivos
                                if archivos_procesados % 1000 == 0:
                                    self.logger.info(f"Progreso línea base: {archivos_procesados} archivos")
                            except Exception as e:
                                self.logger.debug(f"Error procesando {ruta_archivo}: {e}")
                                errores += 1
            
            except Exception as e:
                self.logger.error(f"Error procesando ruta {ruta}: {e}")
                errores += 1
        
        # Guardar base de datos
        self._guardar_base_datos()
        
        tiempo_total = time.time() - inicio_tiempo
        
        estadisticas = {
            'archivos_procesados': archivos_procesados,
            'errores': errores,
            'tiempo_total': tiempo_total,
            'rutas_monitoreadas': len(rutas_a_procesar),
            'timestamp': datetime.now().isoformat()
        }
        
        self.estadisticas["archivos_monitoreados"] = archivos_procesados
        self.estadisticas["inicio_monitoreo"] = datetime.now().isoformat()
        
        # Registrar evento SIEM
        if self.siem:
            self.siem.generar_evento(
                "BASELINE_FIM_CREADA",
                f"Línea base FIM creada: {archivos_procesados} archivos en {tiempo_total:.2f}s",
                "info"
            )
        
        self.logger.info(f"Línea base FIM creada: {archivos_procesados} archivos en {tiempo_total:.2f}s")
        return estadisticas
    
    def verificar_integridad(self) -> List[AlertaFIM]:
        """Verificar integridad de archivos monitoreados."""
        self.logger.info("Iniciando verificación de integridad FIM")
        alertas = []
        archivos_verificados = 0
        
        # Verificar archivos existentes en la base de datos
        for ruta_archivo, metadatos_originales in self.base_datos.copy().items():
            try:
                if os.path.exists(ruta_archivo):
                    # Archivo existe, verificar cambios
                    metadatos_actuales = MetadatosArchivo.desde_archivo(ruta_archivo)
                    cambios_detectados = self._comparar_metadatos(metadatos_originales, metadatos_actuales)
                    
                    if cambios_detectados:
                        alerta = AlertaFIM(
                            timestamp=datetime.now(),
                            tipo_cambio=cambios_detectados[0],  # Primer tipo de cambio
                            ruta_archivo=ruta_archivo,
                            detalles_cambio={"cambios": cambios_detectados},
                            metadatos_anteriores=metadatos_originales,
                            metadatos_actuales=metadatos_actuales,
                            nivel_criticidad=self._evaluar_criticidad(ruta_archivo, cambios_detectados)
                        )
                        alertas.append(alerta)
                        
                        # Actualizar base de datos
                        self.base_datos[ruta_archivo] = metadatos_actuales
                else:
                    # Archivo eliminado
                    alerta = AlertaFIM(
                        timestamp=datetime.now(),
                        tipo_cambio=TipoCambioFIM.ARCHIVO_ELIMINADO,
                        ruta_archivo=ruta_archivo,
                        detalles_cambio={"archivo_eliminado": True},
                        metadatos_anteriores=metadatos_originales,
                        metadatos_actuales=None,
                        nivel_criticidad="ALTA"
                    )
                    alertas.append(alerta)
                    
                    # Remover de base de datos
                    del self.base_datos[ruta_archivo]
                
                archivos_verificados += 1
                
            except Exception as e:
                self.logger.warning(f"Error verificando {ruta_archivo}: {e}")
        
        # Buscar archivos nuevos en rutas monitoreadas
        self._detectar_archivos_nuevos(alertas)
        
        # Actualizar estadísticas
        self.estadisticas["verificaciones_realizadas"] += 1
        self.estadisticas["cambios_detectados"] += len(alertas)
        self.estadisticas["tiempo_ultima_verificacion"] = datetime.now().isoformat()
        
        # Guardar base de datos actualizada
        if alertas:
            self._guardar_base_datos()
        
        # Añadir alertas a cola
        for alerta in alertas:
            self.alertas_generadas.append(alerta)
        
        # Registrar eventos SIEM
        if self.siem and alertas:
            for alerta in alertas:
                self.siem.generar_evento(
                    f"FIM_{alerta.tipo_cambio.value.upper()}",
                    f"Cambio detectado en {alerta.ruta_archivo}",
                    "warning" if alerta.nivel_criticidad == "ALTA" else "info"
                )
        
        self.logger.info(f"Verificación FIM completada: {len(alertas)} cambios en {archivos_verificados} archivos")
        return alertas
    
    def _comparar_metadatos(self, original: MetadatosArchivo, actual: MetadatosArchivo) -> List[TipoCambioFIM]:
        """Comparar metadatos y detectar cambios."""
        cambios = []
        
        # Verificar contenido (hashes)
        if (original.hash_md5 != actual.hash_md5 or 
            original.hash_sha256 != actual.hash_sha256):
            cambios.append(TipoCambioFIM.CONTENIDO_MODIFICADO)
        
        # Verificar permisos
        if original.permisos_octal != actual.permisos_octal:
            cambios.append(TipoCambioFIM.PERMISOS_MODIFICADOS)
        
        # Verificar propietario
        if (original.propietario_uid != actual.propietario_uid or
            original.grupo_gid != actual.grupo_gid):
            cambios.append(TipoCambioFIM.PROPIETARIO_MODIFICADO)
        
        # Verificar timestamps (solo si es significativo, >1 minuto)
        if abs((original.fecha_modificacion - actual.fecha_modificacion).total_seconds()) > 60:
            cambios.append(TipoCambioFIM.TIMESTAMP_MODIFICADO)
        
        return cambios
    
    def _detectar_archivos_nuevos(self, alertas: List[AlertaFIM]) -> None:
        """Detectar archivos nuevos en rutas monitoreadas."""
        for ruta in self.rutas_monitoreadas:
            if os.path.isdir(ruta):
                try:
                    for root, dirs, files in os.walk(ruta):
                        for archivo in files:
                            ruta_archivo = os.path.join(root, archivo)
                            
                            # Verificar si está excluido
                            if any(exclusion in ruta_archivo for exclusion in self.rutas_excluidas):
                                continue
                            
                            # Si no está en la base de datos, es nuevo
                            if ruta_archivo not in self.base_datos:
                                try:
                                    metadatos_nuevos = MetadatosArchivo.desde_archivo(ruta_archivo)
                                    
                                    alerta = AlertaFIM(
                                        timestamp=datetime.now(),
                                        tipo_cambio=TipoCambioFIM.ARCHIVO_NUEVO,
                                        ruta_archivo=ruta_archivo,
                                        detalles_cambio={"archivo_nuevo": True},
                                        metadatos_anteriores=None,
                                        metadatos_actuales=metadatos_nuevos,
                                        nivel_criticidad=self._evaluar_criticidad(ruta_archivo, [TipoCambioFIM.ARCHIVO_NUEVO])
                                    )
                                    alertas.append(alerta)
                                    
                                    # Añadir a base de datos
                                    self.base_datos[ruta_archivo] = metadatos_nuevos
                                    
                                except Exception as e:
                                    self.logger.debug(f"Error procesando archivo nuevo {ruta_archivo}: {e}")
                except Exception as e:
                    self.logger.warning(f"Error explorando directorio {ruta}: {e}")
    
    def _evaluar_criticidad(self, ruta_archivo: str, cambios: List[TipoCambioFIM]) -> str:
        """Evaluar criticidad de cambios basado en ruta y tipo de cambio."""
        # Rutas críticas del sistema
        rutas_criticas = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/']
        
        # Tipos de cambio críticos
        cambios_criticos = [TipoCambioFIM.CONTENIDO_MODIFICADO, TipoCambioFIM.ARCHIVO_ELIMINADO]
        
        # Si es ruta crítica o cambio crítico
        if (any(critica in ruta_archivo for critica in rutas_criticas) or
            any(cambio in cambios_criticos for cambio in cambios)):
            return "ALTA"
        
        # Cambios en configuración
        if '/etc/' in ruta_archivo or any(cambio == TipoCambioFIM.PERMISOS_MODIFICADOS for cambio in cambios):
            return "MEDIA"
        
        return "BAJA"
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas del sistema FIM."""
        estadisticas = self.estadisticas.copy()
        estadisticas.update({
            'alertas_pendientes': len([a for a in self.alertas_generadas if not a.procesada]),
            'total_alertas_generadas': len(self.alertas_generadas),
            'archivos_en_base_datos': len(self.base_datos),
            'rutas_monitoreadas': len(self.rutas_monitoreadas),
            'rutas_excluidas': len(self.rutas_excluidas)
        })
        return estadisticas
    
    def obtener_alertas_recientes(self, limite: int = 50) -> List[Dict[str, Any]]:
        """Obtener alertas recientes."""
        alertas_recientes = list(self.alertas_generadas)[-limite:]
        
        # Convertir a formato serializable
        alertas_dict = []
        for alerta in alertas_recientes:
            alerta_dict = {
                'timestamp': alerta.timestamp.isoformat(),
                'tipo_cambio': alerta.tipo_cambio.value,
                'ruta_archivo': alerta.ruta_archivo,
                'detalles_cambio': alerta.detalles_cambio,
                'nivel_criticidad': alerta.nivel_criticidad,
                'procesada': alerta.procesada
            }
            alertas_dict.append(alerta_dict)
        
        return alertas_dict
    
    def agregar_ruta_monitoreo(self, ruta: str) -> bool:
        """Agregar ruta para monitoreo."""
        try:
            if os.path.exists(ruta):
                self.rutas_monitoreadas.add(os.path.abspath(ruta))
                self.logger.info(f"Ruta agregada para monitoreo: {ruta}")
                return True
            else:
                self.logger.warning(f"Ruta no existe: {ruta}")
                return False
        except Exception as e:
            self.logger.error(f"Error agregando ruta {ruta}: {e}")
            return False
    
    def remover_ruta_monitoreo(self, ruta: str) -> bool:
        """Remover ruta del monitoreo."""
        try:
            ruta_abs = os.path.abspath(ruta)
            if ruta_abs in self.rutas_monitoreadas:
                self.rutas_monitoreadas.remove(ruta_abs)
                self.logger.info(f"Ruta removida del monitoreo: {ruta}")
                return True
            else:
                self.logger.warning(f"Ruta no estaba siendo monitoreada: {ruta}")
                return False
        except Exception as e:
            self.logger.error(f"Error removiendo ruta {ruta}: {e}")
            return False

# RESUMEN TÉCNICO: Sistema FIM avanzado para Ares Aegis con monitoreo integral de archivos,
# detección de cambios por hash y metadatos, alertas por criticidad, configuración específica
# para Kali Linux, base de datos persistente JSON, integración SIEM y manejo robusto de errores.
# Arquitectura optimizada para detección de alteraciones no autorizadas en sistemas de pentesting.
