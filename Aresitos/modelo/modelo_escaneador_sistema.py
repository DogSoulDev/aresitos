# -*- coding: utf-8 -*-
"""
ARESITOS - Escaneador de Sistema Kali Linux
==========================================

Escaneador especializado para análisis completo del sistema operativo Kali Linux.
Utiliza únicamente Python nativo + herramientas nativas de Kali Linux.

Funcionalidades:
- Análisis de procesos del sistema
- Detección de servicios y demonios
- Escaneo de archivos sospechosos
- Verificación de integridad del sistema
- Análisis de logs de seguridad
- Detección de rootkits básica
- Verificación de permisos críticos

Principios ARESITOS aplicados:
- Python nativo + Kali tools únicamente
- Sin dependencias externas
- Código limpio y conciso (SOLID/DRY)
- MVC arquitectura respetada
- Sin emojis/tokens (excepto Aresitos.ico/png)

Autor: DogSoulDev
Fecha: Agosto 2025
"""

import subprocess
import os
import time
import threading
import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

# Clases base para compatibilidad
class SecurityError(Exception):
    """Excepción personalizada para errores de seguridad."""
    pass

class TipoEscaneo(Enum):
    """Tipos de escaneo disponibles."""
    BASICO = "basico"
    COMPLETO = "completo"
    PUERTOS = "puertos"
    VULNERABILIDADES = "vulnerabilidades"
    RED = "red"

class NivelCriticidad(Enum):
    """Niveles de criticidad para vulnerabilidades."""
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"

@dataclass
class ResultadoEscaneoSistema:
    """Resultado de escaneo completo del sistema."""
    timestamp: datetime
    procesos_sospechosos: List[Dict[str, Any]]
    servicios_activos: List[Dict[str, Any]]
    archivos_modificados: List[str]
    permisos_incorrectos: List[str]
    alertas_seguridad: List[str]
    logs_criticos: List[str]
    uso_recursos: Dict[str, Any]
    integridad_sistema: Dict[str, Any]
    
    def __post_init__(self):
        if not self.procesos_sospechosos:
            self.procesos_sospechosos = []
        if not self.servicios_activos:
            self.servicios_activos = []
        if not self.archivos_modificados:
            self.archivos_modificados = []
        if not self.permisos_incorrectos:
            self.permisos_incorrectos = []
        if not self.alertas_seguridad:
            self.alertas_seguridad = []
        if not self.logs_criticos:
            self.logs_criticos = []
        if not self.uso_recursos:
            self.uso_recursos = {}
        if not self.integridad_sistema:
            self.integridad_sistema = {}

class EscaneadorSistema:
    """
    Escaneador especializado para análisis completo del sistema Kali Linux.
    Utiliza únicamente herramientas nativas del sistema y Python.
    """
    
    def __init__(self):
        self.logger = self._configurar_logger()
        self.herramientas_sistema = self._verificar_herramientas()
        self.rutas_criticas = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/sudoers',
            '/boot', '/usr/bin', '/usr/sbin', '/var/log'
        ]
        self.procesos_sospechosos_patterns = [
            'nc', 'netcat', 'python.*socket', 'perl.*socket', 
            'bash.*-i', 'sh.*-i', '/tmp/', '/dev/shm'
        ]
    
    def _configurar_logger(self) -> Any:
        """Configurar logger para el escaneador."""
        import logging
        logger = logging.getLogger('EscaneadorSistema')
        logger.setLevel(logging.INFO)
        return logger
    
    def _verificar_herramientas(self) -> Dict[str, bool]:
        """Verificar disponibilidad de herramientas del sistema."""
        herramientas = {
            'ps': 'ps',
            'netstat': 'netstat',
            'ss': 'ss',
            'lsof': 'lsof',
            'find': 'find',
            'grep': 'grep',
            'awk': 'awk',
            'systemctl': 'systemctl',
            'journalctl': 'journalctl',
            'stat': 'stat',
            'sha256sum': 'sha256sum',
            'chkrootkit': 'chkrootkit',
            'rkhunter': 'rkhunter'
        }
        
        disponibles = {}
        for nombre, comando in herramientas.items():
            try:
                result = subprocess.run(['which', comando], 
                                      capture_output=True, text=True, timeout=5)
                disponibles[nombre] = result.returncode == 0
                if disponibles[nombre]:
                    self.logger.info(f"Herramienta {nombre} disponible")
            except Exception:
                disponibles[nombre] = False
        
        return disponibles
    
    def _ejecutar_comando_seguro(self, comando: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Ejecutar comando del sistema de forma segura."""
        try:
            result = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            return {
                'exito': result.returncode == 0,
                'salida': result.stdout,
                'error': result.stderr,
                'codigo': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'salida': '',
                'error': f'Timeout después de {timeout}s',
                'codigo': -1
            }
        except Exception as e:
            return {
                'exito': False,
                'salida': '',
                'error': str(e),
                'codigo': -2
            }
    
    def escanear_procesos_sospechosos(self) -> List[Dict[str, Any]]:
        """Escanear procesos sospechosos del sistema."""
        self.logger.info("Iniciando escaneo de procesos sospechosos")
        procesos_sospechosos = []
        
        if not self.herramientas_sistema.get('ps'):
            return procesos_sospechosos
        
        # Obtener lista completa de procesos
        resultado = self._ejecutar_comando_seguro(['ps', 'aux'])
        
        if not resultado['exito']:
            self.logger.warning(f"Error ejecutando ps: {resultado['error']}")
            return procesos_sospechosos
        
        lineas_procesos = resultado['salida'].strip().split('\n')
        
        for linea in lineas_procesos[1:]:  # Saltar header
            if not linea.strip():
                continue
                
            partes = linea.split(None, 10)
            if len(partes) < 11:
                continue
            
            usuario = partes[0]
            pid = partes[1]
            cpu = partes[2]
            mem = partes[3]
            comando_completo = partes[10]
            
            # Verificar patrones sospechosos
            for patron in self.procesos_sospechosos_patterns:
                if patron in comando_completo.lower():
                    procesos_sospechosos.append({
                        'pid': pid,
                        'usuario': usuario,
                        'cpu': cpu,
                        'memoria': mem,
                        'comando': comando_completo,
                        'razon': f'Coincide con patrón sospechoso: {patron}',
                        'severidad': 'ALTA' if any(x in patron for x in ['/tmp/', 'socket']) else 'MEDIA'
                    })
                    break
        
        self.logger.info(f"Detectados {len(procesos_sospechosos)} procesos sospechosos")
        return procesos_sospechosos
    
    def escanear_servicios_activos(self) -> List[Dict[str, Any]]:
        """Escanear servicios y demonios activos."""
        self.logger.info("Iniciando escaneo de servicios activos")
        servicios = []
        
        # Usar systemctl si está disponible
        if self.herramientas_sistema.get('systemctl'):
            resultado = self._ejecutar_comando_seguro(['systemctl', 'list-units', '--type=service', '--state=active'])
            
            if resultado['exito']:
                lineas = resultado['salida'].strip().split('\n')
                for linea in lineas:
                    if '.service' in linea and 'active' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            servicios.append({
                                'nombre': partes[0],
                                'estado': partes[2],
                                'descripcion': ' '.join(partes[4:]) if len(partes) > 4 else 'N/A'
                            })
        
        # Complementar con netstat/ss para servicios de red
        if self.herramientas_sistema.get('ss'):
            resultado = self._ejecutar_comando_seguro(['ss', '-tuln'])
            
            if resultado['exito']:
                lineas = resultado['salida'].strip().split('\n')
                puertos_escucha = []
                
                for linea in lineas[1:]:  # Saltar header
                    if 'LISTEN' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            direccion_local = partes[3]
                            if ':' in direccion_local:
                                puerto = direccion_local.split(':')[-1]
                                puertos_escucha.append({
                                    'puerto': puerto,
                                    'protocolo': partes[0],
                                    'direccion': direccion_local
                                })
                
                # Agregar información de puertos
                for puerto_info in puertos_escucha:
                    servicios.append({
                        'nombre': f"Puerto {puerto_info['puerto']}",
                        'estado': 'listening',
                        'descripcion': f"Servicio en puerto {puerto_info['puerto']} ({puerto_info['protocolo']})"
                    })
        
        self.logger.info(f"Detectados {len(servicios)} servicios activos")
        return servicios
    
    def verificar_integridad_archivos(self) -> List[str]:
        """Verificar integridad de archivos críticos del sistema."""
        self.logger.info("Verificando integridad de archivos críticos")
        archivos_modificados = []
        
        if not self.herramientas_sistema.get('find'):
            return archivos_modificados
        
        # Buscar archivos modificados recientemente en rutas críticas
        for ruta in self.rutas_criticas:
            if not os.path.exists(ruta):
                continue
            
            # Buscar archivos modificados en las últimas 24 horas
            resultado = self._ejecutar_comando_seguro([
                'find', ruta, '-type', 'f', '-mtime', '-1', '-ls'
            ])
            
            if resultado['exito'] and resultado['salida'].strip():
                lineas = resultado['salida'].strip().split('\n')
                for linea in lineas:
                    if linea.strip():
                        partes = linea.split()
                        if len(partes) >= 11:
                            archivo = ' '.join(partes[10:])
                            archivos_modificados.append(archivo)
        
        self.logger.info(f"Detectados {len(archivos_modificados)} archivos modificados recientemente")
        return archivos_modificados
    
    def verificar_permisos_criticos(self) -> List[str]:
        """Verificar permisos de archivos y directorios críticos."""
        self.logger.info("Verificando permisos de archivos críticos")
        permisos_incorrectos = []
        
        # Archivos con permisos esperados
        archivos_permisos = {
            '/etc/passwd': '644',
            '/etc/shadow': '640',
            '/etc/hosts': '644',
            '/etc/sudoers': '440'
        }
        
        for archivo, permisos_esperados in archivos_permisos.items():
            if not os.path.exists(archivo):
                continue
            
            try:
                stat_info = os.stat(archivo)
                permisos_actuales = oct(stat_info.st_mode)[-3:]
                
                if permisos_actuales != permisos_esperados:
                    permisos_incorrectos.append(
                        f"{archivo}: {permisos_actuales} (esperado: {permisos_esperados})"
                    )
            except Exception as e:
                permisos_incorrectos.append(f"{archivo}: Error leyendo permisos - {str(e)}")
        
        # Buscar archivos con SUID/SGID sospechosos
        if self.herramientas_sistema.get('find'):
            resultado = self._ejecutar_comando_seguro([
                'find', '/', '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', 
                '-exec', 'ls', '-la', '{}', ';'
            ], timeout=60)
            
            if resultado['exito']:
                lineas = resultado['salida'].strip().split('\n')
                archivos_suid = []
                for linea in lineas:
                    if linea.strip() and ('rws' in linea or 'rgs' in linea):
                        archivos_suid.append(linea.strip())
                
                if len(archivos_suid) > 50:  # Muchos archivos SUID pueden ser sospechosos
                    permisos_incorrectos.append(f"Detectados {len(archivos_suid)} archivos con SUID/SGID")
        
        self.logger.info(f"Detectados {len(permisos_incorrectos)} problemas de permisos")
        return permisos_incorrectos
    
    def analizar_logs_seguridad(self) -> List[str]:
        """Analizar logs del sistema en busca de eventos críticos."""
        self.logger.info("Analizando logs de seguridad")
        logs_criticos = []
        
        archivos_log = [
            '/var/log/auth.log',
            '/var/log/syslog', 
            '/var/log/kern.log'
        ]
        
        patrones_criticos = [
            'Failed password',
            'authentication failure',
            'sudo.*COMMAND',
            'kernel.*killed',
            'segfault',
            'attack',
            'intrusion'
        ]
        
        for archivo_log in archivos_log:
            if not os.path.exists(archivo_log):
                continue
            
            for patron in patrones_criticos:
                resultado = self._ejecutar_comando_seguro([
                    'grep', '-i', patron, archivo_log
                ], timeout=30)
                
                if resultado['exito'] and resultado['salida'].strip():
                    lineas = resultado['salida'].strip().split('\n')
                    # Tomar solo las últimas 5 coincidencias para no saturar
                    for linea in lineas[-5:]:
                        if linea.strip():
                            logs_criticos.append(f"{os.path.basename(archivo_log)}: {linea.strip()}")
        
        self.logger.info(f"Detectados {len(logs_criticos)} eventos críticos en logs")
        return logs_criticos
    
    def obtener_uso_recursos(self) -> Dict[str, Any]:
        """Obtener información del uso de recursos del sistema."""
        self.logger.info("Obteniendo información de uso de recursos")
        uso_recursos = {}
        
        # CPU y memoria
        if self.herramientas_sistema.get('ps'):
            resultado = self._ejecutar_comando_seguro(['ps', 'aux', '--sort=-%cpu'])
            
            if resultado['exito']:
                lineas = resultado['salida'].strip().split('\n')
                procesos_cpu = []
                
                for linea in lineas[1:6]:  # Top 5 procesos
                    partes = linea.split(None, 10)
                    if len(partes) >= 11:
                        procesos_cpu.append({
                            'proceso': partes[10],
                            'cpu': partes[2],
                            'memoria': partes[3]
                        })
                
                uso_recursos['top_cpu'] = procesos_cpu
        
        # Información de memoria
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            mem_total = 0
            mem_free = 0
            mem_available = 0
            
            for linea in meminfo.split('\n'):
                if 'MemTotal:' in linea:
                    mem_total = int(linea.split()[1])
                elif 'MemFree:' in linea:
                    mem_free = int(linea.split()[1])
                elif 'MemAvailable:' in linea:
                    mem_available = int(linea.split()[1])
            
            if mem_total > 0:
                uso_recursos['memoria'] = {
                    'total_kb': mem_total,
                    'libre_kb': mem_free,
                    'disponible_kb': mem_available,
                    'uso_porcentaje': round(((mem_total - mem_available) / mem_total) * 100, 2)
                }
        except Exception as e:
            self.logger.warning(f"Error leyendo memoria: {e}")
        
        # Información de disco
        if self.herramientas_sistema.get('find'):
            # Verificar espacio en particiones críticas usando df
            resultado_df = self._ejecutar_comando_seguro(['df', '-h'])
            if resultado_df['exito']:
                lineas_df = resultado_df['salida'].strip().split('\n')
                for linea in lineas_df[1:]:  # Saltar header
                    partes = linea.split()
                    if len(partes) >= 6:
                        dispositivo = partes[0]
                        tamaño = partes[1]
                        usado = partes[2]
                        disponible = partes[3]
                        uso_porcentaje = partes[4].replace('%', '')
                        punto_montaje = partes[5]
                        
                        if punto_montaje in ['/', '/var', '/tmp']:
                            try:
                                uso_recursos[f'disco_{punto_montaje.replace("/", "root" if punto_montaje == "/" else punto_montaje[1:])}'] = {
                                    'dispositivo': dispositivo,
                                    'tamaño': tamaño,
                                    'usado': usado,
                                    'disponible': disponible,
                                    'uso_porcentaje': float(uso_porcentaje) if uso_porcentaje.isdigit() else 0
                                }
                            except ValueError:
                                pass
        
        self.logger.info(f"Información de recursos obtenida: {len(uso_recursos)} métricas")
        return uso_recursos
    
    def detectar_rootkits_basico(self) -> Dict[str, Any]:
        """Detección básica de rootkits usando herramientas disponibles."""
        self.logger.info("Iniciando detección básica de rootkits")
        detecciones = []
        
        # Usar chkrootkit si está disponible
        if self.herramientas_sistema.get('chkrootkit'):
            resultado = self._ejecutar_comando_seguro(['chkrootkit'], timeout=300)
            
            if resultado['exito']:
                lineas = resultado['salida'].strip().split('\n')
                for linea in lineas:
                    if any(palabra in linea.upper() for palabra in ['INFECTED', 'SUSPICIOUS', 'WARNING']):
                        detecciones.append(f"chkrootkit: {linea.strip()}")
        
        # Usar rkhunter si está disponible
        if self.herramientas_sistema.get('rkhunter'):
            resultado = self._ejecutar_comando_seguro(['rkhunter', '--check', '--skip-keypress'], timeout=300)
            
            if resultado['exito']:
                lineas = resultado['salida'].strip().split('\n')
                for linea in lineas:
                    if 'WARNING' in linea.upper():
                        detecciones.append(f"rkhunter: {linea.strip()}")
        
        # Verificaciones manuales básicas
        verificaciones_manuales = []
        
        # Verificar directorios sospechosos
        directorios_sospechosos = ['/tmp', '/dev/shm', '/var/tmp']
        for directorio in directorios_sospechosos:
            if os.path.exists(directorio):
                resultado = self._ejecutar_comando_seguro(['find', directorio, '-type', 'f', '-executable'])
                
                if resultado['exito'] and resultado['salida'].strip():
                    archivos = resultado['salida'].strip().split('\n')
                    if len(archivos) > 10:  # Muchos ejecutables en directorios temporales
                        verificaciones_manuales.append(
                            f"Detectados {len(archivos)} archivos ejecutables en {directorio}"
                        )
        
        self.logger.info(f"Detección de rootkits completada: {len(detecciones)} detecciones automáticas, {len(verificaciones_manuales)} verificaciones manuales")
        
        return {
            'detecciones_automaticas': detecciones,
            'verificaciones_manuales': verificaciones_manuales,
            'total': len(detecciones) + len(verificaciones_manuales)
        }
    
    def escanear_sistema_completo(self) -> ResultadoEscaneoSistema:
        """Realizar escaneo completo del sistema."""
        self.logger.info("=== INICIANDO ESCANEO COMPLETO DEL SISTEMA ===")
        inicio = datetime.now()
        
        # Ejecutar todos los componentes del escaneo
        self.logger.info("Fase 1: Escaneando procesos sospechosos")
        procesos_sospechosos = self.escanear_procesos_sospechosos()
        
        self.logger.info("Fase 2: Escaneando servicios activos")
        servicios_activos = self.escanear_servicios_activos()
        
        self.logger.info("Fase 3: Verificando integridad de archivos")
        archivos_modificados = self.verificar_integridad_archivos()
        
        self.logger.info("Fase 4: Verificando permisos críticos")
        permisos_incorrectos = self.verificar_permisos_criticos()
        
        self.logger.info("Fase 5: Analizando logs de seguridad")
        logs_criticos = self.analizar_logs_seguridad()
        
        self.logger.info("Fase 6: Obteniendo uso de recursos")
        uso_recursos = self.obtener_uso_recursos()
        
        self.logger.info("Fase 7: Detección básica de rootkits")
        integridad_sistema = self.detectar_rootkits_basico()
        
        # Generar alertas basadas en los resultados
        alertas_seguridad = []
        
        if len(procesos_sospechosos) > 0:
            alertas_seguridad.append(f"ALERTA: {len(procesos_sospechosos)} procesos sospechosos detectados")
        
        if len(archivos_modificados) > 10:
            alertas_seguridad.append(f"ALERTA: {len(archivos_modificados)} archivos críticos modificados recientemente")
        
        if len(permisos_incorrectos) > 0:
            alertas_seguridad.append(f"ALERTA: {len(permisos_incorrectos)} problemas de permisos detectados")
        
        if integridad_sistema['total'] > 0:
            alertas_seguridad.append(f"ALERTA: {integridad_sistema['total']} posibles indicadores de rootkit")
        
        memoria_uso = uso_recursos.get('memoria', {}).get('uso_porcentaje', 0)
        if memoria_uso > 90:
            alertas_seguridad.append(f"ALERTA: Uso elevado de memoria ({memoria_uso}%)")
        
        fin = datetime.now()
        duracion = (fin - inicio).total_seconds()
        
        self.logger.info(f"=== ESCANEO COMPLETO FINALIZADO en {duracion:.2f} segundos ===")
        
        return ResultadoEscaneoSistema(
            timestamp=inicio,
            procesos_sospechosos=procesos_sospechosos,
            servicios_activos=servicios_activos,
            archivos_modificados=archivos_modificados,
            permisos_incorrectos=permisos_incorrectos,
            alertas_seguridad=alertas_seguridad,
            logs_criticos=logs_criticos,
            uso_recursos=uso_recursos,
            integridad_sistema=integridad_sistema
        )
    
    def log(self, mensaje: str):
        """Método de logging compatible con la interfaz existente."""
        self.logger.info(mensaje)
