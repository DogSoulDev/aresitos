# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - FIM (File Integrity Monitoring) Kali 2025
Modelo optimizado que integra FIM + Controlador siguiendo principios ARESITOS
"""

import os
import sys
import sqlite3
import hashlib
import subprocess
import threading
import time
import json
import re
import shlex
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Callable
from pathlib import Path

class FIMKali2025:
    """
    Clase principal optimizada FIM (File Integrity Monitoring) para Kali Linux 2025
    Integra todas las funcionalidades de monitoreo de integridad de archivos
    """
    
    def __init__(self):
        self.version = "3.0"
        self.kali_version = "2025"
        self.nombre = "FIM Kali 2025"
        
        # Base de datos SQLite
        self.base_datos_sqlite = "data/fim_kali2025.db"
        
        # Estado del sistema
        self.monitores_activos = {}
        self.configuracion_fim = {}
        self.callbacks = {}
        self.herramientas_disponibles = set()
        self._estado_fim = {
            'monitoreo_activo': False,
            'rutas_monitoreadas': set(),
            'ultimo_escaneo': None,
            'cambios_detectados': 0,
            'archivos_monitoreados': 0
        }
        
        # Configuración de rutas críticas Kali Linux
        self._rutas_criticas_kali = {
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/etc/crontab',
            '/etc/hosts',
            '/var/log',
            '/usr/bin',
            '/usr/sbin',
            '/home'
        }
        
        # Inicialización
        self._verificar_herramientas_kali()
        self._inicializar_base_datos()
        
        self.log("[FIM KALI 2025] Sistema FIM inicializado correctamente")
    
    def log(self, mensaje: str):
        """Sistema de logging optimizado"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {mensaje}")
    
    def _verificar_herramientas_kali(self):
        """Verificar herramientas de seguridad disponibles en Kali Linux"""
        herramientas = [
            'inotifywait',      # Monitoreo tiempo real
            'chkrootkit',       # Detección rootkits
            'rkhunter',         # Scanner rootkits
            'linpeas.sh',       # Auditoría seguridad
            'yara',             # Análisis malware
            'clamscan',         # Antivirus
            'find',             # Búsqueda archivos
            'sha256sum',        # Checksums
            'stat'              # Info archivos
        ]
        
        for herramienta in herramientas:
            try:
                resultado = subprocess.run(['which', herramienta], 
                                         capture_output=True, text=True)
                if resultado.returncode == 0:
                    self.herramientas_disponibles.add(herramienta)
            except:
                pass
        
        self.log(f"✓ Herramientas disponibles: {len(self.herramientas_disponibles)}")
    
    def _inicializar_base_datos(self):
        """Inicializar base de datos SQLite FIM"""
        try:
            os.makedirs(os.path.dirname(self.base_datos_sqlite), exist_ok=True)
            
            conn = sqlite3.connect(self.base_datos_sqlite)
            cursor = conn.cursor()
            
            # Tabla archivos monitoreados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS archivos_monitoreados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ruta TEXT UNIQUE NOT NULL,
                    hash_sha256 TEXT,
                    tamaño INTEGER,
                    permisos TEXT,
                    propietario TEXT,
                    grupo TEXT,
                    modificado_timestamp TEXT,
                    ultimo_check TEXT
                )
            ''')
            
            # Tabla eventos cambios
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS eventos_cambios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo_id INTEGER,
                    tipo_evento TEXT,
                    timestamp TEXT,
                    detalles TEXT,
                    severidad TEXT,
                    FOREIGN KEY (archivo_id) REFERENCES archivos_monitoreados (id)
                )
            ''')
            
            # Tabla detecciones seguridad
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detecciones_seguridad (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    herramienta TEXT,
                    timestamp TEXT,
                    archivo_afectado TEXT,
                    tipo_amenaza TEXT,
                    descripcion TEXT,
                    severidad TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            self.log("✓ Base de datos FIM inicializada")
            
        except Exception as e:
            self.log(f"ERROR base de datos: {e}")
    
    def iniciar_monitoreo_tiempo_real(self, rutas: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Iniciar monitoreo tiempo real con inotify
        """
        if 'inotifywait' not in self.herramientas_disponibles:
            return {"error": "inotifywait no disponible"}
        
        if not rutas:
            rutas = list(self._rutas_criticas_kali)
        
        try:
            for ruta in rutas:
                if os.path.exists(ruta):
                    thread = threading.Thread(
                        target=self._monitorear_ruta_inotify,
                        args=(ruta,),
                        daemon=True
                    )
                    thread.start()
                    self.monitores_activos[ruta] = {
                        'thread': thread,
                        'activo': True,
                        'timestamp_inicio': datetime.now().isoformat()
                    }
                    self._estado_fim['rutas_monitoreadas'].add(ruta)
            
            self._estado_fim['monitoreo_activo'] = True
            self.log(f"✓ Monitoreo iniciado: {len(self.monitores_activos)} rutas")
            
            return {
                "exito": True,
                "rutas_monitoreadas": len(self.monitores_activos),
                "herramienta": "inotify-tools"
            }
            
        except Exception as e:
            self.log(f"ERROR monitoreo: {e}")
            return {"error": str(e)}
    
    def _monitorear_ruta_inotify(self, ruta: str):
        """Thread monitoreo inotify"""
        try:
            cmd = [
                'inotifywait',
                '-m', '-r',  # Monitor continuo recursivo
                '-e', 'modify,create,delete,move,attrib',
                '--format', '%w%f|%e|%T',
                '--timefmt', '%Y-%m-%d %H:%M:%S',
                ruta
            ]
            
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
            
            while self.monitores_activos.get(ruta, {}).get('activo', False):
                if process.stdout:
                    line = process.stdout.readline()
                    if line:
                        self._procesar_evento_inotify(line.strip())
                else:
                    break
                    
        except Exception as e:
            self.log(f"ERROR monitor {ruta}: {e}")
    
    def _procesar_evento_inotify(self, linea_evento: str):
        """Procesar evento inotify y guardar en BD"""
        try:
            partes = linea_evento.split('|')
            if len(partes) >= 3:
                archivo = partes[0]
                evento = partes[1]
                timestamp = partes[2]
                
                # Guardar en base de datos
                conn = sqlite3.connect(self.base_datos_sqlite)
                cursor = conn.cursor()
                
                # Buscar o crear archivo
                cursor.execute('SELECT id FROM archivos_monitoreados WHERE ruta = ?', (archivo,))
                archivo_id = cursor.fetchone()
                
                if not archivo_id:
                    info_archivo = self._obtener_info_archivo(archivo)
                    cursor.execute('''
                        INSERT INTO archivos_monitoreados 
                        (ruta, hash_sha256, tamaño, permisos, propietario, grupo, modificado_timestamp, ultimo_check)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        archivo,
                        info_archivo.get('sha256', ''),
                        info_archivo.get('tamaño', 0),
                        info_archivo.get('permisos', ''),
                        info_archivo.get('propietario', ''),
                        info_archivo.get('grupo', ''),
                        timestamp,
                        datetime.now().isoformat()
                    ))
                    archivo_id = cursor.lastrowid
                else:
                    archivo_id = archivo_id[0]
                
                # Insertar evento
                severidad = self._determinar_severidad_evento(evento, archivo)
                cursor.execute('''
                    INSERT INTO eventos_cambios (archivo_id, tipo_evento, timestamp, detalles, severidad)
                    VALUES (?, ?, ?, ?, ?)
                ''', (archivo_id, evento, timestamp, linea_evento, severidad))
                
                conn.commit()
                conn.close()
                
                self._estado_fim['cambios_detectados'] += 1
                self.log(f"EVENTO FIM: {evento} en {archivo}")
                
        except Exception as e:
            self.log(f"ERROR procesando evento: {e}")
    
    def _obtener_info_archivo(self, ruta: str) -> Dict[str, Any]:
        """Obtener información completa del archivo"""
        try:
            if not os.path.exists(ruta):
                return {}
            
            stat_info = os.stat(ruta)
            info = {
                'tamaño': stat_info.st_size,
                'permisos': oct(stat_info.st_mode)[-3:],
                'propietario': str(stat_info.st_uid),
                'grupo': str(stat_info.st_gid),
                'modificado': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            }
            
            # Calcular SHA256 para archivos pequeños
            if stat_info.st_size < 10*1024*1024:  # Menos de 10MB
                try:
                    with open(ruta, 'rb') as f:
                        info['sha256'] = hashlib.sha256(f.read()).hexdigest()
                except:
                    info['sha256'] = ''
            
            return info
            
        except Exception as e:
            self.log(f"ERROR info archivo {ruta}: {e}")
            return {}
    
    def _determinar_severidad_evento(self, evento: str, archivo: str) -> str:
        """Determinar severidad del evento"""
        if 'delete' in evento or 'moved_from' in evento:
            return 'ALTA'
        elif 'modify' in evento and any(critico in archivo for critico in ['/etc/', '/usr/bin/', '/usr/sbin/']):
            return 'ALTA'
        elif 'create' in evento:
            return 'MEDIA'
        else:
            return 'BAJA'
    
    def escaneo_rootkits_completo(self) -> Dict[str, Any]:
        """
        Escaneo completo de rootkits con múltiples herramientas
        """
        self.log("[SECURITY] Iniciando escaneo rootkits completo")
        
        resultados = {
            "timestamp": datetime.now().isoformat(),
            "herramientas_utilizadas": [],
            "detecciones_totales": 0,
            "detecciones": {}
        }
        
        # 1. Chkrootkit
        if 'chkrootkit' in self.herramientas_disponibles:
            try:
                cmd = ['chkrootkit', '-q']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                detecciones_chk = self._procesar_resultados_chkrootkit(result.stdout)
                resultados["detecciones"]["chkrootkit"] = detecciones_chk
                resultados["herramientas_utilizadas"].append("chkrootkit")
                resultados["detecciones_totales"] += len(detecciones_chk)
                
                # Guardar en BD
                self._guardar_detecciones_seguridad('chkrootkit', detecciones_chk)
                
                self.log(f"✓ Chkrootkit: {len(detecciones_chk)} detecciones")
            except Exception as e:
                self.log(f"ERROR chkrootkit: {e}")
        
        # 2. Rkhunter
        if 'rkhunter' in self.herramientas_disponibles:
            try:
                # Actualizar BD primero
                subprocess.run(['rkhunter', '--update'], capture_output=True, timeout=60)
                
                cmd = ['rkhunter', '--check', '--sk', '--rwo']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                detecciones_rkh = self._procesar_resultados_rkhunter(result.stdout)
                resultados["detecciones"]["rkhunter"] = detecciones_rkh
                resultados["herramientas_utilizadas"].append("rkhunter")
                resultados["detecciones_totales"] += len(detecciones_rkh)
                
                # Guardar en BD
                self._guardar_detecciones_seguridad('rkhunter', detecciones_rkh)
                
                self.log(f"✓ Rkhunter: {len(detecciones_rkh)} detecciones")
            except Exception as e:
                self.log(f"ERROR rkhunter: {e}")
        
        return resultados
    
    def auditoria_seguridad_linpeas(self) -> Dict[str, Any]:
        """
        Auditoría de seguridad con LinPEAS
        """
        self.log("[LINPEAS] Iniciando auditoría seguridad")
        
        if 'linpeas.sh' not in self.herramientas_disponibles:
            return {"error": "linpeas.sh no disponible"}
        
        try:
            cmd = ['linpeas.sh']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            
            problemas = self._procesar_resultados_linpeas(result.stdout)
            
            self.log(f"✓ LinPEAS: {len(problemas)} problemas detectados")
            return {
                "exito": True,
                "problemas_seguridad": problemas,
                "total_problemas": len(problemas),
                "herramienta": "linpeas"
            }
            
        except Exception as e:
            self.log(f"ERROR linpeas: {e}")
            return {"error": str(e)}
    
    def escaneo_malware_yara_clamav(self, directorio: str) -> Dict[str, Any]:
        """
        Escaneo de malware combinado YARA + ClamAV
        """
        self.log(f"[MALWARE] Escaneo malware: {directorio}")
        
        resultados = {
            "timestamp": datetime.now().isoformat(),
            "directorio_escaneado": directorio,
            "herramientas_utilizadas": [],
            "detecciones_totales": 0,
            "detecciones": {}
        }
        
        # 1. YARA
        if 'yara' in self.herramientas_disponibles:
            try:
                reglas_yara = self._obtener_reglas_yara()
                cmd = ['yara', '-r', '-w', reglas_yara, directorio]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                detecciones_yara = self._procesar_resultados_yara(result.stdout)
                resultados["detecciones"]["yara"] = detecciones_yara
                resultados["herramientas_utilizadas"].append("yara")
                resultados["detecciones_totales"] += len(detecciones_yara)
                
                self.log(f"✓ YARA: {len(detecciones_yara)} detecciones")
            except Exception as e:
                self.log(f"ERROR yara: {e}")
        
        # 2. ClamAV
        if 'clamscan' in self.herramientas_disponibles:
            try:
                cmd = ['clamscan', '-r', '--infected', '--no-summary', directorio]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                
                infectados = self._procesar_resultados_clamav(result.stdout)
                resultados["detecciones"]["clamav"] = infectados
                resultados["herramientas_utilizadas"].append("clamav")
                resultados["detecciones_totales"] += len(infectados)
                
                self.log(f"✓ ClamAV: {len(infectados)} infectados")
            except Exception as e:
                self.log(f"ERROR clamav: {e}")
        
        return resultados
    
    def analisis_completo_fim_kali2025(self, rutas_personalizadas: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Análisis completo FIM con todas las herramientas Kali 2025
        """
        self.log("[START] ANÁLISIS COMPLETO FIM KALI 2025")
        
        rutas = rutas_personalizadas or list(self._rutas_criticas_kali)
        
        resultados = {
            "timestamp": datetime.now().isoformat(),
            "version": self.version,
            "kali_version": self.kali_version,
            "rutas_analizadas": rutas,
            "herramientas_utilizadas": [],
            "resumen": {
                "cambios_detectados": 0,
                "rootkits_detectados": 0,
                "malware_detectado": 0,
                "problemas_seguridad": 0
            },
            "analisis": {}
        }
        
        # 1. Monitoreo tiempo real
        self.log("FASE 1: Monitoreo tiempo real")
        monitor_result = self.iniciar_monitoreo_tiempo_real(rutas)
        resultados["analisis"]["monitoreo"] = monitor_result
        if monitor_result.get("exito"):
            resultados["herramientas_utilizadas"].extend(["inotify-tools"])
        
        # 2. Escaneo rootkits
        self.log("FASE 2: Escaneo rootkits")
        rootkit_result = self.escaneo_rootkits_completo()
        resultados["analisis"]["rootkits"] = rootkit_result
        resultados["herramientas_utilizadas"].extend(rootkit_result.get("herramientas_utilizadas", []))
        resultados["resumen"]["rootkits_detectados"] = rootkit_result.get("detecciones_totales", 0)
        
        # 3. Auditoría seguridad
        self.log("FASE 3: Auditoría seguridad")
        linpeas_result = self.auditoria_seguridad_linpeas()
        resultados["analisis"]["seguridad"] = linpeas_result
        if linpeas_result.get("exito"):
            resultados["herramientas_utilizadas"].append("linpeas")
            resultados["resumen"]["problemas_seguridad"] = linpeas_result.get("total_problemas", 0)
        
        # 4. Escaneo malware en rutas críticas
        self.log("FASE 4: Escaneo malware")
        for ruta in [r for r in rutas if os.path.isdir(r)]:
            malware_result = self.escaneo_malware_yara_clamav(ruta)
            resultados["analisis"][f"malware_{os.path.basename(ruta)}"] = malware_result
            resultados["herramientas_utilizadas"].extend(malware_result.get("herramientas_utilizadas", []))
            resultados["resumen"]["malware_detectado"] += malware_result.get("detecciones_totales", 0)
        
        # Estado final
        resultados["resumen"]["cambios_detectados"] = self._estado_fim['cambios_detectados']
        self._estado_fim['ultimo_escaneo'] = datetime.now().isoformat()
        
        self.log(f"[COMPLETED] Análisis completo terminado - {len(set(resultados['herramientas_utilizadas']))} herramientas")
        return resultados
    
    def obtener_estado_fim(self) -> Dict[str, Any]:
        """Obtener estado actual del FIM"""
        return {
            "estado": self._estado_fim.copy(),
            "monitores_activos": len(self.monitores_activos),
            "herramientas_disponibles": list(self.herramientas_disponibles),
            "base_datos": self.base_datos_sqlite,
            "version": f"{self.version} Kali {self.kali_version}"
        }
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        """Obtener estadísticas del FIM para compatibilidad"""
        estado = self.obtener_estado_fim()
        return {
            "version": estado["version"],
            "monitores_activos": estado["monitores_activos"],
            "herramientas_disponibles": len(estado["herramientas_disponibles"]),
            "cambios_detectados": self._estado_fim.get('cambios_detectados', 0),
            "archivos_monitoreados": self._estado_fim.get('archivos_monitoreados', 0),
            "ultimo_escaneo": self._estado_fim.get('ultimo_escaneo'),
            "base_datos_activa": os.path.exists(self.base_datos_sqlite)
        }
    
    def detener_monitoreo(self):
        """Detener todos los monitores activos"""
        for ruta in list(self.monitores_activos.keys()):
            self.monitores_activos[ruta]['activo'] = False
        
        self.monitores_activos.clear()
        self._estado_fim['monitoreo_activo'] = False
        self._estado_fim['rutas_monitoreadas'].clear()
        
        self.log("✓ Monitoreo FIM detenido")
    
    # Métodos auxiliares de procesamiento
    def _procesar_resultados_chkrootkit(self, salida: str) -> List[Dict[str, Any]]:
        """Procesar resultados de chkrootkit"""
        detecciones = []
        for linea in salida.split('\n'):
            if 'INFECTED' in linea or 'Suspicious' in linea:
                detecciones.append({
                    'archivo': linea.split(':')[0] if ':' in linea else linea,
                    'tipo': 'rootkit',
                    'descripcion': linea,
                    'severidad': 'ALTA'
                })
        return detecciones
    
    def _procesar_resultados_rkhunter(self, salida: str) -> List[Dict[str, Any]]:
        """Procesar resultados de rkhunter"""
        detecciones = []
        for linea in salida.split('\n'):
            if 'Warning' in linea or 'INFECTED' in linea:
                detecciones.append({
                    'archivo': linea.split(':')[0] if ':' in linea else linea,
                    'tipo': 'rootkit',
                    'descripcion': linea,
                    'severidad': 'ALTA' if 'INFECTED' in linea else 'MEDIA'
                })
        return detecciones
    
    def _procesar_resultados_linpeas(self, salida: str) -> List[Dict[str, Any]]:
        """Procesar resultados de LinPEAS"""
        problemas = []
        for linea in salida.split('\n'):
            if any(keyword in linea.lower() for keyword in ['vulnerable', 'exploit', 'backdoor', 'suspicious']):
                problemas.append({
                    'descripcion': linea.strip(),
                    'tipo': 'vulnerabilidad',
                    'severidad': 'MEDIA'
                })
        return problemas
    
    def _procesar_resultados_yara(self, salida: str) -> List[Dict[str, Any]]:
        """Procesar resultados de YARA"""
        detecciones = []
        for linea in salida.split('\n'):
            if linea.strip():
                partes = linea.split()
                if len(partes) >= 2:
                    detecciones.append({
                        'regla': partes[0],
                        'archivo': partes[1],
                        'tipo': 'malware',
                        'severidad': 'ALTA'
                    })
        return detecciones
    
    def _procesar_resultados_clamav(self, salida: str) -> List[Dict[str, Any]]:
        """Procesar resultados de ClamAV"""
        infectados = []
        for linea in salida.split('\n'):
            if 'FOUND' in linea:
                partes = linea.split(':')
                if len(partes) >= 2:
                    infectados.append({
                        'archivo': partes[0],
                        'virus': partes[1].replace('FOUND', '').strip(),
                        'tipo': 'virus',
                        'severidad': 'ALTA'
                    })
        return infectados
    
    def _obtener_reglas_yara(self) -> str:
        """Obtener reglas YARA disponibles"""
        rutas_posibles = [
            '/usr/share/yara/rules',
            '/etc/yara/rules',
            '/opt/yara/rules'
        ]
        
        for ruta in rutas_posibles:
            if os.path.exists(ruta):
                return ruta
        
        # Crear reglas básicas si no existen
        return self._crear_reglas_yara_basicas()
    
    def _crear_reglas_yara_basicas(self) -> str:
        """Crear reglas YARA básicas"""
        reglas_basicas = '''
rule Suspicious_ELF {
    meta:
        description = "Detecta ejecutables ELF sospechosos"
    strings:
        $elf = { 7F 45 4C 46 }
        $suspicious = "backdoor"
    condition:
        $elf at 0 and $suspicious
}

rule Suspicious_Script {
    meta:
        description = "Detecta scripts sospechosos"
    strings:
        $shell1 = "#!/bin/bash"
        $shell2 = "#!/bin/sh"
        $suspicious = "rm -rf /"
    condition:
        ($shell1 or $shell2) and $suspicious
}
        '''
        
        ruta_reglas = "/tmp/aresitos_yara_rules.yar"
        try:
            with open(ruta_reglas, 'w') as f:
                f.write(reglas_basicas)
            return ruta_reglas
        except:
            return ""
    
    def _guardar_detecciones_seguridad(self, herramienta: str, detecciones: List[Dict[str, Any]]):
        """Guardar detecciones en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_sqlite)
            cursor = conn.cursor()
            
            for det in detecciones:
                cursor.execute('''
                    INSERT INTO detecciones_seguridad 
                    (herramienta, timestamp, archivo_afectado, tipo_amenaza, descripcion, severidad)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    herramienta,
                    datetime.now().isoformat(),
                    det.get('archivo', ''),
                    det.get('tipo', ''),
                    det.get('descripcion', ''),
                    det.get('severidad', 'MEDIA')
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"ERROR guardando detecciones: {e}")
    
    # ========= MÉTODOS DE COMPATIBILIDAD CON CONTROLADOR FIM =========
    
    @property
    def base_datos(self):
        """Propiedad de compatibilidad - simula base de datos en memoria"""
        return getattr(self, '_base_datos_memoria', {})
    
    @base_datos.setter
    def base_datos(self, valor):
        """Setter para base_datos de compatibilidad"""
        self._base_datos_memoria = valor
    
    def agregar_ruta_monitoreo(self, ruta: str) -> Dict[str, Any]:
        """Agregar ruta al monitoreo FIM"""
        try:
            if not os.path.exists(ruta):
                return {
                    'exito': False,
                    'error': f'Ruta no existe: {ruta}',
                    'ruta': ruta
                }
            
            self._estado_fim['rutas_monitoreadas'].add(ruta)
            
            # Agregar a base_datos simulada para compatibilidad
            if not hasattr(self, '_base_datos_memoria'):
                self._base_datos_memoria = {}
            
            self._base_datos_memoria[ruta] = {
                'agregado': datetime.now().isoformat(),
                'hash': self._calcular_hash_archivo(ruta) if os.path.isfile(ruta) else None,
                'tipo': 'archivo' if os.path.isfile(ruta) else 'directorio'
            }
            
            self.log(f"✓ Ruta agregada al monitoreo: {ruta}")
            
            return {
                'exito': True,
                'mensaje': f'Ruta agregada: {ruta}',
                'ruta': ruta
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': str(e),
                'ruta': ruta
            }
    
    def remover_ruta_monitoreo(self, ruta: str) -> Dict[str, Any]:
        """Remover ruta del monitoreo FIM"""
        try:
            self._estado_fim['rutas_monitoreadas'].discard(ruta)
            
            if hasattr(self, '_base_datos_memoria') and ruta in self._base_datos_memoria:
                del self._base_datos_memoria[ruta]
            
            self.log(f"✓ Ruta removida del monitoreo: {ruta}")
            
            return {
                'exito': True,
                'mensaje': f'Ruta removida: {ruta}',
                'ruta': ruta
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': str(e),
                'ruta': ruta
            }
    
    def crear_baseline(self, rutas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Crear baseline de archivos para monitoreo FIM"""
        try:
            if rutas is None:
                rutas = list(self._rutas_criticas_kali)
            
            baseline_creado = {}
            archivos_procesados = 0
            
            for ruta in rutas:
                if os.path.exists(ruta):
                    if os.path.isfile(ruta):
                        # Archivo individual
                        hash_archivo = self._calcular_hash_archivo(ruta)
                        baseline_creado[ruta] = {
                            'hash': hash_archivo,
                            'timestamp': datetime.now().isoformat(),
                            'tamaño': os.path.getsize(ruta),
                            'permisos': oct(os.stat(ruta).st_mode)[-3:]
                        }
                        archivos_procesados += 1
                    else:
                        # Directorio - procesar archivos dentro
                        for root, dirs, files in os.walk(ruta):
                            for archivo in files[:20]:  # Limitar para no sobrecargar
                                ruta_archivo = os.path.join(root, archivo)
                                try:
                                    hash_archivo = self._calcular_hash_archivo(ruta_archivo)
                                    baseline_creado[ruta_archivo] = {
                                        'hash': hash_archivo,
                                        'timestamp': datetime.now().isoformat(),
                                        'tamaño': os.path.getsize(ruta_archivo),
                                        'permisos': oct(os.stat(ruta_archivo).st_mode)[-3:]
                                    }
                                    archivos_procesados += 1
                                except Exception:
                                    continue  # Saltar archivos que no se pueden leer
            
            # Actualizar base_datos de compatibilidad
            if not hasattr(self, '_base_datos_memoria'):
                self._base_datos_memoria = {}
            self._base_datos_memoria.update(baseline_creado)
            
            self._estado_fim['archivos_monitoreados'] = len(baseline_creado)
            self._estado_fim['ultimo_escaneo'] = datetime.now().isoformat()
            
            self.log(f"✓ Baseline creado: {archivos_procesados} archivos procesados")
            
            return {
                'exito': True,
                'archivos_procesados': archivos_procesados,
                'baseline': baseline_creado,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': str(e),
                'archivos_procesados': 0
            }
    
    def verificar_integridad(self) -> List[Dict[str, Any]]:
        """Verificar integridad de archivos monitoreados"""
        alertas = []
        
        try:
            if not hasattr(self, '_base_datos_memoria') or not self._base_datos_memoria:
                return []
            
            for archivo_path, baseline_info in self._base_datos_memoria.items():
                if os.path.exists(archivo_path) and os.path.isfile(archivo_path):
                    try:
                        hash_actual = self._calcular_hash_archivo(archivo_path)
                        hash_baseline = baseline_info.get('hash')
                        
                        if hash_actual != hash_baseline:
                            alertas.append({
                                'archivo': archivo_path,
                                'tipo': 'modificacion',
                                'hash_anterior': hash_baseline,
                                'hash_actual': hash_actual,
                                'timestamp': datetime.now().isoformat(),
                                'severidad': 'ALTA' if '/etc/' in archivo_path else 'MEDIA'
                            })
                    except Exception:
                        continue
                elif archivo_path in self._base_datos_memoria:
                    # Archivo fue eliminado
                    alertas.append({
                        'archivo': archivo_path,
                        'tipo': 'eliminacion',
                        'timestamp': datetime.now().isoformat(),
                        'severidad': 'CRITICA'
                    })
            
            self._estado_fim['cambios_detectados'] = len(alertas)
            
        except Exception as e:
            self.log(f"Error verificando integridad: {e}")
        
        return alertas
    
    def obtener_alertas_recientes(self, limite: int = 50) -> List[Dict[str, Any]]:
        """Obtener alertas recientes del FIM"""
        try:
            # Obtener alertas de integridad
            alertas = self.verificar_integridad()
            
            # Limitar resultados
            return alertas[:limite]
            
        except Exception as e:
            self.log(f"Error obteniendo alertas: {e}")
            return []
    
    @property
    def gestor_permisos(self):
        """Propiedad de compatibilidad para gestor de permisos"""
        return getattr(self, '_gestor_permisos', None)
    
    def _calcular_hash_archivo(self, ruta: str) -> str:
        """Calcular hash SHA256 de un archivo"""
        try:
            with open(ruta, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def agregar_callback(self, evento: str, callback: Callable):
        """Agregar callback para eventos específicos"""
        if evento not in self.callbacks:
            self.callbacks[evento] = []
        self.callbacks[evento].append(callback)
    
    def _ejecutar_callbacks(self, evento: str, datos: Dict[str, Any]):
        """Ejecutar callbacks registrados"""
        if evento in self.callbacks:
            for callback in self.callbacks[evento]:
                try:
                    callback(datos)
                except Exception as e:
                    self.log(f"Error ejecutando callback: {e}")
    
    def crear_reporte_completo(self) -> Dict[str, Any]:
        """Crear reporte completo del estado FIM"""
        return {
            'timestamp': datetime.now().isoformat(),
            'estado': self._estado_fim,
            'herramientas_disponibles': list(self.herramientas_disponibles),
            'estadisticas': self.obtener_estadisticas(),
            'configuracion': self.configuracion_fim,
            'monitores_activos': len(self.monitores_activos),
            'version': self.version
        }
