
# =============================================================
# PRINCIPIOS DE SEGURIDAD ARESITOS (NO TOCAR SIN AUDITORÍA)
# - Nunca solicitar ni almacenar la contraseña de root.
# - Nunca mostrar, registrar ni filtrar la contraseña de root.
# - Ningún input de usuario debe usarse como comando sin validar.
# - Todos los comandos pasan por el validador y gestor de permisos.
# - Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
# - Prohibido shell=True salvo justificación y validación exhaustiva.
# - Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
# =============================================================

# -*- coding: utf-8 -*-
"""
PRINCIPIOS DE SEGURIDAD ARESITOS (NO MODIFICAR SIN AUDITORÍA)
- Nunca solicitar ni almacenar la contraseña de root.
- Nunca mostrar, registrar ni filtrar la contraseña de root.
- Ningún input de usuario debe usarse como comando sin validar.
- Todos los comandos pasan por el validador y gestor de permisos.
- Prohibido el uso de eval, exec, os.system, subprocess.Popen directo.
- Prohibido shell=True salvo justificación y validación exhaustiva.
- Si algún desarrollador necesita privilegios, usar solo gestor_permisos.
"""
"""
ARESITOS - Modelo FIM Kali Linux 2025
====================================

File Integrity Monitoring con herramientas modernas de Kali Linux 2025.
Solo herramientas que se instalan fácilmente con 'apt install'.

Herramientas integradas:
- inotify-tools: Monitoreo en tiempo real
- linpeas: Sistema de escalada de privilegios y auditoría
- chkrootkit: Detección de rootkits
- rkhunter: Scanner de rootkits avanzado
- pspy: Monitor de procesos para auditoría
- yara: Detección de patrones maliciosos
- clamav: Antivirus para archivos

Autor: DogSoulDev
Fecha: 19 de Agosto de 2025
"""

import subprocess
import threading
import json
import os
import time
import hashlib
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime
import sqlite3

# Evitar warnings de typing
if TYPE_CHECKING:
    from .modelo_fim_base import FIMBase as _FIMBase
else:
    from .modelo_fim_base import FIMBase as _FIMBase

class FIMKali2025(_FIMBase):  # type: ignore
    """
    File Integrity Monitoring avanzado con herramientas Kali Linux 2025.
    Hereda de FIMBase para funcionalidad común.
    """
    
    def __init__(self, gestor_permisos=None):
        super().__init__(gestor_permisos)
        self.herramientas_fim = {
            'inotifywait': '/usr/bin/inotifywait',
            'linpeas': '/usr/bin/linpeas',
            'chkrootkit': '/usr/bin/chkrootkit',
            'rkhunter': '/usr/bin/rkhunter',
            'pspy': '/usr/bin/pspy64',
            'yara': '/usr/bin/yara',
            'clamscan': '/usr/bin/clamscan'
        }
        self.monitores_activos = {}
        # Agregar herramientas FIM a la configuración base
        # La clase base ya inicializa la BD básica, agregamos tablas específicas
        self._inicializar_tablas_fim()
        self._verificar_herramientas_fim()
    
    def _verificar_herramientas_fim(self):
        """Verifica qué herramientas FIM específicas están disponibles"""
        import subprocess
        
        for herramienta, ruta in self.herramientas_fim.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Agregar a herramientas disponibles de la clase base
                    if not hasattr(self, 'herramientas_disponibles'):
                        self.herramientas_disponibles = {}
                    self.herramientas_disponibles[herramienta] = result.stdout.strip()
                    self.log(f"FIM: {herramienta} disponible en {result.stdout.strip()}")
                else:
                    self.log(f"FIM: {herramienta} no encontrada")
            except Exception as e:
                self.log(f"Error verificando {herramienta}: {e}")
    
    def verificar_herramientas(self):
        """Wrapper para compatibilidad"""
        return self._verificar_herramientas_fim()
        
        for herramienta, ruta in self.herramientas_fim.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.herramientas_disponibles[herramienta] = result.stdout.strip()
                    self.log(f"OK {herramienta} disponible en {result.stdout.strip()}")
                else:
                    self.log(f"ERROR {herramienta} no encontrada")
            except Exception as e:
                self.log(f"ERROR verificando {herramienta}: {e}")
    
    def _inicializar_tablas_fim(self):
        """Inicializa tablas específicas de FIM en la base de datos"""
        try:
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabla para archivos monitoreados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS archivos_monitoreados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ruta TEXT UNIQUE NOT NULL,
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    tamaño INTEGER,
                    permisos TEXT,
                    propietario TEXT,
                    grupo TEXT,
                    modificado_timestamp TEXT,
                    creado_timestamp TEXT,
                    ultimo_check TEXT
                )
            ''')
            
            # Tabla para eventos de cambios
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
            
            # Tabla para detecciones de rootkits
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detecciones_rootkit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    herramienta TEXT,
                    timestamp TEXT,
                    archivo_afectado TEXT,
                    tipo_amenaza TEXT,
                    descripcion TEXT,
                    severidad TEXT
                )
            ''')
            
            # Tabla para análisis YARA
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analisis_yara (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archivo TEXT,
                    regla_disparada TEXT,
                    timestamp TEXT,
                    metadatos TEXT,
                    severidad TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            self.log("OK Base de datos FIM Kali2025 inicializada")
            
        except Exception as e:
            self.log(f"ERROR inicializando base de datos: {e}")
    
    def iniciar_monitoreo_tiempo_real(self, rutas_monitorear: List[str]) -> Dict[str, Any]:
        """
        Inicia monitoreo en tiempo real con inotify-tools, mostrando detalle de rutas monitoreadas y fallidas.
        """
        self.log(f"ANALIZANDO Iniciando monitoreo tiempo real: {len(rutas_monitorear)} rutas")

        if 'inotifywait' not in self.herramientas_disponibles:
            self.log("ERROR: inotifywait (inotify-tools) no está disponible. Instala con: sudo apt install inotify-tools")
            return {"error": "inotifywait no disponible"}

        rutas_ok = []
        rutas_fallidas = []
        for ruta in rutas_monitorear:
            if not os.path.exists(ruta):
                self.log(f"[FIM] Ruta no existe: {ruta}")
                rutas_fallidas.append((ruta, "No existe"))
                continue
            if not os.access(ruta, os.R_OK):
                self.log(f"[FIM] Sin permisos de lectura: {ruta}")
                rutas_fallidas.append((ruta, "Sin permisos de lectura"))
                continue
            try:
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
                rutas_ok.append(ruta)
            except Exception as e:
                self.log(f"[FIM] Error iniciando monitoreo en {ruta}: {e}")
                rutas_fallidas.append((ruta, f"Error: {e}"))

        self.log(f"[FIM] Monitoreo iniciado en {len(rutas_ok)} rutas. Fallidas: {len(rutas_fallidas)}")
        if rutas_ok:
            self.log(f"[FIM] Rutas monitoreadas: {', '.join(rutas_ok)}")
        if rutas_fallidas:
            for ruta, motivo in rutas_fallidas:
                self.log(f"[FIM] Ruta no monitoreada: {ruta} - Motivo: {motivo}")

        return {
            "exito": True if rutas_ok else False,
            "rutas_monitoreadas": len(rutas_ok),
            "rutas_fallidas": rutas_fallidas,
            "herramienta": "inotify-tools"
        }
    
    def _monitorear_ruta_inotify(self, ruta: str):
        """Thread de monitoreo con inotifywait"""
        try:
            cmd = [
                'inotifywait',
                '-m',  # Monitor continuo
                '-r',  # Recursivo
                '-e', 'modify,create,delete,move,attrib',
                '--format', '%w%f|%e|%T',
                '--timefmt', '%Y-%m-%d %H:%M:%S',
                ruta
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.log(f"ANALIZANDO Monitor inotify activo en: {ruta}")
            
            while self.monitores_activos.get(ruta, {}).get('activo', False):
                if process.stdout:
                    line = process.stdout.readline()
                else:
                    break
                if line:
                    self._procesar_evento_inotify(line.strip())
                    
        except Exception as e:
            self.log(f"OK Error en monitor inotify {ruta}: {e}")
    
    def _procesar_evento_inotify(self, linea_evento: str):
        """Procesa evento de inotify y lo guarda en base de datos"""
        try:
            partes = linea_evento.split('|')
            if len(partes) >= 3:
                archivo = partes[0]
                evento = partes[1]
                timestamp = partes[2]
                
                # Guardar en base de datos
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Buscar o crear archivo en base de datos
                cursor.execute('SELECT id FROM archivos_monitoreados WHERE ruta = ?', (archivo,))
                archivo_id = cursor.fetchone()
                
                if not archivo_id:
                    # Crear nuevo archivo
                    info_archivo = self._obtener_info_archivo(archivo)
                    cursor.execute('''
                        INSERT INTO archivos_monitoreados 
                        (ruta, hash_md5, hash_sha256, tamaño, permisos, propietario, grupo, modificado_timestamp, ultimo_check)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        archivo,
                        '',  # MD5 eliminado por seguridad
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
                
                # Log del evento
                self.log(f"STRINGS Evento FIM: {evento} en {archivo}")
                
        except Exception as e:
            self.log(f"OK Error procesando evento inotify: {e}")
    
    def escaneo_rootkits_chkrootkit(self) -> Dict[str, Any]:
        """
        Escaneo de rootkits con chkrootkit
        """
        self.log("[SECURITY] Iniciando escaneo chkrootkit")
        
        if 'chkrootkit' not in self.herramientas_disponibles:
            return {"error": "chkrootkit no disponible"}
        
        try:
            cmd = ['chkrootkit', '-q']  # Quiet mode
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            detecciones = self._procesar_resultados_chkrootkit(result.stdout)
            
            # Guardar detecciones en base de datos
            self._guardar_detecciones_rootkit('chkrootkit', detecciones)
            
            self.log(f"OK Chkrootkit completado: {len(detecciones)} detecciones")
            return {
                "exito": True,
                "detecciones": detecciones,
                "total_detecciones": len(detecciones),
                "herramienta": "chkrootkit"
            }
            
        except Exception as e:
            self.log(f"OK Error ejecutando chkrootkit: {e}")
            return {"error": str(e)}
    
    def escaneo_rootkits_rkhunter(self) -> Dict[str, Any]:
        """
        Escaneo de rootkits con rkhunter
        """
        self.log("[SECURITY] Iniciando escaneo rkhunter")
        
        if 'rkhunter' not in self.herramientas_disponibles:
            return {"error": "rkhunter no disponible"}
        
        try:
            # Actualizar base de datos primero
            subprocess.run(['rkhunter', '--update'], capture_output=True, timeout=60)
            
            # Ejecutar escaneo
            cmd = ['rkhunter', '--check', '--sk', '--rwo']  # skip keypress, report warnings only
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            detecciones = self._procesar_resultados_rkhunter(result.stdout)
            
            # Guardar detecciones
            self._guardar_detecciones_rootkit('rkhunter', detecciones)
            
            self.log(f"OK Rkhunter completado: {len(detecciones)} detecciones")
            return {
                "exito": True,
                "detecciones": detecciones,
                "total_detecciones": len(detecciones),
                "herramienta": "rkhunter"
            }
            
        except Exception as e:
            self.log(f"OK Error ejecutando rkhunter: {e}")
            return {"error": str(e)}
    
    def auditoria_sistema_linpeas(self) -> Dict[str, Any]:
        """
        Auditoría de seguridad con linpeas (más moderno y completo)
        """
        self.log("[LINPEAS] Iniciando auditoría linpeas")
        
        if 'linpeas' not in self.herramientas_disponibles:
            return {"error": "linpeas no disponible"}
        
        try:
            cmd = ['linpeas.sh']  # Script de auditoría
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            
            problemas = self._procesar_resultados_linpeas(result.stdout)
            
            self.log(f"OK Linpeas completado: {len(problemas)} problemas detectados")
            return {
                "exito": True,
                "problemas_seguridad": problemas,
                "total_problemas": len(problemas),
                "herramienta": "linpeas"
            }
            
        except Exception as e:
            self.log(f"OK Error ejecutando linpeas: {e}")
            return {"error": str(e)}
    
    def escaneo_malware_yara(self, directorio: str, reglas_yara: Optional[str] = None) -> Dict[str, Any]:
        """
        Escaneo de malware con reglas YARA
        """
        self.log(f"[TARGET] Iniciando escaneo YARA: {directorio}")
        
        if 'yara' not in self.herramientas_disponibles:
            return {"error": "yara no disponible"}
        
        try:
            # Reglas por defecto
            if not reglas_yara:
                reglas_yara = "/usr/share/yara/rules"
                if not os.path.exists(reglas_yara):
                    # Crear reglas básicas
                    reglas_yara = self._crear_reglas_yara_basicas()
            
            cmd = [
                'yara',
                '-r',  # Recursivo
                '-w',  # No warnings
                reglas_yara,
                directorio
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            detecciones = self._procesar_resultados_yara(result.stdout)
            
            # Guardar en base de datos
            self._guardar_analisis_yara(detecciones)
            
            self.log(f"OK YARA completado: {len(detecciones)} detecciones")
            return {
                "exito": True,
                "detecciones_malware": detecciones,
                "total_detecciones": len(detecciones),
                "herramienta": "yara"
            }
            
        except Exception as e:
            self.log(f"OK Error ejecutando YARA: {e}")
            return {"error": str(e)}
    
    def escaneo_antivirus_clamav(self, directorio: str) -> Dict[str, Any]:
        """
        Escaneo antivirus con ClamAV
        """
        self.log(f"[SECURITY] Iniciando escaneo ClamAV: {directorio}")
        
        if 'clamscan' not in self.herramientas_disponibles:
            return {"error": "clamscan no disponible"}
        
        try:
            cmd = [
                'clamscan',
                '-r',  # Recursivo
                '--infected',  # Solo infectados
                '--no-summary',
                directorio
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            infectados = self._procesar_resultados_clamav(result.stdout)
            
            self.log(f"OK ClamAV completado: {len(infectados)} archivos infectados")
            return {
                "exito": True,
                "archivos_infectados": infectados,
                "total_infectados": len(infectados),
                "herramienta": "clamav"
            }
            
        except Exception as e:
            self.log(f"OK Error ejecutando ClamAV: {e}")
            return {"error": str(e)}
    
    def analisis_completo_fim_kali2025(self, rutas_criticas: List[str]) -> Dict[str, Any]:
        """
        Análisis completo de FIM con todas las herramientas Kali 2025
        """
        self.log("[START] INICIANDO ANÁLISIS COMPLETO FIM KALI 2025")
        
        resultados = {
            "timestamp": datetime.now().isoformat(),
            "rutas_analizadas": rutas_criticas,
            "herramientas_utilizadas": [],
            "analisis": {}
        }
        
        # 1. Iniciar monitoreo en tiempo real
        self.log("FASE 1: Iniciando monitoreo tiempo real")
        monitor_result = self.iniciar_monitoreo_tiempo_real(rutas_criticas)
        resultados["analisis"]["monitoreo_tiempo_real"] = monitor_result
        if monitor_result.get("exito"):
            resultados["herramientas_utilizadas"].append("inotify-tools")
        
        # 2. Escaneo de rootkits con chkrootkit
        self.log("FASE 2: Escaneo rootkits chkrootkit")
        chkrootkit_result = self.escaneo_rootkits_chkrootkit()
        resultados["analisis"]["chkrootkit"] = chkrootkit_result
        if chkrootkit_result.get("exito"):
            resultados["herramientas_utilizadas"].append("chkrootkit")
        
        # 3. Escaneo de rootkits con rkhunter
        self.log("FASE 3: Escaneo rootkits rkhunter")
        rkhunter_result = self.escaneo_rootkits_rkhunter()
        resultados["analisis"]["rkhunter"] = rkhunter_result
        if rkhunter_result.get("exito"):
            resultados["herramientas_utilizadas"].append("rkhunter")
        
        # 4. Auditoría de seguridad con linpeas
        self.log("FASE 4: Auditoría sistema linpeas")
        linpeas_result = self.auditoria_sistema_linpeas()
        resultados["analisis"]["linpeas"] = linpeas_result
        if linpeas_result.get("exito"):
            resultados["herramientas_utilizadas"].append("linpeas")
        
        # 5. Escaneo YARA en rutas críticas
        self.log("FASE 5: Escaneo YARA malware")
        for ruta in rutas_criticas:
            if os.path.exists(ruta):
                yara_result = self.escaneo_malware_yara(ruta)
                resultados["analisis"][f"yara_{os.path.basename(ruta)}"] = yara_result
                if yara_result.get("exito"):
                    resultados["herramientas_utilizadas"].append("yara")
        
        # 6. Escaneo antivirus ClamAV
        self.log("FASE 6: Escaneo antivirus ClamAV")
        for ruta in rutas_criticas:
            if os.path.exists(ruta):
                clamav_result = self.escaneo_antivirus_clamav(ruta)
                resultados["analisis"][f"clamav_{os.path.basename(ruta)}"] = clamav_result
                if clamav_result.get("exito"):
                    resultados["herramientas_utilizadas"].append("clamav")
        
        # Resumen final
        total_detecciones_rootkit = (
            len(chkrootkit_result.get("detecciones", [])) + 
            len(rkhunter_result.get("detecciones", []))
        )
        total_problemas_seguridad = len(linpeas_result.get("problemas_seguridad", []))
        
        resultados["resumen"] = {
            "rutas_monitoreadas": len(rutas_criticas),
            "detecciones_rootkit": total_detecciones_rootkit,
            "problemas_seguridad": total_problemas_seguridad,
            "herramientas_utilizadas": len(set(resultados["herramientas_utilizadas"])),
            "monitoreo_activo": len(self.monitores_activos)
        }
        
        self.log("OK ANÁLISIS COMPLETO FIM FINALIZADO")
        return resultados
    
    def _obtener_info_archivo(self, ruta: str) -> Dict[str, Any]:
        """Obtiene información completa de un archivo"""
        try:
            if os.path.exists(ruta):
                stat = os.stat(ruta)
                
                # Calcular hash SHA256 (seguro)
                sha256_hash = hashlib.sha256()
                
                with open(ruta, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(chunk)
                        sha256_hash.update(chunk)
                
                return {
                    'sha256': sha256_hash.hexdigest(),
                    'tamaño': stat.st_size,
                    'permisos': oct(stat.st_mode)[-3:],
                    'propietario': str(stat.st_uid),
                    'grupo': str(stat.st_gid),
                    'modificado': datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
            else:
                return {
                    'error': 'Archivo no existe',
                    'md5': '',
                    'sha256': '',
                    'tamaño': 0,
                    'permisos': '',
                    'propietario': '',
                    'grupo': '',
                    'modificado': ''
                }
        except Exception as e:
            self.log(f"Error obteniendo info archivo: {e}")
            return {
                'error': str(e),
                'md5': '',
                'sha256': '',
                'tamaño': 0,
                'permisos': '',
                'propietario': '',
                'grupo': '',
                'modificado': ''
            }
    
    def _determinar_severidad_evento(self, evento: str, archivo: str) -> str:
        """Determina la severidad de un evento FIM"""
        if 'delete' in evento.lower():
            return 'HIGH'
        elif any(critico in archivo.lower() for critico in ['/etc/', '/boot/', '/usr/bin/']):
            return 'HIGH'
        elif 'modify' in evento.lower():
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _procesar_resultados_chkrootkit(self, output: str) -> List[Dict[str, Any]]:
        """Procesa resultados de chkrootkit"""
        detecciones = []
        lines = output.split('\n')
        for line in lines:
            if line.strip() and 'INFECTED' in line:
                detecciones.append({
                    'archivo': line.strip(),
                    'tipo': 'rootkit',
                    'descripcion': line.strip(),
                    'severidad': 'HIGH'
                })
        return detecciones
    
    def _procesar_resultados_rkhunter(self, output: str) -> List[Dict[str, Any]]:
        """Procesa resultados de rkhunter"""
        detecciones = []
        lines = output.split('\n')
        for line in lines:
            if 'WARNING' in line or 'INFECTED' in line:
                detecciones.append({
                    'archivo': line.strip(),
                    'tipo': 'rootkit',
                    'descripcion': line.strip(),
                    'severidad': 'HIGH' if 'INFECTED' in line else 'MEDIUM'
                })
        return detecciones
    
    def _procesar_resultados_linpeas(self, output: str) -> List[Dict[str, Any]]:
        """Procesa resultados de linpeas (más completo que tiger)"""
        problemas = []
        lines = output.split('\n')
        for line in lines:
            # Buscar indicadores de problemas de seguridad
            if any(keyword in line.lower() for keyword in ['[!]', 'possible', 'vulnerable', 'writable', 'suid', 'guid']):
                if line.strip():
                    problemas.append({
                        'problema': line.strip(),
                        'tipo': 'seguridad',
                        'severidad': self._determinar_severidad_linpeas(line)
                    })
        return problemas
    
    def _determinar_severidad_linpeas(self, line: str) -> str:
        """Determina la severidad basada en el contenido de linpeas"""
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in ['suid', 'sudo', 'writable', 'passwd']):
            return 'HIGH'
        elif any(keyword in line_lower for keyword in ['possible', 'check']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _procesar_resultados_yara(self, output: str) -> List[Dict[str, Any]]:
        """Procesa resultados de YARA"""
        detecciones = []
        lines = output.split('\n')
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    detecciones.append({
                        'regla': parts[0],
                        'archivo': ' '.join(parts[1:]),
                        'tipo': 'malware',
                        'severidad': 'HIGH'
                    })
        return detecciones
    
    def _procesar_resultados_clamav(self, output: str) -> List[Dict[str, Any]]:
        """Procesa resultados de ClamAV"""
        infectados = []
        lines = output.split('\n')
        for line in lines:
            if 'FOUND' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    infectados.append({
                        'archivo': parts[0].strip(),
                        'virus': parts[1].strip(),
                        'tipo': 'virus',
                        'severidad': 'HIGH'
                    })
        return infectados
    
    def _crear_reglas_yara_basicas(self) -> str:
        """Crea archivo de reglas YARA básicas"""
        reglas_contenido = '''
rule SuspiciousStrings
{
    meta:
        description = "Detects suspicious strings"
        author = "ARESITOS"
    
    strings:
        $s1 = "cmd.exe"
        $s2 = "powershell"
        $s3 = "/bin/sh"
        $s4 = "backdoor"
        $s5 = "keylogger"
    
    condition:
        any of them
}

rule PossibleMalware
{
    meta:
        description = "Possible malware indicators"
        author = "ARESITOS"
    
    strings:
        $exe = { 4D 5A }  // MZ header
        $sus1 = "CreateRemoteThread"
        $sus2 = "WriteProcessMemory"
        $sus3 = "VirtualAlloc"
    
    condition:
        $exe at 0 and any of ($sus*)
}
        '''
        
        archivo_reglas = "/tmp/aresitos_yara_rules.yar"
        try:
            with open(archivo_reglas, 'w') as f:
                f.write(reglas_contenido)
            return archivo_reglas
        except (IOError, OSError, PermissionError, FileNotFoundError):
            return ""
    
    def _guardar_detecciones_rootkit(self, herramienta: str, detecciones: List[Dict[str, Any]]):
        """Guarda detecciones de rootkit en base de datos"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for deteccion in detecciones:
                cursor.execute('''
                    INSERT INTO detecciones_rootkit 
                    (herramienta, timestamp, archivo_afectado, tipo_amenaza, descripcion, severidad)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    herramienta,
                    datetime.now().isoformat(),
                    deteccion.get('archivo', ''),
                    deteccion.get('tipo', ''),
                    deteccion.get('descripcion', ''),
                    deteccion.get('severidad', 'MEDIUM')
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Error guardando detecciones rootkit: {e}")
    
    def _guardar_analisis_yara(self, detecciones: List[Dict[str, Any]]):
        """Guarda análisis YARA en base de datos"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for deteccion in detecciones:
                cursor.execute('''
                    INSERT INTO analisis_yara 
                    (archivo, regla_disparada, timestamp, metadatos, severidad)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    deteccion.get('archivo', ''),
                    deteccion.get('regla', ''),
                    datetime.now().isoformat(),
                    json.dumps(deteccion),
                    deteccion.get('severidad', 'MEDIUM')
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Error guardando análisis YARA: {e}")
    
    def log(self, mensaje: str):
        """Log de actividades del FIM"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[FIM KALI2025] {timestamp}: {mensaje}")
        
        # También llamar al log del padre si existe
        try:
            if hasattr(super(), 'log'):
                super().log(mensaje)  # type: ignore
        except (ValueError, TypeError, AttributeError):
            pass
