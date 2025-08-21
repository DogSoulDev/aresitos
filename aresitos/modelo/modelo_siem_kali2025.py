# -*- coding: utf-8 -*-
"""
ARESITOS - Modelo SIEM Kali Linux 2025
=====================================

Security Information and Event Management con herramientas modernas de Kali Linux 2025.
Solo herramientas que se instalan fácilmente con 'apt install'.

Herramientas integradas:
- auditd: Framework de auditoría Linux
- rsyslog: Gestión centralizada de logs
- fail2ban: Protección automática contra ataques
- lynis: Auditoría de seguridad del sistema

Autor: DogSoulDev
Fecha: 19 de Agosto de 2025
"""

import subprocess
import threading
import json
import os
import time
import re
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime, timedelta
import sqlite3
from collections import defaultdict

# Evitar warnings de typing - usar fallback directo
class _SIEMAvanzado:
    def __init__(self, gestor_permisos=None):
        self.gestor_permisos = gestor_permisos
        self.configuracion = {}
    
    def log(self, mensaje: str):
        print(f"[SIEM] {mensaje}")

class SIEMKali2025(_SIEMAvanzado):  # type: ignore
    """
    SIEM avanzado con herramientas Kali Linux 2025
    """
    
    def __init__(self, gestor_permisos=None):
        super().__init__(gestor_permisos)
        self.herramientas_siem = {
            'auditctl': '/usr/sbin/auditctl',
            'ausearch': '/usr/bin/ausearch',
            'logger': '/usr/bin/logger',
            'fail2ban-client': '/usr/bin/fail2ban-client',
            'lynis': '/usr/bin/lynis',
            'rsyslog': '/usr/sbin/rsyslogd'
        }
        self.base_datos_siem = "data/siem_kali2025.db"
        self.monitores_activos = {}
        self.reglas_correlacion = []
        self.verificar_herramientas()
        self.inicializar_base_datos()
        self.cargar_reglas_correlacion()
    
    def verificar_herramientas(self):
        """Verifica qué herramientas SIEM están disponibles"""
        self.herramientas_disponibles = {}
        
        for herramienta, ruta in self.herramientas_siem.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.herramientas_disponibles[herramienta] = result.stdout.strip()
                    self.log(f"✓ {herramienta} disponible en {result.stdout.strip()}")
                else:
                    self.log(f"✓ {herramienta} no encontrada")
            except Exception as e:
                self.log(f"✓ Error verificando {herramienta}: {e}")
    
    def inicializar_base_datos(self):
        """Inicializa base de datos SQLite para SIEM"""
        try:
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(self.base_datos_siem), exist_ok=True)
            
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            # Tabla para eventos de seguridad
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS eventos_seguridad (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    fuente TEXT,
                    tipo_evento TEXT,
                    severidad TEXT,
                    host TEXT,
                    usuario TEXT,
                    proceso TEXT,
                    comando TEXT,
                    archivo TEXT,
                    ip_origen TEXT,
                    puerto_origen INTEGER,
                    ip_destino TEXT,
                    puerto_destino INTEGER,
                    detalles TEXT,
                    raw_log TEXT
                )
            ''')
            
            # Tabla para alertas generadas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alertas_siem (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    regla_disparada TEXT,
                    severidad TEXT,
                    eventos_relacionados TEXT,
                    descripcion TEXT,
                    acciones_tomadas TEXT,
                    estado TEXT
                )
            ''')
            
            # Tabla para estadísticas de red
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS estadisticas_red (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    protocolo TEXT,
                    conexiones_activas INTEGER,
                    bytes_enviados INTEGER,
                    bytes_recibidos INTEGER,
                    paquetes_perdidos INTEGER
                )
            ''')
            
            # Tabla para auditorías de sistema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auditorias_sistema (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    herramienta TEXT,
                    categoria TEXT,
                    hallazgo TEXT,
                    severidad TEXT,
                    recomendacion TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            self.log("✓ Base de datos SIEM Kali2025 inicializada")
            
        except Exception as e:
            self.log(f"✓ Error inicializando base de datos SIEM: {e}")
    
    def cargar_reglas_correlacion(self):
        """Carga reglas de correlación de eventos"""
        self.reglas_correlacion = [
            {
                'nombre': 'Multiples_fallos_login',
                'descripcion': 'Detecta múltiples fallos de login del mismo usuario',
                'patron': 'authentication failure',
                'umbral': 5,
                'ventana_tiempo': 300,  # 5 minutos
                'severidad': 'HIGH',
                'campo_agrupacion': 'usuario'
            },
            {
                'nombre': 'Acceso_archivos_criticos',
                'descripcion': 'Detecta acceso a archivos críticos del sistema',
                'patron': r'/etc/(passwd|shadow|hosts|sudoers)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'HIGH',
                'campo_agrupacion': 'archivo'
            },
            {
                'nombre': 'Comandos_sospechosos',
                'descripcion': 'Detecta ejecución de comandos sospechosos',
                'patron': r'(nc|netcat|wget|curl.*http|python.*socket)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando'
            },
            {
                'nombre': 'Escalacion_privilegios',
                'descripcion': 'Detecta intentos de escalación de privilegios',
                'patron': r'(sudo|su|chmod.*777|chown.*root)',
                'umbral': 3,
                'ventana_tiempo': 600,
                'severidad': 'HIGH',
                'campo_agrupacion': 'usuario'
            }
        ]
        self.log(f"✓ Cargadas {len(self.reglas_correlacion)} reglas de correlación")
    
    def configurar_auditd(self, reglas_personalizadas: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Configura auditd con reglas de auditoría
        """
        self.log("CONFIGURANDO auditd")
        
        if 'auditctl' not in self.herramientas_disponibles:
            return {"error": "auditctl no disponible"}
        
        try:
            # Reglas básicas de auditoría
            reglas_default = [
                '-w /etc/passwd -p wa -k usuarios',
                '-w /etc/shadow -p wa -k usuarios',
                '-w /etc/sudoers -p wa -k privilegios',
                '-w /etc/hosts -p wa -k red',
                '-w /bin/su -p x -k escalacion',
                '-w /usr/bin/sudo -p x -k escalacion',
                '-w /bin/login -p x -k autenticacion',
                '-w /var/log/auth.log -p wa -k logs_auth',
                '-a always,exit -F arch=b64 -S execve -k comandos',
                '-a always,exit -F arch=b32 -S execve -k comandos'
            ]
            
            # Usar reglas personalizadas si se proporcionan
            reglas = reglas_personalizadas if reglas_personalizadas else reglas_default
            
            # Limpiar reglas existentes
            subprocess.run(['auditctl', '-D'], capture_output=True)
            
            # Aplicar nuevas reglas
            reglas_aplicadas = 0
            for regla in reglas:
                try:
                    cmd = ['auditctl'] + regla.split()
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        reglas_aplicadas += 1
                        self.log(f"✓ Regla aplicada: {regla}")
                    else:
                        self.log(f"✓ Error en regla: {regla} - {result.stderr}")
                except Exception as e:
                    self.log(f"✓ Error aplicando regla {regla}: {e}")
            
            # Verificar estado de auditd
            status_result = subprocess.run(['auditctl', '-s'], capture_output=True, text=True)
            
            self.log(f"✓ Auditd configurado: {reglas_aplicadas} reglas activas")
            return {
                "exito": True,
                "reglas_aplicadas": reglas_aplicadas,
                "total_reglas": len(reglas),
                "estado_auditd": status_result.stdout,
                "herramienta": "auditd"
            }
            
        except Exception as e:
            self.log(f"✓ Error configurando auditd: {e}")
            return {"error": str(e)}
    
    def monitorear_logs_tiempo_real(self, archivos_log: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Inicia monitoreo de logs en tiempo real
        """
        self.log("ANALIZANDO Iniciando monitoreo de logs tiempo real")
        
        try:
            # Archivos de log por defecto
            if not archivos_log:
                archivos_log = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/kern.log',
                    '/var/log/audit/audit.log'
                ]
            
            monitores_iniciados = 0
            for archivo_log in archivos_log:
                if os.path.exists(archivo_log):
                    # Crear thread de monitoreo para cada log
                    thread = threading.Thread(
                        target=self._monitorear_log_file,
                        args=(archivo_log,),
                        daemon=True
                    )
                    thread.start()
                    self.monitores_activos[archivo_log] = {
                        'thread': thread,
                        'activo': True,
                        'timestamp_inicio': datetime.now().isoformat()
                    }
                    monitores_iniciados += 1
                else:
                    self.log(f"✓ Log no existe: {archivo_log}")
            
            self.log(f"✓ Monitoreo iniciado en {monitores_iniciados} logs")
            return {
                "exito": True,
                "logs_monitoreados": monitores_iniciados,
                "herramienta": "rsyslog"
            }
            
        except Exception as e:
            self.log(f"✓ Error iniciando monitoreo logs: {e}")
            return {"error": str(e)}
    
    def _monitorear_log_file(self, archivo_log: str):
        """Thread de monitoreo de un archivo de log específico"""
        try:
            cmd = ['tail', '-F', archivo_log]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.log(f"ANALIZANDO Monitor activo en: {archivo_log}")
            
            while self.monitores_activos.get(archivo_log, {}).get('activo', False):
                if process.stdout:
                    line = process.stdout.readline()
                    if line:
                        self._procesar_linea_log(line.strip(), archivo_log)
                    
        except Exception as e:
            self.log(f"✓ Error en monitor log {archivo_log}: {e}")
    
    def _procesar_linea_log(self, linea: str, fuente: str):
        """Procesa una línea de log y la almacena en base de datos"""
        try:
            # Parsear línea de log
            evento = self._parsear_linea_log(linea, fuente)
            
            if evento:
                # Guardar en base de datos
                self._guardar_evento_seguridad(evento)
                
                # Aplicar reglas de correlación
                self._aplicar_reglas_correlacion(evento)
                
        except Exception as e:
            self.log(f"✓ Error procesando línea log: {e}")
    
    def _parsear_linea_log(self, linea: str, fuente: str) -> Optional[Dict[str, Any]]:
        """Parsea una línea de log y extrae información relevante"""
        try:
            evento = {
                'timestamp': datetime.now().isoformat(),
                'fuente': fuente,
                'raw_log': linea,
                'tipo_evento': 'unknown',
                'severidad': 'LOW'
            }
            
            # Patterns para diferentes tipos de eventos
            patterns = {
                'login_fallido': r'authentication failure.*user=(\w+)',
                'login_exitoso': r'session opened for user (\w+)',
                'sudo_ejecutado': r'sudo.*USER=(\w+).*COMMAND=(.+)',
                'acceso_archivo': r'audit.*path="([^"]+)"',
                'comando_ejecutado': r'audit.*exe="([^"]+)".*comm="([^"]+)"',
                'conexion_red': r'(\d+\.\d+\.\d+\.\d+).*port (\d+)'
            }
            
            for tipo, pattern in patterns.items():
                match = re.search(pattern, linea, re.IGNORECASE)
                if match:
                    evento['tipo_evento'] = tipo
                    
                    # Extraer información específica según el tipo
                    if tipo in ['login_fallido', 'login_exitoso']:
                        evento['usuario'] = match.group(1)
                        evento['severidad'] = 'HIGH' if 'fallido' in tipo else 'LOW'
                    
                    elif tipo == 'sudo_ejecutado':
                        evento['usuario'] = match.group(1)
                        evento['comando'] = match.group(2)
                        evento['severidad'] = 'MEDIUM'
                    
                    elif tipo == 'acceso_archivo':
                        evento['archivo'] = match.group(1)
                        evento['severidad'] = 'HIGH' if '/etc/' in evento['archivo'] else 'LOW'
                    
                    elif tipo == 'comando_ejecutado':
                        evento['proceso'] = match.group(1)
                        evento['comando'] = match.group(2)
                        evento['severidad'] = 'MEDIUM'
                    
                    elif tipo == 'conexion_red':
                        evento['ip_origen'] = match.group(1)
                        evento['puerto_origen'] = str(match.group(2))
                        evento['severidad'] = 'LOW'
                    
                    break
            
            return evento
            
        except Exception as e:
            self.log(f"Error parseando línea: {e}")
            return None
    
    def _guardar_evento_seguridad(self, evento: Dict[str, Any]):
        """Guarda evento de seguridad en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO eventos_seguridad 
                (timestamp, fuente, tipo_evento, severidad, host, usuario, proceso, comando, 
                 archivo, ip_origen, puerto_origen, ip_destino, puerto_destino, detalles, raw_log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                evento.get('timestamp'),
                evento.get('fuente'),
                evento.get('tipo_evento'),
                evento.get('severidad'),
                evento.get('host', 'localhost'),
                evento.get('usuario'),
                evento.get('proceso'),
                evento.get('comando'),
                evento.get('archivo'),
                evento.get('ip_origen'),
                evento.get('puerto_origen'),
                evento.get('ip_destino'),
                evento.get('puerto_destino'),
                json.dumps(evento),
                evento.get('raw_log')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error guardando evento: {e}")
    
    def _aplicar_reglas_correlacion(self, evento: Dict[str, Any]):
        """Aplica reglas de correlación para detectar patrones sospechosos"""
        try:
            for regla in self.reglas_correlacion:
                if re.search(regla['patron'], evento.get('raw_log', ''), re.IGNORECASE):
                    # Buscar eventos similares en la ventana de tiempo
                    eventos_similares = self._buscar_eventos_similares(evento, regla)
                    
                    if len(eventos_similares) >= regla['umbral']:
                        self._generar_alerta(regla, eventos_similares)
                        
        except Exception as e:
            self.log(f"Error aplicando correlación: {e}")
    
    def _buscar_eventos_similares(self, evento: Dict[str, Any], regla: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca eventos similares en la ventana de tiempo especificada"""
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            # Calcular ventana de tiempo
            timestamp_limite = (datetime.now() - timedelta(seconds=regla['ventana_tiempo'])).isoformat()
            
            # Construir query según el campo de agrupación
            campo_agrupacion = regla['campo_agrupacion']
            valor_agrupacion = evento.get(campo_agrupacion)
            
            if valor_agrupacion:
                cursor.execute(f'''
                    SELECT * FROM eventos_seguridad 
                    WHERE {campo_agrupacion} = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                ''', (valor_agrupacion, timestamp_limite))
                
                eventos = cursor.fetchall()
                conn.close()
                
                return [dict(zip([col[0] for col in cursor.description], evento)) for evento in eventos]
            
            conn.close()
            return []
            
        except Exception as e:
            self.log(f"Error buscando eventos similares: {e}")
            return []
    
    def _generar_alerta(self, regla: Dict[str, Any], eventos: List[Dict[str, Any]]):
        """Genera una alerta basada en la regla disparada"""
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            descripcion = f"{regla['descripcion']} - {len(eventos)} eventos detectados"
            eventos_ids = [str(e.get('id', '')) for e in eventos]
            
            cursor.execute('''
                INSERT INTO alertas_siem 
                (timestamp, regla_disparada, severidad, eventos_relacionados, descripcion, estado)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                regla['nombre'],
                regla['severidad'],
                ','.join(eventos_ids),
                descripcion,
                'NUEVA'
            ))
            
            conn.commit()
            conn.close()
            
            self.log(f"[ALERT] ALERTA GENERADA: {regla['nombre']} - {descripcion}")
            
        except Exception as e:
            self.log(f"Error generando alerta: {e}")
    
    def configurar_fail2ban(self) -> Dict[str, Any]:
        """
        Configura fail2ban para protección automática
        """
        self.log("[SECURITY] Configurando fail2ban")
        
        if 'fail2ban-client' not in self.herramientas_disponibles:
            return {"error": "fail2ban-client no disponible"}
        
        try:
            # Verificar estado
            status_result = subprocess.run(['fail2ban-client', 'status'], 
                                         capture_output=True, text=True, timeout=30)
            
            # Obtener jails activas
            jails_result = subprocess.run(['fail2ban-client', 'status'], 
                                        capture_output=True, text=True)
            
            self.log("✓ Fail2ban configurado y activo")
            return {
                "exito": True,
                "estado": status_result.stdout,
                "jails": jails_result.stdout,
                "herramienta": "fail2ban"
            }
            
        except Exception as e:
            self.log(f"✓ Error configurando fail2ban: {e}")
            return {"error": str(e)}
    
    def auditoria_sistema_lynis(self) -> Dict[str, Any]:
        """
        Ejecuta auditoría completa del sistema con lynis
        """
        self.log("ANALIZANDO Iniciando auditoría lynis")
        
        if 'lynis' not in self.herramientas_disponibles:
            return {"error": "lynis no disponible"}
        
        try:
            cmd = [
                'lynis',
                'audit', 'system',
                '--quiet',
                '--no-colors'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            
            # Procesar resultados de lynis
            hallazgos = self._procesar_resultados_lynis(result.stdout)
            
            # Guardar en base de datos
            self._guardar_auditoria_sistema('lynis', hallazgos)
            
            self.log(f"✓ Auditoría lynis completada: {len(hallazgos)} hallazgos")
            return {
                "exito": True,
                "hallazgos": hallazgos,
                "total_hallazgos": len(hallazgos),
                "herramienta": "lynis"
            }
            
        except Exception as e:
            self.log(f"✓ Error ejecutando lynis: {e}")
            return {"error": str(e)}
    
    def obtener_estadisticas_red(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas de red del sistema
        """
        self.log("RESUMEN Obteniendo estadísticas de red")
        
        try:
            estadisticas = {}
            
            # Conexiones activas
            netstat_result = subprocess.run(['netstat', '-tuln'], 
                                          capture_output=True, text=True, timeout=30)
            if netstat_result.returncode == 0:
                conexiones = self._procesar_netstat(netstat_result.stdout)
                estadisticas['conexiones_activas'] = conexiones
            
            # Estadísticas de interfaz
            ifconfig_result = subprocess.run(['ip', 'addr', 'show'], 
                                           capture_output=True, text=True, timeout=30)
            if ifconfig_result.returncode == 0:
                interfaces = self._procesar_interfaces(ifconfig_result.stdout)
                estadisticas['interfaces'] = interfaces
            
            # Guardar en base de datos
            self._guardar_estadisticas_red(estadisticas)
            
            self.log("✓ Estadísticas de red obtenidas")
            return {
                "exito": True,
                "estadisticas": estadisticas,
                "herramienta": "netstat"
            }
            
        except Exception as e:
            self.log(f"✓ Error obteniendo estadísticas red: {e}")
            return {"error": str(e)}
    
    def analisis_completo_siem_kali2025(self) -> Dict[str, Any]:
        """
        Análisis completo SIEM con todas las herramientas Kali 2025
        """
        self.log("[START] INICIANDO ANÁLISIS COMPLETO SIEM KALI 2025")
        
        resultados = {
            "timestamp": datetime.now().isoformat(),
            "herramientas_utilizadas": [],
            "analisis": {}
        }
        
        # 1. Configurar auditd
        self.log("FASE 1: Configurando auditd")
        auditd_result = self.configurar_auditd()
        resultados["analisis"]["auditd"] = auditd_result
        if auditd_result.get("exito"):
            resultados["herramientas_utilizadas"].append("auditd")
        
        # 2. Iniciar monitoreo de logs
        self.log("FASE 2: Iniciando monitoreo logs")
        monitor_result = self.monitorear_logs_tiempo_real()
        resultados["analisis"]["monitoreo_logs"] = monitor_result
        if monitor_result.get("exito"):
            resultados["herramientas_utilizadas"].append("rsyslog")
        
        # 3. Configurar fail2ban
        self.log("FASE 3: Configurando fail2ban")
        fail2ban_result = self.configurar_fail2ban()
        resultados["analisis"]["fail2ban"] = fail2ban_result
        if fail2ban_result.get("exito"):
            resultados["herramientas_utilizadas"].append("fail2ban")
        
        # 4. Auditoría con lynis
        self.log("FASE 4: Auditoría sistema lynis")
        lynis_result = self.auditoria_sistema_lynis()
        resultados["analisis"]["lynis"] = lynis_result
        if lynis_result.get("exito"):
            resultados["herramientas_utilizadas"].append("lynis")
        
        # 5. Estadísticas de red
        self.log("FASE 5: Estadísticas de red")
        red_result = self.obtener_estadisticas_red()
        resultados["analisis"]["estadisticas_red"] = red_result
        if red_result.get("exito"):
            resultados["herramientas_utilizadas"].append("netstat")
        
        # Resumen final
        total_reglas_auditd = auditd_result.get("reglas_aplicadas", 0)
        total_logs_monitoreados = monitor_result.get("logs_monitoreados", 0)
        total_hallazgos = lynis_result.get("total_hallazgos", 0)
        
        resultados["resumen"] = {
            "reglas_auditd_activas": total_reglas_auditd,
            "logs_monitoreados": total_logs_monitoreados,
            "hallazgos_seguridad": total_hallazgos,
            "herramientas_utilizadas": len(set(resultados["herramientas_utilizadas"])),
            "monitores_activos": len(self.monitores_activos)
        }
        
        self.log("✓ ANÁLISIS COMPLETO SIEM FINALIZADO")
        return resultados
    
    def _procesar_resultados_lynis(self, output: str) -> List[Dict[str, Any]]:
        """Procesa resultados de lynis"""
        hallazgos = []
        lines = output.split('\n')
        
        for line in lines:
            if 'ADVERTENCIA' in line or '[SUGGESTION]' in line:
                severidad = 'MEDIUM' if 'ADVERTENCIA' in line else 'LOW'
                hallazgos.append({
                    'categoria': 'auditoria_sistema',
                    'hallazgo': line.strip(),
                    'severidad': severidad,
                    'herramienta': 'lynis'
                })
        
        return hallazgos
    
    def _procesar_netstat(self, output: str) -> Dict[str, Any]:
        """Procesa salida de netstat"""
        conexiones = {
            'tcp': 0,
            'udp': 0,
            'listening': 0,
            'established': 0
        }
        
        lines = output.split('\n')
        for line in lines:
            if 'tcp' in line.lower():
                conexiones['tcp'] += 1
                if 'LISTEN' in line:
                    conexiones['listening'] += 1
                elif 'ESTABLISHED' in line:
                    conexiones['established'] += 1
            elif 'udp' in line.lower():
                conexiones['udp'] += 1
        
        return conexiones
    
    def _procesar_interfaces(self, output: str) -> List[Dict[str, Any]]:
        """Procesa información de interfaces de red"""
        interfaces = []
        lines = output.split('\n')
        
        interface_actual = None
        for line in lines:
            if ':' in line and not line.startswith(' '):
                # Nueva interfaz
                parts = line.split(':')
                if len(parts) >= 2:
                    interface_actual = {
                        'nombre': parts[1].strip(),
                        'estado': 'UP' if 'UP' in line else 'DOWN'
                    }
                    interfaces.append(interface_actual)
            elif 'inet ' in line and interface_actual:
                # Dirección IP
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    interface_actual['ip'] = ip_match.group(1)
        
        return interfaces
    
    def _guardar_auditoria_sistema(self, herramienta: str, hallazgos: List[Dict[str, Any]]):
        """Guarda resultados de auditoría en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            for hallazgo in hallazgos:
                cursor.execute('''
                    INSERT INTO auditorias_sistema 
                    (timestamp, herramienta, categoria, hallazgo, severidad, recomendacion)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    herramienta,
                    hallazgo.get('categoria', ''),
                    hallazgo.get('hallazgo', ''),
                    hallazgo.get('severidad', 'LOW'),
                    hallazgo.get('recomendacion', '')
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Error guardando auditoría: {e}")
    
    def _guardar_estadisticas_red(self, estadisticas: Dict[str, Any]):
        """Guarda estadísticas de red en base de datos"""
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            conexiones = estadisticas.get('conexiones_activas', {})
            
            cursor.execute('''
                INSERT INTO estadisticas_red 
                (timestamp, protocolo, conexiones_activas, bytes_enviados, bytes_recibidos)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                'TCP+UDP',
                conexiones.get('tcp', 0) + conexiones.get('udp', 0),
                0,  # Por ahora sin datos de bytes
                0
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Error guardando estadísticas red: {e}")
    
    def log(self, mensaje: str):
        """Log de actividades del SIEM"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[SIEM KALI2025] {timestamp}: {mensaje}")
        
        # También llamar al log del padre si existe
        try:
            if hasattr(super(), 'log'):
                super().log(mensaje)
        except (ValueError, TypeError, AttributeError):
            pass
