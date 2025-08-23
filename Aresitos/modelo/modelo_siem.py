# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Modelo SIEM Consolidado
======================================

Security Information and Event Management con herramientas nativas Kali Linux.
Sistema completo de análisis de eventos de seguridad en tiempo real.

Funcionalidades SIEM Profesionales:
- Recopilación centralizada de logs de seguridad
- Correlación inteligente de eventos de múltiples fuentes  
- Detección automática de amenazas y anomalías
- Análisis de comportamiento de usuarios y entidades (UEBA)
- Generación de alertas críticas en tiempo real
- Dashboard de monitoreo unificado
- Cumplimiento de normativas y auditorías

Herramientas Kali integradas:
- auditd: Auditoría avanzada del sistema Linux
- rsyslog: Gestión centralizada de logs del sistema
- fail2ban: Protección automática contra ataques de fuerza bruta
- lynis: Auditoría completa de seguridad del sistema
- netstat/ss: Monitoreo de conexiones de red
- chkrootkit/rkhunter: Detección de rootkits y malware

Principios ARESITOS aplicados:
- Python nativo + herramientas Kali únicamente
- Sin dependencias externas
- Código limpio y conciso (SOLID/DRY)
- MVC arquitectura respetada
- Sin emojis/tokens (excepto Aresitos.ico/png)

Autor: DogSoulDev
Fecha: Agosto 2025
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
from collections import defaultdict, deque

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
        self.version = "3.0"  # Versión ARESITOS v3.0
        self.kali_version = "2025"  # Versión Kali Linux
        self.herramientas_siem = {
            'auditctl': '/usr/sbin/auditctl',
            'ausearch': '/usr/bin/ausearch', 
            'logger': '/usr/bin/logger',
            'fail2ban-client': '/usr/bin/fail2ban-client',
            'lynis': '/usr/bin/lynis',
            'rsyslog': '/usr/sbin/rsyslogd',
            'netstat': '/bin/netstat',
            'ss': '/usr/bin/ss',
            'grep': '/bin/grep',
            'awk': '/usr/bin/awk',
            'who': '/usr/bin/who',
            'last': '/usr/bin/last',
            'chkrootkit': '/usr/bin/chkrootkit',
            'rkhunter': '/usr/bin/rkhunter'
        }
        
        # Base de datos para persistencia 
        self.base_datos_siem = "data/siem_aresitos.db"
        self.monitores_activos = {}
        self.cache_eventos = {}
        self.correlaciones_activas = {}
        
        # Reglas de correlación avanzadas
        self.reglas_correlacion = []
        self.patrones_ataques_conocidos = self._cargar_patrones_ataques()
        self.baseline_comportamiento = {}
        
        # Configuración optimizada
        self.config_optimizada = {
            'max_eventos_memoria': 10000,
            'intervalo_correlacion': 5,  # segundos
            'umbral_alerta_critica': 5,  # eventos correlacionados
            'tiempo_ventana_correlacion': 300,  # 5 minutos
            'max_falsos_positivos': 3
        }
        
        # Inicializar componentes
        self.verificar_herramientas()
        self.inicializar_base_datos()
        self.cargar_reglas_correlacion()
        
        # Componentes optimizados adicionales
        self.patrones_ataques_conocidos = self._cargar_patrones_ataques()
        self._inicializar_sistema_correlacion_avanzado()
    
    def verificar_herramientas(self):
        """Verifica qué herramientas SIEM están disponibles"""
        self.herramientas_disponibles = {}
        
        for herramienta, ruta in self.herramientas_siem.items():
            try:
                result = subprocess.run(['which', herramienta], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.herramientas_disponibles[herramienta] = result.stdout.strip()
                    self.log(f"OK {herramienta} disponible en {result.stdout.strip()}")
                else:
                    self.log(f"INFO {herramienta} no encontrada")
            except Exception as e:
                self.log(f"ERROR Error verificando {herramienta}: {e}")
    
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
            self.log("OK Base de datos SIEM Kali2025 inicializada")
            
        except Exception as e:
            self.log(f"OK Error inicializando base de datos SIEM: {e}")
    
    def cargar_reglas_correlacion(self):
        """
        Carga reglas de correlación avanzadas basadas en amenazas reales de ciberseguridad.
        Conjunto completo de patrones de detección para SIEM profesional.
        """
        self.reglas_correlacion = [
            # CATEGORIA: AUTENTICACION Y ACCESO
            {
                'nombre': 'Multiples_fallos_login',
                'descripcion': 'Detecta ataques de fuerza bruta con múltiples fallos de login',
                'patron': r'(authentication failure|Failed password|login failed)',
                'umbral': 5,
                'ventana_tiempo': 300,  # 5 minutos
                'severidad': 'HIGH',
                'campo_agrupacion': 'usuario',
                'categoria': 'autenticacion',
                'tecnica_mitre': 'T1110'
            },
            {
                'nombre': 'Login_exitoso_tras_fallos',
                'descripcion': 'Detecta login exitoso después de múltiples fallos (posible compromiso)',
                'patron': r'(Accepted password|session opened)',
                'umbral': 1,
                'ventana_tiempo': 600,
                'severidad': 'CRITICAL',
                'campo_agrupacion': 'usuario',
                'categoria': 'autenticacion',
                'tecnica_mitre': 'T1078'
            },
            {
                'nombre': 'Acceso_horario_inusual',
                'descripcion': 'Detecta accesos fuera del horario laboral normal',
                'patron': r'(session opened|login)',
                'umbral': 1,
                'ventana_tiempo': 3600,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'usuario',
                'categoria': 'autenticacion',
                'tecnica_mitre': 'T1078'
            },
            
            # CATEGORIA: ESCALACION DE PRIVILEGIOS
            {
                'nombre': 'Escalacion_privilegios',
                'descripcion': 'Detecta intentos de escalación de privilegios',
                'patron': r'(sudo|su -|sudo su|chmod.*777|chown.*root)',
                'umbral': 3,
                'ventana_tiempo': 600,
                'severidad': 'HIGH',
                'campo_agrupacion': 'usuario',
                'categoria': 'escalacion',
                'tecnica_mitre': 'T1548'
            },
            {
                'nombre': 'Modificacion_sudoers',
                'descripcion': 'Detecta modificaciones al archivo sudoers',
                'patron': r'/etc/sudoers',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'CRITICAL',
                'campo_agrupacion': 'archivo',
                'categoria': 'escalacion',
                'tecnica_mitre': 'T1548.003'
            },
            {
                'nombre': 'Ejecucion_como_root',
                'descripcion': 'Detecta comandos ejecutados como root por usuarios no autorizados',
                'patron': r'(uid=0|root)',
                'umbral': 5,
                'ventana_tiempo': 300,
                'severidad': 'HIGH',
                'campo_agrupacion': 'usuario',
                'categoria': 'escalacion',
                'tecnica_mitre': 'T1548'
            },
            
            # CATEGORIA: ACCESO A ARCHIVOS CRITICOS
            {
                'nombre': 'Acceso_archivos_criticos',
                'descripcion': 'Detecta acceso a archivos críticos del sistema',
                'patron': r'/etc/(passwd|shadow|hosts|sudoers|ssh/|ssl/)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'HIGH',
                'campo_agrupacion': 'archivo',
                'categoria': 'acceso_archivos',
                'tecnica_mitre': 'T1003'
            },
            {
                'nombre': 'Modificacion_archivos_sistema',
                'descripcion': 'Detecta modificaciones a archivos críticos del sistema',
                'patron': r'/etc/(crontab|passwd|group|hosts\.deny|hosts\.allow)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'CRITICAL',
                'campo_agrupacion': 'archivo',
                'categoria': 'acceso_archivos',
                'tecnica_mitre': 'T1003.008'
            },
            {
                'nombre': 'Acceso_logs_seguridad',
                'descripcion': 'Detecta intentos de acceso o modificación de logs de seguridad',
                'patron': r'/var/log/(auth|secure|audit)',
                'umbral': 1,
                'ventana_tiempo': 300,
                'severidad': 'HIGH',
                'campo_agrupacion': 'archivo',
                'categoria': 'acceso_archivos',
                'tecnica_mitre': 'T1070.002'
            },
            
            # CATEGORIA: COMANDOS SOSPECHOSOS Y MALWARE
            {
                'nombre': 'Comandos_sospechosos',
                'descripcion': 'Detecta ejecución de comandos típicos de atacantes',
                'patron': r'(nc|netcat|wget.*http|curl.*http|python.*socket|perl.*socket)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'comandos',
                'tecnica_mitre': 'T1059'
            },
            {
                'nombre': 'Reverse_shell',
                'descripcion': 'Detecta intentos de establecer reverse shells',
                'patron': r'(bash.*tcp|sh.*tcp|/dev/tcp|mkfifo.*nc)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'CRITICAL',
                'campo_agrupacion': 'comando',
                'categoria': 'comandos',
                'tecnica_mitre': 'T1059.004'
            },
            {
                'nombre': 'Descarga_archivos_remotos',
                'descripcion': 'Detecta descarga de archivos desde ubicaciones remotas',
                'patron': r'(wget|curl|fetch).*http.*\.(sh|py|pl|exe|bin)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'HIGH',
                'campo_agrupacion': 'comando',
                'categoria': 'comandos',
                'tecnica_mitre': 'T1105'
            },
            {
                'nombre': 'Herramientas_reconocimiento',
                'descripcion': 'Detecta uso de herramientas de reconocimiento',
                'patron': r'(nmap|masscan|dirb|gobuster|nikto|sqlmap)',
                'umbral': 3,
                'ventana_tiempo': 600,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'reconocimiento',
                'tecnica_mitre': 'T1046'
            },
            
            # CATEGORIA: ACTIVIDAD DE RED SOSPECHOSA
            {
                'nombre': 'Conexiones_salientes_sospechosas',
                'descripcion': 'Detecta conexiones salientes a puertos inusuales',
                'patron': r'(tcp.*ESTABLISHED.*:(4444|1234|31337|6666|9999))',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'HIGH',
                'campo_agrupacion': 'puerto_destino',
                'categoria': 'red',
                'tecnica_mitre': 'T1071'
            },
            {
                'nombre': 'Escaneo_puertos_interno',
                'descripcion': 'Detecta escaneo de puertos desde hosts internos',
                'patron': r'(nmap|masscan|nc.*-z)',
                'umbral': 10,
                'ventana_tiempo': 300,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'ip_origen',
                'categoria': 'red',
                'tecnica_mitre': 'T1046'
            },
            {
                'nombre': 'Transferencia_datos_masiva',
                'descripcion': 'Detecta transferencias de datos inusualmente grandes',
                'patron': r'(scp|rsync|tar.*gz).*[0-9]{6,}',
                'umbral': 1,
                'ventana_tiempo': 300,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'red',
                'tecnica_mitre': 'T1041'
            },
            
            # CATEGORIA: PERSISTENCIA Y BACKDOORS
            {
                'nombre': 'Modificacion_crontab',
                'descripcion': 'Detecta modificaciones en tareas programadas (persistencia)',
                'patron': r'(crontab|/etc/cron|/var/spool/cron)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'HIGH',
                'campo_agrupacion': 'archivo',
                'categoria': 'persistencia',
                'tecnica_mitre': 'T1053.003'
            },
            {
                'nombre': 'Servicios_nuevos',
                'descripcion': 'Detecta creación de nuevos servicios del sistema',
                'patron': r'(systemctl.*enable|update-rc\.d|chkconfig)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'persistencia',
                'tecnica_mitre': 'T1543.002'
            },
            {
                'nombre': 'Modificacion_bashrc',
                'descripcion': 'Detecta modificaciones a archivos de configuración de shell',
                'patron': r'(\.(bashrc|bash_profile|profile|zshrc))',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'archivo',
                'categoria': 'persistencia',
                'tecnica_mitre': 'T1546.004'
            },
            
            # CATEGORIA: EVASION Y OCULTACION
            {
                'nombre': 'Borrado_logs',
                'descripcion': 'Detecta intentos de borrar o limpiar logs del sistema',
                'patron': r'(rm.*log|>/var/log|truncate.*log|shred.*log)',
                'umbral': 1,
                'ventana_tiempo': 60,
                'severidad': 'CRITICAL',
                'campo_agrupacion': 'comando',
                'categoria': 'evasion',
                'tecnica_mitre': 'T1070.002'
            },
            {
                'nombre': 'Archivos_ocultos',
                'descripcion': 'Detecta creación de archivos ocultos en ubicaciones sospechosas',
                'patron': r'(\./\.|touch.*\.\.|mkdir.*\.\.)',
                'umbral': 3,
                'ventana_tiempo': 300,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'evasion',
                'tecnica_mitre': 'T1564.001'
            },
            {
                'nombre': 'Procesos_ocultos',
                'descripcion': 'Detecta intentos de ocultar procesos',
                'patron': r'(nohup|disown|setsid|screen.*-d)',
                'umbral': 2,
                'ventana_tiempo': 300,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'evasion',
                'tecnica_mitre': 'T1564'
            },
            
            # CATEGORIA: EXFILTRACION DE DATOS
            {
                'nombre': 'Compresion_archivos_sensibles',
                'descripcion': 'Detecta compresión de archivos potencialmente sensibles',
                'patron': r'(tar.*gz|zip|rar).*(/home|/etc|/var)',
                'umbral': 1,
                'ventana_tiempo': 300,
                'severidad': 'HIGH',
                'campo_agrupacion': 'comando',
                'categoria': 'exfiltracion',
                'tecnica_mitre': 'T1560'
            },
            {
                'nombre': 'Transferencia_externa',
                'descripcion': 'Detecta transferencias de archivos a ubicaciones externas',
                'patron': r'(scp|rsync|ftp).*@.*:',
                'umbral': 1,
                'ventana_tiempo': 300,
                'severidad': 'MEDIUM',
                'campo_agrupacion': 'comando',
                'categoria': 'exfiltracion',
                'tecnica_mitre': 'T1041'
            }
        ]
        self.log(f"OK Cargadas {len(self.reglas_correlacion)} reglas de correlación avanzadas")
        
        # Organizar reglas por categoría para análisis más eficiente
        self.reglas_por_categoria = {}
        for regla in self.reglas_correlacion:
            categoria = regla['categoria']
            if categoria not in self.reglas_por_categoria:
                self.reglas_por_categoria[categoria] = []
            self.reglas_por_categoria[categoria].append(regla)
        
        self.log(f"OK Reglas organizadas en {len(self.reglas_por_categoria)} categorías")
    
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
                        self.log(f"OK Regla aplicada: {regla}")
                    else:
                        self.log(f"OK Error en regla: {regla} - {result.stderr}")
                except Exception as e:
                    self.log(f"OK Error aplicando regla {regla}: {e}")
            
            # Verificar estado de auditd
            status_result = subprocess.run(['auditctl', '-s'], capture_output=True, text=True)
            
            self.log(f"OK Auditd configurado: {reglas_aplicadas} reglas activas")
            return {
                "exito": True,
                "reglas_aplicadas": reglas_aplicadas,
                "total_reglas": len(reglas),
                "estado_auditd": status_result.stdout,
                "herramienta": "auditd"
            }
            
        except Exception as e:
            self.log(f"OK Error configurando auditd: {e}")
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
                    self.log(f"OK Log no existe: {archivo_log}")
            
            self.log(f"OK Monitoreo iniciado en {monitores_iniciados} logs")
            return {
                "exito": True,
                "logs_monitoreados": monitores_iniciados,
                "herramienta": "rsyslog"
            }
            
        except Exception as e:
            self.log(f"OK Error iniciando monitoreo logs: {e}")
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
            self.log(f"OK Error en monitor log {archivo_log}: {e}")
    
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
            self.log(f"OK Error procesando línea log: {e}")
    
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
            
            self.log("OK Fail2ban configurado y activo")
            return {
                "exito": True,
                "estado": status_result.stdout,
                "jails": jails_result.stdout,
                "herramienta": "fail2ban"
            }
            
        except Exception as e:
            self.log(f"OK Error configurando fail2ban: {e}")
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
            
            self.log(f"OK Auditoría lynis completada: {len(hallazgos)} hallazgos")
            return {
                "exito": True,
                "hallazgos": hallazgos,
                "total_hallazgos": len(hallazgos),
                "herramienta": "lynis"
            }
            
        except Exception as e:
            self.log(f"OK Error ejecutando lynis: {e}")
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
            
            self.log("OK Estadísticas de red obtenidas")
            return {
                "exito": True,
                "estadisticas": estadisticas,
                "herramienta": "netstat"
            }
            
        except Exception as e:
            self.log(f"OK Error obteniendo estadísticas red: {e}")
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
        
        self.log("OK ANÁLISIS COMPLETO SIEM FINALIZADO")
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
    
    # =========================================
    # MÉTODOS OPTIMIZADOS ARESITOS v3.0
    # =========================================
    
    def _cargar_patrones_ataques(self) -> Dict[str, Any]:
        """
        Cargar patrones de ataques conocidos en ciberseguridad.
        Base de conocimiento real de amenazas actuales.
        """
        return {
            'brute_force': {
                'descripcion': 'Ataques de fuerza bruta',
                'patrones': [
                    r'Failed password.*from.*port',
                    r'authentication failure.*user=',
                    r'Invalid user.*from'
                ],
                'umbral_eventos': 5,
                'ventana_tiempo': 300,  # 5 minutos
                'severidad': 'alto'
            },
            'privilege_escalation': {
                'descripcion': 'Escalada de privilegios',
                'patrones': [
                    r'sudo.*COMMAND=.*su.*root',
                    r'setuid.*operation not permitted',
                    r'attempted to execute.*as.*root'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 60,
                'severidad': 'critico'
            },
            'lateral_movement': {
                'descripcion': 'Movimiento lateral en la red',
                'patrones': [
                    r'ssh.*connection.*closed by',
                    r'scp.*denied',
                    r'rsync.*permission denied'
                ],
                'umbral_eventos': 3,
                'ventana_tiempo': 600,
                'severidad': 'medio'
            },
            'data_exfiltration': {
                'descripcion': 'Exfiltración de datos',
                'patrones': [
                    r'tar.*\.gz.*tmp',
                    r'zip.*-r.*\/home',
                    r'wget.*-O.*\/dev\/null'
                ],
                'umbral_eventos': 2,
                'ventana_tiempo': 300,
                'severidad': 'critico'
            },
            'port_scanning': {
                'descripcion': 'Escaneo de puertos',
                'patrones': [
                    r'nmap.*scan.*initiated',
                    r'masscan.*started',
                    r'connection.*reset by peer.*rapid'
                ],
                'umbral_eventos': 10,
                'ventana_tiempo': 120,
                'severidad': 'medio'
            },
            'malware_activity': {
                'descripcion': 'Actividad de malware',
                'patrones': [
                    r'\.sh.*\/tmp.*executed',
                    r'wget.*\|.*sh',
                    r'curl.*\|.*bash'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 60,
                'severidad': 'critico'
            },
            'persistence_mechanism': {
                'descripcion': 'Mecanismos de persistencia',
                'patrones': [
                    r'crontab.*-e',
                    r'systemctl.*enable.*\.service',
                    r'\.bashrc.*modified'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 300,
                'severidad': 'alto'
            },
            'credential_dumping': {
                'descripcion': 'Volcado de credenciales',
                'patrones': [
                    r'mimikatz.*sekurlsa',
                    r'cat.*\/etc\/shadow',
                    r'john.*--wordlist',
                    r'hashcat.*-m.*-a'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 60,
                'severidad': 'critico'
            },
            'defense_evasion': {
                'descripcion': 'Evasión de defensas',
                'patrones': [
                    r'killall.*antivirus',
                    r'systemctl.*stop.*firewall',
                    r'iptables.*-F',
                    r'chattr.*\+i.*log'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 180,
                'severidad': 'alto'
            },
            'command_control': {
                'descripcion': 'Comando y control',
                'patrones': [
                    r'nc.*-l.*-p.*[0-9]+',
                    r'python.*socket.*connect',
                    r'socat.*tcp-listen',
                    r'ncat.*--broker'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 120,
                'severidad': 'critico'
            },
            'reconnaissance': {
                'descripcion': 'Reconocimiento del sistema',
                'patrones': [
                    r'whoami.*&.*id',
                    r'ps.*aux.*grep',
                    r'netstat.*-tulnp',
                    r'find.*-perm.*-u=s'
                ],
                'umbral_eventos': 5,
                'ventana_tiempo': 300,
                'severidad': 'medio'
            },
            'log_tampering': {
                'descripcion': 'Manipulación de logs',
                'patrones': [
                    r'rm.*\/var\/log',
                    r'echo.*>.*\.log',
                    r'history.*-c',
                    r'unlink.*syslog'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 60,
                'severidad': 'alto'
            },
            'web_attack': {
                'descripcion': 'Ataques web',
                'patrones': [
                    r'sqlmap.*--dump',
                    r'\.php.*system\(',
                    r'\/bin\/sh.*-i',
                    r'SELECT.*FROM.*WHERE.*1=1'
                ],
                'umbral_eventos': 1,
                'ventana_tiempo': 30,
                'severidad': 'critico'
            },
            'password_attack': {
                'descripcion': 'Ataques a contraseñas',
                'patrones': [
                    r'hydra.*-l.*-P',
                    r'medusa.*-h.*-u',
                    r'ncrack.*-U.*-P',
                    r'hashcat.*-m.*[0-9]+'
                ],
                'umbral_eventos': 3,
                'ventana_tiempo': 600,
                'severidad': 'alto'
            },
            'network_discovery': {
                'descripcion': 'Descubrimiento de red',
                'patrones': [
                    r'nmap.*-sn.*\/[0-9]+',
                    r'masscan.*--rate',
                    r'zmap.*-p.*[0-9]+',
                    r'netdiscover.*-r'
                ],
                'umbral_eventos': 2,
                'ventana_tiempo': 120,
                'severidad': 'medio'
            },
            'privilege_abuse': {
                'descripcion': 'Abuso de privilegios',
                'patrones': [
                    r'sudo.*su.*-',
                    r'su.*root.*-c',
                    r'pkexec.*--user.*root',
                    r'doas.*-u.*root'
                ],
                'umbral_eventos': 2,
                'ventana_tiempo': 300,
                'severidad': 'alto'
            }
        }
    
    def _inicializar_sistema_correlacion_avanzado(self) -> None:
        """
        Inicializar sistema de correlación avanzado para detección de APTs.
        """
        try:
            # Ventanas de tiempo para correlación
            self.ventanas_correlacion = {
                'inmediata': 60,      # 1 minuto
                'corta': 300,         # 5 minutos  
                'media': 1800,        # 30 minutos
                'larga': 7200         # 2 horas
            }
            
            # Cola de eventos para correlación en tiempo real
            self.cola_eventos_correlacion = deque(maxlen=self.config_optimizada['max_eventos_memoria'])
            
            # Índices para búsqueda rápida
            self.indices_eventos = {
                'por_ip': defaultdict(list),
                'por_usuario': defaultdict(list),
                'por_proceso': defaultdict(list),
                'por_tipo': defaultdict(list)
            }
            
            # Estadísticas baseline
            self.baseline_comportamiento = {
                'conexiones_hora': {},
                'logins_usuario': {},
                'procesos_frecuentes': {},
                'horarios_actividad': {},
                'ips_confiables': set(),
                'comandos_baseline': {},
                'usuarios_activos': set()
            }
            
            # Configuración de machine learning básico
            self.ml_config = {
                'ventana_aprendizaje': 86400,  # 24 horas
                'minimo_muestras': 100,
                'factor_desviacion': 2.0,
                'actualizacion_frecuencia': 3600  # 1 hora
            }
            
            # Técnicas MITRE ATT&CK mapping
            self.mitre_techniques = {
                'T1078': 'Valid Accounts',
                'T1110': 'Brute Force', 
                'T1068': 'Exploitation for Privilege Escalation',
                'T1053': 'Scheduled Task/Job',
                'T1021': 'Remote Services',
                'T1005': 'Data from Local System',
                'T1041': 'Exfiltration Over C2 Channel',
                'T1070': 'Indicator Removal on Host',
                'T1055': 'Process Injection',
                'T1190': 'Exploit Public-Facing Application',
                'T1059': 'Command and Scripting Interpreter',
                'T1083': 'File and Directory Discovery',
                'T1018': 'Remote System Discovery',
                'T1057': 'Process Discovery'
            }
            
            # Sistema de scoring avanzado
            self.scoring_system = {
                'factores': {
                    'usuario_privilegiado': 1.5,
                    'horario_inusual': 1.3,
                    'ip_externa': 1.4,
                    'comando_sospechoso': 1.8,
                    'multiples_fallos': 2.0,
                    'escalada_privilegios': 2.5,
                    'acceso_archivos_criticos': 2.2,
                    'red_anomala': 1.6,
                    'proceso_inusual': 1.7,
                    'patron_apt': 3.0
                },
                'umbrales': {
                    'informativo': 0.5,
                    'bajo': 1.0,
                    'medio': 2.5,
                    'alto': 4.0,
                    'critico': 6.0
                }
            }
            
            # Contadores para análisis estadístico
            self.contadores_eventos = {
                'total_eventos': 0,
                'eventos_por_hora': defaultdict(int),
                'eventos_por_usuario': defaultdict(int),
                'eventos_por_ip': defaultdict(int),
                'patrones_detectados': defaultdict(int)
            }
            
            self.log("Sistema de correlación avanzado inicializado")
            
        except Exception as e:
            self.log(f"Error inicializando correlación avanzada: {e}")
    
    def detectar_amenazas_tiempo_real(self, evento: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detectar amenazas en tiempo real usando patrones de ataques conocidos.
        
        Args:
            evento: Evento de seguridad a analizar
            
        Returns:
            Lista de amenazas detectadas
        """
        amenazas_detectadas = []
        
        try:
            # Agregar evento a cola de correlación
            self.cola_eventos_correlacion.append(evento)
            self._actualizar_indices_evento(evento)
            
            # Verificar contra patrones de ataques conocidos
            for nombre_ataque, patron in self.patrones_ataques_conocidos.items():
                if self._evento_coincide_patron(evento, patron):
                    # Buscar eventos relacionados en ventana de tiempo
                    eventos_relacionados = self._buscar_eventos_ventana_tiempo(
                        evento, patron['ventana_tiempo'], patron['patrones']
                    )
                    
                    if len(eventos_relacionados) >= patron['umbral_eventos']:
                        amenaza = {
                            'tipo_amenaza': nombre_ataque,
                            'descripcion': patron['descripcion'],
                            'severidad': patron['severidad'],
                            'eventos_relacionados': len(eventos_relacionados),
                            'timestamp_deteccion': datetime.now().isoformat(),
                            'evento_trigger': evento,
                            'confianza': self._calcular_confianza_amenaza(eventos_relacionados, patron),
                            'recomendaciones': self._generar_recomendaciones_amenaza(nombre_ataque)
                        }
                        amenazas_detectadas.append(amenaza)
                        
                        # Registrar la amenaza en la base de datos
                        self._registrar_amenaza_detectada(amenaza)
            
            # Análisis de anomalías comportamentales
            anomalias = self._detectar_anomalias_comportamiento(evento)
            amenazas_detectadas.extend(anomalias)
            
        except Exception as e:
            self.log(f"Error detectando amenazas en tiempo real: {e}")
        
        return amenazas_detectadas
    
    def _evento_coincide_patron(self, evento: Dict[str, Any], patron: Dict[str, Any]) -> bool:
        """Verificar si un evento coincide con un patrón de ataque."""
        try:
            contenido_evento = f"{evento.get('comando', '')} {evento.get('archivo', '')} {evento.get('proceso', '')}"
            
            for regex_patron in patron['patrones']:
                if re.search(regex_patron, contenido_evento, re.IGNORECASE):
                    return True
            return False
        except Exception:
            return False
    
    def _buscar_eventos_ventana_tiempo(self, evento_base: Dict[str, Any], ventana_segundos: int, patrones: List[str]) -> List[Dict[str, Any]]:
        """Buscar eventos relacionados en una ventana de tiempo."""
        try:
            tiempo_base = datetime.fromisoformat(evento_base.get('timestamp', datetime.now().isoformat()))
            eventos_relacionados = []
            
            for evento in self.cola_eventos_correlacion:
                try:
                    tiempo_evento = datetime.fromisoformat(evento.get('timestamp', datetime.now().isoformat()))
                    diferencia = abs((tiempo_evento - tiempo_base).total_seconds())
                    
                    if diferencia <= ventana_segundos:
                        # Verificar si coincide con algún patrón
                        contenido = f"{evento.get('comando', '')} {evento.get('archivo', '')} {evento.get('proceso', '')}"
                        for patron in patrones:
                            if re.search(patron, contenido, re.IGNORECASE):
                                eventos_relacionados.append(evento)
                                break
                except Exception:
                    continue
            
            return eventos_relacionados
        except Exception:
            return []
    
    def _calcular_confianza_amenaza(self, eventos: List[Dict[str, Any]], patron: Dict[str, Any]) -> float:
        """Calcular nivel de confianza de la amenaza detectada."""
        try:
            # Factores que aumentan la confianza
            factor_cantidad = min(len(eventos) / patron['umbral_eventos'], 2.0)
            factor_diversidad = len(set(e.get('ip_origen', 'unknown') for e in eventos)) / len(eventos)
            factor_velocidad = 1.0  # Simplificado por ahora
            
            confianza = (factor_cantidad * 0.5) + (factor_diversidad * 0.3) + (factor_velocidad * 0.2)
            return min(confianza, 1.0)
        except Exception:
            return 0.5  # Confianza media por defecto
    
    def _generar_recomendaciones_amenaza(self, tipo_amenaza: str) -> List[str]:
        """Generar recomendaciones específicas para cada tipo de amenaza."""
        recomendaciones_mapa = {
            'brute_force': [
                'Implementar fail2ban para bloquear IPs atacantes',
                'Configurar autenticación de dos factores',
                'Revisar políticas de contraseñas',
                'Monitorear logs de autenticación'
            ],
            'privilege_escalation': [
                'Revisar permisos sudo inmediatamente',
                'Auditar cuentas con privilegios elevados',
                'Verificar integridad de archivos del sistema',
                'Implementar principio de menor privilegio'
            ],
            'lateral_movement': [
                'Segmentar la red en VLANs',
                'Monitorear conexiones SSH/RDP',
                'Implementar autenticación basada en certificados',
                'Revisar logs de acceso remoto'
            ],
            'data_exfiltration': [
                'Bloquear transferencias no autorizadas',
                'Monitorear tráfico de red saliente',
                'Implementar DLP (Data Loss Prevention)',
                'Auditar accesos a datos sensibles'
            ],
            'port_scanning': [
                'Configurar IDS/IPS para detectar escaneos',
                'Cerrar puertos innecesarios',
                'Implementar rate limiting',
                'Monitorear conexiones sospechosas'
            ],
            'malware_activity': [
                'Ejecutar análisis antimalware completo',
                'Aislar el sistema comprometido',
                'Revisar integridad de archivos',
                'Verificar conexiones de red maliciosas'
            ],
            'persistence_mechanism': [
                'Revisar crontabs y servicios del sistema',
                'Verificar archivos de configuración',
                'Auditar cambios en el sistema',
                'Restaurar desde backup limpio si es necesario'
            ]
        }
        
        return recomendaciones_mapa.get(tipo_amenaza, ['Revisar logs de seguridad', 'Contactar equipo de respuesta a incidentes'])
    
    def obtener_dashboard_amenazas(self) -> Dict[str, Any]:
        """
        Obtener dashboard consolidado de amenazas para la vista.
        
        Returns:
            Dict con estadísticas y alertas actuales
        """
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            # Obtener estadísticas recientes (últimas 24 horas)
            hace_24h = (datetime.now() - timedelta(hours=24)).isoformat()
            
            # Amenazas por severidad
            cursor.execute('''
                SELECT severidad, COUNT(*) 
                FROM amenazas_detectadas 
                WHERE timestamp > ? 
                GROUP BY severidad
            ''', (hace_24h,))
            
            amenazas_por_severidad = dict(cursor.fetchall())
            
            # Top 10 tipos de amenazas
            cursor.execute('''
                SELECT tipo_amenaza, COUNT(*) as count
                FROM amenazas_detectadas 
                WHERE timestamp > ? 
                GROUP BY tipo_amenaza 
                ORDER BY count DESC 
                LIMIT 10
            ''', (hace_24h,))
            
            top_amenazas = cursor.fetchall()
            
            # IPs más activas
            cursor.execute('''
                SELECT ip_origen, COUNT(*) as count
                FROM eventos_seguridad 
                WHERE timestamp > ? AND ip_origen IS NOT NULL
                GROUP BY ip_origen 
                ORDER BY count DESC 
                LIMIT 10
            ''', (hace_24h,))
            
            ips_activas = cursor.fetchall()
            
            # Alertas críticas recientes
            cursor.execute('''
                SELECT tipo_amenaza, descripcion, timestamp, confianza
                FROM amenazas_detectadas 
                WHERE severidad = 'critico' AND timestamp > ?
                ORDER BY timestamp DESC 
                LIMIT 5
            ''', (hace_24h,))
            
            alertas_criticas = [
                {
                    'tipo': row[0],
                    'descripcion': row[1], 
                    'timestamp': row[2],
                    'confianza': row[3]
                }
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            return {
                'timestamp_dashboard': datetime.now().isoformat(),
                'periodo_analisis': '24 horas',
                'amenazas_por_severidad': amenazas_por_severidad,
                'top_tipos_amenazas': top_amenazas,
                'ips_mas_activas': ips_activas,
                'alertas_criticas_recientes': alertas_criticas,
                'total_eventos_24h': sum(amenazas_por_severidad.values()),
                'estado_sistema': self._evaluar_estado_seguridad(amenazas_por_severidad)
            }
            
        except Exception as e:
            self.log(f"Error generando dashboard: {e}")
            return {
                'error': str(e),
                'timestamp_dashboard': datetime.now().isoformat()
            }
    
    # =========================================
    # MÉTODOS AUXILIARES PARA CORRELACIÓN
    # =========================================
    
    def _actualizar_indices_evento(self, evento: Dict[str, Any]) -> None:
        """Actualizar índices para búsqueda rápida de eventos."""
        try:
            # Índice por IP origen
            if evento.get('ip_origen'):
                self.indices_eventos['por_ip'][evento['ip_origen']].append(evento)
            
            # Índice por usuario
            if evento.get('usuario'):
                self.indices_eventos['por_usuario'][evento['usuario']].append(evento)
            
            # Índice por proceso
            if evento.get('proceso'):
                self.indices_eventos['por_proceso'][evento['proceso']].append(evento)
            
            # Índice por tipo de evento
            if evento.get('tipo_evento'):
                self.indices_eventos['por_tipo'][evento['tipo_evento']].append(evento)
                
        except Exception as e:
            self.log(f"Error actualizando índices: {e}")
    
    def _registrar_amenaza_detectada(self, amenaza: Dict[str, Any]) -> None:
        """Registrar amenaza detectada en la base de datos."""
        try:
            conn = sqlite3.connect(self.base_datos_siem)
            cursor = conn.cursor()
            
            # Crear tabla si no existe
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS amenazas_detectadas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    tipo_amenaza TEXT,
                    descripcion TEXT,
                    severidad TEXT,
                    eventos_relacionados INTEGER,
                    confianza REAL,
                    estado TEXT DEFAULT 'nueva'
                )
            ''')
            
            cursor.execute('''
                INSERT INTO amenazas_detectadas 
                (timestamp, tipo_amenaza, descripcion, severidad, eventos_relacionados, confianza)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                amenaza['timestamp_deteccion'],
                amenaza['tipo_amenaza'],
                amenaza['descripcion'],
                amenaza['severidad'],
                amenaza['eventos_relacionados'],
                amenaza['confianza']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.log(f"Error registrando amenaza: {e}")
    
    def _detectar_anomalias_comportamiento(self, evento: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detectar anomalías en el comportamiento normal del sistema."""
        anomalias = []
        
        try:
            # Anomalía: Conexiones fuera de horario habitual
            hora_actual = datetime.now().hour
            if evento.get('tipo_evento') == 'conexion' and (hora_actual < 6 or hora_actual > 22):
                anomalias.append({
                    'tipo_amenaza': 'actividad_fuera_horario',
                    'descripcion': 'Actividad de red fuera del horario laboral',
                    'severidad': 'medio',
                    'confianza': 0.7,
                    'evento_trigger': evento,
                    'timestamp_deteccion': datetime.now().isoformat()
                })
            
            # Anomalía: Usuario ejecutando comandos inusuales
            if evento.get('comando') and evento.get('usuario'):
                comandos_sospechosos = ['nc', 'netcat', 'python -c', 'perl -e', 'bash -i']
                comando = evento.get('comando', '')
                
                if any(cmd in comando.lower() for cmd in comandos_sospechosos):
                    anomalias.append({
                        'tipo_amenaza': 'comando_sospechoso',
                        'descripcion': f'Usuario {evento["usuario"]} ejecutó comando sospechoso',
                        'severidad': 'alto',
                        'confianza': 0.8,
                        'evento_trigger': evento,
                        'timestamp_deteccion': datetime.now().isoformat()
                    })
            
        except Exception as e:
            self.log(f"Error detectando anomalías: {e}")
        
        return anomalias
    
    def _evaluar_estado_seguridad(self, amenazas_por_severidad: Dict[str, int]) -> str:
        """Evaluar el estado general de seguridad del sistema."""
        try:
            criticas = amenazas_por_severidad.get('critico', 0)
            altas = amenazas_por_severidad.get('alto', 0)
            medias = amenazas_por_severidad.get('medio', 0)
            
            if criticas > 0:
                return 'critico'
            elif altas > 5:
                return 'alto_riesgo'
            elif altas > 0 or medias > 10:
                return 'riesgo_moderado'
            elif medias > 0:
                return 'bajo_riesgo'
            else:
                return 'seguro'
                
        except Exception:
            return 'desconocido'
