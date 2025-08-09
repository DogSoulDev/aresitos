# -*- coding: utf-8 -*-

import datetime
import os
import platform
import subprocess
import re
import json
import time
from typing import Dict, List, Any, Optional
from collections import deque, defaultdict

class SIEM:
    def __init__(self):
        self.eventos = deque(maxlen=10000)
        self.alertas = deque(maxlen=1000)
        self.estadisticas = defaultdict(int)
        self.es_kali = self._detectar_kali()
        
        # Patrones de detección de amenazas
        self.patrones_sospechosos = {
            'login_fallido': [
                r'authentication failure',
                r'failed password',
                r'invalid user',
                r'connection closed by authenticating user'
            ],
            'escalacion_privilegios': [
                r'sudo.*failed',
                r'su.*failed',
                r'pam_unix.*authentication failure'
            ],
            'actividad_red_sospechosa': [
                r'port scan',
                r'syn flood',
                r'invalid packet',
                r'connection reset'
            ],
            'acceso_archivos_criticos': [
                r'/etc/passwd',
                r'/etc/shadow',
                r'/etc/sudoers',
                r'/root/'
            ],
            'procesos_maliciosos': [
                r'nc -l',
                r'netcat.*-l',
                r'/tmp/.*\.sh',
                r'wget.*tmp',
                r'curl.*tmp'
            ]
        }
        
        # Configuración de alertas
        self.config_alertas = {
            'intentos_login_fallido_umbral': 5,
            'ventana_tiempo_login': 300,  # 5 minutos
            'conexiones_sospechosas_umbral': 10,
            'accesos_archivos_criticos_umbral': 3
        }
        
        # Cache para análisis temporal
        self.eventos_temporales = defaultdict(list)
    
    def _detectar_kali(self) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            with open('/etc/os-release', 'r') as f:
                contenido = f.read().lower()
                return 'kali' in contenido or 'debian' in contenido
        except:
            return False
    
    def registrar_evento(self, tipo: str, descripcion: str, severidad: str = "INFO", 
                        origen: str = "SISTEMA", metadata: Optional[Dict] = None) -> Dict[str, Any]:
        timestamp = datetime.datetime.now()
        
        evento = {
            'id': f"{timestamp.timestamp()}_{len(self.eventos)}",
            'timestamp': timestamp,
            'tipo': tipo,
            'descripcion': descripcion,
            'severidad': severidad,
            'origen': origen,
            'sistema': platform.system(),
            'metadata': metadata or {}
        }
        
        self.eventos.append(evento)
        self.estadisticas[tipo] += 1
        self.estadisticas[f"severidad_{severidad}"] += 1
        
        # Análisis en tiempo real
        self._analizar_evento_tiempo_real(evento)
        
        return evento
    
    def _analizar_evento_tiempo_real(self, evento: Dict[str, Any]):
        # Agregar evento a análisis temporal
        minuto_actual = int(time.time() // 60)
        self.eventos_temporales[minuto_actual].append(evento)
        
        # Limpiar eventos antiguos (más de 10 minutos)
        minutos_a_eliminar = [m for m in self.eventos_temporales.keys() if m < minuto_actual - 10]
        for minuto in minutos_a_eliminar:
            del self.eventos_temporales[minuto]
        
        # Detectar patrones sospechosos
        if evento['tipo'] in ['LOGIN_FALLIDO', 'AUTH_FAILURE']:
            self._detectar_ataques_fuerza_bruta()
        elif evento['tipo'] in ['ACCESO_ARCHIVO', 'FILE_ACCESS']:
            self._detectar_acceso_archivos_criticos(evento)
        elif evento['tipo'] in ['CONEXION_RED', 'NETWORK']:
            self._detectar_actividad_red_sospechosa(evento)
    
    def _detectar_ataques_fuerza_bruta(self):
        ahora = time.time()
        ventana_inicio = ahora - self.config_alertas['ventana_tiempo_login']
        
        # Contar intentos de login fallidos en la ventana de tiempo
        intentos_fallidos = 0
        ips_origen = defaultdict(int)
        
        for minuto, eventos_minuto in self.eventos_temporales.items():
            if minuto * 60 >= ventana_inicio:
                for evento in eventos_minuto:
                    if evento['tipo'] in ['LOGIN_FALLIDO', 'AUTH_FAILURE']:
                        intentos_fallidos += 1
                        ip_origen = evento['metadata'].get('ip_origen', 'desconocida')
                        ips_origen[ip_origen] += 1
        
        if intentos_fallidos >= self.config_alertas['intentos_login_fallido_umbral']:
            self._generar_alerta(
                'ATAQUE_FUERZA_BRUTA',
                f"Detectados {intentos_fallidos} intentos de login fallidos en {self.config_alertas['ventana_tiempo_login']/60:.0f} minutos",
                'CRITICA',
                {'intentos': intentos_fallidos, 'ips_origen': dict(ips_origen)}
            )
    
    def _detectar_acceso_archivos_criticos(self, evento: Dict[str, Any]):
        archivo = evento['metadata'].get('archivo', '')
        for patron in self.patrones_sospechosos['acceso_archivos_criticos']:
            if re.search(patron, archivo):
                self._generar_alerta(
                    'ACCESO_ARCHIVO_CRITICO',
                    f"Acceso detectado a archivo crítico: {archivo}",
                    'ALTA',
                    {'archivo': archivo, 'usuario': evento['metadata'].get('usuario')}
                )
                break
    
    def _detectar_actividad_red_sospechosa(self, evento: Dict[str, Any]):
        descripcion = evento['descripcion'].lower()
        for categoria, patrones in self.patrones_sospechosos.items():
            if categoria == 'actividad_red_sospechosa':
                for patron in patrones:
                    if re.search(patron, descripcion):
                        self._generar_alerta(
                            'ACTIVIDAD_RED_SOSPECHOSA',
                            f"Actividad de red sospechosa detectada: {patron}",
                            'MEDIA',
                            {'patron_detectado': patron, 'descripcion_original': evento['descripcion']}
                        )
                        break
    
    def _generar_alerta(self, tipo: str, mensaje: str, severidad: str, metadata: Dict[str, Any]):
        alerta = {
            'id': f"ALERT_{time.time()}_{len(self.alertas)}",
            'timestamp': datetime.datetime.now(),
            'tipo': tipo,
            'mensaje': mensaje,
            'severidad': severidad,
            'metadata': metadata,
            'estado': 'NUEVA'
        }
        
        self.alertas.append(alerta)
        
        # Registrar como evento también
        self.registrar_evento(
            'ALERTA_GENERADA',
            f"Alerta {severidad}: {mensaje}",
            severidad,
            'SIEM',
            metadata
        )
    
    def analizar_logs_sistema_avanzado(self) -> Dict[str, Any]:
        if not self.es_kali:
            return {'error': 'Análisis limitado - Optimizado para Kali Linux'}
        
        analisis = {
            'logs_analizados': [],
            'eventos_criticos': [],
            'resumen_seguridad': {},
            'recomendaciones': []
        }
        
        rutas_logs = {
            '/var/log/auth.log': 'autenticacion',
            '/var/log/syslog': 'sistema',
            '/var/log/kern.log': 'kernel',
            '/var/log/fail2ban.log': 'fail2ban',
            '/var/log/apache2/access.log': 'apache_access',
            '/var/log/apache2/error.log': 'apache_error',
            '/var/log/nginx/access.log': 'nginx_access',
            '/var/log/nginx/error.log': 'nginx_error'
        }
        
        for ruta_log, categoria in rutas_logs.items():
            if os.path.exists(ruta_log):
                try:
                    eventos_encontrados = self._analizar_log_especifico(ruta_log, categoria)
                    analisis['logs_analizados'].append({
                        'archivo': ruta_log,
                        'categoria': categoria,
                        'eventos_encontrados': len(eventos_encontrados),
                        'eventos': eventos_encontrados[:20]  # Limitar para rendimiento
                    })
                    analisis['eventos_criticos'].extend(eventos_encontrados)
                    
                except PermissionError:
                    analisis['logs_analizados'].append({
                        'archivo': ruta_log,
                        'error': 'Sin permisos de lectura'
                    })
                except Exception as e:
                    analisis['logs_analizados'].append({
                        'archivo': ruta_log,
                        'error': str(e)
                    })
        
        # Generar resumen de seguridad
        analisis['resumen_seguridad'] = self._generar_resumen_seguridad(analisis['eventos_criticos'])
        analisis['recomendaciones'] = self._generar_recomendaciones_seguridad(analisis['resumen_seguridad'])
        
        return analisis
    
    def _analizar_log_especifico(self, ruta_log: str, categoria: str) -> List[Dict[str, Any]]:
        eventos_encontrados = []
        
        try:
            # Usar tail para obtener las últimas líneas del log
            cmd = ['tail', '-n', '1000', ruta_log]
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if resultado.returncode == 0:
                lineas = resultado.stdout.split('\n')
                
                for linea in lineas:
                    if linea.strip():
                        evento = self._parsear_linea_log(linea, categoria)
                        if evento:
                            eventos_encontrados.append(evento)
                            
                            # Registrar eventos críticos en el SIEM
                            if evento['severidad'] in ['CRITICA', 'ALTA']:
                                self.registrar_evento(
                                    f"LOG_{categoria.upper()}",
                                    evento['mensaje'],
                                    evento['severidad'],
                                    f"LOG:{ruta_log}",
                                    evento['metadata']
                                )
            
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        return eventos_encontrados
    
    def _parsear_linea_log(self, linea: str, categoria: str) -> Optional[Dict[str, Any]]:
        # Análisis básico de patrones por categoría
        linea_lower = linea.lower()
        
        # Detectar patrones sospechosos
        for tipo_amenaza, patrones in self.patrones_sospechosos.items():
            for patron in patrones:
                if re.search(patron, linea_lower):
                    severidad = self._determinar_severidad_patron(tipo_amenaza)
                    return {
                        'timestamp': self._extraer_timestamp_log(linea),
                        'categoria': categoria,
                        'tipo_amenaza': tipo_amenaza,
                        'patron_detectado': patron,
                        'mensaje': linea[:200],  # Limitar longitud
                        'severidad': severidad,
                        'metadata': {
                            'linea_completa': linea,
                            'categoria_log': categoria
                        }
                    }
        
        return None
    
    def _determinar_severidad_patron(self, tipo_amenaza: str) -> str:
        severidades = {
            'login_fallido': 'MEDIA',
            'escalacion_privilegios': 'ALTA',
            'actividad_red_sospechosa': 'MEDIA',
            'acceso_archivos_criticos': 'ALTA',
            'procesos_maliciosos': 'CRITICA'
        }
        return severidades.get(tipo_amenaza, 'BAJA')
    
    def _extraer_timestamp_log(self, linea: str) -> Optional[datetime.datetime]:
        # Intentar extraer timestamp común de logs de Linux
        patron_fecha = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        match = re.search(patron_fecha, linea)
        if match:
            try:
                fecha_str = match.group(1)
                # Agregar año actual
                fecha_completa = f"{datetime.datetime.now().year} {fecha_str}"
                return datetime.datetime.strptime(fecha_completa, "%Y %b %d %H:%M:%S")
            except:
                pass
        return None
    
    def _generar_resumen_seguridad(self, eventos_criticos: List[Dict[str, Any]]) -> Dict[str, Any]:
        resumen = {
            'total_eventos_criticos': len(eventos_criticos),
            'tipos_amenazas': defaultdict(int),
            'severidades': defaultdict(int),
            'categorias': defaultdict(int),
            'tendencias': {}
        }
        
        for evento in eventos_criticos:
            resumen['tipos_amenazas'][evento.get('tipo_amenaza', 'desconocido')] += 1
            resumen['severidades'][evento.get('severidad', 'BAJA')] += 1
            resumen['categorias'][evento.get('categoria', 'desconocido')] += 1
        
        # Convertir defaultdicts a dicts normales
        resumen['tipos_amenazas'] = dict(resumen['tipos_amenazas'])
        resumen['severidades'] = dict(resumen['severidades'])
        resumen['categorias'] = dict(resumen['categorias'])
        
        return resumen
    
    def _generar_recomendaciones_seguridad(self, resumen: Dict[str, Any]) -> List[str]:
        recomendaciones = []
        
        if resumen['severidades'].get('CRITICA', 0) > 0:
            recomendaciones.append("CRITICO: Se detectaron amenazas críticas. Revisar inmediatamente.")
        
        if resumen['tipos_amenazas'].get('login_fallido', 0) > 10:
            recomendaciones.append("Implementar fail2ban para prevenir ataques de fuerza bruta.")
        
        if resumen['tipos_amenazas'].get('escalacion_privilegios', 0) > 0:
            recomendaciones.append("👤 Revisar configuración de sudo y permisos de usuarios.")
        
        if resumen['tipos_amenazas'].get('acceso_archivos_criticos', 0) > 0:
            recomendaciones.append("📁 Implementar monitoreo adicional en archivos críticos del sistema.")
        
        if resumen['tipos_amenazas'].get('actividad_red_sospechosa', 0) > 5:
            recomendaciones.append("Considerar implementar un firewall más restrictivo.")
        
        if not recomendaciones:
            recomendaciones.append("No se detectaron amenazas críticas en el análisis actual.")
        
        return recomendaciones
    
    def obtener_alertas_activas(self, limite: int = 50) -> List[Dict[str, Any]]:
        alertas_activas = [a for a in self.alertas if a['estado'] == 'NUEVA']
        return list(alertas_activas)[-limite:]
    
    def marcar_alerta_como_revisada(self, alerta_id: str) -> bool:
        for alerta in self.alertas:
            if alerta['id'] == alerta_id:
                alerta['estado'] = 'REVISADA'
                alerta['timestamp_revision'] = datetime.datetime.now()
                return True
        return False
    
    def obtener_estadisticas_generales(self) -> Dict[str, Any]:
        ahora = datetime.datetime.now()
        hace_una_hora = ahora - datetime.timedelta(hours=1)
        hace_un_dia = ahora - datetime.timedelta(days=1)
        
        eventos_hora = [e for e in self.eventos if e['timestamp'] >= hace_una_hora]
        eventos_dia = [e for e in self.eventos if e['timestamp'] >= hace_un_dia]
        
        return {
            'total_eventos': len(self.eventos),
            'eventos_ultima_hora': len(eventos_hora),
            'eventos_ultimo_dia': len(eventos_dia),
            'total_alertas': len(self.alertas),
            'alertas_activas': len([a for a in self.alertas if a['estado'] == 'NUEVA']),
            'tipos_eventos': dict(self.estadisticas),
            'sistema': platform.system(),
            'es_kali': self.es_kali,
            'timestamp_ultima_actividad': self.eventos[-1]['timestamp'] if self.eventos else None
        }

# RESUMEN: Sistema SIEM avanzado con análisis de logs, detección de amenazas en tiempo real,
# generación de alertas automatizadas y recomendaciones de seguridad para Kali Linux.