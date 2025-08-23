# -*- coding: utf-8 -*-
"""
ARESITOS - Sistema de Escaneo Consolidado
========================================

Punto de entrada principal para el sistema de escaneo consolidado.
Integra los escaneadores especializados en un interface unificada.

Arquitectura consolidada:
- EscaneadorSistema: Análisis completo del sistema operativo Kali Linux
- EscaneadorRed: Escaneo de red, IPs, puertos, DNS y servicios

Principios ARESITOS aplicados:
- Python nativo + Kali tools únicamente
- Sin dependencias externas
- Código limpio y conciso (SOLID/DRY)
- MVC arquitectura respetada
- Sin emojis/tokens (excepto Aresitos.ico/png)

Autor: DogSoulDev
Fecha: Agosto 2025
"""

from typing import Dict, List, Any, Optional
from datetime import datetime

# Importar escaneadores especializados
from .modelo_escaneador_sistema import EscaneadorSistema, ResultadoEscaneoSistema, TipoEscaneo, NivelCriticidad, SecurityError
from .modelo_escaneador_red import EscaneadorRed, ResultadoEscaneoRed

class EscaneadorCompleto:
    """
    Escaneador principal que coordina los escaneadores especializados.
    Mantiene compatibilidad con la interfaz existente.
    """
    
    def __init__(self, gestor_permisos=None):
        """Inicializar escaneador completo."""
        self.version = "3.0"  # Versión ARESITOS v3.0
        self.gestor_permisos = gestor_permisos
        self.escaneador_sistema = EscaneadorSistema()
        self.escaneador_red = EscaneadorRed()
        
        # Configuración básica
        self.configuracion = {
            'timeout_default': 30,
            'max_puertos': 1000,
            'escaneo_agresivo': False
        }
    
    def escanear_completo(self, objetivo: Optional[str] = None, tipo: str = "completo") -> Dict[str, Any]:
        """
        Realizar escaneo completo combinando sistema y red.
        
        Args:
            objetivo: IP o hostname objetivo (None para autodetección)
            tipo: Tipo de escaneo ("completo", "sistema", "red", "puertos", "servicios")
        
        Returns:
            Diccionario con resultados completos del escaneo
        """
        inicio = datetime.now()
        
        resultados = {
            'timestamp': inicio.isoformat(),
            'objetivo': objetivo,
            'tipo_escaneo': tipo,
            'sistema': {},
            'red': {},
            'resumen': {},
            'alertas_criticas': [],
            'tiempo_total': 0
        }
        
        try:
            # Escaneo del sistema si corresponde
            if tipo in ["completo", "sistema"]:
                self.log("Iniciando escaneo del sistema...")
                resultado_sistema = self.escaneador_sistema.escanear_sistema_completo()
                resultados['sistema'] = {
                    'procesos_sospechosos': resultado_sistema.procesos_sospechosos,
                    'servicios_activos': resultado_sistema.servicios_activos,
                    'archivos_modificados': resultado_sistema.archivos_modificados,
                    'permisos_incorrectos': resultado_sistema.permisos_incorrectos,
                    'logs_criticos': resultado_sistema.logs_criticos,
                    'uso_recursos': resultado_sistema.uso_recursos,
                    'integridad_sistema': resultado_sistema.integridad_sistema
                }
                
                # Agregar alertas críticas del sistema
                resultados['alertas_criticas'].extend(resultado_sistema.alertas_seguridad)
            
            # Escaneo de red si corresponde
            if tipo in ["completo", "red", "puertos", "servicios", "dns", "discovery", "web", "fingerprint"]:
                self.log("Iniciando escaneo de red...")
                resultado_red = self.escaneador_red.escanear_red_completo(objetivo, tipo)
                resultados['red'] = {
                    'objetivo': resultado_red.objetivo,
                    'puertos_abiertos': resultado_red.puertos_abiertos,
                    'servicios_detectados': resultado_red.servicios_detectados,
                    'informacion_dns': resultado_red.informacion_dns,
                    'hosts_descubiertos': resultado_red.hosts_descubiertos,
                    'fingerprint_sistema': resultado_red.fingerprint_sistema,
                    'servicios_web': resultado_red.servicios_web
                }
                
                # Generar alertas de red
                if len(resultado_red.puertos_abiertos) > 20:
                    resultados['alertas_criticas'].append(
                        f"ALERTA: {len(resultado_red.puertos_abiertos)} puertos abiertos detectados"
                    )
                
                # Verificar puertos de riesgo completo (50+ puertos críticos)
                puertos_riesgo = self._obtener_puertos_riesgo_completos()
                puertos_abiertos_riesgo = []
                
                for puerto_info in resultado_red.puertos_abiertos:
                    puerto_num = puerto_info.get('puerto', 0)
                    if puerto_num in puertos_riesgo:
                        riesgo_info = puertos_riesgo[puerto_num]
                        puerto_info['nivel_riesgo'] = riesgo_info['nivel']
                        puerto_info['descripcion_riesgo'] = riesgo_info['descripcion']
                        puerto_info['ataques_comunes'] = riesgo_info['ataques']
                        puertos_abiertos_riesgo.append(puerto_info)
                
                if puertos_abiertos_riesgo:
                    # Clasificar por nivel de riesgo
                    criticos = [p for p in puertos_abiertos_riesgo if p['nivel_riesgo'] == 'critico']
                    altos = [p for p in puertos_abiertos_riesgo if p['nivel_riesgo'] == 'alto']
                    medios = [p for p in puertos_abiertos_riesgo if p['nivel_riesgo'] == 'medio']
                    
                    if criticos:
                        resultados['alertas_criticas'].append(
                            f"CRITICO: Puertos de riesgo crítico abiertos: {[p['puerto'] for p in criticos]}"
                        )
                    if altos:
                        resultados['alertas_criticas'].append(
                            f"ALTO: Puertos de alto riesgo abiertos: {[p['puerto'] for p in altos]}"
                        )
                    if medios:
                        resultados['alertas_criticas'].append(
                            f"MEDIO: Puertos de riesgo medio abiertos: {[p['puerto'] for p in medios]}"
                        )
            
            # Generar resumen
            fin = datetime.now()
            tiempo_total = (fin - inicio).total_seconds()
            
            resultados['tiempo_total'] = tiempo_total
            resultados['resumen'] = {
                'procesos_sospechosos': len(resultados.get('sistema', {}).get('procesos_sospechosos', [])),
                'puertos_abiertos': len(resultados.get('red', {}).get('puertos_abiertos', [])),
                'servicios_detectados': len(resultados.get('red', {}).get('servicios_detectados', [])),
                'alertas_criticas': len(resultados['alertas_criticas']),
                'tiempo_ejecucion': f"{tiempo_total:.2f}s",
                'componentes_escaneados': []
            }
            
            if 'sistema' in resultados and resultados['sistema']:
                resultados['resumen']['componentes_escaneados'].append('Sistema')
            if 'red' in resultados and resultados['red']:
                resultados['resumen']['componentes_escaneados'].append('Red')
            
            resultados['exito'] = True
            
        except Exception as e:
            resultados['exito'] = False
            resultados['error'] = str(e)
            self.log(f"Error durante el escaneo: {e}")
        
        return resultados
    
    def log(self, mensaje: str):
        """Método de logging."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[ESCANEADOR] {timestamp}: {mensaje}")
    
    def _obtener_puertos_riesgo_completos(self) -> Dict[int, Dict[str, Any]]:
        """
        Obtener lista completa de puertos de riesgo en ciberseguridad.
        Basado en principios ARESITOS: información real de amenazas actuales.
        
        Returns:
            Diccionario con puerto como clave y información de riesgo como valor
        """
        return {
            # PUERTOS CRÍTICOS (máximo riesgo)
            20: {'nivel': 'critico', 'descripcion': 'FTP Data Transfer', 'ataques': ['FTP Bounce', 'Data Hijacking']},
            21: {'nivel': 'critico', 'descripcion': 'FTP Control', 'ataques': ['Brute Force', 'Anonymous Access', 'Buffer Overflow']},
            22: {'nivel': 'critico', 'descripcion': 'SSH', 'ataques': ['Brute Force', 'Key Theft', 'Lateral Movement']},
            23: {'nivel': 'critico', 'descripcion': 'Telnet', 'ataques': ['Credential Theft', 'Session Hijacking', 'MITM']},
            25: {'nivel': 'critico', 'descripcion': 'SMTP', 'ataques': ['Email Spoofing', 'Spam Relay', 'Data Exfiltration']},
            53: {'nivel': 'critico', 'descripcion': 'DNS', 'ataques': ['DNS Poisoning', 'Zone Transfer', 'DDoS Amplification']},
            69: {'nivel': 'critico', 'descripcion': 'TFTP', 'ataques': ['File Theft', 'Configuration Exposure', 'Boot Image Modification']},
            79: {'nivel': 'critico', 'descripcion': 'Finger', 'ataques': ['User Enumeration', 'Information Disclosure']},
            80: {'nivel': 'critico', 'descripcion': 'HTTP', 'ataques': ['XSS', 'SQLi', 'CSRF', 'LFI/RFI', 'Directory Traversal']},
            110: {'nivel': 'critico', 'descripcion': 'POP3', 'ataques': ['Credential Theft', 'Email Access', 'MITM']},
            111: {'nivel': 'critico', 'descripcion': 'RPCbind', 'ataques': ['RPC Enumeration', 'Service Discovery', 'Buffer Overflow']},
            135: {'nivel': 'critico', 'descripcion': 'RPC Endpoint Mapper', 'ataques': ['RPC Exploits', 'DCOM Attacks']},
            139: {'nivel': 'critico', 'descripcion': 'NetBIOS Session', 'ataques': ['SMB Relay', 'Null Sessions', 'Share Enumeration']},
            143: {'nivel': 'critico', 'descripcion': 'IMAP', 'ataques': ['Credential Theft', 'Email Access', 'Buffer Overflow']},
            161: {'nivel': 'critico', 'descripcion': 'SNMP', 'ataques': ['Community String Attacks', 'Information Disclosure', 'Device Control']},
            389: {'nivel': 'critico', 'descripcion': 'LDAP', 'ataques': ['LDAP Injection', 'Anonymous Bind', 'Directory Traversal']},
            443: {'nivel': 'critico', 'descripcion': 'HTTPS', 'ataques': ['SSL/TLS Attacks', 'Certificate Attacks', 'Web Application Attacks']},
            445: {'nivel': 'critico', 'descripcion': 'SMB', 'ataques': ['EternalBlue', 'SMB Relay', 'Pass-the-Hash', 'Ransomware']},
            993: {'nivel': 'critico', 'descripcion': 'IMAPS', 'ataques': ['SSL/TLS Attacks', 'Certificate Spoofing']},
            995: {'nivel': 'critico', 'descripcion': 'POP3S', 'ataques': ['SSL/TLS Attacks', 'Certificate Attacks']},
            
            # PUERTOS DE ALTO RIESGO
            113: {'nivel': 'alto', 'descripcion': 'Ident', 'ataques': ['User Enumeration', 'Information Disclosure']},
            119: {'nivel': 'alto', 'descripcion': 'NNTP', 'ataques': ['News Server Attacks', 'Information Disclosure']},
            135: {'nivel': 'alto', 'descripcion': 'RPC Endpoint', 'ataques': ['DCOM Exploits', 'Remote Code Execution']},
            264: {'nivel': 'alto', 'descripcion': 'BGMP', 'ataques': ['Routing Attacks', 'Network Manipulation']},
            389: {'nivel': 'alto', 'descripcion': 'LDAP', 'ataques': ['Directory Attacks', 'Authentication Bypass']},
            512: {'nivel': 'alto', 'descripcion': 'rexec', 'ataques': ['Remote Command Execution', 'Credential Theft']},
            513: {'nivel': 'alto', 'descripcion': 'rlogin', 'ataques': ['Remote Login Attacks', 'Session Hijacking']},
            514: {'nivel': 'alto', 'descripcion': 'rsh', 'ataques': ['Remote Shell Access', 'Command Injection']},
            515: {'nivel': 'alto', 'descripcion': 'LPD', 'ataques': ['Print Server Attacks', 'File Access']},
            636: {'nivel': 'alto', 'descripcion': 'LDAPS', 'ataques': ['SSL LDAP Attacks', 'Certificate Attacks']},
            1433: {'nivel': 'alto', 'descripcion': 'MSSQL', 'ataques': ['SQL Injection', 'Database Attacks', 'Privilege Escalation']},
            1521: {'nivel': 'alto', 'descripcion': 'Oracle DB', 'ataques': ['Database Attacks', 'TNS Poisoning', 'Privilege Escalation']},
            2049: {'nivel': 'alto', 'descripcion': 'NFS', 'ataques': ['File System Access', 'Data Theft', 'Mount Attacks']},
            3268: {'nivel': 'alto', 'descripcion': 'LDAP GC', 'ataques': ['Active Directory Attacks', 'Global Catalog Enumeration']},
            3269: {'nivel': 'alto', 'descripcion': 'LDAP GC SSL', 'ataques': ['AD SSL Attacks', 'Certificate Attacks']},
            3306: {'nivel': 'alto', 'descripcion': 'MySQL', 'ataques': ['SQL Injection', 'Database Attacks', 'Credential Theft']},
            3389: {'nivel': 'alto', 'descripcion': 'RDP', 'ataques': ['BlueKeep', 'RDP Brute Force', 'Session Hijacking', 'Credential Theft']},
            5432: {'nivel': 'alto', 'descripcion': 'PostgreSQL', 'ataques': ['SQL Injection', 'Database Attacks', 'Privilege Escalation']},
            5985: {'nivel': 'alto', 'descripcion': 'WinRM HTTP', 'ataques': ['Remote Management Attacks', 'Credential Theft']},
            5986: {'nivel': 'alto', 'descripcion': 'WinRM HTTPS', 'ataques': ['Encrypted Remote Attacks', 'Certificate Attacks']},
            6379: {'nivel': 'alto', 'descripcion': 'Redis', 'ataques': ['NoSQL Injection', 'Data Exposure', 'RCE via Lua']},
            8080: {'nivel': 'alto', 'descripcion': 'HTTP Alt', 'ataques': ['Web App Attacks', 'Proxy Attacks', 'Admin Panel Access']},
            8443: {'nivel': 'alto', 'descripcion': 'HTTPS Alt', 'ataques': ['SSL Web Attacks', 'Management Interface Attacks']},
            9200: {'nivel': 'alto', 'descripcion': 'Elasticsearch', 'ataques': ['Data Exposure', 'NoSQL Injection', 'Cluster Attacks']},
            27017: {'nivel': 'alto', 'descripcion': 'MongoDB', 'ataques': ['NoSQL Injection', 'Database Exposure', 'Replica Set Attacks']},
            
            # PUERTOS DE RIESGO MEDIO
            37: {'nivel': 'medio', 'descripcion': 'Time', 'ataques': ['Time-based Attacks', 'Information Disclosure']},
            42: {'nivel': 'medio', 'descripcion': 'WINS', 'ataques': ['Name Resolution Attacks', 'Network Mapping']},
            43: {'nivel': 'medio', 'descripcion': 'WHOIS', 'ataques': ['Information Gathering', 'Domain Enumeration']},
            49: {'nivel': 'medio', 'descripcion': 'TACACS', 'ataques': ['Authentication Attacks', 'Network Device Access']},
            70: {'nivel': 'medio', 'descripcion': 'Gopher', 'ataques': ['Protocol Tunneling', 'SSRF Attacks']},
            87: {'nivel': 'medio', 'descripcion': 'Link', 'ataques': ['Link Protocol Attacks', 'Network Manipulation']},
            88: {'nivel': 'medio', 'descripcion': 'Kerberos', 'ataques': ['Kerberoasting', 'Golden Ticket', 'Silver Ticket']},
            102: {'nivel': 'medio', 'descripcion': 'MS Exchange', 'ataques': ['Email Server Attacks', 'Information Disclosure']},
            179: {'nivel': 'medio', 'descripcion': 'BGP', 'ataques': ['Route Hijacking', 'Network Manipulation']},
            199: {'nivel': 'medio', 'descripcion': 'SMUX', 'ataques': ['SNMP Attacks', 'Network Management Attacks']},
            427: {'nivel': 'medio', 'descripcion': 'SLP', 'ataques': ['Service Discovery Attacks', 'Network Enumeration']},
            444: {'nivel': 'medio', 'descripcion': 'SNPP', 'ataques': ['Paging Attacks', 'Message Interception']},
            464: {'nivel': 'medio', 'descripcion': 'Kerberos Password', 'ataques': ['Password Change Attacks', 'Kerberos Exploits']},
            465: {'nivel': 'medio', 'descripcion': 'SMTPS', 'ataques': ['Email SSL Attacks', 'Certificate Attacks']},
            500: {'nivel': 'medio', 'descripcion': 'IKE', 'ataques': ['VPN Attacks', 'IPSec Exploits']},
            548: {'nivel': 'medio', 'descripcion': 'AFP', 'ataques': ['Apple File Attacks', 'Authentication Bypass']},
            554: {'nivel': 'medio', 'descripcion': 'RTSP', 'ataques': ['Media Stream Attacks', 'Buffer Overflow']},
            587: {'nivel': 'medio', 'descripcion': 'SMTP Submission', 'ataques': ['Email Relay Attacks', 'Authentication Bypass']},
            593: {'nivel': 'medio', 'descripcion': 'RPC over HTTP', 'ataques': ['HTTP RPC Attacks', 'Exchange Exploits']},
            631: {'nivel': 'medio', 'descripcion': 'IPP', 'ataques': ['Printer Attacks', 'CUPS Exploits']},
            749: {'nivel': 'medio', 'descripcion': 'Kerberos Admin', 'ataques': ['Admin Interface Attacks', 'Privilege Escalation']},
            750: {'nivel': 'medio', 'descripcion': 'Kerberos IV', 'ataques': ['Legacy Kerberos Attacks', 'Downgrade Attacks']},
            873: {'nivel': 'medio', 'descripcion': 'rsync', 'ataques': ['File Synchronization Attacks', 'Data Theft']},
            902: {'nivel': 'medio', 'descripcion': 'VMware Auth', 'ataques': ['Virtualization Attacks', 'VM Escape']},
            1194: {'nivel': 'medio', 'descripcion': 'OpenVPN', 'ataques': ['VPN Attacks', 'Traffic Interception']},
            1723: {'nivel': 'medio', 'descripcion': 'PPTP', 'ataques': ['VPN Attacks', 'Protocol Weakness Exploits']},
            2375: {'nivel': 'medio', 'descripcion': 'Docker', 'ataques': ['Container Escape', 'Docker API Attacks']},
            2376: {'nivel': 'medio', 'descripcion': 'Docker SSL', 'ataques': ['Encrypted Container Attacks', 'Certificate Attacks']},
            4444: {'nivel': 'medio', 'descripcion': 'Metasploit', 'ataques': ['Reverse Shell', 'Payload Delivery']},
            5060: {'nivel': 'medio', 'descripcion': 'SIP', 'ataques': ['VoIP Attacks', 'Call Hijacking']},
            5061: {'nivel': 'medio', 'descripcion': 'SIP TLS', 'ataques': ['Encrypted VoIP Attacks', 'TLS VoIP Exploits']},
            5900: {'nivel': 'medio', 'descripcion': 'VNC', 'ataques': ['Remote Desktop Attacks', 'Screen Hijacking']},
            6000: {'nivel': 'medio', 'descripcion': 'X11', 'ataques': ['X Server Attacks', 'Display Hijacking']},
            6667: {'nivel': 'medio', 'descripcion': 'IRC', 'ataques': ['Botnet C&C', 'IRC Exploits']},
            7001: {'nivel': 'medio', 'descripcion': 'Cassandra', 'ataques': ['NoSQL Database Attacks', 'Data Exposure']},
            8000: {'nivel': 'medio', 'descripcion': 'HTTP Alt', 'ataques': ['Web Application Attacks', 'Development Server Attacks']},
            8888: {'nivel': 'medio', 'descripcion': 'HTTP Alt', 'ataques': ['Web Panel Attacks', 'Proxy Attacks']},
            9000: {'nivel': 'medio', 'descripcion': 'SonarQube', 'ataques': ['Code Analysis Attacks', 'Information Disclosure']},
            9090: {'nivel': 'medio', 'descripcion': 'Prometheus', 'ataques': ['Metrics Exposure', 'Monitoring System Attacks']},
            9999: {'nivel': 'medio', 'descripcion': 'Urchin', 'ataques': ['Web Analytics Attacks', 'Data Exposure']},
            11211: {'nivel': 'medio', 'descripcion': 'Memcached', 'ataques': ['DDoS Amplification', 'Data Exposure']},
            50000: {'nivel': 'medio', 'descripcion': 'SAP', 'ataques': ['ERP Attacks', 'Business Logic Exploits']}
        }
    
    # =========================================
    # MÉTODOS DELEGADOS PARA COMPATIBILIDAD
    # =========================================
    
    # Métodos del escaneador de sistema
    def obtener_procesos_sistema(self) -> List[Dict[str, Any]]:
        """Delegar al escaneador de sistema."""
        return self.escaneador_sistema.escanear_procesos_sospechosos()
    
    def obtener_servicios_activos(self) -> List[Dict[str, Any]]:
        """Delegar al escaneador de sistema."""
        return self.escaneador_sistema.escanear_servicios_activos()
    
    def verificar_integridad_archivos(self, directorios: Optional[List[str]] = None) -> List[str]:
        """Delegar al escaneador de sistema."""
        return self.escaneador_sistema.verificar_integridad_archivos()
    
    def analizar_logs_sistema(self) -> List[str]:
        """Delegar al escaneador de sistema."""
        return self.escaneador_sistema.analizar_logs_seguridad()
    
    def detectar_rootkits(self) -> Dict[str, Any]:
        """Delegar al escaneador de sistema."""
        return self.escaneador_sistema.detectar_rootkits_basico()
    
    def obtener_uso_recursos(self) -> Dict[str, Any]:
        """Delegar al escaneador de sistema."""
        return self.escaneador_sistema.obtener_uso_recursos()
    
    # Métodos del escaneador de red
    def obtener_ip_local(self) -> str:
        """Delegar al escaneador de red."""
        return self.escaneador_red._autodetectar_objetivo()
    
    def escanear_puertos(self, objetivo: str, puertos: Optional[List[int]] = None, tipo: str = "tcp") -> List[Dict[str, Any]]:
        """Delegar al escaneador de red."""
        if tipo.lower() == "udp":
            return self.escaneador_red.escanear_puertos_udp(objetivo, puertos)
        else:
            return self.escaneador_red.escanear_puertos_tcp(objetivo, puertos)
    
    def detectar_servicios(self, objetivo: str, puertos_abiertos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Delegar al escaneador de red."""
        return self.escaneador_red.detectar_servicios_avanzados(objetivo, puertos_abiertos)
    
    def resolver_dns(self, hostname: str) -> Dict[str, Any]:
        """Delegar al escaneador de red."""
        return self.escaneador_red.resolver_dns(hostname)
    
    def descubrir_hosts(self, objetivo: str) -> List[Dict[str, Any]]:
        """Delegar al escaneador de red."""
        return self.escaneador_red.descubrir_hosts_red(objetivo)
    
    def fingerprint_objetivo(self, objetivo: str) -> Dict[str, Any]:
        """Delegar al escaneador de red."""
        return self.escaneador_red.fingerprint_sistema(objetivo)
    
    def escanear_servicios_web(self, objetivo: str, puertos: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Delegar al escaneador de red."""
        return self.escaneador_red.detectar_servicios_web(objetivo, puertos)
    
    # Métodos compatibles con versiones anteriores
    def escanear_sistema(self, tipo: str = "completo") -> Dict[str, Any]:
        """Compatibilidad: escanear solo sistema."""
        return self.escanear_completo(None, "sistema")
    
    def escanear_red_objetivo(self, objetivo: str, tipo: str = "puertos") -> Dict[str, Any]:
        """Compatibilidad: escanear objetivo de red."""
        return self.escanear_completo(objetivo, tipo)
    
    def escanear_puertos_objetivo(self, objetivo: str, rango_puertos: str = "1-1000") -> Dict[str, Any]:
        """Compatibilidad: escanear puertos específicos."""
        # Convertir rango a lista de puertos
        try:
            if '-' in rango_puertos:
                inicio, fin = map(int, rango_puertos.split('-'))
                puertos_lista = list(range(inicio, min(fin + 1, inicio + 1000)))  # Limitar a 1000 puertos
            else:
                puertos_lista = [int(rango_puertos)]
        except ValueError:
            puertos_lista = list(range(1, 1001))  # Default range
        
        puertos = self.escanear_puertos(objetivo, puertos_lista)
        return {
            'objetivo': objetivo,
            'puertos_abiertos': puertos,
            'timestamp': datetime.now().isoformat()
        }

# Aliases para compatibilidad con código existente
EscaneadorAvanzado = EscaneadorCompleto
EscaneadorAvanzadoReal = EscaneadorCompleto
EscaneadorBase = EscaneadorCompleto  # Alias adicional para compatibilidad
Escaneador = EscaneadorCompleto

# Funciones de utilidad para compatibilidad
def crear_escaneador(gestor_permisos=None) -> EscaneadorCompleto:
    """Crear instancia del escaneador principal."""
    return EscaneadorCompleto(gestor_permisos)

def obtener_tipos_escaneo() -> List[str]:
    """Obtener tipos de escaneo disponibles."""
    return ["completo", "sistema", "red", "puertos", "servicios", "dns", "discovery", "web", "fingerprint"]

def obtener_niveles_criticidad() -> List[str]:
    """Obtener niveles de criticidad disponibles."""
    return ["baja", "media", "alta", "critica"]

# Información del módulo
__version__ = "3.0.0"
__author__ = "DogSoulDev"
__description__ = "Sistema de escaneo consolidado para ARESITOS"

# Exportaciones principales
__all__ = [
    'EscaneadorCompleto',
    'EscaneadorAvanzado', 
    'EscaneadorAvanzadoReal',
    'EscaneadorBase',
    'Escaneador',
    'EscaneadorSistema',
    'EscaneadorRed',
    'SecurityError',
    'TipoEscaneo',
    'NivelCriticidad',
    'crear_escaneador',
    'obtener_tipos_escaneo',
    'obtener_niveles_criticidad'
]
