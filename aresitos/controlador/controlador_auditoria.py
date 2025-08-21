# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador de Auditoría Avanzado
Controlador especializado en auditorías de seguridad completas para Kali Linux
"""

import subprocess
import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from aresitos.modelo.modelo_utilidades_sistema import ModeloUtilidadesSistema

class ControladorAuditoria:
    """
    Controlador avanzado para auditorías de seguridad.
    Integra múltiples herramientas de Kali Linux para análisis completo.
    """
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.utilidades_sistema = ModeloUtilidadesSistema()
        
        # Configuración de auditoría
        self.config_auditoria = {
            'timeout_herramientas': 300,  # 5 minutos por herramienta
            'nivel_detalle': 'completo',
            'incluir_reportes': True,
            'generar_recomendaciones': True
        }
        
        # Herramientas de auditoría disponibles
        self.herramientas_auditoria = {
            'lynis': 'Auditoría completa del sistema',
            'rkhunter': 'Detección de rootkits', 
            'chkrootkit': 'Verificación de rootkits',
            'linpeas': 'Escalada de privilegios Linux',
            'pspy': 'Monitoreo de procesos sin root',
            'clamav': 'Escaneo de malware'
        }
    
    def ejecutar_auditoria_lynis(self) -> Dict[str, Any]:
        """
        Ejecuta auditoría completa con Lynis.
        
        Returns:
            Diccionario con resultados de auditoría
        """
        resultado = {
            'herramienta': 'lynis',
            'timestamp': datetime.now().isoformat(),
            'exito': False,
            'puntuacion': 0,
            'vulnerabilidades': [],
            'recomendaciones': [],
            'reporte_completo': '',
            'archivos_generados': []
        }
        
        try:
            # Ejecutar Lynis con parámetros específicos
            comando = [
                'sudo', 'lynis', 
                'audit', 'system',
                '--auditor', 'ares-aegis',
                '--cronjob',  # Para salida parseable
                '--quiet'
            ]
            
            proceso = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=self.config_auditoria['timeout_herramientas']
            )
            
            if proceso.returncode == 0:
                resultado['exito'] = True
                resultado['reporte_completo'] = proceso.stdout
                
                # Parsear resultados de Lynis
                self._parsear_resultados_lynis(proceso.stdout, resultado)
                
                # Buscar archivos de reporte generados
                rutas_reportes = [
                    '/var/log/lynis.log',
                    '/var/log/lynis-report.dat'
                ]
                
                for ruta in rutas_reportes:
                    if Path(ruta).exists():
                        resultado['archivos_generados'].append(ruta)
            else:
                resultado['error'] = proceso.stderr
                
        except subprocess.TimeoutExpired:
            resultado['error'] = 'Timeout ejecutando Lynis'
        except FileNotFoundError:
            resultado['error'] = 'Lynis no encontrado - instalar con: apt install lynis'
        except Exception as e:
            resultado['error'] = str(e)
            
        return resultado
    
    def _parsear_resultados_lynis(self, salida: str, resultado: Dict[str, Any]):
        """Parsea la salida de Lynis para extraer información relevante."""
        lineas = salida.split('\n')
        
        for linea in lineas:
            # Extraer puntuación de seguridad
            if 'hardening index' in linea.lower():
                try:
                    # Buscar número en la línea
                    import re
                    numeros = re.findall(r'\d+', linea)
                    if numeros:
                        resultado['puntuacion'] = int(numeros[0])
                except:
                    pass
            
            # Extraer warnings/sugerencias
            if 'warning' in linea.lower():
                resultado['vulnerabilidades'].append(linea.strip())
            elif 'suggestion' in linea.lower():
                resultado['recomendaciones'].append(linea.strip())
    
    def ejecutar_deteccion_rootkits(self) -> Dict[str, Any]:
        """
        Ejecuta detección completa de rootkits con múltiples herramientas.
        
        Returns:
            Diccionario con resultados de detección
        """
        resultado = {
            'herramientas_usadas': [],
            'timestamp': datetime.now().isoformat(),
            'rootkits_detectados': [],
            'archivos_sospechosos': [],
            'recomendaciones': [],
            'exito': False
        }
        
        # Ejecutar rkhunter
        try:
            print(" Ejecutando rkhunter...")
            cmd_rkhunter = ['sudo', 'rkhunter', '--check', '--skip-keypress', '--report-warnings-only']
            
            proceso = subprocess.run(
                cmd_rkhunter,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            resultado['herramientas_usadas'].append('rkhunter')
            
            if 'warning' in proceso.stdout.lower() or 'infected' in proceso.stdout.lower():
                resultado['rootkits_detectados'].extend(
                    self._extraer_detecciones_rkhunter(proceso.stdout)
                )
                
        except Exception as e:
            resultado['errores_rkhunter'] = str(e)
        
        # Ejecutar chkrootkit
        try:
            print(" Ejecutando chkrootkit...")
            cmd_chkrootkit = ['sudo', 'chkrootkit']
            
            proceso = subprocess.run(
                cmd_chkrootkit,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            resultado['herramientas_usadas'].append('chkrootkit')
            
            if 'infected' in proceso.stdout.lower():
                resultado['rootkits_detectados'].extend(
                    self._extraer_detecciones_chkrootkit(proceso.stdout)
                )
                
        except Exception as e:
            resultado['errores_chkrootkit'] = str(e)
        
        # Generar recomendaciones
        if resultado['rootkits_detectados']:
            resultado['recomendaciones'].extend([
                "Revisar inmediatamente los rootkits detectados",
                "Ejecutar análisis forense adicional",
                "Considerar reinstalación del sistema si está comprometido"
            ])
        else:
            resultado['recomendaciones'].append("No se detectaron rootkits - sistema limpio")
        
        resultado['exito'] = len(resultado['herramientas_usadas']) > 0
        return resultado
    
    def _extraer_detecciones_rkhunter(self, salida: str) -> List[str]:
        """Extrae detecciones específicas de rkhunter."""
        detecciones = []
        lineas = salida.split('\n')
        
        for linea in lineas:
            if 'warning' in linea.lower() or 'infected' in linea.lower():
                detecciones.append(linea.strip())
        
        return detecciones
    
    def _extraer_detecciones_chkrootkit(self, salida: str) -> List[str]:
        """Extrae detecciones específicas de chkrootkit."""
        detecciones = []
        lineas = salida.split('\n')
        
        for linea in lineas:
            if 'infected' in linea.lower():
                detecciones.append(linea.strip())
        
        return detecciones
    
    def verificar_permisos_criticos(self) -> Dict[str, Any]:
        """
        Verifica permisos de archivos y directorios críticos del sistema.
        
        Returns:
            Diccionario con análisis de permisos
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'archivos_verificados': 0,
            'problemas_permisos': [],
            'archivos_mundo_escribible': [],
            'archivos_suid_sgid': [],
            'recomendaciones': []
        }
        
        # Archivos críticos del sistema a verificar
        archivos_criticos = [
            '/etc/passwd',
            '/etc/shadow', 
            '/etc/group',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/boot',
            '/usr/bin/sudo',
            '/usr/bin/su'
        ]
        
        try:
            for archivo in archivos_criticos:
                if os.path.exists(archivo):
                    resultado['archivos_verificados'] += 1
                    info_archivo = os.stat(archivo)
                    permisos = oct(info_archivo.st_mode)[-3:]
                    
                    # Verificar permisos problemáticos
                    if archivo == '/etc/shadow' and permisos != '640':
                        resultado['problemas_permisos'].append(
                            f"{archivo}: permisos {permisos} (debería ser 640)"
                        )
                    
                    elif archivo == '/etc/passwd' and permisos != '644':
                        resultado['problemas_permisos'].append(
                            f"{archivo}: permisos {permisos} (debería ser 644)"
                        )
            
            # Buscar archivos world-writable
            cmd_world_writable = [
                'find', '/', '-type', 'f', '-perm', '-002', 
                '!', '-path', '/proc/*', 
                '!', '-path', '/sys/*',
                '!', '-path', '/dev/*',
                '2>/dev/null'
            ]
            
            proceso = subprocess.run(
                cmd_world_writable,
                capture_output=True,
                text=True,
                timeout=60,
                shell=True
            )
            
            if proceso.stdout:
                resultado['archivos_mundo_escribible'] = proceso.stdout.strip().split('\n')[:10]  # Limitar a 10
            
            # Buscar archivos SUID/SGID
            cmd_suid = [
                'find', '/', '-type', 'f', 
                '(', '-perm', '-4000', '-o', '-perm', '-2000', ')',
                '!', '-path', '/proc/*',
                '2>/dev/null'
            ]
            
            proceso = subprocess.run(
                cmd_suid,
                capture_output=True, 
                text=True,
                timeout=60,
                shell=True
            )
            
            if proceso.stdout:
                resultado['archivos_suid_sgid'] = proceso.stdout.strip().split('\n')[:20]  # Limitar a 20
            
            # Generar recomendaciones
            if resultado['problemas_permisos']:
                resultado['recomendaciones'].append("Corregir permisos de archivos críticos del sistema")
            
            if resultado['archivos_mundo_escribible']:
                resultado['recomendaciones'].append("Revisar archivos con permisos de escritura global")
            
            if len(resultado['archivos_suid_sgid']) > 15:
                resultado['recomendaciones'].append("Revisar cantidad excesiva de archivos SUID/SGID")
        
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado
    
    def analizar_servicios_sistema(self) -> Dict[str, Any]:
        """
        Analiza servicios del sistema en busca de configuraciones inseguras.
        
        Returns:
            Diccionario con análisis de servicios
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'servicios_analizados': 0,
            'servicios_activos': [],
            'servicios_inseguros': [],
            'puertos_abiertos': [],
            'recomendaciones': []
        }
        
        try:
            # Obtener servicios activos
            cmd_servicios = ['systemctl', 'list-units', '--type=service', '--state=active', '--no-pager']
            
            proceso = subprocess.run(
                cmd_servicios,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proceso.returncode == 0:
                lineas = proceso.stdout.split('\n')
                for linea in lineas[1:]:  # Saltar encabezado
                    if '.service' in linea and 'active' in linea:
                        servicio = linea.split()[0]
                        resultado['servicios_activos'].append(servicio)
                        resultado['servicios_analizados'] += 1
            
            # Verificar servicios potencialmente inseguros
            servicios_riesgo = ['telnet', 'ftp', 'rsh', 'rlogin', 'tftp']
            for servicio in servicios_riesgo:
                if any(servicio in s for s in resultado['servicios_activos']):
                    resultado['servicios_inseguros'].append(f"{servicio}: protocolo inseguro activo")
            
            # Obtener puertos abiertos
            cmd_puertos = ['ss', '-tlnp']
            
            proceso = subprocess.run(
                cmd_puertos,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proceso.returncode == 0:
                lineas = proceso.stdout.split('\n')
                for linea in lineas[1:]:  # Saltar encabezado
                    if 'LISTEN' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            puerto_info = partes[3]
                            resultado['puertos_abiertos'].append(puerto_info)
            
            # Generar recomendaciones específicas
            if resultado['servicios_inseguros']:
                resultado['recomendaciones'].append("Deshabilitar servicios con protocolos inseguros")
            
            if len(resultado['puertos_abiertos']) > 10:
                resultado['recomendaciones'].append("Revisar cantidad excesiva de puertos abiertos")
            
            resultado['recomendaciones'].append("Revisar periódicamente servicios activos")
            
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado
    
    def ejecutar_auditoria_completa(self) -> Dict[str, Any]:
        """
        Ejecuta una auditoría completa del sistema.
        
        Returns:
            Diccionario con resultados consolidados
        """
        resultado_completo = {
            'timestamp_inicio': datetime.now().isoformat(),
            'timestamp_fin': None,
            'exito': False,
            'resumen_ejecutivo': {},
            'auditorias_individuales': {}
        }
        
        print(" Iniciando auditoría completa del sistema...")
        
        try:
            # 1. Auditoría Lynis
            print(" Ejecutando auditoría Lynis...")
            resultado_completo['auditorias_individuales']['lynis'] = self.ejecutar_auditoria_lynis()
            
            # 2. Detección de rootkits
            print("✓ Ejecutando detección de rootkits...")
            resultado_completo['auditorias_individuales']['rootkits'] = self.ejecutar_deteccion_rootkits()
            
            # 3. Verificación de permisos
            print(" Verificando permisos críticos...")
            resultado_completo['auditorias_individuales']['permisos'] = self.verificar_permisos_criticos()
            
            # 4. Análisis de servicios
            print(" Analizando servicios del sistema...")
            resultado_completo['auditorias_individuales']['servicios'] = self.analizar_servicios_sistema()
            
            resultado_completo['timestamp_fin'] = datetime.now().isoformat()
            resultado_completo['exito'] = True
            
            # Generar resumen ejecutivo
            resultado_completo['resumen_ejecutivo'] = self._generar_resumen_ejecutivo(
                resultado_completo['auditorias_individuales']
            )
            
            print("OK Auditoría completa finalizada")
            
        except Exception as e:
            resultado_completo['error'] = str(e)
            resultado_completo['timestamp_fin'] = datetime.now().isoformat()
        
        return resultado_completo
    
    def _generar_resumen_ejecutivo(self, auditorias: Dict[str, Any]) -> Dict[str, Any]:
        """Genera un resumen ejecutivo de todas las auditorías."""
        resumen = {
            'puntuacion_general': 0,
            'nivel_riesgo': 'bajo',
            'problemas_criticos': 0,
            'problemas_menores': 0,
            'recomendaciones_prioritarias': [],
            'estado_general': 'seguro'
        }
        
        try:
            # Calcular puntuación general
            if 'lynis' in auditorias and auditorias['lynis']['exito']:
                resumen['puntuacion_general'] = auditorias['lynis']['puntuacion']
            
            # Contar problemas críticos
            if 'rootkits' in auditorias:
                problemas_rootkits = len(auditorias['rootkits'].get('rootkits_detectados', []))
                resumen['problemas_criticos'] += problemas_rootkits
            
            if 'permisos' in auditorias:
                problemas_permisos = len(auditorias['permisos'].get('problemas_permisos', []))
                resumen['problemas_menores'] += problemas_permisos
            
            if 'servicios' in auditorias:
                servicios_inseguros = len(auditorias['servicios'].get('servicios_inseguros', []))
                resumen['problemas_menores'] += servicios_inseguros
            
            # Determinar nivel de riesgo
            if resumen['problemas_criticos'] > 0:
                resumen['nivel_riesgo'] = 'alto'
                resumen['estado_general'] = 'comprometido'
            elif resumen['problemas_menores'] > 5:
                resumen['nivel_riesgo'] = 'medio'
                resumen['estado_general'] = 'vulnerable'
            
            # Recomendaciones prioritarias
            if resumen['problemas_criticos'] > 0:
                resumen['recomendaciones_prioritarias'].append("CRÍTICO: Rootkits detectados - Investigar inmediatamente")
            
            if resumen['puntuacion_general'] < 50:
                resumen['recomendaciones_prioritarias'].append("Puntuación de seguridad baja - Implementar hardening")
            
            if resumen['problemas_menores'] > 3:
                resumen['recomendaciones_prioritarias'].append("Corregir problemas de configuración detectados")
        
        except Exception as e:
            resumen['error_generando_resumen'] = str(e)
        
        return resumen
        exitosos = sum(1 for r in resultados.values() if r.get('exito', False))
        
        return {
            'total_verificaciones': total_checks,
            'exitosas': exitosos,
            'fallidas': total_checks - exitosos,
            'porcentaje_exito': (exitosos / total_checks * 100) if total_checks > 0 else 0
        }

    def verificar_funcionalidad_kali(self):
        """
        Verificar que todas las funcionalidades de auditoría funcionen en Kali Linux.
        """
        from datetime import datetime
        
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'sistema_operativo': None,
            'gestor_permisos': False,
            'herramientas_disponibles': {},
            'permisos_sudo': False,
            'funcionalidad_completa': False,
            'recomendaciones': []
        }
        
        try:
            import platform
            resultado['sistema_operativo'] = platform.system()
            
            # Verificar gestor de permisos
            if self.modelo_principal and hasattr(self.modelo_principal, 'gestor_permisos'):
                if self.modelo_principal.gestor_permisos is not None:
                    resultado['gestor_permisos'] = True
                    
                    # Verificar permisos sudo si está disponible
                    try:
                        resultado['permisos_sudo'] = self.modelo_principal.gestor_permisos.verificar_sudo_disponible()
                    except Exception:
                        resultado['permisos_sudo'] = False
                    
                    # Verificar herramientas específicas de Auditoría
                    herramientas = ['lynis', 'rkhunter', 'chkrootkit', 'systemctl']
                    for herramienta in herramientas:
                        estado = self.modelo_principal.gestor_permisos.verificar_permisos_herramienta(herramienta)
                        resultado['herramientas_disponibles'][herramienta] = estado
            
            # Evaluar funcionalidad completa
            herramientas_ok = sum(1 for h in resultado['herramientas_disponibles'].values() 
                                if h.get('disponible', False) and h.get('permisos_ok', False))
            
            resultado['funcionalidad_completa'] = (
                resultado['gestor_permisos'] and 
                resultado['permisos_sudo'] and 
                herramientas_ok >= 2  # Al menos 2 herramientas de auditoría
            )
            
            # Generar recomendaciones
            if not resultado['funcionalidad_completa']:
                if not resultado['gestor_permisos']:
                    resultado['recomendaciones'].append("Gestor de permisos no disponible")
                
                if not resultado['permisos_sudo']:
                    resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
                
                if herramientas_ok < 2:
                    resultado['recomendaciones'].append("Instalar herramientas auditoría: sudo apt install lynis rkhunter chkrootkit")
            
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado

# RESUMEN TÉCNICO: Controlador de auditorías de seguridad para Kali Linux. Coordina 
# análisis de sistema con lynis, detección de rootkits, verificación de permisos y 
# servicios. Arquitectura MVC con principios SOLID, herramientas nativas sin 
# dependencias externas, optimizado para auditorías de seguridad profesionales.
