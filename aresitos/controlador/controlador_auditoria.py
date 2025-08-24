# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador de Auditoría Avanzado
Controlador especializado en auditorías de seguridad completas para Kali Linux
"""

import subprocess
import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from aresitos.controlador.controlador_base import ControladorBase

class ControladorAuditoria(ControladorBase):
    """
    Controlador avanzado para auditorías de seguridad.
    Integra múltiples herramientas de Kali Linux para análisis completo.
    """
    
    def __init__(self, modelo_principal):
        super().__init__(modelo_principal, "ControladorAuditoria")
        
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
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación de inicialización específica para auditorías."""
        try:
            # Verificar herramientas de auditoría disponibles
            herramientas_disponibles = {}
            for herramienta, descripcion in self.herramientas_auditoria.items():
                disponible = self._validar_herramienta_disponible(herramienta)
                herramientas_disponibles[herramienta] = {
                    'disponible': disponible,
                    'descripcion': descripcion
                }
            
            # Verificar si al menos algunas herramientas están disponibles
            herramientas_ok = sum(1 for h in herramientas_disponibles.values() if h['disponible'])
            
            if herramientas_ok == 0:
                return {
                    'exito': False,
                    'error': 'No hay herramientas de auditoría disponibles',
                    'herramientas_disponibles': herramientas_disponibles,
                    'recomendacion': 'Instalar herramientas: sudo apt install lynis rkhunter chkrootkit'
                }
            
            return {
                'exito': True,
                'mensaje': f'Controlador de auditoría inicializado con {herramientas_ok} herramientas',
                'herramientas_disponibles': herramientas_disponibles,
                'herramientas_count': herramientas_ok
            }
            
        except Exception as e:
            return {
                'exito': False,
                'error': f'Error inicializando controlador de auditoría: {str(e)}'
            }
    
    def _validar_herramienta_disponible(self, herramienta: str) -> bool:
        """
        Valida si una herramienta está disponible en el sistema.
        
        Args:
            herramienta: Nombre de la herramienta a validar
            
        Returns:
            bool: True si la herramienta está disponible
        """
        try:
            resultado = subprocess.run(
                ['which', herramienta], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return resultado.returncode == 0
        except Exception:
            return False
    
    def _ejecutar_comando_seguro(self, comando: List[str], timeout: int = 300) -> Dict[str, Any]:
        """
        Ejecuta un comando de forma segura con manejo de errores.
        
        Args:
            comando: Lista con el comando y argumentos
            timeout: Tiempo límite en segundos
            
        Returns:
            Diccionario con resultado del comando
        """
        resultado = {
            'exito': False,
            'codigo_salida': None,
            'stdout': '',
            'stderr': '',
            'error': None
        }
        
        try:
            proceso = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            resultado['exito'] = proceso.returncode == 0
            resultado['codigo_salida'] = proceso.returncode
            resultado['stdout'] = proceso.stdout
            resultado['stderr'] = proceso.stderr
            
        except subprocess.TimeoutExpired:
            resultado['error'] = f'Timeout ejecutando comando: {" ".join(comando)}'
        except FileNotFoundError:
            resultado['error'] = f'Comando no encontrado: {comando[0]}'
        except Exception as e:
            resultado['error'] = str(e)
            
        return resultado
    
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
        
        # Validar que Lynis esté disponible
        if not self._validar_herramienta_disponible('lynis'):
            resultado['error'] = 'Lynis no encontrado - instalar con: apt install lynis'
            return resultado
        
        # Ejecutar Lynis con parámetros específicos
        comando = [
            'sudo', 'lynis', 
            'audit', 'system',
            '--auditor', 'aresitos',
            '--cronjob',  # Para salida parseable
            '--quiet'
        ]
        
        resultado_comando = self._ejecutar_comando_seguro(
            comando, 
            self.config_auditoria['timeout_herramientas']
        )
        
        if resultado_comando['exito']:
            resultado['exito'] = True
            resultado['reporte_completo'] = resultado_comando['stdout']
            
            # Parsear resultados de Lynis
            self._parsear_resultados_lynis(resultado_comando['stdout'], resultado)
            
            # Buscar archivos de reporte generados
            rutas_reportes = [
                '/var/log/lynis.log',
                '/var/log/lynis-report.dat'
            ]
            
            for ruta in rutas_reportes:
                if Path(ruta).exists():
                    resultado['archivos_generados'].append(ruta)
        else:
            resultado['error'] = resultado_comando['error'] or resultado_comando['stderr']
                
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
                except (ValueError, IndexError, TypeError) as e:
                    self.logger.warning(f"Error extrayendo puntuación: {e}")
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
        
        # Ejecutar rkhunter si está disponible
        if self._validar_herramienta_disponible('rkhunter'):
            print("Ejecutando rkhunter...")
            cmd_rkhunter = ['sudo', 'rkhunter', '--check', '--skip-keypress', '--report-warnings-only']
            
            resultado_rkhunter = self._ejecutar_comando_seguro(cmd_rkhunter, 300)
            
            if resultado_rkhunter['exito']:
                resultado['herramientas_usadas'].append('rkhunter')
                
                if 'warning' in resultado_rkhunter['stdout'].lower() or 'infected' in resultado_rkhunter['stdout'].lower():
                    resultado['rootkits_detectados'].extend(
                        self._extraer_detecciones_rkhunter(resultado_rkhunter['stdout'])
                    )
            else:
                resultado['errores_rkhunter'] = resultado_rkhunter['error']
        
        # Ejecutar chkrootkit si está disponible
        if self._validar_herramienta_disponible('chkrootkit'):
            print("Ejecutando chkrootkit...")
            cmd_chkrootkit = ['sudo', 'chkrootkit']
            
            resultado_chkrootkit = self._ejecutar_comando_seguro(cmd_chkrootkit, 300)
            
            if resultado_chkrootkit['exito']:
                resultado['herramientas_usadas'].append('chkrootkit')
                
                if 'infected' in resultado_chkrootkit['stdout'].lower():
                    resultado['rootkits_detectados'].extend(
                        self._extraer_detecciones_chkrootkit(resultado_chkrootkit['stdout'])
                    )
            else:
                resultado['errores_chkrootkit'] = resultado_chkrootkit['error']
        
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
    
    def ejecutar_auditoria_completa_legacy(self) -> Dict[str, Any]:
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
        
        print("Iniciando auditoría completa del sistema...")
        
        try:
            # 1. Auditoría Lynis
            print("Ejecutando auditoría Lynis...")
            resultado_completo['auditorias_individuales']['lynis'] = self.ejecutar_auditoria_lynis()
            
            # 2. Detección de rootkits
            print("Ejecutando detección de rootkits...")
            resultado_completo['auditorias_individuales']['rootkits'] = self.ejecutar_deteccion_rootkits()
            
            # 3. Verificación de permisos
            print("Verificando permisos críticos...")
            resultado_completo['auditorias_individuales']['permisos'] = self.verificar_permisos_criticos()
            
            # 4. Análisis de servicios
            print("Analizando servicios del sistema...")
            resultado_completo['auditorias_individuales']['servicios'] = self.analizar_servicios_sistema()
            
            resultado_completo['timestamp_fin'] = datetime.now().isoformat()
            resultado_completo['exito'] = True
            
            # Generar resumen ejecutivo
            resultado_completo['resumen_ejecutivo'] = self._generar_resumen_ejecutivo(
                resultado_completo['auditorias_individuales']
            )
            
            print("Auditoría completa finalizada")
            
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
    
    def ejecutar_auditoria_completa(self, tipo: str = "completa") -> Dict[str, Any]:
        """
        Ejecuta auditoría específica según el tipo solicitado.
        
        Args:
            tipo: Tipo de auditoría ("lynis", "rootkits", "permisos", "servicios", "completa")
            
        Returns:
            Diccionario con resultados de auditoría
        """
        resultado = {
            'timestamp_inicio': datetime.now().isoformat(),
            'timestamp_fin': None,
            'exito': False,
            'tipo_auditoria': tipo,
            'salida': '',
            'error': None
        }
        
        try:
            if tipo.lower() == "lynis":
                # Ejecutar solo auditoría Lynis
                resultado_lynis = self.ejecutar_auditoria_lynis()
                resultado.update(resultado_lynis)
                resultado['salida'] = resultado_lynis.get('resultado_texto', '')
                
            elif tipo.lower() == "rootkits":
                # Ejecutar solo detección de rootkits
                resultado_rootkits = self.ejecutar_deteccion_rootkits()
                resultado.update(resultado_rootkits)
                resultado['salida'] = f"Rootkits detectados: {len(resultado_rootkits.get('rootkits_detectados', []))}"
                
            elif tipo.lower() == "permisos":
                # Ejecutar solo verificación de permisos
                resultado_permisos = self.verificar_permisos_criticos()
                resultado.update(resultado_permisos)
                resultado['salida'] = f"Problemas de permisos: {len(resultado_permisos.get('problemas_permisos', []))}"
                
            elif tipo.lower() == "servicios":
                # Ejecutar solo análisis de servicios
                resultado_servicios = self.analizar_servicios_sistema()
                resultado.update(resultado_servicios)
                resultado['salida'] = f"Servicios analizados: {len(resultado_servicios.get('servicios_activos', []))}"
                
            else:
                # Auditoría completa (comportamiento original)
                return self.ejecutar_auditoria_completa_legacy()
                
            resultado['timestamp_fin'] = datetime.now().isoformat()
            resultado['exito'] = True
            
        except Exception as e:
            resultado['error'] = str(e)
            resultado['timestamp_fin'] = datetime.now().isoformat()
            resultado['exito'] = False
        
        return resultado
    
    def verificar_rootkits(self, tipo_verificacion: str = "completa") -> Dict[str, Any]:
        """
        Verificar rootkits en el sistema usando múltiples herramientas.
        
        Args:
            tipo_verificacion: Tipo de verificación ("rapida", "completa", "profunda")
            
        Returns:
            Dict con resultados de verificación de rootkits
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'tipo_verificacion': tipo_verificacion,
            'herramientas_usadas': [],
            'rootkits_detectados': [],
            'archivos_sospechosos': [],
            'procesos_sospechosos': [],
            'exito': False,
            'resumen': ''
        }
        
        try:
            total_detecciones = 0
            
            # 1. Verificación con rkhunter si está disponible
            if self._validar_herramienta_disponible('rkhunter'):
                resultado['herramientas_usadas'].append('rkhunter')
                cmd_rkhunter = ['sudo', 'rkhunter', '--check', '--sk', '--rwo']
                resultado_rkhunter = self._ejecutar_comando_seguro(cmd_rkhunter, timeout=180)
                
                if resultado_rkhunter['exito']:
                    # Analizar salida de rkhunter
                    if 'Warning' in resultado_rkhunter['stdout'] or 'Infection' in resultado_rkhunter['stdout']:
                        for linea in resultado_rkhunter['stdout'].split('\n'):
                            if 'Warning:' in linea or 'Infection:' in linea:
                                resultado['rootkits_detectados'].append(f"rkhunter: {linea.strip()}")
                                total_detecciones += 1
            
            # 2. Verificación con chkrootkit si está disponible
            if self._validar_herramienta_disponible('chkrootkit'):
                resultado['herramientas_usadas'].append('chkrootkit')
                cmd_chkrootkit = ['sudo', 'chkrootkit']
                resultado_chkrootkit = self._ejecutar_comando_seguro(cmd_chkrootkit, timeout=180)
                
                if resultado_chkrootkit['exito']:
                    # Analizar salida de chkrootkit
                    if 'INFECTED' in resultado_chkrootkit['stdout']:
                        for linea in resultado_chkrootkit['stdout'].split('\n'):
                            if 'INFECTED' in linea:
                                resultado['rootkits_detectados'].append(f"chkrootkit: {linea.strip()}")
                                total_detecciones += 1
            
            # 3. Verificación básica de archivos sospechosos
            archivos_sospechosos = [
                '/tmp/.hidden', '/tmp/.ice-unix/.hidden', '/dev/shm/.hidden',
                '/usr/bin/.hidden', '/var/tmp/.hidden'
            ]
            
            for archivo in archivos_sospechosos:
                if os.path.exists(archivo):
                    resultado['archivos_sospechosos'].append(archivo)
                    total_detecciones += 1
            
            # 4. Verificación de procesos sospechosos
            cmd_ps = ['ps', 'aux']
            resultado_ps = self._ejecutar_comando_seguro(cmd_ps, timeout=30)
            
            if resultado_ps['exito']:
                procesos_sospechosos = ['.hidden', 'rootkit', 'backdoor', '/tmp/...']
                for linea in resultado_ps['stdout'].split('\n'):
                    for patron in procesos_sospechosos:
                        if patron in linea.lower():
                            resultado['procesos_sospechosos'].append(linea.strip())
                            total_detecciones += 1
            
            resultado['exito'] = True
            resultado['resumen'] = f"Verificación completada con {len(resultado['herramientas_usadas'])} herramientas. {total_detecciones} detecciones."
            
            if total_detecciones == 0:
                resultado['resumen'] += " Sistema limpio."
            else:
                resultado['resumen'] += f" ALERTA: {total_detecciones} posibles amenazas detectadas."
                
        except Exception as e:
            resultado['error'] = str(e)
            resultado['exito'] = False
            
        return resultado
    
    def analizar_configuracion(self, tipo_analisis: str = "basico") -> Dict[str, Any]:
        """
        Analizar configuración de seguridad del sistema.
        
        Args:
            tipo_analisis: Tipo de análisis ("basico", "intermedio", "avanzado")
            
        Returns:
            Dict con resultados del análisis de configuración
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'tipo_analisis': tipo_analisis,
            'configuraciones_analizadas': [],
            'problemas_encontrados': [],
            'recomendaciones': [],
            'puntuacion_seguridad': 0,
            'exito': False
        }
        
        try:
            puntuacion = 100  # Empezar con puntuación perfecta
            
            # 1. Analizar configuración SSH
            ssh_config = '/etc/ssh/sshd_config'
            if os.path.exists(ssh_config):
                resultado['configuraciones_analizadas'].append('SSH')
                try:
                    with open(ssh_config, 'r') as f:
                        contenido_ssh = f.read()
                    
                    # Verificar configuraciones críticas de SSH
                    if 'PermitRootLogin yes' in contenido_ssh:
                        resultado['problemas_encontrados'].append('SSH: PermitRootLogin habilitado')
                        resultado['recomendaciones'].append('Deshabilitar login root SSH')
                        puntuacion -= 20
                    
                    if 'PasswordAuthentication yes' in contenido_ssh:
                        resultado['problemas_encontrados'].append('SSH: Autenticación por contraseña habilitada')
                        resultado['recomendaciones'].append('Usar autenticación por clave SSH')
                        puntuacion -= 10
                        
                except Exception as e:
                    resultado['problemas_encontrados'].append(f'Error leyendo SSH config: {e}')
            
            # 2. Analizar configuración de firewall
            resultado['configuraciones_analizadas'].append('Firewall')
            cmd_ufw = ['ufw', 'status']
            resultado_ufw = self._ejecutar_comando_seguro(cmd_ufw, timeout=10)
            
            if resultado_ufw['exito']:
                if 'Status: inactive' in resultado_ufw['stdout']:
                    resultado['problemas_encontrados'].append('Firewall: UFW inactivo')
                    resultado['recomendaciones'].append('Activar firewall UFW')
                    puntuacion -= 25
            else:
                resultado['problemas_encontrados'].append('Firewall: UFW no configurado')
                puntuacion -= 15
            
            # 3. Verificar actualizaciones del sistema
            resultado['configuraciones_analizadas'].append('Actualizaciones')
            cmd_updates = ['apt', 'list', '--upgradable']
            resultado_updates = self._ejecutar_comando_seguro(cmd_updates, timeout=30)
            
            if resultado_updates['exito']:
                lineas_updates = resultado_updates['stdout'].count('\n')
                if lineas_updates > 10:
                    resultado['problemas_encontrados'].append(f'Sistema: {lineas_updates} actualizaciones pendientes')
                    resultado['recomendaciones'].append('Actualizar sistema: sudo apt update && sudo apt upgrade')
                    puntuacion -= 15
            
            # 4. Verificar servicios innecesarios
            resultado['configuraciones_analizadas'].append('Servicios')
            servicios_riesgosos = ['telnet', 'ftp', 'rsh', 'rlogin']
            
            for servicio in servicios_riesgosos:
                cmd_service = ['systemctl', 'is-active', servicio]
                resultado_service = self._ejecutar_comando_seguro(cmd_service, timeout=5)
                
                if resultado_service['exito'] and 'active' in resultado_service['stdout']:
                    resultado['problemas_encontrados'].append(f'Servicio inseguro activo: {servicio}')
                    resultado['recomendaciones'].append(f'Deshabilitar servicio: sudo systemctl disable {servicio}')
                    puntuacion -= 20
            
            # 5. Verificar permisos críticos
            resultado['configuraciones_analizadas'].append('Permisos')
            archivos_criticos = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            
            for archivo in archivos_criticos:
                if os.path.exists(archivo):
                    stat = os.stat(archivo)
                    permisos = oct(stat.st_mode)[-3:]
                    
                    if archivo == '/etc/shadow' and permisos != '640':
                        resultado['problemas_encontrados'].append(f'Permisos incorrectos: {archivo} ({permisos})')
                        resultado['recomendaciones'].append(f'Corregir permisos: sudo chmod 640 {archivo}')
                        puntuacion -= 15
            
            resultado['puntuacion_seguridad'] = max(0, puntuacion)
            resultado['exito'] = True
            
            # Generar resumen final
            if resultado['puntuacion_seguridad'] >= 90:
                nivel_seguridad = "EXCELENTE"
            elif resultado['puntuacion_seguridad'] >= 75:
                nivel_seguridad = "BUENO"
            elif resultado['puntuacion_seguridad'] >= 60:
                nivel_seguridad = "REGULAR"
            else:
                nivel_seguridad = "CRÍTICO"
            
            resultado['nivel_seguridad'] = nivel_seguridad
            resultado['resumen'] = f"Análisis completado. Puntuación: {puntuacion}/100 ({nivel_seguridad})"
            
        except Exception as e:
            resultado['error'] = str(e)
            resultado['exito'] = False
            
        return resultado
    
    def obtener_resultados_auditoria(self, filtro: str = "todos") -> Dict[str, Any]:
        """
        Obtener resultados de auditorías anteriores.
        
        Args:
            filtro: Filtro para resultados ("todos", "recientes", "criticos")
            
        Returns:
            Dict con resultados de auditorías
        """
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'filtro_aplicado': filtro,
            'auditorias_encontradas': [],
            'total_auditorias': 0,
            'resumen_estadisticas': {},
            'exito': False
        }
        
        try:
            # Buscar archivos de resultados de auditoría
            directorios_busqueda = [
                '/var/log/lynis',
                '/tmp/auditoria_resultados',
                './logs',
                './reportes'
            ]
            
            auditorias_encontradas = []
            
            for directorio in directorios_busqueda:
                if os.path.exists(directorio):
                    try:
                        archivos = os.listdir(directorio)
                        for archivo in archivos:
                            if any(palabra in archivo.lower() for palabra in ['audit', 'lynis', 'security', 'report']):
                                ruta_completa = os.path.join(directorio, archivo)
                                if os.path.isfile(ruta_completa):
                                    stat = os.stat(ruta_completa)
                                    auditorias_encontradas.append({
                                        'archivo': archivo,
                                        'ruta': ruta_completa,
                                        'tamaño': stat.st_size,
                                        'fecha_modificacion': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                        'tipo': self._determinar_tipo_auditoria(archivo)
                                    })
                    except PermissionError:
                        continue
            
            # Aplicar filtros
            if filtro == "recientes":
                # Obtener solo auditorías de los últimos 7 días
                import time
                hace_semana = time.time() - (7 * 24 * 60 * 60)
                auditorias_filtradas = [
                    a for a in auditorias_encontradas 
                    if os.path.getmtime(a['ruta']) > hace_semana
                ]
            elif filtro == "criticos":
                # Filtrar auditorías que contienen palabras críticas
                auditorias_filtradas = [
                    a for a in auditorias_encontradas 
                    if any(palabra in a['archivo'].lower() for palabra in ['critical', 'high', 'vulnerability'])
                ]
            else:
                auditorias_filtradas = auditorias_encontradas
            
            # Ordenar por fecha (más recientes primero)
            auditorias_filtradas.sort(key=lambda x: x['fecha_modificacion'], reverse=True)
            
            # Generar estadísticas
            tipos_auditoria = {}
            tamaño_total = 0
            
            for auditoria in auditorias_filtradas:
                tipo = auditoria['tipo']
                tipos_auditoria[tipo] = tipos_auditoria.get(tipo, 0) + 1
                tamaño_total += auditoria['tamaño']
            
            resultado['auditorias_encontradas'] = auditorias_filtradas[:20]  # Limitar a 20 más recientes
            resultado['total_auditorias'] = len(auditorias_filtradas)
            resultado['resumen_estadisticas'] = {
                'tipos_auditoria': tipos_auditoria,
                'tamaño_total_mb': round(tamaño_total / (1024*1024), 2),
                'auditorias_recientes': len([a for a in auditorias_filtradas if 'fecha_modificacion' in a])
            }
            resultado['exito'] = True
            
        except Exception as e:
            resultado['error'] = str(e)
            resultado['exito'] = False
            
        return resultado
    
    def _determinar_tipo_auditoria(self, nombre_archivo: str) -> str:
        """Determinar el tipo de auditoría basado en el nombre del archivo."""
        nombre_lower = nombre_archivo.lower()
        
        if 'lynis' in nombre_lower:
            return 'lynis'
        elif 'rootkit' in nombre_lower or 'rkhunter' in nombre_lower:
            return 'rootkits'
        elif 'nuclei' in nombre_lower:
            return 'vulnerabilidades'
        elif 'nmap' in nombre_lower:
            return 'escaneo_red'
        elif 'security' in nombre_lower:
            return 'seguridad_general'
        else:
            return 'general'
    

# RESUMEN TÉCNICO: Controlador de auditorías de seguridad para Kali Linux. Coordina 
# análisis de sistema con lynis, detección de rootkits, verificación de permisos y 
# servicios. Arquitectura MVC con principios SOLID, herramientas nativas sin 
# dependencias externas, optimizado para auditorías de seguridad profesionales ARESITOS.

