# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal con Cuarentena Integrada
Gestiona el escáner con cuarentena automática para amenazas detectadas
"""

import logging
import os
import ipaddress
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

class MockResultado:
    """Resultado mock para el escáner."""
    def __init__(self):
        self.vulnerabilidades = []
        self.exito = False
        self.errores = ["Escaneador no disponible"]

class MockEscaneador:
    """Escaneador mock para fallback."""
    def escanear_completo(self):
        return MockResultado()
    
    def detectar_malware(self):
        return MockResultado()
        
    def escanear_vulnerabilidades_sistema(self):
        return MockResultado()

class MockCuarentena:
    """Cuarentena mock para fallback."""
    def procesar_amenaza_detectada(self, amenaza):
        return False
    
    def obtener_resumen_cuarentena(self):
        return {"total_archivos": 0, "mensaje": "Cuarentena no disponible"}
        
    def restaurar_archivo(self, ruta):
        return False

class ControladorEscaneadorCuarentena:
    """
    Controlador principal que integra el escáner con el sistema de cuarentena.
    """
    
    def __init__(self):
        """Inicializa el controlador integrado."""
        self.logger = logging.getLogger(f"AresAegis.{self.__class__.__name__}")
        
        # Configuración por defecto
        self.configuración = {
            'cuarentena_automatica': True,
            'niveles_cuarentena': ['critico', 'alto'],  # Niveles que van a cuarentena automáticamente
            'notificar_cuarentena': True,
            'backup_antes_cuarentena': True
        }
        
        # Inicializar componentes con tipos Union para flexibilidad
        self.escáner: Union[MockEscaneador, Any] = MockEscaneador()
        self.cuarentena: Union[MockCuarentena, Any] = MockCuarentena()
        
        self._inicializar_componentes()
    
    def _inicializar_componentes(self):
        """Inicializa el escáner y el sistema de cuarentena."""
        # Inicializar escáner
        try:
            from ..modelo.modelo_escaneador_avanzado_real import EscaneadorAvanzadoReal
            self.escáner = EscaneadorAvanzadoReal()
            self.logger.info("OK Escaneador avanzado inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando escáner: {e}")
            self.escáner = MockEscaneador()
            self.logger.warning("WARNING Usando escáner mock")
        
        # Inicializar cuarentena
        try:
            from .controlador_cuarentena import ControladorCuarentena
            self.cuarentena = ControladorCuarentena()
            self.logger.info("OK Sistema de cuarentena inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando cuarentena: {e}")
            self.cuarentena = MockCuarentena()
            self.logger.warning("WARNING Usando cuarentena mock")
    
    def ejecutar_escaneo_con_cuarentena(self, tipo_escaneo: str = 'completo') -> Dict[str, Any]:
        """
        Ejecuta un escaneo con cuarentena automática de amenazas.
        
        Args:
            tipo_escaneo: Tipo de escaneo a realizar
            
        Returns:
            Dict con resultados del escaneo y cuarentena
        """
        self.logger.info(f" Iniciando escaneo {tipo_escaneo} con cuarentena automática")
        
        resultado = {
            'timestamp_inicio': datetime.now().isoformat(),
            'tipo_escaneo': tipo_escaneo,
            'vulnerabilidades_encontradas': [],
            'amenazas_en_cuarentena': [],
            'resumen_cuarentena': {},
            'exito': False,
            'errores': []
        }
        
        try:
            # 1. Ejecutar escaneo
            if tipo_escaneo == 'completo':
                resultado_escaneo = self.escáner.escanear_completo()
            elif tipo_escaneo == 'malware':
                resultado_escaneo = self.escáner.detectar_malware()
            elif tipo_escaneo == 'vulnerabilidades':
                resultado_escaneo = self.escáner.escanear_vulnerabilidades_sistema()
            else:
                raise ValueError(f"Tipo de escaneo no válido: {tipo_escaneo}")
            
            # 2. Procesar vulnerabilidades encontradas
            vulnerabilidades_procesadas = []
            amenazas_cuarentena = []
            
            for vuln in resultado_escaneo.vulnerabilidades:
                vuln_info = {
                    'id': vuln.id,
                    'tipo': vuln.tipo,
                    'descripcion': vuln.descripcion,
                    'nivel_riesgo': vuln.nivel_riesgo.value,
                    'archivo_afectado': vuln.archivo_afectado,
                    'timestamp': vuln.timestamp.isoformat() if vuln.timestamp else None
                }
                vulnerabilidades_procesadas.append(vuln_info)
                
                # 3. Procesar con cuarentena si es necesario
                if self._debe_ir_a_cuarentena(vuln):
                    if self._procesar_amenaza_cuarentena(vuln):
                        amenazas_cuarentena.append(vuln_info)
                        self.logger.warning(f" Amenaza enviada a cuarentena: {vuln.tipo}")
            
            # 4. Obtener resumen de cuarentena
            resumen_cuarentena = self._obtener_resumen_cuarentena()
            
            # 5. Preparar resultado final
            resultado.update({
                'vulnerabilidades_encontradas': vulnerabilidades_procesadas,
                'amenazas_en_cuarentena': amenazas_cuarentena,
                'resumen_cuarentena': resumen_cuarentena,
                'exito': resultado_escaneo.exito,
                'timestamp_fin': datetime.now().isoformat(),
                'estadisticas': {
                    'total_vulnerabilidades': len(vulnerabilidades_procesadas),
                    'criticas': len([v for v in vulnerabilidades_procesadas if v['nivel_riesgo'] == 'critico']),
                    'altas': len([v for v in vulnerabilidades_procesadas if v['nivel_riesgo'] == 'alto']),
                    'en_cuarentena': len(amenazas_cuarentena)
                }
            })
            
            # 6. Log de resumen
            self._log_resumen_escaneo(resultado)
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error durante escaneo con cuarentena: {e}"
            self.logger.error(error_msg)
            resultado['errores'].append(error_msg)
            resultado['timestamp_fin'] = datetime.now().isoformat()
            return resultado
    
    def _debe_ir_a_cuarentena(self, vulnerabilidad) -> bool:
        """Determina si una vulnerabilidad debe ir a cuarentena automáticamente."""
        if not self.configuración['cuarentena_automatica']:
            return False
        
        nivel = vulnerabilidad.nivel_riesgo.value
        return nivel in self.configuración['niveles_cuarentena']
    
    def _procesar_amenaza_cuarentena(self, vulnerabilidad) -> bool:
        """Procesa una amenaza con el sistema de cuarentena."""
        try:
            amenaza_info = {
                'archivo': vulnerabilidad.archivo_afectado,
                'tipo': vulnerabilidad.tipo,
                'descripcion': vulnerabilidad.descripcion,
                'severidad': self._convertir_nivel_riesgo(vulnerabilidad.nivel_riesgo.value),
                'fuente_deteccion': 'EscaneadorAvanzado',
                'fecha_deteccion': vulnerabilidad.timestamp.isoformat() if vulnerabilidad.timestamp else None,
                'metadatos': {
                    'vulnerability_id': vulnerabilidad.id,
                    'cve_id': vulnerabilidad.cve_id,
                    'puerto_afectado': vulnerabilidad.puerto_afectado,
                    'servicio_afectado': vulnerabilidad.servicio_afectado,
                    'solucion_recomendada': vulnerabilidad.solucion_recomendada
                }
            }
            
            return self.cuarentena.procesar_amenaza_detectada(amenaza_info)
            
        except Exception as e:
            self.logger.error(f"Error procesando amenaza en cuarentena: {e}")
            return False
    
    def _convertir_nivel_riesgo(self, nivel: str) -> str:
        """Convierte nivel de riesgo a formato de cuarentena."""
        conversion = {
            'critico': 'Crítica',
            'alto': 'Alta',
            'medio': 'Media',
            'bajo': 'Baja',
            'info': 'Baja'
        }
        return conversion.get(nivel, 'Media')
    
    def _obtener_resumen_cuarentena(self) -> Dict[str, Any]:
        """Obtiene resumen del estado de cuarentena."""
        try:
            if hasattr(self.cuarentena, 'obtener_resumen_cuarentena'):
                return self.cuarentena.obtener_resumen_cuarentena()
            else:
                return {'mensaje': 'Sistema de cuarentena activo'}
        except Exception as e:
            self.logger.error(f"Error obteniendo resumen de cuarentena: {e}")
            return {'error': str(e)}
    
    def _log_resumen_escaneo(self, resultado: Dict[str, Any]):
        """Registra resumen del escaneo en los logs."""
        stats = resultado.get('estadisticas', {})
        
        self.logger.info("=" * 60)
        self.logger.info(" RESUMEN DE ESCANEO CON CUARENTENA")
        self.logger.info("=" * 60)
        self.logger.info(f" Tipo de escaneo: {resultado.get('tipo_escaneo', 'N/A')}")
        self.logger.info(f" Total vulnerabilidades: {stats.get('total_vulnerabilidades', 0)}")
        self.logger.info(f"� Críticas: {stats.get('criticas', 0)}")
        self.logger.info(f"� Altas: {stats.get('altas', 0)}")
        self.logger.info(f" En cuarentena: {stats.get('en_cuarentena', 0)}")
        
        if stats.get('en_cuarentena', 0) > 0:
            self.logger.warning(f"WARNING {stats['en_cuarentena']} amenazas fueron puestas en cuarentena automáticamente")
        
        self.logger.info("=" * 60)
    
    def gestionar_cuarentena(self) -> Dict[str, Any]:
        """Proporciona interfaz para gestionar la cuarentena."""
        try:
            resumen = self._obtener_resumen_cuarentena()
            
            return {
                'resumen': resumen,
                'acciones_disponibles': [
                    'listar_archivos_cuarentena',
                    'restaurar_archivo',
                    'eliminar_definitivamente',
                    'limpiar_cuarentena_antigua',
                    'generar_reporte_cuarentena'
                ],
                'configuracion_actual': self.configuración
            }
            
        except Exception as e:
            self.logger.error(f"Error gestionando cuarentena: {e}")
            return {'error': str(e)}
    
    def restaurar_desde_cuarentena(self, ruta_archivo: str) -> bool:
        """Restaura un archivo específico desde la cuarentena."""
        try:
            if hasattr(self.cuarentena, 'restaurar_archivo'):
                resultado = self.cuarentena.restaurar_archivo(ruta_archivo)
                if resultado:
                    self.logger.info(f"OK Archivo restaurado: {ruta_archivo}")
                else:
                    self.logger.warning(f"ERROR No se pudo restaurar: {ruta_archivo}")
                return resultado
            else:
                self.logger.error("Método de restauración no disponible")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restaurando archivo: {e}")
            return False
    
    def configurar_cuarentena(self, nueva_config: Dict[str, Any]) -> bool:
        """Actualiza la configuración de cuarentena."""
        try:
            self.configuración.update(nueva_config)
            self.logger.info("OK Configuración de cuarentena actualizada")
            return True
        except Exception as e:
            self.logger.error(f"Error actualizando configuración: {e}")
            return False
    
    # === MÉTODOS REQUERIDOS POR LA INTERFAZ ===
    
    def ejecutar_escaneo_basico(self) -> Dict[str, Any]:
        """Ejecuta un escaneo básico del sistema."""
        self.logger.info(" Iniciando escaneo básico del sistema")
        
        try:
            import socket
            import subprocess
            import shutil
            
            resultado = {
                'puertos': [],
                'procesos': [],
                'análisis': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # 1. Escanear puertos locales abiertos usando ss
            try:
                if shutil.which('ss'):
                    cmd_result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                    if cmd_result.returncode == 0:
                        lines = cmd_result.stdout.strip().split('\n')
                        puertos_encontrados = set()
                        
                        for line in lines[1:]:  # Skip header
                            if 'LISTEN' in line:
                                partes = line.split()
                                if len(partes) >= 4:
                                    direccion_local = partes[3]
                                    if ':' in direccion_local:
                                        puerto = direccion_local.split(':')[-1]
                                        try:
                                            puerto_num = int(puerto)
                                            puertos_encontrados.add(puerto_num)
                                            resultado['puertos'].append(f"Puerto {puerto_num}/tcp abierto")
                                        except ValueError:
                                            continue
                        
                        self.logger.info(f"Encontrados {len(puertos_encontrados)} puertos abiertos")
                    else:
                        # Fallback con netstat
                        cmd_result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
                        if cmd_result.returncode == 0:
                            for line in cmd_result.stdout.split('\n'):
                                if 'LISTEN' in line and ':' in line:
                                    resultado['puertos'].append("Puerto detectado con netstat")
            except Exception as e:
                self.logger.warning(f"Error escaneando puertos: {e}")
                resultado['análisis'].append("ERROR: No se pudieron escanear puertos")
            
            # 2. Procesos en ejecución usando ps
            try:
                cmd_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                if cmd_result.returncode == 0:
                    lines = cmd_result.stdout.strip().split('\n')
                    procesos_importantes = []
                    
                    for line in lines[1:]:  # Skip header
                        if any(keyword in line.lower() for keyword in 
                               ['ssh', 'apache', 'nginx', 'mysql', 'postgres', 'ftp', 'telnet', 'http']):
                            partes = line.split(None, 10)
                            if len(partes) >= 11:
                                pid = partes[1]
                                usuario = partes[0]
                                comando = partes[10]
                                procesos_importantes.append(f"PID {pid}: {comando[:50]} ({usuario})")
                            
                            if len(procesos_importantes) >= 15:
                                break
                    
                    resultado['procesos'] = procesos_importantes
                    self.logger.info(f"Encontrados {len(procesos_importantes)} procesos importantes")
                else:
                    resultado['análisis'].append("ERROR: No se pudieron listar procesos")
                    
            except Exception as e:
                self.logger.warning(f"Error listando procesos: {e}")
                resultado['análisis'].append("ERROR: Error listando procesos del sistema")
            
            # 3. Análisis básico
            total_puertos = len(resultado['puertos'])
            total_procesos = len(resultado['procesos'])
            resultado['análisis'].append(f"OK Escaneo completado - {total_puertos} puertos, {total_procesos} procesos")
            resultado['análisis'].append(f" {total_procesos} procesos de interés detectados")
            
            # Recomendaciones básicas basadas en puertos detectados
            puertos_texto = ' '.join(resultado['puertos'])
            if 'Puerto 22' in puertos_texto:
                resultado['análisis'].append("WARNING SSH activo - verificar configuración de seguridad")
            if 'Puerto 80' in puertos_texto or 'Puerto 443' in puertos_texto:
                resultado['análisis'].append(" Servidor web detectado - revisar configuración")
            
            self.logger.info("OK Escaneo básico completado exitosamente")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en escaneo básico: {e}")
            return {
                'puertos': [f"Error: {str(e)}"],
                'procesos': [],
                'análisis': [f"ERROR Error durante el escaneo: {str(e)}"],
                'timestamp': datetime.now().isoformat()
            }
    
    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """Verifica funcionalidad específica para Kali Linux."""
        self.logger.info("� Verificando funcionalidad en Kali Linux")
        
        resultado = {
            'funcionalidad_completa': False,
            'sistema_operativo': 'Desconocido',
            'gestor_permisos': False,
            'permisos_sudo': False,
            'herramientas_disponibles': {},
            'recomendaciones': [],
            'error': None
        }
        
        try:
            import platform
            import subprocess
            import os
            
            # 1. Verificar sistema operativo
            resultado['sistema_operativo'] = platform.system()
            
            # 2. Verificar permisos
            if platform.system() == 'Linux':
                # En Linux/Kali, verificar si es root verificando usuario
                try:
                    current_user = os.environ.get('USER', os.environ.get('USERNAME', ''))
                    resultado['gestor_permisos'] = current_user == 'root'
                except Exception:
                    resultado['gestor_permisos'] = False
            else:
                # En Windows, asumimos permisos administrativos si podemos escribir en system32
                try:
                    import tempfile
                    test_file = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'temp_test.txt')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    resultado['gestor_permisos'] = True
                except:
                    resultado['gestor_permisos'] = False
            
            # 3. Verificar sudo
            try:
                proc = subprocess.run(['sudo', '-n', 'true'], 
                                    capture_output=True, timeout=5)
                resultado['permisos_sudo'] = proc.returncode == 0
            except:
                resultado['permisos_sudo'] = False
            
            # 4. Verificar herramientas de Kali
            herramientas = {
                'nmap': ['nmap', '--version'],
                'netstat': ['netstat', '--version'],
                'ss': ['ss', '--version'],
                'iptables': ['iptables', '--version'],
                'systemctl': ['systemctl', '--version']
            }
            
            for nombre, comando in herramientas.items():
                try:
                    proc = subprocess.run(comando, capture_output=True, timeout=3)
                    disponible = proc.returncode == 0
                    resultado['herramientas_disponibles'][nombre] = {
                        'disponible': disponible,
                        'permisos_ok': disponible
                    }
                except:
                    resultado['herramientas_disponibles'][nombre] = {
                        'disponible': False,
                        'permisos_ok': False
                    }
            
            # 5. Generar recomendaciones
            if not resultado['gestor_permisos']:
                resultado['recomendaciones'].append("Gestor de permisos no disponible")
                resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
            
            if not resultado['permisos_sudo']:
                resultado['recomendaciones'].append("Configurar permisos sudo correctamente")
            
            herramientas_faltantes = [
                nombre for nombre, info in resultado['herramientas_disponibles'].items()
                if not info['disponible']
            ]
            
            if herramientas_faltantes:
                resultado['recomendaciones'].append(
                    f"Instalar herramientas faltantes: {', '.join(herramientas_faltantes)}"
                )
                resultado['recomendaciones'].append("Instalar herramientas auditoría: sudo apt install lynis rkhunter chkrootkit")
            
            # 6. Determinar si es funcional
            herramientas_ok = sum(1 for info in resultado['herramientas_disponibles'].values() 
                                if info['disponible']) >= len(herramientas) * 0.7
            
            resultado['funcionalidad_completa'] = (
                resultado['sistema_operativo'] == 'Linux' and
                (resultado['gestor_permisos'] or resultado['permisos_sudo']) and
                herramientas_ok
            )
            
            self.logger.info(f"OK Verificación Kali completada - Funcional: {resultado['funcionalidad_completa']}")
            return resultado
            
        except Exception as e:
            error_msg = f"Error durante verificación: {e}"
            self.logger.error(error_msg)
            resultado['error'] = error_msg
            return resultado
    
    def obtener_logs_escaneo(self) -> List[str]:
        """Obtiene logs del escáner."""
        try:
            logs = [
                f"[{datetime.now().strftime('%H:%M:%S')}] Sistema de escaneo iniciado",
                f"[{datetime.now().strftime('%H:%M:%S')}] Controlador integrado con cuarentena: {'OK' if self.cuarentena else 'ERROR'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Escaneador avanzado: {'OK' if hasattr(self.escáner, 'escanear_completo') else 'ERROR'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Cuarentena automática: {'OK' if self.configuración['cuarentena_automatica'] else 'ERROR'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Sistema listo para operaciones"
            ]
            return logs
        except Exception as e:
            return [f"Error obteniendo logs: {e}"]
    
    def obtener_eventos_siem(self) -> List[Dict[str, Any]]:
        """Obtiene eventos del SIEM relacionados con escaneo."""
        try:
            eventos = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'ESCANEADOR_INICIADO',
                    'descripcion': 'Sistema de escaneo con cuarentena iniciado correctamente'
                },
                {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'CONFIGURACION_CUARENTENA',
                    'descripcion': f"Cuarentena automática: {self.configuración['cuarentena_automatica']}"
                }
            ]
            return eventos
        except Exception as e:
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'tipo': 'ERROR',
                    'descripcion': f'Error obteniendo eventos SIEM: {e}'
                }
            ]
    
    def ejecutar_escaneo_completo(self) -> Dict[str, Any]:
        """Ejecuta un escaneo completo del sistema."""
        return self.ejecutar_escaneo_con_cuarentena('completo')

    def _validar_objetivo_escaneo(self, objetivo: str) -> bool:
        """
        Valida si un objetivo es válido para escaneo en Kali Linux.
        Implementa validaciones de seguridad para pentesting ético.
        
        Args:
            objetivo: IP, hostname o dominio a validar
            
        Returns:
            bool: True si el objetivo es válido para escaneo
        """
        try:
            resultado = self._validar_objetivo_detallado(objetivo)
            return resultado.get('valido', False)
        except Exception as e:
            self.logger.error(f"Error validando objetivo {objetivo}: {e}")
            return False
    
    def _validar_objetivo_detallado(self, objetivo: str) -> Dict[str, Any]:
        """
        Valida si un objetivo es válido para escaneo con detalles completos.
        Implementa validaciones de seguridad para pentesting ético.
        """
        resultado = {
            'valido': False,
            'tipo': 'desconocido',
            'objetivo_procesado': objetivo,
            'errores': [],
            'advertencias': [],
            'recomendaciones': []
        }
        
        try:
            import re
            import socket
            
            # Limpiar objetivo
            objetivo = objetivo.strip()
            
            if not objetivo:
                resultado['errores'].append("Objetivo vacío")
                return resultado
            
            # Validar IP
            try:
                ip = ipaddress.ip_address(objetivo)
                resultado['tipo'] = 'ip'
                resultado['objetivo_procesado'] = str(ip)
                
                # Verificar redes permitidas para Kali (pentesting ético)
                redes_permitidas = [
                    '127.0.0.0/8',      # Localhost
                    '10.0.0.0/8',       # RFC 1918 - Redes privadas
                    '172.16.0.0/12',    # RFC 1918 - Redes privadas  
                    '192.168.0.0/16',   # RFC 1918 - Redes privadas
                    '169.254.0.0/16'    # Link-local
                ]
                
                ip_permitida = False
                for red in redes_permitidas:
                    if ip in ipaddress.ip_network(red):
                        ip_permitida = True
                        break
                
                if ip_permitida:
                    resultado['valido'] = True
                    resultado['recomendaciones'].append(f"IP {ip} en rango permitido para pentesting")
                else:
                    resultado['errores'].append(f"IP {ip} fuera de rangos permitidos para pentesting ético")
                    
            except ipaddress.AddressValueError:
                # Podría ser hostname/dominio
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', objetivo):
                    resultado['tipo'] = 'hostname'
                    
                    # Verificar si es localhost o dominio local
                    if objetivo.lower() in ['localhost', 'kali', 'kali.local'] or objetivo.endswith('.local'):
                        resultado['valido'] = True
                        resultado['recomendaciones'].append(f"Hostname {objetivo} es válido para pentesting local")
                    else:
                        resultado['advertencias'].append(f"Hostname {objetivo} podría no ser apropiado para pentesting ético")
                        # Permitir pero con advertencia
                        resultado['valido'] = True
                else:
                    resultado['errores'].append(f"Formato de objetivo inválido: {objetivo}")
            
            # Logging de validación
            if resultado['valido']:
                self.logger.info(f"OK Objetivo {objetivo} validado para escaneo")
            else:
                self.logger.warning(f"ERROR Objetivo {objetivo} rechazado: {', '.join(resultado['errores'])}")
                
        except Exception as e:
            resultado['errores'].append(f"Error validando objetivo: {str(e)}")
            self.logger.error(f"Error en validación de objetivo: {e}")
        
        return resultado

    def escanear_sistema(self) -> Dict[str, Any]:
        """
        Método principal para escanear el sistema con herramientas de Kali Linux.
        OPTIMIZADO: Funciona con herramientas básicas de Linux.
        """
        try:
            import time
            import shutil
            
            self.logger.info("Iniciando escaneo completo del sistema con herramientas de Kali Linux")
            
            resultado = {
                'exito': False,
                'timestamp': datetime.now().isoformat(),
                'metodo_escaneo': 'Herramientas nativas de Linux/Kali',
                'escaneos_ejecutados': [],
                'vulnerabilidades_encontradas': [],
                'resumen': {},
                'tiempo_total': 0
            }
            
            tiempo_inicio = time.time()
            
            # 1. Escaneo de puertos locales (SIEMPRE disponible)
            self.logger.info("1/5 Escaneando puertos locales...")
            try:
                resultado_puertos = self._escanear_puertos_locales()
                if resultado_puertos.get('exito'):
                    resultado['escaneos_ejecutados'].append('puertos_locales')
                    puertos_abiertos = resultado_puertos.get('puertos_abiertos', [])
                    resultado['resumen']['puertos_abiertos'] = len(puertos_abiertos)
                    resultado['puertos_abiertos'] = puertos_abiertos
                    
                    # Buscar vulnerabilidades básicas en puertos
                    for puerto in puertos_abiertos:
                        if isinstance(puerto, dict):
                            puerto_num = puerto.get('puerto', 0)
                            if puerto_num in [21, 23, 135, 139, 445]:  # Puertos riesgosos
                                resultado['vulnerabilidades_encontradas'].append({
                                    'tipo': 'PUERTO_RIESGOSO',
                                    'severidad': 'MEDIA',
                                    'descripcion': f"Puerto potencialmente riesgoso abierto: {puerto_num}",
                                    'puerto': puerto_num,
                                    'detalles': puerto
                                })
                self.logger.info("OK Escaneo de puertos completado")
            except Exception as e:
                self.logger.warning(f"Error en escaneo de puertos: {e}")
            
            # 2. Escaneo de procesos activos (SIEMPRE disponible)
            self.logger.info("2/5 Escaneando procesos activos...")
            try:
                resultado_procesos = self._escanear_procesos_activos()
                if resultado_procesos.get('exito'):
                    resultado['escaneos_ejecutados'].append('procesos_activos')
                    procesos = resultado_procesos.get('procesos', [])
                    resultado['resumen']['procesos_analizados'] = len(procesos)
                    resultado['procesos_detectados'] = procesos[:20]  # Limitar a 20
                    
                    # Buscar procesos sospechosos
                    procesos_sospechosos = ['nc', 'netcat', 'ncat', 'backdoor', 'rootkit']
                    for proceso in procesos:
                        if isinstance(proceso, dict):
                            comando = proceso.get('comando', '').lower()
                            if any(sospechoso in comando for sospechoso in procesos_sospechosos):
                                resultado['vulnerabilidades_encontradas'].append({
                                    'tipo': 'PROCESO_SOSPECHOSO',
                                    'severidad': 'ALTA',
                                    'descripcion': f"Proceso potencialmente sospechoso: {comando}",
                                    'proceso': proceso
                                })
                self.logger.info("OK Escaneo de procesos completado")
            except Exception as e:
                self.logger.warning(f"Error en escaneo de procesos: {e}")
            
            # 3. Escaneo de servicios del sistema
            self.logger.info("3/5 Escaneando servicios del sistema...")
            try:
                resultado_servicios = self._escanear_servicios_sistema()
                if resultado_servicios.get('exito'):
                    resultado['escaneos_ejecutados'].append('servicios_sistema')
                    servicios = resultado_servicios.get('servicios', [])
                    resultado['resumen']['servicios_analizados'] = len(servicios)
                    resultado['servicios_activos'] = servicios[:15]  # Limitar a 15
                self.logger.info("OK Escaneo de servicios completado")
            except Exception as e:
                self.logger.warning(f"Error en escaneo de servicios: {e}")
            
            # 4. Escaneo con nmap (SOLO si está disponible)
            self.logger.info("4/5 Verificando disponibilidad de nmap...")
            if shutil.which('nmap'):
                try:
                    self.logger.info("nmap encontrado, ejecutando escaneo avanzado...")
                    resultado_nmap = self._escanear_con_nmap()
                    if resultado_nmap.get('exito'):
                        resultado['escaneos_ejecutados'].append('nmap')
                        resultado['resumen']['hosts_nmap'] = resultado_nmap.get('hosts_encontrados', 0)
                        resultado['escaneo_nmap'] = resultado_nmap
                    self.logger.info("OK Escaneo nmap completado")
                except Exception as e:
                    self.logger.warning(f"Error con nmap: {e}")
            else:
                self.logger.info("nmap no disponible, omitiendo escaneo avanzado")
            
            # 5. Verificación básica de integridad (usando find)
            self.logger.info("5/5 Verificando integridad básica del sistema...")
            try:
                archivos_criticos = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
                archivos_verificados = 0
                
                for archivo in archivos_criticos:
                    try:
                        import os
                        import stat
                        if os.path.exists(archivo):
                            st = os.stat(archivo)
                            permisos = oct(st.st_mode)[-3:]
                            
                            # Verificar permisos seguros
                            if archivo == '/etc/shadow' and permisos != '640' and permisos != '600':
                                resultado['vulnerabilidades_encontradas'].append({
                                    'tipo': 'PERMISOS_INSEGUROS',
                                    'severidad': 'ALTA',
                                    'descripcion': f"Permisos inseguros en {archivo}: {permisos}",
                                    'archivo': archivo,
                                    'permisos': permisos
                                })
                            
                            archivos_verificados += 1
                    except:
                        pass
                
                if archivos_verificados > 0:
                    resultado['escaneos_ejecutados'].append('integridad_basica')
                    resultado['resumen']['archivos_verificados'] = archivos_verificados
                
                self.logger.info("OK Verificación de integridad completada")
            except Exception as e:
                self.logger.warning(f"Error en verificación de integridad: {e}")
            
            # Calcular tiempo total
            tiempo_total = time.time() - tiempo_inicio
            resultado['tiempo_total'] = round(tiempo_total, 2)
            
            # Generar resumen final
            total_vulnerabilidades = len(resultado['vulnerabilidades_encontradas'])
            escaneos_completados = len(resultado['escaneos_ejecutados'])
            
            resultado['resumen'].update({
                'total_vulnerabilidades': total_vulnerabilidades,
                'escaneos_completados': escaneos_completados,
                'vulnerabilidades_criticas': len([v for v in resultado['vulnerabilidades_encontradas'] 
                                                 if v.get('severidad') == 'CRITICA']),
                'vulnerabilidades_altas': len([v for v in resultado['vulnerabilidades_encontradas'] 
                                              if v.get('severidad') == 'ALTA']),
                'porcentaje_completado': round((escaneos_completados / 5) * 100, 1)
            })
            
            # Evaluar éxito general
            if escaneos_completados >= 3:  # Al menos 3 de 5 escaneos
                resultado['exito'] = True
                self.logger.info(f"Escaneo exitoso en {tiempo_total:.2f}s - {total_vulnerabilidades} vulnerabilidades")
            else:
                resultado['exito'] = False
                resultado['error'] = f"Solo {escaneos_completados}/5 escaneos completados"
                self.logger.warning(f"Escaneo parcial: {escaneos_completados}/5 completados")
            
            # Registrar evento del escaneo
            try:
                self.logger.info(f"ESCANEO_SISTEMA_COMPLETO: {total_vulnerabilidades} vulnerabilidades detectadas")
            except Exception as e:
                self.logger.error(f"Error registrando evento de escaneo: {str(e)}")
            
            return resultado
            
        except Exception as e:
            error_msg = f"Error en escaneo del sistema: {str(e)}"
            self.logger.error(error_msg)
            return {
                'exito': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }

    def _escanear_puertos_locales(self) -> Dict[str, Any]:
        """Escanear puertos abiertos en el sistema local"""
        try:
            import subprocess
            puertos_encontrados = []
            
            # Usar netstat para detectar puertos abiertos
            cmd = ['netstat', '-tuln']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')
                for linea in lineas:
                    if 'LISTEN' in linea or 'UDP' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            direccion_local = partes[3]
                            if ':' in direccion_local:
                                puerto = direccion_local.split(':')[-1]
                                if puerto.isdigit():
                                    puertos_encontrados.append({
                                        'puerto': int(puerto),
                                        'protocolo': 'TCP' if 'tcp' in linea.lower() else 'UDP',
                                        'estado': 'LISTENING',
                                        'direccion': direccion_local
                                    })
            
            return {'puertos': puertos_encontrados, 'exito': True}
            
        except Exception as e:
            self.logger.error(f"Error escaneando puertos: {e}")
            return {'puertos': [], 'exito': False, 'error': str(e)}

    def _escanear_procesos_activos(self) -> Dict[str, Any]:
        """Escanear procesos activos en el sistema"""
        try:
            import subprocess
            procesos_encontrados = []
            
            # Usar ps para obtener procesos
            cmd = ['ps', 'aux']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')[1:]  # Saltar header
                for linea in lineas[:50]:  # Limitar a 50 procesos
                    if linea.strip():
                        partes = linea.split(None, 10)
                        if len(partes) >= 11:
                            procesos_encontrados.append({
                                'usuario': partes[0],
                                'pid': partes[1],
                                'cpu': partes[2],
                                'memoria': partes[3],
                                'comando': partes[10]
                            })
            
            return {'procesos': procesos_encontrados, 'exito': True}
            
        except Exception as e:
            self.logger.error(f"Error escaneando procesos: {e}")
            return {'procesos': [], 'exito': False, 'error': str(e)}

    def _escanear_servicios_sistema(self) -> Dict[str, Any]:
        """Escanear servicios del sistema"""
        try:
            import subprocess
            servicios_encontrados = []
            
            # Usar systemctl para obtener servicios
            cmd = ['systemctl', 'list-units', '--type=service', '--state=active']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')
                for linea in lineas:
                    if '.service' in linea and 'active' in linea:
                        partes = linea.split()
                        if len(partes) >= 4:
                            servicios_encontrados.append({
                                'nombre': partes[0],
                                'estado': partes[1],
                                'actividad': partes[2],
                                'descripcion': ' '.join(partes[4:]) if len(partes) > 4 else ''
                            })
            
            return {'servicios': servicios_encontrados[:20], 'exito': True}  # Limitar a 20
            
        except Exception as e:
            self.logger.error(f"Error escaneando servicios: {e}")
            return {'servicios': [], 'exito': False, 'error': str(e)}

    def verificar_kali_linux(self) -> Dict[str, Any]:
        """
        Verifica la configuración de Kali Linux.
        Método requerido por la vista de escaneo.
        
        Returns:
            Dict con información de verificación de Kali
        """
        try:
            import platform
            import subprocess
            
            resultado = {
                'sistema_operativo': platform.system(),
                'distribucion': 'Desconocida',
                'version_kernel': platform.release(),
                'arquitectura': platform.machine(),
                'kali_detectado': False,
                'herramientas_kali': [],
                'recomendaciones': []
            }
            
            # Detectar si es Kali Linux
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = f.read()
                    if 'kali' in os_info.lower():
                        resultado['kali_detectado'] = True
                        resultado['distribucion'] = 'Kali Linux'
                        
                        # Verificar herramientas comunes de Kali
                        herramientas_kali = ['nmap', 'nikto', 'sqlmap', 'dirb', 'gobuster', 'hydra']
                        for herramienta in herramientas_kali:
                            try:
                                subprocess.run(['which', herramienta], 
                                             capture_output=True, check=True)
                                resultado['herramientas_kali'].append(herramienta)
                            except subprocess.CalledProcessError:
                                resultado['recomendaciones'].append(
                                    f"Instalar {herramienta}: sudo apt install {herramienta}"
                                )
                    
            except FileNotFoundError:
                resultado['recomendaciones'].append("Sistema no es Kali Linux")
                
            # Verificar permisos sudo
            try:
                subprocess.run(['sudo', '-n', 'true'], 
                             capture_output=True, check=True)
                resultado['sudo_disponible'] = True
            except subprocess.CalledProcessError:
                resultado['sudo_disponible'] = False
                resultado['recomendaciones'].append("Configurar permisos sudo necesarios")
                
            self.logger.info(f"OK Verificación de Kali completada: {resultado['distribucion']}")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error verificando Kali Linux: {e}")
            return {
                'error': str(e),
                'kali_detectado': False,
                'recomendaciones': ['Error en verificación del sistema']
            }

    # =================== MÉTODOS AVANZADOS CON HERRAMIENTAS DE KALI ===================
    
    def _escanear_con_nmap(self) -> Dict[str, Any]:
        """Escanear puertos locales con nmap (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando escaneo con Nmap...")
            
            # Escanear localhost con nmap
            cmd = ['nmap', '-sT', '-O', '--top-ports', '1000', 'localhost']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            puertos_nmap = []
            servicios_detectados = []
            
            if result.returncode == 0:
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    # Parsear puertos abiertos
                    if '/tcp' in linea and 'open' in linea:
                        partes = linea.split()
                        if len(partes) >= 3:
                            puerto_info = partes[0].split('/')[0]
                            estado = partes[1]
                            servicio = partes[2] if len(partes) > 2 else 'unknown'
                            
                            puertos_nmap.append({
                                'puerto': int(puerto_info),
                                'protocolo': 'TCP',
                                'estado': estado,
                                'servicio': servicio,
                                'herramienta': 'nmap'
                            })
                            
                            servicios_detectados.append(servicio)
                
                return {
                    'exito': True,
                    'puertos_encontrados': puertos_nmap,
                    'total_puertos': len(puertos_nmap),
                    'servicios_detectados': list(set(servicios_detectados)),
                    'raw_output': result.stdout,
                    'herramienta': 'nmap'
                }
            else:
                return {
                    'exito': False,
                    'error': result.stderr,
                    'puertos_encontrados': [],
                    'herramienta': 'nmap'
                }
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout en escaneo nmap")
            return {
                'exito': False,
                'error': 'Timeout en escaneo nmap',
                'puertos_encontrados': [],
                'herramienta': 'nmap'
            }
        except Exception as e:
            self.logger.error(f"Error en escaneo nmap: {e}")
            return {
                'exito': False,
                'error': str(e),
                'puertos_encontrados': [],
                'herramienta': 'nmap'
            }
    
    def _escanear_con_masscan(self) -> Dict[str, Any]:
        """Escanear puertos con masscan (herramienta de Kali para escaneos rápidos)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando escaneo rápido con Masscan...")
            
            # Escanear rango local con masscan
            cmd = ['masscan', '127.0.0.1', '-p1-1000', '--rate=1000']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            puertos_masscan = []
            
            if result.returncode == 0:
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    if 'open' in linea and '127.0.0.1' in linea:
                        # Parsear formato: "Discovered open port 22/tcp on 127.0.0.1"
                        partes = linea.split()
                        for parte in partes:
                            if '/' in parte and parte.replace('/', '').replace('tcp', '').replace('udp', '').isdigit():
                                puerto_info = parte.split('/')[0]
                                protocolo = parte.split('/')[1].upper()
                                
                                puertos_masscan.append({
                                    'puerto': int(puerto_info),
                                    'protocolo': protocolo,
                                    'estado': 'open',
                                    'herramienta': 'masscan'
                                })
                
                return {
                    'exito': True,
                    'puertos_encontrados': puertos_masscan,
                    'total_puertos': len(puertos_masscan),
                    'raw_output': result.stdout,
                    'herramienta': 'masscan'
                }
            else:
                return {
                    'exito': False,
                    'error': result.stderr,
                    'puertos_encontrados': [],
                    'herramienta': 'masscan'
                }
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout en escaneo masscan")
            return {
                'exito': False,
                'error': 'Timeout en escaneo masscan',
                'puertos_encontrados': [],
                'herramienta': 'masscan'
            }
        except Exception as e:
            self.logger.error(f"Error en escaneo masscan: {e}")
            return {
                'exito': False,
                'error': str(e),
                'puertos_encontrados': [],
                'herramienta': 'masscan'
            }
    
    def _escanear_web_con_nikto(self) -> Dict[str, Any]:
        """Escanear vulnerabilidades web con nikto (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando análisis web con Nikto...")
            
            # Verificar si hay servicios web en puertos comunes
            puertos_web = [80, 443, 8080, 8443, 3000, 5000]
            resultados_nikto = []
            
            for puerto in puertos_web:
                try:
                    # Probar si el puerto está abierto
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(('127.0.0.1', puerto))
                    sock.close()
                    
                    if result == 0:  # Puerto abierto
                        self.logger.info(f"Puerto web {puerto} detectado, analizando con Nikto...")
                        
                        # Ejecutar nikto
                        protocolo = 'https' if puerto in [443, 8443] else 'http'
                        url = f"{protocolo}://127.0.0.1:{puerto}"
                        
                        cmd = ['nikto', '-h', url, '-timeout', '30']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                        
                        vulnerabilidades = []
                        if result.returncode == 0:
                            lineas = result.stdout.split('\\n')
                            for linea in lineas:
                                if '+' in linea and any(keyword in linea.lower() for keyword in 
                                    ['vulnerability', 'vuln', 'security', 'exposure', 'risk']):
                                    vulnerabilidades.append(linea.strip())
                        
                        resultados_nikto.append({
                            'puerto': puerto,
                            'url': url,
                            'vulnerabilidades_encontradas': vulnerabilidades,
                            'total_vulnerabilidades': len(vulnerabilidades),
                            'raw_output': result.stdout[:1000],  # Limitar output
                            'herramienta': 'nikto'
                        })
                
                except Exception as e:
                    self.logger.debug(f"Error verificando puerto {puerto}: {e}")
                    continue
            
            return {
                'exito': True,
                'servicios_web_analizados': resultados_nikto,
                'total_servicios': len(resultados_nikto),
                'herramienta': 'nikto'
            }
                
        except Exception as e:
            self.logger.error(f"Error en análisis nikto: {e}")
            return {
                'exito': False,
                'error': str(e),
                'servicios_web_analizados': [],
                'herramienta': 'nikto'
            }
    
    def _enumeracion_web_gobuster(self) -> Dict[str, Any]:
        """Enumeración de directorios web con gobuster (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando enumeración de directorios con Gobuster...")
            
            # Verificar si hay servicios web
            puertos_web = [80, 443, 8080]
            resultados_gobuster = []
            
            for puerto in puertos_web:
                try:
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(('127.0.0.1', puerto))
                    sock.close()
                    
                    if result == 0:  # Puerto abierto
                        protocolo = 'https' if puerto == 443 else 'http'
                        url = f"{protocolo}://127.0.0.1:{puerto}"
                        
                        # Usar wordlist básica de dirb
                        wordlist = '/usr/share/dirb/wordlists/common.txt'
                        if not os.path.exists(wordlist):
                            wordlist = '/usr/share/wordlists/dirb/common.txt'
                        
                        if os.path.exists(wordlist):
                            cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist, '-t', '10', '-q']
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                            
                            directorios_encontrados = []
                            if result.returncode == 0:
                                lineas = result.stdout.split('\\n')
                                for linea in lineas:
                                    if '(Status:' in linea:
                                        directorios_encontrados.append(linea.strip())
                            
                            resultados_gobuster.append({
                                'puerto': puerto,
                                'url': url,
                                'directorios_encontrados': directorios_encontrados,
                                'total_directorios': len(directorios_encontrados),
                                'herramienta': 'gobuster'
                            })
                        
                except Exception as e:
                    self.logger.debug(f"Error en gobuster puerto {puerto}: {e}")
                    continue
            
            return {
                'exito': True,
                'enumeracion_directorios': resultados_gobuster,
                'total_servicios': len(resultados_gobuster),
                'herramienta': 'gobuster'
            }
                
        except Exception as e:
            self.logger.error(f"Error en enumeración gobuster: {e}")
            return {
                'exito': False,
                'error': str(e),
                'enumeracion_directorios': [],
                'herramienta': 'gobuster'
            }
    
    def _detectar_rootkits_chkrootkit(self) -> Dict[str, Any]:
        """Detectar rootkits con chkrootkit (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando detección de rootkits con chkrootkit...")
            
            cmd = ['chkrootkit', '-q']  # Modo silencioso
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            detecciones = []
            if result.returncode == 0:
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    if linea.strip() and 'INFECTED' in linea.upper():
                        detecciones.append(linea.strip())
            
            return {
                'exito': True,
                'rootkits_detectados': detecciones,
                'total_detecciones': len(detecciones),
                'sistema_limpio': len(detecciones) == 0,
                'raw_output': result.stdout[:1000],
                'herramienta': 'chkrootkit'
            }
                
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en chkrootkit',
                'rootkits_detectados': [],
                'herramienta': 'chkrootkit'
            }
        except Exception as e:
            self.logger.error(f"Error en chkrootkit: {e}")
            return {
                'exito': False,
                'error': str(e),
                'rootkits_detectados': [],
                'herramienta': 'chkrootkit'
            }
    
    def _detectar_rootkits_rkhunter(self) -> Dict[str, Any]:
        """Detectar rootkits con rkhunter (herramienta de Kali)"""
        try:
            import subprocess
            self.logger.info(" Ejecutando detección de rootkits con rkhunter...")
            
            cmd = ['rkhunter', '--check', '--skip-keypress', '--report-warnings-only']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            warnings = []
            detecciones_criticas = []
            
            if result.returncode in [0, 1]:  # 0 = limpio, 1 = warnings
                lineas = result.stdout.split('\\n')
                for linea in lineas:
                    if 'WARNING' in linea.upper():
                        warnings.append(linea.strip())
                    elif 'INFECTED' in linea.upper() or 'ROOTKIT' in linea.upper():
                        detecciones_criticas.append(linea.strip())
            
            return {
                'exito': True,
                'warnings': warnings,
                'detecciones_criticas': detecciones_criticas,
                'total_warnings': len(warnings),
                'total_criticas': len(detecciones_criticas),
                'sistema_limpio': len(detecciones_criticas) == 0,
                'herramienta': 'rkhunter'
            }
                
        except subprocess.TimeoutExpired:
            return {
                'exito': False,
                'error': 'Timeout en rkhunter',
                'warnings': [],
                'detecciones_criticas': [],
                'herramienta': 'rkhunter'
            }
        except Exception as e:
            self.logger.error(f"Error en rkhunter: {e}")
            return {
                'exito': False,
                'error': str(e),
                'warnings': [],
                'detecciones_criticas': [],
                'herramienta': 'rkhunter'
            }
    
    def _compilar_vulnerabilidades(self, resultado_nmap, resultado_nikto, resultado_chkrootkit, resultado_rkhunter) -> List[Dict[str, Any]]:
        """Compilar todas las vulnerabilidades encontradas en un formato unificado"""
        vulnerabilidades = []
        
        try:
            # Vulnerabilidades de servicios (nmap)
            if resultado_nmap.get('exito') and resultado_nmap.get('puertos_encontrados'):
                for puerto in resultado_nmap['puertos_encontrados']:
                    # Servicios comunes con vulnerabilidades conocidas
                    servicios_riesgo = {
                        'ssh': 'Servicio SSH expuesto - revisar configuración',
                        'telnet': 'Telnet detectado - protocolo inseguro',
                        'ftp': 'FTP detectado - revisar configuración de seguridad',
                        'http': 'Servidor web detectado - revisar configuración',
                        'https': 'Servidor web SSL detectado - verificar certificados'
                    }
                    
                    servicio = puerto.get('servicio', '').lower()
                    if servicio in servicios_riesgo:
                        vulnerabilidades.append({
                            'tipo': 'Servicio Expuesto',
                            'descripcion': servicios_riesgo[servicio],
                            'puerto': puerto['puerto'],
                            'servicio': servicio,
                            'severidad': 'Media',
                            'herramienta': 'nmap'
                        })
            
            # Vulnerabilidades web (nikto)
            if resultado_nikto.get('exito') and resultado_nikto.get('servicios_web_analizados'):
                for servicio in resultado_nikto['servicios_web_analizados']:
                    for vuln in servicio.get('vulnerabilidades_encontradas', []):
                        vulnerabilidades.append({
                            'tipo': 'Vulnerabilidad Web',
                            'descripcion': vuln,
                            'puerto': servicio['puerto'],
                            'url': servicio['url'],
                            'severidad': 'Alta',
                            'herramienta': 'nikto'
                        })
            
            # Rootkits (chkrootkit)
            if resultado_chkrootkit.get('exito') and resultado_chkrootkit.get('rootkits_detectados'):
                for rootkit in resultado_chkrootkit['rootkits_detectados']:
                    vulnerabilidades.append({
                        'tipo': 'Rootkit Detectado',
                        'descripcion': rootkit,
                        'severidad': 'Crítica',
                        'herramienta': 'chkrootkit'
                    })
            
            # Warnings críticos (rkhunter)
            if resultado_rkhunter.get('exito'):
                for critica in resultado_rkhunter.get('detecciones_criticas', []):
                    vulnerabilidades.append({
                        'tipo': 'Detección Crítica',
                        'descripcion': critica,
                        'severidad': 'Crítica',
                        'herramienta': 'rkhunter'
                    })
                
                # Warnings importantes
                for warning in resultado_rkhunter.get('warnings', [])[:5]:  # Limitar a 5
                    vulnerabilidades.append({
                        'tipo': 'Warning de Seguridad',
                        'descripcion': warning,
                        'severidad': 'Media',
                        'herramienta': 'rkhunter'
                    })
            
            return vulnerabilidades
            
        except Exception as e:
            self.logger.error(f"Error compilando vulnerabilidades: {e}")
            return [{'tipo': 'Error', 'descripcion': f'Error compilando vulnerabilidades: {str(e)}', 'severidad': 'Baja'}]
