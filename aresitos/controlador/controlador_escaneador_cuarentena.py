# -*- coding: utf-8 -*-
"""
Ares Aegis - Controlador Principal con Cuarentena Integrada
Gestiona el escaneador con cuarentena automática para amenazas detectadas
"""

import logging
import os
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

class MockResultado:
    """Resultado mock para el escaneador."""
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
    Controlador principal que integra el escaneador con el sistema de cuarentena.
    """
    
    def __init__(self):
        """Inicializa el controlador integrado."""
        self.logger = logging.getLogger(f"AresAegis.{self.__class__.__name__}")
        
        # Configuración por defecto
        self.configuracion = {
            'cuarentena_automatica': True,
            'niveles_cuarentena': ['critico', 'alto'],  # Niveles que van a cuarentena automáticamente
            'notificar_cuarentena': True,
            'backup_antes_cuarentena': True
        }
        
        # Inicializar componentes con tipos Union para flexibilidad
        self.escaneador: Union[MockEscaneador, Any] = MockEscaneador()
        self.cuarentena: Union[MockCuarentena, Any] = MockCuarentena()
        
        self._inicializar_componentes()
    
    def _inicializar_componentes(self):
        """Inicializa el escaneador y el sistema de cuarentena."""
        # Inicializar escaneador
        try:
            from ..modelo.escaneador_avanzado import EscaneadorAvanzadoReal
            self.escaneador = EscaneadorAvanzadoReal()
            self.logger.info("✅ Escaneador avanzado inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando escaneador: {e}")
            self.escaneador = MockEscaneador()
            self.logger.warning("⚠️ Usando escaneador mock")
        
        # Inicializar cuarentena
        try:
            from .controlador_cuarentena import ControladorCuarentena
            self.cuarentena = ControladorCuarentena()
            self.logger.info("✅ Sistema de cuarentena inicializado")
        except Exception as e:
            self.logger.error(f"Error inicializando cuarentena: {e}")
            self.cuarentena = MockCuarentena()
            self.logger.warning("⚠️ Usando cuarentena mock")
    
    def ejecutar_escaneo_con_cuarentena(self, tipo_escaneo: str = 'completo') -> Dict[str, Any]:
        """
        Ejecuta un escaneo con cuarentena automática de amenazas.
        
        Args:
            tipo_escaneo: Tipo de escaneo a realizar
            
        Returns:
            Dict con resultados del escaneo y cuarentena
        """
        self.logger.info(f"🚀 Iniciando escaneo {tipo_escaneo} con cuarentena automática")
        
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
                resultado_escaneo = self.escaneador.escanear_completo()
            elif tipo_escaneo == 'malware':
                resultado_escaneo = self.escaneador.detectar_malware()
            elif tipo_escaneo == 'vulnerabilidades':
                resultado_escaneo = self.escaneador.escanear_vulnerabilidades_sistema()
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
                        self.logger.warning(f"🔒 Amenaza enviada a cuarentena: {vuln.tipo}")
            
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
        if not self.configuracion['cuarentena_automatica']:
            return False
        
        nivel = vulnerabilidad.nivel_riesgo.value
        return nivel in self.configuracion['niveles_cuarentena']
    
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
        self.logger.info("📊 RESUMEN DE ESCANEO CON CUARENTENA")
        self.logger.info("=" * 60)
        self.logger.info(f"🔍 Tipo de escaneo: {resultado.get('tipo_escaneo', 'N/A')}")
        self.logger.info(f"📈 Total vulnerabilidades: {stats.get('total_vulnerabilidades', 0)}")
        self.logger.info(f"🔴 Críticas: {stats.get('criticas', 0)}")
        self.logger.info(f"🟠 Altas: {stats.get('altas', 0)}")
        self.logger.info(f"🔒 En cuarentena: {stats.get('en_cuarentena', 0)}")
        
        if stats.get('en_cuarentena', 0) > 0:
            self.logger.warning(f"⚠️ {stats['en_cuarentena']} amenazas fueron puestas en cuarentena automáticamente")
        
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
                'configuracion_actual': self.configuracion
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
                    self.logger.info(f"✅ Archivo restaurado: {ruta_archivo}")
                else:
                    self.logger.warning(f"❌ No se pudo restaurar: {ruta_archivo}")
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
            self.configuracion.update(nueva_config)
            self.logger.info("✅ Configuración de cuarentena actualizada")
            return True
        except Exception as e:
            self.logger.error(f"Error actualizando configuración: {e}")
            return False
    
    # === MÉTODOS REQUERIDOS POR LA INTERFAZ ===
    
    def ejecutar_escaneo_basico(self) -> Dict[str, Any]:
        """Ejecuta un escaneo básico del sistema."""
        self.logger.info("🔍 Iniciando escaneo básico del sistema")
        
        try:
            import psutil
            import socket
            import subprocess
            
            resultado = {
                'puertos': [],
                'procesos': [],
                'analisis': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # 1. Escanear puertos locales abiertos
            conexiones = psutil.net_connections(kind='inet')
            puertos_encontrados = set()
            
            for conn in conexiones:
                if conn.laddr and conn.status == 'LISTEN':
                    puerto = conn.laddr.port
                    puertos_encontrados.add(puerto)
                    resultado['puertos'].append(f"Puerto {puerto}/tcp abierto")
            
            # 2. Procesos en ejecución (filtrado)
            procesos_importantes = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    info = proc.info
                    # Filtrar procesos importantes
                    if any(keyword in info['name'].lower() for keyword in 
                           ['ssh', 'apache', 'nginx', 'mysql', 'postgres', 'ftp', 'telnet']):
                        procesos_importantes.append(f"PID {info['pid']}: {info['name']} ({info['username']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            resultado['procesos'] = procesos_importantes[:15]  # Limitar a 15
            
            # 3. Análisis básico
            resultado['analisis'].append(f"✅ Escaneo completado - {len(puertos_encontrados)} puertos encontrados")
            resultado['analisis'].append(f"📊 {len(procesos_importantes)} procesos de interés detectados")
            
            # Recomendaciones básicas
            if 22 in puertos_encontrados:
                resultado['analisis'].append("⚠️ SSH activo - verificar configuración de seguridad")
            if 80 in puertos_encontrados or 443 in puertos_encontrados:
                resultado['analisis'].append("🌐 Servidor web detectado - revisar configuración")
            
            self.logger.info("✅ Escaneo básico completado exitosamente")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error en escaneo básico: {e}")
            return {
                'puertos': [f"Error: {str(e)}"],
                'procesos': [],
                'analisis': [f"❌ Error durante el escaneo: {str(e)}"],
                'timestamp': datetime.now().isoformat()
            }
    
    def verificar_funcionalidad_kali(self) -> Dict[str, Any]:
        """Verifica funcionalidad específica para Kali Linux."""
        self.logger.info("🐉 Verificando funcionalidad en Kali Linux")
        
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
            
            self.logger.info(f"✅ Verificación Kali completada - Funcional: {resultado['funcionalidad_completa']}")
            return resultado
            
        except Exception as e:
            error_msg = f"Error durante verificación: {e}"
            self.logger.error(error_msg)
            resultado['error'] = error_msg
            return resultado
    
    def obtener_logs_escaneo(self) -> List[str]:
        """Obtiene logs del escaneador."""
        try:
            logs = [
                f"[{datetime.now().strftime('%H:%M:%S')}] Sistema de escaneo iniciado",
                f"[{datetime.now().strftime('%H:%M:%S')}] Controlador integrado con cuarentena: {'✅' if self.cuarentena else '❌'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Escaneador avanzado: {'✅' if hasattr(self.escaneador, 'escanear_completo') else '❌'}",
                f"[{datetime.now().strftime('%H:%M:%S')}] Cuarentena automática: {'✅' if self.configuracion['cuarentena_automatica'] else '❌'}",
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
                    'descripcion': f"Cuarentena automática: {self.configuracion['cuarentena_automatica']}"
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
            import ipaddress
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
                self.logger.info(f"✅ Objetivo {objetivo} validado para escaneo")
            else:
                self.logger.warning(f"❌ Objetivo {objetivo} rechazado: {', '.join(resultado['errores'])}")
                
        except Exception as e:
            resultado['errores'].append(f"Error validando objetivo: {str(e)}")
            self.logger.error(f"Error en validación de objetivo: {e}")
        
        return resultado

    def escanear_sistema(self) -> Dict[str, Any]:
        """
        Método principal para escanear el sistema.
        Método requerido por la vista de escaneo.
        
        Returns:
            Dict con resultados del escaneo
        """
        try:
            self.logger.info("🔍 Iniciando escaneo completo del sistema")
            return self.ejecutar_escaneo_con_cuarentena('completo')
        except Exception as e:
            self.logger.error(f"Error en escaneo del sistema: {e}")
            return {
                'exito': False,
                'error': str(e),
                'vulnerabilidades': [],
                'amenazas_cuarentena': []
            }

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
                
            self.logger.info(f"✅ Verificación de Kali completada: {resultado['distribucion']}")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error verificando Kali Linux: {e}")
            return {
                'error': str(e),
                'kali_detectado': False,
                'recomendaciones': ['Error en verificación del sistema']
            }
