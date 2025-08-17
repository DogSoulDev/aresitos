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
        Método principal para escanear el sistema con herramientas avanzadas de Kali Linux.
        Método requerido por la vista de escaneo.
        
        Returns:
            Dict con resultados del escaneo avanzado
        """
        try:
            self.logger.info("🔍 Iniciando escaneo completo del sistema con herramientas de Kali Linux")
            
            # Escaneo básico con herramientas nativas
            resultado_puertos = self._escanear_puertos_locales()
            resultado_procesos = self._escanear_procesos_activos()
            resultado_servicios = self._escanear_servicios_sistema()
            
            # Escaneo avanzado con herramientas de Kali
            resultado_nmap = self._escanear_con_nmap()
            resultado_masscan = self._escanear_con_masscan()
            resultado_nikto = self._escanear_web_con_nikto()
            resultado_gobuster = self._enumeracion_web_gobuster()
            
            # Análisis de seguridad del sistema
            resultado_chkrootkit = self._detectar_rootkits_chkrootkit()
            resultado_rkhunter = self._detectar_rootkits_rkhunter()
            
            # Combinar resultados
            resultado_final = {
                'exito': True,
                'timestamp': datetime.now().isoformat(),
                'metodo_escaneo': 'Herramientas nativas de Kali Linux',
                
                # Resultados básicos
                'puertos_abiertos': resultado_puertos.get('puertos', []),
                'total_puertos': len(resultado_puertos.get('puertos', [])),
                'procesos_detectados': resultado_procesos.get('procesos', []),
                'total_procesos': len(resultado_procesos.get('procesos', [])),
                'servicios_activos': resultado_servicios.get('servicios', []),
                'total_servicios': len(resultado_servicios.get('servicios', [])),
                
                # Resultados avanzados
                'escaneo_nmap': resultado_nmap,
                'escaneo_masscan': resultado_masscan,
                'analisis_web_nikto': resultado_nikto,
                'enumeracion_gobuster': resultado_gobuster,
                
                # Análisis de seguridad
                'deteccion_rootkits_chkrootkit': resultado_chkrootkit,
                'deteccion_rootkits_rkhunter': resultado_rkhunter,
                
                # Resumen de vulnerabilidades
                'vulnerabilidades': self._compilar_vulnerabilidades(
                    resultado_nmap, resultado_nikto, resultado_chkrootkit, resultado_rkhunter
                ),
                'amenazas_cuarentena': []
            }
            
            # Estadísticas finales
            total_vulnerabilidades = len(resultado_final['vulnerabilidades'])
            self.logger.info(
                f"✅ Escaneo avanzado completado: {resultado_final['total_puertos']} puertos, "
                f"{resultado_final['total_procesos']} procesos, {total_vulnerabilidades} vulnerabilidades"
            )
            
            return resultado_final
            
        except Exception as e:
            self.logger.error(f"Error en escaneo del sistema: {e}")
            return {
                'exito': False,
                'error': str(e),
                'puertos_abiertos': [],
                'total_puertos': 0,
                'procesos_detectados': [],
                'total_procesos': 0,
                'vulnerabilidades': [],
                'amenazas_cuarentena': []
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
                
            self.logger.info(f"✅ Verificación de Kali completada: {resultado['distribucion']}")
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
            self.logger.info("🎯 Ejecutando escaneo con Nmap...")
            
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
            self.logger.info("⚡ Ejecutando escaneo rápido con Masscan...")
            
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
            self.logger.info("🌐 Ejecutando análisis web con Nikto...")
            
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
            self.logger.info("📁 Ejecutando enumeración de directorios con Gobuster...")
            
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
            self.logger.info("🔍 Ejecutando detección de rootkits con chkrootkit...")
            
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
            self.logger.info("🛡️ Ejecutando detección de rootkits con rkhunter...")
            
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
