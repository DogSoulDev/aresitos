# -*- coding: utf-8 -*-
"""
ARESITOS - Controlador de Actualización
=======================================

Controlador para manejar el sistema de actualización integral de ARESITOS.
Maneja actualizaciones de Kali Linux, herramientas y bases de datos.

Autor: DogSoulDev
Fecha: 16 de Agosto de 2025
"""

import subprocess
import os
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from aresitos.controlador.controlador_base import ControladorBase

class ControladorActualizacion(ControladorBase):
    """
    Controlador para el sistema de actualización integral de ARESITOS.
    Maneja actualizaciones del sistema, herramientas y bases de datos.
    """
    
    def __init__(self, modelo):
        super().__init__(modelo, "ControladorActualizacion")
        
        # Estado del sistema de actualización
        self.actualizacion_en_progreso = False
        self.ultima_verificacion = None
        self.actualizaciones_pendientes = {}
        
        # URLs oficiales para actualizaciones
        self.urls_oficiales = {
            'kali_repo': 'http://http.kali.org/kali',
            'kali_security': 'http://security.kali.org/kali-security',
            'nmap_scripts': 'https://svn.nmap.org/nmap/scripts/',
            'metasploit': 'https://github.com/rapid7/metasploit-framework',
            'wordlists': 'https://github.com/danielmiessler/SecLists'
        }
        
        # Herramientas críticas de pentesting
        self.herramientas_criticas = [
            'nmap', 'sqlmap', 'hydra', 'nikto', 'metasploit-framework',
            'burpsuite', 'wireshark', 'aircrack-ng', 'john', 'hashcat',
            'gobuster', 'dirb', 'wfuzz', 'masscan', 'nessus'
        ]
        
        # Configuraciones importantes del sistema
        self.configuraciones_sistema = [
            '/etc/ssh/sshd_config',
            '/etc/sudoers', 
            '/etc/hosts',
            '/etc/resolv.conf',
            '/etc/apt/sources.list'
        ]
        
        self.logger.info("Controlador de Actualización inicializado")
    
    async def _inicializar_impl(self) -> Dict[str, Any]:
        """Implementación específica de inicialización del controlador de actualización."""
        try:
            self.logger.info("Inicializando sistema de actualización...")
            
            # Verificar que estamos en un sistema Linux compatible
            import platform
            if platform.system().lower() != 'linux':
                return {
                    'exito': False,
                    'error': 'Sistema de actualización solo compatible con Linux'
                }
            
            # Verificar herramientas básicas del sistema
            herramientas_requeridas = ['apt', 'sudo', 'which']
            herramientas_faltantes = []
            
            for herramienta in herramientas_requeridas:
                try:
                    resultado = subprocess.run(['which', herramienta], 
                                             capture_output=True, timeout=5)
                    if resultado.returncode != 0:
                        herramientas_faltantes.append(herramienta)
                except Exception:
                    herramientas_faltantes.append(herramienta)
            
            if herramientas_faltantes:
                return {
                    'exito': False,
                    'error': f'Herramientas faltantes: {", ".join(herramientas_faltantes)}'
                }
            
            # Verificación inicial de actualizaciones
            self.logger.info("Realizando verificación inicial de actualizaciones...")
            verificacion_inicial = self.verificar_actualizaciones_disponibles()
            
            resultado = {
                'exito': True,
                'mensaje': 'Sistema de actualización inicializado correctamente',
                'verificacion_inicial': verificacion_inicial,
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info("Sistema de actualización inicializado exitosamente")
            return resultado
            
        except Exception as e:
            error_msg = f"Error inicializando sistema de actualización: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    async def _finalizar_impl(self) -> Dict[str, Any]:
        """Implementación específica de finalización del controlador de actualización."""
        try:
            self.logger.info("Finalizando sistema de actualización...")
            
            # Cancelar cualquier actualización en progreso
            if self.actualizacion_en_progreso:
                self.cancelar_actualizacion()
            
            # Limpiar estado interno
            self.actualizacion_en_progreso = False
            self.ultima_verificacion = None
            self.actualizaciones_pendientes = {}
            
            resultado = {
                'exito': True,
                'mensaje': 'Sistema de actualización finalizado correctamente',
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info("Sistema de actualización finalizado exitosamente")
            return resultado
            
        except Exception as e:
            error_msg = f"Error finalizando sistema de actualización: {str(e)}"
            self.logger.error(error_msg)
            return {'exito': False, 'error': error_msg}
    
    def verificar_actualizaciones_disponibles(self) -> Dict[str, Any]:
        """
        Verificar qué actualizaciones están disponibles en el sistema.
        
        Returns:
            Dict con información de actualizaciones disponibles
        """
        resultado = {
            'exito': False,
            'timestamp': datetime.now().isoformat(),
            'sistema': {},
            'herramientas': {},
            'bases_datos': {},
            'configuraciones': {},
            'resumen': {
                'total_actualizaciones': 0,
                'criticas': 0,
                'recomendadas': 0
            }
        }
        
        try:
            self.logger.info("Verificando actualizaciones disponibles...")
            
            # 1. Verificar actualizaciones del sistema
            resultado['sistema'] = self._verificar_sistema_kali()
            
            # 2. Verificar herramientas
            resultado['herramientas'] = self._verificar_herramientas()
            
            # 3. Verificar bases de datos
            resultado['bases_datos'] = self._verificar_bases_datos()
            
            # 4. Verificar configuraciones
            resultado['configuraciones'] = self._verificar_configuraciones()
            
            # 5. Generar resumen
            resultado['resumen'] = self._generar_resumen_actualizaciones(resultado)
            
            resultado['exito'] = True
            self.ultima_verificacion = datetime.now()
            
            self.logger.info(f"Verificación completada: {resultado['resumen']['total_actualizaciones']} actualizaciones disponibles")
            
        except Exception as e:
            resultado['error'] = str(e)
            self.logger.error(f"Error verificando actualizaciones: {e}")
        
        return resultado
    
    def _verificar_sistema_kali(self) -> Dict[str, Any]:
        """Verificar actualizaciones del sistema Kali Linux"""
        sistema = {
            'actualizaciones_disponibles': 0,
            'paquetes_actualizables': [],
            'espacio_requerido': '0 MB',
            'ultima_actualizacion': None
        }
        
        try:
            # Actualizar lista de paquetes sin modificar el sistema
            subprocess.run(['sudo', 'apt', 'update'], 
                         capture_output=True, timeout=120, check=True)
            
            # Obtener lista de paquetes actualizables
            result = subprocess.run(['apt', 'list', '--upgradable'], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                lineas = result.stdout.split('\n')
                paquetes = [linea for linea in lineas if 'upgradable' in linea]
                
                sistema['actualizaciones_disponibles'] = len(paquetes)
                sistema['paquetes_actualizables'] = paquetes[:10]  # Primeros 10
                
                # Simular cálculo de espacio (apt no siempre lo proporciona)
                if len(paquetes) > 0:
                    sistema['espacio_requerido'] = f"{len(paquetes) * 5} MB (estimado)"
            
            # Obtener fecha de última actualización
            try:
                stat_info = os.stat('/var/lib/apt/periodic/update-success-stamp')
                sistema['ultima_actualizacion'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            except:
                sistema['ultima_actualizacion'] = "Desconocida"
                
        except subprocess.TimeoutExpired:
            sistema['error'] = "Timeout verificando sistema"
        except subprocess.CalledProcessError as e:
            sistema['error'] = f"Error ejecutando apt: {e}"
        except Exception as e:
            sistema['error'] = str(e)
        
        return sistema
    
    def _verificar_herramientas(self) -> Dict[str, Any]:
        """Verificar estado de herramientas de pentesting"""
        herramientas = {
            'instaladas': 0,
            'faltantes': 0,
            'detalles': {},
            'recomendaciones': []
        }
        
        for herramienta in self.herramientas_criticas:
            try:
                # Verificar si está instalada
                result = subprocess.run(['which', herramienta], 
                                      capture_output=True, timeout=5)
                
                if result.returncode == 0:
                    herramientas['instaladas'] += 1
                    ruta = result.stdout.decode().strip()
                    
                    # Obtener versión si es posible
                    version = self._obtener_version_herramienta(herramienta)
                    
                    herramientas['detalles'][herramienta] = {
                        'estado': 'instalada',
                        'ruta': ruta,
                        'version': version
                    }
                else:
                    herramientas['faltantes'] += 1
                    herramientas['detalles'][herramienta] = {
                        'estado': 'faltante',
                        'ruta': None,
                        'version': None
                    }
                    herramientas['recomendaciones'].append(f"Instalar {herramienta}")
                    
            except Exception as e:
                herramientas['detalles'][herramienta] = {
                    'estado': 'error',
                    'error': str(e)
                }
        
        return herramientas
    
    def _obtener_version_herramienta(self, herramienta: str) -> Optional[str]:
        """Obtener versión de una herramienta específica"""
        comandos_version = {
            'nmap': ['nmap', '--version'],
            'sqlmap': ['sqlmap', '--version'],
            'hydra': ['hydra', '-h'],
            'nikto': ['nikto', '-Version'],
            'metasploit-framework': ['msfconsole', '--version'],
            'john': ['john', '--version'],
            'hashcat': ['hashcat', '--version']
        }
        
        try:
            if herramienta in comandos_version:
                result = subprocess.run(comandos_version[herramienta], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Extraer primera línea que generalmente contiene la versión
                    return result.stdout.split('\n')[0][:100]  # Limitar longitud
        except:
            pass
        
        return "Versión no disponible"
    
    def _verificar_bases_datos(self) -> Dict[str, Any]:
        """Verificar estado de bases de datos de seguridad"""
        bases_datos = {
            'nse_scripts': self._verificar_nse_scripts(),
            'wordlists': self._verificar_wordlists(),
            'metasploit_db': self._verificar_metasploit_db(),
            'locate_db': self._verificar_locate_db()
        }
        
        return bases_datos
    
    def _verificar_nse_scripts(self) -> Dict[str, Any]:
        """Verificar scripts NSE de Nmap"""
        nse_info = {'estado': 'desconocido', 'scripts': 0, 'ultima_actualizacion': None}
        
        try:
            scripts_dir = '/usr/share/nmap/scripts'
            if os.path.exists(scripts_dir):
                scripts = [f for f in os.listdir(scripts_dir) if f.endswith('.nse')]
                nse_info['scripts'] = len(scripts)
                nse_info['estado'] = 'disponible'
                
                # Fecha de modificación del directorio
                stat_info = os.stat(scripts_dir)
                nse_info['ultima_actualizacion'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            else:
                nse_info['estado'] = 'no_encontrado'
        except Exception as e:
            nse_info['error'] = str(e)
        
        return nse_info
    
    def _verificar_wordlists(self) -> Dict[str, Any]:
        """Verificar wordlists del sistema"""
        wordlists_info = {'estado': 'desconocido', 'archivos': 0, 'tamaño_total': '0 MB'}
        
        try:
            wordlists_dir = '/usr/share/wordlists'
            if os.path.exists(wordlists_dir):
                archivos = []
                tamaño_total = 0
                
                for root, dirs, files in os.walk(wordlists_dir):
                    for file in files:
                        ruta_completa = os.path.join(root, file)
                        try:
                            tamaño_total += os.path.getsize(ruta_completa)
                            archivos.append(file)
                        except:
                            pass
                
                wordlists_info['archivos'] = len(archivos)
                wordlists_info['tamaño_total'] = f"{tamaño_total // (1024*1024)} MB"
                wordlists_info['estado'] = 'disponible'
            else:
                wordlists_info['estado'] = 'no_encontrado'
        except Exception as e:
            wordlists_info['error'] = str(e)
        
        return wordlists_info
    
    def _verificar_metasploit_db(self) -> Dict[str, Any]:
        """Verificar base de datos de Metasploit"""
        msf_info = {'estado': 'desconocido', 'version': None}
        
        try:
            # Verificar si msfdb está disponible
            result = subprocess.run(['which', 'msfdb'], capture_output=True, timeout=5)
            if result.returncode == 0:
                # Verificar estado de la base de datos
                result = subprocess.run(['msfdb', 'status'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    msf_info['estado'] = 'activa' if 'active' in result.stdout.lower() else 'inactiva'
                else:
                    msf_info['estado'] = 'no_configurada'
            else:
                msf_info['estado'] = 'no_instalado'
        except Exception as e:
            msf_info['error'] = str(e)
        
        return msf_info
    
    def _verificar_locate_db(self) -> Dict[str, Any]:
        """Verificar base de datos locate"""
        locate_info = {'estado': 'desconocido', 'ultima_actualizacion': None}
        
        try:
            db_path = '/var/lib/mlocate/mlocate.db'
            if os.path.exists(db_path):
                stat_info = os.stat(db_path)
                locate_info['ultima_actualizacion'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                locate_info['estado'] = 'disponible'
            else:
                locate_info['estado'] = 'no_encontrado'
        except Exception as e:
            locate_info['error'] = str(e)
        
        return locate_info
    
    def _verificar_configuraciones(self) -> Dict[str, Any]:
        """Verificar configuraciones importantes del sistema"""
        configuraciones = {'archivos': {}, 'ssh': {}, 'sudo': {}}
        
        # Verificar archivos de configuración
        for archivo in self.configuraciones_sistema:
            try:
                if os.path.exists(archivo):
                    stat_info = os.stat(archivo)
                    configuraciones['archivos'][archivo] = {
                        'existe': True,
                        'permisos': oct(stat_info.st_mode)[-3:],
                        'ultima_modificacion': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                    }
                else:
                    configuraciones['archivos'][archivo] = {'existe': False}
            except Exception as e:
                configuraciones['archivos'][archivo] = {'error': str(e)}
        
        # Verificar configuración SSH específica
        configuraciones['ssh'] = self._verificar_config_ssh()
        
        # Verificar configuración sudo
        configuraciones['sudo'] = self._verificar_config_sudo()
        
        return configuraciones
    
    def _verificar_config_ssh(self) -> Dict[str, Any]:
        """Verificar configuración SSH"""
        ssh_config = {'puerto': 22, 'root_login': 'unknown', 'password_auth': 'unknown'}
        
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                contenido = f.read()
                
                # Extraer configuraciones importantes
                for linea in contenido.split('\n'):
                    linea = linea.strip()
                    if linea.startswith('Port '):
                        ssh_config['puerto'] = int(linea.split()[1])
                    elif linea.startswith('PermitRootLogin '):
                        ssh_config['root_login'] = linea.split()[1]
                    elif linea.startswith('PasswordAuthentication '):
                        ssh_config['password_auth'] = linea.split()[1]
        except Exception as e:
            ssh_config['error'] = str(e)
        
        return ssh_config
    
    def _verificar_config_sudo(self) -> Dict[str, Any]:
        """Verificar configuración sudo"""
        sudo_config = {'timeout': 'unknown', 'require_password': True}
        
        try:
            # Verificar si el usuario actual puede ejecutar sudo sin password
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, timeout=5)
            sudo_config['require_password'] = result.returncode != 0
        except Exception as e:
            sudo_config['error'] = str(e)
        
        return sudo_config
    
    def _generar_resumen_actualizaciones(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generar resumen de actualizaciones"""
        resumen = {
            'total_actualizaciones': 0,
            'criticas': 0,
            'recomendadas': 0,
            'estado_general': 'desconocido'
        }
        
        # Contar actualizaciones del sistema
        if 'sistema' in data and data['sistema'].get('actualizaciones_disponibles', 0) > 0:
            resumen['total_actualizaciones'] += data['sistema']['actualizaciones_disponibles']
            resumen['criticas'] += data['sistema']['actualizaciones_disponibles']
        
        # Contar herramientas faltantes
        if 'herramientas' in data:
            faltantes = data['herramientas'].get('faltantes', 0)
            resumen['total_actualizaciones'] += faltantes
            resumen['recomendadas'] += faltantes
        
        # Determinar estado general
        if resumen['criticas'] > 0:
            resumen['estado_general'] = 'critico'
        elif resumen['recomendadas'] > 0:
            resumen['estado_general'] = 'recomendado'
        else:
            resumen['estado_general'] = 'actualizado'
        
        return resumen
    
    def ejecutar_actualizacion_completa(self, opciones: Dict[str, bool]) -> Dict[str, Any]:
        """
        Ejecutar actualización completa del sistema.
        
        Args:
            opciones: Dict con opciones de actualización (sistema, herramientas, etc.)
            
        Returns:
            Dict con resultado de la actualización
        """
        if self.actualizacion_en_progreso:
            return {'exito': False, 'error': 'Actualización ya en progreso'}
        
        self.actualizacion_en_progreso = True
        
        resultado = {
            'exito': False,
            'timestamp_inicio': datetime.now().isoformat(),
            'timestamp_fin': None,
            'componentes_actualizados': [],
            'errores': [],
            'reinicios_requeridos': []
        }
        
        try:
            self.logger.info("Iniciando actualización completa del sistema")
            
            # 1. Actualizar sistema Kali Linux
            if opciones.get('sistema', False):
                resultado_sistema = self._actualizar_sistema_kali()
                if resultado_sistema['exito']:
                    resultado['componentes_actualizados'].append('Sistema Kali Linux')
                else:
                    resultado['errores'].append(f"Sistema: {resultado_sistema.get('error', 'Error desconocido')}")
            
            # 2. Actualizar herramientas
            if opciones.get('herramientas', False):
                resultado_herramientas = self._actualizar_herramientas()
                if resultado_herramientas['exito']:
                    resultado['componentes_actualizados'].append('Herramientas de pentesting')
                else:
                    resultado['errores'].append(f"Herramientas: {resultado_herramientas.get('error', 'Error desconocido')}")
            
            # 3. Actualizar bases de datos
            if opciones.get('bases_datos', False):
                resultado_bd = self._actualizar_bases_datos()
                if resultado_bd['exito']:
                    resultado['componentes_actualizados'].append('Bases de datos')
                else:
                    resultado['errores'].append(f"Bases de datos: {resultado_bd.get('error', 'Error desconocido')}")
            
            # 4. Verificar si se requiere reinicio
            if self._verificar_reinicio_requerido():
                resultado['reinicios_requeridos'].append('Sistema completo')
            
            resultado['exito'] = len(resultado['errores']) == 0
            resultado['timestamp_fin'] = datetime.now().isoformat()
            
            self.logger.info(f"Actualización completada: {len(resultado['componentes_actualizados'])} componentes actualizados")
            
        except Exception as e:
            resultado['error'] = str(e)
            self.logger.error(f"Error durante actualización: {e}")
        finally:
            self.actualizacion_en_progreso = False
        
        return resultado
    
    def _actualizar_sistema_kali(self) -> Dict[str, Any]:
        """Actualizar sistema operativo Kali Linux"""
        resultado = {'exito': False, 'detalles': []}
        
        try:
            # 1. Actualizar lista de paquetes
            self.logger.info("Actualizando lista de paquetes...")
            subprocess.run(['sudo', 'apt', 'update'], timeout=300, check=True)
            resultado['detalles'].append("Lista de paquetes actualizada")
            
            # 2. Actualizar paquetes del sistema
            self.logger.info("Actualizando paquetes del sistema...")
            subprocess.run(['sudo', 'apt', 'upgrade', '-y'], timeout=1800, check=True)
            resultado['detalles'].append("Paquetes del sistema actualizados")
            
            # 3. Limpiar paquetes innecesarios
            self.logger.info("Limpiando paquetes innecesarios...")
            subprocess.run(['sudo', 'apt', 'autoremove', '-y'], timeout=300, check=True)
            subprocess.run(['sudo', 'apt', 'autoclean'], timeout=300, check=True)
            resultado['detalles'].append("Paquetes innecesarios limpiados")
            
            resultado['exito'] = True
            
        except subprocess.TimeoutExpired:
            resultado['error'] = "Timeout durante actualización del sistema"
        except subprocess.CalledProcessError as e:
            resultado['error'] = f"Error ejecutando comando: {e}"
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado
    
    def _actualizar_herramientas(self) -> Dict[str, Any]:
        """Actualizar herramientas de pentesting"""
        resultado = {'exito': False, 'detalles': []}
        
        try:
            # Actualizar Metasploit database
            try:
                subprocess.run(['sudo', 'msfdb', 'reinit'], timeout=300, check=True)
                resultado['detalles'].append("Base de datos Metasploit actualizada")
            except:
                resultado['detalles'].append("Error actualizando Metasploit")
            
            # Actualizar scripts NSE
            try:
                subprocess.run(['sudo', 'nmap', '--script-updatedb'], timeout=300, check=True)
                resultado['detalles'].append("Scripts NSE actualizados")
            except:
                resultado['detalles'].append("Error actualizando scripts NSE")
            
            resultado['exito'] = True
            
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado
    
    def _actualizar_bases_datos(self) -> Dict[str, Any]:
        """Actualizar bases de datos de seguridad"""
        resultado = {'exito': False, 'detalles': []}
        
        try:
            # Actualizar base de datos locate
            try:
                subprocess.run(['sudo', 'updatedb'], timeout=300, check=True)
                resultado['detalles'].append("Base de datos locate actualizada")
            except:
                resultado['detalles'].append("Error actualizando locate")
            
            resultado['exito'] = True
            
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado
    
    def _verificar_reinicio_requerido(self) -> bool:
        """Verificar si se requiere reinicio del sistema"""
        try:
            return os.path.exists('/var/run/reboot-required')
        except:
            return False
    
    def cancelar_actualizacion(self) -> Dict[str, Any]:
        """Cancelar actualización en progreso"""
        if not self.actualizacion_en_progreso:
            return {'exito': False, 'error': 'No hay actualización en progreso'}
        
        # Nota: En la práctica, cancelar apt upgrade puede ser complicado
        # Este método principalmente cambia el estado interno
        self.actualizacion_en_progreso = False
        
        self.logger.warning("Actualización cancelada por el usuario")
        
        return {
            'exito': True,
            'mensaje': 'Actualización cancelada. El sistema puede estar en estado inconsistente.'
        }


# RESUMEN: Controlador completo para sistema de actualización integral de ARESITOS
