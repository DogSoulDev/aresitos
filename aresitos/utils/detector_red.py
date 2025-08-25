# -*- coding: utf-8 -*-
"""
ARESITOS - Detector de Red
==========================

Utilidad para detectar automáticamente la configuración de red del sistema.
Solo para Kali Linux.

Autor: DogSoulDev
Fecha: 23 de Agosto de 2025
"""

import subprocess
import re
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple, Any


class DetectorRed:
    """Detector automático de configuración de red para Kali Linux"""
    
    @staticmethod
    def obtener_red_local() -> Dict[str, Any]:
        """
        Detectar automáticamente la red local del sistema.
        
        Returns:
            Dict con ip_local, red_cidr, gateway, interfaz
        """
        try:
            # Usar ip route para obtener la ruta predeterminada
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            
            gateway = None
            interfaz = None
            
            # Analizar salida: default via 192.168.88.1 dev eth0 proto dhcp metric 100
            if result.stdout:
                match = re.search(r'default via (\S+) dev (\S+)', result.stdout)
                if match:
                    gateway = match.group(1)
                    interfaz = match.group(2)
            
            # Obtener IP de la interfaz principal
            if interfaz:
                result_addr = subprocess.run(['ip', 'addr', 'show', interfaz], 
                                           capture_output=True, text=True, timeout=5)
                
                # Buscar inet 192.168.88.133/24
                match = re.search(r'inet (\S+)/(\d+)', result_addr.stdout)
                if match:
                    ip_local = match.group(1)
                    prefijo = int(match.group(2))
                    
                    # Calcular red CIDR
                    network = ipaddress.IPv4Network(f"{ip_local}/{prefijo}", strict=False)
                    red_cidr = str(network)
                    
                    return {
                        'ip_local': ip_local,
                        'red_cidr': red_cidr,
                        'gateway': gateway or 'No detectado',
                        'interfaz': interfaz,
                        'prefijo': prefijo
                    }
            
            # Fallback: método alternativo usando socket
            return DetectorRed._detectar_red_fallback()
            
        except Exception as e:
            print(f"Error detectando red: {e}")
            return DetectorRed._detectar_red_fallback()
    
    @staticmethod
    def _detectar_red_fallback() -> Dict[str, Any]:
        """Método fallback para detectar red"""
        try:
            # Conectar a servidor externo para determinar IP local
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip_local = s.getsockname()[0]
            
            # Asumir red /24 más común
            network = ipaddress.IPv4Network(f"{ip_local}/24", strict=False)
            
            return {
                'ip_local': ip_local,
                'red_cidr': str(network),
                'gateway': 'Auto-detectado',
                'interfaz': 'auto',
                'prefijo': 24
            }
        except (ValueError, TypeError, OSError) as e:
            logging.debug(f'Error en excepción: {e}')
            return {
                'ip_local': '127.0.0.1',
                'red_cidr': '127.0.0.0/8',
                'gateway': '127.0.0.1',
                'interfaz': 'lo',
                'prefijo': 8
            }
    
    @staticmethod
    def obtener_objetivos_escaneo() -> Tuple[str, str]:
        """
        Obtener objetivos apropiados para escaneo.
        
        Returns:
            Tuple (ip_local, red_cidr)
        """
        info_red = DetectorRed.obtener_red_local()
        return info_red['ip_local'], info_red['red_cidr']
    
    @staticmethod
    def es_red_privada(ip: str) -> bool:
        """Verificar si una IP está en rango privado"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except (ValueError, TypeError, OSError) as e:
            logging.debug(f'Error en excepción: {e}')
            return False
    
    @staticmethod
    def obtener_info_completa() -> Dict[str, Any]:
        """Obtener información completa de red para Dashboard"""
        info_base = DetectorRed.obtener_red_local()
        
        try:
            # Obtener todas las interfaces
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
            interfaces = []
            
            current_interface = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # Línea de interfaz
                if ': ' in line and '<' in line and '>' in line:
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        current_interface = parts[1].split(':')[0]
                        flags = line.split('<')[1].split('>')[0]
                        estado = "ACTIVA" if "UP" in flags else "INACTIVA"
                        
                        interfaces.append({
                            'nombre': current_interface,
                            'estado': estado,
                            'flags': flags
                        })
                
                # IP de la interfaz
                elif current_interface and 'inet ' in line:
                    ip_info = line.split('inet ')[1].split()[0]
                    if interfaces:
                        interfaces[-1]['ip'] = ip_info
            
            info_base['interfaces'] = interfaces
            return info_base
            
        except Exception as e:
            info_base['interfaces'] = []
            info_base['error'] = str(e)
            return info_base
